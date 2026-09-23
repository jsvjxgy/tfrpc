/*
 * SPDX-License-Identifier: GPL-3.0-only
 * v2.c - frp wire protocol v2: magic, frames, ClientHello/ServerHello
 * handshake, AEAD control channel key derivation, and v2 message framing.
 *
 * Only aes-256-gcm is advertised, so the server selects it and we do not
 * need to implement xchacha20-poly1305.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "tfrpc.h"
#include <arpa/inet.h>

#define V2_MAGIC "FRP\x00\x02\r\n"
#define V2_MAGIC_LEN 7   /* Go's MagicV2 is exactly these 7 bytes */

#define V2_FRAME_TYPE_CLIENT_HELLO 1
#define V2_FRAME_TYPE_SERVER_HELLO 2
#define V2_FRAME_TYPE_MESSAGE      16

/* v2 message type ids (pkg/msg/wire_v2.go) */
#define V2_MSG_LOGIN           1

/* ---------------- plain v2 wire frames (handshake phase) ---------------- */

static int v2_frame_write(tconn_t *c, uint16_t type, const uint8_t *payload, uint32_t len) {
    uint8_t hdr[8];
    hdr[0] = (uint8_t)(type >> 8);
    hdr[1] = (uint8_t)(type & 0xff);
    hdr[2] = 0;
    hdr[3] = 0;
    hdr[4] = (uint8_t)(len >> 24);
    hdr[5] = (uint8_t)(len >> 16);
    hdr[6] = (uint8_t)(len >> 8);
    hdr[7] = (uint8_t)(len & 0xff);
    if (tconn_write_full(c, hdr, 8) < 0)
        return -1;
    if (len > 0 && tconn_write_full(c, payload, len) < 0)
        return -1;
    return 0;
}

/* returns 0 on success; *type and malloc'd *payload set */
static int v2_frame_read(tconn_t *c, uint16_t *type, uint8_t **payload, uint32_t *len) {
    uint8_t hdr[8];
    if (tconn_read_full(c, hdr, 8) < 0)
        return -1;
    *type = (uint16_t)((hdr[0] << 8) | hdr[1]);
    *len = ((uint32_t)hdr[4] << 24) | ((uint32_t)hdr[5] << 16) |
           ((uint32_t)hdr[6] << 8) | hdr[7];
    if (*len > 1024 * 1024)
        return -1;
    *payload = malloc(*len + 1);
    if (!*payload) {
        *payload = NULL;
        return -1;
    }
    if (*len > 0 && tconn_read_full(c, *payload, *len) < 0) {
        free(*payload);
        *payload = NULL;
        return -1;
    }
    (*payload)[*len] = '\0';
    return 0;
}

/* ---------------- v2 message framing (used after AEAD is enabled too) ---------------- */

int v2_msg_write(tconn_t *c, uint16_t msg_type, const char *json, size_t len) {
    uint8_t *payload;
    uint32_t plen = (uint32_t)(2 + len);
    int rc;

    payload = malloc(plen);
    if (!payload)
        return -1;
    payload[0] = (uint8_t)(msg_type >> 8);
    payload[1] = (uint8_t)(msg_type & 0xff);
    if (len > 0)
        memcpy(payload + 2, json, len);

    rc = v2_frame_write(c, V2_FRAME_TYPE_MESSAGE, payload, plen);
    free(payload);
    return rc;
}

int v2_msg_read(tconn_t *c, uint16_t *msg_type, char **json, size_t *json_len) {
    uint16_t ftype;
    uint8_t *payload;
    uint32_t plen;
    if (v2_frame_read(c, &ftype, &payload, &plen) < 0) {
        if (json)
            *json = NULL;
        return -1;
    }
    if (ftype != V2_FRAME_TYPE_MESSAGE || plen < 2) {
        free(payload);
        if (json)
            *json = NULL;
        return -1;
    }
    *msg_type = (uint16_t)((payload[0] << 8) | payload[1]);
    *json = malloc(plen - 1);
    if (!*json) {
        free(payload);
        *json = NULL;
        return -1;
    }
    memcpy(*json, payload + 2, plen - 2);
    (*json)[plen - 2] = '\0';
    *json_len = plen - 2;
    free(payload);
    return 0;
}

/* ---------------- handshake ---------------- */

static int build_client_hello(tfrpc_config_t *cfg, char *out, size_t out_len,
                              uint8_t random[32]) {
    char b64[64];
    if (random_bytes(random, 32) < 0)
        return -1;
    base64_encode(random, 32, b64);
    int n = snprintf(out, out_len,
                     "{\"bootstrap\":{\"transport\":\"tcp\",\"tcpMux\":%s},"
                     "\"capabilities\":{\"message\":{\"codecs\":[\"json\"],"
                     "\"udpPacketCodecs\":[\"binary-v1\"]},"
                     "\"crypto\":{\"algorithms\":[\"xchacha20-poly1305\",\"aes-256-gcm\"],"
                     "\"clientRandom\":\"%s\"}}}",
                     cfg->tcp_mux ? "true" : "false", b64);
    if (n < 0 || (size_t)n >= out_len)
        return -1;   /* truncated ClientHello would break the handshake */
    return 0;
}

static void write_u64be(uint8_t out[8], uint64_t v) {
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t)(v >> (56 - i * 8));
}

void v2_derive_keys(const char *token, const uint8_t *client_hello, size_t ch_len,
                    const uint8_t *server_hello, size_t sh_len,
                    const char *algorithm, uint8_t c2s[32], uint8_t s2c[32]) {
    uint8_t transcript[32];
    uint8_t lenb[8];
    char info_c2s[128], info_s2c[128];
    sha256_ctx_t ctx;

    snprintf(info_c2s, sizeof(info_c2s), "frp wire v2 control aead %s client-to-server", algorithm);
    snprintf(info_s2c, sizeof(info_s2c), "frp wire v2 control aead %s server-to-client", algorithm);
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)"frp wire v2 crypto transcript",
                  strlen("frp wire v2 crypto transcript"));
    sha256_update(&ctx, (const uint8_t *)"\x00", 1);
    sha256_update(&ctx, (const uint8_t *)"client hello", 12);
    sha256_update(&ctx, (const uint8_t *)"\x00", 1);
    write_u64be(lenb, ch_len);
    sha256_update(&ctx, lenb, 8);
    sha256_update(&ctx, client_hello, ch_len);
    sha256_update(&ctx, (const uint8_t *)"\x00", 1);
    sha256_update(&ctx, (const uint8_t *)"server hello", 12);
    sha256_update(&ctx, (const uint8_t *)"\x00", 1);
    write_u64be(lenb, sh_len);
    sha256_update(&ctx, lenb, 8);
    sha256_update(&ctx, server_hello, sh_len);
    sha256_final(&ctx, transcript);

    hkdf_sha256((const uint8_t *)token, strlen(token),
                transcript, 32,
                (const uint8_t *)info_c2s, strlen(info_c2s),
                c2s, 32);
    hkdf_sha256((const uint8_t *)token, strlen(token),
                transcript, 32,
                (const uint8_t *)info_s2c, strlen(info_s2c),
                s2c, 32);
}

/* v2 client handshake: magic + ClientHello + Login, read ServerHello + LoginResp.
 * On success the control channel is switched to the AEAD stream and cfg->run_id
 * is set. Returns 0 on success. */
int v2_client_handshake(tconn_t *c, tfrpc_config_t *cfg) {
    char clienthello[512];
    uint8_t random[32];
    char *ch_payload = NULL;
    uint8_t *sh_payload = NULL;
    uint8_t *loginresp = NULL;
    uint32_t sh_len = 0;
    size_t lr_len = 0;
    uint16_t ftype;
    json_buf_t b;
    char err[256] = "";
    char algorithm[64] = "";
    char udpcodec[32] = "";
    uint8_t c2s[32], s2c[32];
    int rc = -1;

    if (tconn_write_full(c, V2_MAGIC, V2_MAGIC_LEN) < 0)
        return -1;

    if (build_client_hello(cfg, clienthello, sizeof(clienthello), random) < 0)
        return -1;
    if (v2_frame_write(c, V2_FRAME_TYPE_CLIENT_HELLO,
                       (const uint8_t *)clienthello, strlen(clienthello)) < 0)
        return -1;
    ch_payload = strdup(clienthello);
    if (!ch_payload)
        return -1;

    proto_build_login(cfg, cfg->run_id[0] ? cfg->run_id : NULL, &b);
    if (v2_msg_write(c, V2_MSG_LOGIN, b.buf, b.len) < 0) {
        jbuf_free(&b);
        goto out;
    }
    jbuf_free(&b);

    if (v2_frame_read(c, &ftype, &sh_payload, &sh_len) < 0)
        goto out;
    if (ftype != V2_FRAME_TYPE_SERVER_HELLO) {
        log_msg(LOG_ERROR, "v2: unexpected frame type %d, want ServerHello", ftype);
        goto out;
    }

    jget_str((const char *)sh_payload, "error", err, sizeof(err));
    if (err[0]) {
        log_msg(LOG_ERROR, "v2 server hello error: %s", err);
        goto out;
    }
    jget_str((const char *)sh_payload, "algorithm", algorithm, sizeof(algorithm));
    jget_str((const char *)sh_payload, "udpPacketCodec", udpcodec, sizeof(udpcodec));
    if (strcmp(algorithm, "aes-256-gcm") != 0 &&
        strcmp(algorithm, "xchacha20-poly1305") != 0) {
        log_msg(LOG_ERROR, "v2: unsupported algorithm [%s]", algorithm);
        goto out;
    }
    log_msg(LOG_DEBUG, "v2: negotiated %s, udp codec %s", algorithm,
            udpcodec[0] ? udpcodec : "(json)");

    if (v2_msg_read(c, &ftype, (char **)&loginresp, &lr_len) < 0) {
        log_msg(LOG_ERROR, "v2: read login response failed");
        goto out;
    }
    {
        char lerr[256] = "";
        jget_str((const char *)loginresp, "error", lerr, sizeof(lerr));
        if (lerr[0]) {
            atomic_store(&g_login_rejected, 1);
            log_msg(LOG_ERROR, "login rejected: %s", lerr);
            goto out;
        }
        jget_str((const char *)loginresp, "run_id", cfg->run_id, sizeof(cfg->run_id));
        log_msg(LOG_INFO, "login ok, run id [%s], user [%s] (v2)", cfg->run_id, cfg->user);
    }

v2_derive_keys(cfg->token, (const uint8_t *)ch_payload, strlen(ch_payload),
               sh_payload, sh_len, algorithm, c2s, s2c);
    tconn_enable_aead(c, c2s, s2c, strcmp(algorithm, "xchacha20-poly1305") == 0);
    rc = 0;

out:
    free(ch_payload);
    free(sh_payload);
    free(loginresp);
    return rc;
}
/* ---------------- v2 binary UDP packet codec ---------------- */

/* encode a client->server UDP packet: flags|remoteAddr|2B len|payload */
int v2_udp_packet_encode(uint8_t *out, size_t outcap,
                         const uint8_t *payload, size_t len,
                         const char *ip, int port) {
    uint8_t addr[1 + 16 + 2 + 1];
    size_t o = 0;
    int family;
    unsigned char a6[16];

    if (inet_pton(AF_INET, ip, a6) == 1)
        family = 4;
    else if (inet_pton(AF_INET6, ip, a6) == 1)
        family = 6;
    else
        return -1;

    if (outcap < 1 + (family == 4 ? 8 : 20) + 2 + len)
        return -1;
    out[o++] = 0x02; /* remote addr present */
    addr[0] = (uint8_t)family;
    if (family == 4) {
        memcpy(addr + 1, a6, 4);
        addr[5] = (uint8_t)(port >> 8);
        addr[6] = (uint8_t)(port & 0xff);
        addr[7] = 0; /* zone length */
        memcpy(out + o, addr, 8);
        o += 8;
    } else {
        memcpy(addr + 1, a6, 16);
        addr[17] = (uint8_t)(port >> 8);
        addr[18] = (uint8_t)(port & 0xff);
        addr[19] = 0; /* zone length */
        memcpy(out + o, addr, 20);
        o += 20;
    }
    out[o++] = (uint8_t)(len >> 8);
    out[o++] = (uint8_t)(len & 0xff);
    memcpy(out + o, payload, len);
    return (int)(o + len);
}

/* decode a server->client UDP packet body into payload + remote addr */
int v2_udp_packet_decode(const uint8_t *body, size_t body_len,
                         uint8_t *payload, size_t payload_cap, size_t *payload_len,
                         char *ip, size_t ip_len, int *port) {
    size_t off = 0;
    uint8_t flags;
    int family;
    size_t ipbytes;
    unsigned char a4[16];

    if (body_len < 1)
        return -1;
    flags = body[off++];
    if (flags & 0x01) {
        /* local addr */
        if (off >= body_len)
            return -1;
        family = body[off++];
        ipbytes = family == 4 ? 4 : 16;
        if (body_len - off < ipbytes + 2 + 1)
            return -1;
        off += ipbytes + 2 + 1 + body[off + ipbytes + 2];
        if (off > body_len)
            return -1;
    }
    if (!(flags & 0x02))
        return -1;
    if (off >= body_len)
        return -1;
    family = body[off++];
    ipbytes = family == 4 ? 4 : 16;
    if (body_len - off < ipbytes + 2 + 1)
        return -1;
    memcpy(a4, body + off, ipbytes);
    off += ipbytes;
    *port = (int)((body[off] << 8) | body[off + 1]);
    off += 2;
    {
        size_t zlen = body[off++];
        if (body_len - off < zlen + 2)
            return -1;
        off += zlen;
    }
    if (family == 4)
        snprintf(ip, ip_len, "%u.%u.%u.%u", a4[0], a4[1], a4[2], a4[3]);
    else
        snprintf(ip, ip_len, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 a4[0], a4[1], a4[2], a4[3], a4[4], a4[5], a4[6], a4[7],
                 a4[8], a4[9], a4[10], a4[11], a4[12], a4[13], a4[14], a4[15]);
    {
        size_t plen = (size_t)((body[off] << 8) | body[off + 1]);
        off += 2;
        if (body_len - off < plen)
            return -1;
        if (plen > payload_cap)
            return -1;
        memcpy(payload, body + off, plen);
        *payload_len = plen;
    }
    return 0;
}


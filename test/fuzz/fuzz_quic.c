/*
 * SPDX-License-Identifier: GPL-3.0-only
 * fuzz_quic.c - libFuzzer harness for the QUIC parsers (white-box).
 *
 * Input format: the first byte selects the target, the rest is fed to it.
 *   0: 1-RTT frame parser (plaintext frames, as a peer with valid keys)
 *   1: Initial-space frame parser
 *   2: Handshake-space frame parser
 *   3: Handshake CRYPTO reassembly + message parser (state preset to 1)
 *   4: 1-RTT frames delivered to a live stream (reassembly queue)
 *   5: raw space-0 CRYPTO input (ServerHello path, state 0)
 *   6: coalesced datagram parse (quic_process_packet with random bytes)
 *   7: receive path with VALID Initial keys: input becomes plaintext frames
 *      of a crafted server Initial packet passed to quic_recv_long
 *   8: receive path with VALID 1-RTT keys; the top input bit selects key
 *      phase 1, exercising the key-update rotation in quic_recv_short
 *   9: structured ServerHello (fixed prefix + fuzz extensions)
 *  10: structured EncryptedExtensions (transport parameters parser)
 *  11: structured Certificate message (DER inside the TLS framing)
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined -Iinclude -o fuzz_quic \
 *       test/fuzz/fuzz_quic.c src/crypto.c src/x25519.c src/x509.c \
 *       src/ecdsa.c src/bignum.c src/base64.c src/net.c src/log.c -pthread
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "tfrpc.h"

_Atomic int g_running = 1;

#include "../src/quic.c"

static quic_conn_t *g_c;
static uint8_t g_sap_secret[32];   /* fixed app secret for valid 1-RTT input */

static void free_streams(void) {
    quic_stream_t *s = g_c->streams;
    while (s) {
        quic_stream_t *n = s->next;
        free(s->rxbuf);
        while (s->rxq) {
            quic_rxchunk_t *ch = s->rxq;
            s->rxq = ch->next;
            free(ch->data);
            free(ch);
        }
        pthread_mutex_destroy(&s->mu);
        pthread_cond_destroy(&s->cv);
        free(s);
        s = n;
    }
    g_c->streams = NULL;
}

static void free_txq(void) {
    while (g_c->txq) {
        quic_txpkt_t *n = g_c->txq->next;
        free(g_c->txq);
        g_c->txq = n;
    }
    g_c->txq_bytes = 0;
}

static void setup_keys(void) {
    uint8_t isec[32], srv[32];
    quic_hkdf_extract(QUIC_INITIAL_SALT, sizeof(QUIC_INITIAL_SALT),
                      g_c->dcid, g_c->dcid_len, isec);
    quic_expand_label(isec, 32, "server in", NULL, 0, srv, 32);
    quic_keys_init(&g_c->sinit, srv);
    for (int i = 0; i < 32; i++)
        g_sap_secret[i] = (uint8_t)(i * 31 + 7);
    quic_keys_init(&g_c->sap, g_sap_secret);
    memcpy(g_c->sap_secret, g_sap_secret, 32);
    memcpy(g_c->cap_secret, g_sap_secret, 32);
    quic_keys_init(&g_c->cap, g_sap_secret);
    g_c->key_phase = 0;
}

static void reset_state(void) {
    free_streams();
    free_txq();
    while (g_c->crypto_pending) {
        quic_rxchunk_t *ch = g_c->crypto_pending;
        g_c->crypto_pending = ch->next;
        free(ch->data);
        free(ch);
    }
    g_c->crypto_pending_bytes = 0;
    g_c->closed = 0;
    g_c->hs_done = 0;
    g_c->hs_failed = 0;
    g_c->hs_inlen = 0;
    g_c->crypto_ini_off = 0;
    g_c->crypto_hs_off = 0;
    g_c->rpn_initial = 0;
    g_c->rpn_handshake = 0;
    g_c->rpn_app = 0;
    g_c->pn_initial = 0;
    g_c->pn_handshake = 0;
    g_c->pn_app = 0;
    g_c->server_scid_len = 0;
    memset(&g_c->hs, 0, sizeof(g_c->hs));
    sha256_init(&g_c->hs.transcript);
    g_c->hs.state = 1;
    g_c->cpt_ini_n = 0;
    g_c->cpt_hs_n = 0;
    g_c->tx_ini_acked = g_c->tx_ini_sent = 0;
    g_c->tx_hs_acked = g_c->tx_hs_sent = 0;
    /* restore the phase-0 receive keys (a previous input may have rotated) */
    quic_keys_init(&g_c->sap, g_sap_secret);
    memcpy(g_c->sap_secret, g_sap_secret, 32);
    memcpy(g_c->cap_secret, g_sap_secret, 32);
    quic_keys_init(&g_c->cap, g_sap_secret);
    g_c->psap.valid = 0;
    g_c->key_phase = 0;
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* craft a server Initial packet carrying `frames` as plaintext */
static size_t craft_initial(const uint8_t *frames, size_t flen, uint8_t *out) {
    quic_keys_t *k = &g_c->sinit;
    if (flen > QUIC_MAX_DGRAM - 64)
        flen = QUIC_MAX_DGRAM - 64;
    uint64_t pn = 0;
    size_t pn_len = pn_encode_len(pn);
    size_t p = 0;
    out[p++] = (uint8_t)(0xc0 | (uint8_t)(pn_len - 1));
    out[p++] = 0; out[p++] = 0; out[p++] = 0; out[p++] = 1;
    out[p++] = (uint8_t)g_c->dcid_len;
    memcpy(out + p, g_c->dcid, g_c->dcid_len); p += g_c->dcid_len;
    out[p++] = 8;
    memset(out + p, 0x42, 8); p += 8;
    out[p++] = 0;                                  /* token length */
    size_t len_at = p;
    p += 2;
    size_t pn_pos = p;
    size_t payload_len = pn_len + flen + 16;
    out[len_at] = (uint8_t)(0x40 | (payload_len >> 8));
    out[len_at + 1] = (uint8_t)payload_len;

    uint8_t plain_pn[4] = { 0, 0, 0, 0 };
    uint8_t aad[QUIC_MAX_DGRAM];
    memcpy(aad, out, pn_pos);
    memcpy(aad + pn_pos, plain_pn, pn_len);
    uint8_t ct[QUIC_MAX_DGRAM], tag[16], nonce[12];
    memcpy(ct, frames, flen);
    quic_nonce(nonce, k, pn);
    aes_gcm_seal(k->key, 16, nonce, aad, pn_pos + pn_len, ct, flen, tag);
    size_t q = pn_pos;
    memcpy(out + q, plain_pn, pn_len); q += pn_len;
    memcpy(out + q, ct, flen); q += flen;
    memcpy(out + q, tag, 16); q += 16;
    quic_apply_hp(k, out, out + pn_pos, pn_len, out + pn_pos, q - pn_pos);
    return q;
}

/* craft a server 1-RTT packet; phase selects the key phase bit / keys */
static size_t craft_short(int phase, const uint8_t *frames, size_t flen, uint8_t *out) {
    quic_keys_t cur, nk;
    if (flen > QUIC_MAX_DGRAM - 64)
        flen = QUIC_MAX_DGRAM - 64;
    memcpy(&cur, &g_c->sap, sizeof(cur));
    if (phase) {
        uint8_t ns[32];
        quic_expand_label(g_sap_secret, 32, "quic ku", NULL, 0, ns, 32);
        quic_keys_init(&nk, ns);
        memcpy(nk.hp, cur.hp, sizeof(nk.hp));   /* HP key never rotates */
        cur = nk;
    }
    uint64_t pn = 0;
    size_t pn_len = pn_encode_len(pn);
    size_t p = 0;
    out[p++] = (uint8_t)(0x40 | (phase ? 0x04 : 0) | (uint8_t)(pn_len - 1));
    memcpy(out + p, g_c->dcid, g_c->dcid_len); p += g_c->dcid_len;
    size_t pn_pos = p;
    uint8_t plain_pn[4] = { 0, 0, 0, 0 };
    uint8_t aad[QUIC_MAX_DGRAM];
    memcpy(aad, out, pn_pos);
    memcpy(aad + pn_pos, plain_pn, pn_len);
    uint8_t ct[QUIC_MAX_DGRAM], tag[16], nonce[12];
    memcpy(ct, frames, flen);
    quic_nonce(nonce, &cur, pn);
    aes_gcm_seal(cur.key, 16, nonce, aad, pn_pos + pn_len, ct, flen, tag);
    size_t q = pn_pos;
    memcpy(out + q, plain_pn, pn_len); q += pn_len;
    memcpy(out + q, ct, flen); q += flen;
    memcpy(out + q, tag, 16); q += 16;
    quic_apply_hp(&cur, out, out + pn_pos, pn_len, out + pn_pos, q - pn_pos);
    return q;
}

/* wrap `body` as a handshake message of `type` and feed it as one CRYPTO
 * chunk in the given space */
static void feed_message(int space, uint8_t type, const uint8_t *body, size_t blen) {
    uint8_t msg[4096];
    if (blen > sizeof(msg) - 4)
        blen = sizeof(msg) - 4;
    msg[0] = type;
    msg[1] = (uint8_t)(blen >> 16);
    msg[2] = (uint8_t)(blen >> 8);
    msg[3] = (uint8_t)blen;
    memcpy(msg + 4, body, blen);
    uint64_t off = (space == 0) ? g_c->crypto_ini_off : g_c->crypto_hs_off;
    quic_crypto_input(g_c, space, off, msg, blen + 4);
}

/* build a ServerHello body: fixed prefix + fuzz bytes as extensions */
static void feed_server_hello(const uint8_t *p, size_t n) {
    uint8_t body[4096];
    size_t o = 0;
    body[o++] = 0x03; body[o++] = 0x03;
    for (int i = 0; i < 32; i++)
        body[o++] = (uint8_t)i;
    body[o++] = 0;                              /* session id length */
    body[o++] = 0x13; body[o++] = 0x01;         /* cipher suite */
    body[o++] = 0x01; body[o++] = 0x00;         /* compression */
    if (o + 2 + n > sizeof(body))
        n = sizeof(body) - o - 2;
    body[o++] = (uint8_t)(n >> 8);
    body[o++] = (uint8_t)n;
    memcpy(body + o, p, n);
    o += n;
    g_c->hs.state = 0;
    feed_message(0, 2, body, o);
}

/* build an EncryptedExtensions body: extensions = fuzz bytes */
static void feed_ee(const uint8_t *p, size_t n) {
    uint8_t body[4096];
    size_t o = 0;
    if (n > sizeof(body) - 2)
        n = sizeof(body) - 2;
    body[o++] = (uint8_t)(n >> 8);
    body[o++] = (uint8_t)n;
    memcpy(body + o, p, n);
    o += n;
    g_c->hs.state = 1;
    feed_message(1, 8, body, o);
}

/* build a Certificate body with the fuzz bytes as the leaf DER */
static void feed_cert(const uint8_t *p, size_t n) {
    uint8_t body[4096];
    size_t o = 0;
    if (n > sizeof(body) - 8)
        n = sizeof(body) - 8;
    body[o++] = 0;                              /* request context length */
    size_t list_at = o;
    o += 3;                                     /* list length */
    body[o++] = (uint8_t)(n >> 16);
    body[o++] = (uint8_t)(n >> 8);
    body[o++] = (uint8_t)n;
    memcpy(body + o, p, n);
    o += n;
    body[o++] = 0; body[o++] = 0; body[o++] = 0;  /* no extensions */
    size_t list = o - list_at - 3;
    body[list_at] = (uint8_t)(list >> 16);
    body[list_at + 1] = (uint8_t)(list >> 8);
    body[list_at + 2] = (uint8_t)list;
    g_c->hs.state = 1;
    feed_message(1, 11, body, o);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2)
        return 0;
    if (!g_c) {
        g_c = calloc(1, sizeof(*g_c));
        if (!g_c)
            return 0;
        pthread_mutex_init(&g_c->mu, NULL);
        pthread_cond_init(&g_c->cv, NULL);
        g_c->fd = -1;
        g_c->dcid_len = 8;
        memcpy(g_c->dcid, "fuzzdcid", 8);
        g_c->scid_len = 8;
        memcpy(g_c->scid, "fuzzscid", 8);
        setup_keys();
    }
    reset_state();

    uint8_t mode = data[0] % 12;
    const uint8_t *p = data + 1;
    size_t n = size - 1;
    uint8_t pkt[QUIC_MAX_DGRAM];

    switch (mode) {
    case 0:
    case 1:
    case 2:
        quic_parse_frames(g_c, (int)mode, p, n);
        break;
    case 3: {
        size_t pos = 0;
        while (pos < n) {
            size_t chunk = (n - pos) > 300 ? 300 : (n - pos);
            uint64_t off = (pos + chunk < n) ? rd32(p + pos) & 0x1ff : g_c->crypto_hs_off;
            if (pos + 4 <= n && pos + 4 + chunk <= n)
                quic_crypto_input(g_c, 1, off, p + pos + 4, chunk);
            pos += 4 + chunk;
        }
        if (n >= 4) {
            uint8_t msg[16];
            msg[0] = p[0] % 32;
            msg[1] = 0; msg[2] = 0; msg[3] = (uint8_t)(n > 12 ? n - 12 : 0);
            quic_crypto_input(g_c, 1, g_c->crypto_hs_off, msg, 4);
            if (n > 12)
                quic_crypto_input(g_c, 1, g_c->crypto_hs_off, p + 4, n - 12);
        }
        break;
    }
    case 4: {
        quic_stream_t *s = calloc(1, sizeof(*s));
        if (s) {
            s->qc = g_c;
            s->rxcap = 16;
            s->rxbuf = malloc(16);
            pthread_mutex_init(&s->mu, NULL);
            pthread_cond_init(&s->cv, NULL);
            s->id = 0;
            g_c->streams = s;
            quic_parse_frames(g_c, 2, p, n);
        }
        break;
    }
    case 5:
        g_c->hs.state = 0;
        quic_crypto_input(g_c, 0, 0, p, n);
        break;
    case 6:
        quic_process_packet(g_c, p, n);
        break;
    case 7: {
        size_t plen = n > QUIC_MAX_DGRAM - 64 ? QUIC_MAX_DGRAM - 64 : n;
        size_t pl = craft_initial(p, plen, pkt);
        quic_recv_long(g_c, pkt, pl);
        break;
    }
    case 8: {
        int phase = (n > 0) && (p[0] & 1);
        const uint8_t *fr = p + 1;
        size_t fl = n - 1;
        size_t pl = craft_short(phase, fr, fl, pkt);
        quic_recv_short(g_c, pkt, pl);
        break;
    }
    case 9:
        feed_server_hello(p, n);
        break;
    case 10:
        feed_ee(p, n);
        break;
    case 11:
        feed_cert(p, n);
        break;
    default:
        break;
    }
    return 0;
}

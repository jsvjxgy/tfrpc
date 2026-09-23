/*
 * SPDX-License-Identifier: GPL-3.0-only
 * tconn.c - unified connection abstraction (raw socket or yamux stream)
 * with optional lazy AES-128-CFB encryption matching frp's golib crypto:
 *  - first write prepends a random 16-byte IV
 *  - first read consumes the peer's 16-byte IV
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>

#include "tfrpc.h"
#include "kcp.h"
#include "snappy.h"
#include "tls.h"
#include "x509.h"

static int tconn_write_plain(tconn_t *c, const void *buf, size_t n);
static int tconn_read_plain(tconn_t *c, void *buf, size_t n);
static int tconn_write_enc(tconn_t *c, const void *buf, size_t n);
static int tconn_read_enc(tconn_t *c, void *buf, size_t n);

tconn_t *tconn_socket(int fd) {
    tconn_t *c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->kind = 0;
    c->fd = fd;
    return c;
}

tconn_t *tconn_stream(void *sess) {
    tconn_t *c = calloc(1, sizeof(*c));
    void *st;
    if (!c)
        return NULL;
    st = yamux_open(sess);
    if (!st) {
        free(c);
        return NULL;
    }
    c->kind = 1;
    c->sess = sess;
    c->st = st;
    return c;
}

/* wrap fd with TLS when transport.tls.enable is set (returns tls_conn or NULL) */
static int kcp_io_read(void *io, uint8_t *buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        int r = kcp_read((kcpconn_t *)io, buf + done, (int)(len - done));
        if (r <= 0)
            return -1;
        done += (size_t)r;
    }
    return 0;
}

static int kcp_io_write(void *io, const uint8_t *buf, size_t len) {
    return kcp_write((kcpconn_t *)io, buf, (int)len);
}

static void *tls_wrap_common(const tfrpc_config_t *cfg, int fd, void *kconn) {
    if (!cfg->tls_enable)
        return NULL;
    tls_skip_marker = cfg->tls_disable_first_byte ? 1 : 0;
    if (getenv("TFRPC_TLS_FORCE12"))
        tls_force_12 = 1;
    const char *sn = cfg->tls_server_name[0] ? cfg->tls_server_name : cfg->server_addr;

    x509_cert_t ca;
    const x509_cert_t *ca_p = NULL;
    if (cfg->tls_trusted_ca[0]) {
        FILE *f = fopen(cfg->tls_trusted_ca, "rb");
        if (!f) {
            log_msg(LOG_WARN, "cannot open trustedCaFile %s", cfg->tls_trusted_ca);
            return NULL;
        }
        char pem[16384];
        size_t n = fread(pem, 1, sizeof(pem) - 1, f);
        fclose(f);
        pem[n] = '\0';
        uint8_t der[8192];
        size_t dlen = 0;
        if (x509_pem_first_cert(pem, n, der, sizeof(der), &dlen) < 0) {
            log_msg(LOG_WARN, "no certificate in trustedCaFile %s", cfg->tls_trusted_ca);
            return NULL;
        }
        if (x509_parse(der, dlen, &ca) < 0) {
            log_msg(LOG_WARN, "cannot parse trusted CA certificate");
            return NULL;
        }
        ca_p = &ca;
    }

    /* optional client certificate (mTLS) */
    uint8_t cert_der[8192];
    size_t cert_len = 0;
    rsa_priv_t key;
    int has_key = 0;
    if (cfg->tls_cert_file[0] && cfg->tls_key_file[0]) {
        FILE *cf = fopen(cfg->tls_cert_file, "rb");
        FILE *kf = fopen(cfg->tls_key_file, "rb");
        if (!cf || !kf) {
            log_msg(LOG_WARN, "cannot open certFile/keyFile");
            if (cf) fclose(cf);
            if (kf) fclose(kf);
            return NULL;
        }
        char cpem[32768], kpem[32768];
        size_t cn = fread(cpem, 1, sizeof(cpem) - 1, cf);
        size_t kn = fread(kpem, 1, sizeof(kpem) - 1, kf);
        fclose(cf);
        fclose(kf);
        cpem[cn] = '\0';
        kpem[kn] = '\0';
        if (x509_pem_first_cert(cpem, cn, cert_der, sizeof(cert_der), &cert_len) < 0) {
            log_msg(LOG_WARN, "cannot parse client certificate");
            return NULL;
        }
        if (x509_parse_private_key(kpem, kn, &key) < 0) {
            log_msg(LOG_WARN, "cannot parse client private key");
            return NULL;
        }
        has_key = 1;
    }

    if (kconn)
        return tls_connect_io(kconn, kcp_io_read, kcp_io_write, sn, ca_p,
                              cert_len ? cert_der : NULL, cert_len,
                              has_key ? &key : NULL);
    return tls_connect(fd, sn, ca_p, cert_len ? cert_der : NULL,
                       cert_len, has_key ? &key : NULL);
}

void *tconn_tls_wrap(const tfrpc_config_t *cfg, int fd) {
    return tls_wrap_common(cfg, fd, NULL);
}

void *tconn_tls_wrap_kcp(const tfrpc_config_t *cfg, void *kconn) {
    return tls_wrap_common(cfg, -1, kconn);
}

tconn_t *tconn_socket_tls(int fd, void *tls) {
    tconn_t *c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->kind = 0;
    c->fd = fd;
    c->tls = tls;
    return c;
}

tconn_t *tconn_kcp(void *kconn) {
    tconn_t *c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->kind = 2;
    c->kconn = kconn;
    return c;
}

tconn_t *tconn_kcp_tls(void *kconn, void *tls) {
    tconn_t *c = tconn_kcp(kconn);
    if (!c)
        return NULL;
    c->tls = tls;   /* TLS sits on top of the KCP session */
    return c;
}

void tconn_set_deadline(tconn_t *c, int timeout_ms) {
    if (!c)
        return;
    if (c->kind == 2)
        kcp_set_deadline(c->kconn, timeout_ms);
}

int tconn_enable_crypto(tconn_t *c, const uint8_t key[16]) {
    c->crypto = 1;
    memcpy(c->ckey, key, 16);
    return 0;
}

int tconn_enable_aead(tconn_t *c, const uint8_t write_key[32], const uint8_t read_key[32],
                      int xchacha) {
    c->aead = 1;
    c->aead_xchacha = xchacha;
    memcpy(c->awrite_key, write_key, 32);
    memcpy(c->aread_key, read_key, 32);
    return 0;
}

#define AEAD_FRAME_HDR 4
#define AEAD_TAG_LEN 16
#define AEAD_MAX_PAYLOAD (64 * 1024)

static int aead_nonce_len(tconn_t *c) { return c->aead_xchacha ? 24 : 12; }

static void aead_inc_nonce(uint8_t *nonce, int nlen) {
    for (int i = nlen - 1; i >= 0; i--)
        if (++nonce[i] != 0)
            break;
}

/* write one AEAD frame: 4B ciphertext length || ciphertext */
static int aead_write_frame(tconn_t *c, const uint8_t *plain, size_t len) {
    uint8_t hdr[AEAD_FRAME_HDR];
    int nlen = aead_nonce_len(c);
    uint8_t *aad = malloc(nlen + AEAD_FRAME_HDR);
    uint8_t *ct;
    size_t ct_len = len + AEAD_TAG_LEN;
    uint8_t tag[AEAD_TAG_LEN];
    int rc = -1;
    if (!aad)
        return -1;

    hdr[0] = (uint8_t)(ct_len >> 24);
    hdr[1] = (uint8_t)(ct_len >> 16);
    hdr[2] = (uint8_t)(ct_len >> 8);
    hdr[3] = (uint8_t)ct_len;
    memcpy(aad, c->awrite_stream_nonce, nlen);
    memcpy(aad + nlen, hdr, AEAD_FRAME_HDR);

    ct = malloc(ct_len);
    if (!ct) { free(aad); return -1; }
    memcpy(ct, plain, len);
    if (c->aead_xchacha)
        xchacha20_poly1305_seal(c->awrite_key, c->awrite_nonce, aad, nlen + AEAD_FRAME_HDR,
                                ct, len, tag);
    else
        aes_gcm_seal(c->awrite_key, 32, c->awrite_nonce, aad, nlen + AEAD_FRAME_HDR,
                     ct, len, tag);
    memcpy(ct + len, tag, AEAD_TAG_LEN);
    aead_inc_nonce(c->awrite_nonce, nlen);

    if (tconn_write_plain(c, hdr, AEAD_FRAME_HDR) == 0 &&
        tconn_write_plain(c, ct, ct_len) == 0)
        rc = 0;
    free(ct);
    free(aad);
    return rc;
}

static int tconn_aead_enc_init(tconn_t *c) {
    int nlen = aead_nonce_len(c);
    if (c->aead_w_header_sent)
        return 0;
    if (random_bytes(c->awrite_nonce, nlen) < 0)
        return -1;
    memcpy(c->awrite_stream_nonce, c->awrite_nonce, nlen);
    if (tconn_write_plain(c, c->awrite_nonce, nlen) < 0)
        return -1;
    c->aead_w_header_sent = 1;
    return 0;
}

static int aead_read_frame(tconn_t *c, uint8_t *out, size_t *out_len) {
    uint8_t hdr[AEAD_FRAME_HDR];
    int nlen = aead_nonce_len(c);
    uint8_t *aad = malloc(nlen + AEAD_FRAME_HDR);
    uint8_t *ct;
    uint32_t ct_len;
    uint8_t *tag;
    int r = -1;
    if (!aad)
        return -1;

    if (tconn_read_plain(c, hdr, AEAD_FRAME_HDR) < 0) { free(aad); return -1; }
    ct_len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
             ((uint32_t)hdr[2] << 8) | hdr[3];
    if (ct_len < AEAD_TAG_LEN || ct_len > AEAD_MAX_PAYLOAD + AEAD_TAG_LEN) { free(aad); return -1; }

    ct = malloc(ct_len);
    if (!ct) { free(aad); return -1; }
    if (tconn_read_plain(c, ct, ct_len) < 0) { free(ct); free(aad); return -1; }
    tag = ct + ct_len - AEAD_TAG_LEN;
    memcpy(aad, c->aread_stream_nonce, nlen);
    memcpy(aad + nlen, hdr, AEAD_FRAME_HDR);

    *out_len = ct_len - AEAD_TAG_LEN;
    if (c->aead_xchacha) {
        if (xchacha20_poly1305_open(c->aread_key, c->aread_nonce, aad, nlen + AEAD_FRAME_HDR,
                                    ct, *out_len, tag) != 0)
            goto done;
    } else {
        if (aes_gcm_open(c->aread_key, 32, c->aread_nonce, aad, nlen + AEAD_FRAME_HDR,
                         ct, *out_len, tag) != 0)
            goto done;
    }
    aead_inc_nonce(c->aread_nonce, nlen);
    memcpy(out, ct, *out_len);
    r = 0;
done:
    free(ct);
    free(aad);
    return r;
}

static int tconn_aead_dec_init(tconn_t *c) {
    int nlen = aead_nonce_len(c);
    if (c->aead_r_header_sent)
        return 0;
    if (tconn_read_plain(c, c->aread_nonce, nlen) < 0)
        return -1;
    memcpy(c->aread_stream_nonce, c->aread_nonce, nlen);
    c->aead_r_header_sent = 1;
    return 0;
}

static void tconn_aead_free(tconn_t *c) {
    free(c->rxbuf);
    c->rxbuf = NULL;
    c->rxlen = c->rxcap = 0;
}

/* refill rxbuf with at least `need` decrypted bytes */
static int aead_fill(tconn_t *c, size_t need) {
    while (c->rxlen < need) {
        uint8_t tmp[AEAD_MAX_PAYLOAD];
        size_t n = 0;
        if (c->rxlen + AEAD_MAX_PAYLOAD > c->rxcap) {
            size_t ncap = c->rxcap ? c->rxcap * 2 : AEAD_MAX_PAYLOAD;
            while (ncap < c->rxlen + AEAD_MAX_PAYLOAD)
                ncap *= 2;
            uint8_t *nb = realloc(c->rxbuf, ncap);
            if (!nb)
                return -1;
            c->rxbuf = nb;
            c->rxcap = ncap;
        }
        if (aead_read_frame(c, tmp, &n) < 0)
            return -1;
        memcpy(c->rxbuf + c->rxlen, tmp, n);
        c->rxlen += n;
    }
    return 0;
}

static int tconn_write_plain(tconn_t *c, const void *buf, size_t n) {
    if (c->tls)
        return tls_write((tls_conn_t *)c->tls, buf, n);
    if (c->kind == 0)
        return write_full(c->fd, buf, n);
    if (c->kind == 2) {
        if (n > 0x7fffffff)
            return -1;
        return kcp_write(c->kconn, buf, (int)n);
    }
    return yamux_stream_write(c->st, buf, n);
}

static int tconn_read_plain(tconn_t *c, void *buf, size_t n) {
    if (c->tls) {
        size_t done = 0;
        while (done < n) {
            int r = tls_read((tls_conn_t *)c->tls, (uint8_t *)buf + done, n - done);
            if (r <= 0)
                return -1;
            done += (size_t)r;
        }
        return 0;
    }
    if (c->kind == 0)
        return read_full(c->fd, buf, n);
    if (c->kind == 2) {
        size_t done = 0;
        while (done < n) {
            int r = kcp_read(c->kconn, (uint8_t *)buf + done, (int)(n - done));
            if (r <= 0)
                return -1;
            done += (size_t)r;
        }
        return 0;
    }
    {
        size_t done = 0;
        while (done < n) {
            int r = yamux_stream_read(c->st, (uint8_t *)buf + done, n - done);
            if (r <= 0)
                return -1;
            done += (size_t)r;
        }
        return 0;
    }
}

/* ensure the outgoing IV has been written and enc ctx created */
static int tconn_enc_init(tconn_t *c) {
    uint8_t iv[16];
    if (!c->crypto || c->enc_iv_sent)
        return 0;
    if (random_bytes(iv, sizeof(iv)) < 0)
        return -1;
    if (tconn_write_plain(c, iv, sizeof(iv)) < 0)
        return -1;
    c->enc_ctx = aes_cfb_new(c->ckey, 16, iv, 1);
    if (!c->enc_ctx)
        return -1;
    c->enc_iv_sent = 1;
    return 0;
}

/* consume the peer's IV and create the dec ctx */
static int tconn_dec_init(tconn_t *c) {
    uint8_t iv[16];
    if (!c->crypto || c->dec_iv_read)
        return 0;
    if (tconn_read_plain(c, iv, sizeof(iv)) < 0)
        return -1;
    c->dec_ctx = aes_cfb_new(c->ckey, 16, iv, 0);
    if (!c->dec_ctx)
        return -1;
    c->dec_iv_read = 1;
    return 0;
}

static int tconn_read_enc(tconn_t *c, void *buf, size_t n) {
    if (c->aead) {
        if (!c->aead_r_header_sent) {
            if (tconn_aead_dec_init(c) < 0)
                return -1;
        }
        if (aead_fill(c, n) < 0)
            return -1;
        memcpy(buf, c->rxbuf, n);
        memmove(c->rxbuf, c->rxbuf + n, c->rxlen - n);
        c->rxlen -= n;
        return 0;
    }
    if (c->crypto && !c->dec_iv_read) {
        if (tconn_dec_init(c) < 0)
            return -1;
    }
    if (tconn_read_plain(c, buf, n) < 0)
        return -1;
    if (c->crypto)
        aes_cfb_stream(c->dec_ctx, buf, n);
    return 0;
}

int tconn_read_some(tconn_t *c, void *buf, size_t n) {
    ssize_t r;
    if (c->compress)
        return snappy_reader_read(c->zr, buf, n);
    if (c->aead) {
        if (!c->aead_r_header_sent) {
            if (tconn_aead_dec_init(c) < 0)
                return -1;
        }
        if (c->rxlen == 0) {
            if (aead_fill(c, 1) < 0)
                return -1;
        }
        if (c->rxlen == 0)
            return 0;
        size_t m = n < c->rxlen ? n : c->rxlen;
        memcpy(buf, c->rxbuf, m);
        memmove(c->rxbuf, c->rxbuf + m, c->rxlen - m);
        c->rxlen -= m;
        return (int)m;
    }
    if (c->crypto && !c->dec_iv_read) {
        if (tconn_dec_init(c) < 0)
            return -1;
    }
    if (c->tls)
        r = tls_read((tls_conn_t *)c->tls, buf, n);
    else if (c->kind == 0)
        r = read(c->fd, buf, n);
    else if (c->kind == 2)
        r = kcp_read(c->kconn, buf, (int)n);
    else
        r = yamux_stream_read(c->st, buf, n);
    if (r <= 0)
        return (int)r;
    if (c->crypto)
        aes_cfb_stream(c->dec_ctx, buf, (size_t)r);
    return (int)r;
}

static int tconn_write_enc(tconn_t *c, const void *buf, size_t n) {
    uint8_t *tmp = NULL;
    if (c->aead) {
        if (tconn_aead_enc_init(c) < 0)
            return -1;
        while (n > 0) {
            size_t chunk = n > AEAD_MAX_PAYLOAD ? AEAD_MAX_PAYLOAD : n;
            if (aead_write_frame(c, (const uint8_t *)buf, chunk) < 0)
                return -1;
            buf = (const uint8_t *)buf + chunk;
            n -= chunk;
        }
        return 0;
    }
    if (c->crypto) {
        if (tconn_enc_init(c) < 0)
            return -1;
        tmp = malloc(n ? n : 1);
        if (!tmp)
            return -1;
        memcpy(tmp, buf, n);
        aes_cfb_stream(c->enc_ctx, tmp, n);
        buf = tmp;
    }
    {
        int rc = tconn_write_plain(c, buf, n);
        free(tmp);
        return rc;
    }
}

int tconn_wait_readable(tconn_t *c, int timeout_ms) {
    if (c->aead) {
        if (c->rxlen > 0)
            return 1;
        if (c->kind == 0) {
            struct pollfd pfd = {.fd = c->fd, .events = POLLIN};
            int pr = poll(&pfd, 1, timeout_ms);
            if (pr > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR)))
                return 1;
            return 0;
        }
        if (c->kind == 2)
            return kcp_wait_readable(c->kconn, timeout_ms);
        return yamux_stream_wait_readable(c->st, timeout_ms);
    }
    if (c->kind == 0) {
        struct pollfd pfd = {.fd = c->fd, .events = POLLIN};
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR)))
            return 1;
        return 0;
    }
    if (c->kind == 2)
        return kcp_wait_readable(c->kconn, timeout_ms);
    return yamux_stream_wait_readable(c->st, timeout_ms);
}

/* compression layer: snappy writer feeds the encryption layer; the snappy
 * reader pulls decrypted bytes from it (frp applies compression outside
 * encryption, so write = compress->encrypt and read = decrypt->decompress). */

static int tconn_compress_out(void *ctx, const uint8_t *data, size_t len) {
    return tconn_write_enc((tconn_t *)ctx, data, len);
}

static int tconn_compress_in(void *ctx, uint8_t *data, size_t len) {
    return tconn_read_enc((tconn_t *)ctx, data, len);
}

int tconn_enable_compression(tconn_t *c) {
    if (c->compress)
        return 0;
    c->zw = snappy_writer_new(tconn_compress_out, c);
    c->zr = snappy_reader_new(tconn_compress_in, c);
    if (!c->zw || !c->zr)
        return -1;
    c->compress = 1;
    return 0;
}

int tconn_write_full(tconn_t *c, const void *buf, size_t n) {
    if (c->compress)
        return snappy_writer_write(c->zw, buf, n);
    return tconn_write_enc(c, buf, n);
}

/* flush buffered compressor output (e.g. before half-closing the stream) */
int tconn_flush(tconn_t *c) {
    if (c && c->compress && c->zw)
        return snappy_writer_flush(c->zw);
    return 0;
}

int tconn_read_full(tconn_t *c, void *buf, size_t n) {
    if (c->compress) {
        size_t done = 0;
        while (done < n) {
            int r = snappy_reader_read(c->zr, (uint8_t *)buf + done, n - done);
            if (r <= 0)
                return -1;
            done += (size_t)r;
        }
        return 0;
    }
    return tconn_read_enc(c, buf, n);
}

/* wake a blocked reader/writer on this connection without freeing it.
 * Used by the relay so one failing direction cannot free a tconn that the
 * other direction is still using. */
void tconn_abort(tconn_t *c) {
    if (!c)
        return;
    /* dispatch by transport kind: TLS-over-KCP has fd == -1, so a plain
       shutdown(c->fd) would be a no-op there and leave the peer direction
       blocked until the heartbeat timeout */
    if (c->kind == 1) {
        yamux_stream_abort(c->st);
    } else if (c->kind == 2) {
        kcp_abort(c->kconn);
    } else if (c->fd >= 0) {
        shutdown(c->fd, SHUT_RDWR);   /* plain socket or TLS over TCP */
    }
}

void tconn_close(tconn_t *c) {
    if (!c)
        return;
    if (c->compress) {
        snappy_writer_flush(c->zw);   /* do not lose the buffered tail */
        snappy_writer_free(c->zw);
        snappy_reader_free(c->zr);
        c->zw = c->zr = NULL;
    }
    if (c->enc_ctx) aes_cfb_free(c->enc_ctx);
    if (c->dec_ctx) aes_cfb_free(c->dec_ctx);
    if (c->aead)
        tconn_aead_free(c);
    secure_zero(c->ckey, sizeof(c->ckey));
    secure_zero(c->awrite_key, sizeof(c->awrite_key));
    secure_zero(c->aread_key, sizeof(c->aread_key));
    secure_zero(c->awrite_nonce, sizeof(c->awrite_nonce));
    secure_zero(c->aread_nonce, sizeof(c->aread_nonce));
    if (c->tls) {
        tls_close((tls_conn_t *)c->tls);   /* closes the fd when it owns one */
        if (c->kind == 2)
            kcp_close(c->kconn);           /* TLS over KCP: release the session */
    } else if (c->kind == 0) {
        close(c->fd);
    } else if (c->kind == 2) {
        kcp_close(c->kconn);
    } else {
        yamux_stream_close(c->st);
    }
    free(c);
}
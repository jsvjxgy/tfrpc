/*
 * SPDX-License-Identifier: GPL-3.0-only
 * tls.c - minimal TLS 1.3 client, self-contained (no external crypto/TLS
 * library).  Only what frp needs: TLS_AES_128_GCM_SHA256, X25519 key share,
 * no client certificate, certificate chain verification skipped (matching
 * frp's default when trustedCaFile is not configured), Finished verified.
 *
 * Wire flow (frp): the client writes a 0x17 byte before the TLS ClientHello
 * so an frps listening on a shared port can tell TLS from plain TCP.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>

#include "tfrpc.h"
#include "x25519.h"
#include "x509.h"
#include "ecdsa.h"
#include "tls.h"

int tls_skip_marker = 0;   /* test hook: do not send the frp 0x17 marker */
int tls_force_12 = 0;      /* test hook: advertise TLS 1.2 only */

#define TLSDBG(...) do { } while (0)

#define TLS_REC_CCS 20
#define TLS_REC_ALERT 21
#define TLS_REC_HANDSHAKE 22
#define TLS_REC_APP 23

static int fd_io_read(void *io, uint8_t *buf, size_t len) {
    return read_full((int)(intptr_t)io, buf, len);
}
static int fd_io_write(void *io, const uint8_t *buf, size_t len) {
    return write_full((int)(intptr_t)io, buf, len);
}

struct tls_conn {
    int fd;
    int owns_fd;              /* close(fd) on tls_close */
    void *io;                 /* opaque transport (fd or kcpconn) */
    int (*io_read)(void *io, uint8_t *buf, size_t len);
    int (*io_write)(void *io, const uint8_t *buf, size_t len);
    const char *server_name;
    uint8_t chs_key[16], chs_iv[12];   /* client handshake traffic */
    uint8_t shs_key[16], shs_iv[12];   /* server handshake traffic */
    uint8_t cap_key[16], cap_iv[12];   /* client application traffic */
    uint8_t sap_key[16], sap_iv[12];   /* server application traffic */
    uint64_t cseq, sseq;
    int hs_done;
    const x509_cert_t *ca;   /* non-NULL -> verify certificate chain + hostname */
    x509_cert_t leaf;        /* server (leaf) certificate */
    int has_leaf;
    /* client certificate (mTLS) */
    const uint8_t *client_cert;
    size_t client_cert_len;
    const rsa_priv_t *client_key;
    int cert_requested;

    sha256_ctx_t transcript;
    /* TLS 1.2 state */
    uint8_t client_random[32], server_random[32];
    uint8_t c12_key[16], s12_key[16];
    uint8_t c12_iv[4], s12_iv[4];
    uint8_t master_secret[48];
    int tls12;

    uint8_t *rx;
    size_t rxlen, rxpos, rxcap;

    uint8_t *hbuf;
    size_t hlen, hcap;
};

static int tls12_handshake(tls_conn_t *t, const char *server_name, uint16_t suite);

/* ------------------------- HKDF helpers (RFC 8446) ------------------------ */

static void hkdf_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len, uint8_t out[32]) {
    hmac_sha256(salt, salt_len, ikm, ikm_len, out);
}

static void hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len) {
    uint8_t t[32];
    size_t tlen = 0, done = 0;
    uint8_t ctr = 1;
    while (done < out_len) {
        uint8_t msg[32 + 512 + 1];
        size_t mlen = 0;
        if (tlen) {
            memcpy(msg, t, tlen);
            mlen += tlen;
        }
        memcpy(msg + mlen, info, info_len);
        mlen += info_len;
        msg[mlen++] = ctr;
        hmac_sha256(prk, 32, msg, mlen, t);
        tlen = 32;
        size_t n = out_len - done < 32 ? out_len - done : 32;
        memcpy(out + done, t, n);
        done += n;
        ctr++;
    }
}

static void hkdf_expand_label(const uint8_t secret[32], const char *label,
                              const uint8_t *context, size_t context_len,
                              uint8_t *out, size_t out_len) {
    uint8_t info[2 + 1 + 6 + 64 + 1 + 255];
    size_t o = 0;
    size_t llen = strlen(label);
    info[o++] = (uint8_t)(out_len >> 8);
    info[o++] = (uint8_t)(out_len & 0xff);
    info[o++] = (uint8_t)(6 + llen);
    memcpy(info + o, "tls13 ", 6);
    o += 6;
    memcpy(info + o, label, llen);
    o += llen;
    info[o++] = (uint8_t)context_len;
    if (context_len)
        memcpy(info + o, context, context_len);
    o += context_len;
    hkdf_expand(secret, info, o, out, out_len);
}

static void derive_secret(const uint8_t secret[32], const char *label,
                          const uint8_t transcript_hash[32], uint8_t out[32]) {
    hkdf_expand_label(secret, label, transcript_hash, 32, out, 32);
}

static void transcript_hash(const sha256_ctx_t *ctx, uint8_t out[32]) {
    sha256_ctx_t tmp = *ctx;
    sha256_final(&tmp, out);
}

/* ----------------------------- record layer ----------------------------- */

static void build_nonce(uint8_t nonce[12], const uint8_t iv[12], uint64_t seq) {
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] ^= (uint8_t)(seq >> (8 * (7 - i)));
}

static int tls_send_encrypted(tls_conn_t *t, uint8_t inner_type,
                              const uint8_t *data, size_t len,
                              const uint8_t key[16], const uint8_t iv[12],
                              uint64_t *seq) {
    size_t plen = len + 1;
    uint8_t *plain = malloc(plen);
    if (!plain)
        return -1;
    memcpy(plain, data, len);
    plain[len] = inner_type;

    uint8_t hdr[5];
    hdr[0] = TLS_REC_APP;
    hdr[1] = 0x03;
    hdr[2] = 0x03;
    uint16_t clen = (uint16_t)(plen + 16);
    hdr[3] = (uint8_t)(clen >> 8);
    hdr[4] = (uint8_t)(clen & 0xff);

    uint8_t nonce[12], tag[16];
    build_nonce(nonce, iv, (*seq)++);
    aes_gcm_seal(key, 16, nonce, hdr, 5, plain, plen, tag);

    int rc = 0;
    if (t->io_write(t->io, hdr, 5) < 0 ||
        t->io_write(t->io, plain, plen) < 0 ||
        t->io_write(t->io, tag, 16) < 0)
        rc = -1;
    free(plain);
    return rc;
}

/* read one record header; returns record type, payload length */
static int tls_rec_header(tls_conn_t *t, uint8_t *type, uint16_t *len) {
    uint8_t hdr[5];
    if (t->io_read(t->io, hdr, 5) < 0)
        return -1;
    *type = hdr[0];
    *len = (uint16_t)((hdr[3] << 8) | hdr[4]);
    return 0;
}

/* read + decrypt one application-data record into out.
 * returns 0 on success, 1 if a compatibility record was skipped, -1 on error */
static int tls_recv_encrypted(tls_conn_t *t, uint8_t *inner_type,
                              uint8_t *out, size_t *out_len, size_t cap,
                              const uint8_t key[16], const uint8_t iv[12],
                              uint64_t *seq) {
    uint8_t hdr[5];
    if (t->io_read(t->io, hdr, 5) < 0)
        return -1;
    uint8_t type = hdr[0];
    uint16_t clen = (uint16_t)((hdr[3] << 8) | hdr[4]);
    if (type == TLS_REC_CCS) {
        uint8_t b;
        return t->io_read(t->io, &b, 1) < 0 ? -1 : 1;
    }
    if (type != TLS_REC_APP || clen < 17 || clen > 17000)
        return -1;
    uint8_t *ct = malloc(clen);
    if (!ct)
        return -1;
    if (t->io_read(t->io, ct, clen) < 0) {
        free(ct);
        return -1;
    }
    uint8_t nonce[12];
    build_nonce(nonce, iv, (*seq)++);
    uint8_t *tag = ct + clen - 16;
    if (aes_gcm_open(key, 16, nonce, hdr, 5, ct, clen - 16, tag) != 0) {
        free(ct);
        return -1;
    }
    size_t plen = clen - 16;
    while (plen > 0 && ct[plen - 1] == 0)
        plen--;
    if (plen == 0 || plen - 1 > cap) {
        free(ct);
        return -1;
    }
    *inner_type = ct[plen - 1];
    *out_len = plen - 1;
    memcpy(out, ct, plen - 1);
    free(ct);
    return 0;
}

/* read one plaintext record (skipping CCS/alert) */
static int tls_recv_plain_record(tls_conn_t *t, uint8_t *type,
                                 uint8_t *out, size_t *out_len, size_t cap) {
    for (;;) {
        uint8_t rt;
        uint16_t len;
        if (tls_rec_header(t, &rt, &len) < 0)
            return -1;
        if (len > cap)
            return -1;
        if (t->io_read(t->io, out, len) < 0)
            return -1;
        if (rt == TLS_REC_CCS)
            continue;
        if (rt == TLS_REC_ALERT)
            return -1;
        *type = rt;
        *out_len = len;
        return 0;
    }
}

/* --------------------------- handshake helpers --------------------------- */

static void transcript_add(tls_conn_t *t, const uint8_t *msg, size_t len) {
    sha256_update(&t->transcript, msg, len);
}

/* pull one complete handshake message (decrypting records as needed) */
static int hs_next(tls_conn_t *t, uint8_t *type, uint8_t **msg, size_t *len) {
    for (;;) {
        if (t->hlen >= 4) {
            size_t mlen = ((size_t)t->hbuf[1] << 16) | ((size_t)t->hbuf[2] << 8) | t->hbuf[3];
            if (t->hlen >= 4 + mlen) {
                *type = t->hbuf[0];
                *msg = t->hbuf + 4;
                *len = mlen;
                return 0;
            }
        }
        uint8_t rec[17000];
        uint8_t it;
        size_t rlen = 0;
        int rc = tls_recv_encrypted(t, &it, rec, &rlen, sizeof(rec),
                                    t->shs_key, t->shs_iv, &t->sseq);
        if (rc < 0)
            return -1;
        if (rc == 1)
            continue;   /* skipped CCS */
        if (it != TLS_REC_HANDSHAKE) {
                return -1;
        }
        if (t->hlen + rlen > t->hcap) {
            size_t ncap = (t->hlen + rlen) * 2 + 256;
            uint8_t *nb = realloc(t->hbuf, ncap);
            if (!nb)
                return -1;
            t->hbuf = nb;
            t->hcap = ncap;
        }
        memcpy(t->hbuf + t->hlen, rec, rlen);
        t->hlen += rlen;
    }
}

static void hs_consume(tls_conn_t *t, size_t total) {
    memmove(t->hbuf, t->hbuf + total, t->hlen - total);
    t->hlen -= total;
}

/* ------------------------------- handshake ------------------------------- */

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put24(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v; }


/* ------------------------------ TLS 1.2 ---------------------------------- */

/* TLS 1.2 PRF with SHA-256 (RFC 5246 s.5) */
static void tls12_prf(const uint8_t *secret, size_t secret_len,
                      const char *label, const uint8_t *seed, size_t seed_len,
                      uint8_t *out, size_t out_len) {
    uint8_t ls[96 + 96];
    size_t llen = strlen(label);
    memcpy(ls, label, llen);
    memcpy(ls + llen, seed, seed_len);
    size_t ls_len = llen + seed_len;
    uint8_t a[32], t[32], buf[32 + 96 + 96];
    hmac_sha256(secret, secret_len, ls, ls_len, a);
    size_t done = 0;
    while (done < out_len) {
        memcpy(buf, a, 32);
        memcpy(buf + 32, ls, ls_len);
        hmac_sha256(secret, secret_len, buf, 32 + ls_len, t);
        size_t n = out_len - done < 32 ? out_len - done : 32;
        memcpy(out + done, t, n);
        done += n;
        hmac_sha256(secret, secret_len, a, 32, a);
    }
}

/* TLS 1.2 AES-128-GCM record: type|ver|len| explicit_nonce(8) | ct | tag(16) */
static int tls12_send(tls_conn_t *t, uint8_t type, const uint8_t *data, size_t len) {
    uint8_t hdr[5], nonce[12], aad[13], tag[16];
    hdr[0] = type; hdr[1] = 0x03; hdr[2] = 0x03;
    uint16_t rlen = (uint16_t)(8 + len + 16);
    hdr[3] = (uint8_t)(rlen >> 8); hdr[4] = (uint8_t)rlen;
    uint64_t seq = t->cseq++;
    memcpy(nonce, t->c12_iv, 4);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t)(seq >> (8 * (7 - i)));
    for (int i = 0; i < 8; i++)
        aad[i] = (uint8_t)(seq >> (8 * (7 - i)));
    aad[8] = type; aad[9] = 0x03; aad[10] = 0x03;
    aad[11] = (uint8_t)(len >> 8); aad[12] = (uint8_t)len;
    uint8_t *ct = malloc(len ? len : 1);
    if (!ct)
        return -1;
    memcpy(ct, data, len);
    aes_gcm_seal(t->c12_key, 16, nonce, aad, 13, ct, len, tag);
    int rc = 0;
    if (t->io_write(t->io, hdr, 5) < 0 || t->io_write(t->io, nonce + 4, 8) < 0 ||
        t->io_write(t->io, ct, len) < 0 || t->io_write(t->io, tag, 16) < 0)
        rc = -1;
    free(ct);
    return rc;
}

/* receive one TLS 1.2 record; skips CCS.  Returns 0 on success */
static int tls12_recv(tls_conn_t *t, uint8_t *type, uint8_t *out, size_t *out_len, size_t cap) {
    for (;;) {
        uint8_t hdr[5];
        if (t->io_read(t->io, hdr, 5) < 0)
            return -1;
        uint16_t rlen = (uint16_t)((hdr[3] << 8) | hdr[4]);
        if (rlen > 18432)
            return -1;
        uint8_t *rec = malloc(rlen ? rlen : 1);
        if (!rec)
            return -1;
        if (rlen && t->io_read(t->io, rec, rlen) < 0) {
            free(rec);
            return -1;
        }
        if (hdr[0] == TLS_REC_CCS) {
            free(rec);
            continue;
        }
        if (hdr[0] != TLS_REC_APP && hdr[0] != TLS_REC_HANDSHAKE) {
            free(rec);
            return -1;
        }
        if (rlen < 24) {
            free(rec);
            return -1;
        }
        uint8_t nonce[12], aad[13], tag[16];
        uint64_t seq = t->sseq++;
        memcpy(nonce, t->s12_iv, 4);
        memcpy(nonce + 4, rec, 8);
        size_t plen = rlen - 8 - 16;
        for (int i = 0; i < 8; i++)
            aad[i] = (uint8_t)(seq >> (8 * (7 - i)));
        aad[8] = hdr[0]; aad[9] = 0x03; aad[10] = 0x03;
        aad[11] = (uint8_t)(plen >> 8); aad[12] = (uint8_t)plen;
        memcpy(tag, rec + 8 + plen, 16);
        if (aes_gcm_open(t->s12_key, 16, nonce, aad, 13, rec + 8, plen, tag) != 0) {
            free(rec);
            return -1;
        }
        if (plen > cap) {
            free(rec);
            return -1;
        }
        memcpy(out, rec + 8, plen);
        *out_len = plen;
        *type = hdr[0];
        free(rec);
        return 0;
    }
}

/* read a plaintext TLS 1.2 handshake record into out */
static int tls12_recv_plain(tls_conn_t *t, uint8_t *out, size_t *out_len, size_t cap) {
    for (;;) {
        uint8_t hdr[5];
        if (t->io_read(t->io, hdr, 5) < 0) {
            return -1;
        }
        uint16_t rlen = (uint16_t)((hdr[3] << 8) | hdr[4]);
        if (rlen > cap) {
            return -1;
        }
        if (t->io_read(t->io, out, rlen) < 0) {
            return -1;
        }
        if (hdr[0] == TLS_REC_CCS)
            continue;
        if (hdr[0] != TLS_REC_HANDSHAKE) {
            return -1;
        }
        *out_len = rlen;
        return 0;
    }
}

static int tls12_handshake(tls_conn_t *t, const char *server_name, uint16_t suite) {
    (void)suite;   /* signature scheme is taken from ServerKeyExchange */
    uint8_t rec[18432];
    size_t rlen = 0;
    uint8_t server_pub[32];
    int got_pub = 0;
    uint16_t sig_scheme = 0;
    const uint8_t *sig = NULL;
    size_t sig_len = 0;

    /* Certificate */
    if (tls12_recv_plain(t, rec, &rlen, sizeof(rec)) < 0 || rlen < 4 || rec[0] != 11) {
        return -1;
    }
    {
        size_t mlen = ((size_t)rec[1] << 16) | ((size_t)rec[2] << 8) | rec[3];
        const uint8_t *body = rec + 4;
        if (mlen < 3 || 4 + mlen > rlen)
            return -1;   /* message must be complete within the record */
        /* TLS 1.2 Certificate: just certificate_list (no context, no extensions) */
        size_t list = ((size_t)body[0] << 16) | ((size_t)body[1] << 8) | body[2];
        if (3 + list > mlen)
            return -1;
        x509_cert_t chain[8];
        int nchain = 0;
        size_t q = 3, remaining = list;
        while (remaining >= 3 && nchain < 8) {
            size_t elen = ((size_t)body[q] << 16) | ((size_t)body[q + 1] << 8) | body[q + 2];
            if (3 + elen > remaining)
                return -1;
            if (x509_parse(body + q + 3, elen, &chain[nchain]) < 0)
                return -1;
            nchain++;
            q += 3 + elen;
            remaining -= 3 + elen;
        }
        if (nchain == 0)
            return -1;
        t->leaf = chain[0];
        t->has_leaf = 1;
        if (t->ca) {
            int ok;
            if (nchain == 1) {
                ok = x509_verify_signed_by(&chain[0], t->ca) == 0;
            } else {
                ok = 1;
                for (int i = 0; i < nchain - 1; i++)
                    if (x509_verify_signed_by(&chain[i], &chain[i + 1]) != 0) { ok = 0; break; }
                if (ok && x509_verify_signed_by(&chain[nchain - 1], t->ca) != 0)
                    ok = 0;
            }
            if (!ok)
                return -1;
            const char *host = server_name ? server_name : "";
            if (host[0] && x509_check_hostname(&chain[0], host) < 0)
                return -1;
        }
        transcript_add(t, rec, 4 + mlen);
    }

    /* ServerKeyExchange */
    if (tls12_recv_plain(t, rec, &rlen, sizeof(rec)) < 0 || rlen < 4 || rec[0] != 12) {
        return -1;
    }
    {
        size_t mlen = ((size_t)rec[1] << 16) | ((size_t)rec[2] << 8) | rec[3];
        const uint8_t *b = rec + 4;
        if (mlen < 5 || 4 + mlen > rlen)
            return -1;
        /* curve_type(1)=3, named_curve(2), pubkey_len(1), pubkey(32) */
        if (b[0] != 3 || mlen < 4 + 32)
            return -1;
        uint16_t curve = (uint16_t)((b[1] << 8) | b[2]);
        uint8_t klen = b[3];
        if (klen != 32 || curve != 0x001d)
            return -1;
        memcpy(server_pub, b + 4, 32);
        got_pub = 1;
        /* signature */
        size_t off = 4 + 32;
        if (off + 4 > mlen)
            return -1;
        sig_scheme = (uint16_t)((b[off] << 8) | b[off + 1]);
        sig_len = (uint16_t)((b[off + 2] << 8) | b[off + 3]);
        if (off + 4 + sig_len > mlen)
            return -1;
        sig = b + off + 4;
        /* verify signature over client_random + server_random + params */
        {
            uint8_t signed_data[32 + 32 + 4 + 32];
            memcpy(signed_data, t->client_random, 32);
            memcpy(signed_data + 32, t->server_random, 32);
            memcpy(signed_data + 64, b, 4 + 32);
            uint8_t digest[32];
            sha256_digest(signed_data, sizeof(signed_data), digest);
            int vok;
            if (sig_scheme == 0x0403) {          /* ecdsa_secp256r1_sha256 */
                vok = t->leaf.key_type == X509_KEY_ECDSA &&
                      ecdsa_p256_verify(t->leaf.ec_pub, sizeof(t->leaf.ec_pub),
                                        digest, 32, sig, sig_len) == 0;
            } else if (sig_scheme == 0x0804 || sig_scheme == 0x0805 ||
                       sig_scheme == 0x0806) {   /* rsa_pss_rsae_* */
                vok = t->leaf.key_type == X509_KEY_RSA &&
                      rsa_pss_verify(&t->leaf.pub, digest, 32, sig, sig_len) == 0;
            } else {                             /* rsa_pkcs1_* */
                vok = t->leaf.key_type == X509_KEY_RSA &&
                      rsa_pkcs1_verify(&t->leaf.pub, digest, 32, sig, sig_len) == 0;
            }
            if (!vok)
                return -1;
        }
        transcript_add(t, rec, 4 + mlen);
    }
    if (!got_pub)
        return -1;
    /* ServerHelloDone */
    if (tls12_recv_plain(t, rec, &rlen, sizeof(rec)) < 0 || rlen < 4 || rec[0] != 14) {
        return -1;
    }
    {
        size_t mlen = ((size_t)rec[1] << 16) | ((size_t)rec[2] << 8) | rec[3];
        if (mlen != 0 || rlen < 4)
            return -1;
    }
    transcript_add(t, rec, 4);

    /* ClientKeyExchange: ECDHE public key */
    uint8_t priv[32], pub[32];
    if (random_bytes(priv, 32) < 0)
        return -1;
    x25519_base(pub, priv);
    {
        uint8_t cke[4 + 1 + 32];
        cke[0] = 16;
        put24(cke + 1, 33);
        cke[4] = 32;
        memcpy(cke + 5, pub, 32);
        {
            static const uint8_t cke_hdr[3] = {0x16, 0x03, 0x03};
            if (t->io_write(t->io, cke_hdr, 3) < 0)
                return -1;
        }
        uint8_t rl[2] = {0, 37};
        if (t->io_write(t->io, rl, 2) < 0 || t->io_write(t->io, cke, 37) < 0)
            return -1;
        transcript_add(t, cke, 37);
    }

    /* key schedule */
    uint8_t pre_master[32];
    x25519(pre_master, priv, server_pub);
    secure_zero(priv, sizeof(priv));
    {
        uint8_t acc = 0;
        for (int i = 0; i < 32; i++)
            acc |= pre_master[i];
        if (acc == 0)
            return -1;   /* low-order point */
    }
    uint8_t seed[64];
    memcpy(seed, t->client_random, 32);
    memcpy(seed + 32, t->server_random, 32);
    tls12_prf(pre_master, 32, "master secret", seed, 64, t->master_secret, 48);
    secure_zero(pre_master, sizeof(pre_master));
    memcpy(seed, t->server_random, 32);
    memcpy(seed + 32, t->client_random, 32);
    uint8_t kb[40];
    tls12_prf(t->master_secret, 48, "key expansion", seed, 64, kb, 40);
    memcpy(t->c12_key, kb, 16);
    memcpy(t->s12_key, kb + 16, 16);
    memcpy(t->c12_iv, kb + 32, 4);
    memcpy(t->s12_iv, kb + 36, 4);
    secure_zero(kb, sizeof(kb));
    secure_zero(seed, sizeof(seed));
    t->cseq = t->sseq = 0;

    /* ChangeCipherSpec + Finished */
    {
        uint8_t ccs[6] = {TLS_REC_CCS, 0x03, 0x03, 0x00, 0x01, 0x01};
        if (t->io_write(t->io, ccs, 6) < 0)
            return -1;
        uint8_t th[32], vd[12], fin[16];
        transcript_hash(&t->transcript, th);
        tls12_prf(t->master_secret, 48, "client finished", th, 32, vd, 12);
        fin[0] = 20; fin[1] = 0; fin[2] = 0; fin[3] = 12;
        memcpy(fin + 4, vd, 12);
        if (tls12_send(t, TLS_REC_HANDSHAKE, fin, 16) < 0)
            return -1;
        transcript_add(t, fin, 16);
    }

    /* server ChangeCipherSpec + Finished */
    {
        uint8_t hdr[5];
        if (t->io_read(t->io, hdr, 5) < 0)
            return -1;
        if (hdr[0] != TLS_REC_CCS)
            return -1;
        uint8_t b;
        if (t->io_read(t->io, &b, 1) < 0)
            return -1;
        uint8_t type, fin[64];
        size_t flen = 0;
        if (tls12_recv(t, &type, fin, &flen, sizeof(fin)) < 0)
            return -1;
        if (type != TLS_REC_HANDSHAKE || flen < 16 || fin[0] != 20)
            return -1;
        uint8_t th[32], vd[12];
        transcript_hash(&t->transcript, th);
        tls12_prf(t->master_secret, 48, "server finished", th, 32, vd, 12);
        if (crypto_memcmp_ct(vd, fin + 4, 12) != 0) {
            return -1;
        }
        transcript_add(t, fin, 16);
    }
    t->tls12 = 1;
    t->hs_done = 1;
    return 0;
}

static int tls_do_handshake(tls_conn_t *t, const char *server_name) {
    t->server_name = server_name;
    uint8_t priv[32], pub[32];
    if (random_bytes(priv, 32) < 0)
        return -1;
    x25519_base(pub, priv);

    /* ---- ClientHello ---- */
    uint8_t ch[512];
    size_t o = 0;
    ch[o++] = 0x03; ch[o++] = 0x03;
    uint8_t rnd[32], sid[32];
    if (random_bytes(rnd, 32) < 0 || random_bytes(sid, 32) < 0)
        return -1;
    memcpy(ch + o, rnd, 32); o += 32;
    memcpy(t->client_random, rnd, 32);
    ch[o++] = 32;
    memcpy(ch + o, sid, 32); o += 32;
    if (tls_force_12) {
        put16(ch + o, 4); o += 2;
        put16(ch + o, 0xc02f); o += 2;
        put16(ch + o, 0xc02b); o += 2;
    } else {
        put16(ch + o, 6); o += 2;
        put16(ch + o, 0x1301); o += 2;               /* TLS_AES_128_GCM_SHA256 (1.3) */
        put16(ch + o, 0xc02f); o += 2;               /* ECDHE_RSA_AES128_GCM_SHA256 (1.2) */
        put16(ch + o, 0xc02b); o += 2;               /* ECDHE_ECDSA_AES128_GCM_SHA256 (1.2) */
    }
    ch[o++] = 1; ch[o++] = 0;
    size_t ext_len_off = o;
    put16(ch + o, 0); o += 2;
    size_t ext_start = o;

    if (tls_force_12) {
        put16(ch + o, 43); put16(ch + o + 2, 3); o += 4;
        ch[o++] = 2; put16(ch + o, 0x0303); o += 2;    /* TLS 1.2 only */
    } else {
        put16(ch + o, 43); put16(ch + o + 2, 5); o += 4;
        ch[o++] = 4; put16(ch + o, 0x0304); o += 2;    /* TLS 1.3 preferred */
        put16(ch + o, 0x0303); o += 2;                 /* TLS 1.2 fallback */
    }
    put16(ch + o, 13); put16(ch + o + 2, 22); o += 4;  /* signature_algorithms */
    put16(ch + o, 20); o += 2;                         /* supported list length */
    {
        static const uint16_t sigs[] = {0x0804, 0x0805, 0x0806, 0x0403, 0x0503,
                                        0x0603, 0x0401, 0x0501, 0x0601, 0x0201};
        for (unsigned i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
            put16(ch + o, sigs[i]); o += 2;
        }
    }
    put16(ch + o, 10); put16(ch + o + 2, 4); o += 4;   /* supported_groups */
    put16(ch + o, 2); o += 2;                          /* list length */
    put16(ch + o, 0x001d); o += 2;                     /* x25519 */
    if (!tls_force_12) {                               /* key_share is TLS 1.3 only */
        put16(ch + o, 51); put16(ch + o + 2, 38); o += 4;
        put16(ch + o, 36); o += 2;
        put16(ch + o, 0x001d); o += 2;
        put16(ch + o, 32); o += 2;
        memcpy(ch + o, pub, 32); o += 32;
    }
    if (server_name && server_name[0]) {               /* SNI */
        size_t nlen = strlen(server_name);
        if (nlen > 255 || o + 9 + nlen > sizeof(ch))
            return -1;   /* RFC 6066 host_name limit / buffer bound */
        put16(ch + o, 0); put16(ch + o + 2, (uint16_t)(5 + nlen)); o += 4;
        put16(ch + o, (uint16_t)(3 + nlen)); o += 2;
        ch[o++] = 0;
        put16(ch + o, (uint16_t)nlen); o += 2;
        memcpy(ch + o, server_name, nlen); o += nlen;
    }
    put16(ch + ext_len_off, (uint16_t)(o - ext_start));

    uint8_t hdr[4], rec[5];
    hdr[0] = 1; put24(hdr + 1, (uint32_t)o);
    rec[0] = TLS_REC_HANDSHAKE; rec[1] = 0x03; rec[2] = 0x01;
    put16(rec + 3, (uint16_t)(4 + o));

    uint8_t marker = 0x17;   /* frp TLS marker */
    if ((!tls_skip_marker && t->io_write(t->io, &marker, 1) < 0) ||
        t->io_write(t->io, rec, 5) < 0 || t->io_write(t->io, hdr, 4) < 0 ||
        t->io_write(t->io, ch, o) < 0)
        return -1;
    transcript_add(t, hdr, 4);
    transcript_add(t, ch, o);

    /* ---- ServerHello ---- */
    uint8_t srv[8192];
    uint8_t rtype;
    size_t slen = 0;
    if (tls_recv_plain_record(t, &rtype, srv, &slen, sizeof(srv)) < 0) {
        return -1;
    }
    if (rtype != TLS_REC_HANDSHAKE || slen < 4 + 38 || srv[0] != 2) {
        return -1;
    }
    size_t sh_len = ((size_t)srv[1] << 16) | ((size_t)srv[2] << 8) | srv[3];
    if (sh_len + 4 > slen)
        return -1;
    uint8_t *sh = srv + 4;
    size_t p = 0;
    p += 2;
    memcpy(t->server_random, sh + p, 32);
    p += 32;
    if (p >= sh_len) return -1;
    uint8_t sid_len = sh[p++];
    if (p + sid_len + 3 > sh_len) return -1;
    p += sid_len;
    uint16_t suite = (uint16_t)((sh[p] << 8) | sh[p + 1]); p += 2;
    if (suite != 0x1301 && suite != 0xc02f && suite != 0xc02b)
        return -1;
    p += 1;   /* legacy_compression_method */
    uint8_t server_pub[32];
    int got_pub = 0;
    int is13 = 0;
    size_t sext_end = sh_len;
    if (p + 2 <= sh_len) {
        uint16_t sext_len = (uint16_t)((sh[p] << 8) | sh[p + 1]);
        p += 2;
        sext_end = p + sext_len;
        if (sext_end > sh_len)
            return -1;
    }
    while (p + 4 <= sext_end) {
        uint16_t et = (uint16_t)((sh[p] << 8) | sh[p + 1]);
        uint16_t el = (uint16_t)((sh[p + 2] << 8) | sh[p + 3]);
        p += 4;
        if (p + el > sext_end) return -1;
        if (et == 43 && el >= 2) {          /* supported_versions */
            if (((sh[p] << 8) | sh[p + 1]) == 0x0304)
                is13 = 1;
        }
        if (et == 51 && el >= 36) {
            uint16_t group = (uint16_t)((sh[p] << 8) | sh[p + 1]);
            uint16_t klen = (uint16_t)((sh[p + 2] << 8) | sh[p + 3]);
            if (group == 0x001d && klen == 32) {
                memcpy(server_pub, sh + p + 4, 32);
                got_pub = 1;
            }
        }
        p += el;
    }
    transcript_add(t, srv, 4 + sh_len);
    if (!is13) {
        /* server negotiated TLS 1.2 */
        if (suite != 0xc02f && suite != 0xc02b)
            return -1;
        return tls12_handshake(t, server_name, suite);
    }
    if (!got_pub) { TLSDBG("no key share"); return -1; }

    /* ---- key schedule ---- */
    uint8_t shared[32];
    x25519(shared, priv, server_pub);
    secure_zero(priv, sizeof(priv));
    {
        /* RFC 7748: reject the all-zero shared secret produced by
           low-order points (defense in depth) */
        uint8_t acc = 0;
        for (int i = 0; i < 32; i++)
            acc |= shared[i];
        if (acc == 0)
            return -1;
    }

    uint8_t zero[32] = {0};
    uint8_t empty_hash[32];
    sha256_digest(NULL, 0, empty_hash);
    uint8_t early[32], derived[32], hs_secret[32], th[32];
    hkdf_extract(NULL, 0, zero, 32, early);
    derive_secret(early, "derived", empty_hash, derived);
    hkdf_extract(derived, 32, shared, 32, hs_secret);
    secure_zero(shared, sizeof(shared));
    secure_zero(early, sizeof(early));
    secure_zero(derived, sizeof(derived));

    uint8_t chs[32], shs[32];
    transcript_hash(&t->transcript, th);
    derive_secret(hs_secret, "c hs traffic", th, chs);
    derive_secret(hs_secret, "s hs traffic", th, shs);
    hkdf_expand_label(chs, "key", NULL, 0, t->chs_key, 16);
    hkdf_expand_label(chs, "iv", NULL, 0, t->chs_iv, 12);
    hkdf_expand_label(shs, "key", NULL, 0, t->shs_key, 16);
    hkdf_expand_label(shs, "iv", NULL, 0, t->shs_iv, 12);
    t->cseq = t->sseq = 0;

    /* ---- encrypted server handshake ---- */
    uint8_t mt, *msg;
    size_t mlen;

    if (hs_next(t, &mt, &msg, &mlen) < 0 || mt != 8) {     /* EncryptedExtensions */
        return -1;
    }
    transcript_add(t, t->hbuf, 4 + mlen);
    hs_consume(t, 4 + mlen);

    /* optional CertificateRequest (mTLS) */
    if (hs_next(t, &mt, &msg, &mlen) < 0)
        return -1;
    if (mt == 13) {
        t->cert_requested = 1;
        transcript_add(t, t->hbuf, 4 + mlen);
        hs_consume(t, 4 + mlen);
        if (hs_next(t, &mt, &msg, &mlen) < 0)
            return -1;
    }

    if (hs_next(t, &mt, &msg, &mlen) < 0 || mt != 11) {    /* Certificate */
        return -1;
    }
    {
        /* Certificate: context_len(1) | list_len(3) | entry_len(3) | DER | ... */
        if (mlen < 4)
            return -1;
        size_t ctx = msg[0];
        size_t cp = 1 + ctx;
        if (cp + 3 > mlen)
            return -1;
        size_t list = ((size_t)msg[cp] << 16) | ((size_t)msg[cp + 1] << 8) | msg[cp + 2];
        cp += 3;
        if (cp + list > mlen || list < 3)
            return -1;
        x509_cert_t chain[8];
        int nchain = 0;
        {
            size_t q = cp;  /* start of certificate_list entries */
            size_t remaining = list;
            while (remaining >= 3 && nchain < 8) {
                size_t elen = ((size_t)msg[q] << 16) | ((size_t)msg[q + 1] << 8) | msg[q + 2];
                if (3 + elen + 2 > remaining)
                    return -1;
                if (x509_parse(msg + q + 3, elen, &chain[nchain]) < 0) {
                    return -1;
                }
                nchain++;
                /* CertificateEntry = cert_data(3+len) | extensions(2+ext_len) */
                size_t ext = ((size_t)msg[q + 3 + elen] << 8) | msg[q + 3 + elen + 1];
                if (3 + elen + 2 + ext > remaining)
                    return -1;
                q += 3 + elen + 2 + ext;
                remaining -= 3 + elen + 2 + ext;
            }
        }
        if (nchain == 0)
            return -1;
        t->leaf = chain[0];
        t->has_leaf = 1;
        if (t->ca) {
            int ok = 0;
            if (nchain == 1) {
                ok = x509_verify_signed_by(&chain[0], t->ca) == 0;
            } else {
                ok = 1;
                for (int i = 0; i < nchain - 1; i++) {
                    if (x509_verify_signed_by(&chain[i], &chain[i + 1]) != 0) {
                        ok = 0;
                        break;
                    }
                }
                if (ok && x509_verify_signed_by(&chain[nchain - 1], t->ca) != 0)
                    ok = 0;
            }
            if (!ok) {
                return -1;
            }
            const char *host = t->server_name ? t->server_name : "";
            if (host[0] && x509_check_hostname(&chain[0], host) < 0) {
                return -1;
            }
        }
        transcript_add(t, t->hbuf, 4 + mlen);
        hs_consume(t, 4 + mlen);
    }

    if (hs_next(t, &mt, &msg, &mlen) < 0 || mt != 15) {    /* CertificateVerify */
        return -1;
    }
    if (t->ca) {
        /* content = 64*0x20 || "TLS 1.3, server CertificateVerify" || 0x00 || hash */
        static const char label[] = "TLS 1.3, server CertificateVerify";
        uint8_t content[64 + sizeof(label) - 1 + 1 + 32];
        memset(content, 0x20, 64);
        memcpy(content + 64, label, sizeof(label) - 1);
        content[64 + sizeof(label) - 1] = 0x00;
        uint8_t th_cert[32];
        transcript_hash(&t->transcript, th_cert);
        memcpy(content + 64 + sizeof(label) - 1 + 1, th_cert, 32);
        uint8_t digest[32];
        sha256_digest(content, sizeof(content), digest);
        /* CertificateVerify: scheme(2) | sig_len(2) | sig */
        if (mlen < 4)
            return -1;
        uint16_t scheme = (uint16_t)((msg[0] << 8) | msg[1]);
        uint16_t cv_slen = (uint16_t)((msg[2] << 8) | msg[3]);
        if (mlen < (size_t)(4 + cv_slen))
            return -1;
        if (!t->has_leaf) {
            return -1;
        }
        if (scheme == 0x0804) {          /* rsa_pss_rsae_sha256 */
            if (t->leaf.key_type != X509_KEY_RSA ||
                rsa_pss_verify(&t->leaf.pub, digest, 32, msg + 4, cv_slen) != 0) {
                return -1;
            }
        } else if (scheme == 0x0403) {   /* ecdsa_secp256r1_sha256 */
            if (t->leaf.key_type != X509_KEY_ECDSA ||
                ecdsa_p256_verify(t->leaf.ec_pub, sizeof(t->leaf.ec_pub),
                                  digest, 32, msg + 4, cv_slen) != 0) {
                return -1;
            }
        } else {
            return -1;
        }
    }
    transcript_add(t, t->hbuf, 4 + mlen);
    hs_consume(t, 4 + mlen);

    if (hs_next(t, &mt, &msg, &mlen) < 0 || mt != 20 || mlen != 32)   /* Finished */
        return -1;
    {
        uint8_t fk[32], expect[32], th_cv[32];
        transcript_hash(&t->transcript, th_cv);   /* CH..CertificateVerify */
        hkdf_expand_label(shs, "finished", NULL, 0, fk, 32);
        hmac_sha256(fk, 32, th_cv, 32, expect);
        if (crypto_memcmp_ct(expect, msg, 32) != 0) {
            return -1;
        }
        transcript_add(t, t->hbuf, 4 + mlen);
        hs_consume(t, 4 + mlen);
    }

    /* transcript now = CH..server Finished */
    uint8_t th_app[32];
    transcript_hash(&t->transcript, th_app);

    /* ---- client Certificate + CertificateVerify (mTLS) ---- */
    if (t->cert_requested && !(t->client_cert && t->client_key)) {
        /* no client cert: must still send an empty Certificate message */
        uint8_t empty[8];
        empty[0] = 11;                  /* Certificate */
        put24(empty + 1, 4);            /* body length */
        empty[4] = 0;                   /* certificate_request_context: empty */
        put24(empty + 5, 0);            /* certificate_list: empty */
        if (tls_send_encrypted(t, TLS_REC_HANDSHAKE, empty, 8,
                               t->chs_key, t->chs_iv, &t->cseq) < 0)
            return -1;
        transcript_add(t, empty, 8);
    }
    if (t->cert_requested && t->client_cert && t->client_key) {
        size_t clen = t->client_cert_len;
        size_t total = 1 + 3 + 3 + clen + 2;
        uint8_t *cmsg = malloc(4 + total);
        if (!cmsg)
            return -1;
        uint8_t *w = cmsg;
        w[0] = 11;                       /* Certificate */
        put24(w + 1, (uint32_t)total);
        w += 4;
        w[0] = 0;                        /* certificate_request_context: empty */
        put24(w + 1, (uint32_t)(3 + clen + 2));
        put24(w + 4, (uint32_t)clen);
        memcpy(w + 7, t->client_cert, clen);
        w[7 + clen] = 0; w[8 + clen] = 0;   /* extensions: empty */
        if (tls_send_encrypted(t, TLS_REC_HANDSHAKE, cmsg, 4 + total,
                               t->chs_key, t->chs_iv, &t->cseq) < 0) {
            free(cmsg);
            return -1;
        }
        transcript_add(t, cmsg, 4 + total);
        free(cmsg);

        /* CertificateVerify: sign with the client key */
        static const char clabel[] = "TLS 1.3, client CertificateVerify";
        uint8_t content[64 + sizeof(clabel) - 1 + 1 + 32];
        memset(content, 0x20, 64);
        memcpy(content + 64, clabel, sizeof(clabel) - 1);
        content[64 + sizeof(clabel) - 1] = 0x00;
        uint8_t th_cv[32];
        transcript_hash(&t->transcript, th_cv);
        memcpy(content + 64 + sizeof(clabel) - 1 + 1, th_cv, 32);
        uint8_t digest[32];
        sha256_digest(content, sizeof(content), digest);
        uint8_t sig[512];
        size_t sig_len = 0;
        if (rsa_pss_sign(t->client_key, digest, 32, sig, &sig_len) != 0)
            return -1;
        uint8_t *cv = malloc(4 + 2 + 2 + sig_len);
        if (!cv)
            return -1;
        cv[0] = 15;                      /* CertificateVerify */
        put24(cv + 1, (uint32_t)(2 + 2 + sig_len));
        put16(cv + 4, 0x0804);           /* rsa_pss_rsae_sha256 */
        put16(cv + 6, (uint16_t)sig_len);
        memcpy(cv + 8, sig, sig_len);
        if (tls_send_encrypted(t, TLS_REC_HANDSHAKE, cv, 4 + 4 + sig_len,
                               t->chs_key, t->chs_iv, &t->cseq) < 0) {
            free(cv);
            return -1;
        }
        transcript_add(t, cv, 4 + 4 + sig_len);
        free(cv);
    }

    /* ---- client Finished ---- */
    {
        uint8_t fk[32], verify[32], fin[36], th_fin[32];
        /* transcript includes client Certificate/CertificateVerify (mTLS) */
        transcript_hash(&t->transcript, th_fin);
        hkdf_expand_label(chs, "finished", NULL, 0, fk, 32);
        hmac_sha256(fk, 32, th_fin, 32, verify);
        fin[0] = 20; put24(fin + 1, 32);
        memcpy(fin + 4, verify, 32);
        if (tls_send_encrypted(t, TLS_REC_HANDSHAKE, fin, 36,
                               t->chs_key, t->chs_iv, &t->cseq) < 0)
            return -1;
        transcript_add(t, fin, 36);
    }

    /* ---- application traffic keys ---- */
    {
        uint8_t derived2[32], master[32], cap[32], sap[32];
        derive_secret(hs_secret, "derived", empty_hash, derived2);
        hkdf_extract(derived2, 32, zero, 32, master);
        derive_secret(master, "c ap traffic", th_app, cap);
        derive_secret(master, "s ap traffic", th_app, sap);
        hkdf_expand_label(cap, "key", NULL, 0, t->cap_key, 16);
        hkdf_expand_label(cap, "iv", NULL, 0, t->cap_iv, 12);
        hkdf_expand_label(sap, "key", NULL, 0, t->sap_key, 16);
        hkdf_expand_label(sap, "iv", NULL, 0, t->sap_iv, 12);
    }
    t->cseq = t->sseq = 0;
    t->hs_done = 1;
    secure_zero(priv, sizeof(priv));
    secure_zero(hs_secret, sizeof(hs_secret));
    secure_zero(chs, sizeof(chs));
    secure_zero(shs, sizeof(shs));
    return 0;
}

/* -------------------------------- public -------------------------------- */

static tls_conn_t *tls_connect_common(int fd, int owns_fd, void *io,
                                      tls_io_read_fn rd, tls_io_write_fn wr,
                                      const char *server_name, const x509_cert_t *ca,
                                      const uint8_t *client_cert, size_t client_cert_len,
                                      const rsa_priv_t *client_key) {
    tls_conn_t *t = calloc(1, sizeof(*t));
    if (!t)
        return NULL;
    t->fd = fd;
    t->owns_fd = owns_fd;
    t->io = io;
    t->io_read = rd;
    t->io_write = wr;
    t->ca = ca;
    t->client_cert = client_cert;
    t->client_cert_len = client_cert_len;
    t->client_key = client_key;
    t->rxcap = 17000;
    t->rx = malloc(t->rxcap);
    if (!t->rx) {
        free(t);
        return NULL;
    }
    sha256_init(&t->transcript);
    if (tls_do_handshake(t, server_name) < 0) {
        free(t->rx);
        free(t->hbuf);
        free(t);
        return NULL;
    }
    return t;
}

tls_conn_t *tls_connect(int fd, const char *server_name, const x509_cert_t *ca,
                        const uint8_t *client_cert, size_t client_cert_len,
                        const rsa_priv_t *client_key) {
    return tls_connect_common(fd, 1, (void *)(intptr_t)fd, fd_io_read, fd_io_write,
                              server_name, ca, client_cert, client_cert_len, client_key);
}

tls_conn_t *tls_connect_io(void *io, tls_io_read_fn rd, tls_io_write_fn wr,
                           const char *server_name, const x509_cert_t *ca,
                           const uint8_t *client_cert, size_t client_cert_len,
                           const rsa_priv_t *client_key) {
    return tls_connect_common(-1, 0, io, rd, wr,
                              server_name, ca, client_cert, client_cert_len, client_key);
}

void tls_shutdown(tls_conn_t *t) {
    if (t && t->fd >= 0)
        shutdown(t->fd, SHUT_RDWR);
}

void tls_close(tls_conn_t *t) {
    if (!t)
        return;
    if (t->fd >= 0)
        close(t->fd);
    t->fd = -1;
    free(t->rx);
    free(t->hbuf);
    secure_zero(t, sizeof(*t));   /* traffic keys, secrets, transcript */
    free(t);
}

int tls_read(tls_conn_t *t, void *buf, size_t len) {
    if (t->tls12) {
        for (;;) {
            if (t->rxpos < t->rxlen) {
                size_t n = t->rxlen - t->rxpos;
                if (n > len)
                    n = len;
                memcpy(buf, t->rx + t->rxpos, n);
                t->rxpos += n;
                if (t->rxpos >= t->rxlen)
                    t->rxpos = t->rxlen = 0;
                return (int)n;
            }
            uint8_t type;
            size_t rlen = 0;
            if (tls12_recv(t, &type, t->rx, &rlen, t->rxcap) < 0)
                return -1;
            if (type != TLS_REC_APP)
                return -1;
            t->rxlen = rlen;
            t->rxpos = 0;
        }
    }
    for (;;) {
        if (t->rxpos < t->rxlen) {
            size_t n = t->rxlen - t->rxpos;
            if (n > len)
                n = len;
            memcpy(buf, t->rx + t->rxpos, n);
            t->rxpos += n;
            if (t->rxpos >= t->rxlen)
                t->rxpos = t->rxlen = 0;
            return (int)n;
        }
        uint8_t it;
        size_t rlen = 0;
        int rc = tls_recv_encrypted(t, &it, t->rx, &rlen, t->rxcap,
                                    t->sap_key, t->sap_iv, &t->sseq);
        if (rc < 0)
            return -1;
        if (rc == 1)
            continue;
        if (it == TLS_REC_APP) {
            t->rxlen = rlen;
            t->rxpos = 0;
            continue;
        }
        if (it == TLS_REC_ALERT)
            return -1;
        if (it == TLS_REC_HANDSHAKE)
            continue;   /* post-handshake messages (e.g. NewSessionTicket) */
        return -1;
    }
}

int tls_write(tls_conn_t *t, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len > 0) {
        size_t n = len > 16384 ? 16384 : len;
        if (t->tls12) {
            if (tls12_send(t, TLS_REC_APP, p, n) < 0)
                return -1;
            p += n;
            len -= n;
            continue;
        }
        if (tls_send_encrypted(t, TLS_REC_APP, p, n,
                               t->cap_key, t->cap_iv, &t->cseq) < 0)
            return -1;
        p += n;
        len -= n;
    }
    return 0;
}

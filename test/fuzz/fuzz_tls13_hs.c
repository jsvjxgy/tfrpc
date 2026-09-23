/*
 * SPDX-License-Identifier: GPL-3.0-only
 * fuzz_tls13_hs.c - libFuzzer harness for the encrypted half of a TLS 1.3
 * handshake.
 *
 * The harness plays a full server.  When the client asks for the
 * ServerHello, we parse its already-sent ClientHello from the reverse pipe,
 * compute the shared secret with our ephemeral X25519 key, derive the same
 * server handshake traffic keys the client will, and then encrypt the
 * fuzzer-controlled Certificate / CertificateVerify / Finished payloads so
 * the client's encrypted-handshake parsers run on attacker-controlled data.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined -Iinclude -o tls13hs_fuzzer \
 *       test/fuzz_tls13_hs.c src/crypto.c src/log.c src/net.c src/x25519.c \
 *       src/x509.c src/ecdsa.c src/bignum.c src/base64.c -pthread
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "tfrpc.h"
#include "x25519.h"

#include "../src/tls.c"

typedef struct {
    uint8_t buf[1 << 16];
    size_t len;
    size_t pos;
} pipe_t;

typedef struct {
    pipe_t *srv_to_cli;   /* what the client reads */
    pipe_t *cli_to_srv;   /* what the client wrote  */
    const uint8_t *fuzz;
    size_t fuzz_len;
    uint8_t spriv[32];
    int prepared;
    uint8_t shs_key[16], shs_iv[12];
    uint8_t transcript[32];
    uint64_t sseq;
} ctx_t;

static void put24h(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v;
}

/* find the key_share client public key in a ClientHello record stream */
static const uint8_t *find_client_pub(const uint8_t *p, size_t n) {
    if (n < 5 || p[0] != 0x16)
        return NULL;
    size_t hs = 5 + 4;              /* record hdr + handshake hdr */
    if (n < hs)
        return NULL;
    size_t body = ((size_t)p[6] << 16) | ((size_t)p[7] << 8) | p[8];
    size_t end = hs + body;
    if (end > n)
        end = n;
    size_t q = hs + 2 + 32;         /* version + random */
    if (q >= end) return NULL;
    q += 1 + p[q];                  /* session id */
    if (q + 2 > end) return NULL;
    q += 2 + p[q];                  /* cipher suites */
    if (q + 1 > end) return NULL;
    q += 1 + p[q];                  /* compression */
    if (q + 2 > end) return NULL;
    size_t ext_len = ((size_t)p[q] << 8) | p[q + 1];
    q += 2;
    size_t ext_end = q + ext_len;
    if (ext_end > end) ext_end = end;
    while (q + 4 <= ext_end) {
        uint16_t et = (uint16_t)((p[q] << 8) | p[q + 1]);
        uint16_t el = (uint16_t)((p[q + 2] << 8) | p[q + 3]);
        q += 4;
        if (q + el > ext_end) break;
        if (et == 0x0033 && el >= 38) {          /* key_share */
            /* client_shares: list_len(2) entry: group(2) klen(2) key(32) */
            if (el >= 2 + 2 + 2 + 32 &&
                p[q + 2] == 0x00 && p[q + 3] == 0x1d &&
                p[q + 4] == 0x00 && p[q + 5] == 0x20)
                return p + q + 6;
        }
        q += el;
    }
    return NULL;
}

static void emit_record(ctx_t *c, uint8_t inner_type, const uint8_t *pt, size_t plen);

static uint8_t g_sh_bytes[512];
static size_t g_sh_len;

static int pipe_read(void *io, uint8_t *out, size_t len) {
    ctx_t *c = io;
    if (!c->prepared) {
        c->prepared = 1;
        const uint8_t *cpub = find_client_pub(c->cli_to_srv->buf, c->cli_to_srv->len);
        if (cpub) {
            uint8_t shared[32];
            x25519(shared, c->spriv, cpub);

            uint8_t zero[32] = {0};
            uint8_t empty_hash[32];
            sha256_digest(NULL, 0, empty_hash);
            uint8_t early[32], derived[32], hs_secret[32], th[32];
            hkdf_extract(NULL, 0, zero, 32, early);
            derive_secret(early, "derived", empty_hash, derived);
            hkdf_extract(derived, 32, shared, 32, hs_secret);

            /* transcript = ClientHello || ServerHello */
            sha256_ctx_t ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, c->cli_to_srv->buf, c->cli_to_srv->len);
            sha256_update(&ctx, g_sh_bytes, g_sh_len);
            sha256_final(&ctx, th);

            uint8_t shs[32];
            derive_secret(hs_secret, "s hs traffic", th, shs);
            hkdf_expand_label(shs, "key", NULL, 0, c->shs_key, 16);
            hkdf_expand_label(shs, "iv", NULL, 0, c->shs_iv, 12);

            /* encrypt the fuzzer payload as one or more handshake records */
            size_t off = 0;
            while (off < c->fuzz_len) {
                size_t plen = c->fuzz_len - off;
                if (plen > 1024)
                    plen = 1024;
                emit_record(c, 22 /* handshake */, c->fuzz + off, plen);
                off += plen;
                if (c->sseq > 32)
                    break;
            }
            /* Finished (type 20) so a successful parse terminates cleanly */
            {
                uint8_t fin[36];
                fin[0] = 20;
                fin[1] = 0; fin[2] = 0; fin[3] = 32;
                memset(fin + 4, 0xAA, 32);
                emit_record(c, 22, fin, 36);
            }
        }
    }
    pipe_t *p = c->srv_to_cli;
    if (len > p->len - p->pos)
        return -1;
    memcpy(out, p->buf + p->pos, len);
    p->pos += len;
    return 0;
}

static int pipe_write(void *io, const uint8_t *in, size_t len) {
    ctx_t *c = io;
    pipe_t *p = c->cli_to_srv;
    if (len > sizeof(p->buf) - p->len)
        return -1;
    memcpy(p->buf + p->len, in, len);
    p->len += len;
    return 0;
}

static void emit_record(ctx_t *c, uint8_t inner_type, const uint8_t *pt, size_t plen) {
    uint8_t nonce[12];
    memcpy(nonce, c->shs_iv, 12);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] ^= (uint8_t)(c->sseq >> (56 - i * 8));
    uint8_t *rec = malloc(plen + 1 + 16);
    if (!rec)
        return;
    rec[0] = 0x17; rec[1] = 0x03; rec[2] = 0x03;
    size_t clen = plen + 1 + 16;
    rec[3] = (uint8_t)(clen >> 8); rec[4] = (uint8_t)clen;
    memcpy(rec + 5, pt, plen);
    rec[5 + plen] = inner_type;
    uint8_t tag[16];
    aes_gcm_seal(c->shs_key, 16, nonce, rec, 5, rec + 5, plen + 1, tag);
    memcpy(rec + 5 + plen + 1, tag, 16);
    pipe_t *p = c->srv_to_cli;
    if (5 + clen <= sizeof(p->buf) - p->len) {
        memcpy(p->buf + p->len, rec, 5 + clen);
        p->len += 5 + clen;
    }
    free(rec);
    c->sseq++;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8)
        return 0;

    static pipe_t s2c, c2s;      /* static: avoid 128K stack */
    static ctx_t c;
    memset(&s2c, 0, sizeof(s2c));
    memset(&c2s, 0, sizeof(c2s));
    memset(&c, 0, sizeof(c));
    c.srv_to_cli = &s2c;
    c.cli_to_srv = &c2s;
    c.fuzz = data;
    c.fuzz_len = size;

    random_bytes(c.spriv, 32);
    uint8_t spub[32];
    x25519_base(spub, c.spriv);

    /* ServerHello */
    uint8_t sh[256];
    size_t o = 0;
    sh[o++] = 0x03; sh[o++] = 0x03;
    uint8_t srand[32];
    random_bytes(srand, 32);
    memcpy(sh + o, srand, 32); o += 32;
    sh[o++] = 0;
    sh[o++] = 0x13; sh[o++] = 0x01;
    sh[o++] = 0;
    size_t ext_at = o;
    sh[o++] = 0; sh[o++] = 0;
    size_t ext_start = o;
    sh[o++] = 0x00; sh[o++] = 0x2b; sh[o++] = 0x00; sh[o++] = 0x02; sh[o++] = 0x03; sh[o++] = 0x04;
    sh[o++] = 0x00; sh[o++] = 0x33; sh[o++] = 0x00; sh[o++] = 0x24;
    sh[o++] = 0x00; sh[o++] = 0x1d; sh[o++] = 0x00; sh[o++] = 0x20;
    memcpy(sh + o, spub, 32); o += 32;
    sh[ext_at] = (uint8_t)((o - ext_start) >> 8);
    sh[ext_at + 1] = (uint8_t)(o - ext_start);

    uint8_t hs_hdr[4] = {2, 0, 0, 0};
    put24h(hs_hdr + 1, (uint32_t)o);
    uint8_t rec[5] = {0x16, 0x03, 0x03, 0, 0};
    uint16_t blen = (uint16_t)(o + 4);
    rec[3] = (uint8_t)(blen >> 8); rec[4] = (uint8_t)blen;
    /* write ServerHello into the client's input pipe */
    memcpy(s2c.buf + s2c.len, rec, 5); s2c.len += 5;
    memcpy(s2c.buf + s2c.len, hs_hdr, 4); s2c.len += 4;
    memcpy(s2c.buf + s2c.len, sh, o); s2c.len += o;
    memcpy(g_sh_bytes, hs_hdr, 4);
    memcpy(g_sh_bytes + 4, sh, o);
    g_sh_len = 4 + o;

    /* Pre-derive keys assuming we can see the ClientHello: we cannot until
       the client writes it, so encrypt the fuzzer payloads later, after the
       first read returns.  To keep this deterministic we instead append a
       fixed placeholder now and replace it in pipe_read(). */
    c.prepared = 0;

    tls_skip_marker = 1;
    tls_force_12 = 0;
    tls_conn_t *t = tls_connect_io(&c, pipe_read, pipe_write, "fuzz.local", NULL, NULL, 0, NULL);
    if (t) {
        uint8_t buf[512];
        (void)tls_read(t, buf, sizeof(buf));
        tls_close(t);
    }
    return 0;
}

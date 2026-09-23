/*
 * SPDX-License-Identifier: GPL-3.0-only
 * fuzz_tls_inner.c - libFuzzer harness for the *decrypted* TLS payload path.
 *
 * The input is treated as a sequence of records whose inner type is chosen by
 * the first byte of each chunk; the harness encrypts each payload with fixed
 * traffic keys (so the AEAD tag validates) and feeds the result to tls_read.
 * This reaches the post-decryption parsers (handshake messages, alerts,
 * post-handshake data) that a tag-mismatch would otherwise hide.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined -Iinclude -o tls_inner_fuzzer \
 *       test/fuzz_tls_inner.c src/crypto.c src/log.c src/net.c src/x25519.c \
 *       src/x509.c src/ecdsa.c src/bignum.c src/base64.c -pthread
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "tfrpc.h"

#include "../src/tls.c"

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} mem_in_t;

static int mem_read(void *io, uint8_t *buf, size_t len) {
    mem_in_t *m = io;
    if (len > m->len - m->pos)
        return -1;
    memcpy(buf, m->data + m->pos, len);
    m->pos += len;
    return 0;
}

static int mem_write(void *io, const uint8_t *buf, size_t len) {
    (void)io; (void)buf; (void)len;
    return 0;
}

/* fixed traffic key/iv shared by the harness and the conn under test */
static const uint8_t KEY[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
static const uint8_t IV[12]  = {9,9,9,9,9,9,9,9,9,9,9,9};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2)
        return 0;

    tls_conn_t t;
    memset(&t, 0, sizeof(t));
    t.fd = -1;
    t.hs_done = 1;
    t.tls12 = 0;
    memcpy(t.sap_key, KEY, 16);
    memcpy(t.sap_iv, IV, 12);
    t.rxcap = 17000;
    t.rx = malloc(t.rxcap);
    if (!t.rx)
        return 0;

    /* Build an encrypted record stream from the input: chunks of
       [inner_type:1][len:2][payload] become one record each. */
    size_t pos = 0;
    uint8_t *wire = malloc(size * 2 + 64);
    size_t wlen = 0;
    uint64_t seq = 0;
    if (!wire) { free(t.rx); return 0; }

    while (pos + 3 <= size && wlen + size + 64 < size * 2 + 64) {
        uint8_t itype = data[pos];
        size_t plen = ((size_t)data[pos + 1] << 8) | data[pos + 2];
        pos += 3;
        if (plen > size - pos)
            plen = size - pos;
        if (plen == 0)
            break;
        /* inner = payload || inner_type, encrypted as one TLS record */
        size_t ilen = plen + 1;
        uint8_t *pt = malloc(ilen);
        if (!pt) break;
        memcpy(pt, data + pos, plen);
        pt[plen] = itype;
        pos += plen;

        uint8_t hdr[5] = {0x17, 0x03, 0x03, (uint8_t)((ilen + 16) >> 8), (uint8_t)(ilen + 16)};
        uint8_t nonce[12];
        memcpy(nonce, IV, 12);
        for (int i = 0; i < 8; i++)
            nonce[4 + i] ^= (uint8_t)(seq >> (56 - i * 8));
        uint8_t tag[16];
        aes_gcm_seal(KEY, 16, nonce, hdr, 5, pt, ilen, tag);
        if (wlen + 5 + ilen + 16 <= size * 2 + 64) {
            memcpy(wire + wlen, hdr, 5); wlen += 5;
            memcpy(wire + wlen, pt, ilen); wlen += ilen;
            memcpy(wire + wlen, tag, 16); wlen += 16;
        }
        free(pt);
        seq++;
        if (wlen > 65536)
            break;
    }

    mem_in_t m = { wire, wlen, 0 };
    t.io = &m;
    t.io_read = mem_read;
    t.io_write = mem_write;

    uint8_t buf[8192];
    for (int i = 0; i < 16; i++) {
        int r = tls_read(&t, buf, sizeof(buf));
        if (r <= 0)
            break;
    }
    free(wire);
    free(t.rx);
    free(t.hbuf);
    return 0;
}

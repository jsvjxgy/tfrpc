/*
 * SPDX-License-Identifier: GPL-3.0-only
 * fuzz_tls_rec.c - libFuzzer harness for the post-handshake record layer.
 *
 * Bypasses the handshake by constructing a tls_conn_t with fixed traffic
 * keys, then feeds the input as incoming TLS records.  This exercises
 * tls_recv_encrypted / tls_read (TLS 1.3) and tls12_recv (TLS 1.2) without
 * needing a real handshake.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined -Iinclude -o tls_rec_fuzzer \
 *       test/fuzz_tls_rec.c src/crypto.c src/log.c src/net.c -pthread
 * (tls.c is #included for access to its static internals.)
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "tfrpc.h"

/* pull in the static record/parser helpers */
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1)
        return 0;

    mem_in_t m = { data + 1, size - 1, 0 };
    tls_conn_t t;
    memset(&t, 0, sizeof(t));
    t.fd = -1;
    t.hs_done = 1;
    t.tls12 = (data[0] & 1) ? 1 : 0;
    /* fixed traffic keys so record decryption reaches the parser */
    memset(t.sap_key, 0x42, 16);
    memset(t.sap_iv, 0x24, 12);
    memset(t.s12_key, 0x42, 16);
    memset(t.s12_iv, 0x24, 4);
    t.rxcap = 17000;
    t.rx = malloc(t.rxcap);
    if (!t.rx)
        return 0;
    t.io = &m;
    t.io_read = mem_read;
    t.io_write = mem_write;

    uint8_t buf[8192];
    for (int i = 0; i < 8; i++) {
        int r = tls_read(&t, buf, sizeof(buf));
        if (r <= 0)
            break;
    }
    free(t.rx);
    free(t.hbuf);
    return 0;
}

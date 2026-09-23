/*
 * SPDX-License-Identifier: GPL-3.0-only
 * fuzz_tls.c - libFuzzer harness for the TLS client handshake.
 *
 * The input is a fake "server response" stream: the first byte selects the
 * TLS version (0 = 1.3, 1 = 1.2) and the rest is fed to the client as if it
 * came from the server, so libFuzzer explores the record/handshake parsers
 * with coverage feedback.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined -Iinclude -o tls_fuzzer \
 *       test/fuzz_tls.c src/tls.c src/crypto.c src/x25519.c src/bignum.c \
 *       src/x509.c src/ecdsa.c src/log.c -pthread
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "tfrpc.h"
#include "tls.h"

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
    size_t max_out;   /* cap on how much the client may "write" */
} mem_io_t;

static int mem_read(void *io, uint8_t *buf, size_t len) {
    mem_io_t *m = io;
    if (len > m->len - m->pos)
        return -1;
    memcpy(buf, m->data + m->pos, len);
    m->pos += len;
    return 0;
}

static int mem_write(void *io, const uint8_t *buf, size_t len) {
    mem_io_t *m = io;
    (void)buf;
    if (len > m->max_out)
        return -1;
    m->max_out -= len;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2)
        return 0;

    tls_skip_marker = 1;                 /* frp default: no 0x17 marker */
    tls_force_12 = (data[0] & 1) ? 1 : 0;

    mem_io_t m = { data + 1, size - 1, 0, 1 << 20 };

    /* no CA -> skip chain verification, still exercises every parser */
    tls_conn_t *t = tls_connect_io(&m, mem_read, mem_write, "fuzz.local",
                                   NULL, NULL, 0, NULL);
    if (t) {
        uint8_t buf[512];
        /* read a little in case the handshake completed and data is queued */
        (void)tls_read(t, buf, sizeof(buf));
        tls_close(t);
    }
    return 0;
}

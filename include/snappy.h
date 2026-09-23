/*
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef TFRPC_SNAPPY_H
#define TFRPC_SNAPPY_H

#include <stdint.h>
#include <stddef.h>

/* snappy framed-stream codec, byte-compatible with github.com/golang/snappy
 * (the library frp uses for `useCompression`).  Compression is applied on the
 * client side before encryption, so the wire order is
 *   write: plaintext -> snappy -> [encrypt] -> wire
 *   read:  wire -> [decrypt] -> snappy -> plaintext
 */

/* write len bytes downstream (returns 0 on success, -1 on error) */
typedef int (*snappy_out_fn)(void *ctx, const uint8_t *data, size_t len);
/* read exactly len bytes from upstream (0 on success, -1 on error) */
typedef int (*snappy_in_fn)(void *ctx, uint8_t *data, size_t len);

typedef struct snappy_writer snappy_writer_t;
typedef struct snappy_reader snappy_reader_t;

snappy_writer_t *snappy_writer_new(snappy_out_fn out, void *ctx);
void snappy_writer_free(snappy_writer_t *w);
int snappy_writer_write(snappy_writer_t *w, const uint8_t *data, size_t len);
/* emit any buffered partial block (call before closing the connection) */
int snappy_writer_flush(snappy_writer_t *w);

snappy_reader_t *snappy_reader_new(snappy_in_fn in, void *ctx);
void snappy_reader_free(snappy_reader_t *r);
/* returns bytes read (may be < len), 0 on clean EOF, -1 on error */
int snappy_reader_read(snappy_reader_t *r, uint8_t *out, size_t len);

uint32_t crc32c(const uint8_t *data, size_t len);

#endif

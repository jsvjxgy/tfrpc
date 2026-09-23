/*
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef TFRPC_TLS_H
#define TFRPC_TLS_H

#include <stddef.h>
#include <stdint.h>
#include "bignum.h"
#include "x509.h"

typedef struct tls_conn tls_conn_t;

/* when set, tls_connect does not send frp's 0x17 marker */
extern int tls_skip_marker;
extern int tls_force_12;

/* TLS over an arbitrary transport: read/write callbacks return 0 on success
 * and -1 on error.  Used for KCP where there is no socket fd. */
typedef int (*tls_io_read_fn)(void *io, uint8_t *buf, size_t len);
typedef int (*tls_io_write_fn)(void *io, const uint8_t *buf, size_t len);

/* Perform a TLS 1.3 client handshake over fd (frp sends a 0x17 marker first).
 * Returns NULL on failure. Certificate chain is not verified (matching frp's
 * default when no trustedCaFile is configured). */
tls_conn_t *tls_connect(int fd, const char *server_name, const x509_cert_t *ca,
                        const uint8_t *client_cert, size_t client_cert_len,
                        const rsa_priv_t *client_key);

/* Same handshake over a callback-based transport (e.g. a KCP session). */
tls_conn_t *tls_connect_io(void *io, tls_io_read_fn rd, tls_io_write_fn wr,
                           const char *server_name, const x509_cert_t *ca,
                           const uint8_t *client_cert, size_t client_cert_len,
                           const rsa_priv_t *client_key);
void tls_close(tls_conn_t *t);   /* also closes the fd */
void tls_shutdown(tls_conn_t *t);
/* returns bytes read (>0), 0 on EOF, -1 on error */
int tls_read(tls_conn_t *t, void *buf, size_t len);
int tls_write(tls_conn_t *t, const void *buf, size_t len);

#endif

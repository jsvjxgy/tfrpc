/*
 * SPDX-License-Identifier: GPL-3.0-only
 * quic.h - minimal IETF QUIC v1 (RFC 9000) client, enough to talk to frps.
 *
 * Implements a single-session, multi-stream QUIC client: one session is
 * dialed to frps' quicBindPort and every "connection" (control or work)
 * becomes one bidirectional stream on that session, matching frp's
 * ConnectionManager model.
 *
 * Wire format and handshake follow RFC 9000 (frames, packet protection)
 * and RFC 9001 (TLS 1.3 over QUIC).  Flow control is honored in both
 * directions, out-of-order stream data is reassembled, unacknowledged
 * 1-RTT packets are retransmitted, and key updates are supported.
 */

#ifndef TFRPC_QUIC_H
#define TFRPC_QUIC_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

typedef struct quic_conn quic_conn_t;     /* one QUIC session */
typedef struct quic_stream quic_stream_t; /* one bidirectional stream */

/* dial frps' QUIC port.  server_name is used for SNI and, when `ca` is
 * non-NULL, certificate verification.  Returns NULL on failure. */
quic_conn_t *quic_dial(const char *host, uint16_t port, const char *server_name,
                       const void *ca, int timeout_ms);

/* open a new bidirectional stream on the session (one frp connection) */
quic_stream_t *quic_open_stream(quic_conn_t *c);

/* stream I/O: 0 on success, -1 on error/closed; read blocks until data,
 * close, or the deadline (ms, 0 = none). */
int quic_stream_read(quic_stream_t *s, uint8_t *buf, int len);
int quic_stream_write(quic_stream_t *s, const uint8_t *buf, int len);
int quic_stream_close(quic_stream_t *s);
void quic_stream_abort(quic_stream_t *s);      /* wake a blocked reader */
int quic_stream_wait_readable(quic_stream_t *s, int timeout_ms);
void quic_set_deadline(quic_stream_t *s, int timeout_ms);

/* detach and free a stream; only call once no thread uses it anymore */
void quic_stream_free(quic_stream_t *s);

/* session teardown: shutdown wakes all blocked stream I/O without freeing
 * anything (call before waiting for relay threads); close then releases the
 * session and must be the last call */
void quic_conn_shutdown(quic_conn_t *c);
void quic_conn_close(quic_conn_t *c);

#endif

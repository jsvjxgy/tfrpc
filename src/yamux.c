/*
 * SPDX-License-Identifier: GPL-3.0-only
 * yamux.c - minimal yamux (client side) implementation.
 *
 * Enables tfrpc to speak the multiplexed protocol that a default frps
 * (transport.tcpMux = true) expects, per the yamux spec:
 *   12-byte header (version, type, flags, streamID, length) + payload.
 *
 * We only implement what a frp client needs: open streams (odd IDs),
 * send data with flow control, receive data with window updates, and
 * answer pings.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

#include "tfrpc.h"

#define YMX_INITIAL_WINDOW   (6 * 1024 * 1024)
#define YMX_WINDOW_THRESHOLD (3 * 1024 * 1024)
#define YMX_FRAME_HDR        12
#define YMX_MAX_FRAME        (256 * 1024)   /* hashicorp/yamux max frame size */

#define YMX_TYPE_DATA          0x0
#define YMX_TYPE_WINDOW_UPDATE 0x1
#define YMX_TYPE_PING          0x2
#define YMX_TYPE_GO_AWAY       0x3

#define YMX_FLAG_SYN 0x1
#define YMX_FLAG_ACK 0x2
#define YMX_FLAG_FIN 0x4
#define YMX_FLAG_RST 0x8

typedef struct yamux_stream yamux_stream_t;
typedef struct yamux_session yamux_session_t;

struct yamux_stream {
    uint32_t id;
    int fin_sent;
    _Atomic int rx_closed;
    _Atomic int tx_closed;

    uint8_t *rxbuf;
    size_t rxlen;
    size_t rxpos;   /* read offset; data lives in [rxpos, rxlen) */
    size_t rxcap;

    uint32_t recv_window;
    uint32_t recv_freed;
    uint32_t send_window;

    yamux_session_t *sess;
    struct yamux_stream *next;
};

struct yamux_session {
    int fd;   /* for the fd-based transport; -1 if using io callbacks */
    pthread_t reader;
    pthread_mutex_t lock;   /* stream state */
    pthread_mutex_t wlock;  /* serializes writes to the wire */
    pthread_cond_t cond;
    yamux_stream_t *streams;
    uint32_t next_stream_id;
    _Atomic int closed;

    /* pluggable transport */
    struct yamux_io {
        int (*read)(void *ctx, void *buf, size_t n);
        int (*write)(void *ctx, const void *buf, size_t n);
        void (*shutdown)(void *ctx);   /* wake a blocked read, no free */
        void (*close)(void *ctx);
        void *ctx;
    } io;
};

static int yamux_io_read(void *ctx, void *buf, size_t n) {
    return read_full((int)(intptr_t)ctx, buf, n);
}

static int yamux_io_write(void *ctx, const void *buf, size_t n) {
    return write_full((int)(intptr_t)ctx, buf, n);
}

static void yamux_io_shutdown(void *ctx) {
    shutdown((int)(intptr_t)ctx, SHUT_RDWR);
}

static void yamux_io_close(void *ctx) {
    close((int)(intptr_t)ctx);
}

static void yamux_send_frame(yamux_session_t *s, uint8_t type, uint16_t flags,
                             uint32_t stream_id, const uint8_t *payload,
                             uint32_t len) {
    uint8_t hdr[YMX_FRAME_HDR];
    pthread_mutex_lock(&s->wlock);
    hdr[0] = 0;                              /* version */
    hdr[1] = type;
    hdr[2] = (uint8_t)(flags >> 8);
    hdr[3] = (uint8_t)(flags & 0xff);
    hdr[4] = (uint8_t)(stream_id >> 24);
    hdr[5] = (uint8_t)(stream_id >> 16);
    hdr[6] = (uint8_t)(stream_id >> 8);
    hdr[7] = (uint8_t)(stream_id & 0xff);
    hdr[8] = (uint8_t)(len >> 24);
    hdr[9] = (uint8_t)(len >> 16);
    hdr[10] = (uint8_t)(len >> 8);
    hdr[11] = (uint8_t)(len & 0xff);
    if (s->io.write(s->io.ctx, hdr, YMX_FRAME_HDR) == 0 && payload && len > 0)
        (void)s->io.write(s->io.ctx, payload, len);
    pthread_mutex_unlock(&s->wlock);
}

static yamux_stream_t *yamux_find(yamux_session_t *s, uint32_t id) {
    yamux_stream_t *st;
    for (st = s->streams; st; st = st->next)
        if (st->id == id)
            return st;
    return NULL;
}

/* signal the waiters that the session state changed */
static void yamux_broadcast(yamux_session_t *s) {
    pthread_cond_broadcast(&s->cond);
}

static void yamux_stream_append(yamux_stream_t *st, const uint8_t *data, uint32_t len) {
    if (len == 0 || !data)
        return;
    if (st->rxlen + len > st->rxcap) {
        /* reclaim already-consumed space first (amortizes the copy) */
        if (st->rxpos > 0) {
            memmove(st->rxbuf, st->rxbuf + st->rxpos, st->rxlen - st->rxpos);
            st->rxlen -= st->rxpos;
            st->rxpos = 0;
        }
        if (st->rxlen + len > st->rxcap) {
            size_t ncap = st->rxcap ? st->rxcap * 2 : 16384;
            while (ncap < st->rxlen + len)
                ncap *= 2;
            uint8_t *nb = realloc(st->rxbuf, ncap);
            if (!nb)
                return;   /* out of memory: drop the frame payload */
            st->rxbuf = nb;
            st->rxcap = ncap;
        }
    }
    memcpy(st->rxbuf + st->rxlen, data, len);
    st->rxlen += len;
}

static void yamux_reader(void *arg) {
    yamux_session_t *s = arg;
    while (!s->closed) {
        uint8_t hdr[YMX_FRAME_HDR];
        uint8_t *payload = NULL;
        uint32_t stream_id, len;
        uint8_t type;
        uint16_t flags;
        int err;

        err = s->io.read(s->io.ctx, hdr, YMX_FRAME_HDR);
        if (err < 0)
            break;

        type = hdr[1];
        flags = (uint16_t)((hdr[2] << 8) | hdr[3]);
        stream_id = ((uint32_t)hdr[4] << 24) | ((uint32_t)hdr[5] << 16) |
                    ((uint32_t)hdr[6] << 8) | hdr[7];
        len = ((uint32_t)hdr[8] << 24) | ((uint32_t)hdr[9] << 16) |
              ((uint32_t)hdr[10] << 8) | hdr[11];

        /* only DATA frames carry a payload; for window-update/ping/go-away
           the length field is the value itself, no payload follows.
           Reject oversized frames before allocating (hashicorp/yamux caps
           frames at 256 KiB; without this a hostile peer could force a
           multi-gigabyte allocation). */
        if (type == YMX_TYPE_DATA && len > 0) {
            if (len > YMX_MAX_FRAME)
                break;
            payload = malloc(len);
            if (!payload)
                break;
            if (s->io.read(s->io.ctx, payload, len) < 0) {
                free(payload);
                break;
            }
        }

        pthread_mutex_lock(&s->lock);
        switch (type) {
        case YMX_TYPE_DATA: {
            yamux_stream_t *st = yamux_find(s, stream_id);
            if (!st) {
                /* server-initiated stream (even id): accept it */
                if ((stream_id & 1) == 0) {
                    st = calloc(1, sizeof(*st));
                    if (!st)
                        break;
                    st->id = stream_id;
                    st->recv_window = YMX_INITIAL_WINDOW;
                    st->send_window = 0;
                    st->sess = s;
                    st->next = s->streams;
                    s->streams = st;
                    yamux_send_frame(s, YMX_TYPE_WINDOW_UPDATE, YMX_FLAG_ACK,
                                     stream_id, NULL, YMX_INITIAL_WINDOW);
                }
            }
            if (st) {
                if (st->recv_window >= len) {
                    st->recv_window -= len;
                    yamux_stream_append(st, payload, len);
                } else {
                }

                if (flags & YMX_FLAG_FIN)
                    st->rx_closed = 1;
                if (flags & YMX_FLAG_RST)
                    st->rx_closed = st->tx_closed = 1;
            }
            break;
        }
        case YMX_TYPE_WINDOW_UPDATE: {
            yamux_stream_t *st = yamux_find(s, stream_id);
            if (st) {
                st->send_window += len;
                if (flags & YMX_FLAG_FIN)
                    st->rx_closed = 1;
                if (flags & YMX_FLAG_RST)
                    st->rx_closed = st->tx_closed = 1;
            }
            break;
        }
        case YMX_TYPE_PING:
            /* if it's a ping request (SYN), echo it back with ACK; the
               length field carries the opaque ping id, no payload */
            if (flags & YMX_FLAG_SYN) {
                yamux_send_frame(s, YMX_TYPE_PING, YMX_FLAG_ACK, 0,
                                 NULL, len);
            }
            break;
        case YMX_TYPE_GO_AWAY:
            s->closed = 1;
            break;
        default:
            break;
        }
        yamux_broadcast(s);
        pthread_mutex_unlock(&s->lock);

        free(payload);
    }

    pthread_mutex_lock(&s->lock);
    s->closed = 1;
    yamux_broadcast(s);
    pthread_mutex_unlock(&s->lock);
}

static void *yamux_reader_wrapper(void *arg) {
    yamux_reader(arg);
    return NULL;
}

/* public API ---------------------------------------------------------- */

typedef struct yamux_session yamux_session_t;

void *yamux_client_new(int fd) {
    return yamux_client_new_io(yamux_io_read, yamux_io_write,
                               yamux_io_shutdown, yamux_io_close,
                               (void *)(intptr_t)fd);
}

/* create a yamux client session over a pluggable transport */
void *yamux_client_new_io(int (*read_fn)(void *, void *, size_t),
                          int (*write_fn)(void *, const void *, size_t),
                          void (*shutdown_fn)(void *),
                          void (*close_fn)(void *), void *ctx) {
    yamux_session_t *s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->fd = -1;
    s->io.read = read_fn;
    s->io.write = write_fn;
    s->io.shutdown = shutdown_fn;
    s->io.close = close_fn;
    s->io.ctx = ctx;
    s->next_stream_id = 1; /* client uses odd ids */
    pthread_mutex_init(&s->lock, NULL);
    pthread_mutex_init(&s->wlock, NULL);
    pthread_cond_init(&s->cond, NULL);
    if (pthread_create(&s->reader, NULL, yamux_reader_wrapper, s) != 0) {
        pthread_mutex_destroy(&s->lock);
        pthread_mutex_destroy(&s->wlock);
        pthread_cond_destroy(&s->cond);
        free(s);
        return NULL;
    }
    return s;
}

void *yamux_open(void *sessp) {
    yamux_session_t *s = sessp;
    yamux_stream_t *st;
    pthread_mutex_lock(&s->lock);
    if (s->closed) {
        pthread_mutex_unlock(&s->lock);
        return NULL;
    }
    st = calloc(1, sizeof(*st));
    if (!st) {
        pthread_mutex_unlock(&s->lock);
        return NULL;
    }
    st->id = s->next_stream_id;
    s->next_stream_id += 2;
    st->recv_window = YMX_INITIAL_WINDOW;
    st->send_window = 0;   /* sender window is fully peer-advertised via WU */
    st->sess = s;
    st->next = s->streams;
    s->streams = st;
    pthread_mutex_unlock(&s->lock);

    /* SYN: announce the stream and advertise our receive window (like Go yamux) */
    yamux_send_frame(s, YMX_TYPE_WINDOW_UPDATE, YMX_FLAG_SYN, st->id, NULL,
                     YMX_INITIAL_WINDOW);
    return st;
}

/* blocking read; returns >0 bytes, 0 on clean EOF, -1 on error */
int yamux_stream_read(void *stp, uint8_t *buf, size_t n) {
    yamux_stream_t *st = stp;
    yamux_session_t *s = st->sess;
    size_t got = 0;
    uint32_t freed = 0;

    pthread_mutex_lock(&s->lock);
    while (st->rxlen <= st->rxpos && !st->rx_closed && !s->closed) {
        pthread_cond_wait(&s->cond, &s->lock);
    }
    if (st->rxlen > st->rxpos) {
        size_t avail = st->rxlen - st->rxpos;
        got = n < avail ? n : avail;
        memcpy(buf, st->rxbuf + st->rxpos, got);
        st->rxpos += got;
        if (st->rxpos == st->rxlen)
            st->rxpos = st->rxlen = 0;
        st->recv_freed += (uint32_t)got;
        st->recv_window += (uint32_t)got;
        if (st->recv_freed >= YMX_WINDOW_THRESHOLD) {
            freed = st->recv_freed;
            st->recv_freed = 0;
        }
    }
    int closed_now = (st->rx_closed || s->closed);
    pthread_mutex_unlock(&s->lock);

    if (freed > 0) {
        yamux_send_frame(s, YMX_TYPE_WINDOW_UPDATE, 0, st->id, NULL, freed);
    }

    if (got > 0)
        return (int)got;
    if (closed_now)
        return 0;
    return -1;
}

/* blocking write; returns 0 on success, -1 on error */
int yamux_stream_write(void *stp, const uint8_t *buf, size_t n) {
    yamux_stream_t *st = stp;
    yamux_session_t *s = st->sess;
    size_t off = 0;

    pthread_mutex_lock(&s->lock);
    while (off < n) {
        while (st->send_window == 0 && !s->closed) {
            pthread_cond_wait(&s->cond, &s->lock);
        }
        if (s->closed || st->tx_closed) {
            pthread_mutex_unlock(&s->lock);
            return -1;
        }
        uint32_t chunk = n - off > 65536 ? 65536 : (uint32_t)(n - off);
        if (chunk > st->send_window)
            chunk = st->send_window;
        /* unlock while writing the frame to avoid holding the lock */
        pthread_mutex_unlock(&s->lock);
        yamux_send_frame(s, YMX_TYPE_DATA, 0, st->id, buf + off, chunk);
        pthread_mutex_lock(&s->lock);
        st->send_window -= chunk;
        off += chunk;
    }
    pthread_mutex_unlock(&s->lock);
    return 0;
}

/* wait until the stream has data to read, is closed, or timeout expires.
 * returns 1 if readable, 0 on timeout */
int yamux_stream_wait_readable(void *stp, int timeout_ms) {
    yamux_stream_t *st = stp;
    yamux_session_t *s = st->sess;
    struct timespec ts;
    int rc = 0;

    pthread_mutex_lock(&s->lock);
    if (st->rxlen > st->rxpos || st->rx_closed || s->closed) {
        pthread_mutex_unlock(&s->lock);
        return 1;
    }
    if (timeout_ms <= 0) {
        pthread_cond_wait(&s->cond, &s->lock);
    } else {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&s->cond, &s->lock, &ts);
    }
    if (st->rxlen > st->rxpos || st->rx_closed || s->closed)
        rc = 1;
    pthread_mutex_unlock(&s->lock);
    return rc;
}

/* wake a blocked reader without closing the session (used by the relay to
 * avoid use-after-free when one direction fails) */
void yamux_stream_abort(void *stp) {
    yamux_stream_t *st = stp;
    yamux_session_t *s = st->sess;
    pthread_mutex_lock(&s->lock);
    st->rx_closed = 1;
    st->tx_closed = 1;
    pthread_cond_broadcast(&s->cond);
    pthread_mutex_unlock(&s->lock);
}

int yamux_stream_close(void *stp) {
    yamux_stream_t *st = stp;
    yamux_session_t *s = st->sess;
    if (!st->fin_sent) {
        st->fin_sent = 1;
        st->tx_closed = 1;
        yamux_send_frame(s, YMX_TYPE_DATA, YMX_FLAG_FIN, st->id, NULL, 0);
    }
    return 0;
}

/* mark the session closed and wake every blocked stream reader, but keep the
 * underlying transport open.  Call this, wait for worker threads to finish,
 * then call yamux_close() so the io is not freed while still in use. */
void yamux_shutdown(void *sessp) {
    yamux_session_t *s = sessp;
    if (!s)
        return;
    pthread_mutex_lock(&s->lock);
    s->closed = 1;
    pthread_mutex_unlock(&s->lock);
    yamux_broadcast(s);
}

void yamux_close(void *sessp) {
    yamux_session_t *s = sessp;
    if (!s)
        return;
    yamux_shutdown(s);
    /* wake a blocked transport read, join, then release the transport */
    if (s->io.shutdown)
        s->io.shutdown(s->io.ctx);
    pthread_join(s->reader, NULL);
    if (s->io.close)
        s->io.close(s->io.ctx);

    /* free every stream (rxbuf included) */
    yamux_stream_t *st = s->streams;
    while (st) {
        yamux_stream_t *next = st->next;
        free(st->rxbuf);
        free(st);
        st = next;
    }
    pthread_mutex_destroy(&s->lock);
    pthread_mutex_destroy(&s->wlock);
    pthread_cond_destroy(&s->cond);
    free(s);
}
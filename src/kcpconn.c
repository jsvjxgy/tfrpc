/*
 * SPDX-License-Identifier: GPL-3.0-only kcpconn.c - KCP session layer: a UDP socket running the KCP state machine,
 * framed exactly like kcp-go v5.6.13 with FEC 10/3 (frp's configuration).
 *
 * Outgoing: KCP frame -> [seqid 4B LE][type 0xf1 2B LE][size 2B LE][KCP frame]
 * Incoming: the server (frps) always sends FEC-framed packets; type 0xf1
 * carries the KCP frame at offset 8, type 0xf2 (parity) is dropped.
 *
 * frp client settings replicated here:
 *   stream mode, writeDelay, NoDelay(1,20,2,1), MTU 1350, window 1024/1024,
 *   ackNoDelay=false, conv=1. */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <stdatomic.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "kcp.h"

#define KCP_FEC_HEADER_SIZE 6
#define KCP_FEC_HEADER_PLUS2 8
#define KCP_TYPE_DATA 0xf1
#define KCP_TYPE_PARITY 0xf2

struct kcpconn {
    int fd;
    kcp_t *kcp;

    pthread_t reader_thr;
    pthread_t update_thr;
    int reader_started;
    int update_started;

    uint32_t fec_next;

    pthread_mutex_t mu;
    pthread_cond_t read_cond;
    pthread_cond_t write_cond;

    uint8_t *rbuf;   /* buffered overflow from kcp_recv */
    int rlen;
    int rpos;
    int rcap;

    int write_delay;
    int64_t deadline;   /* monotonic ms, 0 = none */

    _Atomic int closed;
    _Atomic int aborted;
};

static void kcpconn_lock(kcpconn_t *c) { pthread_mutex_lock(&c->mu); }
static void kcpconn_unlock(kcpconn_t *c) { pthread_mutex_unlock(&c->mu); }

static void kcpconn_signal(kcpconn_t *c) {
    pthread_cond_broadcast(&c->read_cond);
    pthread_cond_broadcast(&c->write_cond);
}

static int64_t mono_ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* the output callback: called while c->mu is held.  Wraps the KCP frame in
 * the FEC data packet and sends it over UDP. */
static void kcp_output(const uint8_t *frame, int size, void *ud) {
    kcpconn_t *c = ud;
    if (c->closed)
        return;
    if (size <= 0 || size > 1500)
        return;   /* defensive: never overflow the packet buffer */
    uint8_t pkt[8 + 1500];
    uint32_t seq = c->fec_next++;
    pkt[0] = (uint8_t)seq;
    pkt[1] = (uint8_t)(seq >> 8);
    pkt[2] = (uint8_t)(seq >> 16);
    pkt[3] = (uint8_t)(seq >> 24);
    pkt[4] = KCP_TYPE_DATA;
    pkt[5] = 0;
    uint16_t sz = (uint16_t)(2 + size);
    pkt[6] = (uint8_t)sz;
    pkt[7] = (uint8_t)(sz >> 8);
    memcpy(pkt + 8, frame, (size_t)size);
    if (send(c->fd, pkt, 8 + size, 0) < 0) {
        /* ignore transient send errors */
    }
}

/* feed one received UDP payload into the session */
static void kcp_packet_input(kcpconn_t *c, const uint8_t *data, int n) {
    if (n >= KCP_FEC_HEADER_SIZE) {
        uint16_t fec_flag = (uint16_t)(data[4] | data[5] << 8);
        if (fec_flag == KCP_TYPE_DATA) {
            if (n >= KCP_FEC_HEADER_PLUS2)
                kcp_input(c->kcp, data + KCP_FEC_HEADER_PLUS2, n - KCP_FEC_HEADER_PLUS2, 1, 0);
            return;
        }
        if (fec_flag == KCP_TYPE_PARITY) {
            /* no Reed-Solomon decode in this build; KCP ARQ covers loss */
            return;
        }
    }
    /* bare KCP frame (defensive; kcp-go server always FEC-frames) */
    kcp_input(c->kcp, data, n, 1, 0);
}

static void *kcp_reader(void *arg) {
    kcpconn_t *c = arg;
    uint8_t buf[1500];
    for (;;) {
        /* poll with a timeout so the loop notices c->closed even if the
           platform's UDP shutdown() does not wake a blocked recv() */
        struct pollfd pfd = {.fd = c->fd, .events = POLLIN};
        int pr = poll(&pfd, 1, 500);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (atomic_load(&c->closed))
            break;
        if (pr == 0)
            continue;
        ssize_t n = recv(c->fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
            if (atomic_load(&c->closed))
                break;
            if (n < 0) {
                /* transient socket error (e.g. ICMP unreachable): keep going;
                 * a genuinely dead peer is caught by the heartbeat loop */
                continue;
            }
            break;   /* n == 0: peer closed */
        }
        kcpconn_lock(c);
        kcp_packet_input(c, buf, (int)n);
        if (kcp_peek_size(c->kcp) > 0)
            pthread_cond_broadcast(&c->read_cond);
        if (kcp_wait_snd(c->kcp) < (int)c->kcp->snd_wnd &&
            kcp_wait_snd(c->kcp) < (int)c->kcp->rmt_wnd)
            pthread_cond_broadcast(&c->write_cond);
        kcpconn_unlock(c);
    }
    return NULL;
}

static void *kcp_updater(void *arg) {
    kcpconn_t *c = arg;
    for (;;) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 20 * 1000000L;   /* interval = 20ms (nodelay) */
        nanosleep(&ts, NULL);
        kcpconn_lock(c);
        if (c->closed) {
            kcpconn_unlock(c);
            break;
        }
        kcp_update(c->kcp, kcp_current_ms());
        if (kcp_wait_snd(c->kcp) < (int)c->kcp->snd_wnd &&
            kcp_wait_snd(c->kcp) < (int)c->kcp->rmt_wnd)
            pthread_cond_broadcast(&c->write_cond);
        kcpconn_unlock(c);
    }
    return NULL;
}

kcpconn_t *kcp_dial(const char *host, uint16_t port, int timeout_ms) {
    struct addrinfo hints, *res = NULL;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res)
        return NULL;

    int fd = -1;
    struct addrinfo *ai;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        return NULL;

    (void)timeout_ms;
    int sz = 4194304;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));

    kcpconn_t *c = calloc(1, sizeof(*c));
    if (!c) {
        close(fd);
        return NULL;
    }
    c->fd = fd;
    c->write_delay = 1;
    pthread_mutex_init(&c->mu, NULL);
    pthread_cond_init(&c->read_cond, NULL);
    pthread_cond_init(&c->write_cond, NULL);

    c->kcp = kcp_create(1, kcp_output, c);   /* conv = 1, like frp */
    if (!c->kcp) {
        close(fd);
        free(c);
        return NULL;
    }
    kcp_setmtu(c->kcp, 1350);
    kcp_nodelay(c->kcp, 1, 20, 2, 1);
    kcp_wndsize(c->kcp, 1024, 1024);
    c->kcp->stream = 1;   /* SetStreamMode(true) */

    if (pthread_create(&c->reader_thr, NULL, kcp_reader, c) != 0) {
        kcp_close(c);
        return NULL;
    }
    c->reader_started = 1;
    if (pthread_create(&c->update_thr, NULL, kcp_updater, c) != 0) {
        kcp_close(c);
        return NULL;
    }
    c->update_started = 1;
    return c;
}

int kcp_connected(kcpconn_t *c) { return c && !c->closed; }

void kcp_set_deadline(kcpconn_t *c, int timeout_ms) {
    if (!c)
        return;
    kcpconn_lock(c);
    c->deadline = timeout_ms > 0 ? mono_ms_now() + timeout_ms : 0;
    kcpconn_unlock(c);
}

int kcp_read(kcpconn_t *c, void *buf, int len) {
    if (!c)
        return -1;
    kcpconn_lock(c);
    uint8_t *out = buf;
    int total = 0;

    /* serve from the overflow buffer first */
    if (c->rpos < c->rlen) {
        int avail = c->rlen - c->rpos;
        int take = avail < len ? avail : len;
        memcpy(out, c->rbuf + c->rpos, (size_t)take);
        c->rpos += take;
        total += take;
        if (c->rpos >= c->rlen)
            c->rpos = c->rlen = 0;
        kcpconn_unlock(c);
        return total;
    }

    for (;;) {
        int peek = kcp_peek_size(c->kcp);
        if (peek > 0)
            break;
        if (c->closed || c->aborted) {
            kcpconn_unlock(c);
            return -1;
        }
        if (c->deadline && mono_ms_now() > c->deadline) {
            kcpconn_unlock(c);
            return -1;
        }
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);   /* pthread_cond_timedwait uses absolute time */
        ts.tv_nsec += 200 * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&c->read_cond, &c->mu, &ts);
    }

    int peek = kcp_peek_size(c->kcp);
    int n;
    if (peek <= len) {
        n = kcp_recv(c->kcp, out, len);
    } else {
        if (c->rcap < peek) {
            uint8_t *nb = realloc(c->rbuf, (size_t)peek);
            if (!nb) {
                kcpconn_unlock(c);
                return -1;
            }
            c->rbuf = nb;
            c->rcap = peek;
        }
        n = kcp_recv(c->kcp, c->rbuf, peek);
        if (n <= 0) {
            kcpconn_unlock(c);
            return -1;
        }
        int take = n < len ? n : len;
        memcpy(out, c->rbuf, (size_t)take);
        c->rpos = take;
        c->rlen = n;
        total += take;
        kcpconn_unlock(c);
        return total;
    }
    kcpconn_unlock(c);
    return n;
}

int kcp_write(kcpconn_t *c, const void *buf, int len) {
    if (!c)
        return -1;
    kcpconn_lock(c);
    for (;;) {
        if (c->closed || c->aborted) {
            kcpconn_unlock(c);
            return -1;
        }
        int ws = kcp_wait_snd(c->kcp);
        if (ws < (int)c->kcp->snd_wnd && ws < (int)c->kcp->rmt_wnd)
            break;
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 100 * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&c->write_cond, &c->mu, &ts);
    }
    kcp_send(c->kcp, buf, len);
    int ws = kcp_wait_snd(c->kcp);
    if (ws >= (int)c->kcp->snd_wnd || ws >= (int)c->kcp->rmt_wnd || !c->write_delay)
        kcp_flush(c->kcp, 0);
    kcpconn_unlock(c);
    return 0;
}

/* wake blocked readers/writers without freeing the session */
void kcp_abort(kcpconn_t *c) {
    if (!c)
        return;
    kcpconn_lock(c);
    c->aborted = 1;
    kcpconn_signal(c);
    kcpconn_unlock(c);
    if (c->fd >= 0)
        shutdown(c->fd, SHUT_RDWR);   /* wake the blocking recv() */
}

int kcp_wait_readable(kcpconn_t *c, int timeout_ms) {
    if (!c)
        return -1;
    kcpconn_lock(c);
    if (kcp_peek_size(c->kcp) > 0 || c->closed || c->aborted) {
        kcpconn_unlock(c);
        return 1;
    }
    if (timeout_ms <= 0) {
        pthread_cond_wait(&c->read_cond, &c->mu);
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&c->read_cond, &c->mu, &ts);
    }
    int rc = (kcp_peek_size(c->kcp) > 0 || c->closed || c->aborted) ? 1 : 0;
    kcpconn_unlock(c);
    return rc;
}

void kcp_close(kcpconn_t *c) {
    if (!c)
        return;
    kcpconn_lock(c);
    if (c->closed) {
        kcpconn_unlock(c);
        return;
    }
    c->closed = 1;
    kcpconn_signal(c);
    kcpconn_unlock(c);

    /* wake the reader (without closing the fd), then join before closing so
     * recv() and close() never race on the same descriptor */
    shutdown(c->fd, SHUT_RDWR);
    if (c->reader_started)
        pthread_join(c->reader_thr, NULL);
    if (c->update_started)
        pthread_join(c->update_thr, NULL);
    close(c->fd);
    c->fd = -1;

    kcpconn_lock(c);
    kcp_release(c->kcp);
    c->kcp = NULL;
    free(c->rbuf);
    kcpconn_unlock(c);

    pthread_mutex_destroy(&c->mu);
    pthread_cond_destroy(&c->read_cond);
    pthread_cond_destroy(&c->write_cond);
    free(c);
}
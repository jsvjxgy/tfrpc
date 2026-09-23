/*
 * SPDX-License-Identifier: GPL-3.0-only
 * workconn.c - handle a work connection established with frps.
 *
 * Flow (v1):
 *   open stream/TCP -> NewWorkConn (plain) -> StartWorkConn (plain)
 *   -> if use_encryption, enable AES on the connection
 *   -> relay (tcp/http/https) or exchange UDPPacket messages (udp).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tfrpc.h"
#include "kcp.h"


#define UDP_PEER_IDLE_MS  30000
#define RELAY_BUF         16384

extern void *g_session;             /* yamux session (may be NULL) */
extern _Atomic int g_running;

/* ---------------- helpers ---------------- */

static void strip_user_prefix(char *name, const char *user) {
    size_t ulen = strlen(user);
    if (ulen > 0 && strncmp(name, user, ulen) == 0 && name[ulen] == '.') {
        memmove(name, name + ulen + 1, strlen(name + ulen + 1) + 1);
    }
}

static proxy_cfg_t *find_proxy(tfrpc_config_t *cfg, const char *name) {
    int i;
    for (i = 0; i < cfg->proxy_count; i++)
        if (strcmp(cfg->proxies[i].name, name) == 0)
            return &cfg->proxies[i];
    return NULL;
}

/* open a connection to frps: yamux stream if mux on, else new TCP */
static void enable_proxy_crypto(tfrpc_config_t *cfg, tconn_t *conn) {
    uint8_t key[16];
    derive_key(cfg->token, key, sizeof(key));
    tconn_enable_crypto(conn, key);
}

/* ---------------- tcp / http / https relay ---------------- */

typedef struct {
    tconn_t *work;
    tconn_t *local;
    pthread_mutex_t lock;
    int closed;
} relay_ctx_t;

/* Free the work conn.  Only called after both relay threads have joined, so
 * nothing can be using it any more. */
static void relay_close_all(relay_ctx_t *rc) {
    pthread_mutex_lock(&rc->lock);
    if (!rc->closed) {
        rc->closed = 1;
        tconn_close(rc->work);
        rc->work = NULL;
    }
    pthread_mutex_unlock(&rc->lock);
}

/* Wake both directions without freeing anything (safe to call from a relay
 * thread while its peer is still running). */
static void relay_abort(relay_ctx_t *rc) {
    pthread_mutex_lock(&rc->lock);
    if (!rc->closed) {
        tconn_abort(rc->work);
        tconn_abort(rc->local);
    }
    pthread_mutex_unlock(&rc->lock);
}

static void *relay_forward(void *arg) {
    tconn_t *src = ((tconn_t **)arg)[0];
    tconn_t *dst = ((tconn_t **)arg)[1];
    relay_ctx_t *rc = ((relay_ctx_t **)arg)[2];
    uint8_t buf[RELAY_BUF];
    for (;;) {
        int n = tconn_read_some(src, buf, sizeof(buf));
        if (n < 0) {
            relay_abort(rc);
            return NULL;
        }
        if (n == 0) {
            /* clean EOF: half-close only this direction.  Send FIN on the
               yamux stream (or shutdown the socket's write side) so the peer
               sees end-of-data, but keep the opposite direction alive so a
               large in-flight response is not cut off.
               KCP has no half-close; like frp's libio.Join, wake the peer
               direction instead of leaving it blocked until the heartbeat
               timeout. */
            tconn_flush(dst);   /* emit any buffered compressed tail */
            if (dst->kind == 1)
                yamux_stream_close(dst->st);
            else if (dst->kind == 0)
                shutdown(dst->fd, SHUT_WR);
            else if (dst->kind == 2)
                kcp_abort(dst->kconn);
            return NULL;
        }
        if (tconn_write_full(dst, buf, (size_t)n) < 0) {
            relay_abort(rc);
            return NULL;
        }
    }
}

static void relay_tunnel(tconn_t *work, int local_fd) {
    tconn_t *local = tconn_socket(local_fd);
    pthread_t t1, t2;
    relay_ctx_t rc;
    tconn_t *arg1[3], *arg2[3];

    if (!local) {
        close(local_fd);
        return;
    }
    memset(&rc, 0, sizeof(rc));
    rc.work = work;
    rc.local = local;
    pthread_mutex_init(&rc.lock, NULL);

    arg1[0] = local; arg1[1] = work; arg1[2] = (tconn_t *)&rc;  /* local -> work */
    arg2[0] = work;  arg2[1] = local; arg2[2] = (tconn_t *)&rc;  /* work -> local */

    int ok1 = pthread_create(&t1, NULL, relay_forward, arg1) == 0;
    int ok2 = pthread_create(&t2, NULL, relay_forward, arg2) == 0;
    if (!ok1 || !ok2) {
        relay_abort(&rc);
        if (ok1) pthread_join(t1, NULL);
        if (ok2) pthread_join(t2, NULL);
        relay_close_all(&rc);
        tconn_close(local);
        pthread_mutex_destroy(&rc.lock);
        return;
    }

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    relay_close_all(&rc);

    tconn_close(local);
    pthread_mutex_destroy(&rc.lock);
}

static void relay_workconn(tfrpc_config_t *cfg, const proxy_cfg_t *pxy, tconn_t *work) {
    int local_fd;

    local_fd = tcp_connect(pxy->local_ip, pxy->local_port, 10000);
    if (local_fd < 0) {
        log_msg(LOG_WARN, "proxy [%s] connect local %s:%d failed",
                pxy->name, pxy->local_ip, pxy->local_port);
        tconn_close(work);
        return;
    }
    if (pxy->use_encryption)
        enable_proxy_crypto(cfg, work);
    if (pxy->use_compression)
        tconn_enable_compression(work);

    log_msg(LOG_INFO, "proxy [%s] relay started (enc=%s, comp=%s)", pxy->name,
            pxy->use_encryption ? "aes-128-cfb" : "off",
            pxy->use_compression ? "snappy" : "off");

    relay_tunnel(work, local_fd);
    log_msg(LOG_INFO, "proxy [%s] relay closed", pxy->name);
}

/* ---------------- udp ---------------- */

typedef struct udp_peer {
    char key[96];
    char ip[64];
    int port;
    int fd;
    int64_t last_active;
    pthread_t reader;
    struct udp_state *st;
    struct udp_peer *next;
} udp_peer_t;

typedef struct udp_state {
    tconn_t *work;
    tfrpc_config_t *cfg;
    proxy_cfg_t *pxy;
    pthread_mutex_t lock;
    udp_peer_t *peers;
    _Atomic int closing;
} udp_state_t;

static udp_peer_t *udp_find(udp_state_t *st, const char *ip, int port) {
    udp_peer_t *p;
    char key[96];
    snprintf(key, sizeof(key), "%s:%d", ip, port);
    for (p = st->peers; p; p = p->next)
        if (strcmp(p->key, key) == 0)
            return p;
    return NULL;
}

static void udp_send_packet(udp_state_t *st, const uint8_t *content, size_t len,
                            const char *ip, int port) {
    int rc;
    if (st->cfg->wire_v2) {
        uint8_t body[1 + 8 + 2 + UDP_PACKET_SIZE];
        int blen = v2_udp_packet_encode(body, sizeof(body), content, len, ip, port);
        if (blen < 0)
            return;
        pthread_mutex_lock(&st->lock);
        if (!st->closing)
            rc = frp_send_msg(st->work, st->cfg, FRP_UDP_PACKET_BIN, (char *)body, blen);
        else
            rc = -1;
        pthread_mutex_unlock(&st->lock);
        (void)rc;
        return;
    }
    {
        json_buf_t b;
        jbuf_init(&b);
        jbuf_open(&b);
        jbuf_add_base64(&b, "c", content, len);
        jbuf_add_udpaddr(&b, "r", ip, port);
        jbuf_close(&b);
        pthread_mutex_lock(&st->lock);
        if (!st->closing)
            rc = frp_send_msg(st->work, st->cfg, FRP_UDP_PACKET, b.buf, b.len);
        else
            rc = -1;
        pthread_mutex_unlock(&st->lock);
        jbuf_free(&b);
        (void)rc;
    }
}

static void udp_send_ping(udp_state_t *st) {
    json_buf_t b;
    int rc;
    proto_build_ping(st->cfg, &b);
    pthread_mutex_lock(&st->lock);
    if (!st->closing)
        rc = frp_send_msg(st->work, st->cfg, FRP_PING, b.buf, b.len);
    else
        rc = -1;
    pthread_mutex_unlock(&st->lock);
    jbuf_free(&b);
    (void)rc;
}

/* reader thread for one connected UDP socket (local service replies) */
static void *udp_peer_reader(void *arg) {
    udp_peer_t *peer = arg;
    udp_state_t *st = peer->st;
    uint8_t buf[UDP_PACKET_SIZE];

    while (atomic_load(&g_running) && !atomic_load(&st->closing)) {
        struct pollfd pfd = {.fd = peer->fd, .events = POLLIN};
        int64_t idle;
        int pr;

        pr = poll(&pfd, 1, 1000);
        if (pr < 0 && errno != EINTR)
            break;

        pthread_mutex_lock(&st->lock);
        idle = mono_ms() - peer->last_active;
        pthread_mutex_unlock(&st->lock);
        if (idle > UDP_PEER_IDLE_MS)
            break;

        if (pr > 0 && (pfd.revents & POLLIN)) {
            ssize_t r = read(peer->fd, buf, sizeof(buf));
            if (r < 0)
                break;
            if (r == 0)
                continue;
            pthread_mutex_lock(&st->lock);
            peer->last_active = mono_ms();
            pthread_mutex_unlock(&st->lock);
            udp_send_packet(st, buf, (size_t)r, peer->ip, peer->port);
        }
    }
    return NULL;
}

static void udp_peer_remove(udp_state_t *st, udp_peer_t *peer) {
    udp_peer_t **pp;
    for (pp = &st->peers; *pp; pp = &(*pp)->next) {
        if (*pp == peer) {
            *pp = peer->next;
            break;
        }
    }
    close(peer->fd);
    free(peer);
}

/* create a connected UDP socket to the local service for a remote peer */
static udp_peer_t *udp_peer_create(udp_state_t *st, const char *ip, int port) {
    udp_peer_t *peer;
    struct sockaddr_storage addr;
    socklen_t alen;
    int family;
    char key[96];
    int fd;

    snprintf(key, sizeof(key), "%s:%d", ip, port);

    /* resolve the local service address: IPv4 or IPv6 */
    memset(&addr, 0, sizeof(addr));
    {
        struct sockaddr_in a4;
        struct sockaddr_in6 a6;
        memset(&a4, 0, sizeof(a4));
        memset(&a6, 0, sizeof(a6));
        a4.sin_family = AF_INET;
        a4.sin_port = htons((uint16_t)st->pxy->local_port);
        a6.sin6_family = AF_INET6;
        a6.sin6_port = htons((uint16_t)st->pxy->local_port);
        if (inet_pton(AF_INET, st->pxy->local_ip, &a4.sin_addr) == 1) {
            family = AF_INET;
            memcpy(&addr, &a4, sizeof(a4));
            alen = sizeof(a4);
        } else if (inet_pton(AF_INET6, st->pxy->local_ip, &a6.sin6_addr) == 1) {
            family = AF_INET6;
            memcpy(&addr, &a6, sizeof(a6));
            alen = sizeof(a6);
        } else {
            family = AF_INET;
            a4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            memcpy(&addr, &a4, sizeof(a4));
            alen = sizeof(a4);
        }
    }

    fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return NULL;

    if (connect(fd, (struct sockaddr *)&addr, alen) < 0) {
        close(fd);
        return NULL;
    }

    peer = calloc(1, sizeof(*peer));
    if (!peer) {
        close(fd);
        return NULL;
    }
    snprintf(peer->key, sizeof(peer->key), "%s", key);
    snprintf(peer->ip, sizeof(peer->ip), "%s", ip);
    peer->port = port;
    peer->fd = fd;
    peer->st = st;
    peer->last_active = mono_ms();
    peer->next = st->peers;
    st->peers = peer;

    if (pthread_create(&peer->reader, NULL, udp_peer_reader, peer) != 0) {
        udp_peer_remove(st, peer);
        return NULL;
    }
    return peer;
}

/* udp handler: main work-conn thread reads tunnel packets, dispatches to peers */
static void udp_workconn(tfrpc_config_t *cfg, const proxy_cfg_t *pxy, tconn_t *work) {
    udp_state_t st;
    int64_t last_heartbeat = mono_ms();

    memset(&st, 0, sizeof(st));
    st.work = work;
    st.cfg = cfg;
    st.pxy = (proxy_cfg_t *)pxy;
    pthread_mutex_init(&st.lock, NULL);

    if (pxy->use_encryption)
        enable_proxy_crypto(cfg, work);
    if (pxy->use_compression)
        tconn_enable_compression(work);

    log_msg(LOG_INFO, "proxy [%s] udp tunnel started (enc=%s, comp=%s)", pxy->name,
            pxy->use_encryption ? "aes-128-cfb" : "off",
            pxy->use_compression ? "snappy" : "off");

    while (atomic_load(&g_running) && !atomic_load(&st.closing)) {
        int64_t now = mono_ms();

        if (now - last_heartbeat >= UDP_HEARTBEAT_INTERVAL * 1000) {
            udp_send_ping(&st);
            last_heartbeat = now;
        }

        if (!tconn_wait_readable(work, 1000))
            continue;

        {
            char *payload = NULL;
            size_t plen = 0;
            frp_msg_t mtype;
            if (frp_recv_msg(work, cfg, &mtype, &payload, &plen) < 0)
                break;
            if (mtype == FRP_UDP_PACKET || mtype == FRP_UDP_PACKET_BIN) {
                uint8_t content[UDP_PACKET_SIZE];
                size_t content_len = 0;
                char rip[64];
                int rport = 0;
                int ok = 0;
                if (mtype == FRP_UDP_PACKET_BIN) {
                    ok = v2_udp_packet_decode((const uint8_t *)payload, plen,
                                              content, sizeof(content), &content_len,
                                              rip, sizeof(rip), &rport) == 0;
                } else {
                    ok = jget_base64(payload, "c", content, sizeof(content), &content_len) &&
                         jget_udpaddr(payload, "r", rip, sizeof(rip), &rport);
                }
                if (ok) {
                    udp_peer_t *peer;
                    pthread_mutex_lock(&st.lock);
                    peer = udp_find(&st, rip, rport);
                    if (!peer)
                        peer = udp_peer_create(&st, rip, rport);
                    if (peer) {
                        peer->last_active = mono_ms();
                        if (content_len > 0)
                            (void)write(peer->fd, content, content_len);
                    }
                    pthread_mutex_unlock(&st.lock);
                }
            }
            free(payload);
        }
    }

    /* teardown: detach the peer list under the lock, then join each reader
       without holding it (the reader takes st.lock between polls, so joining
       while holding the lock could deadlock).  Readers notice st.closing and
       exit within one poll timeout; only then is the fd closed. */
    pthread_mutex_lock(&st.lock);
    atomic_store(&st.closing, 1);
    udp_peer_t *peers = st.peers;
    st.peers = NULL;
    pthread_mutex_unlock(&st.lock);
    while (peers) {
        udp_peer_t *p = peers;
        peers = p->next;
        pthread_join(p->reader, NULL);
        close(p->fd);
        free(p);
    }

    tconn_close(work);
    pthread_mutex_destroy(&st.lock);
    log_msg(LOG_INFO, "proxy [%s] udp tunnel closed", pxy->name);
}

/* ---------------- entry point ---------------- */

void workconn_start(tfrpc_config_t *cfg) {
    tconn_t *work;
    char *payload = NULL;
    size_t plen = 0;
    frp_msg_t type;
    char proxy_name[MAX_NAME_LEN] = "";
    proxy_cfg_t *pxy;
    json_buf_t b;

    work = open_frp_conn(cfg);
    if (!work) {
        log_msg(LOG_WARN, "work conn connect failed");
        return;
    }
    /* v2 work connections carry the magic (no ClientHello) so frps detects v2 */
    if (cfg->wire_v2) {
        static const char magic[] = "FRP\x00\x02\r\n";
        if (tconn_write_full(work, magic, 7) < 0) {
            tconn_close(work);
            return;
        }
    }

    proto_build_new_work_conn(cfg, &b);
    if (frp_send_msg(work, cfg, FRP_NEW_WORK_CONN, b.buf, b.len) < 0) {
        jbuf_free(&b);
        tconn_close(work);
        return;
    }
    jbuf_free(&b);

    if (frp_recv_msg(work, cfg, &type, &payload, &plen) < 0) {
        tconn_close(work);
        return;
    }
    if (type != FRP_START_WORK_CONN) {
        log_msg(LOG_WARN, "work conn unexpected response type %d", type);
        free(payload);
        tconn_close(work);
        return;
    }

    {
        char err[256] = "";
        jget_str(payload, "error", err, sizeof(err));
        if (err[0]) {
            log_msg(LOG_WARN, "work conn rejected: %s", err);
            free(payload);
            tconn_close(work);
            return;
        }
    }
    jget_str(payload, "proxy_name", proxy_name, sizeof(proxy_name));
    free(payload);

    strip_user_prefix(proxy_name, cfg->user);
    pxy = find_proxy(cfg, proxy_name);
    if (!pxy) {
        log_msg(LOG_WARN, "work conn for unknown proxy [%s]", proxy_name);
        tconn_close(work);
        return;
    }

    switch (pxy->type) {
    case PROXY_TCP:
    case PROXY_HTTP:
    case PROXY_HTTPS:
        relay_workconn(cfg, pxy, work);
        break;
    case PROXY_UDP:
        udp_workconn(cfg, pxy, work);
        break;
    }
}
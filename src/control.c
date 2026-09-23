/*
 * SPDX-License-Identifier: GPL-3.0-only
 * control.c - the frps control connection: login, register proxies,
 * heartbeat, dispatch work connections, and reconnect on failure.
 *
 * Supports both tcpMux (yamux) and plain TCP per the frp wire protocol.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>

#include "tfrpc.h"
#include "kcp.h"
#include "tls.h"

#define T_LOGIN_RESP      '1'

void *g_session = NULL;      /* yamux session, or NULL when tcpMux off */
_Atomic int g_login_rejected = 0;   /* set when the server rejects the login */
extern _Atomic int g_running;      /* global stop flag */

/* yamux transport adapters for a TLS session */
static int tls_yamux_read(void *ctx, void *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        int r = tls_read((tls_conn_t *)ctx, (uint8_t *)buf + done, n - done);
        if (r <= 0)
            return -1;
        done += (size_t)r;
    }
    return 0;
}

static int tls_yamux_write(void *ctx, const void *buf, size_t n) {
    return tls_write((tls_conn_t *)ctx, buf, n);
}

static void tls_yamux_shutdown(void *ctx) {
    tls_shutdown((tls_conn_t *)ctx);
}

static void tls_yamux_close(void *ctx) {
    tls_close((tls_conn_t *)ctx);
}

/* combined TLS-over-KCP context used when both KCP and TLS are enabled */
typedef struct {
    void *tls;
    void *kcp;
} kcp_tls_ctx_t;

static int kcptls_read(void *ctx, void *buf, size_t n) {
    kcp_tls_ctx_t *c = ctx;
    size_t done = 0;
    while (done < n) {
        int r = tls_read((tls_conn_t *)c->tls, (uint8_t *)buf + done, n - done);
        if (r <= 0)
            return -1;
        done += (size_t)r;
    }
    return 0;
}

static int kcptls_write(void *ctx, const void *buf, size_t n) {
    kcp_tls_ctx_t *c = ctx;
    return tls_write((tls_conn_t *)c->tls, buf, n);   /* 0 on success, -1 on error */
}

static void kcptls_shutdown(void *ctx) {
    kcp_tls_ctx_t *c = ctx;
    kcp_abort((kcpconn_t *)c->kcp);   /* wake blocked readers/writers */
}

static void kcptls_close(void *ctx) {
    kcp_tls_ctx_t *c = ctx;
    if (c->tls)
        tls_close((tls_conn_t *)c->tls);
    if (c->kcp)
        kcp_close((kcpconn_t *)c->kcp);
    free(c);
}

/* yamux transport adapters for a KCP session (kcpconn) */
static int kcp_yamux_read(void *ctx, void *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        int r = kcp_read((kcpconn_t *)ctx, (uint8_t *)buf + done, (int)(n - done));
        if (r <= 0)
            return -1;
        done += (size_t)r;
    }
    return 0;
}

static int kcp_yamux_write(void *ctx, const void *buf, size_t n) {
    if (n > 0x7fffffff)
        return -1;
    return kcp_write((kcpconn_t *)ctx, buf, (int)n);
}

static void kcp_yamux_shutdown(void *ctx) {
    kcp_abort((kcpconn_t *)ctx);
}

static void kcp_yamux_close(void *ctx) {
    kcp_close((kcpconn_t *)ctx);
}

/* active (detached) work-conn threads: teardown waits for them so the yamux
 * session's transport is not freed while a relay thread is still using it */
static pthread_mutex_t g_wc_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_wc_cond = PTHREAD_COND_INITIALIZER;
static int g_wc_active = 0;

static void *workconn_thread(void *arg) {
    workconn_start((tfrpc_config_t *)arg);
    pthread_mutex_lock(&g_wc_lock);
    g_wc_active--;
    pthread_cond_broadcast(&g_wc_cond);
    pthread_mutex_unlock(&g_wc_lock);
    return NULL;
}

/* wait until every detached work-conn thread has exited (bounded) */
static void workconn_wait_all(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;
    pthread_mutex_lock(&g_wc_lock);
    while (g_wc_active > 0)
        if (pthread_cond_timedwait(&g_wc_cond, &g_wc_lock, &ts) != 0)
            break;
    pthread_mutex_unlock(&g_wc_lock);
}

/* open a connection to frps: a yamux stream if mux is on, else a new
 * TCP or KCP connection depending on transport.protocol. */
tconn_t *open_frp_conn(tfrpc_config_t *cfg) {
    if (cfg->tcp_mux) {
        if (g_session)
            return tconn_stream(g_session);
        return NULL;
    }
    if (cfg->protocol_kcp) {
        kcpconn_t *k = kcp_dial(cfg->server_addr, (uint16_t)cfg->server_port, 10000);
        if (!k)
            return NULL;
        if (cfg->tls_enable) {
            void *tls = tconn_tls_wrap_kcp(cfg, k);
            if (!tls) {
                log_msg(LOG_WARN, "TLS handshake with %s:%d failed (kcp)",
                        cfg->server_addr, cfg->server_port);
                kcp_close(k);
                return NULL;
            }
            return tconn_kcp_tls(k, tls);
        }
        return tconn_kcp(k);
    }
    int fd = tcp_connect(cfg->server_addr, cfg->server_port, 10000);
    if (fd < 0)
        return NULL;
    void *tls = tconn_tls_wrap(cfg, fd);
    if (cfg->tls_enable && !tls) {
        log_msg(LOG_WARN, "TLS handshake with %s:%d failed", cfg->server_addr, cfg->server_port);
        close(fd);
        return NULL;
    }
    if (tls)
        return tconn_socket_tls(fd, tls);
    return tconn_socket(fd);
}

/* spawn a detached work-connection thread (used by both the registration
 * phase and the main control loop when frps sends ReqWorkConn) */
static void spawn_workconn_thread(tfrpc_config_t *cfg) {
    pthread_t th;
    pthread_mutex_lock(&g_wc_lock);
    g_wc_active++;
    pthread_mutex_unlock(&g_wc_lock);
    if (pthread_create(&th, NULL, workconn_thread, (void *)cfg) == 0) {
        pthread_detach(th);
    } else {
        pthread_mutex_lock(&g_wc_lock);
        g_wc_active--;
        pthread_mutex_unlock(&g_wc_lock);
    }
}

/* register every proxy; returns 0 on success */
static int register_proxies(tconn_t *ctl, tfrpc_config_t *cfg) {
    int i;
    for (i = 0; i < cfg->proxy_count; i++) {
        char *payload = NULL;
        size_t plen = 0;
        frp_msg_t type;
        json_buf_t b;
        proto_build_new_proxy(&cfg->proxies[i], &b);
        if (frp_send_msg(ctl, cfg, FRP_NEW_PROXY, b.buf, b.len) < 0) {
            jbuf_free(&b);
            return -1;
        }
        jbuf_free(&b);
        /* wait for this proxy's response; frps may interleave ReqWorkConn
           messages, which must be served without losing the response */
        for (;;) {
            if (frp_recv_msg(ctl, cfg, &type, &payload, &plen) < 0) {
                free(payload);
                return -1;
            }
            if (type == FRP_REQ_WORK_CONN) {
                spawn_workconn_thread(cfg);
                free(payload);
                continue;
            }
            break;
        }
        if (type == FRP_NEW_PROXY_RESP) {
            char err[256] = "";
            char remote[256] = "";
            jget_str(payload, "error", err, sizeof(err));
            jget_str(payload, "remote_addr", remote, sizeof(remote));
            if (err[0]) {
                log_msg(LOG_ERROR, "proxy [%s] register failed: %s",
                        cfg->proxies[i].name, err);
                free(payload);
                continue;   /* a failed proxy does not tear down the session */
            }
            log_msg(LOG_INFO, "proxy [%s] ready, remote %s",
                    cfg->proxies[i].name, remote);
        } else {
            log_msg(LOG_WARN, "unexpected message type %d while registering", type);
        }
        free(payload);
    }
    return 0;
}

/* one full session: connect, login, register, then loop. returns on error. */
static void run_session(tfrpc_config_t *cfg) {
    tconn_t *ctl = NULL;
    kcpconn_t *kconn = NULL;
    int64_t last_ping, last_pong;
    int raw_fd = -1;

    if (cfg->tcp_mux) {
        if (cfg->protocol_kcp) {
            kconn = kcp_dial(cfg->server_addr, (uint16_t)cfg->server_port, 10000);
            if (!kconn) {
                log_msg(LOG_WARN, "kcp dial to %s:%d failed", cfg->server_addr, cfg->server_port);
                return;
            }
            if (cfg->tls_enable) {
                /* frp runs TLS over KCP; do the same so the session is
                   encrypted and tls.force on the server is satisfied */
                void *tls = tconn_tls_wrap_kcp(cfg, kconn);
                if (!tls) {
                    log_msg(LOG_WARN, "TLS handshake with %s:%d failed (kcp)",
                            cfg->server_addr, cfg->server_port);
                    kcp_close(kconn);
                    return;
                }
                kcp_tls_ctx_t *ctx = malloc(sizeof(*ctx));
                if (!ctx) {
                    tls_close((tls_conn_t *)tls);
                    kcp_close(kconn);
                    return;
                }
                ctx->tls = tls;
                ctx->kcp = kconn;
                g_session = yamux_client_new_io(kcptls_read, kcptls_write,
                                                kcptls_shutdown, kcptls_close, ctx);
            } else {
                g_session = yamux_client_new_io(kcp_yamux_read, kcp_yamux_write,
                                                kcp_yamux_shutdown, kcp_yamux_close, kconn);
            }
            if (!g_session) {
                log_msg(LOG_WARN, "create yamux session failed");
                kcp_close(kconn);
                return;
            }
        } else {
            raw_fd = tcp_connect(cfg->server_addr, cfg->server_port, 10000);
            if (raw_fd < 0) {
                log_msg(LOG_WARN, "connect to %s:%d failed", cfg->server_addr, cfg->server_port);
                return;
            }
            void *tls = tconn_tls_wrap(cfg, raw_fd);
            if (cfg->tls_enable && !tls) {
                log_msg(LOG_WARN, "TLS handshake with %s:%d failed", cfg->server_addr, cfg->server_port);
                close(raw_fd);
                return;
            }
            g_session = tls ? yamux_client_new_io(tls_yamux_read, tls_yamux_write,
                                                  tls_yamux_shutdown, tls_yamux_close, tls)
                            : yamux_client_new(raw_fd);
            if (!g_session) {
                if (tls)
                    tls_close(tls);   /* also closes the fd */
                else
                    close(raw_fd);
                return;
            }
        }
        ctl = tconn_stream(g_session);
        if (!ctl) {
            log_msg(LOG_WARN, "open control stream failed");
            yamux_close(g_session);
            g_session = NULL;
            return;
        }
        log_msg(LOG_INFO, "connected to %s:%d (tcpMux%s)", cfg->server_addr,
                cfg->server_port, cfg->protocol_kcp ? ", kcp" : "");
    } else {
        ctl = open_frp_conn(cfg);
        if (!ctl) {
            log_msg(LOG_WARN, "connect to %s:%d failed", cfg->server_addr, cfg->server_port);
            return;
        }
        if (cfg->protocol_kcp)
            kconn = ctl->kconn;
        log_msg(LOG_INFO, "connected to %s:%d%s", cfg->server_addr,
                cfg->server_port, cfg->protocol_kcp ? " (kcp)" : "");
    }

    /* a KCP "connect" is instant (UDP); a silent peer must not block the
       login handshake forever, so bound it with a deadline */
    if (cfg->protocol_kcp && kconn)
        kcp_set_deadline(kconn, 15000);

    if (cfg->wire_v2) {
        if (v2_client_handshake(ctl, cfg) < 0) {
            log_msg(LOG_ERROR, "v2 handshake failed");
            tconn_close(ctl);
            goto teardown;
        }
    } else {
        if (proto_send_login(ctl, cfg, cfg->run_id[0] ? cfg->run_id : NULL) < 0) {
            log_msg(LOG_WARN, "send login failed");
            tconn_close(ctl);
            goto teardown;
        }

        {
            char *payload = NULL;
            size_t plen = 0;
            int type = msg_read_t(ctl, &payload, &plen);
            if (type != T_LOGIN_RESP) {
                log_msg(LOG_ERROR, "login failed: unexpected response type %d", type);
                free(payload);
                tconn_close(ctl);
                goto teardown;
            }
            char err[256] = "";
            jget_str(payload, "error", err, sizeof(err));
            if (err[0]) {
                atomic_store(&g_login_rejected, 1);
                log_msg(LOG_ERROR, "login rejected: %s", err);
                free(payload);
                tconn_close(ctl);
                goto teardown;
            }
            jget_str(payload, "run_id", cfg->run_id, sizeof(cfg->run_id));
            free(payload);
            log_msg(LOG_INFO, "login ok, run id [%s], user [%s]", cfg->run_id, cfg->user);

            /* v1: after the plaintext login handshake, the control channel is
               encrypted with AES-128-CFB (golib crypto), key derived from token */
            {
                uint8_t key[16];
                derive_key(cfg->token, key, sizeof(key));
                tconn_enable_crypto(ctl, key);
            }
        }
    }

    if (register_proxies(ctl, cfg) < 0) {
        tconn_close(ctl);
        goto teardown;
    }

    if (cfg->protocol_kcp && kconn)
        kcp_set_deadline(kconn, 0);

    last_ping = last_pong = mono_ms();

    while (atomic_load(&g_running)) {
        int64_t now = mono_ms();

        if (now - last_ping >= CONTROL_HEARTBEAT_INTERVAL * 1000) {
            json_buf_t b;
            proto_build_ping(cfg, &b);
            int rc = frp_send_msg(ctl, cfg, FRP_PING, b.buf, b.len);
            jbuf_free(&b);
            if (rc < 0) {
                log_msg(LOG_WARN, "send ping failed");
                break;
            }
            last_ping = now;
        }
        if (now - last_pong >= CONTROL_HEARTBEAT_TIMEOUT * 1000) {
            log_msg(LOG_WARN, "heartbeat timeout, reconnecting");
            break;
        }

        if (!tconn_wait_readable(ctl, 500))
            continue;

        {
            char *payload = NULL;
            size_t plen = 0;
            frp_msg_t type;
            if (frp_recv_msg(ctl, cfg, &type, &payload, &plen) < 0) {
                log_msg(LOG_WARN, "control read error");
                free(payload);
                break;
            }
            switch (type) {
            case FRP_REQ_WORK_CONN:
                spawn_workconn_thread(cfg);
                break;
            case FRP_NEW_PROXY_RESP:
                break;
            case FRP_PONG: {
                char err[256] = "";
                jget_str(payload, "error", err, sizeof(err));
                if (err[0]) {
                    log_msg(LOG_ERROR, "pong error: %s", err);
                    free(payload);
                    goto session_end;
                }
                last_pong = mono_ms();
                break;
            }
            default:
                log_msg(LOG_DEBUG, "ignoring control message type %d", type);
                break;
            }
            free(payload);
        }
    }

session_end:
    tconn_close(ctl);

teardown:
    if (cfg->tcp_mux && g_session) {
        /* wake relay threads, let them exit, then release the transport */
        yamux_shutdown(g_session);
        workconn_wait_all();
        yamux_close(g_session);
        g_session = NULL;
    }
}

int control_run(tfrpc_config_t *cfg) {
    int fail_count = 0;
    while (atomic_load(&g_running)) {
        run_session(cfg);
        if (!atomic_load(&g_running))
            break;
        if (atomic_load(&g_login_rejected)) {
            if (cfg->login_fail_exit) {
                log_msg(LOG_ERROR, "login rejected by server, exiting");
                atomic_store(&g_running, 0);
                break;
            }
            atomic_store(&g_login_rejected, 0);  /* allow retry when loginFailExit is off */
        }
        fail_count++;
        int delay = fail_count < 3 ? 1 : (fail_count < 5 ? 5 : 10);
        log_msg(LOG_WARN, "reconnecting in %d seconds...", delay);
        /* interruptible wait: SIGTERM/SIGINT are delivered to the sigwait
           thread, which clears g_running; a plain sleep() would not be
           interrupted and could delay shutdown by up to 10 seconds */
        for (int i = 0; i < delay * 10 && atomic_load(&g_running); i++)
            usleep(100 * 1000);
    }
    return 0;
}
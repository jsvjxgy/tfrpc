/*
 * SPDX-License-Identifier: GPL-3.0-only
 * proto.c - frp v1 wire protocol.
 *
 * Message framing (golib/msg/json):
 *   [1 byte type][8 byte big-endian length][JSON payload]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>

#include "tfrpc.h"

/* message type bytes (pkg/msg/msg.go) */
#define T_LOGIN            'o'
#define T_NEW_PROXY        'p'
#define T_NEW_WORK_CONN    'w'
#define T_PING             'h'
#define T_UDP_PACKET       'u'

static int64_t now_ts(void) {
    return (int64_t)time(NULL);
}

int msg_write_t(tconn_t *c, uint8_t type, const char *json, size_t len) {
    uint8_t *frame;
    size_t frame_len = 9 + len;
    uint64_t be_len = (uint64_t)len;
    int i, rc;

    frame = malloc(frame_len);
    if (!frame)
        return -1;
    frame[0] = type;
    for (i = 0; i < 8; i++)
        frame[1 + i] = (uint8_t)(be_len >> (56 - i * 8));
    if (len > 0)
        memcpy(frame + 9, json, len);

    rc = tconn_write_full(c, frame, frame_len);
    free(frame);
    return rc;
}

/* returns type byte (0-255), -1 on error. *payload malloc'd. */
int msg_read_t(tconn_t *c, char **payload, size_t *payload_len) {
    uint8_t hdr[9];
    uint64_t len;
    int i;
    if (tconn_read_full(c, hdr, 9) < 0)
        return -1;
    len = 0;
    for (i = 0; i < 8; i++)
        len = (len << 8) | hdr[1 + i];
    if (len > MAX_MSG_LEN) {
        /* drain and fail */
        char tmp[1024];
        size_t left = len;
        while (left > 0) {
            size_t chunk = left > sizeof(tmp) ? sizeof(tmp) : left;
            if (tconn_read_full(c, tmp, chunk) < 0)
                break;
            left -= chunk;
        }
        return -1;
    }
    *payload = malloc(len + 1);
    if (*payload == NULL)
        return -1;
    if (len > 0 && tconn_read_full(c, *payload, (size_t)len) < 0) {
        free(*payload);
        return -1;
    }
    (*payload)[len] = '\0';
    *payload_len = (size_t)len;
    return hdr[0];
}

/* ------------------------- message builders ------------------------- */

void proto_build_login(tfrpc_config_t *cfg, const char *run_id, json_buf_t *b) {
    char key[33];
    char hostname[128] = "";
    int64_t ts = now_ts();

    gethostname(hostname, sizeof(hostname));
    md5_hex(cfg->token, ts, key);

    jbuf_init(b);
    jbuf_open(b);
    jbuf_add_str(b, "version", TFRPC_VERSION);
    jbuf_add_str(b, "hostname", hostname);
    jbuf_add_str(b, "os", "linux");
#ifdef __mips__
    jbuf_add_str(b, "arch", "mips");
#else
    jbuf_add_str(b, "arch", "x86");
#endif
    jbuf_add_str(b, "user", cfg->user);
    jbuf_add_str(b, "privilege_key", key);
    jbuf_add_int(b, "timestamp", ts);
    if (run_id && run_id[0])
        jbuf_add_str(b, "run_id", run_id);
    jbuf_add_int(b, "pool_count", cfg->pool_count);
    jbuf_close(b);
}

void proto_build_new_proxy(const proxy_cfg_t *pxy, json_buf_t *b) {
    jbuf_init(b);
    jbuf_open(b);
    jbuf_add_str(b, "proxy_name", pxy->name);
    switch (pxy->type) {
    case PROXY_TCP:  jbuf_add_str(b, "proxy_type", "tcp"); break;
    case PROXY_UDP:  jbuf_add_str(b, "proxy_type", "udp"); break;
    case PROXY_HTTP: jbuf_add_str(b, "proxy_type", "http"); break;
    case PROXY_HTTPS:jbuf_add_str(b, "proxy_type", "https"); break;
    }
    jbuf_add_bool(b, "use_encryption", pxy->use_encryption);
    jbuf_add_bool(b, "use_compression", pxy->use_compression);
    if (pxy->type == PROXY_TCP || pxy->type == PROXY_UDP) {
        jbuf_add_int(b, "remote_port", pxy->remote_port);
    } else {
        /* http/https: custom_domains array */
        int i;
        jbuf_add_key(b, "custom_domains");
        jbuf_append_raw(b, "[", 1);
        for (i = 0; i < pxy->custom_domains_count; i++) {
            if (i > 0)
                jbuf_append_raw(b, ",", 1);
            json_escape_str(b, pxy->custom_domains[i]);
        }
        jbuf_append_raw(b, "]", 1);
    }
    jbuf_close(b);
}

void proto_build_new_work_conn(tfrpc_config_t *cfg, json_buf_t *b) {
    char key[33];
    int64_t ts = now_ts();
    md5_hex(cfg->token, ts, key);
    jbuf_init(b);
    jbuf_open(b);
    jbuf_add_str(b, "run_id", cfg->run_id);
    jbuf_add_str(b, "privilege_key", key);
    jbuf_add_int(b, "timestamp", ts);
    jbuf_close(b);
}

void proto_build_ping(tfrpc_config_t *cfg, json_buf_t *b) {
    char key[33];
    int64_t ts = now_ts();
    md5_hex(cfg->token, ts, key);
    jbuf_init(b);
    jbuf_open(b);
    jbuf_add_str(b, "privilege_key", key);
    jbuf_add_int(b, "timestamp", ts);
    jbuf_close(b);
}

int proto_send_login(tconn_t *c, tfrpc_config_t *cfg, const char *run_id) {
    json_buf_t b;
    int rc;
    proto_build_login(cfg, run_id, &b);
    rc = msg_write_t(c, T_LOGIN, b.buf, b.len);
    jbuf_free(&b);
    return rc;
}

int proto_send_new_proxy(tconn_t *c, const proxy_cfg_t *pxy) {
    json_buf_t b;
    int rc;
    proto_build_new_proxy(pxy, &b);
    rc = msg_write_t(c, T_NEW_PROXY, b.buf, b.len);
    jbuf_free(&b);
    return rc;
}

int proto_send_new_work_conn(tconn_t *c, tfrpc_config_t *cfg) {
    json_buf_t b;
    int rc;
    proto_build_new_work_conn(cfg, &b);
    rc = msg_write_t(c, T_NEW_WORK_CONN, b.buf, b.len);
    jbuf_free(&b);
    return rc;
}

int proto_send_ping(tconn_t *c, tfrpc_config_t *cfg) {
    json_buf_t b;
    int rc;
    proto_build_ping(cfg, &b);
    rc = msg_write_t(c, T_PING, b.buf, b.len);
    jbuf_free(&b);
    return rc;
}

int proto_send_udp_packet(tconn_t *c, const uint8_t *content, size_t len,
                          const char *remote_ip, int remote_port) {
    json_buf_t b;
    int rc;
    jbuf_init(&b);
    jbuf_open(&b);
    jbuf_add_base64(&b, "c", content, len);
    jbuf_add_udpaddr(&b, "r", remote_ip, remote_port);
    jbuf_close(&b);
    rc = msg_write_t(c, T_UDP_PACKET, b.buf, b.len);
    jbuf_free(&b);
    return rc;
}
/* ------------------- protocol-independent message I/O ------------------- */

static int frp_v1_byte(frp_msg_t t) {
    switch (t) {
    case FRP_LOGIN: return 'o';
    case FRP_LOGIN_RESP: return '1';
    case FRP_NEW_PROXY: return 'p';
    case FRP_NEW_PROXY_RESP: return '2';
    case FRP_NEW_WORK_CONN: return 'w';
    case FRP_REQ_WORK_CONN: return 'r';
    case FRP_START_WORK_CONN: return 's';
    case FRP_PING: return 'h';
    case FRP_PONG: return '4';
    case FRP_UDP_PACKET: return 'u';
    default: return '?';
    }
}

static int frp_v2_id(frp_msg_t t) {
    switch (t) {
    case FRP_LOGIN: return 1;
    case FRP_LOGIN_RESP: return 2;
    case FRP_NEW_PROXY: return 3;
    case FRP_NEW_PROXY_RESP: return 4;
    case FRP_NEW_WORK_CONN: return 6;
    case FRP_REQ_WORK_CONN: return 7;
    case FRP_START_WORK_CONN: return 8;
    case FRP_PING: return 11;
    case FRP_PONG: return 12;
    case FRP_UDP_PACKET: return 13;
    case FRP_UDP_PACKET_BIN: return 19;
    default: return -1;
    }
}

static frp_msg_t frp_v2_from_id(int id) {
    switch (id) {
    case 1: return FRP_LOGIN;
    case 2: return FRP_LOGIN_RESP;
    case 3: return FRP_NEW_PROXY;
    case 4: return FRP_NEW_PROXY_RESP;
    case 6: return FRP_NEW_WORK_CONN;
    case 7: return FRP_REQ_WORK_CONN;
    case 8: return FRP_START_WORK_CONN;
    case 11: return FRP_PING;
    case 12: return FRP_PONG;
    case 13: return FRP_UDP_PACKET;
    case 19: return FRP_UDP_PACKET_BIN;
    default: return FRP_PONG; /* unknown -> caller should ignore */
    }
}

int frp_send_msg(tconn_t *c, tfrpc_config_t *cfg, frp_msg_t type,
                 const char *json, size_t len) {
    if (cfg->wire_v2)
        return v2_msg_write(c, (uint16_t)frp_v2_id(type), json, len);
    return msg_write_t(c, (uint8_t)frp_v1_byte(type), json, len);
}

int frp_recv_msg(tconn_t *c, tfrpc_config_t *cfg, frp_msg_t *type,
                 char **json, size_t *len) {
    if (cfg->wire_v2) {
        uint16_t id;
        if (v2_msg_read(c, &id, json, len) < 0)
            return -1;
        *type = frp_v2_from_id((int)id);
        return 0;
    }
    {
        int t = msg_read_t(c, json, len);
        if (t < 0)
            return -1;
        switch (t) {
        case 'o': *type = FRP_LOGIN; break;
        case '1': *type = FRP_LOGIN_RESP; break;
        case 'p': *type = FRP_NEW_PROXY; break;
        case '2': *type = FRP_NEW_PROXY_RESP; break;
        case 'w': *type = FRP_NEW_WORK_CONN; break;
        case 'r': *type = FRP_REQ_WORK_CONN; break;
        case 's': *type = FRP_START_WORK_CONN; break;
        case 'h': *type = FRP_PING; break;
        case '4': *type = FRP_PONG; break;
        case 'u': *type = FRP_UDP_PACKET; break;
        default: *type = FRP_PONG; break;
        }
        return 0;
    }
}

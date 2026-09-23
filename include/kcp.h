/*
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef TFRPC_KCP_H
#define TFRPC_KCP_H

#include <stdint.h>
#include <stddef.h>

/* session layer (kcpconn.c) */
typedef struct kcpconn kcpconn_t;

kcpconn_t *kcp_dial(const char *host, uint16_t port, int timeout_ms);
int kcp_read(kcpconn_t *c, void *buf, int len);
int kcp_write(kcpconn_t *c, const void *buf, int len);
int kcp_wait_readable(kcpconn_t *c, int timeout_ms);
void kcp_set_deadline(kcpconn_t *c, int timeout_ms);
void kcp_close(kcpconn_t *c);
void kcp_abort(kcpconn_t *c);
int kcp_connected(kcpconn_t *c);

#ifdef __cplusplus
extern "C" {
#endif

#define KCP_RTO_NDL 30
#define KCP_RTO_MIN 100
#define KCP_RTO_DEF 200
#define KCP_RTO_MAX 60000
#define KCP_CMD_PUSH 81
#define KCP_CMD_ACK 82
#define KCP_CMD_WASK 83
#define KCP_CMD_WINS 84
#define KCP_ASK_SEND 1
#define KCP_ASK_TELL 2
#define KCP_WND_SND 32
#define KCP_WND_RCV 32
#define KCP_MTU_DEF 1400
#define KCP_ACK_FAST 3
#define KCP_INTERVAL 100
#define KCP_OVERHEAD 24
#define KCP_DEADLINK 20
#define KCP_THRESH_INIT 2
#define KCP_THRESH_MIN 2
#define KCP_PROBE_INIT 7000
#define KCP_PROBE_LIMIT 120000

typedef struct kcp_seg {
    uint32_t conv;
    uint8_t cmd;
    uint8_t frg;
    uint16_t wnd;
    uint32_t ts;
    uint32_t sn;
    uint32_t una;
    uint32_t rto;
    uint32_t xmit;
    uint32_t resendts;
    uint32_t fastack;
    uint32_t acked;
    uint8_t *data;
    int datalen;
    int datacap;
} kcp_seg_t;

typedef struct kcp_segq {
    kcp_seg_t *segs;
    int len;
    int cap;
} kcp_segq_t;

typedef struct kcp_ack {
    uint32_t sn;
    uint32_t ts;
} kcp_ack_t;

typedef struct kcp_ackq {
    kcp_ack_t *items;
    int len;
    int cap;
} kcp_ackq_t;

typedef struct kcp kcp_t;

typedef void (*kcp_output_cb)(const uint8_t *buf, int size, void *ud);

struct kcp {
    uint32_t conv, mtu, mss, state;
    uint32_t snd_una, snd_nxt, rcv_nxt;
    uint32_t ssthresh;
    int32_t rx_rttvar, rx_srtt;
    uint32_t rx_rto, rx_minrto;
    uint32_t snd_wnd, rcv_wnd, rmt_wnd, cwnd, probe;
    uint32_t interval, ts_flush;
    uint32_t nodelay, updated;
    uint32_t ts_probe, probe_wait;
    uint32_t dead_link, incr;
    int32_t fastresend;
    int32_t nocwnd, stream;

    kcp_segq_t snd_queue;
    kcp_segq_t rcv_queue;
    kcp_segq_t snd_buf;
    kcp_segq_t rcv_buf;
    kcp_ackq_t acklist;

    uint8_t *buffer;
    kcp_output_cb output;
    void *output_ud;
};

uint32_t kcp_current_ms(void);

kcp_t *kcp_create(uint32_t conv, kcp_output_cb output, void *ud);
void kcp_release(kcp_t *kcp);
int kcp_setmtu(kcp_t *kcp, int mtu);
int kcp_nodelay(kcp_t *kcp, int nodelay, int interval, int resend, int nc);
int kcp_wndsize(kcp_t *kcp, int sndwnd, int rcvwnd);
int kcp_wait_snd(kcp_t *kcp);
int kcp_peek_size(kcp_t *kcp);
int kcp_recv(kcp_t *kcp, uint8_t *buffer, int len);
int kcp_send(kcp_t *kcp, const uint8_t *buffer, int len);
void kcp_input(kcp_t *kcp, const uint8_t *data, int len, int regular, int ack_nodelay);
void kcp_flush(kcp_t *kcp, int ack_only);
void kcp_update(kcp_t *kcp, uint32_t current);

#ifdef __cplusplus
}
#endif

#endif
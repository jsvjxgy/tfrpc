/*
 * SPDX-License-Identifier: GPL-3.0-only kcp.c - KCP reliable UDP protocol core (client role).
 * Faithful C port of kcp-go v5.6.13 kcp.go so the wire format matches frps
 * byte-for-byte.  This file is the pure state machine; the UDP session,
 * threading and FEC framing live in kcpconn.c. */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "kcp.h"

static inline uint32_t k_imin(uint32_t a, uint32_t b) { return a <= b ? a : b; }
static inline uint32_t k_imax(uint32_t a, uint32_t b) { return a >= b ? a : b; }
static inline uint32_t k_ibound(uint32_t lo, uint32_t mid, uint32_t hi) {
    return k_imin(k_imax(lo, mid), hi);
}
static inline int32_t k_itimediff(uint32_t later, uint32_t earlier) {
    return (int32_t)(later - earlier);
}

uint32_t kcp_current_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static int segq_append(kcp_segq_t *q, kcp_seg_t *seg) {
    if (q->len >= q->cap) {
        int ncap = q->cap ? q->cap * 2 : 32;
        kcp_seg_t *ns = realloc(q->segs, (size_t)ncap * sizeof(kcp_seg_t));
        if (!ns)
            return -1;   /* out of memory */
        q->segs = ns;
        q->cap = ncap;
    }
    q->segs[q->len++] = *seg;
    return 0;
}

static void segq_remove_front(kcp_segq_t *q, int n) {
    for (int i = 0; i < n; i++) {
        if (q->segs[i].data)
            free(q->segs[i].data);
    }
    if (n >= q->len) {
        q->len = 0;
        return;
    }
    memmove(q->segs, q->segs + n, (size_t)(q->len - n) * sizeof(kcp_seg_t));
    q->len -= n;
}

/* remove front entries without freeing their data: used when ownership of the
 * segment data moves to another queue (snd_queue->snd_buf, rcv_buf->rcv_queue) */
static void segq_remove_front_nofree(kcp_segq_t *q, int n) {
    if (n >= q->len) {
        q->len = 0;
        return;
    }
    memmove(q->segs, q->segs + n, (size_t)(q->len - n) * sizeof(kcp_seg_t));
    q->len -= n;
}

static void segq_clear(kcp_segq_t *q) {
    for (int i = 0; i < q->len; i++)
        if (q->segs[i].data)
            free(q->segs[i].data);
    free(q->segs);
    q->segs = NULL;
    q->len = q->cap = 0;
}

static void ackq_append(kcp_ackq_t *q, uint32_t sn, uint32_t ts) {
    if (q->len >= q->cap) {
        int ncap = q->cap ? q->cap * 2 : 64;
        kcp_ack_t *ni = realloc(q->items, (size_t)ncap * sizeof(kcp_ack_t));
        if (!ni)
            return;   /* out of memory: drop this ack (peer will retransmit) */
        q->items = ni;
        q->cap = ncap;
    }
    q->items[q->len].sn = sn;
    q->items[q->len].ts = ts;
    q->len++;
}

kcp_t *kcp_create(uint32_t conv, kcp_output_cb output, void *ud) {
    kcp_t *kcp = calloc(1, sizeof(kcp_t));
    if (!kcp)
        return NULL;
    kcp->conv = conv;
    kcp->snd_wnd = KCP_WND_SND;
    kcp->rcv_wnd = KCP_WND_RCV;
    kcp->rmt_wnd = KCP_WND_RCV;
    kcp->mtu = KCP_MTU_DEF;
    kcp->mss = KCP_MTU_DEF - KCP_OVERHEAD;
    kcp->buffer = malloc(KCP_MTU_DEF);
    if (!kcp->buffer) {
        free(kcp);
        return NULL;
    }
    kcp->rx_rto = KCP_RTO_DEF;
    kcp->rx_minrto = KCP_RTO_MIN;
    kcp->interval = KCP_INTERVAL;
    kcp->ts_flush = KCP_INTERVAL;
    kcp->ssthresh = KCP_THRESH_INIT;
    kcp->dead_link = KCP_DEADLINK;
    kcp->output = output;
    kcp->output_ud = ud;
    return kcp;
}

void kcp_release(kcp_t *kcp) {
    if (!kcp)
        return;
    segq_clear(&kcp->snd_queue);
    segq_clear(&kcp->rcv_queue);
    segq_clear(&kcp->snd_buf);
    segq_clear(&kcp->rcv_buf);
    free(kcp->acklist.items);
    free(kcp->buffer);
    free(kcp);
}

int kcp_setmtu(kcp_t *kcp, int mtu) {
    if (mtu < 50 || mtu < KCP_OVERHEAD)
        return -1;
    uint8_t *nb = malloc((size_t)mtu);
    if (!nb)
        return -2;
    free(kcp->buffer);
    kcp->buffer = nb;
    kcp->mtu = (uint32_t)mtu;
    kcp->mss = (uint32_t)mtu - KCP_OVERHEAD;
    return 0;
}

int kcp_nodelay(kcp_t *kcp, int nodelay, int interval, int resend, int nc) {
    if (nodelay >= 0) {
        kcp->nodelay = (uint32_t)nodelay;
        kcp->rx_minrto = nodelay != 0 ? KCP_RTO_NDL : KCP_RTO_MIN;
    }
    if (interval >= 0) {
        if (interval > 5000)
            interval = 5000;
        else if (interval < 10)
            interval = 10;
        kcp->interval = (uint32_t)interval;
    }
    if (resend >= 0)
        kcp->fastresend = resend;
    if (nc >= 0)
        kcp->nocwnd = nc;
    return 0;
}

int kcp_wndsize(kcp_t *kcp, int sndwnd, int rcvwnd) {
    if (sndwnd > 0)
        kcp->snd_wnd = (uint32_t)sndwnd;
    if (rcvwnd > 0)
        kcp->rcv_wnd = (uint32_t)rcvwnd;
    return 0;
}

int kcp_wait_snd(kcp_t *kcp) {
    return kcp->snd_buf.len + kcp->snd_queue.len;
}

int kcp_peek_size(kcp_t *kcp) {
    if (kcp->rcv_queue.len == 0)
        return -1;
    kcp_seg_t *seg = &kcp->rcv_queue.segs[0];
    if (seg->frg == 0)
        return seg->datalen;
    if (kcp->rcv_queue.len < (int)seg->frg + 1)
        return -1;
    int length = 0;
    for (int k = 0; k < kcp->rcv_queue.len; k++) {
        seg = &kcp->rcv_queue.segs[k];
        length += seg->datalen;
        if (seg->frg == 0)
            break;
    }
    return length;
}

static void kcp_del_seg(kcp_seg_t *seg) {
    if (seg->data) {
        free(seg->data);
        seg->data = NULL;
        seg->datalen = 0;
    }
}

int kcp_recv(kcp_t *kcp, uint8_t *buffer, int len) {
    if (len <= 0 || !buffer)
        return -1;
    int peeksize = kcp_peek_size(kcp);
    if (peeksize < 0)
        return -1;
    if (peeksize > len)
        return -2;

    int fast_recover = 0;
    if (kcp->rcv_queue.len >= (int)kcp->rcv_wnd)
        fast_recover = 1;

    int count = 0;
    int n = 0;
    while (count < kcp->rcv_queue.len) {
        kcp_seg_t *seg = &kcp->rcv_queue.segs[count];
        memcpy(buffer, seg->data, (size_t)seg->datalen);
        buffer += seg->datalen;
        n += seg->datalen;
        count++;
        kcp_del_seg(seg);
        if (seg->frg == 0)
            break;
    }
    if (count > 0)
        segq_remove_front(&kcp->rcv_queue, count);

    count = 0;
    while (count < kcp->rcv_buf.len) {
        kcp_seg_t *seg = &kcp->rcv_buf.segs[count];
        if (seg->sn == kcp->rcv_nxt && kcp->rcv_queue.len + count < (int)kcp->rcv_wnd) {
            kcp->rcv_nxt++;
            count++;
        } else {
            break;
        }
    }
    if (count > 0) {
        for (int i = 0; i < count; i++)
            segq_append(&kcp->rcv_queue, &kcp->rcv_buf.segs[i]);
        segq_remove_front_nofree(&kcp->rcv_buf, count);
    }

    if (kcp->rcv_queue.len < (int)kcp->rcv_wnd && fast_recover)
        kcp->probe |= KCP_ASK_TELL;

    return n;
}

static kcp_seg_t *kcp_new_seg(int size) {
    kcp_seg_t *seg = calloc(1, sizeof(kcp_seg_t));
    if (!seg)
        return NULL;
    if (size > 0) {
        seg->data = malloc((size_t)size);
        if (!seg->data) {
            free(seg);
            return NULL;
        }
        seg->datacap = size;
        seg->datalen = size;
    }
    return seg;
}

int kcp_send(kcp_t *kcp, const uint8_t *buffer, int len) {
    if (len <= 0 || !buffer)
        return -1;
    const uint8_t *buf = buffer;

    /* append to previous segment in streaming mode if possible */
    if (kcp->stream != 0) {
        int n = kcp->snd_queue.len;
        if (n > 0) {
            kcp_seg_t *seg = &kcp->snd_queue.segs[n - 1];
            if (seg->datalen < (int)kcp->mss) {
                int capacity = (int)kcp->mss - seg->datalen;
                int extend = capacity < len ? capacity : len;
                if (seg->datalen + extend > seg->datacap) {
                    uint8_t *nd = realloc(seg->data, (size_t)seg->datalen + extend);
                    if (!nd)
                        return -3;   /* out of memory */
                    seg->data = nd;
                    seg->datacap = seg->datalen + extend;
                }
                memcpy(seg->data + seg->datalen, buf, (size_t)extend);
                seg->datalen += extend;
                buf += extend;
                len -= extend;
            }
        }
        if (len == 0)
            return 0;
    }

    int count;
    if (len <= (int)kcp->mss)
        count = 1;
    else
        count = (len + (int)kcp->mss - 1) / (int)kcp->mss;

    if (count > 255)
        return -2;
    if (count == 0)
        count = 1;

    for (int i = 0; i < count; i++) {
        int size = len > (int)kcp->mss ? (int)kcp->mss : len;
        if (size <= 0)
            return -3;
        kcp_seg_t *seg = kcp_new_seg(size);
        if (!seg)
            return -3;
        memcpy(seg->data, buf, (size_t)size);
        seg->frg = kcp->stream == 0 ? (uint8_t)(count - i - 1) : 0;
        if (segq_append(&kcp->snd_queue, seg) < 0) {
            free(seg->data);
            free(seg);
            return -3;
        }
        buf += size;
        len -= size;
        free(seg);
    }
    return 0;
}

static void kcp_update_ack(kcp_t *kcp, int32_t rtt) {
    uint32_t rto;
    if (kcp->rx_srtt == 0) {
        kcp->rx_srtt = rtt;
        kcp->rx_rttvar = rtt >> 1;
    } else {
        int32_t delta = rtt - kcp->rx_srtt;
        kcp->rx_srtt += delta >> 3;
        if (delta < 0)
            delta = -delta;
        if (rtt < kcp->rx_srtt - kcp->rx_rttvar)
            kcp->rx_rttvar += (delta - kcp->rx_rttvar) >> 5;
        else
            kcp->rx_rttvar += (delta - kcp->rx_rttvar) >> 2;
    }
    rto = (uint32_t)kcp->rx_srtt + k_imax(kcp->interval, (uint32_t)kcp->rx_rttvar << 2);
    kcp->rx_rto = k_ibound(kcp->rx_minrto, rto, KCP_RTO_MAX);
}

static void kcp_shrink_buf(kcp_t *kcp) {
    if (kcp->snd_buf.len > 0)
        kcp->snd_una = kcp->snd_buf.segs[0].sn;
    else
        kcp->snd_una = kcp->snd_nxt;
}

static void kcp_parse_ack(kcp_t *kcp, uint32_t sn) {
    if (k_itimediff(sn, kcp->snd_una) < 0 || k_itimediff(sn, kcp->snd_nxt) >= 0)
        return;
    for (int k = 0; k < kcp->snd_buf.len; k++) {
        kcp_seg_t *seg = &kcp->snd_buf.segs[k];
        if (sn == seg->sn) {
            seg->acked = 1;
            kcp_del_seg(seg);
            break;
        }
        if (k_itimediff(sn, seg->sn) < 0)
            break;
    }
}

static void kcp_parse_fastack(kcp_t *kcp, uint32_t sn, uint32_t ts) {
    if (k_itimediff(sn, kcp->snd_una) < 0 || k_itimediff(sn, kcp->snd_nxt) >= 0)
        return;
    for (int k = 0; k < kcp->snd_buf.len; k++) {
        kcp_seg_t *seg = &kcp->snd_buf.segs[k];
        if (k_itimediff(sn, seg->sn) < 0)
            break;
        else if (sn != seg->sn && k_itimediff(seg->ts, ts) <= 0)
            seg->fastack++;
    }
}

static int kcp_parse_una(kcp_t *kcp, uint32_t una) {
    int count = 0;
    while (count < kcp->snd_buf.len) {
        kcp_seg_t *seg = &kcp->snd_buf.segs[count];
        if (k_itimediff(una, seg->sn) > 0) {
            kcp_del_seg(seg);
            count++;
        } else {
            break;
        }
    }
    if (count > 0)
        segq_remove_front(&kcp->snd_buf, count);
    return count;
}

static int kcp_parse_data(kcp_t *kcp, kcp_seg_t *newseg) {
    uint32_t sn = newseg->sn;
    if (k_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) >= 0 ||
        k_itimediff(sn, kcp->rcv_nxt) < 0)
        return 1;

    int n = kcp->rcv_buf.len - 1;
    int insert_idx = 0;
    int repeat = 0;
    for (int i = n; i >= 0; i--) {
        kcp_seg_t *seg = &kcp->rcv_buf.segs[i];
        if (seg->sn == sn) {
            repeat = 1;
            break;
        }
        if (k_itimediff(sn, seg->sn) > 0) {
            insert_idx = i + 1;
            break;
        }
    }

    if (!repeat) {
        kcp_seg_t copy = *newseg;
        if (copy.datalen > 0) {
            copy.data = malloc((size_t)copy.datalen);
            if (!copy.data)
                return 1;   /* out of memory: treat as duplicate/drop */
            copy.datacap = copy.datalen;
            memcpy(copy.data, newseg->data, (size_t)copy.datalen);
        } else {
            copy.data = NULL;
            copy.datacap = 0;
        }

        if (insert_idx == n + 1) {
            if (segq_append(&kcp->rcv_buf, &copy) < 0) {
                free(copy.data);
                return 1;
            }
        } else {
            kcp_seg_t t;
            memset(&t, 0, sizeof(t));
            if (segq_append(&kcp->rcv_buf, &t) < 0) {   /* grow */
                free(copy.data);
                return 1;
            }
            memmove(&kcp->rcv_buf.segs[insert_idx + 1], &kcp->rcv_buf.segs[insert_idx],
                    (size_t)(kcp->rcv_buf.len - insert_idx - 1) * sizeof(kcp_seg_t));
            kcp->rcv_buf.segs[insert_idx] = copy;
        }
    }

    int count = 0;
    while (count < kcp->rcv_buf.len) {
        kcp_seg_t *seg = &kcp->rcv_buf.segs[count];
        if (seg->sn == kcp->rcv_nxt && kcp->rcv_queue.len + count < (int)kcp->rcv_wnd) {
            kcp->rcv_nxt++;
            count++;
        } else {
            break;
        }
    }
    if (count > 0) {
        for (int i = 0; i < count; i++)
            segq_append(&kcp->rcv_queue, &kcp->rcv_buf.segs[i]);
        segq_remove_front_nofree(&kcp->rcv_buf, count);
    }

    return repeat;
}

void kcp_input(kcp_t *kcp, const uint8_t *data, int len, int regular, int ack_nodelay) {
    uint32_t snd_una = kcp->snd_una;
    if (len < KCP_OVERHEAD)
        return;

    uint32_t latest = 0;
    int flag = 0;
    int window_slides = 0;
    const uint8_t *p = data;
    int rem = len;

    while (rem >= KCP_OVERHEAD) {
        uint32_t conv = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
        if (conv != kcp->conv)
            return;
        uint8_t cmd = p[4];
        uint8_t frg = p[5];
        uint16_t wnd = (uint16_t)(p[6] | p[7] << 8);
        uint32_t ts = (uint32_t)p[8] | (uint32_t)p[9] << 8 | (uint32_t)p[10] << 16 | (uint32_t)p[11] << 24;
        uint32_t sn = (uint32_t)p[12] | (uint32_t)p[13] << 8 | (uint32_t)p[14] << 16 | (uint32_t)p[15] << 24;
        uint32_t una = (uint32_t)p[16] | (uint32_t)p[17] << 8 | (uint32_t)p[18] << 16 | (uint32_t)p[19] << 24;
        uint32_t length = (uint32_t)p[20] | (uint32_t)p[21] << 8 | (uint32_t)p[22] << 16 | (uint32_t)p[23] << 24;
        if (length > (uint32_t)(rem - KCP_OVERHEAD))   /* unsigned compare: no sign overflow */
            return;

        if (cmd != KCP_CMD_PUSH && cmd != KCP_CMD_ACK &&
            cmd != KCP_CMD_WASK && cmd != KCP_CMD_WINS)
            return;

        if (regular)
            kcp->rmt_wnd = wnd;
        if (kcp_parse_una(kcp, una) > 0)
            window_slides = 1;
        kcp_shrink_buf(kcp);

        if (cmd == KCP_CMD_ACK) {
            kcp_parse_ack(kcp, sn);
            kcp_parse_fastack(kcp, sn, ts);
            flag |= 1;
            latest = ts;
        } else if (cmd == KCP_CMD_PUSH) {
            if (k_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) < 0) {
                ackq_append(&kcp->acklist, sn, ts);
                if (k_itimediff(sn, kcp->rcv_nxt) >= 0) {
                    kcp_seg_t seg;
                    memset(&seg, 0, sizeof(seg));
                    seg.conv = conv;
                    seg.cmd = cmd;
                    seg.frg = frg;
                    seg.wnd = wnd;
                    seg.ts = ts;
                    seg.sn = sn;
                    seg.una = una;
                    seg.data = (uint8_t *)p + KCP_OVERHEAD;
                    seg.datalen = (int)length;
                    kcp_parse_data(kcp, &seg);
                }
            }
        } else if (cmd == KCP_CMD_WASK) {
            kcp->probe |= KCP_ASK_TELL;
        } else if (cmd == KCP_CMD_WINS) {
            /* do nothing */
        }

        p += KCP_OVERHEAD + length;
        rem -= KCP_OVERHEAD + (int)length;
    }

    if (flag != 0 && regular) {
        uint32_t current = kcp_current_ms();
        if (k_itimediff(current, latest) >= 0)
            kcp_update_ack(kcp, k_itimediff(current, latest));
    }

    if (kcp->nocwnd == 0) {
        if (k_itimediff(kcp->snd_una, snd_una) > 0) {
            if (kcp->cwnd < kcp->rmt_wnd) {
                uint32_t mss = kcp->mss;
                if (kcp->cwnd < kcp->ssthresh) {
                    kcp->cwnd++;
                    kcp->incr += mss;
                } else {
                    if (kcp->incr < mss)
                        kcp->incr = mss;
                    kcp->incr += (mss * mss) / kcp->incr + (mss / 16);
                    if ((kcp->cwnd + 1) * mss <= kcp->incr) {
                        if (mss > 0)
                            kcp->cwnd = (kcp->incr + mss - 1) / mss;
                        else
                            kcp->cwnd = kcp->incr + mss - 1;
                    }
                }
                if (kcp->cwnd > kcp->rmt_wnd) {
                    kcp->cwnd = kcp->rmt_wnd;
                    kcp->incr = kcp->rmt_wnd * mss;
                }
            }
        }
    }

    if (window_slides)
        kcp_flush(kcp, 0);
    else if (ack_nodelay && kcp->acklist.len > 0)
        kcp_flush(kcp, 1);
}

static uint16_t kcp_wnd_unused(kcp_t *kcp) {
    if (kcp->rcv_queue.len < (int)kcp->rcv_wnd)
        return (uint16_t)((int)kcp->rcv_wnd - kcp->rcv_queue.len);
    return 0;
}

static void seg_encode(const kcp_seg_t *seg, uint8_t *ptr) {
    uint32_t conv = seg->conv;
    uint8_t cmd = seg->cmd;
    uint8_t frg = seg->frg;
    uint16_t wnd = seg->wnd;
    uint32_t ts = seg->ts, sn = seg->sn, una = seg->una;
    uint32_t length = (uint32_t)seg->datalen;
    ptr[0] = (uint8_t)conv;
    ptr[1] = (uint8_t)(conv >> 8);
    ptr[2] = (uint8_t)(conv >> 16);
    ptr[3] = (uint8_t)(conv >> 24);
    ptr[4] = cmd;
    ptr[5] = frg;
    ptr[6] = (uint8_t)wnd;
    ptr[7] = (uint8_t)(wnd >> 8);
    ptr[8] = (uint8_t)ts;
    ptr[9] = (uint8_t)(ts >> 8);
    ptr[10] = (uint8_t)(ts >> 16);
    ptr[11] = (uint8_t)(ts >> 24);
    ptr[12] = (uint8_t)sn;
    ptr[13] = (uint8_t)(sn >> 8);
    ptr[14] = (uint8_t)(sn >> 16);
    ptr[15] = (uint8_t)(sn >> 24);
    ptr[16] = (uint8_t)una;
    ptr[17] = (uint8_t)(una >> 8);
    ptr[18] = (uint8_t)(una >> 16);
    ptr[19] = (uint8_t)(una >> 24);
    ptr[20] = (uint8_t)length;
    ptr[21] = (uint8_t)(length >> 8);
    ptr[22] = (uint8_t)(length >> 16);
    ptr[23] = (uint8_t)(length >> 24);
}

void kcp_flush(kcp_t *kcp, int ack_only) {
    kcp_seg_t seg;
    memset(&seg, 0, sizeof(seg));
    seg.conv = kcp->conv;
    seg.cmd = KCP_CMD_ACK;
    seg.wnd = kcp_wnd_unused(kcp);
    seg.una = kcp->rcv_nxt;

    uint8_t *buffer = kcp->buffer;
    uint8_t *ptr = buffer;
    int bufsize = 0;
    int mtu = (int)kcp->mtu;

    for (int i = 0; i < kcp->acklist.len; i++) {
        uint32_t asn = kcp->acklist.items[i].sn;
        uint32_t ats = kcp->acklist.items[i].ts;
        if (bufsize + KCP_OVERHEAD > mtu) {
            kcp->output(buffer, bufsize, kcp->output_ud);
            ptr = buffer;
            bufsize = 0;
        }
        if (k_itimediff(asn, kcp->rcv_nxt) >= 0 || kcp->acklist.len - 1 == i) {
            seg.sn = asn;
            seg.ts = ats;
            seg_encode(&seg, ptr);
            ptr += KCP_OVERHEAD;
            bufsize += KCP_OVERHEAD;
        }
    }
    kcp->acklist.len = 0;

    if (ack_only) {
        if (bufsize > 0) {
            kcp->output(buffer, bufsize, kcp->output_ud);
        }
        return;
    }

    if (kcp->rmt_wnd == 0) {
        uint32_t current = kcp_current_ms();
        if (kcp->probe_wait == 0) {
            kcp->probe_wait = KCP_PROBE_INIT;
            kcp->ts_probe = current + kcp->probe_wait;
        } else {
            if (k_itimediff(current, kcp->ts_probe) >= 0) {
                if (kcp->probe_wait < KCP_PROBE_INIT)
                    kcp->probe_wait = KCP_PROBE_INIT;
                kcp->probe_wait += kcp->probe_wait / 2;
                if (kcp->probe_wait > KCP_PROBE_LIMIT)
                    kcp->probe_wait = KCP_PROBE_LIMIT;
                kcp->ts_probe = current + kcp->probe_wait;
                kcp->probe |= KCP_ASK_SEND;
            }
        }
    } else {
        kcp->ts_probe = 0;
        kcp->probe_wait = 0;
    }

    if (kcp->probe & KCP_ASK_SEND) {
        seg.cmd = KCP_CMD_WASK;
        if (bufsize + KCP_OVERHEAD > mtu) {
            kcp->output(buffer, bufsize, kcp->output_ud);
            ptr = buffer;
            bufsize = 0;
        }
        seg_encode(&seg, ptr);
        ptr += KCP_OVERHEAD;
        bufsize += KCP_OVERHEAD;
    }

    if (kcp->probe & KCP_ASK_TELL) {
        seg.cmd = KCP_CMD_WINS;
        if (bufsize + KCP_OVERHEAD > mtu) {
            kcp->output(buffer, bufsize, kcp->output_ud);
            ptr = buffer;
            bufsize = 0;
        }
        seg_encode(&seg, ptr);
        ptr += KCP_OVERHEAD;
        bufsize += KCP_OVERHEAD;
    }

    kcp->probe = 0;

    uint32_t cwnd = k_imin(kcp->snd_wnd, kcp->rmt_wnd);
    if (kcp->nocwnd == 0)
        cwnd = k_imin(kcp->cwnd, cwnd);

    int new_segs_count = 0;
    while (new_segs_count < kcp->snd_queue.len) {
        if (k_itimediff(kcp->snd_nxt, kcp->snd_una + cwnd) >= 0)
            break;
        kcp_seg_t newseg = kcp->snd_queue.segs[new_segs_count];
        newseg.conv = kcp->conv;
        newseg.cmd = KCP_CMD_PUSH;
        newseg.sn = kcp->snd_nxt;
        segq_append(&kcp->snd_buf, &newseg);
        kcp->snd_nxt++;
        new_segs_count++;
    }
    if (new_segs_count > 0)
        segq_remove_front_nofree(&kcp->snd_queue, new_segs_count);

    uint32_t resent = kcp->fastresend > 0 ? (uint32_t)kcp->fastresend : 0xffffffffu;

    uint32_t current = kcp_current_ms();
    uint32_t change = 0, lost_segs = 0, fast_retrans_segs = 0, early_retrans_segs = 0;
    int32_t minrto = (int32_t)kcp->interval;

    for (int k = 0; k < kcp->snd_buf.len; k++) {
        kcp_seg_t *segment = &kcp->snd_buf.segs[k];
        int needsend = 0;
        if (segment->acked == 1)
            continue;
        if (segment->xmit == 0) {
            needsend = 1;
            segment->rto = kcp->rx_rto;
            segment->resendts = current + segment->rto;
        } else if (segment->fastack >= resent) {
            needsend = 1;
            segment->fastack = 0;
            segment->rto = kcp->rx_rto;
            segment->resendts = current + segment->rto;
            change++;
            fast_retrans_segs++;
        } else if (segment->fastack > 0 && new_segs_count == 0) {
            needsend = 1;
            segment->fastack = 0;
            segment->rto = kcp->rx_rto;
            segment->resendts = current + segment->rto;
            change++;
            early_retrans_segs++;
        } else if (k_itimediff(current, segment->resendts) >= 0) {
            needsend = 1;
            if (kcp->nodelay == 0)
                segment->rto += kcp->rx_rto;
            else
                segment->rto += kcp->rx_rto / 2;
            segment->fastack = 0;
            segment->resendts = current + segment->rto;
            lost_segs++;
        }

        if (needsend) {
            current = kcp_current_ms();
            segment->xmit++;
            segment->ts = current;
            segment->wnd = seg.wnd;
            segment->una = seg.una;

            int need = KCP_OVERHEAD + segment->datalen;
            if (bufsize + need > mtu) {
                kcp->output(buffer, bufsize, kcp->output_ud);
                ptr = buffer;
                bufsize = 0;
            }
            seg_encode(segment, ptr);
            ptr += KCP_OVERHEAD;
            memcpy(ptr, segment->data, (size_t)segment->datalen);
            ptr += segment->datalen;
            bufsize += need;

            if (segment->xmit >= kcp->dead_link)
                kcp->state = 0xFFFFFFFFu;
        }

        int32_t rto_diff = k_itimediff(segment->resendts, current);
        if (rto_diff > 0 && rto_diff < minrto)
            minrto = rto_diff;
    }

    if (bufsize > 0)
        kcp->output(buffer, bufsize, kcp->output_ud);

    uint32_t sum = lost_segs;
    if (lost_segs > 0 || fast_retrans_segs > 0 || early_retrans_segs > 0) {
        sum = lost_segs + fast_retrans_segs + early_retrans_segs;
    }

    if (kcp->nocwnd == 0) {
        if (change > 0) {
            uint32_t inflight = kcp->snd_nxt - kcp->snd_una;
            kcp->ssthresh = inflight / 2;
            if (kcp->ssthresh < KCP_THRESH_MIN)
                kcp->ssthresh = KCP_THRESH_MIN;
            kcp->cwnd = kcp->ssthresh + resent;
            kcp->incr = kcp->cwnd * kcp->mss;
        }
        if (lost_segs > 0) {
            kcp->ssthresh = cwnd / 2;
            if (kcp->ssthresh < KCP_THRESH_MIN)
                kcp->ssthresh = KCP_THRESH_MIN;
            kcp->cwnd = 1;
            kcp->incr = kcp->mss;
        }
        if (kcp->cwnd < 1) {
            kcp->cwnd = 1;
            kcp->incr = kcp->mss;
        }
    }

    (void)sum;
    (void)minrto;
}

void kcp_update(kcp_t *kcp, uint32_t current) {
    if (kcp->updated == 0) {
        kcp->updated = 1;
        kcp->ts_flush = current;
    }

    int32_t slap = k_itimediff(current, kcp->ts_flush);
    if (slap >= 10000 || slap < -10000) {
        kcp->ts_flush = current;
        slap = 0;
    }

    if (slap >= 0) {
        kcp->ts_flush += kcp->interval;
        if (k_itimediff(current, kcp->ts_flush) >= 0)
            kcp->ts_flush = current + kcp->interval;
        kcp_flush(kcp, 0);
    }
}
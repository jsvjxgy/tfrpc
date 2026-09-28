/*
 * SPDX-License-Identifier: GPL-3.0-only
 * quic.c - IETF QUIC v1 (RFC 9000) client for talking to frps.
 *
 * Single-session, multi-stream client: one session to frps' QUIC port and
 * one bidirectional stream per frp "connection" (control or work), matching
 * frp's ConnectionManager model.  Implements QUIC-TLS (RFC 9001): the
 * ClientHello travels in Initial CRYPTO frames, the remainder of the
 * handshake in Handshake frames, application data in 1-RTT short-header
 * packets.  Includes flow control in both directions, out-of-order stream
 * and handshake CRYPTO reassembly, a 1-RTT loss-recovery queue with
 * exponential backoff, byte-accurate handshake retransmission, and key
 * updates (the server rolls keys after FirstKeyUpdateInterval packets;
 * header protection keys stay fixed while packet protection keys are
 * re-derived from the stored traffic secrets).  Idle sessions send PING
 * every 10 s and close after 30 s without a valid packet, matching frps'
 * QUIC defaults.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tfrpc.h"
extern _Atomic int g_running;   /* global stop flag (main.c) */
#include "x25519.h"
#include "x509.h"
#include "ecdsa.h"
#include "quic.h"

/* ------------------------------------------------------------------ */
/* constants                                                           */
/* ------------------------------------------------------------------ */

#define QUIC_VERSION 0x00000001u

static const uint8_t QUIC_INITIAL_SALT[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

#define PKT_INITIAL   0x00
#define PKT_HANDSHAKE 0x20

#define FR_PADDING      0x00
#define FR_PING         0x01
#define FR_ACK          0x02
#define FR_RESET_STREAM 0x04
#define FR_STOP_SENDING 0x05
#define FR_CRYPTO       0x06
#define FR_NEW_TOKEN    0x07
#define FR_STREAM       0x08
#define FR_MAX_DATA     0x10
#define FR_MAX_STREAM_DATA 0x11
#define FR_MAX_STREAMS  0x12
#define FR_NEW_CONNECTION_ID 0x18
#define FR_CONNECTION_CLOSE 0x1c
#define FR_CONNECTION_CLOSE_APP 0x1d
#define FR_HANDSHAKE_DONE 0x1e

#define QUIC_MAX_DGRAM 1400

/* ------------------------------------------------------------------ */
/* packet protection keys                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t hp[16];
    int valid;
} quic_keys_t;

/* HKDF-Expand (RFC 5869) over an existing PRK */
static void quic_hkdf_expand(const uint8_t prk[32], const uint8_t *info,
                             size_t info_len, uint8_t *out, size_t out_len) {
    uint8_t t[32];
    size_t tlen = 0, done = 0;
    uint8_t ctr = 1;
    while (done < out_len) {
        uint8_t msg[32 + 512 + 1];
        size_t mlen = 0;
        if (tlen) {
            memcpy(msg, t, tlen);
            mlen += tlen;
        }
        if (info_len > 512)
            info_len = 512;
        memcpy(msg + mlen, info, info_len);
        mlen += info_len;
        msg[mlen++] = ctr;
        hmac_sha256(prk, 32, msg, mlen, t);
        tlen = 32;
        size_t n = out_len - done < 32 ? out_len - done : 32;
        memcpy(out + done, t, n);
        done += n;
        ctr++;
    }
}

/* HKDF-Expand-Label with QUIC label encoding (RFC 8446 7.1 / RFC 9001 5.1) */
static void quic_expand_label(const uint8_t *secret, size_t secret_len,
                              const char *label,
                              const uint8_t *ctx, size_t ctx_len,
                              uint8_t *out, size_t out_len) {
    (void)secret_len;
    size_t llen = 6 + strlen(label);
    uint8_t hkdf_label[2 + 1 + 262 + 1 + 64];
    size_t p = 0;
    hkdf_label[p++] = (uint8_t)(out_len >> 8);
    hkdf_label[p++] = (uint8_t)out_len;
    hkdf_label[p++] = (uint8_t)llen;
    memcpy(hkdf_label + p, "tls13 ", 6); p += 6;
    memcpy(hkdf_label + p, label, strlen(label)); p += strlen(label);
    hkdf_label[p++] = (uint8_t)ctx_len;
    if (ctx_len)
        memcpy(hkdf_label + p, ctx, ctx_len);
    p += ctx_len;
    quic_hkdf_expand(secret, hkdf_label, p, out, out_len);
}

static void quic_keys_init(quic_keys_t *k, const uint8_t *secret) {
    quic_expand_label(secret, 32, "quic key", NULL, 0, k->key, 16);
    quic_expand_label(secret, 32, "quic iv", NULL, 0, k->iv, 12);
    quic_expand_label(secret, 32, "quic hp", NULL, 0, k->hp, 16);
    k->valid = 1;
}

static void quic_hkdf_extract(const uint8_t *salt, size_t salt_len,
                              const uint8_t *ikm, size_t ikm_len, uint8_t out[32]) {
    hmac_sha256(salt, salt_len, ikm, ikm_len, out);
}

/* Derive-Secret(secret, label, transcript) */
static void quic_derive_secret(const uint8_t secret[32], const char *label,
                               const uint8_t transcript_hash[32], uint8_t out[32]) {
    quic_expand_label(secret, 32, label, transcript_hash, 32, out, 32);
}

/* header protection mask (RFC 9001 5.4) */
static void quic_hp_mask(const quic_keys_t *k, const uint8_t *cipher,
                         size_t pn_offset, size_t cipher_len, uint8_t mask[16]) {
    memset(mask, 0, 16);
    if (cipher_len < pn_offset + 4 + 16)
        return;
    aes_block_encrypt(k->hp, cipher + pn_offset + 4, mask);
}

/* ------------------------------------------------------------------ */
/* varint / packet number                                              */
/* ------------------------------------------------------------------ */

static size_t varint_put(uint8_t *p, uint64_t v) {
    if (v < 64) { p[0] = (uint8_t)v; return 1; }
    if (v < 16384) { p[0] = (uint8_t)(0x40 | (v >> 8)); p[1] = (uint8_t)v; return 2; }
    if (v < 1ull << 30) {
        p[0] = (uint8_t)(0x80 | (v >> 24)); p[1] = (uint8_t)(v >> 16);
        p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; return 4;
    }
    p[0] = (uint8_t)(0xc0 | (v >> 56)); p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8); p[7] = (uint8_t)v; return 8;
}

static int varint_get(const uint8_t *p, size_t len, uint64_t *v, size_t *used) {
    if (len < 1)
        return -1;
    uint8_t b = p[0];
    if ((b & 0xc0) == 0) { *v = b & 0x3f; *used = 1; return 0; }
    if ((b & 0xc0) == 0x40) {
        if (len < 2) return -1;
        *v = ((uint64_t)(b & 0x3f) << 8) | p[1]; *used = 2; return 0;
    }
    if ((b & 0xc0) == 0x80) {
        if (len < 4) return -1;
        *v = ((uint64_t)(b & 0x3f) << 24) | ((uint64_t)p[1] << 16) |
             ((uint64_t)p[2] << 8) | p[3];
        *used = 4; return 0;
    }
    if (len < 8) return -1;
    *v = ((uint64_t)(b & 0x3f) << 56) | ((uint64_t)p[1] << 48) |
         ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
         ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
         ((uint64_t)p[6] << 8) | p[7];
    *used = 8; return 0;
}

static size_t pn_encode_len(uint64_t pn) {
    return pn < 64 ? 1 : 2;
}

/* RFC 9000 A.3: reconstruct the full packet number */
static uint64_t pn_decode(uint64_t largest, uint64_t truncated, size_t pn_len) {
    if (pn_len < 1 || pn_len > 4)      /* 0 would underflow the shift below */
        pn_len = 1;
    uint64_t bits = (uint64_t)pn_len * 8;
    uint64_t mask = (1ull << bits) - 1;
    uint64_t expected = largest + 1;
    uint64_t candidate = (expected & ~mask) | truncated;
    uint64_t win = 1ull << (bits - 1);
    if (candidate + win <= expected && candidate + (1ull << bits) < (1ull << 62))
        candidate += 1ull << bits;
    return candidate;
}

/* ------------------------------------------------------------------ */
/* connection state                                                    */
/* ------------------------------------------------------------------ */

typedef struct quic_rxchunk {
    uint64_t off;
    size_t len;
    int fin;
    uint8_t *data;
    struct quic_rxchunk *next;
} quic_rxchunk_t;

typedef struct quic_txpkt {
    uint64_t pn;
    size_t flen;
    int64_t next_rtx;
    int backoff_ms;
    int ack_only;
    uint8_t frames[QUIC_MAX_DGRAM];
    struct quic_txpkt *next;
} quic_txpkt_t;

#define QUIC_RX_WINDOW     262144
#define QUIC_CONN_RX_WINDOW 1048576
#define QUIC_TXQ_CAP       4194304

/* one sent handshake CRYPTO range (for byte-level retransmit/ack tracking) */
typedef struct {
    uint64_t pn;
    size_t off, len;
    int acked;
} quic_cpt_t;

typedef struct quic_stream {
    struct quic_conn *qc;
    uint64_t id;
    uint8_t *rxbuf;
    size_t rxlen, rxcap;
    uint64_t rx_offset;
    uint64_t tx_offset;
    uint64_t tx_max;           /* peer's MAX_STREAM_DATA */
    uint64_t rx_max_sent;      /* last window we advertised */
    quic_rxchunk_t *rxq;
    size_t rxq_bytes;
    int rx_closed;
    int aborted;
    int64_t deadline;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    struct quic_stream *next;
} quic_stream_t;

/* client handshake state */
typedef struct {
    uint8_t client_priv[32];
    uint8_t client_pub[32];
    uint8_t server_pub[32];
    int got_server_pub;
    uint8_t client_random[32];
    sha256_ctx_t transcript;
    int state;                 /* 0 = wait ServerHello, 1 = wait rest, 2 = done */
    size_t parse_pos;
    uint8_t c_hs_secret[32];
    uint8_t s_hs_secret[32];
    uint8_t hs_secret[32];     /* generic handshake secret (for master) */
    x509_cert_t leaf;
    int has_leaf;
} quic_hs_t;

struct quic_conn {
    int fd;
    struct sockaddr_storage peer;
    socklen_t peerlen;

    uint8_t dcid[20]; size_t dcid_len;
    uint8_t scid[20]; size_t scid_len;
    uint8_t server_scid[20]; size_t server_scid_len;

    uint64_t pn_initial, pn_handshake, pn_app;
    uint64_t rpn_initial, rpn_handshake, rpn_app;

    quic_keys_t cinit, sinit, chs, shs, cap, sap;
    quic_keys_t pcap, psap;    /* previous-phase keys (grace period) */
    uint8_t cap_secret[32], sap_secret[32];
    int key_phase;

    int hs_done, hs_failed;
    uint8_t hs_in[65536];
    size_t hs_inlen;
    uint64_t crypto_ini_off, crypto_hs_off;
    quic_rxchunk_t *crypto_pending;   /* out-of-order Handshake CRYPTO data */
    size_t crypto_pending_bytes;

    uint8_t tx_ini[4096];
    size_t tx_ini_len, tx_ini_sent;
    uint64_t tx_ini_acked;
    uint8_t tx_hs[256];
    size_t tx_hs_len, tx_hs_sent;
    uint64_t tx_hs_acked;
    int64_t hs_resend_at;
    quic_cpt_t cpt_ini[8], cpt_hs[8];
    int cpt_ini_n, cpt_hs_n;

    const x509_cert_t *ca;
    const char *server_name;

    quic_hs_t hs;
    quic_stream_t *streams;
    uint64_t next_stream_id;

    /* 1-RTT send queue / loss recovery */
    quic_txpkt_t *txq;
    size_t txq_bytes;
    uint64_t tx_max_data, tx_stream_max, tx_data_sent;
    uint64_t rx_consumed, rx_max_data_sent;
    uint64_t peer_max_streams;   /* cumulative peer limit (TP + MAX_STREAMS) */
    uint64_t streams_opened;     /* cumulative streams we have opened */
    int64_t rtx_next, last_ack_at;
    int64_t last_recv_at, last_send_at;
    int rtx_hint;

    _Atomic int closed;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    pthread_t reader;
    int reader_started;
};

#ifdef TFRPC_QUIC_DEBUG
#define DBGQ(...) fprintf(stderr, "[Q] " __VA_ARGS__)
#else
#define DBGQ(...) ((void)0)
#endif
static void quic_signal(quic_conn_t *c) {
    pthread_cond_broadcast(&c->cv);
}

static void quic_nonce(uint8_t nonce[12], const quic_keys_t *k, uint64_t pn) {
    memcpy(nonce, k->iv, 12);
    for (int i = 0; i < 8; i++)
        nonce[11 - i] ^= (uint8_t)(pn >> (8 * i));
}

static void quic_apply_hp(const quic_keys_t *k, uint8_t *hdr,
                          uint8_t *pn_bytes, size_t pn_len,
                          const uint8_t *cipher, size_t clen) {
    uint8_t mask[16];
    quic_hp_mask(k, cipher, 0, clen, mask);
    if (hdr[0] & 0x80)
        hdr[0] ^= (uint8_t)(mask[0] & 0x0f);   /* long header */
    else
        hdr[0] ^= (uint8_t)(mask[0] & 0x1f);   /* short header */
    for (size_t i = 0; i < pn_len && i < 4; i++)
        pn_bytes[i] ^= mask[1 + i];
}

/* remove header protection; returns the packet number length in bytes
 * (RFC 9001 5.4.2: unmask the first byte before reading the length bits) */
static size_t quic_remove_hp(const quic_keys_t *k, uint8_t *buf, size_t n,
                             size_t pn_pos) {
    uint8_t mask[16];
    quic_hp_mask(k, buf + pn_pos, 0, n - pn_pos, mask);
    if (buf[0] & 0x80)
        buf[0] ^= (uint8_t)(mask[0] & 0x0f);
    else
        buf[0] ^= (uint8_t)(mask[0] & 0x1f);
    size_t pn_len = (size_t)(buf[0] & 0x03) + 1;
    for (size_t i = 0; i < pn_len; i++)
        buf[pn_pos + i] ^= mask[1 + i];
    return pn_len;
}

/* ------------------------------------------------------------------ */
/* frame builders                                                      */
/* ------------------------------------------------------------------ */

static size_t frame_crypto(uint8_t *out, uint64_t off, const uint8_t *data, size_t len) {
    size_t p = 0;
    out[p++] = FR_CRYPTO;
    p += varint_put(out + p, off);
    p += varint_put(out + p, len);
    if (len)
        memcpy(out + p, data, len);
    return p + len;
}

static size_t frame_stream(uint8_t *out, uint64_t id, uint64_t off,
                           const uint8_t *data, size_t len, int fin) {
    size_t p = 0;
    uint8_t type = FR_STREAM | 0x02 | 0x04;   /* OFF + LEN */
    if (fin)
        type |= 0x01;
    out[p++] = type;
    p += varint_put(out + p, id);
    p += varint_put(out + p, off);
    p += varint_put(out + p, len);
    if (len)
        memcpy(out + p, data, len);
    return p + len;
}

static size_t frame_ack(uint8_t *out, uint64_t largest) {
    size_t p = 0;
    out[p++] = FR_ACK;
    p += varint_put(out + p, largest);
    p += varint_put(out + p, 0);   /* ack delay */
    p += varint_put(out + p, 0);   /* range count - 1 */
    p += varint_put(out + p, 0);   /* first range (single packet) */
    return p;
}

static size_t frame_max_data(uint8_t *out, uint64_t v) {
    size_t p = 0;
    out[p++] = FR_MAX_DATA;
    p += varint_put(out + p, v);
    return p;
}

static size_t frame_max_stream_data(uint8_t *out, uint64_t id, uint64_t v) {
    size_t p = 0;
    out[p++] = FR_MAX_STREAM_DATA;
    p += varint_put(out + p, id);
    p += varint_put(out + p, v);
    return p;
}

/* ------------------------------------------------------------------ */
/* packet send                                                         */
/* ------------------------------------------------------------------ */

static void quic_send_packet(quic_conn_t *c, uint8_t ptype, quic_keys_t *k,
                             uint64_t *pn, const uint8_t *frames, size_t flen,
                             int pad_to_min) {
    uint8_t buf[QUIC_MAX_DGRAM];
    uint8_t frbuf[QUIC_MAX_DGRAM];
    const uint8_t *f = frames;
    size_t fl = flen;
    uint64_t pktnum = (*pn)++;
    size_t pn_len = pn_encode_len(pktnum);

    size_t p = 0;
    buf[p++] = (uint8_t)(0xc0 | ptype | (uint8_t)(pn_len - 1));   /* + pn len bits */
    buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x01;
    buf[p++] = (uint8_t)c->dcid_len;
    memcpy(buf + p, c->dcid, c->dcid_len); p += c->dcid_len;
    buf[p++] = (uint8_t)c->scid_len;
    memcpy(buf + p, c->scid, c->scid_len); p += c->scid_len;
    if (ptype == PKT_INITIAL)
        buf[p++] = 0;                            /* token length (empty) */
    size_t len_at = p;
    p += 2;                                      /* 2-byte varint length */
    size_t pn_pos = p;

    /* pad client Initial datagrams to at least 1200 bytes (RFC 9000 14.1) */
    if (pad_to_min && ptype == PKT_INITIAL) {
        size_t total = pn_pos + pn_len + fl + 16;
        if (total < 1200) {
            size_t pad = 1200 - total;
            if (fl + pad <= sizeof(frbuf)) {
                memcpy(frbuf, frames, fl);
                memset(frbuf + fl, 0, pad);
                f = frbuf;
                fl += pad;
            }
        }
    }

    size_t payload_len = pn_len + fl + 16;
    buf[len_at] = (uint8_t)(0x40 | (payload_len >> 8));
    buf[len_at + 1] = (uint8_t)payload_len;

    uint8_t plain_pn[4];
    for (size_t i = 0; i < pn_len; i++)
        plain_pn[i] = (uint8_t)(pktnum >> (8 * (pn_len - 1 - i)));

    uint8_t aad[QUIC_MAX_DGRAM];
    memcpy(aad, buf, pn_pos);
    memcpy(aad + pn_pos, plain_pn, pn_len);

    uint8_t ct[QUIC_MAX_DGRAM];
    memcpy(ct, f, fl);
    uint8_t nonce[12], tag[16];
    quic_nonce(nonce, k, pktnum);
    aes_gcm_seal(k->key, 16, nonce, aad, pn_pos + pn_len, ct, fl, tag);

    size_t q = pn_pos;
    memcpy(buf + q, plain_pn, pn_len); q += pn_len;
    memcpy(buf + q, ct, fl); q += fl;
    memcpy(buf + q, tag, 16); q += 16;

    quic_apply_hp(k, buf, buf + pn_pos, pn_len, buf + pn_pos, q - pn_pos);
    DBGQ("send long type=%02x pn=%llu len=%zu\n", ptype, (unsigned long long)pktnum, q);
    sendto(c->fd, buf, q, 0, (struct sockaddr *)&c->peer, c->peerlen);
}

static void quic_send_1rtt(quic_conn_t *c, const uint8_t *frames, size_t flen) {
    uint8_t buf[QUIC_MAX_DGRAM];
    uint64_t pktnum = c->pn_app++;
    size_t pn_len = pn_encode_len(pktnum);

    size_t p = 0;
    /* short header: form bit | key phase | pn length */
    buf[p++] = (uint8_t)(0x40 | (c->key_phase ? 0x04 : 0x00) |
                         (uint8_t)(pn_len - 1));
    memcpy(buf + p, c->dcid, c->dcid_len); p += c->dcid_len;
    size_t pn_pos = p;

    uint8_t plain_pn[4];
    for (size_t i = 0; i < pn_len; i++)
        plain_pn[i] = (uint8_t)(pktnum >> (8 * (pn_len - 1 - i)));

    uint8_t aad[QUIC_MAX_DGRAM];
    memcpy(aad, buf, pn_pos);
    memcpy(aad + pn_pos, plain_pn, pn_len);

    uint8_t ct[QUIC_MAX_DGRAM];
    memcpy(ct, frames, flen);
    uint8_t nonce[12], tag[16];
    quic_nonce(nonce, &c->cap, pktnum);
    aes_gcm_seal(c->cap.key, 16, nonce, aad, pn_pos + pn_len, ct, flen, tag);

    size_t q = pn_pos;
    memcpy(buf + q, plain_pn, pn_len); q += pn_len;
    memcpy(buf + q, ct, flen); q += flen;
    memcpy(buf + q, tag, 16); q += 16;

    quic_apply_hp(&c->cap, buf, buf + pn_pos, pn_len, buf + pn_pos, q - pn_pos);
    sendto(c->fd, buf, q, 0, (struct sockaddr *)&c->peer, c->peerlen);
    c->last_send_at = mono_ms();

    /* keep a copy for loss recovery (skip when the queue is over budget) */
    if (c->txq_bytes + flen <= QUIC_TXQ_CAP) {
        quic_txpkt_t *e = malloc(sizeof(*e));
        if (e) {
            int bo = c->rtx_hint ? c->rtx_hint : 250;
            e->pn = pktnum;
            e->flen = flen;
            e->backoff_ms = bo;
            e->next_rtx = mono_ms() + bo;
            e->ack_only = (flen > 0 &&
                           (frames[0] == FR_ACK || frames[0] == 0x03 ||
                            (flen == 1 && frames[0] == FR_PING)));
            memcpy(e->frames, frames, flen);
            e->next = c->txq;
            c->txq = e;
            c->txq_bytes += flen;
        }
    }
    c->rtx_hint = 0;
}

static void quic_send_ack(quic_conn_t *c, uint8_t ptype, quic_keys_t *k, uint64_t pn) {
    (void)k;
    if (ptype == 0xff)
        DBGQ("send ACK pn=%llu\n", (unsigned long long)pn);
    uint8_t fr[32];
    size_t flen = frame_ack(fr, pn);
    if (ptype == PKT_INITIAL)
        quic_send_packet(c, PKT_INITIAL, &c->cinit, &c->pn_initial, fr, flen, 1);
    else if (ptype == PKT_HANDSHAKE)
        quic_send_packet(c, PKT_HANDSHAKE, &c->chs, &c->pn_handshake, fr, flen, 0);
    else
        quic_send_1rtt(c, fr, flen);
}

/* ------------------------------------------------------------------ */
/* QUIC-TLS handshake                                                  */
/* ------------------------------------------------------------------ */

static void quic_handshake_input(quic_conn_t *c);

static size_t quic_build_client_hello(quic_hs_t *h, uint8_t *out,
                                      const uint8_t *scid, size_t scid_len) {
    uint8_t tp[256];
    size_t t = 0;
    struct { uint64_t id, val; } tps[] = {
        { 0x01, 30000 },      /* max_idle_timeout (ms) */
        { 0x03, 1400 },       /* max_udp_payload_size */
        { 0x04, 1048576 },    /* initial_max_data */
        { 0x05, 262144 },     /* initial_max_stream_data_bidi_local */
        { 0x06, 262144 },     /* initial_max_stream_data_bidi_remote */
        { 0x07, 262144 },     /* initial_max_stream_data_uni */
        { 0x08, 64 },         /* initial_max_streams_bidi */
        { 0x09, 0 },          /* initial_max_streams_uni */
        { 0x0e, 2 },          /* active_connection_id_limit */
    };
    for (size_t i = 0; i < sizeof(tps) / sizeof(tps[0]); i++) {
        uint8_t v[8];
        size_t vl = varint_put(v, tps[i].val);
        t += varint_put(tp + t, tps[i].id);
        t += varint_put(tp + t, vl);
        memcpy(tp + t, v, vl);
        t += vl;
    }
    /* initial_source_connection_id (0x0f) is mandatory (RFC 9000) */
    t += varint_put(tp + t, 0x0f);
    t += varint_put(tp + t, scid_len);
    memcpy(tp + t, scid, scid_len);
    t += scid_len;

    size_t o = 0;
    out[o++] = 1;                      /* ClientHello */
    size_t len_at = o;
    o += 3;
    out[o++] = 0x03; out[o++] = 0x03;  /* legacy_version */
    random_bytes(h->client_random, 32);
    memcpy(out + o, h->client_random, 32); o += 32;
    out[o++] = 0;                      /* session id */
    out[o++] = 0x00; out[o++] = 0x02;  /* cipher suites */
    out[o++] = 0x13; out[o++] = 0x01;  /* TLS_AES_128_GCM_SHA256 */
    out[o++] = 0x01; out[o++] = 0x00;  /* compression: null */
    size_t ext_at = o;
    o += 2;

    /* supported_versions: TLS 1.3 (Go crypto/tls uses the TLS version
     * number in QUIC ClientHello, not the QUIC version) */
    out[o++] = 0x00; out[o++] = 0x2b;
    out[o++] = 0x00; out[o++] = 0x03;
    out[o++] = 0x02; out[o++] = 0x03; out[o++] = 0x04;

    /* supported_groups: x25519 */
    out[o++] = 0x00; out[o++] = 0x0a;
    out[o++] = 0x00; out[o++] = 0x04;
    out[o++] = 0x00; out[o++] = 0x02;
    out[o++] = 0x00; out[o++] = 0x1d;

    /* quic_transport_parameters */
    out[o++] = 0x00; out[o++] = 0x39;
    out[o++] = (uint8_t)(t >> 8); out[o++] = (uint8_t)t;
    memcpy(out + o, tp, t); o += t;

    /* ALPN: "frp" */
    out[o++] = 0x00; out[o++] = 0x10;
    out[o++] = 0x00; out[o++] = 0x06;
    out[o++] = 0x00; out[o++] = 0x04;
    out[o++] = 0x03;
    out[o++] = 'f'; out[o++] = 'r'; out[o++] = 'p';

    /* signature_algorithms */
    out[o++] = 0x00; out[o++] = 0x0d;
    out[o++] = 0x00; out[o++] = 0x06;
    out[o++] = 0x00; out[o++] = 0x04;
    out[o++] = 0x08; out[o++] = 0x04;   /* rsa_pss_rsae_sha256 */
    out[o++] = 0x04; out[o++] = 0x03;   /* ecdsa_secp256r1_sha256 */

    /* key_share (x25519) */
    out[o++] = 0x00; out[o++] = 0x33;
    out[o++] = 0x00; out[o++] = 0x26;
    out[o++] = 0x00; out[o++] = 0x24;
    out[o++] = 0x00; out[o++] = 0x1d;
    out[o++] = 0x00; out[o++] = 0x20;
    memcpy(out + o, h->client_pub, 32); o += 32;

    size_t ext_len = o - (ext_at + 2);
    out[ext_at] = (uint8_t)(ext_len >> 8);
    out[ext_at + 1] = (uint8_t)ext_len;

    size_t body = o - 4;
    out[len_at] = (uint8_t)(body >> 16);
    out[len_at + 1] = (uint8_t)(body >> 8);
    out[len_at + 2] = (uint8_t)body;
    return o;
}

static int quic_parse_server_hello(quic_hs_t *h, const uint8_t *msg, size_t len) {
    size_t p = 0;
    if (len < 2 + 32)
        return -1;
    p += 2;
    p += 32;                      /* server random (unused) */
    if (p >= len) return -1;
    uint8_t sid_len = msg[p++];
    if (p + sid_len + 3 > len) return -1;
    p += sid_len;
    uint16_t suite = (uint16_t)((msg[p] << 8) | msg[p + 1]); p += 2;
    if (suite != 0x1301)
        return -1;
    p += 1 + msg[p];              /* compression */
    if (p + 2 > len) return -1;
    size_t ext_len = ((size_t)msg[p] << 8) | msg[p + 1];
    p += 2;
    size_t ext_end = p + ext_len;
    if (ext_end > len) ext_end = len;
    while (p + 4 <= ext_end) {
        uint16_t et = (uint16_t)((msg[p] << 8) | msg[p + 1]);
        uint16_t el = (uint16_t)((msg[p + 2] << 8) | msg[p + 3]);
        p += 4;
        if (p + el > ext_end) break;
        if (et == 0x0033 && el >= 36 &&
            msg[p] == 0x00 && msg[p + 1] == 0x1d &&
            msg[p + 2] == 0x00 && msg[p + 3] == 0x20) {
            memcpy(h->server_pub, msg + p + 4, 32);
            h->got_server_pub = 1;
        }
        p += el;
    }
    return h->got_server_pub ? 0 : -1;
}

static int quic_derive_hs_keys(quic_conn_t *c, quic_hs_t *h) {
    uint8_t shared[32];
    x25519(shared, h->client_priv, h->server_pub);
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++)
        acc |= shared[i];
    if (acc == 0) {           /* RFC 7748: reject low-order/all-zero output */
        secure_zero(shared, sizeof(shared));
        return -1;
    }
    uint8_t zero[32] = { 0 };
    uint8_t empty_hash[32];
    sha256_digest(NULL, 0, empty_hash);
    uint8_t early[32], derived[32], hs_secret[32], th[32];
    quic_hkdf_extract(NULL, 0, zero, 32, early);
    quic_derive_secret(early, "derived", empty_hash, derived);
    quic_hkdf_extract(derived, 32, shared, 32, hs_secret);

    sha256_ctx_t ctx = h->transcript;
    sha256_final(&ctx, th);
    quic_derive_secret(hs_secret, "c hs traffic", th, h->c_hs_secret);
    quic_derive_secret(hs_secret, "s hs traffic", th, h->s_hs_secret);
    memcpy(h->hs_secret, hs_secret, 32);
    quic_keys_init(&c->chs, h->c_hs_secret);
    quic_keys_init(&c->shs, h->s_hs_secret);

    secure_zero(shared, sizeof(shared));
    secure_zero(early, sizeof(early));
    secure_zero(derived, sizeof(derived));
    secure_zero(hs_secret, sizeof(hs_secret));
    return 0;
}

static void quic_derive_app_keys(quic_conn_t *c, quic_hs_t *h) {
    uint8_t th[32];
    sha256_ctx_t ctx = h->transcript;
    sha256_final(&ctx, th);

    uint8_t zero[32] = { 0 };
    uint8_t empty_hash[32];
    sha256_digest(NULL, 0, empty_hash);
    uint8_t derived2[32], master[32], cap[32], sap[32];
    quic_derive_secret(h->hs_secret, "derived", empty_hash, derived2);
    quic_hkdf_extract(derived2, 32, zero, 32, master);
    quic_derive_secret(master, "c ap traffic", th, cap);
    quic_derive_secret(master, "s ap traffic", th, sap);
    quic_keys_init(&c->cap, cap);
    quic_keys_init(&c->sap, sap);
    memcpy(c->cap_secret, cap, 32);
    memcpy(c->sap_secret, sap, 32);
    secure_zero(derived2, sizeof(derived2));
    secure_zero(master, sizeof(master));
    secure_zero(cap, sizeof(cap));
    secure_zero(sap, sizeof(sap));
}

static void quic_send_client_finished(quic_conn_t *c, quic_hs_t *h) {
    uint8_t th[32], finished_key[32], verify[32];
    sha256_ctx_t ctx = h->transcript;
    sha256_final(&ctx, th);
    quic_expand_label(h->c_hs_secret, 32, "finished", NULL, 0, finished_key, 32);
    hmac_sha256(finished_key, 32, th, 32, verify);

    uint8_t fin[36];
    fin[0] = 20;
    fin[1] = 0; fin[2] = 0; fin[3] = 32;
    memcpy(fin + 4, verify, 32);
    if (c->tx_hs_len + sizeof(fin) <= sizeof(c->tx_hs)) {
        memcpy(c->tx_hs + c->tx_hs_len, fin, sizeof(fin));
        c->tx_hs_len += sizeof(fin);
    }
    sha256_update(&h->transcript, fin, sizeof(fin));
    secure_zero(finished_key, sizeof(finished_key));
    secure_zero(verify, sizeof(verify));
}

/* process all complete handshake messages in hs_in; called with c->mu held */
/* extract peer flow-control limits from EncryptedExtensions */
static void quic_parse_peer_tp(quic_conn_t *c, const uint8_t *body, size_t len) {
    if (len < 2)
        return;
    size_t elen = ((size_t)body[0] << 8) | body[1];
    if (2 + elen > len)
        elen = len - 2;
    size_t p = 2, end = 2 + elen;
    while (p + 4 <= end) {
        uint16_t et = (uint16_t)((body[p] << 8) | body[p + 1]);
        size_t xl = ((size_t)body[p + 2] << 8) | body[p + 3];
        p += 4;
        if (p + xl > end)
            break;
        if (et == 0x0039) {
            size_t q = 0;
            while (q < xl) {
                uint64_t id, vl; size_t u;
                if (varint_get(body + p + q, xl - q, &id, &u) < 0) break;
                q += u;
                if (varint_get(body + p + q, xl - q, &vl, &u) < 0) break;
                q += u;
                if (vl > xl - q) break;
                if (id == 0x04 || id == 0x06 || id == 0x08) {
                    uint64_t v; size_t vn;
                    if (varint_get(body + p + q, xl - q, &v, &vn) == 0) {
                        if (id == 0x04) c->tx_max_data = v;
                        else if (id == 0x06) c->tx_stream_max = v;
                        else c->peer_max_streams = v;
                    }
                }
                q += vl;
            }
        }
        p += xl;
    }
}

static void quic_handshake_input(quic_conn_t *c) {
    quic_hs_t *h = &c->hs;
    while (c->hs_inlen >= h->parse_pos + 4) {
        size_t mlen = ((size_t)c->hs_in[h->parse_pos + 1] << 16) |
                      ((size_t)c->hs_in[h->parse_pos + 2] << 8) |
                      c->hs_in[h->parse_pos + 3];
        if (c->hs_inlen < h->parse_pos + 4 + mlen)
            return;
        uint8_t mtype = c->hs_in[h->parse_pos];
        DBGQ("hs msg type=%u len=%zu state=%d\n", mtype, mlen, h->state);
        const uint8_t *body = c->hs_in + h->parse_pos + 4;

        if (h->state == 0) {
            if (mtype != 2) {
                c->hs_failed = 1;
                break;
            }
            sha256_update(&h->transcript, c->hs_in + h->parse_pos, 4 + mlen);
            if (quic_parse_server_hello(h, body, mlen) < 0 ||
                quic_derive_hs_keys(c, h) < 0) {
                c->hs_failed = 1;
                break;
            }
            h->state = 1;
        } else {
            if (mtype == 8) {            /* EncryptedExtensions */
                quic_parse_peer_tp(c, body, mlen);
                sha256_update(&h->transcript, c->hs_in + h->parse_pos, 4 + mlen);
            } else if (mtype == 11) {    /* Certificate */
                if (mlen < 4) { c->hs_failed = 1; break; }
                size_t p = 1 + body[0];
                if (p + 3 > mlen) { c->hs_failed = 1; break; }
                size_t list = ((size_t)body[p] << 16) | ((size_t)body[p + 1] << 8) | body[p + 2];
                p += 3;
                if (p + list > mlen || list < 3) { c->hs_failed = 1; break; }
                size_t elen = ((size_t)body[p] << 16) | ((size_t)body[p + 1] << 8) | body[p + 2];
                if (3 + elen > list) { c->hs_failed = 1; break; }
                if (x509_parse(body + p + 3, elen, &h->leaf) == 0)
                    h->has_leaf = 1;
                if (c->ca) {
                    if (!h->has_leaf ||
                        x509_verify_signed_by(&h->leaf, c->ca) != 0) {
                        c->hs_failed = 1;
                        break;
                    }
                    if (c->server_name && c->server_name[0] &&
                        x509_check_hostname(&h->leaf, c->server_name) < 0) {
                        c->hs_failed = 1;
                        break;
                    }
                }
                sha256_update(&h->transcript, c->hs_in + h->parse_pos, 4 + mlen);
            } else if (mtype == 15) {    /* CertificateVerify */
                if (c->ca && h->has_leaf) {
                    static const char label[] = "TLS 1.3, server CertificateVerify";
                    uint8_t content[64 + sizeof(label) - 1 + 1 + 32];
                    memset(content, 0x20, 64);
                    memcpy(content + 64, label, sizeof(label) - 1);
                    content[64 + sizeof(label) - 1] = 0;
                    sha256_ctx_t tctx = h->transcript;
                    uint8_t th[32];
                    sha256_final(&tctx, th);
                    memcpy(content + 64 + sizeof(label), th, 32);
                    uint8_t digest[32];
                    sha256_digest(content, sizeof(content), digest);
                    if (mlen < 4) { c->hs_failed = 1; break; }
                    uint16_t scheme = (uint16_t)((body[0] << 8) | body[1]);
                    uint16_t slen = (uint16_t)((body[2] << 8) | body[3]);
                    if (mlen < (size_t)(4 + slen)) { c->hs_failed = 1; break; }
                    int ok;
                    if (scheme == 0x0804)
                        ok = h->leaf.key_type == X509_KEY_RSA &&
                             rsa_pss_verify(&h->leaf.pub, digest, 32, body + 4, slen) == 0;
                    else if (scheme == 0x0403)
                        ok = h->leaf.key_type == X509_KEY_ECDSA &&
                             ecdsa_p256_verify(h->leaf.ec_pub, sizeof(h->leaf.ec_pub),
                                               digest, 32, body + 4, slen) == 0;
                    else
                        ok = 0;
                    if (!ok) { c->hs_failed = 1; break; }
                }
                sha256_update(&h->transcript, c->hs_in + h->parse_pos, 4 + mlen);
            } else if (mtype == 20) {    /* Finished */
                if (mlen != 32) { c->hs_failed = 1; break; }
                sha256_ctx_t tctx = h->transcript;
                uint8_t th[32], finished_key[32], expect[32];
                sha256_final(&tctx, th);
                quic_expand_label(h->s_hs_secret, 32, "finished", NULL, 0, finished_key, 32);
                hmac_sha256(finished_key, 32, th, 32, expect);
                if (crypto_memcmp_ct(expect, body, 32) != 0) {
                    c->hs_failed = 1;
                    break;
                }
                secure_zero(finished_key, sizeof(finished_key));
                sha256_update(&h->transcript, c->hs_in + h->parse_pos, 4 + mlen);
                quic_derive_app_keys(c, h);
                quic_send_client_finished(c, h);
                h->state = 2;
            } else if (mtype == 4) {     /* NewSessionTicket (post-handshake) */
                sha256_update(&h->transcript, c->hs_in + h->parse_pos, 4 + mlen);
            } else {
                c->hs_failed = 1;
                break;
            }
        }
        h->parse_pos += 4 + mlen;
    }
    if (c->hs_failed) {
        c->closed = 1;
        quic_signal(c);
    }
}

/* ------------------------------------------------------------------ */
/* retransmission of client handshake bytes                            */
/* ------------------------------------------------------------------ */

static void quic_flush_crypto(quic_conn_t *c) {
    int64_t now = mono_ms();
    uint8_t ptype;
    quic_keys_t *k;
    uint64_t *pn;
    uint8_t *buf;
    size_t *blen, *bsent;
    uint64_t *backed;
    quic_cpt_t *cpt;
    int *cpt_n;

    if (!c->shs.valid) {
        ptype = PKT_INITIAL;
        k = &c->cinit;
        pn = &c->pn_initial;
        buf = c->tx_ini;
        blen = &c->tx_ini_len;
        bsent = &c->tx_ini_sent;
        backed = &c->tx_ini_acked;
        cpt = c->cpt_ini;
        cpt_n = &c->cpt_ini_n;
    } else {
        ptype = PKT_HANDSHAKE;
        k = &c->chs;
        pn = &c->pn_handshake;
        buf = c->tx_hs;
        blen = &c->tx_hs_len;
        bsent = &c->tx_hs_sent;
        backed = &c->tx_hs_acked;
        cpt = c->cpt_hs;
        cpt_n = &c->cpt_hs_n;
    }
    if (*blen == 0)
        return;

    size_t start = (size_t)*backed;
    if (start >= *blen)
        return;
    if (*bsent < *blen) {
        start = *bsent;               /* append unsent data immediately */
    } else if (now < c->hs_resend_at) {
        return;                       /* everything sent, waiting for the timer */
    }

    size_t len = *blen - start;
    if (len > 1100)
        len = 1100;
    uint8_t fr[1200];
    size_t flen = frame_crypto(fr, start, buf + start, len);
    int pad = (ptype == PKT_INITIAL);
    uint64_t pn_used = *pn;
    quic_send_packet(c, ptype, k, pn, fr, flen, pad);
    *bsent = start + len;

    int found = 0;
    for (int i = 0; i < *cpt_n; i++)
        if (cpt[i].off == start && cpt[i].len == len) {
            cpt[i].pn = pn_used;
            cpt[i].acked = 0;
            found = 1;
            break;
        }
    if (!found && *cpt_n < (int)(sizeof(c->cpt_ini) / sizeof(c->cpt_ini[0]))) {
        cpt[*cpt_n].pn = pn_used;
        cpt[*cpt_n].off = start;
        cpt[*cpt_n].len = len;
        cpt[*cpt_n].acked = 0;
        (*cpt_n)++;
    }
    c->hs_resend_at = now + 400;
}

/* retransmit unacked 1-RTT packets; called with c->mu held */
static void quic_flush_1rtt(quic_conn_t *c) {
    if (!c->cap.valid)
        return;
    int64_t now = mono_ms();
    if (now < c->rtx_next)
        return;
    c->rtx_next = now + 100;
    if (c->hs_done) {
        /* liveness: the server keeps the path warm with its own keepalive,
         * but stay independent in case it is disabled on the peer */
        if (now - c->last_recv_at > 30000) {
            c->closed = 1;
            quic_signal(c);
            return;
        }
        if (now - c->last_send_at > 10000 && now - c->last_recv_at > 10000) {
            uint8_t ping = FR_PING;
            quic_send_1rtt(c, &ping, 1);
        }
    }
    if (c->txq && c->last_ack_at && now - c->last_ack_at > 30000) {
        c->closed = 1;
        quic_signal(c);
        return;
    }
    quic_txpkt_t **pp = &c->txq;
    while (*pp) {
        quic_txpkt_t *e = *pp;
        if (!e->ack_only && now >= e->next_rtx) {
            uint8_t frames[QUIC_MAX_DGRAM];
            size_t flen = e->flen;
            int backoff = e->backoff_ms < 2000 ? e->backoff_ms * 2 : 4000;
            memcpy(frames, e->frames, flen);
            *pp = e->next;
            c->txq_bytes -= e->flen;
            free(e);
            c->rtx_hint = backoff;
            quic_send_1rtt(c, frames, flen);
            c->rtx_hint = 0;
            continue;
        }
        pp = &e->next;
    }
}

/* ------------------------------------------------------------------ */
/* receive path                                                        */
/* ------------------------------------------------------------------ */

/* append data to the stream receive buffer (called with c->mu held) */
static void quic_stream_append(quic_stream_t *s, const uint8_t *data,
                               size_t slen, int fin) {
    if (s->rxlen + slen > s->rxcap) {
        size_t ncap = s->rxcap ? s->rxcap * 2 : 8192;
        while (ncap < s->rxlen + slen)
            ncap *= 2;
        uint8_t *nb = realloc(s->rxbuf, ncap);
        if (nb) { s->rxbuf = nb; s->rxcap = ncap; }
    }
    if (s->rxbuf && s->rxlen + slen <= s->rxcap) {
        if (slen)
            memcpy(s->rxbuf + s->rxlen, data, slen);
        s->rxlen += slen;
        s->rx_offset += slen;
    }
    if (fin)
        s->rx_closed = 1;
}

static void quic_stream_drain(quic_stream_t *s) {
    int progress = 1;
    while (progress) {
        progress = 0;
        quic_rxchunk_t **pp = &s->rxq;
        while (*pp) {
            quic_rxchunk_t *ch = *pp;
            if (ch->off == s->rx_offset) {
                quic_stream_append(s, ch->data, ch->len, ch->fin);
                *pp = ch->next;
                s->rxq_bytes -= ch->len;
                free(ch->data);
                free(ch);
                progress = 1;
                continue;
            }
            pp = &ch->next;
        }
    }
    pthread_cond_broadcast(&s->cv);
}

static void quic_stream_queue_chunk(quic_stream_t *s, uint64_t off,
                                    const uint8_t *data, size_t len, int fin) {
    if (s->rxq_bytes + len > 16 * 1024 * 1024)
        return;
    quic_rxchunk_t *ch = calloc(1, sizeof(*ch));
    if (!ch)
        return;
    if (len > 0) {
        ch->data = malloc(len);
        if (!ch->data) {
            free(ch);
            return;
        }
        memcpy(ch->data, data, len);
    }
    ch->off = off;
    ch->len = len;
    ch->fin = fin;
    quic_rxchunk_t **pp = &s->rxq;
    while (*pp && (*pp)->off < off)
        pp = &(*pp)->next;
    ch->next = *pp;
    *pp = ch;
    s->rxq_bytes += len;
    DBGQ("OOO off=%llu len=%zu fin=%d\n",
         (unsigned long long)off, len, fin);
}

/* queue out-of-order data, splitting around already-queued ranges */
static void quic_stream_queue(quic_stream_t *s, uint64_t off,
                              const uint8_t *data, size_t slen, int fin) {
    while (slen > 0) {
        quic_rxchunk_t *e = s->rxq;
        while (e && e->off + e->len <= off)
            e = e->next;
        if (!e || e->off >= off + slen) {
            quic_stream_queue_chunk(s, off, data, slen, fin);
            return;
        }
        if (e->off > off) {
            size_t piece = (size_t)(e->off - off);
            quic_stream_queue_chunk(s, off, data, piece, 0);
            off += piece;
            data += piece;
            slen -= piece;
            continue;
        }
        size_t skip = (size_t)(e->off + e->len - off);
        if (skip >= slen) {
            if (fin)
                e->fin = 1;
            return;
        }
        off += skip;
        data += skip;
        slen -= skip;
    }
    if (fin) {
        for (quic_rxchunk_t *e = s->rxq; e; e = e->next)
            if (e->off <= off && off <= e->off + e->len) {
                e->fin = 1;
                return;
            }
        quic_stream_queue_chunk(s, off, NULL, 0, 1);
    }
}

static void quic_stream_deliver_locked(quic_stream_t *s, uint64_t sid,
                                       uint64_t off, const uint8_t *data,
                                       size_t slen, int fin) {
    (void)sid;

    /* drop data already consumed */
    if (off < s->rx_offset) {
        size_t skip = (size_t)(s->rx_offset - off);
        if (skip >= slen) {
            quic_stream_drain(s);
            return;
        }
        off += skip;
        data += skip;
        slen -= skip;
    }

    if (off == s->rx_offset) {
        if (s->rxq && slen)
            DBGQ("gap fill sid=%llu off=%llu len=%zu\n",
                 (unsigned long long)sid, (unsigned long long)off, slen);
        quic_stream_append(s, data, slen, fin);
        quic_stream_drain(s);
        return;
    }
    if (slen == 0 && !fin) {
        quic_stream_drain(s);
        return;
    }

    quic_stream_queue(s, off, data, slen, fin);
    quic_stream_drain(s);
}

static void quic_stream_deliver(quic_conn_t *c, uint64_t sid, uint64_t off,
                                const uint8_t *data, size_t slen, int fin) {
    quic_stream_t *s;
    for (s = c->streams; s; s = s->next)
        if (s->id == sid)
            break;
    if (!s)
        return;
    pthread_mutex_lock(&s->mu);
    quic_stream_deliver_locked(s, sid, off, data, slen, fin);
    pthread_mutex_unlock(&s->mu);
}


static void quic_handshake_fail(quic_conn_t *c) {
    c->hs_failed = 1;
    c->closed = 1;
    quic_signal(c);
}

/* mark handshake CRYPTO ranges acked and advance the contiguous prefix */
static void quic_ack_crypto(quic_conn_t *c, int space, uint64_t largest) {
    quic_cpt_t *cpt = (space == 0) ? c->cpt_ini : c->cpt_hs;
    int n = (space == 0) ? c->cpt_ini_n : c->cpt_hs_n;
    uint64_t *backed = (space == 0) ? &c->tx_ini_acked : &c->tx_hs_acked;
    size_t *bsent = (space == 0) ? &c->tx_ini_sent : &c->tx_hs_sent;

    for (int i = 0; i < n; i++)
        if (cpt[i].len > 0 && cpt[i].pn <= largest)
            cpt[i].acked = 1;
    size_t b = 0;
    int progressed = 1;
    while (progressed) {
        progressed = 0;
        for (int i = 0; i < n; i++)
            if (cpt[i].acked && cpt[i].off == b && cpt[i].len > 0) {
                b = cpt[i].off + cpt[i].len;
                progressed = 1;
                break;
            }
    }
    if (b > *backed)
        *backed = b;
    if (*backed > *bsent)
        *backed = *bsent;
}

/* feed queued out-of-order Handshake CRYPTO chunks once the gap is filled */
static void quic_crypto_drain_pending(quic_conn_t *c) {
    int progress = 1;
    while (progress && !c->hs_failed) {
        progress = 0;
        quic_rxchunk_t **pp = &c->crypto_pending;
        while (*pp) {
            quic_rxchunk_t *ch = *pp;
            if (ch->off == c->crypto_hs_off) {
                if (c->hs_inlen + ch->len > sizeof(c->hs_in)) {
                    quic_handshake_fail(c);
                    return;
                }
                memcpy(c->hs_in + c->hs_inlen, ch->data, ch->len);
                c->hs_inlen += ch->len;
                c->crypto_hs_off += ch->len;
                *pp = ch->next;
                c->crypto_pending_bytes -= ch->len;
                free(ch->data);
                free(ch);
                quic_handshake_input(c);
                progress = 1;
                continue;
            }
            pp = &ch->next;
        }
    }
}

/* hand CRYPTO data to the TLS state machine, buffering out-of-order chunks */
static void quic_crypto_input(quic_conn_t *c, int space, uint64_t off,
                              const uint8_t *data, size_t len) {
    if (c->hs_failed || c->hs_done)
        return;
    if (space == 0) {
        /* the ServerHello always fits a single Initial frame */
        if (off < c->crypto_ini_off)
            return;
        if (off != c->crypto_ini_off || c->hs_inlen + len > sizeof(c->hs_in)) {
            quic_handshake_fail(c);
            return;
        }
        memcpy(c->hs_in + c->hs_inlen, data, len);
        c->hs_inlen += len;
        c->crypto_ini_off = off + len;
        quic_handshake_input(c);
        return;
    }
    if (off < c->crypto_hs_off) {
        size_t skip = (size_t)(c->crypto_hs_off - off);
        if (skip >= len)
            return;
        off += skip;
        data += skip;
        len -= skip;
    }
    if (off == c->crypto_hs_off) {
        if (c->hs_inlen + len > sizeof(c->hs_in)) {
            quic_handshake_fail(c);
            return;
        }
        memcpy(c->hs_in + c->hs_inlen, data, len);
        c->hs_inlen += len;
        c->crypto_hs_off = off + len;
        quic_handshake_input(c);
        quic_crypto_drain_pending(c);
        return;
    }
    /* out of order: dedupe against queued chunks, then queue (bounded) */
    if (len == 0 || c->crypto_pending_bytes + len > 16384)
        return;
    for (quic_rxchunk_t *e = c->crypto_pending; e; e = e->next) {
        if (e->off == off && e->len == len)
            return;
        if (off < e->off) {
            if (off + len > e->off)
                len = (size_t)(e->off - off);
        } else if (off < e->off + e->len) {
            size_t skip = (size_t)(e->off + e->len - off);
            if (skip >= len)
                return;
            off += skip;
            data += skip;
            len -= skip;
        }
        if (len == 0)
            return;
    }
    quic_rxchunk_t *ch = calloc(1, sizeof(*ch));
    if (!ch)
        return;
    ch->data = malloc(len);
    if (!ch->data) {
        free(ch);
        return;
    }
    memcpy(ch->data, data, len);
    ch->off = off;
    ch->len = len;
    quic_rxchunk_t **pp = &c->crypto_pending;
    while (*pp && (*pp)->off < off)
        pp = &(*pp)->next;
    ch->next = *pp;
    *pp = ch;
    c->crypto_pending_bytes += len;
}

/* free send-queue records acked in [lo, hi]; called with c->mu held */
static void quic_ack_range(quic_conn_t *c, uint64_t lo, uint64_t hi) {    quic_txpkt_t **pp = &c->txq;
    while (*pp) {
        quic_txpkt_t *e = *pp;
        if (e->pn >= lo && e->pn <= hi) {
            *pp = e->next;
            c->txq_bytes -= e->flen;
            free(e);
        } else {
            pp = &e->next;
        }
    }
}

/* parse frames of one decrypted packet; called with c->mu held.
 * space: 0 = Initial, 1 = Handshake, 2 = 1-RTT */
static void quic_parse_frames(quic_conn_t *c, int space, const uint8_t *pt, size_t ct_len) {
    size_t q = 0;
    while (q < ct_len) {
        uint8_t ftype = pt[q++];
        if (space == 2)
            DBGQ("  frame=0x%02x q=%zu\n", ftype, q);
        if (ftype == FR_PADDING || ftype == FR_PING)
            continue;
        if (ftype == FR_ACK || ftype == 0x03) {   /* 0x03 = ACK_ECN */
            uint64_t largest, v, ranges; size_t u;
            if (varint_get(pt + q, ct_len - q, &largest, &u) < 0) break;
            q += u;
            if (varint_get(pt + q, ct_len - q, &v, &u) < 0) break;   /* ack delay */
            q += u;
            if (varint_get(pt + q, ct_len - q, &ranges, &u) < 0) break;
            q += u;
            if (varint_get(pt + q, ct_len - q, &v, &u) < 0) break;   /* first range */
            q += u;
            uint64_t range_lo = largest >= v ? largest - v : 0;
            if (space == 2 && largest <= (1ull << 40))
                quic_ack_range(c, range_lo, largest);
            if (space == 2)
                c->last_ack_at = mono_ms();
            int bad = 0;
            for (uint64_t i = 0; i < ranges && i < 4096; i++) {
                uint64_t gap, rng;
                if (varint_get(pt + q, ct_len - q, &gap, &u) < 0) { bad = 1; break; }
                q += u;
                if (varint_get(pt + q, ct_len - q, &rng, &u) < 0) { bad = 1; break; }
                q += u;
                if (range_lo < gap + 2) { bad = 1; break; }
                uint64_t hi = range_lo - gap - 2;
                uint64_t lo = hi >= rng ? hi - rng : 0;
                if (space == 2 && hi <= (1ull << 40))
                    quic_ack_range(c, lo, hi);
                range_lo = lo;
            }
            if (!bad && ftype == 0x03) {
                for (int i = 0; i < 3; i++) {                        /* ECT0, ECT1, CE */
                    if (varint_get(pt + q, ct_len - q, &v, &u) < 0) { bad = 1; break; }
                    q += u;
                }
            }
            if (bad) break;
            if (space == 0 || space == 1)
                quic_ack_crypto(c, space, largest);
            if (space == 2)
                quic_signal(c);
            continue;
        }
        if (ftype == FR_CRYPTO) {
            uint64_t off, clen; size_t u;
            if (varint_get(pt + q, ct_len - q, &off, &u) < 0) break;
            q += u;
            if (varint_get(pt + q, ct_len - q, &clen, &u) < 0) break;
            q += u;
            if (q + clen > ct_len) break;
            if (space != 2)
                quic_crypto_input(c, space, off, pt + q, (size_t)clen);
            q += clen;
            continue;
        }
        if (ftype == FR_HANDSHAKE_DONE) {
            c->hs_done = 1;
            c->tx_ini_acked = c->tx_ini_sent;
            c->tx_hs_acked = c->tx_hs_sent;
            c->last_ack_at = mono_ms();
            quic_signal(c);
            continue;
        }
        if ((ftype & 0xf8) == FR_STREAM) {
            uint64_t sid, off = 0, slen; size_t u;
            if (varint_get(pt + q, ct_len - q, &sid, &u) < 0) break;
            q += u;
            if (ftype & 0x04) {
                if (varint_get(pt + q, ct_len - q, &off, &u) < 0) break;
                q += u;
            }
            if (ftype & 0x02) {
                if (varint_get(pt + q, ct_len - q, &slen, &u) < 0) break;
                q += u;
            } else slen = ct_len - q;
            if (q + slen > ct_len) break;
            DBGQ("stream sid=%llu off=%llu len=%zu fin=%d space=%d\n",
                 (unsigned long long)sid, (unsigned long long)off, slen,
                 (int)(ftype & 0x01), space);
            quic_stream_deliver(c, sid, off, pt + q, slen, (ftype & 0x01) != 0);
            q += slen;
            continue;
        }
        if (ftype == FR_CONNECTION_CLOSE_APP || ftype == FR_CONNECTION_CLOSE) {
#ifdef TFRPC_QUIC_DEBUG
            uint64_t errcode = 0, ftype2 = 0, rlen = 0; size_t u;
            if (varint_get(pt + q, ct_len - q, &errcode, &u) == 0) {
                q += u;
                if (ftype == FR_CONNECTION_CLOSE &&
                    varint_get(pt + q, ct_len - q, &ftype2, &u) == 0)
                    q += u;
                if (varint_get(pt + q, ct_len - q, &rlen, &u) == 0)
                    q += u;
                size_t avail = (q <= ct_len) ? ct_len - q : 0;
                int show = rlen > 64 ? 64 : (int)rlen;
                if ((size_t)show > avail)
                    show = (int)avail;
                DBGQ("CONNECTION_CLOSE err=0x%llx frame=0x%llx reason_len=%llu reason=%.*s\n",
                     (unsigned long long)errcode, (unsigned long long)ftype2,
                     (unsigned long long)rlen, show, (const char *)(pt + q));
            }
#endif
            c->closed = 1;
            quic_signal(c);
            break;
        }
        if (ftype == FR_NEW_CONNECTION_ID) {
            uint64_t seq, retire, cl; size_t u;
            if (varint_get(pt + q, ct_len - q, &seq, &u) < 0) break;
            q += u;
            if (varint_get(pt + q, ct_len - q, &retire, &u) < 0) break;
            q += u;
            if (varint_get(pt + q, ct_len - q, &cl, &u) < 0) break;
            q += u;
            if (q + cl + 16 > ct_len) break;
            q += cl + 16;
            continue;
        }
        if (ftype == FR_RESET_STREAM) {
            uint64_t sid, v; size_t u;
            if (varint_get(pt + q, ct_len - q, &sid, &u) < 0) break;
            q += u;
            for (int i = 0; i < 2; i++) {
                if (varint_get(pt + q, ct_len - q, &v, &u) < 0) break;
                q += u;
            }
            for (quic_stream_t *s = c->streams; s; s = s->next)
                if (s->id == sid) {
                    s->rx_closed = 1;
                    pthread_cond_broadcast(&s->cv);
                    break;
                }
            continue;
        }
        if (ftype == FR_STOP_SENDING) {
            uint64_t v; size_t u;
            for (int i = 0; i < 2; i++) {
                if (varint_get(pt + q, ct_len - q, &v, &u) < 0) break;
                q += u;
            }
            continue;
        }
        if (ftype == FR_NEW_TOKEN) {
            uint64_t tl; size_t u;
            if (varint_get(pt + q, ct_len - q, &tl, &u) < 0) break;
            q += u;
            if (tl > ct_len - q) break;
            q += (size_t)tl;
            continue;
        }
        if (ftype == FR_MAX_DATA) {
            uint64_t v; size_t u;
            if (varint_get(pt + q, ct_len - q, &v, &u) < 0) break;
            q += u;
            if (v > c->tx_max_data) {
                c->tx_max_data = v;
                DBGQ("rx MAX_DATA v=%llu\n", (unsigned long long)v);
                quic_signal(c);
            }
            continue;
        }
        if (ftype == FR_MAX_STREAMS) {
            uint64_t v; size_t u;
            if (varint_get(pt + q, ct_len - q, &v, &u) < 0) break;
            q += u;
            if (v > c->peer_max_streams) {
                c->peer_max_streams = v;
                quic_signal(c);
            }
            continue;
        }
        if (ftype == 0x13 ||
            ftype == 0x14 || ftype == 0x16 || ftype == 0x17 || ftype == 0x19) {
            uint64_t v; size_t u;
            if (varint_get(pt + q, ct_len - q, &v, &u) < 0) break;
            q += u;
            continue;
        }
        if (ftype == FR_MAX_STREAM_DATA) {
            uint64_t sid, v; size_t u;
            if (varint_get(pt + q, ct_len - q, &sid, &u) < 0) break;
            q += u;
            if (varint_get(pt + q, ct_len - q, &v, &u) < 0) break;
            q += u;
            for (quic_stream_t *s = c->streams; s; s = s->next)
                if (s->id == sid) {
                    if (v > s->tx_max) {
                        DBGQ("rx MAX_STREAM_DATA sid=%llu v=%llu\n",
                             (unsigned long long)sid, (unsigned long long)v);
                        s->tx_max = v;
                        quic_signal(c);
                    }
                    break;
                }
            continue;
        }
        if (ftype == 0x15) {          /* STREAM_DATA_BLOCKED */
            uint64_t v; size_t u;
            int bad = 0;
            for (int i = 0; i < 2; i++) {
                if (varint_get(pt + q, ct_len - q, &v, &u) < 0) { bad = 1; break; }
                q += u;
            }
            if (bad) break;
            continue;
        }
        if (ftype == 0x1a) {          /* PATH_CHALLENGE -> PATH_RESPONSE */
            if (q + 8 > ct_len) break;
            uint8_t fr[9];
            fr[0] = 0x1b;
            memcpy(fr + 1, pt + q, 8);
            quic_send_1rtt(c, fr, sizeof(fr));
            q += 8;
            continue;
        }
        if (ftype == 0x1b) {          /* PATH_RESPONSE */
            if (q + 8 > ct_len) break;
            q += 8;
            continue;
        }
        break;
    }
}

static size_t quic_recv_long(quic_conn_t *c, const uint8_t *buf, size_t n) {
    if (n < 5)                       /* long header needs version bytes */
        return 0;
    if (n > QUIC_MAX_DGRAM)          /* defensive: caller buffer is smaller */
        n = QUIC_MAX_DGRAM;
    uint8_t ptype = buf[0] & 0x30;
    uint32_t version = ((uint32_t)buf[1] << 24) | ((uint32_t)buf[2] << 16) |
                       ((uint32_t)buf[3] << 8) | buf[4];
    DBGQ("long ptype=%02x ver=%08x\n", ptype, version);
    if (version != QUIC_VERSION)
        return 0;
    size_t p = 5;
    if (p >= n) return 0;
    size_t dlen = buf[p++];
    if (p + dlen >= n) return 0;
    p += dlen;
    size_t slen = buf[p++];
    if (p + slen > n) return 0;
    const uint8_t *scid = buf + p;
    p += slen;
    if (ptype == PKT_INITIAL) {
        uint64_t toklen; size_t tu;
        if (varint_get(buf + p, n - p, &toklen, &tu) < 0)
            return 0;
        p += tu;
        if (toklen > n - p)
            return 0;
        p += (size_t)toklen;
    }
    uint64_t plen; size_t used;
    if (varint_get(buf + p, n - p, &plen, &used) < 0)
        return 0;
    p += used;
    size_t pkt_end = p + (size_t)plen;
    if (pkt_end > n)
        return 0;

    /* the server's SCID becomes our destination CID */
    if (slen > 0 && slen <= sizeof(c->server_scid) && c->server_scid_len == 0) {
        memcpy(c->server_scid, scid, slen);
        c->server_scid_len = slen;
        memcpy(c->dcid, scid, slen);
        c->dcid_len = slen;
    }

    quic_keys_t *k = NULL;
    int space = -1;
    if (ptype == PKT_INITIAL && c->sinit.valid) { k = &c->sinit; space = 0; }
    else if (ptype == PKT_HANDSHAKE && c->shs.valid) { k = &c->shs; space = 1; }
    if (!k)
        return pkt_end;

    size_t pn_pos = p;
    if (pn_pos + 1 + 16 > pkt_end)
        return pkt_end;

    uint8_t tmp[QUIC_MAX_DGRAM];
    memcpy(tmp, buf, n);
    size_t pn_len = quic_remove_hp(k, tmp, n, pn_pos);
    if (pn_pos + pn_len + 16 > pkt_end)
        return pkt_end;

    uint64_t largest = (space == 0) ? c->rpn_initial : c->rpn_handshake;
    uint64_t truncated = 0;
    for (size_t i = 0; i < pn_len; i++)
        truncated = (truncated << 8) | tmp[pn_pos + i];
    uint64_t pktnum = pn_decode(largest, truncated, pn_len);

    uint8_t nonce[12];
    quic_nonce(nonce, k, pktnum);
    size_t cipher_off = pn_pos + pn_len;
    size_t ct_len = pkt_end - cipher_off - 16;
    uint8_t pt[QUIC_MAX_DGRAM];
    memcpy(pt, tmp + cipher_off, ct_len + 16);
    uint8_t aad[QUIC_MAX_DGRAM];
    memcpy(aad, tmp, pn_pos);
    memcpy(aad + pn_pos, tmp + pn_pos, pn_len);
    if (aes_gcm_open(k->key, 16, nonce, aad, pn_pos + pn_len, pt, ct_len, pt + ct_len) != 0) {
        DBGQ("long decrypt FAIL space=%d pn=%llu\n", space, (unsigned long long)pktnum);
        return pkt_end;
    }
    DBGQ("long decrypt OK space=%d pn=%llu frames=%zu\n", space, (unsigned long long)pktnum, ct_len);

    if (space == 0) c->rpn_initial = pktnum; else c->rpn_handshake = pktnum;
    c->last_recv_at = mono_ms();
    quic_parse_frames(c, space, pt, ct_len);
    quic_send_ack(c, ptype, k, pktnum);
    return pkt_end;
}

static size_t quic_recv_short(quic_conn_t *c, const uint8_t *buf, size_t n) {
    if (n > QUIC_MAX_DGRAM)
        n = QUIC_MAX_DGRAM;
    if (!c->sap.valid) {
        DBGQ("short: no app keys yet\n");
        return n;
    }
    size_t p = 1;
    if (p + c->scid_len + 1 > n) return n;
    p += c->scid_len;
    size_t pn_pos = p;
    if (pn_pos + 1 + 16 > n)
        return n;
    uint8_t tmp[QUIC_MAX_DGRAM];
    memcpy(tmp, buf, n);
    size_t pn_len = quic_remove_hp(&c->sap, tmp, n, pn_pos);
    if (pn_pos + pn_len + 16 > n)
        return n;
    uint64_t truncated = 0;
    for (size_t i = 0; i < pn_len; i++)
        truncated = (truncated << 8) | tmp[pn_pos + i];
    uint64_t pktnum = pn_decode(c->rpn_app, truncated, pn_len);

    size_t cipher_off = pn_pos + pn_len;
    size_t ct_len = n - cipher_off - 16;
    uint8_t pt[QUIC_MAX_DGRAM];
    memcpy(pt, tmp + cipher_off, ct_len + 16);
    uint8_t aad[QUIC_MAX_DGRAM];
    memcpy(aad, tmp, pn_pos);
    memcpy(aad + pn_pos, tmp + pn_pos, pn_len);

    /* header protection uses the initial HP key for all key phases */
    uint8_t nonce[12];
    quic_nonce(nonce, &c->sap, pktnum);
    int opened = aes_gcm_open(c->sap.key, 16, nonce, aad, pn_pos + pn_len,
                              pt, ct_len, pt + ct_len) == 0;
    int phase = (tmp[0] >> 2) & 1;
    if (!opened && phase != c->key_phase) {
        /* peer initiated a key update (RFC 9001 6.2) */
        uint8_t ncap[32], nsap[32];
        quic_keys_t nk;
        quic_expand_label(c->sap_secret, 32, "quic ku", NULL, 0, nsap, 32);
        quic_keys_init(&nk, nsap);
        memcpy(nk.hp, c->sap.hp, sizeof(nk.hp));   /* HP key is not updated */
        quic_nonce(nonce, &nk, pktnum);
        if (aes_gcm_open(nk.key, 16, nonce, aad, pn_pos + pn_len,
                         pt, ct_len, pt + ct_len) == 0) {
            quic_expand_label(c->cap_secret, 32, "quic ku", NULL, 0, ncap, 32);
            c->psap = c->sap;
            c->pcap = c->cap;
            memcpy(c->sap_secret, nsap, 32);
            memcpy(c->cap_secret, ncap, 32);
            c->sap = nk;
            quic_keys_init(&c->cap, c->cap_secret);
            memcpy(c->cap.hp, c->pcap.hp, sizeof(c->cap.hp));
            c->key_phase = phase;
            opened = 1;
            DBGQ("key update -> phase=%d\n", phase);
        }
        secure_zero(ncap, sizeof(ncap));
        secure_zero(nsap, sizeof(nsap));
    }
    if (!opened && phase != c->key_phase && c->psap.valid) {
        /* late packet from the previous key phase */
        quic_nonce(nonce, &c->psap, pktnum);
        opened = aes_gcm_open(c->psap.key, 16, nonce, aad, pn_pos + pn_len,
                              pt, ct_len, pt + ct_len) == 0;
    }
    if (!opened) {
        DBGQ("short decrypt FAIL pn=%llu len=%zu\n", (unsigned long long)pktnum, ct_len);
        return n;
    }
    c->rpn_app = pktnum;
    c->last_recv_at = mono_ms();
    DBGQ("short decrypt OK pn=%llu frames=%zu\n", (unsigned long long)pktnum, ct_len);

    quic_parse_frames(c, 2, pt, ct_len);
    quic_send_ack(c, 0xff, &c->cap, pktnum);
    return n;
}

static void quic_process_packet(quic_conn_t *c, const uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        const uint8_t *p = buf + off;
        size_t rem = n - off;
        if (p[0] & 0x80) {
            size_t used = quic_recv_long(c, p, rem);
            if (used == 0 || used > rem)
                break;
            off += used;
        } else {
            quic_recv_short(c, p, rem);
            break;
        }
    }
}

/* ------------------------------------------------------------------ */
/* reader thread                                                       */
/* ------------------------------------------------------------------ */

static void *quic_reader(void *arg) {
    quic_conn_t *c = arg;
    uint8_t buf[QUIC_MAX_DGRAM];
    for (;;) {
        struct pollfd pfd = { .fd = c->fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 100);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (c->closed)
            break;
        pthread_mutex_lock(&c->mu);
        quic_flush_crypto(c);
        quic_flush_1rtt(c);
        pthread_mutex_unlock(&c->mu);
        if (pr == 0)
            continue;
        ssize_t n = recv(c->fd, buf, sizeof(buf), 0);
        DBGQ("recv n=%zd first=%02x\n", n, n > 0 ? buf[0] : 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
            if (c->closed)
                break;
            continue;
        }
        pthread_mutex_lock(&c->mu);
        if (!c->closed)
            quic_process_packet(c, buf, (size_t)n);
        pthread_mutex_unlock(&c->mu);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */

quic_conn_t *quic_dial(const char *host, uint16_t port, const char *server_name,
                       const void *ca, int timeout_ms) {
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res)
        return NULL;

    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    if (fd < 0) {
        freeaddrinfo(res);
        return NULL;
    }

    quic_conn_t *c = calloc(1, sizeof(*c));
    if (!c) {
        close(fd);
        freeaddrinfo(res);
        return NULL;
    }
    c->fd = fd;
    memcpy(&c->peer, ai->ai_addr, ai->ai_addrlen);
    c->peerlen = ai->ai_addrlen;
    freeaddrinfo(res);
    c->ca = ca;
    c->server_name = server_name;
    c->tx_max_data = 1048576;
    c->tx_stream_max = QUIC_RX_WINDOW;
    c->rx_max_data_sent = QUIC_CONN_RX_WINDOW;
    c->last_recv_at = c->last_send_at = mono_ms();
    pthread_mutex_init(&c->mu, NULL);
    pthread_cond_init(&c->cv, NULL);

    uint8_t rnd[16];
    random_bytes(rnd, sizeof(rnd));
    memcpy(c->dcid, rnd, 8);
    c->dcid_len = 8;
    memcpy(c->scid, rnd + 8, 8);
    c->scid_len = 8;

    quic_hs_t *h = &c->hs;
    random_bytes(h->client_priv, 32);
    x25519_base(h->client_pub, h->client_priv);
    sha256_init(&h->transcript);

    size_t chlen = quic_build_client_hello(h, c->tx_ini, c->scid, c->scid_len);
    c->tx_ini_len = chlen;
    sha256_update(&h->transcript, c->tx_ini, chlen);

    uint8_t initial_secret[32], cli_secret[32], srv_secret[32];
    quic_hkdf_extract(QUIC_INITIAL_SALT, sizeof(QUIC_INITIAL_SALT),
                      c->dcid, c->dcid_len, initial_secret);
    quic_expand_label(initial_secret, 32, "client in", NULL, 0, cli_secret, 32);
    quic_expand_label(initial_secret, 32, "server in", NULL, 0, srv_secret, 32);
    quic_keys_init(&c->cinit, cli_secret);
    quic_keys_init(&c->sinit, srv_secret);
    secure_zero(initial_secret, sizeof(initial_secret));
    secure_zero(cli_secret, sizeof(cli_secret));
    secure_zero(srv_secret, sizeof(srv_secret));

    if (pthread_create(&c->reader, NULL, quic_reader, c) != 0) {
        quic_conn_close(c);
        return NULL;
    }
    c->reader_started = 1;

    /* send the ClientHello and wait for the handshake to complete */
    pthread_mutex_lock(&c->mu);
    quic_flush_crypto(c);
    pthread_mutex_unlock(&c->mu);

    int64_t deadline = mono_ms() + timeout_ms;

    pthread_mutex_lock(&c->mu);
    while (!c->hs_done && !c->hs_failed && !c->closed) {
        if (!atomic_load(&g_running))
            break;                       /* SIGTERM during dial: give up fast */
        int64_t left = deadline - mono_ms();
        if (left <= 0)
            break;
        if (left > 250)
            left = 250;
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += left / 1000;
        ts.tv_nsec += (long)(left % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
        pthread_cond_timedwait(&c->cv, &c->mu, &ts);
    }
    int ok = c->hs_done && !c->hs_failed && !c->closed;
    DBGQ("dial wait: done=%d failed=%d closed=%d\n", c->hs_done, c->hs_failed, c->closed);
    pthread_mutex_unlock(&c->mu);

    if (!ok) {
        quic_conn_close(c);
        return NULL;
    }
    return c;
}

quic_stream_t *quic_open_stream(quic_conn_t *c) {
    if (!c)
        return NULL;
    quic_stream_t *s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->rxcap = 8192;
    s->rxbuf = malloc(s->rxcap);
    if (!s->rxbuf) {
        free(s);
        return NULL;
    }
    s->qc = c;
    pthread_mutex_init(&s->mu, NULL);
    pthread_cond_init(&s->cv, NULL);
    pthread_mutex_lock(&c->mu);
    if (c->closed || !c->hs_done) {
        pthread_mutex_unlock(&c->mu);
        pthread_mutex_destroy(&s->mu);
        pthread_cond_destroy(&s->cv);
        free(s->rxbuf);
        free(s);
        return NULL;
    }
    /* respect the peer's concurrent bidirectional stream limit */
    if (c->peer_max_streams == 0)
        c->peer_max_streams = 100;
    DBGQ("open_stream: opened=%llu limit=%llu\n",
         (unsigned long long)c->streams_opened, (unsigned long long)c->peer_max_streams);
    int64_t limit_deadline = mono_ms() + 30000;
    while (!c->closed && c->streams_opened >= c->peer_max_streams) {
        int64_t left = limit_deadline - mono_ms();
        if (left <= 0) {
            pthread_mutex_unlock(&c->mu);
            pthread_mutex_destroy(&s->mu);
            pthread_cond_destroy(&s->cv);
            free(s->rxbuf);
            free(s);
            return NULL;
        }
        if (left > 100)
            left = 100;
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += left / 1000;
        ts.tv_nsec += (long)(left % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
        pthread_cond_timedwait(&c->cv, &c->mu, &ts);
    }
    if (c->closed) {
        pthread_mutex_unlock(&c->mu);
        pthread_mutex_destroy(&s->mu);
        pthread_cond_destroy(&s->cv);
        free(s->rxbuf);
        free(s);
        return NULL;
    }
    c->streams_opened++;
    s->id = c->next_stream_id;
    c->next_stream_id += 4;
    s->tx_max = c->tx_stream_max ? c->tx_stream_max : QUIC_RX_WINDOW;
    s->rx_max_sent = QUIC_RX_WINDOW;
    s->next = c->streams;
    c->streams = s;
    pthread_mutex_unlock(&c->mu);
    return s;
}

int quic_stream_read(quic_stream_t *s, uint8_t *buf, int len) {
    if (!s || len <= 0)
        return -1;
    pthread_mutex_lock(&s->mu);
    while (s->rxlen == 0 && !s->rx_closed && !s->aborted) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        if (s->deadline) {
            int64_t left = s->deadline - mono_ms();
            if (left <= 0) {
                pthread_mutex_unlock(&s->mu);
                return -1;
            }
            if (left < 1000) {
                ts.tv_sec += left / 1000;
                ts.tv_nsec += (long)(left % 1000) * 1000000L;
                if (ts.tv_nsec >= 1000000000L) {
                    ts.tv_sec++;
                    ts.tv_nsec -= 1000000000L;
                }
            } else {
                ts.tv_sec += 1;
            }
        } else {
            ts.tv_sec += 1;
        }
        pthread_cond_timedwait(&s->cv, &s->mu, &ts);
        if (s->qc->closed)
            break;
    }
    size_t got = 0;
    if (s->rxlen > 0) {
        got = s->rxlen < (size_t)len ? s->rxlen : (size_t)len;
        memcpy(buf, s->rxbuf, got);
        memmove(s->rxbuf, s->rxbuf + got, s->rxlen - got);
        s->rxlen -= got;
    }
    int closed_now = s->rx_closed || s->aborted || s->qc->closed;
    pthread_mutex_unlock(&s->mu);
    if (got > 0) {
        quic_conn_t *c = s->qc;
        pthread_mutex_lock(&c->mu);
        if (!c->closed) {
            c->rx_consumed += (uint64_t)got;
            if (s->rx_offset + QUIC_RX_WINDOW - s->rx_max_sent > QUIC_RX_WINDOW / 2) {
                uint8_t fr[24];
                size_t fl = frame_max_stream_data(fr, s->id, s->rx_offset + QUIC_RX_WINDOW);
                quic_send_1rtt(c, fr, fl);
                DBGQ("win upd sid=%llu rx_off=%llu max_sent=%llu\n",
                     (unsigned long long)s->id, (unsigned long long)s->rx_offset,
                     (unsigned long long)s->rx_max_sent);
                s->rx_max_sent = s->rx_offset + QUIC_RX_WINDOW;
            }
            if (c->rx_consumed + QUIC_CONN_RX_WINDOW - c->rx_max_data_sent >
                QUIC_CONN_RX_WINDOW / 2) {
                uint8_t fr[16];
                size_t fl = frame_max_data(fr, c->rx_consumed + QUIC_CONN_RX_WINDOW);
                quic_send_1rtt(c, fr, fl);
                c->rx_max_data_sent = c->rx_consumed + QUIC_CONN_RX_WINDOW;
            }
        }
        pthread_mutex_unlock(&c->mu);
        return (int)got;
    }
    if (closed_now)
        return 0;
    return -1;
}

int quic_stream_write(quic_stream_t *s, const uint8_t *buf, int len) {
    if (!s || len <= 0)
        return -1;
    pthread_mutex_lock(&s->qc->mu);
    if (s->qc->closed || !s->qc->hs_done) {
        pthread_mutex_unlock(&s->qc->mu);
        return -1;
    }
    size_t off = 0;
    while (off < (size_t)len) {
        size_t chunk = (size_t)len - off;
        if (chunk > 1000)
            chunk = 1000;
        while (!s->qc->closed &&
               (s->tx_offset + off + chunk > s->tx_max ||
                s->qc->tx_data_sent + chunk > s->qc->tx_max_data ||
                s->qc->txq_bytes > QUIC_TXQ_CAP)) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += 50 * 1000000L;
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000L;
            }
            pthread_cond_timedwait(&s->qc->cv, &s->qc->mu, &ts);
        }
        if (s->qc->closed) {
            pthread_mutex_unlock(&s->qc->mu);
            return -1;
        }
        uint8_t fr[1200];
        size_t flen = frame_stream(fr, s->id, s->tx_offset + off, buf + off, chunk, 0);
        quic_send_1rtt(s->qc, fr, flen);
        s->qc->tx_data_sent += chunk;
        off += chunk;
    }
    s->tx_offset += (size_t)len;
    pthread_mutex_unlock(&s->qc->mu);
    return 0;
}

int quic_stream_close(quic_stream_t *s) {
    if (!s)
        return -1;
    pthread_mutex_lock(&s->qc->mu);
    uint8_t fr[64];
    size_t flen = frame_stream(fr, s->id, s->tx_offset, NULL, 0, 1);
    quic_send_1rtt(s->qc, fr, flen);
    pthread_mutex_unlock(&s->qc->mu);
    return 0;
}

void quic_stream_abort(quic_stream_t *s) {
    if (!s)
        return;
    pthread_mutex_lock(&s->mu);
    s->aborted = 1;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
}

void quic_stream_free(quic_stream_t *s) {
    if (!s)
        return;
    quic_conn_t *c = s->qc;
    pthread_mutex_lock(&c->mu);
    quic_stream_t **pp = &c->streams;
    while (*pp && *pp != s)
        pp = &(*pp)->next;
    if (*pp)
        *pp = s->next;
    pthread_mutex_unlock(&c->mu);
    while (s->rxq) {
        quic_rxchunk_t *ch = s->rxq;
        s->rxq = ch->next;
        free(ch->data);
        free(ch);
    }
    free(s->rxbuf);
    pthread_mutex_destroy(&s->mu);
    pthread_cond_destroy(&s->cv);
    free(s);
}

int quic_stream_wait_readable(quic_stream_t *s, int timeout_ms) {
    if (!s)
        return 0;
    pthread_mutex_lock(&s->mu);
    if (s->rxlen > 0 || s->rx_closed || s->aborted || s->qc->closed) {
        pthread_mutex_unlock(&s->mu);
        return 1;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int wait_ms = timeout_ms;
    if (s->deadline) {
        int64_t left = s->deadline - mono_ms();
        if (left <= 0) {
            pthread_mutex_unlock(&s->mu);
            return 1;
        }
        if ((int64_t)wait_ms > left)
            wait_ms = (int)left;
    }
    ts.tv_sec += wait_ms / 1000;
    ts.tv_nsec += (long)(wait_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    pthread_cond_timedwait(&s->cv, &s->mu, &ts);
    int r = (s->rxlen > 0 || s->rx_closed || s->aborted || s->qc->closed) ? 1 : 0;
    pthread_mutex_unlock(&s->mu);
    return r;
}

void quic_set_deadline(quic_stream_t *s, int timeout_ms) {
    if (!s)
        return;
    pthread_mutex_lock(&s->mu);
    s->deadline = timeout_ms > 0 ? mono_ms() + timeout_ms : 0;
    pthread_mutex_unlock(&s->mu);
}

void quic_conn_shutdown(quic_conn_t *c) {
    if (!c)
        return;
    pthread_mutex_lock(&c->mu);
    c->closed = 1;
    quic_signal(c);
    for (quic_stream_t *s = c->streams; s; s = s->next)
        pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&c->mu);
}

void quic_conn_close(quic_conn_t *c) {
    if (!c)
        return;
    pthread_mutex_lock(&c->mu);
    c->closed = 1;
    quic_signal(c);
    for (quic_stream_t *s = c->streams; s; s = s->next)
        pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&c->mu);
    if (c->reader_started)
        pthread_join(c->reader, NULL);
    if (c->fd >= 0)
        close(c->fd);
    c->fd = -1;
    quic_stream_t *s = c->streams;
    while (s) {
        quic_stream_t *n = s->next;
        free(s->rxbuf);
        while (s->rxq) {
            quic_rxchunk_t *ch = s->rxq;
            s->rxq = ch->next;
            free(ch->data);
            free(ch);
        }
        pthread_mutex_destroy(&s->mu);
        pthread_cond_destroy(&s->cv);
        free(s);
        s = n;
    }
    while (c->txq) {
        quic_txpkt_t *n = c->txq->next;
        free(c->txq);
        c->txq = n;
    }
    c->txq_bytes = 0;
    while (c->crypto_pending) {
        quic_rxchunk_t *ch = c->crypto_pending;
        c->crypto_pending = ch->next;
        free(ch->data);
        free(ch);
    }
    c->crypto_pending_bytes = 0;
    pthread_mutex_destroy(&c->mu);
    pthread_cond_destroy(&c->cv);
    secure_zero(c->hs.hs_secret, sizeof(c->hs.hs_secret));
    secure_zero(c->hs.c_hs_secret, sizeof(c->hs.c_hs_secret));
    secure_zero(c->hs.s_hs_secret, sizeof(c->hs.s_hs_secret));
    secure_zero(&c->cap, sizeof(c->cap));
    secure_zero(&c->sap, sizeof(c->sap));
    secure_zero(c->cap_secret, sizeof(c->cap_secret));
    secure_zero(c->sap_secret, sizeof(c->sap_secret));
    free(c);
}

/*
 * SPDX-License-Identifier: GPL-3.0-only
 * quic_unit.c - white-box unit tests for the QUIC implementation.
 *
 * Includes quic.c directly so the static helpers (varint, packet-number
 * reconstruction, key schedule, header protection, frame builders, the
 * out-of-order reassembly queue and the handshake-ACK bookkeeping) can be
 * tested deterministically.  Run with `make test`.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "tfrpc.h"

/* quic.c relies on these being defined by the program */
_Atomic int g_running = 1;

#include "../src/quic.c"

static int g_fails;
static int g_checks;

#define CHECK(cond, name)                            \
    do {                                             \
        g_checks++;                                  \
        if (cond) {                                  \
            printf("ok   %s\n", name);               \
        } else {                                     \
            g_fails++;                               \
            printf("FAIL %s\n", name);               \
        }                                            \
    } while (0)

static int hex2bin(const char *h, uint8_t *o) {
    int n = 0;
    while (h[0] && h[1]) {
        unsigned v;
        if (sscanf(h, "%2x", &v) != 1)
            return -1;
        o[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

/* ---------------- varint ---------------- */

static void test_varint(void) {
    static const uint64_t v[] = {
        0, 1, 63, 64, 255, 16383, 16384, 65535,
        (1ull << 30) - 1, 1ull << 30, (1ull << 62) - 1
    };
    int ok = 1;
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        uint8_t buf[8];
        size_t n = varint_put(buf, v[i]);
        uint64_t got = 0;
        size_t used = 0;
        if (varint_get(buf, n, &got, &used) < 0 || got != v[i] || used != n)
            ok = 0;
    }
    CHECK(ok, "varint roundtrip at size boundaries");

    /* non-minimal encodings must decode */
    uint8_t buf[8];
    size_t n = varint_put(buf, 1);           /* 0x01 */
    (void)n;
    uint8_t nonmin[4] = { 0x80, 0x00, 0x00, 0x01 };   /* 4-byte form of 1 */
    uint64_t got = 0;
    size_t used = 0;
    CHECK(varint_get(nonmin, sizeof(nonmin), &got, &used) == 0 &&
          got == 1 && used == 4, "varint decodes non-minimal form");

    /* truncated input must fail, not read out of bounds */
    uint8_t pad[1] = { 0xc0 };
    CHECK(varint_get(pad, sizeof(pad), &got, &used) < 0,
          "varint rejects truncated 8-byte form");
    CHECK(varint_get(pad, 0, &got, &used) < 0, "varint rejects empty input");
}

/* ---------------- packet number ---------------- */

static void test_pn_decode(void) {
    /* RFC 9000 A.3: largest=0xa82f30ea, truncated 0x9b32 on 2 bytes */
    CHECK(pn_decode(0xa82f30eaull, 0x9b32, 2) == 0xa82f9b32ull,
          "pn_decode RFC 9000 A.3 vector");
    CHECK(pn_encode_len(63) == 1 && pn_encode_len(64) == 2,
          "pn_encode_len boundaries");

    /* monotonic round trip across the 1-byte/2-byte boundary */
    uint64_t largest = 0;
    int ok = 1;
    for (uint64_t pn = 0; pn < 700; pn++) {
        size_t len = pn_encode_len(pn);
        uint64_t tr = pn & ((1ull << (8 * len)) - 1);
        if (pn_decode(largest, tr, len) != pn)
            ok = 0;
        largest = pn;
    }
    CHECK(ok, "pn_decode monotonic sequence 0..699");

    /* pn_len 0 is clamped instead of underflowing the shift */
    CHECK(pn_decode(5, 7, 0) == pn_decode(5, 7, 1), "pn_decode clamps pn_len 0");
}

/* ---------------- key schedule / header protection ---------------- */

static void test_keys(void) {
    /* RFC 9001 A.1 client initial keys */
    quic_keys_t k;
    uint8_t secret[32];
    char *h = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea";
    hex2bin(h, secret);
    quic_keys_init(&k, secret);
    uint8_t exp_key[16], exp_iv[12], exp_hp[16];
    hex2bin("1f369613dd76d5467730efcbe3b1a22d", exp_key);
    hex2bin("fa044b2f42a3fd3b46fb255c", exp_iv);
    hex2bin("9f50449e04a0e810283a1e9933adedd2", exp_hp);
    CHECK(memcmp(k.key, exp_key, 16) == 0, "quic_keys_init RFC 9001 A.1 key");
    CHECK(memcmp(k.iv, exp_iv, 12) == 0, "quic_keys_init RFC 9001 A.1 iv");
    CHECK(memcmp(k.hp, exp_hp, 16) == 0, "quic_keys_init RFC 9001 A.1 hp");

    /* HKDF-Expand-Label against the RFC 9001 A.1 "client in" secret */
    uint8_t isec[32], cli[32];
    hex2bin("38762cf7f55934b34d179ae6a4c80cadccbb7f0a", isec);
    uint8_t dcid[8];
    hex2bin("8394c8f03e515708", dcid);
    quic_hkdf_extract(isec, 20, dcid, 8, secret);
    quic_expand_label(secret, 32, "client in", NULL, 0, cli, 32);
    uint8_t exp_cli[32];
    hex2bin("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", exp_cli);
    CHECK(memcmp(cli, exp_cli, 32) == 0, "HKDF client in secret (RFC 9001 A.1)");

    /* header protection round trip (first byte encodes pn_len-1 = 1) */
    uint8_t pkt[64];
    memset(pkt, 0xab, sizeof(pkt));
    pkt[0] = 0xc1;
    uint8_t pn_bytes[4] = { 0x12, 0x34, 0, 0 };
    memcpy(pkt + 10, pn_bytes, 4);
    uint8_t orig0 = pkt[0];
    uint8_t orig_pn[4];
    memcpy(orig_pn, pkt + 10, 4);
    quic_apply_hp(&k, pkt, pkt + 10, 2, pkt + 10, sizeof(pkt) - 10);
    size_t pn_len = quic_remove_hp(&k, pkt, sizeof(pkt), 10);
    CHECK(pkt[0] == orig0 && memcmp(pkt + 10, orig_pn, 2) == 0 && pn_len == 2,
          "apply_hp/remove_hp round trip");

    /* nonce XORs the packet number into the last 8 bytes (RFC 9001 5.3) */
    uint8_t nonce[12];
    quic_nonce(nonce, &k, 0x0102030405060708ull);
    uint8_t exp_nonce[12];
    memcpy(exp_nonce, k.iv, 12);
    exp_nonce[4] ^= 0x01; exp_nonce[5] ^= 0x02; exp_nonce[6] ^= 0x03;
    exp_nonce[7] ^= 0x04; exp_nonce[8] ^= 0x05; exp_nonce[9] ^= 0x06;
    exp_nonce[10] ^= 0x07; exp_nonce[11] ^= 0x08;
    CHECK(memcmp(nonce, exp_nonce, 12) == 0, "quic_nonce layout");
}

/* ---------------- frame builders ---------------- */

static void test_frames(void) {
    uint8_t buf[64];
    uint64_t sid, off, len, v;
    size_t u;

    size_t n = frame_stream(buf, 4, 12345, (const uint8_t *)"hello", 5, 1);
    CHECK(buf[0] == (FR_STREAM | 0x04 | 0x02 | 0x01), "frame_stream type bits");
    size_t q = 1;
    CHECK(varint_get(buf + q, n - q, &sid, &u) == 0 && sid == 4, "frame_stream sid");
    q += u;
    CHECK(varint_get(buf + q, n - q, &off, &u) == 0 && off == 12345, "frame_stream offset");
    q += u;
    CHECK(varint_get(buf + q, n - q, &len, &u) == 0 && len == 5, "frame_stream length");
    q += u;
    CHECK(memcmp(buf + q, "hello", 5) == 0, "frame_stream payload");

    n = frame_ack(buf, 70000);
    CHECK(buf[0] == FR_ACK, "frame_ack type");
    q = 1;
    CHECK(varint_get(buf + q, n - q, &v, &u) == 0 && v == 70000, "frame_ack largest");

    n = frame_max_data(buf, 1ull << 40);
    CHECK(n == 1 + 8 && buf[0] == FR_MAX_DATA, "frame_max_data 8-byte varint");

    n = frame_max_stream_data(buf, 16, 262144);
    CHECK(buf[0] == FR_MAX_STREAM_DATA && n > 3, "frame_max_stream_data");

    n = frame_crypto(buf, 0, NULL, 0);
    CHECK(n == 3 && buf[0] == FR_CRYPTO, "frame_crypto empty");
}

/* ---------------- stream reassembly queue ---------------- */

static quic_stream_t *mk_stream(quic_conn_t *c) {
    quic_stream_t *s = calloc(1, sizeof(*s));
    s->qc = c;
    s->rxcap = 16;
    s->rxbuf = malloc(s->rxcap);
    pthread_mutex_init(&s->mu, NULL);
    pthread_cond_init(&s->cv, NULL);
    return s;
}

static void test_stream_queue(void) {
    quic_conn_t c;
    memset(&c, 0, sizeof(c));
    pthread_mutex_init(&c.mu, NULL);
    pthread_cond_init(&c.cv, NULL);
    quic_stream_t *s = mk_stream(&c);
    s->next = NULL;

    uint8_t m[32];
    for (int i = 0; i < 32; i++)
        m[i] = (uint8_t)i;

    /* out of order, overlap with split, gap fill, duplicate, tail + FIN */
    pthread_mutex_lock(&s->mu);
    quic_stream_deliver_locked(s, 0, 10, m + 10, 10, 0);   /* queue 10..20 */
    quic_stream_deliver_locked(s, 0, 5, m + 5, 10, 0);     /* split -> 5..10 */
    quic_stream_deliver_locked(s, 0, 0, m, 5, 0);          /* drain 0..20 */
    quic_stream_deliver_locked(s, 0, 15, m + 15, 10, 0);   /* consumed trim */
    quic_stream_deliver_locked(s, 0, 20, m + 20, 12, 1);   /* tail + FIN */
    quic_stream_deliver_locked(s, 0, 0, m, 20, 0);         /* duplicate */
    quic_stream_deliver_locked(s, 0, 32, NULL, 0, 1);      /* zero-len FIN dup */
    pthread_mutex_unlock(&s->mu);

    CHECK(s->rx_offset == 32 && s->rxlen == 32 && s->rx_closed == 1 &&
          memcmp(s->rxbuf, m, 32) == 0, "stream queue overlap/duplicate/FIN");
    CHECK(s->rxq == NULL && s->rxq_bytes == 0, "stream queue fully drained");

    /* consumed-prefix trim: everything below rx_offset is ignored */
    pthread_mutex_lock(&s->mu);
    quic_stream_deliver_locked(s, 0, 0, m, 32, 0);
    pthread_mutex_unlock(&s->mu);
    CHECK(s->rxlen == 32, "duplicate of consumed range ignored");

    quic_stream_free(s);
    pthread_mutex_destroy(&c.mu);
    pthread_cond_destroy(&c.cv);
}

/* ---------------- handshake ACK bookkeeping ---------------- */

static void test_ack_crypto(void) {
    quic_conn_t c;
    memset(&c, 0, sizeof(c));
    c.cpt_ini_n = 3;
    c.cpt_ini[0] = (quic_cpt_t){ .pn = 0, .off = 0, .len = 500 };
    c.cpt_ini[1] = (quic_cpt_t){ .pn = 1, .off = 500, .len = 500 };
    c.cpt_ini[2] = (quic_cpt_t){ .pn = 3, .off = 1000, .len = 100 };
    c.tx_ini_sent = 1100;

    quic_ack_crypto(&c, 0, 0);          /* only first packet acked */
    CHECK(c.tx_ini_acked == 500, "ack_crypto advances one range");
    quic_ack_crypto(&c, 0, 1);
    CHECK(c.tx_ini_acked == 1000, "ack_crypto advances contiguous prefix");
    quic_ack_crypto(&c, 0, 99);
    CHECK(c.tx_ini_acked == 1100, "ack_crypto caps at bytes sent");
}


/* ---------------- handshake CRYPTO reassembly ---------------- */

static void test_crypto_ooo(void) {
    quic_conn_t c;
    memset(&c, 0, sizeof(c));
    pthread_mutex_init(&c.mu, NULL);
    pthread_cond_init(&c.cv, NULL);
    c.hs.state = 1;                 /* accept post-ServerHello messages */
    sha256_init(&c.hs.transcript);

    /* a NewSessionTicket message (type 4) with a 300-byte body */
    uint8_t msg[304];
    msg[0] = 4;
    msg[1] = 0x00; msg[2] = 0x01; msg[3] = 0x2c;   /* 300 */
    for (int i = 0; i < 300; i++)
        msg[4 + i] = (uint8_t)(i * 7);

    quic_crypto_input(&c, 1, 100, msg + 100, 100);   /* out of order */
    CHECK(c.crypto_pending_bytes == 100, "crypto OOO queued");
    quic_crypto_input(&c, 1, 200, msg + 200, 104);   /* tail queued */
    quic_crypto_input(&c, 1, 0, msg, 100);           /* gap fill -> drain */
    CHECK(c.hs_inlen == 304 && c.hs.parse_pos == 304 && !c.hs_failed,
          "crypto OOO reassembled in order");
    CHECK(memcmp(c.hs_in, msg, 304) == 0, "crypto buffer content");
    CHECK(c.crypto_pending == NULL, "crypto pending drained");

    quic_crypto_input(&c, 1, 0, msg, 100);           /* duplicate */
    CHECK(c.hs_inlen == 304, "crypto duplicate ignored");

    /* space 0 out-of-order is fatal (ServerHello is a single frame) */
    c.hs_failed = 0;
    quic_crypto_input(&c, 0, 5, msg, 10);
    CHECK(c.hs_failed == 1, "crypto Initial gap fails fast");

    /* overflowing the handshake buffer fails instead of stalling */
    quic_conn_t c2;
    memset(&c2, 0, sizeof(c2));
    pthread_mutex_init(&c2.mu, NULL);
    pthread_cond_init(&c2.cv, NULL);
    c2.hs.state = 1;
    uint8_t big[1024];
    memset(big, 0x4e, sizeof(big));  /* bogus message, accepted at reassembly */
    for (int i = 0; i < 70 && !c2.hs_failed; i++)
        quic_crypto_input(&c2, 1, (uint64_t)i * 1024, big, sizeof(big));
    CHECK(c2.hs_failed == 1, "crypto buffer overflow fails fast");

    pthread_mutex_destroy(&c.mu);
    pthread_cond_destroy(&c.cv);
    pthread_mutex_destroy(&c2.mu);
    pthread_cond_destroy(&c2.cv);
}


/* ---------------- handshake retransmission bookkeeping ---------------- */

static void init_conn(quic_conn_t *c) {
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->mu, NULL);
    pthread_cond_init(&c->cv, NULL);
    c->fd = -1;
    c->cap.valid = 1;
}

static void test_flush_crypto(void) {
    quic_conn_t c;
    init_conn(&c);
    memset(c.tx_ini, 'X', sizeof(c.tx_ini));

    /* one packet, then no immediate resend */
    c.tx_ini_len = 100;
    quic_flush_crypto(&c);
    CHECK(c.tx_ini_sent == 100 && c.cpt_ini_n == 1 &&
          c.cpt_ini[0].off == 0 && c.cpt_ini[0].len == 100,
          "flush_crypto records the first range");
    uint64_t pn_after_first = c.pn_initial;
    quic_flush_crypto(&c);
    CHECK(c.pn_initial == pn_after_first && c.cpt_ini_n == 1,
          "flush_crypto waits for the resend timer");

    /* pipelining: unsent data goes out before any retransmission */
    c.tx_ini_len = 2000;
    c.tx_ini_sent = 0;
    c.tx_ini_acked = 0;
    c.cpt_ini_n = 0;
    quic_flush_crypto(&c);
    quic_flush_crypto(&c);
    CHECK(c.tx_ini_sent == 2000 && c.cpt_ini_n == 2 &&
          c.cpt_ini[0].off == 0 && c.cpt_ini[1].off == 1100,
          "flush_crypto pipelines unsent chunks");

    /* partial ACK advances only the contiguous prefix */
    quic_ack_crypto(&c, 0, c.cpt_ini[0].pn);
    CHECK(c.tx_ini_acked == 1100, "flush_crypto partial ack");

    /* retransmission of the unacked range keeps byte accounting intact */
    c.hs_resend_at = 0;
    uint64_t before = c.pn_initial;
    quic_flush_crypto(&c);
    CHECK(c.pn_initial == before + 1 && c.cpt_ini[1].acked == 0,
          "flush_crypto retransmits the unacked range");

    pthread_mutex_destroy(&c.mu);
    pthread_cond_destroy(&c.cv);
}

/* ---------------- 1-RTT retransmission / idle handling ---------------- */

static void test_flush_1rtt(void) {
    /* idle close on no valid packet for 30 s */
    quic_conn_t c;
    init_conn(&c);
    c.hs_done = 1;
    c.last_recv_at = mono_ms() - 31000;
    c.last_ack_at = mono_ms();
    quic_flush_1rtt(&c);
    CHECK(c.closed == 1, "flush_1rtt closes after idle timeout");

    /* no ACK for 30 s with a pending queue also closes */
    quic_conn_t c2;
    init_conn(&c2);
    c2.hs_done = 1;
    c2.last_recv_at = mono_ms();
    c2.last_ack_at = mono_ms() - 31000;
    quic_txpkt_t *e = calloc(1, sizeof(*e));
    e->flen = 4;
    c2.txq = e;
    c2.txq_bytes = 4;
    quic_flush_1rtt(&c2);
    CHECK(c2.closed == 1, "flush_1rtt closes when nothing is acked");

    /* retransmission backs off exponentially and preserves the frames */
    quic_conn_t c3;
    init_conn(&c3);
    c3.hs_done = 1;
    c3.last_recv_at = mono_ms();
    c3.last_ack_at = mono_ms();
    quic_txpkt_t *r = calloc(1, sizeof(*r));
    r->flen = 3;
    r->frames[0] = 0x06;               /* CRYPTO frame bytes */
    r->next_rtx = mono_ms() - 1;
    r->backoff_ms = 250;
    uint8_t exp_frames[3];
    memcpy(exp_frames, r->frames, 3);
    c3.txq = r;
    c3.txq_bytes = 3;
    quic_flush_1rtt(&c3);
    CHECK(c3.txq && c3.txq != r && c3.txq->backoff_ms == 500 &&
          memcmp(c3.txq->frames, exp_frames, 3) == 0,
          "flush_1rtt retransmits with doubled backoff");

    while (c.txq) { quic_txpkt_t *n = c.txq->next; free(c.txq); c.txq = n; }
    while (c2.txq) { quic_txpkt_t *n = c2.txq->next; free(c2.txq); c2.txq = n; }
    while (c3.txq) { quic_txpkt_t *n = c3.txq->next; free(c3.txq); c3.txq = n; }
    pthread_mutex_destroy(&c.mu);
    pthread_cond_destroy(&c.cv);
    pthread_mutex_destroy(&c2.mu);
    pthread_cond_destroy(&c2.cv);
    pthread_mutex_destroy(&c3.mu);
    pthread_cond_destroy(&c3.cv);
}

/* ---------------- stream deadline / open after close ---------------- */

static void test_stream_misc(void) {
    quic_conn_t c;
    init_conn(&c);
    quic_stream_t *s = mk_stream(&c);
    s->next = NULL;

    s->deadline = mono_ms() - 1;
    uint8_t buf[8];
    int64_t t0 = mono_ms();
    CHECK(quic_stream_read(s, buf, sizeof(buf)) == -1 &&
          mono_ms() - t0 < 500, "stream read honors an expired deadline");
    CHECK(quic_stream_wait_readable(s, 100) == 1,
          "wait_readable reports expired deadline");

    quic_stream_free(s);

    c.closed = 1;
    CHECK(quic_open_stream(&c) == NULL, "open_stream fails when closed");
    c.closed = 0;
    CHECK(quic_open_stream(&c) == NULL, "open_stream fails before handshake");
    c.hs_done = 1;
    s = quic_open_stream(&c);
    CHECK(s != NULL, "open_stream succeeds after handshake");
    if (s)
        quic_stream_free(s);

    pthread_mutex_destroy(&c.mu);
    pthread_cond_destroy(&c.cv);
}

int main(void) {
    /* quic.c references mono_ms/random_bytes only through other objects */
    test_varint();
    test_pn_decode();
    test_keys();
    test_frames();
    test_stream_queue();
    test_ack_crypto();
    test_crypto_ooo();
    test_flush_crypto();
    test_flush_1rtt();
    test_stream_misc();
    printf("\n%d checks, %d failures\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}

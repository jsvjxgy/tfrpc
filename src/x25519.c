/*
 * SPDX-License-Identifier: GPL-3.0-only
 * x25519.c - X25519 (RFC 7748) key agreement, portable 32-bit implementation.
 *
 * Field elements are 16 limbs of 16 bits (little-endian), reduced mod
 * p = 2^255 - 19.  The Montgomery ladder and scalar clamping follow RFC 7748.
 */

#include <stdint.h>
#include <string.h>
#include "x25519.h"

typedef struct {
    uint32_t v[16];
} fe;

/* p = 2^255 - 19 in radix 2^16 */
static const uint32_t P_LIMB[16] = {
    0xffed, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x7fff
};

static void fe_0(fe *h) { memset(h, 0, sizeof(*h)); }
static void fe_1(fe *h) { memset(h, 0, sizeof(*h)); h->v[0] = 1; }
static void fe_copy(fe *h, const fe *f) { *h = *f; }

static void fe_add(fe *h, const fe *f, const fe *g) {
    uint32_t c = 0;
    for (int i = 0; i < 16; i++) {
        uint32_t s = f->v[i] + g->v[i] + c;
        h->v[i] = s & 0xffff;
        c = s >> 16;
    }
    if (c) {
        uint32_t v = c * 38;   /* 2^256 == 38 (mod p) */
        for (int i = 0; i < 16 && v; i++) {
            uint32_t s = h->v[i] + v;
            h->v[i] = s & 0xffff;
            v = s >> 16;
        }
    }
}

static void fe_sub(fe *h, const fe *f, const fe *g) {
    int32_t c = 0;
    for (int i = 0; i < 16; i++) {
        c += (int32_t)f->v[i] - (int32_t)g->v[i];
        h->v[i] = (uint32_t)c & 0xffff;
        c >>= 16;
    }
    if (c < 0) {
        /* borrow: add 2p = 2^256 - 38 */
        int32_t carry = 0;
        for (int i = 0; i < 16; i++) {
            int32_t two_p = (i == 0) ? 0xffda : 0xffff;
            carry += (int32_t)h->v[i] + two_p;
            h->v[i] = (uint32_t)carry & 0xffff;
            carry >>= 16;
        }
    }
}

static void fe_mul(fe *h, const fe *f, const fe *g) {
    uint64_t t[32];
    memset(t, 0, sizeof(t));
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++)
            t[i + j] += (uint64_t)f->v[i] * g->v[j];
    /* fold 2^256 == 38 */
    for (int i = 31; i >= 16; i--) {
        uint64_t v = t[i];
        t[i] = 0;
        t[i - 16] += v * 38;
    }
    uint64_t c = 0;
    for (int i = 0; i < 16; i++) {
        t[i] += c;
        c = t[i] >> 16;
        h->v[i] = (uint32_t)(t[i] & 0xffff);
    }
    uint64_t v = c * 38;
    for (int i = 0; i < 16 && v; i++) {
        uint64_t s = h->v[i] + v;
        h->v[i] = (uint32_t)(s & 0xffff);
        v = s >> 16;
    }
}

static void fe_sq(fe *h, const fe *f) { fe_mul(h, f, f); }

/* multiply by a small (< 2^16) constant */
static void fe_mul_small(fe *h, const fe *f, uint32_t s) {
    uint64_t c = 0;
    for (int i = 0; i < 16; i++) {
        uint64_t v = (uint64_t)f->v[i] * s + c;
        h->v[i] = (uint32_t)(v & 0xffff);
        c = v >> 16;
    }
    uint64_t v = c * 38;
    for (int i = 0; i < 16 && v; i++) {
        uint64_t s2 = h->v[i] + v;
        h->v[i] = (uint32_t)(s2 & 0xffff);
        v = s2 >> 16;
    }
}

/* full reduction to [0, p) */
static void fe_reduce(fe *h, const fe *f) {
    fe t = *f;
    /* carry propagate */
    uint32_t c = 0;
    for (int i = 0; i < 16; i++) {
        uint32_t s = t.v[i] + c;
        t.v[i] = s & 0xffff;
        c = s >> 16;
    }
    uint32_t v = c * 38;
    for (int i = 0; i < 16 && v; i++) {
        uint32_t s = t.v[i] + v;
        t.v[i] = s & 0xffff;
        v = s >> 16;
    }
    /* subtract p up to twice */
    for (int attempt = 0; attempt < 2; attempt++) {
        int32_t borrow = 0;
        uint32_t r[16];
        for (int i = 0; i < 16; i++) {
            borrow += (int32_t)t.v[i] - (int32_t)P_LIMB[i];
            r[i] = (uint32_t)borrow & 0xffff;
            borrow >>= 16;
        }
        if (borrow >= 0)
            memcpy(t.v, r, sizeof(r));
        else
            break;
    }
    *h = t;
}

/* h = z^(p-2) = z^-1  (p-2 = 2^255 - 21; all bits set except 2 and 4) */
static void fe_invert(fe *h, const fe *z) {
    fe r;
    fe_copy(&r, z);
    for (int i = 253; i >= 0; i--) {
        fe_sq(&r, &r);
        if (i != 4 && i != 2)
            fe_mul(&r, &r, z);
    }
    *h = r;
}

static void fe_frombytes(fe *h, const uint8_t s[32]) {
    for (int i = 0; i < 16; i++)
        h->v[i] = (uint32_t)s[2 * i] | ((uint32_t)s[2 * i + 1] << 8);
    h->v[15] &= 0x7fff;   /* mask the top bit (255-bit field) */
}

static void fe_tobytes(uint8_t s[32], const fe *f) {
    fe t;
    fe_reduce(&t, f);
    for (int i = 0; i < 16; i++) {
        s[2 * i] = (uint8_t)(t.v[i] & 0xff);
        s[2 * i + 1] = (uint8_t)(t.v[i] >> 8);
    }
}

static void fe_cswap(fe *a, fe *b, uint32_t swap) {
    uint32_t mask = (uint32_t)(0 - swap);   /* 0 or 0xffffffff */
    for (int i = 0; i < 16; i++) {
        uint32_t t = mask & (a->v[i] ^ b->v[i]);
        a->v[i] ^= t;
        b->v[i] ^= t;
    }
}

void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t k[32];
    memcpy(k, scalar, 32);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    fe_frombytes(&x1, point);
    fe_1(&x2);
    fe_0(&z2);
    fe_copy(&x3, &x1);
    fe_1(&z3);

    uint32_t swap = 0;
    for (int t = 254; t >= 0; t--) {
        uint32_t kt = (k[t >> 3] >> (t & 7)) & 1;
        swap ^= kt;
        fe_cswap(&x2, &x3, swap);
        fe_cswap(&z2, &z3, swap);
        swap = kt;

        fe a, aa, b, bb, e, c, d, da, cb;
        fe_add(&a, &x2, &z2);
        fe_sq(&aa, &a);
        fe_sub(&b, &x2, &z2);
        fe_sq(&bb, &b);
        fe_sub(&e, &aa, &bb);
        fe_add(&c, &x3, &z3);
        fe_sub(&d, &x3, &z3);
        fe_mul(&da, &d, &a);
        fe_mul(&cb, &c, &b);
        fe_add(&tmp0, &da, &cb);
        fe_sq(&x3, &tmp0);
        fe_sub(&tmp1, &da, &cb);
        fe_sq(&tmp1, &tmp1);
        fe_mul(&z3, &x1, &tmp1);
        fe_mul(&x2, &aa, &bb);
        /* z2 = e * (aa + a24*e), a24 = 121665 */
        fe_mul_small(&tmp0, &e, 121665);
        fe_add(&tmp1, &aa, &tmp0);
        fe_mul(&z2, &e, &tmp1);
    }
    fe_cswap(&x2, &x3, swap);
    fe_cswap(&z2, &z3, swap);

    fe_invert(&z2, &z2);
    fe_mul(&x2, &x2, &z2);
    fe_tobytes(out, &x2);
}

void x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
    static const uint8_t base[32] = {9};
    x25519(out, scalar, base);
}

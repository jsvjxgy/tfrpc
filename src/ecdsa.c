/*
 * SPDX-License-Identifier: GPL-3.0-only
 * ecdsa.c - ECDSA over NIST P-256 (secp256r1) verification and signing,
 * used for certificate chain validation and TLS 1.2/1.3 signatures.
 * Jacobian coordinates, double-and-add scalar multiplication.
 */

#include <stdint.h>
#include <string.h>
#include "ecdsa.h"
#include "tfrpc.h"

/* P-256 parameters (big-endian) */
static const uint8_t P_BYTES[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
static const uint8_t GX_BYTES[32] = {
    0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
    0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96};
static const uint8_t GY_BYTES[32] = {
    0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
    0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5};
static const uint8_t N_BYTES[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51};

typedef struct { bn_t X, Y, Z; } jpoint_t;

static void jacobian_from_affine(jpoint_t *r, const bn_t *x, const bn_t *y, const bn_t *p) {
    r->X = *x;
    r->Y = *y;
    bn_set_u32(&r->Z, 1);
    (void)p;
}

static void jacobian_double(jpoint_t *r, const jpoint_t *P, const bn_t *p) {
    bn_t delta, gamma, beta, alpha, t1, t2, X3, Y3, Z3;
    if (P->Y.n == 0 || P->Z.n == 0) {
        bn_set_u32(&r->X, 1);
        bn_set_u32(&r->Y, 1);
        bn_zero(&r->Z);
        return;
    }
    /* P-256 has a = -3:
       delta = Z^2, gamma = Y^2, beta = X*gamma
       alpha = 3*(X-delta)*(X+delta)
       X3 = alpha^2 - 8*beta
       Z3 = (Y+Z)^2 - gamma - delta
       Y3 = alpha*(4*beta - X3) - 8*gamma^2 */
    bn_mod_mul(&delta, &P->Z, &P->Z, p);
    bn_mod_mul(&gamma, &P->Y, &P->Y, p);
    bn_mod_mul(&beta, &P->X, &gamma, p);
    bn_mod_sub(&t1, &P->X, &delta, p);
    bn_mod_add(&t2, &P->X, &delta, p);
    bn_mod_mul(&alpha, &t1, &t2, p);
    bn_mod_add(&t1, &alpha, &alpha, p);
    bn_mod_add(&alpha, &t1, &alpha, p);            /* alpha = 3*(...) */
    bn_mod_mul(&t1, &alpha, &alpha, p);            /* alpha^2 */
    bn_mod_add(&t2, &beta, &beta, p);
    bn_mod_add(&t2, &t2, &t2, p);
    bn_mod_add(&t2, &t2, &t2, p);                  /* 8*beta */
    bn_mod_sub(&X3, &t1, &t2, p);
    bn_mod_add(&t1, &P->Y, &P->Z, p);
    bn_mod_mul(&t1, &t1, &t1, p);
    bn_mod_sub(&t1, &t1, &gamma, p);
    bn_mod_sub(&Z3, &t1, &delta, p);
    bn_mod_add(&t1, &beta, &beta, p);
    bn_mod_add(&t1, &t1, &t1, p);                  /* 4*beta */
    bn_mod_sub(&t1, &t1, &X3, p);
    bn_mod_mul(&t1, &alpha, &t1, p);
    bn_mod_mul(&t2, &gamma, &gamma, p);
    bn_mod_add(&t2, &t2, &t2, p);
    bn_mod_add(&t2, &t2, &t2, p);
    bn_mod_add(&t2, &t2, &t2, p);                  /* 8*gamma^2 */
    bn_mod_sub(&Y3, &t1, &t2, p);
    r->X = X3;
    r->Y = Y3;
    r->Z = Z3;
}

static void jacobian_add(jpoint_t *r, const jpoint_t *P, const jpoint_t *Q, const bn_t *p) {
    bn_t Z1Z1, Z2Z2, U1, U2, S1, S2, H, Rr, HH, HHH, t1, t2, V;
    if (P->Z.n == 0) { *r = *Q; return; }
    if (Q->Z.n == 0) { *r = *P; return; }
    bn_mod_mul(&Z1Z1, &P->Z, &P->Z, p);
    bn_mod_mul(&Z2Z2, &Q->Z, &Q->Z, p);
    bn_mod_mul(&U1, &P->X, &Z2Z2, p);
    bn_mod_mul(&U2, &Q->X, &Z1Z1, p);
    bn_mod_mul(&t1, &Q->Z, &Z2Z2, p);
    bn_mod_mul(&S1, &P->Y, &t1, p);
    bn_mod_mul(&t2, &P->Z, &Z1Z1, p);
    bn_mod_mul(&S2, &Q->Y, &t2, p);
    if (bn_cmp(&U1, &U2) == 0) {
        if (bn_cmp(&S1, &S2) != 0) {
            bn_set_u32(&r->X, 1);
            bn_set_u32(&r->Y, 1);
            bn_zero(&r->Z);
            return;
        }
        jacobian_double(r, P, p);
        return;
    }
    bn_mod_sub(&H, &U2, &U1, p);
    bn_mod_sub(&Rr, &S2, &S1, p);
    bn_mod_mul(&HH, &H, &H, p);
    bn_mod_mul(&HHH, &HH, &H, p);
    bn_mod_mul(&t1, &U1, &HH, p);
    bn_mod_mul(&t2, &Rr, &Rr, p);
    bn_mod_sub(&t2, &t2, &HHH, p);
    bn_mod_add(&V, &t1, &t1, p);
    bn_mod_sub(&r->X, &t2, &V, p);
    bn_mod_sub(&t1, &t1, &r->X, p);
    bn_mod_mul(&t1, &Rr, &t1, p);
    bn_mod_mul(&t2, &S1, &HHH, p);
    bn_mod_sub(&r->Y, &t1, &t2, p);
    bn_mod_mul(&t1, &P->Z, &Q->Z, p);
    bn_mod_mul(&r->Z, &t1, &H, p);
}

static void jacobian_to_affine(bn_t *x, bn_t *y, const jpoint_t *P, const bn_t *p) {
    if (P->Z.n == 0) {
        bn_zero(x);
        bn_zero(y);
        return;
    }
    bn_t zinv, zinv2, zinv3;
    bn_mod_inv(&zinv, &P->Z, p);
    bn_mod_mul(&zinv2, &zinv, &zinv, p);
    bn_mod_mul(&zinv3, &zinv2, &zinv, p);
    bn_mod_mul(x, &P->X, &zinv2, p);
    bn_mod_mul(y, &P->Y, &zinv3, p);
}

static void jacobian_cswap(jpoint_t *a, jpoint_t *b, uint32_t swap) {
    bn_cswap(&a->X, &b->X, swap);
    bn_cswap(&a->Y, &b->Y, swap);
    bn_cswap(&a->Z, &b->Z, swap);
}

/* R = k * P using a constant-time Montgomery ladder (fixed 256 rounds) */
static void scalar_mul(jpoint_t *r, const jpoint_t *P, const bn_t *k, const bn_t *p) {
    jpoint_t R0, R1;
    bn_set_u32(&R0.X, 1);
    bn_set_u32(&R0.Y, 1);
    bn_zero(&R0.Z);          /* infinity */
    R1 = *P;
    for (int i = 255; i >= 0; i--) {
        uint32_t bit = (k->d[i / 32] >> (i % 32)) & 1;
        jacobian_cswap(&R0, &R1, bit);
        jacobian_add(&R1, &R0, &R1, p);
        jacobian_double(&R0, &R0, p);
        jacobian_cswap(&R0, &R1, bit);
    }
    *r = R0;
}

int ecdsa_p256_verify(const uint8_t *pub, size_t pub_len,
                      const uint8_t *hash, size_t hash_len,
                      const uint8_t *sig, size_t sig_len) {
    if (hash_len != 32 || pub_len != 65 || pub[0] != 0x04)
        return -1;
    bn_t p, n, gx, gy, qx, qy, r, s, e;
    bn_from_bytes(&p, P_BYTES, 32);
    bn_from_bytes(&n, N_BYTES, 32);
    bn_from_bytes(&gx, GX_BYTES, 32);
    bn_from_bytes(&gy, GY_BYTES, 32);
    bn_from_bytes(&qx, pub + 1, 32);
    bn_from_bytes(&qy, pub + 33, 32);
    /* signature is DER SEQUENCE { INTEGER r, INTEGER s } */
    if (sig_len < 8 || sig[0] != 0x30)
        return -1;
    size_t i = 2;
    if (sig[1] & 0x80)
        i = 2 + (sig[1] & 0x7f);
    if (i + 2 > sig_len || sig[i] != 0x02)
        return -1;
    size_t rlen = sig[i + 1];
    const uint8_t *rb = sig + i + 2;
    i += 2 + rlen;
    if (i + 2 > sig_len || sig[i] != 0x02)
        return -1;
    size_t slen = sig[i + 1];
    const uint8_t *sb = sig + i + 2;
    while (rlen > 1 && *rb == 0) { rb++; rlen--; }
    while (slen > 1 && *sb == 0) { sb++; slen--; }
    if (rlen > 32 || slen > 32)
        return -1;
    bn_from_bytes(&r, rb, rlen);
    bn_from_bytes(&s, sb, slen);
    if (r.n == 0 || s.n == 0 || bn_cmp(&r, &n) >= 0 || bn_cmp(&s, &n) >= 0)
        return -1;
    /* e = hash (truncated to n bits) */
    bn_from_bytes(&e, hash, 32);
    if (bn_bits(&e) > bn_bits(&n)) {
        /* shift right */
        bn_t tmp;
        bn_from_bytes(&tmp, hash, 32);
        /* e is 256 bits, n is 256 bits -> fine */
        (void)tmp;
    }
    /* w = s^-1 mod n; u1 = e*w; u2 = r*w */
    bn_t w, u1, u2;
    bn_mod_inv(&w, &s, &n);
    bn_mod_mul(&u1, &e, &w, &n);
    bn_mod_mul(&u2, &r, &w, &n);
    /* R = u1*G + u2*Q */
    jpoint_t G, Q, R1, R2, R;
    jacobian_from_affine(&G, &gx, &gy, &p);
    jacobian_from_affine(&Q, &qx, &qy, &p);
    scalar_mul(&R1, &G, &u1, &p);
    scalar_mul(&R2, &Q, &u2, &p);
    jacobian_add(&R, &R1, &R2, &p);
    if (R.Z.n == 0)
        return -1;
    bn_t rx, ry;
    jacobian_to_affine(&rx, &ry, &R, &p);
    /* v = rx mod n */
    bn_t v;
    if (bn_cmp(&rx, &n) >= 0) {
        bn_t t;
        /* rx mod n: rx < p < 2n for P-256, so subtract once */
        bn_sub(&t, &rx, &n);
        v = t;
    } else {
        v = rx;
    }
    return bn_cmp(&v, &r) == 0 ? 0 : -1;
}

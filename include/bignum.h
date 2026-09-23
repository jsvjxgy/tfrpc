/*
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef TFRPC_BIGNUM_H
#define TFRPC_BIGNUM_H

#include <stdint.h>
#include <stddef.h>

#define BN_LIMBS 128

typedef struct {
    uint32_t d[BN_LIMBS];
    int n;
} bn_t;

typedef struct {
    uint8_t n[512];   /* modulus, big-endian */
    size_t nlen;
    uint8_t e[8];     /* public exponent, big-endian */
    size_t elen;
} rsa_pub_t;

void bn_from_bytes(bn_t *a, const uint8_t *b, size_t len);
size_t bn_to_bytes(const bn_t *a, uint8_t *out, size_t len);
int bn_bits(const bn_t *a);
int bn_cmp(const bn_t *a, const bn_t *b);
void bn_mod_exp(bn_t *r, const bn_t *base, const bn_t *exp, const bn_t *m);
void bn_mod_exp_ct(bn_t *r, const bn_t *base, const bn_t *exp, const bn_t *m);
void bn_cswap(bn_t *a, bn_t *b, uint32_t swap);
void bn_mod_add(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m);
void bn_mod_sub(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m);
void bn_mod_mul(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m);
void bn_mod_inv(bn_t *r, const bn_t *a, const bn_t *m);   /* m prime */
void bn_set_u32(bn_t *r, uint32_t v);
void bn_zero(bn_t *a);
void bn_sub(bn_t *r, const bn_t *a, const bn_t *b);

int rsa_pkcs1_verify(const rsa_pub_t *key, const uint8_t *digest, size_t digest_len,
                     const uint8_t *sig, size_t sig_len);
int rsa_pss_verify(const rsa_pub_t *key, const uint8_t *digest, size_t digest_len,
                   const uint8_t *sig, size_t sig_len);

typedef struct {
    uint8_t n[512]; size_t nlen;
    uint8_t d[512]; size_t dlen;
} rsa_priv_t;

/* RSA-PSS sign (SHA-256, salt 32) for TLS 1.3 client CertificateVerify */
int rsa_pss_sign(const rsa_priv_t *key, const uint8_t *digest, size_t digest_len,
                 uint8_t *sig, size_t *sig_len);

#endif

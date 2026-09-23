/*
 * SPDX-License-Identifier: GPL-3.0-only
 * bignum.c - small fixed-width big integer arithmetic and RSA verification
 * (PKCS#1 v1.5 and PSS), used for TLS certificate chain validation.
 *
 * Numbers are little-endian arrays of 32-bit limbs, up to 4096 bits.
 */

#include <stdint.h>
#include <string.h>
#include "bignum.h"
#include "tfrpc.h"

#define BN_LIMBS 128   /* 4096 bits */

void bn_zero(bn_t *a) { memset(a->d, 0, sizeof(a->d)); a->n = 0; }

void bn_from_bytes(bn_t *a, const uint8_t *b, size_t len) {
    bn_zero(a);
    if (len > BN_LIMBS * 4)
        len = BN_LIMBS * 4;
    for (size_t i = 0; i < len; i++) {
        int limb = (int)(i / 4), shift = (int)(i % 4) * 8;
        a->d[limb] |= (uint32_t)b[len - 1 - i] << shift;
    }
    a->n = (int)((len + 3) / 4);
    while (a->n > 0 && a->d[a->n - 1] == 0)
        a->n--;
}

size_t bn_to_bytes(const bn_t *a, uint8_t *out, size_t len) {
    memset(out, 0, len);
    for (int i = 0; i < a->n; i++) {
        for (int j = 0; j < 4; j++) {
            size_t pos = (size_t)i * 4 + j;
            if (pos < len)
                out[len - 1 - pos] = (uint8_t)(a->d[i] >> (8 * j));
        }
    }
    return len;
}

int bn_bits(const bn_t *a) {
    if (a->n == 0)
        return 0;
    uint32_t top = a->d[a->n - 1];
    int b = 0;
    while (top) { b++; top >>= 1; }
    return (a->n - 1) * 32 + b;
}

int bn_cmp(const bn_t *a, const bn_t *b) {
    if (a->n != b->n)
        return a->n < b->n ? -1 : 1;
    for (int i = a->n - 1; i >= 0; i--)
        if (a->d[i] != b->d[i])
            return a->d[i] < b->d[i] ? -1 : 1;
    return 0;
}

void bn_sub(bn_t *r, const bn_t *a, const bn_t *b) {
    int64_t borrow = 0;
    int n = a->n > b->n ? a->n : b->n;
    for (int i = 0; i < n; i++) {
        int64_t v = (int64_t)(i < a->n ? a->d[i] : 0) -
                    (int64_t)(i < b->n ? b->d[i] : 0) - borrow;
        if (v < 0) { v += ((int64_t)1 << 32); borrow = 1; }
        else borrow = 0;
        r->d[i] = (uint32_t)v;
    }
    r->n = n;
    while (r->n > 0 && r->d[r->n - 1] == 0)
        r->n--;
}

/* r = a * b (schoolbook) */
static void bn_mul(bn_t *r, const bn_t *a, const bn_t *b) {
    uint32_t t[BN_LIMBS * 2];
    memset(t, 0, sizeof(t));
    for (int i = 0; i < a->n; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < b->n; j++) {
            uint64_t v = (uint64_t)a->d[i] * b->d[j] + t[i + j] + carry;
            t[i + j] = (uint32_t)v;
            carry = v >> 32;
        }
        int k = i + b->n;
        while (carry) {
            uint64_t v = (uint64_t)t[k] + carry;
            t[k] = (uint32_t)v;
            carry = v >> 32;
            k++;
        }
    }
    int n = a->n + b->n;
    if (n > BN_LIMBS)
        n = BN_LIMBS;
    for (int i = 0; i < n; i++)
        r->d[i] = t[i];
    r->n = n;
    while (r->n > 0 && r->d[r->n - 1] == 0)
        r->n--;
}

/* r = a mod m, bitwise long division (a may be up to 2*BN_LIMBS limbs) */
static void bn_mod(bn_t *r, const uint32_t *a, int an, const bn_t *m) {
    bn_t rem;
    bn_zero(&rem);
    int bits = an * 32;
    for (int i = bits - 1; i >= 0; i--) {
        /* rem = rem*2 + bit(a,i), then reduce */
        uint32_t carry = 0;
        for (int k = 0; k < rem.n; k++) {
            uint32_t nv = (rem.d[k] << 1) | carry;
            carry = rem.d[k] >> 31;
            rem.d[k] = nv;
        }
        if (carry) {
            if (rem.n >= BN_LIMBS)
                return;
            rem.d[rem.n++] = carry;
        }
        if ((a[i / 32] >> (i % 32)) & 1) {
            if (rem.n == 0) {
                rem.d[0] = 1;
                rem.n = 1;
            } else {
                rem.d[0] |= 1;
            }
        }
        while (bn_cmp(&rem, m) >= 0)
            bn_sub(&rem, &rem, m);
    }
    *r = rem;
}

/* constant-time swap of a and b when swap != 0 */
void bn_cswap(bn_t *a, bn_t *b, uint32_t swap) {
    uint32_t mask = (uint32_t)(0 - swap);
    for (int i = 0; i < BN_LIMBS; i++) {
        uint32_t t = mask & (a->d[i] ^ b->d[i]);
        a->d[i] ^= t;
        b->d[i] ^= t;
    }
    int an = a->n, bn = b->n;
    uint32_t d = mask & (uint32_t)(an ^ bn);
    a->n = (int)(d ^ (uint32_t)an);
    b->n = (int)(d ^ (uint32_t)bn);
}

/* r = base^exp mod m, constant-time Montgomery ladder (for secret exponents) */
void bn_mod_exp_ct(bn_t *r, const bn_t *base, const bn_t *exp, const bn_t *m) {
    bn_t r0, r1, t;
    bn_set_u32(&r0, 1);
    bn_mod(&r1, base->d, base->n, m);
    int bits = bn_bits(exp);
    for (int i = bits - 1; i >= 0; i--) {
        uint32_t bit = (exp->d[i / 32] >> (i % 32)) & 1;
        bn_cswap(&r0, &r1, bit);
        bn_mul(&t, &r0, &r1);
        bn_mod(&r1, t.d, t.n, m);
        bn_mul(&t, &r0, &r0);
        bn_mod(&r0, t.d, t.n, m);
        bn_cswap(&r0, &r1, bit);
    }
    *r = r0;
    secure_zero(&r1, sizeof(r1));
    secure_zero(&t, sizeof(t));
}

/* r = base^exp mod m (square-and-multiply from the top bit) */
void bn_mod_exp(bn_t *r, const bn_t *base, const bn_t *exp, const bn_t *m) {
    bn_t result, b;
    bn_zero(&result);
    result.d[0] = 1;
    result.n = 1;
    bn_t tmp;
    bn_mod(&b, base->d, base->n, m);

    int ebits = bn_bits(exp);
    for (int i = ebits - 1; i >= 0; i--) {
        /* result = result^2 mod m */
        bn_mul(&tmp, &result, &result);
        bn_mod(&result, tmp.d, tmp.n, m);
        if ((exp->d[i / 32] >> (i % 32)) & 1) {
            bn_mul(&tmp, &result, &b);
            bn_mod(&result, tmp.d, tmp.n, m);
        }
    }
    *r = result;
}

/* ------------------------------ RSA verify ------------------------------ */

static const uint8_t OID_SHA256[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
static const uint8_t OID_SHA384[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};
static const uint8_t OID_SHA512[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03};

/* RSA PKCS#1 v1.5 signature verify.  digest is the message hash. */
int rsa_pkcs1_verify(const rsa_pub_t *key, const uint8_t *digest, size_t digest_len,
                     const uint8_t *sig, size_t sig_len) {
    if (sig_len > BN_LIMBS * 4)
        return -1;
    bn_t s, e, n, m;
    bn_from_bytes(&s, sig, sig_len);
    bn_from_bytes(&e, key->e, key->elen);
    bn_from_bytes(&n, key->n, key->nlen);
    bn_mod_exp(&m, &s, &e, &n);

    uint8_t em[BN_LIMBS * 4];
    size_t emlen = key->nlen;
    if (emlen > sizeof(em))
        return -1;
    bn_to_bytes(&m, em, emlen);

    /* EM = 0x00 || 0x01 || PS(0xff...) || 0x00 || DigestInfo */
    if (em[0] != 0x00 || em[1] != 0x01)
        return -1;
    size_t i = 2;
    while (i < emlen && em[i] == 0xff)
        i++;
    if (i >= emlen || em[i] != 0x00)
        return -1;
    i++;
    /* DigestInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING digest } */
    if (i + 2 > emlen || em[i] != 0x30)
        return -1;
    size_t seq_len = em[i + 1];
    if (seq_len > emlen - i - 2)
        return -1;
    size_t p = i + 2;
    /* AlgorithmIdentifier */
    if (p + 2 > emlen || em[p] != 0x30)
        return -1;
    size_t alg_len = em[p + 1];
    size_t alg_start = p + 2;
    if (alg_start + alg_len > emlen)
        return -1;
    /* OID */
    if (alg_start + 2 > emlen || em[alg_start] != 0x06)
        return -1;
    size_t oid_len = em[alg_start + 1];
    const uint8_t *oid = em + alg_start + 2;
    size_t expected = 0;
    if (oid_len == sizeof(OID_SHA256) && !memcmp(oid, OID_SHA256, oid_len))
        expected = 32;
    else if (oid_len == sizeof(OID_SHA384) && !memcmp(oid, OID_SHA384, oid_len))
        expected = 48;
    else if (oid_len == sizeof(OID_SHA512) && !memcmp(oid, OID_SHA512, oid_len))
        expected = 64;
    else
        return -1;
    if (expected != digest_len)
        return -1;
    /* OCTET STRING follows the whole AlgorithmIdentifier (OID [+ NULL]) */
    size_t q = alg_start + alg_len;
    if (q + 2 > emlen || em[q] != 0x04)
        return -1;
    size_t dlen = em[q + 1];
    if (dlen != digest_len || q + 2 + dlen > emlen)
        return -1;
    if (crypto_memcmp_ct(em + q + 2, digest, digest_len) != 0)
        return -1;
    return 0;
}

/* MGF1 (RFC 8017) with SHA-256 only (TLS 1.3 rsa_pss_rsae_sha256) */
static void mgf1_sha256(uint8_t *mask, size_t mask_len, const uint8_t *seed, size_t seed_len) {
    uint8_t buf[32 + 4];
    uint32_t ctr = 0;
    size_t done = 0;
    while (done < mask_len) {
        memcpy(buf, seed, seed_len);
        buf[seed_len] = (uint8_t)(ctr >> 24);
        buf[seed_len + 1] = (uint8_t)(ctr >> 16);
        buf[seed_len + 2] = (uint8_t)(ctr >> 8);
        buf[seed_len + 3] = (uint8_t)ctr;
        uint8_t h[32];
        sha256_digest(buf, seed_len + 4, h);
        size_t n = mask_len - done < 32 ? mask_len - done : 32;
        memcpy(mask + done, h, n);
        done += n;
        ctr++;
    }
}

/* RSA-PSS verify (SHA-256, salt length 32) as used by TLS 1.3 */
int rsa_pss_verify(const rsa_pub_t *key, const uint8_t *digest, size_t digest_len,
                   const uint8_t *sig, size_t sig_len) {
    if (digest_len != 32 || sig_len > BN_LIMBS * 4)
        return -1;
    bn_t s, e, n, m;
    bn_from_bytes(&s, sig, sig_len);
    bn_from_bytes(&e, key->e, key->elen);
    bn_from_bytes(&n, key->n, key->nlen);
    bn_mod_exp(&m, &s, &e, &n);

    size_t emlen = key->nlen;
    uint8_t em[BN_LIMBS * 4];
    if (emlen > sizeof(em))
        return -1;
    bn_to_bytes(&m, em, emlen);

    /* EM = maskedDB || H || 0xbc, hLen = 32 */
    if (emlen < 32 + 32 + 2 || em[emlen - 1] != 0xbc)
        return -1;
    size_t db_len = emlen - 32 - 1;
    uint8_t *db = em;
    uint8_t *h = em + db_len;
    /* clear the leftmost 8*emLen - emBits bits; emBits = 2047 for RSA-2048 */
    int em_bits = bn_bits(&n) - 1;
    int clear_bits = 8 * (int)emlen - em_bits;
    if (clear_bits > 0 && clear_bits < 8)
        db[0] &= (uint8_t)(0xff >> clear_bits);
    else if (clear_bits >= 8)
        return -1;

    uint8_t mask[BN_LIMBS * 4];
    mgf1_sha256(mask, db_len, h, 32);
    for (size_t i = 0; i < db_len; i++)
        db[i] ^= mask[i];
    db[0] &= (uint8_t)(0xff >> clear_bits);

    /* DB = PS(0x00...) || 0x01 || salt(32) */
    size_t ps_len = db_len - 32 - 1;
    for (size_t i = 0; i < ps_len; i++)
        if (db[i] != 0x00)
            return -1;
    if (db[ps_len] != 0x01)
        return -1;
    const uint8_t *salt = db + ps_len + 1;

    /* H' = Hash(0x00*8 || mHash || salt) */
    uint8_t mprime[8 + 32 + 32];
    memset(mprime, 0, 8);
    memcpy(mprime + 8, digest, 32);
    memcpy(mprime + 40, salt, 32);
    uint8_t h2[32];
    sha256_digest(mprime, sizeof(mprime), h2);
    if (crypto_memcmp_ct(h2, h, 32) != 0)
        return -1;
    return 0;
}

/* RSA-PSS sign with SHA-256 and 32-byte salt (RFC 8017 s.8.1) */
int rsa_pss_sign(const rsa_priv_t *key, const uint8_t *digest, size_t digest_len,
                 uint8_t *sig, size_t *sig_len) {
    if (digest_len != 32 || key->nlen < 32 + 32 + 2)
        return -1;
    size_t emlen = key->nlen;
    int em_bits = (int)emlen * 8 - 1;   /* emlen <= 512 for RSA keys we handle */   /* RSA modulus is 8k+1 bits typical; assume */
    uint8_t em[BN_LIMBS * 4];
    size_t db_len = emlen - 32 - 1;
    uint8_t salt[32];
    if (random_bytes(salt, 32) < 0)
        return -1;
    /* H = Hash(0x00*8 || mHash || salt) */
    uint8_t mprime[8 + 32 + 32];
    memset(mprime, 0, 8);
    memcpy(mprime + 8, digest, 32);
    memcpy(mprime + 40, salt, 32);
    uint8_t h[32];
    sha256_digest(mprime, sizeof(mprime), h);
    /* DB = PS || 0x01 || salt */
    uint8_t db[BN_LIMBS * 4];
    size_t ps_len = db_len - 32 - 1;
    memset(db, 0, ps_len);
    db[ps_len] = 0x01;
    memcpy(db + ps_len + 1, salt, 32);
    /* maskedDB = DB XOR MGF1(H, dbLen) */
    uint8_t mask[BN_LIMBS * 4];
    mgf1_sha256(mask, db_len, h, 32);
    for (size_t i = 0; i < db_len; i++)
        db[i] ^= mask[i];
    int clear_bits = 8 * (int)emlen - em_bits;
    if (clear_bits > 0 && clear_bits < 8)
        db[0] &= (uint8_t)(0xff >> clear_bits);
    memcpy(em, db, db_len);
    memcpy(em + db_len, h, 32);
    em[emlen - 1] = 0xbc;
    /* s = EM^d mod n */
    bn_t m, d, n, s;
    bn_from_bytes(&m, em, emlen);
    bn_from_bytes(&d, key->d, key->dlen);
    bn_from_bytes(&n, key->n, key->nlen);
    bn_mod_exp_ct(&s, &m, &d, &n);
    secure_zero(&d, sizeof(d));
    bn_to_bytes(&s, sig, emlen);
    *sig_len = emlen;
    return 0;
}

void bn_set_u32(bn_t *r, uint32_t v) {
    bn_zero(r);
    if (v) {
        r->d[0] = v;
        r->n = 1;
    }
}

void bn_mod_add(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m) {
    bn_t t;
    int n = a->n > b->n ? a->n : b->n;
    uint64_t carry = 0;
    for (int i = 0; i < n; i++) {
        uint64_t v = (uint64_t)(i < a->n ? a->d[i] : 0) +
                     (i < b->n ? b->d[i] : 0) + carry;
        t.d[i] = (uint32_t)v;
        carry = v >> 32;
    }
    t.n = n;
    if (carry) {
        if (t.n < BN_LIMBS)
            t.d[t.n++] = (uint32_t)carry;
    }
    while (t.n > 0 && t.d[t.n - 1] == 0)
        t.n--;
    if (bn_cmp(&t, m) >= 0)
        bn_sub(&t, &t, m);
    if (bn_cmp(&t, m) >= 0)
        bn_sub(&t, &t, m);
    *r = t;
}

void bn_mod_sub(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m) {
    if (bn_cmp(a, b) >= 0) {
        bn_t t;
        bn_sub(&t, a, b);
        *r = t;
    } else {
        bn_t t, t2;
        bn_sub(&t, b, a);
        /* r = m - t */
        bn_sub(&t2, m, &t);
        *r = t2;
    }
}

void bn_mod_mul(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m) {
    bn_t t;
    bn_mul(&t, a, b);
    bn_mod(r, t.d, t.n, m);
}

void bn_mod_inv(bn_t *r, const bn_t *a, const bn_t *m) {
    /* m prime: a^(m-2) mod m */
    bn_t e, two;
    bn_set_u32(&two, 2);
    bn_sub(&e, m, &two);
    bn_mod_exp(r, a, &e, m);
}

/*
 * SPDX-License-Identifier: GPL-3.0-only
 * crypto.c - pure C crypto for tfrpc.
 *
 * MD5 (RFC 1321), SHA-1 (RFC 3174), HMAC-SHA1, PBKDF2 (RFC 2898),
 * AES-128 (FIPS-197) in CFB mode.
 *
 * These are compact, self-contained implementations used only to stay
 * wire-compatible with frp's v1 protocol (token auth via md5, per-proxy
 * encryption via PBKDF2-HMAC-SHA1 + AES-128-CFB).
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#endif

#include "tfrpc.h"

/* ------------------------- security helpers ------------------------- */

/* constant-time comparison: returns 0 when equal, non-zero otherwise */
int crypto_memcmp_ct(const void *a, const void *b, size_t n) {
    const uint8_t *pa = a, *pb = b;
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++)
        d |= (uint8_t)(pa[i] ^ pb[i]);
    return d;
}

/* zero a buffer without the compiler optimizing the store away */
void secure_zero(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--)
        *v++ = 0;
}

/* ----------------------------- MD5 ----------------------------- */

typedef struct {
    uint32_t state[4];
    uint64_t count;
    uint8_t buffer[64];
} md5_ctx_t;

static const uint32_t md5_k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint8_t md5_s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static uint32_t rol32(uint32_t v, int s) { return (v << s) | (v >> (32 - s)); }

static void md5_init(md5_ctx_t *c) {
    c->state[0] = 0x67452301;
    c->state[1] = 0xefcdab89;
    c->state[2] = 0x98badcfe;
    c->state[3] = 0x10325476;
    c->count = 0;
}

static void md5_transform(md5_ctx_t *c, const uint8_t block[64]) {
    uint32_t M[16];
    uint32_t a = c->state[0], b = c->state[1], d = c->state[2], f = c->state[3];
    int i;
    for (i = 0; i < 16; i++)
        M[i] = (uint32_t)block[i * 4] | ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);
    for (i = 0; i < 64; i++) {
        uint32_t F, g;
        if (i < 16) {
            F = (b & d) | (~b & f);
            g = i;
        } else if (i < 32) {
            F = (f & b) | (~f & d);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            F = b ^ d ^ f;
            g = (3 * i + 5) % 16;
        } else {
            F = d ^ (b | ~f);
            g = (7 * i) % 16;
        }
        F = F + a + md5_k[i] + M[g];
        a = f;
        f = d;
        d = b;
        b = b + rol32(F, md5_s[i]);
    }
    c->state[0] += a;
    c->state[1] += b;
    c->state[2] += d;
    c->state[3] += f;
}

static void md5_update(md5_ctx_t *c, const uint8_t *data, size_t len) {
    size_t have = (size_t)(c->count & 0x3f);
    c->count += len;
    if (have) {
        size_t need = 64 - have;
        if (len < need) {
            memcpy(c->buffer + have, data, len);
            return;
        }
        memcpy(c->buffer + have, data, need);
        md5_transform(c, c->buffer);
        data += need;
        len -= need;
    }
    while (len >= 64) {
        md5_transform(c, data);
        data += 64;
        len -= 64;
    }
    memcpy(c->buffer, data, len);
}

static void md5_final(md5_ctx_t *c, uint8_t out[16]) {
    uint64_t bits = c->count * 8;
    uint8_t pad[72];
    size_t i, len = (size_t)(c->count & 0x3f);
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    if (len < 56)
        i = 56 - len;
    else
        i = 120 - len;
    md5_update(c, pad, i);
    for (i = 0; i < 8; i++)
        pad[i] = (uint8_t)(bits >> (8 * i));
    md5_update(c, pad, 8);
    for (i = 0; i < 4; i++) {
        out[i * 4] = (uint8_t)(c->state[i]);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(c->state[i] >> 24);
    }
}

/* hex(md5(token + timestamp)) -- frp's GetAuthKey */
void md5_hex(const char *token, int64_t timestamp, char out[33]) {
    md5_ctx_t c;
    uint8_t digest[16];
    char ts[32];
    int i;
    md5_init(&c);
    md5_update(&c, (const uint8_t *)token, strlen(token));
    snprintf(ts, sizeof(ts), "%lld", (long long)timestamp);
    md5_update(&c, (const uint8_t *)ts, strlen(ts));
    md5_final(&c, digest);
    for (i = 0; i < 16; i++)
        sprintf(out + i * 2, "%02x", digest[i]);
    out[32] = '\0';
}

/* ----------------------------- SHA-1 ----------------------------- */

typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[64];
} sha1_ctx_t;

static void sha1_transform(sha1_ctx_t *c, const uint8_t block[64]) {
    uint32_t w[80];
    uint32_t A, B, C, D, E;
    uint32_t F, K, tmp;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
    for (i = 16; i < 80; i++)
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    A = c->state[0]; B = c->state[1]; C = c->state[2]; D = c->state[3]; E = c->state[4];
    for (i = 0; i < 80; i++) {
        if (i < 20) { F = (B & C) | (~B & D); K = 0x5a827999; }
        else if (i < 40) { F = B ^ C ^ D; K = 0x6ed9eba1; }
        else if (i < 60) { F = (B & C) | (B & D) | (C & D); K = 0x8f1bbcdc; }
        else { F = B ^ C ^ D; K = 0xca62c1d6; }
        tmp = rol32(A, 5) + F + E + K + w[i];
        E = D;
        D = C;
        C = rol32(B, 30);
        B = A;
        A = tmp;
    }
    c->state[0] += A; c->state[1] += B; c->state[2] += C; c->state[3] += D; c->state[4] += E;
}

static void sha1_init(sha1_ctx_t *c) {
    c->state[0] = 0x67452301;
    c->state[1] = 0xEFCDAB89;
    c->state[2] = 0x98BADCFE;
    c->state[3] = 0x10325476;
    c->state[4] = 0xC3D2E1F0;
    c->count = 0;
}

static void sha1_update(sha1_ctx_t *c, const uint8_t *data, size_t len) {
    size_t have = (size_t)(c->count & 0x3f);
    c->count += len;
    if (have) {
        size_t need = 64 - have;
        if (len < need) { memcpy(c->buffer + have, data, len); return; }
        memcpy(c->buffer + have, data, need);
        sha1_transform(c, c->buffer);
        data += need; len -= need;
    }
    while (len >= 64) { sha1_transform(c, data); data += 64; len -= 64; }
    memcpy(c->buffer, data, len);
}

static void sha1_final(sha1_ctx_t *c, uint8_t out[20]) {
    uint64_t bits = c->count * 8;
    uint8_t pad[72];
    size_t i, len = (size_t)(c->count & 0x3f);
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    i = (len < 56) ? (56 - len) : (120 - len);
    sha1_update(c, pad, i);
    for (i = 0; i < 8; i++)
        pad[i] = (uint8_t)(bits >> (56 - i * 8));
    sha1_update(c, pad, 8);
    for (i = 0; i < 5; i++) {
        out[i * 4] = (uint8_t)(c->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->state[i]);
    }
}

/* HMAC-SHA1(key, msg) -> out[20] */
static void hmac_sha1(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len, uint8_t out[20]) {
    uint8_t k[64];
    uint8_t ipad[64], opad[64];
    sha1_ctx_t c;
    uint8_t inner[20];
    size_t i;
    memset(k, 0, sizeof(k));
    if (key_len > 64)
        key_len = 64;
    memcpy(k, key, key_len);
    for (i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    sha1_init(&c);
    sha1_update(&c, ipad, 64);
    sha1_update(&c, msg, msg_len);
    sha1_final(&c, inner);
    sha1_init(&c);
    sha1_update(&c, opad, 64);
    sha1_update(&c, inner, 20);
    sha1_final(&c, out);
    secure_zero(k, sizeof(k));
    secure_zero(ipad, sizeof(ipad));
    secure_zero(opad, sizeof(opad));
    secure_zero(inner, sizeof(inner));
    secure_zero(&c, sizeof(c));
}

/* PBKDF2-HMAC-SHA1, iterations from frp's golib: 64, output 16 bytes */
int derive_key(const char *token, uint8_t *out, size_t out_len) {
    static const char salt[] = "frp";
    const size_t slen = sizeof(salt) - 1;
    uint32_t block = 1;
    size_t done = 0;
    uint8_t u[20], t[20];
    uint8_t tmp[4 + sizeof(salt)];
    int i, j;

    memcpy(tmp, salt, slen);
    while (done < out_len) {
        tmp[slen + 0] = (uint8_t)(block >> 24);
        tmp[slen + 1] = (uint8_t)(block >> 16);
        tmp[slen + 2] = (uint8_t)(block >> 8);
        tmp[slen + 3] = (uint8_t)block;
        hmac_sha1((const uint8_t *)token, strlen(token), tmp, slen + 4, u);
        memcpy(t, u, 20);
        for (i = 1; i < 64; i++) {
            hmac_sha1((const uint8_t *)token, strlen(token), u, 20, u);
            for (j = 0; j < 20; j++)
                t[j] ^= u[j];
        }
        for (j = 0; j < 20 && done < out_len; j++)
            out[done++] = t[j];
        block++;
    }
    secure_zero(u, sizeof(u));
    secure_zero(t, sizeof(t));
    secure_zero(tmp, sizeof(tmp));
    return 0;
}

/* ----------------------------- AES-128 ----------------------------- */

static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

typedef struct {
    uint8_t rk[15][16];
    int rounds;   /* 10 (128), 12 (192), 14 (256) */
} aes_ctx_t;

static void aes_expand_key(aes_ctx_t *c, const uint8_t *key, int key_len) {
    if (key_len != 16 && key_len != 24 && key_len != 32)
        key_len = 16;
    int nk = key_len / 4;          /* words in key */
    int nr = nk + 6;               /* rounds */
    uint32_t w[60];
    int i, j;

    c->rounds = nr;
    for (i = 0; i < nk; i++)
        w[i] = ((uint32_t)key[i * 4] << 24) | ((uint32_t)key[i * 4 + 1] << 16) |
               ((uint32_t)key[i * 4 + 2] << 8) | key[i * 4 + 3];

    for (i = nk; i < 4 * (nr + 1); i++) {
        uint32_t tmp = w[i - 1];
        uint8_t rcon = 1;
        if (i % nk == 0) {
            int rc = i / nk;
            while (rc > 1) {
                rcon = (uint8_t)((rcon << 1) ^ (rcon & 0x80 ? 0x1b : 0));
                rc--;
            }
            /* RotWord(tmp) = [b1,b2,b3,b0], then SubWord, then Rcon on byte0 */
            tmp = (((uint32_t)aes_sbox[(tmp >> 16) & 0xff] ^ rcon) << 24) |
                  ((uint32_t)aes_sbox[(tmp >> 8) & 0xff] << 16) |
                  ((uint32_t)aes_sbox[tmp & 0xff] << 8) |
                  aes_sbox[(tmp >> 24) & 0xff];
        } else if (nk > 6 && i % nk == 4) {
            tmp = (uint32_t)aes_sbox[(tmp >> 24) & 0xff] << 24 |
                  (uint32_t)aes_sbox[(tmp >> 16) & 0xff] << 16 |
                  (uint32_t)aes_sbox[(tmp >> 8) & 0xff] << 8 |
                  aes_sbox[tmp & 0xff];
        }
        w[i] = w[i - nk] ^ tmp;
    }

    /* store round keys in column-major byte order: rk[round][col*4+byte] */
    for (i = 0; i <= nr; i++) {
        for (j = 0; j < 4; j++) {
            uint32_t word = w[i * 4 + j];
            c->rk[i][j * 4 + 0] = (uint8_t)(word >> 24);
            c->rk[i][j * 4 + 1] = (uint8_t)(word >> 16);
            c->rk[i][j * 4 + 2] = (uint8_t)(word >> 8);
            c->rk[i][j * 4 + 3] = (uint8_t)word;
        }
    }
    secure_zero(w, sizeof(w));
}

static uint8_t aes_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }

/* Software AES uses the 256-byte S-box (resident in L1) plus bitwise
 * MixColumns, avoiding the 4 KiB T-table cache-timing side channel.  On CPUs
 * with AES-NI the hardware path below is used instead. */

#if defined(__x86_64__) || defined(__i386__)
int tfrpc_aes_force_soft = 0;   /* test hook: force software AES even on AES-NI CPUs */
static int g_aes_ni = -1;   /* -1 = undetected, 0 = no, 1 = yes */

static int aes_ni_detect(void) {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx))
        return (ecx & (1u << 25)) ? 1 : 0;   /* CPUID.1:ECX bit 25 = AES-NI */
    return 0;
}

/* AES-NI block encrypt; the round keys in aes_ctx_t.rk are standard AES
 * column-major bytes, loadable directly into XMM. Compiled with the aes
 * target so a plain (non -maes) build still gets hardware AES on x86. */
__attribute__((target("aes,sse2")))
static void aesni_encrypt_block(const aes_ctx_t *c, const uint8_t in[16], uint8_t out[16]) {
    __m128i st = _mm_loadu_si128((const __m128i *)in);
    st = _mm_xor_si128(st, _mm_loadu_si128((const __m128i *)c->rk[0]));
    for (int round = 1; round < c->rounds; round++)
        st = _mm_aesenc_si128(st, _mm_loadu_si128((const __m128i *)c->rk[round]));
    st = _mm_aesenclast_si128(st, _mm_loadu_si128((const __m128i *)c->rk[c->rounds]));
    _mm_storeu_si128((__m128i *)out, st);
}
#endif

static void aes_encrypt_block(aes_ctx_t *c, uint8_t in[16], uint8_t out[16]) {
#if defined(__x86_64__) || defined(__i386__)
    if (g_aes_ni == -1)
        g_aes_ni = tfrpc_aes_force_soft ? 0 : aes_ni_detect();
    if (g_aes_ni) {
        aesni_encrypt_block(c, in, out);
        return;
    }
#endif
    int round, i, nr = c->rounds;
    uint8_t s[16], t[16];

    for (i = 0; i < 16; i++)
        s[i] = in[i] ^ c->rk[0][i];

    for (round = 1; round < nr; round++) {
        /* SubBytes */
        for (i = 0; i < 16; i++)
            s[i] = aes_sbox[s[i]];
        /* ShiftRows */
        for (i = 0; i < 4; i++) {
            t[i * 4 + 0] = s[i * 4 + 0];
            t[i * 4 + 1] = s[((i + 1) % 4) * 4 + 1];
            t[i * 4 + 2] = s[((i + 2) % 4) * 4 + 2];
            t[i * 4 + 3] = s[((i + 3) % 4) * 4 + 3];
        }
        memcpy(s, t, 16);
        /* MixColumns (bitwise, no table lookups) */
        for (i = 0; i < 4; i++) {
            uint8_t a = s[i * 4 + 0], b = s[i * 4 + 1];
            uint8_t cc = s[i * 4 + 2], d = s[i * 4 + 3];
            uint8_t tmp = a ^ b ^ cc ^ d;
            s[i * 4 + 0] = (uint8_t)(a ^ aes_xtime((uint8_t)(a ^ b)) ^ tmp);
            s[i * 4 + 1] = (uint8_t)(b ^ aes_xtime((uint8_t)(b ^ cc)) ^ tmp);
            s[i * 4 + 2] = (uint8_t)(cc ^ aes_xtime((uint8_t)(cc ^ d)) ^ tmp);
            s[i * 4 + 3] = (uint8_t)(d ^ aes_xtime((uint8_t)(d ^ a)) ^ tmp);
        }
        /* AddRoundKey */
        for (i = 0; i < 16; i++)
            s[i] ^= c->rk[round][i];
    }

    /* final round: SubBytes + ShiftRows + AddRoundKey */
    for (i = 0; i < 16; i++)
        s[i] = aes_sbox[s[i]];
    for (i = 0; i < 4; i++) {
        t[i * 4 + 0] = s[i * 4 + 0];
        t[i * 4 + 1] = s[((i + 1) % 4) * 4 + 1];
        t[i * 4 + 2] = s[((i + 2) % 4) * 4 + 2];
        t[i * 4 + 3] = s[((i + 3) % 4) * 4 + 3];
    }
    for (i = 0; i < 16; i++)
        out[i] = t[i] ^ c->rk[nr][i];
    secure_zero(s, sizeof(s));
    secure_zero(t, sizeof(t));
}

/* ------------------- AES-128-CFB streaming (both directions) ------------------- */

typedef struct {
    aes_ctx_t aes;
    uint8_t cfb[16];
    uint8_t tmp[16];
    size_t pos;
    int encrypt;
} aes_cfb_ctx;

static void aes_cfb_init_common(aes_cfb_ctx *ctx, const uint8_t *key, int key_len,
                                const uint8_t *iv, int encrypt) {
    uint8_t k[32];
    if (key_len != 16 && key_len != 24 && key_len != 32)
        key_len = 16;
    memcpy(k, key, (size_t)key_len);
    aes_expand_key(&ctx->aes, k, key_len);
    memcpy(ctx->cfb, iv, 16);
    ctx->pos = 0;
    ctx->encrypt = encrypt;
}

void aes_cfb_free(void *ctxp) {
    if (ctxp) {
        secure_zero(ctxp, sizeof(aes_cfb_ctx));
        free(ctxp);
    }
}

void *aes_cfb_new(const uint8_t *key, int key_len, const uint8_t *iv, int encrypt) {
    aes_cfb_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    aes_cfb_init_common(ctx, key, key_len, iv, encrypt);
    return ctx;
}

/* streaming CFB transform in place; maintains feedback state across calls */
void aes_cfb_stream(void *ctxp, uint8_t *buf, size_t len) {
    aes_cfb_ctx *ctx = ctxp;

    /* finish a partially-consumed keystream block byte-by-byte */
    while (len > 0 && ctx->pos != 0) {
        uint8_t out = (uint8_t)(buf[0] ^ ctx->tmp[ctx->pos]);
        if (ctx->encrypt)
            ctx->cfb[ctx->pos] = out;
        else
            ctx->cfb[ctx->pos] = buf[0];
        buf[0] = out;
        buf++;
        len--;
        ctx->pos = (ctx->pos + 1) & 15;
    }

    /* whole blocks */
    while (len >= 16) {
        aes_encrypt_block(&ctx->aes, ctx->cfb, ctx->tmp);
        if (ctx->encrypt) {
            for (int i = 0; i < 16; i++) {
                uint8_t o = (uint8_t)(buf[i] ^ ctx->tmp[i]);
                buf[i] = o;
                ctx->cfb[i] = o;
            }
        } else {
            uint8_t orig[16];
            memcpy(orig, buf, 16);
            for (int i = 0; i < 16; i++)
                buf[i] ^= ctx->tmp[i];
            memcpy(ctx->cfb, orig, 16);
        }
        buf += 16;
        len -= 16;
    }

    /* tail */
    while (len > 0) {
        if (ctx->pos == 0) {
            aes_encrypt_block(&ctx->aes, ctx->cfb, ctx->tmp);
            memcpy(ctx->cfb, ctx->tmp, 16);
        }
        uint8_t out = (uint8_t)(buf[0] ^ ctx->tmp[ctx->pos]);
        if (ctx->encrypt)
            ctx->cfb[ctx->pos] = out;
        else
            ctx->cfb[ctx->pos] = buf[0];
        buf[0] = out;
        buf++;
        len--;
        ctx->pos = (ctx->pos + 1) & 15;
    }
}

/* ----------------------------- SHA-256 ----------------------------- */

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr32(uint32_t v, int s) { return (v >> s) | (v << (32 - s)); }

static void sha256_transform(sha256_ctx_t *c, const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a, b, d, e, f, g, h, cc;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
    e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + sha256_k[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

void sha256_init(sha256_ctx_t *c) {
    c->state[0] = 0x6a09e667; c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372; c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f; c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab; c->state[7] = 0x5be0cd19;
    c->count = 0;
}

void sha256_update(sha256_ctx_t *c, const uint8_t *data, size_t len) {
    if (len == 0 || !data)
        return;
    size_t have = (size_t)(c->count & 0x3f);
    c->count += len;
    if (have) {
        size_t need = 64 - have;
        if (len < need) { memcpy(c->buffer + have, data, len); return; }
        memcpy(c->buffer + have, data, need);
        sha256_transform(c, c->buffer);
        data += need; len -= need;
    }
    while (len >= 64) { sha256_transform(c, data); data += 64; len -= 64; }
    memcpy(c->buffer, data, len);
}

void sha256_final(sha256_ctx_t *c, uint8_t out[32]) {
    uint64_t bits = c->count * 8;
    uint8_t pad[72];
    size_t i, len = (size_t)(c->count & 0x3f);
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    i = (len < 56) ? (56 - len) : (120 - len);
    sha256_update(c, pad, i);
    for (i = 0; i < 8; i++)
        pad[i] = (uint8_t)(bits >> (56 - i * 8));
    sha256_update(c, pad, 8);
    for (i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(c->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->state[i]);
    }
}

void sha256_digest(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx_t c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
    uint8_t k[64];
    uint8_t ipad[64], opad[64];
    sha256_ctx_t c;
    uint8_t inner[32];
    size_t i;
    memset(k, 0, sizeof(k));
    if (key_len > 64) key_len = 64;
    if (key_len > 0 && key)
        memcpy(k, key, key_len);
    for (i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, msg_len);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
    secure_zero(k, sizeof(k));
    secure_zero(ipad, sizeof(ipad));
    secure_zero(opad, sizeof(opad));
    secure_zero(inner, sizeof(inner));
    secure_zero(&c, sizeof(c));
}

/* HKDF-SHA256(secret, salt, info, keyLen). salt may be NULL (len 0). */
void hkdf_sha256(const uint8_t *secret, size_t secret_len,
                 const uint8_t *salt, size_t salt_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *out, size_t out_len) {
    uint8_t prk[32];
    uint8_t t[32];
    size_t done = 0;
    uint8_t counter;
    hmac_sha256(salt, salt_len, secret, secret_len, prk);
    counter = 1;
    while (done < out_len) {
        uint8_t input[64 + 128];
        size_t ilen = done > 0 ? 32 : 0;
        if (ilen)
            memcpy(input, t, 32);
        memcpy(input + ilen, info, info_len);
        input[ilen + info_len] = counter;
        hmac_sha256(prk, 32, input, ilen + info_len + 1, t);
        for (size_t j = 0; j < 32 && done < out_len; j++)
            out[done++] = t[j];
        secure_zero(input, sizeof(input));
        counter++;
    }
    secure_zero(prk, sizeof(prk));
    secure_zero(t, sizeof(t));
}



/* ----------------------------- AES-256-GCM ----------------------------- */

/* GF(2^128) multiplication, GCM polynomial x^128+x^7+x^2+x+1.
 *
 * Bitwise (MSB-first) implementation per NIST SP 800-38D Algorithm 1.
 * A 4-bit table variant was attempted for speed but requires bit-reversed
 * table construction to match GCM's bit order; correctness first. */
static uint64_t be64(const uint8_t p[8]) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static void put64(uint8_t p[8], uint64_t v) {
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (56 - i * 8));
}

static void gcm_mult(uint8_t x[16], const uint8_t y[16], uint8_t out[16]) {
    /* 64-bit limbs; same algorithm as the byte-wise version, ~4x fewer ops */
    uint64_t zh = 0, zl = 0;
    uint64_t vh = be64(y), vl = be64(y + 8);
    for (int i = 0; i < 128; i++) {
        if (x[i >> 3] & (0x80 >> (i & 7))) {
            zh ^= vh;
            zl ^= vl;
        }
        uint64_t carry = vl & 1;
        vl = (vl >> 1) | (vh << 63);
        vh = (vh >> 1) ^ (carry ? 0xe100000000000000ULL : 0);
    }
    put64(out, zh);
    put64(out + 8, zl);
}

static void gcm_ghash(const uint8_t h[16], const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t ct_len, uint8_t out[16]) {
    uint8_t y[16];
    uint8_t block[16];
    size_t off;
    memset(y, 0, 16);

    off = 0;
    while (off < aad_len) {
        size_t n = aad_len - off;
        memset(block, 0, 16);
        memcpy(block, aad + off, n < 16 ? n : 16);
        off += n < 16 ? n : 16;
        for (int i = 0; i < 16; i++) y[i] ^= block[i];
        gcm_mult(y, h, y);
    }
    off = 0;
    while (off < ct_len) {
        size_t n = ct_len - off;
        memset(block, 0, 16);
        memcpy(block, ct + off, n < 16 ? n : 16);
        off += n < 16 ? n : 16;
        for (int i = 0; i < 16; i++) y[i] ^= block[i];
        gcm_mult(y, h, y);
    }
    /* length block: len(aad)||len(ct), 64-bit each, big-endian */
    memset(block, 0, 16);
    {
        uint64_t ab = (uint64_t)aad_len * 8, cb = (uint64_t)ct_len * 8;
        for (int i = 0; i < 8; i++) {
            block[i] = (uint8_t)(ab >> (56 - i * 8));
            block[8 + i] = (uint8_t)(cb >> (56 - i * 8));
        }
    }
    for (int i = 0; i < 16; i++) y[i] ^= block[i];
    gcm_mult(y, h, y);
    memcpy(out, y, 16);
}

static void inc32_be(uint8_t x[16]) {
    for (int i = 15; i >= 12; i--)
        if (++x[i] != 0) break;
}

/* GCTR: encrypt/decrypt in place using counter icb */
static void gcm_gctr(const uint8_t *key, int key_len, uint8_t icb[16], uint8_t *data, size_t len) {
    aes_ctx_t c;
    uint8_t e[16];
    size_t off = 0;
    aes_expand_key(&c, key, key_len);
    while (off < len) {
        aes_encrypt_block(&c, icb, e);
        for (int i = 0; i < 16 && off + i < len; i++)
            data[off + i] ^= e[i];
        inc32_be(icb);
        off += 16;
    }
}

/* AES-256-GCM seal. nonce must be 12 bytes. tag is 16 bytes. */
void aes_gcm_seal(const uint8_t *key, int key_len, const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     uint8_t *data, size_t len, uint8_t tag[16]) {
    aes_ctx_t c;
    uint8_t h[16], j0[16], icb[16], s[16], e[16];
    aes_expand_key(&c, key, key_len);
    memset(h, 0, 16);
    aes_encrypt_block(&c, h, h);

    memset(j0, 0, 16);
    memcpy(j0, nonce, 12);
    j0[15] = 1;
    memcpy(icb, j0, 16);
    inc32_be(icb);   /* GCTR starts at inc32(J0); the tag uses E(K, J0) */
    gcm_gctr(key, key_len, icb, data, len);

    gcm_ghash(h, aad, aad_len, data, len, s);
    aes_encrypt_block(&c, j0, e);
    for (int i = 0; i < 16; i++)
        tag[i] = s[i] ^ e[i];
    secure_zero(&c, sizeof(c));
    secure_zero(h, sizeof(h));
    secure_zero(j0, sizeof(j0));
    secure_zero(icb, sizeof(icb));
    secure_zero(s, sizeof(s));
    secure_zero(e, sizeof(e));
}

/* AES-256-GCM open. returns 0 on success (tag valid), -1 on auth failure. */
int aes_gcm_open(const uint8_t *key, int key_len, const uint8_t nonce[12],
                    const uint8_t *aad, size_t aad_len,
                    uint8_t *data, size_t len, const uint8_t tag[16]) {
    aes_ctx_t c;
    uint8_t h[16], j0[16], icb[16], s[16], e[16], t[16];
    aes_expand_key(&c, key, key_len);
    memset(h, 0, 16);
    aes_encrypt_block(&c, h, h);

    memset(j0, 0, 16);
    memcpy(j0, nonce, 12);
    j0[15] = 1;
    memcpy(icb, j0, 16);
    gcm_ghash(h, aad, aad_len, data, len, s);
    aes_encrypt_block(&c, j0, e);
    for (int i = 0; i < 16; i++)
        t[i] = s[i] ^ e[i];

    int diff = 0;
    for (int i = 0; i < 16; i++)
        diff |= t[i] ^ tag[i];

    if (diff == 0) {
        inc32_be(icb);   /* GCTR starts at inc32(J0) */
        gcm_gctr(key, key_len, icb, data, len);
    }
    secure_zero(&c, sizeof(c));
    secure_zero(h, sizeof(h));
    secure_zero(j0, sizeof(j0));
    secure_zero(icb, sizeof(icb));
    secure_zero(s, sizeof(s));
    secure_zero(e, sizeof(e));
    secure_zero(t, sizeof(t));
    return diff == 0 ? 0 : -1;
}

/* ---------------------- ChaCha20 / Poly1305 / XChaCha ---------------------- */

static uint32_t rotl32(uint32_t v, int s) { return (v << s) | (v >> (32 - s)); }

static void chacha20_quarter(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7);
}

static void chacha20_block(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t x[16], st[16];
    static const uint32_t cst[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    int i;
    for (i = 0; i < 4; i++) st[i] = cst[i];
    for (i = 0; i < 8; i++)
        st[4 + i] = (uint32_t)key[i * 4] | ((uint32_t)key[i * 4 + 1] << 8) |
                    ((uint32_t)key[i * 4 + 2] << 16) | ((uint32_t)key[i * 4 + 3] << 24);
    st[12] = counter;
    st[13] = (uint32_t)nonce[0] | ((uint32_t)nonce[1] << 8) |
             ((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);
    st[14] = (uint32_t)nonce[4] | ((uint32_t)nonce[5] << 8) |
             ((uint32_t)nonce[6] << 16) | ((uint32_t)nonce[7] << 24);
    st[15] = (uint32_t)nonce[8] | ((uint32_t)nonce[9] << 8) |
             ((uint32_t)nonce[10] << 16) | ((uint32_t)nonce[11] << 24);
    memcpy(x, st, 64);
    for (i = 0; i < 10; i++) {
        chacha20_quarter(&x[0], &x[4], &x[8], &x[12]);
        chacha20_quarter(&x[1], &x[5], &x[9], &x[13]);
        chacha20_quarter(&x[2], &x[6], &x[10], &x[14]);
        chacha20_quarter(&x[3], &x[7], &x[11], &x[15]);
        chacha20_quarter(&x[0], &x[5], &x[10], &x[15]);
        chacha20_quarter(&x[1], &x[6], &x[11], &x[12]);
        chacha20_quarter(&x[2], &x[7], &x[8], &x[13]);
        chacha20_quarter(&x[3], &x[4], &x[9], &x[14]);
    }
    for (i = 0; i < 16; i++) {
        uint32_t v = x[i] + st[i];
        out[i * 4] = (uint8_t)(v & 0xff);
        out[i * 4 + 1] = (uint8_t)((v >> 8) & 0xff);
        out[i * 4 + 2] = (uint8_t)((v >> 16) & 0xff);
        out[i * 4 + 3] = (uint8_t)((v >> 24) & 0xff);
    }
}

/* HChaCha20: key[32] + in[16] -> out[32], used by XChaCha20 */
static void hchacha20(const uint8_t key[32], const uint8_t in[16], uint8_t out[32]) {
    uint32_t x[16];
    static const uint32_t cst[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    int i;
    for (i = 0; i < 4; i++) x[i] = cst[i];
    for (i = 0; i < 8; i++)
        x[4 + i] = (uint32_t)key[i * 4] | ((uint32_t)key[i * 4 + 1] << 8) |
                   ((uint32_t)key[i * 4 + 2] << 16) | ((uint32_t)key[i * 4 + 3] << 24);
    for (i = 0; i < 4; i++)
        x[12 + i] = (uint32_t)in[i * 4] | ((uint32_t)in[i * 4 + 1] << 8) |
                    ((uint32_t)in[i * 4 + 2] << 16) | ((uint32_t)in[i * 4 + 3] << 24);
    for (i = 0; i < 10; i++) {
        chacha20_quarter(&x[0], &x[4], &x[8], &x[12]);
        chacha20_quarter(&x[1], &x[5], &x[9], &x[13]);
        chacha20_quarter(&x[2], &x[6], &x[10], &x[14]);
        chacha20_quarter(&x[3], &x[7], &x[11], &x[15]);
        chacha20_quarter(&x[0], &x[5], &x[10], &x[15]);
        chacha20_quarter(&x[1], &x[6], &x[11], &x[12]);
        chacha20_quarter(&x[2], &x[7], &x[8], &x[13]);
        chacha20_quarter(&x[3], &x[4], &x[9], &x[14]);
    }
    for (i = 0; i < 4; i++) {
        out[i * 4] = (uint8_t)(x[i] & 0xff);
        out[i * 4 + 1] = (uint8_t)((x[i] >> 8) & 0xff);
        out[i * 4 + 2] = (uint8_t)((x[i] >> 16) & 0xff);
        out[i * 4 + 3] = (uint8_t)((x[i] >> 24) & 0xff);
        out[16 + i * 4] = (uint8_t)(x[12 + i] & 0xff);
        out[16 + i * 4 + 1] = (uint8_t)((x[12 + i] >> 8) & 0xff);
        out[16 + i * 4 + 2] = (uint8_t)((x[12 + i] >> 16) & 0xff);
        out[16 + i * 4 + 3] = (uint8_t)((x[12 + i] >> 24) & 0xff);
    }
}

/* Poly1305 one-time authenticator (RFC 8439) */


typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t leftover;
    uint8_t buffer[16];
} poly1305_state;

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void poly1305_multiply(poly1305_state *st) {
    uint64_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint64_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint64_t t0, t1, t2, t3, t4, c;
    t0 = h0*r0 + h1*(5*r4) + h2*(5*r3) + h3*(5*r2) + h4*(5*r1);
    t1 = h0*r1 + h1*r0 + h2*(5*r4) + h3*(5*r3) + h4*(5*r2);
    t2 = h0*r2 + h1*r1 + h2*r0 + h3*(5*r4) + h4*(5*r3);
    t3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*(5*r4);
    t4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;
    c = t0 >> 26; t0 &= 0x3ffffff; t1 += c;
    c = t1 >> 26; t1 &= 0x3ffffff; t2 += c;
    c = t2 >> 26; t2 &= 0x3ffffff; t3 += c;
    c = t3 >> 26; t3 &= 0x3ffffff; t4 += c;
    c = t4 >> 26; t4 &= 0x3ffffff; t0 += c * 5;
    c = t0 >> 26; t0 &= 0x3ffffff; t1 += c;
    st->h[0] = (uint32_t)t0; st->h[1] = (uint32_t)t1; st->h[2] = (uint32_t)t2;
    st->h[3] = (uint32_t)t3; st->h[4] = (uint32_t)t4;
}

static void poly1305_blocks(poly1305_state *st, const uint8_t *m, size_t bytes, uint32_t hibit) {
    while (bytes >= 16) {
        uint32_t t[5];
        t[0] = le32(m) & 0x3ffffff;
        t[1] = (le32(m + 3) >> 2) & 0x3ffffff;
        t[2] = (le32(m + 6) >> 4) & 0x3ffffff;
        t[3] = (le32(m + 9) >> 6) & 0x3ffffff;
        t[4] = (le32(m + 12) >> 8) | hibit;
        st->h[0] += t[0]; st->h[1] += t[1]; st->h[2] += t[2];
        st->h[3] += t[3]; st->h[4] += t[4];
        poly1305_multiply(st);
        m += 16; bytes -= 16;
    }
}

static void poly1305_finish(poly1305_state *st, uint8_t mac[16]) {
    uint32_t g[5], mask, c;
    uint64_t f;
    int i;
    if (st->leftover) {
        size_t j;
        st->buffer[st->leftover] = 1;
        for (j = st->leftover + 1; j < 16; j++)
            st->buffer[j] = 0;
        st->leftover = 0;
        poly1305_blocks(st, st->buffer, 16, 0);
    }
    c = st->h[1] >> 26; st->h[1] &= 0x3ffffff; st->h[2] += c;
    c = st->h[2] >> 26; st->h[2] &= 0x3ffffff; st->h[3] += c;
    c = st->h[3] >> 26; st->h[3] &= 0x3ffffff; st->h[4] += c;
    c = st->h[4] >> 26; st->h[4] &= 0x3ffffff; st->h[0] += c * 5;
    c = st->h[0] >> 26; st->h[0] &= 0x3ffffff; st->h[1] += c;

    /* compute h + -p */
    g[0] = st->h[0] + 5; c = g[0] >> 26; g[0] &= 0x3ffffff;
    g[1] = st->h[1] + c; c = g[1] >> 26; g[1] &= 0x3ffffff;
    g[2] = st->h[2] + c; c = g[2] >> 26; g[2] &= 0x3ffffff;
    g[3] = st->h[3] + c; c = g[3] >> 26; g[3] &= 0x3ffffff;
    g[4] = st->h[4] + c - (1 << 26);
    mask = (g[4] >> 31) - 1;
    g[0] &= mask; g[1] &= mask; g[2] &= mask; g[3] &= mask; g[4] &= mask;
    mask = ~mask;
    st->h[0] = (st->h[0] & mask) | g[0];
    st->h[1] = (st->h[1] & mask) | g[1];
    st->h[2] = (st->h[2] & mask) | g[2];
    st->h[3] = (st->h[3] & mask) | g[3];
    st->h[4] = (st->h[4] & mask) | g[4];

    /* h = h % 2^128: repack 26-bit limbs into 32-bit words */
    st->h[0] = (st->h[0] | (st->h[1] << 26)) & 0xffffffff;
    st->h[1] = ((st->h[1] >> 6) | (st->h[2] << 20)) & 0xffffffff;
    st->h[2] = ((st->h[2] >> 12) | (st->h[3] << 14)) & 0xffffffff;
    st->h[3] = ((st->h[3] >> 18) | (st->h[4] << 8)) & 0xffffffff;

    /* mac = (h + pad) % 2^128 */
    f = ((uint64_t)st->h[0]) + st->pad[0]; st->h[0] = (uint32_t)f;
    f = ((uint64_t)st->h[1]) + st->pad[1] + (f >> 32); st->h[1] = (uint32_t)f;
    f = ((uint64_t)st->h[2]) + st->pad[2] + (f >> 32); st->h[2] = (uint32_t)f;
    f = ((uint64_t)st->h[3]) + st->pad[3] + (f >> 32); st->h[3] = (uint32_t)f;

    for (i = 0; i < 4; i++) {
        mac[i * 4] = (uint8_t)(st->h[i] & 0xff);
        mac[i * 4 + 1] = (uint8_t)((st->h[i] >> 8) & 0xff);
        mac[i * 4 + 2] = (uint8_t)((st->h[i] >> 16) & 0xff);
        mac[i * 4 + 3] = (uint8_t)((st->h[i] >> 24) & 0xff);
    }
}

/* ChaCha20 keystream, XORed into out in place */
static void chacha20_stream(const uint8_t key[32], const uint8_t nonce[12],
                            uint32_t start_ctr, uint8_t *out, size_t len) {
    uint8_t block[64];
    size_t off = 0;
    while (off < len) {
        chacha20_block(key, start_ctr, nonce, block);
        for (size_t i = 0; i < 64 && off + i < len; i++)
            out[off + i] ^= block[i];
        off += 64;
        start_ctr++;
    }
}



/* ChaCha20-Poly1305 AEAD (RFC 8439). nonce is 12 bytes. */

static void poly1305_init(poly1305_state *st, const uint8_t key[32]) {
    memset(st, 0, sizeof(*st));
    st->r[0] = le32(key) & 0x3ffffff;
    st->r[1] = (le32(key + 3) >> 2) & 0x3ffff03;
    st->r[2] = (le32(key + 6) >> 4) & 0x3ffc0ff;
    st->r[3] = (le32(key + 9) >> 6) & 0x3f03fff;
    st->r[4] = (le32(key + 12) >> 8) & 0x00fffff;
    st->pad[0] = le32(key + 16);
    st->pad[1] = le32(key + 20);
    st->pad[2] = le32(key + 24);
    st->pad[3] = le32(key + 28);
}

static void poly1305_update(poly1305_state *st, const uint8_t *m, size_t len) {
    if (st->leftover) {
        size_t want = 16 - st->leftover;
        if (want > len) want = len;
        memcpy(st->buffer + st->leftover, m, want);
        len -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < 16)
            return;
        poly1305_blocks(st, st->buffer, 16, 1 << 24);
        st->leftover = 0;
    }
    if (len >= 16) {
        size_t want = len & ~15u;
        poly1305_blocks(st, m, want, 1 << 24);
        m += want;
        len -= want;
    }
    if (len) {
        memcpy(st->buffer, m, len);
        st->leftover = len;
    }
}

static void poly1305_final(poly1305_state *st, uint8_t tag[16]) {
    poly1305_finish(st, tag);
}

static void chacha20_poly1305_mac(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *data, size_t len, uint8_t tag[16]) {
    uint8_t otk[64];
    uint8_t polykey[32];
    poly1305_state st;
    uint8_t pad[16];
    size_t rem;

    chacha20_block(key, 0, nonce, otk);
    memcpy(polykey, otk, 32);
    poly1305_init(&st, polykey);
    if (aad_len) {
        poly1305_update(&st, aad, aad_len);
        rem = aad_len & 15;
        if (rem) {
            memset(pad, 0, 16);
            poly1305_update(&st, pad, 16 - rem);
        }
    }
    poly1305_update(&st, data, len);
    rem = len & 15;
    if (rem) {
        memset(pad, 0, 16);
        poly1305_update(&st, pad, 16 - rem);
    }
    {
        uint8_t lenblock[16];
        for (int i = 0; i < 8; i++)
            lenblock[i] = (uint8_t)(((uint64_t)aad_len) >> (8 * i));
        for (int i = 0; i < 8; i++)
            lenblock[8 + i] = (uint8_t)(((uint64_t)len) >> (8 * i));
        poly1305_update(&st, lenblock, 16);
    }
    poly1305_final(&st, tag);
}

void chacha20_poly1305_seal(const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *data, size_t len, uint8_t tag[16]) {
    chacha20_stream(key, nonce, 1, data, len);
    chacha20_poly1305_mac(key, nonce, aad, aad_len, data, len, tag);
}

int chacha20_poly1305_open(const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *data, size_t len, const uint8_t tag[16]) {
    uint8_t calc[16];
    int diff = 0;
    chacha20_poly1305_mac(key, nonce, aad, aad_len, data, len, calc);
    for (int i = 0; i < 16; i++)
        diff |= calc[i] ^ tag[i];
    if (diff == 0)
        chacha20_stream(key, nonce, 1, data, len);
    secure_zero(calc, sizeof(calc));
    return diff == 0 ? 0 : -1;
}

/* XChaCha20-Poly1305: 24-byte nonce. subkey = HChaCha20(key, nonce[0:16]),
 * then ChaCha20-Poly1305 with nonce = nonce[16:24] || 4 zero bytes. */
void xchacha20_poly1305_seal(const uint8_t key[32], const uint8_t nonce24[24],
                             const uint8_t *aad, size_t aad_len,
                             uint8_t *data, size_t len, uint8_t tag[16]) {
    uint8_t subkey[32];
    uint8_t nonce12[12];
    hchacha20(key, nonce24, subkey);
    memset(nonce12, 0, 4);
    memcpy(nonce12 + 4, nonce24 + 16, 8);
    chacha20_poly1305_seal(subkey, nonce12, aad, aad_len, data, len, tag);
    secure_zero(subkey, sizeof(subkey));
}

int xchacha20_poly1305_open(const uint8_t key[32], const uint8_t nonce24[24],
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *data, size_t len, const uint8_t tag[16]) {
    uint8_t subkey[32];
    uint8_t nonce12[12];
    hchacha20(key, nonce24, subkey);
    memset(nonce12, 0, 4);
    memcpy(nonce12 + 4, nonce24 + 16, 8);
    int rc = chacha20_poly1305_open(subkey, nonce12, aad, aad_len, data, len, tag);
    secure_zero(subkey, sizeof(subkey));
    return rc;
}




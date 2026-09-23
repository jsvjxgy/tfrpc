/*
 * SPDX-License-Identifier: GPL-3.0-only
 * unit_tests.c - deterministic unit tests for tfrpc's crypto primitives and
 * wire parsers.  Run with `make test`.
 *
 * Crypto cases use published test vectors (NIST / RFC); parser cases are
 * randomized fuzz loops meant to be run under ASan/UBSan.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>

#include "tfrpc.h"
#include "x25519.h"
#include "ecdsa.h"
#include "x509.h"
#include "snappy.h"

/* the client defines these in main.c / control.c */
_Atomic int g_running = 1;

static int g_fails;
static int g_checks;

static void check(const char *name, const uint8_t *got, const uint8_t *exp, size_t l) {
    g_checks++;
    if (memcmp(got, exp, l) != 0) {
        g_fails++;
        printf("FAIL %s\n", name);
    } else {
        printf("ok   %s\n", name);
    }
}

static int hex2bin(const char *h, uint8_t *o) {
    int n = 0;
    while (h[0] && h[1]) {
        unsigned v;
        sscanf(h, "%2x", &v);
        o[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

static uint32_t g_rng = 0x12345678;
static uint32_t rnd(void) { g_rng = g_rng * 1103515245 + 12345; return g_rng >> 8; }

static void test_crypto_vectors(void) {
    /* SHA-256("abc"), NIST */
    {
        uint8_t d[32];
        const uint8_t e[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
        sha256_digest((const uint8_t *)"abc", 3, d);
        check("SHA-256(abc) NIST", d, e, 32);
    }
    /* HMAC-SHA256 RFC 4231 case 2 */
    {
        const uint8_t key[4] = {'J','e','f','e'};
        const uint8_t e[32] = {0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43};
        uint8_t d[32];
        hmac_sha256(key, 4, (const uint8_t *)"what do ya want for nothing?", 28, d);
        check("HMAC-SHA256 RFC4231#2", d, e, 32);
    }
    /* HKDF-SHA256 RFC 5869 case 1 */
    {
        const uint8_t ikm[22] = {0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
        const uint8_t salt[13] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
        const uint8_t info[10] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9};
        const uint8_t e[42] = {0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65};
        uint8_t okm[42];
        hkdf_sha256(ikm, 22, salt, 13, info, 10, okm, 42);
        check("HKDF-SHA256 RFC5869#1", okm, e, 42);
    }
    /* AES-128-GCM, NIST */
    {
        const uint8_t key[16] = {0}, iv[12] = {0}, pt[16] = {0};
        const uint8_t e[16] = {0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78};
        const uint8_t et[16] = {0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf};
        uint8_t buf[16], tag[16];
        memcpy(buf, pt, 16);
        aes_gcm_seal(key, 16, iv, NULL, 0, buf, 16, tag);
        check("AES-128-GCM ct NIST", buf, e, 16);
        check("AES-128-GCM tag NIST", tag, et, 16);
    }
    /* ChaCha20-Poly1305 RFC 8439 2.8.2 */
    {
        uint8_t key[32], nonce[12], aad[12], buf[114], tag[16], e[114], et[16];
        hex2bin("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key);
        hex2bin("070000004041424344454647", nonce);
        hex2bin("50515253c0c1c2c3c4c5c6c7", aad);
        const char *msg = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        memcpy(buf, msg, 114);
        hex2bin("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116", e);
        hex2bin("1ae10b594f09e26a7e902ecbd0600691", et);
        chacha20_poly1305_seal(key, nonce, aad, 12, buf, 114, tag);
        check("ChaCha20-Poly1305 ct RFC8439", buf, e, 114);
        check("ChaCha20-Poly1305 tag RFC8439", tag, et, 16);
    }
    /* XChaCha20-Poly1305 draft-irtf-cfrg-xchacha-03 A.3 */
    {
        uint8_t key[32], nonce[24], aad[12], buf[114], tag[16], e[114], et[16];
        hex2bin("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key);
        hex2bin("404142434445464748494a4b4c4d4e4f5051525354555657", nonce);
        hex2bin("50515253c0c1c2c3c4c5c6c7", aad);
        const char *msg = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        memcpy(buf, msg, 114);
        hex2bin("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e", e);
        hex2bin("c0875924c1c7987947deafd8780acf49", et);
        xchacha20_poly1305_seal(key, nonce, aad, 12, buf, 114, tag);
        check("XChaCha20-Poly1305 ct draft", buf, e, 114);
        check("XChaCha20-Poly1305 tag draft", tag, et, 16);
    }
    /* AES-128-CFB128 NIST SP800-38A F.3.13 */
    {
        uint8_t key[16], iv[16], buf[64], e[64];
        hex2bin("2b7e151628aed2a6abf7158809cf4f3c", key);
        hex2bin("000102030405060708090a0b0c0d0e0f", iv);
        hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", buf);
        hex2bin("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6", e);
        void *ctx = aes_cfb_new(key, 16, iv, 1);
        aes_cfb_stream(ctx, buf, 64);
        aes_cfb_free(ctx);
        check("AES-128-CFB128 NIST", buf, e, 64);
    }
    /* X25519 RFC 7748 #1 */
    {
        uint8_t k[32], u[32], e[32], out[32];
        hex2bin("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", k);
        hex2bin("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u);
        hex2bin("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", e);
        x25519(out, k, u);
        check("X25519 RFC7748#1", out, e, 32);
    }
    /* ECDSA P-256 over SHA-256("sample") - signature generated with OpenSSL */
    {
        uint8_t pub[65], hash[32], sig[70];
        hex2bin("041ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9", pub);
        sha256_digest((const uint8_t *)"sample", 6, hash);
        hex2bin("3044022061c2911e837b1de42bb08ceb8106d6cc93db351dda8a2616e329fb87386a714f02200b65e7d070155429c0aa2d2c089b0f2dc1d27cf4f992611aa79502aa326e808d", sig);
        g_checks++;
        if (ecdsa_p256_verify(pub, 65, hash, 32, sig, 70) != 0) { g_fails++; printf("FAIL ECDSA P-256 verify\n"); }
        else printf("ok   ECDSA P-256 verify (OpenSSL sig)\n");
        sig[40] ^= 0xff;
        g_checks++;
        if (ecdsa_p256_verify(pub, 65, hash, 32, sig, 70) == 0) { g_fails++; printf("FAIL ECDSA corrupt sig accepted\n"); }
        else printf("ok   ECDSA corrupt sig rejected\n");
    }
}

static uint8_t g_snappy_data[512];
static size_t g_snappy_len, g_snappy_pos;

static int snappy_fuzz_in(void *ctx, uint8_t *data, size_t len) {
    (void)ctx;
    if (g_snappy_pos + len > g_snappy_len)
        return -1;
    memcpy(data, g_snappy_data + g_snappy_pos, len);
    g_snappy_pos += len;
    return 0;
}

static void test_parsers(void) {
    /* JSON: adversarial escapes and truncation */
    {
        static const char *inputs[] = {
            "{\"k\":\"\\u12", "{\"k\":\"\\u", "{\"k\":\"\\u0041\"}",
            "{\"k\":\"", "{\"k\":\"\\", "{\"k\":\"\\x",
            "{\"IP\":\"1.2.3.4\",\"Port\":\"7000\"}", "{\"k\":true}", NULL
        };
        char out[8];
        int64_t iv = 0;
        bool bv = false;
        for (int i = 0; inputs[i]; i++) {
            jget_str(inputs[i], "k", out, sizeof(out));
            jget_int(inputs[i], "Port", &iv);
            jget_bool(inputs[i], "k", &bv);
        }
        g_checks++;
        printf("ok   JSON parser adversarial inputs\n");
    }
    /* base64 must never overflow a small output buffer */
    {
        char big[8192];
        uint8_t out[100];
        memset(big, 'A', sizeof(big));
        size_t n = base64_decode(big, sizeof(big), out, sizeof(out));
        g_checks++;
        if (n > sizeof(out)) { g_fails++; printf("FAIL base64 overflow (%zu)\n", n); }
        else printf("ok   base64 bounded decode\n");
        /* roundtrip */
        uint8_t data[64], dec[64];
        char enc[128];
        for (int i = 0; i < 64; i++) data[i] = (uint8_t)i;
        size_t el = base64_encode(data, 64, enc);
        size_t dl = base64_decode(enc, el, dec, sizeof(dec));
        g_checks++;
        if (dl != 64 || memcmp(data, dec, 64)) { g_fails++; printf("FAIL base64 roundtrip\n"); }
        else printf("ok   base64 roundtrip\n");
    }
    /* v2 UDP packet decode fuzz */
    {
        uint8_t payload[1500], ip[64];
        int port, bad = 0;
        size_t plen;
        for (int i = 0; i < 100000; i++) {
            uint8_t body[128];
            size_t blen = rnd() % sizeof(body);
            for (size_t j = 0; j < blen; j++) body[j] = (uint8_t)rnd();
            if (v2_udp_packet_decode(body, blen, payload, sizeof(payload), &plen,
                                     (char *)ip, sizeof(ip), &port) == 0 && plen > sizeof(payload))
                bad++;
        }
        g_checks++;
        if (bad) { g_fails++; printf("FAIL v2 udp decode overflow x%d\n", bad); }
        else printf("ok   v2 UDP decode fuzz (100000 inputs)\n");
    }
    /* x509 DER fuzz */
    {
        for (int i = 0; i < 20000; i++) {
            uint8_t der[256];
            size_t dlen = 4 + rnd() % (sizeof(der) - 4);
            for (size_t j = 0; j < dlen; j++) der[j] = (uint8_t)rnd();
            if (i % 3 == 0) { der[0] = 0x30; der[1] = (uint8_t)(rnd() & 0xff); }
            x509_cert_t cert;
            x509_parse(der, dlen, &cert);
        }
        printf("ok   x509 DER fuzz (20000 inputs)\n");
    }
    /* snappy framed-stream fuzz: feed random bytes through a bounded source */
    {
        for (int i = 0; i < 10000; i++) {
            g_snappy_len = 4 + rnd() % (sizeof(g_snappy_data) - 4);
            for (size_t j = 0; j < g_snappy_len; j++)
                g_snappy_data[j] = (uint8_t)rnd();
            g_snappy_pos = 0;
            snappy_reader_t *r = snappy_reader_new(snappy_fuzz_in, NULL);
            if (r) {
                uint8_t out[4096];
                for (int k = 0; k < 4; k++)
                    if (snappy_reader_read(r, out, sizeof(out)) <= 0)
                        break;
                snappy_reader_free(r);
            }
        }
        printf("ok   snappy framed-stream fuzz (10000 inputs)\n");
    }
}

int main(void) {
    printf("== crypto vectors ==\n");
    test_crypto_vectors();
    printf("== parsers ==\n");
    test_parsers();
    printf("\n%d checks, %d failures\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}

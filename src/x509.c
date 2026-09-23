/*
 * SPDX-License-Identifier: GPL-3.0-only
 * x509.c - minimal DER/X.509 certificate parsing and validation for TLS.
 * Supports RSA (PKCS#1 v1.5) signed certificates and DNS SAN host checks,
 * which covers frps' self-signed RSA certificate and common CA certs.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include "x509.h"
#include "ecdsa.h"
#include "tfrpc.h"


typedef struct {
    uint8_t tag;
    size_t len;
    const uint8_t *val;
    const uint8_t *next;
} tlv_t;

static int der_next(const uint8_t **p, const uint8_t *end, tlv_t *t) {
    const uint8_t *q = *p;
    if (q + 2 > end)
        return -1;
    t->tag = q[0];
    q++;
    if (*q < 0x80) {
        t->len = *q++;
    } else {
        int n = *q++ & 0x7f;
        if (n == 0 || n > 4 || q + n > end)
            return -1;
        t->len = 0;
        for (int i = 0; i < n; i++)
            t->len = (t->len << 8) | *q++;
    }
    if (t->len > (size_t)(end - q))   /* subtraction avoids pointer overflow */
        return -1;
    t->val = q;
    t->next = q + t->len;
    *p = t->next;
    return 0;
}

/* AlgorithmIdentifier OID -> signature type + hash length */
static int sig_alg_parse(const uint8_t *oid, size_t len, int *type, int *hash) {
    static const uint8_t rsa256[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b};
    static const uint8_t rsa384[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0c};
    static const uint8_t rsa512[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0d};
    static const uint8_t ec256[]  = {0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02};
    static const uint8_t ec384[]  = {0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x03};
    static const uint8_t ec512[]  = {0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x04};
    if (len == sizeof(rsa256) && !memcmp(oid, rsa256, len)) { *type = X509_KEY_RSA; *hash = 32; return 0; }
    if (len == sizeof(rsa384) && !memcmp(oid, rsa384, len)) { *type = X509_KEY_RSA; *hash = 48; return 0; }
    if (len == sizeof(rsa512) && !memcmp(oid, rsa512, len)) { *type = X509_KEY_RSA; *hash = 64; return 0; }
    if (len == sizeof(ec256) && !memcmp(oid, ec256, len)) { *type = X509_KEY_ECDSA; *hash = 32; return 0; }
    if (len == sizeof(ec384) && !memcmp(oid, ec384, len)) { *type = X509_KEY_ECDSA; *hash = 48; return 0; }
    if (len == sizeof(ec512) && !memcmp(oid, ec512, len)) { *type = X509_KEY_ECDSA; *hash = 64; return 0; }
    return -1;
}

/* parse subjectPublicKeyInfo contents (q points past the outer SEQUENCE) */
static int parse_spki(const uint8_t *q, const uint8_t *qe, x509_cert_t *out) {
    static const uint8_t oid_ec[] = {0x2a,0x86,0x48,0xce,0x3d,0x02,0x01};
    tlv_t alg;
    if (der_next(&q, qe, &alg) < 0 || alg.tag != 0x30)
        return -1;
    int is_ec = 0;
    {
        const uint8_t *ap = alg.val, *ae = alg.next;
        tlv_t oid;
        if (der_next(&ap, ae, &oid) < 0 || oid.tag != 0x06)
            return -1;
        if (oid.len == sizeof(oid_ec) && !memcmp(oid.val, oid_ec, oid.len))
            is_ec = 1;
    }
    if (is_ec) {
        tlv_t bits;
        if (der_next(&q, qe, &bits) < 0 || bits.tag != 0x03 || bits.len < 1)
            return -1;
        size_t plen = bits.len - 1;
        if (plen > 65)
            return -1;
        memcpy(out->ec_pub, bits.val + 1, plen);
        out->key_type = X509_KEY_ECDSA;
        return 0;
    }
    tlv_t bits;
    if (der_next(&q, qe, &bits) < 0 || bits.tag != 0x03 || bits.len < 1)
        return -1;
    /* BIT STRING: first byte is unused-bit count (0), then RSAPublicKey DER */
    const uint8_t *r = bits.val + 1;
    const uint8_t *re = bits.val + bits.len;
    tlv_t rseq;
    if (der_next(&r, re, &rseq) < 0 || rseq.tag != 0x30)
        return -1;
    const uint8_t *rp = rseq.val, *rpe = rseq.next;
    tlv_t mod, exp;
    if (der_next(&rp, rpe, &mod) < 0 || mod.tag != 0x02)
        return -1;
    if (der_next(&rp, rpe, &exp) < 0 || exp.tag != 0x02)
        return -1;
    const uint8_t *mb = mod.val;
    size_t mlen = mod.len;
    while (mlen > 1 && *mb == 0) { mb++; mlen--; }
    if (mlen > sizeof(out->pub.n))
        return -1;
    memcpy(out->pub.n, mb, mlen);
    out->pub.nlen = mlen;
    const uint8_t *eb = exp.val;
    size_t elen = exp.len;
    while (elen > 1 && *eb == 0) { eb++; elen--; }
    if (elen > sizeof(out->pub.e))
        return -1;
    memcpy(out->pub.e, eb, elen);
    out->pub.elen = elen;
    out->key_type = X509_KEY_RSA;
    return 0;
}

int x509_parse(const uint8_t *der, size_t len, x509_cert_t *out) {
    memset(out, 0, sizeof(*out));
    const uint8_t *p = der, *end = der + len;
    tlv_t cert;
    if (der_next(&p, end, &cert) < 0 || cert.tag != 0x30)
        return -1;
    const uint8_t *cp = cert.val, *ce = cert.next;
    tlv_t tbs, sigalg, sigval;
    const uint8_t *tbs_start = cp;   /* include tag+length for the signature */
    if (der_next(&cp, ce, &tbs) < 0 || tbs.tag != 0x30)
        return -1;
    if (der_next(&cp, ce, &sigalg) < 0 || sigalg.tag != 0x30)
        return -1;
    if (der_next(&cp, ce, &sigval) < 0 || sigval.tag != 0x03 || sigval.len < 1)
        return -1;
    out->tbs = tbs_start;
    out->tbs_len = (size_t)(tbs.next - tbs_start);
    out->sig = sigval.val + 1;   /* skip unused-bits byte */
    out->sig_len = sigval.len - 1;

    /* signature algorithm OID */
    {
        const uint8_t *sp = sigalg.val, *spe = sigalg.next;
        tlv_t oid;
        if (der_next(&sp, spe, &oid) < 0 || oid.tag != 0x06)
            return -1;
        if (sig_alg_parse(oid.val, oid.len, &out->sig_type, &out->sig_hash) < 0)
            return -1;
    }

    /* walk tbs fields */
    const uint8_t *tp = tbs.val, *te = tbs.next;
    tlv_t f;
    /* optional version [0] */
    if (tp < te && *tp == 0xa0) {
        if (der_next(&tp, te, &f) < 0)
        return -1;
    }
    /* serial, signature, issuer, validity, subject */
    for (int i = 0; i < 5; i++) {
        const uint8_t *fs = tp;
        if (der_next(&tp, te, &f) < 0)
            return -1;
        if (i == 2) { out->issuer = fs; out->issuer_len = (size_t)(f.next - fs); }
        if (i == 4) { out->subject = fs; out->subject_len = (size_t)(f.next - fs); }
    }
    /* subjectPublicKeyInfo */
    if (der_next(&tp, te, &f) < 0 || f.tag != 0x30)
        return -1;
    if (parse_spki(f.val, f.next, out) < 0)
        return -1;

    /* optional issuerUniqueID [1], subjectUniqueID [2], extensions [3] */
    while (tp < te) {
        if (der_next(&tp, te, &f) < 0)
            break;
        if (f.tag == 0xa3) {
            /* extensions SEQUENCE */
            const uint8_t *ep = f.val, *ee = f.next;
            tlv_t extseq;
            if (der_next(&ep, ee, &extseq) < 0 || extseq.tag != 0x30)
                break;
            const uint8_t *xp = extseq.val, *xe = extseq.next;
            tlv_t ext;
            while (xp < xe && der_next(&xp, xe, &ext) == 0 && ext.tag == 0x30) {
                const uint8_t *ip = ext.val, *ie = ext.next;
                tlv_t oid, val;
                if (der_next(&ip, ie, &oid) < 0 || oid.tag != 0x06)
                    continue;
                /* skip optional critical BOOLEAN */
                if (ip < ie && *ip == 0x01) {
                    if (der_next(&ip, ie, &val) < 0)
                        continue;
                }
                if (der_next(&ip, ie, &val) < 0 || val.tag != 0x04)
                    continue;
                /* subjectAltName OID 2.5.29.17 = 55 1d 11 */
                if (oid.len == 3 && oid.val[0] == 0x55 && oid.val[1] == 0x1d &&
                    oid.val[2] == 0x11) {
                    out->san = val.val;
                    out->san_len = val.len;
                }
            }
        }
    }
    return 0;
}

int x509_issuer_matches(const x509_cert_t *cert, const x509_cert_t *issuer) {
    return cert->issuer && issuer->subject &&
           cert->issuer_len == issuer->subject_len &&
           memcmp(cert->issuer, issuer->subject, cert->issuer_len) == 0;
}

int x509_verify_signed_by(const x509_cert_t *cert, const x509_cert_t *issuer) {
    uint8_t digest[64];
    switch (cert->sig_hash) {
    case 32: sha256_digest(cert->tbs, cert->tbs_len, digest); break;
    default: return -1;   /* SHA-384/512 not implemented */
    }
    if (cert->sig_type == X509_KEY_ECDSA) {
        if (issuer->key_type != X509_KEY_ECDSA)
            return -1;
        return ecdsa_p256_verify(issuer->ec_pub, sizeof(issuer->ec_pub),
                                 digest, (size_t)cert->sig_hash,
                                 cert->sig, cert->sig_len);
    }
    if (issuer->key_type != X509_KEY_RSA)
        return -1;
    return rsa_pkcs1_verify(&issuer->pub, digest, (size_t)cert->sig_hash,
                            cert->sig, cert->sig_len);
}

/* --------------------------- hostname matching --------------------------- */

static int dns_match(const char *pattern, size_t plen, const char *host) {
    size_t hlen = strlen(host);
    /* wildcard: *.example.com matches one leading label only */
    if (plen >= 2 && pattern[0] == '*' && pattern[1] == '.') {
        const char *dot = strchr(host, '.');
        if (!dot)
            return 0;
        const char *suffix = dot;               /* ".example.com" */
        size_t slen = hlen - (size_t)(suffix - host);
        if (slen != plen - 1)
            return 0;
        return memcmp(suffix, pattern + 1, slen) == 0;
    }
    return plen == hlen && memcmp(pattern, host, hlen) == 0;
}

int x509_check_hostname(const x509_cert_t *cert, const char *host) {
    if (!cert->san || cert->san_len == 0)
        return -1;
    const uint8_t *p = cert->san, *end = cert->san + cert->san_len;
    tlv_t seq;
    if (der_next(&p, end, &seq) < 0 || seq.tag != 0x30)
        return -1;
    const uint8_t *gp = seq.val, *ge = seq.next;
    tlv_t gn;
    while (gp < ge && der_next(&gp, ge, &gn) == 0) {
        /* dNSName ::= [2] IA5String -> tag 0x82 */
        if (gn.tag == 0x82) {
            if (dns_match((const char *)gn.val, gn.len, host))
                return 0;
        }
    }
    return -1;
}

/* ------------------------------- PEM ------------------------------------ */

int x509_pem_first_cert(const char *pem, size_t pem_len,
                        uint8_t *der_buf, size_t der_cap, size_t *der_len) {
    static const char begin[] = "-----BEGIN CERTIFICATE-----";
    static const char endmark[] = "-----END CERTIFICATE-----";
    const char *b = NULL, *e = NULL;
    for (size_t i = 0; i + sizeof(begin) - 1 <= pem_len; i++) {
        if (!memcmp(pem + i, begin, sizeof(begin) - 1)) {
            b = pem + i + sizeof(begin) - 1;
            break;
        }
    }
    if (!b)
        return -1;
    for (const char *q = b; q + sizeof(endmark) - 1 <= pem + pem_len; q++) {
        if (!memcmp(q, endmark, sizeof(endmark) - 1)) {
            e = q;
            break;
        }
    }
    if (!e)
        return -1;
    /* strip whitespace, base64-decode */
    char b64[8192];
    size_t bl = 0;
    for (const char *q = b; q < e && bl < sizeof(b64); q++) {
        char ch = *q;
        if (ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t')
            continue;
        b64[bl++] = ch;
    }
    int n = (int)base64_decode(b64, bl, der_buf, der_cap);
    if (n <= 0)
        return -1;
    *der_len = (size_t)n;
    return 0;
}

/* --------------------------- private key parsing ------------------------- */

static int parse_rsa_priv_seq(const uint8_t *p, const uint8_t *end, rsa_priv_t *out) {
    /* RSAPrivateKey ::= SEQUENCE { version, n, e, d, ... } (p at contents) */
    const uint8_t *q = p, *qe = end;
    tlv_t f;
    for (int i = 0; i < 4; i++) {
        if (der_next(&q, qe, &f) < 0 || f.tag != 0x02)
            return -1;
        if (i == 1) {   /* modulus */
            const uint8_t *b = f.val;
            size_t l = f.len;
            while (l > 1 && *b == 0) { b++; l--; }
            if (l > sizeof(out->n))
                return -1;
            memcpy(out->n, b, l);
            out->nlen = l;
        } else if (i == 3) {   /* privateExponent */
            const uint8_t *b = f.val;
            size_t l = f.len;
            while (l > 1 && *b == 0) { b++; l--; }
            if (l > sizeof(out->d))
                return -1;
            memcpy(out->d, b, l);
            out->dlen = l;
        }
    }
    return out->nlen && out->dlen ? 0 : -1;
}

int x509_parse_private_key(const char *pem, size_t pem_len, rsa_priv_t *out) {
    static const char begin1[] = "-----BEGIN RSA PRIVATE KEY-----";
    static const char begin8[] = "-----BEGIN PRIVATE KEY-----";
    static const char endmark[] = "-----END";
    const char *b = NULL;
    size_t skip = 0;
    for (size_t i = 0; i + sizeof(begin1) - 1 <= pem_len; i++) {
        if (!memcmp(pem + i, begin1, sizeof(begin1) - 1)) {
            b = pem + i + sizeof(begin1) - 1;
            skip = 0;
            break;
        }
        if (!memcmp(pem + i, begin8, sizeof(begin8) - 1)) {
            b = pem + i + sizeof(begin8) - 1;
            skip = 1;   /* PKCS#8 */
            break;
        }
    }
    if (!b)
        return -1;
    const char *e = NULL;
    for (const char *q = b; q + 5 <= pem + pem_len; q++) {
        if (!memcmp(q, endmark, 5)) { e = q; break; }
    }
    if (!e)
        return -1;
    char b64[16384];
    size_t bl = 0;
    for (const char *q = b; q < e && bl < sizeof(b64); q++) {
        char ch = *q;
        if (ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t')
            continue;
        b64[bl++] = ch;
    }
    uint8_t der[12288];
    int n = (int)base64_decode(b64, bl, der, sizeof(der));
    if (n <= 0)
        return -1;
    const uint8_t *p = der, *endp = der + n;
    tlv_t seq;
    if (der_next(&p, endp, &seq) < 0 || seq.tag != 0x30)
        return -1;
    if (skip) {
        /* PKCS#8: version INTEGER, AlgorithmIdentifier SEQUENCE, OCTET STRING */
        const uint8_t *q = seq.val, *qe = seq.next;
        tlv_t f;
        if (der_next(&q, qe, &f) < 0 || f.tag != 0x02)
            return -1;
        if (der_next(&q, qe, &f) < 0 || f.tag != 0x30)
            return -1;
        if (der_next(&q, qe, &f) < 0 || f.tag != 0x04)
            return -1;
        const uint8_t *r = f.val, *re = f.next;
        tlv_t inner;
        if (der_next(&r, re, &inner) < 0 || inner.tag != 0x30)
            return -1;
        return parse_rsa_priv_seq(inner.val, inner.next, out);
    }
    return parse_rsa_priv_seq(seq.val, seq.next, out);
}

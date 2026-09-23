/*
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef TFRPC_X509_H
#define TFRPC_X509_H

#include <stdint.h>
#include <stddef.h>
#include "bignum.h"

#define X509_KEY_RSA 0
#define X509_KEY_ECDSA 1

typedef struct {
    const uint8_t *tbs;      /* raw tbsCertificate (for signature) */
    size_t tbs_len;
    const uint8_t *sig;      /* signatureValue */
    size_t sig_len;
    int sig_type;            /* X509_KEY_RSA / X509_KEY_ECDSA */
    int sig_hash;            /* 32/48/64 = SHA-256/384/512 */
    int key_type;
    rsa_pub_t pub;           /* when key_type == RSA */
    uint8_t ec_pub[65];      /* uncompressed point when key_type == ECDSA */
    const uint8_t *san;      /* raw SubjectAltName extension value (SEQUENCE) */
    size_t san_len;
    const uint8_t *issuer;   /* raw issuer Name (for chain matching) */
    size_t issuer_len;
    const uint8_t *subject;  /* raw subject Name */
    size_t subject_len;
} x509_cert_t;

/* parse one DER certificate */
int x509_parse(const uint8_t *der, size_t len, x509_cert_t *out);

/* verify cert's signature using issuer certificate's public key */
int x509_verify_signed_by(const x509_cert_t *cert, const x509_cert_t *issuer);
/* true when cert.issuer == issuer.subject (raw DER compare) */
int x509_issuer_matches(const x509_cert_t *cert, const x509_cert_t *issuer);

/* check that cert matches hostname (SAN dNSName, wildcard aware) */
int x509_check_hostname(const x509_cert_t *cert, const char *host);

/* extract the first certificate from a PEM bundle into der_buf */
int x509_pem_first_cert(const char *pem, size_t pem_len,
                        uint8_t *der_buf, size_t der_cap, size_t *der_len);

/* parse an RSA private key (PKCS#1 or PKCS#8 PEM) */
int x509_parse_private_key(const char *pem, size_t pem_len, rsa_priv_t *out);

#endif

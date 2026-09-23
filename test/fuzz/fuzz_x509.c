/*
 * SPDX-License-Identifier: GPL-3.0-only
 * fuzz_x509.c - libFuzzer harness for the DER/X.509 certificate parser and
 * chain validation.  The input is a certificate DER; a self-signed CA is
 * embedded so that parse -> verify -> hostname -> issuer-match paths all run.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined -O1 -g -std=c11 -Iinclude \
 *       -o x509_fuzzer test/fuzz/fuzz_x509.c src/x509.c src/ecdsa.c \
 *       src/bignum.c src/crypto.c src/log.c src/net.c src/base64.c -pthread
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "tfrpc.h"
#include "x509.h"

#include "fzca_der.h"
#include "fzca_ec_der.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8 || size > 65536)
        return 0;

    x509_cert_t leaf;
    memset(&leaf, 0, sizeof(leaf));
    if (x509_parse(data, size, &leaf) == 0) {
        x509_cert_t ca;
        memset(&ca, 0, sizeof(ca));
        if (x509_parse(g_fuzz_ca_der, g_fuzz_ca_der_len, &ca) == 0) {
            (void)x509_verify_signed_by(&leaf, &ca);
            (void)x509_issuer_matches(&leaf, &ca);
        }
        if (x509_parse(g_fuzz_ca_ec_der, g_fuzz_ca_ec_der_len, &ca) == 0) {
            (void)x509_verify_signed_by(&leaf, &ca);
            (void)x509_issuer_matches(&leaf, &ca);
        }
        (void)x509_check_hostname(&leaf, "fuzz.local");
        (void)x509_check_hostname(&leaf, "*.local");
        (void)x509_check_hostname(&leaf, "");
    }
    return 0;
}

/*
 * SPDX-License-Identifier: GPL-3.0-only
 * fuzz_pem.c - libFuzzer harness for the PEM certificate/private-key loaders
 * (the paths used by trustedCaFile / certFile / keyFile).
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined -O1 -g -std=c11 -Iinclude \
 *       -o pem_fuzzer test/fuzz/fuzz_pem.c src/x509.c src/ecdsa.c \
 *       src/bignum.c src/crypto.c src/log.c src/net.c src/base64.c -pthread
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "tfrpc.h"
#include "x509.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16 || size > 65536)
        return 0;

    char *pem = malloc(size + 1);
    if (!pem)
        return 0;
    memcpy(pem, data, size);
    pem[size] = '\0';

    uint8_t der[8192];
    size_t dlen = 0;
    if (x509_pem_first_cert(pem, size, der, sizeof(der), &dlen) == 0 && dlen > 0) {
        x509_cert_t c;
        memset(&c, 0, sizeof(c));
        (void)x509_parse(der, dlen, &c);
    }

    rsa_priv_t key;
    memset(&key, 0, sizeof(key));
    (void)x509_parse_private_key(pem, size, &key);

    free(pem);
    return 0;
}

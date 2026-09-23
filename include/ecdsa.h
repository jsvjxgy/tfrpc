/*
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef TFRPC_ECDSA_H
#define TFRPC_ECDSA_H

#include <stdint.h>
#include <stddef.h>
#include "bignum.h"

/* Verify an ECDSA P-256 signature. pub is an uncompressed point (65 bytes,
 * 0x04 || X || Y); hash is the 32-byte digest; sig is a DER SEQUENCE. */
int ecdsa_p256_verify(const uint8_t *pub, size_t pub_len,
                      const uint8_t *hash, size_t hash_len,
                      const uint8_t *sig, size_t sig_len);

#endif

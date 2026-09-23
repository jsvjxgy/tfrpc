/*
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef TFRPC_X25519_H
#define TFRPC_X25519_H

#include <stdint.h>

/* X25519 scalar multiplication (RFC 7748) */
void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
/* base point 9 multiplication */
void x25519_base(uint8_t out[32], const uint8_t scalar[32]);

#endif

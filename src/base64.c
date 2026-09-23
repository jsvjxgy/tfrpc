/*
 * SPDX-License-Identifier: GPL-3.0-only
 * base64.c - RFC 4648 base64, used to carry UDP packet content in v1 JSON.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "tfrpc.h"

static const char b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64_encode(const uint8_t *in, size_t in_len, char *out) {
    size_t i, o = 0;
    size_t enc_len = ((in_len + 2) / 3) * 4;
    if (!out)
        return enc_len;
    for (i = 0; i + 2 < in_len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = b64chars[(v >> 18) & 0x3f];
        out[o++] = b64chars[(v >> 12) & 0x3f];
        out[o++] = b64chars[(v >> 6) & 0x3f];
        out[o++] = b64chars[v & 0x3f];
    }
    if (in_len % 3 == 1) {
        uint32_t v = (uint32_t)in[in_len - 1] << 16;
        out[o++] = b64chars[(v >> 18) & 0x3f];
        out[o++] = b64chars[(v >> 12) & 0x3f];
        out[o++] = '=';
        out[o++] = '=';
    } else if (in_len % 3 == 2) {
        uint32_t v = ((uint32_t)in[in_len - 2] << 16) | ((uint32_t)in[in_len - 1] << 8);
        out[o++] = b64chars[(v >> 18) & 0x3f];
        out[o++] = b64chars[(v >> 12) & 0x3f];
        out[o++] = b64chars[(v >> 6) & 0x3f];
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

size_t base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap) {
    size_t i, o = 0;
    uint32_t acc = 0;
    int nbits = 0;
    for (i = 0; i < in_len; i++) {
        if (in[i] == '=' || in[i] == '\0')
            break;
        int v = b64val(in[i]);
        if (v < 0)
            break;
        acc = (acc << 6) | (uint32_t)v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (o >= out_cap)
                break;   /* never write past the caller's buffer */
            out[o++] = (uint8_t)((acc >> nbits) & 0xff);
        }
    }
    return o;
}
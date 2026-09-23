/*
 * SPDX-License-Identifier: GPL-3.0-only
 * snappy.c - snappy framed-stream codec (compress + decompress), byte
 * compatible with github.com/golang/snappy v0.0.4 as used by frp for the
 * per-proxy `useCompression` option.
 *
 * Stream layout (Google snappy framing format):
 *   stream identifier chunk: ff 06 00 00 "sNaPpY"
 *   data chunk: [1B type][3B little-endian length][length bytes]
 *     type 0x00 compressed   : [4B CRC32C of plain][snappy block]
 *     type 0x01 uncompressed : [4B CRC32C of plain][raw bytes]
 *   the length counts the 4 CRC bytes plus the payload.
 *
 * Block layout: varint(plain length) followed by literal/copy tags.
 */

#include <stdlib.h>
#include <string.h>
#include "snappy.h"

#define SN_BLOCK_MAX 65536
#define SN_HT_BITS 14
#define SN_HT_SIZE (1 << SN_HT_BITS)
#define SN_CHUNK_MAX (SN_BLOCK_MAX + SN_BLOCK_MAX / 6 + 64)

/* ------------------------------- CRC32C ------------------------------- */

static uint32_t crc_table[256];
static int crc_ready = 0;

uint32_t crc32c(const uint8_t *data, size_t len) {
    if (!crc_ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? (0x82F63B78u ^ (c >> 1)) : (c >> 1);
            crc_table[i] = c;
        }
        crc_ready = 1;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        c = crc_table[(c ^ data[i]) & 0xff] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* snappy frames store the CRC32C masked (framing-format spec) */
static uint32_t crc32c_mask(uint32_t crc) {
    return ((crc >> 15) | (crc << 17)) + 0xa282ead8u;
}

static uint32_t crc32c_unmask(uint32_t m) {
    m -= 0xa282ead8u;
    return (m >> 17) | (m << 15);
}

/* ---------------------------- block decode ---------------------------- */

/* decode a snappy block into dst (capacity dcap); returns plain length or -1 */
static int sn_block_decode(const uint8_t *src, size_t slen, uint8_t *dst, size_t dcap) {
    size_t ip = 0, op = 0;
    uint32_t dlen = 0;
    int shift = 0;

    for (;;) {
        if (ip >= slen || shift > 28)
            return -1;
        uint8_t b = src[ip++];
        dlen |= (uint32_t)(b & 0x7f) << shift;
        if (!(b & 0x80))
            break;
        shift += 7;
    }
    if (dlen > dcap)
        return -1;

    while (op < dlen) {
        if (ip >= slen)
            return -1;
        uint8_t tag = src[ip++];
        int t = tag & 3;
        if (t == 0) {
            /* literal */
            uint32_t len = tag >> 2;
            if (len >= 60) {
                int n = (int)len - 59;   /* 1..4 extra bytes */
                len = 0;
                if (ip + (size_t)n > slen)
                    return -1;
                for (int k = 0; k < n; k++)
                    len |= (uint32_t)src[ip++] << (8 * k);
            }
            len += 1;
            if (ip + len > slen || op + len > dlen)
                return -1;
            memcpy(dst + op, src + ip, len);
            ip += len;
            op += len;
        } else {
            uint32_t len, offset;
            if (t == 1) {
                len = ((tag >> 2) & 7) + 4;
                if (ip >= slen)
                    return -1;
                offset = ((uint32_t)(tag >> 5) << 8) | src[ip++];
            } else if (t == 2) {
                len = (tag >> 2) + 1;
                if (ip + 2 > slen)
                    return -1;
                offset = (uint32_t)src[ip] | ((uint32_t)src[ip + 1] << 8);
                ip += 2;
            } else {
                len = (tag >> 2) + 1;
                if (ip + 4 > slen)
                    return -1;
                offset = (uint32_t)src[ip] | ((uint32_t)src[ip + 1] << 8) |
                         ((uint32_t)src[ip + 2] << 16) | ((uint32_t)src[ip + 3] << 24);
                ip += 4;
            }
            if (offset == 0 || offset > op || op + len > dlen)
                return -1;
            /* overlapping copies are byte-wise (RLE) */
            for (uint32_t k = 0; k < len; k++)
                dst[op + k] = dst[op - offset + k];
            op += len;
        }
    }
    return op == dlen ? (int)dlen : -1;
}

/* ---------------------------- block encode ---------------------------- */

typedef struct {
    uint32_t *ht;      /* SN_HT_SIZE entries, position+1 (0 = empty) */
} sn_enc_ctx;

static sn_enc_ctx *sn_enc_new(void) {
    sn_enc_ctx *e = calloc(1, sizeof(*e));
    if (e)
        e->ht = calloc(SN_HT_SIZE, sizeof(uint32_t));
    if (e && !e->ht) {
        free(e);
        e = NULL;
    }
    return e;
}

static void sn_enc_free(sn_enc_ctx *e) {
    if (e) {
        free(e->ht);
        free(e);
    }
}

static inline uint32_t sn_load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline uint32_t sn_hash(uint32_t v) {
    return (v * 0x1e35a7bdu) >> (32 - SN_HT_BITS);
}

static void sn_emit_literal(uint8_t *dst, size_t *op, const uint8_t *lit, size_t len) {
    if (len == 0)
        return;
    size_t n = len - 1;
    if (n < 60) {
        dst[(*op)++] = (uint8_t)(n << 2);
    } else {
        int bytes = 0;
        size_t t = n;
        while (t > 0) {
            bytes++;
            t >>= 8;
        }
        dst[(*op)++] = (uint8_t)((59 + bytes) << 2);
        t = n;
        for (int k = 0; k < bytes; k++) {
            dst[(*op)++] = (uint8_t)t;
            t >>= 8;
        }
    }
    memcpy(dst + *op, lit, len);
    *op += len;
}

static void sn_emit_copy(uint8_t *dst, size_t *op, size_t offset, size_t len) {
    while (len > 0) {
        size_t n = len > 64 ? 64 : len;
        if (offset < 2048 && n >= 4 && n <= 11) {
            dst[(*op)++] = (uint8_t)(0x01 | ((n - 4) << 2) | ((offset >> 8) << 5));
            dst[(*op)++] = (uint8_t)(offset & 0xff);
        } else if (offset < 65536) {
            dst[(*op)++] = (uint8_t)(0x02 | ((n - 1) << 2));
            dst[(*op)++] = (uint8_t)(offset & 0xff);
            dst[(*op)++] = (uint8_t)((offset >> 8) & 0xff);
        } else {
            dst[(*op)++] = (uint8_t)(0x03 | ((n - 1) << 2));
            dst[(*op)++] = (uint8_t)(offset & 0xff);
            dst[(*op)++] = (uint8_t)((offset >> 8) & 0xff);
            dst[(*op)++] = (uint8_t)((offset >> 16) & 0xff);
            dst[(*op)++] = (uint8_t)((offset >> 24) & 0xff);
        }
        len -= n;
    }
}

/* encode a block; dst capacity must be >= 32 + slen + slen/6 */
static int sn_block_encode(sn_enc_ctx *e, const uint8_t *src, size_t slen,
                           uint8_t *dst, size_t dcap) {
    size_t op = 0;

    /* varint plain length */
    {
        size_t n = slen;
        while (n >= 0x80) {
            if (op >= dcap)
                return -1;
            dst[op++] = (uint8_t)((n & 0x7f) | 0x80);
            n >>= 7;
        }
        if (op >= dcap)
            return -1;
        dst[op++] = (uint8_t)n;
    }

    if (slen < 4) {
        if (op + slen + 1 > dcap)
            return -1;
        sn_emit_literal(dst, &op, src, slen);
        return (int)op;
    }

    memset(e->ht, 0, SN_HT_SIZE * sizeof(uint32_t));
    size_t i = 0, lit_start = 0;
    while (i + 4 <= slen) {
        uint32_t v = sn_load32(src + i);
        uint32_t h = sn_hash(v);
        uint32_t cand = e->ht[h];
        e->ht[h] = (uint32_t)(i + 1);
        if (cand != 0) {
            size_t j = cand - 1;
            if (j < i && sn_load32(src + j) == v) {
                size_t mlen = 4;
                while (i + mlen < slen && src[j + mlen] == src[i + mlen])
                    mlen++;
                if (op + (i - lit_start) + 8 + (i - lit_start) / 60 > dcap)
                    return -1;
                sn_emit_literal(dst, &op, src + lit_start, i - lit_start);
                sn_emit_copy(dst, &op, i - j, mlen);
                i += mlen;
                lit_start = i;
                continue;
            }
        }
        i++;
    }
    if (op + (slen - lit_start) + 8 + (slen - lit_start) / 60 > dcap)
        return -1;
    sn_emit_literal(dst, &op, src + lit_start, slen - lit_start);
    return (int)op;
}

/* ------------------------------ writer ------------------------------- */

struct snappy_writer {
    int magic_written;
    snappy_out_fn out;
    void *out_ctx;
    uint8_t *enc;
    size_t enc_cap;
    sn_enc_ctx *enc_ctx;
};

snappy_writer_t *snappy_writer_new(snappy_out_fn out, void *ctx) {
    snappy_writer_t *w = calloc(1, sizeof(*w));
    if (!w)
        return NULL;
    w->out = out;
    w->out_ctx = ctx;
    w->enc_ctx = sn_enc_new();
    if (!w->enc_ctx) {
        free(w);
        return NULL;
    }
    return w;
}

void snappy_writer_free(snappy_writer_t *w) {
    if (!w)
        return;
    sn_enc_free(w->enc_ctx);
    free(w->enc);
    free(w);
}

static int sn_write_magic(snappy_writer_t *w) {
    static const uint8_t magic[10] = {0xff, 0x06, 0x00, 0x00, 's', 'N', 'a', 'P', 'p', 'Y'};
    if (w->magic_written)
        return 0;
    if (w->out(w->out_ctx, magic, sizeof(magic)) < 0)
        return -1;
    w->magic_written = 1;
    return 0;
}

static int sn_emit_chunk(snappy_writer_t *w, const uint8_t *src, size_t blen) {
    if (blen == 0)
        return 0;
    size_t need = 32 + blen + blen / 6;
    if (w->enc_cap < need) {
        uint8_t *nb = realloc(w->enc, need);
        if (!nb)
            return -1;
        w->enc = nb;
        w->enc_cap = need;
    }
    int clen = sn_block_encode(w->enc_ctx, src, blen, w->enc, w->enc_cap);
    if (clen < 0)
        return -1;
    uint32_t crc = crc32c_mask(crc32c(src, blen));
    uint8_t hdr[8];
    uint32_t chunk_len;
    if ((size_t)clen < blen) {
        chunk_len = (uint32_t)clen + 4;
        hdr[0] = 0x00;
    } else {
        chunk_len = (uint32_t)blen + 4;
        hdr[0] = 0x01;
    }
    hdr[1] = (uint8_t)(chunk_len & 0xff);
    hdr[2] = (uint8_t)((chunk_len >> 8) & 0xff);
    hdr[3] = (uint8_t)((chunk_len >> 16) & 0xff);
    hdr[4] = (uint8_t)(crc & 0xff);
    hdr[5] = (uint8_t)((crc >> 8) & 0xff);
    hdr[6] = (uint8_t)((crc >> 16) & 0xff);
    hdr[7] = (uint8_t)((crc >> 24) & 0xff);
    if (w->out(w->out_ctx, hdr, 8) < 0)
        return -1;
    const uint8_t *payload = hdr[0] == 0x00 ? w->enc : src;
    size_t plen = hdr[0] == 0x00 ? (size_t)clen : blen;
    if (w->out(w->out_ctx, payload, plen) < 0)
        return -1;
    return 0;
}

int snappy_writer_write(snappy_writer_t *w, const uint8_t *data, size_t len) {
    if (sn_write_magic(w) < 0)
        return -1;
    /* like golang/snappy's NewWriter: do not buffer, emit each write at once */
    while (len > 0) {
        size_t n = len > SN_BLOCK_MAX ? SN_BLOCK_MAX : len;
        if (sn_emit_chunk(w, data, n) < 0)
            return -1;
        data += n;
        len -= n;
    }
    return 0;
}

int snappy_writer_flush(snappy_writer_t *w) {
    return sn_write_magic(w);
}

/* ------------------------------ reader ------------------------------- */

struct snappy_reader {
    uint8_t buf[SN_BLOCK_MAX];
    size_t buf_len;
    size_t buf_pos;
    snappy_in_fn in;
    void *in_ctx;
    uint8_t *chunk;
    size_t chunk_cap;
    int eof;
};

snappy_reader_t *snappy_reader_new(snappy_in_fn in, void *ctx) {
    snappy_reader_t *r = calloc(1, sizeof(*r));
    if (!r)
        return NULL;
    r->in = in;
    r->in_ctx = ctx;
    return r;
}

void snappy_reader_free(snappy_reader_t *r) {
    if (!r)
        return;
    free(r->chunk);
    free(r);
}

static int sn_read_chunk(snappy_reader_t *r) {
    uint8_t hdr[4];
    if (r->in(r->in_ctx, hdr, 4) < 0) {
        r->eof = 1;
        return -1;
    }
    uint8_t type = hdr[0];
    uint32_t clen = (uint32_t)hdr[1] | ((uint32_t)hdr[2] << 8) | ((uint32_t)hdr[3] << 16);
    if (clen > SN_CHUNK_MAX)
        return -1;
    if (r->chunk_cap < clen) {
        uint8_t *nb = realloc(r->chunk, clen);
        if (!nb)
            return -1;
        r->chunk = nb;
        r->chunk_cap = clen;
    }
    if (clen > 0 && r->in(r->in_ctx, r->chunk, clen) < 0)
        return -1;

    if (type == 0x00 || type == 0x01) {
        if (clen < 4)
            return -1;
        uint32_t crc = (uint32_t)r->chunk[0] | ((uint32_t)r->chunk[1] << 8) |
                       ((uint32_t)r->chunk[2] << 16) | ((uint32_t)r->chunk[3] << 24);
        size_t dlen;
        if (type == 0x00) {
            int n = sn_block_decode(r->chunk + 4, clen - 4, r->buf, sizeof(r->buf));
            if (n < 0)
                return -1;
            dlen = (size_t)n;
        } else {
            dlen = clen - 4;
            if (dlen > sizeof(r->buf))
                return -1;
            memcpy(r->buf, r->chunk + 4, dlen);
        }
        if (crc32c(r->buf, dlen) != crc32c_unmask(crc))
            return -1;
        r->buf_len = dlen;
        r->buf_pos = 0;
        return dlen > 0 ? 1 : 0;
    }
    /* stream identifier (0xff) or skippable (0x80..0xfe): ignore and continue */
    if (type == 0xff || type >= 0x80)
        return 0;
    return -1;   /* reserved unskippable */
}

int snappy_reader_read(snappy_reader_t *r, uint8_t *out, size_t len) {
    for (;;) {
        if (r->buf_pos < r->buf_len) {
            size_t avail = r->buf_len - r->buf_pos;
            size_t n = len < avail ? len : avail;
            memcpy(out, r->buf + r->buf_pos, n);
            r->buf_pos += n;
            return (int)n;
        }
        if (r->eof)
            return 0;
        int rc = sn_read_chunk(r);
        if (rc < 0)
            return r->eof ? 0 : -1;
    }
}

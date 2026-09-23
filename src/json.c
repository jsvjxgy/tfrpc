/*
 * SPDX-License-Identifier: GPL-3.0-only
 * json.c - minimal JSON builder/parser tailored to frp v1 control messages.
 *
 * The wire messages have a small, fixed set of shapes, so we avoid a full
 * JSON library: build with jbuf_* helpers, parse with jget_* helpers.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "tfrpc.h"

static void jbuf_reserve(json_buf_t *b, size_t extra) {
    if (b->len + extra + 1 > b->cap) {
        size_t ncap = (b->cap == 0) ? 256 : b->cap * 2;
        while (ncap < b->len + extra + 1)
            ncap *= 2;
        char *nb = realloc(b->buf, ncap);
        if (!nb)
            return;   /* out of memory: leave the buffer unchanged */
        b->buf = nb;
        b->cap = ncap;
    }
}

static void jbuf_append(json_buf_t *b, const char *s, size_t n) {
    jbuf_reserve(b, n);
    if (b->len + n + 1 > b->cap)
        return;       /* out of memory: drop the append */
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    b->buf[b->len] = '\0';
}

void jbuf_init(json_buf_t *b) {
    memset(b, 0, sizeof(*b));
}

void jbuf_free(json_buf_t *b) {
    free(b->buf);
    b->buf = NULL;
    b->len = b->cap = 0;
}

void jbuf_open(json_buf_t *b) {
    jbuf_append(b, "{", 1);
    b->comma = 0;
}

void jbuf_close(json_buf_t *b) {
    jbuf_append(b, "}", 1);
}

/* internal: emit a key and comma handling, then the value follows */
void jbuf_append_raw(json_buf_t *b, const char *s, size_t n) {
    jbuf_append(b, s, n);
}

void jbuf_add_key(json_buf_t *b, const char *key) {
    if (b->comma)
        jbuf_append(b, ",", 1);
    jbuf_append(b, "\"", 1);
    jbuf_append(b, key, strlen(key));
    jbuf_append(b, "\":", 2);
    b->comma = 1;
}

void json_escape_str(json_buf_t *b, const char *val) {
    const unsigned char *p = (const unsigned char *)val;
    jbuf_append(b, "\"", 1);
    while (*p) {
        if (*p == '"' || *p == '\\') {
            char esc[2] = {'\\', (char)*p};
            jbuf_append(b, esc, 2);
        } else if (*p < 0x20) {
            char esc[8];
            snprintf(esc, sizeof(esc), "\\u%04x", *p);
            jbuf_append(b, esc, 6);
        } else {
            jbuf_append(b, (const char *)p, 1);
        }
        p++;
    }
    jbuf_append(b, "\"", 1);
}

void jbuf_add_str(json_buf_t *b, const char *key, const char *val) {
    jbuf_add_key(b, key);
    json_escape_str(b, val);
}

void jbuf_add_int(json_buf_t *b, const char *key, int64_t val) {
    char num[32];
    jbuf_add_key(b, key);
    snprintf(num, sizeof(num), "%lld", (long long)val);
    jbuf_append(b, num, strlen(num));
}

void jbuf_add_bool(json_buf_t *b, const char *key, bool val) {
    jbuf_add_key(b, key);
    jbuf_append(b, val ? "true" : "false", val ? 4 : 5);
}

void jbuf_add_base64(json_buf_t *b, const char *key, const uint8_t *data, size_t len) {
    char *enc;
    jbuf_add_key(b, key);
    enc = malloc(base64_encode(NULL, 0, NULL) + len * 4 / 3 + 4);
    if (!enc)
        return;   /* out of memory: emit the key with no value */
    base64_encode(data, len, enc);
    json_escape_str(b, enc);
    free(enc);
}

void jbuf_add_udpaddr(json_buf_t *b, const char *key, const char *ip, int port) {
    jbuf_add_key(b, key);
    jbuf_append(b, "{\"IP\":", 6);
    json_escape_str(b, ip);
    jbuf_append(b, ",\"Port\":", 8);
    {
        char num[16];
        snprintf(num, sizeof(num), "%d", port);
        jbuf_append(b, num, strlen(num));
    }
    jbuf_append(b, "}", 1);
}

/* ------------------------- parsing ------------------------- */

/* returns pointer just after `"key":` + whitespace, or NULL */
static const char *json_find(const char *json, const char *key) {
    const char *p = json;
    size_t klen = strlen(key);
    while ((p = strstr(p, "\"")) != NULL) {
        p++; /* skip opening quote */
        if (strncmp(p, key, klen) == 0 && p[klen] == '"') {
            p += klen + 1;
            /* skip to ':' */
            while (*p && *p != ':')
                p++;
            if (*p == ':')
                p++;
            while (*p && isspace((unsigned char)*p))
                p++;
            return p;
        }
        /* skip to end of this string */
        p = strchr(p, '"');
        if (!p)
            return NULL;
        p++;
    }
    return NULL;
}

static int json_parse_string(const char *s, char *out, size_t out_len) {
    size_t o = 0;
    if (*s != '"')
        return 0;
    s++;
    while (*s && *s != '"' && o + 1 < out_len) {
        if (*s == '\\') {
            s++;
            if (!*s)
                break;   /* trailing backslash at end of input */
            switch (*s) {
            case '"': out[o++] = '"'; break;
            case '\\': out[o++] = '\\'; break;
            case '/': out[o++] = '/'; break;
            case 'n': out[o++] = '\n'; break;
            case 'r': out[o++] = '\r'; break;
            case 't': out[o++] = '\t'; break;
            case 'b': out[o++] = '\b'; break;
            case 'f': out[o++] = '\f'; break;
            case 'u': {
                unsigned int u = 0;
                int i;
                for (i = 0; i < 4 && s[1 + i]; i++) {
                    char c = s[1 + i];
                    u <<= 4;
                    if (c >= '0' && c <= '9') u |= c - '0';
                    else if (c >= 'a' && c <= 'f') u |= c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F') u |= c - 'A' + 10;
                }
                s += i;   /* only skip what was actually consumed */
                if (i < 4)
                    break;   /* truncated escape: stop parsing */
                if (u < 0x80) {
                    out[o++] = (char)u;
                } else if (u < 0x800) {
                    if (o + 2 >= out_len)
                        break;
                    out[o++] = (char)(0xC0 | (u >> 6));
                    out[o++] = (char)(0x80 | (u & 0x3F));
                } else {
                    if (o + 3 >= out_len)
                        break;
                    out[o++] = (char)(0xE0 | (u >> 12));
                    out[o++] = (char)(0x80 | ((u >> 6) & 0x3F));
                    out[o++] = (char)(0x80 | (u & 0x3F));
                }
                break;
            }
            default: out[o++] = *s; break;
            }
            s++;
        } else {
            out[o++] = *s++;
        }
    }
    out[o] = '\0';
    return 1;
}

int jget_str(const char *json, const char *key, char *out, size_t out_len) {
    const char *v = json_find(json, key);
    if (!v)
        return 0;
    return json_parse_string(v, out, out_len);
}

int jget_int(const char *json, const char *key, int64_t *out) {
    const char *v = json_find(json, key);
    char *end;
    if (!v)
        return 0;
    if (*v == '"') /* tolerate quoted numbers */
        v++;
    *out = strtoll(v, &end, 10);
    return end != v;
}

int jget_bool(const char *json, const char *key, bool *out) {
    const char *v = json_find(json, key);
    if (!v)
        return 0;
    if (strncmp(v, "true", 4) == 0) { *out = true; return 1; }
    if (strncmp(v, "false", 5) == 0) { *out = false; return 1; }
    return 0;
}

int jget_base64(const char *json, const char *key, uint8_t *out, size_t out_cap,
                size_t *out_len) {
    const char *v = json_find(json, key);
    size_t len;
    size_t n;
    if (!v || *v != '"')
        return 0;
    v++;
    len = strcspn(v, "\"");
    n = base64_decode(v, len, out, out_cap);
    if (out_len)
        *out_len = n;
    return 1;
}

/* parse `{"IP":"1.2.3.4","Port":123,...}` value at key */
int jget_udpaddr(const char *json, const char *key, char *ip, size_t ip_len, int *port) {
    const char *v = json_find(json, key);
    int64_t p;
    if (!v || *v != '{')
        return 0;
    if (!jget_str(v, "IP", ip, ip_len))
        return 0;
    if (!jget_int(v, "Port", &p))
        return 0;
    *port = (int)p;
    return 1;
}
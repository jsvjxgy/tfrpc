/*
 * SPDX-License-Identifier: GPL-3.0-only
 * config.c - parse a TOML config file subset used by tfrpc.
 *
 * Supports the subset of frp's TOML format:
 *   key = "value"
 *   key = 123
 *   key = true
 *   key.sub = "value"
 *   [[proxies]] ... [proxies.transport] ... [proxies.auth]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "tfrpc.h"

tfrpc_config_t g_cfg;

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s))
        s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1]))
        *--e = '\0';
    return s;
}

static char *trim_quotes(char *s) {
    size_t len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len - 1] == '"') {
        s[len - 1] = '\0';
        return s + 1;
    }
    return s;
}

/* returns -1 on error */
static int parse_toml(const char *path) {
    FILE *f = fopen(path, "r");
    char line[1024];
    int in_proxies = 0;
    int cur_proxy = -1;
    char section[128] = "";

    if (!f) {
        log_msg(LOG_ERROR, "cannot open config file: %s", path);
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        char *p, *eq, *key, *val;
        p = trim(line);
        if (*p == '\0' || *p == '#')
            continue;

        if (*p == '[') {
            if (p[1] == '[') {
                /* [[proxies]] table array */
                char *end = strstr(p + 2, "]]");
                if (!end)
                    continue;
                *end = '\0';
                snprintf(section, sizeof(section), "%s", trim(p + 2));
            } else {
                char *end = strrchr(p, ']');
                if (!end)
                    continue;
                *end = '\0';
                snprintf(section, sizeof(section), "%s", trim(p + 1));
            }
            if (strcmp(section, "proxies") == 0) {
                /* [[proxies]] */
                in_proxies = 1;
                if (g_cfg.proxy_count >= MAX_PROXIES) {
                    log_msg(LOG_ERROR, "too many proxies (max %d)", MAX_PROXIES);
                    fclose(f);
                    return -1;
                }
                cur_proxy = g_cfg.proxy_count;
                memset(&g_cfg.proxies[cur_proxy], 0, sizeof(proxy_cfg_t));
                /* tfrpc defaults to full encryption for every proxy */
                g_cfg.proxies[cur_proxy].use_encryption = true;
                g_cfg.proxy_count++;
            } else if (strncmp(section, "proxies.", 8) == 0) {
                /* proxy sub-section like [proxies.transport] -- keep context */
            } else {
                /* any other table ([auth], [transport], ...) leaves the
                   [[proxies]] context so its keys are parsed as top-level */
                in_proxies = 0;
                cur_proxy = -1;
            }
            continue;
        }

        eq = strchr(p, '=');
        if (!eq)
            continue;
        *eq = '\0';
        key = trim(p);
        val = trim(eq + 1);

        if (in_proxies && cur_proxy >= 0) {
            proxy_cfg_t *pxy = &g_cfg.proxies[cur_proxy];
            /* within [[proxies]] block */
            if (strncmp(section, "proxies.transport", 17) == 0) {
                if (strcmp(key, "useEncryption") == 0)
                    pxy->use_encryption = strcmp(val, "true") == 0;
                else if (strcmp(key, "useCompression") == 0)
                    pxy->use_compression = strcmp(val, "true") == 0;
            } else if (strcmp(key, "name") == 0) {
                snprintf(pxy->name, sizeof(pxy->name), "%s", trim_quotes(val));
            } else if (strcmp(key, "type") == 0) {
                char *t = trim_quotes(val);
                if (strcmp(t, "tcp") == 0) pxy->type = PROXY_TCP;
                else if (strcmp(t, "udp") == 0) pxy->type = PROXY_UDP;
                else if (strcmp(t, "http") == 0) pxy->type = PROXY_HTTP;
                else if (strcmp(t, "https") == 0) pxy->type = PROXY_HTTPS;
                else {
                    log_msg(LOG_ERROR, "unsupported proxy type: %s", t);
                    fclose(f);
                    return -1;
                }
            } else if (strcmp(key, "localIP") == 0) {
                snprintf(pxy->local_ip, sizeof(pxy->local_ip), "%s", trim_quotes(val));
            } else if (strcmp(key, "localPort") == 0) {
                pxy->local_port = atoi(val);
            } else if (strcmp(key, "remotePort") == 0) {
                pxy->remote_port = atoi(val);
            } else if (strcmp(key, "customDomains") == 0) {
                /* parse array: ["a","b"] */
                char *q = val, *d;
                while ((q = strchr(q, '"')) != NULL) {
                    q++;
                    d = strchr(q, '"');
                    if (!d)
                        break;
                    *d = '\0';
                    if (pxy->custom_domains_count < 8)
                        snprintf(pxy->custom_domains[pxy->custom_domains_count++],
                                 sizeof(pxy->custom_domains[0]), "%s", q);
                    q = d + 1;
                }
            }
            continue;
        }

        /* top-level keys, possibly dotted like transport.tcpMux / auth.token */
        if (strcmp(key, "serverAddr") == 0) {
            snprintf(g_cfg.server_addr, sizeof(g_cfg.server_addr), "%s", trim_quotes(val));
        } else if (strcmp(key, "serverPort") == 0) {
            g_cfg.server_port = atoi(val);
        } else if (strcmp(key, "user") == 0) {
            snprintf(g_cfg.user, sizeof(g_cfg.user), "%s", trim_quotes(val));
        } else if (strcmp(key, "loginFailExit") == 0) {
            g_cfg.login_fail_exit = strcmp(val, "false") != 0;
        } else if (strcmp(key, "token") == 0 && strcmp(section, "auth") == 0) {
            snprintf(g_cfg.token, sizeof(g_cfg.token), "%s", trim_quotes(val));
        } else if (strncmp(key, "transport.", 10) == 0) {
            const char *sub = key + 10;
            if (strcmp(sub, "tcpMux") == 0)
                g_cfg.tcp_mux = strcmp(val, "true") == 0;
            else if (strcmp(sub, "wireProtocol") == 0)
                g_cfg.wire_v2 = strcmp(trim_quotes(val), "v2") == 0;
            else if (strcmp(sub, "protocol") == 0)
                g_cfg.protocol_kcp = strcmp(trim_quotes(val), "kcp") == 0;
            else if (strcmp(sub, "poolCount") == 0)
                g_cfg.pool_count = atoi(val);
            else if (strcmp(sub, "tls.enable") == 0)
                g_cfg.tls_enable = strcmp(val, "true") == 0;
            else if (strcmp(sub, "tls.serverName") == 0)
                snprintf(g_cfg.tls_server_name, sizeof(g_cfg.tls_server_name), "%s", trim_quotes(val));
            else if (strcmp(sub, "tls.disableCustomTLSFirstByte") == 0)
                g_cfg.tls_disable_first_byte = strcmp(val, "true") == 0;
            else if (strcmp(sub, "tls.trustedCaFile") == 0)
                snprintf(g_cfg.tls_trusted_ca, sizeof(g_cfg.tls_trusted_ca), "%s", trim_quotes(val));
            else if (strcmp(sub, "tls.certFile") == 0)
                snprintf(g_cfg.tls_cert_file, sizeof(g_cfg.tls_cert_file), "%s", trim_quotes(val));
            else if (strcmp(sub, "tls.keyFile") == 0)
                snprintf(g_cfg.tls_key_file, sizeof(g_cfg.tls_key_file), "%s", trim_quotes(val));
        } else if (strncmp(key, "auth.", 5) == 0) {
            const char *sub = key + 5;
            if (strcmp(sub, "token") == 0)
                snprintf(g_cfg.token, sizeof(g_cfg.token), "%s", trim_quotes(val));
        }
    }
    fclose(f);
    return 0;
}

int config_load(const char *path) {
    int i;
    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.server_port = 7000;
    g_cfg.login_fail_exit = true;
    g_cfg.tcp_mux = true;
    g_cfg.pool_count = 1;   /* frp default (util.EmptyOr(c.PoolCount, 1)) */
    /* frp defaults since v0.50.0: TLS on, custom first byte disabled */
    g_cfg.tls_enable = true;
    g_cfg.tls_disable_first_byte = true;
    if (parse_toml(path) < 0)
        return -1;
    for (i = 0; i < g_cfg.proxy_count; i++)
        if (g_cfg.proxies[i].local_ip[0] == '\0')
            snprintf(g_cfg.proxies[i].local_ip, sizeof(g_cfg.proxies[i].local_ip), "127.0.0.1");
    return 0;
}
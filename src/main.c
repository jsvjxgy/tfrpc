/*
 * SPDX-License-Identifier: GPL-3.0-only
 * main.c - tfrpc entry point.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

#include "tfrpc.h"

_Atomic int g_running = 1;

/* Signals are handled synchronously by a dedicated thread (sigwait) instead of
 * an asynchronous handler, so g_running is only touched from normal code and
 * tools like ThreadSanitizer can track the synchronization. */
static void *signal_thread(void *arg) {
    sigset_t *set = arg;
    int sig;
    for (;;) {
        if (sigwait(set, &sig) == 0) {
            log_msg(LOG_INFO, "signal %d received, shutting down", sig);
            atomic_store(&g_running, 0);
            break;
        }
    }
    return NULL;
}

static void usage(const char *argv0) {
    printf("tfrpc - a minimal C frp client (frp wire protocol v1/v2)\n");
    printf("usage: %s -c <config.toml> [-v]\n", argv0);
}

int main(int argc, char **argv) {
    const char *cfg_path = NULL;
    int verbose = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            cfg_path = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    log_set_verbose(verbose);

    if (!cfg_path) {
        cfg_path = "frpc.toml";
    }
    if (config_load(cfg_path) < 0)
        return 1;

    if (g_cfg.server_addr[0] == '\0' || g_cfg.server_port <= 0) {
        log_msg(LOG_ERROR, "invalid config: serverAddr/serverPort required");
        return 1;
    }
    if (g_cfg.proxy_count == 0) {
        log_msg(LOG_WARN, "no proxies configured");
    }
    log_msg(LOG_INFO, "tfrpc %s connecting to %s:%d (user=%s, proxies=%d)",
            TFRPC_VERSION, g_cfg.server_addr, g_cfg.server_port,
            g_cfg.user[0] ? g_cfg.user : "(none)", g_cfg.proxy_count);

    signal(SIGPIPE, SIG_IGN);
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);   /* block in all threads */
    pthread_t sigth;
    if (pthread_create(&sigth, NULL, signal_thread, &sigset) == 0)
        pthread_detach(sigth);

    control_run(&g_cfg);
    log_msg(LOG_INFO, "tfrpc stopped");
    return 0;
}
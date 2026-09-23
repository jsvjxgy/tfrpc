/*
 * SPDX-License-Identifier: GPL-3.0-only
 * log.c - minimal logging to stdout with timestamps.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

#include "tfrpc.h"

static int g_verbose = 0;

void log_set_verbose(int v) { g_verbose = v; }

void log_msg(int level, const char *fmt, ...) {
    struct timespec ts;
    struct tm tm;
    char timebuf[32];
    const char *prefix;
    va_list ap;

    if (level == LOG_DEBUG && !g_verbose)
        return;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);

    switch (level) {
    case LOG_INFO: prefix = "I"; break;
    case LOG_WARN: prefix = "W"; break;
    case LOG_ERROR: prefix = "E"; break;
    default: prefix = "D"; break;
    }

    printf("%s [%s] ", timebuf, prefix);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}
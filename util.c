/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 ООО «Fishydino»
 * Distributed under the MIT License; see LICENSE.
 */
#include "ruscan.h"
#include <errno.h>
#include <string.h>
#include <time.h>

char rs_lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }

int rs_casecmp(const char *a, const char *b)
{
    for (; *a != '\0' && *b != '\0'; a++, b++) {
        char x = rs_lower(*a), y = rs_lower(*b);
        if (x != y) return (int)(unsigned char)x - (int)(unsigned char)y;
    }
    return (int)(unsigned char)rs_lower(*a) - (int)(unsigned char)rs_lower(*b);
}

int rs_casestr(const char *hay, size_t len, const char *needle)
{
    size_t n = strlen(needle);
    if (n == 0 || len < n) return 0;
    for (size_t i = 0; i + n <= len; i++) {
        size_t j = 0;
        while (j < n && rs_lower(hay[i + j]) == rs_lower(needle[j])) j++;
        if (j == n) return 1;
    }
    return 0;
}

size_t rs_strlcpy(char *dst, const char *src, size_t size)
{
    size_t src_len = strlen(src);
    if (size > 0) {
        size_t n = (src_len < size - 1) ? src_len : size - 1;
        memcpy(dst, src, n);
        dst[n] = '\0';
    }
    return src_len;
}

static int rs_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

void rs_trim(char *s)
{
    size_t a = 0, b;
    while (s[a] != '\0' && rs_space(s[a])) a++;
    for (b = a; s[b] != '\0'; b++) { }
    while (b > a && rs_space(s[b - 1])) b--;
    memmove(s, s + a, b - a);
    s[b - a] = '\0';
}

size_t rs_sanitize(const char *in, size_t in_len, char *out, size_t size, int keep_nl)
{
    size_t o = 0;
    if (size == 0) return 0;
    for (size_t i = 0; i < in_len && o + 1 < size; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '\r') continue;
        out[o++] = (c >= 0x20u && c <= 0x7Eu) ? (char)c
                 : (c == '\n')                ? (keep_nl ? '\n' : ' ')
                 : (c == '\t')                ? ' ' : '.';
    }
    out[o] = '\0';
    return o;
}

long long rs_mono_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (long long)ts.tv_sec * 1000LL + (long long)(ts.tv_nsec / 1000000L);
}

int rs_sleep_ms(long ms)
{
    struct timespec req;
    if (ms <= 0) return 0;
    req.tv_sec = (time_t)(ms / 1000L);
    req.tv_nsec = (long)(ms % 1000L) * 1000000L;
    /* Not resumed on EINTR: an interrupt must surface at once. */
    return (nanosleep(&req, NULL) != 0 && errno == EINTR) ? -1 : 0;
}

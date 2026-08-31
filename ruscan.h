/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 ООО «Fishydino»
 * Distributed under the MIT License; see LICENSE.
 */

/*
 * Ruscan - availability lookup for .RU / .SU / .РФ names. The only host it
 * connects to is the registry WHOIS service; the examined domain is never
 * resolved and never contacted.
 */
#ifndef RUSCAN_H
#define RUSCAN_H

#include <stddef.h>
#include <stdio.h>

#define RS_VERSION       "1.0.0"
#define RS_MAX_DOMAIN    253             /* RFC 1035 presentation limit */
#define RS_MAX_LABEL     63
#define RS_MAX_LINE      1024
#define RS_MAX_FIELD     256
#define RS_MAX_ERR       256
#define RS_MAX_RESPONSE  (256u * 1024u)

typedef enum { RS_FREE = 0, RS_REGISTERED, RS_RESERVED, RS_UNKNOWN, RS_FAILED } rs_status;

typedef struct {
    char      domain[RS_MAX_DOMAIN + 1];
    rs_status status;
    char      state[RS_MAX_FIELD], registrar[RS_MAX_FIELD], org[RS_MAX_FIELD];
    char      created[RS_MAX_FIELD], paid_till[RS_MAX_FIELD], free_date[RS_MAX_FIELD];
    int       nserver_count;
    char      note[RS_MAX_ERR];
} rs_record;

typedef struct {
    size_t total, freed, registered, reserved, unknown, failed, skipped;
} rs_stats;
typedef enum { RS_FMT_TEXT = 0, RS_FMT_CSV, RS_FMT_JSON } rs_format;

char   rs_lower(char c);
int    rs_casecmp(const char *a, const char *b);
int    rs_casestr(const char *hay, size_t len, const char *needle);
size_t rs_strlcpy(char *dst, const char *src, size_t size);   /* returns strlen(src) */
void   rs_trim(char *s);
/* To printable ASCII: no escape sequence or bidi override survives. */
size_t rs_sanitize(const char *in, size_t in_len, char *out, size_t size, int keep_nl);
long long rs_mono_ms(void);
int    rs_sleep_ms(long ms);                    /* 0 slept, -1 interrupted */

/* Two-label ru / su / xn--p1ai names only. 0 ok, -1 with a message in `err`. */
int rs_validate(const char *raw, char *out, size_t size, char *err, size_t err_size);

typedef struct { int timeout_ms; size_t max_response; } rs_whois_opts;
int rs_server_allowed(const char *host);
const char *const *rs_servers(void);
/* Caller frees *out; *trunc marks a cap hit. Referrals are never followed. */
int rs_whois(const char *server, const char *domain, const rs_whois_opts *o,
             char **out, size_t *out_len, int *trunc, char *err, size_t err_size);

void rs_parse(const char *buf, size_t len, rs_record *r);
const char *rs_status_name(rs_status s);
void rs_emit_head(FILE *f, rs_format fmt, const char *server);
void rs_emit_row(FILE *f, rs_format fmt, const rs_record *r, size_t index, int verbose);
void rs_emit_tail(FILE *f, rs_format fmt, const rs_stats *st);
void rs_emit_raw(FILE *f, const char *domain, const char *buf, size_t len);

#endif /* RUSCAN_H */

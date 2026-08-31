/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 ООО «Fishydino»
 * Distributed under the MIT License; see LICENSE.
 */
#include "ruscan.h"
#include <string.h>

static void rs_keep(char *dst, size_t size, const char *val)
{
    if (dst[0] == '\0') rs_sanitize(val, strlen(val), dst, size, 0);
}

#define KEEP(f) rs_keep(r->f, sizeof(r->f), val)

/* Throttling and maintenance stay UNKNOWN rather than a guessed yes or no. */
void rs_parse(const char *buf, size_t len, rs_record *r)
{
    const char *p = buf, *end = buf + len;
    char line[RS_MAX_LINE], first[RS_MAX_ERR] = "";
    int saw_record = 0, saw_none = 0, mismatch = 0, stop_list = 0;

    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t raw = nl ? (size_t)(nl - p) : (size_t)(end - p);
        char *colon, *key, *val;

        rs_sanitize(p, raw, line, sizeof(line), 0);
        p = nl ? nl + 1 : end;
        rs_trim(line);
        if (line[0] == '\0' || line[0] == '%' || line[0] == '#') continue;

        if ((colon = strchr(line, ':')) == NULL) {
            if (rs_casestr(line, strlen(line), "no entries found")) saw_none = 1;
            else if (first[0] == '\0') rs_strlcpy(first, line, sizeof(first));
            continue;
        }
        *colon = '\0';
        key = line; val = colon + 1;
        rs_trim(key); rs_trim(val);
        if (val[0] == '\0') continue;

        if (rs_casecmp(key, "domain") == 0) {
            saw_record = 1;
            if (rs_casecmp(val, r->domain) != 0) mismatch = 1;
        } else if (rs_casecmp(key, "state") == 0)      KEEP(state);
        else if (rs_casecmp(key, "registrar") == 0)    KEEP(registrar);
        else if (rs_casecmp(key, "org") == 0 ||
                 rs_casecmp(key, "person") == 0)       KEEP(org);
        else if (rs_casecmp(key, "created") == 0)      KEEP(created);
        else if (rs_casecmp(key, "paid-till") == 0)    KEEP(paid_till);
        else if (rs_casecmp(key, "free-date") == 0)    KEEP(free_date);
        else if (rs_casecmp(key, "nserver") == 0)      r->nserver_count++;
        else if (rs_casecmp(key, "stop-list") == 0) { stop_list = 1; KEEP(note); }
    }

    if (mismatch) {
        r->status = RS_UNKNOWN;
        rs_strlcpy(r->note, "registry answered about a different name", sizeof(r->note));
    } else if (saw_record) {
        r->status = RS_REGISTERED;
    } else if (stop_list) {
        r->status = RS_RESERVED;
    } else if (saw_none) {
        r->status = RS_FREE;
    } else {
        r->status = RS_UNKNOWN;
        rs_strlcpy(r->note, first[0] != '\0' ? first : "answer not recognised", sizeof(r->note));
    }
}

const char *rs_status_name(rs_status s)
{
    switch (s) {
    case RS_FREE:       return "FREE";
    case RS_REGISTERED: return "REGISTERED";
    case RS_RESERVED:   return "RESERVED";
    case RS_UNKNOWN:    return "UNKNOWN";
    default:            return "FAILED";
    }
}

/* Printable ASCII only, so quoting is all that is left. */
static void rs_json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s != '\0'; s++) {
        if (*s == '"' || *s == '\\') fputc('\\', f);
        fputc(*s, f);
    }
    fputc('"', f);
}

static void rs_csv_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s != '\0'; s++) {
        if (*s == '"') fputc('"', f);
        fputc(*s, f);
    }
    fputc('"', f);
}

void rs_emit_head(FILE *f, rs_format fmt, const char *server)
{
    if (fmt == RS_FMT_CSV)
        fputs("domain,status,state,registrar,org,created,paid_till,free_date,"
              "nservers,note\n", f);
    else if (fmt == RS_FMT_JSON)
        fprintf(f, "{\n  \"tool\": \"ruscan/%s\",\n  \"server\": \"%s\",\n  \"results\": [\n",
                RS_VERSION, server);
}

void rs_emit_row(FILE *f, rs_format fmt, const rs_record *r, size_t index, int verbose)
{
    if (fmt == RS_FMT_TEXT) {
        fprintf(f, "%-32s %s", r->domain, rs_status_name(r->status));
        if (verbose) {
            if (r->state[0] != '\0')     fprintf(f, "  state=%s", r->state);
            if (r->registrar[0] != '\0') fprintf(f, "  registrar=%s", r->registrar);
            if (r->org[0] != '\0')       fprintf(f, "  org=%s", r->org);
            if (r->created[0] != '\0')   fprintf(f, "  created=%s", r->created);
            if (r->paid_till[0] != '\0') fprintf(f, "  paid-till=%s", r->paid_till);
            if (r->free_date[0] != '\0') fprintf(f, "  free-date=%s", r->free_date);
            if (r->nserver_count > 0)     fprintf(f, "  nservers=%d", r->nserver_count);
        }
        if (r->note[0] != '\0' && (verbose || r->status == RS_FAILED ||
                                    r->status == RS_UNKNOWN))
            fprintf(f, "  (%s)", r->note);
        fputc('\n', f);
    } else if (fmt == RS_FMT_CSV) {
        rs_csv_str(f, r->domain);    fputc(',', f);
        rs_csv_str(f, rs_status_name(r->status)); fputc(',', f);
        rs_csv_str(f, r->state);     fputc(',', f);
        rs_csv_str(f, r->registrar); fputc(',', f);
        rs_csv_str(f, r->org);       fputc(',', f);
        rs_csv_str(f, r->created);   fputc(',', f);
        rs_csv_str(f, r->paid_till); fputc(',', f);
        rs_csv_str(f, r->free_date); fputc(',', f);
        fprintf(f, "%d,", r->nserver_count);
        rs_csv_str(f, r->note);      fputc('\n', f);
    } else {
        /* Leading separator: an interrupted run still closes the array. */
        fputs(index == 0 ? "    {" : "  , {", f);
        fputs(" \"domain\": ", f);       rs_json_str(f, r->domain);
        fputs(", \"status\": ", f);      rs_json_str(f, rs_status_name(r->status));
        fputs(", \"state\": ", f);       rs_json_str(f, r->state);
        fputs(", \"registrar\": ", f);   rs_json_str(f, r->registrar);
        fputs(", \"org\": ", f);         rs_json_str(f, r->org);
        fputs(", \"created\": ", f);     rs_json_str(f, r->created);
        fputs(", \"paid_till\": ", f);   rs_json_str(f, r->paid_till);
        fputs(", \"free_date\": ", f);   rs_json_str(f, r->free_date);
        fprintf(f, ", \"nservers\": %d", r->nserver_count);
        fputs(", \"note\": ", f);        rs_json_str(f, r->note);
        fputs(" }\n", f);
    }
}

void rs_emit_tail(FILE *f, rs_format fmt, const rs_stats *st)
{
    if (fmt != RS_FMT_JSON) return;
    fprintf(f, "  ],\n  \"summary\": { \"total\": %zu, \"free\": %zu, "
               "\"registered\": %zu, \"reserved\": %zu, \"unknown\": %zu, "
               "\"failed\": %zu, \"skipped\": %zu }\n}\n",
            st->total, st->freed, st->registered, st->reserved, st->unknown,
            st->failed, st->skipped);
}

void rs_emit_raw(FILE *f, const char *domain, const char *buf, size_t len)
{
    char chunk[RS_MAX_LINE];
    size_t off = 0;

    fprintf(f, "--- raw answer for %s ---\n", domain);
    while (off < len) {
        size_t take = len - off;
        if (take > sizeof(chunk) - 1) take = sizeof(chunk) - 1;
        rs_sanitize(buf + off, take, chunk, sizeof(chunk), 1);
        fputs(chunk, f);
        off += take;
    }
    fputs("\n--- end ---\n", f);
}

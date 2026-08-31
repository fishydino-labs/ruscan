/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 ООО «Fishydino»
 * Distributed under the MIT License; see LICENSE.
 */
#include "ruscan.h"
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RS_DEF_SERVER  "whois.tcinet.ru"
#define RS_DEF_DELAY   1000    /* ms between queries: the registry throttles */
#define RS_MIN_DELAY   200
#define RS_DEF_TIMEOUT 15000
#define RS_MAX_INPUT   100000

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

typedef struct { char *name; char *err; } rs_entry;   /* err != NULL => rejected */
typedef struct { rs_entry *v; size_t n, cap; } rs_list;
typedef struct { char **slot; size_t cap, used; } rs_set;

static uint64_t rs_hash(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    for (; *s != '\0'; s++) h = (h ^ (unsigned char)*s) * 1099511628211ULL;
    return h;
}

static int rs_set_put(rs_set *s, char *key)          /* 1 added, 0 duplicate, -1 oom */
{
    size_t i;
    if (s->used * 10 >= s->cap * 7) {                /* grow at 70% load */
        size_t ncap = s->cap ? s->cap * 2 : 1024;
        char **ns = calloc(ncap, sizeof(*ns));
        if (ns == NULL) return -1;
        for (i = 0; i < s->cap; i++) {
            if (s->slot[i] == NULL) continue;
            for (size_t j = rs_hash(s->slot[i]) & (ncap - 1); ; j = (j + 1) & (ncap - 1))
                if (ns[j] == NULL) { ns[j] = s->slot[i]; break; }
        }
        free(s->slot);
        s->slot = ns; s->cap = ncap;
    }
    for (i = rs_hash(key) & (s->cap - 1); s->slot[i] != NULL; i = (i + 1) & (s->cap - 1))
        if (strcmp(s->slot[i], key) == 0) return 0;
    s->slot[i] = key;
    s->used++;
    return 1;
}

static int rs_list_add(rs_list *l, char *name, char *err)
{
    if (l->n == l->cap) {
        size_t ncap = l->cap ? l->cap * 2 : 128;
        rs_entry *nv = realloc(l->v, ncap * sizeof(*nv));
        if (nv == NULL) return -1;
        l->v = nv; l->cap = ncap;
    }
    l->v[l->n].name = name;
    l->v[l->n].err = err;
    l->n++;
    return 0;
}

static int rs_take(rs_list *l, rs_set *seen, const char *raw, rs_stats *st)
{
    char norm[RS_MAX_DOMAIN + 1], err[RS_MAX_ERR];
    char *name = NULL, *msg = NULL;
    int added;

    if (l->n >= RS_MAX_INPUT) {
        fprintf(stderr, "ruscan: more than %d input names, refusing the rest\n", RS_MAX_INPUT);
        return -1;
    }
    if (rs_validate(raw, norm, sizeof(norm), err, sizeof(err)) != 0) {
        char safe[RS_MAX_DOMAIN + 1];
        rs_sanitize(raw, strlen(raw), safe, sizeof(safe), 0);
        name = strdup(safe);
        msg = strdup(err);
        if (name == NULL || msg == NULL || rs_list_add(l, name, msg) != 0) {
            free(name); free(msg);
            return -1;
        }
        return 0;
    }
    if ((name = strdup(norm)) == NULL) return -1;
    if ((added = rs_set_put(seen, name)) < 0) { free(name); return -1; }
    if (added == 0) { free(name); st->skipped++; return 0; }
    if (rs_list_add(l, name, NULL) != 0) { free(name); return -1; }
    return 0;                                    /* the list now owns `name` */
}

static int rs_read_file(const char *path, rs_list *l, rs_set *seen, rs_stats *st)
{
    FILE *opened = NULL, *f = stdin;
    char line[RS_MAX_LINE];
    int rc = 0;

    if (strcmp(path, "-") != 0) {
        if ((opened = fopen(path, "r")) == NULL) {
            fprintf(stderr, "ruscan: cannot open %s\n", path);
            return -1;
        }
        f = opened;
    }
    while (rc == 0 && fgets(line, sizeof(line), f) != NULL) {
        char *hash = strchr(line, '#');
        if (hash != NULL) *hash = '\0';
        rs_trim(line);
        if (line[0] != '\0') rc = rs_take(l, seen, line, st);
    }
    if (opened != NULL) fclose(opened);
    return rc;
}

static void rs_usage(FILE *f)
{
    fprintf(f,
"ruscan %s - availability lookup for .ru / .su / .xn--p1ai domain names\n\n"
"Usage: ruscan [options] [domain ...]\n\n"
"  -f, --file PATH      read names from PATH, one per line ('-' is stdin)\n"
"  -o, --output PATH    write the report to PATH instead of stdout\n"
"  -F, --format FMT     text (default), csv or json\n"
"  -d, --delay MS       pause between queries (default %d, minimum %d)\n"
"  -t, --timeout MS     budget per query (default %d)\n"
"  -r, --retries N      retries after a network failure (default 1)\n"
"  -s, --server HOST    WHOIS host from the built-in allow-list\n"
"  -R, --raw            also print the sanitised raw answer (text format only)\n"
"  -n, --dry-run        validate and de-duplicate the input, query nothing\n"
"  -v, --verbose        registry detail per name; progress too when redirected\n"
"  -q, --quiet          silence stderr completely\n"
"  -h, --help           this text\n"
"  -V, --version        version\n\n"
"Ruscan never contacts the domain being examined: it speaks only to the\n"
"registry WHOIS service over TCP port 43. Allowed hosts:", RS_VERSION,
        RS_DEF_DELAY, RS_MIN_DELAY, RS_DEF_TIMEOUT);
    for (size_t i = 0; rs_servers()[i] != NULL; i++) fprintf(f, " %s", rs_servers()[i]);
    fprintf(f, "\n\nExit codes: 0 every name answered, 1 usage error, 2 nothing valid to\n"
               "query, 3 some name unresolved, 4 interrupted.\n");
}

int main(int argc, char **argv)
{
    static const struct option opts[] = {
        { "file", required_argument, NULL, 'f' }, { "output", required_argument, NULL, 'o' },
        { "format", required_argument, NULL, 'F' }, { "delay", required_argument, NULL, 'd' },
        { "timeout", required_argument, NULL, 't' }, { "retries", required_argument, NULL, 'r' },
        { "server", required_argument, NULL, 's' }, { "raw", no_argument, NULL, 'R' },
        { "dry-run", no_argument, NULL, 'n' }, { "verbose", no_argument, NULL, 'v' },
        { "quiet", no_argument, NULL, 'q' },
        { "help", no_argument, NULL, 'h' }, { "version", no_argument, NULL, 'V' },
        { NULL, 0, NULL, 0 }
    };
    const char *file = NULL, *outpath = NULL, *server = RS_DEF_SERVER;
    rs_format fmt = RS_FMT_TEXT;
    long delay = RS_DEF_DELAY, timeout = RS_DEF_TIMEOUT, retries = 1;
    int raw = 0, dry = 0, quiet = 0, verbose = 0, progress = 0, opt, exit_code = 0;
    FILE *out = stdout;
    rs_list list = { NULL, 0, 0 };
    rs_set seen = { NULL, 0, 0 };
    rs_stats st;
    rs_whois_opts wopts;
    struct sigaction sa;

    memset(&st, 0, sizeof(st));

    while ((opt = getopt_long(argc, argv, "f:o:F:d:t:r:s:RnvqhV", opts, NULL)) != -1) {
        switch (opt) {
        case 'f': file = optarg; break;
        case 'o': outpath = optarg; break;
        case 'F':
            if (rs_casecmp(optarg, "text") == 0) fmt = RS_FMT_TEXT;
            else if (rs_casecmp(optarg, "csv") == 0) fmt = RS_FMT_CSV;
            else if (rs_casecmp(optarg, "json") == 0) fmt = RS_FMT_JSON;
            else { fprintf(stderr, "ruscan: unknown format '%s'\n", optarg); return 1; }
            break;
        case 'd': delay = strtol(optarg, NULL, 10); break;
        case 't': timeout = strtol(optarg, NULL, 10); break;
        case 'r': retries = strtol(optarg, NULL, 10); break;
        case 's': server = optarg; break;
        case 'R': raw = 1; break;
        case 'n': dry = 1; break;
        case 'v': verbose = 1; break;
        case 'q': quiet = 1; break;
        case 'h': rs_usage(stdout); return 0;
        case 'V': printf("ruscan %s\n", RS_VERSION); return 0;
        default: rs_usage(stderr); return 1;
        }
    }
    if (!rs_server_allowed(server)) {
        fprintf(stderr, "ruscan: server '%s' is not on the allow-list; allowed:", server);
        for (size_t i = 0; rs_servers()[i] != NULL; i++) fprintf(stderr, " %s", rs_servers()[i]);
        fputc('\n', stderr);
        return 1;
    }
    if (delay < RS_MIN_DELAY) delay = RS_MIN_DELAY;      /* politeness floor */
    if (timeout < 1000) timeout = 1000;
    if (timeout > 120000) timeout = 120000;
    if (retries < 0) retries = 0;
    if (retries > 5) retries = 5;
    if (raw && fmt != RS_FMT_TEXT) {
        fprintf(stderr, "ruscan: --raw is available in the text format only\n");
        return 1;
    }
    if (optind >= argc && file == NULL) { rs_usage(stderr); return 1; }

    for (int i = optind; i < argc && exit_code == 0; i++)
        if (rs_take(&list, &seen, argv[i], &st) != 0) exit_code = 1;
    if (exit_code == 0 && file != NULL && rs_read_file(file, &list, &seen, &st) != 0)
        exit_code = 1;
    if (exit_code != 0) goto cleanup;
    if (list.n == 0) { fprintf(stderr, "ruscan: nothing to do\n"); exit_code = 2; goto cleanup; }

    if (dry) {
        size_t bad = 0;
        for (size_t i = 0; i < list.n; i++) {
            if (list.v[i].err != NULL) bad++;
            printf("%-32s %s%s\n", list.v[i].name, list.v[i].err ? "INVALID: " : "OK",
                   list.v[i].err ? list.v[i].err : "");
        }
        if (verbose && !quiet)
            fprintf(stderr, "%zu accepted, %zu rejected, %zu duplicates removed\n",
                    list.n - bad, bad, st.skipped);
        exit_code = bad > 0 ? 2 : 0;
        goto cleanup;
    }
    if (outpath != NULL && (out = fopen(outpath, "w")) == NULL) {
        fprintf(stderr, "ruscan: cannot write to %s\n", outpath);
        exit_code = 1;
        goto cleanup;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    wopts.timeout_ms = (int)timeout;
    wopts.max_response = RS_MAX_RESPONSE;
    /* On a terminal the rows are the progress; a commentary would interleave. */
    progress = verbose && !quiet && !isatty(fileno(out));
    rs_emit_head(out, fmt, server);

    for (size_t i = 0; i < list.n && !g_stop; i++) {
        rs_record rec;
        char err[RS_MAX_ERR] = "", *answer = NULL;
        size_t len = 0;
        int trunc = 0, ok = 0;

        memset(&rec, 0, sizeof(rec));
        rs_strlcpy(rec.domain, list.v[i].name, sizeof(rec.domain));
        if (list.v[i].err != NULL) {
            rec.status = RS_FAILED;
            rs_strlcpy(rec.note, list.v[i].err, sizeof(rec.note));
        } else {
            if (i > 0 && rs_sleep_ms(delay) != 0) g_stop = 1;
            for (long a = 0; a <= retries && !g_stop; a++) {
                if (a > 0 && rs_sleep_ms(delay * 2) != 0) { g_stop = 1; break; }
                if (rs_whois(server, rec.domain, &wopts, &answer, &len, &trunc,
                             err, sizeof(err)) == 0) { ok = 1; break; }
            }
            if (ok) {
                rs_parse(answer, len, &rec);
                if (trunc) rs_strlcpy(rec.note, "answer truncated at the size cap",
                                      sizeof(rec.note));
            } else {
                rec.status = RS_FAILED;
                rs_strlcpy(rec.note, g_stop ? "interrupted" : err, sizeof(rec.note));
            }
        }
        switch (rec.status) {
        case RS_FREE:       st.freed++; break;
        case RS_REGISTERED: st.registered++; break;
        case RS_RESERVED:   st.reserved++; break;
        case RS_UNKNOWN:    st.unknown++; break;
        default:            st.failed++; break;
        }
        st.total++;
        if (raw && answer != NULL) rs_emit_raw(out, rec.domain, answer, len);
        rs_emit_row(out, fmt, &rec, st.total - 1, verbose);
        fflush(out);
        free(answer);
        if (progress)
            fprintf(stderr, "[%zu/%zu] %s -> %s\n", i + 1, list.n, rec.domain,
                    rs_status_name(rec.status));
    }
    rs_emit_tail(out, fmt, &st);

    if (verbose && !quiet)
        fprintf(stderr, "done: %zu queried, %zu free, %zu registered, %zu reserved, "
                        "%zu unknown, %zu failed, %zu duplicates removed\n",
                st.total, st.freed, st.registered, st.reserved, st.unknown, st.failed,
                st.skipped);
    if (g_stop) exit_code = 4;
    else if (st.unknown > 0 || st.failed > 0) exit_code = 3;
    if (out != stdout) fclose(out);

cleanup:
    for (size_t i = 0; i < list.n; i++) { free(list.v[i].name); free(list.v[i].err); }
    free(list.v);
    free(seen.slot);
    return exit_code;
}

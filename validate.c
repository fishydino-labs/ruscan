/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 ООО «Fishydino»
 * Distributed under the MIT License; see LICENSE.
 */
#include "ruscan.h"
#include <string.h>

static const char *const RS_ZONES[] = { "ru", "su", "xn--p1ai", NULL };

#define FAIL(msg) do { rs_strlcpy(err, (msg), err_size); return -1; } while (0)

static int rs_label_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
}

int rs_validate(const char *raw, char *out, size_t size, char *err, size_t err_size)
{
    char b[RS_MAX_DOMAIN + 1];
    size_t len, dots = 0, start = 0, i = 0;
    const char *tld;

    err[0] = out[0] = '\0';
    if (raw == NULL || raw[0] == '\0') FAIL("empty domain name");
    if (rs_strlcpy(b, raw, sizeof(b)) > RS_MAX_DOMAIN) {
        snprintf(err, err_size, "name longer than %d characters", RS_MAX_DOMAIN);
        return -1;
    }
    rs_trim(b);

    /* Transcoding Cyrillic here would risk querying the wrong name silently. */
    for (i = 0; b[i] != '\0'; i++) {
        if ((unsigned char)b[i] >= 0x80u) {
            FAIL("non-ASCII input: supply an internationalised name in "
                 "its punycode form (xn--...)");
        }
        b[i] = rs_lower(b[i]);
    }
    if (strpbrk(b, "/\\:@?#& \t\"'") != NULL) {
        FAIL("expected a bare domain name, not a URL, e-mail address "
             "or quoted string");
    }
    len = strlen(b);
    if (len > 0 && b[len - 1] == '.') b[--len] = '\0';
    if (len == 0) FAIL("empty domain name");

    for (i = 0; ; i++) {
        if (b[i] != '.' && b[i] != '\0') {
            if (!rs_label_char(b[i])) {
                snprintf(err, err_size, "character '%c' is not allowed in a domain name", b[i]);
                return -1;
            }
            continue;
        }
        if (i == start) FAIL("empty label (a dot with nothing beside it)");
        if (i - start > RS_MAX_LABEL) {
            snprintf(err, err_size, "label longer than %d characters", RS_MAX_LABEL);
            return -1;
        }
        if (b[start] == '-' || b[i - 1] == '-') FAIL("label starts or ends with a hyphen");
        if (b[i] == '\0') break;
        dots++;
        start = i + 1;
    }

    if (dots == 0) FAIL("no zone suffix: expected name.ru, name.su or name.xn--p1ai");
    tld = strrchr(b, '.') + 1;
    for (i = 0; ; i++) {
        if (RS_ZONES[i] == NULL) {
            snprintf(err, err_size, "zone '.%s' is outside the scope of this tool "
                                    "(.ru, .su and .xn--p1ai only)", tld);
            return -1;
        }
        if (strcmp(tld, RS_ZONES[i]) == 0) break;
    }
    /* Under msk.ru and friends the registry answers "no entries found"
       regardless, so reporting that as free would be a lie. */
    if (dots != 1)
        FAIL("only second-level names are supported: the registry is not "
             "authoritative for third-level names in public zones");
    if (rs_strlcpy(out, b, size) >= size) FAIL("normalised name does not fit the buffer");
    return 0;
}

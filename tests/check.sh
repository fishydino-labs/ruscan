#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ООО «Fishydino»
# Distributed under the MIT License; see LICENSE.
# Offline test suite: input validation, normalisation, de-duplication and the
# output formats. Nothing here touches the network -- every case runs under
# --dry-run or on locally produced text.
set -u
BIN=./ruscan
fail=0

# ok <label> <expected-exit> <expected-substring> <args...>
ok() {
    label=$1; want_rc=$2; want=$3; shift 3
    out=$($BIN "$@" 2>&1); rc=$?
    if [ "$rc" != "$want_rc" ]; then
        printf 'FAIL %-42s exit %s, expected %s\n' "$label" "$rc" "$want_rc"; fail=1; return
    fi
    case $out in
        *"$want"*) printf 'ok   %s\n' "$label" ;;
        *) printf 'FAIL %-42s missing "%s" in: %s\n' "$label" "$want" "$out"; fail=1 ;;
    esac
}

ok 'accepts a plain name'            0 'yandex.ru'           -n -q yandex.ru
ok 'lower-cases and strips root dot' 0 'yandex.ru'           -n -q YaNdEx.RU.
ok 'accepts .su'                     0 'example.su'          -n -q example.su
ok 'accepts punycode .рф'            0 'xn--80aswg.xn--p1ai' -n -q xn--80aswg.xn--p1ai
ok 'rejects a foreign zone'          2 'outside the scope'   -n -q example.com
ok 'rejects a third-level name'      2 'second-level'        -n -q shop.msk.ru
ok 'rejects a URL'                   2 'bare domain name'    -n -q https://yandex.ru/path
ok 'rejects Cyrillic input'          2 'punycode'            -n -q "яндекс.рф"
ok 'rejects a leading hyphen'        2 'hyphen'              -n -q -- -bad.ru
ok 'rejects an empty label'          2 'empty label'         -n -q 'a..ru'
ok 'rejects a bare zone'             2 'no zone suffix'      -n -q ru
ok 'rejects an off-list server'      1 'allow-list'          -s whois.example.com yandex.ru
ok 'rejects an unknown format'       1 'unknown format'      -F yaml yandex.ru
ok 'refuses raw outside text'        1 'text format only'    -F json -R yandex.ru
ok 'no arguments prints usage'       1 'Usage: ruscan'
ok 'de-duplicates the input'         0 'duplicates removed'  -n -v yandex.ru YANDEX.ru yandex.ru.
ok 'stays silent without -v'         0 'yandex.ru'           -n yandex.ru

# Bulk input from a file, mixing comments, blanks and one bad entry.
tmp=$(mktemp)
printf '# list\nyandex.ru\n\nexample.com\nkremlin.ru  # trailing comment\nyandex.ru\n' > "$tmp"
out=$($BIN -n -q -f "$tmp"); rc=$?
lines=$(printf '%s\n' "$out" | grep -c .)
if [ "$rc" = 2 ] && [ "$lines" = 3 ]; then printf 'ok   bulk file: comments, blanks, dupes\n'
else printf 'FAIL bulk file: exit %s, %s lines\n%s\n' "$rc" "$lines" "$out"; fail=1; fi

# Reading the same list from standard input must give the same result.
if [ "$($BIN -n -q -f - < "$tmp")" = "$out" ]; then printf 'ok   stdin matches file input\n'
else printf 'FAIL stdin differs from file input\n'; fail=1; fi
rm -f "$tmp"

# A rejected name still produces a row in every machine-readable format,
# without any query being sent (the name never resolves to anything).
out=$($BIN -q -F csv example.com 2>&1); rc=$?
case $out in
  *'"example.com","FAILED"'*) printf 'ok   csv row for a rejected name\n' ;;
  *) printf 'FAIL csv row for a rejected name: %s\n' "$out"; fail=1 ;;
esac
[ "$rc" = 3 ] || { printf 'FAIL csv exit code %s, expected 3\n' "$rc"; fail=1; }

out=$($BIN -q -F json example.com 2>&1)
case $out in
  *'"status": "FAILED"'*'"summary"'*) printf 'ok   json document for a rejected name\n' ;;
  *) printf 'FAIL json document: %s\n' "$out"; fail=1 ;;
esac
command -v python3 >/dev/null 2>&1 && {
    printf '%s' "$out" | python3 -c 'import json,sys; json.load(sys.stdin)' \
        && printf 'ok   json parses\n' || { printf 'FAIL json does not parse\n'; fail=1; }
}

[ $fail = 0 ] && printf '\nall checks passed\n' || printf '\nsome checks failed\n'
exit $fail

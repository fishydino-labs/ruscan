# SPDX-License-Identifier: MIT
# Copyright (c) 2026 ООО «Fishydino»
# Distributed under the MIT License; see LICENSE.
# Ruscan - build with warnings as a design tool, not as noise.
CC      ?= cc
PREFIX  ?= /usr/local
BIN      = ruscan
SRC      = main.c util.c validate.c whois.c report.c
OBJ      = $(SRC:.c=.o)
SOURCES  = $(SRC) ruscan.h

STD     := -std=c11
ifeq ($(shell uname -s),Darwin)
FEATURE := -D_DARWIN_C_SOURCE
PIE     :=            # position-independent executables are the default
else
FEATURE := -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
PIE     := -pie
endif
WARN    := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion \
           -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes -Wcast-qual \
           -Wpointer-arith -Wwrite-strings -Wvla
HARDEN  := -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
           -fno-common -fPIE
EXTRA   ?=
CFLAGS  ?= -g
CFLAGS  += $(STD) $(FEATURE) $(WARN) $(HARDEN) $(EXTRA)
LDFLAGS += $(PIE)

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ)

$(OBJ): ruscan.h

check: $(BIN)
	@sh tests/check.sh

test: check

# No external formatter is assumed; whitespace is normalised in place.
fmt:
	@for f in $(SOURCES); do \
	  awk '{ gsub(/\t/, "    "); sub(/[ \t]+$$/, ""); print }' $$f > $$f.tmp; \
	  if cmp -s $$f $$f.tmp; then rm -f $$f.tmp; \
	  else mv $$f.tmp $$f; echo "fmt: rewrote $$f"; fi; \
	done
	@echo "fmt: done"

lint:
	@awk 'length > 99 { print FILENAME ":" FNR ": over 99 columns"; bad = 1 } \
	      /[ \t]+$$/ { print FILENAME ":" FNR ": trailing whitespace"; bad = 1 } \
	      END { exit bad }' $(SOURCES)
	@echo "lint: clean"

# Address and undefined-behaviour sanitisers over the same test suite.
sanitize: clean
	$(MAKE) EXTRA="-fsanitize=address,undefined -fno-omit-frame-pointer" \
	        LDFLAGS="-fsanitize=address,undefined" check

analyze:
	$(CC) --analyze $(STD) $(FEATURE) $(SRC)

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f $(BIN) $(OBJ) *.plist

.PHONY: all check test fmt lint sanitize analyze install uninstall clean

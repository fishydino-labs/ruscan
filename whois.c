/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 ООО «Fishydino»
 * Distributed under the MIT License; see LICENSE.
 */
#include "ruscan.h"
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* whois.ripn.net is the same service under its older name. */
static const char *const RS_SERVERS[] = { "whois.tcinet.ru", "whois.ripn.net", NULL };
#define RS_PORT "43"

const char *const *rs_servers(void) { return RS_SERVERS; }

int rs_server_allowed(const char *host)
{
    for (size_t i = 0; RS_SERVERS[i] != NULL; i++)
        if (rs_casecmp(host, RS_SERVERS[i]) == 0) return 1;
    return 0;
}

/* 1 ready, 0 timeout, -1 error. */
static int rs_wait(int fd, short events, long long deadline)
{
    for (;;) {
        long long remain = deadline - rs_mono_ms();
        struct pollfd p;
        int rc;
        if (remain <= 0) return 0;
        if (remain > 2147483647LL) remain = 2147483647LL;
        p.fd = fd; p.events = events; p.revents = 0;
        rc = poll(&p, 1, (int)remain);
        if (rc >= 0) return rc > 0 ? 1 : 0;
        if (errno != EINTR) return -1;
    }
}

static int rs_connect(const struct addrinfo *ai, long long deadline)
{
    int fd, flags, so_err = 0;
    socklen_t so_len = sizeof(so_err);

    if ((fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) return -1;
    if ((flags = fcntl(fd, F_GETFL, 0)) < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        goto fail;
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) return fd;
    if (errno != EINPROGRESS) goto fail;
    if (rs_wait(fd, POLLOUT, deadline) != 1) goto fail;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len) != 0 || so_err != 0) goto fail;
    return fd;
fail:
    close(fd);
    return -1;
}

static int rs_send_all(int fd, const char *data, size_t len, long long deadline,
                       char *err, size_t err_size)
{
    for (size_t sent = 0; sent < len; ) {
        ssize_t n;
        if (rs_wait(fd, POLLOUT, deadline) != 1) {
            rs_strlcpy(err, "timed out while sending the query", err_size);
            return -1;
        }
        n = send(fd, data + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            snprintf(err, err_size, "send failed: %s", strerror(errno));
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

int rs_whois(const char *server, const char *domain, const rs_whois_opts *o,
             char **out, size_t *out_len, int *trunc, char *err, size_t err_size)
{
    struct addrinfo hints, *res = NULL, *ai;
    long long deadline;
    int fd = -1, gai, qlen;
    char query[RS_MAX_DOMAIN + 4], *buf;
    size_t cap = 8192, len = 0;

    *out = NULL; *out_len = 0; *trunc = 0; err[0] = '\0';

    /* Checked by the caller too; the guarantee belongs next to the socket. */
    if (!rs_server_allowed(server)) {
        snprintf(err, err_size, "server '%s' is not on the allow-list", server);
        return -1;
    }
    deadline = rs_mono_ms() + (long long)o->timeout_ms;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if ((gai = getaddrinfo(server, RS_PORT, &hints, &res)) != 0 || res == NULL) {
        snprintf(err, err_size, "cannot resolve %s: %s", server, gai_strerror(gai));
        return -1;
    }
    for (ai = res; ai != NULL && fd < 0; ai = ai->ai_next) fd = rs_connect(ai, deadline);
    freeaddrinfo(res);
    if (fd < 0) {
        snprintf(err, err_size, "cannot connect to %s port %s", server, RS_PORT);
        return -1;
    }
    /* rs_validate() guarantees no CR or LF here, so no second request. */
    qlen = snprintf(query, sizeof(query), "%s\r\n", domain);
    if (qlen < 0 || (size_t)qlen >= sizeof(query)) {
        rs_strlcpy(err, "query does not fit the request buffer", err_size);
        close(fd);
        return -1;
    }
    if (rs_send_all(fd, query, (size_t)qlen, deadline, err, err_size) != 0) {
        close(fd);
        return -1;
    }
    if ((buf = malloc(cap)) == NULL) {
        rs_strlcpy(err, "out of memory", err_size);
        close(fd);
        return -1;
    }
    for (;;) {
        ssize_t n;
        int ready;
        if (len + 1 >= cap) {                      /* one byte reserved for NUL */
            char *nb;
            size_t ncap = cap * 2;
            if (cap >= o->max_response) { *trunc = 1; break; }
            if (ncap > o->max_response) ncap = o->max_response;
            if ((nb = realloc(buf, ncap)) == NULL) {
                rs_strlcpy(err, "out of memory", err_size);
                goto fail;
            }
            buf = nb; cap = ncap;
        }
        if ((ready = rs_wait(fd, POLLIN, deadline)) == 0) {
            rs_strlcpy(err, "timed out while waiting for the answer", err_size);
            goto fail;
        }
        if (ready < 0) { snprintf(err, err_size, "poll failed: %s", strerror(errno)); goto fail; }
        n = recv(fd, buf + len, cap - len - 1, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            snprintf(err, err_size, "receive failed: %s", strerror(errno));
            goto fail;
        }
        if (n == 0) break;                         /* close means end of answer */
        len += (size_t)n;
    }
    close(fd);
    buf[len] = '\0';
    *out = buf; *out_len = len;
    return 0;
fail:
    free(buf);
    close(fd);
    return -1;
}

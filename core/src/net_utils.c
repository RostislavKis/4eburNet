/*
 * Сетевые и системные утилиты (M-01, M-02)
 *
 * Единственное место в проекте с popen/pclose.
 * Все модули используют exec_cmd* API.
 */

#include "net_utils.h"

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void net_format_addr(const struct sockaddr_storage *ss,
                     char *buf, size_t buflen)
{
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)ss;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof(ip));
        snprintf(buf, buflen, "%s:%u", ip, ntohs(s4->sin_port));
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ss;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof(ip));
        snprintf(buf, buflen, "[%s]:%u", ip, ntohs(s6->sin6_port));
    } else {
        snprintf(buf, buflen, "unknown");
    }
}

/* ------------------------------------------------------------------ */
/*  Инкапсуляция popen (M-02)                                         */
/* ------------------------------------------------------------------ */

int exec_cmd_lines(const char *cmd,
                   void (*callback)(const char *line, void *ctx),
                   void *ctx)
{
    FILE *fp = popen(cmd, "r");
    if (!fp)
        return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (callback)
            callback(line, ctx);
    }

    return pclose(fp);
}

int exec_cmd(const char *cmd)
{
    FILE *fp = popen(cmd, "r");
    if (!fp)
        return -1;
    char buf[256];
    while (fgets(buf, sizeof(buf), fp)) {}
    return pclose(fp);
}

/* Контекст для exec_cmd_contains */
struct contains_ctx {
    const char *needle;
    bool        found;
};

static void contains_cb(const char *line, void *ctx)
{
    struct contains_ctx *c = ctx;
    if (!c->found && strstr(line, c->needle))
        c->found = true;
}

bool exec_cmd_contains(const char *cmd, const char *needle)
{
    struct contains_ctx c = { .needle = needle, .found = false };
    exec_cmd_lines(cmd, contains_cb, &c);
    return c.found;
}

int exec_cmd_capture(const char *cmd,
                     char *err_buf, size_t err_size)
{
    FILE *fp = popen(cmd, "r");
    if (!fp)
        return -1;

    size_t total = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (err_buf && total + len < err_size - 1) {
            memcpy(err_buf + total, line, len);
            total += len;
        }
    }
    if (err_buf)
        err_buf[total] = '\0';

    return pclose(fp);
}

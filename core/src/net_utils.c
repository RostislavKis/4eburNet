/*
 * Сетевые и системные утилиты (M-01, M-02)
 *
 * Единственное место в проекте с popen/pclose.
 * Все модули используют exec_cmd* API.
 */

#include "net_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>
#include "crypto/tls.h"
#include "phoenix.h"

extern char **environ;

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
/*  Валидация имени интерфейса (C-10, C-11)                            */
/* ------------------------------------------------------------------ */

bool valid_ifname(const char *s)
{
    if (!s || !s[0] || strlen(s) >= IFNAMSIZ) return false;
    for (const char *p = s; *p; p++)
        if (!isalnum((unsigned char)*p) &&
            *p != '-' && *p != '_' && *p != '.')
            return false;
    return true;
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

/* ------------------------------------------------------------------ */
/*  exec_cmd_safe — через posix_spawn без shell (H-07)                 */
/* ------------------------------------------------------------------ */

int exec_cmd_safe(const char *const argv[], char *out, size_t outlen)
{
    int pipe_fds[2];
    if (pipe(pipe_fds) < 0) return -1;

    pid_t pid;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, pipe_fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&fa, pipe_fds[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&fa, pipe_fds[0]);
    posix_spawn_file_actions_addclose(&fa, pipe_fds[1]);

    int rc = posix_spawn(&pid, argv[0], &fa, NULL,
                         (char *const *)argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(pipe_fds[1]);

    if (rc != 0) { close(pipe_fds[0]); return -1; }

    size_t total = 0;
    if (out && outlen > 0) {
        ssize_t n;
        while ((n = read(pipe_fds[0], out + total,
                         outlen - 1 - total)) > 0)
            total += (size_t)n;
        out[total] = '\0';
    }
    close(pipe_fds[0]);

    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* ------------------------------------------------------------------ */
/*  net_random_bytes — криптографически безопасный random (C-01)        */
/* ------------------------------------------------------------------ */

int net_random_bytes(uint8_t *buf, size_t len)
{
#ifdef __NR_getrandom
    size_t done = 0;
    while (done < len) {
        ssize_t r = syscall(__NR_getrandom, buf + done, len - done, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) goto fallback;
        done += (size_t)r;
    }
    return 0;
fallback:
#endif
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) { close(fd); return -1; }
        total += (size_t)n;
    }
    close(fd);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  json_escape_str — экранирование строки для JSON (H-6)              */
/* ------------------------------------------------------------------ */

int json_escape_str(const char *src, char *dst, size_t dst_size)
{
    if (!src || !dst || dst_size < 2) {
        if (dst && dst_size > 0) dst[0] = '\0';
        return 0;
    }

    size_t pos = 0;
    for (; *src && pos + 1 < dst_size; src++) {
        unsigned char c = (unsigned char)*src;
        if (c == '"' || c == '\\') {
            if (pos + 2 >= dst_size) break;
            dst[pos++] = '\\';
            dst[pos++] = (char)c;
        } else if (c < 0x20) {
            /* Управляющие символы → \uXXXX */
            if (pos + 6 >= dst_size) break;
            pos += (size_t)snprintf(dst + pos, dst_size - pos,
                                     "\\u%04x", c);
        } else {
            dst[pos++] = (char)c;
        }
    }
    dst[pos] = '\0';
    return (int)pos;
}

int net_http_fetch(const char *url, const char *dest_path)
{
    if (!url || !url[0]) return -1;

    const char *u = url;
    uint16_t port;
    if (strncmp(u, "https://", 8) == 0) { u += 8; port = 443; }
    else if (strncmp(u, "http://", 7) == 0) { u += 7; port = 80; }
    else { port = 443; }

    char host[256] = {0};
    char path[512] = "/";
    const char *slash = strchr(u, '/');
    if (slash) {
        size_t hlen = slash - u;
        if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
        memcpy(host, u, hlen);
        snprintf(path, sizeof(path), "%s", slash);
    } else {
        snprintf(host, sizeof(host), "%s", u);
    }

    char *colon = strchr(host, ':');
    if (colon) {
        char *endptr;
        long p = strtol(colon + 1, &endptr, 10);
        if (endptr != colon + 1 && *endptr == '\0' && p > 0 && p <= 65535)
            port = (uint16_t)p;
        *colon = '\0';
    }

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints = {0};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int gai = getaddrinfo(host, port_str, &hints, &res);
    if (gai != 0) {
        log_msg(LOG_WARN, "net_http_fetch: не удалось резолвить '%s': %s",
                host, gai_strerror(gai));
        return -1;
    }

    int fd = socket(res->ai_family,
                    res->ai_socktype | SOCK_CLOEXEC, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    struct timeval tv = { .tv_sec = 10 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res); close(fd); return -1;
    }
    freeaddrinfo(res);

    tls_config_t tls_cfg = {0};
    snprintf(tls_cfg.sni, sizeof(tls_cfg.sni), "%s", host);
    tls_cfg.verify_cert = false;

    tls_conn_t tls;
    if (tls_connect(&tls, fd, &tls_cfg) < 0) {
        close(fd); return -1;
    }

    char req[1024];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
        path, host);
    tls_send(&tls, req, req_len);

    char tmppath[280];
    snprintf(tmppath, sizeof(tmppath), "%s.XXXXXX", dest_path);
    int tmpfd = mkstemp(tmppath);
    if (tmpfd < 0) { tls_close(&tls); close(fd); return -1; }
    fchmod(tmpfd, 0644);
    FILE *out = fdopen(tmpfd, "w");
    if (!out) {
        close(tmpfd); unlink(tmppath);
        tls_close(&tls); close(fd);
        return -1;
    }

    uint8_t buf[4096];
    bool headers_done = false;
    bool http_ok = false;
    ssize_t total = 0;

    while (1) {
        ssize_t n = tls_recv(&tls, buf, sizeof(buf));
        if (n <= 0) break;

        if (!headers_done) {
            size_t safe_n = (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf) - 1;
            buf[safe_n] = '\0';
            for (ssize_t j = 0; j < n - 3; j++) {
                if (buf[j]=='\r' && buf[j+1]=='\n' &&
                    buf[j+2]=='\r' && buf[j+3]=='\n') {
                    buf[j] = '\0';
                    http_ok = (strstr((char*)buf, " 200") != NULL);
                    headers_done = true;
                    ssize_t body_start = j + 4;
                    if (http_ok && body_start < n)
                        fwrite(buf + body_start, 1, n - body_start, out);
                    total += n - body_start;
                    break;
                }
            }
        } else if (http_ok) {
            fwrite(buf, 1, n, out);
            total += n;
        }
    }

    fclose(out);
    tls_close(&tls);
    close(fd);

    if (!http_ok || total == 0) {
        unlink(tmppath);
        return -1;
    }

    rename(tmppath, dest_path);
    log_msg(LOG_INFO, "net_http_fetch: загружен %s (%zd байт)", dest_path, total);
    return 0;
}

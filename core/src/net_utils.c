/*
 * Сетевые и системные утилиты (M-01, M-02)
 *
 * Единственное место в проекте с popen/pclose.
 * Все модули используют exec_cmd* API.
 */

#include "net_utils.h"
#include "constants.h"

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
#include <poll.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>
#include <time.h>
#include "crypto/tls.h"
#include "4eburnet.h"

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

    /* posix_spawnp выполняет поиск по PATH (posix_spawn требует абсолютный путь) */
    int rc = posix_spawnp(&pid, argv[0], &fa, NULL,
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

/* ── Вспомогательные функции HTTP/HTTPS ── */

/* Парсить host и port из URL */
int net_parse_url_host(const char *url,
                       char *host, size_t host_size,
                       uint16_t *port)
{
    if (!url || !host || !host_size || !port) return -1;
    const char *u = url;
    if (strncmp(u, "https://", 8) == 0) { u += 8; *port = 443; }
    else if (strncmp(u, "http://", 7) == 0) { u += 7; *port = 80; }
    else { *port = 443; }

    const char *slash = strchr(u, '/');
    size_t hlen = slash ? (size_t)(slash - u) : strlen(u);
    if (hlen == 0 || hlen >= host_size) return -1;
    memcpy(host, u, hlen);
    host[hlen] = '\0';

    char *colon = strchr(host, ':');
    if (colon) {
        long p = strtol(colon + 1, NULL, 10);
        if (p > 0 && p <= 65535) *port = (uint16_t)p;
        *colon = '\0';
    }
    return 0;
}

/* Разрешить hostname → IP строку */
int net_resolve_host(const char *host, uint16_t port,
                     char *out_ip, size_t out_ip_size,
                     int *out_family)
{
    if (!host || !host[0] || !out_ip || !out_ip_size) return -1;

    /* Fast path: уже IPv4 */
    struct in_addr a4;
    if (inet_pton(AF_INET, host, &a4) == 1) {
        snprintf(out_ip, out_ip_size, "%s", host);
        if (out_family) *out_family = AF_INET;
        return 0;
    }

    /* Fast path: уже IPv6 (с квадратными скобками или без) */
    struct in6_addr a6;
    const char *h = host;
    char h_clean[256] = {0};
    if (h[0] == '[') {
        const char *rb = strchr(h, ']');
        if (rb) {
            size_t l = (size_t)(rb - h - 1);
            if (l < sizeof(h_clean)) {
                memcpy(h_clean, h + 1, l);
                h = h_clean;
            }
        }
    }
    if (inet_pton(AF_INET6, h, &a6) == 1) {
        snprintf(out_ip, out_ip_size, "%s", h);
        if (out_family) *out_family = AF_INET6;
        return 0;
    }

    /* Domain: нужен getaddrinfo — блокирует */
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    struct addrinfo hints = {0};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    int gai = getaddrinfo(host, port_str, &hints, &res);
    if (gai != 0) {
        log_msg(LOG_WARN, "net_resolve_host: '%s': %s",
                host, gai_strerror(gai));
        return -1;
    }

    /* Предпочесть IPv4 для совместимости */
    struct addrinfo *best = res;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
        if (r->ai_family == AF_INET) { best = r; break; }
    }

    if (best->ai_family == AF_INET) {
        inet_ntop(AF_INET,
            &((struct sockaddr_in *)best->ai_addr)->sin_addr,
            out_ip, (socklen_t)out_ip_size);
    } else {
        inet_ntop(AF_INET6,
            &((struct sockaddr_in6 *)best->ai_addr)->sin6_addr,
            out_ip, (socklen_t)out_ip_size);
    }
    if (out_family) *out_family = best->ai_family;
    freeaddrinfo(res);
    log_msg(LOG_DEBUG, "net_resolve_host: %s → %s", host, out_ip);
    return 0;
}

/*
 * Общий TLS GET + сохранение в файл.
 * fd: уже подключённый сокет (передаётся в tls_connect, затем close).
 */
static int http_do_tls_get(int fd, const char *sni_host,
                            const char *path, const char *dest_path)
{
    /* B1-01: буферы на heap — стековый кадр был ~5.4KB (MIPS стек 8KB) */
    char    *req     = malloc(1024);
    char    *tmppath = malloc(280);
    uint8_t *buf     = malloc(4096);
    if (!req || !tmppath || !buf) {
        log_msg(LOG_ERROR, "http_do_tls_get: нет памяти");
        free(req); free(tmppath); free(buf);
        close(fd); return -1;
    }

    int result = -1;
    FILE *out = NULL;

    tls_config_t tls_cfg = {0};
    snprintf(tls_cfg.sni, sizeof(tls_cfg.sni), "%s", sni_host);
    tls_cfg.verify_cert = false;

    tls_conn_t tls;
    if (tls_connect(&tls, fd, &tls_cfg) < 0) {
        close(fd); goto out;
    }

    int req_len = snprintf(req, 1024,
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
        path, sni_host);
    if (req_len < 0 || req_len >= 1024) {
        log_msg(LOG_ERROR, "net_utils: HTTP запрос обрезан (path=%s)", path);
        tls_close(&tls); close(fd); goto out;
    }
    tls_send(&tls, req, req_len);

    snprintf(tmppath, 280, "%s.XXXXXX", dest_path);
    int tmpfd = mkstemp(tmppath);
    if (tmpfd < 0) { tls_close(&tls); close(fd); goto out; }
    fchmod(tmpfd, 0644);
    out = fdopen(tmpfd, "w");
    if (!out) {
        close(tmpfd); unlink(tmppath);
        tls_close(&tls); close(fd); goto out;
    }

    bool headers_done = false;
    bool http_ok = false;
    ssize_t total = 0;

    while (1) {
        ssize_t n = tls_recv(&tls, buf, 4096);
        if (n <= 0) break;

        if (!headers_done) {
            size_t safe_n = (size_t)n < 4096 ? (size_t)n : 4096 - 1;
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
    out = NULL;
    tls_close(&tls);
    close(fd);

    if (!http_ok || total == 0) {
        unlink(tmppath);
        goto out;
    }

    rename(tmppath, dest_path);
    log_msg(LOG_INFO, "net_http_fetch: загружен %s (%zd байт)", dest_path, total);
    result = 0;

out:
    if (out) fclose(out);
    free(req);
    free(tmppath);
    free(buf);
    return result;
}

/* net_http_fetch_ip — connect по кэшированному IP, без getaddrinfo */
int net_http_fetch_ip(const char *url,
                      const char *resolved_ip,
                      int         addr_family,
                      const char *dest_path)
{
    if (!url || !url[0] || !resolved_ip || !resolved_ip[0]) return -1;

    char sni_host[256] = {0};
    uint16_t port = 443;
    net_parse_url_host(url, sni_host, sizeof(sni_host), &port);

    /* Путь из URL */
    const char *u = url;
    if (strncmp(u, "https://", 8) == 0) u += 8;
    else if (strncmp(u, "http://", 7) == 0) u += 7;
    char path[512] = "/";
    const char *slash = strchr(u, '/');
    if (slash) snprintf(path, sizeof(path), "%s", slash);

    /* Подключиться к resolved_ip напрямую */
    struct sockaddr_storage ss;
    socklen_t ss_len;
    memset(&ss, 0, sizeof(ss));
    if (addr_family == AF_INET6) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&ss;
        a6->sin6_family = AF_INET6;
        a6->sin6_port   = htons(port);
        inet_pton(AF_INET6, resolved_ip, &a6->sin6_addr);
        ss_len = sizeof(*a6);
    } else {
        struct sockaddr_in *a4 = (struct sockaddr_in *)&ss;
        a4->sin_family = AF_INET;
        a4->sin_port   = htons(port);
        inet_pton(AF_INET, resolved_ip, &a4->sin_addr);
        ss_len = sizeof(*a4);
    }

    int fd = socket(addr_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct timeval tv = { .tv_sec = TIMEOUT_NET_FETCH_SEC };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)&ss, ss_len) < 0) {
        close(fd); return -1;
    }

    return http_do_tls_get(fd, sni_host, path, dest_path);
}

/* net_http_fetch — полный fetch с резолвингом (обратная совместимость) */
int net_http_fetch(const char *url, const char *dest_path)
{
    if (!url || !url[0]) return -1;

    char host[256] = {0};
    uint16_t port = 443;
    if (net_parse_url_host(url, host, sizeof(host), &port) < 0) return -1;

    char resolved_ip[64] = {0};
    int family = AF_INET;
    if (net_resolve_host(host, port, resolved_ip, sizeof(resolved_ip),
                         &family) < 0)
        return -1;

    return net_http_fetch_ip(url, resolved_ip, family, dest_path);
}

/* ------------------------------------------------------------------ */
/*  Async spawn: fetch и tcp_ping через fork+pipe для event loop       */
/* ------------------------------------------------------------------ */

/* Дочерняя функция для fetch: выполняется в child process */
static void child_do_fetch(const char *url, const char *dest_path,
                           int pipe_wr)
{
    int rc = net_http_fetch(url, dest_path);
    const char *msg = (rc == 0) ? "OK\n" : "ERR\n";
    write(pipe_wr, msg, strlen(msg));
    close(pipe_wr);
    _exit(0);  /* _exit: не flush stdio, не run atexit */
}

int net_spawn_fetch(const char *url, const char *dest_path)
{
    if (!url || !dest_path) return -1;

    int fds[2];
    if (pipe2(fds, O_CLOEXEC) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]); close(fds[1]); return -1;
    }
    if (pid == 0) {
        /* Дочерний процесс */
        close(fds[0]);
        /* Снять CLOEXEC с write end — он нам нужен */
        fcntl(fds[1], F_SETFD, 0);
        child_do_fetch(url, dest_path, fds[1]);
        _exit(1);  /* не достигается */
    }
    /* Родительский: закрыть write end, вернуть read end */
    close(fds[1]);
    /* Сделать read end nonblocking для epoll */
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    return fds[0];
}

/* Дочерняя функция для TCP ping */
static void child_do_tcp_ping(const char *ip, uint16_t port,
                               int timeout_ms, int pipe_wr)
{
    struct sockaddr_storage ss;
    socklen_t ss_len;
    memset(&ss, 0, sizeof(ss));

    struct sockaddr_in  *s4 = (struct sockaddr_in  *)&ss;
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;

    if (inet_pton(AF_INET, ip, &s4->sin_addr) == 1) {
        s4->sin_family = AF_INET;
        s4->sin_port   = htons(port);
        ss_len = sizeof(*s4);
    } else if (inet_pton(AF_INET6, ip, &s6->sin6_addr) == 1) {
        s6->sin6_family = AF_INET6;
        s6->sin6_port   = htons(port);
        ss_len = sizeof(*s6);
    } else {
        write(pipe_wr, "ERR\n", 4); _exit(0);
    }

    int fd = socket((int)ss.ss_family, SOCK_STREAM, 0);
    if (fd < 0) { write(pipe_wr, "ERR\n", 4); _exit(0); }

    struct timeval tv = {
        .tv_sec  = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    int rc = connect(fd, (struct sockaddr *)&ss, ss_len);
    clock_gettime(CLOCK_MONOTONIC, &t2);
    close(fd);

    if (rc < 0) {
        write(pipe_wr, "ERR\n", 4);
    } else {
        int64_t ms = (int64_t)(t2.tv_sec  - t1.tv_sec)  * 1000
                   + (int64_t)(t2.tv_nsec - t1.tv_nsec) / 1000000;
        char buf[32];
        int n = snprintf(buf, sizeof(buf), "OK %lld\n", (long long)ms);
        if (n > 0) write(pipe_wr, buf, (size_t)n);
    }
    _exit(0);
}

int net_spawn_tcp_ping(const char *ip, uint16_t port, int timeout_ms)
{
    if (!ip || !port) return -1;

    int fds[2];
    if (pipe2(fds, O_CLOEXEC) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]); close(fds[1]); return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        fcntl(fds[1], F_SETFD, 0);
        child_do_tcp_ping(ip, port, timeout_ms, fds[1]);
        _exit(1);
    }
    /* Родительский: закрыть write end, вернуть read end */
    close(fds[1]);
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    return fds[0];
}

/* UDP probe: connect + send 1 байт + poll ответ/ICMP */
static void child_do_udp_ping(const char *ip, uint16_t port,
                               int timeout_ms, int pipe_wr)
{
    struct sockaddr_storage ss;
    socklen_t ss_len;
    memset(&ss, 0, sizeof(ss));
    struct sockaddr_in  *s4 = (struct sockaddr_in  *)&ss;
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;

    if (inet_pton(AF_INET, ip, &s4->sin_addr) == 1) {
        s4->sin_family = AF_INET;
        s4->sin_port   = htons(port);
        ss_len = sizeof(*s4);
    } else if (inet_pton(AF_INET6, ip, &s6->sin6_addr) == 1) {
        s6->sin6_family = AF_INET6;
        s6->sin6_port   = htons(port);
        ss_len = sizeof(*s6);
    } else {
        write(pipe_wr, "ERR\n", 4); _exit(0);
    }

    int fd = socket((int)ss.ss_family, SOCK_DGRAM, 0);
    if (fd < 0) { write(pipe_wr, "ERR\n", 4); _exit(0); }

    /* connect() для UDP — привязывает ICMP errors к этому сокету */
    if (connect(fd, (struct sockaddr *)&ss, ss_len) < 0) {
        close(fd); write(pipe_wr, "ERR\n", 4); _exit(0);
    }

    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    send(fd, "\x00", 1, 0);

    /* Ждём ответ или ICMP error */
    struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLERR };
    int pr = poll(&pfd, 1, timeout_ms);

    clock_gettime(CLOCK_MONOTONIC, &t2);
    int64_t ms = (int64_t)(t2.tv_sec - t1.tv_sec) * 1000
               + (int64_t)(t2.tv_nsec - t1.tv_nsec) / 1000000;

    if (pr > 0) {
        /* POLLERR = ICMP unreachable → хост жив, порт ответил ICMP
         * POLLIN  = получили данные → хост жив
         * Оба случая = host reachable */
        char buf[32];
        int n = snprintf(buf, sizeof(buf), "OK %lld\n", (long long)ms);
        if (n > 0) write(pipe_wr, buf, (size_t)n);
    } else {
        /* timeout — хост недоступен или пакет отфильтрован */
        write(pipe_wr, "ERR\n", 4);
    }
    close(fd);
    _exit(0);
}

int net_spawn_udp_ping(const char *ip, uint16_t port, int timeout_ms)
{
    if (!ip || !port) return -1;

    int fds[2];
    if (pipe2(fds, O_CLOEXEC) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]); close(fds[1]); return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        fcntl(fds[1], F_SETFD, 0);
        child_do_udp_ping(ip, port, timeout_ms, fds[1]);
        _exit(1);
    }
    close(fds[1]);
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    return fds[0];
}

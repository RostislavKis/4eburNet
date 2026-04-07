/*
 * Rule providers — загрузка правил по URL или из файла
 * Кэширование на диске, периодическое обновление
 */

#include "proxy/rule_provider.h"
#include "crypto/tls.h"
#include "net_utils.h"
#include "phoenix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* Создать директорию для файла (H-3: по dirname, не по самому пути) */
static void ensure_dir_for_file(const char *filepath)
{
    char dir[256];
    snprintf(dir, sizeof(dir), "%s", filepath);
    char *slash = strrchr(dir, '/');
    if (!slash) return;
    *slash = '\0';

    /* Рекурсивно создаём промежуточные каталоги */
    for (char *p = dir + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(dir, 0755);
            *p = '/';
        }
    }
    mkdir(dir, 0755);
}

int rule_provider_init(rule_provider_manager_t *rpm, const PhoenixConfig *cfg)
{
    memset(rpm, 0, sizeof(*rpm));
    rpm->cfg = cfg;
    if (cfg->rule_provider_count == 0) return 0;

    rpm->providers = calloc(cfg->rule_provider_count,
                            sizeof(rule_provider_state_t));
    if (!rpm->providers) return -1;
    rpm->count = cfg->rule_provider_count;

    for (int i = 0; i < rpm->count; i++) {
        const RuleProviderConfig *rc = &cfg->rule_providers[i];
        rule_provider_state_t *ps = &rpm->providers[i];

        snprintf(ps->name, sizeof(ps->name), "%s", rc->name);

        if (rc->path[0]) {
            snprintf(ps->cache_path, sizeof(ps->cache_path), "%s", rc->path);
        } else {
            snprintf(ps->cache_path, sizeof(ps->cache_path),
                     "/etc/phoenix/rules/%s.list", rc->name);
        }
        ensure_dir_for_file(ps->cache_path);

        ps->next_update = time(NULL) + (rc->interval > 0 ? rc->interval : 86400);
    }

    log_msg(LOG_INFO, "Rule providers: %d загружено", rpm->count);
    return 0;
}

void rule_provider_free(rule_provider_manager_t *rpm)
{
    free(rpm->providers);
    memset(rpm, 0, sizeof(*rpm));
}

/* HTTP загрузка файла правил через TLS */
static int http_fetch(const char *url, const char *dest_path)
{
    if (!url || !url[0]) return -1;

    /* Определить схему и порт по умолчанию */
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

    /* Найти :port в host (напр. "1.2.3.4:8443") */
    char *colon = strchr(host, ':');
    if (colon) {
        char *endptr;
        long p = strtol(colon + 1, &endptr, 10);
        if (endptr != colon + 1 && *endptr == '\0' && p > 0 && p <= 65535)
            port = (uint16_t)p;
        *colon = '\0';  /* убрать :port из host */
    }

    /* DEC-027: getaddrinfo — поддержка доменных имён (не только IP) */
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints = {0};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    /* DEC-031: getaddrinfo() блокирует event loop при DNS timeout.
       При недоступном DNS сервере (ТСПУ block) — freeze до 30 сек.
       Решение: async DNS через dns_resolver.c в 4.x. */
    int gai = getaddrinfo(host, port_str, &hints, &res);
    if (gai != 0) {
        log_msg(LOG_WARN, "Rule provider: не удалось резолвить '%s': %s",
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

    /* HTTP GET */
    char req[1024];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
        path, host);
    tls_send(&tls, req, req_len);

    /* Atomic tmpfile через mkstemp (C-5: избегаем TOCTOU) */
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
            /* M-3: NUL-terminate буфер перед strstr */
            size_t safe_n = (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf) - 1;
            buf[safe_n] = '\0';

            for (ssize_t j = 0; j < n - 3; j++) {
                if (buf[j]=='\r' && buf[j+1]=='\n' && buf[j+2]=='\r' && buf[j+3]=='\n') {
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

    /* Atomic rename */
    rename(tmppath, dest_path);
    log_msg(LOG_INFO, "Rule provider: загружен %s (%zd байт)", dest_path, total);
    return 0;
}

/* Подсчитать строки в файле (не пустые, не комментарии) */
static int count_rules(const char *path)
{
    /* L-03: O_CLOEXEC */
    int cfd = open(path, O_RDONLY | O_CLOEXEC);
    FILE *f = (cfd >= 0) ? fdopen(cfd, "r") : NULL;
    if (!f) { if (cfd >= 0) close(cfd); return 0; }
    int count = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len > 0 && line[0] != '#') count++;
    }
    fclose(f);
    return count;
}

int rule_provider_load_all(rule_provider_manager_t *rpm)
{
    for (int i = 0; i < rpm->count; i++) {
        rule_provider_state_t *ps = &rpm->providers[i];
        const RuleProviderConfig *rc = &rpm->cfg->rule_providers[i];

        /* Проверить кэш на диске */
        struct stat st;
        if (stat(ps->cache_path, &st) == 0) {
            ps->loaded = true;
            ps->rule_count = count_rules(ps->cache_path);
            ps->last_update = st.st_mtime;
            log_msg(LOG_DEBUG, "Provider %s: кэш %d правил", ps->name, ps->rule_count);
            continue;
        }

        /* Нет кэша — попробовать загрузить */
        if (rc->type == RULE_PROVIDER_HTTP && rc->url[0]) {
            if (http_fetch(rc->url, ps->cache_path) == 0) {
                ps->loaded = true;
                ps->rule_count = count_rules(ps->cache_path);
                ps->last_update = time(NULL);
            } else {
                log_msg(LOG_WARN, "Provider %s: загрузка провалилась", ps->name);
            }
        }
    }
    return 0;
}

/* H-04: максимум 1 провайдер за вызов — не блокируем event loop */
void rule_provider_tick(rule_provider_manager_t *rpm)
{
    time_t now = time(NULL);
    for (int i = 0; i < rpm->count; i++) {
        rule_provider_state_t *ps = &rpm->providers[i];
        const RuleProviderConfig *rc = &rpm->cfg->rule_providers[i];

        if (!rc->enabled || rc->interval <= 0) continue;
        if (now < ps->next_update) continue;

        ps->next_update = now + rc->interval;

        if (rc->type == RULE_PROVIDER_HTTP && rc->url[0]) {
            if (http_fetch(rc->url, ps->cache_path) == 0) {
                ps->loaded = true;
                ps->rule_count = count_rules(ps->cache_path);
                ps->last_update = now;
                log_msg(LOG_INFO, "Provider %s: обновлён (%d правил)",
                        ps->name, ps->rule_count);
            }
        }
        return;  /* только один провайдер за вызов */
    }
}

int rule_provider_update(rule_provider_manager_t *rpm, const char *name)
{
    for (int i = 0; i < rpm->count; i++) {
        if (strcmp(rpm->providers[i].name, name) != 0) continue;
        const RuleProviderConfig *rc = &rpm->cfg->rule_providers[i];
        rule_provider_state_t *ps = &rpm->providers[i];

        if (rc->type == RULE_PROVIDER_HTTP && rc->url[0]) {
            if (http_fetch(rc->url, ps->cache_path) == 0) {
                ps->loaded = true;
                ps->rule_count = count_rules(ps->cache_path);
                ps->last_update = time(NULL);
                return 0;
            }
        }
        return -1;
    }
    return -1;
}

int rule_provider_to_json(const rule_provider_manager_t *rpm,
                          char *buf, size_t buflen)
{
    if (!buflen) return 0;
    int pos = 0;

    /* H-01: guard — snprintf только если есть место */
#define JS(fmt, ...) do { \
    if ((size_t)pos < buflen - 1) \
        pos += snprintf(buf + pos, buflen - (size_t)pos, fmt, ##__VA_ARGS__); \
} while(0)

    JS("{\"providers\":[");
    for (int i = 0; i < rpm->count && (size_t)pos < buflen - 1; i++) {
        const rule_provider_state_t *ps = &rpm->providers[i];
        if (i > 0) JS(",");
        char esc_name[128];
        json_escape_str(ps->name, esc_name, sizeof(esc_name));
        JS("{\"name\":\"%s\",\"loaded\":%s,\"rules\":%d,"
            "\"last_update\":%ld,\"next_update\":%ld}",
            esc_name, ps->loaded ? "true" : "false", ps->rule_count,
            (long)ps->last_update, (long)ps->next_update);
    }
    JS("]}");
#undef JS
    return pos;
}

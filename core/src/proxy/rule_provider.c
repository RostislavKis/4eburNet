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

/*
 * Разрешить хост из URL в IP (один раз), затем скачать по кэшированному IP.
 * Если resolved_ip пустой — выполняет net_resolve_host (блокирует один раз).
 * При последующих вызовах использует кэш → 0мс getaddrinfo.
 */
static int fetch_with_ip_cache(const char *url, const char *cache_path,
                                char *resolved_ip, size_t ip_size,
                                int *resolved_family)
{
    if (!resolved_ip[0]) {
        char h[256] = {0};
        uint16_t p = 443;
        net_parse_url_host(url, h, sizeof(h), &p);
        if (h[0])
            net_resolve_host(h, p, resolved_ip, ip_size, resolved_family);
    }
    if (!resolved_ip[0]) {
        log_msg(LOG_WARN, "fetch_with_ip_cache: не удалось резолвить хост из %s",
                url);
        return -1;
    }
    return net_http_fetch_ip(url, resolved_ip, *resolved_family, cache_path);
}

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
    for (int i = 0; i < rpm->count; i++)
        rpm->providers[i].resolved_family = AF_INET;

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
            if (fetch_with_ip_cache(rc->url, ps->cache_path,
                                    ps->resolved_ip, sizeof(ps->resolved_ip),
                                    &ps->resolved_family) == 0) {
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
            if (fetch_with_ip_cache(rc->url, ps->cache_path,
                                    ps->resolved_ip, sizeof(ps->resolved_ip),
                                    &ps->resolved_family) == 0) {
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
            if (fetch_with_ip_cache(rc->url, ps->cache_path,
                                    ps->resolved_ip, sizeof(ps->resolved_ip),
                                    &ps->resolved_family) == 0) {
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

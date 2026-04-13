/*
 * Proxy groups — выбор сервера по политике
 * SELECT / URL_TEST / FALLBACK / LOAD_BALANCE
 */

#include "proxy/proxy_group.h"
#include "net_utils.h"
#include "4eburnet.h"
#include "constants.h"
#include "resource_manager.h"
#include <regex.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <limits.h>

/* Найти индекс сервера по имени в cfg->servers[] */
static int find_server_by_name(const EburNetConfig *cfg, const char *name)
{
    for (int i = 0; i < cfg->server_count; i++)
        if (strcmp(cfg->servers[i].name, name) == 0)
            return i;
    return -1;
}

int proxy_group_init(proxy_group_manager_t *pgm, const EburNetConfig *cfg)
{
    memset(pgm, 0, sizeof(*pgm));
    pgm->cfg = cfg;
    if (cfg->proxy_group_count == 0) return 0;

    /* M-07: считаем только enabled группы */
    int enabled = 0;
    for (int g = 0; g < cfg->proxy_group_count; g++)
        if (cfg->proxy_groups[g].enabled) enabled++;
    if (enabled == 0) return 0;

    pgm->groups = calloc(enabled, sizeof(proxy_group_state_t));
    if (!pgm->groups) return -1;

    for (int g = 0; g < cfg->proxy_group_count; g++) {
        const ProxyGroupConfig *gc = &cfg->proxy_groups[g];
        if (!gc->enabled) continue;
        proxy_group_state_t *gs = &pgm->groups[pgm->count];

        {   int _n = snprintf(gs->name, sizeof(gs->name), "%s", gc->name);
            if (_n < 0 || (size_t)_n >= sizeof(gs->name))
                log_msg(LOG_DEBUG, "snprintf truncated (non-critical): %s:%d", __FILE__, __LINE__);
        }
        gs->type = gc->type;
        {   int _n = snprintf(gs->test_url, sizeof(gs->test_url), "%s", gc->url);
            if (_n < 0 || (size_t)_n >= sizeof(gs->test_url))
                log_msg(LOG_DEBUG, "snprintf truncated (non-critical): %s:%d", __FILE__, __LINE__);
        }
        gs->timeout_ms = gc->timeout_ms > 0 ? gc->timeout_ms : 5000;
        /* Ограничить таймаут по профилю — защита event loop */
        {
            int max_ms;
            DeviceProfile prof = rm_detect_profile();
            switch (prof) {
            case DEVICE_MICRO:   max_ms = 1000; break;
            case DEVICE_NORMAL:  max_ms = 2000; break;
            default:             max_ms = 5000; break;
            }
            if (gs->timeout_ms > max_ms) {
                log_msg(LOG_WARN,
                    "proxy_group[%s]: timeout_ms %d > лимита %d, обрезан",
                    gs->name, gs->timeout_ms, max_ms);
                gs->timeout_ms = max_ms;
            }
        }
        gs->tolerance_ms = gc->tolerance_ms;
        gs->interval = gc->interval > 0 ? gc->interval : 300;
        gs->next_check = time(NULL) + TIMEOUT_HEALTH_FIRST_SEC;

        /* Итерировать массив серверов группы */
        int total_configured = 0;
        for (int si = 0; si < gc->server_count; si++) {
            const char *tok = gc->servers[si];
            int idx = find_server_by_name(cfg, tok);
            if (idx >= 0) {
                if (gs->server_count < PROXY_GROUP_MAX_SERVERS) {
                    gs->servers[gs->server_count].server_idx = idx;
                    gs->servers[gs->server_count].available = false;
                    gs->servers[gs->server_count].latency_ms = 0;
                    gs->server_count++;
                } else if (total_configured == PROXY_GROUP_MAX_SERVERS) {
                    log_msg(LOG_WARN,
                        "Группа %s: превышен лимит %d серверов",
                        gs->name, PROXY_GROUP_MAX_SERVERS);
                }
                total_configured++;
            } else {
                log_msg(LOG_WARN, "Группа %s: сервер '%s' не найден", gs->name, tok);
            }
        }

        /* Добавить серверы из провайдеров (use: + filter) */
        if (gc->providers && gc->providers[0]) {
            /* Filter: попытаться POSIX ERE, fallback на exclude-list */
            regex_t fre;
            bool use_regex = false;
            bool use_exclude = false;
            char *exclude_words[64];
            int exclude_count = 0;

            memset(exclude_words, 0, sizeof(exclude_words));

            if (gc->filter[0]) {
                if (regcomp(&fre, gc->filter, REG_EXTENDED | REG_NOSUB) == 0) {
                    use_regex = true;
                } else {
                    /* Fallback: извлечь exclude-слова из (?!.*(w1|w2|...))
                     * Ищем самую внутреннюю группу (w1|w2|...) и split по | */
                    const char *inner = NULL;
                    int depth = 0, max_depth = 0;
                    for (const char *p = gc->filter; *p; p++) {
                        if (*p == '(') {
                            depth++;
                            if (depth > max_depth) {
                                max_depth = depth;
                                inner = p + 1;
                            }
                        } else if (*p == ')') {
                            depth--;
                        }
                    }
                    if (inner) {
                        /* Копируем содержимое внутренних скобок, split по | */
                        const char *end = strchr(inner, ')');
                        if (!end) end = inner + strlen(inner);
                        size_t ilen = (size_t)(end - inner);
                        char *ibuf = malloc(ilen + 1);
                        if (ibuf) {
                            memcpy(ibuf, inner, ilen);
                            ibuf[ilen] = '\0';
                            char *sp2 = NULL;
                            for (char *w = strtok_r(ibuf, "|", &sp2); w;
                                 w = strtok_r(NULL, "|", &sp2)) {
                                if (w[0] && exclude_count < 64)
                                    exclude_words[exclude_count++] = strdup(w);
                            }
                            free(ibuf);
                        }
                    }
                    if (exclude_count > 0) {
                        use_exclude = true;
                        log_msg(LOG_DEBUG, "Группа %s: filter → %d exclude слов",
                                gc->name, exclude_count);
                    }
                }
            }

            char *pcopy = strdup(gc->providers);
            if (!pcopy) {
                log_msg(LOG_ERROR, "proxy_group: нет памяти для providers copy");
                continue;
            }
            char *sp = NULL;
            for (char *pn = strtok_r(pcopy, " ", &sp); pn;
                 pn = strtok_r(NULL, " ", &sp)) {
                for (int pi = 0; pi < cfg->provider_server_count; pi++) {
                    const ServerConfig *ps = &cfg->provider_servers[pi];
                    if (strcmp(ps->source_provider, pn) != 0) continue;
                    /* Применить filter */
                    if (use_regex &&
                        regexec(&fre, ps->name, 0, NULL, 0) != 0) continue;
                    if (use_exclude) {
                        bool excluded = false;
                        for (int ei = 0; ei < exclude_count; ei++) {
                            if (strstr(ps->name, exclude_words[ei])) {
                                excluded = true; break;
                            }
                        }
                        if (excluded) continue;
                    }
                    if (gs->server_count >= PROXY_GROUP_MAX_SERVERS) break;
                    gs->servers[gs->server_count].server_idx =
                        cfg->server_count + pi;
                    gs->servers[gs->server_count].available = false;
                    gs->servers[gs->server_count].latency_ms = 0;
                    gs->server_count++;
                }
            }
            free(pcopy);
            if (use_regex) regfree(&fre);
            for (int ei = 0; ei < exclude_count; ei++) free(exclude_words[ei]);
        }

        gs->hc_pipe_fd    = -1;
        gs->hc_server_idx = -1;
        gs->hc_registered = false;

        log_msg(LOG_DEBUG, "Группа %s: тип %d, %d серверов",
                gs->name, gs->type, gs->server_count);
        pgm->count++;
    }

    log_msg(LOG_INFO, "Proxy groups: %d загружено", pgm->count);
    return 0;
}

void proxy_group_free(proxy_group_manager_t *pgm)
{
    for (int i = 0; i < pgm->count; i++) {
        if (pgm->groups[i].hc_pipe_fd >= 0) {
            close(pgm->groups[i].hc_pipe_fd);
            pgm->groups[i].hc_pipe_fd = -1;
        }
    }
    free(pgm->groups);
    memset(pgm, 0, sizeof(*pgm));
}

proxy_group_state_t *proxy_group_find(proxy_group_manager_t *pgm, const char *name)
{
    for (int i = 0; i < pgm->count; i++)
        if (strcmp(pgm->groups[i].name, name) == 0)
            return &pgm->groups[i];
    return NULL;
}

int proxy_group_select_server(proxy_group_manager_t *pgm, const char *group_name)
{
    proxy_group_state_t *g = proxy_group_find(pgm, group_name);
    if (!g || g->server_count == 0) return -1;

    switch (g->type) {
    case PROXY_GROUP_SELECT:
        if (g->selected_idx >= 0 && g->selected_idx < g->server_count)
            return g->servers[g->selected_idx].server_idx;
        return g->servers[0].server_idx;

    case PROXY_GROUP_URL_TEST: {
        int best = -1;
        uint32_t best_lat = UINT32_MAX;
        for (int i = 0; i < g->server_count; i++) {
            if (!g->servers[i].available) continue;
            if (g->servers[i].latency_ms < best_lat) {
                best_lat = g->servers[i].latency_ms;
                best = i;
            }
        }
        return best >= 0 ? g->servers[best].server_idx : g->servers[0].server_idx;
    }

    case PROXY_GROUP_FALLBACK:
        for (int i = 0; i < g->server_count; i++)
            if (g->servers[i].available)
                return g->servers[i].server_idx;
        return g->servers[0].server_idx;

    case PROXY_GROUP_LOAD_BALANCE: {
        int avail = 0;
        for (int i = 0; i < g->server_count; i++)
            if (g->servers[i].available) avail++;
        if (avail == 0) return g->servers[0].server_idx;
        int target = g->rr_idx % avail;
        g->rr_idx++;
        int count = 0;
        for (int i = 0; i < g->server_count; i++) {
            if (!g->servers[i].available) continue;
            if (count == target) return g->servers[i].server_idx;
            count++;
        }
        return g->servers[0].server_idx;
    }
    }

    return -1;
}

void proxy_group_update_result(proxy_group_manager_t *pgm,
                               const char *group_name,
                               int server_idx, bool success,
                               uint32_t latency_ms)
{
    proxy_group_state_t *g = proxy_group_find(pgm, group_name);
    if (!g) return;
    for (int i = 0; i < g->server_count; i++) {
        if (g->servers[i].server_idx != server_idx) continue;
        if (success) {
            g->servers[i].available = true;
            g->servers[i].latency_ms = latency_ms;
            g->servers[i].fail_count = 0;
        } else {
            g->servers[i].fail_count++;
            if (g->servers[i].fail_count >= 3)
                g->servers[i].available = false;
        }
        g->servers[i].last_check = time(NULL);
        return;
    }
}

/* H-1: неблокирующий health-check — максимум 1 группа, 1 сервер за tick.
 * При 3 группах × 3 сервера × 5с таймаут = 5с блок вместо 45с. */
/*
 * Health-check один сервер за вызов (round-robin cursor).
 * Почему по одному: fork() для TCP/UDP ping блокирует на timeout_ms,
 * проверка всех серверов разом создаст N форков одновременно.
 */
void proxy_group_tick(proxy_group_manager_t *pgm)
{
    time_t now = time(NULL);
    for (int g = 0; g < pgm->count; g++) {
        proxy_group_state_t *gs = &pgm->groups[g];
        if (now < gs->next_check) continue;
        if (gs->type == PROXY_GROUP_SELECT) {
            gs->next_check = now + gs->interval;
            continue;
        }
        if (gs->server_count == 0) {
            gs->next_check = now + gs->interval;
            continue;
        }

        /* Проверяем один сервер (по cursor).
         * Если уже идёт async проверка этой группы — пропустить. */
        if (gs->hc_pipe_fd >= 0) return;

        int i = gs->check_cursor % gs->server_count;
        int idx = gs->servers[i].server_idx;
        const ServerConfig *srv = config_get_server(pgm->cfg, idx);
        if (srv) {
            /* UDP-протоколы (AWG, Hysteria2) — UDP probe вместо TCP */
            bool udp_proto = (strcmp(srv->protocol, "awg") == 0 ||
                              strcmp(srv->protocol, "hysteria2") == 0);
            int pfd = udp_proto
                ? net_spawn_udp_ping(srv->address, srv->port, gs->timeout_ms)
                : net_spawn_tcp_ping(srv->address, srv->port, gs->timeout_ms);
            if (pfd >= 0) {
                gs->hc_pipe_fd    = pfd;
                gs->hc_server_idx = i;
                gs->hc_registered = false;
                gs->servers[i].last_check = now;
                /* pipe fd зарегистрируется в epoll из main loop */
            }
        }
        /* cursor и таймер обновляются после получения результата */
        return;  /* только одна группа за tick */
    }
}

void proxy_group_handle_hc_event(proxy_group_state_t *gs,
                                  int fd, uint32_t events)
{
    if (fd != gs->hc_pipe_fd) return;
    (void)events;

    char buf[32] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);

    close(gs->hc_pipe_fd);
    gs->hc_pipe_fd    = -1;
    gs->hc_registered = false;

    int i = gs->hc_server_idx;
    gs->hc_server_idx = -1;

    if (i < 0 || i >= gs->server_count)
        return;

    if (n > 0) {
        buf[n] = '\0';
        if (strncmp(buf, "OK", 2) == 0) {
            long long ms = 0;
            sscanf(buf, "OK %lld", &ms);
            gs->servers[i].latency_ms  = (uint32_t)ms;
            gs->servers[i].available   = true;
            gs->servers[i].fail_count  = 0;
            log_msg(LOG_DEBUG, "proxy_group[%s] server[%d] latency=%lldms",
                    gs->name, i, ms);
        } else {
            gs->servers[i].fail_count++;
            if (gs->servers[i].fail_count >= 3)
                gs->servers[i].available = false;
            log_msg(LOG_DEBUG, "proxy_group[%s] server[%d] недоступен",
                    gs->name, i);
        }
    }

    /* Сдвинуть cursor и при необходимости сбросить таймер */
    gs->check_cursor++;
    if (gs->server_count > 0 &&
        gs->check_cursor % gs->server_count == 0)
        gs->next_check = time(NULL) + gs->interval;
}

bool proxy_group_owns_fd(const proxy_group_state_t *gs, int fd)
{
    return gs->hc_pipe_fd == fd;
}

int proxy_group_select_manual(proxy_group_manager_t *pgm,
                              const char *group_name, int server_idx)
{
    proxy_group_state_t *g = proxy_group_find(pgm, group_name);
    if (!g || g->type != PROXY_GROUP_SELECT) return -1;
    for (int i = 0; i < g->server_count; i++) {
        if (g->servers[i].server_idx == server_idx) {
            g->selected_idx = i;
            return 0;
        }
    }
    return -1;
}

int proxy_group_to_json(const proxy_group_manager_t *pgm,
                        char *buf, size_t buflen)
{
    if (!buflen) return 0;
    int pos = 0;

    /* H-01: guard — snprintf только если есть место */
#define JS(fmt, ...) do { \
    if ((size_t)pos < buflen - 1) \
        pos += snprintf(buf + pos, buflen - (size_t)pos, fmt, ##__VA_ARGS__); \
} while(0)

    JS("{\"groups\":[");
    for (int g = 0; g < pgm->count && (size_t)pos < buflen - 1; g++) {
        const proxy_group_state_t *gs = &pgm->groups[g];
        if (g > 0) JS(",");
        char esc_name[128];
        json_escape_str(gs->name, esc_name, sizeof(esc_name));
        JS("{\"name\":\"%s\",\"type\":%d,\"selected\":%d,\"servers\":[",
            esc_name, gs->type, gs->selected_idx);
        for (int i = 0; i < gs->server_count && (size_t)pos < buflen - 1; i++) {
            if (i > 0) JS(",");
            JS("{\"idx\":%d,\"available\":%s,\"latency\":%u,\"fails\":%u}",
                gs->servers[i].server_idx,
                gs->servers[i].available ? "true" : "false",
                gs->servers[i].latency_ms,
                gs->servers[i].fail_count);
        }
        JS("]}");
    }
    JS("]}");
#undef JS
    return pos;
}

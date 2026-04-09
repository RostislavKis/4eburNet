/*
 * Proxy groups — выбор сервера по политике
 * SELECT / URL_TEST / FALLBACK / LOAD_BALANCE
 */

#include "proxy/proxy_group.h"
#include "net_utils.h"
#include "phoenix.h"
#include "resource_manager.h"

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

/* Найти индекс сервера по имени в cfg->servers[] */
static int find_server_by_name(const PhoenixConfig *cfg, const char *name)
{
    for (int i = 0; i < cfg->server_count; i++)
        if (strcmp(cfg->servers[i].name, name) == 0)
            return i;
    return -1;
}

int proxy_group_init(proxy_group_manager_t *pgm, const PhoenixConfig *cfg)
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

        snprintf(gs->name, sizeof(gs->name), "%s", gc->name);
        gs->type = gc->type;
        snprintf(gs->test_url, sizeof(gs->test_url), "%s", gc->url);
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
        gs->next_check = time(NULL) + gs->interval;

        /* Парсить список серверов (M-5: strtok_r вместо strtok) */
        char buf[512];
        snprintf(buf, sizeof(buf), "%s", gc->servers);
        char *saveptr = NULL;
        char *tok = strtok_r(buf, " ", &saveptr);
        while (tok && gs->server_count < PROXY_GROUP_MAX_SERVERS) {
            int idx = find_server_by_name(cfg, tok);
            if (idx >= 0) {
                gs->servers[gs->server_count].server_idx = idx;
                gs->servers[gs->server_count].available = true;
                gs->servers[gs->server_count].latency_ms = 999;
                gs->server_count++;
            } else {
                log_msg(LOG_WARN, "Группа %s: сервер '%s' не найден", gs->name, tok);
            }
            tok = strtok_r(NULL, " ", &saveptr);
        }

        log_msg(LOG_DEBUG, "Группа %s: тип %d, %d серверов",
                gs->name, gs->type, gs->server_count);
        pgm->count++;
    }

    log_msg(LOG_INFO, "Proxy groups: %d загружено", pgm->count);
    return 0;
}

void proxy_group_free(proxy_group_manager_t *pgm)
{
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

/* Latency test: TCP connect RTT, поддержка IPv4 + IPv6 (V6-07) */
static uint32_t measure_latency(const char *ip, uint16_t port, int timeout_ms)
{
    /* Определить семейство адреса */
    struct sockaddr_storage ss;
    socklen_t ss_len;
    memset(&ss, 0, sizeof(ss));

    struct sockaddr_in  *s4 = (struct sockaddr_in  *)&ss;
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;

    if (inet_pton(AF_INET, ip, &s4->sin_addr) == 1) {
        s4->sin_family = AF_INET;
        s4->sin_port   = htons(port);
        ss_len = sizeof(struct sockaddr_in);
    } else if (inet_pton(AF_INET6, ip, &s6->sin6_addr) == 1) {
        s6->sin6_family = AF_INET6;
        s6->sin6_port   = htons(port);
        ss_len = sizeof(struct sockaddr_in6);
    } else {
        log_msg(LOG_WARN, "measure_latency: невалидный IP: %s", ip);
        return 0;
    }

    int fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 0;

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

    if (rc < 0) return 0;

    uint32_t ms = (uint32_t)(
        (t2.tv_sec  - t1.tv_sec)  * 1000 +
        (t2.tv_nsec - t1.tv_nsec) / 1000000);
    return ms > 0 ? ms : 1;
}

/* H-1: неблокирующий health-check — максимум 1 группа, 1 сервер за tick.
 * При 3 группах × 3 сервера × 5с таймаут = 5с блок вместо 45с. */
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

        /* Проверяем один сервер (по cursor) */
        int i = gs->check_cursor % gs->server_count;
        int idx = gs->servers[i].server_idx;
        if (idx >= 0 && idx < pgm->cfg->server_count) {
            const ServerConfig *srv = &pgm->cfg->servers[idx];
            uint32_t lat = measure_latency(srv->address, srv->port,
                                           gs->timeout_ms);
            gs->servers[i].available = (lat > 0);
            gs->servers[i].latency_ms = lat;
            gs->servers[i].last_check = now;
            if (lat == 0) gs->servers[i].fail_count++;
            else gs->servers[i].fail_count = 0;
        }

        gs->check_cursor++;
        /* Обход завершён — сбросить таймер */
        if (gs->check_cursor % gs->server_count == 0)
            gs->next_check = now + gs->interval;

        return;  /* только одна группа за tick */
    }
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

#ifndef RULE_PROVIDER_H
#define RULE_PROVIDER_H

#include "config.h"
#include <time.h>

typedef struct {
    char   name[64];
    char   cache_path[256];
    time_t last_update;
    time_t next_update;
    int    rule_count;
    bool   loaded;
    char   resolved_ip[64];  /* кэшированный IP хоста URL (inet_pton fast path) */
    int    resolved_family;  /* AF_INET или AF_INET6 */
    /* Async fetch state (audit_v9) */
    int    fetch_pipe_fd;    /* read end pipe, -1 = нет активного fetch */
    bool   fetch_registered; /* pipe fd уже в epoll */
    time_t fetch_started;    /* для timeout */
} rule_provider_state_t;

typedef struct {
    rule_provider_state_t *providers;
    int                    count;
    const PhoenixConfig   *cfg;
} rule_provider_manager_t;

int  rule_provider_init(rule_provider_manager_t *rpm, const PhoenixConfig *cfg);
void rule_provider_free(rule_provider_manager_t *rpm);
int  rule_provider_load_all(rule_provider_manager_t *rpm);
void rule_provider_tick(rule_provider_manager_t *rpm);
int  rule_provider_update(rule_provider_manager_t *rpm, const char *name);
int  rule_provider_to_json(const rule_provider_manager_t *rpm, char *buf, size_t buflen);

/* Обработать готовность pipe от fetch subprocess */
void rule_provider_handle_fetch(rule_provider_manager_t *rpm,
                                 int fd, uint32_t events);
bool rule_provider_owns_fd(const rule_provider_manager_t *rpm, int fd);

#endif

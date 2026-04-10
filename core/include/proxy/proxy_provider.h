#ifndef PROXY_PROVIDER_H
#define PROXY_PROVIDER_H

#include "config.h"
#include "device.h"

/* Состояние одного proxy-provider */
typedef struct {
    char     name[64];
    char     cache_path[256];
    bool     loaded;
    int      server_count;   /* сколько серверов загружено */
    time_t   last_update;
    time_t   next_update;
    int      first_idx;      /* индекс первого сервера в
                                cfg->provider_servers[] */
    char     resolved_ip[64];  /* кэшированный IP хоста URL */
    int      resolved_family;  /* AF_INET или AF_INET6 */
    /* Async fetch state (audit_v9) */
    int      fetch_pipe_fd;    /* read end pipe, -1 = нет активного fetch */
    bool     fetch_registered; /* pipe fd уже в epoll */
    time_t   fetch_started;    /* для timeout */
} proxy_provider_state_t;

typedef struct {
    proxy_provider_state_t *providers;
    int                     count;
    int                     round_robin;  /* индекс следующего провайдера для tick */
    EburNetConfig          *cfg;   /* не const — меняем provider_servers */
} proxy_provider_manager_t;

int  proxy_provider_init(proxy_provider_manager_t *ppm,
                          EburNetConfig *cfg);
void proxy_provider_free(proxy_provider_manager_t *ppm);
int  proxy_provider_load_all(proxy_provider_manager_t *ppm);

/* Один провайдер за вызов — вызывается из main loop каждые 30с */
void proxy_provider_tick(proxy_provider_manager_t *ppm);

/* Максимум серверов из провайдера по профилю */
int  proxy_provider_max_servers(DeviceProfile profile,
                                 int configured_max);

/* Обработать готовность pipe от fetch subprocess */
void proxy_provider_handle_fetch(proxy_provider_manager_t *ppm,
                                  int fd, uint32_t events);
bool proxy_provider_owns_fd(const proxy_provider_manager_t *ppm, int fd);

#endif /* PROXY_PROVIDER_H */

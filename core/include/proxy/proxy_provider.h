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
} proxy_provider_state_t;

typedef struct {
    proxy_provider_state_t *providers;
    int                     count;
    PhoenixConfig          *cfg;   /* не const — меняем provider_servers */
} proxy_provider_manager_t;

int  proxy_provider_init(proxy_provider_manager_t *ppm,
                          PhoenixConfig *cfg);
void proxy_provider_free(proxy_provider_manager_t *ppm);
int  proxy_provider_load_all(proxy_provider_manager_t *ppm);

/* Один провайдер за вызов — вызывается из main loop каждые 30с */
void proxy_provider_tick(proxy_provider_manager_t *ppm);

/* Максимум серверов из провайдера по профилю */
int  proxy_provider_max_servers(DeviceProfile profile,
                                 int configured_max);

#endif /* PROXY_PROVIDER_H */

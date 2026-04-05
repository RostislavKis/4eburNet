#ifndef PROXY_GROUP_H
#define PROXY_GROUP_H

#include "config.h"
#include <time.h>

#define PROXY_GROUP_MAX_SERVERS 32

typedef struct {
    int      server_idx;
    bool     available;
    uint32_t latency_ms;
    uint32_t fail_count;
    time_t   last_check;
} group_server_state_t;

typedef struct {
    char                  name[64];
    proxy_group_type_t    type;
    group_server_state_t  servers[PROXY_GROUP_MAX_SERVERS];
    int                   server_count;
    int                   selected_idx;
    int                   rr_idx;
    int                   check_cursor;   /* H-1: позиция для неблокирующего health-check */
    time_t                next_check;
    char                  test_url[512];
    int                   timeout_ms;
    int                   tolerance_ms;
    int                   interval;
} proxy_group_state_t;

typedef struct {
    proxy_group_state_t *groups;
    int                  count;
    const PhoenixConfig *cfg;
} proxy_group_manager_t;

int  proxy_group_init(proxy_group_manager_t *pgm, const PhoenixConfig *cfg);
void proxy_group_free(proxy_group_manager_t *pgm);

proxy_group_state_t *proxy_group_find(proxy_group_manager_t *pgm, const char *name);
int  proxy_group_select_server(proxy_group_manager_t *pgm, const char *group_name);
void proxy_group_update_result(proxy_group_manager_t *pgm,
                               const char *group_name,
                               int server_idx, bool success, uint32_t latency_ms);
void proxy_group_tick(proxy_group_manager_t *pgm);
int  proxy_group_to_json(const proxy_group_manager_t *pgm, char *buf, size_t buflen);
int  proxy_group_select_manual(proxy_group_manager_t *pgm,
                               const char *group_name, int server_idx);

#endif

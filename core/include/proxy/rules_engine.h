#ifndef RULES_ENGINE_H
#define RULES_ENGINE_H

#include "config.h"
#include "proxy/proxy_group.h"
#include "proxy/rule_provider.h"
#include "geo/geo_loader.h"
#include <sys/socket.h>

typedef enum {
    RULE_TARGET_GROUP  = 0,
    RULE_TARGET_DIRECT = 1,
    RULE_TARGET_REJECT = 2,
} rule_target_type_t;

typedef struct {
    rule_target_type_t type;
    char               group_name[64];
} rule_match_result_t;

typedef struct rules_engine {
    const EburNetConfig      *cfg;
    proxy_group_manager_t    *pgm;
    rule_provider_manager_t  *rpm;
    geo_manager_t            *gm;   /* NULL если geo не инициализирован */
    /* Сортированные правила (по priority ASC) */
    TrafficRule              *sorted_rules;
    int                       rule_count;
} rules_engine_t;

int  rules_engine_init(rules_engine_t *re, const EburNetConfig *cfg,
                       proxy_group_manager_t *pgm,
                       rule_provider_manager_t *rpm,
                       geo_manager_t *gm);
void rules_engine_free(rules_engine_t *re);

/* Определить target: domain может быть NULL */
rule_match_result_t rules_engine_match(rules_engine_t *re,
                                       const char *domain,
                                       const struct sockaddr_storage *dst);

/* Получить server_idx: >=0 OK, -1=DIRECT, -2=REJECT */
int rules_engine_get_server(rules_engine_t *re,
                            const char *domain,
                            const struct sockaddr_storage *dst);

#endif

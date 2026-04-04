#ifndef DNS_RULES_H
#define DNS_RULES_H

#include "config.h"

typedef enum {
    DNS_ACTION_BYPASS  = 0,
    DNS_ACTION_PROXY   = 1,
    DNS_ACTION_BLOCK   = 2,
    DNS_ACTION_DEFAULT = 3,
} dns_action_t;

int  dns_rules_init(const PhoenixConfig *cfg);
void dns_rules_free(void);

/* Определить действие для домена */
dns_action_t dns_rules_match(const char *qname);

/* Загрузить домены из файла */
int dns_rules_load_file(const char *path, dns_action_t action);

#endif /* DNS_RULES_H */

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

/*
 * dns_policy_match — найти nameserver-policy для домена.
 * Возвращает указатель на первое совпадение (по priority ASC)
 * или NULL если нет совпадения.
 *
 * Паттерны: точное совпадение, *.suffix, .suffix
 */
const DnsPolicy *dns_policy_match(const DnsPolicy *policies,
                                   int count,
                                   const char *domain);

/*
 * Порт по умолчанию для типа upstream.
 */
static inline uint16_t dns_policy_default_port(dns_upstream_type_t t)
{
    switch (t) {
    case DNS_UPSTREAM_DOT: return 853;
    case DNS_UPSTREAM_DOH: return 443;
    default:               return 53;
    }
}

#endif /* DNS_RULES_H */

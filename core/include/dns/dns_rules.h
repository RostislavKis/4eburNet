#ifndef DNS_RULES_H
#define DNS_RULES_H

#include "config.h"
#include "geo/geo_loader.h"

typedef enum {
    DNS_ACTION_BYPASS  = 0,
    DNS_ACTION_PROXY   = 1,
    DNS_ACTION_BLOCK   = 2,
    DNS_ACTION_DEFAULT = 3,
} dns_action_t;

int  dns_rules_init(const EburNetConfig *cfg);
void dns_rules_free(void);

/* Определить действие для домена */
dns_action_t dns_rules_match(const char *qname);

/* Загрузить домены из файла */
int dns_rules_load_file(const char *path, dns_action_t action);

/* Перестроить sorted index после загрузки правил */
void dns_rules_rebuild_index(void);

/*
 * Проверить что ответ содержит bogus IP (redirect NXDOMAIN от ISP).
 * bogus_list — пробел-разделённый список IP (из конфига bogus_nxdomain).
 */
bool dns_is_bogus_response(const char *bogus_list,
                            const uint8_t *resp,
                            size_t resp_len);

/*
 * Вариант B (3.5.1): привязать geo_manager к DNS правилам.
 * Вызывать после geo_manager_init() и dns_rules_init().
 * gm=NULL отключает GEOSITE проверку.
 */
void dns_rules_set_geo_manager(const geo_manager_t *gm);

/*
 * Привязать callback к DNS правилам (3.5.5).
 * При DNS_ACTION_DEFAULT вызывает cb(qname) чтобы получить
 * действие от traffic rules engine:
 *   DNS_ACTION_PROXY  → fake-ip
 *   DNS_ACTION_BYPASS → реальный IP
 *   DNS_ACTION_BLOCK  → NXDOMAIN
 * cb=NULL отключает консультацию (graceful degradation).
 */
void dns_rules_set_engine(dns_action_t (*cb)(const char *));

/*
 * Зарегистрировать действие для гео-категории.
 * cat: GEO_CAT_ADS, GEO_CAT_TRACKERS или GEO_CAT_THREATS.
 * action: DNS_ACTION_BLOCK обычно.
 * Вызывать после dns_rules_set_geo_manager().
 */
void dns_rules_add_geosite(geo_cat_type_t cat, dns_action_t action);

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

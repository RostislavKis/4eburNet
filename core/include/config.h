#ifndef CONFIG_H
#define CONFIG_H

#include "phoenix.h"
#include <stddef.h>

/* Описание прокси-сервера из UCI конфига */
typedef struct {
    char     name[64];
    bool     enabled;
    char     protocol[16];    /* vless / trojan / shadowsocks */
    char     address[256];
    uint16_t port;
    char     uuid[64];        /* для vless/vmess */
    char     password[128];   /* для trojan/shadowsocks */
    char     transport[16];   /* "raw" (default) или "xhttp" */
    /* AWG параметры */
    char     awg_private_key[64];
    char     awg_public_key[64];
    char     awg_psk[64];
    char     awg_h1[32], awg_h2[32], awg_h3[32], awg_h4[32];
    uint16_t awg_s1, awg_s2, awg_s3, awg_s4;
    uint8_t  awg_jc;
    uint16_t awg_jmin, awg_jmax;
    char     awg_i1[256], awg_i2[256], awg_i3[256], awg_i4[256], awg_i5[256];
    uint16_t awg_keepalive;
    char     xhttp_path[128];      /* HTTP путь для XHTTP, default "/" */
    char     xhttp_host[128];      /* Host заголовок для XHTTP */
    /* Reality параметры (DEC-025) */
    char     reality_short_id[17]; /* hex-строка до 16 символов + '\0' */
} ServerConfig;

/* DNS конфигурация */
typedef struct {
    bool     enabled;
    uint16_t listen_port;
    char     upstream_bypass[256];
    char     upstream_proxy[256];
    char     upstream_default[256];
    uint16_t upstream_port;
    int      cache_size;
    int      cache_ttl_max;
    bool     doh_enabled;
    char     doh_url[512];
    char     doh_sni[256];
    char     doh_ip[64];     /* IP адрес DoH сервера (если URL содержит домен) */
    uint16_t doh_port;       /* порт DoH, 0 = авто (443 для https) */
    bool     dot_enabled;
    char     dot_server_ip[64];
    uint16_t dot_port;
    char     dot_sni[256];
} DnsConfig;

/* Тип upstream для nameserver-policy */
typedef enum {
    DNS_UPSTREAM_UDP = 0,   /* обычный UDP DNS */
    DNS_UPSTREAM_DOT = 1,   /* DNS over TLS */
    DNS_UPSTREAM_DOH = 2,   /* DNS over HTTPS */
} dns_upstream_type_t;

/* DNS правило маршрутизации (action) */
typedef struct {
    char type[16];       /* bypass|proxy|block */
    char pattern[256];   /* *.example.com или example.com */
} DnsRule;

/* DNS nameserver-policy: домен → конкретный upstream */
typedef struct {
    char                pattern[256];   /* *.example.com или example.com */
    char                upstream[256];  /* IP или URL upstream */
    uint16_t            port;           /* 0 = авто (53/853/443) */
    dns_upstream_type_t type;           /* udp/dot/doh */
    char                sni[256];       /* SNI для DoT/DoH */
    int                 priority;       /* чем меньше — тем приоритетнее */
} DnsPolicy;

/* Политика устройства */
typedef enum {
    DEVICE_POLICY_DEFAULT = 0,
    DEVICE_POLICY_PROXY   = 1,
    DEVICE_POLICY_BYPASS  = 2,
    DEVICE_POLICY_BLOCK   = 3,
} device_policy_t;

/* Конфигурация per-device routing */
typedef struct {
    char            name[64];
    char            alias[128];
    uint8_t         mac[6];
    char            mac_str[18];
    device_policy_t policy;
    char            server_group[64];
    bool            enabled;
    int             priority;
    char            comment[256];
} device_config_t;

/* Тип proxy-group */
typedef enum {
    PROXY_GROUP_SELECT       = 0,
    PROXY_GROUP_URL_TEST     = 1,
    PROXY_GROUP_FALLBACK     = 2,
    PROXY_GROUP_LOAD_BALANCE = 3,
} proxy_group_type_t;

typedef struct {
    char               name[64];
    proxy_group_type_t type;
    char               servers[512];   /* пробел-разделённый список */
    char               url[512];       /* health-check URL */
    int                interval;       /* сек */
    int                timeout_ms;
    int                tolerance_ms;
    bool               enabled;
} ProxyGroupConfig;

/* Тип rule-provider */
typedef enum {
    RULE_PROVIDER_HTTP = 0,
    RULE_PROVIDER_FILE = 1,
} rule_provider_type_t;

typedef enum {
    RULE_FORMAT_DOMAIN    = 0,
    RULE_FORMAT_IPCIDR    = 1,
    RULE_FORMAT_CLASSICAL = 2,
} rule_format_t;

typedef struct {
    char                 name[64];
    rule_provider_type_t type;
    char                 url[512];
    char                 path[256];
    rule_format_t        format;
    int                  interval;    /* сек, 0=никогда */
    bool                 enabled;
    char                 region[8];   /* "" = для всех, "ru"/"cn"/etc = только этот регион */
} RuleProviderConfig;

/* Тип traffic rule */
typedef enum {
    RULE_TYPE_DOMAIN         = 0,
    RULE_TYPE_DOMAIN_SUFFIX  = 1,
    RULE_TYPE_DOMAIN_KEYWORD = 2,
    RULE_TYPE_IP_CIDR        = 3,
    RULE_TYPE_RULE_SET       = 4,
    RULE_TYPE_MATCH          = 5,
    RULE_TYPE_GEOIP          = 6,   /* GEOIP,RU,DIRECT */
    RULE_TYPE_GEOSITE        = 7,   /* GEOSITE,ru,proxy */
} rule_type_t;

typedef struct {
    rule_type_t type;
    char        value[256];
    char        target[64];    /* имя group, DIRECT, REJECT */
    int         priority;
} TrafficRule;

/* Основная конфигурация phoenixd */
typedef struct PhoenixConfig {
    bool           enabled;
    char           log_level[16];
    char           mode[16];        /* rules / global / direct */
    int            server_count;
    ServerConfig  *servers;         /* динамический массив */
    DnsConfig      dns;
    DnsRule       *dns_rules;
    int            dns_rule_count;
    DnsPolicy     *dns_policies;       /* nameserver-policy правила */
    int            dns_policy_count;
    int            tai_utc_offset;      /* TAI-UTC в секундах, default 37 */
    char           lan_interface[32];   /* "br-lan" — для netdev hook */
    device_config_t      *devices;
    int                   device_count;
    ProxyGroupConfig     *proxy_groups;
    int                   proxy_group_count;
    RuleProviderConfig   *rule_providers;
    int                   rule_provider_count;
    TrafficRule          *traffic_rules;
    int                   traffic_rule_count;
    char                  geo_region[8];   /* "ru","cn","us","" — явный конфиг региона */
    char                  geo_dir[256];    /* директория с geo-файлами, "" = /etc/phoenix/geo */
} PhoenixConfig;

/* Загрузка конфига из UCI-файла, возвращает 0 при успехе */
int  config_load(const char *path, PhoenixConfig *cfg);

/* Освобождение памяти конфига */
void config_free(PhoenixConfig *cfg);

/* Вывод конфига в лог для отладки */
void config_dump(const PhoenixConfig *cfg);

#endif /* CONFIG_H */

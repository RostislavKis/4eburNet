#ifndef CONFIG_H
#define CONFIG_H

#include "4eburnet.h"
#include <stddef.h>
#include <stdatomic.h>

/* Описание прокси-сервера из UCI конфига */
typedef struct {
    /* WHY 128: длинные имена с emoji+кириллица в YAML провайдеров занимают
     * 60+ UTF-8 байт. char[64] обрезал имена в середине UTF-8 sequence
     * (% E F % B F % B D в JSON /proxies) → zashboard не мог найти сервер
     * по имени → /proxies/{name}/delay возвращал 404. */
    char     name[128];
    bool     enabled;
    char     protocol[16];    /* vless / trojan / shadowsocks */
    char     address[256];
    uint16_t port;
    char     uuid[64];        /* для vless/vmess */
    char     password[512];   /* для trojan/shadowsocks/hysteria2 */
    char     vmess_security[16]; /* VMess AEAD: "auto"/"aes-128-gcm"/"chacha20-poly1305"/"none" */
    char     ss_method[32];   /* SS cipher: "2022-blake3-chacha20-poly1305" и т.д. */
    char     transport[16];   /* "raw" (default) или "xhttp" */
    /* AWG параметры */
    char     awg_private_key[64];
    char     awg_public_key[64];
    char     awg_psk[64];
    char     awg_h1[32], awg_h2[32], awg_h3[32], awg_h4[32];
    uint16_t awg_s1, awg_s2, awg_s3, awg_s4;
    uint8_t  awg_jc;
    uint16_t awg_jmin, awg_jmax;
    char    *awg_i[5];   /* strdup, NULL если не задано. Освобождается в config_free. */
    uint16_t awg_keepalive;
    uint16_t awg_mtu;              /* AWG MTU, default 1280 */
    char     awg_dns[64];          /* AWG DNS сервер */
    char     awg_reserved[64];     /* AWG reserved bytes (base64) */
    char    *awg_j1;              /* junk template hex blob — strdup, NULL если нет */
    uint16_t awg_itime;           /* init resend timeout сек, 0 = дефолтный (5с) */
    char     xhttp_path[128];      /* HTTP путь для XHTTP, default "/" */
    char     xhttp_host[128];      /* Host заголовок для XHTTP */
    /* Reality параметры (DEC-025) */
    char     reality_short_id[17]; /* hex-строка до 16 символов + '\0' */
    char     reality_pbk[64];      /* Reality public key (x25519, base64url) */
    char     reality_sni[256];        /* servername из YAML/UCI; SNI для Reality TLS */
    char     reality_flow[32];        /* "xtls-rprx-vision" или "" */
    char     reality_fingerprint[16]; /* "chrome", "firefox", "safari", "random" */
    /* Hysteria2-специфичные поля (только при protocol="hysteria2") */
    bool     hy2_obfs_enabled;
    char     hy2_obfs_password[512];
    bool     hy2_insecure;
    char     hy2_sni[256];
    uint32_t hy2_up_mbps;
    uint32_t hy2_down_mbps;
    /* AnyTLS-специфичные поля (только при protocol="anytls") */
    char anytls_password[128]; /* password для SHA256 auth */
    char anytls_sni[256];      /* SNI для TLS (default = host) */
    /* TUIC v5-специфичные поля (только при protocol="tuic") */
    char tuic_uuid[37];        /* UUID строка "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" */
    char tuic_password[128];   /* пароль для TLS-Exporter token */
    int  tuic_udp_relay_mode;  /* 0=native (DATAGRAM), 1=quic (uni-stream) */
    char tuic_cc[16];          /* "cubic"/"newreno"/"bbr1"/"bbr2", default="cubic" */
    char tuic_cc_profile[16];  /* "conservative"/"standard"/"aggressive" (BBR v2) */
#if CONFIG_EBURNET_STLS
    /* ShadowTLS v3 (transport wrapper, protocol="shadowtls") */
    char     stls_password[256]; /* PSK для HMAC верификации */
    char     stls_sni[256];      /* SNI реального сервера ("www.microsoft.com") */
#endif
    /* gRPC transport */
    char     grpc_service_name[64]; /* grpc-service-name из YAML, "" → "GunService" */
    /* WebSocket transport (T0-04) */
    char     ws_path[256];          /* ws-opts.path из YAML, "" → "/" */
    char     ws_host[256];          /* ws-opts.headers.Host из YAML, "" → server.address */
    /* XUDP / Mux.Cool packet encoding (Clash YAML packet-encoding):
     * "" = TCP-only, "xudp" = Mux.Cool UDP, "packetaddr" = legacy v2ray */
    char     packet_encoding[16];
    /* Источник сервера: "" = основной конфиг, иначе имя провайдера */
    char     source_provider[64];
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
    /* Fallback upstream (C1) */
    char     upstream_fallback[256]; /* IP запасного DNS сервера */
    int      fallback_timeout_ms;    /* мс ожидания primary до fallback, 0=1000 */
    /* Bogus NXDOMAIN filter (C2) */
    char     bogus_nxdomain[1024];   /* пробел-разделённый список IP заглушек */
    /* TTL контроль (C3/C6) */
    int      cache_ttl_min;          /* минимальный TTL кэша, 0=выключено */
    /* Таймаут первичного upstream (мс), 0 = 3000 */
    int      upstream_timeout_ms;
    /* Tolerance для выбора fallback: если fallback быстрее на >= N мс (v2.1.8) */
    int      tolerance_ms;
    /* Parallel query (C5) */
    bool     parallel_query;         /* отправить запрос на primary+fallback одновременно */
    /* Fake-IP режим (C4) */
    bool     fake_ip_enabled;        /* включить fake-ip для PROXY доменов */
    char     fake_ip_range[64];      /* пул, например "198.18.0.0/15" */
    int      fake_ip_pool_size;      /* макс. записей, 0 = авто по профилю */
    int      fake_ip_ttl;            /* TTL fake-ip ответов, сек, 0 = 60 */
    /* Fake-IP IPv6 (v1.5-3) */
    bool     fake_ip6_enabled;       /* включить IPv6 fake-ip (AAAA → fd00::/N) */
    char     fake_ip6_range[64];     /* пул IPv6, например "fd00::/120" */
    /* DNS-over-QUIC (DoQ, RFC 9250) */
    bool     doq_enabled;            /* включить DoQ upstream */
    char     doq_server_ip[64];      /* IP адрес DoQ сервера */
    uint16_t doq_server_port;        /* порт (0 = 853) */
    char     doq_sni[256];           /* SNI для TLS-рукопожатия */
    /* Geosite блокировка через geo_loader (list block_geosite в UCI) */
    bool     block_geosite_ads;      /* list block_geosite 'ads' */
    bool     block_geosite_trackers; /* list block_geosite 'trackers' */
    bool     block_geosite_threats;  /* list block_geosite 'threats' */
    /* DEC-031: upstream DNS resolve cache TTL in seconds.
     * UCI key: resolve_ttl. Default 300 (5 мин) применяется в config.c
     * если поле отсутствует или равно 0. Используется
     * dispatcher_resolve_server() для TTL кэша в group_server_state_t. */
    uint32_t resolve_ttl;
    /* UCI key: dns_cookie_secret_path. "" → дефолт /var/lib/4eburnet/cookie.secret */
    char     cookie_secret_path[256];
    /* RFC 8767 stale-while-revalidate (движок в dns_cache.c) */
    bool     stale_while_revalidate; /* отдавать stale+refresh при истёкшем TTL (default true) */
    uint32_t stale_grace_seconds;    /* как долго отдавать stale, сек (default 3600) */
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
    PROXY_GROUP_SELECT            = 0,
    PROXY_GROUP_URL_TEST          = 1,
    PROXY_GROUP_FALLBACK          = 2,
    PROXY_GROUP_LOAD_BALANCE      = 3,
    /* WHY: fastest-whitelist отбирает только CDN-серверы (не блокируются ТСПУ),
     * из них выбирает с минимальной задержкой.
     * Fallback: если CDN-серверов нет — берёт просто самый быстрый среди available. */
    PROXY_GROUP_FASTEST_WHITELIST = 4,
} proxy_group_type_t;

typedef struct {
    char               name[64];
    proxy_group_type_t type;
    char             **servers;         /* dynamic массив имён серверов */
    int                server_count;   /* количество серверов в группе */
    char              *providers;      /* strdup, пробел-разделённый список провайдеров */
    char               filter[512];   /* POSIX ERE regex для фильтрации имён серверов */
    char               url[512];       /* health-check URL */
    int                interval;       /* сек */
    int                timeout_ms;
    int                tolerance_ms;
    /* WHY: стратегия балансировки нагрузки для PROXY_GROUP_LOAD_BALANCE.
     * "round-robin" (default), "consistent-hashing", "sticky-sessions".
     * Хранится в UCI: load_balance_strategy. */
    char               load_balance_strategy[32];
    bool               enabled;
} ProxyGroupConfig;

/* Тип proxy-provider */
typedef enum {
    PROXY_PROVIDER_URL  = 0,
    PROXY_PROVIDER_FILE = 1,
} proxy_provider_type_t;

/* Кастомные HTTP-заголовки для proxy-provider (x-hwid, x-device-os, etc.) */
#define PROXY_PROVIDER_MAX_HEADERS 8

typedef struct {
    char                  name[64];
    proxy_provider_type_t type;
    char                  url[512];    /* URL подписки */
    char                  path[256];   /* кэш на диске */
    int                   interval;    /* сек обновления, 0=никогда */
    bool                  enabled;
    /* Лимит серверов: 0 = авто по профилю */
    int                   max_servers;
    /* Кастомные заголовки провайдера: "Name: Value" строки */
    char                  headers[PROXY_PROVIDER_MAX_HEADERS][256];
    int                   header_count;
} ProxyProviderConfig;

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

/* Формат файла rule-provider (не тип правил — см. rule_format_t).
 * WHY: behavior=domain/ipcidr/classical описывает тип содержимого;
 * file_format=text/yaml описывает кодировку файла (F0-2 sub_convert). */
typedef enum {
    RP_FILE_FORMAT_AUTO = 0,  /* автоопределение по содержимому ("payload:") */
    RP_FILE_FORMAT_TEXT = 1,  /* plain text: один домен/CIDR на строку */
    RP_FILE_FORMAT_YAML = 2,  /* Clash YAML: payload: [...] */
} rp_file_format_t;

typedef struct {
    char                 name[64];
    rule_provider_type_t type;
    char                 url[512];
    char                 path[256];
    rule_format_t        format;
    rp_file_format_t     file_format;  /* формат файла (text/yaml/auto) */
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
    RULE_TYPE_DST_PORT       = 8,   /* DST-PORT,443,DIRECT */
    RULE_TYPE_IP_CIDR6       = 9,   /* WHY: IPv6 CIDR из Clash IP-CIDR6 правил;
                                     * маршрутизируется через ip6 eburnet_nat,
                                     * не через ip eburnet_nat (IPv4-only) */
    RULE_TYPE_AND            = 10,  /* AND,((NETWORK,TCP),(DST-PORT,50000-65535)),TARGET */
    RULE_TYPE_OR             = 11,  /* OR из произвольных вложенных sub_rules */
    RULE_TYPE_REGEX          = 12,  /* POSIX extended regex против domain */
    RULE_TYPE_SRC_PORT       = 13,  /* SRC-PORT,min-max → матч по порту источника */
    RULE_TYPE_PROCESS_NAME   = 14,  /* PROCESS-NAME,name → матч по имени процесса */
} rule_type_t;

typedef struct TrafficRule {
    rule_type_t type;
    char        value[1024];   /* WHY 1024: OR conditions накапливаются через '\n',
                                * 256 хватало только ~3-5 условий (сжато). */
    char        target[64];    /* имя group, DIRECT, REJECT */
    int         priority;
    uint16_t    port_min;      /* 0 = не задан */
    uint16_t    port_max;      /* 0 = не задан; port_min==port_max = одиночный порт */
    uint8_t     network;       /* 0=any, 6=TCP (IPPROTO_TCP), 17=UDP (IPPROTO_UDP) */
    /* OR: вложенные условия (heap, NULL если не OR)
     * WHY: short-circuit match любого из sub_rules без рекурсии.
     * Освобождается в config_free() через loop по traffic_rules[]. */
    struct TrafficRule *sub_rules;
    uint8_t             sub_count;
    /* REGEX: скомпилированный POSIX regex (regex_t*, heap, NULL если не REGEX)
     * WHY: compile один раз при загрузке — regexec() при каждом матче дорог.
     * Освобождается через regfree() + free() в config_free(). */
    void               *compiled_re;
    /* Счётчик срабатываний (атомарный, сбрасывается при reload).
     * WHY: инкремент без лока — множество потоков disp + dns. */
    _Atomic uint32_t    hit_count;
} TrafficRule;

/* Sniffer настройки — MSG_PEEK извлечение hostname из трафика */
/* Список доменов для config-based DPI override */
#define MAX_DPI_DOMAIN_LIST 64

typedef struct {
    char    entries[MAX_DPI_DOMAIN_LIST][128];
    uint8_t count;
} DpiDomainList;

typedef struct {
    bool    tls_sni;                 /* peek TLS ClientHello → SNI */
    bool    http_host;               /* peek HTTP → Host заголовок */
    bool    quic_sni;                /* peek QUIC Initial → SNI (future) */
    bool    override_dest;           /* использовать sniffed host для routing */
    char    bypass_domains[32][128]; /* домены где sniffer отключён */
    uint8_t bypass_count;
    /* WHY: array вместо heap pointer = нет malloc, safe для MIPS BSS */
} SnifferConfig;

/* Основная конфигурация 4eburnetd */
typedef struct EburNetConfig {
    bool           enabled;
    char           log_level[16];
    char           mode[16];        /* rules / global / direct */
    int            server_count;
    ServerConfig  *servers;         /* динамический массив */
    /* Серверы из proxy-providers (динамические, отдельно от servers[]) */
    ServerConfig  *provider_servers;
    int            provider_server_count;
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
    ProxyProviderConfig  *proxy_providers;
    int                   proxy_provider_count;
    RuleProviderConfig   *rule_providers;
    int                   rule_provider_count;
    TrafficRule          *traffic_rules;
    int                   traffic_rule_count;
    char                  geo_region[8];   /* "ru","cn","us","" — явный конфиг региона */
    char                  geo_dir[256];    /* директория с geo-файлами, "" = /etc/4eburnet/geo */
    char                  geo_profile[16]; /* "minimal"/"normal"/"full"; используется geo_update.sh */
    char                  dpi_dir[256];    /* директория с dpi-файлами, "" = /etc/4eburnet/dpi */
    /* DPI bypass стратегия */
    bool                  dpi_enabled;      /* включить DPI bypass */
    int                   dpi_split_pos;    /* позиция TCP split (bytes) */
    int                   dpi_fake_ttl;     /* TTL fake пакета */
    int                   dpi_fake_repeats; /* кол-во fake пакетов */
    char                  dpi_fake_sni[256];/* SNI для fake TLS */
    /* Config-based DPI domain override */
    DpiDomainList         dpi_whitelist;    /* UCI list dpi_whitelist: bypass НЕ применяется */
    DpiDomainList         dpi_blacklist;    /* UCI list dpi_blacklist: bypass ПРИНУДИТЕЛЬНО */
    /* dpi_fooling_ts: добавляется в C.5 (требует raw TCP) */
    /* CDN автообновление ipset.txt */
    int                   cdn_update_interval_days; /* 0=выкл, default 7 */
    char                  cdn_cf_v4_url[256]; /* "" = встроенный default */
    char                  cdn_cf_v6_url[256];
    char                  cdn_fastly_url[256];
    /* opencck auto-updater */
    char                  opencck_url[256];           /* URL .gbin, "" = выключено */
    uint32_t              opencck_update_interval_s;  /* сек, 0 = выключено */
    bool                  warn_ru_server_access; /* предупреждать если нет правила GEOIP,RU,DIRECT */
    bool                  flow_offload;          /* nftables flow offload для DIRECT трафика */
    bool                  tc_fast_enabled;       /* TC ingress fast path (cls_u32 + act_skbedit) */
    uint16_t              mtu;                   /* MTU LAN интерфейса, 0 = не менять (дефолт 1500) */
    uint32_t              lan_prefix;            /* LAN-подсеть, напр. 0xC0A80200 для 192.168.2.0 */
    uint32_t              lan_mask;              /* маска, напр. 0xFFFFFF00 для /24 */
    uint16_t              mixed_port;            /* SOCKS5+HTTP inbound порт (0=выключено, default 1080) */
    bool                  inbound_auth;          /* требовать username/password (RFC 1929) */
    char                  inbound_username[64];  /* логин для inbound auth */
    char                  inbound_password[64];  /* пароль для inbound auth */
    SnifferConfig         sniffer;               /* MSG_PEEK hostname extraction */
} EburNetConfig;

/* Получить ServerConfig по unified индексу:
 * [0..server_count) = cfg->servers[idx]
 * [server_count..server_count+provider_server_count) = cfg->provider_servers[idx-server_count]
 * Возвращает NULL если idx вне диапазона. */
static inline const ServerConfig *config_get_server(const EburNetConfig *cfg, int idx)
{
    if (idx < cfg->server_count)
        return &cfg->servers[idx];
    int pi = idx - cfg->server_count;
    if (pi < cfg->provider_server_count)
        return &cfg->provider_servers[pi];
    return NULL;
}

/* Загрузка конфига из UCI-файла, возвращает 0 при успехе */
int  config_load(const char *path, EburNetConfig *cfg);

/* Освобождение памяти конфига */
void config_free(EburNetConfig *cfg);

/* Вывод конфига в лог для отладки */
void config_dump(const EburNetConfig *cfg);

#endif /* CONFIG_H */

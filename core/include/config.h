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
    char     xhttp_path[128]; /* HTTP путь для XHTTP, default "/" */
    char     xhttp_host[128]; /* Host заголовок для XHTTP */
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
    bool     dot_enabled;
    char     dot_server_ip[64];
    uint16_t dot_port;
    char     dot_sni[256];
} DnsConfig;

/* DNS правило маршрутизации */
typedef struct {
    char type[16];       /* bypass|proxy|block */
    char pattern[256];   /* *.example.com или example.com */
} DnsRule;

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
    char           lan_interface[32];   /* "br-lan" — для netdev hook */
    device_config_t *devices;
    int            device_count;
} PhoenixConfig;

/* Загрузка конфига из UCI-файла, возвращает 0 при успехе */
int  config_load(const char *path, PhoenixConfig *cfg);

/* Освобождение памяти конфига */
void config_free(PhoenixConfig *cfg);

/* Вывод конфига в лог для отладки */
void config_dump(const PhoenixConfig *cfg);

#endif /* CONFIG_H */

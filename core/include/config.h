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
} PhoenixConfig;

/* Загрузка конфига из UCI-файла, возвращает 0 при успехе */
int  config_load(const char *path, PhoenixConfig *cfg);

/* Освобождение памяти конфига */
void config_free(PhoenixConfig *cfg);

/* Вывод конфига в лог для отладки */
void config_dump(const PhoenixConfig *cfg);

#endif /* CONFIG_H */

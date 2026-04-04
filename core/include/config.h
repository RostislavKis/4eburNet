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

/* Основная конфигурация phoenixd */
typedef struct PhoenixConfig {
    bool           enabled;
    char           log_level[16];
    char           mode[16];        /* rules / global / direct */
    int            server_count;
    ServerConfig  *servers;         /* динамический массив */
} PhoenixConfig;

/* Загрузка конфига из UCI-файла, возвращает 0 при успехе */
int  config_load(const char *path, PhoenixConfig *cfg);

/* Освобождение памяти конфига */
void config_free(PhoenixConfig *cfg);

/* Вывод конфига в лог для отладки */
void config_dump(const PhoenixConfig *cfg);

#endif /* CONFIG_H */

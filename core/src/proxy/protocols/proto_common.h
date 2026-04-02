#ifndef PROTO_COMMON_H
#define PROTO_COMMON_H

#include <stdint.h>
#include <stdbool.h>

/* Поддерживаемые протоколы проксирования */
typedef enum {
    PROTO_SHADOWSOCKS,
    PROTO_VLESS,
    PROTO_TROJAN,
    PROTO_NONE
} ProtocolType;

/* Параметры TLS-соединения */
typedef struct {
    const char *sni;            /* Server Name Indication */
    const char *fingerprint;    /* отпечаток для маскировки */
    bool        reality;        /* использовать REALITY вместо обычного TLS */
    const char *reality_pubkey; /* публичный ключ REALITY */
    const char *reality_sid;    /* short ID для REALITY */
} TlsConfig;

/* Описание прокси-сервера */
typedef struct {
    char            name[64];
    char            address[256];
    uint16_t        port;
    ProtocolType    protocol;
    TlsConfig       tls;
    char            password[256];  /* пароль или UUID в зависимости от протокола */
    bool            enabled;
} ProxyServer;

/* Интерфейс протокола — каждый протокол регистрирует свои функции */
typedef struct {
    ProtocolType type;
    const char  *name;

    /* Подключение к серверу, возвращает файловый дескриптор или -1 */
    int  (*connect)(const ProxyServer *server);

    /* Рукопожатие после TCP-соединения */
    int  (*handshake)(int fd, const ProxyServer *server,
                      const char *target_host, uint16_t target_port);

    /* Передача данных между клиентом и сервером */
    int  (*relay)(int client_fd, int server_fd);

    /* Освобождение ресурсов */
    void (*cleanup)(int fd);
} ProtocolHandler;

#endif /* PROTO_COMMON_H */

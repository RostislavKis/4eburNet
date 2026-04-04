#ifndef VLESS_H
#define VLESS_H

#include "crypto/tls.h"

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>

/* UUID — 16 байт бинарный */
typedef struct {
    uint8_t bytes[16];
} vless_uuid_t;

/* Команды VLESS */
typedef enum {
    VLESS_CMD_TCP = 0x01,
    VLESS_CMD_UDP = 0x02,
    VLESS_CMD_MUX = 0x03,
} vless_command_t;

/* Типы адресов */
typedef enum {
    VLESS_ADDR_IPV4   = 0x01,
    VLESS_ADDR_DOMAIN = 0x02,
    VLESS_ADDR_IPV6   = 0x03,
} vless_addr_type_t;

/* Максимальный размер VLESS request header */
#define VLESS_HEADER_MAX    64

/*
 * Парсить UUID строку "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" в 16 байт.
 * Возвращает 0 при успехе, -1 при неверном формате.
 */
int vless_uuid_parse(const char *str, vless_uuid_t *out);

/*
 * Построить VLESS request header в буфер.
 * Возвращает количество записанных байт или -1 при ошибке.
 */
int vless_build_request(uint8_t *buf, size_t buflen,
                        const vless_uuid_t *uuid,
                        const struct sockaddr_storage *dst,
                        vless_command_t cmd);

/*
 * Прочитать VLESS response header (2+ байт) из TLS соединения.
 * Возвращает 0 при успехе, -1 при ошибке.
 */
int vless_read_response(tls_conn_t *tls);

/*
 * Полное VLESS рукопожатие: парсинг UUID → header → отправка → ответ.
 * Вызывается после tls_connect().
 * Возвращает 0 при успехе.
 */
int vless_handshake(tls_conn_t *tls,
                    const struct sockaddr_storage *dst,
                    const char *uuid_str);

#endif /* VLESS_H */

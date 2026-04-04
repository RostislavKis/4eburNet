#ifndef TROJAN_H
#define TROJAN_H

#include "crypto/tls.h"

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>

/* SHA224(password) — 28 байт → 56 hex ASCII */
typedef struct {
    char hex[57];   /* 56 hex + \0 */
} trojan_password_hash_t;

/* Максимальный размер Trojan request header (IPv6) */
#define TROJAN_HEADER_MAX   80

/* Вычислить SHA224(password) в hex строку */
int trojan_hash_password(const char *password,
                         trojan_password_hash_t *out);

/* Построить Trojan request header.
   Возвращает размер или -1 при ошибке. */
int trojan_build_request(uint8_t *buf, size_t buflen,
                         const trojan_password_hash_t *hash,
                         const struct sockaddr_storage *dst);

/* Trojan handshake: hash + header → tls_send.
   Нет response от сервера — сразу relay.
   Возвращает 0 при успехе. */
int trojan_handshake_start(tls_conn_t *tls,
                           const struct sockaddr_storage *dst,
                           const char *password);

#endif /* TROJAN_H */

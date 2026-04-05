/*
 * Протокол Trojan
 *
 * Маскировка под HTTPS: TLS + SHA224(password) + адрес назначения.
 * Нет response от сервера — после header сразу relay данных.
 *
 * Формат Trojan Request:
 *   [56] SHA224(password) hex
 *   [2]  \r\n
 *   [1]  команда (0x01=TCP)
 *   [1]  тип адреса (0x01=IPv4, 0x03=IPv6)
 *   [N]  адрес (4 или 16 байт)
 *   [2]  порт big-endian
 *   [2]  \r\n
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "proxy/protocols/trojan.h"
#include "net_utils.h"
#include "phoenix.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>  /* explicit_bzero */
#include <errno.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------ */
/*  trojan_hash_password — SHA224(password) → 56 hex                   */
/* ------------------------------------------------------------------ */

int trojan_hash_password(const char *password,
                         trojan_password_hash_t *out)
{
    if (!password || !out)
        return -1;

    wc_Sha224 sha;
    if (wc_InitSha224(&sha) != 0)
        return -1;

    wc_Sha224Update(&sha, (const byte *)password, strlen(password));

    byte hash[WC_SHA224_DIGEST_SIZE];  /* 28 байт */
    wc_Sha224Final(&sha, hash);
    wc_Sha224Free(&sha);

    for (int i = 0; i < WC_SHA224_DIGEST_SIZE; i++)
        snprintf(out->hex + i * 2, 3, "%02x", hash[i]);

    /* M-04: обнулить хеш на стеке */
    explicit_bzero(hash, sizeof(hash));

    return 0;
}

/* ------------------------------------------------------------------ */
/*  trojan_build_request                                               */
/* ------------------------------------------------------------------ */

int trojan_build_request(uint8_t *buf, size_t buflen,
                         const trojan_password_hash_t *hash,
                         const struct sockaddr_storage *dst)
{
    if (buflen < TROJAN_HEADER_MAX)
        return -1;

    int pos = 0;

    /* SHA224 hex (56 байт ASCII) */
    memcpy(buf + pos, hash->hex, 56);
    pos += 56;

    /* \r\n */
    buf[pos++] = '\r';
    buf[pos++] = '\n';

    /* Команда: TCP */
    buf[pos++] = 0x01;

    /* Тип адреса + адрес + порт */
    if (dst->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)dst;
        buf[pos++] = 0x01;  /* IPv4 */
        memcpy(buf + pos, &s4->sin_addr, 4);
        pos += 4;
        /* Порт уже в network byte order */
        memcpy(buf + pos, &s4->sin_port, 2);
        pos += 2;
    } else if (dst->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)dst;
        buf[pos++] = 0x04;  /* IPv6 (Trojan spec: 0x04) */
        memcpy(buf + pos, &s6->sin6_addr, 16);
        pos += 16;
        memcpy(buf + pos, &s6->sin6_port, 2);
        pos += 2;
    } else {
        return -1;
    }

    /* \r\n */
    buf[pos++] = '\r';
    buf[pos++] = '\n';

    return pos;
}

/* ------------------------------------------------------------------ */
/*  trojan_handshake_start                                             */
/* ------------------------------------------------------------------ */

int trojan_handshake_start(tls_conn_t *tls,
                           const struct sockaddr_storage *dst,
                           const char *password)
{
    trojan_password_hash_t hash;
    if (trojan_hash_password(password, &hash) < 0) {
        log_msg(LOG_ERROR, "Trojan: не удалось хэшировать пароль");
        return -1;
    }

    uint8_t header[TROJAN_HEADER_MAX];
    int header_len = trojan_build_request(header, sizeof(header),
                                          &hash, dst);
    if (header_len < 0) {
        log_msg(LOG_ERROR, "Trojan: не удалось построить header");
        return -1;
    }

    ssize_t sent = tls_send(tls, header, header_len);
    if (sent != header_len) {
        log_msg(LOG_WARN, "Trojan: не удалось отправить header (%zd/%d)",
                sent, header_len);
        return -1;
    }

    char dst_str[64];
    net_format_addr(dst, dst_str, sizeof(dst_str));
    log_msg(LOG_DEBUG, "Trojan: handshake отправлен (%d байт), dst: %s",
            header_len, dst_str);

    /* Нет response от сервера — сразу relay */
    return 0;
}

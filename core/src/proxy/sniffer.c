/*
 * sniffer.c — извлечение SNI из TLS ClientHello (3.6)
 *
 * Парсит TLS Record → Handshake → ClientHello → extensions → SNI (0x0000).
 * Использует MSG_PEEK + MSG_DONTWAIT: данные из сокета не потребляются,
 * функция не блокирует event loop.
 */

#include "proxy/sniffer.h"

#include "4eburnet.h"

#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

/* Размер буфера для peek — достаточно для большинства ClientHello */
#define SNIFFER_PEEK_SIZE  512

int sniffer_peek_sni(int fd, char *sni_buf, size_t sni_buflen)
{
    /* Всегда NUL-terminate при выходе */
    if (sni_buf && sni_buflen > 0) sni_buf[0] = '\0';
    if (!sni_buf || sni_buflen < 2) return 0;

    uint8_t buf[SNIFFER_PEEK_SIZE];

    /* MSG_PEEK — не потребляем данные из сокета */
    ssize_t n = recv(fd, buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT);
    if (n <= 0) return 0;  /* EAGAIN, ошибка, или соединение закрыто */

    /* Минимум — заголовок TLS Record (5 байт) */
    if (n < 5) return 0;

    /* TLS Record Type: Handshake = 0x16 */
    if (buf[0] != 0x16) return 0;

    /* TLS версия: 0x0301 (TLS 1.0) .. 0x0304 (TLS 1.3) */
    if (buf[1] != 0x03 || buf[2] < 0x01 || buf[2] > 0x04) return 0;

    /* Record length */
    uint16_t rec_len = ((uint16_t)buf[3] << 8) | buf[4];
    if (rec_len < 4) return 0;           /* V7-01: partial record допустим */
    if ((size_t)n < 9) return 0;         /* V7-02: n>=9 ДО buf[5..8] */

    /* Handshake Type: ClientHello = 0x01 */
    if (buf[5] != 0x01) return 0;

    /* Handshake length (3 байта big-endian) */
    uint32_t hs_len = ((uint32_t)buf[6] << 16) |
                      ((uint32_t)buf[7] << 8)  |
                      (uint32_t)buf[8];
    if (hs_len < 34) return 0;

    /* Пропустить: version(2) + random(32) = 34 байта
       pos = начало session_id_length */
    size_t pos = 9 + 2 + 32;
    if ((size_t)n < pos + 1) return 0;

    /* session_id length + данные (0-32 байта) */
    uint8_t sid_len = buf[pos++];
    if (sid_len > 32) return 0;
    pos += sid_len;

    /* cipher_suites: length(2) + данные */
    if ((size_t)n < pos + 2) return 0;
    uint16_t cs_len = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
    pos += 2 + cs_len;

    /* compression_methods: length(1) + данные */
    if ((size_t)n < pos + 1) return 0;
    uint8_t cm_len = buf[pos++];
    pos += cm_len;

    /* extensions: total length(2) */
    if ((size_t)n < pos + 2) return 0;
    uint16_t ext_total = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
    pos += 2;

    /* Ограничиваем ext_end тем, что реально пришло в peek-буфер */
    size_t ext_end = pos + ext_total;
    if (ext_end > (size_t)n) ext_end = (size_t)n;

    /* Перебираем extensions */
    while (pos + 4 <= ext_end) {
        uint16_t ext_type = ((uint16_t)buf[pos]     << 8) | buf[pos + 1];
        uint16_t ext_len  = ((uint16_t)buf[pos + 2] << 8) | buf[pos + 3];
        pos += 4;

        if (pos + ext_len > ext_end) break;

        if (ext_type == 0x0000) {
            /* SNI extension (RFC 6066):
               ServerNameList: list_len(2) + name_type(1) + name_len(2) + name */
            if (ext_len < 5) break;
            /* name_type 0x00 = host_name */
            if (buf[pos + 2] != 0x00) break;
            uint16_t name_len = ((uint16_t)buf[pos + 3] << 8) | buf[pos + 4];
            if (name_len == 0 || pos + 5 + name_len > ext_end) break;

            /* Копируем hostname — с усечением если буфер мал */
            size_t copy_len = name_len;
            if (copy_len >= sni_buflen)
                copy_len = sni_buflen - 1;
            memcpy(sni_buf, buf + pos + 5, copy_len);
            sni_buf[copy_len] = '\0';
            /* V7-03: null-байт в SNI невалиден (RFC 6066) —
               strlen < copy_len означает встроенный \0 */
            if (strlen(sni_buf) != copy_len) {
                log_msg(LOG_DEBUG, "SNI sniffer: null-байт в SNI — отклонено");
                sni_buf[0] = '\0';
                return 0;
            }
            return (int)copy_len;
        }

        pos += ext_len;
    }

    return 0;  /* SNI extension не найден (ESNI/ECH или не-TLS) */
}

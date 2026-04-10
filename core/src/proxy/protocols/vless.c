/*
 * Протокол VLESS (DEC-021)
 *
 * Минималистичный прокси-протокол от Project X.
 * Шифрование на уровне TLS (wolfSSL), не на уровне протокола.
 *
 * Формат VLESS Request:
 *   [1]  версия=0 [16] UUID [1] аддоны_len [M] аддоны
 *   [1]  команда [2] порт [1] тип_адреса [N] адрес
 *
 * Формат VLESS Response:
 *   [1]  версия=0 [1] аддоны_len [M] аддоны
 *   Далее: чистые данные (relay)
 */

#include "proxy/protocols/vless.h"
#include "net_utils.h"
#include "4eburnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/select.h>

/* ------------------------------------------------------------------ */
/*  vless_uuid_parse                                                   */
/* ------------------------------------------------------------------ */

int vless_uuid_parse(const char *str, vless_uuid_t *out)
{
    if (!str || !out)
        return -1;

    /* Убираем дефисы, собираем hex символы */
    char hex[33];
    int hi = 0;

    for (int i = 0; str[i] != '\0'; i++) {
        char c = str[i];
        if (c == '-')
            continue;

        /* Валидация: hex символ */
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return -1;

        if (hi >= 32)
            return -1;  /* слишком длинный */

        hex[hi++] = c;
    }
    hex[hi] = '\0';

    if (hi != 32)
        return -1;  /* UUID = ровно 32 hex символа */

    /* Попарная конвертация hex → байт */
    for (int i = 0; i < 16; i++) {
        char pair[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        unsigned long val = strtoul(pair, NULL, 16);
        out->bytes[i] = (uint8_t)val;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  vless_build_request                                                */
/* ------------------------------------------------------------------ */

int vless_build_request(uint8_t *buf, size_t buflen,
                        const vless_uuid_t *uuid,
                        const struct sockaddr_storage *dst,
                        vless_command_t cmd)
{
    if (buflen < VLESS_HEADER_MAX)
        return -1;

    int pos = 0;

    /* Версия */
    buf[pos++] = 0x00;

    /* UUID (16 байт) */
    memcpy(buf + pos, uuid->bytes, 16);
    pos += 16;

    /* Длина аддонов = 0 */
    buf[pos++] = 0x00;

    /* Команда */
    buf[pos++] = (uint8_t)cmd;

    /* Порт назначения (big-endian) */
    uint16_t port = 0;
    if (dst->ss_family == AF_INET) {
        port = ntohs(((const struct sockaddr_in *)dst)->sin_port);
    } else if (dst->ss_family == AF_INET6) {
        port = ntohs(((const struct sockaddr_in6 *)dst)->sin6_port);
    }
    buf[pos++] = (port >> 8) & 0xFF;
    buf[pos++] = port & 0xFF;

    /* Тип адреса + адрес */
    if (dst->ss_family == AF_INET) {
        buf[pos++] = VLESS_ADDR_IPV4;
        memcpy(buf + pos,
               &((const struct sockaddr_in *)dst)->sin_addr, 4);
        pos += 4;
    } else if (dst->ss_family == AF_INET6) {
        buf[pos++] = VLESS_ADDR_IPV6;
        memcpy(buf + pos,
               &((const struct sockaddr_in6 *)dst)->sin6_addr, 16);
        pos += 16;
    } else {
        return -1;
    }

    return pos;
}

/* ------------------------------------------------------------------ */
/*  vless_read_response — DEPRECATED: legacy блокирующий API           */
/*  Используйте vless_read_response_step() из dispatcher (H-23)       */
/* ------------------------------------------------------------------ */

__attribute__((deprecated(
    "Используйте vless_read_response_step() из dispatcher. "
    "Эта функция блокирует event loop на 5 секунд.")))
int vless_read_response(tls_conn_t *tls)
{
    /* Минимум 2 байта: версия + длина аддонов */
    uint8_t resp[2];
    size_t total = 0;
    int attempts = 50;  /* 50 × 100мс = 5 сек */

    while (total < 2 && attempts-- > 0) {
        ssize_t n = tls_recv(tls, resp + total, 2 - total);
        if (n > 0) {
            total += n;
            continue;
        }
        if (n == 0) {
            log_msg(LOG_WARN, "VLESS: EOF при чтении ответа");
            return -1;
        }
        /* n < 0 */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(tls->fd, &fds);
            struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
            select(tls->fd + 1, &fds, NULL, NULL, &tv);
            continue;
        }
        log_msg(LOG_WARN, "VLESS: не удалось прочитать ответ: %s",
                strerror(errno));
        return -1;
    }
    if (total < 2) {
        log_msg(LOG_WARN, "VLESS: таймаут чтения ответа");
        return -1;
    }

    /* Проверка версии */
    if (resp[0] != 0x00) {
        log_msg(LOG_WARN, "VLESS: неверная версия ответа: 0x%02x",
                resp[0]);
        return -1;
    }

    /* Аддоны — прочитать и игнорировать */
    uint8_t addons_len = resp[1];
    if (addons_len > 0) {
        uint8_t addons[256];
        size_t read_total = 0;
        while (read_total < addons_len) {
            ssize_t n = tls_recv(tls, addons + read_total,
                                 addons_len - read_total);
            if (n <= 0)
                return -1;
            read_total += n;
        }
        log_msg(LOG_DEBUG, "VLESS: %u байт аддонов (проигнорировано)",
                addons_len);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Форматирование адреса для логов                                    */
/* ------------------------------------------------------------------ */

/* vless_fmt_addr → net_format_addr из net_utils.c (M-01) */

/* ------------------------------------------------------------------ */
/*  vless_handshake                                                    */
/* ------------------------------------------------------------------ */

__attribute__((deprecated(
    "Используйте vless_handshake_start(). "
    "Эта функция блокирует event loop.")))
int vless_handshake(tls_conn_t *tls,
                    const struct sockaddr_storage *dst,
                    const char *uuid_str)
{
    /* Парсинг UUID */
    vless_uuid_t uuid;
    if (vless_uuid_parse(uuid_str, &uuid) < 0) {
        log_msg(LOG_ERROR, "VLESS: невалидный UUID");
        return -1;
    }

    char dst_str[64];
    net_format_addr(dst, dst_str, sizeof(dst_str));

    log_msg(LOG_DEBUG, "VLESS handshake: dst: %s", dst_str);

    /* Построить VLESS request header */
    uint8_t header[VLESS_HEADER_MAX];
    int header_len = vless_build_request(header, sizeof(header),
                                         &uuid, dst, VLESS_CMD_TCP);
    if (header_len < 0) {
        log_msg(LOG_ERROR, "VLESS: не удалось построить request header");
        return -1;
    }

    /* Отправить через TLS */
    ssize_t sent = tls_send(tls, header, header_len);
    if (sent != header_len) {
        log_msg(LOG_WARN, "VLESS: не удалось отправить header (%zd/%d)",
                sent, header_len);
        return -1;
    }

    /* Прочитать ответ */
    if (vless_read_response(tls) < 0) {
        log_msg(LOG_WARN, "VLESS: ответ сервера невалиден");
        return -1;
    }

    log_msg(LOG_DEBUG, "VLESS handshake завершён: %s", dst_str);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Неблокирующий API (C-03/C-04)                                      */
/* ------------------------------------------------------------------ */

int vless_handshake_start(tls_conn_t *tls,
                          const struct sockaddr_storage *dst,
                          const char *uuid_str)
{
    /* Парсинг UUID */
    vless_uuid_t uuid;
    if (vless_uuid_parse(uuid_str, &uuid) < 0) {
        log_msg(LOG_ERROR, "VLESS: невалидный UUID");
        return -1;
    }

    char dst_str[64];
    net_format_addr(dst, dst_str, sizeof(dst_str));

    log_msg(LOG_DEBUG, "VLESS handshake start: dst: %s", dst_str);

    /* Построить и отправить VLESS request header */
    uint8_t header[VLESS_HEADER_MAX];
    int header_len = vless_build_request(header, sizeof(header),
                                         &uuid, dst, VLESS_CMD_TCP);
    if (header_len < 0) {
        log_msg(LOG_ERROR, "VLESS: не удалось построить request header");
        return -1;
    }

    ssize_t sent = tls_send(tls, header, header_len);
    if (sent != header_len) {
        log_msg(LOG_WARN, "VLESS: не удалось отправить header (%zd/%d)",
                sent, header_len);
        return -1;
    }

    /* Ответ не ждём — читаем через vless_read_response_step() */
    return 0;
}

int vless_read_response_step(tls_conn_t *tls,
                             uint8_t *resp_buf, uint8_t *resp_len)
{
    /* Читаем 2 байта: версия + длина аддонов */
    while (*resp_len < 2) {
        ssize_t n = tls_recv(tls, resp_buf + *resp_len, 2 - *resp_len);
        if (n > 0) {
            *resp_len += n;
            continue;
        }
        if (n == 0) {
            log_msg(LOG_WARN, "VLESS: EOF при чтении ответа");
            return -1;
        }
        /* n < 0 */
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 1;  /* повторить позже */
        log_msg(LOG_WARN, "VLESS: ошибка чтения ответа: %s",
                strerror(errno));
        return -1;
    }

    /* Проверка версии */
    if (resp_buf[0] != 0x00) {
        log_msg(LOG_WARN, "VLESS: неверная версия ответа: 0x%02x",
                resp_buf[0]);
        return -1;
    }

    /* H-03: вычитать addons, если есть (resp_buf[2] = счётчик прочитанных) */
    if (resp_buf[1] > 0) {
        uint8_t addons_len = resp_buf[1];
        while (resp_buf[2] < addons_len) {
            uint8_t dummy;
            ssize_t n = tls_recv(tls, &dummy, 1);
            if (n > 0) {
                resp_buf[2]++;
                continue;
            }
            if (n == 0) {
                log_msg(LOG_WARN, "VLESS: EOF при чтении addons");
                return -1;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 1;  /* повторить позже */
            return -1;
        }
        log_msg(LOG_DEBUG, "VLESS: %u байт аддонов вычитано", addons_len);
    }

    log_msg(LOG_DEBUG, "VLESS handshake завершён");
    return 0;
}

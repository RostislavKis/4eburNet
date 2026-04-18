/*
 * sniffer.h — TLS ClientHello парсер + SNI sniffer (3.6 / v1.2-3)
 *
 * sniffer_peek_sni()    — MSG_PEEK → только SNI (совместимость)
 * sniffer_parse_hello() — MSG_PEEK → полный ClientHello (JA3/JA4)
 */

#ifndef SNIFFER_H
#define SNIFFER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Лимиты для полей ClientHello */
#define JA3_CIPHER_MAX   64
#define JA3_EXT_MAX      32
#define JA3_GROUP_MAX    16
#define JA3_ECPF_MAX      8

/* ja3_is_grease — фильтр GREASE значений (RFC 8701).
 * Паттерн: 0x?A?A где оба байта одинаковы и младший nibble = 0xA. */
static inline bool ja3_is_grease(uint16_t v)
{
    return (v & 0x0f0fu) == 0x0a0au && (v >> 8) == (v & 0xffu);
}

/* Распарсенный ClientHello — используется для JA3/JA4 вычисления.
 * Размер ~544 байт — выделять через malloc в вызывающем коде. */
typedef struct {
    /* Версии:
     * tls_version      — legacy_version из ClientHello body (buf[9..10])
     *                    используется в JA3
     * supported_version — из extension 0x002b (supported_versions),
     *                    0 если extension отсутствует; используется в JA4 */
    uint16_t tls_version;
    uint16_t supported_version;

    uint16_t ciphers[JA3_CIPHER_MAX];   /* без GREASE */
    int      cipher_count;
    uint16_t extensions[JA3_EXT_MAX];   /* типы без GREASE */
    int      ext_count;
    uint16_t groups[JA3_GROUP_MAX];     /* supported_groups (0x000a) */
    int      group_count;
    uint8_t  ecpf[JA3_ECPF_MAX];        /* ec_point_formats (0x000b) */
    int      ecpf_count;
    char     sni[256];                  /* extension 0x0000 */
    bool     sni_found;
    /* alpn: первый протокол из extension 0x0010.
     * JA4 записывает ALPN отдельно, не включает в hash extensions. */
    char     alpn[32];
    bool     alpn_found;
} ClientHelloInfo;

/*
 * sniffer_peek_sni — извлечь SNI из TLS ClientHello через MSG_PEEK.
 *
 * Читает первые байты сокета fd без потребления данных.
 * При успехе: записывает hostname в sni_buf, возвращает длину.
 * При ошибке/не-TLS/EAGAIN: sni_buf[0]='\0', возвращает 0.
 *
 * Контракт: НЕ блокирует. Если данных нет (EAGAIN) — возвращает 0.
 * Контракт: НЕ изменяет состояние сокета (только MSG_PEEK).
 * Контракт: sni_buf всегда NUL-terminated при возврате.
 * Реализован как обёртка над sniffer_parse_hello().
 */
int sniffer_peek_sni(int fd, char *sni_buf, size_t sni_buflen);

/*
 * sniffer_parse_hello — распарсить ClientHello через MSG_PEEK.
 *
 * Заполняет ciphers, extensions, groups, ecpf, sni, alpn,
 * tls_version, supported_version.
 * Возвращает 0 при успехе, -1 если не TLS ClientHello или EAGAIN.
 * out должен быть выделен вызывающим (malloc/calloc, ~544 байт).
 */
int sniffer_parse_hello(int fd, ClientHelloInfo *out);

#endif /* SNIFFER_H */

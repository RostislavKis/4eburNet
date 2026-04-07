/*
 * sniffer.h — TLS ClientHello SNI sniffer (3.6)
 *
 * Извлекает SNI из TLS ClientHello через MSG_PEEK — без потребления
 * данных из сокета. Используется в dispatcher до создания relay,
 * чтобы передать domain в rules_engine для DOMAIN/GEOSITE правил.
 */

#ifndef SNIFFER_H
#define SNIFFER_H

#include <stddef.h>

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
 */
int sniffer_peek_sni(int fd, char *sni_buf, size_t sni_buflen);

#endif /* SNIFFER_H */

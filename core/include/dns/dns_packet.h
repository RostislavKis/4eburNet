#ifndef DNS_PACKET_H
#define DNS_PACKET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Разобранный DNS запрос */
typedef struct {
    uint16_t id;
    uint8_t  opcode;
    bool     is_query;
    bool     rd;
    char     qname[256];
    uint16_t qtype;
    uint16_t qclass;
} dns_query_t;

/* Разобрать входящий DNS пакет */
int dns_parse_query(const uint8_t *pkt, size_t len, dns_query_t *q);

/* Построить NXDOMAIN ответ */
int dns_build_nxdomain(const dns_query_t *q, uint8_t *buf, size_t buflen);

/* Подставить ID клиента в ответ upstream */
int dns_build_forward_reply(const dns_query_t *q,
                            const uint8_t *upstream_reply, size_t reply_len,
                            uint8_t *buf, size_t buflen);

/* Извлечь минимальный TTL из DNS ответа */
uint32_t dns_extract_min_ttl(const uint8_t *reply, size_t len);

/* Нормализация: lowercase, убрать trailing dot */
void dns_normalize_qname(char *qname);

/*
 * dns_build_a_reply — построить DNS A-ответ с одним IP.
 * ip: IPv4 адрес (host byte order).
 * Возвращает длину ответа или -1.
 */
int dns_build_a_reply(const dns_query_t *q,
                       uint32_t ip,
                       uint32_t ttl,
                       uint8_t *buf, size_t buf_len);

#endif /* DNS_PACKET_H */

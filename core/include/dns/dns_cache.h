#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <stdbool.h>

/* Максимальный размер DNS пакета (EDNS0 совместимо) */
#define DNS_MAX_PACKET 4096

typedef struct {
    char     qname[256];
    uint16_t qtype;
    uint8_t  response[DNS_MAX_PACKET];
    uint16_t response_len;
    time_t   expire_at;
    int      prev;
    int      next;
    bool     used;
} dns_cache_entry_t;

typedef struct {
    dns_cache_entry_t *entries;
    int                capacity;
    int                count;
    int                lru_head;
    int                lru_tail;
    uint8_t            reply_buf[DNS_MAX_PACKET]; /* буфер для ответа с подменённым ID */
} dns_cache_t;

int  dns_cache_init(dns_cache_t *c, int capacity);
void dns_cache_free(dns_cache_t *c);

/* Найти в кэше. Возвращает указатель на ответ с orig_id или NULL */
const uint8_t *dns_cache_get(dns_cache_t *c,
                             const char *qname, uint16_t qtype,
                             uint16_t *resp_len, uint16_t orig_id);

/* Добавить/обновить запись */
void dns_cache_put(dns_cache_t *c,
                   const char *qname, uint16_t qtype,
                   const uint8_t *response, uint16_t resp_len,
                   uint32_t ttl);

#endif /* DNS_CACHE_H */

/*
 * DNS кэш — LRU с TTL
 */

#include "dns/dns_cache.h"
#include "phoenix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t djb2_hash(const char *qname, uint16_t qtype)
{
    uint32_t h = 5381;
    for (const char *p = qname; *p; p++)
        h = h * 33 + (uint8_t)*p;
    h += qtype;
    return h;
}

int dns_cache_init(dns_cache_t *c, int capacity)
{
    memset(c, 0, sizeof(*c));
    if (capacity <= 0) capacity = 256;
    c->entries = calloc(capacity, sizeof(dns_cache_entry_t));
    if (!c->entries) return -1;
    c->capacity = capacity;
    c->lru_head = -1;
    c->lru_tail = -1;
    for (int i = 0; i < capacity; i++) {
        c->entries[i].prev = -1;
        c->entries[i].next = -1;
    }
    return 0;
}

void dns_cache_free(dns_cache_t *c)
{
    if (c->entries) { free(c->entries); c->entries = NULL; }
    c->count = 0;
}

/* LRU: переместить idx в начало */
static void lru_touch(dns_cache_t *c, int idx)
{
    dns_cache_entry_t *e = &c->entries[idx];
    if (c->lru_head == idx) return;

    /* Отцепить */
    if (e->prev >= 0) c->entries[e->prev].next = e->next;
    if (e->next >= 0) c->entries[e->next].prev = e->prev;
    if (c->lru_tail == idx) c->lru_tail = e->prev;

    /* Вставить в начало */
    e->prev = -1;
    e->next = c->lru_head;
    if (c->lru_head >= 0) c->entries[c->lru_head].prev = idx;
    c->lru_head = idx;
    if (c->lru_tail < 0) c->lru_tail = idx;
}

const uint8_t *dns_cache_get(dns_cache_t *c,
                             const char *qname, uint16_t qtype,
                             uint16_t *resp_len, uint16_t orig_id)
{
    uint32_t h = djb2_hash(qname, qtype);
    for (int i = 0; i < c->capacity; i++) {
        int idx = (h + i) % c->capacity;
        dns_cache_entry_t *e = &c->entries[idx];
        if (!e->used) return NULL;
        if (e->qtype == qtype && strcmp(e->qname, qname) == 0) {
            if (time(NULL) >= e->expire_at) {
                e->used = false;
                c->count--;
                return NULL;
            }
            lru_touch(c, idx);
            /* Копируем ответ с подставленным ID */
            memcpy(c->reply_buf, e->response, e->response_len);
            c->reply_buf[0] = (orig_id >> 8) & 0xFF;
            c->reply_buf[1] = orig_id & 0xFF;
            *resp_len = e->response_len;
            return c->reply_buf;
        }
    }
    return NULL;
}

void dns_cache_put(dns_cache_t *c,
                   const char *qname, uint16_t qtype,
                   const uint8_t *response, uint16_t resp_len,
                   uint32_t ttl)
{
    if (resp_len > DNS_MAX_PACKET || resp_len == 0) return;

    uint32_t h = djb2_hash(qname, qtype);
    int target = -1;

    /* Ищем существующий или пустой слот */
    for (int i = 0; i < c->capacity; i++) {
        int idx = (h + i) % c->capacity;
        if (!c->entries[idx].used) { target = idx; break; }
        if (c->entries[idx].qtype == qtype &&
            strcmp(c->entries[idx].qname, qname) == 0) {
            target = idx; break;
        }
    }

    /* Если нет места — evict LRU tail */
    if (target < 0) {
        if (c->lru_tail >= 0) {
            target = c->lru_tail;
            c->entries[target].used = false;
            c->count--;
        } else {
            target = 0;
        }
    }

    dns_cache_entry_t *e = &c->entries[target];
    if (!e->used) c->count++;

    snprintf(e->qname, sizeof(e->qname), "%s", qname);
    e->qtype = qtype;
    memcpy(e->response, response, resp_len);
    e->response_len = resp_len;
    e->expire_at = time(NULL) + ttl;
    e->used = true;

    lru_touch(c, target);
}

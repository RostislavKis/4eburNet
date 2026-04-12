/*
 * DNS кэш — LRU с TTL
 */

#include "dns/dns_cache.h"
#include "4eburnet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define DNS_CACHE_PROBE_MAX  16

/* M-20: FNV-1a вместо djb2 — лучшее распределение */
static uint32_t fnv1a_hash(const char *qname, uint16_t qtype)
{
    uint32_t h = 2166136261u;
    for (const char *p = qname; *p; p++) {
        h ^= (uint8_t)*p;
        h *= 16777619u;
    }
    h ^= qtype;
    h *= 16777619u;
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
    uint32_t h = fnv1a_hash(qname, qtype);
    for (int i = 0; i < DNS_CACHE_PROBE_MAX && i < c->capacity; i++) {
        int idx = (h + i) % c->capacity;
        dns_cache_entry_t *e = &c->entries[idx];
        if (!e->used) return NULL;
        if (e->qtype == qtype && strcmp(e->qname, qname) == 0) {
            if (time(NULL) >= e->expire_at) {
                /* M-26: удалить из LRU перед пометкой unused */
                if (c->lru_head == idx) c->lru_head = e->next;
                if (c->lru_tail == idx) c->lru_tail = e->prev;
                if (e->prev >= 0) c->entries[e->prev].next = e->next;
                if (e->next >= 0) c->entries[e->next].prev = e->prev;
                e->prev = e->next = -1;
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

    uint32_t h = fnv1a_hash(qname, qtype);
    int target = -1;

    /* Ищем существующий или пустой слот */
    for (int i = 0; i < DNS_CACHE_PROBE_MAX && i < c->capacity; i++) {
        int idx = (h + i) % c->capacity;
        if (!c->entries[idx].used) { target = idx; break; }
        if (c->entries[idx].qtype == qtype &&
            strcmp(c->entries[idx].qname, qname) == 0) {
            target = idx; break;
        }
    }

    /* M-03: если нет свободного слота — evict LRU tail, затем probe заново */
    if (target < 0 && c->lru_tail >= 0) {
        int evict = c->lru_tail;
        /* Удалить из LRU */
        if (c->lru_head == evict) c->lru_head = c->entries[evict].next;
        c->lru_tail = c->entries[evict].prev;
        if (c->entries[evict].prev >= 0)
            c->entries[c->entries[evict].prev].next = -1;
        c->entries[evict].used = false;
        c->entries[evict].prev = c->entries[evict].next = -1;
        c->count--;

        /* Попробовать найти слот в НАШЕМ probe sequence */
        for (int i = 0; i < DNS_CACHE_PROBE_MAX && i < c->capacity; i++) {
            int idx2 = (h + i) % c->capacity;
            if (!c->entries[idx2].used) { target = idx2; break; }
        }
        if (target < 0) target = evict;  /* fallback — используем освободившийся */
    } else if (target < 0) {
        target = 0;
    }

    dns_cache_entry_t *e = &c->entries[target];
    if (!e->used) c->count++;

    {   int _n = snprintf(e->qname, sizeof(e->qname), "%s", qname);
        if (_n < 0 || (size_t)_n >= sizeof(e->qname))
            log_msg(LOG_WARN, "DNS cache: qname обрезан: %s", qname);
    }
    e->qtype = qtype;
    memcpy(e->response, response, resp_len);
    e->response_len = resp_len;
    e->expire_at = time(NULL) + ttl;
    e->used = true;

    lru_touch(c, target);
}

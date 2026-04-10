/*
 * fake-ip таблица — виртуальные IP для domain-based routing
 * Часть 1: init + free + flush + hash + LRU helpers
 */

#include "dns/fake_ip.h"
#include "4eburnet.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>

/* ── Адаптивный размер пула ── */

int fake_ip_max_entries_for_profile(DeviceProfile profile,
                                     int configured_max)
{
    int limit;
    switch (profile) {
    case DEVICE_MICRO:  limit = 512;   break;
    case DEVICE_NORMAL: limit = 4096;  break;
    case DEVICE_FULL:   limit = 65536; break;
    default:            limit = 4096;  break;
    }
    if (configured_max > 0 && configured_max < limit)
        return configured_max;
    return limit;
}

/* ── Hash функции ── */

/* djb2 для строк */
static uint32_t hash_str(const char *s)
{
    uint32_t h = 5381;
    while (*s)
        h = h * 33 ^ (uint8_t)*s++;
    return h;
}

/* Hash для IPv4 */
static uint32_t hash_ip(uint32_t ip)
{
    /* Fibonacci hashing */
    return ip * 2654435769u;
}

/* ── Bucket операции ── */

/* Добавить entry в bucket */
static int bucket_add(fake_ip_bucket_t *b, fake_ip_entry_t *e)
{
    if (b->count >= b->capacity) {
        int new_cap = b->capacity ? b->capacity * 2 : 4;
        fake_ip_entry_t **np = realloc(b->entries,
            (size_t)new_cap * sizeof(*np));
        if (!np) return -1;
        b->entries  = np;
        b->capacity = new_cap;
    }
    b->entries[b->count++] = e;
    return 0;
}

/* Удалить entry из bucket по указателю */
static void bucket_remove(fake_ip_bucket_t *b, fake_ip_entry_t *e)
{
    for (int i = 0; i < b->count; i++) {
        if (b->entries[i] == e) {
            b->entries[i] = b->entries[--b->count];
            return;
        }
    }
}

/* ── LRU операции ── */

/* Отсоединить запись из LRU списка */
static void lru_remove(fake_ip_table_t *t, fake_ip_entry_t *e)
{
    if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
    else             t->lru_head            = e->lru_next;
    if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
    else             t->lru_tail            = e->lru_prev;
    e->lru_prev = NULL;
    e->lru_next = NULL;
}

/* Переместить запись в голову LRU (MRU позиция) */
static void lru_move_to_head(fake_ip_table_t *t, fake_ip_entry_t *e)
{
    if (t->lru_head == e) return;  /* уже в голове */
    lru_remove(t, e);
    e->lru_next    = t->lru_head;
    e->lru_prev    = NULL;
    if (t->lru_head) t->lru_head->lru_prev = e;
    t->lru_head    = e;
    if (!t->lru_tail) t->lru_tail = e;
}

/* Добавить новую запись в голову LRU */
static void lru_push_head(fake_ip_table_t *t, fake_ip_entry_t *e)
{
    e->lru_next = t->lru_head;
    e->lru_prev = NULL;
    if (t->lru_head) t->lru_head->lru_prev = e;
    t->lru_head = e;
    if (!t->lru_tail) t->lru_tail = e;
}

/* ── Парсинг CIDR диапазона ── */

/* Распарсить "A.B.C.D/N" → pool_start, pool_size */
static int parse_cidr(const char *range,
                       uint32_t *out_start,
                       uint32_t *out_size)
{
    char buf[64];
    size_t rlen = strlen(range);
    if (rlen >= sizeof(buf)) return -1;
    memcpy(buf, range, rlen + 1);

    char *slash = strchr(buf, '/');
    if (!slash) return -1;
    *slash = '\0';
    int prefix = atoi(slash + 1);
    if (prefix < 1 || prefix > 32) return -1;

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return -1;

    uint32_t ip   = ntohl(addr.s_addr);
    uint32_t mask = prefix == 32
                    ? 0xFFFFFFFFu
                    : ~((1u << (32 - prefix)) - 1u);
    *out_start = ip & mask;   /* сеть выровнена */
    *out_size  = 1u << (32 - prefix);
    return 0;
}

/* ── fake_ip_init ── */

int fake_ip_init(fake_ip_table_t *t, const EburNetConfig *cfg,
                 const char *range, int max_entries)
{
    memset(t, 0, sizeof(*t));
    t->cfg = cfg;

    /* Распарсить диапазон */
    uint32_t start = 0, size = 0;
    if (!range || !range[0] ||
        parse_cidr(range, &start, &size) < 0) {
        /* Default: 198.18.0.0/15 (RFC 5737 тестовый диапазон) */
        parse_cidr("198.18.0.0/15", &start, &size);
    }
    t->pool_start = start + 1;  /* пропустить сетевой адрес */
    t->pool_end   = start + size - 2; /* пропустить broadcast */
    t->pool_size  = t->pool_end - t->pool_start + 1;
    t->next_ip    = t->pool_start;

    /* Проверить корректность пула (защита от /31, /32) */
    if (t->pool_end < t->pool_start ||
        t->pool_size < 2) {
        log_msg(LOG_ERROR,
            "fake-ip: диапазон %s слишком мал "
            "(минимум /30, рекомендуется /15)",
            range ? range : "(null)");
        goto fail;
    }

    /* Ограничить max_entries размером пула */
    if ((uint32_t)max_entries > t->pool_size)
        max_entries = (int)t->pool_size;
    if (max_entries <= 0) max_entries = 4096;
    t->max_entries = max_entries;

    /* Выделить flat array записей */
    t->entries = calloc((size_t)max_entries, sizeof(fake_ip_entry_t));
    if (!t->entries) goto fail;

    /* Вычислить размер hash таблицы (ближайшая степень двойки >= max_entries) */
    int hs = 1;
    while (hs < max_entries) hs <<= 1;
    t->hash_size = hs;

    /* Выделить hash bucket массивы */
    t->by_ip     = calloc((size_t)hs, sizeof(fake_ip_bucket_t));
    t->by_domain = calloc((size_t)hs, sizeof(fake_ip_bucket_t));
    if (!t->by_ip || !t->by_domain) goto fail;

    t->free_count = max_entries;
    t->count      = 0;

    log_msg(LOG_INFO,
        "fake-ip: пул %u.%u.%u.%u–%u.%u.%u.%u (%u адресов, max %d записей)",
        (t->pool_start >> 24) & 0xFF, (t->pool_start >> 16) & 0xFF,
        (t->pool_start >> 8)  & 0xFF,  t->pool_start & 0xFF,
        (t->pool_end   >> 24) & 0xFF, (t->pool_end   >> 16) & 0xFF,
        (t->pool_end   >> 8)  & 0xFF,  t->pool_end   & 0xFF,
        t->pool_size, max_entries);
    return 0;

fail:
    fake_ip_free(t);
    return -1;
}

/* Удалить запись из обоих hash + LRU (не освобождать память) */
static void entry_unlink(fake_ip_table_t *t, fake_ip_entry_t *e)
{
    /* Убрать из by_ip */
    int bi = (int)(hash_ip(e->fake_ip) & (uint32_t)(t->hash_size - 1));
    bucket_remove(&t->by_ip[bi], e);

    /* Убрать из by_domain */
    int di = (int)(hash_str(e->domain) & (uint32_t)(t->hash_size - 1));
    bucket_remove(&t->by_domain[di], e);

    /* Убрать из LRU */
    lru_remove(t, e);

    /* Пометить слот как свободный */
    e->fake_ip = 0;
    t->count--;
    t->free_count++;
}

void fake_ip_flush(fake_ip_table_t *t)
{
    if (!t || !t->entries) return;
    /* Очистить bucket счётчики */
    for (int i = 0; i < t->hash_size; i++) {
        t->by_ip[i].count     = 0;
        t->by_domain[i].count = 0;
    }
    /* Обнулить все записи */
    memset(t->entries, 0, (size_t)t->max_entries *
           sizeof(fake_ip_entry_t));
    t->count      = 0;
    t->free_count = t->max_entries;
    t->lru_head   = NULL;
    t->lru_tail   = NULL;
    t->next_ip    = t->pool_start;
    log_msg(LOG_DEBUG, "fake-ip: таблица очищена");
}

void fake_ip_free(fake_ip_table_t *t)
{
    if (!t) return;
    if (t->by_ip) {
        for (int i = 0; i < t->hash_size; i++)
            free(t->by_ip[i].entries);
        free(t->by_ip);
    }
    if (t->by_domain) {
        for (int i = 0; i < t->hash_size; i++)
            free(t->by_domain[i].entries);
        free(t->by_domain);
    }
    free(t->entries);
    memset(t, 0, sizeof(*t));
}

/* ── Найти свободный слот в flat array ── */

static fake_ip_entry_t *find_free_slot(fake_ip_table_t *t)
{
    for (int i = 0; i < t->max_entries; i++) {
        if (t->entries[i].fake_ip == 0)
            return &t->entries[i];
    }
    return NULL;  /* пул полон */
}

/* ── LRU evict одной записи ── */

static fake_ip_entry_t *evict_lru(fake_ip_table_t *t)
{
    fake_ip_entry_t *victim = t->lru_tail;
    if (!victim) return NULL;
    log_msg(LOG_DEBUG,
        "fake-ip: evict LRU %s (ip %u.%u.%u.%u)",
        victim->domain,
        (victim->fake_ip >> 24) & 0xFF,
        (victim->fake_ip >> 16) & 0xFF,
        (victim->fake_ip >> 8)  & 0xFF,
         victim->fake_ip & 0xFF);
    entry_unlink(t, victim);
    return victim;  /* слот свободен, fake_ip == 0 */
}

/* ── fake_ip_is_fake ── */

bool fake_ip_is_fake(const fake_ip_table_t *t, uint32_t ip)
{
    if (!t || t->pool_size == 0) return false;
    return (ip >= t->pool_start && ip <= t->pool_end);
}

/* ── fake_ip_alloc ── */

uint32_t fake_ip_alloc(fake_ip_table_t *t, const char *domain,
                        uint32_t real_ip, uint32_t ttl)
{
    if (!t || !domain || !domain[0]) return 0;

    /* 1. Проверить существующую запись */
    uint32_t existing = fake_ip_lookup_by_domain(t, domain);
    if (existing != 0) {
        /* Обновить LRU и TTL */
        int di = (int)(hash_str(domain) &
                       (uint32_t)(t->hash_size - 1));
        fake_ip_bucket_t *db = &t->by_domain[di];
        for (int i = 0; i < db->count; i++) {
            fake_ip_entry_t *e = db->entries[i];
            if (e->fake_ip != 0 &&
                strcasecmp(e->domain, domain) == 0) {
                lru_move_to_head(t, e);
                if (ttl > 0) {
                    int cfg_ttl = t->cfg
                        ? t->cfg->dns.fake_ip_ttl : 0;
                    uint32_t use_ttl = ttl;
                    if (cfg_ttl > 0 && use_ttl > (uint32_t)cfg_ttl)
                        use_ttl = (uint32_t)cfg_ttl;
                    e->expire_at = time(NULL) + (time_t)use_ttl;
                }
                if (real_ip != 0) e->real_ip = real_ip;
                break;
            }
        }
        return existing;
    }

    /* 2. Найти свободный слот или вытеснить LRU */
    fake_ip_entry_t *slot = NULL;
    if (t->free_count > 0) {
        slot = find_free_slot(t);
    }
    if (!slot) {
        slot = evict_lru(t);
    }
    if (!slot) {
        log_msg(LOG_WARN, "fake-ip: пул полон и evict не удался");
        return 0;
    }

    /* 3. Назначить следующий IP из пула */
    /* Найти IP который не занят (circular scan) */
    uint32_t candidate = t->next_ip;
    int scanned = 0;
    while (scanned < t->max_entries) {
        /* Проверить что candidate не занят */
        int bi = (int)(hash_ip(candidate) &
                       (uint32_t)(t->hash_size - 1));
        fake_ip_bucket_t *ib = &t->by_ip[bi];
        bool in_use = false;
        for (int i = 0; i < ib->count; i++) {
            if (ib->entries[i]->fake_ip == candidate) {
                in_use = true;
                break;
            }
        }
        if (!in_use) break;  /* нашли свободный IP */

        /* Следующий IP */
        candidate++;
        if (candidate > t->pool_end)
            candidate = t->pool_start;
        scanned++;
    }

    if (scanned >= t->max_entries) {
        /* Все IP заняты — использовать IP вытесненного слота */
        /* (slot был LRU evicted, его IP уже освобождён) */
        /* Найти любой незанятый IP — fallback linear scan */
        log_msg(LOG_WARN,
            "fake-ip: circular scan failed, "
            "используем IP слота");
        /* В этом случае берём pool_start + индекс слота */
        int slot_idx = (int)(slot - t->entries);
        candidate = t->pool_start + (uint32_t)slot_idx;
        if (candidate > t->pool_end)
            candidate = t->pool_end;
    }

    t->next_ip = candidate + 1;
    if (t->next_ip > t->pool_end)
        t->next_ip = t->pool_start;

    /* 4. Заполнить слот */
    slot->fake_ip  = candidate;
    slot->real_ip  = real_ip;
    size_t dlen = strlen(domain);
    if (dlen >= sizeof(slot->domain))
        dlen = sizeof(slot->domain) - 1;
    memcpy(slot->domain, domain, dlen);
    slot->domain[dlen] = '\0';

    /* TTL */
    int cfg_ttl = t->cfg ? t->cfg->dns.fake_ip_ttl : 0;
    uint32_t use_ttl = (ttl > 0) ? ttl : 60;
    if (cfg_ttl > 0 && use_ttl > (uint32_t)cfg_ttl)
        use_ttl = (uint32_t)cfg_ttl;
    slot->expire_at = time(NULL) + (time_t)use_ttl;

    /* 5. Добавить в hash таблицы */
    int bi = (int)(hash_ip(candidate) &
                   (uint32_t)(t->hash_size - 1));
    int di = (int)(hash_str(domain) &
                   (uint32_t)(t->hash_size - 1));
    if (bucket_add(&t->by_ip[bi], slot) < 0) {
        /* OOM: slot остаётся свободным, free_count не трогаем */
        slot->fake_ip = 0;
        return 0;
    }
    if (bucket_add(&t->by_domain[di], slot) < 0) {
        /* OOM: убрать из by_ip который уже добавился */
        bucket_remove(&t->by_ip[bi], slot);
        slot->fake_ip = 0;
        return 0;
    }

    /* 6. Добавить в LRU голову */
    lru_push_head(t, slot);
    t->count++;
    t->free_count--;

    log_msg(LOG_DEBUG,
        "fake-ip: %s → %u.%u.%u.%u (ttl %u)",
        domain,
        (candidate >> 24) & 0xFF, (candidate >> 16) & 0xFF,
        (candidate >> 8)  & 0xFF,  candidate & 0xFF,
        use_ttl);

    return candidate;
}

/* ── fake_ip_lookup_by_domain ── */

uint32_t fake_ip_lookup_by_domain(const fake_ip_table_t *t,
                                   const char *domain)
{
    if (!t || !domain || !domain[0]) return 0;
    int di = (int)(hash_str(domain) &
                   (uint32_t)(t->hash_size - 1));
    const fake_ip_bucket_t *db = &t->by_domain[di];
    for (int i = 0; i < db->count; i++) {
        const fake_ip_entry_t *e = db->entries[i];
        if (e->fake_ip != 0 &&
            strcasecmp(e->domain, domain) == 0)
            return e->fake_ip;
    }
    return 0;
}

/* ── fake_ip_lookup_by_ip ── */

const char *fake_ip_lookup_by_ip(const fake_ip_table_t *t,
                                  const struct sockaddr_storage *addr)
{
    if (!t || !addr) return NULL;

    uint32_t ip = 0;
    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *s4 =
            (const struct sockaddr_in *)addr;
        ip = ntohl(s4->sin_addr.s_addr);
    } else if (addr->ss_family == AF_INET6) {
        /* IPv4-mapped IPv6 ::ffff:A.B.C.D */
        const struct sockaddr_in6 *s6 =
            (const struct sockaddr_in6 *)addr;
        const uint8_t *b6 = s6->sin6_addr.s6_addr;
        if (b6[0] == 0 && b6[1] == 0 && b6[2] == 0 &&
            b6[3] == 0 && b6[4] == 0 && b6[5] == 0 &&
            b6[6] == 0 && b6[7] == 0 && b6[8] == 0 &&
            b6[9] == 0 && b6[10] == 0xFF && b6[11] == 0xFF) {
            ip = ((uint32_t)b6[12] << 24) |
                 ((uint32_t)b6[13] << 16) |
                 ((uint32_t)b6[14] << 8) |
                  b6[15];
        } else {
            return NULL;  /* чистый IPv6 — не fake-ip */
        }
    } else {
        return NULL;
    }

    if (!fake_ip_is_fake(t, ip)) return NULL;

    int bi = (int)(hash_ip(ip) &
                   (uint32_t)(t->hash_size - 1));
    const fake_ip_bucket_t *ib = &t->by_ip[bi];
    for (int i = 0; i < ib->count; i++) {
        if (ib->entries[i]->fake_ip == ip)
            return ib->entries[i]->domain;
    }
    return NULL;
}

/* ── fake_ip_evict_expired ── */

void fake_ip_evict_expired(fake_ip_table_t *t)
{
    if (!t || !t->entries) return;
    time_t now = time(NULL);
    /* Сканируем с хвоста LRU (старейшие первыми) */
    fake_ip_entry_t *e = t->lru_tail;
    while (e) {
        fake_ip_entry_t *prev = e->lru_prev;
        if (e->expire_at > 0 && now >= e->expire_at) {
            log_msg(LOG_DEBUG,
                "fake-ip: истёк TTL %s", e->domain);
            entry_unlink(t, e);
        }
        e = prev;
    }
}

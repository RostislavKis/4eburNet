#ifndef FAKE_IP_H
#define FAKE_IP_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "config.h"
#include "phoenix.h"   /* DeviceProfile */

/* Запись в fake-ip таблице */
typedef struct fake_ip_entry {
    uint32_t   fake_ip;          /* выданный IP (host byte order); 0 = слот свободен (sentinel) */
    char       domain[256];      /* оригинальный домен */
    uint32_t   real_ip;          /* реальный IP (опционально, для debug) */
    time_t     expire_at;        /* unix timestamp истечения (TTL) */
    /* LRU двусвязный список */
    struct fake_ip_entry *lru_prev;
    struct fake_ip_entry *lru_next;
} fake_ip_entry_t;

/* Hash bucket для O(1) lookup */
typedef struct fake_ip_bucket {
    fake_ip_entry_t **entries;
    int               count;
    int               capacity;
} fake_ip_bucket_t;

/* Fake-IP таблица */
typedef struct {
    /* Пул адресов */
    uint32_t   pool_start;     /* первый IP пула (host byte order) */
    uint32_t   pool_end;       /* последний IP пула (включительно) */
    uint32_t   pool_size;      /* pool_end - pool_start + 1 */
    uint32_t   next_ip;        /* следующий IP для выдачи */

    /* Записи — flat array [max_entries], размер max_entries*sizeof(fake_ip_entry_t) */
    fake_ip_entry_t *entries;
    int              max_entries;
    int              count;      /* активных записей */
    int              free_count; /* свободных слотов (sentinel fake_ip==0) */

    /* Hash tables: O(1) lookup */
    /* by_ip: hash(fake_ip) → entry */
    fake_ip_bucket_t *by_ip;
    int               hash_size;  /* всегда степень двойки */

    /* by_domain: hash(domain) → entry */
    fake_ip_bucket_t *by_domain;

    /* LRU: head=MRU, tail=LRU */
    fake_ip_entry_t *lru_head;
    fake_ip_entry_t *lru_tail;

    /* Конфиг (не владеет памятью) */
    const PhoenixConfig *cfg;
} fake_ip_table_t;

/* ── API ── */

/*
 * fake_ip_init — инициализировать таблицу.
 * range: строка "198.18.0.0/15" из конфига.
 * max_entries: максимум записей (адаптируется под профиль).
 * Возвращает 0 при успехе, -1 при ошибке.
 */
int  fake_ip_init(fake_ip_table_t *t, const PhoenixConfig *cfg,
                  const char *range, int max_entries);

/* fake_ip_free — освободить все ресурсы */
void fake_ip_free(fake_ip_table_t *t);

/*
 * fake_ip_flush — сбросить все записи, оставить структуру пула нетронутой.
 * Используется при перезагрузке конфига без пересоздания таблицы.
 */
void fake_ip_flush(fake_ip_table_t *t);

/*
 * fake_ip_alloc — выдать fake IP для домена.
 * Если домен уже есть — вернуть существующий IP.
 * При переполнении — вытеснить LRU запись.
 * real_ip: реальный IP (0 если неизвестен), для debug.
 * ttl: TTL ответа для синхронизации.
 * Возвращает fake IP (host byte order) или 0 при ошибке.
 */
uint32_t fake_ip_alloc(fake_ip_table_t *t, const char *domain,
                        uint32_t real_ip, uint32_t ttl);

/*
 * fake_ip_lookup_by_domain — найти fake IP по домену.
 * Возвращает IP (host byte order) или 0 если не найден.
 */
uint32_t fake_ip_lookup_by_domain(const fake_ip_table_t *t,
                                   const char *domain);

/*
 * fake_ip_lookup_by_ip — найти домен по fake IP.
 * addr: sockaddr_storage с fake IP.
 * Возвращает указатель на строку домена или NULL.
 * Указатель валиден до следующего fake_ip_alloc/eviction.
 */
const char *fake_ip_lookup_by_ip(const fake_ip_table_t *t,
                                  const struct sockaddr_storage *addr);

/*
 * fake_ip_is_fake — проверить принадлежность IP к пулу.
 */
bool fake_ip_is_fake(const fake_ip_table_t *t, uint32_t ip);

/*
 * fake_ip_evict_expired — вытеснить просроченные записи.
 * Вызывается периодически из main loop.
 */
void fake_ip_evict_expired(fake_ip_table_t *t);

/*
 * fake_ip_max_entries_for_profile — адаптивный размер пула.
 */
int fake_ip_max_entries_for_profile(DeviceProfile profile,
                                     int configured_max);

#endif /* FAKE_IP_H */

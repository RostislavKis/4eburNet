/*
 * dpi_adapt.c — Adaptive DPI: кэш стратегий bypass (v1.2-1)
 *
 * Формат dpi_cache.bin:
 *   [uint32_t magic = DPI_ADAPT_MAGIC]
 *   [uint32_t count]
 *   [DpiAdaptRecord × DPI_ADAPT_SLOTS]
 */

#if CONFIG_EBURNET_DPI

#include "dpi/dpi_adapt.h"
#include "4eburnet.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/* FNV1a хэш IP → индекс слота */
static inline uint32_t adapt_hash(uint32_t ip)
{
    uint32_t h = 0x811c9dc5u;
    h ^= (ip & 0xFFu);         h *= 0x01000193u;
    h ^= ((ip >> 8)  & 0xFFu); h *= 0x01000193u;
    h ^= ((ip >> 16) & 0xFFu); h *= 0x01000193u;
    h ^= ((ip >> 24) & 0xFFu); h *= 0x01000193u;
    return h & (DPI_ADAPT_SLOTS - 1u);
}

void dpi_adapt_init(DpiAdaptTable *t)
{
    memset(t, 0, sizeof(*t));
}

/* Найти или создать слот для IP (open addressing, linear probe) */
static DpiAdaptRecord *find_slot(DpiAdaptTable *t, uint32_t ip, bool create)
{
    uint32_t idx = adapt_hash(ip);
    for (uint32_t i = 0; i < DPI_ADAPT_SLOTS; i++) {
        uint32_t s = (idx + i) & (DPI_ADAPT_SLOTS - 1u);
        DpiAdaptRecord *r = &t->slots[s];
        if (r->ip == ip)
            return r;
        if (r->ip == 0) {
            if (!create) return NULL;
            r->ip = ip;
            t->count++;
            return r;
        }
    }
    /* LRU: вытеснить запись с наименьшим last_success */
    uint32_t oldest_time = UINT32_MAX;
    uint32_t oldest_slot = 0;
    for (uint32_t j = 0; j < DPI_ADAPT_SLOTS; j++) {
        if (t->slots[j].last_success < oldest_time) {
            oldest_time = t->slots[j].last_success;
            oldest_slot = j;
        }
    }
    DpiAdaptRecord *r = &t->slots[oldest_slot];
    memset(r, 0, sizeof(*r));
    r->ip = ip;
    return r;
}

dpi_strat_t dpi_adapt_get(const DpiAdaptTable *t, uint32_t ip)
{
    uint32_t idx = adapt_hash(ip);
    for (uint32_t i = 0; i < DPI_ADAPT_SLOTS; i++) {
        uint32_t s = (idx + i) & (DPI_ADAPT_SLOTS - 1u);
        const DpiAdaptRecord *r = &t->slots[s];
        if (r->ip == ip) {
            dpi_strat_t strat = (dpi_strat_t)r->strategy;
            /* Эскалация при нарастании отказов; кэп на BOTH */
            if (r->fail_count >= 3 && strat < DPI_STRAT_BOTH)
                strat = (dpi_strat_t)(strat + 1);
            return strat;
        }
        if (r->ip == 0)
            break;
    }
    return DPI_STRAT_NONE;  /* неизвестный IP — попробовать без обхода */
}

void dpi_adapt_report(DpiAdaptTable *t, uint32_t ip,
                       dpi_strat_t strategy, dpi_result_t result)
{
    DpiAdaptRecord *r = find_slot(t, ip, true);
    if (!r) return;  /* таблица полна */

    if (result == DPI_RESULT_SUCCESS) {
        r->strategy     = (uint8_t)strategy;
        r->fail_count   = 0;
        r->last_success = (uint32_t)time(NULL);
        if (r->hits < UINT32_MAX) r->hits++;
    } else {
        if (r->fail_count < 255) r->fail_count++;
    }
    t->dirty = true;
}

int dpi_adapt_load(DpiAdaptTable *t, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    uint32_t magic = 0, count = 0;
    if (fread(&magic, 4, 1, f) != 1 || magic != DPI_ADAPT_MAGIC ||
        fread(&count, 4, 1, f) != 1) {
        fclose(f);
        return -1;
    }

    size_t n = fread(t->slots, sizeof(DpiAdaptRecord), DPI_ADAPT_SLOTS, f);
    fclose(f);

    if (n != DPI_ADAPT_SLOTS) {
        memset(t->slots, 0, sizeof(t->slots));
        return -1;
    }

    t->count = count;
    t->dirty = false;
    log_msg(LOG_INFO, "DPI adapt: загружено %u записей из %s", count, path);
    return 0;
}

int dpi_adapt_save(const DpiAdaptTable *t, const char *path)
{
    if (!t->dirty) return 0;

    char tmp[280];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) return -1;

    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;

    uint32_t magic = DPI_ADAPT_MAGIC;
    bool ok = (fwrite(&magic,    4,                  1,              f) == 1) &&
              (fwrite(&t->count, 4,                  1,              f) == 1) &&
              (fwrite(t->slots,  sizeof(DpiAdaptRecord),
                      DPI_ADAPT_SLOTS, f) == DPI_ADAPT_SLOTS);
    fclose(f);

    if (!ok) { unlink(tmp); return -1; }
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }

    log_msg(LOG_INFO, "DPI adapt: сохранено %u записей в %s", t->count, path);
    return 0;
}

void dpi_adapt_stats(const DpiAdaptTable *t,
                      uint32_t *out_count, uint32_t *out_hits)
{
    uint32_t hits = 0;
    for (int i = 0; i < DPI_ADAPT_SLOTS; i++)
        hits += t->slots[i].hits;
    if (out_count) *out_count = t->count;
    if (out_hits)  *out_hits  = hits;
}

#endif /* CONFIG_EBURNET_DPI */

/*
 * Глобальные счётчики для IPC stats и LuCI.
 * Атомарные — безопасны для однопоточного демона с signal handlers.
 */

#ifndef EBURNET_STATS_H
#define EBURNET_STATS_H

#include <stdatomic.h>
#include <stdint.h>

typedef struct {
    atomic_uint_fast64_t dns_queries_total;
    atomic_uint_fast64_t dns_cached_total;
    atomic_uint_fast64_t connections_total;
    atomic_uint_fast64_t connections_active;
} eburnet_stats_t;

extern eburnet_stats_t g_stats;

static inline void stats_dns_query(void)  { atomic_fetch_add(&g_stats.dns_queries_total, 1); }
static inline void stats_dns_cached(void) { atomic_fetch_add(&g_stats.dns_cached_total,  1); }
static inline void stats_conn_open(void)  {
    atomic_fetch_add(&g_stats.connections_total,  1);
    atomic_fetch_add(&g_stats.connections_active, 1);
}
static inline void stats_conn_close(void) {
    uint_fast64_t prev = atomic_fetch_sub(&g_stats.connections_active, 1);
    if (prev == 0) atomic_store(&g_stats.connections_active, 0); /* guard underflow */
}

#endif /* EBURNET_STATS_H */

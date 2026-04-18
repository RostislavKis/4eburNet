/*
 * geo_types.h — CIDR структуры и бинарный формат .gbin для geo баз.
 * Используется geo_loader.c и tools/geo_compile.c.
 * Standalone: только stdint.h / stddef.h, никаких зависимостей от демона.
 */

#ifndef GEO_TYPES_H
#define GEO_TYPES_H

#include <stdint.h>
#include <stddef.h>

/* ── CIDR структуры ── */

/* IPv4 CIDR — адреса в host byte order */
typedef struct {
    uint32_t net;   /* сетевой адрес */
    uint32_t mask;  /* маска (0xFFFFFFFF << (32 - prefix)) */
} geo_cidr4_t;

/* IPv6 CIDR */
typedef struct {
    uint8_t net[16]; /* сетевой адрес */
    uint8_t prefix;  /* длина префикса (0..128) */
} geo_cidr6_t;

/* ── Бинарный формат .gbin ── */

#define GEO_BIN_MAGIC    "GEO1"
#define GEO_BIN_VERSION  1

/*
 * Заголовок .gbin файла (36 байт).
 * Раскладка файла:
 *   [geo_bin_header_t 36B]
 *   [uint32_t domain_offsets[domain_count]]   ← смещения в string_pool
 *   [uint32_t suffix_offsets[suffix_count]]   ← смещения в string_pool
 *   [geo_cidr4_t v4[v4_count]]                ← 8 байт каждая
 *   [geo_cidr6_t v6[v6_count]]                ← 17 байт каждая
 *   [char string_pool[string_pool_size]]
 * После mmap — все поинтеры внутрь файла, ни одного malloc.
 */
typedef struct __attribute__((packed)) {
    char     magic[4];           /* "GEO1" */
    uint32_t version;            /* GEO_BIN_VERSION */
    uint32_t region;             /* geo_region_t */
    uint32_t cat_type;           /* geo_cat_type_t */
    uint32_t domain_count;
    uint32_t suffix_count;
    uint32_t v4_count;
    uint32_t v6_count;
    uint32_t string_pool_size;   /* байт в string pool */
} geo_bin_header_t;              /* = 36 байт */

/* ── Вычислить смещение каждой секции внутри файла ── */

static inline size_t geobin_domain_offsets_off(void)
{
    return sizeof(geo_bin_header_t);
}

static inline size_t geobin_suffix_offsets_off(uint32_t domain_count)
{
    return geobin_domain_offsets_off()
           + (size_t)domain_count * sizeof(uint32_t);
}

static inline size_t geobin_v4_off(uint32_t domain_count, uint32_t suffix_count)
{
    return geobin_suffix_offsets_off(domain_count)
           + (size_t)suffix_count * sizeof(uint32_t);
}

static inline size_t geobin_v6_off(uint32_t domain_count, uint32_t suffix_count,
                                    uint32_t v4_count)
{
    return geobin_v4_off(domain_count, suffix_count)
           + (size_t)v4_count * sizeof(geo_cidr4_t);
}

static inline size_t geobin_pool_off(uint32_t domain_count, uint32_t suffix_count,
                                      uint32_t v4_count, uint32_t v6_count)
{
    return geobin_v6_off(domain_count, suffix_count, v4_count)
           + (size_t)v6_count * sizeof(geo_cidr6_t);
}

#endif /* GEO_TYPES_H */

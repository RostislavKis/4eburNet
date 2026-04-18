#ifndef GEO_BLOOM_H
#define GEO_BLOOM_H

#include <stdint.h>
#include <stdbool.h>

/* Размер Bloom filter на категорию */
#define BLOOM_BYTES  (512u * 1024u)   /* 512KB = 4M бит */
/* FPR при 419K доменов, k=3, m=4M: ~1.7% */

/* FNV1a с разными seeds — три независимых хэша */
static inline uint32_t bloom_hash(const char *s, uint32_t seed)
{
    uint32_t h = seed;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 0x01000193u;
    }
    return h;
}

/* Проверить наличие ключа.
 * false → гарантированно НЕТ в set → пропустить bsearch.
 * true  → возможно есть → нужен bsearch для подтверждения.
 * bits=NULL или nbits=0 → всегда true (нет filter). */
static inline bool bloom_check(const uint8_t *bits, uint32_t nbits,
                                const char *key)
{
    if (!bits || nbits == 0) return true;
    uint32_t h0 = bloom_hash(key, 0x811c9dc5u) % nbits;
    uint32_t h1 = bloom_hash(key, 0x01000193u) % nbits;
    uint32_t h2 = bloom_hash(key, 0xc4ac5965u) % nbits;
    return (bits[h0 >> 3] & (1u << (h0 & 7u))) &&
           (bits[h1 >> 3] & (1u << (h1 & 7u))) &&
           (bits[h2 >> 3] & (1u << (h2 & 7u)));
}

/* Добавить ключ в filter (используется в geo_compile). */
static inline void bloom_add(uint8_t *bits, uint32_t nbits,
                              const char *key)
{
    if (!bits || nbits == 0) return;
    uint32_t h0 = bloom_hash(key, 0x811c9dc5u) % nbits;
    uint32_t h1 = bloom_hash(key, 0x01000193u) % nbits;
    uint32_t h2 = bloom_hash(key, 0xc4ac5965u) % nbits;
    bits[h0 >> 3] |= (1u << (h0 & 7u));
    bits[h1 >> 3] |= (1u << (h1 & 7u));
    bits[h2 >> 3] |= (1u << (h2 & 7u));
}

#endif /* GEO_BLOOM_H */

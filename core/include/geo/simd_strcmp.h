#ifndef SIMD_STRCMP_H
#define SIMD_STRCMP_H

#include <stdint.h>
#include <string.h>

/* Портабельное ускоренное сравнение строк.
 * NEON (aarch64/armv7): 16 байт/такт — __ARM_NEON
 * SSE2 (x86_64):        16 байт/такт — __SSE2__
 * SWAR (MIPS32r2):       4 байта/op  — всегда безопасен (memcpy)
 *
 * ТРЕБОВАНИЕ: string_pool должен иметь >= 16 байт нулевого padding в конце
 * (geo_compile добавляет автоматически при VERSION=2).
 * Без padding использовать только SWAR/scalar вариант. */

#if defined(__ARM_NEON)
#include <arm_neon.h>

/* Безопасен только при наличии 16-byte padding в string_pool */
static inline int fast_strcmp(const char *a, const char *b)
{
    for (;;) {
        uint8x16_t va = vld1q_u8((const uint8_t *)a);
        uint8x16_t vb = vld1q_u8((const uint8_t *)b);
        /* Проверить различие */
        uint8x16_t diff = veorq_u8(va, vb);
        uint64_t d0 = vgetq_lane_u64(vreinterpretq_u64_u8(diff), 0);
        uint64_t d1 = vgetq_lane_u64(vreinterpretq_u64_u8(diff), 1);
        if (d0 | d1)
            return strcmp(a, b);  /* fallback для точного результата */
        /* Проверить '\0' в va */
        uint8x16_t zero = vdupq_n_u8(0);
        uint8x16_t znull = vceqq_u8(va, zero);
        uint64_t z0 = vgetq_lane_u64(vreinterpretq_u64_u8(znull), 0);
        uint64_t z1 = vgetq_lane_u64(vreinterpretq_u64_u8(znull), 1);
        if (z0 | z1) return 0;  /* строки равны, \0 найден */
        a += 16; b += 16;
    }
}

#elif defined(__SSE2__)
#include <emmintrin.h>

static inline int fast_strcmp(const char *a, const char *b)
{
    for (;;) {
        __m128i va   = _mm_loadu_si128((const __m128i *)a);
        __m128i vb   = _mm_loadu_si128((const __m128i *)b);
        __m128i diff = _mm_xor_si128(va, vb);
        __m128i zero = _mm_setzero_si128();
        /* Есть различие? */
        if (_mm_movemask_epi8(_mm_cmpeq_epi8(diff, zero)) != 0xFFFF)
            return strcmp(a, b);
        /* Есть '\0'? */
        if (_mm_movemask_epi8(_mm_cmpeq_epi8(va, zero)) != 0)
            return 0;
        a += 16; b += 16;
    }
}

#else
/* SWAR — работает на MIPS32r2 и любой платформе без SIMD.
 * Читает 4 байта через memcpy — безопасен для любого выравнивания.
 * overread безопасен: string_pool имеет 16-byte padding (geo_compile). */
static inline int fast_strcmp(const char *a, const char *b)
{
    for (;;) {
        uint32_t ca, cb;
        memcpy(&ca, a, sizeof(ca));
        memcpy(&cb, b, sizeof(cb));
        if (ca != cb)
            return strcmp(a, b);  /* fallback для точного результата */
        /* haszero: найти '\0' в ca */
        /* Формула: (ca - 0x01010101) & ~ca & 0x80808080 */
        uint32_t hz = (ca - 0x01010101u) & ~ca & 0x80808080u;
        if (hz) return 0;  /* строки равны, \0 внутри слова */
        a += 4; b += 4;
    }
}
#endif

#endif /* SIMD_STRCMP_H */

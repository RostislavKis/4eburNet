/*
 * BLAKE3 — минимальная portable реализация для SS 2022 KDF
 *
 * Поддерживает derive_key mode для входов < 1024 байт (один chunk).
 * Достаточно для SS 2022: blake3_derive_key(context, PSK||salt, 64, key, 32).
 *
 * На основе спецификации BLAKE3 (https://github.com/BLAKE3-team/BLAKE3).
 * Код в публичном домене (как и оригинал).
 */

#include "crypto/blake3.h"
#include <string.h>

/* BLAKE3 IV (те же что BLAKE2s) */
static const uint32_t IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

/* Флаги */
enum {
    CHUNK_START         = 1 << 0,
    CHUNK_END           = 1 << 1,
    PARENT              = 1 << 2,
    ROOT                = 1 << 3,
    KEYED_HASH          = 1 << 4,
    DERIVE_KEY_CONTEXT  = 1 << 5,
    DERIVE_KEY_MATERIAL = 1 << 6,
};

/* Перестановка сообщения между раундами */
static const uint8_t MSG_SCHEDULE[7][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    { 2, 6, 3,10, 7, 0, 4,13, 1,11,12, 5, 9,14,15, 8},
    { 3, 4,10,12,13, 2, 7,14, 6, 5, 9, 0,11,15, 8, 1},
    {10, 7,12,14, 2, 6, 4, 9, 3, 1,13,11, 5,15, 8, 0},
    {12,13,14, 9, 6,10, 4, 1, 7, 3, 5,11, 0, 8,15, 2},
    {14, 4, 9,13,10, 8, 7,15, 1,12, 2, 0,11, 5, 3, 6},
    { 9, 8,15,13, 1,10,14, 3, 7, 4,12, 5, 6,11, 0, 2},
};

static inline uint32_t rotr32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* Четвертьраунд G */
static inline void g(uint32_t *s, int a, int b, int c, int d,
                     uint32_t mx, uint32_t my)
{
    s[a] = s[a] + s[b] + mx;
    s[d] = rotr32(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d];
    s[b] = rotr32(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my;
    s[d] = rotr32(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d];
    s[b] = rotr32(s[b] ^ s[c], 7);
}

/* Функция сжатия BLAKE3 */
static void compress(const uint32_t cv[8],
                     const uint8_t block[BLAKE3_BLOCK_LEN],
                     uint64_t counter, uint32_t block_len,
                     uint32_t flags,
                     uint32_t out[16])
{
    uint32_t m[16];
    for (int i = 0; i < 16; i++)
        m[i] = load32_le(block + 4 * i);

    uint32_t s[16] = {
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        (uint32_t)counter, (uint32_t)(counter >> 32),
        block_len, flags,
    };

    for (int r = 0; r < 7; r++) {
        const uint8_t *sched = MSG_SCHEDULE[r];
        /* Столбцы */
        g(s, 0, 4,  8, 12, m[sched[ 0]], m[sched[ 1]]);
        g(s, 1, 5,  9, 13, m[sched[ 2]], m[sched[ 3]]);
        g(s, 2, 6, 10, 14, m[sched[ 4]], m[sched[ 5]]);
        g(s, 3, 7, 11, 15, m[sched[ 6]], m[sched[ 7]]);
        /* Диагонали */
        g(s, 0, 5, 10, 15, m[sched[ 8]], m[sched[ 9]]);
        g(s, 1, 6, 11, 12, m[sched[10]], m[sched[11]]);
        g(s, 2, 7,  8, 13, m[sched[12]], m[sched[13]]);
        g(s, 3, 4,  9, 14, m[sched[14]], m[sched[15]]);
    }

    for (int i = 0; i < 8; i++) {
        out[i]     = s[i] ^ s[i + 8];
        out[i + 8] = s[i + 8] ^ cv[i];
    }
}

/* Обработать один блок внутри chunk */
static void hasher_compress_block(blake3_hasher *self)
{
    uint32_t flags = self->flags;
    if (self->blocks_compressed == 0)
        flags |= CHUNK_START;

    uint32_t out[16];
    compress(self->cv, self->buf, self->chunk_counter,
             self->buf_len, flags, out);

    memcpy(self->cv, out, 32);
    self->blocks_compressed++;
    self->buf_len = 0;
}

/* Инициализация hasher с заданным ключом и флагами */
static void hasher_init_internal(blake3_hasher *self,
                                 const uint32_t key[8],
                                 uint8_t flags)
{
    memset(self, 0, sizeof(*self));
    memcpy(self->cv, key, 32);
    self->flags = flags;
}

/* ------------------------------------------------------------------ */
/*  Публичный API                                                      */
/* ------------------------------------------------------------------ */

void blake3_hasher_init_derive_key(blake3_hasher *self,
                                   const char *context)
{
    /* Шаг 1: хэшировать context string с IV в режиме DERIVE_KEY_CONTEXT */
    blake3_hasher ctx_hasher;
    hasher_init_internal(&ctx_hasher, IV, DERIVE_KEY_CONTEXT);
    blake3_hasher_update(&ctx_hasher, context, strlen(context));

    uint8_t context_key[BLAKE3_KEY_LEN];
    blake3_hasher_finalize(&ctx_hasher, context_key, BLAKE3_KEY_LEN);

    /* Шаг 2: использовать context_key как начальный ключ */
    uint32_t key_words[8];
    for (int i = 0; i < 8; i++)
        key_words[i] = load32_le(context_key + 4 * i);

    hasher_init_internal(self, key_words, DERIVE_KEY_MATERIAL);
}

void blake3_hasher_update(blake3_hasher *self,
                          const void *input, size_t input_len)
{
    /* Ограничение: single-chunk <= 1024 байт.
     * Для SS2022 KDF достаточно (64 байта PSK||salt). */
    const uint8_t *data = input;

    while (input_len > 0) {
        /* Если буфер полный — сжать */
        if (self->buf_len == BLAKE3_BLOCK_LEN)
            hasher_compress_block(self);

        size_t want = BLAKE3_BLOCK_LEN - self->buf_len;
        if (want > input_len) want = input_len;

        memcpy(self->buf + self->buf_len, data, want);
        self->buf_len += want;
        data += want;
        input_len -= want;
    }
}

void blake3_hasher_finalize(const blake3_hasher *self,
                            uint8_t *out, size_t out_len)
{
    /* Финальный блок: CHUNK_END + ROOT */
    uint32_t flags = self->flags | CHUNK_END | ROOT;
    if (self->blocks_compressed == 0)
        flags |= CHUNK_START;

    uint32_t out_words[16];
    compress(self->cv, self->buf, self->chunk_counter,
             self->buf_len, flags, out_words);

    /* Записываем выход (до 64 байт из 16 слов) */
    size_t words_needed = (out_len + 3) / 4;
    if (words_needed > 16) words_needed = 16;

    uint8_t full_out[64];
    for (size_t i = 0; i < words_needed; i++)
        store32_le(full_out + 4 * i, out_words[i]);

    if (out_len > 64) out_len = 64;
    memcpy(out, full_out, out_len);
}

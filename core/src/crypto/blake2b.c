/*
 * BLAKE2b — RFC 7693 реализация
 *
 * Используется в Hysteria2 Salamander obfuscation.
 * Тестовые векторы: RFC 7693 Appendix A.
 */

#include "crypto/blake2b.h"

#include <string.h>

/* ── Вспомогательные макросы ──────────────────────────────────────────── */

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static inline uint64_t load64_le(const void *src)
{
    const uint8_t *p = (const uint8_t *)src;
    return (uint64_t)p[0]
         | ((uint64_t)p[1] <<  8)
         | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}

static inline void store64_le(void *dst, uint64_t v)
{
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(v      );
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

/* ── Константы RFC 7693 §2.6 ──────────────────────────────────────────── */

/* IV = первые 64 бита дробных частей sqrt простых 2..19 */
static const uint64_t BLAKE2B_IV[8] = {
    UINT64_C(0x6a09e667f3bcc908),
    UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b),
    UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1),
    UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b),
    UINT64_C(0x5be0cd19137e2179),
};

/* Таблица перестановок (RFC 7693 Table 10) */
static const uint8_t SIGMA[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
};

/* ── G функция (RFC 7693 §3.1, BLAKE2b ротации: 32/24/16/63) ─────────── */

#define G(v, a, b, c, d, x, y) do {          \
    (v)[a] += (v)[b] + (x);                   \
    (v)[d]  = ROTR64((v)[d] ^ (v)[a], 32);   \
    (v)[c] += (v)[d];                         \
    (v)[b]  = ROTR64((v)[b] ^ (v)[c], 24);   \
    (v)[a] += (v)[b] + (y);                   \
    (v)[d]  = ROTR64((v)[d] ^ (v)[a], 16);   \
    (v)[c] += (v)[d];                         \
    (v)[b]  = ROTR64((v)[b] ^ (v)[c], 63);   \
} while (0)

/* ── Compress (12 раундов) ───────────────────────────────────────────── */

static void blake2b_compress(blake2b_state *S,
                              const uint8_t block[BLAKE2B_BLOCKBYTES])
{
    uint64_t m[16];
    uint64_t v[16];

    for (int i = 0; i < 16; i++)
        m[i] = load64_le(block + i * 8);

    for (int i = 0; i < 8; i++)
        v[i] = S->h[i];

    v[ 8] = BLAKE2B_IV[0];
    v[ 9] = BLAKE2B_IV[1];
    v[10] = BLAKE2B_IV[2];
    v[11] = BLAKE2B_IV[3];
    v[12] = BLAKE2B_IV[4] ^ S->t[0];
    v[13] = BLAKE2B_IV[5] ^ S->t[1];
    v[14] = BLAKE2B_IV[6] ^ S->f[0];
    v[15] = BLAKE2B_IV[7] ^ S->f[1];

    for (int r = 0; r < 12; r++) {
        const uint8_t *s = SIGMA[r];
        G(v,  0,  4,  8, 12, m[s[ 0]], m[s[ 1]]);
        G(v,  1,  5,  9, 13, m[s[ 2]], m[s[ 3]]);
        G(v,  2,  6, 10, 14, m[s[ 4]], m[s[ 5]]);
        G(v,  3,  7, 11, 15, m[s[ 6]], m[s[ 7]]);
        G(v,  0,  5, 10, 15, m[s[ 8]], m[s[ 9]]);
        G(v,  1,  6, 11, 12, m[s[10]], m[s[11]]);
        G(v,  2,  7,  8, 13, m[s[12]], m[s[13]]);
        G(v,  3,  4,  9, 14, m[s[14]], m[s[15]]);
    }

    for (int i = 0; i < 8; i++)
        S->h[i] ^= v[i] ^ v[i + 8];
}

/* ── Инкремент счётчика (128-битный, LE) ────────────────────────────── */

static void blake2b_increment_counter(blake2b_state *S, uint64_t inc)
{
    S->t[0] += inc;
    if (S->t[0] < inc)
        S->t[1]++;  /* перенос в старшую половину */
}

/* ── Инициализация ────────────────────────────────────────────────────── */

int blake2b_init(blake2b_state *S, size_t outlen)
{
    if (!S || outlen == 0 || outlen > BLAKE2B_OUTBYTES)
        return -1;

    blake2b_param P;
    memset(&P, 0, sizeof(P));
    P.digest_length = (uint8_t)outlen;
    P.fanout        = 1;
    P.depth         = 1;

    /* h[i] = IV[i] XOR P[i*8..(i+1)*8) */
    const uint8_t *p = (const uint8_t *)&P;
    for (int i = 0; i < 8; i++)
        S->h[i] = BLAKE2B_IV[i] ^ load64_le(p + i * 8);

    S->t[0] = S->t[1] = 0;
    S->f[0] = S->f[1] = 0;
    S->buflen = 0;
    S->outlen = outlen;
    memset(S->buf, 0, sizeof(S->buf));

    return 0;
}

int blake2b_init_key(blake2b_state *S, size_t outlen,
                     const void *key, size_t keylen)
{
    if (!S || !key || keylen == 0 || keylen > BLAKE2B_KEYBYTES)
        return -1;
    if (outlen == 0 || outlen > BLAKE2B_OUTBYTES)
        return -1;

    blake2b_param P;
    memset(&P, 0, sizeof(P));
    P.digest_length = (uint8_t)outlen;
    P.key_length    = (uint8_t)keylen;
    P.fanout        = 1;
    P.depth         = 1;

    const uint8_t *p = (const uint8_t *)&P;
    for (int i = 0; i < 8; i++)
        S->h[i] = BLAKE2B_IV[i] ^ load64_le(p + i * 8);

    S->t[0] = S->t[1] = 0;
    S->f[0] = S->f[1] = 0;
    S->buflen = 0;
    S->outlen = outlen;
    memset(S->buf, 0, sizeof(S->buf));

    /* Первый блок = key || zeros (ровно 128 байт) */
    uint8_t block[BLAKE2B_BLOCKBYTES];
    memset(block, 0, sizeof(block));
    memcpy(block, key, keylen);
    blake2b_update(S, block, BLAKE2B_BLOCKBYTES);
    memset(block, 0, sizeof(block));

    return 0;
}

/* ── Update ───────────────────────────────────────────────────────────── */

int blake2b_update(blake2b_state *S, const void *in, size_t inlen)
{
    if (!S || inlen == 0)
        return 0;
    if (!in)
        return -1;

    const uint8_t *pin = (const uint8_t *)in;
    size_t left = S->buflen;
    size_t fill = BLAKE2B_BLOCKBYTES - left;

    if (inlen > fill) {
        /* Заполнить буфер и сжать */
        memcpy(S->buf + left, pin, fill);
        blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
        blake2b_compress(S, S->buf);
        memset(S->buf, 0, sizeof(S->buf));
        S->buflen = 0;
        pin   += fill;
        inlen -= fill;

        /* Сжать полные блоки напрямую (оставить последний для final) */
        while (inlen > BLAKE2B_BLOCKBYTES) {
            blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
            blake2b_compress(S, pin);
            pin   += BLAKE2B_BLOCKBYTES;
            inlen -= BLAKE2B_BLOCKBYTES;
        }
    }

    /* Сохранить остаток в буфере */
    memcpy(S->buf + S->buflen, pin, inlen);
    S->buflen += inlen;

    return 0;
}

/* ── Final ────────────────────────────────────────────────────────────── */

int blake2b_final(blake2b_state *S, void *out, size_t outlen)
{
    if (!S || !out || outlen < S->outlen)
        return -1;

    /* Установить флаг последнего блока */
    S->f[0] = UINT64_MAX;

    /* Дополнить буфер нулями и сжать */
    memset(S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen);
    blake2b_increment_counter(S, S->buflen);
    blake2b_compress(S, S->buf);

    /* Записать результат в little-endian */
    uint8_t digest[BLAKE2B_OUTBYTES];
    for (int i = 0; i < 8; i++)
        store64_le(digest + i * 8, S->h[i]);

    memcpy(out, digest, S->outlen);

    /* Зачистить состояние */
    memset(S, 0, sizeof(*S));
    memset(digest, 0, sizeof(digest));

    return 0;
}

/* ── Однократный вызов ────────────────────────────────────────────────── */

int blake2b(void *out, size_t outlen,
            const void *in,  size_t inlen,
            const void *key, size_t keylen)
{
    blake2b_state S;
    int ret;

    if (keylen > 0)
        ret = blake2b_init_key(&S, outlen, key, keylen);
    else
        ret = blake2b_init(&S, outlen);

    if (ret < 0)
        return ret;

    /* in == NULL допустим только при inlen == 0 */
    if (inlen > 0) {
        ret = blake2b_update(&S, in, inlen);
        if (ret < 0) {
            memset(&S, 0, sizeof(S));
            return ret;
        }
    }

    return blake2b_final(&S, out, outlen);
}

/* ── Salamander helper ────────────────────────────────────────────────── */

/*
 * Hysteria2 Salamander (QUIC obfuscation):
 *   key_out = BLAKE2b-256(salt || psk)
 */
int blake2b_salamander(const uint8_t *salt, size_t salt_len,
                       const uint8_t *psk,  size_t psk_len,
                       uint8_t *key_out,    size_t key_len)
{
    if (!salt || !psk || !key_out)      return -1;
    if (salt_len == 0 || psk_len == 0)  return -1;
    if (key_len == 0)  key_len = 32;    /* по умолчанию 256 бит */
    if (key_len > BLAKE2B_OUTBYTES)     return -1;

    blake2b_state S;
    if (blake2b_init(&S, key_len) < 0)              return -1;
    if (blake2b_update(&S, salt, salt_len) < 0)     goto fail;
    if (blake2b_update(&S, psk,  psk_len)  < 0)     goto fail;
    return blake2b_final(&S, key_out, key_len);

fail:
    memset(&S, 0, sizeof(S));
    return -1;
}

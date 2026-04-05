/*
 * BLAKE2s — portable реализация для Noise/WireGuard
 * wolfSSL не скомпилирован с --enable-blake2s, используем свою.
 */

#include "crypto/blake2s.h"
#include <string.h>
#include <strings.h>  /* explicit_bzero */

#define BLAKE2S_BLOCK  64
#define BLAKE2S_OUT    32

static const uint32_t blake2s_iv[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

static const uint8_t blake2s_sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,13,12, 0},
};

static inline uint32_t rotr32(uint32_t x, int n) { return (x>>n)|(x<<(32-n)); }
static inline uint32_t load32(const void *p) {
    const uint8_t *b = p;
    return (uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16)|((uint32_t)b[3]<<24);
}

/* blake2s_state_t определён в blake2s.h */

static void blake2s_compress(blake2s_state_t *s, const uint8_t block[BLAKE2S_BLOCK])
{
    uint32_t m[16], v[16];
    for (int i = 0; i < 16; i++) m[i] = load32(block + i*4);

    for (int i = 0; i < 8; i++) v[i] = s->h[i];
    v[8] = blake2s_iv[0]; v[9] = blake2s_iv[1];
    v[10] = blake2s_iv[2]; v[11] = blake2s_iv[3];
    v[12] = blake2s_iv[4] ^ s->t[0];
    v[13] = blake2s_iv[5] ^ s->t[1];
    v[14] = blake2s_iv[6] ^ s->f[0];
    v[15] = blake2s_iv[7] ^ s->f[1];

    #define G(r,i,a,b,c,d) do { \
        v[a]+=v[b]+m[blake2s_sigma[r][2*i]]; v[d]=rotr32(v[d]^v[a],16); \
        v[c]+=v[d]; v[b]=rotr32(v[b]^v[c],12); \
        v[a]+=v[b]+m[blake2s_sigma[r][2*i+1]]; v[d]=rotr32(v[d]^v[a],8); \
        v[c]+=v[d]; v[b]=rotr32(v[b]^v[c],7); \
    } while(0)

    for (int r = 0; r < 10; r++) {
        G(r,0,0,4, 8,12); G(r,1,1,5, 9,13);
        G(r,2,2,6,10,14); G(r,3,3,7,11,15);
        G(r,4,0,5,10,15); G(r,5,1,6,11,12);
        G(r,6,2,7, 8,13); G(r,7,3,4, 9,14);
    }
    #undef G

    for (int i = 0; i < 8; i++) s->h[i] ^= v[i] ^ v[i+8];

    /* L-02: обнулить промежуточные данные на стеке */
    explicit_bzero(m, sizeof(m));
    explicit_bzero(v, sizeof(v));
}

void blake2s_init(blake2s_state_t *s, size_t outlen,
                  const uint8_t *key, size_t keylen)
{
    /* Защита от переполнения: BLAKE2s max key = 32, max out = 32 */
    if (outlen == 0 || outlen > BLAKE2S_OUT) {
        memset(s, 0, sizeof(*s));
        return;
    }
    if (keylen > BLAKE2S_OUT) keylen = BLAKE2S_OUT;

    memset(s, 0, sizeof(*s));
    for (int i = 0; i < 8; i++) s->h[i] = blake2s_iv[i];
    s->h[0] ^= 0x01010000 ^ ((uint32_t)keylen << 8) ^ (uint32_t)outlen;
    s->outlen = (uint8_t)outlen;

    if (keylen > 0) {
        uint8_t block[BLAKE2S_BLOCK] = {0};
        memcpy(block, key, keylen);
        s->t[0] = BLAKE2S_BLOCK;
        blake2s_compress(s, block);
        /* H-07: обнулить ключевой материал на стеке */
        explicit_bzero(block, sizeof(block));
    }
}

void blake2s_update(blake2s_state_t *s, const void *data, size_t len)
{
    const uint8_t *p = data;
    while (len > 0) {
        if (s->buflen == BLAKE2S_BLOCK) {
            s->t[0] += BLAKE2S_BLOCK;
            if (s->t[0] < BLAKE2S_BLOCK) s->t[1]++;
            blake2s_compress(s, s->buf);
            s->buflen = 0;
        }
        size_t fill = BLAKE2S_BLOCK - s->buflen;
        if (fill > len) fill = len;
        memcpy(s->buf + s->buflen, p, fill);
        s->buflen += fill;
        p += fill; len -= fill;
    }
}

void blake2s_final(blake2s_state_t *s, uint8_t *out)
{
    s->t[0] += (uint32_t)s->buflen;
    if (s->t[0] < s->buflen) s->t[1]++;
    s->f[0] = ~(uint32_t)0;
    memset(s->buf + s->buflen, 0, BLAKE2S_BLOCK - s->buflen);
    blake2s_compress(s, s->buf);

    for (size_t i = 0; i < s->outlen; i++)
        out[i] = (s->h[i/4] >> (8*(i%4))) & 0xFF;
}

/* ------------------------------------------------------------------ */
/*  Публичный API                                                      */
/* ------------------------------------------------------------------ */

void blake2s_hash(uint8_t *out, size_t outlen,
                  const void *in, size_t inlen)
{
    blake2s_state_t s;
    blake2s_init(&s, outlen, NULL, 0);
    blake2s_update(&s, in, inlen);
    blake2s_final(&s, out);
}

void blake2s_keyed(uint8_t *out, size_t outlen,
                   const uint8_t *key, size_t keylen,
                   const void *in, size_t inlen)
{
    blake2s_state_t s;
    blake2s_init(&s, outlen, key, keylen);
    blake2s_update(&s, in, inlen);
    blake2s_final(&s, out);
}

/*
 * HMAC для Noise/WireGuard: keyed BLAKE2s, НЕ классический HMAC(ipad/opad).
 * Noise spec: HMAC(key, input) = BLAKE2s(key=key, input=input).
 */
void blake2s_hmac(uint8_t *out, size_t outlen,
                  const uint8_t *key, size_t keylen,
                  const uint8_t *in, size_t inlen)
{
    blake2s_keyed(out, outlen, key, keylen, in, inlen);
}

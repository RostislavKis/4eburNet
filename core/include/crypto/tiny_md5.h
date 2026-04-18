#ifndef TINY_MD5_H
#define TINY_MD5_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* Tiny MD5 — RFC 1321 реализация для JA3 fingerprint.
 * Не использует wolfSSL (NO_MD5 в текущей сборке).
 * Только для fingerprinting, не для криптографических целей. */

typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t  buf[64];
} tiny_md5_ctx;

/* ── Реализация (RFC 1321) ───────────────────────────────────── */

#define _MD5_F(x,y,z) (((x)&(y))|((~(x))&(z)))
#define _MD5_G(x,y,z) (((x)&(z))|((y)&(~(z))))
#define _MD5_H(x,y,z) ((x)^(y)^(z))
#define _MD5_I(x,y,z) ((y)^((x)|(~(z))))
#define _MD5_ROT(x,n) (((x)<<(n))|((x)>>(32-(n))))

static const uint32_t tiny_md5_T[64] = {
    0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,
    0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
    0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,
    0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
    0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,
    0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
    0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,
    0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
    0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,
    0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
    0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,
    0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
    0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,
    0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
    0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,
    0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u,
};

static const uint8_t tiny_md5_S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
};

static inline void tiny_md5_transform(uint32_t state[4],
                                       const uint8_t block[64])
{
    uint32_t a = state[0], b = state[1],
             c = state[2], d = state[3], x[16];
    for (int i = 0; i < 16; i++) {
        x[i] = (uint32_t)block[i*4]          |
               ((uint32_t)block[i*4+1] << 8)  |
               ((uint32_t)block[i*4+2] << 16) |
               ((uint32_t)block[i*4+3] << 24);
    }
    for (int i = 0; i < 64; i++) {
        uint32_t f, g;
        if      (i < 16) { f = _MD5_F(b,c,d); g = (uint32_t)i; }
        else if (i < 32) { f = _MD5_G(b,c,d); g = (uint32_t)(5*i+1)%16; }
        else if (i < 48) { f = _MD5_H(b,c,d); g = (uint32_t)(3*i+5)%16; }
        else             { f = _MD5_I(b,c,d); g = (uint32_t)(7*i)%16;   }
        uint32_t temp = d;
        d = c; c = b;
        b = b + _MD5_ROT(a + f + x[g] + tiny_md5_T[i], tiny_md5_S[i]);
        a = temp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static inline void tiny_md5_init(tiny_md5_ctx *ctx)
{
    ctx->state[0] = 0x67452301u;
    ctx->state[1] = 0xefcdab89u;
    ctx->state[2] = 0x98badcfeu;
    ctx->state[3] = 0x10325476u;
    ctx->count[0] = ctx->count[1] = 0;
}

static inline void tiny_md5_update(tiny_md5_ctx *ctx,
                                    const uint8_t *data, size_t len)
{
    size_t idx = (ctx->count[0] >> 3) & 63u;
    ctx->count[0] += (uint32_t)(len << 3);
    if (ctx->count[0] < (uint32_t)(len << 3)) ctx->count[1]++;
    ctx->count[1] += (uint32_t)(len >> 29);
    size_t part = 64 - idx;
    size_t i = 0;
    if (len >= part) {
        memcpy(ctx->buf + idx, data, part);
        tiny_md5_transform(ctx->state, ctx->buf);
        for (i = part; i + 63 < len; i += 64)
            tiny_md5_transform(ctx->state, data + i);
        idx = 0;
    }
    memcpy(ctx->buf + idx, data + i, len - i);
}

static inline void tiny_md5_final(tiny_md5_ctx *ctx, uint8_t digest[16])
{
    static const uint8_t pad[64] = {0x80};
    uint8_t bits[8];
    for (int i = 0; i < 4; i++) {
        bits[i]   = (uint8_t)((ctx->count[0] >> (i*8)) & 0xFF);
        bits[i+4] = (uint8_t)((ctx->count[1] >> (i*8)) & 0xFF);
    }
    size_t idx = (ctx->count[0] >> 3) & 63u;
    size_t pad_len = (idx < 56) ? 56 - idx : 120 - idx;
    tiny_md5_update(ctx, pad, pad_len);
    tiny_md5_update(ctx, bits, 8);
    for (int i = 0; i < 4; i++) {
        digest[i*4]   = (uint8_t)(ctx->state[i] & 0xFF);
        digest[i*4+1] = (uint8_t)((ctx->state[i] >> 8)  & 0xFF);
        digest[i*4+2] = (uint8_t)((ctx->state[i] >> 16) & 0xFF);
        digest[i*4+3] = (uint8_t)((ctx->state[i] >> 24) & 0xFF);
    }
}

/* tiny_md5_hex — вычислить MD5 строки → 32 hex символа + \0 */
static inline void tiny_md5_hex(const char *str, char hex_out[33])
{
    tiny_md5_ctx ctx;
    uint8_t digest[16];
    tiny_md5_init(&ctx);
    tiny_md5_update(&ctx, (const uint8_t *)str, strlen(str));
    tiny_md5_final(&ctx, digest);
    for (int i = 0; i < 16; i++)
        snprintf(hex_out + i*2, 3, "%02x", (unsigned)digest[i]);
    hex_out[32] = '\0';
}

#undef _MD5_F
#undef _MD5_G
#undef _MD5_H
#undef _MD5_I
#undef _MD5_ROT

#endif /* TINY_MD5_H */

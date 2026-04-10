/*
 * BLAKE2b — криптографическая хэш-функция (RFC 7693)
 *
 * Используется в Hysteria2 Salamander obfuscation:
 *   BLAKE2b-256(8-байтный salt + psk) → 32-байтный XOR ключ
 *
 * Отличия от BLAKE2s:
 *   - 64-битные слова (uint64_t vs uint32_t)
 *   - 12 раундов (vs 10 у BLAKE2s)
 *   - блок 128 байт (vs 64)
 *   - максимальный дайджест 64 байта (vs 32)
 */

#ifndef EBURNET_BLAKE2B_H
#define EBURNET_BLAKE2B_H

#include <stdint.h>
#include <stddef.h>

#define BLAKE2B_BLOCKBYTES    128
#define BLAKE2B_OUTBYTES       64
#define BLAKE2B_KEYBYTES       64
#define BLAKE2B_SALTBYTES      16
#define BLAKE2B_PERSONALBYTES  16

/* Контекст хэширования */
typedef struct {
    uint64_t h[8];                    /* chained state (512 бит) */
    uint64_t t[2];                    /* счётчик обработанных байт */
    uint64_t f[2];                    /* флаги финализации */
    uint8_t  buf[BLAKE2B_BLOCKBYTES]; /* входной буфер */
    size_t   buflen;                  /* байт в буфере */
    size_t   outlen;                  /* длина дайджеста (1..64) */
} blake2b_state;

/* Параметрный блок (RFC 7693 §2.8, упрощённый — sequential mode) */
typedef struct {
    uint8_t  digest_length;                    /* 1..64 */
    uint8_t  key_length;                       /* 0..64 */
    uint8_t  fanout;                           /* 1 для sequential */
    uint8_t  depth;                            /* 1 для sequential */
    uint32_t leaf_length;
    uint32_t node_offset_lo;
    uint32_t node_offset_hi;
    uint8_t  node_depth;
    uint8_t  inner_length;
    uint8_t  reserved[14];
    uint8_t  salt[BLAKE2B_SALTBYTES];
    uint8_t  personal[BLAKE2B_PERSONALBYTES];
} __attribute__((packed)) blake2b_param;

/* API */
int blake2b_init(blake2b_state *S, size_t outlen);
int blake2b_init_key(blake2b_state *S, size_t outlen,
                     const void *key, size_t keylen);
int blake2b_update(blake2b_state *S, const void *in, size_t inlen);
int blake2b_final(blake2b_state *S, void *out, size_t outlen);

/* Однократный вызов */
int blake2b(void *out, size_t outlen,
            const void *in, size_t inlen,
            const void *key, size_t keylen);

/*
 * Salamander helper:
 *   key_out = BLAKE2b-256(salt || psk)
 *
 * salt:    8-байтный случайный префикс QUIC пакета
 * psk:     pre-shared key из конфига
 * key_out: 32-байтный XOR ключ
 */
int blake2b_salamander(const uint8_t *salt, size_t salt_len,
                       const uint8_t *psk,  size_t psk_len,
                       uint8_t *key_out,    size_t key_len);

#endif /* EBURNET_BLAKE2B_H */

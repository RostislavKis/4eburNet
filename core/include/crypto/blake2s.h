#ifndef BLAKE2S_H
#define BLAKE2S_H

#include <stdint.h>
#include <stddef.h>

/* Состояние BLAKE2s (для incremental API) */
typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[64];
    size_t   buflen;
    uint8_t  outlen;
} blake2s_state_t;

/* Incremental API */
void blake2s_init(blake2s_state_t *s, size_t outlen,
                  const uint8_t *key, size_t keylen);
void blake2s_update(blake2s_state_t *s, const void *data, size_t len);
void blake2s_final(blake2s_state_t *s, uint8_t *out);

/* Простой хэш */
void blake2s_hash(uint8_t *out, size_t outlen,
                  const void *in, size_t inlen);

/* Keyed BLAKE2s (MAC) */
void blake2s_keyed(uint8_t *out, size_t outlen,
                   const uint8_t *key, size_t keylen,
                   const void *in, size_t inlen);

/* HMAC-BLAKE2s для Noise HKDF */
void blake2s_hmac(uint8_t *out, size_t outlen,
                  const uint8_t *key, size_t keylen,
                  const uint8_t *in, size_t inlen);

#endif /* BLAKE2S_H */

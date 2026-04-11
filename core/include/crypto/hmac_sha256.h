/*
 * hmac_sha256.h — HMAC-SHA256 обёртка wolfSSL (D.1)
 *
 * Используется ShadowTLS v3 для SessionID и AppData тегов.
 * Компилируется при CONFIG_EBURNET_STLS=1.
 */

#ifndef EBURNET_HMAC_SHA256_H
#define EBURNET_HMAC_SHA256_H

#if CONFIG_EBURNET_STLS

#include <stdint.h>
#include <stddef.h>

/* Вычислить HMAC-SHA256. out — минимум 32 байта. Возвращает 0 или -1. */
int hmac_sha256(const uint8_t *key, size_t keylen,
                const uint8_t *data, size_t datalen,
                uint8_t out[32]);

/*
 * Вычислить HMAC-SHA256 и сравнить первые cmplen байт с expected.
 * Constant-time compare (M-11: без short-circuit).
 * Возвращает 1 если равны, 0 если нет.
 */
int hmac_sha256_verify(const uint8_t *key, size_t keylen,
                       const uint8_t *data, size_t datalen,
                       const uint8_t *expected, size_t cmplen);

#endif /* CONFIG_EBURNET_STLS */
#endif /* EBURNET_HMAC_SHA256_H */

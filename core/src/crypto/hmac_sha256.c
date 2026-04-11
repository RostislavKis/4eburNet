/*
 * hmac_sha256.c — HMAC-SHA256 через wolfSSL (D.1)
 */

#if CONFIG_EBURNET_STLS

#include "crypto/hmac_sha256.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <string.h>

int hmac_sha256(const uint8_t *key, size_t keylen,
                const uint8_t *data, size_t datalen,
                uint8_t out[32])
{
    if (!key || !out) return -1;

    Hmac h;
    if (wc_HmacInit(&h, NULL, INVALID_DEVID) != 0) return -1;
    if (wc_HmacSetKey(&h, WC_SHA256, key, (word32)keylen) != 0) {
        wc_HmacFree(&h); return -1;
    }
    if (datalen > 0 && data) {
        if (wc_HmacUpdate(&h, data, (word32)datalen) != 0) {
            wc_HmacFree(&h); return -1;
        }
    }
    if (wc_HmacFinal(&h, out) != 0) {
        wc_HmacFree(&h); return -1;
    }
    wc_HmacFree(&h);
    return 0;
}

int hmac_sha256_2(const uint8_t *key, size_t keylen,
                  const uint8_t *data1, size_t len1,
                  const uint8_t *data2, size_t len2,
                  uint8_t out[32])
{
    if (!key || !out) return -1;

    Hmac h;
    if (wc_HmacInit(&h, NULL, INVALID_DEVID) != 0) return -1;
    if (wc_HmacSetKey(&h, WC_SHA256, key, (word32)keylen) != 0) {
        wc_HmacFree(&h); return -1;
    }
    if (len1 > 0 && data1) {
        if (wc_HmacUpdate(&h, data1, (word32)len1) != 0) {
            wc_HmacFree(&h); return -1;
        }
    }
    if (len2 > 0 && data2) {
        if (wc_HmacUpdate(&h, data2, (word32)len2) != 0) {
            wc_HmacFree(&h); return -1;
        }
    }
    if (wc_HmacFinal(&h, out) != 0) {
        wc_HmacFree(&h); return -1;
    }
    wc_HmacFree(&h);
    return 0;
}

int hmac_sha256_verify(const uint8_t *key, size_t keylen,
                       const uint8_t *data, size_t datalen,
                       const uint8_t *expected, size_t cmplen)
{
    if (!expected) return 0;

    uint8_t computed[32];
    if (hmac_sha256(key, keylen, data, datalen, computed) != 0) return 0;
    if (cmplen > 32) cmplen = 32;

    /* Constant-time compare (M-11: не short-circuit) */
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < cmplen; i++)
        diff |= computed[i] ^ expected[i];

    return (diff == 0) ? 1 : 0;
}

#endif /* CONFIG_EBURNET_STLS */

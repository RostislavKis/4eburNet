#define _XOPEN_SOURCE 700
#include "crypto/quic.h"

#ifdef CONFIG_PHOENIX_DOQ

#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/openssl/evp.h>   /* wolfSSL_EVP_CIPHER_CTX_free, wolfSSL_EVP_Cipher_key_length */
#include "phoenix.h"               /* log_msg */

/* ── инициализация ───────────────────────────────────────────── */

int quic_ctx_init(WOLFSSL_CTX *ctx, const WOLFSSL_QUIC_METHOD *method)
{
    if (!ctx || !method) return -1;
    int rc = wolfSSL_CTX_set_quic_method(ctx, method);
    return (rc == WOLFSSL_SUCCESS) ? 0 : -1;
}

/* ── вспомогательные static ─────────────────────────────────── */

/* Построить HkdfLabel и выполнить HKDF-Expand-Label (RFC 8446 §7.1).
 * Использует wolfSSL_quic_hkdf_expand — принимает уже извлечённый PRK. */
static int hkdf_expand_label(WOLFSSL *ssl,
                              const uint8_t *secret, size_t slen,
                              const char *label,
                              uint8_t *out, size_t outlen)
{
    const WOLFSSL_EVP_MD *md = wolfSSL_quic_get_md(ssl);
    if (!md) md = wolfSSL_EVP_sha256();   /* fallback для initial-уровня */

    /* HkdfLabel: uint16 length || uint8 label_len || label || uint8 ctx_len=0 */
    uint8_t info[256];
    size_t  pos  = 0;
    const char prefix[] = "tls13 ";
    size_t  plen = 6;
    size_t  llen = strlen(label);

    info[pos++] = (uint8_t)(outlen >> 8);
    info[pos++] = (uint8_t)(outlen & 0xFF);
    info[pos++] = (uint8_t)(plen + llen);
    memcpy(info + pos, prefix, plen); pos += plen;
    memcpy(info + pos, label,  llen); pos += llen;
    info[pos++] = 0x00;   /* context length = 0 */

    int rc = wolfSSL_quic_hkdf_expand(out, outlen, md,
                                      secret, slen,
                                      info, pos);
    return (rc == WOLFSSL_SUCCESS) ? 0 : -1;
}

/* Создать AEAD контекст: encrypt=1 для send, encrypt=0 для recv */
static int init_aead_ctx(quic_aead_ctx_t *ctx,
                          const WOLFSSL_EVP_CIPHER *cipher,
                          const uint8_t *key,
                          const uint8_t *iv,
                          int encrypt)
{
    if (ctx->ctx) {
        wolfSSL_EVP_CIPHER_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
    }
    ctx->ctx = wolfSSL_quic_crypt_new(cipher, key, iv, encrypt);
    if (!ctx->ctx) return -1;
    memcpy(ctx->iv_base, iv, QUIC_IV_LEN);
    ctx->pn = 0;
    return 0;
}

/* Инициализировать AES-ECB контекст защиты заголовков */
static int init_hp_ctx(quic_hp_ctx_t *ctx,
                        const uint8_t *key, size_t key_len)
{
    ctx->is_chacha20 = 0;
    ctx->key_len     = (uint32_t)key_len;
    memcpy(ctx->key, key, key_len);
    wc_AesInit(&ctx->aes_ecb, NULL, INVALID_DEVID);
    int rc = wc_AesSetKeyDirect(&ctx->aes_ecb,
                                 key, (word32)key_len,
                                 NULL, AES_ENCRYPTION);
    return (rc == 0) ? 0 : -1;
}

/* ── вывод ключей ────────────────────────────────────────────── */

int quic_keys_derive(quic_keys_t *keys,
                     WOLFSSL *ssl,
                     const uint8_t *read_secret,
                     const uint8_t *write_secret,
                     size_t secret_len)
{
    if (!keys || !ssl) return -1;

    const WOLFSSL_EVP_CIPHER *cipher = wolfSSL_quic_get_aead(ssl);

    /* Длина ключа из шифра; fallback = 16 (AES-128, initial level) */
    int klen_i = cipher ? wolfSSL_EVP_Cipher_key_length(cipher) : 16;
    if (klen_i <= 0 || klen_i > (int)QUIC_MAX_KEY_LEN) return -1;
    size_t key_len = (size_t)klen_i;

    uint8_t key[QUIC_MAX_KEY_LEN];
    uint8_t iv[QUIC_IV_LEN];
    uint8_t hp[QUIC_MAX_KEY_LEN];

    if (write_secret) {
        if (hkdf_expand_label(ssl, write_secret, secret_len,
                               "quic key", key, key_len)    < 0) return -1;
        if (hkdf_expand_label(ssl, write_secret, secret_len,
                               "quic iv",  iv,  QUIC_IV_LEN) < 0) return -1;
        if (hkdf_expand_label(ssl, write_secret, secret_len,
                               "quic hp",  hp,  key_len)    < 0) return -1;
        if (init_aead_ctx(&keys->send_aead, cipher, key, iv, 1) < 0) return -1;
        if (init_hp_ctx  (&keys->send_hp,   hp, key_len)        < 0) return -1;
        /* обнулить ключевой материал */
        memset(key, 0, sizeof(key));
        memset(iv,  0, sizeof(iv));
        memset(hp,  0, sizeof(hp));
    }

    if (read_secret) {
        if (hkdf_expand_label(ssl, read_secret, secret_len,
                               "quic key", key, key_len)    < 0) return -1;
        if (hkdf_expand_label(ssl, read_secret, secret_len,
                               "quic iv",  iv,  QUIC_IV_LEN) < 0) return -1;
        if (hkdf_expand_label(ssl, read_secret, secret_len,
                               "quic hp",  hp,  key_len)    < 0) return -1;
        if (init_aead_ctx(&keys->recv_aead, cipher, key, iv, 0) < 0) return -1;
        if (init_hp_ctx  (&keys->recv_hp,   hp, key_len)        < 0) return -1;
        memset(key, 0, sizeof(key));
        memset(iv,  0, sizeof(iv));
        memset(hp,  0, sizeof(hp));
    }

    keys->ready = 1;
    return 0;
}

/* Публичная обёртка над init_hp_ctx — для Initial keys вне quic_keys_derive */
int quic_hp_init(quic_hp_ctx_t *ctx, const uint8_t *key, size_t key_len)
{
    return init_hp_ctx(ctx, key, key_len);
}

/* ── AEAD защита пакетов ─────────────────────────────────────── */

/* Nonce = iv_base XOR pn big-endian (RFC 9001 §5.3) */
static void make_nonce(const uint8_t *iv_base, uint64_t pn, uint8_t *nonce)
{
    memcpy(nonce, iv_base, QUIC_IV_LEN);
    nonce[4]  ^= (uint8_t)(pn >> 56);
    nonce[5]  ^= (uint8_t)(pn >> 48);
    nonce[6]  ^= (uint8_t)(pn >> 40);
    nonce[7]  ^= (uint8_t)(pn >> 32);
    nonce[8]  ^= (uint8_t)(pn >> 24);
    nonce[9]  ^= (uint8_t)(pn >> 16);
    nonce[10] ^= (uint8_t)(pn >> 8);
    nonce[11] ^= (uint8_t)(pn & 0xFF);
}

int quic_aead_protect(quic_aead_ctx_t *ctx,
                      uint8_t *out, size_t *out_len,
                      const uint8_t *plain, size_t plain_len,
                      const uint8_t *header, size_t header_len,
                      uint64_t pn)
{
    if (!ctx || !ctx->ctx) return -1;
    if (*out_len < plain_len + QUIC_AEAD_TAG_LEN) return -1;

    uint8_t nonce[QUIC_IV_LEN];
    make_nonce(ctx->iv_base, pn, nonce);

    /* wolfSSL_quic_aead_encrypt(dest, ctx, plain, plainlen, iv, aad, aadlen) */
    int rc = wolfSSL_quic_aead_encrypt(
        out, ctx->ctx,
        plain, plain_len,
        nonce,
        header, header_len);
    if (rc != WOLFSSL_SUCCESS) return -1;

    *out_len = plain_len + QUIC_AEAD_TAG_LEN;
    return 0;
}

int quic_aead_unprotect(quic_aead_ctx_t *ctx,
                        uint8_t *out, size_t *out_len,
                        const uint8_t *enc, size_t enc_len,
                        const uint8_t *header, size_t header_len,
                        uint64_t pn)
{
    if (!ctx || !ctx->ctx) return -1;
    if (enc_len < QUIC_AEAD_TAG_LEN) return -1;

    size_t plain_len = enc_len - QUIC_AEAD_TAG_LEN;
    if (*out_len < plain_len) return -1;

    uint8_t nonce[QUIC_IV_LEN];
    make_nonce(ctx->iv_base, pn, nonce);

    /* wolfSSL_quic_aead_decrypt(dest, ctx, enc, enclen, iv, aad, aadlen) */
    int rc = wolfSSL_quic_aead_decrypt(
        out, ctx->ctx,
        enc, enc_len,
        nonce,
        header, header_len);
    if (rc != WOLFSSL_SUCCESS) return -1;

    *out_len = plain_len;
    return 0;
}

/* ── освобождение ключей ─────────────────────────────────────── */

void quic_keys_free(quic_keys_t *keys)
{
    if (!keys) return;
    if (keys->send_aead.ctx) {
        wolfSSL_EVP_CIPHER_CTX_free(keys->send_aead.ctx);
        keys->send_aead.ctx = NULL;
    }
    if (keys->recv_aead.ctx) {
        wolfSSL_EVP_CIPHER_CTX_free(keys->recv_aead.ctx);
        keys->recv_aead.ctx = NULL;
    }
    /* освобождаем AES-ECB контексты HP (симметрично wc_AesInit) */
    if (keys->ready) {
        wc_AesFree(&keys->send_hp.aes_ecb);
        wc_AesFree(&keys->recv_hp.aes_ecb);
    }
    keys->ready = 0;
}

/* ── защита заголовков (RFC 9001 §5.4.1) ─────────────────────── */

/* Вычислить HP-маску: mask = AES-ECB(hp_key, sample[0..15]) */
static void hp_mask(quic_hp_ctx_t *ctx,
                    const uint8_t *sample, uint8_t mask[AES_BLOCK_SIZE])
{
    wc_AesEncryptDirect(&ctx->aes_ecb, mask, sample);
}

void quic_hp_apply(quic_hp_ctx_t *ctx,
                   uint8_t *hdr, size_t hdr_len,
                   const uint8_t *sample)
{
    uint8_t mask[AES_BLOCK_SIZE];
    hp_mask(ctx, sample, mask);

    /* маскируем биты первого байта: Long Header — биты 0..3; Short — 0..4 */
    if (hdr[0] & 0x80)
        hdr[0] ^= (mask[0] & 0x0F);   /* Long Header */
    else
        hdr[0] ^= (mask[0] & 0x1F);   /* Short Header */

    /* 4 байта Packet Number в конце hdr (мы кодируем фиксированные 4 байта) */
    size_t pn_off = hdr_len - QUIC_MAX_PN_LEN;
    for (size_t i = 0; i < QUIC_MAX_PN_LEN; i++)
        hdr[pn_off + i] ^= mask[1 + i];
}

void quic_hp_remove(quic_hp_ctx_t *ctx,
                    uint8_t *hdr, size_t hdr_len,
                    const uint8_t *sample)
{
    uint8_t mask[AES_BLOCK_SIZE];
    hp_mask(ctx, sample, mask);

    /* Восстановить первый байт */
    if (hdr[0] & 0x80)
        hdr[0] ^= (mask[0] & 0x0F);
    else
        hdr[0] ^= (mask[0] & 0x1F);

    /* Теперь знаем реальную длину PN: биты 0..1 первого байта + 1 */
    size_t pn_len = (size_t)(hdr[0] & 0x03) + 1;
    size_t pn_off = hdr_len - QUIC_MAX_PN_LEN;
    for (size_t i = 0; i < pn_len; i++)
        hdr[pn_off + i] ^= mask[1 + i];
}

#endif /* CONFIG_PHOENIX_DOQ */

/* заглушка: подавить предупреждение "empty translation unit" */
typedef int quic_c_module_t;

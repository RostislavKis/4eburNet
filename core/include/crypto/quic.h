/* quic.h — QUIC-криптография для DoQ (DNS-over-QUIC, RFC 9250)
 *
 * Обёртка над wolfSSL QUIC API (требует --enable-quic в libwolfssl).
 * Только типы и объявления — реализация в crypto/quic.c
 *
 * Предоставляет:
 *   - ключевой материал по уровням шифрования (RFC 9001 §7)
 *   - AEAD защита/снятие защиты пакетов (wolfSSL_quic_aead_*)
 *   - защита заголовков AES-ECB (wc_AesEncryptDirect, RFC 9001 §5.4)
 *   - HKDF вывод ключей (wolfSSL_quic_hkdf_extract/expand)
 *   - регистрация колбэков TLS handshake (WOLFSSL_QUIC_METHOD)
 *
 * Компилируется только при CONFIG_EBURNET_DOQ=1.
 */

#ifndef EBURNET_CRYPTO_QUIC_H
#define EBURNET_CRYPTO_QUIC_H

#if CONFIG_EBURNET_DOQ || CONFIG_EBURNET_QUIC

#include <stdint.h>
#include <stddef.h>

/* wolfssl/options.h должен быть первым — определяет WOLFSSL_QUIC */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>
#include <wolfssl/wolfcrypt/aes.h>

/* ── константы (RFC 9001) ────────────────────────────────────── */

#define QUIC_MAX_KEY_LEN   32u   /* максимальная длина ключа (AES-256/ChaCha20) */
#define QUIC_IV_LEN        12u   /* длина базового IV / nonce (RFC 9001 §5.3)   */
#define QUIC_HP_KEY_LEN    32u   /* максимальная длина HP-ключа                 */
#define QUIC_AEAD_TAG_LEN  16u   /* тег AES-GCM / ChaCha20-Poly1305             */
#define QUIC_MAX_PN_LEN     4u   /* максимальная длина packet number            */

/* ── уровень шифрования ─────────────────────────────────────── */

/* wolfssl_encryption_initial, _early_data, _handshake, _application */
typedef WOLFSSL_ENCRYPTION_LEVEL quic_level_t;

/* ── AEAD контекст одного направления ───────────────────────── */

/* Создаётся через wolfSSL_quic_crypt_new(), переиспользуется на каждом пакете.
 * Nonce для каждого пакета = iv_base XOR pn (RFC 9001 §5.3). */
typedef struct {
    WOLFSSL_EVP_CIPHER_CTX *ctx;                 /* wolfSSL AEAD контекст       */
    uint8_t                 iv_base[QUIC_IV_LEN]; /* базовый IV из вывода HKDF  */
    uint64_t                pn;                  /* счётчик пакетов (для nonce) */
} quic_aead_ctx_t;

/* ── контекст защиты заголовков (Header Protection) ─────────── */

/* HP применяется к первому байту и полю Packet Number.
 * sample = 16 байт из payload начиная с offset 4 после конца PN.
 * AES-ECB: wc_AesSetKeyDirect + wc_AesEncryptDirect. */
typedef struct {
    Aes      aes_ecb;                /* AES-ECB контекст (wc_AesSetKeyDirect)  */
    int      is_chacha20;            /* 1 → ChaCha20-HP (пока не реализован)   */
    uint8_t  key[QUIC_HP_KEY_LEN];  /* копия HP-ключа для переинициализации    */
    uint32_t key_len;               /* 16 (AES-128) или 32 (AES-256) байт      */
} quic_hp_ctx_t;

/* ── ключевой материал одного уровня шифрования ─────────────── */

typedef struct {
    quic_aead_ctx_t send_aead;   /* шифрование исходящих пакетов */
    quic_aead_ctx_t recv_aead;   /* расшифровка входящих пакетов */
    quic_hp_ctx_t   send_hp;     /* HP для исходящих заголовков  */
    quic_hp_ctx_t   recv_hp;     /* HP для входящих заголовков   */
    int             ready;       /* 1 → ключи установлены        */
} quic_keys_t;

/* ── инициализация TLS-контекста ────────────────────────────── */

/* Зарегистрировать QUIC-колбэки на wolfSSL CTX.
 * Обёртка wolfSSL_CTX_set_quic_method. */
int quic_ctx_init(WOLFSSL_CTX *ctx, const WOLFSSL_QUIC_METHOD *method);

/* ── вывод ключей (RFC 9001 §7.3) ───────────────────────────── */

/* Вывести AEAD и HP ключи из секрета одного уровня.
 * read_secret / write_secret передаются из колбэка set_encryption_secrets;
 * один из них может быть NULL (только чтение или только запись).
 * ssl используется для получения AEAD-шифра и MD через wolfSSL_quic_get_*. */
int quic_keys_derive(quic_keys_t *keys,
                     WOLFSSL *ssl,
                     const uint8_t *read_secret,
                     const uint8_t *write_secret,
                     size_t secret_len);

/* Освободить WOLFSSL_EVP_CIPHER_CTX из AEAD-контекстов */
void quic_keys_free(quic_keys_t *keys);

/* Инициализировать HP контекст напрямую (для Initial keys без WOLFSSL*) */
int quic_hp_init(quic_hp_ctx_t *ctx, const uint8_t *key, size_t key_len);

/* ── AEAD защита/снятие защиты (RFC 9001 §5.3) ──────────────── */

/* Зашифровать payload. out должен вмещать plain_len + QUIC_AEAD_TAG_LEN байт.
 * header / header_len — незашифрованный AAD (заголовок пакета).
 * pn — номер пакета от вызывающего кода (не внутренний счётчик ctx->pn). */
int quic_aead_protect(quic_aead_ctx_t *ctx,
                      uint8_t *out, size_t *out_len,
                      const uint8_t *plain, size_t plain_len,
                      const uint8_t *header, size_t header_len,
                      uint64_t pn);

/* Расшифровать payload. out должен вмещать enc_len - QUIC_AEAD_TAG_LEN байт.
 * pn — номер пакета из декодированного заголовка (QUIC UDP не упорядочен). */
int quic_aead_unprotect(quic_aead_ctx_t *ctx,
                        uint8_t *out, size_t *out_len,
                        const uint8_t *enc, size_t enc_len,
                        const uint8_t *header, size_t header_len,
                        uint64_t pn);

/* ── защита заголовков (RFC 9001 §5.4) ──────────────────────── */

/* Применить HP-маску к hdr[0] и байтам packet number.
 * hdr_len — длина заголовка до конца PN (1 + DCIL + SCIL + ... + PN).
 * sample — 16 байт из payload (offset 4 байта после конца PN). */
void quic_hp_apply(quic_hp_ctx_t *ctx,
                   uint8_t *hdr, size_t hdr_len,
                   const uint8_t *sample);

/* Снять HP-маску (операция симметрична — тот же XOR).
 * ТРЕБОВАНИЕ: hdr_len должен включать QUIC_MAX_PN_LEN (4) байта PN.
 * Вызывающий код конструирует заголовок с 4-байт PN полем.
 * После восстановления hdr[0] функция читает реальный pn_len (1-4 байта)
 * и unmask только его — лишние байты остаются замаскированными. */
void quic_hp_remove(quic_hp_ctx_t *ctx,
                    uint8_t *hdr, size_t hdr_len,
                    const uint8_t *sample);

#endif /* CONFIG_EBURNET_DOQ || CONFIG_EBURNET_QUIC */
#endif /* EBURNET_CRYPTO_QUIC_H */

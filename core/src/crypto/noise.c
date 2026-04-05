/*
 * Noise_IKpsk2 handshake (WireGuard)
 *
 * Crypto: X25519 ECDH + BLAKE2s + ChaCha20-Poly1305
 * Спецификация: noise.protocol.org + wireguard.com/protocol/
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/random.h>

#include "crypto/noise.h"
#include "crypto/blake2s.h"
#include "phoenix.h"

#include <string.h>
#include <strings.h>  /* explicit_bzero */
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>

/* Константы WireGuard (не менять) */
static const char CONSTRUCTION[] =
    "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char IDENTIFIER[] =
    "WireGuard v1 zx2c4 Jason@zx2c4.com";
static const char LABEL_MAC1[] = "mac1----";

/* WireGuard message types */
#define MSG_HANDSHAKE_INIT     1
#define MSG_HANDSHAKE_RESPONSE 2
#define MSG_TRANSPORT_DATA     4

/* ------------------------------------------------------------------ */
/*  Вспомогательные Noise функции                                      */
/* ------------------------------------------------------------------ */

static void mix_hash(uint8_t hash[32], const void *data, size_t len)
{
    blake2s_state_t st;
    blake2s_init(&st, 32, NULL, 0);
    blake2s_update(&st, hash, 32);
    blake2s_update(&st, data, len);
    blake2s_final(&st, hash);
}

/* HKDF2: (ck, data) → (ck_out, key_out) */
static void noise_hkdf2(const uint8_t ck[32], const void *data, size_t len,
                         uint8_t ck_out[32], uint8_t key_out[32])
{
    uint8_t prk[32];
    blake2s_hmac(prk, 32, ck, 32, data, len);

    uint8_t one = 1;
    blake2s_hmac(ck_out, 32, prk, 32, &one, 1);

    uint8_t buf[33];
    memcpy(buf, ck_out, 32);
    buf[32] = 2;
    blake2s_hmac(key_out, 32, prk, 32, buf, 33);

    explicit_bzero(prk, sizeof(prk));
    /* L-01: обнулить buf с ключевым материалом */
    explicit_bzero(buf, sizeof(buf));
}

/* HKDF3: (ck, data) → (ck_out, k1, k2) */
static void noise_hkdf3(const uint8_t ck[32], const void *data, size_t len,
                         uint8_t ck_out[32], uint8_t k1[32], uint8_t k2[32])
{
    uint8_t prk[32];
    blake2s_hmac(prk, 32, ck, 32, data, len);

    uint8_t one = 1;
    blake2s_hmac(ck_out, 32, prk, 32, &one, 1);

    uint8_t buf[33];
    memcpy(buf, ck_out, 32);
    buf[32] = 2;
    blake2s_hmac(k1, 32, prk, 32, buf, 33);

    memcpy(buf, k1, 32);
    buf[32] = 3;
    blake2s_hmac(k2, 32, prk, 32, buf, 33);

    explicit_bzero(prk, sizeof(prk));
    /* L-01: обнулить buf с ключевым материалом */
    explicit_bzero(buf, sizeof(buf));
}

/* AEAD encrypt: ChaCha20-Poly1305 */
static int aead_encrypt(const uint8_t key[32], uint64_t counter,
                        const uint8_t *plain, size_t plen,
                        const uint8_t *aad, size_t aad_len,
                        uint8_t *out, uint8_t tag[16])
{
    uint8_t nonce[12] = {0};
    nonce[4]  = (uint8_t)(counter);
    nonce[5]  = (uint8_t)(counter >> 8);
    nonce[6]  = (uint8_t)(counter >> 16);
    nonce[7]  = (uint8_t)(counter >> 24);
    nonce[8]  = (uint8_t)(counter >> 32);
    nonce[9]  = (uint8_t)(counter >> 40);
    nonce[10] = (uint8_t)(counter >> 48);
    nonce[11] = (uint8_t)(counter >> 56);

    return wc_ChaCha20Poly1305_Encrypt(key, nonce,
        aad, (word32)aad_len, plain, (word32)plen, out, tag);
}

/* AEAD decrypt */
static int aead_decrypt(const uint8_t key[32], uint64_t counter,
                        const uint8_t *cipher, size_t clen,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t tag[16], uint8_t *out)
{
    uint8_t nonce[12] = {0};
    nonce[4]  = (uint8_t)(counter);
    nonce[5]  = (uint8_t)(counter >> 8);
    nonce[6]  = (uint8_t)(counter >> 16);
    nonce[7]  = (uint8_t)(counter >> 24);
    nonce[8]  = (uint8_t)(counter >> 32);
    nonce[9]  = (uint8_t)(counter >> 40);
    nonce[10] = (uint8_t)(counter >> 48);
    nonce[11] = (uint8_t)(counter >> 56);

    return wc_ChaCha20Poly1305_Decrypt(key, nonce,
        aad, (word32)aad_len, cipher, (word32)clen, tag, out);
}

/* M-14: clamping для Curve25519 private key */
static void clamp_curve25519_key(uint8_t key[32])
{
    key[0]  &= 248;
    key[31] &= 127;
    key[31] |= 64;
}

/* X25519 ECDH shared secret */
static int x25519_shared(const uint8_t priv[32], const uint8_t pub[32],
                         uint8_t shared[32])
{
    curve25519_key privkey, pubkey;
    word32 outlen = 32;

    wc_curve25519_init(&privkey);
    wc_curve25519_init(&pubkey);

    if (wc_curve25519_import_private(priv, 32, &privkey) != 0) {
        wc_curve25519_free(&privkey);
        wc_curve25519_free(&pubkey);
        return -1;
    }
    if (wc_curve25519_import_public(pub, 32, &pubkey) != 0) {
        wc_curve25519_free(&privkey);
        wc_curve25519_free(&pubkey);
        return -1;
    }

    int rc = wc_curve25519_shared_secret(&privkey, &pubkey, shared, &outlen);

    wc_curve25519_free(&privkey);
    wc_curve25519_free(&pubkey);
    return rc;
}

/* Генерировать X25519 пару ключей */
static int x25519_generate(uint8_t priv[32], uint8_t pub[32])
{
    WC_RNG rng;
    if (wc_InitRng(&rng) != 0)
        return -1;

    curve25519_key key;
    wc_curve25519_init(&key);

    int rc = wc_curve25519_make_key(&rng, 32, &key);
    if (rc == 0) {
        word32 plen = 32;
        if (wc_curve25519_export_private_raw(&key, priv, &plen) != 0) {
            wc_curve25519_free(&key);
            wc_FreeRng(&rng);
            return -1;
        }
        /* H-04: make_key уже делает clamping, повторный clamp убран.
         * clamp остаётся только в noise_init() для user-provided key. */
        if (wc_curve25519_export_public(&key, pub, &plen) != 0) {
            wc_curve25519_free(&key);
            wc_FreeRng(&rng);
            return -1;
        }
    }

    wc_curve25519_free(&key);
    wc_FreeRng(&rng);
    return rc;
}

static int random_bytes(uint8_t *buf, size_t len)
{
    /* getrandom() с loop для partial read (H-03) */
#ifdef __NR_getrandom
    size_t done = 0;
    while (done < len) {
        ssize_t r = syscall(__NR_getrandom, buf + done, len - done, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) goto fallback;
        done += (size_t)r;
    }
    return 0;
fallback:
#endif
    /* Fallback: /dev/urandom с O_RDONLY|O_CLOEXEC */
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        log_msg(LOG_ERROR, "random_bytes: /dev/urandom недоступен");
        return -1;
    }
    size_t fb_done = 0;
    while (fb_done < len) {
        ssize_t n = read(fd, buf + fb_done, len - fb_done);
        if (n <= 0) {
            close(fd);
            log_msg(LOG_ERROR, "random_bytes: read ошибка");
            return -1;
        }
        fb_done += (size_t)n;
    }
    close(fd);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  noise_init                                                         */
/* ------------------------------------------------------------------ */

int noise_init(noise_state_t *ns,
               const uint8_t local_priv[32],
               const uint8_t remote_pub[32],
               const uint8_t psk[32], bool has_psk)
{
    memset(ns, 0, sizeof(*ns));
    memcpy(ns->local_static_private, local_priv, 32);
    /* M-14: clamping перед импортом */
    clamp_curve25519_key(ns->local_static_private);
    memcpy(ns->remote_static_public, remote_pub, 32);

    /* Вычислить наш public key из private (C-05: корректный импорт) */
    curve25519_key key;
    wc_curve25519_init(&key);
    if (wc_curve25519_import_private(ns->local_static_private, 32, &key) != 0) {
        wc_curve25519_free(&key);
        explicit_bzero(ns, sizeof(*ns));
        return -1;
    }
    word32 pub_len = 32;
    if (wc_curve25519_export_public(&key, ns->local_static_public,
                                     &pub_len) != 0) {
        wc_curve25519_free(&key);
        explicit_bzero(ns, sizeof(*ns));
        return -1;
    }
    wc_curve25519_free(&key);

    if (has_psk && psk) {
        memcpy(ns->preshared_key, psk, 32);
        ns->has_psk = true;
    }

    /* Инициализация Noise: hash = BLAKE2s(CONSTRUCTION) */
    blake2s_hash(ns->hash, 32, CONSTRUCTION, strlen(CONSTRUCTION));
    memcpy(ns->chaining_key, ns->hash, 32);

    /* hash = MixHash(hash, IDENTIFIER) */
    mix_hash(ns->hash, IDENTIFIER, strlen(IDENTIFIER));

    /* hash = MixHash(hash, responder_public_key) */
    mix_hash(ns->hash, remote_pub, 32);

    /* Sender Index */
    if (random_bytes((uint8_t *)&ns->local_index, 4) < 0) {
        explicit_bzero(ns, sizeof(*ns));
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  noise_handshake_init_create                                        */
/* ------------------------------------------------------------------ */

int noise_handshake_init_create(noise_state_t *ns,
                                uint8_t *out, size_t *outlen)
{
    if (*outlen < NOISE_INIT_SIZE)
        return -1;

    /* Генерировать ephemeral key pair */
    if (x25519_generate(ns->local_ephemeral_private,
                        ns->local_ephemeral_public) != 0)
        return -1;

    uint8_t *p = out;

    /* msg_type(4) + sender_index(4) */
    p[0] = MSG_HANDSHAKE_INIT; p[1] = 0; p[2] = 0; p[3] = 0;
    memcpy(p + 4, &ns->local_index, 4);
    p += 8;

    /* Ephemeral public key (32) */
    memcpy(p, ns->local_ephemeral_public, 32);
    mix_hash(ns->hash, p, 32);
    p += 32;

    /* MixKey(ck, DH(ephemeral, responder_static)) */
    uint8_t shared[32];
    if (x25519_shared(ns->local_ephemeral_private,
                      ns->remote_static_public, shared) != 0) {
        explicit_bzero(shared, 32);
        return -1;
    }
    noise_hkdf2(ns->chaining_key, shared, 32,
                ns->chaining_key, shared);  /* shared → temp key */

    /* EncryptAndHash(static_public) → encrypted_static(48) */
    uint8_t tag[16];
    if (aead_encrypt(shared, 0,
                     ns->local_static_public, 32,
                     ns->hash, 32,
                     p, tag) != 0) {
        explicit_bzero(shared, 32);
        return -1;
    }
    memcpy(p + 32, tag, 16);
    mix_hash(ns->hash, p, 48);
    p += 48;

    /* MixKey(ck, DH(static, responder_static)) */
    if (x25519_shared(ns->local_static_private,
                      ns->remote_static_public, shared) != 0) {
        explicit_bzero(shared, 32);
        return -1;
    }
    noise_hkdf2(ns->chaining_key, shared, 32,
                ns->chaining_key, shared);

    /* EncryptAndHash(timestamp) → encrypted_timestamp(28) */
    uint8_t timestamp[12];
    /* TAI-UTC = 37 сек (актуально 2017-01-01 -> по сей день, 2026).
     * Обновить при добавлении leap second.
     * Источник: https://www.ietf.org/timezones/data/leap-seconds.list */
    #define TAI64N_BASE (4611686018427387904ULL + 37)
    uint64_t tai = (uint64_t)time(NULL) + TAI64N_BASE;
    timestamp[0] = (uint8_t)(tai >> 56);
    timestamp[1] = (uint8_t)(tai >> 48);
    timestamp[2] = (uint8_t)(tai >> 40);
    timestamp[3] = (uint8_t)(tai >> 32);
    timestamp[4] = (uint8_t)(tai >> 24);
    timestamp[5] = (uint8_t)(tai >> 16);
    timestamp[6] = (uint8_t)(tai >> 8);
    timestamp[7] = (uint8_t)(tai);
    timestamp[8] = 0; timestamp[9] = 0;
    timestamp[10] = 0; timestamp[11] = 0;

    if (aead_encrypt(shared, 0,
                     timestamp, 12, ns->hash, 32,
                     p, tag) != 0) {
        explicit_bzero(shared, 32);
        return -1;
    }
    memcpy(p + 12, tag, 16);
    mix_hash(ns->hash, p, 28);
    p += 28;

    /* MAC1 = BLAKE2s(LABEL_MAC1 || remote_static, msg[0..116]) */
    uint8_t mac1_key[32];
    uint8_t mac1_input[40];
    memcpy(mac1_input, LABEL_MAC1, 8);
    memcpy(mac1_input + 8, ns->remote_static_public, 32);
    blake2s_hash(mac1_key, 32, mac1_input, 40);
    blake2s_keyed(p, 16, mac1_key, 32, out, (size_t)(p - out));
    p += 16;

    /* MAC2 = zeros (no cookie) */
    memset(p, 0, 16);
    p += 16;

    *outlen = (size_t)(p - out);

    /* Обнуление ключевого материала на стеке */
    explicit_bzero(shared, sizeof(shared));
    explicit_bzero(tag, sizeof(tag));
    explicit_bzero(mac1_key, sizeof(mac1_key));
    return 0;
}

/* ------------------------------------------------------------------ */
/*  noise_handshake_response_process                                   */
/* ------------------------------------------------------------------ */

int noise_handshake_response_process(noise_state_t *ns,
                                     const uint8_t *resp, size_t resp_len)
{
    if (resp_len < NOISE_RESPONSE_SIZE)
        return -1;

    /* msg_type(4) + sender_index(4) + receiver_index(4) */
    if (resp[0] != MSG_HANDSHAKE_RESPONSE)
        return -1;

    memcpy(&ns->remote_index, resp + 4, 4);
    /* receiver_index должен совпадать с нашим local_index */
    uint32_t recv_idx;
    memcpy(&recv_idx, resp + 8, 4);
    if (recv_idx != ns->local_index)
        return -1;

    /* Ephemeral public key (32) */
    const uint8_t *resp_ephemeral = resp + 12;
    mix_hash(ns->hash, resp_ephemeral, 32);

    /* MixKey(DH(our_ephemeral, resp_ephemeral)) */
    uint8_t shared[32];
    if (x25519_shared(ns->local_ephemeral_private, resp_ephemeral, shared) != 0) {
        explicit_bzero(shared, 32);
        return -1;
    }
    noise_hkdf2(ns->chaining_key, shared, 32,
                ns->chaining_key, shared);

    /* MixKey(DH(our_static, resp_ephemeral)) */
    if (x25519_shared(ns->local_static_private, resp_ephemeral, shared) != 0) {
        explicit_bzero(shared, 32);
        return -1;
    }
    noise_hkdf2(ns->chaining_key, shared, 32,
                ns->chaining_key, shared);

    /* MixKey with PSK */
    uint8_t temp[32];
    if (ns->has_psk) {
        noise_hkdf3(ns->chaining_key, ns->preshared_key, 32,
                     ns->chaining_key, temp, shared);
        mix_hash(ns->hash, temp, 32);
    } else {
        uint8_t zeros[32] = {0};
        noise_hkdf3(ns->chaining_key, zeros, 32,
                     ns->chaining_key, temp, shared);
        mix_hash(ns->hash, temp, 32);
    }

    /* DecryptAndHash(empty encrypted = 16 bytes tag) */
    const uint8_t *enc_nothing = resp + 44;
    uint8_t dec_nothing[1];
    if (aead_decrypt(shared, 0, NULL, 0, ns->hash, 32,
                     enc_nothing, dec_nothing) != 0)
        return -1;
    mix_hash(ns->hash, enc_nothing, 16);

    /* Derive transport keys */
    noise_hkdf2(ns->chaining_key, NULL, 0,
                ns->send_key, ns->recv_key);

    ns->send_counter = 0;
    ns->recv_counter = 0;
    ns->handshake_complete = true;
    ns->handshake_time = time(NULL);  /* H-04: запомнить время handshake */

    /* Обнуление ключевого материала на стеке */
    explicit_bzero(shared, sizeof(shared));
    explicit_bzero(temp, sizeof(temp));

    log_msg(LOG_DEBUG, "Noise: handshake завершён");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  noise_encrypt / noise_decrypt                                      */
/* ------------------------------------------------------------------ */

/* WireGuard лимиты: rekey после 2^64-2^4-1 пакетов или 180 секунд (H-05) */
#define NOISE_REJECT_AFTER_MESSAGES  (UINT64_MAX - 15ULL)
#define NOISE_REKEY_AFTER_MESSAGES   (1ULL << 60)
#define NOISE_REJECT_AFTER_TIME      180

int noise_encrypt(noise_state_t *ns,
                  const uint8_t *plain, size_t plain_len,
                  uint8_t *out, size_t *out_len)
{
    if (!ns->handshake_complete) return -1;

    /* H-02: проверка лимита пакетов */
    if (ns->send_counter >= NOISE_REJECT_AFTER_MESSAGES) {
        log_msg(LOG_WARN, "Noise: достигнут лимит пакетов, нужен rekey");
        ns->handshake_complete = false;
        return -1;
    }

    /* L-20: soft warning при 2^60 пакетов */
    if (ns->send_counter == NOISE_REKEY_AFTER_MESSAGES)
        log_msg(LOG_INFO, "Noise: рекомендуется rekey (2^60 пакетов)");

    /* H-04: проверка TTL ключа (180 сек)
     * M-09: защита от wrap time_t на 32-bit mipsel */
    {
    time_t now_hs = time(NULL);
    time_t elapsed = (now_hs >= ns->handshake_time)
        ? (now_hs - ns->handshake_time) : 0;
    if (ns->handshake_time > 0 &&
        elapsed > (time_t)NOISE_REJECT_AFTER_TIME) {
        log_msg(LOG_DEBUG, "Noise: ключ устарел (>180s), нужен rekey");
        ns->handshake_complete = false;
        return -1;
    }
    }

    /* Transport header: msg_type(4) + receiver_index(4) + counter(8) */
    out[0] = MSG_TRANSPORT_DATA; out[1] = 0; out[2] = 0; out[3] = 0;
    memcpy(out + 4, &ns->remote_index, 4);
    uint64_t ctr = ns->send_counter++;
    memcpy(out + 8, &ctr, 8);

    /* AEAD encrypt payload */
    uint8_t tag[16];
    if (aead_encrypt(ns->send_key, ctr, plain, plain_len,
                     NULL, 0, out + 16, tag) != 0)
        return -1;
    memcpy(out + 16 + plain_len, tag, 16);

    *out_len = 16 + plain_len + 16;
    return 0;
}

int noise_decrypt(noise_state_t *ns,
                  const uint8_t *cipher, size_t cipher_len,
                  uint8_t *out, size_t *out_len)
{
    if (!ns->handshake_complete || cipher_len < 32)
        return -1;

    uint64_t ctr;
    memcpy(&ctr, cipher + 8, 8);

    /* Strict ordering: пакеты должны приходить по возрастанию counter.
     * Out-of-order через bitmap sliding window — в v2. */
    if (ctr < ns->recv_counter) {
        log_msg(LOG_DEBUG, "Noise: replay/старый пакет "
                "(ctr=%llu < ожидали %llu)",
                (unsigned long long)ctr,
                (unsigned long long)ns->recv_counter);
        return -1;
    }

    size_t payload_len = cipher_len - 32;
    const uint8_t *tag = cipher + 16 + payload_len;

    if (aead_decrypt(ns->recv_key, ctr, cipher + 16, payload_len,
                     NULL, 0, tag, out) != 0)
        return -1;

    *out_len = payload_len;
    ns->recv_counter = ctr + 1;
    return 0;
}

/* H-06: Обнуление ключевого материала при уничтожении состояния */
void noise_state_cleanup(noise_state_t *ns)
{
    if (!ns) return;
    explicit_bzero(ns, sizeof(*ns));
}

/*
 * Hysteria2 Salamander — обфускация QUIC пакетов
 *
 * Протокол:
 *   key = BLAKE2b-256(pkt[0..7] || psk)
 *   pkt[8]      ^= key[0]           — заголовочный байт QUIC
 *   pkt[9+i]    ^= key[i % 32]      — payload, cyclic
 *
 * Salt (pkt[0..7]) не изменяется — он читается для derivation ключа.
 * Операция симметрична: обфускация == деобфускация.
 */

#include "crypto/quic_salamander.h"
#include "crypto/blake2b.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* ── Инициализация ───────────────────────────────────────────────────────── */

int salamander_init(salamander_ctx_t *ctx,
                    const char *password, size_t password_len)
{
    if (!ctx || !password || password_len == 0)
        return -1;
    if (password_len > sizeof(ctx->psk))
        return -1;

    memcpy(ctx->psk, password, password_len);
    ctx->psk_len = password_len;
    return 0;
}

/* ── Генерация случайного salt ───────────────────────────────────────────── */

void salamander_gen_salt(uint8_t *pkt)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = 0;
        while (n < SALAMANDER_SALT_LEN) {
            ssize_t r = read(fd, pkt + n, (size_t)(SALAMANDER_SALT_LEN - n));
            if (r > 0) n += r;
            else break;
        }
        close(fd);
        if (n == SALAMANDER_SALT_LEN)
            return;
    }

    /* PRNG fallback: LCG, инициализированный адресами + errno */
    static uint64_t prng_state;
    if (prng_state == 0)
        prng_state = (uint64_t)(uintptr_t)pkt ^ (uint64_t)errno ^ UINT64_C(0xdeadbeefcafe1234);

    for (int i = 0; i < SALAMANDER_SALT_LEN; i++) {
        prng_state = prng_state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
        pkt[i] = (uint8_t)(prng_state >> 56);
    }
}

/* ── Обфускация / деобфускация пакета ───────────────────────────────────── */

int salamander_process(const salamander_ctx_t *ctx,
                       uint8_t *pkt, size_t pkt_len)
{
    if (!ctx || !pkt)
        return -1;
    if (ctx->psk_len == 0)
        return -1;
    if (pkt_len < SALAMANDER_MIN_PKT)
        return -1;

    /* key = BLAKE2b-256(salt[0..7] || psk) */
    uint8_t key[SALAMANDER_KEY_LEN];
    int rc = blake2b_salamander(pkt, SALAMANDER_SALT_LEN,
                                ctx->psk, ctx->psk_len,
                                key, SALAMANDER_KEY_LEN);
    if (rc != 0)
        return -1;

    /* Заголовочный байт QUIC: pkt[8] ^= key[0] */
    pkt[SALAMANDER_SALT_LEN] ^= key[0];

    /* Payload: pkt[9+i] ^= key[i % 32], cyclic с key[0] */
    size_t payload_start = SALAMANDER_SALT_LEN + 1;
    size_t payload_len   = pkt_len - payload_start;
    for (size_t i = 0; i < payload_len; i++)
        pkt[payload_start + i] ^= key[i % SALAMANDER_KEY_LEN];

    /* Зачистить ключ из стека */
    memset(key, 0, sizeof(key));
    return 0;
}

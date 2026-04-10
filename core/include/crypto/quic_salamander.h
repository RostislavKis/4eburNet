/*
 * Hysteria2 Salamander — обфускация QUIC пакетов
 *
 * Протокол (https://v2.hysteria.network/docs/developers/Protocol/):
 *   Для каждого UDP датаграмма:
 *     1. Прочитать pkt[0..7] как salt (8 случайных байт, открытые)
 *     2. key = BLAKE2b-256(salt[8] || psk)  → 32 байта
 *     3. pkt[8]  ^= key[0]              -- заголовочный байт QUIC
 *     4. pkt[9+i] ^= key[i % 32]        -- payload, cyclic с key[0]
 *
 * Структура пакета (длина N байт):
 *   [0..7]   — salt (8 байт, случайные, не модифицируются)
 *   [8]      — заголовочный байт QUIC, XOR key[0]
 *   [9..N-1] — payload, XOR key[0..] cyclic
 *
 * Операция симметрична (XOR): obfuscate == deobfuscate.
 */

#ifndef EBURNET_QUIC_SALAMANDER_H
#define EBURNET_QUIC_SALAMANDER_H

#include <stdint.h>
#include <stddef.h>

/* Длина salt в начале каждого пакета */
#define SALAMANDER_SALT_LEN   8
/* Длина XOR ключа (BLAKE2b-256) */
#define SALAMANDER_KEY_LEN   32
/* Минимальный пакет: 8 байт salt + 1 байт header */
#define SALAMANDER_MIN_PKT    9

/*
 * Контекст Salamander обфускатора.
 * Инициализируется один раз на QUIC соединение.
 */
typedef struct {
    uint8_t psk[256]; /* pre-shared key (obfs-password из конфига) */
    size_t  psk_len;  /* длина psk */
} salamander_ctx_t;

/*
 * Инициализировать контекст из строки пароля.
 * Возвращает 0 при успехе, -1 при ошибке.
 */
int salamander_init(salamander_ctx_t *ctx,
                    const char *password, size_t password_len);

/*
 * Обфусцировать/деобфусцировать пакет IN PLACE.
 *
 * pkt[0..7]   — salt (читается для key derivation, не изменяется)
 * pkt[8]      — QUIC header byte, XOR key[0]
 * pkt[9..N-1] — payload, XOR key[0..] cyclic
 *
 * Операция симметрична: один вызов обфусцирует, второй — восстанавливает.
 * Возвращает 0 при успехе, -1 при ошибке (pkt_len < 9, ctx не инициализирован).
 */
int salamander_process(const salamander_ctx_t *ctx,
                       uint8_t *pkt, size_t pkt_len);

/*
 * Записать SALAMANDER_SALT_LEN случайных байт в pkt[0..7].
 * Используется отправителем перед обфускацией нового пакета.
 * Source: /dev/urandom с PRNG fallback.
 */
void salamander_gen_salt(uint8_t *pkt);

#endif /* EBURNET_QUIC_SALAMANDER_H */

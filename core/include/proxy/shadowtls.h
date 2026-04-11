/*
 * shadowtls.h — ShadowTLS v3 клиентский транспорт (D.2)
 *
 * Ручной TLS handshake с HMAC-подписанным SessionID.
 * После handshake: AppData records с 4-байтным HMAC тегом.
 *
 * Компилируется при CONFIG_EBURNET_STLS=1.
 */

#ifndef EBURNET_SHADOWTLS_H
#define EBURNET_SHADOWTLS_H

#if CONFIG_EBURNET_STLS

#include <stdint.h>
#include <stddef.h>

/* Состояния ShadowTLS state machine */
typedef enum {
    STLS_INIT           = 0,
    STLS_SEND_CH        = 1,  /* ClientHello отправлен */
    STLS_RECV_SH        = 2,  /* ожидаем ServerHello → извлечь server_random */
    STLS_SKIP_HS        = 3,  /* пропускаем handshake records (Certificate...) */
    STLS_WAIT_FINISHED  = 4,  /* CCS получен, ждём Finished */
    STLS_ACTIVE         = 5,  /* данные идут */
    STLS_ERROR          = 6,
} stls_state_t;

/* Контекст одного ShadowTLS соединения */
typedef struct {
    stls_state_t  state;
    uint8_t       password[256];
    size_t        password_len;
    uint8_t       client_random[32];
    uint8_t       server_random[32];
    uint64_t      send_counter;
    uint64_t      recv_counter;
    /* Буфер для частичного чтения TLS records */
    uint8_t       recv_buf[4096];
    int           recv_len;
} shadowtls_ctx_t;

/* Инициализировать контекст. password = NUL-terminated строка. */
void stls_ctx_init(shadowtls_ctx_t *ctx, const char *password);

/*
 * Отправить ClientHello с SessionID = HMAC(password, client_random).
 * sni: SNI реального сервера (например "www.microsoft.com").
 * Сохраняет client_random в ctx.
 * Устанавливает state = STLS_SEND_CH.
 * Возвращает 0 или -1.
 */
int stls_send_client_hello(int fd, shadowtls_ctx_t *ctx, const char *sni);

/*
 * Обработать входящие TLS records (ServerHello + handshake).
 * Неблокирующий — читает столько сколько есть в сокете.
 * Возвращает:
 *   0 = нужно больше данных (ещё не ACTIVE)
 *   1 = handshake завершён (state = STLS_ACTIVE)
 *  -1 = ошибка (state = STLS_ERROR)
 */
int stls_recv_handshake(int fd, shadowtls_ctx_t *ctx);

/*
 * Обернуть данные в TLS AppData record + HMAC тег (4 байта).
 * out: [0x17, 0x03, 0x03, lenhi, lenlo, hmac[4], data[len]]
 * out_size >= len + 9.
 * Возвращает полную длину записи (len + 9) или -1.
 */
int stls_wrap(shadowtls_ctx_t *ctx,
              const uint8_t *data, int len,
              uint8_t *out, int out_size);

/*
 * Развернуть TLS AppData record, проверить HMAC тег.
 * record: [type, ver_hi, ver_lo, lenhi, lenlo, hmac[4], data...]
 * Возвращает длину данных (без header + hmac) или -1.
 */
int stls_unwrap(shadowtls_ctx_t *ctx,
                const uint8_t *record, int record_len,
                uint8_t *out, int out_size);

#endif /* CONFIG_EBURNET_STLS */
#endif /* EBURNET_SHADOWTLS_H */

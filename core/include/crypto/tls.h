#ifndef TLS_H
#define TLS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/* Профили TLS fingerprint для маскировки под легитимные клиенты */
typedef enum {
    TLS_FP_NONE       = 0,  /* без маскировки */
    TLS_FP_CHROME120  = 1,  /* Chrome 120 */
    TLS_FP_FIREFOX121 = 2,  /* Firefox 121 */
    TLS_FP_IOS17      = 3,  /* Safari iOS 17 */
} tls_fingerprint_t;

/* Параметры TLS соединения */
typedef struct {
    char                sni[256];         /* SNI — собственная копия */
    tls_fingerprint_t   fingerprint;      /* fingerprint профиль */
    bool                verify_cert;      /* проверять сертификат? (false для Reality) */
    const uint8_t      *reality_key;      /* x25519 публичный ключ сервера */
    size_t              reality_key_len;  /* 32 байта */
    const char         *reality_short_id; /* short ID (hex строка) */
} tls_config_t;

/* Состояние одного TLS соединения */
typedef struct {
    void         *ssl;        /* WOLFSSL* */
    void         *ctx;        /* WOLFSSL_CTX* */
    int           fd;         /* TCP дескриптор */
    bool          connected;  /* handshake завершён */
    tls_config_t  config;
} tls_conn_t;

/* Глобальная инициализация wolfSSL (один раз при старте) */
int  tls_global_init(void);

/* Глобальная очистка */
void tls_global_cleanup(void);

/* Создать TLS соединение поверх существующего TCP fd */
int  tls_connect(tls_conn_t *conn, int fd, const tls_config_t *config);

/* Отправить данные через TLS */
ssize_t tls_send(tls_conn_t *conn, const void *buf, size_t len);

/* Получить данные через TLS */
ssize_t tls_recv(tls_conn_t *conn, void *buf, size_t len);

/* Закрыть TLS соединение (не закрывает fd) */
void tls_close(tls_conn_t *conn);

/* Строка последней ошибки wolfSSL */
const char *tls_last_error(void);

#endif /* TLS_H */

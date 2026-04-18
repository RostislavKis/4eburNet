#ifndef DNS_UPSTREAM_ASYNC_H
#define DNS_UPSTREAM_ASYNC_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>
#include "config.h"
#include "crypto/tls.h"

/* Максимум одновременных async DNS соединений */
#define DNS_ASYNC_POOL_SIZE  8

/* Протокол async соединения */
typedef enum {
    ASYNC_DNS_PROTO_DOT = 0,
    ASYNC_DNS_PROTO_DOH = 1,
} async_dns_proto_t;

/* Состояния state machine */
typedef enum {
    ASYNC_DNS_IDLE        = 0,
    ASYNC_DNS_CONNECTING  = 1,  /* O_NONBLOCK connect() → EPOLLOUT */
    ASYNC_DNS_TLS_HS      = 2,  /* wolfSSL_connect() nonblocking */
    ASYNC_DNS_SENDING     = 3,  /* tls_send() nonblocking */
    ASYNC_DNS_RECEIVING   = 4,  /* tls_recv() nonblocking */
    ASYNC_DNS_DONE        = 5,
    ASYNC_DNS_ERROR       = 6,
} async_dns_state_t;

/* Callback при завершении запроса */
typedef void (*async_dns_cb_t)(void *ctx,
                                const uint8_t *resp,
                                size_t resp_len,
                                int error);

/* Одно async DNS соединение */
typedef struct {
    async_dns_state_t state;
    async_dns_proto_t proto;
    int               fd;        /* -1 если не активен */
    bool              tls_init;  /* tls_conn_t инициализирован */
    tls_conn_t        tls;

    /* Параметры соединения (из конфига — без хардкода) */
    char              server_ip[64];
    uint16_t          server_port;
    char              sni[256];

    /* DNS запрос */
    uint8_t  query[4096];
    size_t   query_len;
    uint16_t dns_id;

    /* Буфер отправки (для DoT: [2-byte len][query]) */
    uint8_t  send_buf[4098];
    size_t   send_len;
    size_t   send_pos;   /* сколько уже отправлено */

    /* Буфер приёма */
    uint8_t  recv_buf[4098];
    size_t   recv_pos;   /* сколько уже получено */
    size_t   recv_expected; /* ожидаемая длина (из DoT length prefix) */
    bool     got_length; /* для DoT: получили ли 2-byte length prefix */

    /* Для DoH: дополнительный HTTP буфер */
    char     http_req[2048];  /* сформированный HTTP GET */
    size_t   http_req_len;

    /* Таймаут */
    struct timespec deadline;  /* CLOCK_MONOTONIC */

    /* Callback */
    async_dns_cb_t callback;
    void          *cb_ctx;

    /* Обратная ссылка для epoll data.ptr */
    struct async_dns_pool *pool;
    int pool_idx;   /* индекс в pool->conns[] */

    /* Конфиг (не владеет памятью) */
    const DnsConfig *dns_cfg;
} async_dns_conn_t;

/* Пул async соединений */
typedef struct async_dns_pool {
    async_dns_conn_t conns[DNS_ASYNC_POOL_SIZE];
    int              epoll_fd;  /* master epoll fd из main.c */
} async_dns_pool_t;

/* ── API ── */

/* Инициализировать пул */
void async_dns_pool_init(async_dns_pool_t *pool, int epoll_fd);

/* Освободить все соединения в пуле */
void async_dns_pool_free(async_dns_pool_t *pool);

/*
 * Начать async DoT запрос.
 * Выделяет слот из пула, создаёт nonblocking socket,
 * регистрирует в epoll, начинает connect().
 * Возвращает 0 при успехе, -1 если пул полон или ошибка.
 */
int async_dns_dot_start(async_dns_pool_t *pool,
                        const DnsConfig *cfg,
                        const uint8_t *query, size_t query_len,
                        uint16_t dns_id,
                        async_dns_cb_t callback, void *cb_ctx);

/*
 * Начать async DoH запрос.
 */
int async_dns_doh_start(async_dns_pool_t *pool,
                        const DnsConfig *cfg,
                        const uint8_t *query, size_t query_len,
                        uint16_t dns_id,
                        async_dns_cb_t callback, void *cb_ctx);

/*
 * Обработать epoll событие для конкретного соединения.
 * Вызывается из main epoll loop при событии на conn->fd.
 */
void async_dns_on_event(async_dns_conn_t *conn, uint32_t events);

/*
 * Проверить таймауты всех активных соединений.
 * Вызывается из main loop каждые ~100ms.
 */
void async_dns_check_timeouts(async_dns_pool_t *pool);

/*
 * Проверить, принадлежит ли указатель пулу (для dispatch в main epoll loop).
 */
bool async_dns_is_pool_ptr(const async_dns_pool_t *pool, const void *ptr);

/*
 * Закрыть соединение и вернуть слот в пул.
 * Вызывает callback с error=-1 если соединение активно.
 */
void async_dns_conn_close(async_dns_conn_t *conn);

#endif /* DNS_UPSTREAM_ASYNC_H */

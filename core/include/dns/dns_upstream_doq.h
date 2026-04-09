/* dns_upstream_doq.h — DoQ (DNS-over-QUIC, RFC 9250) клиент
 *
 * Компилируется только при CONFIG_PHOENIX_DOQ=1.
 * Не поддерживается на DEVICE_MICRO (нет QUIC).
 */

#ifndef DNS_UPSTREAM_DOQ_H
#define DNS_UPSTREAM_DOQ_H

#include "phoenix_config.h"

#if CONFIG_PHOENIX_DOQ

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "crypto/quic.h"
#include "config.h"

/* ── константы ─────────────────────────────────────────────────── */

#define DOQ_MAX_STREAMS           4       /* одновременных DNS запросов на соединение */
#define DOQ_HANDSHAKE_TIMEOUT_MS  5000
#define DOQ_QUERY_TIMEOUT_MS      5000
#define DOQ_IDLE_PING_MS          25000
#define DOQ_IDLE_CLOSE_MS         30000

/* ── состояние соединения ───────────────────────────────────────── */

typedef enum {
    DOQ_CONN_IDLE        = 0,
    DOQ_CONN_CONNECTING  = 1,
    DOQ_CONN_HANDSHAKE   = 2,
    DOQ_CONN_READY       = 3,
    DOQ_CONN_CLOSING     = 4,
} doq_conn_state_t;

/* ── состояние одного stream ────────────────────────────────────── */

typedef enum {
    DOQ_STREAM_FREE      = 0,
    DOQ_STREAM_SENT      = 1,   /* STREAM+FIN отправлен */
    DOQ_STREAM_RESPONSE  = 2,   /* получаем ответ       */
    DOQ_STREAM_DONE      = 3,   /* ответ получен полностью */
} doq_stream_state_t;

/* ── callback ответа ────────────────────────────────────────────── */

typedef void (*doq_response_cb_t)(void *ctx,
                                   const uint8_t *resp, size_t resp_len,
                                   int error  /* 0=ok, -1=err */);

/* ── один stream ────────────────────────────────────────────────── */

typedef struct {
    doq_stream_state_t  state;
    uint64_t            stream_id;     /* QUIC stream ID (0,4,8,...) */
    uint16_t            orig_qid;      /* оригинальный DNS ID для восстановления */
    uint8_t             rx_buf[2 + 65535]; /* 2-byte length + DNS ответ */
    size_t              rx_len;        /* накоплено байт */
    uint16_t            dns_len;       /* ожидаем N байт DNS (из первых 2 байт) */
    bool                len_parsed;    /* первые 2 байта разобраны */
    doq_response_cb_t   cb;
    void               *cb_ctx;
    int64_t             deadline_ms;
} doq_stream_t;

/* ── одно QUIC соединение ───────────────────────────────────────── */

typedef struct {
    doq_conn_state_t        state;
    int                     udp_fd;           /* SOCK_DGRAM nonblocking */
    WOLFSSL                *ssl;

    /* буфер TLS handshake data (wolfSSL → наш TX) */
    uint8_t                 hs_buf[4096];
    size_t                  hs_buf_len;
    quic_level_t            hs_level;
    uint64_t                hs_offset[3];    /* отправленных байт CRYPTO per уровень */

    /* QUIC crypto keys: [0]=Initial [1]=Handshake [2]=Application */
    quic_keys_t             keys[3];

    /* packet numbers */
    uint64_t                send_pn[3];       /* следующий PN для отправки */
    uint64_t                recv_largest[3];  /* наибольший полученный PN */
    uint64_t                recv_need_ack[3]; /* 1 = нужно отправить ACK */

    /* Connection IDs (8 байт каждый) */
    uint8_t                 scid[8];          /* Source CID (наш) */
    uint8_t                 dcid[8];          /* Destination CID (сервера) */

    /* Streams */
    doq_stream_t            streams[DOQ_MAX_STREAMS];
    uint64_t                next_stream_id;   /* bidirectional client: 0,4,8,... */

    /* Timing */
    int64_t                 created_ms;
    int64_t                 last_rx_ms;
    int64_t                 last_tx_ms;

    /* Адрес сервера */
    struct sockaddr_storage peer;
    socklen_t               peer_len;
} doq_conn_t;

/* ── пул соединений ─────────────────────────────────────────────── */

typedef struct {
    doq_conn_t  *conns;        /* heap: MICRO=0, NORMAL=2, FULL=4 */
    int          count;
    WOLFSSL_CTX *ssl_ctx;      /* один CTX на пул */
    int          epoll_fd;     /* master epoll для регистрации UDP fd */
} doq_pool_t;

/* ── API ────────────────────────────────────────────────────────── */

int  doq_pool_init(doq_pool_t *pool, int epoll_fd, const DnsConfig *cfg);
void doq_pool_free(doq_pool_t *pool);

/* Запустить DNS запрос через DoQ. Возвращает 0 = поставлен в очередь. */
int  doq_query_start(doq_pool_t *pool, const DnsConfig *cfg,
                      const uint8_t *query, size_t query_len,
                      doq_response_cb_t cb, void *cb_ctx);

/* Обработать epoll EPOLLIN на UDP fd */
void doq_handle_event(doq_pool_t *pool, int fd, uint32_t events);

/* Проверить таймауты (~каждые 100мс из main loop) */
void doq_check_timeouts(doq_pool_t *pool);

/* Проверить принадлежность fd к пулу */
bool doq_pool_owns_fd(const doq_pool_t *pool, int fd);

#endif /* CONFIG_PHOENIX_DOQ */
#endif /* DNS_UPSTREAM_DOQ_H */

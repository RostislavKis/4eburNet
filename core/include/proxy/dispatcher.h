#ifndef DISPATCHER_H
#define DISPATCHER_H

#include "proxy/tproxy.h"
#include "crypto/tls.h"
#include "config.h"

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <time.h>

/* Состояние relay соединения */
typedef enum {
    RELAY_DONE       = 0,   /* слот свободен */
    RELAY_CONNECTING = 1,   /* upstream connect в процессе */
    RELAY_ACTIVE     = 2,   /* relay активен, данные текут */
    RELAY_CLOSING    = 3,   /* один конец закрылся */
} relay_state_t;

/* Предварительное объявление */
typedef struct relay_conn relay_conn_t;

/*
 * Тег для epoll data.ptr — различает client_fd и upstream_fd
 * внутри одного relay (DEC-015: O(1) поиск по событию epoll)
 */
typedef struct {
    relay_conn_t *relay;
    bool          is_client;    /* true = client_fd, false = upstream_fd */
} relay_ep_t;

/* Одно relay соединение: client_fd ↔ upstream_fd */
struct relay_conn {
    int                     client_fd;
    int                     upstream_fd;
    relay_state_t           state;
    struct sockaddr_storage dst;        /* оригинальный dst пакета */
    time_t                  created_at;
    uint64_t                bytes_in;   /* клиент → upstream */
    uint64_t                bytes_out;  /* upstream → клиент */
    relay_ep_t              ep_client;  /* для epoll data.ptr */
    relay_ep_t              ep_upstream;
    tls_conn_t              tls;        /* TLS соединение к upstream */
    bool                    use_tls;    /* true = relay через tls_send/recv */
};

/* Состояние диспетчера */
typedef struct {
    int             epoll_fd;
    relay_conn_t   *conns;              /* массив соединений */
    int             conns_count;        /* текущее количество активных */
    int             conns_max;          /* лимит (из профиля устройства) */
    bool            has_splice;         /* ядро поддерживает splice() */
    int             splice_pipe[2];    /* pipe для splice (однопоточный) */
    uint8_t        *relay_buf;         /* буфер для read/write relay */
    size_t          relay_buf_size;    /* размер буфера (по профилю) */
    uint64_t        total_accepted;
    uint64_t        total_closed;
    uint64_t        tick_count;         /* счётчик вызовов tick */
} dispatcher_state_t;

/*
 * Интерфейс протокола (DEC-016: протоколы подключаются в 1.6)
 *
 * connect() вызывается после TCP connect к upstream.
 * Выполняет протокольное рукопожатие (VLESS header, SS handshake и т.д.)
 * Возвращает 0 при успехе.
 */
typedef struct {
    const char *name;       /* "direct", "vless", "ss", "trojan" */
    int (*connect)(relay_conn_t *relay,
                   const struct sockaddr_storage *dst,
                   const ServerConfig *server);
} proxy_protocol_t;

/* --- Жизненный цикл --- */

int  dispatcher_init(dispatcher_state_t *ds, DeviceProfile profile);
void dispatcher_set_context(dispatcher_state_t *ds,
                            const PhoenixConfig *cfg);
void dispatcher_tick(dispatcher_state_t *ds);
void dispatcher_cleanup(dispatcher_state_t *ds);
void dispatcher_stats(const dispatcher_state_t *ds,
                      uint64_t *accepted, uint64_t *closed);

/* --- Вызывается из tproxy.c (сигнатура НЕ меняется) --- */

void dispatcher_handle_conn(tproxy_conn_t *conn);
void dispatcher_handle_udp(tproxy_conn_t *conn,
                           const uint8_t *data, size_t len);

#endif /* DISPATCHER_H */

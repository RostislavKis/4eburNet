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
    RELAY_CLOSING    = 3,   /* оба конца закрыты, завершаем */
    RELAY_HALF_CLOSE = 4,   /* один конец закрыт, ждём второго (DEC-016) */
    RELAY_TLS_SHAKE  = 5,   /* TLS handshake в процессе (C-03/C-04) */
    RELAY_VLESS_SHAKE = 6,  /* VLESS response ожидание (C-03/C-04) */
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
    bool                    client_eof; /* клиент отправил FIN */
    bool                    upstream_eof; /* upstream отправил FIN */
    int                     server_idx; /* индекс сервера в cfg->servers[] */
    uint8_t                 vless_resp_buf[2]; /* буфер частичного VLESS ответа */
    uint8_t                 vless_resp_len;    /* байт прочитано (0-2) */
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
    /* Health-check состояние серверов */
    struct {
        int       server_idx;
        time_t    last_check;
        time_t    last_success;
        uint32_t  fail_count;
        bool      available;
    } health[8];                        /* до 8 серверов */
    int             health_count;       /* 0 = не инициализирован */
} dispatcher_state_t;

/*
 * Интерфейс протокола (неблокирующий, C-03/C-04)
 *
 * start() вызывается после TCP connect к upstream.
 * Инициирует рукопожатие и устанавливает relay->state.
 * direct: state = RELAY_ACTIVE (мгновенно)
 * vless:  state = RELAY_TLS_SHAKE (продолжается в tick)
 * Возвращает 0 при успехе инициации.
 */
typedef struct {
    const char *name;       /* "direct", "vless", "ss", "trojan" */
    int (*start)(relay_conn_t *relay,
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

/* --- Health-check failover --- */

/* Выбрать лучший доступный сервер (индекс в cfg->servers[]) */
int  dispatcher_select_server(dispatcher_state_t *ds,
                              const PhoenixConfig *cfg);

/* Обновить статус сервера после попытки подключения */
void dispatcher_server_result(dispatcher_state_t *ds,
                              int server_idx, bool success);

/* --- Вызывается из tproxy.c (сигнатура НЕ меняется) --- */

void dispatcher_handle_conn(tproxy_conn_t *conn);
void dispatcher_handle_udp(tproxy_conn_t *conn,
                           const uint8_t *data, size_t len);

#endif /* DISPATCHER_H */

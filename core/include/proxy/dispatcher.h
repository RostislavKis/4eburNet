#ifndef DISPATCHER_H
#define DISPATCHER_H

#include "proxy/tproxy.h"
#include "crypto/tls.h"
#include "4eburnet_config.h"
#if CONFIG_EBURNET_FAKE_IP
#include "dns/fake_ip.h"
#endif
#if CONFIG_EBURNET_STLS
#include "proxy/shadowtls.h"
#endif
#if CONFIG_EBURNET_DPI
#include "dpi/dpi_adapt.h"
#endif
#include "config.h"
#include "routing/device_policy.h"
#include "proxy/proxy_group.h"
#if CONFIG_EBURNET_GRPC_MULTIPLEX
#include "proxy/protocols/grpc.h"
#endif
#if CONFIG_EBURNET_XUDP
#include "proxy/protocols/muxcool.h"
#endif

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <stdatomic.h>
#include <time.h>
#define DISPATCHER_MAX_HEALTH  64

/* Runtime лимиты по mem_tier (G15-2). Выставляются один раз в main()
 * после mem_tier_init(); читаются в hot path без доп. вызовов функций. */
extern unsigned g_dispatcher_max_events;
extern unsigned g_relay_drain_per_call;

/* Состояние relay соединения */
typedef enum {
    RELAY_DONE       = 0,   /* слот свободен */
    RELAY_CONNECTING = 1,   /* upstream connect в процессе */
    RELAY_ACTIVE     = 2,   /* relay активен, данные текут */
    RELAY_CLOSING    = 3,   /* оба конца закрыты, завершаем */
    RELAY_HALF_CLOSE = 4,   /* один конец закрыт, ждём второго (DEC-016) */
    RELAY_TLS_SHAKE  = 5,   /* TLS handshake в процессе (C-03/C-04) */
    RELAY_VLESS_SHAKE = 6,  /* VLESS response ожидание (C-03/C-04) */
    RELAY_XHTTP_DN_CONNECT = 7,  /* XHTTP: download fd TCP connect */
    RELAY_XHTTP_UP_TLS  = 8,    /* XHTTP: upload TLS handshake */
    RELAY_XHTTP_DN_TLS  = 9,    /* XHTTP: download TLS handshake */
    RELAY_XHTTP_UP_REQ  = 10,   /* XHTTP: POST headers + VLESS */
    RELAY_XHTTP_DN_REQ  = 11,   /* XHTTP: GET + parse 200 OK */
    RELAY_XHTTP_ACTIVE  = 12,   /* XHTTP: chunked relay активен */
    RELAY_REALITY_HS    = 13,   /* Reality TLS 1.3 handshake (custom stack) */
#if CONFIG_EBURNET_AWG
    RELAY_AWG_HANDSHAKE = 14,  /* AWG UDP handshake */
    RELAY_AWG_ACTIVE    = 15,  /* AWG туннель активен */
#endif
#if CONFIG_EBURNET_STLS
    RELAY_STLS_SHAKE    = 16,  /* ShadowTLS handshake в процессе */
#endif
    RELAY_REALITY_VLESS = 17,   /* VLESS over Reality, ждём VLESS response */
    RELAY_GRPC_HS       = 18,   /* gRPC HTTP/2 handshake (T0-03) */
    RELAY_WS_HS         = 19,   /* WebSocket HTTP Upgrade handshake (T0-04) */
    RELAY_HTTP_UG_HS    = 20,   /* HTTPUpgrade handshake (T0-06) */
#if CONFIG_EBURNET_QUIC
    RELAY_HY2_CONNECT   = 21,   /* Hysteria2: QUIC HS + H3 auth завершён, ждём TCPResponse (T0-07) */
#endif
#if CONFIG_EBURNET_XUDP
    RELAY_MUXCOOL_HS    = 22,   /* VLESS+CMD=Mux handshake (после TLS) */
    RELAY_MUXCOOL_ACTIVE = 23,  /* активный relay через wake_fd */
#endif
} relay_state_t;

/* Предварительные объявления */
typedef struct relay_conn relay_conn_t;
struct xhttp_state;   /* из vless_xhttp.h */
struct ss_state;      /* из shadowsocks.h */
struct awg_state;     /* из awg.h — awg_state_t */
struct rules_engine;  /* из rules_engine.h */
struct vision_state;  /* из vision.h (T0-02) */
struct reality_conn_s;  /* из crypto/reality/reality_conn.h */
struct reality_auth_s;  /* из crypto/reality/reality_auth.h */

/*
 * Тег для epoll data.ptr — различает client_fd и upstream_fd
 * внутри одного relay (DEC-015: O(1) поиск по событию epoll).
 *
 * ep_type первое поле struct'а — позволяет диспатчеру в epoll loop
 * полиморфно различать relay_ep_t и grpc_conn_ep_t через `*(int*)data.ptr`.
 * relay_alloc делает calloc → ep_type=0=EPOLL_EP_RELAY автоматически
 * для встроенных полей relay_conn_t (ep_client/ep_upstream/ep_download).
 * Stack-allocated relay_ep_t требуют явного {.ep_type=EPOLL_EP_RELAY}.
 */
#define EPOLL_EP_RELAY        0
#define EPOLL_EP_GRPC_CONN    2
#define EPOLL_EP_MUXCOOL_CONN 4
typedef struct {
    int           ep_type;      /* = EPOLL_EP_RELAY (0) */
    relay_conn_t *relay;
    bool          is_client;    /* true = client_fd, false = upstream_fd */
} relay_ep_t;

/* grpc_conn_ep_t определён в proxy/protocols/grpc.h (включён выше при MULTIPLEX) */

#if CONFIG_EBURNET_XUDP
/* Persistent watcher для разделяемого Mux conn->tcp_fd. Layout совпадает с
 * grpc_conn_ep_t (int ep_type → conn → epoll_fd) — позволяет полиморфному
 * dispatch в epoll loop через `*(int*)data.ptr`. */
typedef struct {
    int                 ep_type;    /* = EPOLL_EP_MUXCOOL_CONN (4) */
    muxcool_conn_t     *conn;
    int                 epoll_fd;
} muxcool_conn_ep_t;

#define UDP_SESSION_TABLE_SIZE  256   /* степень 2, маска & (SIZE-1) */
#define UDP_SESSION_TTL_SEC      30   /* сессия удаляется после 30с без активности */

typedef struct {
    struct sockaddr_storage src;  /* клиент: IP:port */
    struct sockaddr_storage dst;  /* назначение: IP:port */
} udp_session_key_t;

typedef struct udp_session {
    udp_session_key_t       key;
    muxcool_stream_t       *stream;      /* Mux.Cool stream для этой UDP сессии */
    struct sockaddr_storage src_addr;    /* клиентский адрес для ответного sendmsg */
    time_t                  last_active;
    bool                    relay_owned; /* true = relay владеет stream, TTL cleanup не освобождает */
    struct udp_session     *next;        /* hash chain */
} udp_session_t;
#endif

/* Одно relay соединение: client_fd ↔ upstream_fd */
struct relay_conn {
    int                     client_fd;
    int                     upstream_fd;
    relay_state_t           state;
    struct sockaddr_storage dst;        /* оригинальный dst пакета */
    time_t                  created_at;
    time_t                  last_active;  /* время последней передачи (M-09) */
    uint64_t                bytes_in;   /* клиент → upstream */
    uint64_t                bytes_out;  /* upstream → клиент */
    char                    client_mac[18]; /* MAC клиента для traffic stats, "" если неизвестен */
    relay_ep_t              ep_client;  /* для epoll data.ptr */
    relay_ep_t              ep_upstream;
    tls_conn_t             *tls;        /* NULL если TLS не нужен */
    bool                    use_tls;    /* true = relay через tls_send/recv */
    bool                    client_eof; /* клиент отправил FIN */
    bool                    upstream_eof; /* upstream отправил FIN */
    int                     server_idx; /* индекс сервера в cfg->servers[] */
    /* DPI bypass (C.5) */
    bool                    dpi_bypass;      /* применить DPI bypass на первом пакете */
    bool                    dpi_first_done;  /* первый пакет уже обработан */
#if CONFIG_EBURNET_DPI
    dpi_strat_t             dpi_strategy;   /* применённая стратегия */
    bool                    dpi_success;    /* upstream ответил — DPI сработал */
#endif
    char                    ja3[33];        /* JA3 хэш первого TLS ClientHello */
    uint8_t                 vless_resp_buf[3]; /* [0]=ver, [1]=addons_len, [2]=addons_read */
    uint8_t                 vless_resp_len;    /* байт прочитано (0-2) */
    /* XHTTP транспорт */
    struct xhttp_state     *xhttp;            /* NULL если не XHTTP */
    struct ss_state        *ss;              /* NULL если не SS 2022 */
    struct awg_state       *awg;             /* NULL если не AWG */
#if CONFIG_EBURNET_STLS
    shadowtls_ctx_t        *stls;           /* NULL если не ShadowTLS transport */
    void                   *stls_io;        /* stls_io_ctx_t*, wolfSSL I/O context */
#endif
    struct vision_state    *vision;         /* NULL если не Vision (T0-02) */
    struct grpc_conn       *grpc;           /* NULL если не gRPC transport (T0-03) */
#if CONFIG_EBURNET_GRPC_MULTIPLEX
    grpc_stream_t          *grpc_stream;   /* NULL если не multiplexed gRPC */
#endif
#if CONFIG_EBURNET_XUDP
    muxcool_stream_t       *muxcool_stream; /* NULL если не XUDP/Mux.Cool */
    bool                    is_udp_relay;   /* UDP relay без client_fd */
    udp_session_key_t       udp_sess_key;   /* ключ для нахождения UDP сессии */
    struct sockaddr_storage src_udp_addr;   /* src UDP клиента */
#endif
    struct ws_client_conn  *ws;            /* NULL если не WS transport (T0-04) */
    struct http_upgrade_conn *http_ug;    /* NULL если не HTTPUpgrade (T0-06) */
#if CONFIG_EBURNET_QUIC
    /* WHY: hysteria2 требует отдельные conn (UDP fd + QUIC state) и stream
     * (TCP proxy stream поверх QUIC). void* чтобы не включать hysteria2.h в
     * каждый файл, который включает dispatcher.h. */
    void                   *hy2_conn;    /* hysteria2_conn_t*, NULL если не Hysteria2 (T0-07) */
    void                   *hy2_stream;  /* hysteria2_stream_t*, NULL если нет активного stream */
#endif
    char                    domain[256];    /* домен назначения из fake-ip/SNI; "" если IP */
    char                    group_name[64]; /* имя группы для retry; "" если DIRECT/нет группы */
    uint8_t                 retries;        /* счётчик попыток retry (0..3) */
    time_t  upstream_first_byte_deadline;  /* 0 = неактивен; deadline получения первого байта upstream */
    time_t  connect_deadline;             /* 0 = нет; дедлайн TCP connect (time(NULL)+5) */
    /* Reality TLS 1.3 (custom stack, заменяет wolfSSL для Reality VLESS).
     * Активен когда server->reality_pbk[0] != '\0'. Тогда use_tls = false. */
    struct reality_conn_s  *reality;        /* NULL если не Reality */
    struct reality_auth_s  *reality_auth;   /* owned, освобождается в relay_free */
    /* WHY: deferred keygen — wc_curve25519_make_key ~10-15ms на MIPS 880MHz блокирует
     * event loop при N одновременных RELAY_CONNECTING. RELAY_CONNECTING не throttled →
     * N×10ms пауза DNS recv-Q → iOS timeout → death spiral. Деферируем keygen в
     * RELAY_REALITY_HS под тот же REALITY_HS_PER_TICK=2 лимит. */
    bool                    reality_pending_init; /* Curve25519 keygen отложен */
    int                     download_fd;       /* XHTTP GET fd (-1 если нет) */
    relay_ep_t              ep_download;       /* epoll тег для download_fd */
    /* Буфер ожидающих данных upstream→client (при EAGAIN write на client_fd).
     * WHY: relay_buf — общий на все relay; reality_recv уже сдвинул rbuf_pos.
     * Без сохранения остатка данные теряются → TCP stream corruption → HTTP/2 reset. */
    uint8_t  *to_client_buf;   /* NULL = нет ожидающих данных */
    size_t    to_client_len;
    size_t    to_client_pos;
    bool      epollout_client; /* true = EPOLLOUT зарегистрирован на client_fd */
#ifdef __mips__
    /* WHY: EPOLLET upstream + for(;;) drain = сотни ms блокировки dispatcher_tick
     * (AES-GCM без HW accl). Переключаем в LT при входе в RELAY_ACTIVE, чтобы
     * можно было ограничить итерации и дать DNS обработаться. */
    bool      upstream_lt_mode;
    /* WHY: LT upstream_fd + to_client_buf полный → relay_transfer сразу EAGAIN
     * без чтения → persistent EPOLLIN spin 23% CPU. upstream_fd_paused = true
     * означает что upstream_fd убран из epoll до сброса to_client_buf (EPOLLOUT). */
    bool      upstream_fd_paused;
#endif
    /* WHY: после VLESS+Reality handshake xray PrivateVPN отвечает Vision frames
     * сразу, ДО получения inner ClientHello от клиента. Если переслать iPhone
     * раньше его собственного ClientHello — iPhone видит "ServerHello из
     * ниоткуда" → TLS protocol violation → close+Alert. Симптом: relay closed
     * in=0..30 out=6500. Флаг отметит что клиент успел отправить хотя бы один
     * пакет (включая ClientHello). До этого upstream→client пересылка
     * приостанавливается. */
    bool      client_sent_first;
#if CONFIG_EBURNET_AWG
    uint32_t  awg_hs_epollin_count; /* счётчик EPOLLIN в RELAY_AWG_HANDSHAKE; > 50 → timeout */
#endif
};

/* Состояние диспетчера */
typedef struct {
    int             epoll_fd;
    relay_conn_t   *conns;              /* массив соединений */
    int             conns_count;        /* текущее количество активных */
    int             conns_max;          /* лимит (из профиля устройства) */
    /* splice удалён: shared pipe = data corruption (H-12, C-05) */
    uint8_t        *relay_buf;         /* буфер для read/write relay */
    size_t          relay_buf_size;    /* размер буфера (по профилю) */
#if CONFIG_EBURNET_STLS
    uint8_t        *stls_buf;         /* буфер для stls_wrap/unwrap (relay_buf_size+9) */
#endif
    int             next_free;          /* clock-hand подсказка (H-05) */
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
    } health[DISPATCHER_MAX_HEALTH];    /* до DISPATCHER_MAX_HEALTH серверов */
    int             health_count;       /* 0 = не инициализирован */
    time_t          health_reset_at;    /* следующий health reset (M-07) */
#if CONFIG_EBURNET_GRPC_MULTIPLEX
    grpc_conn_pool_t *grpc_pool;        /* pool разделяемых H2 соединений */
#endif
#if CONFIG_EBURNET_XUDP
    muxcool_pool_t  *muxcool_pool;      /* pool VLESS+Mux.Cool conn'ов для XUDP */
    udp_session_t   *udp_sessions[UDP_SESSION_TABLE_SIZE]; /* hash table UDP сессий */
    int              udp_session_count;
    int              udp_reply_fd;       /* TPROXY reply socket (IP_TRANSPARENT) */
#endif
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
                            const EburNetConfig *cfg);
void dispatcher_set_rules_engine(struct rules_engine *re);
void dispatcher_set_pgm(proxy_group_manager_t *pgm);

/* Pre-warm DNS cache всех upstream-серверов из групп. Блокирует на N×~100ms
 * один раз при старте — потом hot path всегда cache hit, dispatcher_tick
 * не упирается в SO_RCVTIMEO=1с при первом resolve. */
void dispatcher_prewarm_resolve(proxy_group_manager_t *pgm,
                                const EburNetConfig *cfg);
void dispatcher_tick(dispatcher_state_t *ds);
void dispatcher_cleanup(dispatcher_state_t *ds);
void dispatcher_stats(const dispatcher_state_t *ds,
                      uint64_t *accepted, uint64_t *closed);

/* Последний JA3 хэш TLS соединения (32 hex + \0, или "" если нет) */
const char *dispatcher_get_last_ja3(void);

/* Счётчик ECH/ESNI соединений и тип последнего расширения */
uint32_t dispatcher_get_ech_connections(void);
uint16_t dispatcher_get_last_ech_type(void);

/* --- Health-check failover --- */

/* Выбрать лучший доступный сервер (индекс в cfg->servers[]) */
int  dispatcher_select_server(dispatcher_state_t *ds,
                              const EburNetConfig *cfg);

/* Обновить статус сервера после попытки подключения */
void dispatcher_server_result(dispatcher_state_t *ds,
                              int server_idx, bool success);

/* Установить глобальную fake-ip таблицу для reverse lookup */
#if CONFIG_EBURNET_FAKE_IP
void dispatcher_set_fake_ip(fake_ip_table_t *t);
#else
static inline void dispatcher_set_fake_ip(void *t) { (void)t; }
#endif

/* Установить device manager для per-device traffic stats */
void dispatcher_set_dm(device_manager_t *dm);

/* --- Вызывается из tproxy.c (сигнатура НЕ меняется) --- */

void dispatcher_handle_conn(tproxy_conn_t *conn);
void dispatcher_handle_udp(tproxy_conn_t *conn,
                           const uint8_t *data, size_t len);

/* Метрики диспетчера — устанавливаются из dispatcher.c */
extern atomic_uint g_dispatcher_tick_us;  /* высший зафиксированный tick мкс */
extern atomic_uint g_dns_recv_q_max;      /* пиковый recv-Q DNS сокета */

#endif /* DISPATCHER_H */

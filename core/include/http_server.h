#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "proxy/proxy_group.h"
#include "proxy/rule_provider.h"
#include "routing/device_policy.h"
#include "proxy/dispatcher.h"
#include "geo/geo_loader.h"

/* ── Константы ────────────────────────────────────────────────────── */
#define HTTP_PORT         8080
#define HTTP_MAX_CONN     8
#define HTTP_TIMEOUT_SEC  30
#define HTTP_BUF_SIZE     4096
/* HTTP_PATH_MAX 1024: длинные имена серверов в URL — emoji (4 байта) +
 * кириллица (2 байта) + spaces в URL-encoded виде (3 ASCII за байт) дают
 * до ~190 байт на имя. Плюс /proxies/<name>/delay?url=...&timeout=...
 * spec ≈250 байт. Старый лимит 256 обрезал query string и иногда сам путь
 * → /delay suffix исчезал → 405. Запас для будущих длинных имён. */
#define HTTP_PATH_MAX     1024
#define HTTP_MAX_BODY     65536

/* ── HTTP коды статусов ───────────────────────────────────────────── */
#define HTTP_200  200
#define HTTP_400  400
#define HTTP_404  404
#define HTTP_405  405
#define HTTP_500  500

/* ── Одно HTTP соединение ─────────────────────────────────────────── */
typedef struct http_conn_s {
    int    fd;                      /* дескриптор клиента, -1 = свободный слот */
    struct sockaddr_in peer_addr;   /* заполняется при accept4 */
    time_t connected_at;            /* время подключения для таймаута */
    char   path[HTTP_PATH_MAX];     /* распарсенный путь запроса */
    int    method_ok;               /* 1 = распознанный метод, 0 = другой */
    int    is_post;                 /* 1 = POST метод */
    int    is_put;                  /* 1 = PUT метод */
    int    is_patch;                /* 1 = PATCH метод */
    int    is_delete;               /* 1 = DELETE метод */
    int    is_options;              /* 1 = OPTIONS (CORS preflight) */
    int    content_length;          /* Content-Length из заголовка */
    int    headers_done;            /* 1 = заголовки полностью прочитаны */
    char   buf[HTTP_BUF_SIZE];      /* буфер чтения входящего запроса */
    int    buf_len;                 /* количество байт в buf */
    /* ─── WebSocket state (Phase 2 Group 5) ─── */
    int    is_websocket;            /* 1 после successful WS upgrade */
    int    ws_route;                /* enum ws_route (из ws.h) */
    /* ─── Async write state (§10) ─── */
    uint8_t *send_buf;              /* heap, pending write; NULL если нечего слать */
    size_t   send_len;              /* всего байт в send_buf */
    size_t   send_pos;              /* сколько уже отправлено */
    FILE    *send_file;             /* NULL или открытый файл для async file send */
    off_t    send_offset;           /* текущая позиция в файле */
    off_t    send_remaining;        /* байт осталось отправить */
} HttpConn;

/* ── Основная структура HTTP сервера ──────────────────────────────── */
typedef struct {
    int      listen_fd;             /* слушающий сокет */
    HttpConn conns[HTTP_MAX_CONN];  /* пул соединений */
    char     api_token[64];         /* токен для /api/control, из UCI; пусто = запрещено */
    /* WS /traffic stream state (previous snapshot для delta) */
    uint64_t traffic_prev_up;
    uint64_t traffic_prev_down;
} HttpServer;

/* ── Async write helpers (используются из ws_frame.c) ───────────────── */

/* Добавить данные в pending send-буфер соединения. */
int conn_queue_write(struct http_conn_s *c, const void *data, size_t len);

/* Сбросить pending send-буфер; при EAGAIN — добавить EPOLLOUT и вернуть 0. */
int conn_flush(struct http_conn_s *c, int epoll_fd);

/* ── Прототипы функций ────────────────────────────────────────────── */

/* Передать указатель на конфиг для /api/control (tc_fast, dpi toggles).
   Вызывать из main.c сразу после http_server_init(). */
typedef struct EburNetConfig EburNetConfig;  /* forward declaration */
void http_server_set_config(const EburNetConfig *cfg);

/* Передать указатель на менеджер групп для group_select/group_test.
   Вызывать из main.c после http_server_init(). */
void http_server_set_pgm(proxy_group_manager_t *pgm);

/* Передать указатель на device manager для /api/devices.
   Вызывать из main.c после http_server_init(). */
void http_server_set_dm(device_manager_t *dm);

/* Передать указатель на dispatcher для GET /connections.
   Вызывать из main.c после http_server_init(). */
void http_server_set_dispatcher(dispatcher_state_t *ds);

/* Передать указатель на rule_provider_manager для /providers/rules ruleCount.
   Вызывать из main.c после http_server_init(). */
void http_server_set_rpm(rule_provider_manager_t *rpm);

/* Создать слушающий сокет на HTTP_PORT.
   Инициализировать пул соединений.
   Возвращает 0 при успехе, -1 при ошибке. */
int  http_server_init(HttpServer *srv);

/* Зарегистрировать listen_fd и все открытые conn fds в epoll.
   Вызывать один раз после http_server_init(). */
void http_server_register_epoll(HttpServer *srv, int epoll_fd);

/* Обработать событие epoll на fd.
   evmask — events из epoll_event.events (EPOLLIN | EPOLLOUT | ...).
   Возвращает 0 если fd принадлежит серверу, -1 если fd не наш. */
int  http_server_handle(HttpServer *srv, int fd, int epoll_fd, uint32_t evmask);

/* Закрыть соединения с истёкшим таймаутом.
   Вызывать периодически из главного цикла. */
void http_server_tick(HttpServer *srv, int epoll_fd);

/* Periodic broadcast для WS streams (/memory в Part B).
   Вызывать из main loop раз в секунду (tick % 100 при 10ms timeout). */
void http_server_broadcast_tick(HttpServer *srv, int epoll_fd);

/* Освободить все ресурсы сервера. */
void http_server_close(HttpServer *srv);

/* Вернуть текущий ожидаемый JA3 хэш (32 hex + \0). */
const char *http_server_get_ja3_expected(void);

/* Записать кэш серверов в /tmp/4eburnet-servers.json (без блокировки). */
void http_server_write_servers_cache(void);

/* Обновить флаг готовности гео-баз — отображается в /api/status.
   Вызывать из main.c после geo_manager_init. */
void http_server_set_geo_loaded(bool loaded);

/* Передать указатель на geo_manager для route_api_geo.
   Вызывать из main.c после geo_manager_init и при каждом reload.
   WHY: прямой доступ без IPC (IPC deadlock в single-threaded epoll). */
void http_server_set_geo_manager(const geo_manager_t *gm);

/* Передать указатель на rules_engine для hit_count в GET /rules.
   Вызывать из main.c после rules_engine_init (и при каждом reload). */
typedef struct rules_engine rules_engine_t;
void http_server_set_re(rules_engine_t *re);

/* Перечитать api_token из UCI — вызывать при SIGHUP reload.
   Без этого смена токена в UCI требует полного рестарта. */
void http_server_reload_token(void);

/* Записать кэш DNS-конфига в /tmp/4eburnet-dns.json (без блокировки). */
void http_server_write_dns_cache(void);

#endif /* HTTP_SERVER_H */

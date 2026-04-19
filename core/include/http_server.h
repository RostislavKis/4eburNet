#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <time.h>
#include <sys/types.h>

/* ── Константы ────────────────────────────────────────────────────── */
#define HTTP_PORT         8080
#define HTTP_MAX_CONN     8
#define HTTP_TIMEOUT_SEC  30
#define HTTP_BUF_SIZE     4096
#define HTTP_PATH_MAX     256
#define HTTP_MAX_BODY     65536

/* ── HTTP коды статусов ───────────────────────────────────────────── */
#define HTTP_200  200
#define HTTP_400  400
#define HTTP_404  404
#define HTTP_405  405
#define HTTP_500  500

/* ── Одно HTTP соединение ─────────────────────────────────────────── */
typedef struct {
    int    fd;                      /* дескриптор клиента, -1 = свободный слот */
    time_t connected_at;            /* время подключения для таймаута */
    char   path[HTTP_PATH_MAX];     /* распарсенный путь запроса */
    int    method_ok;               /* 1 = GET или POST, 0 = другой метод */
    int    is_post;                 /* 1 = POST метод */
    int    content_length;          /* Content-Length из заголовка */
    int    headers_done;            /* 1 = заголовки полностью прочитаны */
    char   buf[HTTP_BUF_SIZE];      /* буфер чтения входящего запроса */
    int    buf_len;                 /* количество байт в buf */
} HttpConn;

/* ── Основная структура HTTP сервера ──────────────────────────────── */
typedef struct {
    int      listen_fd;             /* слушающий сокет */
    HttpConn conns[HTTP_MAX_CONN];  /* пул соединений */
    char     api_token[64];         /* токен для /api/control, из UCI; пусто = запрещено */
} HttpServer;

/* ── Прототипы функций ────────────────────────────────────────────── */

/* Передать указатель на конфиг для /api/control (tc_fast, dpi toggles).
   Вызывать из main.c сразу после http_server_init(). */
typedef struct EburNetConfig EburNetConfig;  /* forward declaration */
void http_server_set_config(const EburNetConfig *cfg);

/* Создать слушающий сокет на HTTP_PORT.
   Инициализировать пул соединений.
   Возвращает 0 при успехе, -1 при ошибке. */
int  http_server_init(HttpServer *srv);

/* Зарегистрировать listen_fd и все открытые conn fds в epoll.
   Вызывать один раз после http_server_init(). */
void http_server_register_epoll(HttpServer *srv, int epoll_fd);

/* Обработать событие epoll на fd.
   Возвращает 0 если fd принадлежит серверу, -1 если fd не наш. */
int  http_server_handle(HttpServer *srv, int fd, int epoll_fd);

/* Закрыть соединения с истёкшим таймаутом.
   Вызывать периодически из главного цикла. */
void http_server_tick(HttpServer *srv, int epoll_fd);

/* Освободить все ресурсы сервера. */
void http_server_close(HttpServer *srv);

/* Вернуть текущий ожидаемый JA3 хэш (32 hex + \0). */
const char *http_server_get_ja3_expected(void);

#endif /* HTTP_SERVER_H */

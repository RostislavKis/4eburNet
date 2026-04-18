#ifndef VLESS_XHTTP_H
#define VLESS_XHTTP_H

#include "crypto/tls.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

/* Session ID — 16 случайных байт в hex */
typedef struct {
    char hex[33];
} xhttp_session_id_t;

/* Состояние XHTTP соединения */
typedef struct xhttp_state {
    tls_conn_t          upload;         /* POST (клиент → сервер) */
    tls_conn_t          download;       /* GET (сервер → клиент) */
    xhttp_session_id_t  session_id;
    char                path[128];
    char                host[256];
    bool                upload_ready;
    bool                download_ready;
    /* Буфер парсинга HTTP ответа download */
    uint8_t             resp_buf[4096];
    size_t              resp_len;
    bool                headers_parsed;
    /* Буфер парсинга chunk длины при recv */
    char                chunk_hdr[16];
    size_t              chunk_hdr_len;
    size_t              chunk_remaining; /* байт до конца текущего chunk */
    bool                chunk_in_data;  /* true = читаем данные chunk */
    bool                chunk_awaiting_crlf; /* ждём \r\n после данных */
    uint8_t             chunk_crlf_read;     /* байт \r\n прочитано (0/1/2) */
} xhttp_state_t;

/* Сгенерировать session ID из /dev/urandom */
void xhttp_session_id_gen(xhttp_session_id_t *sid);

/* Начать XHTTP: tls_connect_start для обоих fd */
int xhttp_start(xhttp_state_t *xh, int upload_fd, int download_fd,
                const tls_config_t *tls_cfg,
                const char *path, const char *host);

/* Шаг TLS handshake (неблокирующий) */
tls_step_result_t xhttp_upload_tls_step(xhttp_state_t *xh);
tls_step_result_t xhttp_download_tls_step(xhttp_state_t *xh);

/* Отправить POST заголовки + VLESS header (после TLS upload) */
int xhttp_send_upload_request(xhttp_state_t *xh,
                              const struct sockaddr_storage *dst,
                              const char *uuid_str);

/* Отправить GET запрос (после TLS download) */
int xhttp_send_download_request(xhttp_state_t *xh);

/* Парсить HTTP response (200 OK) — неблокирующий шаг */
/* Возвращает: 0=готово, 1=повторить, -1=ошибка */
int xhttp_parse_response_step(xhttp_state_t *xh);

/* Отправить данные через chunked POST */
ssize_t xhttp_send_chunk(xhttp_state_t *xh,
                         const uint8_t *data, size_t len);

/* Получить данные из chunked GET */
ssize_t xhttp_recv_chunk(xhttp_state_t *xh,
                         uint8_t *buf, size_t buflen);

/* Закрыть оба TLS соединения */
void xhttp_close(xhttp_state_t *xh);

#endif /* VLESS_XHTTP_H */

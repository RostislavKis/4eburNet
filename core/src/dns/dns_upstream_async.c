/*
 * dns_upstream_async.c — неблокирующий DNS upstream (DoT/DoH)
 * Интегрируется в master epoll loop через async_dns_on_event().
 */

/* wolfSSL options.h — ПЕРВЫМ, до остальных wolfSSL headers */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include "dns/dns_upstream_async.h"
#include "4eburnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Таймаут по умолчанию если не задан в конфиге */
#define ASYNC_DNS_TIMEOUT_MS_DEFAULT 3000

/* Выделить свободный слот из пула */
static async_dns_conn_t *alloc_slot(async_dns_pool_t *pool)
{
    for (int i = 0; i < DNS_ASYNC_POOL_SIZE; i++) {
        if (pool->conns[i].state == ASYNC_DNS_IDLE) {
            async_dns_conn_t *c = &pool->conns[i];
            memset(c, 0, sizeof(*c));
            c->fd       = -1;
            c->pool     = pool;
            c->pool_idx = i;
            return c;
        }
    }
    return NULL;  /* пул полон */
}

void async_dns_pool_init(async_dns_pool_t *pool, int epoll_fd)
{
    memset(pool, 0, sizeof(*pool));
    pool->epoll_fd = epoll_fd;
    for (int i = 0; i < DNS_ASYNC_POOL_SIZE; i++) {
        pool->conns[i].fd       = -1;
        pool->conns[i].state    = ASYNC_DNS_IDLE;
        pool->conns[i].pool     = pool;
        pool->conns[i].pool_idx = i;
    }
}

void async_dns_conn_close(async_dns_conn_t *conn)
{
    if (!conn || conn->state == ASYNC_DNS_IDLE) return;

    /* Вызвать callback с ошибкой если запрос не завершён успешно */
    if (conn->state != ASYNC_DNS_DONE && conn->callback) {
        conn->callback(conn->cb_ctx, NULL, 0, -1);
    }

    /* Снять с epoll */
    if (conn->fd >= 0 && conn->pool->epoll_fd >= 0)
        epoll_ctl(conn->pool->epoll_fd, EPOLL_CTL_DEL,
                  conn->fd, NULL);

    /* Закрыть TLS */
    if (conn->tls_init) {
        tls_close(&conn->tls);
        conn->tls_init = false;
    }

    /* Закрыть fd */
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }

    /* Вернуть слот */
    conn->state    = ASYNC_DNS_IDLE;
    conn->callback = NULL;
    conn->cb_ctx   = NULL;
}

void async_dns_pool_free(async_dns_pool_t *pool)
{
    for (int i = 0; i < DNS_ASYNC_POOL_SIZE; i++)
        async_dns_conn_close(&pool->conns[i]);
}

bool async_dns_is_pool_ptr(const async_dns_pool_t *pool, const void *ptr)
{
    /* Проверить что ptr указывает на один из слотов пула.
       Используем полуоткрытый интервал [first, end) */
    const void *first = (const void *)&pool->conns[0];
    const void *end   = (const void *)&pool->conns[DNS_ASYNC_POOL_SIZE];
    return (ptr >= first && ptr < end);
}

/* ── Вспомогательные ── */

/* Создать nonblocking socket + начать connect */
static int start_connect(async_dns_conn_t *conn)
{
    /* Определить семейство адреса */
    struct sockaddr_storage ss;
    socklen_t ss_len;
    memset(&ss, 0, sizeof(ss));

    struct sockaddr_in  *s4 = (struct sockaddr_in  *)&ss;
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;

    if (inet_pton(AF_INET, conn->server_ip, &s4->sin_addr) == 1) {
        s4->sin_family = AF_INET;
        s4->sin_port   = htons(conn->server_port);
        ss_len = sizeof(*s4);
    } else if (inet_pton(AF_INET6, conn->server_ip, &s6->sin6_addr) == 1) {
        s6->sin6_family = AF_INET6;
        s6->sin6_port   = htons(conn->server_port);
        ss_len = sizeof(*s6);
    } else {
        log_msg(LOG_WARN, "async_dns: невалидный IP: %s", conn->server_ip);
        return -1;
    }

    conn->fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (conn->fd < 0) return -1;

    /* O_NONBLOCK */
    int flags = fcntl(conn->fd, F_GETFL, 0);
    if (flags < 0 || fcntl(conn->fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(conn->fd); conn->fd = -1; return -1;
    }

    /* Зарегистрировать в epoll — ждём EPOLLOUT (connect ready) */
    struct epoll_event ev = {
        .events   = EPOLLOUT | EPOLLERR | EPOLLHUP,
        .data.ptr = conn,
    };
    if (epoll_ctl(conn->pool->epoll_fd, EPOLL_CTL_ADD,
                  conn->fd, &ev) < 0) {
        close(conn->fd); conn->fd = -1; return -1;
    }

    /* Начать nonblocking connect */
    int rc = connect(conn->fd, (struct sockaddr *)&ss, ss_len);
    if (rc < 0 && errno != EINPROGRESS) {
        epoll_ctl(conn->pool->epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
        close(conn->fd); conn->fd = -1; return -1;
    }

    /* Установить deadline */
    clock_gettime(CLOCK_MONOTONIC, &conn->deadline);
    int timeout_ms = ASYNC_DNS_TIMEOUT_MS_DEFAULT;
    conn->deadline.tv_sec  += timeout_ms / 1000;
    conn->deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (conn->deadline.tv_nsec >= 1000000000L) {
        conn->deadline.tv_sec++;
        conn->deadline.tv_nsec -= 1000000000L;
    }

    conn->state = ASYNC_DNS_CONNECTING;
    log_msg(LOG_DEBUG, "async_dns: connect → %s:%u (%s)",
            conn->server_ip, conn->server_port,
            conn->proto == ASYNC_DNS_PROTO_DOH ? "DoH" : "DoT");
    return 0;
}

/* ── Публичный API ── */

int async_dns_dot_start(async_dns_pool_t *pool,
                        const DnsConfig *cfg,
                        const uint8_t *query, size_t query_len,
                        uint16_t dns_id,
                        async_dns_cb_t callback, void *cb_ctx)
{
    if (!cfg || !query || query_len == 0 || query_len > 4096)
        return -1;

    async_dns_conn_t *conn = alloc_slot(pool);
    if (!conn) {
        log_msg(LOG_WARN, "async_dns: пул полон (DoT)");
        return -1;
    }

    conn->proto    = ASYNC_DNS_PROTO_DOT;
    conn->dns_cfg  = cfg;
    conn->callback = callback;
    conn->cb_ctx   = cb_ctx;
    conn->dns_id   = dns_id;

    /* Параметры из конфига — без хардкода */
    {   int _n = snprintf(conn->server_ip, sizeof(conn->server_ip),
                 "%s", cfg->dot_server_ip[0] ? cfg->dot_server_ip : "");
        if (_n < 0 || (size_t)_n >= sizeof(conn->server_ip))
            log_msg(LOG_WARN, "async DoT: server_ip обрезан");
    }
    conn->server_port = cfg->dot_port > 0 ? cfg->dot_port : 853;
    {   int _n = snprintf(conn->sni, sizeof(conn->sni),
                 "%s", cfg->dot_sni[0] ? cfg->dot_sni : "");
        if (_n < 0 || (size_t)_n >= sizeof(conn->sni))
            log_msg(LOG_WARN, "async DoT: SNI обрезан");
    }

    if (!conn->server_ip[0]) {
        log_msg(LOG_WARN, "async_dns: dot_server_ip не задан в конфиге");
        conn->state = ASYNC_DNS_IDLE;
        return -1;
    }

    /* Сохранить запрос */
    memcpy(conn->query, query, query_len);
    conn->query_len = query_len;

    /* DoT framing: [2-byte len][query] */
    conn->send_buf[0] = (uint8_t)((query_len >> 8) & 0xFF);
    conn->send_buf[1] = (uint8_t)(query_len & 0xFF);
    memcpy(conn->send_buf + 2, query, query_len);
    conn->send_len = query_len + 2;
    conn->send_pos = 0;

    return start_connect(conn);
}

/* ── TLS nonblocking helper ── */

/*
 * Один шаг TLS handshake через tls_connect_start/tls_connect_step.
 * Возвращает: 1=готово, 0=ждём epoll, -1=ошибка.
 */
static int tls_handshake_step(async_dns_conn_t *conn)
{
    if (!conn->tls_init) {
        tls_config_t tls_cfg = {0};
        if (conn->sni[0]) {
            int _n = snprintf(tls_cfg.sni, sizeof(tls_cfg.sni), "%s", conn->sni);
            if (_n < 0 || (size_t)_n >= sizeof(tls_cfg.sni))
                log_msg(LOG_WARN, "async DoT: TLS SNI обрезан");
        }
        tls_cfg.fingerprint = TLS_FP_NONE;
        /* DoT серверы имеют валидные CA-сертификаты.
         * VERIFY_PEER обязателен — иначе ТСПУ может подменить DNS через MitM */
        tls_cfg.verify_cert = true;

        if (tls_connect_start(&conn->tls, conn->fd, &tls_cfg) < 0) {
            log_msg(LOG_WARN, "async_dns: tls_connect_start failed");
            return -1;
        }
        conn->tls_init = true;
    }

    tls_step_result_t r = tls_connect_step(&conn->tls);
    if (r == TLS_OK)
        return 1;
    if (r == TLS_WANT_IO) {
        /* tls_connect_step не различает WANT_READ/WANT_WRITE — мониторим оба */
        struct epoll_event ev = {
            .events   = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
            .data.ptr = conn,
        };
        epoll_ctl(conn->pool->epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
        return 0;
    }
    log_msg(LOG_WARN, "async_dns: TLS handshake error (%s)", conn->server_ip);
    return -1;
}

/* Переключить epoll на EPOLLOUT, перейти в SENDING */
static void begin_sending(async_dns_conn_t *conn)
{
    struct epoll_event ev = {
        .events   = EPOLLOUT | EPOLLERR | EPOLLHUP,
        .data.ptr = conn,
    };
    epoll_ctl(conn->pool->epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
    conn->state = ASYNC_DNS_SENDING;
}

/* Переключить epoll на EPOLLIN, перейти в RECEIVING */
static void begin_receiving(async_dns_conn_t *conn)
{
    struct epoll_event ev = {
        .events   = EPOLLIN | EPOLLERR | EPOLLHUP,
        .data.ptr = conn,
    };
    epoll_ctl(conn->pool->epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
    conn->state       = ASYNC_DNS_RECEIVING;
    conn->recv_pos    = 0;
    if (conn->proto == ASYNC_DNS_PROTO_DOT) {
        conn->got_length    = false;
        conn->recv_expected = 2;  /* сначала читаем 2-byte length prefix */
    } else {
        conn->recv_expected = sizeof(conn->recv_buf) - 1;
    }
}

/* ── Основной обработчик событий ── */

void async_dns_on_event(async_dns_conn_t *conn, uint32_t events)
{
    if (!conn || conn->state == ASYNC_DNS_IDLE ||
        conn->state == ASYNC_DNS_DONE ||
        conn->state == ASYNC_DNS_ERROR)
        return;

    if (events & (EPOLLERR | EPOLLHUP)) {
        log_msg(LOG_WARN, "async_dns: socket error state=%d %s",
                conn->state, conn->server_ip);
        conn->state = ASYNC_DNS_ERROR;
        async_dns_conn_close(conn);
        return;
    }

    /* goto-based state machine: переходы без блокировки */
restart:
    switch (conn->state) {

    case ASYNC_DNS_CONNECTING:
        if (!(events & EPOLLOUT)) break;
        {
            int sockerr = 0;
            socklen_t elen = sizeof(sockerr);
            getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &sockerr, &elen);
            if (sockerr != 0) {
                log_msg(LOG_WARN, "async_dns: connect failed %s:%u: %s",
                        conn->server_ip, conn->server_port,
                        strerror(sockerr));
                conn->state = ASYNC_DNS_ERROR;
                async_dns_conn_close(conn);
                return;
            }
        }
        log_msg(LOG_DEBUG, "async_dns: connected %s:%u",
                conn->server_ip, conn->server_port);
        conn->state = ASYNC_DNS_TLS_HS;
        goto restart;  /* сразу начать TLS handshake */

    case ASYNC_DNS_TLS_HS: {
        int r = tls_handshake_step(conn);
        if (r < 0) {
            conn->state = ASYNC_DNS_ERROR;
            async_dns_conn_close(conn);
            return;
        }
        if (r == 1) {
            log_msg(LOG_DEBUG, "async_dns: TLS OK %s", conn->server_ip);
            begin_sending(conn);
            goto restart;  /* сразу попробовать отправить */
        }
        /* r == 0: ждём следующего epoll события */
        break;
    }

    case ASYNC_DNS_SENDING:
        while (conn->send_pos < conn->send_len) {
            ssize_t n = wolfSSL_write(
                (WOLFSSL *)conn->tls.ssl,
                conn->send_buf + conn->send_pos,
                (int)(conn->send_len - conn->send_pos));
            if (n > 0) {
                conn->send_pos += (size_t)n;
                continue;
            }
            int err = wolfSSL_get_error((WOLFSSL *)conn->tls.ssl, (int)n);
            if (err == WOLFSSL_ERROR_WANT_WRITE) {
                struct epoll_event ev = {
                    .events   = EPOLLOUT | EPOLLERR | EPOLLHUP,
                    .data.ptr = conn,
                };
                epoll_ctl(conn->pool->epoll_fd, EPOLL_CTL_MOD,
                          conn->fd, &ev);
                return;
            }
            if (err == WOLFSSL_ERROR_WANT_READ) {
                struct epoll_event ev = {
                    .events   = EPOLLIN | EPOLLERR | EPOLLHUP,
                    .data.ptr = conn,
                };
                epoll_ctl(conn->pool->epoll_fd, EPOLL_CTL_MOD,
                          conn->fd, &ev);
                return;
            }
            log_msg(LOG_WARN, "async_dns: write error %d (%s)",
                    err, conn->server_ip);
            conn->state = ASYNC_DNS_ERROR;
            async_dns_conn_close(conn);
            return;
        }
        /* Всё отправлено */
        begin_receiving(conn);
        goto restart;

    case ASYNC_DNS_RECEIVING:
        if (!(events & EPOLLIN)) break;
        for (;;) {
            size_t space = sizeof(conn->recv_buf) - conn->recv_pos - 1;
            if (space == 0) break;

            ssize_t n = wolfSSL_read(
                (WOLFSSL *)conn->tls.ssl,
                conn->recv_buf + conn->recv_pos,
                (int)space);
            if (n > 0) {
                conn->recv_pos += (size_t)n;

                /* DoT: разбор 2-byte length prefix */
                if (conn->proto == ASYNC_DNS_PROTO_DOT &&
                    !conn->got_length && conn->recv_pos >= 2) {
                    conn->recv_expected =
                        (size_t)(((uint16_t)conn->recv_buf[0] << 8) |
                                  conn->recv_buf[1]) + 2;
                    if (conn->recv_expected < 2 ||
                        conn->recv_expected > sizeof(conn->recv_buf) - 1) {
                        conn->state = ASYNC_DNS_ERROR;
                        async_dns_conn_close(conn);
                        return;
                    }
                    conn->got_length = true;
                }

                /* Проверить завершённость */
                bool done = false;
                if (conn->proto == ASYNC_DNS_PROTO_DOT) {
                    done = conn->got_length &&
                           conn->recv_pos >= conn->recv_expected;
                } else {
                    /* DoH: got_length = нашли \r\n\r\n, recv_expected = полная длина */
                    conn->recv_buf[conn->recv_pos] = '\0';
                    if (!conn->got_length) {
                        char *hdr_end = strstr((char *)conn->recv_buf,
                                               "\r\n\r\n");
                        if (hdr_end) {
                            conn->got_length = true;
                            size_t body_offset = (size_t)(hdr_end + 4 -
                                                 (char *)conn->recv_buf);
                            /* Парсим Content-Length (case-insensitive: оба варианта) */
                            char *cl = strstr((char *)conn->recv_buf,
                                              "Content-Length:");
                            if (!cl) cl = strstr((char *)conn->recv_buf,
                                                 "content-length:");
                            if (cl) {
                                size_t clen = (size_t)atoi(cl + 15);
                                conn->recv_expected = body_offset + clen;
                            } else {
                                /* Нет Content-Length — ждём connection close */
                                conn->recv_expected = 0;
                            }
                        }
                    }
                    /* done если recv_expected задан и достигнут */
                    if (conn->got_length && conn->recv_expected > 0)
                        done = (conn->recv_pos >= conn->recv_expected);
                    /* иначе done только при WOLFSSL_ERROR_ZERO_RETURN (ниже) */
                }

                if (!done) continue;

                /* Готово — извлечь DNS ответ */
                conn->state = ASYNC_DNS_DONE;
                uint8_t *resp     = NULL;
                size_t   resp_len = 0;

                if (conn->proto == ASYNC_DNS_PROTO_DOT) {
                    resp     = conn->recv_buf + 2;
                    resp_len = conn->recv_pos - 2;
                } else {
                    uint8_t *body = (uint8_t *)strstr(
                        (char *)conn->recv_buf, "\r\n\r\n");
                    if (body) {
                        body    += 4;
                        resp     = body;
                        resp_len = conn->recv_pos -
                                   (size_t)(body - conn->recv_buf);
                    }
                }

                if (resp && resp_len >= 12 && conn->callback)
                    conn->callback(conn->cb_ctx, resp, resp_len, 0);
                else if (conn->callback)
                    conn->callback(conn->cb_ctx, NULL, 0, -1);

                async_dns_conn_close(conn);
                return;
            }

            /* n <= 0 */
            int err = wolfSSL_get_error((WOLFSSL *)conn->tls.ssl, (int)n);
            if (err == WOLFSSL_ERROR_WANT_READ)
                break;  /* ждём следующего EPOLLIN */
            if (err == WOLFSSL_ERROR_WANT_WRITE) {
                struct epoll_event ev = {
                    .events   = EPOLLOUT | EPOLLERR | EPOLLHUP,
                    .data.ptr = conn,
                };
                epoll_ctl(conn->pool->epoll_fd, EPOLL_CTL_MOD,
                          conn->fd, &ev);
                break;
            }
            if (err == WOLFSSL_ERROR_ZERO_RETURN) {
                /* Сервер закрыл соединение */
                uint8_t *resp     = conn->recv_buf;
                size_t   resp_len = conn->recv_pos;
                if (conn->proto == ASYNC_DNS_PROTO_DOT &&
                    conn->got_length && conn->recv_pos > 2) {
                    resp    += 2;
                    resp_len -= 2;
                }
                conn->state = ASYNC_DNS_DONE;
                if (resp_len >= 12 && conn->callback)
                    conn->callback(conn->cb_ctx, resp, resp_len, 0);
                else if (conn->callback)
                    conn->callback(conn->cb_ctx, NULL, 0, -1);
                async_dns_conn_close(conn);
                return;
            }
            log_msg(LOG_WARN, "async_dns: read error %d (%s)",
                    err, conn->server_ip);
            conn->state = ASYNC_DNS_ERROR;
            async_dns_conn_close(conn);
            return;
        }
        break;

    default:
        break;
    }
}

/* ── Проверка таймаутов ── */

void async_dns_check_timeouts(async_dns_pool_t *pool)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    for (int i = 0; i < DNS_ASYNC_POOL_SIZE; i++) {
        async_dns_conn_t *c = &pool->conns[i];
        if (c->state == ASYNC_DNS_IDLE ||
            c->state == ASYNC_DNS_DONE ||
            c->state == ASYNC_DNS_ERROR)
            continue;

        if (now.tv_sec > c->deadline.tv_sec ||
            (now.tv_sec == c->deadline.tv_sec &&
             now.tv_nsec >= c->deadline.tv_nsec)) {
            log_msg(LOG_WARN, "async_dns: timeout %s:%u (%s)",
                    c->server_ip, c->server_port,
                    c->proto == ASYNC_DNS_PROTO_DOH ? "DoH" : "DoT");
            c->state = ASYNC_DNS_ERROR;
            async_dns_conn_close(c);
        }
    }
}

int async_dns_doh_start(async_dns_pool_t *pool,
                        const DnsConfig *cfg,
                        const uint8_t *query, size_t query_len,
                        uint16_t dns_id,
                        async_dns_cb_t callback, void *cb_ctx)
{
    if (!cfg || !query || query_len == 0 || query_len > 4096)
        return -1;
    if (!cfg->doh_url[0]) {
        log_msg(LOG_WARN, "async_dns: doh_url не задан в конфиге");
        return -1;
    }

    async_dns_conn_t *conn = alloc_slot(pool);
    if (!conn) {
        log_msg(LOG_WARN, "async_dns: пул полон (DoH)");
        return -1;
    }

    conn->proto    = ASYNC_DNS_PROTO_DOH;
    conn->dns_cfg  = cfg;
    conn->callback = callback;
    conn->cb_ctx   = cb_ctx;
    conn->dns_id   = dns_id;

    /* Парсить URL → host, path */
    const char *url = cfg->doh_url;
    if (strncmp(url, "https://", 8) == 0) url += 8;
    const char *slash = strchr(url, '/');
    char host[256] = {0};
    char path[256] = "/dns-query";
    if (slash) {
        size_t hlen = (size_t)(slash - url);
        if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
        memcpy(host, url, hlen);
        host[hlen] = '\0';
        size_t plen = strlen(slash);
        if (plen >= sizeof(path)) plen = sizeof(path) - 1;
        memcpy(path, slash, plen);
        path[plen] = '\0';
    } else {
        size_t ulen = strlen(url);
        if (ulen >= sizeof(host)) ulen = sizeof(host) - 1;
        memcpy(host, url, ulen);
        host[ulen] = '\0';
    }

    /* IP: doh_ip из конфига, или doh_sni (legacy), или host из URL */
    const char *ip = cfg->doh_ip[0]  ? cfg->doh_ip  :
                     cfg->doh_sni[0] ? cfg->doh_sni : host;
    size_t iplen = strlen(ip);
    if (iplen >= sizeof(conn->server_ip)) iplen = sizeof(conn->server_ip) - 1;
    memcpy(conn->server_ip, ip, iplen);
    conn->server_ip[iplen] = '\0';
    conn->server_port = cfg->doh_port > 0 ? cfg->doh_port : 443;
    {   int _n = snprintf(conn->sni, sizeof(conn->sni), "%s", host);
        if (_n < 0 || (size_t)_n >= sizeof(conn->sni))
            log_msg(LOG_WARN, "async DoH: SNI обрезан: %s", host);
    }

    /* Сохранить запрос */
    memcpy(conn->query, query, query_len);
    conn->query_len = query_len;

    /* Base64url encode запроса */
    char *b64 = malloc(1024);
    if (!b64) return -1;
    {
        static const char tbl[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        size_t pos = 0;
        for (size_t i = 0; i < query_len && pos < 1020; i += 3) {
            uint32_t v = (uint32_t)query[i] << 16;
            if (i + 1 < query_len) v |= (uint32_t)query[i + 1] << 8;
            if (i + 2 < query_len) v |= query[i + 2];
            b64[pos++] = tbl[(v >> 18) & 0x3F];
            b64[pos++] = tbl[(v >> 12) & 0x3F];
            if (i + 1 < query_len) b64[pos++] = tbl[(v >> 6) & 0x3F];
            if (i + 2 < query_len) b64[pos++] = tbl[v & 0x3F];
        }
        b64[pos] = '\0';
    }

    /* Сформировать HTTP GET */
    {   int _n = snprintf(conn->http_req, sizeof(conn->http_req),
            "GET %s?dns=%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Accept: application/dns-message\r\n"
            "Connection: close\r\n"
            "\r\n",
            path, b64, host);
        free(b64);
        if (_n < 0 || (size_t)_n >= sizeof(conn->http_req)) {
            log_msg(LOG_WARN, "async DoH: HTTP request обрезан");
            conn->state = ASYNC_DNS_IDLE;
            return -1;
        }
        conn->http_req_len = (size_t)_n;
    }

    /* send_buf = HTTP запрос (отправляется после TLS handshake) */
    if (conn->http_req_len >= sizeof(conn->send_buf)) {
        conn->state = ASYNC_DNS_IDLE;
        return -1;
    }
    memcpy(conn->send_buf, conn->http_req, conn->http_req_len);
    conn->send_len = conn->http_req_len;
    conn->send_pos = 0;

    return start_connect(conn);
}

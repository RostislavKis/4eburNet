/*
 * Диспетчер relay соединений
 *
 * Принимает перехваченные соединения от tproxy,
 * подключается к upstream серверу, запускает двунаправленный relay.
 *
 * DEC-014: отдельный epoll для relay соединений
 * DEC-015: epoll data.ptr для O(1) поиска relay
 */

#include "proxy/dispatcher.h"
#include "proxy/protocols/vless.h"
#include "crypto/tls.h"
#include "phoenix.h"
#include "resource_manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Максимум событий epoll за один tick */
#define DISPATCHER_MAX_EVENTS   64

/* Таймаут зависших соединений (секунды) */
#define RELAY_TIMEOUT_SEC       60

/* Частота проверки таймаутов (раз в N тиков) */
#define RELAY_TIMEOUT_CHECK     100

/* Размер pipe буфера для splice */
#define SPLICE_PIPE_SIZE        65536

/* ------------------------------------------------------------------ */
/*  Глобальный контекст (handle_conn вызывается без аргумента ds)      */
/* ------------------------------------------------------------------ */

static dispatcher_state_t *g_dispatcher = NULL;
static const PhoenixConfig *g_config    = NULL;

void dispatcher_set_context(dispatcher_state_t *ds,
                            const PhoenixConfig *cfg)
{
    g_dispatcher = ds;
    g_config     = cfg;
}

/* ------------------------------------------------------------------ */
/*  Форматирование адреса для логов                                    */
/* ------------------------------------------------------------------ */

static void fmt_addr(const struct sockaddr_storage *ss,
                     char *buf, size_t buflen)
{
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)ss;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof(ip));
        snprintf(buf, buflen, "%s:%u", ip, ntohs(s4->sin_port));
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ss;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof(ip));
        snprintf(buf, buflen, "[%s]:%u", ip, ntohs(s6->sin6_port));
    } else {
        snprintf(buf, buflen, "unknown");
    }
}

/* ------------------------------------------------------------------ */
/*  Протокол "direct" — relay без шифрования (для тестов)               */
/* ------------------------------------------------------------------ */

static int protocol_direct_connect(relay_conn_t *relay,
                                   const struct sockaddr_storage *dst,
                                   const ServerConfig *server)
{
    (void)relay;
    (void)dst;
    (void)server;
    return 0;
}

static const proxy_protocol_t proto_direct = {
    .name    = "direct",
    .connect = protocol_direct_connect,
};

/* ------------------------------------------------------------------ */
/*  Протокол VLESS — TLS + VLESS header                                */
/* ------------------------------------------------------------------ */

static int vless_protocol_connect(relay_conn_t *relay,
                                  const struct sockaddr_storage *dst,
                                  const ServerConfig *server)
{
    tls_config_t cfg = {
        .sni         = server->address,
        .fingerprint = TLS_FP_CHROME120,
        .verify_cert = false,
    };

    if (tls_connect(&relay->tls, relay->upstream_fd, &cfg) < 0)
        return -1;

    if (vless_handshake(&relay->tls, dst, server->uuid) < 0) {
        tls_close(&relay->tls);
        return -1;
    }

    relay->use_tls = true;
    return 0;
}

static const proxy_protocol_t proto_vless = {
    .name    = "vless",
    .connect = vless_protocol_connect,
};

/* ------------------------------------------------------------------ */
/*  Выбор протокола по имени из конфига                                 */
/* ------------------------------------------------------------------ */

static const proxy_protocol_t *protocol_find(const char *name)
{
    if (strcmp(name, "direct") == 0)
        return &proto_direct;
    if (strcmp(name, "vless") == 0)
        return &proto_vless;

    /* Неизвестный протокол — используем direct как fallback */
    log_msg(LOG_WARN, "relay: протокол '%s' не поддержан, используется direct",
            name);
    return &proto_direct;
}

/* ------------------------------------------------------------------ */
/*  Проверка поддержки splice()                                        */
/* ------------------------------------------------------------------ */

static bool check_splice_support(void)
{
    int p[2];
    if (pipe(p) < 0)
        return false;

    /* Пробуем splice из /dev/null в pipe */
    int devnull = open("/dev/null", O_RDONLY);
    if (devnull < 0) {
        close(p[0]); close(p[1]);
        return false;
    }

    ssize_t rc = splice(devnull, NULL, p[1], NULL, 1,
                        SPLICE_F_NONBLOCK);
    close(devnull);
    close(p[0]);
    close(p[1]);

    /* splice возвращает 0 (нет данных) или -1 с EAGAIN — оба значат поддержку */
    return (rc >= 0 || errno == EAGAIN);
}

/* ------------------------------------------------------------------ */
/*  relay_alloc / relay_free                                           */
/* ------------------------------------------------------------------ */

static relay_conn_t *relay_alloc(dispatcher_state_t *ds)
{
    for (int i = 0; i < ds->conns_max; i++) {
        if (ds->conns[i].state == RELAY_DONE) {
            relay_conn_t *r = &ds->conns[i];
            memset(r, 0, sizeof(*r));
            r->client_fd   = -1;
            r->upstream_fd = -1;
            r->state       = RELAY_CONNECTING;
            /* Настроить epoll теги */
            r->ep_client.relay     = r;
            r->ep_client.is_client = true;
            r->ep_upstream.relay     = r;
            r->ep_upstream.is_client = false;
            ds->conns_count++;
            return r;
        }
    }
    log_msg(LOG_WARN, "relay: все слоты заняты (%d/%d)",
            ds->conns_count, ds->conns_max);
    return NULL;
}

static void relay_free(dispatcher_state_t *ds, relay_conn_t *r)
{
    if (r->use_tls) {
        tls_close(&r->tls);
        r->use_tls = false;
    }

    if (r->client_fd >= 0) {
        epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->client_fd, NULL);
        close(r->client_fd);
    }
    if (r->upstream_fd >= 0) {
        epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->upstream_fd, NULL);
        close(r->upstream_fd);
    }

    if (r->state != RELAY_DONE) {
        log_msg(LOG_DEBUG, "relay: закрыт (in:%lu out:%lu)",
                (unsigned long)r->bytes_in,
                (unsigned long)r->bytes_out);
        ds->total_closed++;
        ds->conns_count--;
    }

    r->client_fd   = -1;
    r->upstream_fd = -1;
    r->state       = RELAY_DONE;
}

/* ------------------------------------------------------------------ */
/*  upstream_connect — неблокирующее подключение к upstream              */
/* ------------------------------------------------------------------ */

static int upstream_connect(dispatcher_state_t *ds,
                            relay_conn_t *r,
                            const ServerConfig *server)
{
    /* Парсим адрес сервера через inet_pton (без getaddrinfo) */
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));

    struct sockaddr_in *a4 = (struct sockaddr_in *)&addr;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&addr;

    if (inet_pton(AF_INET, server->address, &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        a4->sin_port   = htons(server->port);
    } else if (inet_pton(AF_INET6, server->address, &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        a6->sin6_port   = htons(server->port);
    } else {
        log_msg(LOG_ERROR, "relay: невалидный адрес upstream '%s'",
                server->address);
        return -1;
    }

    int family = addr.ss_family;
    socklen_t addrlen = (family == AF_INET)
        ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_msg(LOG_ERROR, "relay: socket(upstream): %s", strerror(errno));
        return -1;
    }

    int rc = connect(fd, (struct sockaddr *)&addr, addrlen);
    if (rc < 0 && errno != EINPROGRESS) {
        log_msg(LOG_WARN, "relay: connect(%s:%u): %s",
                server->address, server->port, strerror(errno));
        close(fd);
        return -1;
    }

    r->upstream_fd = fd;

    /* Добавить upstream_fd в epoll: ждём завершения connect (EPOLLOUT) */
    struct epoll_event ev = {
        .events  = EPOLLOUT | EPOLLET,
        .data.ptr = &r->ep_upstream,
    };
    if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        log_msg(LOG_ERROR, "relay: epoll_ctl(upstream): %s", strerror(errno));
        close(fd);
        r->upstream_fd = -1;
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  relay_transfer — передать данные между двумя fd                    */
/* ------------------------------------------------------------------ */

static ssize_t relay_transfer(dispatcher_state_t *ds,
                              relay_conn_t *r, bool from_client)
{
    ssize_t n;

    if (from_client) {
        /*
         * Клиент → upstream
         * Читаем из client_fd (всегда plain TCP)
         */
        if (!r->use_tls && ds->has_splice) {
            /* splice: client → pipe → upstream (zero-copy) */
            n = splice(r->client_fd, NULL, ds->splice_pipe[1], NULL,
                       SPLICE_PIPE_SIZE, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
            if (n <= 0)
                return n;
            ssize_t written = 0;
            while (written < n) {
                ssize_t w = splice(ds->splice_pipe[0], NULL,
                                   r->upstream_fd, NULL,
                                   n - written,
                                   SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
                if (w < 0) {
                    if (errno == EAGAIN) break;
                    return -1;
                }
                written += w;
            }
            return written;
        }

        /* read/write (или TLS upstream) */
        n = read(r->client_fd, ds->relay_buf, ds->relay_buf_size);
        if (n <= 0)
            return n;

        if (r->use_tls)
            return tls_send(&r->tls, ds->relay_buf, n);

        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(r->upstream_fd,
                              ds->relay_buf + written, n - written);
            if (w < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                return -1;
            }
            written += w;
        }
        return written;

    } else {
        /*
         * Upstream → клиент
         * Пишем в client_fd (всегда plain TCP)
         */
        if (r->use_tls)
            n = tls_recv(&r->tls, ds->relay_buf, ds->relay_buf_size);
        else
            n = read(r->upstream_fd, ds->relay_buf, ds->relay_buf_size);

        if (n <= 0)
            return n;

        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(r->client_fd,
                              ds->relay_buf + written, n - written);
            if (w < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                return -1;
            }
            written += w;
        }
        return written;
    }
}

/* ------------------------------------------------------------------ */
/*  dispatcher_init                                                    */
/* ------------------------------------------------------------------ */

int dispatcher_init(dispatcher_state_t *ds, DeviceProfile profile)
{
    memset(ds, 0, sizeof(*ds));
    ds->epoll_fd       = -1;
    ds->splice_pipe[0] = -1;
    ds->splice_pipe[1] = -1;

    /* Лимит соединений по профилю */
    switch (profile) {
    case DEVICE_MICRO:  ds->conns_max = MICRO_MAX_CONNECTIONS;  break;
    case DEVICE_NORMAL: ds->conns_max = NORMAL_MAX_CONNECTIONS; break;
    case DEVICE_FULL:   ds->conns_max = FULL_MAX_CONNECTIONS;   break;
    default:            ds->conns_max = NORMAL_MAX_CONNECTIONS; break;
    }

    ds->conns = calloc(ds->conns_max, sizeof(relay_conn_t));
    if (!ds->conns) {
        log_msg(LOG_ERROR, "relay: не удалось выделить %d слотов",
                ds->conns_max);
        return -1;
    }

    /* Размер relay буфера по профилю */
    ds->relay_buf_size = rm_buffer_size(profile);
    ds->relay_buf = malloc(ds->relay_buf_size);
    if (!ds->relay_buf) {
        log_msg(LOG_ERROR, "relay: не удалось выделить буфер %zu байт",
                ds->relay_buf_size);
        free(ds->conns);
        ds->conns = NULL;
        return -1;
    }

    /* epoll */
    ds->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ds->epoll_fd < 0) {
        log_msg(LOG_ERROR, "relay: epoll_create1: %s", strerror(errno));
        free(ds->relay_buf);
        free(ds->conns);
        ds->conns = NULL;
        return -1;
    }

    /* Проверка splice */
    ds->has_splice = check_splice_support();
    if (ds->has_splice) {
        if (pipe(ds->splice_pipe) < 0) {
            ds->has_splice = false;
            log_msg(LOG_WARN, "relay: pipe для splice не создан: %s",
                    strerror(errno));
        } else {
            /* Неблокирующий pipe */
            fcntl(ds->splice_pipe[0], F_SETFL, O_NONBLOCK);
            fcntl(ds->splice_pipe[1], F_SETFL, O_NONBLOCK);
        }
    }

    log_msg(LOG_INFO, "Диспетчер запущен (макс. %d соединений, splice: %s, "
            "буфер: %zu)",
            ds->conns_max, ds->has_splice ? "да" : "нет",
            ds->relay_buf_size);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  dispatcher_handle_conn — приём TCP от tproxy                       */
/* ------------------------------------------------------------------ */

void dispatcher_handle_conn(tproxy_conn_t *conn)
{
    if (!g_dispatcher || !g_config) {
        log_msg(LOG_ERROR, "relay: контекст не инициализирован");
        if (conn->fd >= 0) close(conn->fd);
        return;
    }

    dispatcher_state_t *ds = g_dispatcher;
    const PhoenixConfig *cfg = g_config;

    /* Выбрать первый enabled сервер */
    const ServerConfig *server = NULL;
    for (int i = 0; i < cfg->server_count; i++) {
        if (cfg->servers[i].enabled) {
            server = &cfg->servers[i];
            break;
        }
    }
    if (!server) {
        log_msg(LOG_WARN, "relay: нет доступных серверов");
        close(conn->fd);
        return;
    }

    /* Выделить слот */
    relay_conn_t *r = relay_alloc(ds);
    if (!r) {
        close(conn->fd);
        return;
    }

    r->client_fd  = conn->fd;
    r->dst        = conn->dst;
    r->created_at = time(NULL);

    /* Неблокирующее подключение к upstream */
    if (upstream_connect(ds, r, server) < 0) {
        relay_free(ds, r);
        return;
    }

    /* Добавить client_fd в epoll (EPOLLIN — данные от клиента) */
    struct epoll_event ev = {
        .events   = EPOLLIN | EPOLLET,
        .data.ptr = &r->ep_client,
    };
    if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD, r->client_fd, &ev) < 0) {
        log_msg(LOG_ERROR, "relay: epoll_ctl(client): %s", strerror(errno));
        relay_free(ds, r);
        return;
    }

    ds->total_accepted++;

    char dst_str[64];
    fmt_addr(&r->dst, dst_str, sizeof(dst_str));
    log_msg(LOG_DEBUG, "relay: %s → %s:%u (upstream %s)",
            dst_str, server->address, server->port, server->protocol);
}

/* ------------------------------------------------------------------ */
/*  dispatcher_handle_udp — UDP пока только логируем                   */
/* ------------------------------------------------------------------ */

void dispatcher_handle_udp(tproxy_conn_t *conn,
                           const uint8_t *data, size_t len)
{
    char src_str[64], dst_str[64];
    fmt_addr(&conn->src, src_str, sizeof(src_str));
    fmt_addr(&conn->dst, dst_str, sizeof(dst_str));

    log_msg(LOG_DEBUG, "relay UDP: %s → %s (%zu байт)", src_str, dst_str, len);

    (void)data;
}

/* ------------------------------------------------------------------ */
/*  dispatcher_tick — обработка событий relay                          */
/* ------------------------------------------------------------------ */

void dispatcher_tick(dispatcher_state_t *ds)
{
    if (ds->epoll_fd < 0)
        return;

    struct epoll_event events[DISPATCHER_MAX_EVENTS];
    int n = epoll_wait(ds->epoll_fd, events, DISPATCHER_MAX_EVENTS, 0);

    for (int i = 0; i < n; i++) {
        relay_ep_t *ep = events[i].data.ptr;
        if (!ep || !ep->relay)
            continue;

        relay_conn_t *r = ep->relay;
        uint32_t ev = events[i].events;

        /* Ошибка или разрыв */
        if (ev & (EPOLLERR | EPOLLHUP)) {
            relay_free(ds, r);
            continue;
        }

        switch (r->state) {
        case RELAY_CONNECTING:
            /* Ждём завершения connect к upstream (EPOLLOUT) */
            if (!ep->is_client && (ev & EPOLLOUT)) {
                int err = 0;
                socklen_t errlen = sizeof(err);
                getsockopt(r->upstream_fd, SOL_SOCKET, SO_ERROR,
                           &err, &errlen);

                if (err != 0) {
                    log_msg(LOG_WARN,
                        "relay: connect к upstream провалился: %s",
                        strerror(err));
                    relay_free(ds, r);
                    continue;
                }

                /* connect успешен — переключить upstream на EPOLLIN */
                struct epoll_event mod = {
                    .events   = EPOLLIN | EPOLLET,
                    .data.ptr = &r->ep_upstream,
                };
                epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD,
                          r->upstream_fd, &mod);

                /* Протокольное рукопожатие */
                const ServerConfig *server = NULL;
                if (g_config) {
                    for (int j = 0; j < g_config->server_count; j++) {
                        if (g_config->servers[j].enabled) {
                            server = &g_config->servers[j];
                            break;
                        }
                    }
                }

                if (server) {
                    const proxy_protocol_t *proto =
                        protocol_find(server->protocol);
                    if (proto->connect(r, &r->dst, server) < 0) {
                        log_msg(LOG_WARN,
                            "relay: протокольное рукопожатие провалилось");
                        relay_free(ds, r);
                        continue;
                    }
                }

                r->state = RELAY_ACTIVE;
                log_msg(LOG_DEBUG, "relay: соединение к upstream установлено");
            }
            break;

        case RELAY_ACTIVE:
            if (ep->is_client && (ev & EPOLLIN)) {
                /* Данные от клиента → upstream */
                for (;;) {
                    ssize_t transferred = relay_transfer(
                        ds, r, true);
                    if (transferred > 0) {
                        r->bytes_in += transferred;
                        continue;
                    }
                    if (transferred == 0) {
                        /* EOF от клиента */
                        r->state = RELAY_CLOSING;
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        r->state = RELAY_CLOSING;
                    }
                    break;
                }
            }

            if (!ep->is_client && (ev & EPOLLIN)) {
                /* Данные от upstream → клиент */
                for (;;) {
                    ssize_t transferred = relay_transfer(
                        ds, r, false);
                    if (transferred > 0) {
                        r->bytes_out += transferred;
                        continue;
                    }
                    if (transferred == 0) {
                        r->state = RELAY_CLOSING;
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        r->state = RELAY_CLOSING;
                    }
                    break;
                }
            }

            if (r->state == RELAY_CLOSING)
                relay_free(ds, r);
            break;

        case RELAY_CLOSING:
            relay_free(ds, r);
            break;

        case RELAY_DONE:
            break;
        }
    }

    ds->tick_count++;

    /* Периодическая проверка таймаутов */
    if (ds->tick_count % RELAY_TIMEOUT_CHECK == 0) {
        time_t now = time(NULL);
        for (int i = 0; i < ds->conns_max; i++) {
            relay_conn_t *r = &ds->conns[i];
            if (r->state != RELAY_DONE &&
                now - r->created_at > RELAY_TIMEOUT_SEC) {
                log_msg(LOG_DEBUG, "relay: таймаут соединения");
                relay_free(ds, r);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/*  dispatcher_cleanup                                                 */
/* ------------------------------------------------------------------ */

void dispatcher_cleanup(dispatcher_state_t *ds)
{
    /* Закрыть все активные relay */
    if (ds->conns) {
        for (int i = 0; i < ds->conns_max; i++) {
            if (ds->conns[i].state != RELAY_DONE)
                relay_free(ds, &ds->conns[i]);
        }
        free(ds->conns);
        ds->conns = NULL;
    }

    if (ds->relay_buf) {
        free(ds->relay_buf);
        ds->relay_buf = NULL;
    }

    if (ds->splice_pipe[0] >= 0) { close(ds->splice_pipe[0]); }
    if (ds->splice_pipe[1] >= 0) { close(ds->splice_pipe[1]); }
    ds->splice_pipe[0] = -1;
    ds->splice_pipe[1] = -1;

    if (ds->epoll_fd >= 0) { close(ds->epoll_fd); ds->epoll_fd = -1; }

    log_msg(LOG_INFO, "Диспетчер остановлен (обработано: %lu, закрыто: %lu)",
            (unsigned long)ds->total_accepted,
            (unsigned long)ds->total_closed);

    g_dispatcher = NULL;
    g_config     = NULL;
}

/* ------------------------------------------------------------------ */
/*  dispatcher_stats                                                   */
/* ------------------------------------------------------------------ */

void dispatcher_stats(const dispatcher_state_t *ds,
                      uint64_t *accepted, uint64_t *closed)
{
    if (accepted) *accepted = ds->total_accepted;
    if (closed)   *closed   = ds->total_closed;
}

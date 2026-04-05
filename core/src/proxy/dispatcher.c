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
#include "proxy/protocols/vless_xhttp.h"
#include "proxy/protocols/trojan.h"
#include "proxy/protocols/shadowsocks.h"
#include "proxy/protocols/awg.h"
#include "crypto/tls.h"
#include "net_utils.h"
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

/* Таймаут бездействия (секунды) */
#define RELAY_TIMEOUT_SEC           60
#define RELAY_HALF_CLOSE_TIMEOUT    15  /* half-close: вдвое меньше (M-09) */

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

/* fmt_addr → net_format_addr из net_utils.c (M-01) */

/* ------------------------------------------------------------------ */
/*  Протокол "direct" — relay без шифрования (для тестов)               */
/* ------------------------------------------------------------------ */

static int protocol_direct_start(relay_conn_t *relay,
                                 const struct sockaddr_storage *dst,
                                 const ServerConfig *server)
{
    (void)dst;
    (void)server;
    /* direct: мгновенно активен, без TLS/handshake */
    relay->state = RELAY_ACTIVE;
    return 0;
}

static const proxy_protocol_t proto_direct = {
    .name  = "direct",
    .start = protocol_direct_start,
};

/* ------------------------------------------------------------------ */
/*  Протокол VLESS — неблокирующий TLS + VLESS header (C-03/C-04)      */
/* ------------------------------------------------------------------ */

static int vless_protocol_start(relay_conn_t *relay,
                                const struct sockaddr_storage *dst,
                                const ServerConfig *server)
{
    (void)dst;
    tls_config_t cfg = {0};
    snprintf(cfg.sni, sizeof(cfg.sni), "%s", server->address);
    cfg.fingerprint = TLS_FP_CHROME120;
    cfg.verify_cert = false;

    if (tls_connect_start(&relay->tls, relay->upstream_fd, &cfg) < 0)
        return -1;

    relay->use_tls = true;
    relay->state = RELAY_TLS_SHAKE;
    return 0;
}

static const proxy_protocol_t proto_vless = {
    .name  = "vless",
    .start = vless_protocol_start,
};

/* ------------------------------------------------------------------ */
/*  Протокол VLESS + XHTTP транспорт                                   */
/* ------------------------------------------------------------------ */

static int xhttp_protocol_start(relay_conn_t *relay,
                                const struct sockaddr_storage *dst,
                                const ServerConfig *server)
{
    (void)dst;

    /* upstream_fd уже подключён (upload). Создаём download fd. */
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
        return -1;
    }

    int family = addr.ss_family;
    socklen_t addrlen = (family == AF_INET)
        ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    int dl_fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (dl_fd < 0)
        return -1;

    if (connect(dl_fd, (struct sockaddr *)&addr, addrlen) < 0 &&
        errno != EINPROGRESS) {
        close(dl_fd);
        return -1;
    }

    relay->download_fd = dl_fd;

    /* epoll теги для download */
    relay->ep_download.relay     = relay;
    relay->ep_download.is_client = false;

    /* Выделяем XHTTP состояние */
    relay->xhttp = calloc(1, sizeof(xhttp_state_t));
    if (!relay->xhttp) {
        close(dl_fd);
        relay->download_fd = -1;
        return -1;
    }

    tls_config_t cfg = {0};
    const char *sni_host = server->xhttp_host[0]
        ? server->xhttp_host : server->address;
    snprintf(cfg.sni, sizeof(cfg.sni), "%s", sni_host);
    cfg.fingerprint = TLS_FP_CHROME120;
    cfg.verify_cert = false;

    const char *path = server->xhttp_path[0]
        ? server->xhttp_path : "/";

    if (xhttp_start(relay->xhttp, relay->upstream_fd, dl_fd,
                     &cfg, path, sni_host) < 0) {
        free(relay->xhttp);
        relay->xhttp = NULL;
        close(dl_fd);
        relay->download_fd = -1;
        return -1;
    }

    relay->use_tls = true;

    /* download_fd ждёт connect → EPOLLOUT */
    relay->state = RELAY_XHTTP_DN_CONNECT;

    return 0;
}

static const proxy_protocol_t proto_xhttp = {
    .name  = "vless+xhttp",
    .start = xhttp_protocol_start,
};

/* ------------------------------------------------------------------ */
/*  Протокол Trojan — TLS + SHA224(password) header                    */
/* ------------------------------------------------------------------ */

static int trojan_protocol_start(relay_conn_t *relay,
                                 const struct sockaddr_storage *dst,
                                 const ServerConfig *server)
{
    (void)dst;
    tls_config_t cfg = {0};
    snprintf(cfg.sni, sizeof(cfg.sni), "%s", server->address);
    cfg.fingerprint = TLS_FP_CHROME120;
    cfg.verify_cert = false;

    if (tls_connect_start(&relay->tls, relay->upstream_fd, &cfg) < 0)
        return -1;

    relay->use_tls = true;
    relay->state = RELAY_TLS_SHAKE;
    return 0;
}

static const proxy_protocol_t proto_trojan = {
    .name  = "trojan",
    .start = trojan_protocol_start,
};

/* ------------------------------------------------------------------ */
/*  Протокол Shadowsocks 2022 — AEAD без TLS                          */
/* ------------------------------------------------------------------ */

static int ss_protocol_start(relay_conn_t *relay,
                             const struct sockaddr_storage *dst,
                             const ServerConfig *server)
{
    relay->ss = malloc(sizeof(ss_state_t));
    if (!relay->ss)
        return -1;

    if (ss_handshake_start(relay->ss, relay->upstream_fd,
                            dst, server->password) < 0) {
        free(relay->ss);
        relay->ss = NULL;
        return -1;
    }

    relay->state = RELAY_ACTIVE;
    return 0;
}

static const proxy_protocol_t proto_ss = {
    .name  = "shadowsocks",
    .start = ss_protocol_start,
};

/* ------------------------------------------------------------------ */
/*  Протокол AWG — UDP, без TCP connect                                */
/* ------------------------------------------------------------------ */

static int awg_protocol_start(relay_conn_t *relay,
                              const struct sockaddr_storage *dst,
                              const ServerConfig *server)
{
    (void)dst;
    relay->awg = malloc(sizeof(awg_state_t));
    if (!relay->awg) return -1;

    if (awg_init(relay->awg, server) < 0) {
        free(relay->awg); relay->awg = NULL;
        return -1;
    }

    if (awg_handshake_start(relay->awg, server->address, server->port) < 0) {
        awg_close(relay->awg);
        free(relay->awg); relay->awg = NULL;
        return -1;
    }

    /* AWG UDP fd в dispatcher epoll */
    if (g_dispatcher) {
        struct epoll_event ev = {
            .events   = EPOLLIN | EPOLLET,
            .data.ptr = &relay->ep_upstream,
        };
        epoll_ctl(g_dispatcher->epoll_fd, EPOLL_CTL_ADD,
                  relay->awg->udp_fd, &ev);
    }

    relay->upstream_fd = relay->awg->udp_fd;
    relay->state = RELAY_AWG_HANDSHAKE;
    return 0;
}

static const proxy_protocol_t proto_awg = {
    .name  = "awg",
    .start = awg_protocol_start,
};

/* ------------------------------------------------------------------ */
/*  Выбор протокола по имени из конфига                                 */
/* ------------------------------------------------------------------ */

static const proxy_protocol_t *protocol_find_for_server(
    const ServerConfig *server)
{
    if (strcmp(server->protocol, "direct") == 0)
        return &proto_direct;

    if (strcmp(server->protocol, "vless") == 0) {
        if (server->transport[0] &&
            strcmp(server->transport, "xhttp") == 0)
            return &proto_xhttp;
        return &proto_vless;
    }
    if (strcmp(server->protocol, "trojan") == 0)
        return &proto_trojan;
    if (strcmp(server->protocol, "shadowsocks") == 0 ||
        strcmp(server->protocol, "ss") == 0)
        return &proto_ss;
    if (strcmp(server->protocol, "awg") == 0)
        return &proto_awg;

    log_msg(LOG_WARN, "relay: протокол '%s' не поддержан, используется direct",
            server->protocol);
    return &proto_direct;
}

/* check_splice_support удалён — аудит C-05: один pipe на все relay
   давал data corruption при partial write */

/* ------------------------------------------------------------------ */
/*  relay_alloc / relay_free                                           */
/* ------------------------------------------------------------------ */

static relay_conn_t *relay_alloc(dispatcher_state_t *ds)
{
    /* Clock-hand поиск: O(1) амортизированный (H-05) */
    int start = ds->next_free;
    for (int i = 0; i < ds->conns_max; i++) {
        int idx = (start + i) % ds->conns_max;
        if (ds->conns[idx].state == RELAY_DONE) {
            ds->next_free = (idx + 1) % ds->conns_max;
            relay_conn_t *r = &ds->conns[idx];
            memset(r, 0, sizeof(*r));
            r->client_fd   = -1;
            r->upstream_fd = -1;
            r->download_fd = -1;
            r->xhttp       = NULL;
            r->ss          = NULL;
            r->awg         = NULL;
            r->state       = RELAY_CONNECTING;
            r->last_active = time(NULL);
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
    if (r->download_fd >= 0) {
        epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->download_fd, NULL);
        close(r->download_fd);
    }
    if (r->awg) {
        if (r->awg->udp_fd >= 0)
            epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL,
                      r->awg->udp_fd, NULL);
        awg_close(r->awg);
        free(r->awg);
        r->awg = NULL;
    }
    if (r->xhttp) {
        xhttp_close(r->xhttp);
        free(r->xhttp);
        r->xhttp = NULL;
    }
    if (r->ss) {
        free(r->ss);
        r->ss = NULL;
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
    r->download_fd = -1;
    r->state       = RELAY_DONE;
}

/* ------------------------------------------------------------------ */
/*  relay_do_half_close — TCP half-close (DEC-016)                     */
/* ------------------------------------------------------------------ */

static void relay_do_half_close(relay_conn_t *r, bool client_side)
{
    if (client_side) {
        r->client_eof = true;
        /* TLS: не вызываем shutdown — просто не пишем больше */
        if (!r->use_tls && r->upstream_fd >= 0)
            shutdown(r->upstream_fd, SHUT_WR);
    } else {
        r->upstream_eof = true;
        /* client_fd всегда plain TCP */
        if (r->client_fd >= 0)
            shutdown(r->client_fd, SHUT_WR);
    }

    if (r->client_eof && r->upstream_eof) {
        r->state = RELAY_CLOSING;
    } else {
        r->state = RELAY_HALF_CLOSE;
        log_msg(LOG_DEBUG, "relay: half-close (%s)",
                client_side ? "client EOF" : "upstream EOF");
    }
}

/* ------------------------------------------------------------------ */
/*  Health-check: выбор и оценка серверов                              */
/* ------------------------------------------------------------------ */

int dispatcher_select_server(dispatcher_state_t *ds,
                             const PhoenixConfig *cfg)
{
    /* Lazy init — заполнить health[] при первом вызове */
    if (ds->health_count == 0 && cfg->server_count > 0) {
        int count = cfg->server_count;
        if (count > 8) count = 8;
        for (int i = 0; i < count; i++) {
            ds->health[i].server_idx = i;
            ds->health[i].available  = true;
            ds->health[i].fail_count = 0;
        }
        ds->health_count = count;
    }

    /* Первый enabled + available + fail_count < 3 */
    int fallback = -1;
    for (int i = 0; i < ds->health_count; i++) {
        int idx = ds->health[i].server_idx;
        if (idx >= cfg->server_count)
            continue;
        if (!cfg->servers[idx].enabled)
            continue;
        if (fallback < 0)
            fallback = idx;
        if (ds->health[i].available && ds->health[i].fail_count < 3)
            return idx;
    }

    /* Все недоступны → fallback на первый enabled */
    if (fallback >= 0) {
        log_msg(LOG_DEBUG, "relay: все серверы недоступны, fallback на %d",
                fallback);
    }
    return fallback;
}

void dispatcher_server_result(dispatcher_state_t *ds,
                              int server_idx, bool success)
{
    for (int i = 0; i < ds->health_count; i++) {
        if (ds->health[i].server_idx != server_idx)
            continue;

        if (success) {
            ds->health[i].fail_count = 0;
            ds->health[i].available  = true;
            ds->health[i].last_success = time(NULL);
        } else {
            ds->health[i].fail_count++;
            ds->health[i].last_check = time(NULL);
            if (ds->health[i].fail_count >= 3) {
                ds->health[i].available = false;
                log_msg(LOG_WARN,
                    "Сервер %d недоступен (%u ошибок подряд)",
                    server_idx, ds->health[i].fail_count);
            }
        }
        return;
    }
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
    /* Направление уже закрыто half-close → пропустить */
    if (from_client && r->client_eof)
        return 0;
    if (!from_client && r->upstream_eof)
        return 0;

    ssize_t n;

    /* AWG: UDP шифрование */
    if (r->awg && r->awg->handshake_done) {
        if (from_client) {
            n = read(r->client_fd, ds->relay_buf, ds->relay_buf_size);
            if (n <= 0) return n;
            return awg_send(r->awg, ds->relay_buf, n);
        } else {
            /* AWG upstream данные через awg_process_incoming в tick */
            return 0;
        }
    }

    /* SS 2022: AEAD шифрование без TLS */
    if (r->ss) {
        if (from_client) {
            n = read(r->client_fd, ds->relay_buf, ds->relay_buf_size);
            if (n <= 0) return n;
            return ss_send(r->ss, r->upstream_fd, ds->relay_buf, n);
        } else {
            n = ss_recv(r->ss, r->upstream_fd,
                        ds->relay_buf, ds->relay_buf_size);
            if (n <= 0) return n;
            ssize_t w = write(r->client_fd, ds->relay_buf, n);
            return (w > 0) ? n : w;
        }
    }

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

    /*
     * splice отключён — один pipe на всех даёт data corruption
     * при partial write (аудит C-05). TLS relay (основной путь)
     * использует tls_send/recv через userspace буфер.
     */
    ds->has_splice = false;
    ds->splice_pipe[0] = -1;
    ds->splice_pipe[1] = -1;
    log_msg(LOG_DEBUG,
        "splice отключён (data corruption fix, аудит C-05)");

    ds->health_reset_at = time(NULL) + 30;  /* первый health reset через 30 сек */

    log_msg(LOG_INFO, "Диспетчер запущен (макс. %d соединений, буфер: %zu)",
            ds->conns_max, ds->relay_buf_size);
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

    /* Выбрать сервер через health-check */
    int idx = dispatcher_select_server(ds, cfg);
    if (idx < 0) {
        log_msg(LOG_WARN, "relay: нет доступных серверов");
        close(conn->fd);
        return;
    }
    const ServerConfig *server = &cfg->servers[idx];

    /* Выделить слот */
    relay_conn_t *r = relay_alloc(ds);
    if (!r) {
        close(conn->fd);
        return;
    }

    r->client_fd  = conn->fd;
    r->dst        = conn->dst;
    r->created_at = time(NULL);
    r->server_idx = idx;

    /* AWG: UDP, минует TCP connect */
    if (strcmp(server->protocol, "awg") == 0) {
        if (awg_protocol_start(r, &conn->dst, server) < 0) {
            dispatcher_server_result(ds, idx, false);
            relay_free(ds, r);
        } else {
            ds->total_accepted++;
            char dst_str[64];
            net_format_addr(&r->dst, dst_str, sizeof(dst_str));
            log_msg(LOG_DEBUG, "relay: %s → %s:%u (AWG UDP)",
                    dst_str, server->address, server->port);
        }
        return;
    }

    /* Неблокирующее подключение к upstream (TCP) */
    if (upstream_connect(ds, r, server) < 0) {
        dispatcher_server_result(ds, idx, false);
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
    net_format_addr(&r->dst, dst_str, sizeof(dst_str));
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
    net_format_addr(&conn->src, src_str, sizeof(src_str));
    net_format_addr(&conn->dst, dst_str, sizeof(dst_str));

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
                    dispatcher_server_result(ds, r->server_idx, false);
                    relay_free(ds, r);
                    continue;
                }

                /* connect успешен — переключить upstream на EPOLLIN|EPOLLOUT */
                struct epoll_event mod = {
                    .events   = EPOLLIN | EPOLLOUT | EPOLLET,
                    .data.ptr = &r->ep_upstream,
                };
                epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD,
                          r->upstream_fd, &mod);

                /* Запустить протокольное рукопожатие (неблокирующее) */
                const ServerConfig *server = NULL;
                if (g_config && r->server_idx < g_config->server_count)
                    server = &g_config->servers[r->server_idx];

                if (server) {
                    const proxy_protocol_t *proto =
                        protocol_find_for_server(server);
                    if (proto->start(r, &r->dst, server) < 0) {
                        log_msg(LOG_WARN,
                            "relay: инициация протокола провалилась");
                        dispatcher_server_result(ds, r->server_idx, false);
                        relay_free(ds, r);
                        continue;
                    }
                } else {
                    r->state = RELAY_ACTIVE;
                }

                /* state установлен внутри proto->start() */
                /* XHTTP: download_fd нужно добавить в epoll */
                if (r->download_fd >= 0) {
                    struct epoll_event dev = {
                        .events   = EPOLLOUT | EPOLLET,
                        .data.ptr = &r->ep_download,
                    };
                    epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD,
                              r->download_fd, &dev);
                }
                log_msg(LOG_DEBUG, "relay: TCP connect OK, протокол: %s%s",
                        server ? server->protocol : "direct",
                        r->xhttp ? "+xhttp" : "");
            }
            break;

        case RELAY_TLS_SHAKE:
            /* TLS handshake — один шаг за tick (C-03) */
            if (ep->is_client) break;
            if (!(ev & (EPOLLIN | EPOLLOUT))) break;
            {
                tls_step_result_t tls_rc = tls_connect_step(&r->tls);
                if (tls_rc == TLS_OK) {
                    const ServerConfig *server = NULL;
                    if (g_config && r->server_idx < g_config->server_count)
                        server = &g_config->servers[r->server_idx];

                    if (!server) {
                        relay_free(ds, r);
                        break;
                    }

                    if (strcmp(server->protocol, "trojan") == 0) {
                        /* Trojan: header → сразу ACTIVE (нет response) */
                        if (trojan_handshake_start(&r->tls, &r->dst,
                                                    server->password) < 0) {
                            dispatcher_server_result(ds, r->server_idx, false);
                            relay_free(ds, r);
                            break;
                        }
                        dispatcher_server_result(ds, r->server_idx, true);
                        r->state = RELAY_ACTIVE;
                        log_msg(LOG_DEBUG, "relay: Trojan активен");
                    } else {
                        /* VLESS: header → ждём response */
                        if (vless_handshake_start(&r->tls, &r->dst,
                                                   server->uuid) < 0) {
                            dispatcher_server_result(ds, r->server_idx, false);
                            relay_free(ds, r);
                            break;
                        }
                        r->state = RELAY_VLESS_SHAKE;
                        r->vless_resp_len = 0;
                    }

                    /* upstream: ждём EPOLLIN */
                    struct epoll_event mod = {
                        .events   = EPOLLIN | EPOLLET,
                        .data.ptr = &r->ep_upstream,
                    };
                    epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD,
                              r->upstream_fd, &mod);
                } else if (tls_rc == TLS_ERR) {
                    dispatcher_server_result(ds, r->server_idx, false);
                    relay_free(ds, r);
                }
                /* TLS_WANT_IO → ждём следующего epoll события */
            }
            break;

        case RELAY_VLESS_SHAKE:
            /* VLESS response — один шаг за tick (C-04) */
            if (ep->is_client) break;
            if (!(ev & EPOLLIN)) break;
            {
                int vrc = vless_read_response_step(&r->tls,
                    r->vless_resp_buf, &r->vless_resp_len);
                if (vrc == 0) {
                    /* VLESS готов → relay активен */
                    dispatcher_server_result(ds, r->server_idx, true);
                    r->state = RELAY_ACTIVE;
                    log_msg(LOG_DEBUG,
                        "relay: VLESS установлен, relay активен");
                } else if (vrc < 0) {
                    dispatcher_server_result(ds, r->server_idx, false);
                    relay_free(ds, r);
                }
                /* vrc == 1 → ждём данных */
            }
            break;

        case RELAY_HALF_CLOSE:
        case RELAY_ACTIVE:
            if (ep->is_client && (ev & EPOLLIN)) {
                /* Данные от клиента → upstream */
                for (;;) {
                    ssize_t transferred = relay_transfer(
                        ds, r, true);
                    if (transferred > 0) {
                        r->bytes_in += transferred;
                        r->last_active = time(NULL);
                        continue;
                    }
                    if (transferred == 0) {
                        relay_do_half_close(r, true);
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
                        r->last_active = time(NULL);
                        continue;
                    }
                    if (transferred == 0) {
                        relay_do_half_close(r, false);
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        r->state = RELAY_CLOSING;
                    }
                    break;
                }
            }

            if (r->state == RELAY_CLOSING)
                relay_free(ds, r);
            break;

        /* --- XHTTP состояния --- */

        case RELAY_XHTTP_DN_CONNECT:
            /* download fd TCP connect завершён (EPOLLOUT) */
            if (!ep->is_client && (ev & EPOLLOUT) &&
                events[i].data.ptr == &r->ep_download) {
                int err = 0;
                socklen_t errlen = sizeof(err);
                getsockopt(r->download_fd, SOL_SOCKET, SO_ERROR,
                           &err, &errlen);
                if (err != 0) {
                    log_msg(LOG_WARN, "XHTTP: download connect: %s",
                            strerror(err));
                    relay_free(ds, r);
                    break;
                }
                /* Оба fd подключены → начать upload TLS */
                struct epoll_event mod = {
                    .events = EPOLLIN | EPOLLOUT | EPOLLET,
                    .data.ptr = &r->ep_upstream,
                };
                epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD,
                          r->upstream_fd, &mod);
                r->state = RELAY_XHTTP_UP_TLS;
            }
            break;

        case RELAY_XHTTP_UP_TLS:
            if (events[i].data.ptr != &r->ep_upstream) break;
            if (!(ev & (EPOLLIN | EPOLLOUT))) break;
            {
                tls_step_result_t tr = xhttp_upload_tls_step(r->xhttp);
                if (tr == TLS_OK) {
                    /* Upload TLS готов → download TLS */
                    struct epoll_event mod = {
                        .events = EPOLLIN | EPOLLOUT | EPOLLET,
                        .data.ptr = &r->ep_download,
                    };
                    epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD,
                              r->download_fd, &mod);
                    r->state = RELAY_XHTTP_DN_TLS;
                } else if (tr == TLS_ERR) {
                    dispatcher_server_result(ds, r->server_idx, false);
                    relay_free(ds, r);
                }
            }
            break;

        case RELAY_XHTTP_DN_TLS:
            if (events[i].data.ptr != &r->ep_download) break;
            if (!(ev & (EPOLLIN | EPOLLOUT))) break;
            {
                tls_step_result_t tr = xhttp_download_tls_step(r->xhttp);
                if (tr == TLS_OK) {
                    r->state = RELAY_XHTTP_UP_REQ;
                    /* Сразу отправляем POST */
                    const ServerConfig *srv = NULL;
                    if (g_config && r->server_idx < g_config->server_count)
                        srv = &g_config->servers[r->server_idx];
                    if (!srv || xhttp_send_upload_request(r->xhttp,
                            &r->dst, srv->uuid) < 0) {
                        relay_free(ds, r);
                        break;
                    }
                    /* Отправляем GET */
                    if (xhttp_send_download_request(r->xhttp) < 0) {
                        relay_free(ds, r);
                        break;
                    }
                    r->state = RELAY_XHTTP_DN_REQ;
                } else if (tr == TLS_ERR) {
                    dispatcher_server_result(ds, r->server_idx, false);
                    relay_free(ds, r);
                }
            }
            break;

        case RELAY_XHTTP_UP_REQ:
            /* Не должен попасть сюда — переход сразу в DN_REQ */
            break;

        case RELAY_XHTTP_DN_REQ:
            /* Парсим HTTP 200 OK от download */
            if (events[i].data.ptr != &r->ep_download) break;
            if (!(ev & EPOLLIN)) break;
            {
                int prc = xhttp_parse_response_step(r->xhttp);
                if (prc == 0) {
                    dispatcher_server_result(ds, r->server_idx, true);
                    r->state = RELAY_XHTTP_ACTIVE;
                    log_msg(LOG_DEBUG, "XHTTP: relay активен");
                } else if (prc < 0) {
                    dispatcher_server_result(ds, r->server_idx, false);
                    relay_free(ds, r);
                }
            }
            break;

        case RELAY_XHTTP_ACTIVE:
            /* client → upload (chunked POST) */
            if (ep->is_client && (ev & EPOLLIN)) {
                for (;;) {
                    ssize_t n = read(r->client_fd,
                                     ds->relay_buf, ds->relay_buf_size);
                    if (n > 0) {
                        ssize_t sent = xhttp_send_chunk(
                            r->xhttp, ds->relay_buf, n);
                        if (sent > 0) {
                            r->bytes_in += sent;
                            r->last_active = time(NULL);
                            continue;
                        }
                    }
                    if (n == 0) {
                        relay_do_half_close(r, true);
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        r->state = RELAY_CLOSING;
                    }
                    break;
                }
            }
            /* download → client (chunked GET) */
            if (events[i].data.ptr == &r->ep_download && (ev & EPOLLIN)) {
                for (;;) {
                    ssize_t n = xhttp_recv_chunk(
                        r->xhttp, ds->relay_buf, ds->relay_buf_size);
                    if (n > 0) {
                        ssize_t wr = write(r->client_fd, ds->relay_buf, (size_t)n);
                        if (wr < 0) {
                            if (errno != EAGAIN && errno != EPIPE)
                                log_msg(LOG_DEBUG, "relay: XHTTP write ошибка: %s",
                                        strerror(errno));
                            relay_free(ds, r);
                            goto next_event_xhttp;
                        }
                        r->bytes_out += (uint64_t)wr;
                        r->last_active = time(NULL);
                        continue;
                    }
                    if (n == 0) {
                        relay_do_half_close(r, false);
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        r->state = RELAY_CLOSING;
                    }
                    break;
                }
            }
            if (r->state == RELAY_CLOSING)
                relay_free(ds, r);
            next_event_xhttp:
            break;

        /* --- AWG состояния --- */

        case RELAY_AWG_HANDSHAKE:
            if (!ep->is_client && r->awg) {
                int arc = awg_process_incoming(r->awg);
                if (arc == 1) {
                    dispatcher_server_result(ds, r->server_idx, true);
                    r->state = RELAY_AWG_ACTIVE;
                    log_msg(LOG_DEBUG, "relay: AWG активен");
                } else if (arc < 0) {
                    dispatcher_server_result(ds, r->server_idx, false);
                    relay_free(ds, r);
                } else {
                    awg_tick(r->awg);
                }
            }
            break;

        case RELAY_AWG_ACTIVE:
            if (ep->is_client && (ev & EPOLLIN)) {
                /* client → AWG */
                for (;;) {
                    ssize_t n = read(r->client_fd,
                                     ds->relay_buf, ds->relay_buf_size);
                    if (n > 0) {
                        awg_send(r->awg, ds->relay_buf, n);
                        r->bytes_in += n;
                        r->last_active = time(NULL);
                        continue;
                    }
                    if (n == 0) relay_do_half_close(r, true);
                    else if (errno != EAGAIN) r->state = RELAY_CLOSING;
                    break;
                }
            }
            if (!ep->is_client && (ev & EPOLLIN) && r->awg) {
                /* AWG → client */
                int arc = awg_process_incoming(r->awg);
                if (arc == 2) {
                    uint8_t buf[2048];
                    ssize_t n = awg_recv(r->awg, buf, sizeof(buf));
                    if (n > 0) {
                        ssize_t wr = write(r->client_fd, buf, (size_t)n);
                        if (wr < 0) {
                            if (errno != EAGAIN && errno != EPIPE)
                                log_msg(LOG_DEBUG, "relay: AWG write ошибка: %s",
                                        strerror(errno));
                            relay_free(ds, r);
                            break;
                        }
                        r->bytes_out += (uint64_t)wr;
                        r->last_active = time(NULL);
                    }
                } else if (arc < 0) {
                    r->state = RELAY_CLOSING;
                }
            }
            if (r->awg) awg_tick(r->awg);
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

    /* Периодическая проверка таймаутов (M-03: ранний выход, M-09: idle) */
    if (ds->tick_count % RELAY_TIMEOUT_CHECK == 0
        && ds->conns_count > 0) {
        time_t now = time(NULL);
        int checked = 0;
        for (int i = 0; i < ds->conns_max
                        && checked < ds->conns_count; i++) {
            relay_conn_t *r = &ds->conns[i];
            if (r->state == RELAY_DONE)
                continue;
            checked++;

            time_t idle_since = r->last_active > r->created_at
                                ? r->last_active : r->created_at;
            int timeout = (r->state == RELAY_HALF_CLOSE)
                          ? RELAY_HALF_CLOSE_TIMEOUT
                          : RELAY_TIMEOUT_SEC;

            if (now - idle_since > timeout) {
                log_msg(LOG_DEBUG,
                    "relay: idle таймаут %lds (state=%d)",
                    (long)(now - idle_since), r->state);
                relay_free(ds, r);
            }
        }
    }

    /* Health reset по абсолютному времени (M-07) */
    {
        time_t now_t = time(NULL);
        if (now_t >= ds->health_reset_at && ds->health_count > 0) {
            ds->health_reset_at = now_t + 30;
            for (int i = 0; i < ds->health_count; i++) {
                if (!ds->health[i].available) {
                    ds->health[i].available  = true;
                    ds->health[i].fail_count = 0;
                    log_msg(LOG_DEBUG,
                        "health: сервер %d сброшен для повторной проверки",
                        ds->health[i].server_idx);
                }
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

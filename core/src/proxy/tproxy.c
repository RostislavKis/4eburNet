/*
 * Прозрачное проксирование (TPROXY)
 *
 * Неблокирующий TCP+UDP сервер на порту 7893.
 * Ядро Linux доставляет перехваченные соединения через TPROXY.
 * Читает оригинальный адрес назначения (SO_ORIGINAL_DST / cmsg)
 * и передаёт в dispatcher для дальнейшей обработки.
 */

#include "proxy/tproxy.h"
#include "proxy/dispatcher.h"
#include "phoenix.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

/*
 * Константы netfilter — могут отсутствовать в musl headers.
 * Значения стандартные, не меняются между версиями ядра.
 */
#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST     80
#endif

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR  20
#endif

#ifndef IPV6_RECVORIGDSTADDR
#define IPV6_RECVORIGDSTADDR 74
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT      19
#endif

#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT    75
#endif

/* IP_ORIGDSTADDR — тип cmsg для UDP оригинального dst */
#ifndef IP_ORIGDSTADDR
#define IP_ORIGDSTADDR      IP_RECVORIGDSTADDR
#endif

#ifndef IPV6_ORIGDSTADDR
#define IPV6_ORIGDSTADDR    IPV6_RECVORIGDSTADDR
#endif

/* Максимум событий epoll за один вызов process */
#define TPROXY_MAX_EVENTS   16

/* Размер буфера для cmsg (UDP) */
#define TPROXY_CMSG_SIZE    256

/* Размер буфера для чтения UDP дейтаграмм */
#define TPROXY_UDP_BUF      65536

/* ------------------------------------------------------------------ */
/*  Вспомогательные: форматирование адресов для логов                   */
/* ------------------------------------------------------------------ */

static void format_addr(const struct sockaddr_storage *ss,
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
/*  Создание TCP listen сокета с флагами TPROXY                        */
/* ------------------------------------------------------------------ */

static int tproxy_create_tcp_socket(int family, uint16_t port,
                                    int rcvbuf_size)
{
    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_msg(LOG_ERROR, "TPROXY: socket(TCP, %s): %s",
                family == AF_INET ? "IPv4" : "IPv6", strerror(errno));
        return -1;
    }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));

    if (family == AF_INET) {
        setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &yes, sizeof(yes));
        setsockopt(fd, IPPROTO_IP, IP_RECVORIGDSTADDR, &yes, sizeof(yes));
    } else {
        setsockopt(fd, IPPROTO_IPV6, IPV6_TRANSPARENT, &yes, sizeof(yes));
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, &yes, sizeof(yes));
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
    }

    if (rcvbuf_size > 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                   &rcvbuf_size, sizeof(rcvbuf_size));

    /* bind */
    if (family == AF_INET) {
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port   = htons(port),
            .sin_addr   = { .s_addr = INADDR_ANY },
        };
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_msg(LOG_ERROR, "TPROXY: bind(TCP4, :%u): %s",
                    port, strerror(errno));
            close(fd);
            return -1;
        }
    } else {
        struct sockaddr_in6 addr = {
            .sin6_family = AF_INET6,
            .sin6_port   = htons(port),
            .sin6_addr   = IN6ADDR_ANY_INIT,
        };
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_msg(LOG_ERROR, "TPROXY: bind(TCP6, :%u): %s",
                    port, strerror(errno));
            close(fd);
            return -1;
        }
    }

    if (listen(fd, TPROXY_BACKLOG) < 0) {
        log_msg(LOG_ERROR, "TPROXY: listen(:%u): %s",
                port, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

/* ------------------------------------------------------------------ */
/*  Создание UDP сокета с флагами TPROXY                               */
/* ------------------------------------------------------------------ */

static int tproxy_create_udp_socket(int family, uint16_t port,
                                    int rcvbuf_size)
{
    int fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_msg(LOG_ERROR, "TPROXY: socket(UDP, %s): %s",
                family == AF_INET ? "IPv4" : "IPv6", strerror(errno));
        return -1;
    }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));

    if (family == AF_INET) {
        setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &yes, sizeof(yes));
        setsockopt(fd, IPPROTO_IP, IP_RECVORIGDSTADDR, &yes, sizeof(yes));
    } else {
        setsockopt(fd, IPPROTO_IPV6, IPV6_TRANSPARENT, &yes, sizeof(yes));
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, &yes, sizeof(yes));
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
    }

    if (rcvbuf_size > 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                   &rcvbuf_size, sizeof(rcvbuf_size));

    if (family == AF_INET) {
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port   = htons(port),
            .sin_addr   = { .s_addr = INADDR_ANY },
        };
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_msg(LOG_ERROR, "TPROXY: bind(UDP4, :%u): %s",
                    port, strerror(errno));
            close(fd);
            return -1;
        }
    } else {
        struct sockaddr_in6 addr = {
            .sin6_family = AF_INET6,
            .sin6_port   = htons(port),
            .sin6_addr   = IN6ADDR_ANY_INIT,
        };
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_msg(LOG_ERROR, "TPROXY: bind(UDP6, :%u): %s",
                    port, strerror(errno));
            close(fd);
            return -1;
        }
    }

    return fd;
}

/* ------------------------------------------------------------------ */
/*  Чтение оригинального dst для TCP соединения                        */
/* ------------------------------------------------------------------ */

static int tproxy_get_original_dst(int fd, struct sockaddr_storage *dst,
                                   int family)
{
    memset(dst, 0, sizeof(*dst));

    if (family == AF_INET) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &addr, &len) == 0) {
            dst->ss_family = AF_INET;
            memcpy(dst, &addr, sizeof(addr));
            return 0;
        }
    } else {
        struct sockaddr_in6 addr;
        socklen_t len = sizeof(addr);
        if (getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST,
                       &addr, &len) == 0) {
            dst->ss_family = AF_INET6;
            memcpy(dst, &addr, sizeof(addr));
            return 0;
        }
    }

    /* Запасной вариант: getsockname (когда TPROXY bind на реальный IP) */
    socklen_t len = sizeof(*dst);
    if (getsockname(fd, (struct sockaddr *)dst, &len) == 0)
        return 0;

    log_msg(LOG_WARN, "TPROXY: не удалось прочитать оригинальный dst: %s",
            strerror(errno));
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Приём TCP соединений (edge-triggered — читаем до EAGAIN)           */
/* ------------------------------------------------------------------ */

static void tproxy_accept_tcp(tproxy_state_t *ts, int listen_fd,
                              int family)
{
    for (;;) {
        struct sockaddr_storage src;
        socklen_t srclen = sizeof(src);

        int client = accept4(listen_fd, (struct sockaddr *)&src, &srclen,
                             SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (client < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;  /* все соединения приняты */
            if (errno == EMFILE || errno == ENFILE) {
                log_msg(LOG_WARN, "TPROXY: лимит дескрипторов");
                ts->rejected++;
                break;
            }
            log_msg(LOG_ERROR, "TPROXY: accept4: %s", strerror(errno));
            break;
        }

        tproxy_conn_t conn = {
            .fd          = client,
            .proto       = IPPROTO_TCP,
            .src         = src,
            .accepted_at = time(NULL),
        };

        if (tproxy_get_original_dst(client, &conn.dst, family) < 0) {
            close(client);
            ts->rejected++;
            continue;
        }

        ts->accepted++;

        char src_str[64], dst_str[64];
        format_addr(&conn.src, src_str, sizeof(src_str));
        format_addr(&conn.dst, dst_str, sizeof(dst_str));
        log_msg(LOG_DEBUG, "TPROXY TCP: %s → %s", src_str, dst_str);

        dispatcher_handle_conn(&conn);
    }
}

/* ------------------------------------------------------------------ */
/*  Приём UDP дейтаграмм (edge-triggered — читаем до EAGAIN)           */
/* ------------------------------------------------------------------ */

static void tproxy_recv_udp(tproxy_state_t *ts, int udp_fd, int family)
{
    uint8_t buf[TPROXY_UDP_BUF];

    for (;;) {
        struct sockaddr_storage src;
        struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
        char cmsg_buf[TPROXY_CMSG_SIZE];

        struct msghdr msg = {
            .msg_name       = &src,
            .msg_namelen    = sizeof(src),
            .msg_iov        = &iov,
            .msg_iovlen     = 1,
            .msg_control    = cmsg_buf,
            .msg_controllen = sizeof(cmsg_buf),
        };

        ssize_t n = recvmsg(udp_fd, &msg, MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            log_msg(LOG_ERROR, "TPROXY: recvmsg(UDP): %s", strerror(errno));
            break;
        }

        tproxy_conn_t conn = {
            .fd          = -1,
            .proto       = IPPROTO_UDP,
            .src         = src,
            .accepted_at = time(NULL),
        };
        memset(&conn.dst, 0, sizeof(conn.dst));

        /* Извлечь оригинальный dst из cmsg */
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
             cm != NULL;
             cm = CMSG_NXTHDR(&msg, cm)) {
            if (family == AF_INET &&
                cm->cmsg_level == IPPROTO_IP &&
                cm->cmsg_type  == IP_ORIGDSTADDR) {
                memcpy(&conn.dst, CMSG_DATA(cm),
                       sizeof(struct sockaddr_in));
                break;
            }
            if (family == AF_INET6 &&
                cm->cmsg_level == IPPROTO_IPV6 &&
                cm->cmsg_type  == IPV6_ORIGDSTADDR) {
                memcpy(&conn.dst, CMSG_DATA(cm),
                       sizeof(struct sockaddr_in6));
                break;
            }
        }

        ts->accepted++;
        dispatcher_handle_udp(&conn, buf, (size_t)n);
    }
}

/* ------------------------------------------------------------------ */
/*  tproxy_init                                                        */
/* ------------------------------------------------------------------ */

int tproxy_init(tproxy_state_t *ts, uint16_t port,
                DeviceProfile profile)
{
    memset(ts, 0, sizeof(*ts));
    ts->tcp4_fd  = -1;
    ts->tcp6_fd  = -1;
    ts->udp4_fd  = -1;
    ts->udp6_fd  = -1;
    ts->epoll_fd = -1;

    /* Размер буфера приёма по профилю устройства */
    int rcvbuf;
    switch (profile) {
    case DEVICE_MICRO:  rcvbuf = 64  * 1024; break;
    case DEVICE_NORMAL: rcvbuf = 256 * 1024; break;
    case DEVICE_FULL:   rcvbuf = 1024 * 1024; break;
    default:            rcvbuf = 256 * 1024; break;
    }

    /* TCP IPv4 */
    ts->tcp4_fd = tproxy_create_tcp_socket(AF_INET, port, rcvbuf);
    if (ts->tcp4_fd < 0)
        goto fail;

    /* TCP IPv6 */
    ts->tcp6_fd = tproxy_create_tcp_socket(AF_INET6, port, rcvbuf);
    if (ts->tcp6_fd < 0)
        goto fail;

    /* UDP IPv4 */
    ts->udp4_fd = tproxy_create_udp_socket(AF_INET, port, rcvbuf);
    if (ts->udp4_fd < 0)
        goto fail;

    /* UDP IPv6 */
    ts->udp6_fd = tproxy_create_udp_socket(AF_INET6, port, rcvbuf);
    if (ts->udp6_fd < 0)
        goto fail;

    /* epoll */
    ts->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ts->epoll_fd < 0) {
        log_msg(LOG_ERROR, "TPROXY: epoll_create1: %s", strerror(errno));
        goto fail;
    }

    /* Регистрация всех 4 сокетов в epoll (edge-triggered) */
    struct epoll_event ev = { .events = EPOLLIN | EPOLLET };
    int fds[] = { ts->tcp4_fd, ts->tcp6_fd, ts->udp4_fd, ts->udp6_fd };
    for (int i = 0; i < 4; i++) {
        ev.data.fd = fds[i];
        if (epoll_ctl(ts->epoll_fd, EPOLL_CTL_ADD, fds[i], &ev) < 0) {
            log_msg(LOG_ERROR, "TPROXY: epoll_ctl_add: %s", strerror(errno));
            goto fail;
        }
    }

    ts->running = true;
    log_msg(LOG_INFO, "TPROXY слушает на порту %u (TCP+UDP, IPv4+IPv6)",
            port);
    return 0;

fail:
    tproxy_cleanup(ts);
    return -1;
}

/* ------------------------------------------------------------------ */
/*  tproxy_process — неблокирующая обработка событий                    */
/* ------------------------------------------------------------------ */

void tproxy_process(tproxy_state_t *ts)
{
    if (ts->epoll_fd < 0)
        return;

    struct epoll_event events[TPROXY_MAX_EVENTS];
    int n = epoll_wait(ts->epoll_fd, events, TPROXY_MAX_EVENTS, 0);

    for (int i = 0; i < n; i++) {
        int fd = events[i].data.fd;

        if      (fd == ts->tcp4_fd) tproxy_accept_tcp(ts, fd, AF_INET);
        else if (fd == ts->tcp6_fd) tproxy_accept_tcp(ts, fd, AF_INET6);
        else if (fd == ts->udp4_fd) tproxy_recv_udp(ts, fd, AF_INET);
        else if (fd == ts->udp6_fd) tproxy_recv_udp(ts, fd, AF_INET6);
    }
}

/* ------------------------------------------------------------------ */
/*  tproxy_handle_event — обработка одного fd (master epoll, H-10)     */
/* ------------------------------------------------------------------ */

void tproxy_handle_event(tproxy_state_t *ts, int fd)
{
    if      (fd == ts->tcp4_fd) tproxy_accept_tcp(ts, fd, AF_INET);
    else if (fd == ts->tcp6_fd) tproxy_accept_tcp(ts, fd, AF_INET6);
    else if (fd == ts->udp4_fd) tproxy_recv_udp(ts, fd, AF_INET);
    else if (fd == ts->udp6_fd) tproxy_recv_udp(ts, fd, AF_INET6);
}

/* ------------------------------------------------------------------ */
/*  tproxy_cleanup                                                     */
/* ------------------------------------------------------------------ */

void tproxy_cleanup(tproxy_state_t *ts)
{
    uint64_t accepted = ts->accepted;
    uint64_t rejected = ts->rejected;

    if (ts->epoll_fd >= 0) { close(ts->epoll_fd); ts->epoll_fd = -1; }
    if (ts->tcp4_fd  >= 0) { close(ts->tcp4_fd);  ts->tcp4_fd  = -1; }
    if (ts->tcp6_fd  >= 0) { close(ts->tcp6_fd);  ts->tcp6_fd  = -1; }
    if (ts->udp4_fd  >= 0) { close(ts->udp4_fd);  ts->udp4_fd  = -1; }
    if (ts->udp6_fd  >= 0) { close(ts->udp6_fd);  ts->udp6_fd  = -1; }

    ts->running = false;

    log_msg(LOG_INFO,
        "TPROXY остановлен (принято: %lu, отброшено: %lu)",
        (unsigned long)accepted, (unsigned long)rejected);
}

/* ------------------------------------------------------------------ */
/*  tproxy_stats                                                       */
/* ------------------------------------------------------------------ */

void tproxy_stats(const tproxy_state_t *ts,
                  uint64_t *accepted, uint64_t *rejected)
{
    if (accepted) *accepted = ts->accepted;
    if (rejected) *rejected = ts->rejected;
}

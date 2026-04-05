/*
 * DNS сервер — UDP/TCP listener, split DNS, кэш
 */

#include "dns/dns_server.h"
#include "dns/dns_packet.h"
#include "dns/dns_cache.h"
#include "dns/dns_rules.h"
#include "dns/dns_upstream.h"
#include "phoenix.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int dns_server_init(dns_server_t *ds, const PhoenixConfig *cfg)
{
    memset(ds, 0, sizeof(*ds));
    ds->udp_fd = -1;
    ds->tcp_fd = -1;
    ds->cfg    = cfg;

    if (!cfg->dns.enabled || cfg->dns.listen_port == 0) {
        log_msg(LOG_DEBUG, "DNS демон отключён");
        return -1;
    }

    uint16_t port = cfg->dns.listen_port;

    /* UDP сокет */
    ds->udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (ds->udp_fd < 0) {
        log_msg(LOG_ERROR, "DNS: socket(UDP): %s", strerror(errno));
        return -1;
    }

    int yes = 1;
    setsockopt(ds->udp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
        .sin_addr   = { .s_addr = INADDR_ANY },
    };

    if (bind(ds->udp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_msg(LOG_ERROR, "DNS: bind(UDP :%u): %s", port, strerror(errno));
        close(ds->udp_fd); ds->udp_fd = -1;
        return -1;
    }

    /* TCP сокет */
    ds->tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (ds->tcp_fd < 0) {
        log_msg(LOG_ERROR, "DNS: socket(TCP): %s", strerror(errno));
        close(ds->udp_fd); ds->udp_fd = -1;
        return -1;
    }

    setsockopt(ds->tcp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(ds->tcp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_msg(LOG_ERROR, "DNS: bind(TCP :%u): %s", port, strerror(errno));
        close(ds->udp_fd); ds->udp_fd = -1;
        close(ds->tcp_fd); ds->tcp_fd = -1;
        return -1;
    }

    if (listen(ds->tcp_fd, 16) < 0) {
        log_msg(LOG_ERROR, "DNS: listen: %s", strerror(errno));
        close(ds->udp_fd); ds->udp_fd = -1;
        close(ds->tcp_fd); ds->tcp_fd = -1;
        return -1;
    }

    /* Кэш */
    int cache_sz = cfg->dns.cache_size > 0 ? cfg->dns.cache_size : 256;
    dns_cache_init(&ds->cache, cache_sz);

    log_msg(LOG_INFO, "DNS демон запущен на порту %u (кэш: %d)", port, cache_sz);
    return 0;
}

void dns_server_cleanup(dns_server_t *ds)
{
    if (ds->udp_fd >= 0) { close(ds->udp_fd); ds->udp_fd = -1; }
    if (ds->tcp_fd >= 0) { close(ds->tcp_fd); ds->tcp_fd = -1; }
    dns_cache_free(&ds->cache);
    log_msg(LOG_INFO, "DNS демон остановлен");
}

int dns_server_register_epoll(dns_server_t *ds, int master_epoll_fd)
{
    struct epoll_event ev = { .events = EPOLLIN };

    if (ds->udp_fd >= 0) {
        ev.data.fd = ds->udp_fd;
        if (epoll_ctl(master_epoll_fd, EPOLL_CTL_ADD, ds->udp_fd, &ev) < 0)
            log_msg(LOG_WARN, "DNS: epoll_ctl ADD udp: %s", strerror(errno));
    }
    if (ds->tcp_fd >= 0) {
        ev.data.fd = ds->tcp_fd;
        if (epoll_ctl(master_epoll_fd, EPOLL_CTL_ADD, ds->tcp_fd, &ev) < 0)
            log_msg(LOG_WARN, "DNS: epoll_ctl ADD tcp: %s", strerror(errno));
    }
    return 0;
}

/* Выбрать upstream и отправить запрос
 * TODO: перевести на асинхронный резолвинг — сейчас блокирует main loop
 * на время upstream таймаута (до 2 сек UDP, до 5 сек DoT/DoH) (M-16, C-02). */
static ssize_t resolve_query(dns_server_t *ds, dns_action_t action,
                             const uint8_t *query, size_t query_len,
                             uint8_t *response, size_t resp_buflen)
{
    const DnsConfig *d = &ds->cfg->dns;
    const char *server = NULL;
    uint16_t port = d->upstream_port ? d->upstream_port : 53;

    switch (action) {
    case DNS_ACTION_BYPASS:
        server = d->upstream_bypass;
        break;
    case DNS_ACTION_PROXY:
        /* DoH > DoT > обычный UDP */
        if (d->doh_enabled && d->doh_url[0])
            return dns_doh_query(d, query, query_len,
                                response, resp_buflen);
        if (d->dot_enabled && d->dot_server_ip[0])
            return dns_dot_query(d->dot_server_ip, d->dot_port,
                                d->dot_sni,
                                query, query_len,
                                response, resp_buflen);
        server = d->upstream_proxy;
        break;
    case DNS_ACTION_DEFAULT:
    default:
        server = d->upstream_default;
        break;
    case DNS_ACTION_BLOCK:
        return -1;  /* не должно сюда попасть */
    }

    if (!server || !server[0]) {
        log_msg(LOG_WARN, "DNS: upstream не настроен для action %d", action);
        return -1;
    }

    return dns_upstream_query(server, port, query, query_len,
                             response, resp_buflen, 2000);
}

/* Per-source rate limiting (H-13: DNS amplification) */
#define DNS_RATE_LIMIT  100
#define DNS_RATE_WINDOW 1

/* Обработка одного UDP DNS запроса */
static void handle_udp_query(dns_server_t *ds)
{
    uint8_t pkt[DNS_MAX_PACKET];
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);

    ssize_t n = recvfrom(ds->udp_fd, pkt, sizeof(pkt), MSG_DONTWAIT,
                         (struct sockaddr *)&client_addr, &client_len);
    if (n <= 0)
        return;

    /* Rate limiting per source IP (H-13) */
    uint32_t src_ip = 0;
    if (client_addr.ss_family == AF_INET)
        src_ip = ((struct sockaddr_in *)&client_addr)->sin_addr.s_addr;

    time_t now_t = time(NULL);
    int slot = (int)(src_ip % 256);
    if (ds->rate_table[slot].ip == src_ip) {
        if (now_t - ds->rate_table[slot].window_start < DNS_RATE_WINDOW) {
            if (++ds->rate_table[slot].count > DNS_RATE_LIMIT) {
                log_msg(LOG_DEBUG, "DNS: rate limit для %08x", src_ip);
                return;
            }
        } else {
            ds->rate_table[slot].window_start = now_t;
            ds->rate_table[slot].count = 1;
        }
    } else {
        ds->rate_table[slot].ip = src_ip;
        ds->rate_table[slot].count = 1;
        ds->rate_table[slot].window_start = now_t;
    }

    dns_query_t q;
    if (dns_parse_query(pkt, n, &q) < 0) {
        log_msg(LOG_DEBUG, "DNS: невалидный запрос (%zd байт)", n);
        return;
    }

    log_msg(LOG_DEBUG, "DNS: запрос %s (type %u)", q.qname, q.qtype);

    /* Проверить кэш */
    uint16_t resp_len = 0;
    const uint8_t *cached = dns_cache_get(&ds->cache, q.qname, q.qtype,
                                          &resp_len, q.id);
    if (cached) {
        if (sendto(ds->udp_fd, cached, resp_len, 0,
                   (struct sockaddr *)&client_addr, client_len) < 0)
            log_msg(LOG_DEBUG, "DNS: sendto (cache): %s", strerror(errno));
        log_msg(LOG_DEBUG, "DNS: %s из кэша", q.qname);
        return;
    }

    /* Определить action */
    dns_action_t action = dns_rules_match(q.qname);

    if (action == DNS_ACTION_BLOCK) {
        uint8_t nxdomain[DNS_MAX_PACKET];
        int nx_len = dns_build_nxdomain(&q, nxdomain, sizeof(nxdomain));
        if (nx_len > 0) {
            if (sendto(ds->udp_fd, nxdomain, nx_len, 0,
                       (struct sockaddr *)&client_addr, client_len) < 0)
                log_msg(LOG_DEBUG, "DNS: sendto: %s", strerror(errno));
            log_msg(LOG_DEBUG, "DNS: %s → NXDOMAIN (blocked)", q.qname);
        }
        return;
    }

    /* Запрос к upstream */
    uint8_t response[DNS_MAX_PACKET];
    ssize_t resp_n = resolve_query(ds, action, pkt, n,
                                   response, sizeof(response));
    if (resp_n <= 0) {
        log_msg(LOG_DEBUG, "DNS: %s — upstream не ответил", q.qname);
        return;
    }

    /* Подставить ID клиента и отправить */
    uint8_t reply[DNS_MAX_PACKET];
    int reply_len = dns_build_forward_reply(&q, response, resp_n,
                                            reply, sizeof(reply));
    if (reply_len > 0) {
        if (sendto(ds->udp_fd, reply, reply_len, 0,
                   (struct sockaddr *)&client_addr, client_len) < 0)
            log_msg(LOG_DEBUG, "DNS: sendto: %s", strerror(errno));

        /* Положить в кэш */
        uint32_t ttl = dns_extract_min_ttl(response, resp_n);
        int max_ttl = ds->cfg->dns.cache_ttl_max;
        if (max_ttl > 0 && ttl > (uint32_t)max_ttl)
            ttl = max_ttl;
        dns_cache_put(&ds->cache, q.qname, q.qtype,
                      response, resp_n, ttl);

        log_msg(LOG_DEBUG, "DNS: %s → %s (ttl %u)",
                q.qname,
                action == DNS_ACTION_BYPASS ? "bypass" :
                action == DNS_ACTION_PROXY  ? "proxy" : "default",
                ttl);
    }
}

/* Обработка TCP DNS (accept + read + process + write + close)
 * TODO: async TCP DNS handler — v2. Текущий блокирующий вариант
 * ограничен SO_RCVTIMEO=2s, допустимо для малой нагрузки. */
static void handle_tcp_query(dns_server_t *ds)
{
    /* Blocking сокет с таймаутом вместо NONBLOCK+MSG_WAITALL (H-07) */
    int client = accept4(ds->tcp_fd, NULL, NULL, SOCK_CLOEXEC);
    if (client < 0)
        return;

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Читаем [2 bytes length][DNS query] */
    uint8_t len_buf[2];
    if (recv(client, len_buf, 2, MSG_WAITALL) != 2) {
        close(client); return;
    }
    uint16_t qlen = ((uint16_t)len_buf[0] << 8) | len_buf[1];
    if (qlen < 12 || qlen > DNS_MAX_PACKET) {
        close(client); return;
    }

    uint8_t pkt[DNS_MAX_PACKET];
    if (recv(client, pkt, qlen, MSG_WAITALL) != qlen) {
        close(client); return;
    }

    dns_query_t q;
    if (dns_parse_query(pkt, qlen, &q) < 0) {
        close(client); return;
    }

    /* Та же логика что для UDP */
    uint8_t response[DNS_MAX_PACKET];
    ssize_t resp_n;

    dns_action_t action = dns_rules_match(q.qname);
    if (action == DNS_ACTION_BLOCK) {
        resp_n = dns_build_nxdomain(&q, response, sizeof(response));
    } else {
        resp_n = resolve_query(ds, action, pkt, qlen,
                               response, sizeof(response));
        if (resp_n > 0) {
            /* Подставить ID */
            response[0] = (q.id >> 8) & 0xFF;
            response[1] = q.id & 0xFF;
        }
    }

    if (resp_n > 0) {
        uint8_t tcp_reply[2 + DNS_MAX_PACKET];
        tcp_reply[0] = (resp_n >> 8) & 0xFF;
        tcp_reply[1] = resp_n & 0xFF;
        memcpy(tcp_reply + 2, response, resp_n);
        ssize_t w = write(client, tcp_reply, 2 + resp_n);
        if (w < 0)
            log_msg(LOG_DEBUG, "DNS TCP: write: %s", strerror(errno));
    }

    close(client);
}

void dns_server_handle_event(dns_server_t *ds, int fd)
{
    if (fd == ds->udp_fd)
        handle_udp_query(ds);
    else if (fd == ds->tcp_fd)
        handle_tcp_query(ds);
}

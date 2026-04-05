/*
 * DNS сервер — UDP/TCP listener, split DNS, кэш
 * Async UDP resolver через pending queue + epoll (C-06/H-18)
 */

#include "dns/dns_server.h"
#include "dns/dns_packet.h"
#include "dns/dns_cache.h"
#include "dns/dns_rules.h"
#include "dns/dns_upstream.h"
#include "dns/dns_resolver.h"
#include "phoenix.h"

#include <stdlib.h>
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
    ds->master_epoll_fd = -1;
    ds->cfg    = cfg;

    dns_pending_init(&ds->pending);

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

    ds->initialized = true;
    log_msg(LOG_INFO, "DNS демон запущен на порту %u (кэш: %d)", port, cache_sz);
    return 0;
}

void dns_server_cleanup(dns_server_t *ds)
{
    /* Закрыть все pending upstream сокеты */
    for (int i = 0; i < DNS_PENDING_MAX; i++) {
        if (ds->pending.slots[i].active)
            dns_pending_complete(&ds->pending, i);
    }
    if (ds->udp_fd >= 0) { close(ds->udp_fd); ds->udp_fd = -1; }
    if (ds->tcp_fd >= 0) { close(ds->tcp_fd); ds->tcp_fd = -1; }
    dns_cache_free(&ds->cache);
    ds->initialized = false;
    log_msg(LOG_INFO, "DNS демон остановлен");
}

int dns_server_register_epoll(dns_server_t *ds, int master_epoll_fd)
{
    ds->master_epoll_fd = master_epoll_fd;

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

/* Блокирующий resolve — только для DoH/DoT (пока синхронно) */
static ssize_t resolve_query_sync(dns_server_t *ds, dns_action_t action,
                                  const uint8_t *query, size_t query_len,
                                  uint8_t *response, size_t resp_buflen)
{
    const DnsConfig *d = &ds->cfg->dns;

    if (action == DNS_ACTION_PROXY) {
        if (d->doh_enabled && d->doh_url[0])
            return dns_doh_query(d, query, query_len,
                                response, resp_buflen);
        if (d->dot_enabled && d->dot_server_ip[0])
            return dns_dot_query(d->dot_server_ip, d->dot_port,
                                d->dot_sni,
                                query, query_len,
                                response, resp_buflen);
    }

    /* Не должно сюда попасть — обычные UDP через async */
    return -1;
}

/* Определить upstream IP и порт для action */
static bool resolve_upstream_addr(const dns_server_t *ds, dns_action_t action,
                                  const char **out_ip, uint16_t *out_port)
{
    const DnsConfig *d = &ds->cfg->dns;
    *out_port = d->upstream_port ? d->upstream_port : 53;

    switch (action) {
    case DNS_ACTION_BYPASS:
        *out_ip = d->upstream_bypass;
        break;
    case DNS_ACTION_PROXY:
        *out_ip = d->upstream_proxy;
        break;
    case DNS_ACTION_DEFAULT:
    default:
        *out_ip = d->upstream_default;
        break;
    case DNS_ACTION_BLOCK:
        return false;
    }

    return (*out_ip && (*out_ip)[0]);
}

/* Per-source rate limiting (H-13: DNS amplification) */
#define DNS_RATE_LIMIT  100
#define DNS_RATE_WINDOW 1

/* Обработка одного UDP DNS запроса — неблокирующий async путь */
static void handle_udp_query(dns_server_t *ds)
{
    uint8_t pkt[DNS_MAX_PACKET];
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);

    ssize_t n = recvfrom(ds->udp_fd, pkt, sizeof(pkt), MSG_DONTWAIT,
                         (struct sockaddr *)&client_addr, &client_len);
    if (n <= 0)
        return;

    /* H-10/H-11: Rate limiting для IPv4 и IPv6, 512 слотов, conservative collision */
    uint8_t src_addr[16] = {0};
    uint8_t src_addr_len = 0;
    if (client_addr.ss_family == AF_INET) {
        memcpy(src_addr, &((struct sockaddr_in *)&client_addr)->sin_addr, 4);
        src_addr_len = 4;
    } else if (client_addr.ss_family == AF_INET6) {
        memcpy(src_addr, &((struct sockaddr_in6 *)&client_addr)->sin6_addr, 16);
        src_addr_len = 16;
    }

    /* Хеш по всем байтам адреса (djb2) */
    uint32_t addr_hash = 5381;
    for (int ai = 0; ai < src_addr_len; ai++)
        addr_hash = addr_hash * 33 + src_addr[ai];

    time_t now_t = time(NULL);
    int slot = (int)(addr_hash % DNS_RATE_TABLE_SIZE);
    if (ds->rate_table[slot].addr_len == src_addr_len &&
        memcmp(ds->rate_table[slot].addr, src_addr, src_addr_len) == 0) {
        if (now_t - ds->rate_table[slot].window_start < DNS_RATE_WINDOW) {
            if (++ds->rate_table[slot].count > DNS_RATE_LIMIT) {
                log_msg(LOG_DEBUG, "DNS: rate limit (slot %d)", slot);
                return;
            }
        } else {
            ds->rate_table[slot].window_start = now_t;
            ds->rate_table[slot].count = 1;
        }
    } else if (ds->rate_table[slot].addr_len == 0) {
        /* Пустой слот — занимаем */
        memcpy(ds->rate_table[slot].addr, src_addr, src_addr_len);
        ds->rate_table[slot].addr_len = src_addr_len;
        ds->rate_table[slot].count = 1;
        ds->rate_table[slot].window_start = now_t;
    }
    /* H-11: collision — другой адрес в слоте, conservative: не сбрасываем */

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

    /* BLOCK — мгновенный NXDOMAIN, без upstream */
    if (action == DNS_ACTION_BLOCK) {
        uint8_t *reply = malloc(DNS_MAX_PACKET);
        if (!reply) return;
        int nx_len = dns_build_nxdomain(&q, reply, DNS_MAX_PACKET);
        if (nx_len > 0) {
            if (sendto(ds->udp_fd, reply, nx_len, 0,
                       (struct sockaddr *)&client_addr, client_len) < 0)
                log_msg(LOG_DEBUG, "DNS: sendto: %s", strerror(errno));
            log_msg(LOG_DEBUG, "DNS: %s -> NXDOMAIN (blocked)", q.qname);
        }
        free(reply);
        return;
    }

    /* DoH/DoT — пока синхронно (async в v2) */
    if (action == DNS_ACTION_PROXY) {
        const DnsConfig *d = &ds->cfg->dns;
        if ((d->doh_enabled && d->doh_url[0]) ||
            (d->dot_enabled && d->dot_server_ip[0])) {
            /* L-16: response и reply на heap */
            uint8_t *response = malloc(DNS_MAX_PACKET);
            uint8_t *reply = malloc(DNS_MAX_PACKET);
            if (!response || !reply) {
                free(response); free(reply);
                return;
            }

            ssize_t resp_n = resolve_query_sync(ds, action, pkt, n,
                                                response, DNS_MAX_PACKET);
            if (resp_n > 0) {
                int reply_len = dns_build_forward_reply(&q, response, resp_n,
                                                        reply, DNS_MAX_PACKET);
                if (reply_len > 0) {
                    if (sendto(ds->udp_fd, reply, reply_len, 0,
                               (struct sockaddr *)&client_addr, client_len) < 0)
                        log_msg(LOG_DEBUG, "DNS: sendto: %s", strerror(errno));

                    uint32_t ttl = dns_extract_min_ttl(response, resp_n);
                    int max_ttl = ds->cfg->dns.cache_ttl_max;
                    if (max_ttl > 0 && ttl > (uint32_t)max_ttl)
                        ttl = max_ttl;
                    dns_cache_put(&ds->cache, q.qname, q.qtype,
                                  response, resp_n, ttl);
                    log_msg(LOG_DEBUG, "DNS: %s -> proxy/DoH (ttl %u)",
                            q.qname, ttl);
                }
            }
            free(response);
            free(reply);
            return;
        }
    }

    /* Обычный UDP upstream — неблокирующий async путь */
    const char *upstream_ip = NULL;
    uint16_t upstream_port = 53;
    if (!resolve_upstream_addr(ds, action, &upstream_ip, &upstream_port)) {
        log_msg(LOG_WARN, "DNS: upstream не настроен для action %d", action);
        return;
    }

    int idx = dns_pending_add(&ds->pending, &q, pkt, n,
                              &client_addr, client_len,
                              action, upstream_ip, upstream_port);
    if (idx < 0) {
        log_msg(LOG_WARN, "DNS: pending очередь полна, сброс запроса %s",
                q.qname);
        return;
    }

    /* Добавить upstream fd в master epoll */
    struct epoll_event ev = {
        .events  = EPOLLIN,
        .data.fd = ds->pending.slots[idx].upstream_fd,
    };
    if (epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_ADD,
                  ds->pending.slots[idx].upstream_fd, &ev) < 0) {
        log_msg(LOG_DEBUG, "DNS: epoll_ctl ADD upstream: %s", strerror(errno));
        dns_pending_complete(&ds->pending, idx);
        return;
    }

    log_msg(LOG_DEBUG, "DNS: %s -> async upstream %s:%u (slot %d)",
            q.qname, upstream_ip, upstream_port, idx);
}

/* Обработка ответа от upstream DNS */
static void handle_upstream_response(dns_server_t *ds, int fd)
{
    dns_pending_t *p = dns_pending_find_fd(&ds->pending, fd);
    if (!p) return;

    /* Индекс слота */
    int idx = (int)(p - ds->pending.slots);

    uint8_t resp[DNS_MAX_PACKET];
    ssize_t resp_n = recv(fd, resp, sizeof(resp), MSG_DONTWAIT);
    if (resp_n <= 2) {
        log_msg(LOG_DEBUG, "DNS: upstream пустой ответ для %s", p->qname);
        epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        dns_pending_complete(&ds->pending, idx);
        return;
    }

    /* Проверить upstream ID */
    uint16_t resp_id = ((uint16_t)resp[0] << 8) | resp[1];
    if (resp_id != p->upstream_id) {
        log_msg(LOG_DEBUG, "DNS: upstream ID mismatch (%u != %u)",
                resp_id, p->upstream_id);
        epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        dns_pending_complete(&ds->pending, idx);
        return;
    }

    /* Восстановить оригинальный client ID */
    resp[0] = (p->client_id >> 8) & 0xFF;
    resp[1] = p->client_id & 0xFF;

    /* Кэшировать ответ */
    uint32_t ttl = dns_extract_min_ttl(resp, resp_n);
    int max_ttl = ds->cfg->dns.cache_ttl_max;
    if (max_ttl > 0 && ttl > (uint32_t)max_ttl)
        ttl = max_ttl;
    dns_cache_put(&ds->cache, p->qname, p->qtype,
                  resp, resp_n, ttl);

    /* Отправить клиенту */
    if (sendto(ds->udp_fd, resp, resp_n, 0,
               (struct sockaddr *)&p->client_addr, p->client_addrlen) < 0)
        log_msg(LOG_DEBUG, "DNS: sendto клиенту: %s", strerror(errno));

    log_msg(LOG_DEBUG, "DNS: %s -> %s (ttl %u, async)",
            p->qname,
            p->action == DNS_ACTION_BYPASS ? "bypass" :
            p->action == DNS_ACTION_PROXY  ? "proxy" : "default",
            ttl);

    /* Убрать из epoll и освободить слот */
    epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    dns_pending_complete(&ds->pending, idx);
}

/* Обработка TCP DNS (accept + read + process + write + close)
 * TCP DNS остаётся синхронным — допустимо для малой нагрузки (SO_RCVTIMEO=2s). */
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

    /* TCP DNS остаётся синхронным: upstream запрос */
    uint8_t response[DNS_MAX_PACKET];
    ssize_t resp_n;

    dns_action_t action = dns_rules_match(q.qname);
    if (action == DNS_ACTION_BLOCK) {
        resp_n = dns_build_nxdomain(&q, response, sizeof(response));
    } else {
        /* Для TCP используем блокирующий upstream */
        const DnsConfig *d = &ds->cfg->dns;
        const char *server = NULL;
        uint16_t port = d->upstream_port ? d->upstream_port : 53;

        switch (action) {
        case DNS_ACTION_BYPASS:
            server = d->upstream_bypass;
            break;
        case DNS_ACTION_PROXY:
            if (d->doh_enabled && d->doh_url[0]) {
                resp_n = dns_doh_query(d, pkt, qlen, response, sizeof(response));
                goto tcp_reply;
            }
            if (d->dot_enabled && d->dot_server_ip[0]) {
                resp_n = dns_dot_query(d->dot_server_ip, d->dot_port,
                                       d->dot_sni, pkt, qlen,
                                       response, sizeof(response));
                goto tcp_reply;
            }
            server = d->upstream_proxy;
            break;
        case DNS_ACTION_DEFAULT:
        default:
            server = d->upstream_default;
            break;
        case DNS_ACTION_BLOCK:
            break;  /* уже обработано выше */
        }

        if (!server || !server[0]) {
            close(client); return;
        }
        resp_n = dns_upstream_query(server, port, pkt, qlen,
                                    response, sizeof(response), 2000);
    }

tcp_reply:
    if (resp_n > 0) {
        /* Подставить ID клиента */
        response[0] = (q.id >> 8) & 0xFF;
        response[1] = q.id & 0xFF;

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

void dns_server_handle_event(dns_server_t *ds, int fd, int master_epoll_fd)
{
    (void)master_epoll_fd;  /* сохранён в ds->master_epoll_fd при register */

    if (fd == ds->udp_fd)
        handle_udp_query(ds);
    else if (fd == ds->tcp_fd)
        handle_tcp_query(ds);
    else
        handle_upstream_response(ds, fd);
}

bool dns_server_is_pending_fd(const dns_server_t *ds, int fd)
{
    return dns_pending_find_fd(
        (dns_pending_queue_t *)&ds->pending, fd) != NULL;
}

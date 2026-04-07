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
#include "net_utils.h"
#include "phoenix.h"

#include <stdio.h>
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
            dns_pending_complete(&ds->pending, i, ds->master_epoll_fd);
    }
    async_dns_pool_free(&ds->async_pool);
    if (ds->udp_fd >= 0) { close(ds->udp_fd); ds->udp_fd = -1; }
    if (ds->tcp_fd >= 0) { close(ds->tcp_fd); ds->tcp_fd = -1; }
    dns_cache_free(&ds->cache);
    ds->initialized = false;
    log_msg(LOG_INFO, "DNS демон остановлен");
}

int dns_server_register_epoll(dns_server_t *ds, int master_epoll_fd)
{
    ds->master_epoll_fd = master_epoll_fd;
    /* Инициализировать async pool теперь когда известен master epoll fd */
    async_dns_pool_init(&ds->async_pool, master_epoll_fd);

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

/* ── Async DoH/DoT callback ── */

/* Контекст передаётся через cb_ctx, живёт до вызова callback (malloc/free) */
typedef struct {
    dns_server_t           *ds;
    struct sockaddr_storage client_addr;
    socklen_t               client_addrlen;
    dns_query_t             query;
    char                    qname[256];
    uint16_t                qtype;
} dns_async_ctx_t;

static void async_doh_dot_cb(void *ctx, const uint8_t *resp,
                              size_t resp_len, int error)
{
    dns_async_ctx_t *c = (dns_async_ctx_t *)ctx;
    if (!c) return;

    if (error == 0 && resp && resp_len >= 12) {
        uint8_t *reply = malloc(DNS_MAX_PACKET);
        if (reply) {
            int reply_len = dns_build_forward_reply(
                &c->query, resp, resp_len, reply, DNS_MAX_PACKET);
            if (reply_len > 0) {
                sendto(c->ds->udp_fd, reply, reply_len, 0,
                       (struct sockaddr *)&c->client_addr,
                       c->client_addrlen);
                uint32_t ttl = dns_extract_min_ttl(resp, resp_len);
                int max_ttl = c->ds->cfg->dns.cache_ttl_max;
                int min_ttl = c->ds->cfg->dns.cache_ttl_min;
                if (max_ttl > 0 && ttl > (uint32_t)max_ttl) ttl = (uint32_t)max_ttl;
                if (min_ttl > 0 && ttl < (uint32_t)min_ttl) ttl = (uint32_t)min_ttl;
                dns_cache_put(&c->ds->cache, c->qname, c->qtype,
                              resp, resp_len, ttl);
                log_msg(LOG_DEBUG, "DNS: %s -> async DoH/DoT (ttl %u)",
                        c->qname, ttl);
            }
            free(reply);
        }
    }
    free(c);
}

/* Блокирующий resolve — только для DoH/DoT (sync fallback) */
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

    /* Nameserver-policy: проверить до стандартного routing */
    const DnsPolicy *policy = dns_policy_match(
        ds->cfg->dns_policies,
        ds->cfg->dns_policy_count,
        q.qname);

    if (policy && policy->upstream[0]) {
        log_msg(LOG_DEBUG, "DNS: %s -> policy upstream %s (type=%d)",
                q.qname, policy->upstream, policy->type);

        uint16_t up_port = policy->port > 0
            ? policy->port
            : dns_policy_default_port(policy->type);

        if (policy->type == DNS_UPSTREAM_UDP) {
            /* UDP: через существующий pending queue */
            int idx = dns_pending_add(&ds->pending, &q, pkt, n,
                                      &client_addr, client_len,
                                      DNS_ACTION_DEFAULT,
                                      policy->upstream, up_port);
            if (idx >= 0) {
                struct epoll_event ev = {
                    .events  = EPOLLIN,
                    .data.fd = ds->pending.slots[idx].upstream_fd,
                };
                epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_ADD,
                          ds->pending.slots[idx].upstream_fd, &ev);
                return;
            }
            log_msg(LOG_WARN, "DNS policy: pending полон, fallback");
        } else if (policy->type == DNS_UPSTREAM_DOT) {
            /* DoT: async если доступен */
            DnsConfig policy_cfg = ds->cfg->dns;
            {
                size_t ulen = strlen(policy->upstream);
                if (ulen >= sizeof(policy_cfg.dot_server_ip))
                    ulen = sizeof(policy_cfg.dot_server_ip) - 1;
                memcpy(policy_cfg.dot_server_ip, policy->upstream, ulen);
                policy_cfg.dot_server_ip[ulen] = '\0';
            }
            policy_cfg.dot_port    = up_port;
            policy_cfg.dot_enabled = true;
            if (policy->sni[0])
                snprintf(policy_cfg.dot_sni,
                         sizeof(policy_cfg.dot_sni),
                         "%s", policy->sni);

            dns_async_ctx_t *ctx = malloc(sizeof(*ctx));
            if (ctx) {
                ctx->ds             = ds;
                ctx->client_addr    = client_addr;
                ctx->client_addrlen = client_len;
                ctx->query          = q;
                snprintf(ctx->qname, sizeof(ctx->qname),
                         "%s", q.qname);
                ctx->qtype = q.qtype;
                if (async_dns_dot_start(&ds->async_pool,
                                        &policy_cfg,
                                        pkt, (size_t)n, q.id,
                                        async_doh_dot_cb, ctx) == 0)
                    return;
                free(ctx);
            }
            log_msg(LOG_WARN, "DNS policy DoT: async failed, fallback");
        } else if (policy->type == DNS_UPSTREAM_DOH) {
            /* DoH: async если доступен */
            DnsConfig policy_cfg = ds->cfg->dns;
            snprintf(policy_cfg.doh_url,
                     sizeof(policy_cfg.doh_url),
                     "%s", policy->upstream);
            policy_cfg.doh_port    = up_port;
            policy_cfg.doh_enabled = true;
            if (policy->sni[0])
                snprintf(policy_cfg.doh_sni,
                         sizeof(policy_cfg.doh_sni),
                         "%s", policy->sni);
            policy_cfg.doh_ip[0] = '\0';  /* использовать URL */

            dns_async_ctx_t *ctx = malloc(sizeof(*ctx));
            if (ctx) {
                ctx->ds             = ds;
                ctx->client_addr    = client_addr;
                ctx->client_addrlen = client_len;
                ctx->query          = q;
                snprintf(ctx->qname, sizeof(ctx->qname),
                         "%s", q.qname);
                ctx->qtype = q.qtype;
                if (async_dns_doh_start(&ds->async_pool,
                                        &policy_cfg,
                                        pkt, (size_t)n, q.id,
                                        async_doh_dot_cb, ctx) == 0)
                    return;
                free(ctx);
            }
            log_msg(LOG_WARN, "DNS policy DoH: async failed, fallback");
        }
        /* Fallback: продолжаем со стандартным routing */
    }

    /* Определить action — стандартный routing */
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

    /* BYPASS домены НИКОГДА не идут через DoH/DoT proxy.
       Это предотвращает DNS утечку паттерна трафика. */
    if (action == DNS_ACTION_BYPASS) {
        if (!ds->cfg->dns.upstream_bypass[0])
            log_msg(LOG_WARN,
                "DNS: upstream_bypass не задан, "
                "RU домены могут утекать через прокси");
        goto udp_upstream;
    }

    /* DoH/DoT — только для PROXY доменов, async через pool */
    if (action == DNS_ACTION_PROXY) {
        const DnsConfig *d = &ds->cfg->dns;
        if ((d->doh_enabled && d->doh_url[0]) ||
            (d->dot_enabled && d->dot_server_ip[0])) {

            dns_async_ctx_t *ctx = malloc(sizeof(*ctx));
            if (!ctx) return;
            ctx->ds            = ds;
            ctx->client_addr   = client_addr;
            ctx->client_addrlen = client_len;
            ctx->query         = q;
            snprintf(ctx->qname, sizeof(ctx->qname), "%s", q.qname);
            ctx->qtype = q.qtype;

            /* Попробовать async DoH */
            if (d->doh_enabled && d->doh_url[0]) {
                if (async_dns_doh_start(&ds->async_pool, d, pkt, (size_t)n,
                                        q.id, async_doh_dot_cb, ctx) == 0) {
                    log_msg(LOG_DEBUG, "DNS: %s -> async DoH", q.qname);
                    return;  /* ctx освободится в callback */
                }
                log_msg(LOG_WARN,
                    "DNS: async DoH start failed (%s), пробуем DoT", q.qname);
            }

            /* Попробовать async DoT */
            if (d->dot_enabled && d->dot_server_ip[0]) {
                if (async_dns_dot_start(&ds->async_pool, d, pkt, (size_t)n,
                                        q.id, async_doh_dot_cb, ctx) == 0) {
                    log_msg(LOG_DEBUG, "DNS: %s -> async DoT", q.qname);
                    return;  /* ctx освободится в callback */
                }
                log_msg(LOG_WARN,
                    "DNS: async DoT start failed (%s), sync fallback", q.qname);
            }

            /* Sync fallback если async пул полон */
            free(ctx);
            uint8_t *response = malloc(DNS_MAX_PACKET);
            uint8_t *reply    = malloc(DNS_MAX_PACKET);
            if (!response || !reply) {
                free(response); free(reply); return;
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
                    int min_ttl = ds->cfg->dns.cache_ttl_min;
                    if (max_ttl > 0 && ttl > (uint32_t)max_ttl) ttl = (uint32_t)max_ttl;
                    if (min_ttl > 0 && ttl < (uint32_t)min_ttl) ttl = (uint32_t)min_ttl;
                    dns_cache_put(&ds->cache, q.qname, q.qtype,
                                  response, resp_n, ttl);
                    log_msg(LOG_DEBUG, "DNS: %s -> proxy/DoH sync (ttl %u)",
                            q.qname, ttl);
                }
            }
            free(response); free(reply);
            return;
        }
    }

    /* Обычный UDP upstream — неблокирующий async путь */
    udp_upstream:;
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

    /* Заполнить fallback upstream если настроен */
    {
        const char *fb = ds->cfg->dns.upstream_fallback;
        if (fb[0]) {
            size_t fblen = strlen(fb);
            if (fblen >= sizeof(ds->pending.slots[idx].fallback_ip))
                fblen = sizeof(ds->pending.slots[idx].fallback_ip) - 1;
            memcpy(ds->pending.slots[idx].fallback_ip, fb, fblen);
            ds->pending.slots[idx].fallback_ip[fblen] = '\0';
            ds->pending.slots[idx].fallback_port =
                ds->cfg->dns.upstream_port ? ds->cfg->dns.upstream_port : 53;
        }
    }

    /* Добавить upstream fd в master epoll */
    struct epoll_event ev = {
        .events  = EPOLLIN,
        .data.fd = ds->pending.slots[idx].upstream_fd,
    };
    if (epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_ADD,
                  ds->pending.slots[idx].upstream_fd, &ev) < 0) {
        log_msg(LOG_DEBUG, "DNS: epoll_ctl ADD upstream: %s", strerror(errno));
        dns_pending_complete(&ds->pending, idx, ds->master_epoll_fd);
        return;
    }

    /* Parallel query — отправить запрос одновременно на fallback */
    if (ds->cfg->dns.parallel_query && ds->cfg->dns.upstream_fallback[0]) {
        int pfd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (pfd >= 0) {
            uint16_t pport = ds->cfg->dns.upstream_port
                ? ds->cfg->dns.upstream_port : 53;
            struct sockaddr_in pa = {
                .sin_family = AF_INET,
                .sin_port   = htons(pport),
            };
            if (inet_pton(AF_INET, ds->cfg->dns.upstream_fallback,
                          &pa.sin_addr) == 1) {
                uint16_t par_id;
                if (net_random_bytes((uint8_t *)&par_id, sizeof(par_id)) < 0)
                    par_id = (uint16_t)(idx ^ (upstream_port << 8));
                /* par_pkt на heap — стек handle_udp_query уже содержит
                   pkt[4096], par_pkt[4096] + frame = риск на MIPS 8KB стеке */
                uint8_t *par_pkt = malloc(DNS_MAX_PACKET);
                if (par_pkt) {
                    memcpy(par_pkt, pkt, n);
                    par_pkt[0] = (par_id >> 8) & 0xFF;
                    par_pkt[1] = par_id & 0xFF;
                    if (sendto(pfd, par_pkt, n, 0,
                               (struct sockaddr *)&pa, sizeof(pa)) >= 0) {
                        ds->pending.slots[idx].parallel_fd = pfd;
                        ds->pending.slots[idx].parallel_upstream_id = par_id;
                        struct epoll_event pev = {
                            .events  = EPOLLIN,
                            .data.fd = pfd,
                        };
                        epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_ADD,
                                  pfd, &pev);
                        log_msg(LOG_DEBUG, "DNS: %s parallel -> %s",
                                q.qname, ds->cfg->dns.upstream_fallback);
                    } else {
                        close(pfd);
                    }
                    free(par_pkt);
                } else {
                    close(pfd);
                }
            } else {
                close(pfd);
            }
        }
    }

    log_msg(LOG_DEBUG, "DNS: %s -> async upstream %s:%u (slot %d)",
            q.qname, upstream_ip, upstream_port, idx);
}

/* Обработка ответа от upstream DNS */
static void handle_upstream_response(dns_server_t *ds, int fd)
{
    dns_pending_t *p = dns_pending_find_fd(&ds->pending, fd);
    if (!p) return;

    int idx = (int)(p - ds->pending.slots);

    /* resp — указатель, может переключиться на tcp_buf при TC retry */
    uint8_t  resp_buf[DNS_MAX_PACKET];
    uint8_t *resp   = resp_buf;
    uint8_t *tcp_buf = NULL;  /* для TC retry cleanup */

    ssize_t resp_n = recv(fd, resp_buf, sizeof(resp_buf), MSG_DONTWAIT);
    if (resp_n <= 2) {
        log_msg(LOG_DEBUG, "DNS: upstream пустой ответ для %s", p->qname);
        epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        dns_pending_complete(&ds->pending, idx, ds->master_epoll_fd);
        return;
    }

    /* M-02: базовая валидация DNS ответа */
    if (resp_n < 12) {
        log_msg(LOG_DEBUG, "DNS: upstream ответ слишком короткий (%zd)", resp_n);
        epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        dns_pending_complete(&ds->pending, idx, ds->master_epoll_fd);
        return;
    }
    if (!(resp[2] & 0x80)) {
        log_msg(LOG_DEBUG, "DNS: upstream ответ без QR=1 для %s", p->qname);
        epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        dns_pending_complete(&ds->pending, idx, ds->master_epoll_fd);
        return;
    }

    /* Проверить upstream ID — parallel query использует другой ID */
    bool from_parallel = (p->parallel_fd >= 0 && fd == p->parallel_fd);
    uint16_t expected_id = from_parallel
        ? p->parallel_upstream_id
        : p->upstream_id;
    uint16_t resp_id = ((uint16_t)resp[0] << 8) | resp[1];
    if (resp_id != expected_id) {
        log_msg(LOG_DEBUG, "DNS: upstream ID mismatch (%u != %u)",
                resp_id, expected_id);
        epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        /* Не удалять слот — ждём правильный ответ от другого fd */
        return;
    }

    /* Восстановить оригинальный client ID */
    resp[0] = (p->client_id >> 8) & 0xFF;
    resp[1] = p->client_id & 0xFF;

    /* Bogus NXDOMAIN filter: заменить redirect IP на NXDOMAIN */
    if (ds->cfg->dns.bogus_nxdomain[0] &&
        dns_is_bogus_response(ds->cfg->dns.bogus_nxdomain,
                              resp, (size_t)resp_n)) {
        log_msg(LOG_DEBUG,
            "DNS: %s -> bogus IP обнаружен, заменяем NXDOMAIN",
            p->qname);
        dns_query_t bogus_q = {
            .id    = p->client_id,
            .qtype = p->qtype,
        };
        size_t qlen = strlen(p->qname);
        if (qlen >= sizeof(bogus_q.qname))
            qlen = sizeof(bogus_q.qname) - 1;
        memcpy(bogus_q.qname, p->qname, qlen);
        bogus_q.qname[qlen] = '\0';
        uint8_t *nx = malloc(DNS_MAX_PACKET);
        if (nx) {
            int nx_len = dns_build_nxdomain(&bogus_q, nx, DNS_MAX_PACKET);
            if (nx_len > 0) {
                sendto(ds->udp_fd, nx, nx_len, 0,
                       (struct sockaddr *)&p->client_addr,
                       p->client_addrlen);
            }
            free(nx);
        }
        epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        dns_pending_complete(&ds->pending, idx, ds->master_epoll_fd);
        return;
    }

    /* TC bit (truncated) — повторить через TCP */
    if (resp_n >= 3 && (resp[2] & 0x02)) {
        log_msg(LOG_DEBUG, "DNS: %s -> TC bit, retry over TCP", p->qname);
        const DnsConfig *d = &ds->cfg->dns;
        const char *server = NULL;
        uint16_t port = d->upstream_port ? d->upstream_port : 53;
        switch (p->action) {
        case DNS_ACTION_BYPASS:  server = d->upstream_bypass;  break;
        case DNS_ACTION_PROXY:   server = d->upstream_proxy;   break;
        default:                 server = d->upstream_default; break;
        }
        if (server && server[0]) {
            tcp_buf = malloc(DNS_MAX_PACKET);
            if (tcp_buf) {
                bool tcp_ok = false;
                ssize_t tcp_n = 0;
                int tfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
                if (tfd >= 0) {
                    struct sockaddr_in taddr = {
                        .sin_family = AF_INET,
                        .sin_port   = htons(port),
                    };
                    struct timeval tv = { .tv_sec = 2 };
                    setsockopt(tfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                    setsockopt(tfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                    if (inet_pton(AF_INET, server, &taddr.sin_addr) == 1 &&
                        connect(tfd, (struct sockaddr *)&taddr,
                                sizeof(taddr)) == 0) {
                        uint8_t lbuf[2] = {
                            (uint8_t)((p->query_len >> 8) & 0xFF),
                            (uint8_t)(p->query_len & 0xFF),
                        };
                        if (send(tfd, lbuf, 2, 0) == 2 &&
                            send(tfd, p->query, p->query_len, 0)
                                == (ssize_t)p->query_len) {
                            uint8_t rlen[2];
                            if (recv(tfd, rlen, 2, MSG_WAITALL) == 2) {
                                uint16_t rsize = ((uint16_t)rlen[0] << 8)
                                                 | rlen[1];
                                if (rsize >= 12 &&
                                    rsize <= DNS_MAX_PACKET &&
                                    recv(tfd, tcp_buf, rsize,
                                         MSG_WAITALL) == rsize) {
                                    tcp_buf[0] = (p->client_id >> 8) & 0xFF;
                                    tcp_buf[1] = p->client_id & 0xFF;
                                    tcp_n  = rsize;
                                    tcp_ok = true;
                                }
                            }
                        }
                    }
                    close(tfd);
                }
                if (tcp_ok) {
                    resp   = tcp_buf;
                    resp_n = tcp_n;
                } else {
                    free(tcp_buf);
                    tcp_buf = NULL;
                }
            }
        }
    }

    /* TTL: применить min + max */
    uint32_t ttl = dns_extract_min_ttl(resp, resp_n);
    int max_ttl = ds->cfg->dns.cache_ttl_max;
    int min_ttl = ds->cfg->dns.cache_ttl_min;
    if (max_ttl > 0 && ttl > (uint32_t)max_ttl) ttl = (uint32_t)max_ttl;
    if (min_ttl > 0 && ttl < (uint32_t)min_ttl) ttl = (uint32_t)min_ttl;
    dns_cache_put(&ds->cache, p->qname, p->qtype,
                  resp, resp_n, ttl);

    /* Отправить клиенту */
    if (sendto(ds->udp_fd, resp, resp_n, 0,
               (struct sockaddr *)&p->client_addr, p->client_addrlen) < 0)
        log_msg(LOG_DEBUG, "DNS: sendto клиенту: %s", strerror(errno));

    log_msg(LOG_DEBUG, "DNS: %s -> %s (ttl %u, async%s)",
            p->qname,
            p->action == DNS_ACTION_BYPASS ? "bypass" :
            p->action == DNS_ACTION_PROXY  ? "proxy" : "default",
            ttl,
            from_parallel ? ", parallel" : "");

    /* Убрать из epoll и освободить слот */
    epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    dns_pending_complete(&ds->pending, idx, ds->master_epoll_fd);
    free(tcp_buf);  /* NULL-safe */
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

    /* M-01: буферы на heap вместо стека (12KB+ на MICRO опасно) */
    uint8_t *pkt = malloc(DNS_MAX_PACKET);
    uint8_t *response = malloc(DNS_MAX_PACKET);
    uint8_t *tcp_reply = malloc(DNS_MAX_PACKET + 2);
    if (!pkt || !response || !tcp_reply) {
        free(pkt); free(response); free(tcp_reply);
        close(client); return;
    }

    /* Читаем [2 bytes length][DNS query] */
    uint8_t len_buf[2];
    if (recv(client, len_buf, 2, MSG_WAITALL) != 2)
        goto cleanup;
    uint16_t qlen = ((uint16_t)len_buf[0] << 8) | len_buf[1];
    if (qlen < 12 || qlen > DNS_MAX_PACKET)
        goto cleanup;

    if (recv(client, pkt, qlen, MSG_WAITALL) != qlen)
        goto cleanup;

    dns_query_t q;
    if (dns_parse_query(pkt, qlen, &q) < 0)
        goto cleanup;

    /* TCP DNS остаётся синхронным: upstream запрос */
    ssize_t resp_n;

    dns_action_t action = dns_rules_match(q.qname);
    if (action == DNS_ACTION_BLOCK) {
        resp_n = dns_build_nxdomain(&q, response, DNS_MAX_PACKET);
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
                resp_n = dns_doh_query(d, pkt, qlen, response, DNS_MAX_PACKET);
                goto tcp_reply;
            }
            if (d->dot_enabled && d->dot_server_ip[0]) {
                resp_n = dns_dot_query(d->dot_server_ip, d->dot_port,
                                       d->dot_sni, pkt, qlen,
                                       response, DNS_MAX_PACKET);
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

        if (!server || !server[0])
            goto cleanup;
        resp_n = dns_upstream_query(server, port, pkt, qlen,
                                    response, DNS_MAX_PACKET, 2000);
    }

tcp_reply:
    if (resp_n > 0) {
        /* Подставить ID клиента */
        response[0] = (q.id >> 8) & 0xFF;
        response[1] = q.id & 0xFF;

        tcp_reply[0] = (resp_n >> 8) & 0xFF;
        tcp_reply[1] = resp_n & 0xFF;
        memcpy(tcp_reply + 2, response, resp_n);
        ssize_t w = write(client, tcp_reply, 2 + resp_n);
        if (w < 0)
            log_msg(LOG_DEBUG, "DNS TCP: write: %s", strerror(errno));
    }

cleanup:
    free(pkt);
    free(response);
    free(tcp_reply);
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

bool dns_server_is_async_ptr(const dns_server_t *ds, void *ptr)
{
    return async_dns_is_pool_ptr(&ds->async_pool, ptr);
}

void dns_server_handle_async_event(dns_server_t *ds, void *ptr,
                                   uint32_t events)
{
    (void)ds;
    async_dns_on_event((async_dns_conn_t *)ptr, events);
}

void dns_server_check_async_timeouts(dns_server_t *ds)
{
    async_dns_check_timeouts(&ds->async_pool);
}

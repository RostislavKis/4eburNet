/*
 * DNS сервер — UDP/TCP listener, split DNS, кэш
 * Async UDP resolver через pending queue + epoll (C-06/H-18)
 */

#include "dns/dns_server.h"
#include "dns/dns_packet.h"
#include "dns/dns_cache.h"
#include "dns/dns_rules.h"
#include "dns/dns_upstream.h"
#include "stats.h"
#include "geo/geo_loader.h"
#include "dns/dns_resolver.h"
#include "net_utils.h"
#include "4eburnet.h"
#include "resource_manager.h"
#include "device.h"

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

int dns_server_init(dns_server_t *ds, const EburNetConfig *cfg)
{
    memset(ds, 0, sizeof(*ds));
    ds->udp_fd = -1;
    ds->tcp_fd = -1;
    ds->master_epoll_fd = -1;
    ds->cfg    = cfg;

    if (!cfg->dns.enabled || cfg->dns.listen_port == 0) {
        log_msg(LOG_DEBUG, "DNS демон отключён");
        return -1;
    }

    DeviceProfile profile = rm_detect_profile();

    uint16_t port = cfg->dns.listen_port;

    /* UDP сокет */
    ds->udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (ds->udp_fd < 0) {
        log_msg(LOG_ERROR, "DNS: socket(UDP): %s", strerror(errno));
        return -1;
    }

    int yes = 1;
    if (setsockopt(ds->udp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
        log_msg(LOG_WARN, "dns: SO_REUSEADDR(UDP): %s", strerror(errno));

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

    if (setsockopt(ds->tcp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
        log_msg(LOG_WARN, "dns: SO_REUSEADDR(TCP): %s", strerror(errno));

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

    /* Rate table: heap, размер по профилю (MICRO=64, NORMAL=256, FULL=512) */
    {
        int rtsize;
        switch (profile) {
        case DEVICE_MICRO:   rtsize = DNS_RATE_TABLE_MICRO;  break;
        case DEVICE_NORMAL:  rtsize = DNS_RATE_TABLE_NORMAL; break;
        default:             rtsize = DNS_RATE_TABLE_FULL;   break;
        }
        ds->rate_table = calloc((size_t)rtsize, sizeof(dns_rate_entry_t));
        if (!ds->rate_table) {
            log_msg(LOG_ERROR, "dns_server_init: OOM rate_table");
            close(ds->udp_fd); ds->udp_fd = -1;
            close(ds->tcp_fd); ds->tcp_fd = -1;
            dns_cache_free(&ds->cache);
            return -1;
        }
        ds->rate_table_size = rtsize;
    }

    /* Pending queue: heap, capacity по профилю */
    if (dns_pending_init(&ds->pending, device_dns_pending(profile)) < 0) {
        log_msg(LOG_ERROR, "dns_server_init: OOM pending queue");
        close(ds->udp_fd); ds->udp_fd = -1;
        close(ds->tcp_fd); ds->tcp_fd = -1;
        dns_cache_free(&ds->cache);
        free(ds->rate_table); ds->rate_table = NULL;
        return -1;
    }

    /* TCP клиенты: heap, capacity по профилю */
    int tcp_cap = device_dns_tcp_clients(profile);
    ds->tcp_clients = calloc((size_t)tcp_cap, sizeof(dns_tcp_client_t));
    if (!ds->tcp_clients) {
        log_msg(LOG_ERROR, "dns_server_init: OOM tcp_clients");
        close(ds->udp_fd); ds->udp_fd = -1;
        close(ds->tcp_fd); ds->tcp_fd = -1;
        dns_cache_free(&ds->cache);
        free(ds->rate_table); ds->rate_table = NULL;
        dns_pending_free(&ds->pending);
        return -1;
    }
    ds->tcp_clients_count = tcp_cap;
    for (int i = 0; i < tcp_cap; i++) {
        ds->tcp_clients[i].active      = false;
        ds->tcp_clients[i].fd          = -1;
        ds->tcp_clients[i].pending_idx = -1;
        ds->tcp_clients[i].tx_buf      = NULL;
    }

    ds->initialized = true;
    log_msg(LOG_INFO, "DNS демон запущен на порту %u (кэш: %d)", port, cache_sz);
    return 0;
}

void dns_server_cleanup(dns_server_t *ds)
{
    /* Закрыть TCP DNS клиентов */
    for (int i = 0; i < ds->tcp_clients_count; i++) {
        dns_tcp_client_t *tc = &ds->tcp_clients[i];
        if (!tc->active) continue;
        if (ds->master_epoll_fd >= 0)
            epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, tc->fd, NULL);
        close(tc->fd);
        free(tc->tx_buf);
        tc->active = false;
        tc->fd     = -1;
        tc->tx_buf = NULL;
    }
    free(ds->tcp_clients);
    ds->tcp_clients       = NULL;
    ds->tcp_clients_count = 0;
    /* Закрыть все pending upstream сокеты */
    for (int i = 0; i < ds->pending.capacity; i++) {
        if (ds->pending.slots[i].active)
            dns_pending_complete(&ds->pending, i, ds->master_epoll_fd);
    }
    dns_pending_free(&ds->pending);
#if CONFIG_EBURNET_DOH
    async_dns_pool_free(&ds->async_pool);
#endif
#if CONFIG_EBURNET_FAKE_IP
    if (ds->fake_ip_ready) {
        fake_ip_free(&ds->fake_ip);
        ds->fake_ip_ready = false;
    }
#endif
    if (ds->udp_fd >= 0) { close(ds->udp_fd); ds->udp_fd = -1; }
    if (ds->tcp_fd >= 0) { close(ds->tcp_fd); ds->tcp_fd = -1; }
    dns_cache_free(&ds->cache);
    free(ds->rate_table);
    ds->rate_table = NULL;
    ds->rate_table_size = 0;
    ds->initialized = false;
    log_msg(LOG_INFO, "DNS демон остановлен");
}

int dns_server_register_epoll(dns_server_t *ds, int master_epoll_fd)
{
    ds->master_epoll_fd = master_epoll_fd;
#if CONFIG_EBURNET_DOH
    /* Инициализировать async pool теперь когда известен master epoll fd */
    async_dns_pool_init(&ds->async_pool, master_epoll_fd);
#endif

    /* Инициализировать fake-ip если включён */
    const DnsConfig *dcfg = &ds->cfg->dns;
#if CONFIG_EBURNET_FAKE_IP
    if (dcfg->fake_ip_enabled) {
        DeviceProfile profile = rm_detect_profile();
        int max_e = fake_ip_max_entries_for_profile(
            profile, dcfg->fake_ip_pool_size);
        const char *range = dcfg->fake_ip_range[0]
            ? dcfg->fake_ip_range : "198.51.100.0/24";
        if (fake_ip_init(&ds->fake_ip, ds->cfg,
                          range, max_e) == 0) {
            ds->fake_ip_ready = true;
            log_msg(LOG_INFO,
                "fake-ip: включён, пул %s, макс. %d записей",
                range, max_e);
        } else {
            log_msg(LOG_WARN, "fake-ip: init не удался, отключён");
        }
    }
#else
    (void)dcfg;
#endif /* CONFIG_EBURNET_FAKE_IP */

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

#if CONFIG_EBURNET_DOH
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
                if (sendto(c->ds->udp_fd, reply, reply_len, 0,
                           (struct sockaddr *)&c->client_addr,
                           c->client_addrlen) < 0)
                    log_msg(LOG_WARN, "dns: sendto (async): %s", strerror(errno));
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

#endif /* CONFIG_EBURNET_DOH */

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
    case DNS_ACTION_BLOCK:
        return false;
    case DNS_ACTION_DEFAULT:
    default:
        *out_ip = d->upstream_default;
        break;
    }

    return (*out_ip && (*out_ip)[0]);
}

/* Per-source rate limiting (H-13: DNS amplification) */
#define DNS_RATE_LIMIT  100
#define DNS_RATE_WINDOW 1

/*
 * Обработка одного UDP DNS запроса — неблокирующий async путь.
 * Почему одна функция: запрос проходит pipeline (rate-limit → cache →
 * policy → fake-ip → DoH/DoT → UDP upstream) с ранним выходом на каждом
 * этапе. Разбиение на функции усложнит передачу контекста client_addr/query.
 */
static void handle_udp_query(dns_server_t *ds)
{
    uint8_t *pkt = malloc(DNS_MAX_PACKET);
    if (!pkt) return;
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);

    ssize_t n = recvfrom(ds->udp_fd, pkt, DNS_MAX_PACKET, MSG_DONTWAIT,
                         (struct sockaddr *)&client_addr, &client_len);
    if (n <= 0)
        goto out;

    stats_dns_query();

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
    if (!ds->rate_table) goto skip_rate;
    int slot = (int)(addr_hash % (uint32_t)ds->rate_table_size);
    if (ds->rate_table[slot].addr_len == src_addr_len &&
        memcmp(ds->rate_table[slot].addr, src_addr, src_addr_len) == 0) {
        if (now_t - ds->rate_table[slot].window_start < DNS_RATE_WINDOW) {
            if (++ds->rate_table[slot].count > DNS_RATE_LIMIT) {
                log_msg(LOG_DEBUG, "DNS: rate limit (slot %d)", slot);
                goto out;
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
skip_rate:;

    dns_query_t q;
    if (dns_parse_query(pkt, n, &q) < 0) {
        log_msg(LOG_DEBUG, "DNS: невалидный запрос (%zd байт)", n);
        goto out;
    }

    log_msg(LOG_DEBUG, "DNS: запрос %s (type %u)", q.qname, q.qtype);

    /* Проверить кэш */
    uint16_t resp_len = 0;
    const uint8_t *cached = dns_cache_get(&ds->cache, q.qname, q.qtype,
                                          &resp_len, q.id);
    if (cached) {
        stats_dns_cached();
        if (sendto(ds->udp_fd, cached, resp_len, 0,
                   (struct sockaddr *)&client_addr, client_len) < 0)
            log_msg(LOG_DEBUG, "DNS: sendto (cache): %s", strerror(errno));
        log_msg(LOG_DEBUG, "DNS: %s из кэша", q.qname);
        goto out;
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
                goto out;
            }
            log_msg(LOG_WARN, "DNS policy: pending полон, fallback");
        } else if (policy->type == DNS_UPSTREAM_DOT) {
            /* DoT: async если доступен
             * B1-02: DnsConfig на heap — ~3.8KB (47% MIPS стека) */
            DnsConfig *policy_cfg = malloc(sizeof(DnsConfig));
            if (policy_cfg) {
                *policy_cfg = ds->cfg->dns;
                {
                    size_t ulen = strlen(policy->upstream);
                    if (ulen >= sizeof(policy_cfg->dot_server_ip))
                        ulen = sizeof(policy_cfg->dot_server_ip) - 1;
                    memcpy(policy_cfg->dot_server_ip, policy->upstream, ulen);
                    policy_cfg->dot_server_ip[ulen] = '\0';
                }
                policy_cfg->dot_port    = up_port;
                policy_cfg->dot_enabled = true;
                if (policy->sni[0])
                    snprintf(policy_cfg->dot_sni,
                             sizeof(policy_cfg->dot_sni),
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
                                            policy_cfg,
                                            pkt, (size_t)n, q.id,
                                            async_doh_dot_cb, ctx) == 0) {
                        free(policy_cfg);
                        goto out;
                    }
                    free(ctx);
                }
                free(policy_cfg);
            }
            log_msg(LOG_WARN, "DNS policy DoT: async failed, fallback");
        } else if (policy->type == DNS_UPSTREAM_DOH) {
            /* DoH: async если доступен
             * B1-02: DnsConfig на heap — ~3.8KB (47% MIPS стека) */
            DnsConfig *policy_cfg = malloc(sizeof(DnsConfig));
            if (policy_cfg) {
                *policy_cfg = ds->cfg->dns;
                snprintf(policy_cfg->doh_url,
                         sizeof(policy_cfg->doh_url),
                         "%s", policy->upstream);
                policy_cfg->doh_port    = up_port;
                policy_cfg->doh_enabled = true;
                if (policy->sni[0])
                    snprintf(policy_cfg->doh_sni,
                             sizeof(policy_cfg->doh_sni),
                             "%s", policy->sni);
                policy_cfg->doh_ip[0] = '\0';

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
                                            policy_cfg,
                                            pkt, (size_t)n, q.id,
                                            async_doh_dot_cb, ctx) == 0) {
                        free(policy_cfg);
                        goto out;
                    }
                    free(ctx);
                }
                free(policy_cfg);
            }
            log_msg(LOG_WARN, "DNS policy DoH: async failed, fallback");
        }
        /* Fallback: продолжаем со стандартным routing */
    }

    /* Определить action — стандартный routing */
    dns_action_t action = dns_rules_match(q.qname);

    /* BLOCK — мгновенный NXDOMAIN, без upstream */
    if (action == DNS_ACTION_BLOCK) {
        /* A3: инкремент adblock счётчика по категории */
        geo_cat_type_t bcat = ds->geo_manager
            ? geo_match_domain_cat(ds->geo_manager, q.qname)
            : GEO_CAT_GENERIC;
        switch (bcat) {
        case GEO_CAT_ADS:      stats_blocked_ads();      break;
        case GEO_CAT_TRACKERS: stats_blocked_trackers();  break;
        case GEO_CAT_THREATS:  stats_blocked_threats();   break;
        default:               stats_blocked_ads();       break;
        }
        uint8_t *reply = malloc(DNS_MAX_PACKET);
        if (!reply) goto out;
        int nx_len = dns_build_nxdomain(&q, reply, DNS_MAX_PACKET);
        if (nx_len > 0) {
            if (sendto(ds->udp_fd, reply, nx_len, 0,
                       (struct sockaddr *)&client_addr, client_len) < 0)
                log_msg(LOG_DEBUG, "DNS: sendto: %s", strerror(errno));
            log_msg(LOG_DEBUG, "DNS: %s -> NXDOMAIN (blocked, cat=%d)",
                    q.qname, bcat);
        }
        free(reply);
        goto out;
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

#if CONFIG_EBURNET_FAKE_IP
    /* Fake-IP: только для A-запросов PROXY доменов */
    if (ds->fake_ip_ready &&
        ds->cfg->dns.fake_ip_enabled &&
        action == DNS_ACTION_PROXY &&
        q.qtype == 1) {  /* QTYPE=A */

        uint32_t fake_ip_addr = fake_ip_alloc(
            &ds->fake_ip, q.qname, 0, 0);

        if (fake_ip_addr != 0) {
            uint8_t *reply = malloc(DNS_MAX_PACKET);
            if (reply) {
                int cfg_ttl = ds->cfg->dns.fake_ip_ttl;
                uint32_t ttl = (cfg_ttl > 0)
                    ? (uint32_t)cfg_ttl : 60u;
                int reply_len = dns_build_a_reply(
                    &q, fake_ip_addr, ttl,
                    reply, DNS_MAX_PACKET);
                if (reply_len > 0) {
                    dns_cache_put(&ds->cache, q.qname,
                                  q.qtype, reply,
                                  (uint16_t)reply_len, ttl);
                    if (sendto(ds->udp_fd, reply,
                               reply_len, 0,
                               (struct sockaddr *)&client_addr,
                               client_len) < 0)
                        log_msg(LOG_DEBUG,
                            "fake-ip: sendto: %s",
                            strerror(errno));
                    log_msg(LOG_DEBUG,
                        "DNS fake-ip: %s → %u.%u.%u.%u",
                        q.qname,
                        (fake_ip_addr >> 24) & 0xFF,
                        (fake_ip_addr >> 16) & 0xFF,
                        (fake_ip_addr >> 8)  & 0xFF,
                         fake_ip_addr & 0xFF);
                }
                free(reply);
            }
            goto out;  /* ответили fake IP, реальный upstream не нужен */
        }
        /* fake_ip_alloc вернул 0 — пул исчерпан, fallback реальный upstream */
        log_msg(LOG_WARN,
            "fake-ip: пул исчерпан для %s, fallback", q.qname);
    }

    /* AAAA запрос для fake-ip домена → NODATA (нет IPv6 в режиме fake-ip).
       Это предотвращает утечку доменов на реальный IPv6 upstream. */
    if (ds->fake_ip_ready &&
        ds->cfg->dns.fake_ip_enabled &&
        action == DNS_ACTION_PROXY &&
        q.qtype == 28) {  /* QTYPE=AAAA */
        /* Проверить что домен уже в fake-ip таблице
           (т.е. клиент уже получил fake A-ответ) */
        if (fake_ip_lookup_by_domain(&ds->fake_ip, q.qname) != 0) {
            uint8_t *nodata = malloc(DNS_MAX_PACKET);
            if (nodata) {
                int nd_len = dns_build_nxdomain(&q, nodata, DNS_MAX_PACKET);
                if (nd_len > 3) {
                    /* Переписать RCODE с 3 (NXDOMAIN) на 0 (NODATA) */
                    nodata[2] = 0x81;  /* QR=1 RD=1 */
                    nodata[3] = 0x80;  /* RA=1 RCODE=0 */
                    nodata[6] = 0; nodata[7] = 0;  /* ANCOUNT=0 */
                    if (sendto(ds->udp_fd, nodata, nd_len, 0,
                               (struct sockaddr *)&client_addr, client_len) < 0)
                        log_msg(LOG_WARN, "dns: sendto (NODATA): %s", strerror(errno));
                    log_msg(LOG_DEBUG, "fake-ip: %s AAAA → NODATA", q.qname);
                }
                free(nodata);
            }
            goto out;
        }
    }
#endif /* CONFIG_EBURNET_FAKE_IP */

#if CONFIG_EBURNET_DOH
    /* DoH/DoT — только для PROXY доменов, async через pool */
    if (action == DNS_ACTION_PROXY) {
        const DnsConfig *d = &ds->cfg->dns;
        if ((d->doh_enabled && d->doh_url[0]) ||
            (d->dot_enabled && d->dot_server_ip[0])) {

            dns_async_ctx_t *ctx = malloc(sizeof(*ctx));
            if (!ctx) goto out;
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
                    goto out;  /* ctx освободится в callback */
                }
                log_msg(LOG_WARN,
                    "DNS: async DoH start failed (%s), пробуем DoT", q.qname);
            }

            /* Попробовать async DoT */
            if (d->dot_enabled && d->dot_server_ip[0]) {
                if (async_dns_dot_start(&ds->async_pool, d, pkt, (size_t)n,
                                        q.id, async_doh_dot_cb, ctx) == 0) {
                    log_msg(LOG_DEBUG, "DNS: %s -> async DoT", q.qname);
                    goto out;  /* ctx освободится в callback */
                }
                log_msg(LOG_WARN,
                    "DNS: async DoT start failed (%s), dropped", q.qname);
            }

            free(ctx);
            log_msg(LOG_WARN,
                "DNS: async пул исчерпан для %s, SERVFAIL (клиент повторит)",
                q.qname);
            goto out;
        }
    }
#endif /* CONFIG_EBURNET_DOH */

    /* Обычный UDP upstream — неблокирующий async путь */
    udp_upstream:;
    const char *upstream_ip = NULL;
    uint16_t upstream_port = 53;
    if (!resolve_upstream_addr(ds, action, &upstream_ip, &upstream_port)) {
        log_msg(LOG_WARN, "DNS: upstream не настроен для action %d", action);
        goto out;
    }

    int idx = dns_pending_add(&ds->pending, &q, pkt, n,
                              &client_addr, client_len,
                              action, upstream_ip, upstream_port);
    if (idx < 0) {
        log_msg(LOG_WARN, "DNS: pending очередь полна, сброс запроса %s",
                q.qname);
        goto out;
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
        goto out;
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
out:
    free(pkt);
}

/* ── TCP DNS async state machine (audit_v9) ── */

static dns_tcp_client_t *tcp_client_alloc(dns_server_t *ds)
{
    for (int i = 0; i < ds->tcp_clients_count; i++) {
        if (!ds->tcp_clients[i].active)
            return &ds->tcp_clients[i];
    }
    return NULL;
}

static dns_tcp_client_t *tcp_client_find_fd(dns_server_t *ds, int fd)
{
    for (int i = 0; i < ds->tcp_clients_count; i++) {
        if (ds->tcp_clients[i].active && ds->tcp_clients[i].fd == fd)
            return &ds->tcp_clients[i];
    }
    return NULL;
}

static void tcp_client_close(dns_server_t *ds, dns_tcp_client_t *tc)
{
    if (!tc->active) return;
    epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, tc->fd, NULL);
    close(tc->fd);
    /* Отменить pending если был — до dns_pending_complete во избежание re-entrant */
    if (tc->pending_idx >= 0) {
        int idx = tc->pending_idx;
        int tc_idx = (int)(tc - ds->tcp_clients);
        tc->pending_idx = -1;
        dns_pending_t *p = &ds->pending.slots[idx];
        /* F2: проверяем ownership — слот мог быть реаллоцирован */
        if (p->active && p->tcp_client_idx == tc_idx)
            dns_pending_complete(&ds->pending, idx, ds->master_epoll_fd);
    }
    free(tc->tx_buf);
    tc->tx_buf     = NULL;
    tc->active     = false;
    tc->fd         = -1;
}

/* Слить буфер отправки (вызывается из EPOLLOUT или сразу после queue_response) */
static void tcp_client_send(dns_server_t *ds, dns_tcp_client_t *tc)
{
    while (tc->tx_sent < tc->tx_len) {
        ssize_t n = send(tc->fd,
                         tc->tx_buf + tc->tx_sent,
                         tc->tx_len  - tc->tx_sent,
                         MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            tcp_client_close(ds, tc);
            return;
        }
        tc->tx_sent += (size_t)n;
    }
    /* Всё отправлено — закрыть соединение */
    tcp_client_close(ds, tc);
}

/* Подготовить ответ к отправке: malloc tx_buf с length prefix, попробовать сразу */
static int tcp_client_queue_response(dns_server_t *ds, dns_tcp_client_t *tc,
                                     const uint8_t *resp, size_t resp_len)
{
    free(tc->tx_buf);
    tc->tx_buf = malloc(2 + resp_len);
    if (!tc->tx_buf) return -1;
    tc->tx_buf[0] = (resp_len >> 8) & 0xFF;
    tc->tx_buf[1] = resp_len & 0xFF;
    memcpy(tc->tx_buf + 2, resp, resp_len);
    tc->tx_len  = 2 + resp_len;
    tc->tx_sent = 0;
    tc->state   = DNS_TCP_SENDING;

    /* Попытка отправить немедленно — без ожидания EPOLLOUT */
    tcp_client_send(ds, tc);

    /* Если tc ещё жив и не всё отправлено — зарегистрировать EPOLLOUT */
    if (tc->active && tc->state == DNS_TCP_SENDING) {
        struct epoll_event ev = {
            .events  = EPOLLOUT | EPOLLET,
            .data.fd = tc->fd,
        };
        epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_MOD, tc->fd, &ev);
    }
    return 0;
}

/* Разобрать DNS запрос из rx_buf и направить в pending или ответить BLOCK */
static void tcp_client_dispatch(dns_server_t *ds, dns_tcp_client_t *tc)
{
    const uint8_t *pkt  = tc->rx_buf + 2;
    uint16_t       plen = tc->pkt_len;

    dns_query_t q;
    if (dns_parse_query(pkt, plen, &q) < 0) {
        tcp_client_close(ds, tc);
        return;
    }

    /* G1: проверить кэш — TCP клиенты тоже получают закэшированные ответы */
    {
        uint16_t cached_len = 0;
        const uint8_t *cached = dns_cache_get(&ds->cache, q.qname, q.qtype,
                                              &cached_len, q.id);
        if (cached) {
            if (tcp_client_queue_response(ds, tc, cached, cached_len) < 0)
                tcp_client_close(ds, tc);
            log_msg(LOG_DEBUG, "DNS TCP: %s из кэша", q.qname);
            return;
        }
    }

    /* G2: nameserver-policy — до стандартного routing (как в UDP пути) */
    const DnsPolicy *policy = dns_policy_match(
        ds->cfg->dns_policies,
        ds->cfg->dns_policy_count,
        q.qname);
    if (policy && policy->upstream[0] && policy->type == DNS_UPSTREAM_UDP) {
        uint16_t up_port = policy->port > 0
            ? policy->port : dns_policy_default_port(policy->type);
        int tc_idx = (int)(tc - ds->tcp_clients);
        int pidx = dns_pending_add_tcp(&ds->pending, &q, pkt, plen,
                                       DNS_ACTION_DEFAULT,
                                       policy->upstream, up_port, tc_idx);
        if (pidx >= 0) {
            tc->pending_idx = pidx;
            tc->state       = DNS_TCP_PROCESSING;
            struct epoll_event ev = {
                .events  = EPOLLIN,
                .data.fd = ds->pending.slots[pidx].upstream_fd,
            };
            epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_ADD,
                      ds->pending.slots[pidx].upstream_fd, &ev);
            log_msg(LOG_DEBUG, "DNS TCP: %s -> policy upstream %s",
                    q.qname, policy->upstream);
            return;
        }
        log_msg(LOG_WARN, "DNS TCP policy: pending полон, fallback");
    }
    /* DoT/DoH policy для TCP не поддерживается — fallback стандартный routing */

    dns_action_t action = dns_rules_match(q.qname);

    if (action == DNS_ACTION_BLOCK) {
        /* A3: adblock счётчик (TCP path) */
        geo_cat_type_t bcat = ds->geo_manager
            ? geo_match_domain_cat(ds->geo_manager, q.qname)
            : GEO_CAT_GENERIC;
        switch (bcat) {
        case GEO_CAT_ADS:      stats_blocked_ads();      break;
        case GEO_CAT_TRACKERS: stats_blocked_trackers();  break;
        case GEO_CAT_THREATS:  stats_blocked_threats();   break;
        default:               stats_blocked_ads();       break;
        }
        uint8_t *resp = malloc(DNS_MAX_PACKET);
        if (!resp) { tcp_client_close(ds, tc); return; }
        int nx_len = dns_build_nxdomain(&q, resp, DNS_MAX_PACKET);
        if (nx_len > 0) {
            if (tcp_client_queue_response(ds, tc, resp, (size_t)nx_len) < 0)
                tcp_client_close(ds, tc);
        } else {
            tcp_client_close(ds, tc);
        }
        free(resp);
        return;
    }

    const char *upstream_ip  = NULL;
    uint16_t    upstream_port = 53;
    if (!resolve_upstream_addr(ds, action, &upstream_ip, &upstream_port)) {
        tcp_client_close(ds, tc);
        return;
    }

    int tc_idx = (int)(tc - ds->tcp_clients);
    int idx = dns_pending_add_tcp(&ds->pending, &q, pkt, plen,
                                  action, upstream_ip, upstream_port, tc_idx);
    if (idx < 0) {
        log_msg(LOG_WARN, "DNS TCP: pending полон для %s", q.qname);
        tcp_client_close(ds, tc);
        return;
    }

    tc->pending_idx = idx;
    tc->state       = DNS_TCP_PROCESSING;

    /* Добавить upstream fd в master epoll */
    struct epoll_event ev = {
        .events  = EPOLLIN,
        .data.fd = ds->pending.slots[idx].upstream_fd,
    };
    epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_ADD,
              ds->pending.slots[idx].upstream_fd, &ev);
    log_msg(LOG_DEBUG, "DNS TCP: %s -> async upstream %s:%u (slot %d)",
            q.qname, upstream_ip, upstream_port, idx);
}

/* Обработать epoll событие на TCP DNS клиентском соединении */
static void handle_tcp_client_event(dns_server_t *ds, dns_tcp_client_t *tc,
                                    uint32_t events)
{
    if (tc->state == DNS_TCP_SENDING) {
        tcp_client_send(ds, tc);
        return;
    }

    if (!(events & (EPOLLIN | EPOLLHUP | EPOLLERR))) return;

    /* Дренаж приёма до EAGAIN (EPOLLET) */
    for (;;) {
        size_t target;
        if (tc->state == DNS_TCP_READING_LEN)
            target = 2;
        else if (tc->state == DNS_TCP_READING_PKT)
            target = 2 + (size_t)tc->pkt_len;
        else {
            /* F3: клиент разорвал соединение пока ждём upstream */
            if (events & (EPOLLHUP | EPOLLERR))
                tcp_client_close(ds, tc);
            return;
        }

        size_t to_read = target - tc->rx_len;
        if (to_read == 0) break;

        ssize_t n = recv(tc->fd, tc->rx_buf + tc->rx_len,
                         to_read, MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            tcp_client_close(ds, tc);
            return;
        }
        if (n == 0) {
            tcp_client_close(ds, tc);
            return;
        }
        tc->rx_len += (size_t)n;

        if (tc->state == DNS_TCP_READING_LEN && tc->rx_len == 2) {
            uint16_t plen = ((uint16_t)tc->rx_buf[0] << 8) | tc->rx_buf[1];
            if (plen < 12 || plen > DNS_MAX_PACKET) {
                tcp_client_close(ds, tc);
                return;
            }
            tc->pkt_len = plen;
            tc->state   = DNS_TCP_READING_PKT;
            continue;
        }

        if (tc->state == DNS_TCP_READING_PKT &&
            tc->rx_len == (size_t)(2 + tc->pkt_len)) {
            tcp_client_dispatch(ds, tc);
            return;
        }
    }
}

/* Принять новое TCP DNS соединение и разместить в свободный слот */
static void accept_tcp_client(dns_server_t *ds)
{
    int fd = accept4(ds->tcp_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) return;

    dns_tcp_client_t *tc = tcp_client_alloc(ds);
    if (!tc) {
        /* Нет свободных слотов */
        log_msg(LOG_DEBUG, "DNS TCP: нет свободных слотов (max %d)",
                ds->tcp_clients_count);
        close(fd);
        return;
    }

    tc->fd          = fd;
    tc->state       = DNS_TCP_READING_LEN;
    tc->rx_len      = 0;
    tc->pkt_len     = 0;
    tc->pending_idx = -1;
    tc->tx_buf      = NULL;
    tc->tx_len      = 0;
    tc->tx_sent     = 0;
    clock_gettime(CLOCK_MONOTONIC, &tc->accepted_at);

    struct epoll_event ev = {
        .events  = EPOLLIN | EPOLLET,
        .data.fd = fd,
    };
    if (epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        close(fd);
        return;
    }
    tc->active = true;
    log_msg(LOG_DEBUG, "DNS TCP: новое соединение fd=%d", fd);
}

/* Обработка ответа от upstream DNS */
static void handle_upstream_response(dns_server_t *ds, int fd)
{
    dns_pending_t *p = dns_pending_find_fd(&ds->pending, fd);
    if (!p) return;

    int idx = (int)(p - ds->pending.slots);

    /* resp — указатель, может переключиться на tcp_buf при TC retry */
    uint8_t *resp_buf = malloc(DNS_MAX_PACKET);
    if (!resp_buf) return;
    uint8_t *resp   = resp_buf;
    uint8_t *tcp_buf = NULL;  /* для TC retry cleanup */

    ssize_t resp_n = recv(fd, resp_buf, DNS_MAX_PACKET, MSG_DONTWAIT);
    if (resp_n <= 2) {
        log_msg(LOG_DEBUG, "DNS: upstream пустой ответ для %s", p->qname);
        epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        dns_pending_complete(&ds->pending, idx, ds->master_epoll_fd);
        goto out_resp;
    }

    /* M-02: базовая валидация DNS ответа */
    if (resp_n < 12) {
        log_msg(LOG_DEBUG, "DNS: upstream ответ слишком короткий (%zd)", resp_n);
        epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        dns_pending_complete(&ds->pending, idx, ds->master_epoll_fd);
        goto out_resp;
    }
    if (!(resp[2] & 0x80)) {
        log_msg(LOG_DEBUG, "DNS: upstream ответ без QR=1 для %s", p->qname);
        epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        dns_pending_complete(&ds->pending, idx, ds->master_epoll_fd);
        goto out_resp;
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
        goto out_resp;
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
                if (p->tcp_client_idx >= 0 &&
                    p->tcp_client_idx < ds->tcp_clients_count) {
                    dns_tcp_client_t *tc = &ds->tcp_clients[p->tcp_client_idx];
                    if (tc->active) {
                        tc->pending_idx = -1;
                        if (tcp_client_queue_response(ds, tc, nx,
                                                      (size_t)nx_len) < 0)
                            tcp_client_close(ds, tc);
                    }
                } else {
                    if (sendto(ds->udp_fd, nx, nx_len, 0,
                               (struct sockaddr *)&p->client_addr,
                               p->client_addrlen) < 0)
                        log_msg(LOG_WARN, "dns: sendto (parallel): %s", strerror(errno));
                }
            }
            free(nx);
        }
        epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        dns_pending_complete(&ds->pending, idx, ds->master_epoll_fd);
        goto out_resp;
    }

    /* TC bit (truncated) — TCP retry отключён (audit_v9: блокирует event loop).
     * Клиент повторит через UDP с EDNS0 буфером. */
    if (resp_n >= 3 && (resp[2] & 0x02)) {
        log_msg(LOG_DEBUG, "DNS: %s -> TC bit (retry отключён)", p->qname);
    }

    /* TTL: применить min + max */
    uint32_t ttl = dns_extract_min_ttl(resp, resp_n);
    int max_ttl = ds->cfg->dns.cache_ttl_max;
    int min_ttl = ds->cfg->dns.cache_ttl_min;
    if (max_ttl > 0 && ttl > (uint32_t)max_ttl) ttl = (uint32_t)max_ttl;
    if (min_ttl > 0 && ttl < (uint32_t)min_ttl) ttl = (uint32_t)min_ttl;
    dns_cache_put(&ds->cache, p->qname, p->qtype,
                  resp, resp_n, ttl);

    /* Отправить клиенту — UDP или TCP */
    if (p->tcp_client_idx >= 0 &&
        p->tcp_client_idx < ds->tcp_clients_count) {
        dns_tcp_client_t *tc = &ds->tcp_clients[p->tcp_client_idx];
        if (tc->active) {
            tc->pending_idx = -1;
            if (tcp_client_queue_response(ds, tc, resp, (size_t)resp_n) < 0)
                tcp_client_close(ds, tc);
        }
    } else {
        if (sendto(ds->udp_fd, resp, resp_n, 0,
                   (struct sockaddr *)&p->client_addr, p->client_addrlen) < 0)
            log_msg(LOG_DEBUG, "DNS: sendto клиенту: %s", strerror(errno));
    }

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
out_resp:
    free(resp_buf);
}

void dns_server_handle_event(dns_server_t *ds, int fd, int master_epoll_fd,
                             uint32_t events)
{
    (void)master_epoll_fd;  /* сохранён в ds->master_epoll_fd при register */

    if (fd == ds->udp_fd) {
        handle_udp_query(ds);
    } else if (fd == ds->tcp_fd) {
        accept_tcp_client(ds);
    } else {
        dns_tcp_client_t *tc = tcp_client_find_fd(ds, fd);
        if (tc)
            handle_tcp_client_event(ds, tc, events);
        else
            handle_upstream_response(ds, fd);
    }
}

bool dns_server_is_pending_fd(const dns_server_t *ds, int fd)
{
    if (dns_pending_find_fd((dns_pending_queue_t *)&ds->pending, fd) != NULL)
        return true;
    /* TCP клиентские fds тоже маршрутизируются через dns_server_handle_event */
    for (int i = 0; i < ds->tcp_clients_count; i++) {
        if (ds->tcp_clients[i].active && ds->tcp_clients[i].fd == fd)
            return true;
    }
    return false;
}

void dns_server_check_pending_timeouts(dns_server_t *ds)
{
#define DNS_TIMEOUT_SEC 2
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    for (int i = 0; i < ds->pending.capacity; i++) {
        dns_pending_t *p = &ds->pending.slots[i];
        if (!p->active) continue;

        long elapsed = now.tv_sec - p->sent_at.tv_sec;
        if (!(elapsed > DNS_TIMEOUT_SEC ||
              (elapsed == DNS_TIMEOUT_SEC &&
               now.tv_nsec >= p->sent_at.tv_nsec)))
            continue;

        /* Попробовать fallback если не использовали */
        if (!p->fallback_used && p->fallback_ip[0]) {
            int ffd = socket(AF_INET,
                             SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (ffd >= 0) {
                struct sockaddr_in fa = {
                    .sin_family = AF_INET,
                    .sin_port   = htons(p->fallback_port),
                };
                if (inet_pton(AF_INET, p->fallback_ip,
                              &fa.sin_addr) == 1 &&
                    sendto(ffd, p->query, p->query_len, 0,
                           (struct sockaddr *)&fa, sizeof(fa)) >= 0) {
                    epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL,
                              p->upstream_fd, NULL);
                    close(p->upstream_fd);
                    p->upstream_fd   = ffd;
                    p->fallback_fd   = -1;
                    p->fallback_used = true;
                    clock_gettime(CLOCK_MONOTONIC, &p->sent_at);
                    struct epoll_event ev = {
                        .events  = EPOLLIN,
                        .data.fd = ffd,
                    };
                    epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_ADD,
                              ffd, &ev);
                    log_msg(LOG_DEBUG,
                        "DNS: %s timeout, retry via fallback %s",
                        p->qname, p->fallback_ip);
                    continue;
                }
                close(ffd);
            }
        }

        log_msg(LOG_DEBUG, "DNS: upstream timeout для %s", p->qname);
        epoll_ctl(ds->master_epoll_fd, EPOLL_CTL_DEL,
                  p->upstream_fd, NULL);

        /* DEBT-2: TCP клиент получает SERVFAIL немедленно */
        if (p->tcp_client_idx >= 0 &&
            p->tcp_client_idx < ds->tcp_clients_count) {
            dns_tcp_client_t *tc = &ds->tcp_clients[p->tcp_client_idx];
            if (tc->active && tc->pending_idx == i) {
                tc->pending_idx = -1;
                dns_query_t sfq = { .id = p->client_id, .qtype = p->qtype };
                size_t qlen = strlen(p->qname);
                if (qlen >= sizeof(sfq.qname))
                    qlen = sizeof(sfq.qname) - 1;
                memcpy(sfq.qname, p->qname, qlen);
                sfq.qname[qlen] = '\0';
                uint8_t *sf = malloc(DNS_MAX_PACKET);
                if (sf) {
                    int sf_len = dns_build_servfail(&sfq,
                                                    sf, DNS_MAX_PACKET);
                    if (sf_len > 0)
                        tcp_client_queue_response(ds, tc, sf,
                                                  (size_t)sf_len);
                    else
                        tcp_client_close(ds, tc);
                    free(sf);
                } else {
                    tcp_client_close(ds, tc);
                }
            }
        }

        dns_pending_complete(&ds->pending, i, ds->master_epoll_fd);
    }
#undef DNS_TIMEOUT_SEC
}

void dns_server_check_tcp_timeouts(dns_server_t *ds)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    for (int i = 0; i < ds->tcp_clients_count; i++) {
        dns_tcp_client_t *tc = &ds->tcp_clients[i];
        if (!tc->active) continue;
        long elapsed = now.tv_sec - tc->accepted_at.tv_sec;
        if (elapsed >= 5) {
            log_msg(LOG_DEBUG, "DNS TCP: клиент [%d] таймаут 5с, закрываем", i);
            tcp_client_close(ds, tc);
        }
    }
}

#if CONFIG_EBURNET_DOH
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
#endif /* CONFIG_EBURNET_DOH */

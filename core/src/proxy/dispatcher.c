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
#include "constants.h"
#include "stats.h"
#if CONFIG_EBURNET_VLESS
#include "proxy/protocols/vless.h"
#include "proxy/protocols/vless_xhttp.h"
#include "proxy/protocols/vision.h"
#include "proxy/protocols/grpc.h"
#include "proxy/protocols/ws_client.h"
#include "proxy/protocols/http_upgrade.h"
#include "crypto/reality/reality_conn.h"
#include "crypto/reality/reality_auth.h"
#endif
#if CONFIG_EBURNET_TROJAN
#include "proxy/protocols/trojan.h"
#endif
#if CONFIG_EBURNET_SS
#include "proxy/protocols/shadowsocks.h"
#endif
#if CONFIG_EBURNET_AWG
#include "proxy/protocols/awg.h"
#endif
#if CONFIG_EBURNET_QUIC
#include "proxy/hysteria2.h"
#endif
#include "proxy/rules_engine.h"
#include "proxy/proxy_group.h"
#if CONFIG_EBURNET_SNIFFER
#include "proxy/sniffer.h"
#include "proxy/ja3.h"
#endif
#if CONFIG_EBURNET_DPI
#include "dpi/dpi_filter.h"
#include "dpi/dpi_strategy.h"
#include "dpi/dpi_adapt.h"
#endif
#include "crypto/tls.h"
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "net_utils.h"
#include "4eburnet.h"
#include "resource_manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* Runtime лимиты по mem_tier (G15-2). Default = LOW значения,
 * mem_tier_init() через main() переустановит до event loop. */
unsigned g_dispatcher_max_events = 8;
unsigned g_relay_drain_per_call  = 4;

/* Compile-time максимум для статических массивов epoll_event[].
 * Runtime берёт min(g_dispatcher_max_events, DISPATCHER_MAX_EVENTS_CAP). */
#define DISPATCHER_MAX_EVENTS_CAP   64

/* Таймаут бездействия (секунды). 30с — компромисс: Telegram WebSocket
 * keepalive обычно 15-30с (PING fгname) → не убивает чаты, но избавляется от
 * зомби-сессий (Canada Trojan видел 362с lifetime out=0).
 * При жалобах "Telegram пропадает" — поднять до 45-60с. */
#define RELAY_TIMEOUT_SEC           30
#define RELAY_HALF_CLOSE_TIMEOUT    10  /* half-close ещё короче */
/* MIPS MT7621A: Curve25519 ~10-15 мс без аппаратного ускорения →
 * не более 2 Reality handshake за один dispatcher_tick (~10 мс). */
#define REALITY_HS_PER_TICK         2u

/* WHY: глобальный лимит одновременных Reality HS (все архитектуры).
 * YouTube burst: 8 соединений одновременно → 8×keygen = 3.5s dispatcher stall.
 * Лимит 2 = keygen суммарно ≤30ms при уже начатых HS не блокируют. */
#define REALITY_HS_MAX_CONCURRENT   2u
static uint32_t s_reality_hs_active = 0;

/* Лимит retry per tick — предотвращает N×upstream_connect burst при HC batch + retry chain */
static int s_retries_this_tick = 0;

/* Частота проверки таймаутов (раз в N тиков) */
#define RELAY_TIMEOUT_CHECK     100

/* При провале HS пытаемся переключиться на следующий сервер в группе (до 3 раз).
 * Если retry невозможен или exhausted — освобождаем relay полностью. */
#define RELAY_FAIL_OR_RETRY(ds, r) \
    do { \
        if (relay_try_retry((ds), (r)) == 0) return; \
        relay_free((ds), (r)); \
        return; \
    } while (0)

/* Размер static resolve cache для gs=NULL call sites */
#define GLOBAL_RESOLVE_CACHE    4

/* splice удалён: shared pipe = data corruption (H-12, C-05) */

/* ------------------------------------------------------------------ */
/*  Глобальный контекст (handle_conn вызывается без аргумента ds)      */
/* ------------------------------------------------------------------ */

/* DEC-032: глобальный контекст g_dispatcher/g_config.
 * Текущая однопоточная epoll архитектура делает это безопасным.
 * Рефакторинг запланирован в v2.0 при переходе на io_uring. */
#if CONFIG_EBURNET_STLS
#include <wolfssl/options.h>
#include <wolfssl/error-ssl.h>

/* Буфер для приёма ShadowTLS wrapped records в wolfSSL recv callback.
 * TLS record максимум = TLS_RECORD_HDR(5) + 16383 = 16388 байт.
 * Для VLESS/Trojan wolfSSL по умолчанию ≤ 4096 байт.
 * При переполнении: rbuf_len == STLS_IO_RBUF_SIZE && rec_sz < 0 → ERR_GENERAL. */
#define STLS_IO_RBUF_SIZE  4096

/* wolfSSL I/O context для ShadowTLS transport */
typedef struct {
    shadowtls_ctx_t *stls;
    int              fd;
    uint8_t          rbuf[STLS_IO_RBUF_SIZE];
    int              rbuf_len;
} stls_io_ctx_t;
#endif /* CONFIG_EBURNET_STLS */

/*
 * dispatcher_resolve_server — resolve upstream сервера с TTL-кэшем и
 * fallback-цепочкой. DEC-031 production-grade замена net_resolve_host в
 * dispatcher call sites.
 *
 * Решает:
 *   1. Рекурсию libc getaddrinfo → /etc/resolv.conf → 127.0.0.1 →
 *      (никого / 4eburnetd сам): net_resolve_host_direct идёт на
 *      cfg->dns.upstream_bypass / upstream_default напрямую через UDP.
 *   2. Re-resolve на каждый relay: per-server кэш с TTL в
 *      group_server_state_t (family != 0 && resolved_until > now).
 *   3. Единичный upstream fail: primary (upstream_bypass) →
 *      fallback (upstream_default). Failure не кэшируется чтобы
 *      следующий relay попробовал заново.
 *
 * Fast path: address — literal IPv4/IPv6 → inet_pton, без DNS.
 * Cache path: gs != NULL && valid → copy из gs, без DNS.
 * Resolve path: direct UDP к UCI upstreams, на success кэшируем в gs.
 *
 * @param server    UCI ServerConfig snapshot (immutable).
 * @param cfg       EburNetConfig для dns.upstream_bypass / _default /
 *                  resolve_ttl. MUST NOT be NULL.
 * @param gs        group_server_state_t для кэша. NULL → без кэша
 *                  (ad-hoc resolve, напр. для провайдерских серверов
 *                  вне пула группы).
 * @param out_ip    [INET6_ADDRSTRLEN] буфер для результата.
 * @param out_size  размер out_ip.
 * @param out_family AF_INET или AF_INET6 (writable).
 *
 * @return 0 — success; -1 — total failure (оба upstream недоступны).
 */
static int dispatcher_resolve_server(const ServerConfig *server,
                                     const EburNetConfig *cfg,
                                     group_server_state_t *gs,
                                     char *out_ip, size_t out_size,
                                     int *out_family)
{
    if (!server || !cfg || !out_ip ||
        out_size < INET6_ADDRSTRLEN || !out_family) {
        return -1;
    }

    /* Fast path: literal IPv4. */
    struct in_addr v4;
    if (inet_pton(AF_INET, server->address, &v4) == 1) {
        snprintf(out_ip, out_size, "%s", server->address);
        *out_family = AF_INET;
        return 0;
    }
    /* Fast path: literal IPv6 (без скобок — net_resolve_host_direct
     * обрабатывает [addr] форму сам). */
    struct in6_addr v6;
    if (inet_pton(AF_INET6, server->address, &v6) == 1) {
        snprintf(out_ip, out_size, "%s", server->address);
        *out_family = AF_INET6;
        return 0;
    }

    /* Cache path (gs-based). */
    if (gs && gs->resolved_family != 0 &&
        gs->resolved_until > time(NULL)) {
        snprintf(out_ip, out_size, "%s", gs->resolved_ip);
        *out_family = gs->resolved_family;
        return 0;
    }

    /* Fallback static cache для gs=NULL call sites (upstream_connect).
     * WHY: без gs каждый новый relay вызывает net_resolve_host_direct
     * (~20ms–3s блокировки) → main epoll loop не успевает дренировать DNS
     * recv-Q → 181KB backlog → полная остановка под iOS burst. */
    static struct {
        char   addr[256];
        char   ip[64];
        int    family;
        time_t until;
    } s_global_resolve[GLOBAL_RESOLVE_CACHE];

    if (!gs) {
        time_t _now = time(NULL);
        for (int _i = 0; _i < GLOBAL_RESOLVE_CACHE; _i++) {
            if (s_global_resolve[_i].addr[0] &&
                strcmp(s_global_resolve[_i].addr, server->address) == 0 &&
                s_global_resolve[_i].until > _now) {
                snprintf(out_ip, out_size, "%s", s_global_resolve[_i].ip);
                *out_family = s_global_resolve[_i].family;
                return 0;
            }
        }
    }

    /* Resolve chain: upstream_bypass → upstream_default.
     * Failure НЕ кэшируем чтобы не застрять до истечения TTL. */
    const char *dns_primary =
        (cfg->dns.upstream_bypass[0]) ? cfg->dns.upstream_bypass : NULL;
    const char *dns_fallback =
        (cfg->dns.upstream_default[0]) ? cfg->dns.upstream_default : NULL;

    int rc = -1;
    const char *used_dns = NULL;
    if (dns_primary) {
        rc = net_resolve_host_direct(server->address, dns_primary,
                                     out_ip, out_size, out_family);
        if (rc == 0) used_dns = dns_primary;
    }
    if (rc != 0 && dns_fallback &&
        (dns_primary == NULL || strcmp(dns_primary, dns_fallback) != 0)) {
        log_msg(LOG_WARN,
                "dispatcher_resolve: %s via %s failed, fallback to %s",
                server->address,
                dns_primary ? dns_primary : "(none)",
                dns_fallback);
        rc = net_resolve_host_direct(server->address, dns_fallback,
                                     out_ip, out_size, out_family);
        if (rc == 0) used_dns = dns_fallback;
    }

    if (rc != 0) {
        log_msg(LOG_ERROR,
                "dispatcher_resolve: %s: все upstream DNS недоступны",
                server->address);
        return -1;
    }

    /* Cache success. TTL default=3600 (1ч) если UCI resolve_ttl не задано.
     * WHY 3600: серверы провайдеров (xxee.ru) меняют IP редко. Pre-warm
     * на старте + длинный TTL = почти всегда cache hit, не блокируем event
     * loop через blocking UDP recv в hot path. */
    uint32_t ttl = cfg->dns.resolve_ttl ? cfg->dns.resolve_ttl : 3600;
    if (gs) {
        snprintf(gs->resolved_ip, sizeof(gs->resolved_ip), "%s", out_ip);
        gs->resolved_family = *out_family;
        gs->resolved_until  = time(NULL) + (time_t)ttl;
    } else {
        /* Сохраняем в static cache: вытесняем oldest или первый пустой слот. */
        time_t _now = time(NULL);
        int _slot = 0;
        time_t _oldest = s_global_resolve[0].until;
        for (int _i = 1; _i < GLOBAL_RESOLVE_CACHE; _i++) {
            if (!s_global_resolve[_i].addr[0]) { _slot = _i; goto _save; }
            if (s_global_resolve[_i].until < _oldest) {
                _oldest = s_global_resolve[_i].until;
                _slot = _i;
            }
        }
        _save:
        snprintf(s_global_resolve[_slot].addr,
                 sizeof(s_global_resolve[_slot].addr), "%s", server->address);
        snprintf(s_global_resolve[_slot].ip,
                 sizeof(s_global_resolve[_slot].ip), "%s", out_ip);
        s_global_resolve[_slot].family = *out_family;
        s_global_resolve[_slot].until  = _now + (time_t)ttl;
    }

    log_msg(LOG_INFO,
            "dispatcher_resolve: %s -> %s (via %s, cached=%s)",
            server->address, out_ip,
            used_dns ? used_dns : "?",
            gs ? "yes" : "no");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  dispatcher_prewarm_resolve — резолвить все upstream при старте      */
/* ------------------------------------------------------------------ */
/*
 * WHY: net_resolve_host_direct делает блокирующий UDP recv с SO_RCVTIMEO=1с.
 * Когда dispatcher_resolve_server попадает в cache miss (первый relay через
 * каждый сервер), recv() блокирует epoll loop на 100-1000ms → dispatcher_tick
 * выходит за порог 100ms → весь throughput всех relay стоит. Наблюдалось
 * dispatcher_tick=1041мс при 21 cached=no resolve за 9 минут.
 *
 * Pre-warm проходит по всем gs->servers[] один раз при старте, синхронно
 * резолвит уникальные hostnames через primary upstream и заполняет
 * gs->resolved_ip/family/until. Блокирует на N×~100ms один раз. После —
 * hot path всегда cache hit, recv() не вызывается из event loop.
 */
void dispatcher_prewarm_resolve(proxy_group_manager_t *pgm,
                                const EburNetConfig *cfg)
{
    if (!pgm || !cfg) return;

    /* Дедуп уникальных hostnames через локальный массив. */
    struct seen_entry { char host[128]; char ip[INET6_ADDRSTRLEN]; int family; };
    struct seen_entry seen[64];
    int seen_count = 0;

    int total_resolved = 0, total_literal = 0, total_failed = 0;
    uint32_t ttl = cfg->dns.resolve_ttl ? cfg->dns.resolve_ttl : 3600;
    time_t until = time(NULL) + (time_t)ttl;

    const char *dns_primary = cfg->dns.upstream_bypass[0]
                              ? cfg->dns.upstream_bypass : NULL;
    const char *dns_fallback = cfg->dns.upstream_default[0]
                               ? cfg->dns.upstream_default : NULL;

    for (int g = 0; g < pgm->count; g++) {
        proxy_group_state_t *gs = &pgm->groups[g];
        for (int i = 0; i < gs->server_count; i++) {
            const ServerConfig *sc = config_get_server(cfg, gs->servers[i].server_idx);
            if (!sc || !sc->address[0]) continue;

            /* Литерал IP — заполнить кэш мгновенно */
            struct in_addr a4;
            struct in6_addr a6;
            if (inet_pton(AF_INET, sc->address, &a4) == 1) {
                snprintf(gs->servers[i].resolved_ip,
                         sizeof(gs->servers[i].resolved_ip), "%s", sc->address);
                gs->servers[i].resolved_family = AF_INET;
                gs->servers[i].resolved_until  = until;
                total_literal++;
                continue;
            }
            if (inet_pton(AF_INET6, sc->address, &a6) == 1) {
                snprintf(gs->servers[i].resolved_ip,
                         sizeof(gs->servers[i].resolved_ip), "%s", sc->address);
                gs->servers[i].resolved_family = AF_INET6;
                gs->servers[i].resolved_until  = until;
                total_literal++;
                continue;
            }

            /* Look in seen-cache */
            int seen_idx = -1;
            for (int s = 0; s < seen_count; s++) {
                if (strcmp(seen[s].host, sc->address) == 0) {
                    seen_idx = s; break;
                }
            }

            char ip[INET6_ADDRSTRLEN];
            int family = 0;

            if (seen_idx >= 0) {
                snprintf(ip, sizeof(ip), "%s", seen[seen_idx].ip);
                family = seen[seen_idx].family;
            } else {
                int rc = -1;
                if (dns_primary)
                    rc = net_resolve_host_direct(sc->address, dns_primary,
                                                  ip, sizeof(ip), &family);
                if (rc != 0 && dns_fallback &&
                    (!dns_primary || strcmp(dns_primary, dns_fallback) != 0))
                    rc = net_resolve_host_direct(sc->address, dns_fallback,
                                                  ip, sizeof(ip), &family);
                if (rc != 0) { total_failed++; continue; }

                if (seen_count < 64) {
                    snprintf(seen[seen_count].host,
                             sizeof(seen[seen_count].host), "%s", sc->address);
                    snprintf(seen[seen_count].ip,
                             sizeof(seen[seen_count].ip), "%s", ip);
                    seen[seen_count].family = family;
                    seen_count++;
                }
                total_resolved++;
            }

            snprintf(gs->servers[i].resolved_ip,
                     sizeof(gs->servers[i].resolved_ip), "%s", ip);
            gs->servers[i].resolved_family = family;
            gs->servers[i].resolved_until  = until;
        }
    }

    log_msg(LOG_INFO,
        "dispatcher: pre-resolve %d hostnames, %d literal IPs, %d failed (ttl=%us)",
        total_resolved, total_literal, total_failed, ttl);

    /* Второй проход: hot path в xhttp_protocol_start / upstream_connect
     * вызывает dispatcher_resolve_server(... gs=NULL ...) — этот call site
     * использует ОТДЕЛЬНЫЙ s_global_resolve static cache. Без warming его
     * первый relay через каждый сервер всё равно блокирует event loop.
     * Прогоняем dispatcher_resolve_server для каждого уникального hostname
     * — он сам заполнит s_global_resolve (cached=yes на all subsequent calls). */
    int gcache_warmed = 0;
    for (int s = 0; s < seen_count; s++) {
        /* Минимальный фейковый ServerConfig для resolve. */
        ServerConfig fake;
        memset(&fake, 0, sizeof(fake));
        snprintf(fake.address, sizeof(fake.address), "%s", seen[s].host);
        char ip[INET6_ADDRSTRLEN];
        int family = 0;
        if (dispatcher_resolve_server(&fake, cfg, NULL, ip, sizeof(ip), &family) == 0)
            gcache_warmed++;
    }
    log_msg(LOG_INFO,
        "dispatcher: global resolve cache warmed for %d/%d hostnames",
        gcache_warmed, seen_count);
}

#if CONFIG_EBURNET_STLS
/* wolfSSL send callback: wrap через ShadowTLS.
 * Сигнатура: int (*)(void*, char*, int, void*) — совместима с CallbackIOSend
 * (WOLFSSL* ≡ void* на ABI уровне). */
static int stls_ssl_send(void *ssl, char *buf, int sz, void *ctx)
{
    (void)ssl;
    stls_io_ctx_t *io = (stls_io_ctx_t *)ctx;
    /* Malloc необходим: stls_buf из dispatcher_state_t
     * недоступен из wolfSSL I/O callback context.
     * Для SS (use_tls=false) wrap использует stls_buf без malloc. */
    uint8_t *tmp = malloc((size_t)sz + 9);
    if (!tmp) return WOLFSSL_CBIO_ERR_GENERAL;
    int wlen = stls_wrap(io->stls, (const uint8_t *)buf, sz, tmp, sz + 9);
    if (wlen < 0) { free(tmp); return WOLFSSL_CBIO_ERR_GENERAL; }
    ssize_t s = send(io->fd, tmp, (size_t)wlen, MSG_NOSIGNAL);
    free(tmp);
    if (s < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        return WOLFSSL_CBIO_ERR_CONN_RST;
    }
    return sz;
}

/* wolfSSL recv callback: unwrap ShadowTLS record */
static int stls_ssl_recv(void *ssl, char *buf, int sz, void *ctx)
{
    (void)ssl;
    stls_io_ctx_t *io = (stls_io_ctx_t *)ctx;

    /* Читаем данные в rbuf если есть место */
    int space = (int)sizeof(io->rbuf) - io->rbuf_len;
    if (space > 0) {
        ssize_t n = recv(io->fd, io->rbuf + io->rbuf_len,
                         (size_t)space, MSG_DONTWAIT);
        if (n > 0) {
            io->rbuf_len += (int)n;
        } else if (n == 0) {
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return WOLFSSL_CBIO_ERR_CONN_RST;
        }
    }

    /* Полная STLS запись? */
    int rec_sz = stls_record_size(io->rbuf, io->rbuf_len);
    if (rec_sz < 0) {
        /* rbuf полон но неполная запись — протокольная ошибка */
        if (io->rbuf_len >= STLS_IO_RBUF_SIZE)
            return WOLFSSL_CBIO_ERR_GENERAL;
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }

    /* Unwrap */
    int ulen = stls_unwrap(io->stls, io->rbuf, rec_sz,
                            (uint8_t *)buf, sz);
    /* Убрать запись из rbuf */
    io->rbuf_len -= rec_sz;
    if (io->rbuf_len > 0)
        memmove(io->rbuf, io->rbuf + rec_sz, (size_t)io->rbuf_len);

    if (ulen < 0) return WOLFSSL_CBIO_ERR_GENERAL;
    return (ulen > 0) ? ulen : WOLFSSL_CBIO_ERR_WANT_READ;
}
#endif /* CONFIG_EBURNET_STLS */

static dispatcher_state_t *g_dispatcher   = NULL;
static const EburNetConfig *g_config      = NULL;
static rules_engine_t     *g_rules_engine = NULL;
#if CONFIG_EBURNET_DPI
/* Глобальный кэш адаптивных DPI стратегий */
DpiAdaptTable g_dpi_adapt;
#endif
#if CONFIG_EBURNET_FAKE_IP
static fake_ip_table_t    *g_fake_ip      = NULL;
#endif
static device_manager_t        *g_dm           = NULL;
static proxy_group_manager_t   *g_pgm          = NULL;
#if CONFIG_EBURNET_SNIFFER
/* Последний вычисленный JA3 хэш — для /api/status */
static char g_last_ja3[33] = {0};
#endif

/* Метрики диспетчера (экспортируются через dispatcher.h) */
atomic_uint g_dispatcher_tick_us = 0;  /* высший зафиксированный tick мкс */
atomic_uint g_dns_recv_q_max     = 0;  /* пиковый recv-Q DNS (заполняет dns_server.c) */

void dispatcher_set_context(dispatcher_state_t *ds,
                            const EburNetConfig *cfg)
{
    g_dispatcher = ds;
    g_config     = cfg;
}

void dispatcher_set_rules_engine(rules_engine_t *re)
{
    g_rules_engine = re;
}

void dispatcher_set_pgm(proxy_group_manager_t *pgm)
{
    g_pgm = pgm;
}

#if CONFIG_EBURNET_FAKE_IP
void dispatcher_set_fake_ip(fake_ip_table_t *t)
{
    g_fake_ip = t;
}
#endif

void dispatcher_set_dm(device_manager_t *dm)
{
    g_dm = dm;
}

/* ── ARP кэш: IP → MAC для per-device traffic stats ── */

typedef struct {
    uint32_t ip;         /* IPv4 host byte order, 0 = слот свободен */
    char     mac[18];    /* "aa:bb:cc:dd:ee:ff\0" */
} arp_cache_entry_t;

#define ARP_CACHE_SIZE 64
static arp_cache_entry_t s_arp_cache[ARP_CACHE_SIZE];
static time_t            s_arp_cache_ts = 0;  /* время последнего обновления */

/* Обновить кэш из /proc/net/arp (не чаще раз в 30 секунд) */
static void arp_cache_refresh(void)
{
    time_t now = time(NULL);
    if (now - s_arp_cache_ts < 30) return;
    s_arp_cache_ts = now;

    memset(s_arp_cache, 0, sizeof(s_arp_cache));
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return;

    static char line[128];   /* static: MIPS стек 8KB */
    if (fgets(line, sizeof(line), f)) {   /* пропустить заголовок */
        int idx = 0;
        while (idx < ARP_CACHE_SIZE && fgets(line, sizeof(line), f)) {
            char ip_str[16] = {0}, flags_str[8] = {0}, mac_str[18] = {0};
            if (sscanf(line, "%15s %*s %7s %17s",
                       ip_str, flags_str, mac_str) != 3) continue;
            unsigned int flags = (unsigned int)strtoul(flags_str, NULL, 16);
            if (!(flags & 0x2)) continue;   /* только ATF_COM */
            struct in_addr addr;
            if (inet_pton(AF_INET, ip_str, &addr) != 1) continue;
            s_arp_cache[idx].ip = ntohl(addr.s_addr);
            /* Нормализовать MAC в нижний регистр */
            for (int i = 0; mac_str[i]; i++)
                mac_str[i] = (char)tolower((unsigned char)mac_str[i]);
            memcpy(s_arp_cache[idx].mac, mac_str, 18);
            idx++;
        }
    }
    fclose(f);
}

/* Найти MAC по IPv4 (host byte order). Возвращает "" если не найден. */
static const char *arp_lookup_mac(uint32_t ip4)
{
    arp_cache_refresh();
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (s_arp_cache[i].ip == ip4)
            return s_arp_cache[i].mac;
    }
    return "";
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
/*  T0-01: map_fingerprint + reality_pbk base64url decode              */
/* ------------------------------------------------------------------ */

/* WHY: для "random" — round-robin по доступным профилям.
 * Mihomo выбирает случайный fingerprint для каждого соединения. Мы не имеем
 * полноценного random (нет DRBG в hot path), но детерминированная ротация
 * Chrome→Firefox→iOS даёт 3 разных JA3 на каждые 3 соединения. Anti-bot
 * системы (YouTube/CDN) видели 12 одинаковых Chrome 120 ClientHello подряд
 * к одному Reality endpoint — закрывали после ~8KB. Ротация снимает паттерн. */
static tls_fingerprint_t map_fingerprint(const char *s)
{
    if (!s || !s[0])                                return TLS_FP_CHROME120;
    if (strcmp(s, "firefox") == 0)                  return TLS_FP_FIREFOX121;
    if (strcmp(s, "safari") == 0 || strcmp(s, "ios") == 0)
                                                    return TLS_FP_IOS17;
    if (strcmp(s, "chrome") == 0)                   return TLS_FP_CHROME120;
    if (strcmp(s, "random") == 0) {
        static const tls_fingerprint_t profiles[3] = {
            TLS_FP_CHROME120,
            TLS_FP_FIREFOX121,
            TLS_FP_IOS17,
        };
        static atomic_uint _fp_counter = 0;
        unsigned idx = atomic_fetch_add_explicit(&_fp_counter, 1u,
                                                 memory_order_relaxed) % 3u;
        return profiles[idx];
    }
    return TLS_FP_CHROME120;
}

/* base64url → 32 байта. 0 при успехе, -1 иначе.
 * Собственный декодер RFC 4648 §5: A-Z=0-25, a-z=26-51, 0-9=52-61, -=62, _=63.
 * НЕ использует wolfSSL Base64_Decode: тот декодирует base64url некорректно. */

static int b64url_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

static int reality_pbk_decode(const char *b64url, uint8_t out[32])
{
    /* Reality pubkey = ровно 43 символа base64url = 32 байта.
     * 43 = 10 полных групп по 4 символа (→ 30 байт)
     *    + 1 неполная группа из 3 символов (implicit '=') → 2 байта.
     * Итого: 32 байта. */
    if (!b64url) return -1;
    size_t n = strnlen(b64url, 64);
    if (n != 43) return -1;

    size_t out_pos = 0;

    /* 10 полных групп по 4 символа → 30 байт */
    for (size_t i = 0; i < 40; i += 4) {
        int a = b64url_val(b64url[i]);
        int b = b64url_val(b64url[i + 1]);
        int c = b64url_val(b64url[i + 2]);
        int d = b64url_val(b64url[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
        out[out_pos++] = (uint8_t)((a << 2) | (b >> 4));
        out[out_pos++] = (uint8_t)(((b & 0x0F) << 4) | (c >> 2));
        out[out_pos++] = (uint8_t)(((c & 0x03) << 6) | d);
    }

    /* Неполная группа: символы [40..42] = 3 символа → 2 байта (implicit '=') */
    {
        int a = b64url_val(b64url[40]);
        int b = b64url_val(b64url[41]);
        int c = b64url_val(b64url[42]);
        if (a < 0 || b < 0 || c < 0) return -1;
        out[out_pos++] = (uint8_t)((a << 2) | (b >> 4));
        out[out_pos++] = (uint8_t)(((b & 0x0F) << 4) | (c >> 2));
    }

    return (out_pos == 32) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/*  Протокол VLESS — неблокирующий TLS + VLESS header (C-03/C-04)      */
/* ------------------------------------------------------------------ */

#if CONFIG_EBURNET_VLESS
static int vless_protocol_start(relay_conn_t *relay,
                                const struct sockaddr_storage *dst,
                                const ServerConfig *server)
{
    (void)dst;

    /* Reality TLS: если reality_pbk задан → custom TLS 1.3 stack (не wolfSSL).
     * wolfSSL не поддерживает x25519 static ephemeral для Reality ECDH auth.
     * Custom stack — модули core/src/crypto/reality/. */
    if (server->reality_pbk[0]) {
        /* WHY: keygen деферируется в dispatcher_tick RELAY_REALITY_HS.
         * reality_auth_init (wc_curve25519_make_key ~10-15ms MIPS) здесь
         * блокировала бы event loop при N одновременных connect-completions.
         * reality_conn_new безопасен с нулевым auth — tls13_hs_init лишь
         * хранит указатель; eph_pub не читается до первого tls13_hs_step. */
        reality_auth_t *auth = (reality_auth_t *)calloc(1, sizeof(reality_auth_t));
        if (!auth) return -1;

        /* Reality SNI: priority server->reality_sni (YAML servername),
         * fallback на server->address. Captured mihomo CH с SNI=address был
         * Trojan-проксированный, не Reality — Reality использует servername. */
        const char *sni = server->reality_sni[0]
                        ? server->reality_sni : server->address;
        relay->reality = (struct reality_conn_s *)
                            reality_conn_new(relay->upstream_fd, sni, auth);
        if (!relay->reality) {
            free(auth);   /* reality_auth_init не вызывался — only free */
            return -1;
        }
        relay->reality_auth         = (struct reality_auth_s *)auth;
        relay->use_tls              = false;   /* НЕ wolfSSL */
        relay->reality_pending_init = true;    /* keygen произойдёт в RELAY_REALITY_HS */
        log_msg(LOG_INFO, "relay [%s] CONNECTING→REALITY_HS", server->name);
        relay->state                = RELAY_REALITY_HS;
        log_msg(LOG_DEBUG, "VLESS: Reality TLS handshake запущен (%s:%u)",
                server->address, server->port);
        return 0;
    }

    /* Стандартный путь: wolfSSL TLS (без Reality auth) */
    tls_config_t cfg = {0};
    /* T0-01: SNI из reality_sni (YAML servername), fallback — address */
    const char *sni_src = server->reality_sni[0]
                        ? server->reality_sni : server->address;
    {   int _n = snprintf(cfg.sni, sizeof(cfg.sni), "%s", sni_src);
        if (_n < 0 || (size_t)_n >= sizeof(cfg.sni)) {
            log_msg(LOG_WARN, "VLESS: SNI обрезан: %s", sni_src);
            return -1;
        }
    }
    cfg.fingerprint = map_fingerprint(server->reality_fingerprint);
    cfg.verify_cert = false;
    /* WHY: gRPC требует ALPN "h2"; WS требует "http/1.1" — иначе Chrome fingerprint
     * согласует h2, сервер ждёт HTTP/2 frames, а relay шлёт HTTP/1.1 WS Upgrade → RST. */
    if (server->transport[0] && strcmp(server->transport, "grpc") == 0)
        strncpy(cfg.alpn, "h2", sizeof(cfg.alpn) - 1);
    else if (server->transport[0] && strcmp(server->transport, "ws") == 0)
        strncpy(cfg.alpn, "http/1.1", sizeof(cfg.alpn) - 1);
    /* DEC-025: передаём shortId для диагностики после handshake */
    if (server->reality_short_id[0])
        cfg.reality_short_id = server->reality_short_id;
    /* T0-01: декодируем reality_pbk (base64url, 43 сим → 32 байт).
     * tls_connect_start делает deep-copy в malloc, стек OK. */
    uint8_t pbk_bytes[32];
    if (server->reality_pbk[0] &&
        reality_pbk_decode(server->reality_pbk, pbk_bytes) == 0) {
        cfg.reality_key     = pbk_bytes;
        cfg.reality_key_len = 32;
    }
#if CONFIG_EBURNET_STLS
    /* ShadowTLS I/O callbacks: wolfSSL ↔ stls_wrap/unwrap ↔ upstream_fd */
    if (relay->stls_io) {
        cfg.io_send = stls_ssl_send;
        cfg.io_recv = stls_ssl_recv;
        cfg.io_ctx  = relay->stls_io;
    }
#endif

    relay->tls = malloc(sizeof(tls_conn_t));
    if (!relay->tls) return -1;
    if (tls_connect_start(relay->tls, relay->upstream_fd, &cfg) < 0) {
        free(relay->tls); relay->tls = NULL;
        return -1;
    }

    relay->use_tls = true;
    log_msg(LOG_INFO, "relay [%s] CONNECTING→TLS_SHAKE", server->name);
    relay->state = RELAY_TLS_SHAKE;
    return 0;
}

static const proxy_protocol_t proto_vless = {
    .name  = "vless",
    .start = vless_protocol_start,
};
#endif /* CONFIG_EBURNET_VLESS */

/* ------------------------------------------------------------------ */
/*  Протокол VLESS + XHTTP транспорт                                   */
/* ------------------------------------------------------------------ */

#if CONFIG_EBURNET_VLESS
static int xhttp_protocol_start(relay_conn_t *relay,
                                const struct sockaddr_storage *dst,
                                const ServerConfig *server)
{
    (void)dst;

    /* stream-one если Reality pbk настроен (один H2 POST = upload+download).
     * WHY: refs/mihomo/transport/xhttp/config.go EffectiveMode():
     *   hasReality && no DownloadSettings → "stream-one". */
    bool use_stream_one = (server->reality_pbk[0] != '\0');

    /* upstream_fd уже подключён (upload). Для stream-up создаём download fd. */
    /* inet_pton fast path для IP; hostname → net_resolve_host */
    char resolved_ip[INET6_ADDRSTRLEN] = {0};
    int  resolved_family = AF_INET;

    if (inet_pton(AF_INET, server->address,
                  &(struct in_addr){0}) == 1) {
        {   int _n = snprintf(resolved_ip, sizeof(resolved_ip), "%s", server->address);
            if (_n < 0 || (size_t)_n >= sizeof(resolved_ip))
                log_msg(LOG_WARN, "dispatcher: resolved_ip обрезан: %s:%d", __FILE__, __LINE__);
        }
        resolved_family = AF_INET;
    } else if (inet_pton(AF_INET6, server->address,
                         &(struct in6_addr){0}) == 1) {
        {   int _n = snprintf(resolved_ip, sizeof(resolved_ip), "%s", server->address);
            if (_n < 0 || (size_t)_n >= sizeof(resolved_ip))
                log_msg(LOG_WARN, "dispatcher: resolved_ip обрезан: %s:%d", __FILE__, __LINE__);
        }
        resolved_family = AF_INET6;
    } else {
        /* DEC-031: dispatcher_resolve_server обходит libc getaddrinfo
         * (который идёт в resolv.conf → 127.0.0.1 → рекурсия в наш DNS).
         * Использует cfg->dns.upstream_bypass/default через UDP напрямую.
         * gs=NULL в этом call site: xhttp_protocol_start/upstream_connect
         * не получают group_server_state_t — caching через relay_conn_t
         * добавим отдельной итерацией. Без кэша resolve вызывается на
         * каждый relay, но через UCI upstream (не libc) → работает. */
        if (g_config) {
            dispatcher_resolve_server(server, g_config, NULL,
                                      resolved_ip, sizeof(resolved_ip),
                                      &resolved_family);
        } else {
            /* Strict fallback if global config not set (init race). */
            net_resolve_host(server->address, server->port,
                             resolved_ip, sizeof(resolved_ip), &resolved_family);
        }
        if (!resolved_ip[0]) {
            log_msg(LOG_WARN, "XHTTP: не удалось резолвить '%s'",
                    server->address);
            return -1;
        }
    }

    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    struct sockaddr_in  *a4 = (struct sockaddr_in  *)&addr;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&addr;

    if (resolved_family == AF_INET) {
        a4->sin_family = AF_INET;
        inet_pton(AF_INET, resolved_ip, &a4->sin_addr);
        a4->sin_port = htons(server->port);
    } else {
        a6->sin6_family = AF_INET6;
        inet_pton(AF_INET6, resolved_ip, &a6->sin6_addr);
        a6->sin6_port = htons(server->port);
    }

    int family    = addr.ss_family;
    socklen_t addrlen = (family == AF_INET)
        ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    /* dl_fd = -1 для stream-one (один fd для обоих направлений) */
    int dl_fd = -1;
    if (!use_stream_one) {
        dl_fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (dl_fd < 0)
            return -1;

        if (connect(dl_fd, (struct sockaddr *)&addr, addrlen) < 0 &&
            errno != EINPROGRESS) {
            close(dl_fd);
            return -1;
        }

        relay->ep_download.relay     = relay;
        relay->ep_download.is_client = false;
    }
    relay->download_fd = dl_fd;

    /* Выделяем XHTTP состояние */
    relay->xhttp = calloc(1, sizeof(xhttp_state_t));
    if (!relay->xhttp) {
        if (dl_fd >= 0) { close(dl_fd); relay->download_fd = -1; }
        return -1;
    }

    tls_config_t cfg = {0};
    /* T0-01: SNI chain — xhttp_host → reality_sni → address */
    const char *sni_host = server->xhttp_host[0]  ? server->xhttp_host
                         : server->reality_sni[0] ? server->reality_sni
                         : server->address;
    {   int _n = snprintf(cfg.sni, sizeof(cfg.sni), "%s", sni_host);
        if (_n < 0 || (size_t)_n >= sizeof(cfg.sni)) {
            log_msg(LOG_WARN, "XHTTP: SNI обрезан: %s", sni_host);
            free(relay->xhttp);
            relay->xhttp = NULL;
            if (dl_fd >= 0) { close(dl_fd); relay->download_fd = -1; }
            return -1;
        }
    }
    cfg.fingerprint = map_fingerprint(server->reality_fingerprint);
    cfg.verify_cert = false;
    /* T0-01 C.6: Reality pbk для XHTTP+Reality серверов.
     * xhttp_start синхронно вызывает tls_connect_start (vless_xhttp.c),
     * который делает memcpy(malloc,...) — stack lifetime до возврата OK. */
    uint8_t xhttp_pbk_bytes[32];
    if (server->reality_pbk[0] &&
        reality_pbk_decode(server->reality_pbk, xhttp_pbk_bytes) == 0) {
        cfg.reality_key     = xhttp_pbk_bytes;
        cfg.reality_key_len = 32;
    }

    const char *path = server->xhttp_path[0]
        ? server->xhttp_path : "/";

    if (xhttp_start(relay->xhttp, relay->upstream_fd, dl_fd,
                     &cfg, path, sni_host) < 0) {
        free(relay->xhttp);
        relay->xhttp = NULL;
        if (dl_fd >= 0) { close(dl_fd); relay->download_fd = -1; }
        return -1;
    }

    relay->use_tls = true;

    /* stream-one: пропустить DN_CONNECT (нет download fd), начать с UP_TLS.
     * stream-up: ждать TCP connect download fd → RELAY_XHTTP_DN_CONNECT. */
    relay->state = use_stream_one ? RELAY_XHTTP_UP_TLS : RELAY_XHTTP_DN_CONNECT;

    return 0;
}

static const proxy_protocol_t proto_xhttp = {
    .name  = "vless+xhttp",
    .start = xhttp_protocol_start,
};
#endif /* CONFIG_EBURNET_VLESS */

/* ------------------------------------------------------------------ */
/*  Протокол Trojan — TLS + SHA224(password) header                    */
/* ------------------------------------------------------------------ */

#if CONFIG_EBURNET_TROJAN
static int trojan_protocol_start(relay_conn_t *relay,
                                 const struct sockaddr_storage *dst,
                                 const ServerConfig *server)
{
    (void)dst;
    tls_config_t cfg = {0};
    {   int _n = snprintf(cfg.sni, sizeof(cfg.sni), "%s", server->address);
        if (_n < 0 || (size_t)_n >= sizeof(cfg.sni)) {
            log_msg(LOG_WARN, "Trojan: SNI обрезан: %s", server->address);
            return -1;
        }
    }
    cfg.fingerprint = TLS_FP_CHROME120;
    cfg.verify_cert = false;
    /* WHY: gRPC требует ALPN "h2"; WS требует "http/1.1" — та же проблема что и VLESS */
    if (server->transport[0] && strcmp(server->transport, "grpc") == 0)
        strncpy(cfg.alpn, "h2", sizeof(cfg.alpn) - 1);
    else if (server->transport[0] && strcmp(server->transport, "ws") == 0)
        strncpy(cfg.alpn, "http/1.1", sizeof(cfg.alpn) - 1);
#if CONFIG_EBURNET_STLS
    if (relay->stls_io) {
        cfg.io_send = stls_ssl_send;
        cfg.io_recv = stls_ssl_recv;
        cfg.io_ctx  = relay->stls_io;
    }
#endif

    relay->tls = malloc(sizeof(tls_conn_t));
    if (!relay->tls) return -1;
    if (tls_connect_start(relay->tls, relay->upstream_fd, &cfg) < 0) {
        free(relay->tls); relay->tls = NULL;
        return -1;
    }

    relay->use_tls = true;
    relay->state = RELAY_TLS_SHAKE;
    return 0;
}

static const proxy_protocol_t proto_trojan = {
    .name  = "trojan",
    .start = trojan_protocol_start,
};
#endif /* CONFIG_EBURNET_TROJAN */

/* ------------------------------------------------------------------ */
/*  Протокол Shadowsocks 2022 — AEAD без TLS                          */
/* ------------------------------------------------------------------ */

#if CONFIG_EBURNET_SS
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
#endif /* CONFIG_EBURNET_SS */

/* ------------------------------------------------------------------ */
/*  Протокол AWG — UDP, без TCP connect                                */
/* ------------------------------------------------------------------ */

#if CONFIG_EBURNET_AWG
static int awg_protocol_start(relay_conn_t *relay,
                              const struct sockaddr_storage *dst,
                              const ServerConfig *server)
{
    (void)dst;
    relay->awg = malloc(sizeof(awg_state_t));
    if (!relay->awg) return -1;

    if (awg_init(relay->awg, server,
                 g_config ? g_config->tai_utc_offset : 37) < 0) {
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
        if (epoll_ctl(g_dispatcher->epoll_fd, EPOLL_CTL_ADD,
                      relay->awg->udp_fd, &ev) < 0)
            log_msg(LOG_WARN, "relay: epoll_ctl(AWG udp): %s", strerror(errno));
    }

    relay->upstream_fd = relay->awg->udp_fd;
    relay->state = RELAY_AWG_HANDSHAKE;
    return 0;
}

static const proxy_protocol_t proto_awg = {
    .name  = "awg",
    .start = awg_protocol_start,
};
#endif /* CONFIG_EBURNET_AWG */

/* ------------------------------------------------------------------ */
/*  Протокол Hysteria2 — QUIC, async RELAY_HY2_CONNECT state            */
/* ------------------------------------------------------------------ */

#if CONFIG_EBURNET_QUIC
static int hysteria2_protocol_start(relay_conn_t *relay,
                                    const struct sockaddr_storage *dst,
                                    const ServerConfig *server)
{
    (void)dst; /* host:port берётся из relay->dst / relay->domain в тике */

    hysteria2_config_t cfg = {0};
    strncpy(cfg.server_addr, server->address, sizeof(cfg.server_addr) - 1);
    cfg.server_port = server->port;
    strncpy(cfg.password, server->password, sizeof(cfg.password) - 1);
    if (server->hy2_sni[0])
        strncpy(cfg.sni, server->hy2_sni, sizeof(cfg.sni) - 1);
    cfg.insecure      = server->hy2_insecure;
    cfg.obfs_enabled  = server->hy2_obfs_enabled;
    if (server->hy2_obfs_enabled)
        strncpy(cfg.obfs_password, server->hy2_obfs_password,
                sizeof(cfg.obfs_password) - 1);
    cfg.up_mbps   = server->hy2_up_mbps;
    cfg.down_mbps = server->hy2_down_mbps;

    relay->hy2_conn = hysteria2_conn_new(&cfg);
    if (!relay->hy2_conn) return -1;

    /* Фаза 0: создать UDP сокет, TLS, отправить Initial пакеты.
     * udp_fd становится валидным после этого вызова. Возвращает 0 или 1. */
    if (hysteria2_connect_step((hysteria2_conn_t *)relay->hy2_conn) < 0) {
        log_msg(LOG_WARN, "relay: hysteria2 init '%s': %s",
                server->name,
                hysteria2_strerror((hysteria2_conn_t *)relay->hy2_conn));
        hysteria2_conn_free((hysteria2_conn_t *)relay->hy2_conn);
        relay->hy2_conn = NULL;
        return -1;
    }

    int udp_fd = hysteria2_get_fd((hysteria2_conn_t *)relay->hy2_conn);
    if (udp_fd < 0) {
        hysteria2_conn_free((hysteria2_conn_t *)relay->hy2_conn);
        relay->hy2_conn = NULL;
        return -1;
    }
    if (g_dispatcher) {
        struct epoll_event ev = {
            .events   = EPOLLIN | EPOLLET,
            .data.ptr = &relay->ep_upstream,
        };
        if (epoll_ctl(g_dispatcher->epoll_fd, EPOLL_CTL_ADD, udp_fd, &ev) < 0)
            log_msg(LOG_WARN, "relay: epoll_ctl(HY2 udp): %s", strerror(errno));
    }
    relay->upstream_fd = udp_fd;
    relay->state = RELAY_HY2_CONNECT; /* hy2_stream == NULL → фаза 1 в тике */
    return 0;
}

static const proxy_protocol_t proto_hysteria2 = {
    .name  = "hysteria2",
    .start = hysteria2_protocol_start,
};
#endif /* CONFIG_EBURNET_QUIC */

/* ------------------------------------------------------------------ */
/*  Выбор протокола по имени из конфига                                 */
/* ------------------------------------------------------------------ */

static const proxy_protocol_t *protocol_find_for_server(
    const ServerConfig *server)
{
    if (strcmp(server->protocol, "direct") == 0)
        return &proto_direct;

#if CONFIG_EBURNET_VLESS
    if (strcmp(server->protocol, "vless") == 0) {
        if (server->transport[0] &&
            strcmp(server->transport, "xhttp") == 0)
            return &proto_xhttp;
        return &proto_vless;
    }
#endif
#if CONFIG_EBURNET_TROJAN
    if (strcmp(server->protocol, "trojan") == 0)
        return &proto_trojan;
#endif
#if CONFIG_EBURNET_SS
    if (strcmp(server->protocol, "shadowsocks") == 0 ||
        strcmp(server->protocol, "ss") == 0)
        return &proto_ss;
#endif
#if CONFIG_EBURNET_AWG
    if (strcmp(server->protocol, "awg") == 0)
        return &proto_awg;
#endif
#if CONFIG_EBURNET_QUIC
    if (strcmp(server->protocol, "hysteria2") == 0)
        return &proto_hysteria2;
#endif

    log_msg(LOG_WARN, "relay: протокол '%s' не поддержан, используется direct",
            server->protocol);
    return &proto_direct;
}

/* check_splice_support удалён — аудит C-05: один pipe на все relay
   давал data corruption при partial write */

#if CONFIG_EBURNET_XUDP
/* Forward declarations UDP session helpers — определения после dispatcher_handle_conn */
static int      sockaddr_equal(const struct sockaddr_storage *a,
                               const struct sockaddr_storage *b);
static uint32_t udp_session_hash(const udp_session_key_t *k);
static udp_session_t *udp_session_find(dispatcher_state_t *ds,
                                        const udp_session_key_t *k);
static udp_session_t *udp_session_create(dispatcher_state_t *ds,
                                          const udp_session_key_t *k,
                                          muxcool_stream_t *stream);
#endif

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
#if CONFIG_EBURNET_STLS
            r->stls        = NULL;
            r->stls_io     = NULL;
#endif
            r->state       = RELAY_CONNECTING;
            r->last_active = time(NULL);
            r->ep_client.relay     = r;
            r->ep_client.is_client = true;
            r->ep_upstream.relay     = r;
            r->ep_upstream.is_client = false;
            ds->conns_count++;
            stats_conn_open();
            return r;
        }
    }
    log_msg(LOG_WARN, "relay: все слоты заняты (%d/%d)",
            ds->conns_count, ds->conns_max);
    return NULL;
}

static void relay_free(dispatcher_state_t *ds, relay_conn_t *r)
{
#if CONFIG_EBURNET_VLESS
    /* WHY: EPOLLERR/EPOLLHUP срабатывают до switch() → RELAY_REALITY_HS case
     * не выполняется → декремент потеряется. Снимаем здесь безусловно. */
    if (r->state == RELAY_REALITY_HS && !r->reality_pending_init
            && s_reality_hs_active > 0)
        s_reality_hs_active--;
#endif
    bool had_vision = (r->vision != NULL);
    bool had_grpc   = (r->grpc   != NULL);
    bool had_upstream_eof = r->upstream_eof;
    bool had_client_eof  = r->client_eof;
#if CONFIG_EBURNET_DPI
    /* Соединение закрывается — DPI применялось, но upstream не ответил → отказ */
    if (r->dpi_first_done && !r->dpi_success) {
        uint32_t dst_ip = (r->dst.ss_family == AF_INET)
            ? ntohl(((struct sockaddr_in *)&r->dst)->sin_addr.s_addr) : 0u;
        if (dst_ip)
            dpi_adapt_report(&g_dpi_adapt, dst_ip,
                             r->dpi_strategy, DPI_RESULT_FAIL);
    }
#endif
    if (r->use_tls && r->tls) {
        tls_close(r->tls);
        free(r->tls); r->tls = NULL;
        r->use_tls = false;
    }

    if (r->client_fd >= 0) {
        epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->client_fd, NULL);
        close(r->client_fd);
        r->client_fd = -1;
    }
#if CONFIG_EBURNET_GRPC_MULTIPLEX
    /* Pool relay: upstream_fd — либо conn->tcp_fd (первичный, pool закроет при eviction),
     * либо wake_fd (вторичный, grpc_stream_release закроет). EPOLL_CTL_DEL выполняем,
     * но close — через pool/stream. */
    if (r->grpc_stream && r->upstream_fd >= 0) {
        epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->upstream_fd, NULL);
        r->upstream_fd = -1;
    }
#endif
#if CONFIG_EBURNET_XUDP
    /* Mux.Cool pool relay: upstream_fd = wake_fd (eventfd, освободит
     * muxcool_stream_release). conn->tcp_fd управляется watcher'ом —
     * НЕ трогаем. */
    if (r->muxcool_stream && r->upstream_fd >= 0 &&
        r->upstream_fd == r->muxcool_stream->wake_fd) {
        epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->upstream_fd, NULL);
        r->upstream_fd = -1;
    }
#endif
    if (r->upstream_fd >= 0) {
        epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->upstream_fd, NULL);
        close(r->upstream_fd);
        r->upstream_fd = -1;
#if CONFIG_EBURNET_AWG
        /* WHY: upstream_fd == awg->udp_fd; после close() awg_close()
         * не должна снова закрывать тот же (уже переиспользованный) fd */
        if (r->awg) r->awg->udp_fd = -1;
#endif
#if CONFIG_EBURNET_QUIC
        /* WHY: аналогично AWG — upstream_fd == hy2_conn->udp_fd; после close()
         * hysteria2_conn_free() не должна снова закрывать тот же fd */
        if (r->hy2_conn) hysteria2_invalidate_fd((hysteria2_conn_t *)r->hy2_conn);
#endif
    }
    if (r->download_fd >= 0) {
        epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->download_fd, NULL);
        close(r->download_fd);
        r->download_fd = -1;
    }
#if CONFIG_EBURNET_AWG
    if (r->awg) {
        if (r->awg->udp_fd >= 0)
            epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL,
                      r->awg->udp_fd, NULL);
        awg_close(r->awg);
        free(r->awg);
        r->awg = NULL;
    }
#endif
#if CONFIG_EBURNET_VLESS
    if (r->xhttp) {
        xhttp_close(r->xhttp);
        free(r->xhttp);
        r->xhttp = NULL;
    }
#endif
#if CONFIG_EBURNET_SS
    if (r->ss) {
        ss_cleanup(r->ss);  /* C-08: освободить overflow буфер */
        free(r->ss);
        r->ss = NULL;
    }
#endif
#if CONFIG_EBURNET_STLS
    if (r->stls_io) { free(r->stls_io); r->stls_io = NULL; }
    if (r->stls)    { free(r->stls);    r->stls = NULL; }
#endif
    /* T0-02: Vision state (нет внутренних malloc'ов — достаточно free самого struct) */
    if (r->vision) { free(r->vision); r->vision = NULL; }
    /* T0-03: gRPC transport state */
    if (r->grpc) { free(r->grpc); r->grpc = NULL; }
#if CONFIG_EBURNET_GRPC_MULTIPLEX
    if (r->grpc_stream) { grpc_stream_release(r->grpc_stream); r->grpc_stream = NULL; }
#endif
#if CONFIG_EBURNET_XUDP
    /* UDP relay: найти и удалить сессию из hash table перед release stream.
     * relay_owned=true → stream освобождается ниже (обычный muxcool_stream_release). */
    if (r->is_udp_relay) {
        uint32_t _hidx = udp_session_hash(&r->udp_sess_key);
        udp_session_t **_pp = &ds->udp_sessions[_hidx];
        while (*_pp) {
            if (sockaddr_equal(&(*_pp)->key.src, &r->udp_sess_key.src) &&
                sockaddr_equal(&(*_pp)->key.dst, &r->udp_sess_key.dst)) {
                udp_session_t *_tmp = *_pp;
                *_pp = _tmp->next;
                free(_tmp);
                ds->udp_session_count--;
                break;
            }
            _pp = &(*_pp)->next;
        }
    }
    if (r->muxcool_stream) {
        muxcool_stream_release(r->muxcool_stream);
        r->muxcool_stream = NULL;
    }
#endif
    /* T0-04: WebSocket transport state */
    if (r->ws)      { free(r->ws);      r->ws      = NULL; }
    /* T0-06: HTTPUpgrade transport state */
    if (r->http_ug) { free(r->http_ug); r->http_ug = NULL; }
#if CONFIG_EBURNET_QUIC
    /* T0-07: Hysteria2 transport state */
    if (r->hy2_stream) {
        hysteria2_stream_close((hysteria2_conn_t *)r->hy2_conn,
                               (hysteria2_stream_t *)r->hy2_stream);
        free(r->hy2_stream); r->hy2_stream = NULL;
    }
    if (r->hy2_conn) {
        hysteria2_conn_free((hysteria2_conn_t *)r->hy2_conn);
        r->hy2_conn = NULL;
    }
#endif

    /* Pending write buffer upstream→client */
    if (r->to_client_buf) {
        free(r->to_client_buf);
        r->to_client_buf = NULL;
    }
    r->to_client_len    = 0;
    r->to_client_pos    = 0;
    r->epollout_client  = false;

#if CONFIG_EBURNET_VLESS
    /* Reality TLS connection (custom stack) */
    if (r->reality) {
        reality_conn_free((reality_conn_t *)r->reality);
        r->reality = NULL;
    }
    if (r->reality_auth) {
        /* WHY: reality_auth_free вызывает wc_FreeRng → close(rng.seed.fd).
         * Если pending_init=true, то reality_auth_init не вызывался и rng.seed.fd=0
         * (calloc-нули) — close(0) закроет stdin демона. Guard обязателен. */
        if (!r->reality_pending_init)
            reality_auth_free((reality_auth_t *)r->reality_auth);
        free(r->reality_auth);
        r->reality_auth = NULL;
    }
#endif

    if (r->state != RELAY_DONE) {
        if (had_vision) {
            const ServerConfig *_srv = (r->server_idx >= 0 && g_config)
                ? config_get_server(g_config, r->server_idx) : NULL;
            log_msg(LOG_INFO,
                    "relay закрыт Vision: in=%lu out=%lu lifetime=%lus"
                    " eof_up=%d eof_cli=%d server=%s",
                    (unsigned long)r->bytes_in,
                    (unsigned long)r->bytes_out,
                    (unsigned long)(time(NULL) - r->created_at),
                    (int)had_upstream_eof,
                    (int)had_client_eof,
                    _srv ? _srv->name : "?");
        } else if (had_grpc) {
            const ServerConfig *s = (r->server_idx >= 0 && g_config)
                ? config_get_server(g_config, r->server_idx) : NULL;
            log_msg(LOG_INFO,
                    "relay закрыт gRPC: in=%lu out=%lu lifetime=%lus server=%s",
                    (unsigned long)r->bytes_in,
                    (unsigned long)r->bytes_out,
                    (unsigned long)(time(NULL) - r->created_at),
                    s ? s->name : "?");
            /* WHY: gRPC HS прошёл (bytes_in > 0 = данные клиента отправлены),
             * но сервер не ответил (bytes_out == 0). Сервер принимает соединение
             * но не проксирует → считаем отказом для failover на следующий сервер. */
            if (r->bytes_out == 0 && r->bytes_in > 0 && r->server_idx >= 0) {
                dispatcher_server_result(ds, r->server_idx, false);
                proxy_group_mark_server_fail(g_pgm, r->server_idx);
            }
        } else {
            if (r->bytes_in > 0 || r->bytes_out > 0) {
                const ServerConfig *_s = (r->server_idx >= 0 && g_config)
                    ? config_get_server(g_config, r->server_idx) : NULL;
                log_msg(LOG_INFO,
                        "relay closed [%s] up=%lu down=%lu lifetime=%lus domain=%s",
                        _s ? _s->name : (r->server_idx == -1 ? "DIRECT" : "?"),
                        (unsigned long)r->bytes_in,
                        (unsigned long)r->bytes_out,
                        (unsigned long)(time(NULL) - r->created_at),
                        r->domain[0] ? r->domain : "(null)");
            }
        }
        /* Учесть трафик в per-device статистике */
        if (g_dm && r->client_mac[0])
            device_traffic_inc(g_dm, r->client_mac,
                               r->bytes_in, r->bytes_out);
        ds->total_closed++;
        ds->conns_count--;
        stats_conn_close();
    }

    r->client_fd   = -1;
    r->upstream_fd = -1;
    r->download_fd = -1;
    r->state       = RELAY_DONE;
}

/* ------------------------------------------------------------------ */
/*  relay_release_upstream — освобождает upstream, НЕ трогает client  */
/* ------------------------------------------------------------------ */

static void relay_release_upstream(dispatcher_state_t *ds, relay_conn_t *r)
{
#if CONFIG_EBURNET_VLESS
    if (r->state == RELAY_REALITY_HS && !r->reality_pending_init
            && s_reality_hs_active > 0)
        s_reality_hs_active--;
#endif

    if (r->use_tls && r->tls) {
        tls_close(r->tls);
        free(r->tls); r->tls = NULL;
        r->use_tls = false;
    }

#if CONFIG_EBURNET_GRPC_MULTIPLEX
    if (r->grpc_stream && r->upstream_fd >= 0) {
        epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->upstream_fd, NULL);
        r->upstream_fd = -1;
    }
#endif
#if CONFIG_EBURNET_XUDP
    if (r->muxcool_stream && r->upstream_fd >= 0 &&
        r->upstream_fd == r->muxcool_stream->wake_fd) {
        epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->upstream_fd, NULL);
        r->upstream_fd = -1;
    }
#endif
    if (r->upstream_fd >= 0) {
        epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->upstream_fd, NULL);
        close(r->upstream_fd);
        r->upstream_fd = -1;
#if CONFIG_EBURNET_AWG
        if (r->awg) r->awg->udp_fd = -1;
#endif
#if CONFIG_EBURNET_QUIC
        if (r->hy2_conn) hysteria2_invalidate_fd((hysteria2_conn_t *)r->hy2_conn);
#endif
    }
    if (r->download_fd >= 0) {
        epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->download_fd, NULL);
        close(r->download_fd);
        r->download_fd = -1;
    }
#if CONFIG_EBURNET_AWG
    if (r->awg) {
        if (r->awg->udp_fd >= 0)
            epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->awg->udp_fd, NULL);
        awg_close(r->awg);
        free(r->awg); r->awg = NULL;
    }
#endif
#if CONFIG_EBURNET_VLESS
    if (r->xhttp) {
        xhttp_close(r->xhttp);
        free(r->xhttp); r->xhttp = NULL;
    }
#endif
#if CONFIG_EBURNET_SS
    if (r->ss) {
        ss_cleanup(r->ss);
        free(r->ss); r->ss = NULL;
    }
#endif
#if CONFIG_EBURNET_STLS
    if (r->stls_io) { free(r->stls_io); r->stls_io = NULL; }
    if (r->stls)    { free(r->stls);    r->stls = NULL; }
#endif
    if (r->vision) { free(r->vision); r->vision = NULL; }
    if (r->grpc)   { free(r->grpc);   r->grpc = NULL; }
#if CONFIG_EBURNET_GRPC_MULTIPLEX
    if (r->grpc_stream) { grpc_stream_release(r->grpc_stream); r->grpc_stream = NULL; }
#endif
#if CONFIG_EBURNET_XUDP
    if (r->muxcool_stream) {
        muxcool_stream_release(r->muxcool_stream);
        r->muxcool_stream = NULL;
    }
#endif
    if (r->ws)      { free(r->ws);      r->ws = NULL; }
    if (r->http_ug) { free(r->http_ug); r->http_ug = NULL; }
#if CONFIG_EBURNET_QUIC
    if (r->hy2_stream) {
        hysteria2_stream_close((hysteria2_conn_t *)r->hy2_conn,
                               (hysteria2_stream_t *)r->hy2_stream);
        free(r->hy2_stream); r->hy2_stream = NULL;
    }
    if (r->hy2_conn) {
        hysteria2_conn_free((hysteria2_conn_t *)r->hy2_conn);
        r->hy2_conn = NULL;
    }
#endif
    if (r->to_client_buf) { free(r->to_client_buf); r->to_client_buf = NULL; }
    r->to_client_len   = 0;
    r->to_client_pos   = 0;
    r->epollout_client = false;
#if CONFIG_EBURNET_VLESS
    if (r->reality) {
        reality_conn_free((reality_conn_t *)r->reality);
        r->reality = NULL;
    }
    if (r->reality_auth) {
        if (!r->reality_pending_init)
            reality_auth_free((reality_auth_t *)r->reality_auth);
        free(r->reality_auth);
        r->reality_auth = NULL;
    }
#endif
    r->upstream_eof        = false;
    r->client_eof          = false;
    r->client_sent_first   = false;
    r->vless_resp_len      = 0;
    r->reality_pending_init = false;
#if CONFIG_EBURNET_DPI
    r->dpi_first_done = false;
    r->dpi_success    = false;
#endif
#ifdef __mips__
    r->upstream_lt_mode   = false;
    r->upstream_fd_paused = false;
#endif
    r->connect_deadline = 0;
    r->state = RELAY_CONNECTING;
}

/* ------------------------------------------------------------------ */
/*  relay_try_retry — выбрать следующий сервер, не закрывая клиента   */
/* ------------------------------------------------------------------ */

/* forward declarations — определения ниже в файле */
static int upstream_connect(dispatcher_state_t *ds,
                            relay_conn_t *r,
                            const ServerConfig *server);
#if CONFIG_EBURNET_GRPC_MULTIPLEX
static int grpc_stream_send_proto_header(relay_conn_t *r, const ServerConfig *server);
#endif

static int relay_try_retry(dispatcher_state_t *ds, relay_conn_t *r)
{
    /* Лимит до 2 retry per tick — предотвращает burst upstream_connect при многопоточных HS fail */
    if (s_retries_this_tick >= 2) return -1;
    s_retries_this_tick++;

    /* HS fail — исключаем сервер только в группе этого relay.
     * WHY: mark_server_fail_immediate бьёт по всем группам → каскадный failover
     * N-серверов × M-групп за один тик, dispatcher_tick 130-155ms.
     * HC восстановит available через mark_server_ok после успешных проверок. */
    if (r->server_idx >= 0)
        proxy_group_mark_server_fail_for_group(g_pgm, r->server_idx, r->group_name);

    if (r->retries >= 3) return -1;
    if (!g_pgm || r->group_name[0] == '\0') return -1;
    if (r->client_fd < 0) return -1;

    int new_idx = proxy_group_select_server(g_pgm, r->group_name);
    if (new_idx < 0 || new_idx == r->server_idx) return -1;

    const ServerConfig *srv = g_config
        ? config_get_server(g_config, new_idx) : NULL;
    if (!srv) return -1;
    /* AWG и Hysteria2 — UDP, другая логика; пропускаем */
    if (strcmp(srv->protocol, "awg") == 0 ||
        strcmp(srv->protocol, "hysteria2") == 0)
        return -1;

    relay_release_upstream(ds, r);

    r->retries++;
    r->server_idx = new_idx;
    r->bytes_in   = 0;
    r->bytes_out  = 0;
    r->upstream_first_byte_deadline = 0;  /* новый HS установит deadline после своего завершения */

    log_msg(LOG_INFO, "relay retry %u/3: → %s (domain=%s)",
            r->retries, srv->name,
            r->domain[0] ? r->domain : "(null)");

#if CONFIG_EBURNET_GRPC_MULTIPLEX
    /* WHY: relay_release_upstream() обнулил r->grpc_stream. Если новый сервер
     * тоже gRPC — нужно получить stream из pool ДО upstream_connect, иначе
     * в TLS_SHAKE→GRPC_HS переходе сработает guard "MULTIPLEX без grpc_stream". */
    if (ds->grpc_pool && srv->transport[0] && strcmp(srv->transport, "grpc") == 0) {
        char _authority[288];
        int  _an;
        if (srv->port == 443 || srv->port == 80)
            _an = snprintf(_authority, sizeof(_authority), "%s", srv->address);
        else
            _an = snprintf(_authority, sizeof(_authority), "%s:%u",
                           srv->address, srv->port);
        if (_an < 0 || (size_t)_an >= sizeof(_authority))
            _authority[sizeof(_authority) - 1] = '\0';
        const char *_svc = srv->grpc_service_name[0]
                           ? srv->grpc_service_name : "GunService";
        int _needs_io = 0, _tcp_fd_unused = -1;
        grpc_stream_t *_gs = grpc_pool_acquire_stream(ds->grpc_pool, new_idx,
                                                       _authority, _svc,
                                                       &_needs_io, &_tcp_fd_unused);
        if (!_gs) {
            log_msg(LOG_WARN, "relay: retry gRPC pool acquire провалился");
            return -1;
        }
        r->grpc_stream = _gs;
        if (_needs_io == 0) {
            /* Существующее соединение: secondary stream — активируем немедленно */
            r->upstream_fd = _gs->wake_fd;
            if (grpc_stream_send_proto_header(r, srv) < 0) {
                grpc_stream_release(r->grpc_stream);
                r->grpc_stream = NULL;
                r->upstream_fd = -1;
                return -1;
            }
            dispatcher_server_result(ds, new_idx, true);
            struct epoll_event _wev = { .events = EPOLLIN, .data.ptr = &r->ep_upstream };
            if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD, r->upstream_fd, &_wev) < 0) {
                r->upstream_fd = -1;
                return -1;
            }
            r->state             = RELAY_ACTIVE;
            r->client_sent_first = true;
            log_msg(LOG_INFO, "relay retry [%s] gRPC secondary stream id=%u",
                    srv->name, _gs->stream_id);
            return 0;
        }
        /* _needs_io == 1: продолжаем к upstream_connect — grpc_stream уже установлен */
    }
#endif

    return upstream_connect(ds, r, srv);
}

/* ------------------------------------------------------------------ */
/*  relay_do_half_close — TCP half-close (DEC-016)                     */
/* ------------------------------------------------------------------ */

static void relay_do_half_close(relay_conn_t *r, bool client_side)
{
    /* WHY: idempotent — на одном EPOLLRDHUP функция вызывается из 2-3 мест
     * (relay_handle_active, EPOLLHUP handler, error path). Без этого guard
     * пишется по 8-9 одинаковых INFO логов на close + лишние shutdown(SHUT_WR)
     * на уже закрытом fd. Каждое log_msg = write() в /tmp ≈ 30-50 µs на mipsel,
     * и блокирует epoll loop. */
    if (client_side) {
        if (r->client_eof) return;
        r->client_eof = true;
        if (!r->use_tls && r->upstream_fd >= 0)
            shutdown(r->upstream_fd, SHUT_WR);
    } else {
        if (r->upstream_eof) return;
        r->upstream_eof = true;
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
                             const EburNetConfig *cfg)
{
    /* Lazy init — заполнить health[] при первом вызове */
    if (ds->health_count == 0 && cfg->server_count > 0) {
        int count = cfg->server_count;
        if (count > DISPATCHER_MAX_HEALTH) count = DISPATCHER_MAX_HEALTH;
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
        const ServerConfig *sc = config_get_server(cfg, idx);
        if (!sc || !sc->enabled)
            continue;
        if (fallback < 0)
            fallback = idx;
        if (ds->health[i].available && ds->health[i].fail_count < HEALTH_MAX_FAILURES)
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
            if (ds->health[i].fail_count >= HEALTH_MAX_FAILURES) {
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
    /* inet_pton fast path для IP; hostname → net_resolve_host */
    char resolved_ip[INET6_ADDRSTRLEN] = {0};
    int  resolved_family = AF_INET;

    if (inet_pton(AF_INET, server->address,
                  &(struct in_addr){0}) == 1) {
        {   int _n = snprintf(resolved_ip, sizeof(resolved_ip), "%s", server->address);
            if (_n < 0 || (size_t)_n >= sizeof(resolved_ip))
                log_msg(LOG_WARN, "dispatcher: resolved_ip обрезан: %s:%d", __FILE__, __LINE__);
        }
        resolved_family = AF_INET;
    } else if (inet_pton(AF_INET6, server->address,
                         &(struct in6_addr){0}) == 1) {
        {   int _n = snprintf(resolved_ip, sizeof(resolved_ip), "%s", server->address);
            if (_n < 0 || (size_t)_n >= sizeof(resolved_ip))
                log_msg(LOG_WARN, "dispatcher: resolved_ip обрезан: %s:%d", __FILE__, __LINE__);
        }
        resolved_family = AF_INET6;
    } else {
        /* DEC-031: dispatcher_resolve_server обходит libc getaddrinfo
         * (который идёт в resolv.conf → 127.0.0.1 → рекурсия в наш DNS).
         * Использует cfg->dns.upstream_bypass/default через UDP напрямую.
         * gs=NULL в этом call site: xhttp_protocol_start/upstream_connect
         * не получают group_server_state_t — caching через relay_conn_t
         * добавим отдельной итерацией. Без кэша resolve вызывается на
         * каждый relay, но через UCI upstream (не libc) → работает. */
        if (g_config) {
            dispatcher_resolve_server(server, g_config, NULL,
                                      resolved_ip, sizeof(resolved_ip),
                                      &resolved_family);
        } else {
            /* Strict fallback if global config not set (init race). */
            net_resolve_host(server->address, server->port,
                             resolved_ip, sizeof(resolved_ip), &resolved_family);
        }
        if (!resolved_ip[0]) {
            log_msg(LOG_ERROR, "relay: не удалось резолвить upstream '%s'",
                    server->address);
            return -1;
        }
    }

    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));

    struct sockaddr_in  *a4 = (struct sockaddr_in  *)&addr;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&addr;

    if (resolved_family == AF_INET) {
        a4->sin_family = AF_INET;
        inet_pton(AF_INET, resolved_ip, &a4->sin_addr);
        a4->sin_port = htons(server->port);
    } else {
        a6->sin6_family = AF_INET6;
        inet_pton(AF_INET6, resolved_ip, &a6->sin6_addr);
        a6->sin6_port = htons(server->port);
    }

    int family = addr.ss_family;
    socklen_t addrlen = (family == AF_INET)
        ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_msg(LOG_ERROR, "relay: socket(upstream): %s", strerror(errno));
        return -1;
    }

    log_msg(LOG_INFO, "relay connect: %s → %s:%u (resolved: %s)",
            server->name, server->address, server->port, resolved_ip);

    int rc = connect(fd, (struct sockaddr *)&addr, addrlen);
    if (rc < 0 && errno != EINPROGRESS) {
        log_msg(LOG_WARN, "relay: connect(%s:%u): %s",
                server->address, server->port, strerror(errno));
        close(fd);
        return -1;
    }

    r->upstream_fd = fd;
    /* EINPROGRESS: connect не завершён, ставим дедлайн 5с */
    if (rc < 0)
        r->connect_deadline = time(NULL) + 5;

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
/*  reality_send_fn — callback для vision_write_ex в Reality path     */
/* ------------------------------------------------------------------ */

#if CONFIG_EBURNET_VLESS
static ssize_t reality_send_fn(void *ctx, const uint8_t *buf, size_t len)
{
    return reality_send((reality_conn_t *)ctx, buf, len);
}
#endif

/* ------------------------------------------------------------------ */
/*  Хелперы: EPOLLOUT управление на client_fd                          */
/* ------------------------------------------------------------------ */

static void relay_client_epollout_set(dispatcher_state_t *ds, relay_conn_t *r)
{
    if (r->epollout_client || r->client_fd < 0) return;
    struct epoll_event mod = {
        .events   = EPOLLIN | EPOLLOUT,
        .data.ptr = &r->ep_client,
    };
    if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD, r->client_fd, &mod) == 0)
        r->epollout_client = true;
    else
        log_msg(LOG_WARN, "relay: epoll MOD client EPOLLOUT: %s", strerror(errno));
}

static void relay_client_epollout_clear(dispatcher_state_t *ds, relay_conn_t *r)
{
    if (!r->epollout_client || r->client_fd < 0) return;
    /* LT mode: ClientHello может лежать в буфере пока идёт VLESS handshake.
     * EPOLLET здесь убивает EPOLLIN если данные уже были к моменту MOD.
     * WHY: видели in=0..30 bytes_in при out=6500 — edge потерян при epollout_clear. */
    struct epoll_event mod = {
        .events   = EPOLLIN,
        .data.ptr = &r->ep_client,
    };
    if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD, r->client_fd, &mod) == 0)
        r->epollout_client = false;
}

/* T0-03: forward declarations — определения ниже в файле */
static ssize_t grpc_tls_send(void *ctx, uint8_t *buf, size_t len);
static ssize_t grpc_tls_recv(void *ctx, uint8_t *buf, size_t len);
#if CONFIG_EBURNET_GRPC_MULTIPLEX
static int     grpc_stream_send_proto_header(relay_conn_t *r, const ServerConfig *server);
#endif

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

#if CONFIG_EBURNET_AWG
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
#endif

#if CONFIG_EBURNET_SS
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
            /* M-06: partial write = fatal для framed SS 2022 */
            ssize_t w = write(r->client_fd, ds->relay_buf, (size_t)n);
            if (w < 0) return -1;
            if (w < n) {
                log_msg(LOG_DEBUG, "relay: SS partial write %zd/%zd", w, n);
                return -1;
            }
            return w;
        }
    }
#endif

    if (from_client) {
        /*
         * Клиент → upstream
         * Читаем из client_fd (всегда plain TCP)
         */
        /* read/write (или TLS upstream) */
        n = read(r->client_fd, ds->relay_buf, ds->relay_buf_size);
        if (n <= 0)
            return n;

#if CONFIG_EBURNET_VLESS
        /* Reality TLS — fast path: шифрует и отправляет через custom stack.
         * DPI/STLS/wolfSSL обходим, Reality самодостаточный. */
        if (r->reality) {
            if (r->vision)
                return vision_write_ex(r->vision, reality_send_fn,
                                       r->reality,
                                       ds->relay_buf, (size_t)n);
            return reality_send((reality_conn_t *)r->reality,
                                  ds->relay_buf, (size_t)n);
        }
#endif

#if CONFIG_EBURNET_DPI
        if (!r->use_tls && r->dpi_bypass && !r->dpi_first_done) {
            r->dpi_first_done = true;

            /* Получить стратегию из адаптивного кэша */
            uint32_t dst_ip = (r->dst.ss_family == AF_INET)
                ? ntohl(((struct sockaddr_in *)&r->dst)->sin_addr.s_addr) : 0u;
            r->dpi_strategy = dpi_adapt_get(&g_dpi_adapt, dst_ip);

            /* Инициализация параметров стратегии из g_config */
            dpi_strategy_config_t strat;
            memset(&strat, 0, sizeof(strat));
            strat.enabled      = true;
            strat.split_pos    = (g_config && g_config->dpi_split_pos > 0)
                                 ? g_config->dpi_split_pos    : 1;
            strat.fake_ttl     = (g_config && g_config->dpi_fake_ttl > 0)
                                 ? g_config->dpi_fake_ttl     : 5;
            strat.fake_repeats = (g_config && g_config->dpi_fake_repeats > 0)
                                 ? g_config->dpi_fake_repeats : 8;
            {   int _n = snprintf(strat.fake_sni, sizeof(strat.fake_sni), "%s",
                         (g_config && g_config->dpi_fake_sni[0])
                         ? g_config->dpi_fake_sni : EBURNET_DPI_DEFAULT_FAKE_SNI);
                if (_n < 0 || (size_t)_n >= sizeof(strat.fake_sni))
                    log_msg(LOG_WARN, "DPI: fake_sni обрезан: %s:%d", __FILE__, __LINE__);
            }

            bool do_fake = (r->dpi_strategy == DPI_STRAT_FAKE_TTL ||
                            r->dpi_strategy == DPI_STRAT_BOTH);
            bool do_frag = (r->dpi_strategy == DPI_STRAT_FRAGMENT ||
                            r->dpi_strategy == DPI_STRAT_BOTH);

            if (do_fake) {
                /* malloc чтобы не переполнять стек MIPS (8KB) */
                uint8_t *fake_buf = malloc(DPI_FAKE_PKT_SIZE);
                if (fake_buf) {
                    int fake_len = dpi_make_fake_payload(fake_buf, DPI_FAKE_PKT_SIZE,
                                                          DPI_PROTO_TCP,
                                                          strat.fake_sni);
                    if (fake_len > 0) {
                        if (dpi_send_fake(r->upstream_fd, fake_buf, fake_len,
                                          strat.fake_ttl, strat.fake_repeats) < 0)
                            log_msg(LOG_DEBUG, "dpi: fake+TTL упал, продолжаем");
                    }
                    free(fake_buf);
                }
            }

            if (do_frag) {
                return (ssize_t)dpi_send_fragment(r->upstream_fd,
                                                   ds->relay_buf, (int)n,
                                                   strat.split_pos);
            }
            /* DPI_STRAT_NONE или DPI_STRAT_FAKE_TTL (без фрагментации):
             * продолжаем обычной записью в upstream (fall-through) */
        }
#endif

#if CONFIG_EBURNET_STLS
        /* ShadowTLS transport: обернуть данные перед отправкой */
        if (r->stls && r->stls->state == STLS_ACTIVE && !r->use_tls) {
            int wlen = stls_wrap(r->stls, ds->relay_buf, (int)n,
                                 ds->stls_buf,
                                 (int)(ds->relay_buf_size + 9));
            if (wlen < 0) return -1;
            ssize_t sent = send(r->upstream_fd, ds->stls_buf, (size_t)wlen,
                                MSG_NOSIGNAL);
            return (sent == wlen) ? n : (ssize_t)-1;
        }
#endif

        /* T0-04: WS transport — обернуть клиентские данные в WS binary frame */
        if (r->ws) {
            ssize_t s = ws_client_send(r->ws, grpc_tls_send, r->tls,
                                       ds->relay_buf, (size_t)n);
            return s < 0 ? -1 : n;
        }

        /* T0-03: gRPC transport — обернуть клиентские данные в gRPC DATA frame.
         * WHY цикл: grpc_send отправляет не более GRPC_SEND_CHUNK (498) байт за
         * вызов. Если не цикл — read() вернёт n>498, мы отправим только 498 байт,
         * остаток потеряется при следующем read(). TLS ClientHello обычно 500-600
         * байт → обрезанный ClientHello → сервер не может распарсить → out=0. */
        if (r->grpc) {
            size_t off = 0;
            while (off < (size_t)n) {
                ssize_t s = grpc_send(r->grpc, grpc_tls_send, r->tls,
                                      ds->relay_buf + off, (size_t)n - off);
                if (s < 0) break;
                off += (size_t)s;
            }
            return off > 0 ? (ssize_t)off : (ssize_t)-1;
        }
#if CONFIG_EBURNET_GRPC_MULTIPLEX
        if (r->grpc_stream) {
            void *tctx = r->grpc_stream->conn->tls;
            if (grpc_stream_send(r->grpc_stream, grpc_pool_tls_send, tctx,
                                 ds->relay_buf, (size_t)n) < 0)
                return -1;
            return n;
        }
#endif

#if CONFIG_EBURNET_QUIC
        /* T0-07: Hysteria2 — записать данные в QUIC TCP stream */
        if (r->hy2_conn && r->hy2_stream)
            return hysteria2_tcp_send((hysteria2_conn_t *)r->hy2_conn,
                                      (hysteria2_stream_t *)r->hy2_stream,
                                      ds->relay_buf, (size_t)n);
#endif

        if (r->use_tls) {
#if CONFIG_EBURNET_VLESS
            /* T0-02: Vision полный state machine (padding+direct transition) */
            if (r->vision)
                return vision_write(r->vision, r->upstream_fd,
                                    r->tls, r->use_tls,
                                    ds->relay_buf, (size_t)n);
#endif
            return tls_send(r->tls, ds->relay_buf, n);
        }

        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(r->upstream_fd,
                              ds->relay_buf + written, n - written);
            if (w < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (written == 0) { errno = EAGAIN; return -1; }
                    break;
                }
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

        /* WHY: если предыдущий write вернул EAGAIN, данные сохранены в
         * to_client_buf. Дренируем их до чтения новых данных из upstream:
         * relay_buf — общий буфер, он будет перезаписан при следующем вызове. */
        if (r->to_client_buf) {
            ssize_t w = write(r->client_fd,
                              r->to_client_buf + r->to_client_pos,
                              r->to_client_len  - r->to_client_pos);
            if (w > 0) {
                r->to_client_pos += (size_t)w;
                if (r->to_client_pos >= r->to_client_len) {
                    free(r->to_client_buf); r->to_client_buf = NULL;
                    r->to_client_len = 0;   r->to_client_pos = 0;
                    relay_client_epollout_clear(ds, r);
                }
                return w;
            }
            /* EAGAIN или ошибка: клиент ещё не готов принять */
            if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                errno = EAGAIN;
            return -1;
        }

#if CONFIG_EBURNET_STLS
        /* ShadowTLS transport: прочитать и развернуть */
        if (r->stls && r->stls->state == STLS_ACTIVE && !r->use_tls) {
            n = read(r->upstream_fd, ds->relay_buf, ds->relay_buf_size);
            if (n <= 0) return n;
            int ulen = stls_unwrap(r->stls, ds->relay_buf, (int)n,
                                   ds->stls_buf,
                                   (int)(ds->relay_buf_size + 9));
            if (ulen <= 0) return (ulen == 0) ? 0 : -1;
            ssize_t wr = 0;
            while (wr < ulen) {
                ssize_t w = write(r->client_fd, ds->stls_buf + wr,
                                  (size_t)(ulen - wr));
                if (w < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        if (wr == 0) { errno = EAGAIN; return -1; }
                        break;
                    }
                    return -1;
                }
                wr += w;
            }
            return wr;
        }
#endif

#if CONFIG_EBURNET_VLESS
        /* T0-02 Step 11: XTLS splice — после cmd=Direct xray bypasses outer TLS
         * (и wolfSSL, и Reality) и шлёт raw inner TLS bytes прямо в TCP socket.
         * WHY для Reality тоже: xray переключается в splice mode независимо от
         * transport — raw TCP recv нужен и для Reality, иначе reality_recv
         * пытается расшифровать raw inner TLS как outer Reality TLS → AEAD fail. */
        if (r->vision && r->vision->splice_read) {
            int raw_fd = r->reality
                       ? ((reality_conn_t *)r->reality)->fd
                       : tls_raw_fd(r->tls);
            if (raw_fd < 0) return -1;
            n = recv(raw_fd, ds->relay_buf, ds->relay_buf_size, 0);
            if (n <= 0) return n;
        } else if (r->reality) {
            /* Reality TLS: получаем зашифрованные application_data records
             * и расшифровываем через custom stack. */
            n = reality_recv((reality_conn_t *)r->reality,
                               ds->relay_buf, ds->relay_buf_size);
        } else
#endif
        /* T0-04: WS transport — снять WS frame header */
        if (r->ws)
            n = ws_client_recv(r->ws, grpc_tls_recv, r->tls,
                               ds->relay_buf, ds->relay_buf_size);
        /* T0-03: gRPC transport — снять H2 + gRPC framing */
        else if (r->grpc)
            n = grpc_recv(r->grpc, grpc_tls_send, grpc_tls_recv, r->tls,
                          ds->relay_buf, ds->relay_buf_size);
#if CONFIG_EBURNET_GRPC_MULTIPLEX
        else if (r->grpc_stream) {
            grpc_stream_t *_gs  = r->grpc_stream;
            void          *_tctx = _gs->conn->tls;
            /* Вторичный поток (wake_fd >= 0): дренируем eventfd счётчик */
            if (_gs->wake_fd >= 0) {
                uint64_t _val;
                (void)read(r->upstream_fd, &_val, sizeof(_val));
            }
            n = grpc_stream_recv(_gs, grpc_pool_tls_send, grpc_pool_tls_recv,
                                 _tctx, ds->relay_buf, ds->relay_buf_size);
        }
#endif
#if CONFIG_EBURNET_QUIC
        /* T0-07: Hysteria2 — прочитать данные из QUIC TCP stream */
        else if (r->hy2_conn && r->hy2_stream)
            n = hysteria2_tcp_recv((hysteria2_conn_t *)r->hy2_conn,
                                   (hysteria2_stream_t *)r->hy2_stream,
                                   ds->relay_buf, ds->relay_buf_size);
#endif
        else if (r->use_tls)
            n = tls_recv(r->tls, ds->relay_buf, ds->relay_buf_size);
        else
            n = read(r->upstream_fd, ds->relay_buf, ds->relay_buf_size);

        if (n <= 0)
            return n;

#if CONFIG_EBURNET_VLESS
        /* T0-02: Vision unpad — снять padding headers от сервера in-place.
         * vision_unpad возвращает -1+EAGAIN когда весь chunk был padding (нет
         * content для forward'а). Пробрасываем -1+EAGAIN наверх — relay_handle_active
         * корректно обработает как "ждём ещё" (break без half_close). */
        if (r->vision && !r->vision->read_direct) {
            ssize_t up = vision_unpad(r->vision, ds->relay_buf, (size_t)n);
            if (up < 0) return -1;   /* errno=EAGAIN preserved */
            n = up;
        }
#endif



        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(r->client_fd,
                              ds->relay_buf + written, n - written);
            if (w > 0) { written += w; continue; }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* WHY: relay_buf — shared, перезапишется следующим вызовом.
                 * Сохраняем недоставленный остаток чтобы не потерять байты TCP
                 * stream (потеря → HTTP/2 corruption → session reset storm). */
                size_t remaining = (size_t)(n - written);
                uint8_t *pb = malloc(remaining);
                if (!pb) {
                    /* WHY: OOM при сохранении хвоста partial write. remaining байт
                     * нельзя спасти — relay_buf будет перезаписан следующим upstream
                     * read. TCP stream нарушен → единственный safe path: закрыть
                     * relay. Лучше ECONNRESET клиенту чем тихая потеря фреймов.
                     * errno=EAGAIN: предотвращает double-free в call sites (они
                     * не вызовут relay_free повторно при errno==EAGAIN). */
                    log_msg(LOG_WARN,
                        "relay_transfer: OOM remaining=%zu — closing relay", remaining);
                    relay_free(ds, r);
                    errno = EAGAIN;
                    return -1;
                }
                memcpy(pb, ds->relay_buf + written, remaining);
                r->to_client_buf = pb;
                r->to_client_len = remaining;
                r->to_client_pos = 0;
                relay_client_epollout_set(ds, r);
                if (written == 0) { errno = EAGAIN; return -1; }
                break;  /* частично записали — вернём written */
            }
            return -1;
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
    ds->epoll_fd = -1;

    /* Лимит соединений по профилю */
    switch (profile) {
    case DEVICE_MICRO:  ds->conns_max = MICRO_MAX_CONNECTIONS;  break;
    case DEVICE_NORMAL: ds->conns_max = NORMAL_MAX_CONNECTIONS; break;
    case DEVICE_FULL:   ds->conns_max = FULL_MAX_CONNECTIONS;   break;
    default:            ds->conns_max = NORMAL_MAX_CONNECTIONS; break;
    }

    {
        long free_kb = sysconf(_SC_AVPHYS_PAGES) * sysconf(_SC_PAGESIZE) / 1024;
        size_t need_kb = (size_t)ds->conns_max * sizeof(relay_conn_t) / 1024;
        if (free_kb > 0 && (size_t)free_kb < need_kb * 2)
            log_msg(LOG_WARN,
                    "relay: возможна нехватка RAM: need~%zuKB free~%ldKB",
                    need_kb, free_kb);
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

#if CONFIG_EBURNET_STLS
    ds->stls_buf = malloc(ds->relay_buf_size + 9);
    if (!ds->stls_buf) {
        log_msg(LOG_ERROR, "relay: не удалось выделить stls_buf");
        free(ds->relay_buf); ds->relay_buf = NULL;
        free(ds->conns);     ds->conns     = NULL;
        return -1;
    }
#endif

    /* epoll */
    ds->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ds->epoll_fd < 0) {
        log_msg(LOG_ERROR, "relay: epoll_create1: %s", strerror(errno));
        free(ds->relay_buf); ds->relay_buf = NULL;
        free(ds->conns);     ds->conns     = NULL;
        return -1;
    }

    /* splice удалён: shared pipe = data corruption (H-12, C-05) */

    ds->health_reset_at = time(NULL) + TIMEOUT_HEALTH_RESET_SEC;

#if CONFIG_EBURNET_DPI
    dpi_adapt_init(&g_dpi_adapt);
    dpi_adapt_load(&g_dpi_adapt, "/etc/4eburnet/dpi_cache.bin");
#endif

#if CONFIG_EBURNET_GRPC_MULTIPLEX
    ds->grpc_pool = grpc_pool_init();
    if (!ds->grpc_pool) {
        log_msg(LOG_ERROR, "relay: не удалось инициализировать gRPC pool");
        if (ds->epoll_fd >= 0) { close(ds->epoll_fd); ds->epoll_fd = -1; }
        free(ds->relay_buf); ds->relay_buf = NULL;
#if CONFIG_EBURNET_STLS
        if (ds->stls_buf) { free(ds->stls_buf); ds->stls_buf = NULL; }
#endif
        free(ds->conns); ds->conns = NULL;
        return -1;
    }
#endif

#if CONFIG_EBURNET_XUDP
    ds->muxcool_pool = muxcool_pool_init();
    if (!ds->muxcool_pool) {
        log_msg(LOG_ERROR, "relay: не удалось инициализировать muxcool pool");
#if CONFIG_EBURNET_GRPC_MULTIPLEX
        if (ds->grpc_pool) { grpc_pool_free(ds->grpc_pool); ds->grpc_pool = NULL; }
#endif
        if (ds->epoll_fd >= 0) { close(ds->epoll_fd); ds->epoll_fd = -1; }
        free(ds->relay_buf); ds->relay_buf = NULL;
#if CONFIG_EBURNET_STLS
        if (ds->stls_buf) { free(ds->stls_buf); ds->stls_buf = NULL; }
#endif
        free(ds->conns); ds->conns = NULL;
        return -1;
    }
    ds->udp_reply_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ds->udp_reply_fd >= 0) {
        int val = 1;
        if (setsockopt(ds->udp_reply_fd, IPPROTO_IP,
                       IP_TRANSPARENT, &val, sizeof(val)) < 0)
            log_msg(LOG_WARN, "relay: udp_reply_fd IP_TRANSPARENT: %s",
                    strerror(errno));
    } else {
        log_msg(LOG_WARN, "relay: не удалось создать UDP reply socket: %s",
                strerror(errno));
        ds->udp_reply_fd = -1;
    }
#endif

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
    const EburNetConfig *cfg = g_config;

    /* Выбрать сервер через health-check */
#if CONFIG_EBURNET_SNIFFER
    char ja3[33] = {0};
#endif
    /* Домен назначения — сохраняется из fake-ip/SNI для VLESS ADDR_DOMAIN */
    const char *relay_domain = NULL;
    char pending_group_name[64] = "";
    int idx;
    if (g_rules_engine && g_rules_engine->rule_count > 0) {
        /* 3.6: SNI sniffer — извлечь домен из TLS ClientHello */
        char sni[256] = {0};
        const char *domain = NULL;

        /* Fake-IP: если dst IP из пула → знаем домен без SNI */
#if CONFIG_EBURNET_FAKE_IP
        if (g_fake_ip) {
            const char *fake_domain =
                fake_ip_lookup_by_ip(g_fake_ip, &conn->dst);

            /* IPv6 fake-ip lookup (v1.5-3) */
            if (!fake_domain && conn->dst.ss_family == AF_INET6) {
                const struct sockaddr_in6 *s6 =
                    (const struct sockaddr_in6 *)&conn->dst;
                /* IPv4-mapped (::ffff:0:0/96) уже обработан выше */
                static const uint8_t v4mapped_pfx[12] =
                    {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff};
                if (memcmp(s6->sin6_addr.s6_addr, v4mapped_pfx, 12) != 0) {
                    /* Чистый IPv6 — ищем в fake6 таблице */
                    if (g_fake_ip->v6_enabled)
                        fake_domain = fake_ip6_lookup_by_ip(
                            g_fake_ip, &s6->sin6_addr);
                }
            }

            if (fake_domain) {
                domain = fake_domain;
                relay_domain = fake_domain;
            }
        }
#endif

#if CONFIG_EBURNET_SNIFFER
        if (!domain && conn->fd >= 0) {
            ClientHelloInfo *hello = calloc(1, sizeof(ClientHelloInfo));
            if (hello) {
                if (sniffer_parse_hello(conn->fd, hello) == 0) {
                    if (hello->sni_found) {
                        size_t snl = strlen(hello->sni);
                        if (snl >= sizeof(sni)) snl = sizeof(sni) - 1;
                        memcpy(sni, hello->sni, snl);
                        sni[snl] = '\0';
                        domain = sni;
                        relay_domain = sni;
                        log_msg(LOG_DEBUG, "SNI sniffer: %s", sni);
                    }
                    char ja4[40] = {0};
                    ja3_compute(hello, ja3, NULL, 0);
                    ja4_compute(hello, ja4);
                    if (ja3[0]) memcpy(g_last_ja3, ja3, sizeof(g_last_ja3));
                    const char *browser = ja3_match_reference(ja3);
                    if (browser)
                        log_msg(LOG_DEBUG,
                            "TLS fingerprint: %s JA3=%s", browser, ja3);
                    else if (ja3[0])
                        log_msg(LOG_DEBUG,
                            "TLS fingerprint: JA3=%s JA4=%s", ja3, ja4);
                    if (hello->ech_found) {
                        log_msg(LOG_DEBUG,
                            "TLS ECH detected (ext=0x%04x): SNI encrypted, IP-based routing",
                            (unsigned)hello->ech_ext_type);
                        stats_inc_ech(hello->ech_ext_type);
                    }
                }
                free(hello);
            }
        }
#endif

#if CONFIG_EBURNET_DPI
        dpi_match_t dpi_match = DPI_MATCH_NONE;
        if (cfg->dpi_enabled && dpi_filter_is_ready()) {
            uint32_t  dst4     = 0;
            uint16_t  dst_port = 0;
            uint8_t   dst6[16];
            uint8_t  *ip6_ptr  = NULL;
            if (conn->dst.ss_family == AF_INET) {
                const struct sockaddr_in *s4 =
                    (const struct sockaddr_in *)&conn->dst;
                dst4     = ntohl(s4->sin_addr.s_addr);
                dst_port = ntohs(s4->sin_port);
            } else if (conn->dst.ss_family == AF_INET6) {
                const struct sockaddr_in6 *s6 =
                    (const struct sockaddr_in6 *)&conn->dst;
                memcpy(dst6, &s6->sin6_addr, 16);
                ip6_ptr  = dst6;
                dst_port = ntohs(s6->sin6_port);
            }
            dpi_match = dpi_filter_match(domain, dst4, ip6_ptr, dst_port);
        }
#endif

        /* Диагностика маршрутизации: какое правило сработало → группа → idx */
        rule_match_result_t _mr_log =
            rules_engine_match(g_rules_engine, domain, &conn->dst);
        const char *_rt_log =
            (_mr_log.type == RULE_TARGET_GROUP)  ? _mr_log.group_name :
            (_mr_log.type == RULE_TARGET_DIRECT) ? "DIRECT" : "REJECT";
        if (_mr_log.type == RULE_TARGET_GROUP && _mr_log.group_name[0])
            strncpy(pending_group_name, _mr_log.group_name,
                    sizeof(pending_group_name) - 1);
        const char *_rule_kind;
        switch (_mr_log.matched_rule_type) {
        case RULE_TYPE_DOMAIN:         _rule_kind = "DOMAIN";         break;
        case RULE_TYPE_DOMAIN_SUFFIX:  _rule_kind = "DOMAIN-SUFFIX";  break;
        case RULE_TYPE_DOMAIN_KEYWORD: _rule_kind = "DOMAIN-KEYWORD"; break;
        case RULE_TYPE_IP_CIDR:        _rule_kind = "IP-CIDR";        break;
        case RULE_TYPE_RULE_SET:       _rule_kind = "RULE-SET";       break;
        case RULE_TYPE_MATCH:          _rule_kind = "MATCH";          break;
        case RULE_TYPE_GEOIP:          _rule_kind = "GEOIP";          break;
        case RULE_TYPE_GEOSITE:        _rule_kind = "GEOSITE";        break;
        case RULE_TYPE_DST_PORT:       _rule_kind = "DST-PORT";       break;
        case RULE_TYPE_IP_CIDR6:       _rule_kind = "IP-CIDR6";       break;
        default:                       _rule_kind = "NO-MATCH";       break;
        }
        idx = rules_engine_get_server(g_rules_engine, domain, &conn->dst);
        {
            char _dst_log[64];
            net_format_addr(&conn->dst, _dst_log, sizeof(_dst_log));
            log_msg(LOG_INFO,
                "relay route TCP: dst=%s domain=%s rule=%s payload='%s' group=%s idx=%d",
                _dst_log, domain ? domain : "(null)",
                _rule_kind, _mr_log.matched_payload, _rt_log, idx);
        }
        if (idx == -2) {
            log_msg(LOG_DEBUG, "relay: REJECT (rules engine)");
            close(conn->fd);
            return;
        }
        if (idx == -1) {
            /* DIRECT: relay напрямую к dst без прокси */
            char dst_str[64];
            net_format_addr(&conn->dst, dst_str, sizeof(dst_str));
            log_msg(LOG_INFO, "relay: DIRECT %s (domain=%s)",
                    dst_str, relay_domain ? relay_domain : "(null)");

            relay_conn_t *r = relay_alloc(ds);
            if (!r) { close(conn->fd); return; }

            r->client_fd  = conn->fd;
            r->dst        = conn->dst;
            r->created_at = time(NULL);
            r->server_idx = -1;
            /* MAC клиента для traffic stats */
            if (conn->src.ss_family == AF_INET) {
                uint32_t cip = ntohl(
                    ((const struct sockaddr_in *)&conn->src)->sin_addr.s_addr);
                snprintf(r->client_mac, sizeof(r->client_mac), "%s",
                         arp_lookup_mac(cip));
            }
#if CONFIG_EBURNET_SNIFFER
            if (ja3[0]) memcpy(r->ja3, ja3, sizeof(r->ja3));
#endif
#if CONFIG_EBURNET_DPI
            r->dpi_bypass    = (dpi_match == DPI_MATCH_BYPASS);
            r->dpi_first_done = false;  /* явно, хотя memset уже 0 */
#endif

            int dfd = socket(conn->dst.ss_family,
                             SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (dfd < 0) { relay_free(ds, r); return; }
            r->upstream_fd = dfd;

            socklen_t slen = (conn->dst.ss_family == AF_INET6)
                ? sizeof(struct sockaddr_in6)
                : sizeof(struct sockaddr_in);
            int rc = connect(dfd, (struct sockaddr *)&conn->dst, slen);
            if (rc < 0 && errno != EINPROGRESS) {
                relay_free(ds, r);
                return;
            }

            r->use_tls = false;
            r->state   = (rc == 0) ? RELAY_ACTIVE : RELAY_CONNECTING;

            /* Инициализировать relay теги ДО epoll_ctl */
            r->ep_client.relay     = r;
            r->ep_client.is_client = true;
            r->ep_upstream.relay     = r;
            r->ep_upstream.is_client = false;

            struct epoll_event ev = { .events = EPOLLIN };
            ev.data.ptr = &r->ep_client;
            if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD, r->client_fd, &ev) < 0)
                log_msg(LOG_WARN, "relay: epoll_ctl(DIRECT client): %s", strerror(errno));
            ev.data.ptr = &r->ep_upstream;
            ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
            if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD, r->upstream_fd, &ev) < 0)
                log_msg(LOG_WARN, "relay: epoll_ctl(DIRECT upstream): %s", strerror(errno));

            ds->total_accepted++;
            return;
        }
    } else {
        idx = dispatcher_select_server(ds, cfg);
    }
    if (idx < 0) {
        log_msg(LOG_WARN, "relay: нет доступных серверов");
        close(conn->fd);
        return;
    }
    const ServerConfig *server = config_get_server(cfg, idx);
    if (!server) {
        log_msg(LOG_WARN, "relay: сервер idx=%d не найден", idx);
        close(conn->fd); return;
    }
    log_msg(LOG_INFO,
            "relay: pick server[%d] proto='%s' name='%s' addr=%s:%u",
            idx, server->protocol, server->name,
            server->address, server->port);

    /* Выделить слот */
    relay_conn_t *r = relay_alloc(ds);
    if (!r) {
        log_msg(LOG_WARN, "relay: relay_alloc fail (slots полон?)");
        close(conn->fd);
        return;
    }

    r->client_fd  = conn->fd;
    r->dst        = conn->dst;
    r->created_at = time(NULL);
    r->server_idx = idx;
    if (relay_domain && relay_domain[0])
        strncpy(r->domain, relay_domain, sizeof(r->domain) - 1);
    strncpy(r->group_name, pending_group_name, sizeof(r->group_name) - 1);
    /* MAC клиента для traffic stats */
    if (conn->src.ss_family == AF_INET) {
        uint32_t cip = ntohl(
            ((const struct sockaddr_in *)&conn->src)->sin_addr.s_addr);
        snprintf(r->client_mac, sizeof(r->client_mac), "%s",
                 arp_lookup_mac(cip));
    }
#if CONFIG_EBURNET_SNIFFER
    if (ja3[0]) memcpy(r->ja3, ja3, sizeof(r->ja3));
#endif

#if CONFIG_EBURNET_AWG
    /* AWG: UDP, минует TCP connect */
    if (strcmp(server->protocol, "awg") == 0) {
        log_msg(LOG_INFO, "AWG: вход в protocol_start (срв %d)", idx);
        int _awg_rc = awg_protocol_start(r, &conn->dst, server);
        log_msg(LOG_INFO, "AWG: protocol_start rc=%d errno=%d",
                _awg_rc, errno);
        if (_awg_rc < 0) {
            dispatcher_server_result(ds, idx, false);
            relay_free(ds, r);
        } else {
            /* L-05: AWG client_fd в epoll (чтение от клиента) */
            struct epoll_event cev = {
                .events = EPOLLIN,
                .data.ptr = &r->ep_client,
            };
            if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD, r->client_fd, &cev) < 0)
                log_msg(LOG_WARN, "AWG: epoll_ctl client_fd: %s", strerror(errno));
            ds->total_accepted++;
            char dst_str[64];
            net_format_addr(&r->dst, dst_str, sizeof(dst_str));
            log_msg(LOG_DEBUG, "relay: %s → %s:%u (AWG UDP)",
                    dst_str, server->address, server->port);
        }
        return;
    }
#endif

#if CONFIG_EBURNET_GRPC_MULTIPLEX
    /* gRPC multiplexing: захватить stream из pool до TCP connect.
     * needs_io=0: существующее соединение активно → немедленно RELAY_ACTIVE.
     * needs_io=1: новое соединение → продолжаем к upstream_connect (TCP+TLS+H2). */
    if (server->transport[0] && strcmp(server->transport, "grpc") == 0) {
        char authority[288];
        int _an;
        if (server->port == 443 || server->port == 80)
            _an = snprintf(authority, sizeof(authority), "%s", server->address);
        else
            _an = snprintf(authority, sizeof(authority),
                           "%s:%u", server->address, server->port);
        if (_an < 0 || (size_t)_an >= sizeof(authority))
            authority[sizeof(authority) - 1] = '\0';
        const char *svc = server->grpc_service_name[0]
                          ? server->grpc_service_name : "GunService";

        int needs_io = 0, tcp_fd_unused = -1;
        grpc_stream_t *gs = grpc_pool_acquire_stream(ds->grpc_pool, idx,
                                                      authority, svc,
                                                      &needs_io, &tcp_fd_unused);
        if (!gs) {
            log_msg(LOG_WARN, "relay: gRPC pool acquire провалился: %s",
                    strerror(errno));
            dispatcher_server_result(ds, idx, false);
            relay_free(ds, r);
            return;
        }
        r->grpc_stream = gs;

        if (needs_io == 0) {
            /* Вторичный поток: соединение активно, proto header отправляем сразу.
             * r->upstream_fd = eventfd wake_fd (не TCP fd); закрывается grpc_stream_release. */
            r->upstream_fd = gs->wake_fd;

            if (grpc_stream_send_proto_header(r, server) < 0) {
                dispatcher_server_result(ds, idx, false);
                relay_free(ds, r);
                return;
            }
            dispatcher_server_result(ds, idx, true);

            struct epoll_event _wev = {
                .events   = EPOLLIN,
                .data.ptr = &r->ep_upstream,
            };
            if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD, r->upstream_fd, &_wev) < 0) {
                log_msg(LOG_ERROR, "relay: epoll_ctl(wake_fd): %s", strerror(errno));
                /* wake_fd будет закрыт в relay_free через grpc_stream_release */
                r->upstream_fd = -1;
                relay_free(ds, r);
                return;
            }

            r->state             = RELAY_ACTIVE;
            r->client_sent_first = true;
            log_msg(LOG_INFO, "relay [%s] gRPC мультиплекс stream id=%u",
                    server->name, gs->stream_id);

            struct epoll_event _cev2 = {
                .events   = EPOLLIN | EPOLLRDHUP,
                .data.ptr = &r->ep_client,
            };
            if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD, r->client_fd, &_cev2) < 0)
                log_msg(LOG_WARN, "relay: epoll_ctl(client): %s", strerror(errno));
            ds->total_accepted++;
            return;
        }
        /* needs_io == 1: продолжаем к upstream_connect (TCP+TLS+H2) */
    }
#endif /* CONFIG_EBURNET_GRPC_MULTIPLEX */

#if CONFIG_EBURNET_XUDP
    /* XUDP/Mux.Cool: используется ТОЛЬКО для UDP трафика (packet-encoding=xudp
     * в mihomo означает UDP-инкапсуляцию, НЕ TCP mux). TCP всегда через
     * обычный VLESS CMD=TCP. Блок ниже зарезервирован для UDP relay path. */
    if (false &&
        server->packet_encoding[0] &&
        strcmp(server->packet_encoding, "xudp") == 0 &&
        (strcmp(server->protocol, "vless") == 0 ||
         strcmp(server->protocol, "trojan") == 0)) {
        uint8_t  m_addr[16];
        uint8_t  m_addr_type = 0, m_addr_len = 0;
        uint16_t m_port = 0;
        bool     m_ok = false;
        if (conn->dst.ss_family == AF_INET) {
            const struct sockaddr_in *s4 =
                (const struct sockaddr_in *)&conn->dst;
            memcpy(m_addr, &s4->sin_addr.s_addr, 4);
            m_addr_type = MUXCOOL_ADDR_IPV4;
            m_addr_len  = 4;
            m_port      = ntohs(s4->sin_port);
            m_ok = true;
        } else if (conn->dst.ss_family == AF_INET6) {
            const struct sockaddr_in6 *s6 =
                (const struct sockaddr_in6 *)&conn->dst;
            memcpy(m_addr, &s6->sin6_addr, 16);
            m_addr_type = MUXCOOL_ADDR_IPV6;
            m_addr_len  = 16;
            m_port      = ntohs(s6->sin6_port);
            m_ok = true;
        }

        if (m_ok) {
            int m_needs_io = 0;
            muxcool_stream_t *ms = muxcool_pool_acquire_stream(
                ds->muxcool_pool, idx,
                false,                    /* TCP relay через Mux */
                m_addr_type, m_addr, m_addr_len, m_port,
                NULL,                     /* client_src=NULL → no GlobalID */
                &m_needs_io);
            if (!ms) {
                log_msg(LOG_WARN, "muxcool: pool acquire fail: %s",
                        strerror(errno));
                /* Fallback на обычный путь без xudp */
            } else {
                r->muxcool_stream = ms;
                if (m_needs_io == 0) {
                    /* Reuse: conn активен. NEW frame отправится при первом
                     * client write через muxcool_stream_send. */
                    if (ms->wake_fd < 0) {
                        log_msg(LOG_ERROR,
                                "muxcool: wake_fd<0 на reuse");
                        muxcool_stream_release(ms);
                        r->muxcool_stream = NULL;
                        dispatcher_server_result(ds, idx, false);
                        relay_free(ds, r);
                        return;
                    }
                    r->upstream_fd = ms->wake_fd;
                    struct epoll_event _wev = {
                        .events   = EPOLLIN,
                        .data.ptr = &r->ep_upstream,
                    };
                    if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD,
                                  r->upstream_fd, &_wev) < 0) {
                        log_msg(LOG_ERROR, "muxcool: epoll(wake_fd): %s",
                                strerror(errno));
                        r->upstream_fd = -1;
                        relay_free(ds, r);
                        return;
                    }
                    dispatcher_server_result(ds, idx, true);
                    r->state = RELAY_MUXCOOL_ACTIVE;
                    r->client_sent_first = true;
                    log_msg(LOG_INFO,
                            "relay [%s] muxcool reuse sid=%u",
                            server->name, ms->session_id);
                    struct epoll_event _cev = {
                        .events   = EPOLLIN | EPOLLRDHUP,
                        .data.ptr = &r->ep_client,
                    };
                    if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD,
                                  r->client_fd, &_cev) < 0)
                        log_msg(LOG_WARN, "muxcool: epoll(client): %s",
                                strerror(errno));
                    ds->total_accepted++;
                    return;
                }
                /* needs_io == 1: продолжить к upstream_connect */
            }
        }
    }
#endif /* CONFIG_EBURNET_XUDP */

    /* Неблокирующее подключение к upstream (TCP) */
    if (upstream_connect(ds, r, server) < 0) {
        dispatcher_server_result(ds, idx, false);
        relay_free(ds, r);
        return;
    }

    /* Добавить client_fd в epoll (EPOLLIN — данные от клиента).
     * WHY LT (без EPOLLET): iPhone может отправить inner ClientHello пока
     * идёт Reality/VLESS handshake к upstream. relay_handle_tls/reality
     * делают `if (ep->is_client) return;` без чтения → EPOLLET edge event
     * "потребляется" и не повторяется до новых байт. ClientHello навсегда
     * остаётся в kernel buffer, bytes_in=0, видеотрафик не идёт.
     * LT mode гарантирует повторный EPOLLIN на каждом тике пока буфер не
     * пуст → handshake handlers продолжают игнорировать, но в RELAY_ACTIVE
     * мы наконец прочитаем ClientHello. */
    struct epoll_event ev = {
        .events   = EPOLLIN | EPOLLRDHUP,
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
/* ------------------------------------------------------------------ */
/*  UDP session table (XUDP/Mux.Cool) — Шаг 1                         */
/* ------------------------------------------------------------------ */

#if CONFIG_EBURNET_XUDP

static int sockaddr_equal(const struct sockaddr_storage *a,
                          const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family)
        return 0;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
        const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
        return a4->sin_addr.s_addr == b4->sin_addr.s_addr &&
               a4->sin_port == b4->sin_port;
    }
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
        return memcmp(&a6->sin6_addr, &b6->sin6_addr, 16) == 0 &&
               a6->sin6_port == b6->sin6_port;
    }
    return 0;
}

static uint32_t udp_session_hash(const udp_session_key_t *k)
{
    uint32_t h = 0;
    if (k->src.ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)&k->src;
        const struct sockaddr_in *d4 = (const struct sockaddr_in *)&k->dst;
        h ^= s4->sin_addr.s_addr ^ (uint32_t)s4->sin_port;
        h ^= d4->sin_addr.s_addr ^ (uint32_t)d4->sin_port;
    } else if (k->src.ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)&k->src;
        const struct sockaddr_in6 *d6 = (const struct sockaddr_in6 *)&k->dst;
        const uint32_t *sa = (const uint32_t *)&s6->sin6_addr;
        const uint32_t *da = (const uint32_t *)&d6->sin6_addr;
        h ^= sa[0] ^ sa[1] ^ sa[2] ^ sa[3] ^ (uint32_t)s6->sin6_port;
        h ^= da[0] ^ da[1] ^ da[2] ^ da[3] ^ (uint32_t)d6->sin6_port;
    }
    return h & (UDP_SESSION_TABLE_SIZE - 1);
}

static udp_session_t *udp_session_find(dispatcher_state_t *ds,
                                        const udp_session_key_t *k)
{
    uint32_t idx = udp_session_hash(k);
    udp_session_t *s = ds->udp_sessions[idx];
    while (s) {
        if (sockaddr_equal(&s->key.src, &k->src) &&
            sockaddr_equal(&s->key.dst, &k->dst))
            return s;
        s = s->next;
    }
    return NULL;
}

static udp_session_t *udp_session_create(dispatcher_state_t *ds,
                                          const udp_session_key_t *k,
                                          muxcool_stream_t *stream)
{
    udp_session_t *s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->key         = *k;
    s->stream      = stream;
    s->last_active = time(NULL);
    uint32_t idx          = udp_session_hash(k);
    s->next               = ds->udp_sessions[idx];
    ds->udp_sessions[idx] = s;
    ds->udp_session_count++;
    return s;
}

static void udp_sessions_cleanup(dispatcher_state_t *ds, time_t now)
{
    for (int i = 0; i < UDP_SESSION_TABLE_SIZE; i++) {
        udp_session_t **pp = &ds->udp_sessions[i];
        while (*pp) {
            udp_session_t *s = *pp;
            if (now - s->last_active > UDP_SESSION_TTL_SEC) {
                *pp = s->next;
                if (!s->relay_owned && s->stream)
                    muxcool_stream_release(s->stream);
                free(s);
                ds->udp_session_count--;
            } else {
                pp = &s->next;
            }
        }
    }
}

#endif /* CONFIG_EBURNET_XUDP (session table helpers) */

/* ------------------------------------------------------------------ */
/*  dispatcher_handle_udp_reply — ответ клиенту через TPROXY reply fd  */
/* ------------------------------------------------------------------ */

#if CONFIG_EBURNET_XUDP
/* Вызывается когда muxcool_connection_recv_dispatch заполнил stream->pending.
 * Шаг 3 подключит этот вызов через epoll на stream->wake_fd. */
static void dispatcher_handle_udp_reply(dispatcher_state_t *ds,
                                         udp_session_t *sess,
                                         const uint8_t *data, size_t len)
{
    if (ds->udp_reply_fd < 0 || !data || len == 0)
        return;

    struct iovec iov = { .iov_base = (void *)data, .iov_len = len };
    struct msghdr msg = {
        .msg_name    = &sess->src_addr,
        .msg_namelen = (sess->src_addr.ss_family == AF_INET)
                       ? (socklen_t)sizeof(struct sockaddr_in)
                       : (socklen_t)sizeof(struct sockaddr_in6),
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };

    if (sess->key.dst.ss_family == AF_INET) {
        char cmsgbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
        memset(cmsgbuf, 0, sizeof(cmsgbuf));
        msg.msg_control    = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);
        struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
        cm->cmsg_level = IPPROTO_IP;
        cm->cmsg_type  = IP_PKTINFO;
        cm->cmsg_len   = CMSG_LEN(sizeof(struct in_pktinfo));
        struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cm);
        pi->ipi_ifindex  = 0;
        pi->ipi_spec_dst = ((struct sockaddr_in *)&sess->key.dst)->sin_addr;
        pi->ipi_addr     = pi->ipi_spec_dst;
        if (sendmsg(ds->udp_reply_fd, &msg, 0) < 0)
            log_msg(LOG_DEBUG, "UDP reply sendmsg IPv4: %s", strerror(errno));
    } else if (sess->key.dst.ss_family == AF_INET6) {
        char cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
        memset(cmsgbuf, 0, sizeof(cmsgbuf));
        msg.msg_control    = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);
        struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
        cm->cmsg_level = IPPROTO_IPV6;
        cm->cmsg_type  = IPV6_PKTINFO;
        cm->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));
        struct in6_pktinfo *pi6 = (struct in6_pktinfo *)CMSG_DATA(cm);
        pi6->ipi6_ifindex = 0;
        pi6->ipi6_addr    = ((struct sockaddr_in6 *)&sess->key.dst)->sin6_addr;
        if (sendmsg(ds->udp_reply_fd, &msg, 0) < 0)
            log_msg(LOG_DEBUG, "UDP reply sendmsg IPv6: %s", strerror(errno));
    }
}
#endif /* CONFIG_EBURNET_XUDP */

/* ------------------------------------------------------------------ */
/*  dispatcher_handle_udp — UDP relay через XUDP/Mux.Cool              */
/* ------------------------------------------------------------------ */

void dispatcher_handle_udp(tproxy_conn_t *conn,
                           const uint8_t *data, size_t len)
{
#if CONFIG_EBURNET_XUDP
    if (!g_dispatcher || !g_config || !g_dispatcher->muxcool_pool)
        return;
    dispatcher_state_t *ds = g_dispatcher;

    /* Порт назначения */
    uint16_t dst_port = 0;
    if (conn->dst.ss_family == AF_INET)
        dst_port = ntohs(((struct sockaddr_in *)&conn->dst)->sin_port);
    else if (conn->dst.ss_family == AF_INET6)
        dst_port = ntohs(((struct sockaddr_in6 *)&conn->dst)->sin6_port);

    /* Временный лог для верификации XUDP приёма (первые 5 вызовов) */
    static int udp_dbg = 0;
    if (udp_dbg++ < 5) {
        char src_dbg[64];
        net_format_addr(&conn->src, src_dbg, sizeof(src_dbg));
        log_msg(LOG_INFO, "UDP: src=%s dst_port=%u len=%zu",
                src_dbg, (unsigned)dst_port, len);
    }

    /* Выбрать сервер через proxy group */
    int server_idx = dispatcher_select_server(ds, g_config);
    if (server_idx < 0) {
        log_msg(LOG_DEBUG, "relay UDP: нет доступного сервера, дроп");
        return;
    }
    const ServerConfig *srv = config_get_server(g_config, server_idx);
    if (!srv || !srv->packet_encoding[0] ||
        strcmp(srv->packet_encoding, "xudp") != 0)
        return;  /* сервер не поддерживает XUDP */

    /* Ключ сессии */
    udp_session_key_t key;
    key.src = conn->src;
    key.dst = conn->dst;

    udp_session_t *sess = udp_session_find(ds, &key);
    if (!sess) {
        /* Определить addr для Mux.Cool stream */
        char domain_buf[256];
        uint8_t addr_buf[256];
        domain_buf[0] = '\0';
        uint8_t addr_type = MUXCOOL_ADDR_IPV4;
        uint8_t addr_len  = 4;

#if CONFIG_EBURNET_FAKE_IP
        if (g_fake_ip) {
            const char *d = fake_ip_lookup_by_ip(g_fake_ip, &conn->dst);
            if (!d && conn->dst.ss_family == AF_INET6 && g_fake_ip->v6_enabled)
                d = fake_ip6_lookup_by_ip(g_fake_ip,
                        &((struct sockaddr_in6 *)&conn->dst)->sin6_addr);
            if (d)
                strncpy(domain_buf, d, sizeof(domain_buf) - 1);
        }
#endif
        if (domain_buf[0]) {
            addr_type = MUXCOOL_ADDR_DOMAIN;
            addr_len  = (uint8_t)strlen(domain_buf);
            memcpy(addr_buf, domain_buf, addr_len);
        } else if (conn->dst.ss_family == AF_INET) {
            addr_type = MUXCOOL_ADDR_IPV4;
            addr_len  = 4;
            memcpy(addr_buf, &((struct sockaddr_in *)&conn->dst)->sin_addr, 4);
        } else {
            addr_type = MUXCOOL_ADDR_IPV6;
            addr_len  = 16;
            memcpy(addr_buf, &((struct sockaddr_in6 *)&conn->dst)->sin6_addr, 16);
        }

        int needs_io = 0;
        muxcool_stream_t *stream = muxcool_pool_acquire_stream(
            ds->muxcool_pool, server_idx,
            true,         /* is_udp */
            addr_type, addr_buf, addr_len, dst_port,
            &conn->src,   /* client_src для GlobalID */
            &needs_io);
        if (!stream) {
            log_msg(LOG_DEBUG, "relay UDP: muxcool pool full, дроп");
            return;
        }
        if (needs_io == 1) {
            relay_conn_t *ur = relay_alloc(ds);
            if (!ur) {
                muxcool_stream_release(stream);
                return;
            }
            ur->server_idx    = server_idx;
            ur->dst           = conn->dst;
            ur->muxcool_stream = stream;
            ur->is_udp_relay  = true;
            ur->udp_sess_key  = key;
            ur->src_udp_addr  = conn->src;
            if (upstream_connect(ds, ur, srv) < 0) {
                relay_free(ds, ur);
            }
            return;
        }

        sess = udp_session_create(ds, &key, stream);
        if (!sess) {
            muxcool_stream_release(stream);
            return;
        }
        sess->src_addr = conn->src;
    }

    sess->last_active = time(NULL);

    /* Отправить данные через Mux.Cool */
    muxcool_conn_t *mc = sess->stream->conn;
    if (!mc || !mc->transport_ctx)
        return;

    ssize_t sent = muxcool_stream_send(
        sess->stream,
        mc->transport_send, mc->transport_ctx,
        data, len);
    if (sent < 0 && errno != EAGAIN) {
        int saved_errno = errno;
        char src_str[64], dst_str[64];
        net_format_addr(&conn->src, src_str, sizeof(src_str));
        net_format_addr(&conn->dst, dst_str, sizeof(dst_str));
        log_msg(LOG_WARN, "relay UDP muxcool_send: %s → %s: errno=%d",
                src_str, dst_str, saved_errno);
    }
#else
    char src_str[64], dst_str[64];
    net_format_addr(&conn->src, src_str, sizeof(src_str));
    net_format_addr(&conn->dst, dst_str, sizeof(dst_str));
    log_msg(LOG_DEBUG, "relay UDP: %s → %s (%zu байт, XUDP отключён)",
            src_str, dst_str, len);
    (void)data;
#endif
}

/* ------------------------------------------------------------------ */
/*  C-06: декомпозированные обработчики relay state                    */
/* ------------------------------------------------------------------ */

/* grpc_io_fn callbacks — адаптируют wolfSSL tls_send/recv к grpc_io_fn сигнатуре */
static ssize_t grpc_tls_send(void *ctx, uint8_t *buf, size_t len)
{
    return tls_send((tls_conn_t *)ctx, buf, len);
}
static ssize_t grpc_tls_recv(void *ctx, uint8_t *buf, size_t len)
{
    return tls_recv((tls_conn_t *)ctx, buf, len);
}

/* Отправить протокольный header (Trojan или VLESS) как первый gRPC DATA frame.
 * WHY: gRPC поток открывается нашим HEADERS POST, первый DATA frame несёт
 * протокольный заголовок; только потом пойдут реальные данные клиента. */
static int grpc_send_proto_header(relay_conn_t *r, const ServerConfig *server)
{
    /* Стек буфер: MAX(TROJAN_HEADER_MAX=320, VLESS_HEADER_MAX=300) */
    uint8_t hdr[320];
    int     hdr_len = 0;

    if (strcmp(server->protocol, "trojan") == 0) {
        trojan_password_hash_t hash;
        if (trojan_hash_password(server->password, &hash) < 0) {
            log_msg(LOG_WARN, "gRPC: trojan hash провалился");
            return -1;
        }
        hdr_len = trojan_build_request(hdr, sizeof(hdr), &hash, &r->dst,
                                       r->domain[0] ? r->domain : NULL);
    } else {
        /* VLESS */
        vless_uuid_t uuid;
        if (vless_uuid_parse(server->uuid, &uuid) < 0) {
            log_msg(LOG_WARN, "gRPC: VLESS UUID невалидный");
            return -1;
        }
        hdr_len = vless_build_request(hdr, sizeof(hdr), &uuid, &r->dst,
                                      r->domain[0] ? r->domain : NULL,
                                      VLESS_CMD_TCP, NULL, 0);
    }
    if (hdr_len <= 0) {
        log_msg(LOG_WARN, "gRPC: не удалось построить proto header");
        return -1;
    }
    ssize_t n = grpc_send(r->grpc, grpc_tls_send, r->tls,
                          hdr, (size_t)hdr_len);
    if (n < 0) {
        log_msg(LOG_WARN, "gRPC: proto header send провалился: %s",
                strerror(errno));
        return -1;
    }
    r->grpc->state = GRPC_HS_PROTO_SENT;
    return 0;
}

/* Отправить протокольный header (Trojan или VLESS) через pool grpc_stream_t.
 * Используется в MULTIPLEX path — grpc_stream_send добавит HEADERS + DATA. */
#if CONFIG_EBURNET_GRPC_MULTIPLEX
static int grpc_stream_send_proto_header(relay_conn_t *r, const ServerConfig *server)
{
    uint8_t hdr[320];
    int     hdr_len = 0;

    if (strcmp(server->protocol, "trojan") == 0) {
        trojan_password_hash_t hash;
        if (trojan_hash_password(server->password, &hash) < 0) {
            log_msg(LOG_WARN, "gRPC stream: trojan hash провалился");
            return -1;
        }
        hdr_len = trojan_build_request(hdr, sizeof(hdr), &hash, &r->dst,
                                       r->domain[0] ? r->domain : NULL);
    } else {
        vless_uuid_t uuid;
        if (vless_uuid_parse(server->uuid, &uuid) < 0) {
            log_msg(LOG_WARN, "gRPC stream: VLESS UUID невалидный");
            return -1;
        }
        hdr_len = vless_build_request(hdr, sizeof(hdr), &uuid, &r->dst,
                                      r->domain[0] ? r->domain : NULL,
                                      VLESS_CMD_TCP, NULL, 0);
    }
    if (hdr_len <= 0) {
        log_msg(LOG_WARN, "gRPC stream: не удалось построить proto header");
        return -1;
    }
    grpc_stream_t *s    = r->grpc_stream;
    void          *tctx = s->conn->tls;
    if (grpc_stream_send(s, grpc_pool_tls_send, tctx, hdr, (size_t)hdr_len) < 0) {
        log_msg(LOG_WARN, "gRPC stream: proto header send провалился: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* Установить persistent watcher на conn->tcp_fd при переходе primary
 * relay → RELAY_ACTIVE. Заменяет primary tag (&r->ep_upstream) на watcher
 * через MOD, регистрирует wake_fd через ep_upstream и переключает
 * r->upstream_fd на wake_fd. После этого conn->tcp_fd драйвится watcher'ом
 * независимо от primary relay'а — secondary streams продолжат получать
 * данные после смерти primary.
 * Возврат: 0 OK; -1 ошибка (caller должен relay_free). */
static int grpc_install_conn_watcher(dispatcher_state_t *ds, relay_conn_t *r)
{
    grpc_stream_t *s = r->grpc_stream;
    if (!s || !s->conn) return 0;
    if (s->conn->conn_ep_ptr) return 0;     /* watcher уже установлен */
    if (s->wake_fd < 0) {
        /* Graceful degradation: без wake_fd primary не сможет читать pending
         * после установки watcher. Не устанавливаем — primary продолжит
         * драйвить tcp_fd напрямую. Limitation: secondary stall после смерти
         * primary остаётся (как до фикса). */
        log_msg(LOG_WARN,
                "grpc watcher: wake_fd=-1 primary, fallback к старой схеме");
        return 0;
    }

    grpc_conn_ep_t *w = calloc(1, sizeof(*w));
    if (!w) return -1;
    w->ep_type  = EPOLL_EP_GRPC_CONN;
    w->conn     = s->conn;
    w->epoll_fd = ds->epoll_fd;

    /* MOD conn->tcp_fd: data.ptr с &r->ep_upstream → watcher */
    struct epoll_event mev = {
        .events   = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP,
        .data.ptr = w,
    };
    if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD, s->conn->tcp_fd, &mev) < 0) {
        log_msg(LOG_ERROR,
                "grpc watcher: EPOLL_CTL_MOD tcp_fd=%d: %s",
                s->conn->tcp_fd, strerror(errno));
        free(w);
        return -1;
    }

    /* ADD wake_fd с tag &r->ep_upstream — primary получает eventfd-сигналы
     * о новых данных в pending_to_client */
    struct epoll_event eev = {
        .events   = EPOLLIN,
        .data.ptr = &r->ep_upstream,
    };
    if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD, s->wake_fd, &eev) < 0) {
        log_msg(LOG_ERROR,
                "grpc watcher: EPOLL_CTL_ADD wake_fd=%d: %s",
                s->wake_fd, strerror(errno));
        /* Откат MOD — вернуть tcp_fd на primary tag */
        struct epoll_event back = {
            .events   = EPOLLIN | EPOLLET,
            .data.ptr = &r->ep_upstream,
        };
        epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD, s->conn->tcp_fd, &back);
        free(w);
        return -1;
    }

    s->conn->conn_ep_ptr = w;
    r->upstream_fd       = s->wake_fd;
    return 0;
}
#endif /* CONFIG_EBURNET_GRPC_MULTIPLEX */

#if CONFIG_EBURNET_XUDP
/* Установить persistent watcher на muxcool conn->tcp_fd при переходе
 * primary relay → RELAY_MUXCOOL_ACTIVE. Аналогично grpc_install_conn_watcher
 * (v1.5.97) — позволяет secondary streams продолжить работать после
 * смерти primary relay'а. Возврат: 0 OK; -1 ошибка (caller relay_free). */
static int muxcool_install_conn_watcher(dispatcher_state_t *ds,
                                         relay_conn_t *r)
{
    muxcool_stream_t *s = r->muxcool_stream;
    if (!s || !s->conn) return 0;
    if (s->conn->conn_ep_ptr) return 0;     /* watcher уже установлен */
    if (s->wake_fd < 0) {
        log_msg(LOG_WARN,
                "muxcool watcher: wake_fd=-1 primary, fallback");
        return 0;
    }

    muxcool_conn_ep_t *w = calloc(1, sizeof(*w));
    if (!w) return -1;
    w->ep_type  = EPOLL_EP_MUXCOOL_CONN;
    w->conn     = s->conn;
    w->epoll_fd = ds->epoll_fd;

    /* MOD: tcp_fd с &r->ep_upstream → watcher tag */
    struct epoll_event mev = {
        .events   = EPOLLIN | EPOLLERR | EPOLLHUP,
        .data.ptr = w,
    };
    if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD, s->conn->tcp_fd, &mev) < 0) {
        log_msg(LOG_ERROR,
                "muxcool watcher: MOD tcp_fd=%d: %s",
                s->conn->tcp_fd, strerror(errno));
        free(w);
        return -1;
    }

    /* ADD: wake_fd с &r->ep_upstream — primary получает eventfd-сигналы */
    struct epoll_event eev = {
        .events   = EPOLLIN,
        .data.ptr = &r->ep_upstream,
    };
    if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD, s->wake_fd, &eev) < 0) {
        log_msg(LOG_ERROR,
                "muxcool watcher: ADD wake_fd=%d: %s",
                s->wake_fd, strerror(errno));
        struct epoll_event back = {
            .events   = EPOLLIN | EPOLLET,
            .data.ptr = &r->ep_upstream,
        };
        epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD, s->conn->tcp_fd, &back);
        free(w);
        return -1;
    }

    s->conn->conn_ep_ptr = w;
    r->upstream_fd       = s->wake_fd;
    return 0;
}
#endif /* CONFIG_EBURNET_XUDP */

#if CONFIG_EBURNET_XUDP
/* Forward-декларации transport callbacks (определения — ниже, после VLESS handlers) */
static ssize_t cb_tls_send(void *ctx, const uint8_t *buf, size_t len);
static ssize_t cb_tls_recv(void *ctx, uint8_t *buf, size_t len);
static void    cb_tls_free(void *ctx);
static ssize_t cb_reality_send(void *ctx, const uint8_t *buf, size_t len);
static ssize_t cb_reality_recv(void *ctx, uint8_t *buf, size_t len);

typedef struct { ws_client_conn_t *ws; tls_conn_t *tls; } muxcool_ws_ctx_t;
static ssize_t cb_ws_send(void *ctx, const uint8_t *buf, size_t len);
static ssize_t cb_ws_recv(void *ctx, uint8_t *buf, size_t len);
static void    cb_ws_free(void *ctx);

static ssize_t cb_xhttp_send(void *ctx, const uint8_t *buf, size_t len);
static ssize_t cb_xhttp_recv(void *ctx, uint8_t *buf, size_t len);
static void    cb_xhttp_free(void *ctx);

#if CONFIG_EBURNET_GRPC_MULTIPLEX
typedef struct { grpc_stream_t *stream; void *ssl; } muxcool_grpc_ctx_t;
static ssize_t cb_grpc_send(void *ctx, const uint8_t *buf, size_t len);
static ssize_t cb_grpc_recv(void *ctx, uint8_t *buf, size_t len);
static void    cb_grpc_free(void *ctx);
#endif /* CONFIG_EBURNET_GRPC_MULTIPLEX */
#endif /* CONFIG_EBURNET_XUDP */

/* TLS handshake + VLESS response (нет continue — безопасно вынесены) */
static void relay_handle_tls(dispatcher_state_t *ds, relay_conn_t *r,
                              relay_ep_t *ep, uint32_t ev)
{
    if (r->state == RELAY_TLS_SHAKE) {
        if (ep->is_client) return;
        if (!(ev & (EPOLLIN | EPOLLOUT))) return;

        tls_step_result_t tls_rc = tls_connect_step(r->tls);
        if (tls_rc == TLS_OK) {
            const ServerConfig *server = NULL;
            if (g_config && r->server_idx >= 0)
                server = config_get_server(g_config, r->server_idx);

            /* DEC-025: диагностика Reality shortId */
            if (server && server->reality_short_id[0]) {
                uint8_t rnd[32];
                int rn = tls_get_client_random(r->tls, rnd, sizeof(rnd));
                if (rn >= 8) {
                    char hex[17] = {0};
                    for (int hi = 0; hi < 8; hi++) {
                        int _n = snprintf(hex + hi * 2, 3, "%02x", rnd[hi]);
                        if (_n < 0 || _n >= 3)
                            log_msg(LOG_DEBUG, "snprintf truncated (non-critical): %s:%d", __FILE__, __LINE__);
                    }
                    log_msg(LOG_DEBUG,
                            "Reality shortId=%s clientRandom[0:8]=%s",
                            server->reality_short_id, hex);
                } else {
                    log_msg(LOG_DEBUG,
                            "Reality shortId=%s (clientRandom недоступен)",
                            server->reality_short_id);
                }
            }

            if (!server) {
                relay_free(ds, r);
                return;
            }

            /* T0-03: gRPC transport — инициировать HTTP/2 handshake поверх TLS.
             * Protocol header (Trojan/VLESS) будет отправлен в RELAY_GRPC_HS
             * после завершения HTTP/2 handshake. */
            if (server->transport[0] &&
                strcmp(server->transport, "grpc") == 0) {
#if CONFIG_EBURNET_GRPC_MULTIPLEX
                /* Первичный поток: TLS завершён — вписываем tcp_fd и WOLFSSL* в pool conn.
                 * Передаём WOLFSSL* pool'у (он вызовет wolfSSL_free в grpc_pool_free).
                 * Обнуляем r->tls->ssl чтобы relay_free не сделал double-free. */
                if (!r->grpc_stream) {
                    log_msg(LOG_ERROR, "relay: gRPC MULTIPLEX без grpc_stream");
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                r->grpc_stream->conn->tcp_fd = r->upstream_fd;
                r->grpc_stream->conn->tls    = ((tls_conn_t *)r->tls)->ssl;
                ((tls_conn_t *)r->tls)->ssl  = NULL; /* WOLFSSL* теперь у pool */
                log_msg(LOG_INFO, "relay [%s] TLS_SHAKE→GRPC_HS pool (svc=%s)",
                        server->name, r->grpc_stream->conn->service_name);
                r->state = RELAY_GRPC_HS;
                r->vless_resp_len = 0;
#else
                r->grpc = calloc(1, sizeof(grpc_conn_t));
                if (!r->grpc) {
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                char authority[288];
                /* WHY: gRPC-go (xray) опускает port из :authority для дефолтных
                 * портов (443 для https, 80 для http) — RFC 3986 §3.2.3.
                 * "bg1.xxee.ru:443" вместо "bg1.xxee.ru" → xray может RST_STREAM. */
                int _an;
                if (server->port == 443 || server->port == 80)
                    _an = snprintf(authority, sizeof(authority), "%s", server->address);
                else
                    _an = snprintf(authority, sizeof(authority),
                                   "%s:%u", server->address, server->port);
                if (_an < 0 || (size_t)_an >= sizeof(authority))
                    authority[sizeof(authority) - 1] = '\0';
                const char *svc = server->grpc_service_name[0]
                                  ? server->grpc_service_name : "GunService";
                grpc_conn_init(r->grpc, svc, authority);
                log_msg(LOG_INFO, "relay [%s] TLS_SHAKE→GRPC_HS (svc=%s)",
                        server->name, svc);
                r->state = RELAY_GRPC_HS;
                r->vless_resp_len = 0; /* сброс для gRPC VLESS response чтения */
#endif /* CONFIG_EBURNET_GRPC_MULTIPLEX */
            }
#if CONFIG_EBURNET_XUDP
            else if (r->muxcool_stream) {
                /* TLS установлен для нового Mux.Cool conn'а. Передаём fd+tls
                 * во владение pool. Watcher install отложен до перехода в
                 * ACTIVE (RELAY_MUXCOOL_HS), потому что VLESS handshake
                 * нужен events на tcp_fd через &r->ep_upstream. */
                if (!r->muxcool_stream->conn) {
                    log_msg(LOG_ERROR, "muxcool: conn==NULL после TLS HS");
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                muxcool_conn_t *mc = r->muxcool_stream->conn;
                mc->tcp_fd = r->upstream_fd;
                WOLFSSL *mc_ssl = ((tls_conn_t *)r->tls)->ssl;
                ((tls_conn_t *)r->tls)->ssl = NULL; /* WOLFSSL* теперь у muxcool */
                muxcool_conn_set_transport(mc, mc_ssl,
                                           cb_tls_send, cb_tls_recv, cb_tls_free);
                log_msg(LOG_INFO,
                        "relay [%s] TLS_SHAKE→MUXCOOL_HS sid=%u",
                        server->name, r->muxcool_stream->session_id);
                r->state = RELAY_MUXCOOL_HS;
                r->vless_resp_len = 0;
            }
#endif /* CONFIG_EBURNET_XUDP */
            else if (server->transport[0] &&
                strcmp(server->transport, "ws") == 0) {
                /* T0-04: WebSocket transport — HTTP Upgrade поверх TLS */
                r->ws = calloc(1, sizeof(ws_client_conn_t));
                if (!r->ws) {
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                const char *ws_path = server->ws_path[0] ? server->ws_path : "/";
                const char *ws_host = server->ws_host[0] ? server->ws_host : server->address;
                ws_client_init(r->ws, ws_path, ws_host);
                log_msg(LOG_INFO, "relay [%s] TLS_SHAKE→WS_HS (path=%s host=%s)",
                        server->name, ws_path, ws_host);
                r->state = RELAY_WS_HS;
            } else if (server->transport[0] &&
                strcmp(server->transport, "httpupgrade") == 0) {
                /* T0-06: HTTPUpgrade — GET без Sec-WebSocket-Key, raw TCP после 101 */
                r->http_ug = calloc(1, sizeof(http_upgrade_conn_t));
                if (!r->http_ug) {
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                const char *hu_path = server->ws_path[0] ? server->ws_path : "/";
                const char *hu_host = server->ws_host[0] ? server->ws_host : server->address;
                http_upgrade_init(r->http_ug, hu_path, hu_host);
                log_msg(LOG_INFO, "relay [%s] TLS_SHAKE→HTTP_UG_HS (path=%s host=%s)",
                        server->name, hu_path, hu_host);
                r->state = RELAY_HTTP_UG_HS;
            } else if (strcmp(server->protocol, "trojan") == 0) {
                if (trojan_handshake_start(r->tls, &r->dst,
                                            server->password,
                                            r->domain[0] ? r->domain : NULL) < 0) {
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                dispatcher_server_result(ds, r->server_idx, true);
                r->state = RELAY_ACTIVE;
                r->upstream_first_byte_deadline = time(NULL) + 10;
                log_msg(LOG_DEBUG, "relay: Trojan активен");
            } else {
                /* T0-02: активировать Vision если reality_flow содержит "vision".
                 * Step 3: только сигнализация addons; split/pad логика — Step 4. */
                uint8_t  vision_addons[VISION_ADDONS_LEN];
                uint8_t  vision_addons_len = 0;
                /* T0-02 Vision: ВРЕМЕННО отключено — несовместимость с
                 * сервером xray (out plateau 55-57 байт). Vision-серверы
                 * пойдут как обычный VLESS Reality в compat mode (xray
                 * принимает без Vision-signalling). Infrastructure code
                 * сохранён для будущего breakthrough. */
#if CONFIG_VISION_ENABLED
                if (server->reality_flow[0] &&
                    strstr(server->reality_flow, "vision")) {
                    /* UUID из строки → 16 байт бинарный для padding header */
                    vless_uuid_t vuuid;
                    if (vless_uuid_parse(server->uuid, &vuuid) != 0) {
                        log_msg(LOG_WARN,
                                "VLESS: невалидный UUID для Vision init");
                        dispatcher_server_result(ds, r->server_idx, false);
                        RELAY_FAIL_OR_RETRY(ds, r);
                    }
                    r->vision = malloc(sizeof(vision_state_t));
                    if (!r->vision) {
                        dispatcher_server_result(ds, r->server_idx, false);
                        RELAY_FAIL_OR_RETRY(ds, r);
                    }
                    vision_state_init(r->vision, 0, vuuid.bytes);
                    vision_addons_len = (uint8_t)vision_build_addons(
                                            vision_addons,
                                            sizeof(vision_addons));
                    log_msg(LOG_DEBUG,
                            "VLESS: Vision flow активирован (%s)",
                            server->reality_flow);
                }
#endif /* CONFIG_VISION_ENABLED */
                if (vless_handshake_start(r->tls, &r->dst,
                                          r->domain[0] ? r->domain : NULL,
                                          server->uuid,
                                          vision_addons_len ? vision_addons : NULL,
                                          vision_addons_len) < 0) {
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                log_msg(LOG_INFO, "relay [%s] TLS_SHAKE→VLESS_SHAKE", server->name);
                r->state = RELAY_VLESS_SHAKE;
                r->vless_resp_len = 0;
            }

            /* WHY EPOLLOUT для WS/HTTPUpgrade: EPOLLET edge уже потреблён при
             * TLS Finished — MOD с EPOLLOUT форсирует немедленный fire если
             * сокет записываем, что запускает первый шаг HS (отправку GET). */
            uint32_t mod_events = EPOLLIN | EPOLLET;
            if (r->state == RELAY_WS_HS || r->state == RELAY_HTTP_UG_HS)
                mod_events |= EPOLLOUT;
            struct epoll_event mod = {
                .events   = mod_events,
                .data.ptr = &r->ep_upstream,
            };
            epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD,
                      r->upstream_fd, &mod);
        } else if (tls_rc == TLS_ERR) {
            dispatcher_server_result(ds, r->server_idx, false);
            RELAY_FAIL_OR_RETRY(ds, r);
        }
    } else {
        /* RELAY_VLESS_SHAKE */
        if (ep->is_client) return;
        if (!(ev & EPOLLIN)) return;

        int vrc = vless_read_response_step(r->tls,
            r->vless_resp_buf, &r->vless_resp_len);
        if (vrc == 0) {
            dispatcher_server_result(ds, r->server_idx, true);
            log_msg(LOG_INFO, "relay VLESS_SHAKE→ACTIVE");
            r->state = RELAY_ACTIVE;
            r->upstream_first_byte_deadline = time(NULL) + 10;
            log_msg(LOG_DEBUG, "relay: VLESS установлен, relay активен");
        } else if (vrc < 0) {
            dispatcher_server_result(ds, r->server_idx, false);
            RELAY_FAIL_OR_RETRY(ds, r);
        }
    }
}

/* Активный relay — двунаправленная передача */
static void relay_handle_active(dispatcher_state_t *ds, relay_conn_t *r,
                                 relay_ep_t *ep, uint32_t ev, time_t now)
{
    if (ep->is_client && (ev & EPOLLIN)) {
#ifdef __mips__
        /* WHY: client_fd тоже в LT mode → без лимита возможен busy-spin при
         * непрерывном клиентском трафике; те же 4 итерации, что и upstream. */
        int _client_iters = 0;
#endif
        for (;;) {
            ssize_t transferred = relay_transfer(ds, r, true);
            if (transferred > 0) {
                r->bytes_in += transferred;
                stats_traffic_up((uint64_t)transferred);
                r->last_active = now;
                /* Помечаем: ClientHello прошёл — теперь можно forward
                 * upstream→client. Однократный дренаж upstream если кеш накопился. */
                if (!r->client_sent_first) {
                    r->client_sent_first = true;
                    ssize_t up_drain = relay_transfer(ds, r, false);
                    if (up_drain > 0) {
                        r->bytes_out += (uint64_t)up_drain;
                        stats_traffic_down((uint64_t)up_drain);
                    }
                }
#ifdef __mips__
                if (++_client_iters >= (int)g_relay_drain_per_call) break;
#endif
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

    /* EPOLLOUT на client_fd: клиент снова принимает данные → слить pending.
     * WHY: to_client_buf заполняется когда write(client_fd) возвращает EAGAIN.
     * relay_client_epollout_set регистрирует EPOLLOUT; здесь сливаем и снимаем. */
    if (ep->is_client && (ev & EPOLLOUT) && r->epollout_client &&
        r->state != RELAY_CLOSING) {
        /* Снять EPOLLOUT сначала: relay_transfer зарегистрирует снова если нужно */
        relay_client_epollout_clear(ds, r);
#ifdef __mips__
        /* Вернуть upstream_fd в epoll если был снят из-за полного to_client_buf */
        if (r->upstream_fd_paused && r->upstream_fd >= 0 && !r->upstream_eof) {
            struct epoll_event _ev_up = {
                .events   = r->upstream_lt_mode ? (EPOLLIN | EPOLLRDHUP)
                                                : (EPOLLIN | EPOLLRDHUP | EPOLLET),
                .data.ptr = &r->ep_upstream,
            };
            if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD, r->upstream_fd, &_ev_up) == 0)
                r->upstream_fd_paused = false;
        }
        /* WHY: после слива to_client_buf relay_transfer читает upstream через
         * reality_recv (AES-GCM). Без лимита цикл не выходит пока upstream
         * не опустеет → busy-spin при большом health-check ответе на MT7621A.
         * LT mode upstream_fd гарантирует повторное EPOLLIN на следующем тике. */
        int _epo_iters = 0;
#endif
        for (;;) {
            ssize_t transferred = relay_transfer(ds, r, false);
            if (transferred > 0) {
                r->bytes_out += (uint64_t)transferred;
                stats_traffic_down((uint64_t)transferred);
                r->last_active = now;
#ifdef __mips__
                if (++_epo_iters >= (int)g_relay_drain_per_call) break;
#endif
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

    if (r->state == RELAY_CLOSING) {
        relay_free(ds, r);
        return;
    }

    /* WHY: upstream_eof=true → FIN принят; буфер прочитан → kernel сигналит
     * EPOLLRDHUP без EPOLLIN (пустой буфер). Старая проверка ev&EPOLLIN не
     * срабатывала → fd оставался в epoll → EPOLLRDHUP каждый тик → busy-spin 94%.
     * Снимаем upstream_fd при ЛЮБОМ событии если upstream_eof уже выставлен. */
    if (!ep->is_client && r->upstream_eof) {
        if (r->upstream_fd >= 0)
            epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->upstream_fd, NULL);
        return;
    }

    /* WHY EPOLLRDHUP: сервер может закрыть TCP без TLS close_notify.
     * Ядро доставляет только EPOLLRDHUP (без EPOLLIN) → recv() вернёт 0 →
     * reality_recv → ECONNRESET → relay_free. Без этого upstream_fd в LT
     * продолжает генерировать EPOLLRDHUP каждый тик → busy-spin. */
    if (!ep->is_client && (ev & (EPOLLIN | EPOLLRDHUP))) {
        /* WHY client_sent_first guard: xray PrivateVPN отвечает Vision frames
         * (ServerHello, ~6.5KB) сразу после VLESS handshake — ДО получения
         * inner ClientHello от iPhone. Если переслать iPhone раньше его
         * собственного ClientHello — iPhone видит mystery ServerHello → TLS
         * protocol violation → close+Alert. Откладываем upstream→client до
         * первого client→upstream transfer. EPOLLRDHUP пропускаем (FIN от
         * сервера должен closed relay вне зависимости от direction). */
        if (!r->client_sent_first && !(ev & EPOLLRDHUP)) {
            return;
        }
        /* gRPC: долить отложенные WINDOW_UPDATE до чтения новых данных.
         * WHY: при EAGAIN на send WU (wolfSSL WANT_WRITE) increment копится
         * в pending_wnd_*; без retry серверный recv window не пополняется
         * → DATA frames застывают после исчерпания 1MB. EPOLLIN на upstream
         * означает что socket снова writable (TLS обычно симметричен под epoll). */
#if !CONFIG_EBURNET_GRPC_MULTIPLEX
        if (r->grpc &&
            (r->grpc->pending_wnd_conn || r->grpc->pending_wnd_stream)) {
            (void)grpc_flush_pending_windows(r->grpc,
                                              grpc_tls_send, r->tls);
        }
#endif
#ifdef __mips__
        /* WHY: ограничиваем AES-GCM за один вызов. LT mode (upstream_lt_mode)
         * гарантирует перезапуск события если данные остались в буфере. */
        int _relay_iters = 0;
#endif
        for (;;) {
            ssize_t transferred = relay_transfer(ds, r, false);
            int saved_errno_d = errno; /* log_msg на MIPS затирает errno через localtime */
            if (transferred > 0) {
#if CONFIG_EBURNET_DPI
                /* Первые данные от upstream → DPI стратегия сработала */
                if (r->dpi_first_done && !r->dpi_success) {
                    r->dpi_success = true;
                    uint32_t dst_ip = (r->dst.ss_family == AF_INET)
                        ? ntohl(((struct sockaddr_in *)&r->dst)->sin_addr.s_addr) : 0u;
                    if (dst_ip)
                        dpi_adapt_report(&g_dpi_adapt, dst_ip,
                                         r->dpi_strategy, DPI_RESULT_SUCCESS);
                }
#endif
                r->bytes_out += transferred;
                stats_traffic_down((uint64_t)transferred);
                r->last_active = now;
#ifdef __mips__
                if (++_relay_iters >= (int)g_relay_drain_per_call) break;
#endif
                continue;
            }
            if (transferred == 0) {
                relay_do_half_close(r, false);
            } else if (saved_errno_d != EAGAIN && saved_errno_d != EWOULDBLOCK) {
                r->state = RELAY_CLOSING;
#ifdef __mips__
            } else if (r->to_client_buf && !r->upstream_fd_paused && r->upstream_fd >= 0) {
                /* WHY: LT upstream_fd + to_client_buf полный → relay_transfer
                 * сразу EAGAIN без чтения → persistent EPOLLIN spin. Убираем
                 * upstream_fd из epoll пока to_client_buf не слит (EPOLLOUT). */
                epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->upstream_fd, NULL);
                r->upstream_fd_paused = true;
#endif
            }
            break;
        }
    }

    if (r->state == RELAY_CLOSING)
        relay_free(ds, r);
}

/* XHTTP state machine (6 состояний, goto→return) */
static void relay_handle_xhttp(dispatcher_state_t *ds, relay_conn_t *r,
                                relay_ep_t *ep, uint32_t ev,
                                const struct epoll_event *cur_event,
                                time_t now)
{
    switch (r->state) {
    case RELAY_XHTTP_DN_CONNECT:
        if (!ep->is_client && (ev & EPOLLOUT) &&
            cur_event->data.ptr == &r->ep_download) {
            int err = 0;
            socklen_t errlen = sizeof(err);
            getsockopt(r->download_fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
            if (err != 0) {
                log_msg(LOG_WARN, "XHTTP: download connect: %s", strerror(err));
                relay_free(ds, r);
                return;
            }
            struct epoll_event mod = {
                .events = EPOLLIN | EPOLLOUT | EPOLLET,
                .data.ptr = &r->ep_upstream,
            };
            epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD, r->upstream_fd, &mod);
            r->state = RELAY_XHTTP_UP_TLS;
        }
        return;

    case RELAY_XHTTP_UP_TLS:
        if (cur_event->data.ptr != &r->ep_upstream) return;
        if (!(ev & (EPOLLIN | EPOLLOUT))) return;
        if (!r->xhttp) { relay_free(ds, r); return; }
        {
            tls_step_result_t tr = xhttp_upload_tls_step(r->xhttp);
            if (tr == TLS_OK) {
                if (r->download_fd >= 0) {
                    /* stream-up: переключить download fd на EPOLLIN|EPOLLOUT */
                    struct epoll_event mod = {
                        .events = EPOLLIN | EPOLLOUT | EPOLLET,
                        .data.ptr = &r->ep_download,
                    };
                    epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD, r->download_fd, &mod);
                    r->state = RELAY_XHTTP_DN_TLS;
                } else {
                    /* stream-one: TLS готов → сразу отправить H2 POST */
                    const ServerConfig *srv = NULL;
                    if (g_config && r->server_idx >= 0)
                        srv = config_get_server(g_config, r->server_idx);
                    if (!srv ||
                        xhttp_send_upload_request(r->xhttp, &r->dst, srv->uuid) < 0 ||
                        xhttp_send_download_request(r->xhttp) < 0) {
                        dispatcher_server_result(ds, r->server_idx, false);
                        RELAY_FAIL_OR_RETRY(ds, r);
                    }
                    r->state = RELAY_XHTTP_DN_REQ;
                }
            } else if (tr == TLS_ERR) {
                dispatcher_server_result(ds, r->server_idx, false);
                RELAY_FAIL_OR_RETRY(ds, r);
            }
        }
        return;

    case RELAY_XHTTP_DN_TLS:
        if (cur_event->data.ptr != &r->ep_download) return;
        if (!(ev & (EPOLLIN | EPOLLOUT))) return;
        if (!r->xhttp) { relay_free(ds, r); return; }
        {
            tls_step_result_t tr = xhttp_download_tls_step(r->xhttp);
            if (tr == TLS_OK) {
                r->state = RELAY_XHTTP_UP_REQ;
                const ServerConfig *srv = NULL;
                if (g_config && r->server_idx >= 0)
                    srv = config_get_server(g_config, r->server_idx);
                if (!srv || xhttp_send_upload_request(r->xhttp,
                        &r->dst, srv->uuid) < 0) {
                    relay_free(ds, r);
                    return;
                }
                if (xhttp_send_download_request(r->xhttp) < 0) {
                    relay_free(ds, r);
                    return;
                }
                r->state = RELAY_XHTTP_DN_REQ;
            } else if (tr == TLS_ERR) {
                dispatcher_server_result(ds, r->server_idx, false);
                RELAY_FAIL_OR_RETRY(ds, r);
            }
        }
        return;

    case RELAY_XHTTP_UP_REQ:
        return;

    case RELAY_XHTTP_DN_REQ:
        /* stream-one: 200 OK приходит на ep_upstream (upload fd = единственный fd).
         * stream-up: 200 OK приходит на ep_download. */
        if (r->download_fd >= 0) {
            if (cur_event->data.ptr != &r->ep_download) return;
        } else {
            if (cur_event->data.ptr != &r->ep_upstream) return;
        }
        if (!(ev & EPOLLIN)) return;
        if (!r->xhttp) { relay_free(ds, r); return; }
        {
            int prc = xhttp_parse_response_step(r->xhttp);
            if (prc == 0) {
#if CONFIG_EBURNET_XUDP
                if (r->muxcool_stream && r->muxcool_stream->conn) {
                    muxcool_conn_t *mc = r->muxcool_stream->conn;
                    mc->tcp_fd = r->xhttp->upload.fd;
                    muxcool_conn_set_transport(mc, r->xhttp,
                                               cb_xhttp_send, cb_xhttp_recv,
                                               cb_xhttp_free);
                    r->xhttp = NULL;
                    log_msg(LOG_INFO, "relay XHTTP_DN_REQ→MUXCOOL_HS sid=%u",
                            r->muxcool_stream->session_id);
                    r->state = RELAY_MUXCOOL_HS;
                    r->vless_resp_len = 0;
                    return;
                }
#endif /* CONFIG_EBURNET_XUDP */
                dispatcher_server_result(ds, r->server_idx, true);
                r->state = RELAY_XHTTP_ACTIVE;
                log_msg(LOG_DEBUG, "XHTTP: relay активен");
            } else if (prc < 0) {
                dispatcher_server_result(ds, r->server_idx, false);
                RELAY_FAIL_OR_RETRY(ds, r);
            }
        }
        return;

    case RELAY_XHTTP_ACTIVE:
        if (!r->xhttp) { relay_free(ds, r); return; }
        if (ep->is_client && (ev & EPOLLIN)) {
            for (;;) {
                ssize_t n = read(r->client_fd,
                                 ds->relay_buf, ds->relay_buf_size);
                if (n > 0) {
                    ssize_t sent = xhttp_send_chunk(r->xhttp, ds->relay_buf, n);
                    if (sent > 0) {
                        r->bytes_in += sent;
                        stats_traffic_up((uint64_t)sent);
                        r->last_active = now;
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
        /* stream-one: download данные на ep_upstream; stream-up: ep_download */
        if ((r->download_fd >= 0
                 ? cur_event->data.ptr == (void *)&r->ep_download
                 : cur_event->data.ptr == (void *)&r->ep_upstream)
            && (ev & EPOLLIN)) {
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
                        return;
                    }
                    if (wr < n) {
                        log_msg(LOG_DEBUG, "relay: XHTTP partial write %zd/%zd",
                                wr, (ssize_t)n);
                        relay_free(ds, r);
                        return;
                    }
                    r->bytes_out += (uint64_t)wr;
                    stats_traffic_down((uint64_t)wr);
                    r->last_active = now;
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
        return;

    default:
        return;
    }
}

#if CONFIG_EBURNET_AWG
/* AWG state machine (Noise handshake + relay) */
static void relay_handle_awg(dispatcher_state_t *ds, relay_conn_t *r,
                              relay_ep_t *ep, uint32_t ev, time_t now)
{
    if (r->state == RELAY_AWG_HANDSHAKE) {
        r->awg_hs_epollin_count++;
        /* WHY: AWG HS зависает навсегда (hs_done=0) при неответе сервера →
         * сотни EPOLLIN заполняют dispatcher tick, блокируя YouTube/Telegram.
         * Лимит 50: ~30с при интервале awg_tick ~600ms. */
        if (r->awg_hs_epollin_count > 50) {
            const ServerConfig *_srv = g_config
                ? config_get_server(g_config, r->server_idx) : NULL;
            log_msg(LOG_WARN, "AWG HS timeout (50 EPOLLIN без hs_done): сервер %s",
                    _srv ? _srv->name : "?");
            dispatcher_server_result(ds, r->server_idx, false);
            RELAY_FAIL_OR_RETRY(ds, r);
        }
        if (!ep->is_client && r->awg) {
            log_msg(LOG_INFO, "AWG HS: ev=0x%x fd=%d srv=%d",
                    ev, r->upstream_fd, r->server_idx);
            int arc = awg_process_incoming(r->awg);
            int saved_errno = errno;
            log_msg(LOG_INFO,
                    "AWG HS: process_incoming ret=%d errno=%d hs_done=%d",
                    arc, saved_errno, r->awg->handshake_done);
            if (arc == 1) {
                dispatcher_server_result(ds, r->server_idx, true);
                r->state = RELAY_AWG_ACTIVE;
                log_msg(LOG_INFO, "AWG HS: → ACTIVE (срв %d)", r->server_idx);
            } else if (arc < 0) {
                log_msg(LOG_WARN,
                        "AWG HS: process_incoming -1 → relay_free (срв %d)",
                        r->server_idx);
                dispatcher_server_result(ds, r->server_idx, false);
                relay_free(ds, r);
            } else {
                awg_tick(r->awg);
            }
        } else if (ep->is_client) {
            /* Логируем только каждые 100 раз — AWG HS может получать много
             * client EPOLLIN пока туннель не установлен. */
            if ((r->awg_hs_epollin_count % 100) == 1)
                log_msg(LOG_INFO,
                        "AWG HS: client EPOLLIN ignored #%u (HS pending) ev=0x%x",
                        r->awg_hs_epollin_count, ev);
        }
        return;
    }

    /* RELAY_AWG_ACTIVE */
    if (ep->is_client && (ev & EPOLLIN)) {
        for (;;) {
            ssize_t n = read(r->client_fd,
                             ds->relay_buf, ds->relay_buf_size);
            if (n > 0) {
                awg_send(r->awg, ds->relay_buf, n);
                r->bytes_in += n;
                stats_traffic_up((uint64_t)n);
                r->last_active = now;
                continue;
            }
            if (n == 0) relay_do_half_close(r, true);
            else if (errno != EAGAIN) r->state = RELAY_CLOSING;
            break;
        }
    }
    if (!ep->is_client && (ev & EPOLLIN) && r->awg) {
        int arc = awg_process_incoming(r->awg);
        if (arc == 2) {
            uint8_t *buf = ds->relay_buf;
            size_t   buf_sz = ds->relay_buf_size;
            ssize_t n = awg_recv(r->awg, buf, buf_sz);
            if (n > 0) {
                ssize_t wr = write(r->client_fd, buf, (size_t)n);
                if (wr < 0) {
                    if (errno != EAGAIN && errno != EPIPE)
                        log_msg(LOG_DEBUG, "relay: AWG write ошибка: %s",
                                strerror(errno));
                    relay_free(ds, r);
                    return;
                }
                if (wr < n) {
                    log_msg(LOG_DEBUG, "relay: AWG partial write %zd/%zd",
                            wr, (ssize_t)n);
                    relay_free(ds, r);
                    return;
                }
                r->bytes_out += (uint64_t)wr;
                stats_traffic_down((uint64_t)wr);
                r->last_active = now;
            }
        } else if (arc < 0) {
            r->state = RELAY_CLOSING;
        }
    }
    if (r->awg) awg_tick(r->awg);
    if (r->state == RELAY_CLOSING)
        relay_free(ds, r);
}
#endif /* CONFIG_EBURNET_AWG */

#if CONFIG_EBURNET_VLESS
/* ------------------------------------------------------------------ */
/*  Reality TLS state machine: handshake + VLESS response               */
/* ------------------------------------------------------------------ */

/* Дренаж клиентских данных → Vision+Reality → xray.
 * WHY: xray с xtls-rprx-vision не отвечает на VLESS request пока не
 * получит inner-TLS данные (ClientHello) от клиента.
 * Вызывается при переходе в RELAY_REALITY_VLESS и при последующих
 * EPOLLIN на client_fd пока ожидаем VLESS response. */
static void reality_vless_drain_client(dispatcher_state_t *ds,
                                        relay_conn_t *r)
{
#ifdef __mips__
    int _drain_iters = 0;
#endif
    for (;;) {
        ssize_t n = read(r->client_fd, ds->relay_buf, ds->relay_buf_size);
        if (n > 0) {
            ssize_t sent = r->vision
                ? vision_write_ex(r->vision, reality_send_fn,
                                   r->reality, ds->relay_buf, (size_t)n)
                : reality_send((reality_conn_t *)r->reality,
                                 ds->relay_buf, (size_t)n);
            if (sent < 0) {
                log_msg(LOG_WARN,
                        "Reality VLESS: пересылка данных клиента провалилась");
                dispatcher_server_result(ds, r->server_idx, false);
                relay_free(ds, r);
                return;
            }
            /* WHY: bytes_in/client_sent_first не обновлялись здесь, хотя
             * ClientHello уже отправлен в upstream. В итоге guard в
             * relay_handle_active(!client_sent_first) блокировал upstream→client
             * до EPOLLRDHUP — iPhone получал ServerHello только после разрыва.
             * Симптом: relay closed in=0 out=5526, YouTube не открывается. */
            r->bytes_in += (uint64_t)n;
            r->client_sent_first = true;
            r->last_active = time(NULL);
#ifdef __mips__
            if (++_drain_iters >= (int)g_relay_drain_per_call) break;
#endif
            continue;
        }
        if (n == 0) {
            relay_free(ds, r);
            return;
        }
        break; /* EAGAIN — данных нет, выходим */
    }
}

static void relay_handle_reality(dispatcher_state_t *ds,
                                   relay_conn_t *r,
                                   relay_ep_t *ep, uint32_t ev)
{
    /* WHY: в RELAY_REALITY_VLESS пробрасываем клиентские данные к xray
     * (inner TLS ClientHello нужен xray с Vision до отправки VLESS response). */
    if (ep->is_client) {
        if (r->state == RELAY_REALITY_VLESS && (ev & EPOLLIN))
            reality_vless_drain_client(ds, r);
        return;
    }
    if (!(ev & (EPOLLIN | EPOLLOUT))) return;

    if (r->state == RELAY_REALITY_HS) {
        int rc;
        /* EPOLLET: сервер шлёт ServerHello+EE+Cert+CV+Finished одним burst-ом.
         * Нельзя возвращаться в epoll после rc==0: новый EPOLLIN не придёт.
         * Крутим цикл пока шаги потребляют уже буферизованные данные (rc==0).
         * rc==-2 (WANT_READ/EAGAIN) — реально нечего читать, ждём epoll. */
        do {
            rc = reality_conn_step((reality_conn_t *)r->reality);
            if (rc == 1) {
                /* Reality TLS 1.3 handshake завершён */
                reality_conn_t *rcp = (reality_conn_t *)r->reality;
                if (rcp->hs.reality && !rcp->hs.reality->verified) {
                    log_msg(LOG_DEBUG,
                            "Reality: cert не аутентифицирован (decoy) — "
                            "продолжаем в compat mode");
                }
                log_msg(LOG_DEBUG, "Reality: handshake завершён");

                /* Запускаем VLESS handshake поверх Reality */
                const ServerConfig *srv = (g_config && r->server_idx >= 0)
                                    ? config_get_server(g_config, r->server_idx)
                                    : NULL;
                if (!srv) {
                    log_msg(LOG_WARN, "Reality: server_idx %d не найден",
                            r->server_idx);
                    relay_free(ds, r);
                    return;
                }

#if CONFIG_EBURNET_XUDP
                /* Mux.Cool поверх Reality: передаём reality_conn во владение pool */
                if (r->muxcool_stream && r->muxcool_stream->conn) {
                    muxcool_conn_t *mc = r->muxcool_stream->conn;
                    mc->tcp_fd = r->upstream_fd;
                    muxcool_conn_set_transport(mc, r->reality,
                                               cb_reality_send, cb_reality_recv,
                                               (void(*)(void*))reality_conn_free);
                    r->reality = NULL;
                    log_msg(LOG_INFO, "relay [%s] REALITY_HS→MUXCOOL_HS sid=%u",
                            srv->name, r->muxcool_stream->session_id);
                    r->state = RELAY_MUXCOOL_HS;
                    r->vless_resp_len = 0;
                    return;
                }
#endif /* CONFIG_EBURNET_XUDP */

                uint8_t vision_addons[VISION_ADDONS_LEN];
                uint8_t vision_addons_len = 0;
                if (srv->reality_flow[0] &&
                    strstr(srv->reality_flow, "vision")) {
                    vless_uuid_t vuuid;
                    if (vless_uuid_parse(srv->uuid, &vuuid) != 0) {
                        log_msg(LOG_WARN,
                                "VLESS Reality: невалидный UUID для Vision");
                        dispatcher_server_result(ds, r->server_idx, false);
                        RELAY_FAIL_OR_RETRY(ds, r);
                    }
                    r->vision = malloc(sizeof(vision_state_t));
                    if (!r->vision) {
                        dispatcher_server_result(ds, r->server_idx, false);
                        RELAY_FAIL_OR_RETRY(ds, r);
                    }
                    vision_state_init(r->vision, 0, vuuid.bytes);
                    vision_addons_len = (uint8_t)vision_build_addons(
                                            vision_addons,
                                            sizeof(vision_addons));
                    log_msg(LOG_DEBUG,
                            "VLESS Reality: Vision активирован (%s)",
                            srv->reality_flow);
                }

                if (vless_handshake_start_reality(r->reality, &r->dst,
                                                    r->domain[0] ? r->domain : NULL,
                                                    srv->uuid,
                                                    vision_addons_len
                                                      ? vision_addons : NULL,
                                                    vision_addons_len) < 0) {
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                /* WHY: xray-core с Vision flow не отвечает до получения первого
                 * Vision-framed пакета от клиента. Отправляем пустой probe
                 * (cmd=CONTINUE, content_len=0) чтобы разблокировать сервер. */
                if (r->vision) {
                    vision_write_ex(r->vision, reality_send_fn, r->reality,
                                    NULL, 0);
                    log_msg(LOG_DEBUG, "Reality+Vision: empty probe отправлен");
                }
                log_msg(LOG_INFO, "relay [%s] REALITY_HS→REALITY_VLESS", srv->name);
                r->state = RELAY_REALITY_VLESS;
                r->vless_resp_len = 0;

                /* После Reality+VLESS header — нужны только входящие байты */
                struct epoll_event mod = {
                    .events   = EPOLLIN | EPOLLET,
                    .data.ptr = &r->ep_upstream,
                };
                epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD,
                          r->upstream_fd, &mod);
                /* WHY: client_fd использует EPOLLET — EPOLLIN мог сработать
                 * раньше и быть проигнорирован (HS-фаза не читала клиента).
                 * Дренируем сейчас: inner-TLS данные нужны xray до ответа. */
                reality_vless_drain_client(ds, r);
                return;
            } else if (rc == -1) {
                log_msg(LOG_WARN, "Reality: handshake провалился");
                dispatcher_server_result(ds, r->server_idx, false);
                RELAY_FAIL_OR_RETRY(ds, r);
            }
            /* rc == 0: шаг выполнен, данные ещё есть в буфере → следующая итерация
             * rc == -2: WANT_READ (EAGAIN) → выходим, ждём epoll */
        } while (rc == 0);
        return;
    }

    /* RELAY_REALITY_VLESS: читаем VLESS response через Reality */
    int vrc = vless_read_response_step_reality(r->reality,
                                                  r->vless_resp_buf,
                                                  &r->vless_resp_len);
    if (vrc == 0) {
        dispatcher_server_result(ds, r->server_idx, true);
        proxy_group_mark_server_ok(g_pgm, r->server_idx);
        log_msg(LOG_INFO, "relay REALITY_VLESS→ACTIVE");
        r->state = RELAY_ACTIVE;
        r->upstream_first_byte_deadline = time(NULL) + 10;
        log_msg(LOG_DEBUG, "relay: VLESS+Reality установлен, активен");
#ifdef __mips__
        /* WHY: на MIPS AES-GCM без HW accl ~0.5ms/запись. EPOLLET + for(;;) drain
         * всего буфера = десятки ms блокировки dispatcher_tick → DNS голодание.
         * Переходим в LT: loop можно ограничить, событие перезапустится если данные остались. */
        if (r->upstream_fd >= 0 && !r->upstream_lt_mode) {
            struct epoll_event _ev_lt = {
                .events   = EPOLLIN | EPOLLRDHUP,
                .data.ptr = &r->ep_upstream,
            };
            epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD, r->upstream_fd, &_ev_lt);
            r->upstream_lt_mode = true;
        }
#endif
        /* WHY: с EPOLLET данные могут уже быть в recv-буфере сокета в момент
         * перехода состояния (VLESS response и первые данные пришли одним TCP burst-ом).
         * Без немедленного дренажа EPOLLIN не придёт до прихода НОВЫХ байт → данные
         * зависают в ядре → CLOSE_WAIT с recv-Q → YouTube/браузер не получает ответ. */
        relay_ep_t drain_ep = { .relay = r, .is_client = false };
        relay_handle_active(ds, r, &drain_ep, EPOLLIN, time(NULL));
        /* WHY: client_fd зарегистрирован с EPOLLIN|EPOLLET ДО handshake.
         * iPhone мог отправить inner ClientHello пока шёл Reality+VLESS
         * handshake к upstream — kernel держит данные в recv-буфере, но
         * EPOLLET не сгенерирует новый event до прихода НОВЫХ байт.
         * Симптом: relay closed in=0..7 out=6500+ (сервер начал TLS handshake
         * но получил пустоту от клиента). Принудительный drain client side
         * после ACTIVE дренирует kernel buffer и пропускает ClientHello к
         * upstream. Делаем только если relay ещё ACTIVE — initial upstream
         * drain мог уже перевести в HALF_CLOSE/CLOSING. */
        if (r->state == RELAY_ACTIVE) {
            relay_ep_t drain_cli = { .relay = r, .is_client = true };
            relay_handle_active(ds, r, &drain_cli, EPOLLIN, time(NULL));
        }
    } else if (vrc < 0) {
        dispatcher_server_result(ds, r->server_idx, false);
        RELAY_FAIL_OR_RETRY(ds, r);
    }
}
#endif /* CONFIG_EBURNET_VLESS */

#if CONFIG_EBURNET_XUDP
/* ================================================================
 * Mux.Cool transport I/O callbacks (transport-agnostic).
 * Каждый транспорт предоставляет send/recv callbacks + free_fn
 * которые устанавливаются через muxcool_conn_set_transport().
 * ================================================================ */

/* ── Plain TLS (ctx = WOLFSSL*) ── */
static ssize_t cb_tls_send(void *ctx, const uint8_t *buf, size_t len)
{
    int r = wolfSSL_write((WOLFSSL *)ctx, buf, (int)len);
    if (r < 0) {
        int e = wolfSSL_get_error((WOLFSSL *)ctx, r);
        if (e == WOLFSSL_ERROR_WANT_WRITE || e == WOLFSSL_ERROR_WANT_READ)
            errno = EAGAIN;
        return -1;
    }
    return (ssize_t)r;
}
static ssize_t cb_tls_recv(void *ctx, uint8_t *buf, size_t len)
{
    int r = wolfSSL_read((WOLFSSL *)ctx, buf, (int)len);
    if (r < 0) {
        int e = wolfSSL_get_error((WOLFSSL *)ctx, r);
        if (e == WOLFSSL_ERROR_WANT_READ || e == WOLFSSL_ERROR_WANT_WRITE)
            errno = EAGAIN;
        return -1;
    }
    return (ssize_t)r;
}
static void cb_tls_free(void *ctx) { if (ctx) wolfSSL_free((WOLFSSL *)ctx); }

/* ── Reality (ctx = reality_conn_t*) ── */
static ssize_t cb_reality_send(void *ctx, const uint8_t *buf, size_t len)
{
    return reality_send((reality_conn_t *)ctx, buf, len);
}
static ssize_t cb_reality_recv(void *ctx, uint8_t *buf, size_t len)
{
    return reality_recv((reality_conn_t *)ctx, buf, len);
}
/* free = reality_conn_free — передаётся напрямую как void(*)(void*) */

/* ── WebSocket+TLS (ctx = muxcool_ws_ctx_t*, тип объявлен выше) ── */

/* TLS wrappers для ws_client_send/recv (ws_io_fn = non-const) */
static ssize_t _mux_ws_tls_send(void *ctx, uint8_t *buf, size_t len)
{
    return tls_send((tls_conn_t *)ctx, buf, len);
}
static ssize_t _mux_ws_tls_recv(void *ctx, uint8_t *buf, size_t len)
{
    return tls_recv((tls_conn_t *)ctx, buf, len);
}
static ssize_t cb_ws_send(void *ctx, const uint8_t *buf, size_t len)
{
    muxcool_ws_ctx_t *c = ctx;
    return ws_client_send(c->ws, _mux_ws_tls_send, c->tls, buf, len);
}
static ssize_t cb_ws_recv(void *ctx, uint8_t *buf, size_t len)
{
    muxcool_ws_ctx_t *c = ctx;
    return ws_client_recv(c->ws, _mux_ws_tls_recv, c->tls, buf, len);
}
static void cb_ws_free(void *ctx)
{
    muxcool_ws_ctx_t *c = ctx;
    if (!c) return;
    if (c->ws)  { free(c->ws);  c->ws  = NULL; }
    if (c->tls) { tls_close(c->tls); free(c->tls); c->tls = NULL; }
    free(c);
}

/* ── XHTTP (ctx = xhttp_state_t*) ── */
static ssize_t cb_xhttp_send(void *ctx, const uint8_t *buf, size_t len)
{
    return xhttp_send_chunk((xhttp_state_t *)ctx, buf, len);
}
static ssize_t cb_xhttp_recv(void *ctx, uint8_t *buf, size_t len)
{
    return xhttp_recv_chunk((xhttp_state_t *)ctx, buf, len);
}
static void cb_xhttp_free(void *ctx)
{
    if (!ctx) return;
    xhttp_close((xhttp_state_t *)ctx);
    free(ctx);
}

#if CONFIG_EBURNET_GRPC_MULTIPLEX
/* ── gRPC pool stream (ctx = muxcool_grpc_ctx_t*, тип объявлен выше) ── */

static ssize_t cb_grpc_send(void *ctx, const uint8_t *buf, size_t len)
{
    muxcool_grpc_ctx_t *c = ctx;
    return (ssize_t)grpc_stream_send(c->stream, grpc_pool_tls_send, c->ssl,
                                      buf, len);
}
static ssize_t cb_grpc_recv(void *ctx, uint8_t *buf, size_t len)
{
    muxcool_grpc_ctx_t *c = ctx;
    return (ssize_t)grpc_stream_recv(c->stream, grpc_pool_tls_send,
                                      grpc_pool_tls_recv, c->ssl, buf, len);
}
static void cb_grpc_free(void *ctx)
{
    muxcool_grpc_ctx_t *c = ctx;
    if (!c) return;
    if (c->stream) { grpc_stream_release(c->stream); c->stream = NULL; }
    /* ssl управляется grpc_connection_t — НЕ освобождаем */
    free(c);
}
#endif /* CONFIG_EBURNET_GRPC_MULTIPLEX */

#endif /* CONFIG_EBURNET_XUDP */

#if CONFIG_EBURNET_GRPC_MULTIPLEX
/* WHY: raw recv() drain уничтожает зашифрованные DATA frames,
 * не давая wolfSSL их расшифровать и доставить pending_to_client.
 * Результат: premature EOS для iOS → серый экран YouTube.
 *
 * Правильный подход: не трогать tcp_fd. Стримы сами деградируют
 * через wolfSSL_read → EBADF/EOF → relay_free когда пробудятся.
 * pool_tick уберёт GRPC_CONN_IDLE через GRPC_CONN_IDLE_TIMEOUT_SEC. */
static void grpc_conn_teardown(dispatcher_state_t *ds, grpc_conn_ep_t *w)
{
    (void)ds;

    grpc_connection_t *pconn = w->conn;
    if (!pconn)
        return;

    /* Пнуть wake_fd всех живых streams чтобы они быстро завершились */
    for (int i = 0; i < GRPC_STREAMS_PER_CONN_MAX; i++) {
        if (pconn->streams[i] && pconn->streams[i]->wake_fd >= 0) {
            uint64_t v = 1;
            write(pconn->streams[i]->wake_fd, &v, sizeof(v));
        }
    }

    /* НЕ закрывать tcp_fd, НЕ делать raw recv drain, НЕ менять state */
    /* wolfSSL продолжит работу через существующий tcp_fd */
}
#endif /* CONFIG_EBURNET_GRPC_MULTIPLEX */

/* ------------------------------------------------------------------ */
/*  dispatcher_tick — обработка событий relay (C-06 декомпозиция)       */
/* ------------------------------------------------------------------ */
void dispatcher_tick(dispatcher_state_t *ds)
{
    if (ds->epoll_fd < 0)
        return;

    struct timespec ts_start;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    s_retries_this_tick = 0;

    /* WHY: throttle только для RELAY_REALITY_HS (keygen + HS-шаги содержат Curve25519).
     * RELAY_REALITY_VLESS использует только AES-GCM — throttle там не нужен. */
#ifdef __mips__
    static uint32_t s_reality_hs_this_tick = 0;
    s_reality_hs_this_tick = 0;
#endif

    /* mem_tier-driven лимит (G15-2): LOW=8, MID=32, HIGH=64.
     * Заменил MIPS-only static 8 — динамический лимит универсален:
     * на 128MB MIPS получаем 8 (4ms AES-GCM), на 512MB+ — 64. */
    unsigned _max_ev = g_dispatcher_max_events;
    if (_max_ev > DISPATCHER_MAX_EVENTS_CAP) _max_ev = DISPATCHER_MAX_EVENTS_CAP;
    struct epoll_event events[DISPATCHER_MAX_EVENTS_CAP];
    int n = epoll_wait(ds->epoll_fd, events, (int)_max_ev, 0);

    time_t now = time(NULL);

    for (int i = 0; i < n; i++) {
        if (!events[i].data.ptr) continue;

#if CONFIG_EBURNET_GRPC_MULTIPLEX
        /* Полиморфный диспатч по ep_type (первое поле обоих struct).
         * EPOLL_EP_GRPC_CONN: persistent watcher разделяемого conn->tcp_fd —
         * драйвит recv_dispatch, заполняет pending_to_client streams и
         * сигнализирует им через wake_fd. */
        if (*(int *)events[i].data.ptr == EPOLL_EP_GRPC_CONN) {
            grpc_conn_ep_t *w = (grpc_conn_ep_t *)events[i].data.ptr;
            uint32_t wev = events[i].events;
            if (wev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                grpc_conn_teardown(ds, w);
                continue;
            }
            grpc_connection_t *pconn = w->conn;
            if (!pconn || !pconn->tls) continue;
            void *ptls = pconn->tls;
            int rc;
            int iters = 0;
            do {
                rc = grpc_connection_recv_dispatch(pconn,
                                                   grpc_pool_tls_send,
                                                   grpc_pool_tls_recv, ptls);
                if (++iters >= 64) break; /* MIPS fairness cap */
            } while (rc == 1);
            continue;
        }
#endif
#if CONFIG_EBURNET_XUDP
        /* EPOLL_EP_MUXCOOL_CONN: persistent watcher Mux.Cool conn->tcp_fd —
         * драйвит recv_dispatch, заполняет pending streams и сигналит wake_fd. */
        if (*(int *)events[i].data.ptr == EPOLL_EP_MUXCOOL_CONN) {
            muxcool_conn_ep_t *mw = (muxcool_conn_ep_t *)events[i].data.ptr;
            uint32_t mev = events[i].events;
            if (mev & (EPOLLERR | EPOLLHUP)) {
                /* Соединение оборвалось — cleanup через pool_tick. */
                continue;
            }
            muxcool_conn_t *mconn = mw->conn;
            if (!mconn || !mconn->transport_ctx) continue;
            int mrc;
            int miters = 0;
            do {
                mrc = muxcool_connection_recv_dispatch(mconn,
                                                        mconn->transport_send,
                                                        mconn->transport_recv,
                                                        mconn->transport_ctx);
                if (++miters >= 64) break; /* MIPS fairness cap */
            } while (mrc == 1);
            continue;
        }
#endif

        relay_ep_t *ep = events[i].data.ptr;
        if (!ep->relay)
            continue;

        relay_conn_t *r = ep->relay;
        uint32_t ev = events[i].events;

        /* M-05: guard — relay уже освобождён другим событием в этом batch */
        if (r->state == RELAY_DONE) continue;

        /* Ошибка или разрыв */
        if (ev & (EPOLLERR | EPOLLHUP)) {
            relay_free(ds, r);
            continue;
        }

        switch (r->state) {
        case RELAY_CONNECTING:
            /* WHY: при FIN от peer до завершения connect (SYN-ACK + FIN) ядро
             * доставляет EPOLLRDHUP без EPOLLOUT. Без обработки relay зависает
             * в CONNECTING до таймаута 60s. EPOLLERR (RST) и EPOLLHUP закрыты
             * выше (~строка 3151) — здесь только FIN-only path. */
            if (!ep->is_client && (ev & EPOLLRDHUP) && !(ev & EPOLLOUT)) {
                log_msg(LOG_DEBUG,
                    "relay[%d]: CONNECTING upstream closed (EPOLLRDHUP, no EPOLLOUT)",
                    r->upstream_fd);
                relay_free(ds, r);
                continue;
            }
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

                /* connect успешен — сброс дедлайна и переключить upstream на EPOLLIN|EPOLLOUT */
                r->connect_deadline = 0;
                struct epoll_event mod = {
                    .events   = EPOLLIN | EPOLLOUT | EPOLLET,
                    .data.ptr = &r->ep_upstream,
                };
                if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD,
                              r->upstream_fd, &mod) < 0)
                    log_msg(LOG_WARN, "relay: epoll_ctl(MOD connect): %s", strerror(errno));

                /* Запустить протокольное рукопожатие (неблокирующее) */
                const ServerConfig *server = NULL;
                if (g_config && r->server_idx >= 0)
                    server = config_get_server(g_config, r->server_idx);

                if (server) {
#if CONFIG_EBURNET_STLS
                    /* ShadowTLS transport: handshake до inner protocol */
                    if (server->stls_password[0] &&
                        server->transport[0] &&
                        strcmp(server->transport, "shadowtls") == 0) {
                        shadowtls_ctx_t *stls =
                            malloc(sizeof(shadowtls_ctx_t));
                        if (!stls) {
                            relay_free(ds, r); continue;
                        }
                        stls_ctx_init(stls, server->stls_password);
                        r->stls = stls;
                        if (stls_send_client_hello(r->upstream_fd, stls,
                                                    server->stls_sni) < 0) {
                            log_msg(LOG_WARN,
                                "relay: ShadowTLS ClientHello провалился");
                            dispatcher_server_result(ds, r->server_idx,
                                                     false);
                            relay_free(ds, r);
                            continue;
                        }
                        r->state = RELAY_STLS_SHAKE;
                        break;
                    }
#endif
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
        case RELAY_VLESS_SHAKE:
            relay_handle_tls(ds, r, ep, ev);
            break;

        case RELAY_GRPC_HS: {
            /* T0-03: gRPC HTTP/2 handshake + протокольный header */
            if (ep->is_client) break;
            if (!(ev & (EPOLLIN | EPOLLOUT))) break;

            const ServerConfig *srv_grpc =
                (g_config && r->server_idx >= 0)
                ? config_get_server(g_config, r->server_idx) : NULL;
            if (!srv_grpc) { relay_free(ds, r); break; }

#if CONFIG_EBURNET_GRPC_MULTIPLEX
            if (r->grpc_stream) {
                /* MULTIPLEX: H2 HS через grpc_connection_hs_step (уже есть TLS) */
                grpc_connection_t *pconn = r->grpc_stream->conn;
                void *ptls = pconn->tls;

                if (pconn->state != GRPC_CONN_ACTIVE) {
                    int  pret = 0;
                    int  piters = 0;
                    do {
                        pret = grpc_connection_hs_step(pconn,
                                                       grpc_pool_tls_send,
                                                       grpc_pool_tls_recv,
                                                       ptls);
                        if (pret < 0) {
                            int saved = errno;
                            if (saved != EAGAIN && saved != EWOULDBLOCK) {
                                log_msg(LOG_WARN,
                                        "gRPC pool HS провалился [%s]: %s",
                                        srv_grpc->name, strerror(saved));
                                dispatcher_server_result(ds, r->server_idx, false);
                                RELAY_FAIL_OR_RETRY(ds, r);
                            }
                            break;
                        }
                        if (++piters >= 64) { pret = -1; errno = EAGAIN; break; }
                    } while (pret == 0);
                    if (pconn->state != GRPC_CONN_ACTIVE) break; /* EAGAIN */

                    /* H2 HS завершён */
#if CONFIG_EBURNET_XUDP
                    if (r->muxcool_stream && r->muxcool_stream->conn) {
                        muxcool_grpc_ctx_t *gctx = malloc(sizeof(*gctx));
                        if (!gctx) {
                            dispatcher_server_result(ds, r->server_idx, false);
                            RELAY_FAIL_OR_RETRY(ds, r);
                        }
                        gctx->stream   = r->grpc_stream;
                        gctx->ssl      = pconn->tls;
                        r->grpc_stream = NULL;
                        muxcool_conn_t *mc = r->muxcool_stream->conn;
                        mc->tcp_fd = pconn->tcp_fd;
                        muxcool_conn_set_transport(mc, gctx,
                                                   cb_grpc_send, cb_grpc_recv,
                                                   cb_grpc_free);
                        log_msg(LOG_INFO, "relay [%s] GRPC_HS→MUXCOOL_HS sid=%u",
                                srv_grpc->name, r->muxcool_stream->session_id);
                        r->state = RELAY_MUXCOOL_HS;
                        r->vless_resp_len = 0;
                        break;
                    }
#endif /* CONFIG_EBURNET_XUDP */
                    if (grpc_stream_send_proto_header(r, srv_grpc) < 0) {
                        dispatcher_server_result(ds, r->server_idx, false);
                        RELAY_FAIL_OR_RETRY(ds, r);
                    }

                    if (strcmp(srv_grpc->protocol, "trojan") == 0) {
                        r->client_sent_first = true;
                        dispatcher_server_result(ds, r->server_idx, true);
                        r->state = RELAY_ACTIVE;
                        r->upstream_first_byte_deadline = now + 10;
                        /* Установить watcher ДО forced drain — relay_transfer
                         * ожидает r->upstream_fd = wake_fd для grpc_stream */
                        if (grpc_install_conn_watcher(ds, r) < 0) {
                            relay_free(ds, r);
                            break;
                        }
                        {
                            relay_ep_t _dep = {
                                .ep_type   = EPOLL_EP_RELAY,
                                .relay     = r,
                                .is_client = false,
                            };
                            relay_handle_active(ds, r, &_dep, EPOLLIN, time(NULL));
                        }
                        if (r->state == RELAY_ACTIVE) {
                            relay_ep_t _cep = {
                                .ep_type   = EPOLL_EP_RELAY,
                                .relay     = r,
                                .is_client = true,
                            };
                            relay_handle_active(ds, r, &_cep, EPOLLIN, time(NULL));
                        }
                        break;
                    }
                    /* VLESS: fall through к чтению response */
                }

                /* VLESS response через gRPC stream */
                if (r->vless_resp_len < 2) {
                    ssize_t prv = grpc_stream_recv(r->grpc_stream,
                                                   grpc_pool_tls_send,
                                                   grpc_pool_tls_recv, ptls,
                                                   r->vless_resp_buf + r->vless_resp_len,
                                                   2u - r->vless_resp_len);
                    if (prv < 0) {
                        int saved = errno;
                        if (saved != EAGAIN && saved != EWOULDBLOCK) {
                            log_msg(LOG_WARN,
                                    "gRPC pool VLESS response провалился [%s]: %s",
                                    srv_grpc->name, strerror(saved));
                            dispatcher_server_result(ds, r->server_idx, false);
                            RELAY_FAIL_OR_RETRY(ds, r);
                        }
                        break;
                    }
                    r->vless_resp_len += (uint8_t)prv;
                }
                if (r->vless_resp_len >= 2) {
                    uint8_t addons_need = r->vless_resp_buf[1];
                    if (addons_need > 0 && r->vless_resp_buf[2] < addons_need) {
                        uint8_t scratch[256];
                        ssize_t prv2 = grpc_stream_recv(r->grpc_stream,
                                                        grpc_pool_tls_send,
                                                        grpc_pool_tls_recv, ptls,
                                                        scratch,
                                                        (size_t)(addons_need - r->vless_resp_buf[2]));
                        if (prv2 < 0) {
                            int saved = errno;
                            if (saved != EAGAIN && saved != EWOULDBLOCK) {
                                dispatcher_server_result(ds, r->server_idx, false);
                                RELAY_FAIL_OR_RETRY(ds, r);
                            }
                            break;
                        }
                        r->vless_resp_buf[2] += (uint8_t)prv2;
                        if (r->vless_resp_buf[2] < addons_need) break;
                    }
                    dispatcher_server_result(ds, r->server_idx, true);
                    log_msg(LOG_INFO,
                            "relay [%s] GRPC_HS→ACTIVE pool (VLESS resp ok)",
                            srv_grpc->name);
                    r->state = RELAY_ACTIVE;
                    r->upstream_first_byte_deadline = now + 10;
                    /* Установить persistent watcher на conn->tcp_fd —
                     * вторичные streams теперь получают данные независимо от
                     * жизни этого primary relay. */
                    if (grpc_install_conn_watcher(ds, r) < 0) {
                        relay_free(ds, r);
                        break;
                    }
                }
                break;
            }
#endif /* CONFIG_EBURNET_GRPC_MULTIPLEX */

            if (!r->grpc) { relay_free(ds, r); break; }

            if (r->grpc->state != GRPC_HS_PROTO_SENT) {
                /* WHY цикл до EAGAIN: сервер может слать SETTINGS + WINDOW_UPDATE
                 * в нескольких TLS records в одном TCP сегменте. wolfSSL_pending()
                 * не видит следующий record до его расшифровки, а EPOLLET не
                 * сработает повторно — данные уже в TCP буфере. Только цикл до
                 * EAGAIN гарантирует обработку всего burst за один epoll тик.
                 * WHY лимит 64: при ненормальном сервере (много SETTINGS/WINDOW_UPDATE)
                 * или OOM-деградации TLS буферов цикл без лимита монополизировал
                 * dispatcher_tick на 3.94s (наблюдалось 2026-05-06). 64 итерации =
                 * ~32ms MIPS (0.5ms/AES-GCM × 64) — достаточно для нормального HS. */
                int ret = 0;
                int _hs_iters = 0;
                do {
                    ret = grpc_handshake_step(r->grpc,
                                              grpc_tls_send, grpc_tls_recv,
                                              r->tls);
                    if (ret < 0) {
                        int saved = errno;
                        if (saved != EAGAIN && saved != EWOULDBLOCK) {
                            log_msg(LOG_WARN,
                                    "gRPC HS провалился [%s]: %s",
                                    srv_grpc->name, strerror(saved));
                            dispatcher_server_result(ds, r->server_idx, false);
                            RELAY_FAIL_OR_RETRY(ds, r);
                        }
                        break; /* EAGAIN или fatal — выходим из цикла */
                    }
                    /* ret == 2: gRPC HEADERS только что отправлены.
                     * WHY Trojan: xray шлёт 200 OK ТОЛЬКО после получения Trojan
                     * DATA frame. Ждать 200 OK перед отправкой DATA = дедлок.
                     * Решение: для Trojan отправляем proto header здесь немедленно;
                     * 200 OK придёт позже и будет задренирован в grpc_recv.
                     * WHY VLESS ret=0: VLESS получает 200 OK до DATA, продолжаем
                     * цикл пока не прочитаем 200 OK (или EAGAIN). */
                    if (ret == 2 && strcmp(srv_grpc->protocol, "trojan") == 0) {
                        if (grpc_send_proto_header(r, srv_grpc) < 0) {
                            dispatcher_server_result(ds, r->server_idx, false);
                            RELAY_FAIL_OR_RETRY(ds, r);
                        }
                        break; /* state = GRPC_HS_PROTO_SENT; переход в ACTIVE ниже */
                    }
                    if (ret == 2) ret = 0; /* VLESS: продолжаем читать до 200 OK */
                    /* WHY: лимит защищает от monopolization при аномальном burst.
                     * Остаёмся в RELAY_GRPC_HS — следующий epoll event продолжит. */
                    if (++_hs_iters >= 64) { ret = -1; errno = EAGAIN; break; }
                } while (ret == 0); /* продолжаем пока фреймы доступны */
                /* EAGAIN — ждём следующего epoll события.
                 * Исключение: Trojan отправил proto header early (state = PROTO_SENT). */
                if (ret <= 0 && r->grpc->state != GRPC_HS_PROTO_SENT) break;

                /* ret == 1 (VLESS: 200 OK получен) или state == GRPC_HS_PROTO_SENT
                 * (Trojan: proto header отправлен до 200 OK). */
                if (r->grpc->state != GRPC_HS_PROTO_SENT) {
                    /* VLESS: 200 OK получен — отправляем proto header */
                    if (grpc_send_proto_header(r, srv_grpc) < 0) {
                        dispatcher_server_result(ds, r->server_idx, false);
                        RELAY_FAIL_OR_RETRY(ds, r);
                    }
                }
                /* Для Trojan нет response — сразу ACTIVE.
                 * WHY: после отправки Trojan-заголовка сервер пришлёт HTTP/2 SETTINGS.
                 * Без client_sent_first=true guard в relay_handle_active блокирует
                 * grpc_recv → SETTINGS ACK не уходит → сервер закрывает через ~15с (out=0). */
                if (strcmp(srv_grpc->protocol, "trojan") == 0) {
                    r->client_sent_first = true;
                    dispatcher_server_result(ds, r->server_idx, true);
                    {
                        char _dstbuf[64] = "(no-ip)";
                        if (r->dst.ss_family == AF_INET) {
                            inet_ntop(AF_INET,
                                &((struct sockaddr_in *)&r->dst)->sin_addr,
                                _dstbuf, sizeof(_dstbuf));
                        }
                        uint16_t _port = (r->dst.ss_family == AF_INET)
                            ? ntohs(((struct sockaddr_in *)&r->dst)->sin_port) : 0;
                        log_msg(LOG_INFO,
                                "relay [%s] GRPC_HS→ACTIVE (Trojan) dst=%s:%u domain=%s",
                                srv_grpc->name, _dstbuf, _port,
                                r->domain[0] ? r->domain : "(empty)");
                    }
                    r->state = RELAY_ACTIVE;
                    r->upstream_first_byte_deadline = now + 10;
                    /* WHY forced drain (upstream): с EPOLLET данные (WINDOW_UPDATE,
                     * SETTINGS) от сервера могут остаться в wolfSSL buffer после HS
                     * loop — EPOLLIN не придёт до прихода НОВЫХ байт. Дренируем
                     * немедленно: обрабатываем остатки, обновляем flow control окна.
                     * WHY drain client: iPhone мог послать данные пока шёл HS — те
                     * байты в recv-буфере client_fd, EPOLLET не сгенерирует новый
                     * event. Без drain → ClientHello не дойдёт до xray. */
                    {
                        relay_ep_t _dep = { .relay = r, .is_client = false };
                        relay_handle_active(ds, r, &_dep, EPOLLIN, time(NULL));
                    }
                    if (r->state == RELAY_ACTIVE) {
                        relay_ep_t _cep = { .relay = r, .is_client = true };
                        relay_handle_active(ds, r, &_cep, EPOLLIN, time(NULL));
                    }
                    break;
                }
                /* VLESS: ждём 2-байтовый response в следующем вызове */
            }

            /* Шаг 2 (только VLESS): читаем VLESS response через gRPC.
             * Один recv за epoll-событие — как в RELAY_VLESS_SHAKE. */
            if (r->vless_resp_len < 2) {
                ssize_t rv = grpc_recv(r->grpc, grpc_tls_send, grpc_tls_recv, r->tls,
                                       r->vless_resp_buf + r->vless_resp_len,
                                       2u - r->vless_resp_len);
                if (rv < 0) {
                    int saved = errno;
                    if (saved != EAGAIN && saved != EWOULDBLOCK) {
                        log_msg(LOG_WARN,
                                "gRPC VLESS response провалился [%s]: %s",
                                srv_grpc->name, strerror(saved));
                        dispatcher_server_result(ds, r->server_idx, false);
                        RELAY_FAIL_OR_RETRY(ds, r);
                    }
                    break;
                }
                r->vless_resp_len += (uint8_t)rv;
            }
            if (r->vless_resp_len >= 2) {
                /* WHY: VLESS response = version(1) + addons_len(1) + addons(N).
                 * Если addons_len > 0 — addons остаются в gRPC stream → corruption. */
                uint8_t addons_need = r->vless_resp_buf[1];
                if (addons_need > 0 && r->vless_resp_buf[2] < addons_need) {
                    uint8_t scratch[256];
                    ssize_t rv = grpc_recv(r->grpc, grpc_tls_send, grpc_tls_recv, r->tls,
                                           scratch,
                                           (size_t)(addons_need - r->vless_resp_buf[2]));
                    if (rv < 0) {
                        int saved = errno;
                        if (saved != EAGAIN && saved != EWOULDBLOCK) {
                            dispatcher_server_result(ds, r->server_idx, false);
                            RELAY_FAIL_OR_RETRY(ds, r);
                        }
                        break;
                    }
                    r->vless_resp_buf[2] += (uint8_t)rv;
                    if (r->vless_resp_buf[2] < addons_need) break;
                }
                dispatcher_server_result(ds, r->server_idx, true);
                log_msg(LOG_INFO,
                        "relay [%s] GRPC_HS→ACTIVE (VLESS resp ok)",
                        srv_grpc->name);
                r->state = RELAY_ACTIVE;
                r->upstream_first_byte_deadline = now + 10;
            }
            break;
        }

        case RELAY_WS_HS: {
            /* T0-04: WebSocket HTTP Upgrade handshake + VLESS response поверх TLS.
             * WHY не RELAY_VLESS_SHAKE: vless_read_response_step читает raw TLS,
             * тогда как VLESS response для WS завёрнут в WS binary frame.
             * Держим весь WS+VLESS flow здесь через ws_client_recv. */
            if (ep->is_client) break;
            if (!(ev & (EPOLLIN | EPOLLOUT))) break;

            const ServerConfig *srv_ws =
                (g_config && r->server_idx >= 0)
                ? config_get_server(g_config, r->server_idx) : NULL;
            if (!srv_ws || !r->ws) { relay_free(ds, r); break; }

            if (!r->ws->proto_sent) {
                /* Фаза 1: WS HTTP Upgrade handshake */
                int ret = ws_client_handshake_step(r->ws,
                                                   grpc_tls_send, grpc_tls_recv,
                                                   r->tls);
                if (ret < 0) {
                    int saved_errno = errno;
                    if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) break;
                    log_msg(LOG_WARN, "WS HS провалился [%s]: %s",
                            srv_ws->name, strerror(saved_errno));
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                if (ret == 0) break; /* ждём ещё данных */

#if CONFIG_EBURNET_XUDP
                /* Mux.Cool поверх WS: передаём ws+tls во владение pool */
                if (r->muxcool_stream && r->muxcool_stream->conn) {
                    muxcool_ws_ctx_t *wctx = malloc(sizeof(*wctx));
                    if (!wctx) {
                        dispatcher_server_result(ds, r->server_idx, false);
                        RELAY_FAIL_OR_RETRY(ds, r);
                    }
                    wctx->ws  = (ws_client_conn_t *)r->ws;
                    wctx->tls = (tls_conn_t *)r->tls;
                    r->ws      = NULL;
                    r->tls     = NULL;
                    r->use_tls = false;
                    muxcool_conn_t *mc = r->muxcool_stream->conn;
                    mc->tcp_fd = r->upstream_fd;
                    muxcool_conn_set_transport(mc, wctx,
                                               cb_ws_send, cb_ws_recv, cb_ws_free);
                    log_msg(LOG_INFO, "relay [%s] WS_HS→MUXCOOL_HS sid=%u",
                            srv_ws->name, r->muxcool_stream->session_id);
                    r->state = RELAY_MUXCOOL_HS;
                    r->vless_resp_len = 0;
                    break;
                }
#endif /* CONFIG_EBURNET_XUDP */

                /* WS ACTIVE → отправляем VLESS protocol header */
                vless_uuid_t ws_uuid;
                if (vless_uuid_parse(srv_ws->uuid, &ws_uuid) < 0) {
                    log_msg(LOG_WARN, "WS: VLESS UUID невалидный [%s]", srv_ws->name);
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                uint8_t vless_hdr[300];
                int hdr_len = vless_build_request(
                    vless_hdr, sizeof(vless_hdr),
                    &ws_uuid, &r->dst,
                    r->domain[0] ? r->domain : NULL,
                    VLESS_CMD_TCP, NULL, 0);
                if (hdr_len <= 0) {
                    log_msg(LOG_WARN, "WS: не удалось построить VLESS header");
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                if (ws_client_send(r->ws, grpc_tls_send, r->tls,
                                   vless_hdr, (size_t)hdr_len) < 0) {
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                r->ws->proto_sent = true;
                r->vless_resp_len = 0;
                log_msg(LOG_INFO, "relay [%s] WS_HS→VLESS_RESP", srv_ws->name);
                /* падаем в фазу 2 если EPOLLIN доступен */
            }

            /* Фаза 2: читаем 2-байтовый VLESS response через WS frames */
            while (r->vless_resp_len < 2) {
                ssize_t rv = ws_client_recv(r->ws, grpc_tls_recv, r->tls,
                                            r->vless_resp_buf + r->vless_resp_len,
                                            2u - r->vless_resp_len);
                if (rv < 0) {
                    int saved_errno = errno;
                    if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) break;
                    log_msg(LOG_WARN, "WS VLESS resp провалился [%s]: %s",
                            srv_ws->name, strerror(saved_errno));
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                if (rv == 0) {
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                r->vless_resp_len += (uint8_t)rv;
            }
            if (r->vless_resp_len < 2) break; /* ждём ещё */

            dispatcher_server_result(ds, r->server_idx, true);
            log_msg(LOG_INFO, "relay [%s] WS_HS→ACTIVE (VLESS resp ok)", srv_ws->name);
            r->state = RELAY_ACTIVE;
            r->upstream_first_byte_deadline = now + 10;
            break;
        }

        case RELAY_HTTP_UG_HS: {
            /* T0-06: HTTPUpgrade handshake + VLESS header поверх TLS.
             * После 101: raw TCP → переходим в RELAY_VLESS_SHAKE (стандартный путь). */
            if (ep->is_client) break;
            if (!(ev & (EPOLLIN | EPOLLOUT))) break;

            const ServerConfig *srv_hu =
                (g_config && r->server_idx >= 0)
                ? config_get_server(g_config, r->server_idx) : NULL;
            if (!srv_hu || !r->http_ug) { relay_free(ds, r); break; }

            int hu_ret = http_upgrade_step(r->http_ug,
                             (http_ug_io_fn)grpc_tls_send,
                             (http_ug_io_fn)grpc_tls_recv,
                             r->tls);
            if (hu_ret < 0) {
                int saved_errno = errno;
                if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) break;
                log_msg(LOG_WARN, "HTTPUpgrade HS провалился [%s]: %s",
                        srv_hu->name, strerror(saved_errno));
                dispatcher_server_result(ds, r->server_idx, false);
                relay_free(ds, r);
                break;
            }
            if (hu_ret == 0) break; /* ждём ещё данных */

            /* 101 получен → отправить VLESS header (raw TLS, нет framing) */
            vless_uuid_t hu_uuid;
            if (vless_uuid_parse(srv_hu->uuid, &hu_uuid) < 0) {
                log_msg(LOG_WARN, "HTTPUpgrade: невалидный UUID [%s]", srv_hu->name);
                dispatcher_server_result(ds, r->server_idx, false);
                relay_free(ds, r);
                break;
            }
            uint8_t hu_vless_hdr[300];
            int hu_hdr_len = vless_build_request(
                hu_vless_hdr, sizeof(hu_vless_hdr),
                &hu_uuid, &r->dst,
                r->domain[0] ? r->domain : NULL,
                VLESS_CMD_TCP, NULL, 0);
            if (hu_hdr_len <= 0 ||
                tls_send(r->tls, hu_vless_hdr, (size_t)hu_hdr_len) < 0) {
                dispatcher_server_result(ds, r->server_idx, false);
                relay_free(ds, r);
                break;
            }
            /* http_ug больше не нужен — raw TCP в RELAY_ACTIVE */
            free(r->http_ug);
            r->http_ug = NULL;
            r->vless_resp_len = 0;
            r->state = RELAY_VLESS_SHAKE;
            log_msg(LOG_INFO, "relay [%s] HTTP_UG_HS→VLESS_SHAKE", srv_hu->name);
            break;
        }

#if CONFIG_EBURNET_QUIC
        case RELAY_HY2_CONNECT: {
            /* T0-07: QUIC HS + H3 auth + TCPRequest/Response — всё async.
             * Фаза 1 (hy2_stream == NULL): QUIC HS + H3 auth через connect_step.
             * Фаза 2 (hy2_stream != NULL): ожидание TCPResponse. */
            if (ep->is_client) break;
            if (!(ev & EPOLLIN)) break;
            if (!r->hy2_conn) { relay_free(ds, r); break; }

            if (!r->hy2_stream) {
                /* Фаза 1: один шаг QUIC HS + H3 auth */
                int hs_ret = hysteria2_connect_step(
                    (hysteria2_conn_t *)r->hy2_conn);
                if (hs_ret < 0) {
                    log_msg(LOG_WARN, "relay: Hysteria2 HS провалился: %s",
                            hysteria2_strerror((hysteria2_conn_t *)r->hy2_conn));
                    dispatcher_server_result(ds, r->server_idx, false);
                    relay_free(ds, r);
                    break;
                }
                if (hs_ret == 0) break; /* EAGAIN, ждём следующего EPOLLIN */

                /* HS + auth готовы → выделить stream, отправить TCPRequest */
                r->hy2_stream = calloc(1, sizeof(hysteria2_stream_t));
                if (!r->hy2_stream) { relay_free(ds, r); break; }

                char hy2_host[256] = {0};
                uint16_t hy2_port;
                if (r->domain[0]) {
                    strncpy(hy2_host, r->domain, sizeof(hy2_host) - 1);
                } else if (r->dst.ss_family == AF_INET) {
                    inet_ntop(AF_INET,
                              &((struct sockaddr_in *)&r->dst)->sin_addr,
                              hy2_host, sizeof(hy2_host));
                } else {
                    inet_ntop(AF_INET6,
                              &((struct sockaddr_in6 *)&r->dst)->sin6_addr,
                              hy2_host, sizeof(hy2_host));
                }
                hy2_port = (r->dst.ss_family == AF_INET)
                    ? ntohs(((struct sockaddr_in  *)&r->dst)->sin_port)
                    : ntohs(((struct sockaddr_in6 *)&r->dst)->sin6_port);

                if (hysteria2_tcp_open((hysteria2_conn_t *)r->hy2_conn,
                                       (hysteria2_stream_t *)r->hy2_stream,
                                       hy2_host, hy2_port) < 0) {
                    log_msg(LOG_WARN, "relay: hysteria2_tcp_open провалился: %s",
                            hysteria2_strerror((hysteria2_conn_t *)r->hy2_conn));
                    dispatcher_server_result(ds, r->server_idx, false);
                    relay_free(ds, r);
                    break;
                }
                /* TCPRequest отправлен, ждём TCPResponse в следующем EPOLLIN */
                break;
            }

            /* Фаза 2: получить TCPResponse */
            int resp = hysteria2_wait_response_step(
                (hysteria2_conn_t *)r->hy2_conn,
                (hysteria2_stream_t *)r->hy2_stream);
            if (resp < 0) {
                log_msg(LOG_WARN, "relay: Hysteria2 TCPResponse ошибка: %s",
                        ((hysteria2_stream_t *)r->hy2_stream)->error_msg);
                dispatcher_server_result(ds, r->server_idx, false);
                relay_free(ds, r);
                break;
            }
            if (resp == 0) break; /* EAGAIN */

            /* TCPResponse OK → туннель открыт */
            const ServerConfig *srv_hy2 =
                (g_config && r->server_idx >= 0)
                ? config_get_server(g_config, r->server_idx) : NULL;
            dispatcher_server_result(ds, r->server_idx, true);
            log_msg(LOG_INFO, "relay [%s] HY2_CONNECT→ACTIVE",
                    srv_hy2 ? srv_hy2->name : "?");
            r->state = RELAY_ACTIVE;
            r->upstream_first_byte_deadline = now + 10;
            break;
        }
#endif /* CONFIG_EBURNET_QUIC */

#if CONFIG_EBURNET_VLESS
        case RELAY_REALITY_HS:
            /* WHY: сервер закрыл соединение до завершения HS (CLOSE_WAIT).
             * В LT-режиме throttle оставлял fd в epoll с EPOLLRDHUP →
             * epoll_wait возвращал его бесконечно → 23% CPU spin.
             * Закрываем немедленно при любом EPOLLRDHUP/HUP/ERR от upstream.
             *
             * WHY half-close upstream только: при Reality HS fail клиент уже
             * успел послать ClientHello (recv-q=1543 в kernel). Если закрыть
             * клиентский TCP RST'ом — iPhone-приложение видит "сеть ушла"
             * (видео стопит на 2 сек). Снимаем upstream_fd из epoll, помечаем
             * relay в RELAY_HALF_CLOSE — клиент сам пришлёт FIN или попробует
             * другой CDN endpoint в новом TCP. */
            if (!ep->is_client &&
                (ev & (EPOLLRDHUP | EPOLLHUP | EPOLLERR))) {
                log_msg(LOG_WARN, "Reality HS: upstream закрыл соединение (EPOLLRDHUP)");
                dispatcher_server_result(ds, r->server_idx, false);
                RELAY_FAIL_OR_RETRY(ds, r);
            }
            /* WHY: не стартовать новый Reality HS если уже 2 в процессе.
             * pending_init=true = keygen ещё не запускался → блокируем только новые.
             * Уже начатые (pending_init=false) продолжают без задержки. */
            if (r->reality_pending_init
                    && s_reality_hs_active >= REALITY_HS_MAX_CONCURRENT) {
                if (r->upstream_fd >= 0) {
                    struct epoll_event ev_lt2 = {
                        .events   = EPOLLIN | EPOLLRDHUP,
                        .data.ptr = &r->ep_upstream,
                    };
                    epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD, r->upstream_fd, &ev_lt2);
                }
                break;
            }
#ifdef __mips__
            if (s_reality_hs_this_tick++ >= REALITY_HS_PER_TICK) {
                /* WHY: ET stall prevention — если ServerHello уже в буфере но мы throttled,
                 * новый edge event не придёт. Переключаем upstream_fd в LT на этот тик
                 * чтобы epoll_wait вернул событие снова на следующем тике без нового пакета.
                 * ТОЛЬКО EPOLLIN — EPOLLOUT здесь лишний: Reality HS ждёт ServerHello,
                 * сокет всегда writable → EPOLLOUT в LT = busy-spin 100% CPU. */
                if (r->upstream_fd >= 0) {
                    struct epoll_event ev_lt = {
                        .events   = EPOLLIN | EPOLLRDHUP, /* без EPOLLET = LT, без EPOLLOUT */
                        .data.ptr = &r->ep_upstream,
                    };
                    epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD, r->upstream_fd, &ev_lt);
                }
                break;
            }
            /* Восстановить ET если был переведён в LT на предыдущем тике.
             * WHY: НЕТ EPOLLOUT — epoll_ctl(MOD, EPOLLOUT|EPOLLET) на writable сокете
             * немедленно квеит EPOLLOUT независимо от EPOLLET (kernel: ep_modify вызывает
             * ep_item_poll и enqueue при текущей ready → busy-spin даже в ET режиме). */
            if (r->upstream_fd >= 0) {
                struct epoll_event ev_et = {
                    .events   = EPOLLIN | EPOLLET | EPOLLRDHUP,
                    .data.ptr = &r->ep_upstream,
                };
                epoll_ctl(ds->epoll_fd, EPOLL_CTL_MOD, r->upstream_fd, &ev_et);
            }
#endif
            if (r->reality_pending_init) {
                /* WHY: deferred Curve25519 keygen — выполняется здесь под throttle
                 * REALITY_HS_PER_TICK. При accept N Reality-соединений в одном тике
                 * RELAY_CONNECTING вызывал бы N×wc_curve25519_make_key (~10-15ms MIPS)
                 * без ограничений → N×10ms пауза DNS recv-Q → iOS timeout → death spiral. */
                const ServerConfig *srv = (g_config && r->server_idx >= 0)
                                          ? config_get_server(g_config, r->server_idx)
                                          : NULL;
                uint8_t reality_pub[32];
                if (!srv
                    || reality_pbk_decode(srv->reality_pbk, reality_pub) != 0
                    || reality_auth_init((reality_auth_t *)r->reality_auth,
                                         reality_pub,
                                         srv->reality_short_id) != 0) {
                    log_msg(LOG_WARN, "T0-03: deferred reality_auth_init провалился");
                    dispatcher_server_result(ds, r->server_idx, false);
                    RELAY_FAIL_OR_RETRY(ds, r);
                }
                r->reality_pending_init = false;
                s_reality_hs_active++;
            }
            relay_handle_reality(ds, r, ep, ev);
            /* Декремент если relay вышел из REALITY_HS (VLESS→ACTIVE или relay_free).
             * relay_free уже снял счётчик выше — здесь только переход →VLESS. */
            if (r->state != RELAY_REALITY_HS && r->state != RELAY_DONE
                    && s_reality_hs_active > 0)
                s_reality_hs_active--;
            break;
        case RELAY_REALITY_VLESS:
            /* нет throttle — AES-GCM только, Curve25519 отсутствует */
            relay_handle_reality(ds, r, ep, ev);
            break;
#endif

        case RELAY_HALF_CLOSE:
        case RELAY_ACTIVE:
            relay_handle_active(ds, r, ep, ev, now);
            break;

        case RELAY_XHTTP_DN_CONNECT:
        case RELAY_XHTTP_UP_TLS:
        case RELAY_XHTTP_DN_TLS:
        case RELAY_XHTTP_UP_REQ:
        case RELAY_XHTTP_DN_REQ:
        case RELAY_XHTTP_ACTIVE:
            relay_handle_xhttp(ds, r, ep, ev, &events[i], now);
            break;

#if CONFIG_EBURNET_AWG
        case RELAY_AWG_HANDSHAKE:
        case RELAY_AWG_ACTIVE:
            relay_handle_awg(ds, r, ep, ev, now);
            break;
#endif /* CONFIG_EBURNET_AWG */

#if CONFIG_EBURNET_XUDP
        case RELAY_MUXCOOL_HS: {
            if (ep->is_client) break;
            if (!(ev & (EPOLLIN | EPOLLOUT))) break;

            const ServerConfig *srv = (g_config && r->server_idx >= 0)
                ? config_get_server(g_config, r->server_idx) : NULL;
            if (!srv) { relay_free(ds, r); break; }
            if (!r->muxcool_stream || !r->muxcool_stream->conn ||
                !r->muxcool_stream->conn->transport_ctx) {
                relay_free(ds, r); break;
            }

            muxcool_conn_t *mc = r->muxcool_stream->conn;

            /* Phase 1: VLESS+CMD=Mux header — однократно на conn */
            if (!mc->vless_handshake_done) {
                vless_uuid_t uuid;
                if (vless_uuid_parse(srv->uuid, &uuid) < 0) {
                    log_msg(LOG_WARN, "muxcool: bad uuid '%s'", srv->uuid);
                    dispatcher_server_result(ds, r->server_idx, false);
                    relay_free(ds, r); break;
                }
                uint8_t vhdr[32];
                int vlen = vless_build_mux_request(vhdr, sizeof(vhdr), &uuid);
                if (vlen <= 0) { relay_free(ds, r); break; }

                ssize_t wr = mc->transport_send(mc->transport_ctx, vhdr, (size_t)vlen);
                if (wr < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    log_msg(LOG_WARN, "muxcool: VLESS hdr write errno=%d", errno);
                    dispatcher_server_result(ds, r->server_idx, false);
                    relay_free(ds, r); break;
                }
                if ((int)wr != vlen) {
                    log_msg(LOG_WARN,
                            "muxcool: partial VLESS write %zd/%d", wr, vlen);
                    relay_free(ds, r); break;
                }

                /* Phase 2: VLESS response (2 байта + addons), resumable */
                if (r->vless_resp_len < 2) {
                    ssize_t rr = mc->transport_recv(mc->transport_ctx,
                                                    r->vless_resp_buf + r->vless_resp_len,
                                                    2u - r->vless_resp_len);
                    if (rr < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        log_msg(LOG_WARN, "muxcool: VLESS resp read errno=%d", errno);
                        dispatcher_server_result(ds, r->server_idx, false);
                        relay_free(ds, r); break;
                    }
                    r->vless_resp_len += (uint8_t)rr;
                    if (r->vless_resp_len < 2) break;
                }
                /* addons drain */
                uint8_t addons_need = r->vless_resp_buf[1];
                if (addons_need > 0 && r->vless_resp_buf[2] < addons_need) {
                    uint8_t scratch[256];
                    ssize_t rr = mc->transport_recv(mc->transport_ctx, scratch,
                                                    (size_t)(addons_need - r->vless_resp_buf[2]));
                    if (rr < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        relay_free(ds, r); break;
                    }
                    r->vless_resp_buf[2] += (uint8_t)rr;
                    if (r->vless_resp_buf[2] < addons_need) break;
                }
                mc->vless_handshake_done = true;
            }

            /* Phase 3: install watcher → ACTIVE.
             * Watcher MOD'ает conn->tcp_fd (с &r->ep_upstream → watcher tag),
             * ADD'ает wake_fd, переключает r->upstream_fd на wake_fd. */
            if (muxcool_install_conn_watcher(ds, r) < 0) {
                dispatcher_server_result(ds, r->server_idx, false);
                relay_free(ds, r); break;
            }

            dispatcher_server_result(ds, r->server_idx, true);
            r->state = RELAY_MUXCOOL_ACTIVE;
            r->client_sent_first = true;
            log_msg(LOG_INFO,
                    "relay [%s] MUXCOOL_HS→ACTIVE sid=%u",
                    srv->name, r->muxcool_stream->session_id);

            if (r->is_udp_relay) {
                /* UDP relay: создать сессию (relay владеет stream, нет client_fd) */
                udp_session_t *usess = udp_session_create(
                    ds, &r->udp_sess_key, r->muxcool_stream);
                if (usess) {
                    usess->src_addr    = r->src_udp_addr;
                    usess->relay_owned = true;
                } else {
                    log_msg(LOG_WARN, "muxcool: udp_session_create fail");
                }
                break;
            }

            /* Регистрация client_fd (если ещё не) */
            struct epoll_event _cev = {
                .events   = EPOLLIN | EPOLLRDHUP,
                .data.ptr = &r->ep_client,
            };
            if (epoll_ctl(ds->epoll_fd, EPOLL_CTL_ADD,
                          r->client_fd, &_cev) < 0) {
                if (errno != EEXIST)
                    log_msg(LOG_WARN, "muxcool: epoll(client): %s",
                            strerror(errno));
            }
            break;
        }

        case RELAY_MUXCOOL_ACTIVE: {
            if (!r->muxcool_stream || !r->muxcool_stream->conn ||
                !r->muxcool_stream->conn->transport_ctx) {
                relay_free(ds, r); break;
            }
            muxcool_conn_t *mc_a = r->muxcool_stream->conn;

            if (ep->is_client) {
                if (r->is_udp_relay) break; /* нет client_fd у UDP relay */
                if (!(ev & EPOLLIN)) break;
                for (;;) {
                    ssize_t rd = read(r->client_fd, ds->relay_buf,
                                      ds->relay_buf_size);
                    if (rd > 0) {
                        ssize_t sn = muxcool_stream_send(
                            r->muxcool_stream, mc_a->transport_send,
                            mc_a->transport_ctx, ds->relay_buf, (size_t)rd);
                        if (sn < 0) {
                            int sv = errno;
                            if (sv == EAGAIN || sv == EWOULDBLOCK) break;
                            log_msg(LOG_WARN,
                                    "muxcool: send fail errno=%d", sv);
                            relay_free(ds, r);
                            break;
                        }
                        r->bytes_in   += (uint64_t)rd;
                        r->last_active = now;
                        continue;
                    }
                    if (rd == 0) {
                        relay_do_half_close(r, true);
                        break;
                    }
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    relay_free(ds, r);
                    break;
                }
            } else {
                /* upstream wake_fd event → drain eventfd + recv */
                if (!(ev & EPOLLIN)) break;
                {
                    uint64_t v;
                    (void)read(r->upstream_fd, &v, sizeof(v));
                }
                if (r->is_udp_relay) {
                    /* UDP relay: ответные данные → sendmsg клиенту */
                    udp_session_t *udp_sess =
                        udp_session_find(ds, &r->udp_sess_key);
                    for (;;) {
                        ssize_t n = muxcool_stream_recv(
                            r->muxcool_stream,
                            mc_a->transport_send, mc_a->transport_recv,
                            mc_a->transport_ctx,
                            ds->relay_buf, ds->relay_buf_size);
                        if (n > 0) {
                            if (udp_sess)
                                dispatcher_handle_udp_reply(ds, udp_sess,
                                    ds->relay_buf, (size_t)n);
                            r->bytes_out  += (uint64_t)n;
                            r->last_active = now;
                            continue;
                        }
                        if (n == 0) break;
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        relay_free(ds, r);
                        break;
                    }
                    break;
                }
                for (;;) {
                    ssize_t n = muxcool_stream_recv(
                        r->muxcool_stream,
                        mc_a->transport_send, mc_a->transport_recv,
                        mc_a->transport_ctx, ds->relay_buf, ds->relay_buf_size);
                    if (n > 0) {
                        ssize_t wr = write(r->client_fd,
                                           ds->relay_buf, (size_t)n);
                        if (wr < 0) {
                            int sv = errno;
                            if (sv == EAGAIN || sv == EPIPE) break;
                            relay_free(ds, r);
                            break;
                        }
                        r->bytes_out  += (uint64_t)wr;
                        r->last_active = now;
                        continue;
                    }
                    if (n == 0) {
                        relay_do_half_close(r, false);
                        break;
                    }
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    relay_free(ds, r);
                    break;
                }
            }
            break;
        }
#endif /* CONFIG_EBURNET_XUDP */

#if CONFIG_EBURNET_STLS
        case RELAY_STLS_SHAKE:
            /* ShadowTLS handshake — читаем ServerHello + skip HS */
            if (ep->is_client) break;
            if (!(ev & EPOLLIN)) break;
            {
                int hrc = stls_recv_handshake(r->upstream_fd, r->stls);
                if (hrc < 0) {
                    log_msg(LOG_WARN,
                            "relay: ShadowTLS handshake провалился");
                    dispatcher_server_result(ds, r->server_idx, false);
                    relay_free(ds, r);
                    continue;
                }
                if (hrc == 0) break;  /* нужно больше данных */
                /* hrc == 1: handshake завершён → запустить inner protocol */
                const ServerConfig *server = NULL;
                if (g_config && r->server_idx >= 0 &&
                    r->server_idx >= 0)
                    server = config_get_server(g_config, r->server_idx);
                if (server) {
                    /* Для TLS inner protocols: I/O callbacks через STLS */
                    const char *pn = server->protocol;
                    if (r->stls &&
                        (strcmp(pn, "vless") == 0 ||
                         strcmp(pn, "trojan") == 0)) {
                        stls_io_ctx_t *io = calloc(1, sizeof(stls_io_ctx_t));
                        if (!io) { relay_free(ds, r); continue; }
                        io->stls = r->stls;
                        io->fd   = r->upstream_fd;
                        r->stls_io = io;
                    }
                    const proxy_protocol_t *proto =
                        protocol_find_for_server(server);
                    if (proto->start(r, &r->dst, server) < 0) {
                        log_msg(LOG_WARN,
                                "relay: inner proto start провалился");
                        relay_free(ds, r);
                        continue;
                    }
                    /* state установлен proto->start: TLS_SHAKE или ACTIVE */
                } else {
                    r->state = RELAY_ACTIVE;
                }
            }
            break;
#endif

        case RELAY_CLOSING:
            relay_free(ds, r);
            break;

        case RELAY_DONE:
            break;

        default:
            log_msg(LOG_WARN, "relay: неизвестное состояние %d", r->state);
            relay_free(ds, r);
            continue;
        }
    }

    ds->tick_count++;

#ifdef __mips__
    /* Spin-детектор: логируем если dispatcher epoll видит события каждый тик */
    {
        static uint32_t _ds_spin = 0;
        static time_t   _ds_t0   = 0;
        if (n > 0) {
            _ds_spin++;
            time_t _tnow = time(NULL);
            if (_ds_t0 == 0) _ds_t0 = _tnow;
            if (_tnow - _ds_t0 >= 2) {
                relay_ep_t *_ep0 = n > 0 ? events[0].data.ptr : NULL;
                log_msg(LOG_DEBUG,
                        "DSPY: events=%u/2s ev0=0x%x is_client=%d state=%d eof=%d",
                        _ds_spin, n > 0 ? events[0].events : 0,
                        _ep0 && _ep0->relay ? (int)_ep0->is_client : -1,
                        _ep0 && _ep0->relay ? (int)_ep0->relay->state : -1,
                        _ep0 && _ep0->relay ? (int)_ep0->relay->upstream_eof : -1);
                _ds_spin = 0; _ds_t0 = _tnow;
            }
        } else {
            _ds_spin = 0; _ds_t0 = 0;
        }
    }
#endif

    /* Периодическая проверка таймаутов (M-03: ранний выход, M-09: idle) */
    if (ds->tick_count % RELAY_TIMEOUT_CHECK == 0
        && ds->conns_count > 0) {
        /* now уже кэширован в начале tick */
        int checked = 0;
        for (int i = 0; i < ds->conns_max
                        && checked < ds->conns_count; i++) {
            relay_conn_t *r = &ds->conns[i];
            if (r->state == RELAY_DONE)
                continue;
            checked++;

            /* TCP connect timeout: сервер не ответил на SYN за 5с */
            if (r->state == RELAY_CONNECTING &&
                r->connect_deadline > 0 &&
                now > r->connect_deadline) {
                const ServerConfig *_srv = (r->server_idx >= 0 && g_config)
                    ? config_get_server(g_config, r->server_idx) : NULL;
                log_msg(LOG_WARN,
                    "relay connect timeout: %s → %s (5с)",
                    r->domain[0] ? r->domain : "?",
                    _srv ? _srv->name : "?");
                if (relay_try_retry(ds, r) != 0)
                    relay_free(ds, r);
                continue;
            }

            /* Upstream first-byte timeout: если upstream не ответил за 10с после HS */
            if (r->state == RELAY_ACTIVE &&
                r->upstream_first_byte_deadline > 0 &&
                r->bytes_out == 0 &&
                now > r->upstream_first_byte_deadline) {
                const ServerConfig *_srv = (r->server_idx >= 0 && g_config)
                    ? config_get_server(g_config, r->server_idx) : NULL;
                log_msg(LOG_WARN,
                    "relay timeout: нет ответа upstream 10с (up=%lu) domain=%s server=%s",
                    (unsigned long)r->bytes_in,
                    r->domain[0] ? r->domain : "(null)",
                    _srv ? _srv->name : "?");
                if (relay_try_retry(ds, r) != 0)
                    relay_free(ds, r);
                continue;
            }

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
        time_t now_t = now;
        if (now_t >= ds->health_reset_at && ds->health_count > 0) {
            ds->health_reset_at = now_t + TIMEOUT_HEALTH_RESET_SEC;
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

#if CONFIG_EBURNET_GRPC_MULTIPLEX
    if (ds->grpc_pool) grpc_pool_tick(ds->grpc_pool, now);
#endif
#if CONFIG_EBURNET_XUDP
    if (ds->muxcool_pool) muxcool_pool_tick(ds->muxcool_pool, now);
    udp_sessions_cleanup(ds, now);
#endif

    /* Замер длительности тика; обновляем high-watermark */
    struct timespec ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    int64_t elapsed_ns = ((int64_t)ts_end.tv_sec  - (int64_t)ts_start.tv_sec)  * 1000000000LL
                       + ((int64_t)ts_end.tv_nsec - (int64_t)ts_start.tv_nsec);
    uint32_t elapsed_us = (elapsed_ns > 0) ? (uint32_t)(elapsed_ns / 1000LL) : 0u;
    uint32_t prev = atomic_load_explicit(&g_dispatcher_tick_us, memory_order_relaxed);
    while (elapsed_us > prev &&
           !atomic_compare_exchange_weak_explicit(&g_dispatcher_tick_us, &prev, elapsed_us,
                                                  memory_order_relaxed, memory_order_relaxed))
        ;
    if (elapsed_us > 100000u)
        log_msg(LOG_WARN, "dispatcher_tick: %u мкс > порог 100 мс", elapsed_us);
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
#if CONFIG_EBURNET_STLS
    if (ds->stls_buf) {
        free(ds->stls_buf);
        ds->stls_buf = NULL;
    }
#endif

#if CONFIG_EBURNET_GRPC_MULTIPLEX
    if (ds->grpc_pool) { grpc_pool_free(ds->grpc_pool); ds->grpc_pool = NULL; }
#endif
#if CONFIG_EBURNET_XUDP
    if (ds->muxcool_pool) { muxcool_pool_free(ds->muxcool_pool); ds->muxcool_pool = NULL; }
    udp_sessions_cleanup(ds, (time_t)INT64_MAX);
    if (ds->udp_reply_fd >= 0) { close(ds->udp_reply_fd); ds->udp_reply_fd = -1; }
#endif

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

#if CONFIG_EBURNET_SNIFFER
const char *dispatcher_get_last_ja3(void) { return g_last_ja3; }
#else
const char *dispatcher_get_last_ja3(void) { return ""; }
#endif

uint32_t dispatcher_get_ech_connections(void)
{
    return (uint32_t)atomic_load_explicit(&g_stats.ech_connections,
                                          memory_order_relaxed);
}

uint16_t dispatcher_get_last_ech_type(void)
{
    return (uint16_t)atomic_load_explicit(&g_stats.last_ech_type,
                                          memory_order_relaxed);
}

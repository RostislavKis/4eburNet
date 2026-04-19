#include "ipc.h"
#include "config.h"
#include "constants.h"
#include "stats.h"
#include "net_utils.h"
#include "routing/nftables.h"
#include "proxy/dispatcher.h"
#include "http_server.h"
#if CONFIG_EBURNET_DPI
#include "dpi/dpi_adapt.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <errno.h>
#include <time.h>
#include <poll.h>

/* Размер буфера для ответов (достаточно для 200+ серверов/групп) */
#define IPC_RESPONSE_MAX 65536

/* Максимум одновременных IPC клиентов */
#define IPC_MAX_CLIENTS 8

/* ── State machine ─────────────────────────────────────────────────── */

typedef enum {
    IPC_CS_FREE         = 0,
    IPC_CS_READING_HDR  = 1,
    IPC_CS_READING_BODY = 2,
    IPC_CS_WRITING      = 3,
} ipc_cs_t;

typedef struct {
    int           fd;
    ipc_cs_t      state;
    /* чтение заголовка */
    uint8_t       hdr_buf[sizeof(ipc_header_t)];
    size_t        hdr_read;
    ipc_header_t  hdr;
    /* чтение payload (опциональный) */
    char         *payload;
    size_t        payload_read;
    /* ответ — inline буфер без malloc в hot path */
    ipc_header_t  resp_hdr;
    char          resp_body[IPC_RESPONSE_MAX];
    size_t        resp_body_len;
    size_t        resp_sent;
} ipc_client_t;

static ipc_client_t g_clients[IPC_MAX_CLIENTS];
static int          g_epoll_fd = -1;

static ipc_client_t *ipc_client_alloc(int fd)
{
    for (int i = 0; i < IPC_MAX_CLIENTS; i++) {
        if (g_clients[i].state == IPC_CS_FREE) {
            memset(&g_clients[i], 0, sizeof(g_clients[i]));
            g_clients[i].fd    = fd;
            g_clients[i].state = IPC_CS_READING_HDR;
            return &g_clients[i];
        }
    }
    return NULL;
}

static void ipc_client_free(ipc_client_t *c)
{
    if (c->payload) { free(c->payload); c->payload = NULL; }
    if (c->fd >= 0) { close(c->fd);     c->fd      = -1;  }
    c->state = IPC_CS_FREE;
}

bool ipc_is_client_ptr(const void *ptr)
{
    return ptr >= (const void *)&g_clients[0] &&
           ptr <  (const void *)&g_clients[IPC_MAX_CLIENTS];
}

/* Заполнить resp_body уже записанным содержимым (snprintf прямо в resp_body),
 * либо скопировать из внешней строки — и перейти в состояние WRITING. */
static void ipc_set_response(ipc_client_t *c, const char *json)
{
    size_t len = strlen(json);
    if (len >= sizeof(c->resp_body))
        len = sizeof(c->resp_body) - 1;
    if (json != c->resp_body)
        memcpy(c->resp_body, json, len);
    c->resp_body[len]  = '\0';
    c->resp_body_len   = len;
    c->resp_hdr = (ipc_header_t){
        .version    = EBURNET_IPC_VERSION,
        .command    = 0,
        .length     = (uint16_t)(len > UINT16_MAX ? UINT16_MAX : len),
        .request_id = 0,
    };
    c->resp_sent = 0;
    c->state     = IPC_CS_WRITING;
}

/* Контекст для команд proxy_group/rule_provider/rules_engine/geo */
static proxy_group_manager_t    *g_pgm = NULL;
static rule_provider_manager_t  *g_rpm = NULL;
static rules_engine_t           *g_re  = NULL;
static geo_manager_t            *g_gm  = NULL;

void ipc_set_3x_context(proxy_group_manager_t *pgm,
                        rule_provider_manager_t *rpm,
                        rules_engine_t *re,
                        geo_manager_t *gm)
{
    g_pgm = pgm;
    g_rpm = rpm;
    g_re  = re;
    g_gm  = gm;
}

/* Backlog для listen() — количество ожидающих подключений */
#define IPC_LISTEN_BACKLOG 8

int ipc_init(void)
{
    /* Удаляем старый сокет, если остался */
    unlink(EBURNET_IPC_SOCKET);

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_msg(LOG_ERROR, "Не удалось создать Unix-сокет");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, EBURNET_IPC_SOCKET, sizeof(addr.sun_path) - 1);

    /* M-11: umask вместо chmod — избежать TOCTOU */
    mode_t old_umask = umask(0177);
    int bind_rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    umask(old_umask);

    if (bind_rc < 0) {
        log_msg(LOG_ERROR, "Не удалось привязать сокет: %s", EBURNET_IPC_SOCKET);
        close(fd);
        return -1;
    }

    /* Defense-in-depth: явный chmod 600 после bind */
    if (chmod(EBURNET_IPC_SOCKET, 0600) < 0)
        log_msg(LOG_WARN, "IPC: chmod 600 не удался: %s", strerror(errno));

    if (listen(fd, IPC_LISTEN_BACKLOG) < 0) {
        log_msg(LOG_ERROR, "listen() не удался");
        close(fd);
        unlink(EBURNET_IPC_SOCKET);
        return -1;
    }

    /* Неблокирующий режим (M-18: проверка F_GETFL) */
    int flags = fcntl(fd, F_GETFL);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    log_msg(LOG_INFO, "IPC сокет создан: %s", EBURNET_IPC_SOCKET);
    return fd;
}

/* Извлечь строковое поле из JSON: {"key":"value"}.
 * Обрабатывает escaped кавычки \".
 * Возвращает длину скопированного значения, 0 если не найдено. */
static size_t json_get_str(const char *json, const char *key,
                           char *out, size_t out_size)
{
    if (!json || !key || !out || out_size == 0) return 0;
    out[0] = '\0';

    /* Построить шаблон: "key":" */
    char pattern[80];
    int pn = snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    if (pn < 0 || (size_t)pn >= sizeof(pattern)) return 0;

    const char *start = strstr(json, pattern);
    if (!start) return 0;
    start += (size_t)pn;

    /* Копировать до закрывающей " с учётом \" */
    size_t i = 0;
    for (const char *p = start; *p && i < out_size - 1; p++) {
        if (*p == '\\' && *(p + 1)) {
            p++;  /* пропустить escape, скопировать следующий символ */
            out[i++] = *p;
        } else if (*p == '"') {
            break;
        } else {
            out[i++] = *p;
        }
    }
    out[i] = '\0';
    return i;
}

/*
 * ipc_dispatch — обработать команду, уже прочитанную state machine.
 * Пишет ответ в c->resp_body и переводит c->state в IPC_CS_WRITING.
 */
static void ipc_dispatch(ipc_client_t *c, EburNetState *state)
{
    /* buf указывает прямо в inline буфер — нет malloc */
    char *buf = c->resp_body;

    switch ((ipc_command_t)c->hdr.command) {
    case IPC_CMD_STATUS: {
        time_t uptime = time(NULL) - state->start_time;
        const char *profile = "unknown";
        switch (state->profile) {
        case DEVICE_MICRO:  profile = "MICRO";  break;
        case DEVICE_NORMAL: profile = "NORMAL"; break;
        case DEVICE_FULL:   profile = "FULL";   break;
        }
        /* B5-01: geo_loaded + mode в статусе */
        bool geo_ok = false;
        if (g_gm) {
            for (int gi = 0; gi < g_gm->count; gi++)
                if (g_gm->categories[gi].loaded) { geo_ok = true; break; }
        }
        const char *mode = (state->config && state->config->mode[0])
                           ? state->config->mode : "unknown";
        bool flow_ok = nft_flow_offload_is_active();
#if CONFIG_EBURNET_DPI
        uint32_t adapt_count = 0, adapt_hits = 0;
        dpi_adapt_stats(&g_dpi_adapt, &adapt_count, &adapt_hits);
#endif
        snprintf(buf, IPC_RESPONSE_MAX,
                 "{\"status\":\"running\",\"version\":\"%s\","
                 "\"profile\":\"%s\",\"uptime\":%ld,"
                 "\"mode\":\"%s\",\"geo_loaded\":%s,"
                 "\"flow_offload\":%s,"
                 "\"last_ja3\":\"%s\","
                 "\"ja3_expected\":\"%s\""
#if CONFIG_EBURNET_DPI
                 ",\"dpi_adapt_count\":%u"
                 ",\"dpi_adapt_hits\":%u"
#endif
                 "}",
                 EBURNET_VERSION, profile, (long)uptime,
                 mode, geo_ok ? "true" : "false",
                 flow_ok ? "true" : "false",
                 dispatcher_get_last_ja3(),
                 http_server_get_ja3_expected()
#if CONFIG_EBURNET_DPI
                 , adapt_count, adapt_hits
#endif
                 );
        ipc_set_response(c, buf);
        break;
    }

    case IPC_CMD_RELOAD:
        state->reload = true;
        ipc_set_response(c, "{\"status\":\"ok\"}");
        log_msg(LOG_INFO, "IPC: запрошена перезагрузка конфига");
        break;

    case IPC_CMD_STOP:
        state->running = false;
        ipc_set_response(c, "{\"status\":\"stopping\"}");
        log_msg(LOG_INFO, "IPC: запрошена остановка");
        break;

    case IPC_CMD_STATS:
        snprintf(buf, IPC_RESPONSE_MAX,
                 "{\"connections_total\":%llu"
                 ",\"connections_active\":%llu"
                 ",\"dns_queries\":%llu"
                 ",\"dns_cached\":%llu"
                 ",\"blocked_ads\":%llu"
                 ",\"blocked_trackers\":%llu"
                 ",\"blocked_threats\":%llu}",
                 (unsigned long long)atomic_load(&g_stats.connections_total),
                 (unsigned long long)atomic_load(&g_stats.connections_active),
                 (unsigned long long)atomic_load(&g_stats.dns_queries_total),
                 (unsigned long long)atomic_load(&g_stats.dns_cached_total),
                 (unsigned long long)atomic_load(&g_stats.blocked_ads),
                 (unsigned long long)atomic_load(&g_stats.blocked_trackers),
                 (unsigned long long)atomic_load(&g_stats.blocked_threats));
        ipc_set_response(c, buf);
        break;

    case IPC_CMD_GROUP_LIST:
        if (g_pgm) {
            /* Пишем прямо в c->resp_body — нет отдельного malloc */
            proxy_group_to_json(g_pgm, buf, IPC_RESPONSE_MAX);
            ipc_set_response(c, buf);
        } else {
            ipc_set_response(c, "{\"groups\":[]}");
        }
        break;

    case IPC_CMD_GROUP_SELECT: {
        /* payload уже прочитан state machine в c->payload */
        const char *payload = c->payload ? c->payload : "";
        char grp[64] = {0}, srv[64] = {0};
        json_get_str(payload, "group",  grp, sizeof(grp));
        json_get_str(payload, "server", srv, sizeof(srv));
        if (grp[0] && srv[0] && g_pgm) {
            int srv_idx = -1;
            for (int si = 0; si < g_pgm->cfg->server_count; si++) {
                if (strcmp(g_pgm->cfg->servers[si].name, srv) == 0) {
                    srv_idx = si;
                    break;
                }
            }
            int r = (srv_idx >= 0)
                    ? proxy_group_select_manual(g_pgm, grp, srv_idx)
                    : -1;
            ipc_set_response(c, r == 0
                ? "{\"status\":\"ok\"}"
                : "{\"status\":\"error\",\"msg\":\"group or server not found\"}");
        } else if (!g_pgm) {
            ipc_set_response(c, "{\"status\":\"error\",\"msg\":\"no groups\"}");
        } else {
            ipc_set_response(c,
                "{\"status\":\"error\",\"msg\":\"missing group or server\"}");
        }
        break;
    }

    case IPC_CMD_GROUP_TEST:
        if (g_pgm) {
            proxy_group_tick(g_pgm);
            ipc_set_response(c, "{\"status\":\"ok\"}");
        } else {
            ipc_set_response(c, "{\"error\":\"no groups\"}");
        }
        break;

    case IPC_CMD_PROVIDER_LIST:
        if (g_rpm) {
            rule_provider_to_json(g_rpm, buf, IPC_RESPONSE_MAX);
            ipc_set_response(c, buf);
        } else {
            ipc_set_response(c, "{\"providers\":[]}");
        }
        break;

    case IPC_CMD_PROVIDER_UPDATE: {
        /* payload уже прочитан state machine в c->payload */
        const char *payload = c->payload ? c->payload : "";
        char pname[64] = {0};
        json_get_str(payload, "name", pname, sizeof(pname));
        if (pname[0] && g_rpm) {
            int r = rule_provider_update(g_rpm, pname);
            ipc_set_response(c, r == 0
                ? "{\"status\":\"ok\"}"
                : "{\"status\":\"error\",\"msg\":\"provider not found\"}");
        } else if (!g_rpm) {
            ipc_set_response(c,
                "{\"status\":\"error\",\"msg\":\"no providers\"}");
        } else {
            ipc_set_response(c,
                "{\"status\":\"error\",\"msg\":\"missing name\"}");
        }
        break;
    }

    case IPC_CMD_RULES_LIST:
        if (g_re && g_re->sorted_rules) {
            /* Пишем прямо в c->resp_body (= buf) */
            size_t pos = 0;
            size_t need = IPC_RESPONSE_MAX;
            int w;
#define IPC_SNPRINTF(fmt, ...) do { \
    w = snprintf(buf + pos, need - pos, fmt, ##__VA_ARGS__); \
    if (w < 0 || (size_t)w >= need - pos) goto rules_trunc; \
    pos += (size_t)w; \
} while(0)
            IPC_SNPRINTF("{\"rules\":[");
            for (int ri = 0; ri < g_re->rule_count; ri++) {
                const TrafficRule *tr = &g_re->sorted_rules[ri];
                static char esc_val[512], esc_tgt[128];
                memset(esc_val, 0, sizeof(esc_val));
                memset(esc_tgt, 0, sizeof(esc_tgt));
                json_escape_str(tr->value,  esc_val, sizeof(esc_val));
                json_escape_str(tr->target, esc_tgt, sizeof(esc_tgt));
                if (ri > 0) IPC_SNPRINTF(",");
                IPC_SNPRINTF("{\"type\":%d,\"value\":\"%s\","
                    "\"target\":\"%s\",\"priority\":%d}",
                    tr->type, esc_val, esc_tgt, tr->priority);
            }
            IPC_SNPRINTF("]}");
            goto rules_send;
rules_trunc:
            /* B6-01: при truncation — валидный JSON */
            log_msg(LOG_WARN, "ipc: rules list truncated");
            pos = 0;
            snprintf(buf, need, "{\"rules\":[],\"truncated\":true}");
            pos = strlen(buf);
rules_send:
#undef IPC_SNPRINTF
            if (pos < need) buf[pos] = '\0';
            ipc_set_response(c, buf);
        } else {
            ipc_set_response(c, "{\"rules\":[]}");
        }
        break;

    case IPC_CMD_GEO_STATUS:
        if (g_gm) {
            size_t p = 0;
            p += (size_t)snprintf(buf + p, IPC_RESPONSE_MAX - p,
                "{\"region\":\"%s\",\"categories\":[",
                geo_region_name(g_gm->current_region));
            /* B6-02: резерв 4 байта под "]}\0" */
            const size_t geo_reserve = 4;
            for (int gi = 0; gi < g_gm->count &&
                 p < IPC_RESPONSE_MAX - 128 - geo_reserve; gi++) {
                const geo_category_t *gc = &g_gm->categories[gi];
                if (gi > 0)
                    p += (size_t)snprintf(buf + p, IPC_RESPONSE_MAX - p, ",");
                p += (size_t)snprintf(buf + p, IPC_RESPONSE_MAX - p,
                    "{\"name\":\"%s\",\"region\":\"%s\","
                    "\"loaded\":%s,\"v4\":%d,\"v6\":%d,"
                    "\"domains\":%d,\"suffixes\":%d}",
                    gc->name, geo_region_name(gc->region),
                    gc->loaded ? "true" : "false",
                    gc->v4_count, gc->v6_count,
                    gc->domain_count, gc->suffix_count);
            }
            if (p >= IPC_RESPONSE_MAX - geo_reserve)
                p = IPC_RESPONSE_MAX - geo_reserve;
            p += (size_t)snprintf(buf + p, IPC_RESPONSE_MAX - p, "]}");
            ipc_set_response(c, buf);
        } else {
            ipc_set_response(c,
                "{\"region\":\"UNKNOWN\",\"categories\":[]}");
        }
        break;

#if CONFIG_EBURNET_DPI
    case IPC_CMD_CDN_UPDATE:
        state->cdn_update_requested = true;
        ipc_set_response(c,
            "{\"status\":\"ok\",\"msg\":\"cdn update scheduled\"}");
        log_msg(LOG_INFO, "IPC: запрошено обновление CDN IP");
        break;

    case IPC_CMD_DPI_GET: {
        /* P6-01: вернуть текущие DPI настройки */
        const EburNetConfig *cfg = state->config;
        if (!cfg) {
            ipc_set_response(c, "{\"error\":\"config not ready\"}");
            break;
        }
        static char esc_sni[512];
        memset(esc_sni, 0, sizeof(esc_sni));
        json_escape_str(cfg->dpi_fake_sni, esc_sni, sizeof(esc_sni));
        snprintf(buf, IPC_RESPONSE_MAX,
            "{\"enabled\":%s,\"split_pos\":%d,\"fake_ttl\":%d,"
            "\"fake_count\":%d,\"fake_sni\":\"%s\"}",
            cfg->dpi_enabled ? "true" : "false",
            cfg->dpi_split_pos, cfg->dpi_fake_ttl,
            cfg->dpi_fake_repeats, esc_sni);
        ipc_set_response(c, buf);
        break;
    }

    case IPC_CMD_DPI_SET: {
        /* payload: {"enabled":"true","split_pos":"2","fake_ttl":"5",...} */
        const char *payload = (c->payload && c->payload[0]) ? c->payload : "{}";
        EburNetConfig *cfg = (EburNetConfig *)state->config;
        if (cfg) {
            char val[64] = {0};
            if (json_get_str(payload, "enabled", val, sizeof(val)))
                cfg->dpi_enabled = (strcmp(val, "true") == 0 ||
                                    strcmp(val, "1") == 0);
            if (json_get_str(payload, "split_pos", val, sizeof(val))) {
                int v = atoi(val);
                if (v > 0 && v < 1400) cfg->dpi_split_pos = v;
            }
            if (json_get_str(payload, "fake_ttl", val, sizeof(val))) {
                int v = atoi(val);
                if (v > 0 && v <= 64) cfg->dpi_fake_ttl = v;
            }
            if (json_get_str(payload, "fake_count", val, sizeof(val))) {
                int v = atoi(val);
                if (v > 0 && v <= 20) cfg->dpi_fake_repeats = v;
            }
            if (json_get_str(payload, "fake_sni", val, sizeof(val))) {
                int _n = snprintf(cfg->dpi_fake_sni,
                                   sizeof(cfg->dpi_fake_sni), "%s", val);
                (void)_n;
            }
        }
        /* Сохранить кэш адаптации при изменении DPI настроек */
        dpi_adapt_save(&g_dpi_adapt, "/etc/4eburnet/dpi_cache.bin");
        ipc_set_response(c, "{\"status\":\"ok\"}");
        log_msg(LOG_INFO, "IPC: DPI настройки обновлены");
        break;
    }
#endif

    default:
        log_msg(LOG_WARN, "IPC: неизвестная команда %u", c->hdr.command);
        ipc_set_response(c, "{\"error\":\"unknown command\"}");
        break;
    }
}

/* ── ipc_accept ────────────────────────────────────────────────────── */

void ipc_accept(int server_fd, EburNetState *state, int epoll_fd)
{
    (void)state;
    g_epoll_fd = epoll_fd;

    int cfd = accept4(server_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (cfd < 0) return;

    /* Fail-secure: только root */
    struct ucred cr;
    socklen_t cl = sizeof(cr);
    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) < 0 ||
        cr.uid != 0) {
        log_msg(LOG_WARN, "IPC: отклонён non-root или SO_PEERCRED fail");
        close(cfd);
        return;
    }

    ipc_client_t *c = ipc_client_alloc(cfd);
    if (!c) {
        log_msg(LOG_WARN, "IPC: все %d слота заняты", IPC_MAX_CLIENTS);
        close(cfd);
        return;
    }

    struct epoll_event ev = {
        .events   = EPOLLIN | EPOLLET | EPOLLRDHUP,
        .data.ptr = c,
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cfd, &ev) < 0)
        ipc_client_free(c);
}

/* ── ipc_try_write ───────────────────────────────────────────────── */
/* Попытка записи ответа. Вызывается:
 *   1. Сразу после ipc_dispatch (не ждать EPOLLOUT)
 *   2. При EPOLLOUT событии в state machine
 * Возвращает: 0 = продолжить, -1 = закрыть */
static int ipc_try_write(ipc_client_t *c)
{
    size_t total = sizeof(ipc_header_t) + c->resp_body_len;
    for (;;) {
        if (c->resp_sent >= total) break;
        struct iovec iov[2];
        int niov = 0;
        if (c->resp_sent < sizeof(ipc_header_t)) {
            iov[niov].iov_base =
                (char *)&c->resp_hdr + c->resp_sent;
            iov[niov].iov_len  =
                sizeof(ipc_header_t) - c->resp_sent;
            niov++;
        }
        size_t bd = c->resp_sent > sizeof(ipc_header_t)
                    ? c->resp_sent - sizeof(ipc_header_t) : 0;
        if (bd < c->resp_body_len) {
            iov[niov].iov_base = c->resp_body + bd;
            iov[niov].iov_len  = c->resp_body_len - bd;
            niov++;
        }
        if (niov == 0) break;
        ssize_t r = writev(c->fd, iov, niov);
        if (r < 0) {
            if (errno == EAGAIN) {
                /* Добавить EPOLLOUT: снимется автоматически при EPOLL_CTL_DEL */
                struct epoll_event _ev = {
                    .events   = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP,
                    .data.ptr = c,
                };
                epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, c->fd, &_ev);
                return 0;
            }
            return -1;
        }
        c->resp_sent += (size_t)r;
    }
    if (c->resp_sent >= total) {
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, c->fd, NULL);
        ipc_client_free(c);
    }
    return 0;
}

/* ── ipc_client_event: state machine ──────────────────────────────── */

int ipc_client_event(void *ptr, uint32_t events, EburNetState *state)
{
    ipc_client_t *c = (ipc_client_t *)ptr;

    if (events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR))
        goto close_client;

    /* ── READING_HDR ─────────────────────────────────────────────── */
    if (c->state == IPC_CS_READING_HDR && (events & EPOLLIN)) {
        for (;;) {
            ssize_t n = recv(c->fd,
                             c->hdr_buf + c->hdr_read,
                             sizeof(ipc_header_t) - c->hdr_read,
                             MSG_DONTWAIT);
            if (n < 0) { if (errno == EAGAIN) break; goto close_client; }
            if (n == 0) goto close_client;
            c->hdr_read += (size_t)n;
            if (c->hdr_read == sizeof(ipc_header_t)) break;
        }
        if (c->hdr_read == sizeof(ipc_header_t)) {
            memcpy(&c->hdr, c->hdr_buf, sizeof(ipc_header_t));
            if (c->hdr.version != EBURNET_IPC_VERSION) {
                /* Неверная версия — отправить ошибку и закрыть */
                ipc_set_response(c, "{\"error\":\"version mismatch\"}");
            } else if (c->hdr.length > 0) {
                /* uint16_t гарантирует length <= 65535 < IPC_RESPONSE_MAX */
                c->payload = malloc((size_t)c->hdr.length + 1);
                if (!c->payload) {
                    ipc_set_response(c, "{\"error\":\"OOM\"}");
                } else {
                    c->state = IPC_CS_READING_BODY;
                }
            } else {
                ipc_dispatch(c, state);
                if (c->state == IPC_CS_WRITING)
                    if (ipc_try_write(c) < 0) return -1;
            }
        }
    }

    /* ── READING_BODY ─────────────────────────────────────────────── */
    if (c->state == IPC_CS_READING_BODY && (events & EPOLLIN)) {
        for (;;) {
            ssize_t n = recv(c->fd,
                             c->payload + c->payload_read,
                             c->hdr.length - c->payload_read,
                             MSG_DONTWAIT);
            if (n < 0) { if (errno == EAGAIN) break; goto close_client; }
            if (n == 0) goto close_client;
            c->payload_read += (size_t)n;
            if (c->payload_read == c->hdr.length) break;
        }
        if (c->payload_read == c->hdr.length) {
            c->payload[c->hdr.length] = '\0';
            ipc_dispatch(c, state);
            if (c->state == IPC_CS_WRITING)
                if (ipc_try_write(c) < 0) return -1;
        }
    }

    /* ── WRITING — writev header+body за 1 syscall ────────────────── */
    if (c->state == IPC_CS_WRITING && (events & EPOLLOUT))
        return ipc_try_write(c);
    return 0;

close_client:
    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, c->fd, NULL);
    ipc_client_free(c);
    return -1;
}

void ipc_cleanup(int server_fd)
{
    if (server_fd >= 0) {
        close(server_fd);
        unlink(EBURNET_IPC_SOCKET);
        log_msg(LOG_INFO, "IPC сокет закрыт");
    }
}

/* Подключиться к Unix-сокету с таймаутом через O_NONBLOCK + poll.
   SO_*TIMEO не влияет на connect() для AF_UNIX — используем poll.
   Возвращает готовый блокирующий fd или -1. */
static int ipc_connect_nonblock(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd); return -1;
    }
    if (rc != 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int pr = poll(&pfd, 1, 3000);
        if (pr <= 0) { close(fd); return -1; }
        int err = 0; socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err != 0) { close(fd); return -1; }
    }

    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    struct timeval tv = { .tv_sec = TIMEOUT_IPC_CLIENT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}

int ipc_send_command(ipc_command_t cmd, char *buf, size_t buf_size)
{
    int fd = ipc_connect_nonblock(EBURNET_IPC_SOCKET);
    if (fd < 0)
        return -1;

    /* Отправляем запрос */
    ipc_header_t hdr = {
        .version    = EBURNET_IPC_VERSION,
        .command    = (uint8_t)cmd,
        .length     = 0,
        .request_id = 1,
    };
    if (write(fd, &hdr, sizeof(hdr)) < 0) {
        close(fd);
        return -1;
    }

    /* Читаем ответ: заголовок + тело */
    ipc_header_t resp;
    ssize_t rn = read(fd, &resp, sizeof(resp));
    if (rn != sizeof(resp)) {
        close(fd);
        return -1;
    }

    if (resp.length > 0) {
        /* Читаем не больше чем buf_size - 1 (M-10) */
        size_t to_read = resp.length;
        if (to_read >= buf_size)
            to_read = buf_size - 1;
        rn = read(fd, buf, to_read);
        if (rn > 0)
            buf[rn] = '\0';
        else
            buf[0] = '\0';
    } else {
        buf[0] = '\0';
    }

    close(fd);
    return 0;
}

int ipc_send_command_payload(ipc_command_t cmd,
                              const char *payload,
                              char *buf, size_t buf_size)
{
    int fd = ipc_connect_nonblock(EBURNET_IPC_SOCKET);
    if (fd < 0) return -1;

    uint16_t plen = 0;
    if (payload) {
        size_t pl = strlen(payload);
        if (pl > UINT16_MAX) pl = UINT16_MAX;
        plen = (uint16_t)pl;
    }

    ipc_header_t hdr = {
        .version    = EBURNET_IPC_VERSION,
        .command    = (uint8_t)cmd,
        .length     = plen,
        .request_id = 1,
    };
    if (write(fd, &hdr, sizeof(hdr)) < 0) { close(fd); return -1; }
    if (plen > 0 && write(fd, payload, plen) < 0) { close(fd); return -1; }

    ipc_header_t resp;
    ssize_t rn = read(fd, &resp, sizeof(resp));
    if (rn != (ssize_t)sizeof(resp)) { close(fd); return -1; }

    if (resp.length > 0) {
        size_t to_read = resp.length;
        if (to_read >= buf_size) to_read = buf_size - 1;
        rn = read(fd, buf, to_read);
        if (rn > 0) buf[rn] = '\0';
        else         buf[0] = '\0';
    } else {
        buf[0] = '\0';
    }

    close(fd);
    return 0;
}

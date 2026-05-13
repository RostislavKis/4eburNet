#include "http_server.h"
#include "ws.h"
#include "logo_png.h"
#include "4eburnet.h"
#include "config.h"
#include "net_utils.h"
#include "stats.h"
#include "routing/nftables.h"
#include "routing/tc_fast.h"
#include "routing/device_policy.h"
#if CONFIG_EBURNET_DPI
#include "dpi/dpi_adapt.h"
#include "dpi/cdn_updater.h"
#endif
#include "proxy/dispatcher.h"
#include "proxy/rules_engine.h"
#include "proxy/hc_vless.h"
#include "sub_parser/clash_yaml.h"

#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <poll.h>
#include <sys/wait.h>
#include <netdb.h>
#include <pty.h>
#include <termios.h>
#include <sys/ioctl.h>
#include "ipc.h"

/* ── Валидация MD5-хэша: ровно 32 hex-символа ────────────────────── */
static int is_md5_hex(const char *s, size_t n)
{
    if (n != 32) return 0;
    for (size_t i = 0; i < 32; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

/* ── Forward declarations ─────────────────────────────────────────── */
static void conn_close(HttpConn *conn, int epoll_fd);
static void http_dispatch(HttpConn *conn, int epoll_fd);
static void route_api_status(HttpConn *conn, int epoll_fd);
static void route_ipc_passthrough(HttpConn *conn, int epoll_fd, const char *cmd);
static void route_api_servers(HttpConn *conn, int epoll_fd);
static void route_api_dns(HttpConn *conn, int epoll_fd);
static void route_api_control(HttpConn *conn, int epoll_fd, const char *api_token);
static void route_api_geo(HttpConn *conn, int epoll_fd);
static void route_api_groups(HttpConn *conn, int epoll_fd);
static void route_api_logs(HttpConn *conn, int epoll_fd);
static void route_api_devices(HttpConn *conn, int epoll_fd);
static void route_api_backup(HttpConn *conn, int epoll_fd);
static void route_api_restore(HttpConn *conn, int epoll_fd);
static void route_api_dns_upstream_get(HttpConn *conn, int epoll_fd);
static void route_api_dns_upstream_patch(HttpConn *conn, int epoll_fd);
static void route_api_dns_upstream_test(HttpConn *conn, int epoll_fd);
static void route_api_dns_patch(HttpConn *conn, int epoll_fd);
static void route_api_dns_cache_flush(HttpConn *conn, int epoll_fd);
static void route_api_dns_fakeip_flush(HttpConn *conn, int epoll_fd);
static void route_api_dns_query(HttpConn *conn, int epoll_fd);
static void route_api_dns_test_upstream(HttpConn *conn, int epoll_fd);
static void route_api_dns_stats(HttpConn *conn, int epoll_fd);
static void route_api_dpi_get(HttpConn *conn, int epoll_fd);
static void route_api_dpi_patch(HttpConn *conn, int epoll_fd);
static void route_api_sniffer_get(HttpConn *conn, int epoll_fd);
static void route_api_sniffer_patch(HttpConn *conn, int epoll_fd);
static void route_api_sniffer_stats(HttpConn *conn, int epoll_fd);
static void route_api_dns_policies_get(HttpConn *conn, int epoll_fd);
static void route_api_dns_policies_post(HttpConn *conn, int epoll_fd);
static void route_api_dns_policies_delete(HttpConn *conn, int epoll_fd, const char *id_str);
static void route_api_dns_policies_reorder(HttpConn *conn, int epoll_fd);
static void route_api_network_get(HttpConn *conn, int epoll_fd);
static void route_api_network_patch(HttpConn *conn, int epoll_fd);
static void route_api_cdn_get(HttpConn *conn, int epoll_fd);
static void route_api_cdn_patch(HttpConn *conn, int epoll_fd);
static void route_api_logs_download(HttpConn *conn, int epoll_fd);
static void route_api_geo_update(HttpConn *conn, int epoll_fd);
static void route_api_servers_post(HttpConn *conn, int epoll_fd);
static void route_api_servers_put(HttpConn *conn, int epoll_fd, const char *name);
static void route_api_servers_delete(HttpConn *conn, int epoll_fd, const char *name);
static void route_api_subscribe_parse(HttpConn *conn, int epoll_fd);
static void route_api_subscribe_import(HttpConn *conn, int epoll_fd);
static void route_api_rules_post(HttpConn *conn, int epoll_fd);
static void route_api_rules_patch(HttpConn *conn, int epoll_fd, const char *sec_id);
static void route_api_rules_delete(HttpConn *conn, int epoll_fd, const char *sec_id);
static void route_api_rules_test(HttpConn *conn, int epoll_fd);
static void route_api_providers_proxies_post(HttpConn *conn, int epoll_fd);
static void route_api_providers_proxies_patch(HttpConn *conn, int epoll_fd, const char *name);
static void route_api_providers_proxies_delete(HttpConn *conn, int epoll_fd, const char *name);
static void route_api_providers_rules_post(HttpConn *conn, int epoll_fd);
static void route_api_providers_rules_patch(HttpConn *conn, int epoll_fd, const char *name);
static void route_api_providers_rules_delete(HttpConn *conn, int epoll_fd, const char *name);
static void route_api_devices_patch(HttpConn *conn, int epoll_fd, const char *mac);
static void route_api_groups_patch(HttpConn *conn, int epoll_fd, const char *name);
static void reload_daemon(void); /* forward — определена ниже route_api_restore */

/* ── Буферы для ответов — статические, не в стеке ────────────────── */
static char s_ipc_buf[4096];
static char s_logs_buf[8192];
/* WS payload буфер: вынесен из ws_handle_connection во избежание function-local static */
static char s_ws_payload[4096];

/* ── Токен /api/control, инициализируется в http_server_init ─────── */
static char s_api_token[64];
/* Флаг готовности гео-баз — обновляется из main.c после geo_manager_init */
static bool s_geo_loaded = false;
/* Указатель на geo_manager для route_api_geo (прямой доступ, без IPC) */
static const geo_manager_t *s_geo = NULL;

/* ── WS /logs: кольцевой буфер последних 100 строк лога ─────────── */
#define LOG_RING_SIZE 500
#define LOG_LINE_MAX  256
static char s_log_ring[LOG_RING_SIZE][LOG_LINE_MAX];  /* BSS ~128KB */
static int  s_log_ring_head  = 0;   /* следующая позиция записи */
static int  s_log_ring_count = 0;   /* всего записано (насыщается на LOG_RING_SIZE) */

/* ── WS /ws/events: кольцевой буфер последних 10 событий ─────────── */
#define EVENTS_RING_COUNT 10
#define EVENTS_ENTRY_MAX  256
static char s_events_ring[EVENTS_RING_COUNT][EVENTS_ENTRY_MAX];
static int  s_events_ring_head  = 0;
static int  s_events_ring_count = 0;

/* Указатели на HttpServer и epoll_fd для хука из log_msg */
static HttpServer *s_ws_srv      = NULL;
static int         s_ws_epoll_fd = -1;

/* ── SSH pty bridge state ──────────────────────────────────────────── */
typedef struct {
    int   pty_master;  /* master side of pty pair, -1 = нет сеанса */
    pid_t child_pid;   /* pid /bin/ash */
    bool  active;
} SshSession;

static SshSession  s_ssh     = {.pty_master = -1, .child_pid = -1, .active = false};
static HttpConn   *s_ssh_conn = NULL;  /* WS соединение текущего SSH сеанса */

/* ── Конфиг-указатель для toggle управления ──────────────────────── */
static const EburNetConfig *s_cfg = NULL;

/* ── Менеджер групп для group_select/group_test ───────────────────── */
static proxy_group_manager_t *s_pgm = NULL;

void http_server_set_pgm(proxy_group_manager_t *pgm) { s_pgm = pgm; }

/* ── Менеджер rule-провайдеров для /providers/rules ruleCount ───────── */
static rule_provider_manager_t *s_rpm = NULL;

void http_server_set_rpm(rule_provider_manager_t *rpm) { s_rpm = rpm; }

/* ── Указатель на device manager — инициализируется из main.c ───────── */
static device_manager_t *s_dm = NULL;

void http_server_set_dm(device_manager_t *dm) { s_dm = dm; }

static dispatcher_state_t *s_ds = NULL;

void http_server_set_dispatcher(dispatcher_state_t *ds) { s_ds = ds; }

void http_server_set_geo_loaded(bool loaded) { s_geo_loaded = loaded; }
void http_server_set_geo_manager(const geo_manager_t *gm) { s_geo = gm; }

/* ── rules_engine для hit_count в GET /rules ──────────────────────── */
static rules_engine_t *s_re = NULL;
void http_server_set_re(rules_engine_t *re) { s_re = re; }

/* WHY: api_token читается из UCI при старте и при SIGHUP reload.
 * Без обновления смена токена в UCI требует полного рестарта демона. */
void http_server_reload_token(void)
{
    char buf[64] = {0};
    FILE *tf = popen("uci -q get 4eburnet.main.api_token 2>/dev/null", "r");
    if (tf) {
        if (fgets(buf, sizeof(buf), tf)) {
            size_t l = strlen(buf);
            if (l > 0 && buf[l-1] == '\n') buf[l-1] = '\0';
        }
        pclose(tf);
    }
    if (buf[0] == '\0') return;
    strncpy(s_api_token, buf, sizeof(s_api_token) - 1);
    s_api_token[sizeof(s_api_token) - 1] = '\0';
    log_msg(LOG_INFO, "http_server: api_token обновлён");
}

/* ── WS /logs: хук из log_msg → ring buffer + push клиентам ─────── */
/* Вызывается из log_msg каждый раз когда появляется новая строка лога.
 * WHY: хук вызывается в main event loop (log_msg не thread-safe в любом случае);
 * ws_send_text + conn_flush НЕ вызывают log_msg — рекурсии нет. */
static void http_ws_log_hook(const char *line)
{
    /* Сохраняем в кольцевой буфер */
    strncpy(s_log_ring[s_log_ring_head], line, LOG_LINE_MAX - 1);
    s_log_ring[s_log_ring_head][LOG_LINE_MAX - 1] = '\0';
    s_log_ring_head = (s_log_ring_head + 1) % LOG_RING_SIZE;
    if (s_log_ring_count < LOG_RING_SIZE) s_log_ring_count++;

    /* Пушим клиентам /logs если есть подключения */
    if (!s_ws_srv || s_ws_epoll_fd < 0) return;

    /* Формат Clash/Mihomo: {"type":"info","payload":"..."} */
    const char *type = "info";
    if (strstr(line, "] [ERROR]")) type = "error";
    else if (strstr(line, "] [WARN]"))  type = "warning";
    else if (strstr(line, "] [DEBUG]")) type = "debug";

    char json[LOG_LINE_MAX + 64];
    /* WHY: экранируем только " и \ — log_msg не генерирует контрольных символов */
    char escaped[LOG_LINE_MAX * 2];
    int ei = 0;
    for (int si = 0; line[si] && ei < (int)sizeof(escaped) - 2; si++) {
        if (line[si] == '"' || line[si] == '\\')
            escaped[ei++] = '\\';
        escaped[ei++] = line[si];
    }
    escaped[ei] = '\0';

    int jlen = snprintf(json, sizeof(json),
                        "{\"type\":\"%s\",\"payload\":\"%s\"}", type, escaped);
    if (jlen <= 0 || (size_t)jlen >= sizeof(json)) return;

    for (int i = 0; i < HTTP_MAX_CONN; i++) {
        HttpConn *c = &s_ws_srv->conns[i];
        if (c->fd < 0 || !c->is_websocket) continue;
        if (c->ws_route != WS_ROUTE_LOGS) continue;
        if (ws_send_text(c, s_ws_epoll_fd, json, (size_t)jlen) < 0)
            conn_close(c, s_ws_epoll_fd);
    }
}

/* Отправить историю лога новому WS /logs подписчику */
static void ws_logs_send_history(HttpConn *conn, int epoll_fd)
{
    if (s_log_ring_count == 0) return;
    /* Итерируем от старой к новой (FIFO порядок) */
    int start = (s_log_ring_count < LOG_RING_SIZE)
                ? 0
                : s_log_ring_head;  /* head указывает на самую старую */
    for (int i = 0; i < s_log_ring_count; i++) {
        int idx = (start + i) % LOG_RING_SIZE;
        const char *line = s_log_ring[idx];
        if (!line[0]) continue;

        const char *type = "info";
        if (strstr(line, "] [ERROR]")) type = "error";
        else if (strstr(line, "] [WARN]"))  type = "warning";
        else if (strstr(line, "] [DEBUG]")) type = "debug";

        char json[LOG_LINE_MAX + 64];
        char escaped[LOG_LINE_MAX * 2];
        int ei = 0;
        for (int si = 0; line[si] && ei < (int)sizeof(escaped) - 2; si++) {
            if (line[si] == '"' || line[si] == '\\')
                escaped[ei++] = '\\';
            escaped[ei++] = line[si];
        }
        escaped[ei] = '\0';
        int jlen = snprintf(json, sizeof(json),
                            "{\"type\":\"%s\",\"payload\":\"%s\"}", type, escaped);
        if (jlen > 0 && (size_t)jlen < sizeof(json)) {
            if (ws_send_text(conn, epoll_fd, json, (size_t)jlen) < 0) {
                conn_close(conn, epoll_fd);
                return;
            }
        }
    }
}

/* ── WS /ws/events: broadcast + history + emit ──────────────────────
 * broadcast: разослать json всем подключённым /ws/events клиентам */
static void ws_events_broadcast(const char *json, int n)
{
    if (!s_ws_srv || s_ws_epoll_fd < 0) return;
    for (int i = 0; i < HTTP_MAX_CONN; i++) {
        HttpConn *c = &s_ws_srv->conns[i];
        if (c->fd < 0 || !c->is_websocket) continue;
        if (c->ws_route != WS_ROUTE_EVENTS) continue;
        if (ws_send_text(c, s_ws_epoll_fd, json, (size_t)n) < 0)
            conn_close(c, s_ws_epoll_fd);
    }
}

/* Отправить историю событий новому /ws/events подписчику (хронологически) */
static void ws_events_send_history(HttpConn *conn, int epoll_fd)
{
    if (s_events_ring_count == 0) return;
    int start = (s_events_ring_count < EVENTS_RING_COUNT)
                ? 0
                : s_events_ring_head;
    for (int i = 0; i < s_events_ring_count; i++) {
        int idx = (start + i) % EVENTS_RING_COUNT;
        const char *ev = s_events_ring[idx];
        if (!ev[0]) continue;
        if (ws_send_text(conn, epoll_fd, ev, strlen(ev)) < 0) {
            conn_close(conn, epoll_fd);
            return;
        }
    }
}

/* Публичный API: записать событие в ring buffer и разослать подписчикам */
void http_server_emit_event(const char *json_event)
{
    if (!json_event || !json_event[0]) return;
    strncpy(s_events_ring[s_events_ring_head], json_event, EVENTS_ENTRY_MAX - 1);
    s_events_ring[s_events_ring_head][EVENTS_ENTRY_MAX - 1] = '\0';
    s_events_ring_head = (s_events_ring_head + 1) % EVENTS_RING_COUNT;
    if (s_events_ring_count < EVENTS_RING_COUNT) s_events_ring_count++;
    ws_events_broadcast(json_event, (int)strlen(json_event));
}

/* hex4 — 4 hex ASCII символа → unsigned long */
static unsigned long hex4(const char *s) {
    unsigned long v = 0;
    for (int k = 0; k < 4; k++) {
        v <<= 4;
        unsigned char c = (unsigned char)s[k];
        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
    }
    return v;
}

/* ── Извлечь строковое значение по ключу из JSON ─────────────────────
 * Фикс A: байты >= 0x80 (multi-byte UTF-8) копируются as-is.
 * Фикс B: \uXXXX + surrogate pairs разворачиваются в UTF-8.
 * Фикс C: пробелы вокруг ':' и '"' допустимы ("name" : "val"). */
static size_t http_json_get_str(const char *json, const char *key,
                                char *out, size_t out_sz)
{
    if (!json || !key || !out || out_sz == 0) return 0;
    out[0] = '\0';
    char pat[80];
    int pn = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (pn < 0 || (size_t)pn >= sizeof(pat)) return 0;
    const char *start = strstr(json, pat);
    if (!start) return 0;
    start += (size_t)pn;
    while (*start == ' ' || *start == '\t') start++;
    if (*start != ':') return 0;
    start++;
    while (*start == ' ' || *start == '\t') start++;
    if (*start != '"') return 0;
    start++;
    size_t i = 0;
    const char *p = start;
    while (*p && i < out_sz - 1) {
        if (*p == '"') break;
        if (*p != '\\') { out[i++] = *p++; continue; }
        p++;
        if (!*p) break;
        /* Стандартные JSON escape-последовательности */
        if      (*p == 'n')  { out[i++] = '\n'; p++; continue; }
        else if (*p == 'r')  { out[i++] = '\r'; p++; continue; }
        else if (*p == 't')  { out[i++] = '\t'; p++; continue; }
        else if (*p == 'b')  { out[i++] = '\b'; p++; continue; }
        else if (*p == 'f')  { out[i++] = '\f'; p++; continue; }
        else if (*p != 'u')  { out[i++] = *p++; continue; }
        p++;
        if (!p[0] || !p[1] || !p[2] || !p[3]) break;
        unsigned long hi = hex4(p); p += 4;
        unsigned long cp = hi;
        if (hi >= 0xD800 && hi <= 0xDBFF &&
            p[0] == '\\' && p[1] == 'u' && p[2] && p[3] && p[4] && p[5]) {
            unsigned long lo = hex4(p + 2);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + (hi - 0xD800) * 0x400 + (lo - 0xDC00); p += 6;
            } else { continue; }
        }
        if      (cp <= 0x7F)                        { out[i++] = (char)cp; }
        else if (cp <= 0x7FF   && i + 2 < out_sz)  { out[i++] = (char)(0xC0|(cp>>6));  out[i++] = (char)(0x80|(cp&0x3F)); }
        else if (cp <= 0xFFFF  && i + 3 < out_sz)  { out[i++] = (char)(0xE0|(cp>>12)); out[i++] = (char)(0x80|((cp>>6)&0x3F)); out[i++] = (char)(0x80|(cp&0x3F)); }
        else if (cp <= 0x10FFFF && i + 4 < out_sz) { out[i++] = (char)(0xF0|(cp>>18)); out[i++] = (char)(0x80|((cp>>12)&0x3F)); out[i++] = (char)(0x80|((cp>>6)&0x3F)); out[i++] = (char)(0x80|(cp&0x3F)); }
    }
    out[i] = '\0';
    return i;
}

/* Как http_json_get_str, но также извлекает числа и булевые значения без кавычек */
static size_t http_json_get_val(const char *json, const char *key, char *out, size_t out_sz)
{
    size_t n = http_json_get_str(json, key, out, out_sz);
    if (n > 0) return n;
    if (!json || !key || !out || out_sz == 0) return 0;
    out[0] = '\0';
    char pat[80];
    int pn = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (pn < 0 || (size_t)pn >= sizeof(pat)) return 0;
    const char *start = strstr(json, pat);
    if (!start) return 0;
    start += (size_t)pn;
    while (*start == ' ' || *start == '\t') start++;
    if (*start != ':') return 0;
    start++;
    while (*start == ' ' || *start == '\t') start++;
    if (*start == '"') return 0;
    size_t i = 0;
    while (*start && i < out_sz - 1) {
        char c = *start;
        if (c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
        out[i++] = c;
        start++;
    }
    out[i] = '\0';
    return i;
}

/* ── Ожидаемый JA3 хэш (задаётся через /api/control action=ja3_expected) */
static char g_ja3_expected[33] = {0};

void http_server_set_config(const EburNetConfig *cfg)
{
    s_cfg = cfg;
}

const char *http_server_get_ja3_expected(void)
{
    return g_ja3_expected;
}

/* ── Вспомогательная функция закрытия соединения ─────────────────── */
/* ── SSH pty bridge ────────────────────────────────────────────────── */

/* Проверить, что клиент из LAN (RFC 1918 + loopback) */
static bool ssh_is_lan_client(const struct sockaddr_in *addr)
{
    uint32_t ip = ntohl(addr->sin_addr.s_addr);
    if ((ip & 0xFF000000u) == 0x0A000000u) return true;  /* 10.0.0.0/8 */
    if ((ip & 0xFFF00000u) == 0xAC100000u) return true;  /* 172.16.0.0/12 */
    if ((ip & 0xFFFF0000u) == 0xC0A80000u) return true;  /* 192.168.0.0/16 */
    if ((ip & 0xFF000000u) == 0x7F000000u) return true;  /* 127.0.0.0/8 */
    return false;
}

/* Запустить pty + /bin/ash; добавить pty_master в epoll */
static int ssh_session_start(void)
{
    if (s_ssh.active) return 0;

    int master, slave;
    struct winsize ws = {.ws_row = 24, .ws_col = 80};
    if (openpty(&master, &slave, NULL, NULL, &ws) != 0) {
        log_msg(LOG_ERROR, "SSH: openpty: %s", strerror(errno));
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(master); close(slave);
        return -1;
    }

    if (pid == 0) {
        /* child: перейти в отдельную сессию, назначить управляющий терминал */
        close(master);
        setsid();
        ioctl(slave, TIOCSCTTY, 0);
        dup2(slave, STDIN_FILENO);
        dup2(slave, STDOUT_FILENO);
        dup2(slave, STDERR_FILENO);
        if (slave > STDERR_FILENO) close(slave);
        setenv("TERM", "xterm-256color", 1);
        setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
        setenv("HOME", "/root", 1);
        setenv("USER", "root", 1);
        execl("/bin/ash", "/bin/ash", "-l", NULL);
        execl("/bin/sh",  "/bin/sh",  "-l", NULL);
        _exit(1);
    }

    close(slave);
    fcntl(master, F_SETFL, O_NONBLOCK);

    s_ssh.pty_master = master;
    s_ssh.child_pid  = pid;
    s_ssh.active     = true;

    /* Добавить pty_master в master epoll — LT для надёжности */
    if (s_ws_epoll_fd >= 0) {
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = master};
        epoll_ctl(s_ws_epoll_fd, EPOLL_CTL_ADD, master, &ev);
    }

    log_msg(LOG_INFO, "SSH: сеанс запущен pid=%d fd=%d", (int)pid, master);
    return 0;
}

/* Остановить pty сеанс */
static void ssh_session_stop(void)
{
    if (!s_ssh.active) return;

    if (s_ssh.pty_master >= 0) {
        if (s_ws_epoll_fd >= 0)
            epoll_ctl(s_ws_epoll_fd, EPOLL_CTL_DEL, s_ssh.pty_master, NULL);
        close(s_ssh.pty_master);
        s_ssh.pty_master = -1;
    }
    if (s_ssh.child_pid > 0) {
        kill(s_ssh.child_pid, SIGHUP);
        /* SA_NOCLDWAIT в main.c авто-reap — waitpid не нужен */
        s_ssh.child_pid = -1;
    }
    s_ssh.active  = false;
    s_ssh_conn    = NULL;
    log_msg(LOG_INFO, "SSH: сеанс закрыт");
}

/* Прочитать вывод pty и отправить клиенту как binary WS frame */
static void ssh_pty_on_output(int epoll_fd)
{
    /* WHY: статический буфер — MIPS stack limit 8KB */
    static uint8_t s_pty_buf[4096];

    for (;;) {
        ssize_t n = read(s_ssh.pty_master, s_pty_buf, sizeof(s_pty_buf));
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            /* ash завершился или pty закрылся */
            HttpConn *sc = s_ssh_conn;
            ssh_session_stop();
            if (sc)
                ws_send_text(sc, epoll_fd, "{\"type\":\"exit\"}", 15);
            return;
        }
        if (s_ssh_conn)
            ws_send_binary(s_ssh_conn, epoll_fd, s_pty_buf, (uint32_t)n);
    }
}

/* Обработать WS frame от SSH клиента (ввод / resize) */
static void ws_ssh_on_input(const uint8_t *data, uint32_t len)
{
    if (!s_ssh.active || s_ssh.pty_master < 0) return;

    /* Resize: {"type":"resize","rows":N,"cols":M} */
    if (len > 2 && data[0] == '{') {
        char buf[128] = {0};
        size_t cplen = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
        memcpy(buf, data, cplen);
        if (strstr(buf, "resize")) {
            int rows = 24, cols = 80;
            const char *pr = strstr(buf, "rows");
            const char *pc = strstr(buf, "cols");
            if (pr) sscanf(pr, "rows\":%d", &rows);
            if (pc) sscanf(pc, "cols\":%d", &cols);
            struct winsize ws = {
                .ws_row = (uint16_t)rows,
                .ws_col = (uint16_t)cols
            };
            ioctl(s_ssh.pty_master, TIOCSWINSZ, &ws);
            return;
        }
    }

    /* Raw keyboard input */
    (void)write(s_ssh.pty_master, data, len);
}

static void conn_close(HttpConn *conn, int epoll_fd)
{
    if (conn->fd >= 0) {
        /* Если это WebSocket — best-effort close frame перед close() */
        if (conn->is_websocket) {
            ws_send_close(conn, epoll_fd, 1000);  /* 1000 = normal */
        }
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
        close(conn->fd);
        conn->fd = -1;
    }
    conn->is_websocket = 0;
    conn->ws_route = WS_ROUTE_NONE;
    /* Если это SSH conn — прибить сеанс */
    if (conn == s_ssh_conn)
        ssh_session_stop();
    conn->buf_len = 0;
    conn->headers_done = 0;
    free(conn->send_buf);
    conn->send_buf  = NULL;
    conn->send_len  = 0;
    conn->send_pos  = 0;
    if (conn->send_file) { fclose(conn->send_file); conn->send_file = NULL; }
    conn->send_offset    = 0;
    conn->send_remaining = 0;
}

/* ── Обработка WebSocket frames (client → server) ─────────────────── */
static void ws_handle_connection(HttpConn *conn, int epoll_fd)
{
    /* Несколько frames могут лежать подряд в buf — цикл */
    while (conn->buf_len > 0) {
        uint8_t opcode = 0;
        size_t plen = 0, consumed = 0;

        int r = ws_parse_frame(conn->buf, (size_t)conn->buf_len,
                               &opcode, s_ws_payload, sizeof(s_ws_payload),
                               &plen, &consumed);
        if (r == 0) return;  /* Incomplete — wait for more data */
        if (r == -1) {
            /* WS_OP_CLOSE → UTF-8 invalid TEXT (RFC 6455 §8.1 → code 1007) */
            uint16_t code = (opcode == WS_OP_CLOSE) ? 1007 : 1002;
            ws_send_close(conn, epoll_fd, code);
            conn_close(conn, epoll_fd);
            return;
        }

        switch (opcode) {
            case WS_OP_TEXT:
            case WS_OP_BINARY:
                if (conn->ws_route == WS_ROUTE_ECHO) {
                    if (ws_send_text(conn, epoll_fd, s_ws_payload, plen) < 0) {
                        conn_close(conn, epoll_fd);
                        return;
                    }
                } else if (conn->ws_route == WS_ROUTE_SSH) {
                    ws_ssh_on_input((const uint8_t *)s_ws_payload, (uint32_t)plen);
                }
                break;

            case WS_OP_PING:
                if (ws_send_pong(conn, epoll_fd, s_ws_payload, plen) < 0) {
                    conn_close(conn, epoll_fd);
                    return;
                }
                break;

            case WS_OP_PONG:
                /* Ignore — клиент ack'ает наш ping */
                break;

            case WS_OP_CLOSE:
                ws_send_close(conn, epoll_fd, 1000);
                /* После ws_send_close — не вызывать повторно в conn_close */
                conn->is_websocket = 0;
                conn_close(conn, epoll_fd);
                return;

            default:
                ws_send_close(conn, epoll_fd, 1002);
                conn_close(conn, epoll_fd);
                return;
        }

        /* Сдвинуть буфер */
        if (consumed < (size_t)conn->buf_len) {
            memmove(conn->buf, conn->buf + consumed,
                    (size_t)conn->buf_len - consumed);
        }
        conn->buf_len -= (int)consumed;
    }
}

/* ── Определить Content-Type по расширению файла ──────────────────── */
/* Возвращает статическую строку — не освобождать. */
static const char *mime_by_ext(const char *path)
{
    if (!path) return "application/octet-stream";
    const char *dot = strrchr(path, '.');
    if (!dot || dot == path) return "application/octet-stream";
    dot++;  /* skip '.' */

    if (!strcasecmp(dot, "html") || !strcasecmp(dot, "htm"))
        return "text/html; charset=utf-8";
    if (!strcasecmp(dot, "js") || !strcasecmp(dot, "mjs"))
        return "application/javascript; charset=utf-8";
    if (!strcasecmp(dot, "css"))
        return "text/css; charset=utf-8";
    if (!strcasecmp(dot, "json"))
        return "application/json; charset=utf-8";
    if (!strcasecmp(dot, "webmanifest"))
        return "application/manifest+json";
    if (!strcasecmp(dot, "woff2"))
        return "font/woff2";
    if (!strcasecmp(dot, "woff"))
        return "font/woff";
    if (!strcasecmp(dot, "ttf"))
        return "font/ttf";
    if (!strcasecmp(dot, "otf"))
        return "font/otf";
    if (!strcasecmp(dot, "eot"))
        return "application/vnd.ms-fontobject";
    if (!strcasecmp(dot, "png"))
        return "image/png";
    if (!strcasecmp(dot, "jpg") || !strcasecmp(dot, "jpeg"))
        return "image/jpeg";
    if (!strcasecmp(dot, "gif"))
        return "image/gif";
    if (!strcasecmp(dot, "svg"))
        return "image/svg+xml";
    if (!strcasecmp(dot, "ico"))
        return "image/x-icon";
    if (!strcasecmp(dot, "webp"))
        return "image/webp";
    if (!strcasecmp(dot, "txt") || !strcasecmp(dot, "log"))
        return "text/plain; charset=utf-8";
    if (!strcasecmp(dot, "xml"))
        return "application/xml; charset=utf-8";
    if (!strcasecmp(dot, "map"))
        return "application/json";

    return "application/octet-stream";
}

/* ── Добавить данные в буфер отложенной отправки ─────────────────── */
int conn_queue_write(HttpConn *c, const void *data, size_t len)
{
    if (len == 0) return 0;
    /* Компактировать: убрать уже отправленные байты из начала */
    if (c->send_pos > 0 && c->send_buf) {
        size_t remain = c->send_len - c->send_pos;
        if (remain > 0)
            memmove(c->send_buf, c->send_buf + c->send_pos, remain);
        c->send_len = remain;
        c->send_pos = 0;
    }
    size_t new_len = c->send_len + len;
    uint8_t *nb = realloc(c->send_buf, new_len);
    if (!nb) return -1;
    memcpy(nb + c->send_len, data, len);
    c->send_buf = nb;
    c->send_len = new_len;
    return 0;
}

/* ── Слить буфер; при EAGAIN добавить EPOLLOUT и вернуть 0 ───────── */
int conn_flush(HttpConn *c, int epoll_fd)
{
    while (c->send_pos < c->send_len) {
        ssize_t r = write(c->fd,
                          c->send_buf + c->send_pos,
                          c->send_len - c->send_pos);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct epoll_event ev;
                ev.events  = EPOLLIN | EPOLLOUT | EPOLLRDHUP;  /* LT: EPOLLET на HTTP запрещён */
                ev.data.fd = c->fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, c->fd, &ev);
                return 0;
            }
            return -1;
        }
        if (r == 0) return -1;
        c->send_pos += (size_t)r;
    }
    free(c->send_buf);
    c->send_buf = NULL;
    c->send_len = 0;
    c->send_pos = 0;
    return 0;
}

/* ── Продолжить async отдачу файла при EPOLLOUT ─────────────────────
 * Возвращает 1 = завершено, 0 = EAGAIN (ждать EPOLLOUT), -1 = ошибка.
 * WHY: статический буфер 4KB в BSS — MIPS stack 8KB не позволяет локальный. */
static int http_send_file_continue(HttpConn *conn)
{
    static uint8_t s_file_buf[4096];

    while (conn->send_remaining > 0) {
        size_t to_read = sizeof(s_file_buf);
        if ((off_t)to_read > conn->send_remaining)
            to_read = (size_t)conn->send_remaining;

        size_t n_read = fread(s_file_buf, 1, to_read, conn->send_file);
        if (n_read == 0) {
            fclose(conn->send_file);
            conn->send_file      = NULL;
            conn->send_remaining = 0;
            return -1;
        }

        ssize_t n_sent = send(conn->fd, s_file_buf, n_read, MSG_NOSIGNAL);
        if (n_sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Откатить позицию файла к send_offset */
                fseeko(conn->send_file, conn->send_offset, SEEK_SET);
                return 0;
            }
            fclose(conn->send_file);
            conn->send_file      = NULL;
            conn->send_remaining = 0;
            return -1;
        }

        conn->send_offset    += (off_t)n_sent;
        conn->send_remaining -= (off_t)n_sent;

        if ((size_t)n_sent < n_read) {
            /* Частичная отправка — сбросить позицию к новому offset */
            fseeko(conn->send_file, conn->send_offset, SEEK_SET);
            return 0;
        }
    }

    fclose(conn->send_file);
    conn->send_file      = NULL;
    conn->send_remaining = 0;
    return 1;
}

/* ── CORS headers для ответа (mihomo-compat: разрешаем всё) ─────────
 * Отражаем Origin запроса (echo) — это позволяет credentials, в отличие от
 * Allow-Origin: *. Без Origin (same-origin/curl/wget) — пустая строка.
 * Добавлены Allow-Credentials/Methods/Headers — нужны для preflight (OPTIONS)
 * и для XHR с custom headers (Authorization, Content-Type). */
static void cors_origin_hdr(const char *req_buf, char *out, size_t outlen)
{
    out[0] = '\0';
    if (!req_buf) return;
    const char *h = strstr(req_buf, "\nOrigin: ");
    if (!h) h = strstr(req_buf, "\norigin: ");
    if (!h) return;
    h += 9;
    char val[160];
    size_t i = 0;
    while (i < sizeof(val) - 1 && h[i] != '\r' && h[i] != '\n' && h[i] != '\0') {
        val[i] = h[i];
        i++;
    }
    val[i] = '\0';
    if (val[0] == '\0') return;
    snprintf(out, outlen,
        "Access-Control-Allow-Origin: %s\r\n"
        "Access-Control-Allow-Credentials: true\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
        "Vary: Origin\r\n",
        val);
}

/* ── Отправить HTTP ответ: заголовок + тело, затем закрыть conn ───── */
static void http_send(HttpConn *conn, int epoll_fd,
                      int status, const char *ctype,
                      const void *body, size_t body_len)
{
    const char *status_str;
    switch (status) {
        case 200: status_str = "OK";                    break;
        case 400: status_str = "Bad Request";           break;
        case 401: status_str = "Unauthorized";          break;
        case 403: status_str = "Forbidden";             break;
        case 404: status_str = "Not Found";             break;
        case 405: status_str = "Method Not Allowed";    break;
        case 429: status_str = "Too Many Requests";     break;
        case 500: status_str = "Internal Server Error"; break;
        case 503: status_str = "Service Unavailable";   break;
        default:  status_str = "Error";                 break;
    }

    /* MIPS: суммарный кадр cors[384]+hdr[768]=1152B превышает stack limit 512B.
     * Только из epoll single-threaded loop — re-entrancy невозможна (см. ws_client.c:133). */
    static char cors[384];
    cors_origin_hdr(conn->buf, cors, sizeof(cors));
    static char hdr[768];
    int  hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.0 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        status, status_str, ctype, body_len, cors);

    if (hdr_len <= 0 || hdr_len >= (int)sizeof(hdr)) {
        conn_close(conn, epoll_fd);
        return;
    }
    if (conn_queue_write(conn, hdr, (size_t)hdr_len) < 0 ||
        (body && body_len > 0 && conn_queue_write(conn, body, body_len) < 0)) {
        conn_close(conn, epoll_fd);
        return;
    }
    if (conn_flush(conn, epoll_fd) < 0 || !conn->send_buf)
        conn_close(conn, epoll_fd);
    /* send_buf != NULL → EAGAIN, EPOLLOUT зарегистрирован, закрытие в handler */
}

/* ── 307 Temporary Redirect (mihomo-compat для /ui → /ui/) ──────── */
static void http_send_redirect(HttpConn *conn, int epoll_fd,
                               const char *location)
{
    /* MIPS: cors[384]+body[160]+hdr[768]=1312B > stack limit 512B. Single-threaded epoll. */
    static char cors[384];
    cors_origin_hdr(conn->buf, cors, sizeof(cors));

    char body[160];
    int body_len = snprintf(body, sizeof(body),
        "<a href=\"%s\">Temporary Redirect</a>.\n", location);
    if (body_len <= 0 || body_len >= (int)sizeof(body)) {
        conn_close(conn, epoll_fd);
        return;
    }

    static char hdr[768];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.0 307 Temporary Redirect\r\n"
        "Location: %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        location, body_len, cors);

    if (hdr_len <= 0 || hdr_len >= (int)sizeof(hdr)) {
        conn_close(conn, epoll_fd);
        return;
    }
    if (conn_queue_write(conn, hdr, (size_t)hdr_len) < 0 ||
        conn_queue_write(conn, body, (size_t)body_len) < 0) {
        conn_close(conn, epoll_fd);
        return;
    }
    if (conn_flush(conn, epoll_fd) < 0 || !conn->send_buf)
        conn_close(conn, epoll_fd);
}

/* ── Отдать файл с диска как HTTP ответ (async EPOLLOUT) ─────────── */
static void http_send_file(HttpConn *conn, int epoll_fd,
                           int status, const char *ctype,
                           const char *filepath)
{
    struct stat st;
    if (stat(filepath, &st) != 0 || st.st_size <= 0) {
        const char body404[] = "Not Found";
        http_send(conn, epoll_fd, 404, "text/plain",
                  body404, sizeof(body404) - 1);
        return;
    }

    FILE *f = fopen(filepath, "rb");
    if (!f) {
        const char body404[] = "Not Found";
        http_send(conn, epoll_fd, 404, "text/plain",
                  body404, sizeof(body404) - 1);
        return;
    }

    const char *status_str = (status == 200) ? "OK" : "Not Modified";
    /* MIPS: cors[384]+hdr[768]=1152B > stack limit 512B. Single-threaded epoll. */
    static char cors[384];
    cors_origin_hdr(conn->buf, cors, sizeof(cors));
    static char hdr[768];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %lld\r\n"
        "Cache-Control: max-age=3600\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        status, status_str, ctype, (long long)st.st_size, cors);

    if (hdr_len <= 0 || hdr_len >= (int)sizeof(hdr)) {
        fclose(f);
        conn_close(conn, epoll_fd);
        return;
    }

    /* Заголовки малы — всегда умещаются в сокетный буфер */
    if (send(conn->fd, hdr, (size_t)hdr_len, MSG_NOSIGNAL) < 0) {
        fclose(f);
        conn_close(conn, epoll_fd);
        return;
    }

    conn->send_file      = f;
    conn->send_offset    = 0;
    conn->send_remaining = st.st_size;

    int rc = http_send_file_continue(conn);
    if (rc == 1) {
        conn_close(conn, epoll_fd);
    } else if (rc == 0) {
        /* EAGAIN — добавить EPOLLOUT к событиям */
        struct epoll_event ev;
        ev.events  = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
        ev.data.fd = conn->fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
    } else {
        conn_close(conn, epoll_fd);
    }
}

/* ── /api/status — собрать JSON из PID + /proc + UCI ─────────────── */
/* Намеренно НЕ вызывает popen("4eburnetd --ipc") — это вызвало бы
   дедлок: дочерний процесс подключается к IPC-сокету демона,
   а демон заблокирован в fread(), ожидая ответа от дочернего.    */
static void route_api_status(HttpConn *conn, int epoll_fd)
{
    int  running = 0;
    int  pid     = 0;
    long uptime  = 0;

    /* Проверить PID файл */
    FILE *pf = fopen("/var/run/4eburnet.pid", "r");
    if (pf) {
        if (fscanf(pf, "%d", &pid) == 1 && pid > 0) {
            char comm_path[64];
            snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
            FILE *cf = fopen(comm_path, "r");
            if (cf) {
                char comm[32] = {0};
                if (fgets(comm, sizeof(comm), cf)) {
                    size_t l = strlen(comm);
                    if (l > 0 && comm[l - 1] == '\n') comm[l - 1] = '\0';
                    running = (strcmp(comm, "4eburnetd") == 0);
                }
                fclose(cf);
            }
        }
        fclose(pf);
    }

    /* Посчитать аптайм из /proc/<pid>/stat поле 22 (starttime ticks) */
    if (running && pid > 0) {
        char stat_path[64];
        snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
        FILE *sf = fopen(stat_path, "r");
        if (sf) {
            unsigned long starttime = 0;
            /* Поле 22 в /proc/pid/stat — время старта в ticks с boot */
            if (fscanf(sf,
                "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
                "%*u %*u %*d %*d %*d %*d %*d %*d %lu", &starttime) == 1) {
                /* /proc/uptime даёт uptime системы в секундах */
                FILE *uf = fopen("/proc/uptime", "r");
                if (uf) {
                    double sys_uptime = 0.0;
                    if (fscanf(uf, "%lf", &sys_uptime) == 1)
                        uptime = (long)(sys_uptime - (double)starttime / 100.0);
                    fclose(uf);
                }
            }
            fclose(sf);
        }
        if (uptime < 0) uptime = 0;
    }

    /* Прочитать mode из UCI конфига напрямую — без fork */
    char mode[32] = "rules";
    {
        FILE *cf = fopen("/etc/config/4eburnet", "r");
        if (cf) {
            char ln[128];
            while (fgets(ln, sizeof(ln), cf)) {
                const char *lp = ln;
                while (*lp == '\t' || *lp == ' ') lp++;
                if (strncmp(lp, "option mode", 11) == 0) {
                    const char *q = strchr(lp + 11, '\'');
                    if (!q) q = strchr(lp + 11, '"');
                    if (q) {
                        q++;
                        const char *e = strchr(q, '\'');
                        if (!e) e = strchr(q, '"');
                        if (e) {
                            int mlen = (int)(e - q);
                            if (mlen > 0 && mlen < (int)sizeof(mode)) {
                                memcpy(mode, q, (size_t)mlen);
                                mode[mlen] = '\0';
                            }
                        }
                    }
                    break;
                }
            }
            fclose(cf);
        }
    }

    /* Определить профиль */
    const char *profile = "NORMAL";
    FILE *mf = fopen("/proc/meminfo", "r");
    if (mf) {
        unsigned long mem_kb = 0;
        if (fscanf(mf, "MemTotal: %lu", &mem_kb) == 1) {
            if (mem_kb > 262144) profile = "FULL";
        }
        fclose(mf);
    }

    /* Собрать DPI статистику */
    uint32_t dpi_adapt_count = 0, dpi_adapt_hits = 0;
#if CONFIG_EBURNET_DPI
    dpi_adapt_stats(&g_dpi_adapt, &dpi_adapt_count, &dpi_adapt_hits);
#endif

    /* Сравнение last_ja3 с ожидаемым — warn если задан и не совпадает */
    const char *last_ja3 = dispatcher_get_last_ja3();
    bool ja3_match = true;
    if (g_ja3_expected[0] && last_ja3[0])
        ja3_match = (strcmp(g_ja3_expected, last_ja3) == 0);
    if (!ja3_match)
        log_msg(LOG_WARN, "JA3 mismatch: ожидается %s, последний %s",
                g_ja3_expected, last_ja3);

    /* Сформировать JSON */
    char esc_mode[64];
    json_escape_str(mode, esc_mode, sizeof(esc_mode));
    int n = snprintf(s_ipc_buf, sizeof(s_ipc_buf),
        "{\"status\":\"%s\",\"version\":\"" EBURNET_VERSION "\","
        "\"uptime\":%ld,\"mode\":\"%s\",\"profile\":\"%s\","
        "\"last_ja3\":\"%s\",\"ja3_expected\":\"%s\",\"ja3_match\":%s,"
        "\"flow_offload\":%s,\"tc_fast\":%s,"
        "\"dpi_enabled\":%s,"
        "\"dpi_adapt_count\":%u,\"dpi_adapt_hits\":%u,"
        "\"conn_active\":%llu,\"conn_total\":%llu,"
        "\"dns_queries\":%llu,\"dns_cached\":%llu,"
        "\"blocked_ads\":%llu,\"blocked_trackers\":%llu,\"blocked_threats\":%llu,"
        "\"ech_connections\":%llu,"
        "\"last_ech_type\":\"0x%04x\","
        "\"dispatcher_tick_us_peak\":%u,"
        "\"dns_recv_q_max\":%u,"
        "\"geo_loaded\":%s}",
        running ? "running" : "stopped",
        uptime, esc_mode, profile,
        last_ja3, g_ja3_expected, ja3_match ? "true" : "false",
        nft_flow_offload_is_active() ? "true" : "false",
        tc_fast_is_active()          ? "true" : "false",
        (s_cfg && s_cfg->dpi_enabled) ? "true" : "false",
        dpi_adapt_count, dpi_adapt_hits,
        (unsigned long long)atomic_load(&g_stats.connections_active),
        (unsigned long long)atomic_load(&g_stats.connections_total),
        (unsigned long long)atomic_load(&g_stats.dns_queries_total),
        (unsigned long long)atomic_load(&g_stats.dns_cached_total),
        (unsigned long long)atomic_load(&g_stats.blocked_ads),
        (unsigned long long)atomic_load(&g_stats.blocked_trackers),
        (unsigned long long)atomic_load(&g_stats.blocked_threats),
        (unsigned long long)atomic_load(&g_stats.ech_connections),
        (unsigned)atomic_load(&g_stats.last_ech_type),
        atomic_load_explicit(&g_dispatcher_tick_us, memory_order_relaxed),
        atomic_load_explicit(&g_dns_recv_q_max, memory_order_relaxed),
        s_geo_loaded ? "true" : "false");

    http_send(conn, epoll_fd, 200, "application/json",
              s_ipc_buf, (size_t)(n > 0 ? n : 0));
}

/* ── route_ipc_passthrough — читать из статус-файла ──────────────── */
/* АРХИТЕКТУРНАЯ ЗАМЕТКА: popen("4eburnetd --ipc <cmd>") из самого
   демона вызывает дедлок — дочерний процесс подключается к IPC-сокету
   демона, а демон заблокирован в fread(). Вместо этого демон пишет
   актуальные данные в /tmp/4eburnet-<cmd>.json по тику, HTTP сервер
   читает оттуда.
   Файлы записываются в main.c (Промт 6 tick).                       */
static void route_ipc_passthrough(HttpConn *conn, int epoll_fd,
                                  const char *cmd)
{
    /* Путь к кешированному JSON */
    char path[64];
    snprintf(path, sizeof(path), "/tmp/4eburnet-%s.json", cmd);

    FILE *f = fopen(path, "r");
    if (!f) {
        /* Файл ещё не создан — вернуть пустой объект/массив */
        const char empty[] = "{}";
        http_send(conn, epoll_fd, 200, "application/json",
                  empty, sizeof(empty) - 1);
        return;
    }

    size_t n = fread(s_ipc_buf, 1, sizeof(s_ipc_buf) - 1, f);
    fclose(f);
    s_ipc_buf[n] = '\0';

    /* Найти начало JSON */
    char *js = s_ipc_buf;
    while (*js && *js != '{' && *js != '[')
        js++;

    if (*js == '\0') {
        const char empty[] = "{}";
        http_send(conn, epoll_fd, 200, "application/json",
                  empty, sizeof(empty) - 1);
        return;
    }

    http_send(conn, epoll_fd, 200, "application/json",
              js, strlen(js));
}

/* ── json_append_str — добавить экранированную строку в буфер ─────── */
static int json_append_str(char *dst, int pos, int max, const char *val)
{
    if (pos + 3 >= max) return pos;
    dst[pos++] = '"';
    for (const char *c = val; *c && pos + 4 < max; c++) {
        if (*c == '"' || *c == '\\') {
            dst[pos++] = '\\';
            dst[pos++] = *c;
        } else if ((unsigned char)*c < 0x20) {
            /* пропустить управляющие символы */
        } else {
            dst[pos++] = *c;
        }
    }
    dst[pos++] = '"';
    return pos;
}

/* ── json_opt_str — добавить поле только если значение не пустое ──── */
static int json_opt_str(char *dst, int pos, int max,
                        const char *key, const char *val)
{
    if (!val || !val[0]) return pos;
    pos += snprintf(dst + pos, (size_t)(max - pos), ",\"%s\":", key);
    return json_append_str(dst, pos, max, val);
}

/* ── serialize_server — сериализовать один сервер в JSON-объект ──── */
static int serialize_server(char *dst, int pos, int max,
    const char *name,  const char *type,
    const char *host,  const char *port,
    const char *uuid,  const char *pass,
    const char *tport, const char *tls,
    const char *sni,   const char *fp,
    const char *pbk,   const char *sid,
    const char *pubkey, int has_privkey,
    const char *mtu,   const char *dns,
    const char *rsrv)
{
    /* Запас 64 байта для завершения объекта и разделителей */
    if (pos >= max - 64) return pos;
    pos += snprintf(dst + pos, (size_t)(max - pos), "{\"name\":");
    pos  = json_append_str(dst, pos, max, name);
    pos += snprintf(dst + pos, (size_t)(max - pos), ",\"type\":");
    pos  = json_append_str(dst, pos, max, type);
    pos += snprintf(dst + pos, (size_t)(max - pos), ",\"host\":");
    pos  = json_append_str(dst, pos, max, host);
    pos += snprintf(dst + pos, (size_t)(max - pos),
                    ",\"port\":%s", port[0] ? port : "0");
    /* Недостаточно места для опциональных полей — закрыть объект */
    if (pos >= max - 128) {
        if (pos + 2 < max) dst[pos++] = '}';
        return pos;
    }
    /* Опциональные поля протоколов */
    pos = json_opt_str(dst, pos, max, "uuid",      uuid);
    pos = json_opt_str(dst, pos, max, "password",  pass);
    pos = json_opt_str(dst, pos, max, "transport", tport);
    pos = json_opt_str(dst, pos, max, "security",  tls);
    pos = json_opt_str(dst, pos, max, "sni",       sni);
    pos = json_opt_str(dst, pos, max, "fp",        fp);
    pos = json_opt_str(dst, pos, max, "pbk",       pbk);
    pos = json_opt_str(dst, pos, max, "sid",       sid);
    /* AWG поля */
    pos = json_opt_str(dst, pos, max, "public_key", pubkey);
    if (has_privkey)
        pos += snprintf(dst + pos, (size_t)(max - pos),
                        ",\"private_key\":\"SET\"");
    pos = json_opt_str(dst, pos, max, "mtu",      mtu);
    pos = json_opt_str(dst, pos, max, "dns",      dns);
    pos = json_opt_str(dst, pos, max, "reserved", rsrv);
    if (pos + 2 < max) dst[pos++] = '}';
    return pos;
}

/* ── write_servers_cache — записать кэш серверов из cfg в /tmp ────── */
static void write_servers_cache(void)
{
    if (!s_cfg) return;

    static char buf[8192];
    int pos = 0, max = (int)sizeof(buf);
    buf[pos++] = '[';
    int first = 1;

    int total = s_cfg->server_count + s_cfg->provider_server_count;
    for (int i = 0; i < total; i++) {
        const ServerConfig *sc = config_get_server(s_cfg, i);
        if (!sc || !sc->name[0]) continue;

        char port_s[8];
        snprintf(port_s, sizeof(port_s), "%u", sc->port);

        /* Security mode: reality если есть pbk, иначе пусто */
        const char *tls_s = sc->reality_pbk[0] ? "reality" : "";
        /* SNI: берём из hy2 или stls если заполнено */
        const char *sni_s = sc->hy2_sni[0] ? sc->hy2_sni : "";
#if CONFIG_EBURNET_STLS
        if (!sni_s[0] && sc->stls_sni[0]) sni_s = sc->stls_sni;
#endif

        if (!first && pos + 1 < max) buf[pos++] = ',';
        first = 0;
        pos = serialize_server(buf, pos, max,
            sc->name, sc->protocol, sc->address, port_s,
            sc->uuid, sc->password, sc->transport, tls_s,
            sni_s, "", sc->reality_pbk, sc->reality_short_id,
            sc->awg_public_key, sc->awg_private_key[0] ? 1 : 0,
            "", sc->awg_dns, sc->awg_reserved);
    }
    if (pos + 2 < max) buf[pos++] = ']';
    buf[pos] = '\0';

    FILE *f = fopen("/tmp/4eburnet-servers.json.tmp", "w");
    if (!f) return;
    fwrite(buf, 1, (size_t)pos, f);
    fclose(f);
    rename("/tmp/4eburnet-servers.json.tmp", "/tmp/4eburnet-servers.json");
}

/* ── /api/servers — список серверов из кэша /tmp ────────────────── */
static void route_api_servers(HttpConn *conn, int epoll_fd)
{
    route_ipc_passthrough(conn, epoll_fd, "servers");
}

/* ── write_dns_cache — записать кэш DNS конфига из cfg в /tmp ─────── */
static void write_dns_cache(void)
{
    if (!s_cfg) return;

    const DnsConfig *d = &s_cfg->dns;
    static char buf[8192];
    int pos = 0, max = (int)sizeof(buf);

    buf[pos++] = '{';

#define DNS_STR(key, val) \
    do { if ((val)[0]) { \
        pos = json_append_str(buf, pos, max, (key)); \
        if (pos + 1 < max) buf[pos++] = ':'; \
        pos = json_append_str(buf, pos, max, (val)); \
        if (pos + 1 < max) buf[pos++] = ','; \
    } } while (0)

#define DNS_INT(key, val) \
    do { pos += snprintf(buf + pos, (size_t)(max - pos), \
                         "\"%s\":%d,", (key), (val)); } while (0)

#define DNS_BOOL(key, val) \
    do { pos += snprintf(buf + pos, (size_t)(max - pos), \
                         "\"%s\":%s,", (key), (val) ? "true" : "false"); } while (0)

    DNS_BOOL("enabled",          d->enabled);
    DNS_INT ("listen_port",      d->listen_port);
    DNS_STR ("upstream_bypass",  d->upstream_bypass);
    DNS_STR ("upstream_proxy",   d->upstream_proxy);
    DNS_STR ("upstream_default", d->upstream_default);
    DNS_STR ("upstream_fallback",d->upstream_fallback);
    DNS_INT ("cache_size",       d->cache_size);
    DNS_INT ("cache_ttl_max",    d->cache_ttl_max);
    DNS_INT ("cache_ttl_min",    d->cache_ttl_min);
    DNS_BOOL("doh_enabled",      d->doh_enabled);
    DNS_STR ("doh_url",          d->doh_url);
    DNS_BOOL("dot_enabled",      d->dot_enabled);
    DNS_BOOL("fake_ip_enabled",  d->fake_ip_enabled);
    DNS_STR ("fake_ip_range",    d->fake_ip_range);
    DNS_BOOL("fake_ip6_enabled", d->fake_ip6_enabled);
    DNS_STR ("fake_ip_range_v6", d->fake_ip6_range);
    DNS_BOOL("block_ads",        d->block_geosite_ads);
    DNS_BOOL("block_trackers",   d->block_geosite_trackers);
    DNS_BOOL("block_threats",    d->block_geosite_threats);
    DNS_BOOL("stale_while_revalidate", d->stale_while_revalidate);
    DNS_INT ("stale_grace_seconds",    d->stale_grace_seconds);
    DNS_STR ("geo_profile",      s_cfg->geo_profile);
    /* DoH детали */
    DNS_STR ("doh_sni",          d->doh_sni);
    DNS_STR ("doh_ip",           d->doh_ip);
    DNS_INT ("doh_port",         d->doh_port);
    /* DoT детали */
    DNS_STR ("dot_server_ip",    d->dot_server_ip);
    DNS_STR ("dot_sni",          d->dot_sni);
    DNS_INT ("dot_port",         d->dot_port);
    /* DoQ */
    DNS_BOOL("doq_enabled",      d->doq_enabled);
    DNS_STR ("doq_server_ip",    d->doq_server_ip);
    DNS_INT ("doq_port",         d->doq_server_port);
    DNS_STR ("doq_sni",          d->doq_sni);
    /* Query opts */
    DNS_INT ("upstream_timeout_ms",  d->upstream_timeout_ms);
    DNS_INT ("fallback_timeout_ms",  d->fallback_timeout_ms);
    DNS_INT ("tolerance_ms",         d->tolerance_ms);
    DNS_BOOL("parallel_query",       d->parallel_query);
    DNS_STR ("bogus_nxdomain",       d->bogus_nxdomain);

#undef DNS_STR
#undef DNS_INT
#undef DNS_BOOL

    /* Убрать trailing запятую */
    if (pos > 1 && buf[pos - 1] == ',') pos--;
    if (pos + 2 < max) buf[pos++] = '}';
    buf[pos] = '\0';

    FILE *f = fopen("/tmp/4eburnet-dns.json.tmp", "w");
    if (!f) return;
    fwrite(buf, 1, (size_t)pos, f);
    fclose(f);
    rename("/tmp/4eburnet-dns.json.tmp", "/tmp/4eburnet-dns.json");
}

/* ── /api/dns — DNS настройки из кэша /tmp ──────────────────────── */
static void route_api_dns(HttpConn *conn, int epoll_fd)
{
    route_ipc_passthrough(conn, epoll_fd, "dns");
}

/* Выделить строку JSON-поля {"key":"..."} → скопировать в out.
 * Возвращает 0 при успехе. */
static int json_extract_str(const char *json, const char *key,
                             char *out, size_t out_size)
{
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_size - 1)
        out[i++] = *p++;
    out[i] = '\0';
    return (*p == '"') ? 0 : -1;
}

/* ── GET /api/dns/upstream ───────────────────────────────────────── */
static void route_api_dns_upstream_get(HttpConn *conn, int epoll_fd)
{
    char body[256];
    const char *ip = (s_cfg && s_cfg->dns.upstream_bypass[0])
                     ? s_cfg->dns.upstream_bypass : "";
    int n = snprintf(body, sizeof(body), "{\"ip\":\"%s\"}", ip);
    http_send(conn, epoll_fd, 200, "application/json", body, (size_t)n);
}

/* ── PATCH /api/dns/upstream ─────────────────────────────────────── */
static void route_api_dns_upstream_patch(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) goto bad;
    const char *body = hdr_end + 4;

    char ip[64] = {0};
    if (json_extract_str(body, "ip", ip, sizeof(ip)) < 0) goto bad;

    struct in_addr  v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, ip, &v4) != 1 && inet_pton(AF_INET6, ip, &v6) != 1)
        goto bad;

    /* WHY: exec_cmd_safe argv — нет shell injection, consistency с остальными UCI вызовами.
     * ip уже валидирован inet_pton выше — только цифры/точки/двоеточия. */
    {
        char uci_val[128];
        snprintf(uci_val, sizeof(uci_val), "4eburnet.dns.upstream_bypass=%s", ip);
        const char *set_argv[]    = {"uci", "set", uci_val, NULL};
        const char *commit_argv[] = {"uci", "commit", "4eburnet", NULL};
        exec_cmd_safe(set_argv,    NULL, 0);
        exec_cmd_safe(commit_argv, NULL, 0);
    }

    /* Обновить в памяти — намеренный const cast, объект mutable в main.c */
    if (s_cfg)
        snprintf(((EburNetConfig *)s_cfg)->dns.upstream_bypass,
                 sizeof(s_cfg->dns.upstream_bypass), "%s", ip);

    const char ok[] = "{\"ok\":true}";
    http_send(conn, epoll_fd, 200, "application/json", ok, sizeof(ok) - 1);
    return;
bad:;
    const char err[] = "{\"ok\":false,\"error\":\"invalid ip\"}";
    http_send(conn, epoll_fd, 400, "application/json", err, sizeof(err) - 1);
}

/* ── POST /api/dns/upstream/test ─────────────────────────────────── */
static void route_api_dns_upstream_test(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) goto bad;
    const char *body = hdr_end + 4;

    char ip[64] = {0};
    if (json_extract_str(body, "ip", ip, sizeof(ip)) < 0 || !ip[0]) {
        /* Нет IP в теле — тестируем текущий upstream_bypass */
        if (!s_cfg || !s_cfg->dns.upstream_bypass[0]) goto bad;
        snprintf(ip, sizeof(ip), "%s", s_cfg->dns.upstream_bypass);
    } else {
        struct in_addr  v4;
        struct in6_addr v6;
        if (inet_pton(AF_INET, ip, &v4) != 1 && inet_pton(AF_INET6, ip, &v6) != 1)
            goto bad;
    }

    int fds[2];
    if (pipe(fds) < 0) goto bad;

    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); goto bad; }
    if (pid == 0) {
        close(fds[0]);
        char out_ip[64]; int family;
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        int rc = net_resolve_host_direct("google.com", ip, out_ip, sizeof(out_ip), &family);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        if (rc == 0) {
            int64_t ms = (int64_t)(t2.tv_sec  - t1.tv_sec)  * 1000
                       + (int64_t)(t2.tv_nsec - t1.tv_nsec) / 1000000;
            char buf[64];
            int n = snprintf(buf, sizeof(buf), "OK %lld\n", (long long)ms);
            write(fds[1], buf, (size_t)n);
        } else {
            write(fds[1], "ERR\n", 4);
        }
        _exit(0);
    }
    close(fds[1]);

    char rbuf[64] = {0};
    struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
    ssize_t rn = -1;
    if (poll(&pfd, 1, 5000) > 0)
        rn = read(fds[0], rbuf, sizeof(rbuf) - 1);
    close(fds[0]);
    waitpid(pid, NULL, 0);

    char result[128];
    int n;
    if (rn > 0 && strncmp(rbuf, "OK", 2) == 0) {
        long long ms = atoll(rbuf + 3);
        n = snprintf(result, sizeof(result),
                     "{\"ok\":true,\"latency_ms\":%lld}", ms);
    } else {
        n = snprintf(result, sizeof(result),
                     "{\"ok\":false,\"error\":\"timeout or unreachable\"}");
    }
    http_send(conn, epoll_fd, 200, "application/json", result, (size_t)n);
    return;
bad:;
    const char err[] = "{\"ok\":false,\"error\":\"invalid request\"}";
    http_send(conn, epoll_fd, 400, "application/json", err, sizeof(err) - 1);
}

/* ── Mapping UCI server.protocol → Clash type name ──────────────── */
static const char *uci_type_to_clash(const char *uci_type)
{
    if (!uci_type || !uci_type[0]) return "Unknown";
    if (!strcmp(uci_type, "awg") || !strcmp(uci_type, "wg") ||
        !strcmp(uci_type, "wireguard")) return "WireGuard";
    if (!strcmp(uci_type, "vless"))     return "Vless";
    if (!strcmp(uci_type, "vmess"))     return "Vmess";
    if (!strcmp(uci_type, "trojan"))    return "Trojan";
    if (!strcmp(uci_type, "ss") || !strcmp(uci_type, "shadowsocks") ||
        !strcmp(uci_type, "ss2022"))    return "Shadowsocks";
    if (!strcmp(uci_type, "hy2") || !strcmp(uci_type, "hysteria2"))
        return "Hysteria2";
    if (!strcmp(uci_type, "anytls"))
        return "anytls";
    /* WHY: zashboard распознаёт "tuic" тип (v1.5.173 транспорт). */
    if (!strcmp(uci_type, "tuic") || !strcmp(uci_type, "tuic5"))
        return "tuic";
    if (!strcmp(uci_type, "stls") || !strcmp(uci_type, "shadowtls"))
        return "ShadowTLS";
    return "Unknown";
}

/* ── Mapping нашего transport → Clash network field ─────────────── */
static const char *transport_to_clash_network(const char *t)
{
    if (!t || !t[0] || !strcmp(t, "raw") || !strcmp(t, "reality")) return "tcp";
    if (!strcmp(t, "grpc"))   return "grpc";
    if (!strcmp(t, "ws"))     return "ws";
    if (!strcmp(t, "xhttp") || !strcmp(t, "httpupgrade")) return "xhttp";
    return "tcp";
}

/* ── Mapping proxy_group_type_t → Clash group type ──────────────── */
static const char *uci_group_to_clash(int type)
{
    switch (type) {
        case 0: return "Selector";
        case 1: return "URLTest";
        case 2: return "Fallback";
        case 3: return "LoadBalance";
        case 4: return "fastest-whitelist";
        default: return "Selector";
    }
}

/* ─── /storage/zashboard ────────────────────────────────────────────
 * Persistence для user-настроек дашборда (тема, колонки, sort).
 * Без этого endpoint zashboard на каждом F5 сбрасывает настройки.
 * Хранилище: /etc/4eburnet/zashboard.json (persistent между рестартами).
 * GET → читаем файл, PUT → перезаписываем тело, DELETE → unlink. */
#define ZASHBOARD_STORAGE_PATH "/etc/4eburnet/zashboard.json"
#define ZASHBOARD_STORAGE_MAX  (256 * 1024)  /* 256 KB достаточно для prefs */

static void route_zashboard_storage(HttpConn *conn, int epoll_fd)
{
    if (conn->is_delete) {
        unlink(ZASHBOARD_STORAGE_PATH);
        const char ok[] = "{}";
        http_send(conn, epoll_fd, 200, "application/json", ok, sizeof(ok) - 1);
        return;
    }
    if (conn->is_put) {
        const char *body = strstr(conn->buf, "\r\n\r\n");
        if (!body) {
            const char e[] = "{\"message\":\"missing body\"}";
            http_send(conn, epoll_fd, 400, "application/json", e, sizeof(e) - 1);
            return;
        }
        body += 4;
        int body_len = conn->content_length > 0
            ? conn->content_length
            : (int)(conn->buf + conn->buf_len - body);
        if (body_len < 0) body_len = 0;
        if (body_len > ZASHBOARD_STORAGE_MAX) body_len = ZASHBOARD_STORAGE_MAX;
        FILE *f = fopen(ZASHBOARD_STORAGE_PATH, "w");
        if (!f) {
            const char e[] = "{\"message\":\"storage write failed\"}";
            http_send(conn, epoll_fd, 500, "application/json", e, sizeof(e) - 1);
            return;
        }
        if (body_len > 0) fwrite(body, 1, (size_t)body_len, f);
        fclose(f);
        const char ok[] = "{}";
        http_send(conn, epoll_fd, 200, "application/json", ok, sizeof(ok) - 1);
        return;
    }
    /* GET: вернуть содержимое или пустой объект если файла нет */
    FILE *f = fopen(ZASHBOARD_STORAGE_PATH, "r");
    if (!f) {
        const char empty[] = "{}";
        http_send(conn, epoll_fd, 200, "application/json", empty, sizeof(empty) - 1);
        return;
    }
    char *buf = malloc(ZASHBOARD_STORAGE_MAX);
    if (!buf) {
        fclose(f);
        const char e[] = "{\"message\":\"oom\"}";
        http_send(conn, epoll_fd, 500, "application/json", e, sizeof(e) - 1);
        return;
    }
    size_t n = fread(buf, 1, ZASHBOARD_STORAGE_MAX, f);
    fclose(f);
    if (n == 0) {
        free(buf);
        const char empty[] = "{}";
        http_send(conn, epoll_fd, 200, "application/json", empty, sizeof(empty) - 1);
        return;
    }
    http_send(conn, epoll_fd, 200, "application/json", buf, n);
    free(buf);
}

/* ─── GET /monitor — standalone HTML страница мониторинга ───────────
 * Открывается в новом окне браузера: http://router:8080/monitor
 * Показывает WS /logs + /traffic + /connections в реальном времени.
 * WHY: нужна при geo update, reload, subscribe import — наблюдение
 * за процессом без перехода в основной дашборд. */
static void route_monitor(HttpConn *conn, int epoll_fd)
{
    static const char MONITOR_HTML[] =
"<!DOCTYPE html>\n"
"<html lang='ru'>\n"
"<head>\n"
"<meta charset='UTF-8'>\n"
"<title>4eburNet Monitor</title>\n"
"<style>\n"
"body{background:#0d1117;color:#c9d1d9;font-family:monospace;margin:0;padding:8px}\n"
"h3{color:#58a6ff;margin:4px 0;font-size:14px}\n"
".panel{background:#161b22;border:1px solid #30363d;border-radius:6px;"
"padding:8px;margin-bottom:8px;height:220px;overflow-y:auto}\n"
".le{margin:1px 0;font-size:12px;line-height:1.4}\n"
".le.error{color:#f85149}.le.warn{color:#e3b341}.le.info{color:#3fb950}\n"
".metric{display:inline-block;margin-right:16px;font-size:13px}\n"
".metric span{color:#58a6ff;font-weight:bold}\n"
"button{background:#21262d;border:1px solid #30363d;color:#c9d1d9;"
"padding:4px 12px;border-radius:6px;cursor:pointer;font-size:12px}\n"
"button:hover{background:#30363d}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<div style='display:flex;justify-content:space-between;align-items:center'>\n"
"<h2 style='color:#58a6ff;margin:0'>4eburNet Monitor</h2>\n"
"<div>\n"
"<button onclick='clearAll()'>Очистить</button>\n"
"<button onclick='togglePause()' id='pauseBtn'>Пауза</button>\n"
"</div>\n"
"</div>\n"
"<div style='margin:8px 0'>\n"
"<span class='metric'>&#8593; <span id='up'>0</span> KB/s</span>\n"
"<span class='metric'>&#8595; <span id='dn'>0</span> KB/s</span>\n"
"<span class='metric'>Соед: <span id='cc'>0</span></span>\n"
"<span class='metric'>DNS: <span id='dq'>0</span></span>\n"
"<span class='metric'>Блок: <span id='db'>0</span></span>\n"
"</div>\n"
"<h3>Системные логи</h3>\n"
"<div class='panel' id='logPanel'></div>\n"
"<h3>Активные соединения</h3>\n"
"<div class='panel' id='connPanel'></div>\n"
"<script>\n"
"var paused=false,lp=document.getElementById('logPanel'),cp=document.getElementById('connPanel');\n"
"function addLog(t,lv){if(paused)return;var d=document.createElement('div');\n"
"d.className='le '+(lv||'info');\n"
"d.textContent=new Date().toTimeString().slice(0,8)+' '+t;\n"
"lp.appendChild(d);if(lp.children.length>200)lp.removeChild(lp.firstChild);\n"
"lp.scrollTop=lp.scrollHeight;}\n"
"function clearAll(){lp.innerHTML='';cp.innerHTML='';}\n"
"function togglePause(){paused=!paused;document.getElementById('pauseBtn').textContent=paused?'Возобновить':'Пауза';}\n"
"function conn(path,onmsg,onclose){\n"
"var ws=new WebSocket('ws://'+location.host+path);\n"
"ws.onmessage=onmsg;ws.onclose=function(){setTimeout(function(){conn(path,onmsg,onclose);},2000)};return ws;}\n"
"conn('/logs',function(e){try{var d=JSON.parse(e.data);\n"
"var lv=(d.type||'').toLowerCase();lv=lv==='error'?'error':lv==='warning'||lv==='warn'?'warn':'info';\n"
"addLog('['+(d.type||'INFO')+'] '+(d.payload||d.message||e.data),lv);}catch(x){addLog(e.data,'info');}});\n"
"conn('/traffic',function(e){try{var d=JSON.parse(e.data);\n"
"document.getElementById('up').textContent=((d.up||0)/1024).toFixed(1);\n"
"document.getElementById('dn').textContent=((d.down||0)/1024).toFixed(1);}catch(x){}});\n"
"conn('/connections',function(e){try{var d=JSON.parse(e.data),cs=d.connections||[];\n"
"document.getElementById('cc').textContent=cs.length;\n"
"if(!paused){cp.innerHTML='';cs.slice(0,50).forEach(function(c){\n"
"var div=document.createElement('div'),m=c.metadata||{};\n"
"div.className='le info';\n"
"div.textContent=(m.host||m.destinationIP||'?')+':'+(m.destinationPort||'?')+\n"
"' -> '+(c.chains||[]).join('->')+\n"
"' ^'+((c.upload||0)/1024).toFixed(0)+'KB'+\n"
"' v'+((c.download||0)/1024).toFixed(0)+'KB';\n"
"cp.appendChild(div);});}}catch(x){}});\n"
"function updateDns(){fetch('/api/dns/stats').then(function(r){return r.json();}).then(function(d){\n"
"document.getElementById('dq').textContent=d.queries||0;\n"
"document.getElementById('db').textContent=d.blocked||0;}).catch(function(){});\n"
"setTimeout(updateDns,5000);}\n"
"updateDns();\n"
"addLog('Monitor запущен','info');\n"
"</script>\n"
"</body>\n"
"</html>\n";

    http_send(conn, epoll_fd, 200, "text/html; charset=utf-8",
              MONITOR_HTML, sizeof(MONITOR_HTML) - 1);
}

/* ─── Clash API compat: GET /version ────────────────────────────────
 * zashboard /setup проверяет этот endpoint для validation backend.
 * Возвращаем 4eburnet version, маркируем как mihomo-meta-compatible. */
static void route_clash_version(HttpConn *conn, int epoll_fd)
{
    char body[256];
    int n = snprintf(body, sizeof(body),
        "{\"version\":\"4eburnet-%s\",\"premium\":false,\"meta\":true}",
        EBURNET_VERSION);
    http_send(conn, epoll_fd, 200, "application/json; charset=utf-8",
              body, (size_t)n);
}

/* ─── Clash API compat: GET /configs ────────────────────────────────
 * Минимальный shape для zashboard settings page.
 * Читаем живые данные из s_cfg (pre-parsed UCI).
 * PATCH /configs — Phase 2 Group 3 (write support). */
static void route_clash_configs(HttpConn *conn, int epoll_fd)
{
    const char *loglvl = "info";
    if (s_cfg && s_cfg->log_level[0]) {
        if (!strcasecmp(s_cfg->log_level, "debug"))       loglvl = "debug";
        else if (!strcasecmp(s_cfg->log_level, "warn"))   loglvl = "warning";
        else if (!strcasecmp(s_cfg->log_level, "error"))  loglvl = "error";
        else if (!strcasecmp(s_cfg->log_level, "silent")) loglvl = "silent";
        else                                              loglvl = "info";
    }

    const char *mode = "rule";
    if (s_cfg && s_cfg->mode[0]) {
        if (!strcasecmp(s_cfg->mode, "global"))      mode = "global";
        else if (!strcasecmp(s_cfg->mode, "direct")) mode = "direct";
        else                                          mode = "rule";
    }

    char esc_uname[128] = "";
    if (s_cfg && s_cfg->inbound_username[0])
        json_escape_str(s_cfg->inbound_username, esc_uname, sizeof(esc_uname));

    /* статически в BSS — 896B > MIPS stack limit 512B */
    static char body[896];
    int n = snprintf(body, sizeof(body),
        "{\"port\":0,"
         "\"socks-port\":0,"
         "\"redir-port\":0,"
         "\"tproxy-port\":%u,"
         "\"mixed-port\":0,"
         "\"authentication\":[],"
         "\"allow-lan\":true,"
         "\"bind-address\":\"*\","
         "\"mode\":\"%s\","
         "\"log-level\":\"%s\","
         "\"ipv6\":false,"
         "\"secret\":\"\","
         "\"tun\":{\"enable\":false},"
         "\"inbound_auth\":%s,"
         "\"inbound_username\":\"%s\"}",
        /* WHY: NFT_TPROXY_PORT из nftables.h — единственный source of truth для порта TPROXY. */
        (unsigned)NFT_TPROXY_PORT, mode, loglvl,
        (s_cfg && s_cfg->inbound_auth) ? "true" : "false",
        esc_uname);
    http_send(conn, epoll_fd, 200, "application/json; charset=utf-8",
              body, (size_t)n);
}

/* ─── PATCH /configs — изменить mode или log-level ──────────────────
 * Body: {"mode":"global"} или {"log-level":"debug"}.
 * WHY: zashboard отправляет PATCH /configs при переключении режима
 * в UI. UCI commit + SIGHUP → config_load пересчитывает s_cfg.
 * SIGHUP обязателен для log-level (static в log.c). */
static void route_clash_configs_patch(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) {
        http_send(conn, epoll_fd, 204, "application/json", "", 0);
        return;
    }
    const char *body = hdr_end + 4;
    bool changed = false;

    char mode[32] = {0};
    if (json_extract_str(body, "mode", mode, sizeof(mode)) == 0 && mode[0]) {
        if (!strcmp(mode, "rule") || !strcmp(mode, "global") ||
            !strcmp(mode, "direct")) {
            char uci_arg[48];
            snprintf(uci_arg, sizeof(uci_arg), "4eburnet.main.mode=%s", mode);
            const char *set_argv[]    = {"uci", "set", uci_arg, NULL};
            const char *commit_argv[] = {"uci", "commit", "4eburnet", NULL};
            exec_cmd_safe(set_argv, NULL, 0);
            exec_cmd_safe(commit_argv, NULL, 0);
            if (s_cfg)
                snprintf(((EburNetConfig *)s_cfg)->mode,
                         sizeof(s_cfg->mode), "%s", mode);
            changed = true;
        }
    }

    char loglvl[16] = {0};
    if (json_extract_str(body, "log-level", loglvl, sizeof(loglvl)) == 0
        && loglvl[0]) {
        const char *uci_lvl = NULL;
        if      (!strcmp(loglvl, "debug"))   uci_lvl = "debug";
        else if (!strcmp(loglvl, "info"))    uci_lvl = "info";
        else if (!strcmp(loglvl, "warning")) uci_lvl = "warn";
        else if (!strcmp(loglvl, "error"))   uci_lvl = "error";
        else if (!strcmp(loglvl, "silent"))  uci_lvl = "silent";
        if (uci_lvl) {
            char uci_arg[56];
            snprintf(uci_arg, sizeof(uci_arg),
                     "4eburnet.main.log_level=%s", uci_lvl);
            const char *set_argv[]    = {"uci", "set", uci_arg, NULL};
            const char *commit_argv[] = {"uci", "commit", "4eburnet", NULL};
            exec_cmd_safe(set_argv, NULL, 0);
            exec_cmd_safe(commit_argv, NULL, 0);
            if (s_cfg)
                snprintf(((EburNetConfig *)s_cfg)->log_level,
                         sizeof(s_cfg->log_level), "%s", uci_lvl);
            changed = true;
        }
    }

    char auth_val[8] = {0};
    http_json_get_val(body, "inbound_auth", auth_val, sizeof(auth_val));
    if (auth_val[0]) {
        bool enable = (!strcmp(auth_val, "true") || !strcmp(auth_val, "1"));
        const char *uci_v = enable ? "4eburnet.main.inbound_auth=1"
                                   : "4eburnet.main.inbound_auth=0";
        const char *set_argv[]    = {"uci", "set", uci_v, NULL};
        const char *commit_argv[] = {"uci", "commit", "4eburnet", NULL};
        exec_cmd_safe(set_argv, NULL, 0);
        exec_cmd_safe(commit_argv, NULL, 0);
        if (s_cfg) ((EburNetConfig *)s_cfg)->inbound_auth = enable;
        changed = true;
    }

    char sd_u[64] = {0};
    if (json_extract_str(body, "inbound_username", sd_u, sizeof(sd_u)) == 0
        && sd_u[0]) {
        char uci_arg[80];
        snprintf(uci_arg, sizeof(uci_arg), "4eburnet.main.inbound_username=%s", sd_u);
        const char *set_argv[]    = {"uci", "set", uci_arg, NULL};
        const char *commit_argv[] = {"uci", "commit", "4eburnet", NULL};
        exec_cmd_safe(set_argv, NULL, 0);
        exec_cmd_safe(commit_argv, NULL, 0);
        if (s_cfg) strncpy(((EburNetConfig *)s_cfg)->inbound_username, sd_u,
                           sizeof(s_cfg->inbound_username) - 1);
        changed = true;
    }

    char sd_p[64] = {0};
    if (json_extract_str(body, "inbound_password", sd_p, sizeof(sd_p)) == 0
        && sd_p[0]) {
        char uci_arg[80];
        snprintf(uci_arg, sizeof(uci_arg), "4eburnet.main.inbound_password=%s", sd_p);
        const char *set_argv[]    = {"uci", "set", uci_arg, NULL};
        const char *commit_argv[] = {"uci", "commit", "4eburnet", NULL};
        exec_cmd_safe(set_argv, NULL, 0);
        exec_cmd_safe(commit_argv, NULL, 0);
        if (s_cfg) strncpy(((EburNetConfig *)s_cfg)->inbound_password, sd_p,
                           sizeof(s_cfg->inbound_password) - 1);
        changed = true;
    }

    if (changed)
        kill(getpid(), SIGHUP);
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* Найти latency_ms сервера с unified индексом srv_idx в любой группе pgm.
 * Возвращает первое НЕНУЛЕВОЕ значение из всех групп где встречается srv_idx.
 * WHY: один сервер может быть в нескольких группах, batch HC обновил latency
 * только в одной — другие группы хранят 0. Возврат 0 от первой match скрывает
 * реальную latency если sequence неудачный (например AWG в TELEGRAM с lat=0
 * перед AWG Group с lat=12). */
static uint32_t pgm_server_latency(const proxy_group_manager_t *pgm, int srv_idx)
{
    if (!pgm) return 0;
    for (int g = 0; g < pgm->count; g++) {
        const proxy_group_state_t *gs = &pgm->groups[g];
        for (int i = 0; i < gs->server_count; i++) {
            if (gs->servers[i].server_idx == srv_idx
                && gs->servers[i].latency_ms > 0)
                return gs->servers[i].latency_ms;
        }
    }
    return 0;
}

/* Признак "alive" для сервера (Clash API): true если runtime HC отметил
 * сервер как available хотя бы в одной группе. Сервер без runtime записи
 * (HC ещё не пробежал) → true как у mihomo: до первого HC сервер считается
 * живым по умолчанию, иначе zashboard скрывал бы все серверы при старте. */
static bool pgm_server_alive(const proxy_group_manager_t *pgm, int srv_idx)
{
    if (!pgm) return true;
    bool seen_in_group = false;
    for (int g = 0; g < pgm->count; g++) {
        const proxy_group_state_t *gs = &pgm->groups[g];
        for (int i = 0; i < gs->server_count; i++) {
            if (gs->servers[i].server_idx == srv_idx) {
                seen_in_group = true;
                if (gs->servers[i].available)
                    return true;
            }
        }
    }
    /* В runtime есть запись и ни в одной группе не available → dead */
    return !seen_in_group;
}

/* Возвращает состояние сервера в первой группе где есть HC данные.
 * Предпочитаем запись с непустым ring buffer (ring_pos > 0).
 * WHY: нужен для генерации history[] с latency sparkline в GET /proxies. */
static const group_server_state_t *pgm_server_state(const proxy_group_manager_t *pgm,
                                                     int srv_idx)
{
    if (!pgm) return NULL;
    const group_server_state_t *fallback = NULL;
    for (int g = 0; g < pgm->count; g++) {
        const proxy_group_state_t *gs = &pgm->groups[g];
        for (int i = 0; i < gs->server_count; i++) {
            if (gs->servers[i].server_idx != srv_idx) continue;
            if (gs->servers[i].latency_ring_pos > 0)
                return &gs->servers[i];
            if (!fallback)
                fallback = &gs->servers[i];
        }
    }
    return fallback;
}

/* Группа "alive" если selected_idx валиден и хотя бы один сервер available */
static bool pgm_group_alive(const proxy_group_state_t *gs)
{
    if (!gs || gs->server_count == 0) return true;  /* пустая до HC = alive */
    for (int i = 0; i < gs->server_count; i++)
        if (gs->servers[i].available) return true;
    return false;
}

/* ─── Clash API compat: GET /proxies ────────────────────────────────
 * Главный endpoint для dashboard. Возвращает {"proxies":{...}}
 * где ключ = имя, значение = {name,type,udp,now?,all?,history}.
 *
 * Состав:
 *   - каждая proxy_group → Selector/URLTest/Fallback/LoadBalance
 *   - каждый server (main + provider_servers) → тип по protocol
 *   - DIRECT, REJECT — встроенные meta-прокси
 *   - GLOBAL — корневой Selector со всеми группами + DIRECT/REJECT
 *
 * Buffer — static 64KB. Покрывает конфиги с 64+ provider серверами. */
static void route_clash_proxies(HttpConn *conn, int epoll_fd)
{
    static char buf[262144];
    int pos = 0, max = (int)sizeof(buf);
    int first = 1;

    if (!s_cfg) {
        const char empty[] = "{\"proxies\":{}}";
        http_send(conn, epoll_fd, 200, "application/json; charset=utf-8",
                  empty, sizeof(empty) - 1);
        return;
    }

    pos += snprintf(buf + pos, (size_t)(max - pos), "{\"proxies\":{");

#define EMIT_KV_SEP() do { \
    if (!first && pos + 1 < max) buf[pos++] = ','; \
    first = 0; \
} while (0)

    /* ── Групп ── */
    for (int g = 0; g < s_cfg->proxy_group_count && pos < max - 512; g++) {
        const ProxyGroupConfig *grp = &s_cfg->proxy_groups[g];
        if (!grp->name[0]) continue;

        EMIT_KV_SEP();
        pos = json_append_str(buf, pos, max, grp->name);
        pos += snprintf(buf + pos, (size_t)(max - pos), ":{\"name\":");
        pos = json_append_str(buf, pos, max, grp->name);

        /* "now" — выбранный сервер из runtime state (selected_idx),
         * fallback на первый сервер статического конфига */
        proxy_group_state_t *gs = s_pgm
            ? proxy_group_find(s_pgm, grp->name) : NULL;
        bool grp_alive = pgm_group_alive(gs);
        pos += snprintf(buf + pos, (size_t)(max - pos),
            ",\"type\":\"%s\",\"udp\":true,\"alive\":%s,\"history\":[]"
            ",\"interval\":%d,\"tolerance\":%d",
            uci_group_to_clash((int)grp->type),
            grp_alive ? "true" : "false",
            grp->interval, grp->tolerance_ms);
        if (grp->url[0]) {
            pos += snprintf(buf + pos, (size_t)(max - pos), ",\"testUrl\":");
            pos = json_append_str(buf, pos, max, grp->url);
        }
        if (grp->filter[0]) {
            pos += snprintf(buf + pos, (size_t)(max - pos), ",\"filter\":");
            pos = json_append_str(buf, pos, max, grp->filter);
        }
        /* strategy возвращается только для load-balance групп */
        if (grp->type == PROXY_GROUP_LOAD_BALANCE) {
            const char *strat = grp->load_balance_strategy[0]
                                ? grp->load_balance_strategy : "round-robin";
            pos += snprintf(buf + pos, (size_t)(max - pos), ",\"strategy\":");
            pos = json_append_str(buf, pos, max, strat);
        }
        pos += snprintf(buf + pos, (size_t)(max - pos), ",\"now\":");

        const char *now_name = proxy_group_get_current(gs, s_cfg);
        if (!now_name[0] && grp->server_count > 0 && grp->servers && grp->servers[0])
            now_name = grp->servers[0];
        pos = json_append_str(buf, pos, max, now_name);

        /* "all": [...] — из runtime state, включает provider_servers.
         * WHY: grp->servers[] содержит только UCI-статические серверы;
         * провайдерские серверы хранятся в cfg->provider_servers[] и
         * линкуются через gs->servers[].server_idx (unified индекс). */
        pos += snprintf(buf + pos, (size_t)(max - pos), ",\"all\":[");
        int all_first = 1;
        if (gs && gs->server_count > 0) {
            for (int i = 0; i < gs->server_count && pos < max - 64; i++) {
                const ServerConfig *sc =
                    config_get_server(s_cfg, gs->servers[i].server_idx);
                if (!sc || !sc->name[0]) continue;
                if (!all_first && pos + 1 < max) buf[pos++] = ',';
                all_first = 0;
                pos = json_append_str(buf, pos, max, sc->name);
            }
        } else {
            /* Fallback: pgm не инициализирован — статические серверы конфига */
            for (int i = 0; i < grp->server_count && pos < max - 64; i++) {
                if (!grp->servers[i]) continue;
                if (!all_first && pos + 1 < max) buf[pos++] = ',';
                all_first = 0;
                pos = json_append_str(buf, pos, max, grp->servers[i]);
            }
        }
        if (pos + 2 < max) { buf[pos++] = ']'; buf[pos++] = '}'; }
    }

    /* ── Серверы ── */
    int total_srv = s_cfg->server_count + s_cfg->provider_server_count;
    for (int i = 0; i < total_srv && pos < max - 256; i++) {
        const ServerConfig *sc = config_get_server(s_cfg, i);
        if (!sc || !sc->name[0]) continue;

        EMIT_KV_SEP();
        pos = json_append_str(buf, pos, max, sc->name);
        pos += snprintf(buf + pos, (size_t)(max - pos), ":{\"name\":");
        pos = json_append_str(buf, pos, max, sc->name);
        bool alive  = pgm_server_alive(s_pgm, i);
        const char *net = transport_to_clash_network(sc->transport);
        /* Mihomo Clash API: отдельное поле "xudp":true для серверов с
         * packet-encoding=xudp. Zashboard использует его для тега XUDP. */
        const char *xudp_kv = (sc->packet_encoding[0] &&
                               strcmp(sc->packet_encoding, "xudp") == 0)
                              ? ",\"xudp\":true" : "";
        /* WHY: zashboard распознаёт "anytls":true, "tuic":true и "awg":true как теги
         * протокола (аналогично xudp). */
        const char *anytls_kv = (strcmp(sc->protocol, "anytls") == 0)
                                ? ",\"anytls\":true" : "";
        const char *tuic_kv   = (strcmp(sc->protocol, "tuic") == 0 ||
                                 strcmp(sc->protocol, "tuic5") == 0)
                                ? ",\"tuic\":true" : "";
        const char *awg_kv    = (strcmp(sc->protocol, "awg") == 0 ||
                                 strcmp(sc->protocol, "wg") == 0)
                                ? ",\"awg\":true" : "";
        /* Генерируем history[] из ring buffer (до 20 точек для sparkline).
         * lat==0 или lat==UINT32_MAX → сервер не тестировался или провалил HC. */
        const group_server_state_t *srv_st = pgm_server_state(s_pgm, i);
        int filled = srv_st ? (int)(srv_st->latency_ring_pos < 20
                                   ? (int)srv_st->latency_ring_pos : 20) : 0;
        pos += snprintf(buf + pos, (size_t)(max - pos),
            ",\"type\":\"%s\",\"network\":\"%s\",\"udp\":true%s%s%s%s,\"alive\":%s,\"history\":[",
            uci_type_to_clash(sc->protocol), net, xudp_kv, anytls_kv, tuic_kv,
            awg_kv, alive ? "true" : "false");
        if (filled > 0 && srv_st) {
            time_t now_ts = time(NULL);
            /* Начальная позиция кольца: если заполнен полностью — от ring_pos,
             * иначе — от 0. Элементы от старых к новым. */
            int ring_start = (srv_st->latency_ring_pos < 20)
                             ? 0 : (int)(srv_st->latency_ring_pos % 20);
            int hist_first = 1;
            for (int hi = 0; hi < filled && pos < max - 72; hi++) {
                int ring_idx = (ring_start + hi) % 20;
                uint16_t delay = srv_st->latency_ring[ring_idx];
                /* Приближённое время: 30с между HC (зазор между точками) */
                time_t pts = now_ts - (time_t)((filled - 1 - hi) * 30);
                char tsbuf[28];
                struct tm *ptm = gmtime(&pts);
                strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%dT%H:%M:%SZ", ptm);
                pos += snprintf(buf + pos, (size_t)(max - pos),
                    "%s{\"time\":\"%s\",\"delay\":%u}",
                    hist_first ? "" : ",", tsbuf, (unsigned)delay);
                hist_first = 0;
            }
        }
        if (pos + 2 < max) { buf[pos++] = ']'; buf[pos++] = '}'; }
    }

    /* ── DIRECT ── */
    if (pos < max - 128) {
        EMIT_KV_SEP();
        pos += snprintf(buf + pos, (size_t)(max - pos),
            "\"DIRECT\":{\"name\":\"DIRECT\",\"type\":\"Direct\","
            "\"udp\":true,\"alive\":true,\"history\":[]}");
    }

    /* ── REJECT ── */
    if (pos < max - 128) {
        EMIT_KV_SEP();
        pos += snprintf(buf + pos, (size_t)(max - pos),
            "\"REJECT\":{\"name\":\"REJECT\",\"type\":\"Reject\","
            "\"udp\":false,\"alive\":true,\"history\":[]}");
    }

    /* ── GLOBAL — все группы + DIRECT + REJECT ── */
    if (pos < max - 512 && s_cfg->proxy_group_count > 0) {
        const char *first_grp = s_cfg->proxy_groups[0].name;
        EMIT_KV_SEP();
        pos += snprintf(buf + pos, (size_t)(max - pos),
            "\"GLOBAL\":{\"name\":\"GLOBAL\",\"type\":\"Selector\","
            "\"udp\":true,\"alive\":true,\"history\":[],\"now\":");
        pos = json_append_str(buf, pos, max, first_grp);
        pos += snprintf(buf + pos, (size_t)(max - pos), ",\"all\":[");
        for (int g = 0; g < s_cfg->proxy_group_count; g++) {
            if (g > 0 && pos + 1 < max) buf[pos++] = ',';
            pos = json_append_str(buf, pos, max,
                                  s_cfg->proxy_groups[g].name);
            if (pos >= max - 64) break;
        }
        pos += snprintf(buf + pos, (size_t)(max - pos),
                        ",\"DIRECT\",\"REJECT\"]}");
    }

#undef EMIT_KV_SEP

    /* Закрыть objects */
    if (pos + 2 < max) { buf[pos++] = '}'; buf[pos++] = '}'; }
    buf[pos] = '\0';

    http_send(conn, epoll_fd, 200, "application/json; charset=utf-8",
              buf, (size_t)pos);
}

/* ─── Clash API compat: GET /rules ─────────────────────────────── */
static const char *rule_type_to_str(rule_type_t t)
{
    switch (t) {
    case RULE_TYPE_DOMAIN:         return "DOMAIN";
    case RULE_TYPE_DOMAIN_SUFFIX:  return "DOMAIN-SUFFIX";
    case RULE_TYPE_DOMAIN_KEYWORD: return "DOMAIN-KEYWORD";
    case RULE_TYPE_IP_CIDR:        return "IP-CIDR";
    case RULE_TYPE_IP_CIDR6:       return "IP-CIDR6";
    case RULE_TYPE_RULE_SET:       return "RULE-SET";
    case RULE_TYPE_MATCH:          return "MATCH";
    case RULE_TYPE_GEOIP:          return "GEOIP";
    case RULE_TYPE_GEOSITE:        return "GEOSITE";
    case RULE_TYPE_DST_PORT:       return "DST-PORT";
    case RULE_TYPE_SRC_PORT:       return "SRC-PORT";
    case RULE_TYPE_PROCESS_NAME:   return "PROCESS-NAME";
    case RULE_TYPE_AND:            return "AND";
    case RULE_TYPE_OR:             return "OR";
    case RULE_TYPE_REGEX:          return "REGEX";
    default:                       return "UNKNOWN";
    }
}

static void route_clash_rules(HttpConn *conn, int epoll_fd)
{
    /* WHY 131072: 399 правил × ~200 байт (extra + sub_conditions) ≈ 80KB;
     * старые 32KB обрезали список на 227/399. */
    static char buf[131072];
    int pos = 0, max = (int)sizeof(buf);

    if (!s_cfg || s_cfg->traffic_rule_count == 0) {
        const char empty[] = "{\"rules\":[]}";
        http_send(conn, epoll_fd, 200, "application/json; charset=utf-8",
                  empty, sizeof(empty) - 1);
        return;
    }

    pos += snprintf(buf + pos, (size_t)(max - pos), "{\"rules\":[");
    for (int i = 0; i < s_cfg->traffic_rule_count && pos < max - 256; i++) {
        const TrafficRule *r = &s_cfg->traffic_rules[i];
        if (i > 0 && pos + 1 < max) buf[pos++] = ',';

        /* payload: для OR — строим из sub_rules; иначе — r->value */
        pos += snprintf(buf + pos, (size_t)(max - pos),
                        "{\"type\":\"%s\",\"payload\":",
                        rule_type_to_str(r->type));
        if (r->type == RULE_TYPE_OR && r->sub_rules && r->sub_count > 0) {
            /* OR payload = "TYPE1:VALUE1,TYPE2:VALUE2,..." */
            static char or_payload[512];
            int pp = 0;
            for (uint8_t si = 0; si < r->sub_count && pp < (int)sizeof(or_payload) - 64; si++) {
                const TrafficRule *sub = &r->sub_rules[si];
                if (si > 0) or_payload[pp++] = ',';
                pp += snprintf(or_payload + pp, sizeof(or_payload) - (size_t)pp,
                               "%s:%s", rule_type_to_str(sub->type), sub->value);
            }
            or_payload[pp] = '\0';
            pos = json_append_str(buf, pos, max, or_payload);
        } else {
            pos = json_append_str(buf, pos, max, r->value);
        }
        pos += snprintf(buf + pos, (size_t)(max - pos), ",\"proxy\":");
        pos = json_append_str(buf, pos, max, r->target);

        /* sub_conditions для OR — для редактирования в dashboard */
        if (r->type == RULE_TYPE_OR && r->sub_rules && r->sub_count > 0) {
            pos += snprintf(buf + pos, (size_t)(max - pos), ",\"sub_conditions\":[");
            for (uint8_t si = 0; si < r->sub_count && pos < max - 128; si++) {
                const TrafficRule *sub = &r->sub_rules[si];
                if (si > 0 && pos + 1 < max) buf[pos++] = ',';
                pos += snprintf(buf + pos, (size_t)(max - pos),
                                "{\"type\":\"%s\",\"value\":",
                                rule_type_to_str(sub->type));
                pos = json_append_str(buf, pos, max, sub->value);
                if (pos + 1 < max) buf[pos++] = '}';
            }
            if (pos + 1 < max) buf[pos++] = ']';
        }

        /* hit_count из sorted_rules (с атомарным счётчиком) */
        uint32_t hits = 0;
        if (s_re && s_re->sorted_rules) {
            /* sorted_rules — копия с индексами в другом порядке;
             * ищем по type+target для совпадения с текущим правилом cfg */
            for (int j = 0; j < s_re->rule_count; j++) {
                const TrafficRule *sr = &s_re->sorted_rules[j];
                if (sr->type == r->type &&
                    strcmp(sr->target, r->target) == 0 &&
                    strcmp(sr->value,  r->value)  == 0) {
                    hits = (uint32_t)atomic_load(&sr->hit_count);
                    break;
                }
            }
        }
        pos += snprintf(buf + pos, (size_t)(max - pos),
                        ",\"extra\":{\"hitCount\":%u,\"hitAt\":\"\","
                        "\"missAt\":\"\",\"missCount\":0,\"disabled\":false}",
                        hits);

        if (pos + 1 < max) buf[pos++] = '}';
    }
    if (pos + 2 < max) { buf[pos++] = ']'; buf[pos++] = '}'; }
    buf[pos] = '\0';

    http_send(conn, epoll_fd, 200, "application/json; charset=utf-8",
              buf, (size_t)pos);
}

/* ─── PATCH /rules/disable — переключить все правила ────────────────
 * WHY: zashboard кнопка "Disable Rules" = временный bypass mode.
 * Читаем текущий UCI rules_enabled, инвертируем, сохраняем. */
static void route_clash_rules_disable(HttpConn *conn, int epoll_fd)
{
    char cur[4] = {0};
    {
        FILE *f = popen("uci -q get 4eburnet.main.rules_enabled 2>/dev/null", "r");
        if (f) {
            if (fgets(cur, sizeof(cur), f))
                cur[strcspn(cur, "\r\n")] = '\0';
            pclose(f);
        }
    }
    /* Если не задано или "1" → отключить ("0"), иначе → включить ("1") */
    const char *new_val = (!cur[0] || strcmp(cur, "1") == 0) ? "0" : "1";
    char uci_arg[48];
    snprintf(uci_arg, sizeof(uci_arg),
             "4eburnet.main.rules_enabled=%s", new_val);
    const char *set_argv[]    = {"uci", "set", uci_arg, NULL};
    const char *commit_argv[] = {"uci", "commit", "4eburnet", NULL};
    exec_cmd_safe(set_argv, NULL, 0);
    exec_cmd_safe(commit_argv, NULL, 0);
    reload_daemon();
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ─── Clash API compat: GET /providers/proxies ─────────────────── */
static void route_clash_providers_proxies(HttpConn *conn, int epoll_fd)
{
    static char buf[16384];
    int pos = 0, max = (int)sizeof(buf);

    pos += snprintf(buf + pos, (size_t)(max - pos), "{\"providers\":{");

    if (s_cfg) {
        for (int i = 0; i < s_cfg->proxy_provider_count && pos < max - 256; i++) {
            const ProxyProviderConfig *p = &s_cfg->proxy_providers[i];
            if (!p->enabled || !p->name[0]) continue;
            const char *vtype = (p->type == PROXY_PROVIDER_URL) ? "HTTP" : "File";
            const char *ptype = (p->type == PROXY_PROVIDER_URL) ? "http" : "file";
            if (i > 0 && pos + 1 < max) buf[pos++] = ',';
            pos = json_append_str(buf, pos, max, p->name);
            pos += snprintf(buf + pos, (size_t)(max - pos),
                            ":{\"name\":");
            pos = json_append_str(buf, pos, max, p->name);
            pos += snprintf(buf + pos, (size_t)(max - pos),
                            ",\"type\":\"%s\",\"vehicleType\":\"%s\""
                            ",\"interval\":%d,\"url\":",
                            ptype, vtype, p->interval);
            pos  = json_append_str(buf, pos, max, p->url);
            pos += snprintf(buf + pos, (size_t)(max - pos),
                            ",\"updatedAt\":\"\",\"subscriptionInfo\":null"
                            ",\"proxies\":[");
            /* Итерируем provider_servers[] по source_provider == p->name */
            int first_srv = 1;
            for (int j = 0;
                 j < s_cfg->provider_server_count && pos < max - 128;
                 j++) {
                const ServerConfig *sv = &s_cfg->provider_servers[j];
                if (!sv->enabled || !sv->name[0]) continue;
                if (strcmp(sv->source_provider, p->name) != 0) continue;
                if (!first_srv && pos + 1 < max) buf[pos++] = ',';
                first_srv = 0;
                pos += snprintf(buf + pos, (size_t)(max - pos), "{\"name\":");
                pos  = json_append_str(buf, pos, max, sv->name);
                pos += snprintf(buf + pos, (size_t)(max - pos),
                                ",\"type\":\"%s\"}", sv->protocol);
            }
            pos += snprintf(buf + pos, (size_t)(max - pos), "]}");
        }
    }

    if (pos + 2 < max) { buf[pos++] = '}'; buf[pos++] = '}'; }
    buf[pos] = '\0';
    http_send(conn, epoll_fd, 200, "application/json; charset=utf-8",
              buf, (size_t)pos);
}

/* ─── Clash API compat: GET /providers/rules ────────────────────── */
static void route_clash_providers_rules(HttpConn *conn, int epoll_fd)
{
    static char buf[16384];
    int pos = 0, max = (int)sizeof(buf);

    static const char *const fmt_str[] = {"domain", "ipcidr", "classical"};

    pos += snprintf(buf + pos, (size_t)(max - pos), "{\"providers\":{");

    if (s_cfg) {
        int first = 1;
        for (int i = 0; i < s_cfg->rule_provider_count && pos < max - 256; i++) {
            const RuleProviderConfig *p = &s_cfg->rule_providers[i];
            if (!p->enabled || !p->name[0]) continue;
            const char *vtype = (p->type == RULE_PROVIDER_HTTP) ? "HTTP" : "File";
            const char *ptype = (p->type == RULE_PROVIDER_HTTP) ? "http" : "file";
            int fi = (int)p->format;
            const char *fmt = (fi >= 0 && fi <= 2) ? fmt_str[fi] : "domain";
            if (!first && pos + 1 < max) buf[pos++] = ',';
            first = 0;
            pos = json_append_str(buf, pos, max, p->name);
            pos += snprintf(buf + pos, (size_t)(max - pos),
                            ":{\"name\":");
            pos = json_append_str(buf, pos, max, p->name);
            /* Реальный ruleCount из rpm если доступен */
            int rc = 0;
            if (s_rpm) {
                for (int j = 0; j < s_rpm->count; j++) {
                    if (strcmp(s_rpm->providers[j].name, p->name) == 0) {
                        rc = s_rpm->providers[j].rule_count;
                        break;
                    }
                }
            }
            pos += snprintf(buf + pos, (size_t)(max - pos),
                            ",\"type\":\"%s\",\"vehicleType\":\"%s\""
                            ",\"format\":\"%s\",\"interval\":%d,\"url\":",
                            ptype, vtype, fmt, p->interval);
            pos  = json_append_str(buf, pos, max, p->url);
            pos += snprintf(buf + pos, (size_t)(max - pos),
                            ",\"updatedAt\":\"\",\"ruleCount\":%d}",
                            rc);
        }
    }

    if (pos + 2 < max) { buf[pos++] = '}'; buf[pos++] = '}'; }
    buf[pos] = '\0';
    http_send(conn, epoll_fd, 200, "application/json; charset=utf-8",
              buf, (size_t)pos);
}

/* PING_MAX_CONCURRENT/s_ping_active удалены: route_clash_proxy_delay больше
 * не форкает HC (только cached). Лимит fork сейчас в route_clash_group_delay_batch
 * через GROUP_HC_BATCH_MAX. */

/* ── Percent-decode URL компонента (имена серверов — Unicode/эмодзи) */
static void url_pct_decode(const char *src, char *dst, size_t dsz)
{
    size_t wi = 0;
    for (size_t ri = 0; src[ri] && wi < dsz - 1; ) {
        unsigned char c = (unsigned char)src[ri];
        if (c == '%' && isxdigit((unsigned char)src[ri+1])
                     && isxdigit((unsigned char)src[ri+2])) {
            char hex[3] = { src[ri+1], src[ri+2], '\0' };
            dst[wi++] = (char)(unsigned char)strtol(hex, NULL, 16);
            ri += 3;
        } else if (c == '+') {
            dst[wi++] = ' ';
            ri++;
        } else {
            dst[wi++] = (char)c;
            ri++;
        }
    }
    dst[wi] = '\0';
}

/* ── GET|PUT /proxies/{name}/delay — cached latency only, без fork ──
 *
 * Mihomo-семантика для одного сервера:
 *   1. Lookup в s_cfg (unified индекс: статика + provider_servers)
 *   2. Не найден → 404
 *   3. Найден:
 *      - cached > 0 && <= 9999 → {"delay": cached}, HTTP 200
 *      - cached == 0 (ещё не тестировался) → {"delay": 0}, HTTP 200
 *      - cached > 9999 (ошибка/clamp) → {"delay": 0}, HTTP 200
 *      - AWG (protocol="awg") → {"delay": 0}, HTTP 200 (HC через UDP-handshake
 *        часто провалится для WARP endpoint, mihomo показывает AWG без ping)
 *
 * НИКОГДА не форкать HC: TLS handshake на MIPS = 200-400мс, при timeout=1500мс
 * не успеваем → 408 → zashboard показывает сервер как dead. Свежие latency
 * приходят через proxy_group_tick (фоновый HC раунд) или batch через
 * /group/{name}/delay (молния группы). Этот endpoint только читает кэш. */
static void route_clash_proxy_delay(HttpConn *conn, int epoll_fd,
                                     const char *name, const char *qs)
{
    (void)qs;  /* timeout/url игнорируются — мы не запускаем HC */

    if (!s_cfg) {
        const char e[] = "{\"message\":\"не инициализирован\"}";
        http_send(conn, epoll_fd, 503, "application/json; charset=utf-8",
                  e, sizeof(e) - 1);
        return;
    }

    const ServerConfig *found = NULL;
    int found_idx = -1;
    int total = s_cfg->server_count + s_cfg->provider_server_count;
    for (int i = 0; i < total; i++) {
        const ServerConfig *sc = config_get_server(s_cfg, i);
        if (sc && sc->name[0] && strcmp(sc->name, name) == 0) {
            found     = sc;
            found_idx = i;
            break;
        }
    }

    if (!found) {
        const char e[] = "{\"message\":\"proxy not found\"}";
        http_send(conn, epoll_fd, 404, "application/json; charset=utf-8",
                  e, sizeof(e) - 1);
        return;
    }

    uint32_t cached = 0;
    if (s_pgm && found_idx >= 0)
        cached = pgm_server_latency(s_pgm, found_idx);

    /* Невалидный диапазон → нормализуем в 0 (zashboard покажет без цифры).
     * AWG получает fake delay=1 от batch HC (см. route_clash_group_delay_batch);
     * до первого batch у AWG cached=0 — тоже OK. */
    if (cached > 9999) cached = 0;

    char body[64];
    int  bl = snprintf(body, sizeof(body), "{\"delay\":%u}", cached);
    http_send(conn, epoll_fd, 200, "application/json; charset=utf-8",
              body, (size_t)bl);
}

/* ── batch HC всех серверов группы (mihomo-compat /group/:name/delay) ─
 * Запускает HC параллельно с лимитом GROUP_HC_BATCH_MAX, возвращает map
 * {server_name: ms}. Серверы провалившие HC — отсутствуют в ответе (как
 * mihomo). Обновляет latency_ms / fail_count / available в gs->servers
 * для синхронизации с runtime state — нажатие молнии в zashboard сразу
 * приводит группу в актуальное состояние.
 *
 * Параметры (v1.5.114 — отступ от v1.5.113 24 параллельных = OOM на EC330):
 *   GROUP_HC_BATCH_MAX = 8  fork-ов max. WHY 24 → 8: при batch и быстрых
 *     повторных нажатиях молнии в UI накапливалось 70+ живых child (parent
 *     close pipe не убивает child — он висит на UDP poll до своего timeout).
 *     8 × 4MB = 32MB max RSS — безопасно для EC330 116MB.
 *   GROUP_HC_DEADLINE_SEC = 20  endpoint deadline.
 *   timeout_per_server = min(client*2, 2000) — короткий per-fork timeout
 *     ускоряет освобождение child процессов. */
#define GROUP_HC_BATCH_MAX 8
#define GROUP_HC_DEADLINE_SEC 20
#define GROUP_HC_TIMEOUT_FLOOR_MS 1500
#define GROUP_HC_TIMEOUT_CAP_MS   2000

typedef struct {
    int          srv_idx;
    const char  *name;
    int          pipe_fd;
    int          lat_ms;
    bool         ok;
    bool         finished_real;  /* HC реально завершился (read из pipe) */
    bool         spawn_failed;   /* fork/spawn провалился — не штрафуем */
} gd_slot_t;

static int gd_spawn_one(const ServerConfig *sc, const char *hc_host,
                        uint16_t hc_port, int timeout_ms,
                        const EburNetConfig *cfg)
{
    if (!sc) return -1;
    (void)cfg;
    /* AWG: реальный WireGuard Init (с junks/CPS) через net_spawn_awg_check,
     * измерение RTT при первом UDP ответе. Cloudflare WARP отвечает error,
     * настоящие AmneziaVPN — handshake response — оба варианта дают RTT. */
#if CONFIG_EBURNET_AWG
    if (strcmp(sc->protocol, "awg") == 0)
        return net_spawn_awg_check(sc, cfg ? cfg->tai_utc_offset : 0,
                                   timeout_ms);
#endif
    if (strcmp(sc->protocol, "vless") == 0 ||
        strcmp(sc->protocol, "trojan") == 0)
        return hc_vless_spawn(sc, hc_host, hc_port, timeout_ms);
    if (strcmp(sc->protocol, "hysteria2") == 0)
        return net_spawn_udp_ping(sc->address, sc->port, timeout_ms);
    /* TCP ping fallback — только если address уже IP (DNS resolve в child
     * нет, fake-IP даст 2ms ложное OK). */
    struct in_addr  a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET,  sc->address, &a4) == 1 ||
        inet_pton(AF_INET6, sc->address, &a6) == 1)
        return net_spawn_tcp_ping(sc->address, sc->port, timeout_ms);
    return -1;
}

static void route_clash_group_delay_batch(HttpConn *conn, int epoll_fd,
                                          proxy_group_state_t *gs,
                                          const char *qs)
{
    /* Client timeout (zashboard шлёт обычно 1500-5000) — это лимит на ОДИН
     * сервер в его представлении. У нас HC через TLS HS на MIPS занимает
     * 200-600мс, при больших RTT до 2-3с. Усиливаем до min(client*3, 5000). */
    int client_timeout_ms = 5000;
    char     hc_host[256] = "cp.cloudflare.com";
    uint16_t hc_port      = 80;
    bool url_in_qs = false;
    if (qs && qs[0]) {
        const char *tv = strstr(qs, "timeout=");
        if (tv) {
            int t = atoi(tv + 8);
            if (t > 0 && t <= 30000) client_timeout_ms = t;
        }
        const char *uv = strstr(qs, "url=");
        if (uv) {
            net_parse_url_host(uv + 4, hc_host, sizeof(hc_host), &hc_port);
            url_in_qs = true;
        }
    }
    if (!url_in_qs && gs->test_url[0])
        net_parse_url_host(gs->test_url, hc_host, sizeof(hc_host), &hc_port);

    int per_server_ms = client_timeout_ms * 2;
    if (per_server_ms > GROUP_HC_TIMEOUT_CAP_MS)   per_server_ms = GROUP_HC_TIMEOUT_CAP_MS;
    if (per_server_ms < GROUP_HC_TIMEOUT_FLOOR_MS) per_server_ms = GROUP_HC_TIMEOUT_FLOOR_MS;

    int N = gs->server_count;
    if (N <= 0) {
        const char e[] = "{}";
        http_send(conn, epoll_fd, 200, "application/json; charset=utf-8",
                  e, sizeof(e) - 1);
        return;
    }

    gd_slot_t *slots = calloc((size_t)N, sizeof(gd_slot_t));
    if (!slots) {
        const char e[] = "{\"message\":\"out of memory\"}";
        http_send(conn, epoll_fd, 500, "application/json; charset=utf-8",
                  e, sizeof(e) - 1);
        return;
    }
    for (int i = 0; i < N; i++) {
        slots[i].srv_idx = gs->servers[i].server_idx;
        slots[i].pipe_fd = -1;
        const ServerConfig *sc = config_get_server(s_cfg, slots[i].srv_idx);
        slots[i].name = (sc && sc->name[0]) ? sc->name : NULL;
    }

    time_t deadline = time(NULL) + GROUP_HC_DEADLINE_SEC;
    int started = 0, pending = 0, finished = 0;

    while (finished < N) {
        time_t now_ts = time(NULL);
        if (now_ts >= deadline) break;

        while (pending < GROUP_HC_BATCH_MAX && started < N) {
            int i = started++;
            const ServerConfig *sc = config_get_server(s_cfg, slots[i].srv_idx);
            int pfd = gd_spawn_one(sc, hc_host, hc_port, per_server_ms, s_cfg);
            if (pfd < 0) {
                slots[i].spawn_failed = true;
                finished++;
                continue;
            }
            slots[i].pipe_fd = pfd;
            pending++;
        }
        if (pending == 0) break;

        struct pollfd pfds[GROUP_HC_BATCH_MAX];
        int idx_map[GROUP_HC_BATCH_MAX];
        int npfd = 0;
        for (int i = 0; i < N && npfd < GROUP_HC_BATCH_MAX; i++) {
            if (slots[i].pipe_fd < 0) continue;
            idx_map[npfd] = i;
            pfds[npfd].fd      = slots[i].pipe_fd;
            pfds[npfd].events  = POLLIN;
            pfds[npfd].revents = 0;
            npfd++;
        }
        if (npfd == 0) break;

        int budget_ms = (int)((deadline - now_ts) * 1000);
        int round_to  = per_server_ms + 1000;
        if (round_to > budget_ms) round_to = budget_ms;
        if (round_to <= 0) break;
        int pr = poll(pfds, npfd, round_to);
        if (pr <= 0) {
            /* poll timeout / deadline — оставляем pending pipe_fd для cleanup;
             * НЕ помечаем finished_real, чтобы не штрафовать незавершённые HC. */
            break;
        }
        for (int k = 0; k < npfd; k++) {
            if (!(pfds[k].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            int i = idx_map[k];
            char buf[32] = {0};
            ssize_t n = read(slots[i].pipe_fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                if (strncmp(buf, "OK ", 3) == 0) {
                    long long ms = 0;
                    sscanf(buf, "OK %lld", &ms);
                    if (ms > 0 && ms <= 9999) {
                        slots[i].lat_ms = (int)ms;
                        slots[i].ok     = true;
                    }
                }
            }
            close(slots[i].pipe_fd);
            slots[i].pipe_fd       = -1;
            slots[i].finished_real = true;
            pending--;
            finished++;
        }
    }

    for (int i = 0; i < N; i++)
        if (slots[i].pipe_fd >= 0) {
            close(slots[i].pipe_fd);
            slots[i].pipe_fd = -1;
        }

    /* Обновить runtime state. Серверы у которых HC реально завершился
     * (finished_real=true) — обновляются. Серверы прерванные deadline или
     * spawn_failed — не штрафуем, как mihomo. */
    time_t tnow = time(NULL);
    for (int i = 0; i < N; i++) {
        if (!slots[i].finished_real) continue;
        if (slots[i].ok) {
            gs->servers[i].latency_ms = (uint32_t)slots[i].lat_ms;
            if (gs->servers[i].fail_count > 0) gs->servers[i].fail_count--;
            if (gs->servers[i].fail_count == 0) gs->servers[i].available = true;
        } else {
            gs->servers[i].fail_count++;
            if (gs->servers[i].fail_count >= 3)
                gs->servers[i].available = false;
        }
        gs->servers[i].last_check = tnow;
    }

    /* WHY 64KB: имя сервера до 128 UTF-8 байт + JSON escaping ×2 + ":<lat>,"
     * = ~280 байт/сервер. 100 серверов × 280 = 28000 → 32KB мало,
     * 64KB с запасом. */
    static char body[65536];
    int pos = 0, max = (int)sizeof(body);
    pos += snprintf(body + pos, (size_t)(max - pos), "{");
    int first = 1;
    /* Включаем ВСЕ серверы группы у которых есть хоть какой-то результат:
     * 1. Если batch HC дал результат (slots[i].ok) → его lat_ms.
     * 2. Иначе → последний известный latency из любой группы pgm
     *    (background HC через proxy_group_tick).
     * 3. Иначе сервер не включается (zashboard покажет без цифры, но
     *    благодаря init available=true в proxy_group.c — останется alive).
     *
     * WHY: deadline 30с режет 30+ серверов от полного теста (66 / 24 ≈ 3
     * раунда но dead servers держат слот таймаутом 3с). Без fallback на
     * pgm_lat zashboard видит "нет данных" → скрывает сервер. */
    for (int i = 0; i < N && pos < max - 512; i++) {
        if (!slots[i].name) continue;
        int emit_ms = 0;
        if (slots[i].ok && slots[i].lat_ms > 0) {
            emit_ms = slots[i].lat_ms;
        } else if (s_pgm) {
            uint32_t pgm_lat = pgm_server_latency(s_pgm, slots[i].srv_idx);
            if (pgm_lat > 0 && pgm_lat <= 9999) emit_ms = (int)pgm_lat;
        }
        if (emit_ms <= 0) continue;
        if (!first && pos + 1 < max) body[pos++] = ',';
        first = 0;
        pos = json_append_str(body, pos, max, slots[i].name);
        pos += snprintf(body + pos, (size_t)(max - pos), ":%d", emit_ms);
    }
    if (pos + 2 < max) body[pos++] = '}';
    body[pos] = '\0';

    free(slots);

    http_send(conn, epoll_fd, 200, "application/json; charset=utf-8",
              body, (size_t)pos);
}

/* ── GET|PUT /storage/{key} — in-memory key-value для zashboard ───── */
#define STORAGE_SLOTS   8
#define STORAGE_KEY_SZ  64
#define STORAGE_VAL_SZ  4096

typedef struct {
    char key[STORAGE_KEY_SZ];
    char val[STORAGE_VAL_SZ];
} storage_slot_t;
static storage_slot_t s_storage[STORAGE_SLOTS];

static void route_storage(HttpConn *conn, int epoll_fd, const char *key)
{
    static char resp_buf[STORAGE_KEY_SZ + STORAGE_VAL_SZ + 64];

    if (!conn->is_put) {
        /* GET: поиск по ключу */
        for (int i = 0; i < STORAGE_SLOTS; i++) {
            if (s_storage[i].key[0] && strcmp(s_storage[i].key, key) == 0) {
                int n = snprintf(resp_buf, sizeof(resp_buf), "{\"key\":");
                n = json_append_str(resp_buf, n, (int)sizeof(resp_buf), key);
                n += snprintf(resp_buf + n, (int)sizeof(resp_buf) - n, ",\"data\":");
                n = json_append_str(resp_buf, n, (int)sizeof(resp_buf),
                                    s_storage[i].val);
                n += snprintf(resp_buf + n, (int)sizeof(resp_buf) - n, "}");
                http_send(conn, epoll_fd, 200,
                          "application/json; charset=utf-8",
                          resp_buf, (size_t)n);
                return;
            }
        }
        const char e[] = "{\"message\":\"not found\"}";
        http_send(conn, epoll_fd, 404, "application/json; charset=utf-8",
                  e, sizeof(e) - 1);
        return;
    }

    /* PUT: проверка размера */
    if (conn->content_length <= 0 ||
        conn->content_length >= STORAGE_VAL_SZ) {
        const char e[] = "{\"message\":\"payload too large\"}";
        http_send(conn, epoll_fd, 413, "application/json; charset=utf-8",
                  e, sizeof(e) - 1);
        return;
    }

    /* Найти/создать слот до чтения body */
    int slot = -1;
    for (int i = 0; i < STORAGE_SLOTS; i++) {
        if (s_storage[i].key[0] && strcmp(s_storage[i].key, key) == 0) {
            slot = i;
            break;
        }
        if (slot < 0 && !s_storage[i].key[0])
            slot = i;
    }
    if (slot < 0) {
        /* Вытесняем первый слот (LRU не нужен — 8 слотов достаточно) */
        slot = 0;
    }

    /* Найти конец заголовков и прочитать body прямо в слот */
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) {
        const char e[] = "{\"message\":\"bad request\"}";
        http_send(conn, epoll_fd, 400, "application/json; charset=utf-8",
                  e, sizeof(e) - 1);
        return;
    }
    const char *body_start = hdr_end + 4;
    size_t prefetch = (size_t)(conn->buf + conn->buf_len - body_start);
    size_t need     = (size_t)conn->content_length;
    if (prefetch > need) prefetch = need;
    memcpy(s_storage[slot].val, body_start, prefetch);
    size_t received = prefetch;

    if (received < need) {
        int fl = fcntl(conn->fd, F_GETFL);
        if (fl != -1) fcntl(conn->fd, F_SETFL, fl & ~O_NONBLOCK);
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        while (received < need) {
            ssize_t n = read(conn->fd,
                             s_storage[slot].val + received,
                             need - received);
            if (n <= 0) break;
            received += (size_t)n;
        }
        if (fl != -1) fcntl(conn->fd, F_SETFL, fl | O_NONBLOCK);
    }
    s_storage[slot].val[received] = '\0';
    strncpy(s_storage[slot].key, key, STORAGE_KEY_SZ - 1);
    s_storage[slot].key[STORAGE_KEY_SZ - 1] = '\0';

    int n = snprintf(resp_buf, sizeof(resp_buf), "{\"key\":");
    n = json_append_str(resp_buf, n, (int)sizeof(resp_buf), key);
    n += snprintf(resp_buf + n, (int)sizeof(resp_buf) - n, ",\"data\":");
    n = json_append_str(resp_buf, n, (int)sizeof(resp_buf), s_storage[slot].val);
    n += snprintf(resp_buf + n, (int)sizeof(resp_buf) - n, "}");
    http_send(conn, epoll_fd, 200, "application/json; charset=utf-8",
              resp_buf, (size_t)n);
}

/* ── build_connections_json — собрать Clash-формат JSON из relay ──── */
/* WHY: вызывается GET /connections и WS /connections.
 * Возвращает heap-строку — вызывающий делает free(). */
static char *build_connections_json(void)
{
    size_t cap = 32768;
    char  *buf = malloc(cap);
    if (!buf) return NULL;

    int n = snprintf(buf, cap,
        "{\"downloadTotal\":%llu,\"uploadTotal\":%llu,\"connections\":[",
        (unsigned long long)atomic_load_explicit(
            &g_stats.traffic_down_bytes, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(
            &g_stats.traffic_up_bytes, memory_order_relaxed));

    bool first = true;

    if (s_ds) {
        for (int i = 0; i < s_ds->conns_max; i++) {
            relay_conn_t *r = &s_ds->conns[i];
            if (r->state == RELAY_DONE) continue;
            if (r->client_fd < 0 && !r->is_udp_relay) continue;

            /* dst IP и порт */
            char dst_ip[64] = "";
            uint16_t dst_port = 0;
            if (r->dst.ss_family == AF_INET) {
                const struct sockaddr_in *s4 =
                    (const struct sockaddr_in *)&r->dst;
                inet_ntop(AF_INET, &s4->sin_addr, dst_ip, sizeof(dst_ip));
                dst_port = ntohs(s4->sin_port);
            } else if (r->dst.ss_family == AF_INET6) {
                const struct sockaddr_in6 *s6 =
                    (const struct sockaddr_in6 *)&r->dst;
                inet_ntop(AF_INET6, &s6->sin6_addr, dst_ip, sizeof(dst_ip));
                dst_port = ntohs(s6->sin6_port);
            }

            const char *host = r->domain[0] ? r->domain : dst_ip;

            /* start time ISO 8601 */
            char start_str[32] = "1970-01-01T00:00:00Z";
            if (r->created_at > 0) {
                struct tm tm_buf;
                gmtime_r(&r->created_at, &tm_buf);
                strftime(start_str, sizeof(start_str),
                         "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
            }

            /* chains JSON array */
            char chains[512] = "[";
            size_t ch_len = 1;
            for (int ci = 0; ci < r->proxy_chain_len && ci < 2; ci++) {
                char ce[140];
                json_escape_str(r->proxy_chain[ci], ce, sizeof(ce));
                if (ci > 0) chains[ch_len++] = ',';
                ch_len += (size_t)snprintf(chains + ch_len,
                                           sizeof(chains) - ch_len,
                                           "\"%s\"", ce);
            }
            if (r->proxy_chain_len == 0) {
                ch_len += (size_t)snprintf(chains + ch_len,
                                           sizeof(chains) - ch_len,
                                           "\"DIRECT\"");
            }
            if (ch_len < sizeof(chains)) chains[ch_len++] = ']';
            chains[ch_len] = '\0';

            char host_e[300], rule_e[48], payload_e[160];
            json_escape_str(host, host_e, sizeof(host_e));
            json_escape_str(r->rule_type[0]    ? r->rule_type    : "MATCH",
                            rule_e, sizeof(rule_e));
            json_escape_str(r->rule_payload[0] ? r->rule_payload : "",
                            payload_e, sizeof(payload_e));

            char ja3_e[40] = "", ja4_e[80] = "";
            if (r->ja3[0]) json_escape_str(r->ja3, ja3_e, sizeof(ja3_e));
            if (r->ja4[0]) json_escape_str(r->ja4, ja4_e, sizeof(ja4_e));

            char src_alias_e[130] = "";
            if (s_dm && r->client_mac[0]) {
                const device_config_t *dev =
                    device_policy_find(s_dm, r->client_mac);
                if (dev && dev->alias[0])
                    json_escape_str(dev->alias, src_alias_e, sizeof(src_alias_e));
            }

            const char *net = r->is_udp ? "udp" : "tcp";

            char entry[1760];
            int elen = snprintf(entry, sizeof(entry),
                "%s{"
                "\"id\":\"%d\","
                "\"metadata\":{"
                  "\"network\":\"%s\","
                  "\"type\":\"TPROXY\","
                  "\"sourceIP\":\"\","
                  "\"sourcePort\":\"0\","
                  "\"sourceAlias\":\"%s\","
                  "\"destinationIP\":\"%s\","
                  "\"destinationPort\":\"%u\","
                  "\"host\":\"%s\","
                  "\"dnsMode\":\"fake-ip\","
                  "\"processPath\":\"\""
                "},"
                "\"upload\":%llu,"
                "\"download\":%llu,"
                "\"start\":\"%s\","
                "\"chains\":%s,"
                "\"rule\":\"%s\","
                "\"rulePayload\":\"%s\","
                "\"ja3\":\"%s\","
                "\"ja4\":\"%s\""
                "}",
                first ? "" : ",",
                i, net,
                src_alias_e, dst_ip, dst_port, host_e,
                (unsigned long long)r->bytes_out,
                (unsigned long long)r->bytes_in,
                start_str, chains,
                rule_e, payload_e,
                ja3_e, ja4_e);

            if (n + elen + 8 >= (int)cap) {
                cap *= 2;
                char *nb = realloc(buf, cap);
                if (!nb) break;
                buf = nb;
            }
            memcpy(buf + n, entry, (size_t)elen);
            n += elen;
            first = false;
        }
    }

    n += snprintf(buf + n, cap - (size_t)n, "]}");
    return buf;
}

/* ── GET /connections — статистика активных соединений ────────────── */
static void route_clash_connections(HttpConn *conn, int epoll_fd)
{
    char *json = build_connections_json();
    if (!json) {
        static const char OOM[] = "{\"error\":\"OOM\"}";
        http_send(conn, epoll_fd, 500, "application/json; charset=utf-8",
                  OOM, sizeof(OOM)-1);
        return;
    }
    http_send(conn, epoll_fd, 200, "application/json; charset=utf-8",
              json, strlen(json));
    free(json);
}

/* ── Per-IP rate limit таблица (open addressing, linear probe) ───── */
#define HTTP_RATE_MS      200
#define RATE_LIMIT_SLOTS  64u
#define RATE_LIMIT_PROBE   8u

typedef struct {
    uint32_t ip;      /* IPv4 network order; 0 = пустой слот */
    long     last_ms;
} RateLimitEntry;

static RateLimitEntry s_rl_table[RATE_LIMIT_SLOTS]; /* BSS, нули при старте */

/* Возвращает true если ip превысил лимит (запрос нужно отклонить). */
static bool rate_limit_check(uint32_t ip)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long now_ms = (long)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);

    /* FNV1a для uint32_t → начальный слот */
    uint32_t h = 2166136261u;
    h ^= (uint8_t)(ip);         h *= 16777619u;
    h ^= (uint8_t)(ip >>  8);   h *= 16777619u;
    h ^= (uint8_t)(ip >> 16);   h *= 16777619u;
    h ^= (uint8_t)(ip >> 24);   h *= 16777619u;
    uint32_t base = h & (RATE_LIMIT_SLOTS - 1u);

    /* LRU eviction: индекс и метка минимального last_ms среди зондируемых слотов */
    uint32_t lru_idx  = base;
    long     lru_ms   = s_rl_table[base].last_ms;

    for (uint32_t i = 0; i < RATE_LIMIT_PROBE; i++) {
        uint32_t idx = (base + i) & (RATE_LIMIT_SLOTS - 1u);
        RateLimitEntry *e = &s_rl_table[idx];

        if (e->ip == ip) {
            if ((now_ms - e->last_ms) < HTTP_RATE_MS)
                return true;  /* rate-limited */
            e->last_ms = now_ms;
            return false;
        }

        if (e->ip == 0u) {    /* пустой слот — занять */
            e->ip      = ip;
            e->last_ms = now_ms;
            return false;
        }

        if (e->last_ms < lru_ms) {
            lru_ms  = e->last_ms;
            lru_idx = idx;
        }
    }

    /* Все PROBE слотов заняты чужими IP — вытеснить самый старый */
    s_rl_table[lru_idx].ip      = ip;
    s_rl_table[lru_idx].last_ms = now_ms;
    return false;
}

/* ── http_dispatch — маршрутизация запросов ──────────────────────── */
/* Сервер слушает на 0.0.0.0 — доступен из LAN и localhost */

static void http_dispatch(HttpConn *conn, int epoll_fd)
{

    /* Явная защита от path traversal */
    if (strstr(conn->path, "/../") || strstr(conn->path, "\\..\\") ||
        strncmp(conn->path, "../", 3) == 0) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"error\":\"bad request\"}", 22);
        return;
    }

    /* CORS preflight: OPTIONS — 204 No Content + CORS headers, без тела.
     * Браузер шлёт OPTIONS перед PUT/PATCH/DELETE с custom headers
     * (Authorization, Content-Type) — без 204 эти запросы блокируются. */
    if (conn->is_options) {
        /* MIPS: cors[384]+hdr[768]=1152B > stack limit 512B. Single-threaded epoll. */
        static char cors[384];
        cors_origin_hdr(conn->buf, cors, sizeof(cors));
        static char hdr[768];
        int hl = snprintf(hdr, sizeof(hdr),
            "HTTP/1.0 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "Access-Control-Max-Age: 600\r\n"
            "%s"
            "Connection: close\r\n\r\n",
            cors);
        if (hl > 0 && hl < (int)sizeof(hdr)) {
            if (conn_queue_write(conn, hdr, (size_t)hl) >= 0)
                conn_flush(conn, epoll_fd);
        }
        if (!conn->send_buf) conn_close(conn, epoll_fd);
        return;
    }

    /* Метод не распознан → 405 */
    if (!conn->method_ok) {
        const char body[] = "Method Not Allowed";
        http_send(conn, epoll_fd, 405, "text/plain",
                  body, sizeof(body) - 1);
        return;
    }

    const char *p = conn->path;

    /* ─── WebSocket upgrade check ───────────────────────────────────── */
    {
        char ws_key[WS_KEY_MAX];
        int wsr = ws_parse_upgrade(conn->buf, (size_t)conn->buf_len,
                                   ws_key, sizeof(ws_key));
        if (wsr == 1) {
            /* Отделить path от query string (zashboard шлёт ?token=...) */
            const char *qm = strchr(p, '?');
            size_t plen = qm ? (size_t)(qm - p) : strlen(p);

            int is_echo    = (plen == 8 && strncmp(p, "/ws/echo",    8) == 0);
            int is_memory  = (plen == 7 && strncmp(p, "/memory",     7) == 0)
                          || (plen == 10 && strncmp(p, "/ws/memory",  10) == 0);
            int is_traffic = (plen == 8 && strncmp(p, "/traffic",    8) == 0)
                          || (plen == 11 && strncmp(p, "/ws/traffic", 11) == 0);
            /* WHY: Clash-совместимые /logs и /ws/logs — оба варианта как у /memory и /traffic */
            int is_logs    = (plen == 5  && strncmp(p, "/logs",          5) == 0)
                          || (plen == 8  && strncmp(p, "/ws/logs",       8) == 0);
            /* WHY: /connections и /ws/connections — оба варианта */
            int is_conns   = (plen == 12 && strncmp(p, "/connections",   12) == 0)
                          || (plen == 15 && strncmp(p, "/ws/connections", 15) == 0);
            int is_ssh     = (plen == 4  && strncmp(p, "/ssh",           4) == 0);
            int is_events  = (plen == 10 && strncmp(p, "/ws/events",    10) == 0);

            if (!is_echo && !is_memory && !is_traffic && !is_logs && !is_conns && !is_ssh && !is_events) {
                http_send(conn, epoll_fd, 404, "text/plain",
                          "WebSocket path not found", 24);
                return;
            }
            char accept[WS_ACCEPT_MAX];
            if (ws_compute_accept(ws_key, accept, sizeof(accept)) != 0) {
                http_send(conn, epoll_fd, 500, "text/plain",
                          "handshake error", 15);
                return;
            }
            if (ws_send_101(conn->fd, accept) != 0) {
                conn_close(conn, epoll_fd);
                return;
            }
            /* Переключение в WebSocket режим — fd остаётся открытым */
            conn->is_websocket = 1;
            conn->ws_route = is_traffic ? WS_ROUTE_TRAFFIC
                           : is_memory  ? WS_ROUTE_MEMORY
                           : is_logs    ? WS_ROUTE_LOGS
                           : is_conns   ? WS_ROUTE_CONNECTIONS
                           : is_ssh     ? WS_ROUTE_SSH
                           : is_events  ? WS_ROUTE_EVENTS
                           :              WS_ROUTE_ECHO;
            conn->buf_len = 0;
            conn->headers_done = 0;
            /* /logs: отправить историю сразу после handshake */
            if (is_logs)
                ws_logs_send_history(conn, epoll_fd);
            /* /ws/events: отправить историю последних 10 событий */
            if (is_events)
                ws_events_send_history(conn, epoll_fd);
            /* /ssh: LAN-only guard + запуск pty сеанса */
            if (is_ssh) {
                if (!ssh_is_lan_client(&conn->peer_addr)) {
                    ws_send_text(conn, epoll_fd, "{\"error\":\"SSH only from LAN\"}", 28);
                    conn_close(conn, epoll_fd);
                    return;
                }
                if (ssh_session_start() != 0) {
                    ws_send_text(conn, epoll_fd, "{\"error\":\"Failed to start shell\"}", 33);
                    conn_close(conn, epoll_fd);
                    return;
                }
                s_ssh_conn = conn;
            }
            return;
        } else if (wsr == -1) {
            http_send(conn, epoll_fd, 400, "text/plain",
                      "bad WebSocket upgrade", 21);
            return;
        }
        /* wsr == 0: normal HTTP request — fall through */
    }

    /* ─── Static assets from /usr/share/4eburnet/dashboard/ ───────────
     * Covers: index.html, /assets/xxx, /sw.js, /workbox-xxx.js,
     *         /manifest.webmanifest, favicons, /pwa-xxx.png, /registerSW.js
     * Whitelist — narrow attack surface, no arbitrary FS read.
     *
     * Mihomo-compat: тот же dashboard доступен и под /ui/ — открытие
     * http://router:8080/ui/ ведёт на index.html, /ui/assets/ раздаёт
     * ассеты. /ui без trailing slash → 307 Temporary Redirect на /ui/. */
    {
        const char *dashroot = "/usr/share/4eburnet/dashboard";
        char fpath[512];
        const char *sub = p;

        /* /ui без / — 307 redirect (mihomo делает так же) */
        if (strcmp(sub, "/ui") == 0) {
            http_send_redirect(conn, epoll_fd, "/ui/");
            return;
        }

        /* Strip /ui префикс — раздача под двумя путями: / и /ui/ */
        if (strncmp(sub, "/ui/", 4) == 0) {
            sub += 3;  /* оставляем ведущий '/', срезаем 'ui' */
        }

        /* Root → index.html (после strip /ui/) */
        if (strcmp(sub, "/") == 0) {
            sub = "/index.html";
        }

        /* Extra safety: no double slashes, no backslash, length limit.
         * NUL-байтов нет — HTTP parser уже это гарантирует через
         * strncmp/strstr. Traversal '/../' уже блокирован выше. */
        if (strstr(sub, "//") || strchr(sub, '\\')) {
            goto not_static;
        }
        if (strlen(sub) > 256) {
            goto not_static;
        }
        if (sub[0] != '/') goto not_static;

        /* Whitelist: index.html + /assets/ + service-worker files +
         * PWA icons + favicons. Держим surface узкой. */
        int is_static = 0;
        if (strcmp(sub, "/index.html") == 0) is_static = 1;
        else if (strncmp(sub, "/assets/", 8) == 0) is_static = 1;
        else if (strcmp(sub, "/sw.js") == 0) is_static = 1;
        else if (strcmp(sub, "/registerSW.js") == 0) is_static = 1;
        else if (strncmp(sub, "/workbox-", 9) == 0) is_static = 1;
        else if (strcmp(sub, "/manifest.webmanifest") == 0) is_static = 1;
        else if (strcmp(sub, "/favicon.ico") == 0) is_static = 1;
        else if (strcmp(sub, "/favicon.svg") == 0) is_static = 1;
        else if (strcmp(sub, "/favicon-dark.svg") == 0) is_static = 1;
        else if (strcmp(sub, "/icon.svg") == 0) is_static = 1;
        else if (strncmp(sub, "/pwa-", 5) == 0) is_static = 1;
        else if (strcmp(sub, "/apple-touch-icon.png") == 0) is_static = 1;
        else if (strcmp(sub, "/maskable-icon.png") == 0) is_static = 1;
        else if (strcmp(sub, "/robots.txt") == 0) is_static = 1;

        if (!is_static) goto not_static;

        /* Build full path */
        int n = snprintf(fpath, sizeof(fpath), "%s%s", dashroot, sub);
        if (n <= 0 || (size_t)n >= sizeof(fpath)) goto not_static;

        /* Whitelist-hit должен существовать; иначе 404. */
        struct stat st;
        if (stat(fpath, &st) != 0 || !S_ISREG(st.st_mode)) {
            http_send(conn, epoll_fd, 404, "text/plain",
                      "File not found", 14);
            return;
        }

        http_send_file(conn, epoll_fd, 200, mime_by_ext(sub), fpath);
        return;
    }
    not_static:
    /* ─── End static block ─── */

    /* GET /monitor — standalone страница мониторинга в реальном времени */
    if (strcmp(p, "/monitor") == 0 && !conn->is_post && !conn->is_put &&
        !conn->is_patch && !conn->is_delete) {
        route_monitor(conn, epoll_fd);
        return;
    }

    /* zashboard запрашивает /zashboard-settings.json при старте.
     * Возвращаем пустой JSON чтобы не было 404 в консоли браузера. */
    if (strcmp(p, "/zashboard-settings.json") == 0) {
        http_send(conn, epoll_fd, 200, "application/json; charset=utf-8", "{}", 2);
        return;
    }

    /* GET /logo.png → embedded PNG массив (legacy backwards compat) */
    if (strcmp(p, "/logo.png") == 0) {
        http_send(conn, epoll_fd, 200, "image/png",
                  logo_png_data, (size_t)logo_png_size);
        return;
    }

    /* ─── Clash-compatible API (no /api/ prefix, per Clash spec) ───
     * zashboard ожидает эти endpoint'ы. Добавляем по мере
     * реализации. Phase 2 Group 1 Part A: /version + /configs. */
    if (strcmp(p, "/version") == 0) {
        route_clash_version(conn, epoll_fd);
        return;
    }
    /* zashboard persistence (GET/PUT/DELETE) — без этого дашборд сбрасывает
     * settings на каждом F5. */
    if (strcmp(p, "/storage/zashboard") == 0) {
        route_zashboard_storage(conn, epoll_fd);
        return;
    }
    if (strcmp(p, "/configs") == 0) {
        if (conn->is_patch)
            route_clash_configs_patch(conn, epoll_fd);
        else
            route_clash_configs(conn, epoll_fd);
        return;
    }
    if (strcmp(p, "/proxies") == 0) {
        route_clash_proxies(conn, epoll_fd);
        return;
    }
    /* GET|PUT /proxies/{name}/delay?timeout=N
     * PUT /proxies/{group} {"name":"server"} — Clash API для выбора сервера */
    if (strncmp(p, "/proxies/", 9) == 0) {
        const char *qm   = strchr(p, '?');
        const char *qs   = qm ? qm + 1 : "";
        size_t      plen = qm ? (size_t)(qm - p) : strlen(p);
        if (plen > 15 && memcmp(p + plen - 6, "/delay", 6) == 0) {
            size_t nlen = plen - 9 - 6;  /* 9=len("/proxies/"), 6=len("/delay") */
            char raw[512];
            if (nlen >= sizeof(raw)) nlen = sizeof(raw) - 1;
            memcpy(raw, p + 9, nlen);
            raw[nlen] = '\0';
            char name[512];
            url_pct_decode(raw, name, sizeof(name));
            route_clash_proxy_delay(conn, epoll_fd, name, qs);
            return;
        }
        /* PUT /proxies/{group} {"name":"server"} — Clash standard selector switch */
        if (conn->is_put && s_pgm && s_cfg) {
            size_t nlen = plen - 9;
            char raw[512];
            if (nlen >= sizeof(raw)) nlen = sizeof(raw) - 1;
            memcpy(raw, p + 9, nlen);
            raw[nlen] = '\0';
            char grp[512];
            url_pct_decode(raw, grp, sizeof(grp));
            /* Прочитать "name" из JSON тела */
            const char *body = strstr(conn->buf, "\r\n\r\n");
            char srv_name[256] = {0};
            if (body) {
                body += 4;
                http_json_get_str(body, "name", srv_name, sizeof(srv_name));
            }
            if (!grp[0] || !srv_name[0]) {
                const char e[] = "{\"message\":\"missing group or name\"}";
                http_send(conn, epoll_fd, 400, "application/json", e, sizeof(e) - 1);
                return;
            }
            proxy_group_state_t *g = proxy_group_find(s_pgm, grp);
            if (!g) {
                const char e[] = "{\"message\":\"group not found\"}";
                http_send(conn, epoll_fd, 404, "application/json", e, sizeof(e) - 1);
                return;
            }
            int found = 0;
            for (int i = 0; i < g->server_count; i++) {
                const ServerConfig *sc = config_get_server(s_cfg, g->servers[i].server_idx);
                if (sc && strcmp(sc->name, srv_name) == 0) {
                    g->selected_idx = i;
                    g->pinned        = true;
                    found = 1;
                    break;
                }
            }
            if (found) {
                proxy_group_save_all_selections(s_pgm, s_cfg);
                http_send(conn, epoll_fd, 204, "application/json", "", 0);
            } else {
                const char e[] = "{\"message\":\"server not found in group\"}";
                http_send(conn, epoll_fd, 404, "application/json", e, sizeof(e) - 1);
            }
            return;
        }
        /* DELETE /proxies/{group} — снять pinned выбор, вернуться к auto.
         * WHY: zashboard отправляет DELETE когда пользователь сбрасывает
         * ручной выбор сервера в url-test/fallback группе. */
        if (conn->is_delete && s_pgm && s_cfg) {
            size_t nlen = plen - 9;
            char raw[512];
            if (nlen >= sizeof(raw)) nlen = sizeof(raw) - 1;
            memcpy(raw, p + 9, nlen);
            raw[nlen] = '\0';
            char grp[512];
            url_pct_decode(raw, grp, sizeof(grp));
            proxy_group_state_t *g = proxy_group_find(s_pgm, grp);
            if (!g) {
                const char e[] = "{\"message\":\"group not found\"}";
                http_send(conn, epoll_fd, 404, "application/json",
                          e, sizeof(e) - 1);
                return;
            }
            g->pinned = false;
            proxy_group_save_all_selections(s_pgm, s_cfg);
            http_send(conn, epoll_fd, 204, "application/json", "", 0);
            return;
        }
    }
    /* GET /group/{name}/delay?url=...&timeout=... — zashboard compat.
     * Mihomo-семантика: batch HC всех серверов группы, ответ = map
     * {server_name: ms}. Серверы с провалом HC — отсутствуют в ответе.
     * Обновляет gs->servers (latency/fail_count/available) → нажатие
     * молнии в zashboard синхронизирует состояние группы. */
    if (strncmp(p, "/group/", 7) == 0) {
        const char *qm   = strchr(p, '?');
        const char *qs   = qm ? qm + 1 : "";
        size_t      plen = qm ? (size_t)(qm - p) : strlen(p);
        if (plen > 13 && memcmp(p + plen - 6, "/delay", 6) == 0) {
            size_t nlen = plen - 7 - 6;  /* 7=len("/group/"), 6=len("/delay") */
            char raw[512];
            if (nlen >= sizeof(raw)) nlen = sizeof(raw) - 1;
            memcpy(raw, p + 7, nlen);
            raw[nlen] = '\0';
            char gname[512];
            url_pct_decode(raw, gname, sizeof(gname));
            proxy_group_state_t *gs = s_pgm
                ? proxy_group_find(s_pgm, gname) : NULL;
            if (!gs) {
                const char e[] = "{\"message\":\"group not found\"}";
                http_send(conn, epoll_fd, 404,
                          "application/json; charset=utf-8", e, sizeof(e) - 1);
                return;
            }
            route_clash_group_delay_batch(conn, epoll_fd, gs, qs);
            return;
        }
    }
    if (strcmp(p, "/connections") == 0) {
        if (conn->is_delete)
            /* DELETE /connections — close all; connections:[] = нет что закрывать */
            http_send(conn, epoll_fd, 204, "application/json", "", 0);
        else
            route_clash_connections(conn, epoll_fd);
        return;
    }
    /* DELETE /connections/{id} — закрыть конкретный relay по id */
    if (strncmp(p, "/connections/", 13) == 0 && conn->is_delete) {
        if (s_ds && p[13]) {
            uint32_t idx = (uint32_t)strtoul(p + 13, NULL, 10);
            dispatcher_close_relay(s_ds, idx);
        }
        http_send(conn, epoll_fd, 204, "application/json", "", 0);
        return;
    }
    /* GET|PUT /storage/{key} — zashboard настройки */
    if (strncmp(p, "/storage/", 9) == 0 && p[9]) {
        route_storage(conn, epoll_fd, p + 9);
        return;
    }
    /* PATCH /rules/disable — перед /rules чтобы точное совпадение не перехватило */
    if (strcmp(p, "/rules/disable") == 0 && conn->is_patch) {
        route_clash_rules_disable(conn, epoll_fd);
        return;
    }
    if (strcmp(p, "/rules") == 0) {
        route_clash_rules(conn, epoll_fd);
        return;
    }
    if (strcmp(p, "/providers/proxies") == 0) {
        route_clash_providers_proxies(conn, epoll_fd);
        return;
    }
    if (strcmp(p, "/providers/rules") == 0) {
        route_clash_providers_rules(conn, epoll_fd);
        return;
    }

    /* GET /api/status → JSON из --ipc status */
    if (strcmp(p, "/api/status") == 0) {
        route_api_status(conn, epoll_fd);
        return;
    }

    /* GET /api/groups → кэш /tmp/4eburnet-groups.json */
    if (strcmp(p, "/api/groups") == 0) {
        route_api_groups(conn, epoll_fd);
        return;
    }
    /* PATCH /api/groups/{name} — изменить параметры proxy-group */
    if (strncmp(p, "/api/groups/", 12) == 0 && p[12] && conn->is_patch) {
        route_api_groups_patch(conn, epoll_fd, p + 12); return;
    }

    /* GET /api/stats → --ipc stats */
    if (strcmp(p, "/api/stats") == 0) {
        route_ipc_passthrough(conn, epoll_fd, "stats");
        return;
    }

    /* GET /api/servers → UCI парсинг (только GET) */
    if (strcmp(p, "/api/servers") == 0 &&
        !conn->is_post && !conn->is_put && !conn->is_delete && !conn->is_patch) {
        route_api_servers(conn, epoll_fd);
        return;
    }

    /* GET /api/dns → UCI dns секция (только GET) */
    if (strcmp(p, "/api/dns") == 0 &&
        !conn->is_post && !conn->is_put && !conn->is_delete && !conn->is_patch) {
        route_api_dns(conn, epoll_fd);
        return;
    }

    /* GET /api/dns/upstream — текущий upstream_bypass */
    if (strcmp(p, "/api/dns/upstream") == 0 && !conn->is_post && !conn->is_patch) {
        route_api_dns_upstream_get(conn, epoll_fd);
        return;
    }

    /* PATCH /api/dns/upstream — сохранить upstream_bypass */
    if (strcmp(p, "/api/dns/upstream") == 0 && conn->is_patch) {
        route_api_dns_upstream_patch(conn, epoll_fd);
        return;
    }

    /* POST /api/dns/upstream/test — проверить latency DNS */
    if (strcmp(p, "/api/dns/upstream/test") == 0 && conn->is_post) {
        route_api_dns_upstream_test(conn, epoll_fd);
        return;
    }

    /* POST /api/control → управление демоном */
    if (strcmp(p, "/api/control") == 0 && conn->is_post) {
        route_api_control(conn, epoll_fd, s_api_token);
        return;
    }

    /* GET /api/geo → список geo баз */
    if (strncmp(p, "/api/geo", 8) == 0 && !conn->is_post) {
        route_api_geo(conn, epoll_fd);
        return;
    }

    /* GET /api/logs/download → скачать лог-файл как attachment */
    if (strcmp(p, "/api/logs/download") == 0 && !conn->is_post) {
        route_api_logs_download(conn, epoll_fd);
        return;
    }

    /* GET /api/logs → лог-файл */
    if (strncmp(p, "/api/logs", 9) == 0 && !conn->is_post) {
        route_api_logs(conn, epoll_fd);
        return;
    }

    /* GET /api/devices → ARP + DHCP + UCI политики */
    if (strcmp(p, "/api/devices") == 0 && !conn->is_post) {
        route_api_devices(conn, epoll_fd);
        return;
    }

    /* GET /api/backup → tar.gz /etc/config/4eburnet (допускается ?token=) */
    if ((strcmp(p, "/api/backup") == 0 ||
         strncmp(p, "/api/backup?", 12) == 0) && !conn->is_post) {
        route_api_backup(conn, epoll_fd);
        return;
    }

    /* POST /api/restore → восстановить конфиг из tar.gz */
    if (strcmp(p, "/api/restore") == 0 && conn->is_post) {
        route_api_restore(conn, epoll_fd);
        return;
    }

    /* ─── Dashboard Фаза 3 — CRUD + расширенные endpoints ─────────── */

    /* POST /api/servers — создать сервер */
    if (strcmp(p, "/api/servers") == 0 && conn->is_post) {
        route_api_servers_post(conn, epoll_fd); return;
    }
    /* PUT|DELETE /api/servers/{name} */
    if (strncmp(p, "/api/servers/", 13) == 0 && p[13]) {
        const char *sname = p + 13;
        if (conn->is_put)    { route_api_servers_put(conn, epoll_fd, sname); return; }
        if (conn->is_delete) { route_api_servers_delete(conn, epoll_fd, sname); return; }
    }
    /* POST /api/subscribe/parse */
    if (strcmp(p, "/api/subscribe/parse") == 0 && conn->is_post) {
        route_api_subscribe_parse(conn, epoll_fd); return;
    }
    /* POST /api/subscribe/import */
    if (strcmp(p, "/api/subscribe/import") == 0 && conn->is_post) {
        route_api_subscribe_import(conn, epoll_fd); return;
    }

    /* POST /api/rules — создать правило (перед /api/rules/test) */
    if (strcmp(p, "/api/rules") == 0 && conn->is_post) {
        route_api_rules_post(conn, epoll_fd); return;
    }
    /* POST /api/rules/test — тестировать совпадение */
    if (strcmp(p, "/api/rules/test") == 0 && conn->is_post) {
        route_api_rules_test(conn, epoll_fd); return;
    }
    /* PATCH|DELETE /api/rules/{id} */
    if (strncmp(p, "/api/rules/", 11) == 0 && p[11]) {
        const char *rid = p + 11;
        if (conn->is_patch)  { route_api_rules_patch(conn, epoll_fd, rid); return; }
        if (conn->is_delete) { route_api_rules_delete(conn, epoll_fd, rid); return; }
    }

    /* POST /api/providers/proxies */
    if (strcmp(p, "/api/providers/proxies") == 0 && conn->is_post) {
        route_api_providers_proxies_post(conn, epoll_fd); return;
    }
    /* PATCH /api/providers/proxies/{name} */
    if (strncmp(p, "/api/providers/proxies/", 23) == 0 && p[23] && conn->is_patch) {
        route_api_providers_proxies_patch(conn, epoll_fd, p + 23); return;
    }
    /* DELETE /api/providers/proxies/{name} */
    if (strncmp(p, "/api/providers/proxies/", 23) == 0 && p[23] && conn->is_delete) {
        route_api_providers_proxies_delete(conn, epoll_fd, p + 23); return;
    }
    /* POST /api/providers/rules */
    if (strcmp(p, "/api/providers/rules") == 0 && conn->is_post) {
        route_api_providers_rules_post(conn, epoll_fd); return;
    }
    /* PATCH /api/providers/rules/{name} */
    if (strncmp(p, "/api/providers/rules/", 21) == 0 && p[21] && conn->is_patch) {
        route_api_providers_rules_patch(conn, epoll_fd, p + 21); return;
    }
    /* DELETE /api/providers/rules/{name} */
    if (strncmp(p, "/api/providers/rules/", 21) == 0 && p[21] && conn->is_delete) {
        route_api_providers_rules_delete(conn, epoll_fd, p + 21); return;
    }

    /* PATCH /api/dns — изменить DNS настройки (перед /api/dns/...) */
    if (strcmp(p, "/api/dns") == 0 && conn->is_patch) {
        route_api_dns_patch(conn, epoll_fd); return;
    }
    /* POST /api/dns/cache/flush */
    if (strcmp(p, "/api/dns/cache/flush") == 0 && conn->is_post) {
        route_api_dns_cache_flush(conn, epoll_fd); return;
    }
    /* POST /api/dns/fakeip/flush */
    if (strcmp(p, "/api/dns/fakeip/flush") == 0 && conn->is_post) {
        route_api_dns_fakeip_flush(conn, epoll_fd); return;
    }
    /* GET /api/dns/test-upstream?upstream=X&type=Y */
    if (strncmp(p, "/api/dns/test-upstream", 22) == 0 && !conn->is_post && !conn->is_patch) {
        route_api_dns_test_upstream(conn, epoll_fd); return;
    }
    /* GET /api/dns/query?name=X&type=Y */
    if (strncmp(p, "/api/dns/query", 14) == 0 && !conn->is_post && !conn->is_patch) {
        route_api_dns_query(conn, epoll_fd); return;
    }
    /* GET /api/dns/stats */
    if (strcmp(p, "/api/dns/stats") == 0 && !conn->is_post && !conn->is_patch) {
        route_api_dns_stats(conn, epoll_fd); return;
    }
    /* GET /api/dns/policies */
    if (strcmp(p, "/api/dns/policies") == 0 &&
        !conn->is_post && !conn->is_patch && !conn->is_delete) {
        route_api_dns_policies_get(conn, epoll_fd); return;
    }
    /* POST /api/dns/policies */
    if (strcmp(p, "/api/dns/policies") == 0 && conn->is_post) {
        route_api_dns_policies_post(conn, epoll_fd); return;
    }
    /* PATCH /api/dns/policies/reorder */
    if (strcmp(p, "/api/dns/policies/reorder") == 0 && conn->is_patch) {
        route_api_dns_policies_reorder(conn, epoll_fd); return;
    }
    /* DELETE /api/dns/policies/{id} */
    if (strncmp(p, "/api/dns/policies/", 18) == 0 && p[18] && conn->is_delete) {
        route_api_dns_policies_delete(conn, epoll_fd, p + 18); return;
    }

    /* GET /api/dpi */
    if (strcmp(p, "/api/dpi") == 0 && !conn->is_post && !conn->is_patch) {
        route_api_dpi_get(conn, epoll_fd); return;
    }
    /* PATCH /api/dpi */
    if (strcmp(p, "/api/dpi") == 0 && conn->is_patch) {
        route_api_dpi_patch(conn, epoll_fd); return;
    }
    /* GET /api/sniffer */
    if (strcmp(p, "/api/sniffer") == 0 && !conn->is_post && !conn->is_patch) {
        route_api_sniffer_get(conn, epoll_fd); return;
    }
    /* PATCH /api/sniffer */
    if (strcmp(p, "/api/sniffer") == 0 && conn->is_patch) {
        route_api_sniffer_patch(conn, epoll_fd); return;
    }
    /* GET /api/sniffer/stats */
    if (strcmp(p, "/api/sniffer/stats") == 0 && !conn->is_post && !conn->is_patch) {
        route_api_sniffer_stats(conn, epoll_fd); return;
    }
    /* GET /api/network */
    if (strcmp(p, "/api/network") == 0 && !conn->is_post && !conn->is_patch) {
        route_api_network_get(conn, epoll_fd); return;
    }
    /* PATCH /api/network */
    if (strcmp(p, "/api/network") == 0 && conn->is_patch) {
        route_api_network_patch(conn, epoll_fd); return;
    }
    /* GET /api/cdn */
    if (strcmp(p, "/api/cdn") == 0 && !conn->is_post && !conn->is_patch) {
        route_api_cdn_get(conn, epoll_fd); return;
    }
    /* PATCH /api/cdn */
    if (strcmp(p, "/api/cdn") == 0 && conn->is_patch) {
        route_api_cdn_patch(conn, epoll_fd); return;
    }
    /* POST /api/geo/update — async geo update (перед /api/geo GET) */
    if (strcmp(p, "/api/geo/update") == 0 && conn->is_post) {
        route_api_geo_update(conn, epoll_fd); return;
    }

    /* PATCH /api/devices/{mac} */
    if (strncmp(p, "/api/devices/", 13) == 0 && p[13] && conn->is_patch) {
        route_api_devices_patch(conn, epoll_fd, p + 13); return;
    }

    /* Всё остальное → 404 */
    const char body404[] = "{\"error\":\"not found\"}";
    http_send(conn, epoll_fd, 404, "application/json",
              body404, sizeof(body404) - 1);
}

/* ── GET /api/backup — выгрузить tar.gz конфига ──────────────────── */
static void route_api_backup(HttpConn *conn, int epoll_fd)
{
    static char backup_buf[262144]; /* 256KB — gzip конфига в BSS */
    static char hdr_buf[384];

    /* Z3: backup содержит api_token — требуем авторизацию */
    if (s_api_token[0] != '\0') {
        bool auth_ok = false;
        const char *auth = strstr(conn->buf, "Authorization: Bearer ");
        if (!auth) auth = strstr(conn->buf, "authorization: bearer ");
        /* Для GET token также принимается через ?token= */
        if (!auth) {
            auth = strstr(conn->path, "?token=");
            if (auth) auth += 7; /* пропустить "?token=" */
        }
        if (auth) {
            size_t tlen = strlen(s_api_token);
            auth_ok = (strncmp(auth, s_api_token, tlen) == 0 &&
                       (auth[tlen] == '\r' || auth[tlen] == '\n' ||
                        auth[tlen] == '\0' || auth[tlen] == '&'));
        }
        if (!auth_ok) {
            const char e[] = "{\"ok\":false,\"error\":\"unauthorized\"}";
            http_send(conn, epoll_fd, 401, "application/json", e, sizeof(e)-1);
            return;
        }
    }

    FILE *f = popen("/bin/tar -czf - /etc/config/4eburnet 2>/dev/null", "r");
    if (!f) {
        const char e[] = "{\"ok\":false,\"error\":\"popen failed\"}";
        http_send(conn, epoll_fd, 500, "application/json", e, sizeof(e)-1);
        return;
    }

    size_t total = 0, n;
    while (total < sizeof(backup_buf)) {
        n = fread(backup_buf + total, 1, sizeof(backup_buf) - total, f);
        if (n == 0) break;
        total += n;
    }
    /* SA_NOCLDWAIT в main.c мешает pclose waitpid — игнорируем rc */
    pclose(f);

    if (total == 0) {
        const char e[] = "{\"ok\":false,\"error\":\"tar failed\"}";
        http_send(conn, epoll_fd, 500, "application/json", e, sizeof(e)-1);
        return;
    }

    /* Дата YYYYMMDD для имени файла */
    time_t      now = time(NULL);
    struct tm  *tm  = gmtime(&now);
    char        date[16];
    snprintf(date, sizeof(date), "%04d%02d%02d",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);

    /* MIPS: cors[384] в route_api_backup — static для единообразия с http_send/redirect/file. */
    static char s_backup_cors[384];
    cors_origin_hdr(conn->buf, s_backup_cors, sizeof(s_backup_cors));
    int hn = snprintf(hdr_buf, sizeof(hdr_buf),
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/gzip\r\n"
        "Content-Length: %zu\r\n"
        "Content-Disposition: attachment; "
            "filename=\"4eburnet-backup-%s.tar.gz\"\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        total, date, s_backup_cors);

    if (hn <= 0 || hn >= (int)sizeof(hdr_buf)) {
        const char e[] = "{\"ok\":false,\"error\":\"header overflow\"}";
        http_send(conn, epoll_fd, 500, "application/json", e, sizeof(e)-1);
        return;
    }

    if (conn_queue_write(conn, hdr_buf, (size_t)hn) < 0 ||
        conn_queue_write(conn, backup_buf, total) < 0) {
        conn_close(conn, epoll_fd);
        return;
    }
    log_msg(LOG_INFO, "backup: отправлено %zu байт", total);
    if (conn_flush(conn, epoll_fd) < 0 || !conn->send_buf)
        conn_close(conn, epoll_fd);
}

/* ── POST /api/restore — восстановить конфиг из tar.gz ──────────── */
static void route_api_restore(HttpConn *conn, int epoll_fd)
{
    static char restore_buf[65536]; /* 64KB в BSS */

    /* --- Авторизация (паттерн из route_api_control) --- */
    if (s_api_token[0] != '\0') {
        bool auth_ok = false;
        /* Z2: искать Authorization только в заголовках, не в теле */
        const char *hdr_limit = strstr(conn->buf, "\r\n\r\n");
        size_t search_len = hdr_limit
            ? (size_t)(hdr_limit - conn->buf)
            : (size_t)conn->buf_len;
        char saved = hdr_limit ? hdr_limit[0] : '\0';
        if (hdr_limit) ((char *)hdr_limit)[0] = '\0';
        const char *auth = strstr(conn->buf, "Authorization: Bearer ");
        if (!auth) auth = strstr(conn->buf, "authorization: bearer ");
        if (hdr_limit) ((char *)hdr_limit)[0] = saved;
        (void)search_len;
        if (auth) {
            auth += strlen("Authorization: Bearer ");
            size_t tlen = strlen(s_api_token);
            auth_ok = (strncmp(auth, s_api_token, tlen) == 0 &&
                       (auth[tlen] == '\r' || auth[tlen] == '\n' ||
                        auth[tlen] == '\0'));
        }
        if (!auth_ok) {
            const char e[] = "{\"ok\":false,\"error\":\"unauthorized\"}";
            http_send(conn, epoll_fd, 401, "application/json", e, sizeof(e)-1);
            return;
        }
    } else {
        /* WHY: при fresh-install api_token не настроен. Разрешаем localhost
         * для первоначальной настройки. С других IP — 403 (security). */
        if (conn->peer_addr.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
            const char e[] = "{\"ok\":false,\"error\":\"api_token not configured\"}";
            http_send(conn, epoll_fd, 403, "application/json", e, sizeof(e)-1);
            return;
        }
    }

    /* --- Проверить Content-Length --- */
    if (conn->content_length == 0) {
        const char e[] = "{\"ok\":false,\"error\":\"Content-Length required\"}";
        http_send(conn, epoll_fd, 411, "application/json", e, sizeof(e)-1);
        return;
    }
    /* content_length == -1: парсер получил CL > HTTP_MAX_BODY */
    if (conn->content_length < 0 ||
        conn->content_length > (int)sizeof(restore_buf)) {
        const char e[] = "{\"ok\":false,\"error\":\"payload too large (max 64KB)\"}";
        http_send(conn, epoll_fd, 413, "application/json", e, sizeof(e)-1);
        return;
    }

    /* --- Найти конец заголовков --- */
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) {
        const char e[] = "{\"ok\":false,\"error\":\"bad request\"}";
        http_send(conn, epoll_fd, 400, "application/json", e, sizeof(e)-1);
        return;
    }

    /* Z1: защита от slow body hold — блокирующий read не будет ждать вечно */
    {
        struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
        setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    /* --- Переключить в blocking --- */
    int fl = fcntl(conn->fd, F_GETFL);
    if (fl != -1)
        fcntl(conn->fd, F_SETFL, fl & ~O_NONBLOCK);

    /* --- Скопировать prefetch + дочитать остаток --- */
    const char *body_start = hdr_end + 4;
    size_t prefetch = (size_t)(conn->buf + conn->buf_len - body_start);
    if (prefetch > (size_t)conn->content_length)
        prefetch = (size_t)conn->content_length;
    memcpy(restore_buf, body_start, prefetch);
    size_t received = prefetch;

    while (received < (size_t)conn->content_length) {
        ssize_t n = read(conn->fd,
                         restore_buf + received,
                         (size_t)conn->content_length - received);
        if (n <= 0) break;
        received += (size_t)n;
    }

    if (received != (size_t)conn->content_length) {
        const char e[] = "{\"ok\":false,\"error\":\"incomplete body\"}";
        http_send(conn, epoll_fd, 400, "application/json", e, sizeof(e)-1);
        return;
    }

    /* --- Распаковать через stdin pipe --- */
    FILE *f = popen("/bin/tar -xzf - -C / 2>/dev/null", "w");
    if (!f) {
        const char e[] = "{\"ok\":false,\"error\":\"popen failed\"}";
        http_send(conn, epoll_fd, 500, "application/json", e, sizeof(e)-1);
        return;
    }
    /* Z6: проверить gzip magic bytes до передачи tar — отклонить не-gzip данные */
    if (received < 2 || (unsigned char)restore_buf[0] != 0x1f ||
                        (unsigned char)restore_buf[1] != 0x8b) {
        const char e[] = "{\"ok\":false,\"error\":\"not a gzip archive\"}";
        http_send(conn, epoll_fd, 400, "application/json", e, sizeof(e)-1);
        return;
    }

    /* Z6 audit_v42: pclose rc ненадёжен (SA_NOCLDWAIT в main.c).
       Формат входных данных проверяем через gzip magic выше. */
    size_t written = fwrite(restore_buf, 1, received, f);
    pclose(f); /* rc ненадёжен из-за SA_NOCLDWAIT */

    if (written != received) {
        const char e[] = "{\"ok\":false,\"error\":\"restore failed\"}";
        http_send(conn, epoll_fd, 500, "application/json", e, sizeof(e)-1);
        return;
    }

    /* --- Сначала ответ, потом SIGHUP (иначе ответ не дойдёт) --- */
    pid_t reload_pid = 0;
    FILE *pf = fopen("/var/run/4eburnet.pid", "r");
    if (pf) {
        if (fscanf(pf, "%d", (int *)&reload_pid) != 1)
            reload_pid = 0;
        fclose(pf);
    }

    log_msg(LOG_INFO, "restore: применено %zu байт, SIGHUP → pid %d",
            received, (int)reload_pid);
    const char ok[] = "{\"ok\":true}";
    http_send(conn, epoll_fd, 200, "application/json", ok, sizeof(ok)-1);

    if (reload_pid > 0)
        kill(reload_pid, SIGHUP);
}

static void run_initd(const char *action); /* forward — определена ниже */

/* Допустимые символы UCI-имени секции: alphanumeric + _ - */
static bool uci_name_safe(const char *s)
{
    if (!s || !s[0] || strlen(s) > 63) return false;
    for (const char *p = s; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return false;
    }
    return true;
}

/* Найти анонимную UCI-секцию traffic_rule по type+value.
 * Заполняет sec_out именем секции (e.g. "cfg123abc"), возвращает 0 или -1.
 * Если val_s пуст — ищет только по type (для MATCH). */
static int uci_find_traffic_rule(const char *type_s, const char *val_s,
                                  char *sec_out, size_t sec_sz)
{
    static char buf[8192];
    const char *const argv[] = {"uci", "show", "4eburnet", NULL};
    memset(buf, 0, sizeof(buf));
    exec_cmd_safe(argv, buf, sizeof(buf) - 1);
    const char *p = buf;
    while ((p = strstr(p, "=traffic_rule")) != NULL) {
        const char *bol = p;
        while (bol > buf && *(bol - 1) != '\n') bol--;
        if (strncmp(bol, "4eburnet.", 9) != 0) { p++; continue; }
        const char *sec_start = bol + 9, *sec_end = p;
        bool has_dot = false;
        for (const char *q = sec_start; q < sec_end; q++)
            if (*q == '.') { has_dot = true; break; }
        if (has_dot) { p++; continue; }
        size_t sn = (size_t)(sec_end - sec_start);
        if (sn == 0 || sn >= sec_sz || sn >= 32) { p++; continue; }
        char sec[32] = {0};
        memcpy(sec, sec_start, sn);
        char tp[128], vp[256];
        snprintf(tp, sizeof(tp), "4eburnet.%s.type='%s'", sec, type_s);
        snprintf(vp, sizeof(vp), "4eburnet.%s.value='%s'", sec, val_s);
        bool type_ok = strstr(buf, tp) != NULL;
        bool val_ok  = (!val_s || !val_s[0]) || strstr(buf, vp) != NULL;
        if (type_ok && val_ok) {
            memcpy(sec_out, sec, sn);
            sec_out[sn] = '\0';
            return 0;
        }
        p++;
    }
    return -1;
}

/* SIGHUP демону если PID известен, иначе run_initd("reload"). */
static void reload_daemon(void)
{
    FILE *pf = fopen("/var/run/4eburnet.pid", "r");
    if (pf) {
        int pid = 0;
        if (fscanf(pf, "%d", &pid) == 1 && pid > 0)
            kill(pid, SIGHUP);
        else
            run_initd("reload");
        fclose(pf);
    } else {
        run_initd("reload");
    }
}

/* WHY: execv вместо system() — нет shell injection риска при будущей
 * параметризации; fork async — parent не ждёт, epoll не блокируется. */
static void run_initd(const char *action)
{
    pid_t pid = fork();
    if (pid == 0) {
        const char *argv[] = {"/etc/init.d/4eburnet", action, NULL};
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    /* async: parent не ждёт завершения child */
}

/* ── POST /api/control — управление демоном ──────────────────────── */
/* Принимает {"action":"start|stop|reload|..."}, выполняет через init.d. */
static void route_api_control(HttpConn *conn, int epoll_fd, const char *api_token)
{
    /* Rate limit 200мс per IP: защита от flood POST /api/control */
    if (rate_limit_check(conn->peer_addr.sin_addr.s_addr)) {
        http_send(conn, epoll_fd, 429, "application/json",
                  "{\"error\":\"rate limit\"}", 21);
        return;
    }

    /* Если токен задан — требовать Authorization: Bearer <token> */
    if (api_token[0] != '\0') {
        bool auth_ok = false;
        const char *auth = strstr(conn->buf, "Authorization: Bearer ");
        if (!auth) auth = strstr(conn->buf, "authorization: bearer ");
        if (auth) {
            auth += strlen("Authorization: Bearer ");
            size_t tlen = strlen(api_token);
            /* З3: constant-time — volatile diff предотвращает ранний выход компилятора,
             * исключая timing side-channel при побайтовом угадывании токена с LAN */
            volatile uint8_t diff = 0;
            for (size_t i = 0; i < tlen; i++)
                diff |= (uint8_t)auth[i] ^ (uint8_t)api_token[i];
            auth_ok = (diff == 0) && (strlen(auth) == tlen ||
                       auth[tlen] == '\r' || auth[tlen] == '\n');
        }
        if (!auth_ok) {
            const char err[] = "{\"ok\":false,\"error\":\"unauthorized\"}";
            http_send(conn, epoll_fd, 401, "application/json",
                      err, sizeof(err) - 1);
            return;
        }
    } else {
        /* WHY: при fresh-install api_token не настроен. Разрешаем localhost
         * для первоначальной настройки. С других IP — 403 (security). */
        if (conn->peer_addr.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
            const char err[] = "{\"ok\":false,\"error\":\"api_token not configured\"}";
            http_send(conn, epoll_fd, 403, "application/json",
                      err, sizeof(err) - 1);
            return;
        }
    }

    /* Тело запроса расположено после \r\n\r\n */
    const char *body = strstr(conn->buf, "\r\n\r\n");
    if (body) body += 4;

    if (!body || !*body) {
        const char err[] = "{\"ok\":false,\"error\":\"empty body\"}";
        http_send(conn, epoll_fd, 400, "application/json",
                  err, sizeof(err) - 1);
        return;
    }

    /* Найти "action" без полного JSON-парсера */
    const char *act = strstr(body, "\"action\"");
    if (!act) {
        const char err[] = "{\"ok\":false,\"error\":\"no action\"}";
        http_send(conn, epoll_fd, 400, "application/json",
                  err, sizeof(err) - 1);
        return;
    }

    /* Пропустить до значения: ..."action":"VALUE"... */
    const char *val = strchr(act + 8, ':');
    if (!val) val = "";
    else {
        val++;
        while (*val == ' ' || *val == '"' || *val == '\'') val++;
    }

    const char *ok_resp  = "{\"ok\":true}";
    const char *err_resp = "{\"ok\":false,\"error\":\"unknown action\"}";

    if (strncmp(val, "start", 5) == 0) {
        run_initd("start");
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "stop", 4) == 0) {
        run_initd("stop");
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "reload", 6) == 0) {
        /* Перезагрузить конфиг через SIGHUP если PID известен,
           иначе через init.d reload */
        /* Daemon mode: SIGHUP → handle_reload (main.c).
           SIGUSR1 не перехватывается — убивает процесс. */
        FILE *pf = fopen("/var/run/4eburnet.pid", "r");
        if (pf) {
            int pid = 0;
            if (fscanf(pf, "%d", &pid) == 1 && pid > 0)
                kill(pid, SIGHUP);
            else
                run_initd("reload");
            fclose(pf);
        } else {
            run_initd("reload");
        }
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "dpi_clear", 9) == 0) {
#if CONFIG_EBURNET_DPI
        dpi_adapt_init(&g_dpi_adapt);
        unlink("/etc/4eburnet/dpi_cache.bin");
        log_msg(LOG_INFO, "DPI adapt: кэш очищен");
#endif
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "flow_offload_on", 15) == 0) {
        /* Сначала ответ — nft_flow_offload_enable блокирует epoll (~2с),
         * но это редкое ручное действие; форк нельзя: g_flow_offload_active
         * static в nftables.c и не виден родителю после fork. */
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
        nft_flow_offload_enable(s_cfg && s_cfg->lan_interface[0]
                                ? s_cfg->lan_interface : NULL);
        log_msg(LOG_INFO, "flow offload: включён из dashboard");
    } else if (strncmp(val, "flow_offload_off", 16) == 0) {
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
        nft_flow_offload_disable();
        log_msg(LOG_INFO, "flow offload: выключен из dashboard");
    } else if (strncmp(val, "tc_fast_on", 10) == 0) {
        /* Аналогично: g_tc_fast_active static → только send-first паттерн */
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
        if (s_cfg) {
            const char *iface = s_cfg->lan_interface[0]
                                ? s_cfg->lan_interface : "br-lan";
            tc_fast_enable(iface, s_cfg->lan_prefix, s_cfg->lan_mask);
            log_msg(LOG_INFO, "tc fast: включён из dashboard");
        }
    } else if (strncmp(val, "tc_fast_off", 11) == 0) {
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
        {
            const char *iface = (s_cfg && s_cfg->lan_interface[0])
                                ? s_cfg->lan_interface : "br-lan";
            tc_fast_disable(iface);
            log_msg(LOG_INFO, "tc fast: выключен из dashboard");
        }
    } else if (strncmp(val, "dpi_on", 6) == 0) {
        /* uci commit синхронный — SIGHUP только после завершения */
        {
            const char *const argv_set[]    = {"uci", "set",
                                               "4eburnet.main.dpi_enabled=1", NULL};
            const char *const argv_commit[] = {"uci", "commit", "4eburnet", NULL};
            exec_cmd_safe(argv_set,    NULL, 0);
            exec_cmd_safe(argv_commit, NULL, 0);
        }
        FILE *pf = fopen("/var/run/4eburnet.pid", "r");
        if (pf) {
            int _pid = 0;
            if (fscanf(pf, "%d", &_pid) == 1 && _pid > 0) kill(_pid, SIGHUP);
            fclose(pf);
        }
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "dpi_off", 7) == 0) {
        {
            const char *const argv_set[]    = {"uci", "set",
                                               "4eburnet.main.dpi_enabled=0", NULL};
            const char *const argv_commit[] = {"uci", "commit", "4eburnet", NULL};
            exec_cmd_safe(argv_set,    NULL, 0);
            exec_cmd_safe(argv_commit, NULL, 0);
        }
        FILE *pf = fopen("/var/run/4eburnet.pid", "r");
        if (pf) {
            int _pid = 0;
            if (fscanf(pf, "%d", &_pid) == 1 && _pid > 0) kill(_pid, SIGHUP);
            fclose(pf);
        }
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "ja3_expected", 12) == 0) {
        /* Установить ожидаемый JA3 хэш (32 hex + \0).
         * Тело: {"action":"ja3_expected","hash":"<32hex>"} */
        const char *hp = strstr(body, "\"hash\"");
        if (hp) {
            hp = strchr(hp + 6, ':');
            if (hp) {
                while (*hp == ':' || *hp == ' ' || *hp == '"') hp++;
                size_t hl = 0;
                while (hp[hl] && hp[hl] != '"' && hp[hl] != '\r' &&
                       hp[hl] != '\n' && hl < 32) hl++;
                if (!is_md5_hex(hp, hl)) {
                    http_send(conn, epoll_fd, 400, "application/json",
                              "{\"error\":\"invalid ja3 hash\"}", 27);
                    return;
                }
                memcpy(g_ja3_expected, hp, hl);
                g_ja3_expected[hl] = '\0';
                char uci_arg[80];
                snprintf(uci_arg, sizeof(uci_arg),
                         "4eburnet.@main[0].ja3_expected=%s",
                         g_ja3_expected);
                const char *const argv_set[]    = {"uci", "set", uci_arg, NULL};
                const char *const argv_commit[] = {"uci", "commit", "4eburnet", NULL};
                exec_cmd_safe(argv_set,    NULL, 0);
                exec_cmd_safe(argv_commit, NULL, 0);
                log_msg(LOG_INFO, "JA3 expected hash: %s (сохранён в UCI)", g_ja3_expected);
            }
        }
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "group_select", 12) == 0) {
        if (!s_pgm || !s_cfg) {
            http_send(conn, epoll_fd, 503, "application/json",
                      "{\"ok\":false,\"error\":\"no groups\"}", 31);
            return;
        }
        char grp[64] = {0}, srv[128] = {0};
        http_json_get_str(body, "group",  grp, sizeof(grp));
        http_json_get_str(body, "server", srv, sizeof(srv));
        if (!grp[0] || !srv[0]) {
            http_send(conn, epoll_fd, 400, "application/json",
                      "{\"ok\":false,\"error\":\"missing group or server\"}", 46);
            return;
        }
        proxy_group_state_t *gs = proxy_group_find(s_pgm, grp);
        if (!gs) {
            http_send(conn, epoll_fd, 400, "application/json",
                      "{\"ok\":false,\"error\":\"group not found\"}", 38);
            return;
        }
        int found = 0;
        for (int i = 0; i < gs->server_count; i++) {
            const ServerConfig *sc = config_get_server(s_cfg, gs->servers[i].server_idx);
            if (sc && strcmp(sc->name, srv) == 0) {
                gs->selected_idx = i;
                found = 1;
                break;
            }
        }
        if (found) {
            http_send(conn, epoll_fd, 200, "application/json",
                      ok_resp, strlen(ok_resp));
        } else {
            http_send(conn, epoll_fd, 400, "application/json",
                      "{\"ok\":false,\"error\":\"server not found in group\"}", 48);
        }
    } else if (strncmp(val, "group_test", 10) == 0) {
        /* WHY: fork изолирует health-check; parent отвечает немедленно, не блокирует epoll */
        if (s_pgm) {
            pid_t pid = fork();
            if (pid == 0) {
                proxy_group_tick(s_pgm);
                _exit(0);
            }
        }
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "device_policy_set", 17) == 0) {
        /* Установить per-device политику маршрутизации по MAC */
        char mac_raw[32]  = {0};
        char policy_s[16] = {0};
        char name_s[64]   = {0};

        http_json_get_str(body, "mac",    mac_raw,  sizeof(mac_raw));
        http_json_get_str(body, "policy", policy_s, sizeof(policy_s));
        http_json_get_str(body, "name",   name_s,   sizeof(name_s));

        /* Валидация MAC: ровно 17 символов XX:XX:XX:XX:XX:XX */
        int mac_ok = (strlen(mac_raw) == 17);
        if (mac_ok) {
            for (int i = 0; i < 17; i++) {
                if (i % 3 == 2) {
                    if (mac_raw[i] != ':') { mac_ok = 0; break; }
                } else {
                    char c = (char)tolower((unsigned char)mac_raw[i]);
                    if (!((c>='0'&&c<='9')||(c>='a'&&c<='f')))
                        { mac_ok = 0; break; }
                }
            }
        }
        if (!mac_ok) {
            const char e[] = "{\"ok\":false,\"error\":\"invalid mac\"}";
            http_send(conn, epoll_fd, 400, "application/json",
                      e, sizeof(e) - 1);
            return;
        }

        /* Валидация и преобразование policy */
        device_policy_t pol_val = DEVICE_POLICY_DEFAULT;
        if      (strcmp(policy_s, "proxy")   == 0) pol_val = DEVICE_POLICY_PROXY;
        else if (strcmp(policy_s, "bypass")  == 0) pol_val = DEVICE_POLICY_BYPASS;
        else if (strcmp(policy_s, "block")   == 0) pol_val = DEVICE_POLICY_BLOCK;
        else if (strcmp(policy_s, "default") == 0) pol_val = DEVICE_POLICY_DEFAULT;
        else {
            const char e[] = "{\"ok\":false,\"error\":\"invalid policy\"}";
            http_send(conn, epoll_fd, 400, "application/json",
                      e, sizeof(e) - 1);
            return;
        }

        /* Применить в памяти: найти существующую запись или добавить */
        if (s_dm) {
            /* device_policy_find возвращает const — ищем напрямую */
            device_config_t *found = NULL;
            for (int i = 0; i < s_dm->count; i++) {
                if (strcmp(s_dm->devices[i].mac_str, mac_raw) == 0) {
                    found = &s_dm->devices[i];
                    break;
                }
            }
            if (!found) {
                /* Новое устройство: собрать device_config_t */
                static device_config_t nd_static;
                memset(&nd_static, 0, sizeof(nd_static));
                snprintf(nd_static.mac_str, sizeof(nd_static.mac_str), "%s", mac_raw);
                /* Парсинг MAC-байт из строки */
                unsigned int b[6] = {0};
                if (sscanf(mac_raw, "%x:%x:%x:%x:%x:%x",
                           &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) == 6) {
                    for (int i = 0; i < 6; i++)
                        nd_static.mac[i] = (uint8_t)b[i];
                }
                nd_static.policy  = pol_val;
                nd_static.enabled = true;
                if (name_s[0])
                    snprintf(nd_static.name, sizeof(nd_static.name), "%s", name_s);
                if (device_policy_add(s_dm, &nd_static) < 0) {
                    log_msg(LOG_WARN,
                        "device_policy_set: OOM при добавлении %s", mac_raw);
                    const char oom[] =
                        "{\"ok\":false,\"error\":\"out of memory\"}";
                    http_send(conn, epoll_fd, 500, "application/json",
                              oom, sizeof(oom) - 1);
                    return;
                }
            } else {
                found->policy = pol_val;
                if (name_s[0])
                    snprintf(found->name, sizeof(found->name), "%s", name_s);
            }
            /* Применить nftables без перезапуска демона */
            const char *iface = (s_cfg && s_cfg->lan_interface[0])
                                ? s_cfg->lan_interface : "br-lan";
            device_policy_apply(s_dm, iface);
        }

        /* Нормализовать MAC для UCI секции: dev_aabbccddeeff */
        char sec_name[32] = "dev_";
        int  sn = 4;
        for (int i = 0; i < 17; i++) {
            if (mac_raw[i] != ':')
                sec_name[sn++] = (char)tolower((unsigned char)mac_raw[i]);
        }
        sec_name[sn] = '\0';

        /* uci set 4eburnet.SEC=device_config (создать секцию) */
        static char uci_sec_arg[64];
        snprintf(uci_sec_arg, sizeof(uci_sec_arg),
                 "4eburnet.%s=device_config", sec_name);
        const char *const argv_type[] = {"uci", "set", uci_sec_arg, NULL};
        exec_cmd_safe(argv_type, NULL, 0);

        /* uci set 4eburnet.SEC.policy=VAL */
        static char uci_pol_arg[64];
        snprintf(uci_pol_arg, sizeof(uci_pol_arg),
                 "4eburnet.%s.policy=%s", sec_name, policy_s);
        const char *const argv_pol[] = {"uci", "set", uci_pol_arg, NULL};
        exec_cmd_safe(argv_pol, NULL, 0);

        /* uci set 4eburnet.SEC.mac=MAC */
        static char uci_mac_arg[64];
        snprintf(uci_mac_arg, sizeof(uci_mac_arg),
                 "4eburnet.%s.mac=%s", sec_name, mac_raw);
        const char *const argv_mac[] = {"uci", "set", uci_mac_arg, NULL};
        exec_cmd_safe(argv_mac, NULL, 0);

        /* uci set 4eburnet.SEC.name=NAME (только если передано) */
        if (name_s[0]) {
            static char uci_name_arg[128];
            snprintf(uci_name_arg, sizeof(uci_name_arg),
                     "4eburnet.%s.name=%s", sec_name, name_s);
            const char *const argv_name[] = {"uci", "set", uci_name_arg, NULL};
            exec_cmd_safe(argv_name, NULL, 0);
        }

        /* uci commit 4eburnet */
        const char *const argv_commit[] = {"uci", "commit", "4eburnet", NULL};
        exec_cmd_safe(argv_commit, NULL, 0);

        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "cdn_update", 10) == 0) {
#if CONFIG_EBURNET_DPI
        if (s_cfg) {
            int cdnfd = cdn_updater_update_async(s_cfg);
            if (cdnfd >= 0) close(cdnfd);  /* fire-and-forget */
        }
#endif
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));

    } else if (strncmp(val, "server_add", 10) == 0) {
        char srv_name[64] = {0}, proto[16] = {0};
        char address[256] = {0}, port_s[8] = {0};
        http_json_get_str(body, "name",    srv_name, sizeof(srv_name));
        http_json_get_str(body, "proto",   proto,    sizeof(proto));
        http_json_get_str(body, "address", address,  sizeof(address));
        http_json_get_str(body, "port",    port_s,   sizeof(port_s));
        long port_l = port_s[0] ? strtol(port_s, NULL, 10) : 0;
        static const char *const allowed_protos[] = {
            "vless","trojan","shadowsocks","hysteria2","vmess", NULL};
        bool proto_ok = false;
        for (int k = 0; allowed_protos[k]; k++)
            if (strcmp(proto, allowed_protos[k]) == 0) { proto_ok = true; break; }
        if (!srv_name[0] || !uci_name_safe(srv_name) || !proto_ok ||
            !address[0]  || port_l < 1 || port_l > 65535) {
            const char e[] = "{\"ok\":false,\"error\":\"invalid params\"}";
            http_send(conn, epoll_fd, 400, "application/json", e, sizeof(e) - 1);
        } else {
            static char sa0[128], sa1[128], sa2[320], sa3[80], sa4[80];
            snprintf(sa0, sizeof(sa0), "4eburnet.%s=server",       srv_name);
            snprintf(sa1, sizeof(sa1), "4eburnet.%s.protocol=%s",  srv_name, proto);
            snprintf(sa2, sizeof(sa2), "4eburnet.%s.address=%s",   srv_name, address);
            snprintf(sa3, sizeof(sa3), "4eburnet.%s.port=%ld",     srv_name, port_l);
            snprintf(sa4, sizeof(sa4), "4eburnet.%s.enabled=1",    srv_name);
            const char *const va0[] = {"uci","set",sa0,NULL};
            const char *const va1[] = {"uci","set",sa1,NULL};
            const char *const va2[] = {"uci","set",sa2,NULL};
            const char *const va3[] = {"uci","set",sa3,NULL};
            const char *const va4[] = {"uci","set",sa4,NULL};
            const char *const vac[] = {"uci","commit","4eburnet",NULL};
            exec_cmd_safe(va0,NULL,0); exec_cmd_safe(va1,NULL,0);
            exec_cmd_safe(va2,NULL,0); exec_cmd_safe(va3,NULL,0);
            exec_cmd_safe(va4,NULL,0); exec_cmd_safe(vac,NULL,0);
            reload_daemon();
            http_send(conn, epoll_fd, 200, "application/json",
                      ok_resp, strlen(ok_resp));
        }

    } else if (strncmp(val, "server_delete", 13) == 0) {
        char srv_name[64] = {0};
        http_json_get_str(body, "name", srv_name, sizeof(srv_name));
        if (!srv_name[0] || !uci_name_safe(srv_name)) {
            const char e[] = "{\"ok\":false,\"error\":\"invalid name\"}";
            http_send(conn, epoll_fd, 400, "application/json", e, sizeof(e) - 1);
        } else {
            static char sd0[128];
            snprintf(sd0, sizeof(sd0), "4eburnet.%s", srv_name);
            const char *const vd0[] = {"uci","delete",sd0,NULL};
            const char *const vdc[] = {"uci","commit","4eburnet",NULL};
            exec_cmd_safe(vd0,NULL,0); exec_cmd_safe(vdc,NULL,0);
            reload_daemon();
            http_send(conn, epoll_fd, 200, "application/json",
                      ok_resp, strlen(ok_resp));
        }

    } else if (strncmp(val, "provider_add", 12) == 0) {
        char pname[64] = {0}, url[512] = {0}, intv_s[8] = {0};
        http_json_get_str(body, "name",     pname,  sizeof(pname));
        http_json_get_str(body, "url",      url,    sizeof(url));
        http_json_get_str(body, "interval", intv_s, sizeof(intv_s));
        long intv = intv_s[0] ? strtol(intv_s, NULL, 10) : 86400;
        if (!pname[0] || !uci_name_safe(pname) || !url[0]) {
            const char e[] = "{\"ok\":false,\"error\":\"invalid params\"}";
            http_send(conn, epoll_fd, 400, "application/json", e, sizeof(e) - 1);
        } else {
            static char pb0[128], pb1[640], pb2[80], pb3[80];
            snprintf(pb0, sizeof(pb0), "4eburnet.%s=proxy_provider", pname);
            snprintf(pb1, sizeof(pb1), "4eburnet.%s.url=%s",         pname, url);
            snprintf(pb2, sizeof(pb2), "4eburnet.%s.interval=%ld",   pname, intv);
            snprintf(pb3, sizeof(pb3), "4eburnet.%s.enabled=1",      pname);
            const char *const vp0[] = {"uci","set",pb0,NULL};
            const char *const vp1[] = {"uci","set",pb1,NULL};
            const char *const vp2[] = {"uci","set",pb2,NULL};
            const char *const vp3[] = {"uci","set",pb3,NULL};
            const char *const vpc[] = {"uci","commit","4eburnet",NULL};
            exec_cmd_safe(vp0,NULL,0); exec_cmd_safe(vp1,NULL,0);
            exec_cmd_safe(vp2,NULL,0); exec_cmd_safe(vp3,NULL,0);
            exec_cmd_safe(vpc,NULL,0);
            reload_daemon();
            http_send(conn, epoll_fd, 200, "application/json",
                      ok_resp, strlen(ok_resp));
        }

    } else if (strncmp(val, "provider_delete", 15) == 0) {
        char pname[64] = {0};
        http_json_get_str(body, "name", pname, sizeof(pname));
        if (!pname[0] || !uci_name_safe(pname)) {
            const char e[] = "{\"ok\":false,\"error\":\"invalid name\"}";
            http_send(conn, epoll_fd, 400, "application/json", e, sizeof(e) - 1);
        } else {
            static char pdl[128];
            snprintf(pdl, sizeof(pdl), "4eburnet.%s", pname);
            const char *const vpd[] = {"uci","delete",pdl,NULL};
            const char *const vpc[] = {"uci","commit","4eburnet",NULL};
            exec_cmd_safe(vpd,NULL,0); exec_cmd_safe(vpc,NULL,0);
            reload_daemon();
            http_send(conn, epoll_fd, 200, "application/json",
                      ok_resp, strlen(ok_resp));
        }

    } else if (strncmp(val, "provider_update", 15) == 0) {
        /* Перезагружает конфиг и триггерит rule_provider_tick при следующем тике */
        reload_daemon();
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));

    } else if (strncmp(val, "rule_add", 8) == 0) {
        char rtype[32] = {0}, rval[256] = {0}, rtgt[64] = {0}, rpri_s[8] = {0};
        http_json_get_str(body, "type",     rtype,  sizeof(rtype));
        http_json_get_str(body, "value",    rval,   sizeof(rval));
        http_json_get_str(body, "target",   rtgt,   sizeof(rtgt));
        http_json_get_str(body, "priority", rpri_s, sizeof(rpri_s));
        long rpri = rpri_s[0] ? strtol(rpri_s, NULL, 10) : 500;
        static const char *const valid_rtypes[] = {
            "DOMAIN","DOMAIN-SUFFIX","DOMAIN-KEYWORD","IP-CIDR",
            "RULE-SET","MATCH","GEOIP","GEOSITE","DST-PORT", NULL};
        bool rtype_ok = false;
        for (int k = 0; valid_rtypes[k]; k++)
            if (strcmp(rtype, valid_rtypes[k]) == 0) { rtype_ok = true; break; }
        if (!rtype_ok || !rtgt[0]) {
            const char e[] = "{\"ok\":false,\"error\":\"invalid params\"}";
            http_send(conn, epoll_fd, 400, "application/json", e, sizeof(e) - 1);
        } else {
            static char rc2[80], rc3[320], rc4[128], rc5[80];
            snprintf(rc2, sizeof(rc2), "4eburnet.@traffic_rule[-1].type=%s",     rtype);
            snprintf(rc3, sizeof(rc3), "4eburnet.@traffic_rule[-1].value=%s",    rval);
            snprintf(rc4, sizeof(rc4), "4eburnet.@traffic_rule[-1].target=%s",   rtgt);
            snprintf(rc5, sizeof(rc5), "4eburnet.@traffic_rule[-1].priority=%ld",rpri);
            const char *const rra[] = {"uci","add","4eburnet","traffic_rule",NULL};
            const char *const rrt[] = {"uci","set",rc2,NULL};
            const char *const rrv[] = {"uci","set",rc3,NULL};
            const char *const rrg[] = {"uci","set",rc4,NULL};
            const char *const rrp[] = {"uci","set",rc5,NULL};
            const char *const rrc[] = {"uci","commit","4eburnet",NULL};
            exec_cmd_safe(rra,NULL,0); exec_cmd_safe(rrt,NULL,0);
            exec_cmd_safe(rrv,NULL,0); exec_cmd_safe(rrg,NULL,0);
            exec_cmd_safe(rrp,NULL,0); exec_cmd_safe(rrc,NULL,0);
            reload_daemon();
            http_send(conn, epoll_fd, 200, "application/json",
                      ok_resp, strlen(ok_resp));
        }

    } else if (strncmp(val, "rule_delete", 11) == 0) {
        char dtype[32] = {0}, dval[256] = {0};
        http_json_get_str(body, "type",  dtype, sizeof(dtype));
        http_json_get_str(body, "value", dval,  sizeof(dval));
        char dsec[32] = {0};
        if (!dtype[0] || uci_find_traffic_rule(dtype, dval, dsec, sizeof(dsec)) < 0) {
            const char e[] = "{\"ok\":false,\"error\":\"rule not found\"}";
            http_send(conn, epoll_fd, 404, "application/json", e, sizeof(e) - 1);
        } else {
            static char rda[80];
            snprintf(rda, sizeof(rda), "4eburnet.%s", dsec);
            const char *const vrd[] = {"uci","delete",rda,NULL};
            const char *const vrc[] = {"uci","commit","4eburnet",NULL};
            exec_cmd_safe(vrd,NULL,0); exec_cmd_safe(vrc,NULL,0);
            reload_daemon();
            http_send(conn, epoll_fd, 200, "application/json",
                      ok_resp, strlen(ok_resp));
        }

    } else if (strncmp(val, "rule_reorder", 12) == 0) {
        char otype[32] = {0}, oval[256] = {0}, npri_s[8] = {0};
        http_json_get_str(body, "type",     otype,  sizeof(otype));
        http_json_get_str(body, "value",    oval,   sizeof(oval));
        http_json_get_str(body, "priority", npri_s, sizeof(npri_s));
        long npri = npri_s[0] ? strtol(npri_s, NULL, 10) : -1;
        char rsec[32] = {0};
        if (!otype[0] || npri < 0 ||
            uci_find_traffic_rule(otype, oval, rsec, sizeof(rsec)) < 0) {
            const char e[] = "{\"ok\":false,\"error\":\"rule not found\"}";
            http_send(conn, epoll_fd, 404, "application/json", e, sizeof(e) - 1);
        } else {
            static char roa[80];
            snprintf(roa, sizeof(roa), "4eburnet.%s.priority=%ld", rsec, npri);
            const char *const vro[] = {"uci","set",roa,NULL};
            const char *const vrc[] = {"uci","commit","4eburnet",NULL};
            exec_cmd_safe(vro,NULL,0); exec_cmd_safe(vrc,NULL,0);
            reload_daemon();
            http_send(conn, epoll_fd, 200, "application/json",
                      ok_resp, strlen(ok_resp));
        }

    } else {
        http_send(conn, epoll_fd, 400, "application/json",
                  err_resp, strlen(err_resp));
    }
}

/* ── GET /api/groups — список proxy-групп из кэша ────────────────── */
static void route_api_groups(HttpConn *conn, int epoll_fd)
{
    static char grp_cache[65536];
    FILE *f = fopen("/tmp/4eburnet-groups.json", "r");
    if (f) {
        size_t n = fread(grp_cache, 1, sizeof(grp_cache) - 1, f);
        fclose(f);
        if (n > 0) {
            grp_cache[n] = '\0';
            char *js = grp_cache;
            while (*js && *js != '{' && *js != '[') js++;
            if (*js) {
                http_send(conn, epoll_fd, 200, "application/json",
                          js, strlen(js));
                return;
            }
        }
    }
    const char empty[] = "{\"groups\":[]}";
    http_send(conn, epoll_fd, 200, "application/json",
              empty, sizeof(empty) - 1);
}

/* ══════════════════════════════════════════════════════════════════════
 * Dashboard Фаза 3 — CRUD + расширенные endpoints
 * ══════════════════════════════════════════════════════════════════════ */

/* ── Найти UCI server секцию по имени → "4eburnet.NAME" ─────────────── */
static int uci_find_server_section(const char *name, char *out, size_t len)
{
    if (!name || !name[0] || !uci_name_safe(name)) return -1;
    /* uci show 4eburnet.NAME — только эту секцию, не весь конфиг (>100KB) */
    static char target[80];
    snprintf(target, sizeof(target), "4eburnet.%s", name);
    static char buf[512];
    const char *const argv[] = {"uci", "show", target, NULL};
    memset(buf, 0, sizeof(buf));
    exec_cmd_safe(argv, buf, sizeof(buf) - 1);
    static char pat[80];
    snprintf(pat, sizeof(pat), "4eburnet.%s=server", name);
    if (strstr(buf, pat) == NULL) return -1;
    snprintf(out, len, "4eburnet.%s", name);
    return 0;
}

/* ── Найти UCI proxy_provider / rule_provider секцию по имени ─────── */
/* Поддерживает два формата:
 * - именованная секция (из POST /api/providers): 4eburnet.{name}={sec_type}
 * - анонимная секция (из sub_convert.py UCI import): 4eburnet.@{sec_type}[N] */
static int uci_find_provider_section(const char *sec_type, const char *name,
                                      char *out, size_t len)
{
    if (!name || !name[0] || strlen(name) > 128) return -1;

    /* Сначала именованная секция: uci show 4eburnet.{name} */
    static char target[80];
    snprintf(target, sizeof(target), "4eburnet.%s", name);
    static char buf[512];
    const char *const argv_named[] = {"uci", "show", target, NULL};
    memset(buf, 0, sizeof(buf));
    exec_cmd_safe(argv_named, buf, sizeof(buf) - 1);
    static char pat[128];
    snprintf(pat, sizeof(pat), "4eburnet.%s=%s", name, sec_type);
    if (strstr(buf, pat) != NULL) {
        snprintf(out, len, "4eburnet.%s", name);
        return 0;
    }

    /* Анонимная секция: перебираем 4eburnet.@{sec_type}[0..31].name */
    static char get_key[80], got_name[64];
    for (int i = 0; i < 32; i++) {
        snprintf(get_key, sizeof(get_key), "4eburnet.@%s[%d].name", sec_type, i);
        const char *const argv_anon[] = {"uci", "get", get_key, NULL};
        memset(got_name, 0, sizeof(got_name));
        int rc = exec_cmd_safe(argv_anon, got_name, sizeof(got_name) - 1);
        if (rc != 0) break;  /* секций больше нет */
        /* strip trailing newline */
        got_name[strcspn(got_name, "\r\n")] = '\0';
        if (strcmp(got_name, name) == 0) {
            snprintf(out, len, "4eburnet.@%s[%d]", sec_type, i);
            return 0;
        }
    }
    return -1;
}

/* ── Извлечь query param из path (/api/dns/query?name=X&type=Y) ─────── */
static void parse_query_param(const char *path, const char *key,
                               char *out, size_t len)
{
    out[0] = '\0';
    const char *qs = strchr(path, '?');
    if (!qs) return;
    qs++;
    size_t klen = strlen(key);
    while (*qs) {
        if (strncmp(qs, key, klen) == 0 && qs[klen] == '=') {
            const char *val = qs + klen + 1;
            size_t i = 0;
            while (val[i] && val[i] != '&' && i < len - 1) {
                out[i] = val[i]; i++;
            }
            out[i] = '\0';
            return;
        }
        while (*qs && *qs != '&') qs++;
        if (*qs == '&') qs++;
    }
}

/* ── Парсить URI строку: vless/trojan/ss → JSON объект ──────────────── */
/* Возвращает 0 при успехе, -1 если формат не распознан.
 * WHY: Dashboard subscribe/parse endpoint — preview без сохранения. */
static int parse_proxy_uri(const char *uri, char *out, size_t out_sz)
{
    static char protocol[16], user[256], host[256], port_s[8], name[256];
    protocol[0] = user[0] = host[0] = port_s[0] = name[0] = '\0';

    const char *body = NULL;
    if (strncmp(uri, "vless://", 8) == 0) {
        strcpy(protocol, "vless"); body = uri + 8;
    } else if (strncmp(uri, "trojan://", 9) == 0) {
        strcpy(protocol, "trojan"); body = uri + 9;
    } else if (strncmp(uri, "ss://", 5) == 0) {
        strcpy(protocol, "ss"); body = uri + 5;
    } else {
        return -1;
    }

    /* user@host:port?params#name */
    const char *at = strchr(body, '@');
    if (!at) return -1;
    size_t ulen = (size_t)(at - body);
    if (ulen >= sizeof(user)) ulen = sizeof(user) - 1;
    memcpy(user, body, ulen); user[ulen] = '\0';

    const char *hostpart = at + 1;
    /* Имя после # */
    const char *hash = strchr(hostpart, '#');
    if (hash) {
        size_t nlen = strlen(hash + 1);
        if (nlen >= sizeof(name)) nlen = sizeof(name) - 1;
        memcpy(name, hash + 1, nlen); name[nlen] = '\0';
    }
    /* Порт */
    const char *qm  = strchr(hostpart, '?');
    const char *end = hash ? hash : (qm ? qm : hostpart + strlen(hostpart));
    const char *colon = NULL;
    /* Последнее двоеточие до end (IPv6 может содержать двоеточия) */
    for (const char *c = hostpart; c < end; c++)
        if (*c == ':') colon = c;
    if (!colon) return -1;
    size_t hlen = (size_t)(colon - hostpart);
    if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
    memcpy(host, hostpart, hlen); host[hlen] = '\0';
    size_t plen = (size_t)(end - colon - 1);
    if (plen >= sizeof(port_s)) plen = sizeof(port_s) - 1;
    memcpy(port_s, colon + 1, plen); port_s[plen] = '\0';

    /* JSON escape для name и host */
    static char esc_name[512], esc_host[512], esc_user[512];
    json_escape_str(name[0] ? name : host, esc_name, sizeof(esc_name));
    json_escape_str(host,    esc_host, sizeof(esc_host));
    json_escape_str(user,    esc_user, sizeof(esc_user));

    int n = snprintf(out, out_sz,
        "{\"name\":\"%s\",\"protocol\":\"%s\","
        "\"server\":\"%s\",\"port\":%s,\"user\":\"%s\"}",
        esc_name, protocol, esc_host,
        port_s[0] ? port_s : "0", esc_user);
    return (n > 0 && (size_t)n < out_sz) ? 0 : -1;
}

/* ── POST /api/servers — создать новый сервер ─────────────────────── */
static void route_api_servers_post(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) { http_send(conn, epoll_fd, 400, "application/json",
                              "{\"error\":\"no body\"}", 19); return; }
    const char *body = hdr_end + 4;

    static char name[64], proto[32], address[256];
    static char uuid[64], password[128], transport[32];
    static char sni[256], pbk[64], sid[32], flow[32], tls_s[8];
    static char ws_path[256], ws_host[256];
    static char xhttp_path[128], xhttp_host[128];
    static char grpc_service_name[64];
    static char reality_fingerprint[16];
    static char hy2_obfs_password[512];
    static char hy2_obfs_enabled_s[4], hy2_insecure_s[4];
    static char stls_password[256], stls_sni[256];
    static char ss_method_s[32], vmess_security_s[16];
    static char awg_h1_s[32], awg_h2_s[32], awg_h3_s[32], awg_h4_s[32];
    static char awg_psk_s[64], awg_dns_s[64], awg_reserved_s[64];
    static char awg_keepalive_s[16], awg_mtu_s[16];

    http_json_get_str(body, "name",               name,               sizeof(name));
    http_json_get_str(body, "protocol",            proto,              sizeof(proto));
    http_json_get_str(body, "address",             address,            sizeof(address));
    http_json_get_str(body, "uuid",                uuid,               sizeof(uuid));
    http_json_get_str(body, "password",            password,           sizeof(password));
    http_json_get_str(body, "transport",           transport,          sizeof(transport));
    http_json_get_str(body, "sni",                 sni,                sizeof(sni));
    http_json_get_str(body, "pbk",                 pbk,                sizeof(pbk));
    http_json_get_str(body, "sid",                 sid,                sizeof(sid));
    http_json_get_str(body, "flow",                flow,               sizeof(flow));
    http_json_get_str(body, "tls",                 tls_s,              sizeof(tls_s));
    http_json_get_str(body, "ws_path",             ws_path,            sizeof(ws_path));
    http_json_get_str(body, "ws_host",             ws_host,            sizeof(ws_host));
    http_json_get_str(body, "xhttp_path",          xhttp_path,         sizeof(xhttp_path));
    http_json_get_str(body, "xhttp_host",          xhttp_host,         sizeof(xhttp_host));
    http_json_get_str(body, "grpc_service_name",   grpc_service_name,  sizeof(grpc_service_name));
    http_json_get_str(body, "reality_fingerprint", reality_fingerprint, sizeof(reality_fingerprint));
    http_json_get_str(body, "hy2_obfs_enabled",    hy2_obfs_enabled_s,  sizeof(hy2_obfs_enabled_s));
    http_json_get_str(body, "hy2_obfs_password",   hy2_obfs_password,   sizeof(hy2_obfs_password));
    http_json_get_str(body, "hy2_insecure",        hy2_insecure_s,      sizeof(hy2_insecure_s));
    http_json_get_str(body, "stls_password",       stls_password,       sizeof(stls_password));
    http_json_get_str(body, "stls_sni",            stls_sni,            sizeof(stls_sni));
    http_json_get_str(body, "ss_method",           ss_method_s,         sizeof(ss_method_s));
    http_json_get_str(body, "vmess_security",      vmess_security_s,    sizeof(vmess_security_s));
    http_json_get_str(body, "awg_h1",        awg_h1_s,        sizeof(awg_h1_s));
    http_json_get_str(body, "awg_h2",        awg_h2_s,        sizeof(awg_h2_s));
    http_json_get_str(body, "awg_h3",        awg_h3_s,        sizeof(awg_h3_s));
    http_json_get_str(body, "awg_h4",        awg_h4_s,        sizeof(awg_h4_s));
    http_json_get_str(body, "awg_psk",       awg_psk_s,       sizeof(awg_psk_s));
    http_json_get_str(body, "awg_dns",       awg_dns_s,       sizeof(awg_dns_s));
    http_json_get_str(body, "awg_reserved",  awg_reserved_s,  sizeof(awg_reserved_s));
    http_json_get_str(body, "awg_keepalive", awg_keepalive_s, sizeof(awg_keepalive_s));
    http_json_get_str(body, "awg_mtu",       awg_mtu_s,       sizeof(awg_mtu_s));

    /* порт может быть числом или строкой */
    long port_l = 0;
    {
        const char *pk = strstr(body, "\"port\"");
        if (pk) {
            pk += 6;
            while (*pk == ' ' || *pk == ':') pk++;
            if (*pk == '"') pk++;
            port_l = strtol(pk, NULL, 10);
        }
    }

    if (!name[0] || !uci_name_safe(name) || !proto[0] || !address[0]) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"error\":\"missing required fields\"}", 37); return;
    }
    if (port_l < 1 || port_l > 65535) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"error\":\"invalid port\"}", 24); return;
    }

    static char sa0[128], sa1[80], sa2[320], sa3[80], sa4[80];
    static char sa5[96], sa6[320], sa7[320], sa8[96], sa9[64], sa10[80], sa11[80];
    snprintf(sa0, sizeof(sa0), "4eburnet.%s=server",       name);
    snprintf(sa1, sizeof(sa1), "4eburnet.%s.protocol=%s",  name, proto);
    snprintf(sa2, sizeof(sa2), "4eburnet.%s.address=%s",   name, address);
    snprintf(sa3, sizeof(sa3), "4eburnet.%s.port=%ld",     name, port_l);
    snprintf(sa4, sizeof(sa4), "4eburnet.%s.enabled=1",    name);
    const char *const va0[] = {"uci","set",sa0,NULL};
    const char *const va1[] = {"uci","set",sa1,NULL};
    const char *const va2[] = {"uci","set",sa2,NULL};
    const char *const va3[] = {"uci","set",sa3,NULL};
    const char *const va4[] = {"uci","set",sa4,NULL};
    exec_cmd_safe(va0,NULL,0); exec_cmd_safe(va1,NULL,0);
    exec_cmd_safe(va2,NULL,0); exec_cmd_safe(va3,NULL,0);
    exec_cmd_safe(va4,NULL,0);

#define SRV_SET_OPT(buf_, key_, val_) do { \
    if ((val_)[0]) { \
        snprintf((buf_), sizeof(buf_), "4eburnet.%s." key_ "=%s", name, (val_)); \
        const char *const _av[] = {"uci","set",(buf_),NULL}; \
        exec_cmd_safe(_av, NULL, 0); } } while(0)

    SRV_SET_OPT(sa5,  "uuid",      uuid);
    SRV_SET_OPT(sa6,  "password",  password);
    SRV_SET_OPT(sa7,  "transport", transport);
    SRV_SET_OPT(sa8,  "sni",       sni);
    SRV_SET_OPT(sa9,  "pbk",       pbk);
    SRV_SET_OPT(sa10, "sid",       sid);
    SRV_SET_OPT(sa11, "flow",      flow);
    static char sb0[340], sb1[340], sb2[224], sb3[224], sb4[164];
    SRV_SET_OPT(sb0, "ws_path",           ws_path);
    SRV_SET_OPT(sb1, "ws_host",           ws_host);
    SRV_SET_OPT(sb2, "xhttp_path",        xhttp_path);
    SRV_SET_OPT(sb3, "xhttp_host",        xhttp_host);
    SRV_SET_OPT(sb4, "grpc_service_name", grpc_service_name);
    static char sc0[112], sc1[608], sc2[96], sc3[96], sc4[344], sc5[340];
    SRV_SET_OPT(sc0, "reality_fingerprint", reality_fingerprint);
    SRV_SET_OPT(sc1, "hy2_obfs_password",   hy2_obfs_password);
    SRV_SET_OPT(sc2, "hy2_obfs_enabled",    hy2_obfs_enabled_s);
    SRV_SET_OPT(sc3, "hy2_insecure",        hy2_insecure_s);
    SRV_SET_OPT(sc4, "stls_password",       stls_password);
    SRV_SET_OPT(sc5, "stls_sni",            stls_sni);
    static char se0[112], se1[80];
    SRV_SET_OPT(se0, "ss_method",           ss_method_s);
    SRV_SET_OPT(se1, "vmess_security",      vmess_security_s);
    static char sd0[116], sd1[116], sd2[116], sd3[116];
    static char sd4[148], sd5[148], sd6[152], sd7[96], sd8[96];
    SRV_SET_OPT(sd0, "awg_h1",       awg_h1_s);
    SRV_SET_OPT(sd1, "awg_h2",       awg_h2_s);
    SRV_SET_OPT(sd2, "awg_h3",       awg_h3_s);
    SRV_SET_OPT(sd3, "awg_h4",       awg_h4_s);
    SRV_SET_OPT(sd4, "awg_psk",      awg_psk_s);
    SRV_SET_OPT(sd5, "awg_dns",      awg_dns_s);
    SRV_SET_OPT(sd6, "awg_reserved", awg_reserved_s);
    SRV_SET_OPT(sd7, "awg_keepalive", awg_keepalive_s);
    SRV_SET_OPT(sd8, "awg_mtu",      awg_mtu_s);
    /* tls=true/false сохраняем только если непусто */
    if (tls_s[0]) {
        static char sa12[80];
        snprintf(sa12, sizeof(sa12), "4eburnet.%s.tls=%s", name, tls_s);
        const char *const va12[] = {"uci","set",sa12,NULL};
        exec_cmd_safe(va12,NULL,0);
    }
#undef SRV_SET_OPT

    const char *const vac[] = {"uci","commit","4eburnet",NULL};
    exec_cmd_safe(vac,NULL,0);
    reload_daemon();

    static char resp[256];
    snprintf(resp, sizeof(resp), "{\"name\":\"%s\",\"protocol\":\"%s\"}", name, proto);
    http_send(conn, epoll_fd, 201, "application/json", resp, strlen(resp));
}

/* ── PUT /api/servers/{name} — обновить поля сервера ─────────────── */
static void route_api_servers_put(HttpConn *conn, int epoll_fd, const char *name)
{
    static char section[80];
    if (uci_find_server_section(name, section, sizeof(section)) != 0) {
        http_send(conn, epoll_fd, 404, "application/json",
                  "{\"error\":\"not found\"}", 21); return;
    }
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) { http_send(conn, epoll_fd, 400, "application/json",
                              "{\"error\":\"no body\"}", 19); return; }
    const char *body = hdr_end + 4;

    static const char *const flds[] = {
        "protocol","address","port","uuid","password",
        "transport","sni","pbk","sid","flow","tls",
        "ws_path","ws_host","xhttp_path","xhttp_host","grpc_service_name",
        "reality_fingerprint","hy2_obfs_enabled","hy2_obfs_password",
        "hy2_insecure","stls_password","stls_sni",
        "ss_method","vmess_security",
        "awg_h1","awg_h2","awg_h3","awg_h4",
        "awg_psk","awg_dns","awg_reserved","awg_keepalive","awg_mtu", NULL };
    static char kv[512];
    for (int i = 0; flds[i]; i++) {
        static char val[256];
        http_json_get_str(body, flds[i], val, sizeof(val));
        if (val[0]) {
            snprintf(kv, sizeof(kv), "%s.%s=%s", section, flds[i], val);
            const char *const av[] = {"uci","set",kv,NULL};
            exec_cmd_safe(av, NULL, 0);
        }
    }
    const char *const vac[] = {"uci","commit","4eburnet",NULL};
    exec_cmd_safe(vac,NULL,0);
    reload_daemon();
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── DELETE /api/servers/{name} — удалить сервер ─────────────────── */
static void route_api_servers_delete(HttpConn *conn, int epoll_fd, const char *name)
{
    static char section[80];
    if (uci_find_server_section(name, section, sizeof(section)) != 0) {
        http_send(conn, epoll_fd, 404, "application/json",
                  "{\"error\":\"not found\"}", 21); return;
    }
    const char *const vd[] = {"uci","delete",section,NULL};
    const char *const vc[] = {"uci","commit","4eburnet",NULL};
    exec_cmd_safe(vd,NULL,0); exec_cmd_safe(vc,NULL,0);
    reload_daemon();
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── Применить ServerConfig в UCI через анонимную секцию @server[-1] ── */
static int server_config_to_uci_anon(const ServerConfig *srv)
{
    if (!srv->name[0] || !srv->protocol[0] || !srv->address[0] || !srv->port)
        return -1;

    {
        const char *const a[] = {"uci", "add", "4eburnet", "server", NULL};
        exec_cmd_safe(a, NULL, 0);
    }

    static char kv[512];
#define UCI_SET(fld, val) do { \
    if ((val)[0]) { \
        snprintf(kv, sizeof(kv), "4eburnet.@server[-1]." fld "=%s", (val)); \
        const char *const _av[] = {"uci", "set", kv, NULL}; \
        exec_cmd_safe(_av, NULL, 0); } } while(0)
#define UCI_SET_U(fld, n) do { \
    if (n) { \
        snprintf(kv, sizeof(kv), "4eburnet.@server[-1]." fld "=%u", (unsigned)(n)); \
        const char *const _av[] = {"uci", "set", kv, NULL}; \
        exec_cmd_safe(_av, NULL, 0); } } while(0)

    UCI_SET("name",     srv->name);
    UCI_SET("protocol", srv->protocol);
    UCI_SET("address",  srv->address);
    UCI_SET_U("port",   srv->port);
    { /* enabled всегда 1 для импортированных */
        snprintf(kv, sizeof(kv), "4eburnet.@server[-1].enabled=1");
        const char *const ea[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(ea, NULL, 0);
    }
    UCI_SET("uuid",             srv->uuid);
    UCI_SET("password",         srv->password);
    UCI_SET("ss_method",        srv->ss_method);
    UCI_SET("transport",        srv->transport);
    UCI_SET("ws_path",           srv->ws_path);
    UCI_SET("ws_host",           srv->ws_host);
    UCI_SET("xhttp_path",        srv->xhttp_path);
    UCI_SET("xhttp_host",        srv->xhttp_host);
    UCI_SET("grpc_service_name", srv->grpc_service_name);
    UCI_SET("packet_encoding",  srv->packet_encoding);
    UCI_SET("reality_pbk",      srv->reality_pbk);
    UCI_SET("reality_short_id", srv->reality_short_id);
    UCI_SET("reality_sni",      srv->reality_sni);
    UCI_SET("reality_flow",     srv->reality_flow);
    UCI_SET("reality_fingerprint", srv->reality_fingerprint);
    UCI_SET("hy2_sni",          srv->hy2_sni);
    UCI_SET_U("hy2_up_mbps",    srv->hy2_up_mbps);
    UCI_SET_U("hy2_down_mbps",  srv->hy2_down_mbps);
    if (srv->hy2_insecure) {
        snprintf(kv, sizeof(kv), "4eburnet.@server[-1].hy2_insecure=1");
        const char *const ia[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(ia, NULL, 0);
    }
    if (srv->hy2_obfs_enabled) {
        snprintf(kv, sizeof(kv), "4eburnet.@server[-1].hy2_obfs_enabled=1");
        const char *const oa[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(oa, NULL, 0);
    }
    UCI_SET("hy2_obfs_password", srv->hy2_obfs_password);
    UCI_SET("stls_password",     srv->stls_password);
    UCI_SET("stls_sni",          srv->stls_sni);
    UCI_SET("tuic_uuid",     srv->tuic_uuid);
    UCI_SET("tuic_password", srv->tuic_password);
    UCI_SET("tuic_cc",       srv->tuic_cc);
    UCI_SET("awg_private_key", srv->awg_private_key);
    UCI_SET("awg_public_key",  srv->awg_public_key);
    UCI_SET("awg_psk",       srv->awg_psk);
    UCI_SET("awg_h1",        srv->awg_h1);
    UCI_SET("awg_h2",        srv->awg_h2);
    UCI_SET("awg_h3",        srv->awg_h3);
    UCI_SET("awg_h4",        srv->awg_h4);
    UCI_SET("awg_dns",       srv->awg_dns);
    UCI_SET("awg_reserved",  srv->awg_reserved);
    UCI_SET_U("awg_jc",      srv->awg_jc);
    UCI_SET_U("awg_jmin",    srv->awg_jmin);
    UCI_SET_U("awg_jmax",    srv->awg_jmax);
    UCI_SET_U("awg_mtu",     srv->awg_mtu);
    UCI_SET_U("awg_keepalive", srv->awg_keepalive);
    UCI_SET_U("awg_itime",   srv->awg_itime);
    for (int j = 0; j < 5; j++) {
        if (srv->awg_i[j]) {
            snprintf(kv, sizeof(kv), "4eburnet.@server[-1].awg_i%d=%s", j, srv->awg_i[j]);
            const char *const av[] = {"uci", "set", kv, NULL};
            exec_cmd_safe(av, NULL, 0);
        }
    }
    if (srv->awg_j1) {
        snprintf(kv, sizeof(kv), "4eburnet.@server[-1].awg_j1=%s", srv->awg_j1);
        const char *const av[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(av, NULL, 0);
    }
#undef UCI_SET
#undef UCI_SET_U
    return 0;
}

/* ── POST /api/subscribe/parse — preview URI list без сохранения ──── */
static void route_api_subscribe_parse(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) { http_send(conn, epoll_fd, 400, "application/json",
                              "{\"error\":\"no body\"}", 19); return; }
    const char *body = hdr_end + 4;

    static char data[8192], url_sub[512];
    http_json_get_str(body, "data", data, sizeof(data));
    if (!data[0]) {
        http_json_get_str(body, "url", url_sub, sizeof(url_sub));
        if (!url_sub[0]) { http_send(conn, epoll_fd, 400, "application/json",
                                     "{\"error\":\"missing data or url\"}", 31); return; }
        if (net_http_fetch(url_sub, "/tmp/4eburnet_sub_parse.tmp") < 0) {
            http_send(conn, epoll_fd, 502, "application/json",
                      "{\"error\":\"download failed\"}", 26); return;
        }
        FILE *fp = fopen("/tmp/4eburnet_sub_parse.tmp", "r");
        if (fp) {
            size_t n = fread(data, 1, sizeof(data) - 1, fp);
            fclose(fp); data[n] = '\0';
        }
        if (!data[0]) { http_send(conn, epoll_fd, 502, "application/json",
                                  "{\"error\":\"empty response\"}", 25); return; }
    }

    /* Clash YAML — вернуть preview список серверов */
    if (strstr(data, "proxies:")) {
        ServerConfig *srvs = calloc(256, sizeof(ServerConfig));
        if (!srvs) { http_send(conn, epoll_fd, 500, "application/json",
                               "{\"error\":\"oom\"}", 15); return; }
        int n = clash_yaml_parse_proxies(data, strlen(data), srvs, 256, "");
        static char result2[32768];
        int rpos2 = 0;
        result2[rpos2++] = '[';
        static char esc_name[256], esc_addr[256];
        for (int i = 0; i < n && rpos2 + 256 < (int)sizeof(result2); i++) {
            json_escape_str(srvs[i].name,    esc_name, sizeof(esc_name));
            json_escape_str(srvs[i].address, esc_addr, sizeof(esc_addr));
            int written = snprintf(result2 + rpos2, sizeof(result2) - (size_t)rpos2,
                "%s{\"name\":\"%s\",\"protocol\":\"%s\","
                "\"address\":\"%s\",\"port\":%u}",
                i == 0 ? "" : ",",
                esc_name, srvs[i].protocol, esc_addr, srvs[i].port);
            if (written > 0) rpos2 += written;
        }
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < 5; j++) free(srvs[i].awg_i[j]);
            free(srvs[i].awg_j1);
        }
        free(srvs);
        if (rpos2 + 2 < (int)sizeof(result2)) result2[rpos2++] = ']';
        result2[rpos2] = '\0';
        http_send(conn, epoll_fd, 200, "application/json", result2, (size_t)rpos2);
        return;
    }

    /* URI list preview */
    static char result[16384];
    static char item[512];
    int rpos = 0, rmax = (int)sizeof(result);
    result[rpos++] = '[';
    bool first = true;

    char *line = strtok(data, "\n");
    while (line) {
        while (*line == ' ' || *line == '\r') line++;
        if (parse_proxy_uri(line, item, sizeof(item)) == 0) {
            if (!first && rpos + 1 < rmax) result[rpos++] = ',';
            size_t ilen = strlen(item);
            if (rpos + (int)ilen + 2 < rmax) {
                memcpy(result + rpos, item, ilen);
                rpos += (int)ilen;
                first = false;
            }
        }
        line = strtok(NULL, "\n");
    }
    if (rpos + 2 < rmax) result[rpos++] = ']';
    result[rpos] = '\0';
    http_send(conn, epoll_fd, 200, "application/json", result, (size_t)rpos);
}

/* ── POST /api/subscribe/import — URI list → UCI batch add ───────── */
static void route_api_subscribe_import(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) { http_send(conn, epoll_fd, 400, "application/json",
                              "{\"error\":\"no body\"}", 19); return; }
    const char *body = hdr_end + 4;

    static char data[16384], target_group[64];
    http_json_get_str(body, "data",         data,         sizeof(data));
    http_json_get_str(body, "target_group", target_group, sizeof(target_group));

    if (!data[0]) {
        /* Скачать по url через встроенный HTTP клиент */
        static char url[512];
        http_json_get_str(body, "url", url, sizeof(url));
        if (!url[0]) { http_send(conn, epoll_fd, 400, "application/json",
                                 "{\"error\":\"no data or url\"}", 26); return; }
        if (net_http_fetch(url, "/tmp/4eburnet_import.tmp") < 0) {
            http_send(conn, epoll_fd, 502, "application/json",
                      "{\"error\":\"download failed\"}", 26); return;
        }
        FILE *f = fopen("/tmp/4eburnet_import.tmp", "r");
        if (f) {
            size_t n = fread(data, 1, sizeof(data) - 1, f);
            fclose(f); data[n] = '\0';
        }
    }

    int added = 0, errors = 0;

    if (strstr(data, "proxies:")) {
        /* Clash YAML ветка */
        ServerConfig *srvs = calloc(256, sizeof(ServerConfig));
        if (!srvs) { http_send(conn, epoll_fd, 500, "application/json",
                               "{\"error\":\"oom\"}", 15); return; }
        int n = clash_yaml_parse_proxies(data, strlen(data), srvs, 256,
                                          target_group[0] ? target_group : "import");
        for (int i = 0; i < n; i++) {
            if (server_config_to_uci_anon(&srvs[i]) == 0) added++;
            else errors++;
            free(srvs[i].awg_i[0]); free(srvs[i].awg_i[1]);
            free(srvs[i].awg_i[2]); free(srvs[i].awg_i[3]);
            free(srvs[i].awg_i[4]); free(srvs[i].awg_j1);
        }
        free(srvs);
        const char *const yac[] = {"uci","commit","4eburnet",NULL};
        exec_cmd_safe(yac,NULL,0);
        if (added > 0) reload_daemon();
        char yaml_resp[64];
        snprintf(yaml_resp,sizeof(yaml_resp),"{\"added\":%d,\"errors\":%d}", added, errors);
        http_send(conn, epoll_fd, 200, "application/json", yaml_resp, strlen(yaml_resp));
        return;
    }

    char *line = strtok(data, "\n");
    while (line) {
        while (*line == ' ' || *line == '\r') line++;
        static char proto[16], ustr[256], host[256], port_s[8], lname[128];
        proto[0] = ustr[0] = host[0] = port_s[0] = lname[0] = '\0';

        const char *lbody = NULL;
        if      (strncmp(line, "vless://",  8) == 0) { strcpy(proto,"vless");  lbody = line + 8; }
        else if (strncmp(line, "trojan://", 9) == 0) { strcpy(proto,"trojan"); lbody = line + 9; }
        else if (strncmp(line, "ss://",     5) == 0) { strcpy(proto,"ss");     lbody = line + 5; }

        if (lbody) {
            /* Парсим user@host:port#name */
            const char *at = strchr(lbody, '@');
            if (at) {
                size_t ul = (size_t)(at - lbody);
                if (ul < sizeof(ustr)) { memcpy(ustr, lbody, ul); ustr[ul] = '\0'; }
                const char *hash = strchr(at + 1, '#');
                const char *qm   = strchr(at + 1, '?');
                const char *end  = hash ? hash : (qm ? qm : at + 1 + strlen(at + 1));
                /* Последнее двоеточие */
                const char *colon = NULL;
                for (const char *c = at + 1; c < end; c++)
                    if (*c == ':') colon = c;
                if (colon) {
                    size_t hlen = (size_t)(colon - at - 1);
                    if (hlen < sizeof(host)) { memcpy(host, at + 1, hlen); host[hlen] = '\0'; }
                    size_t plen = (size_t)(end - colon - 1);
                    if (plen < sizeof(port_s)) { memcpy(port_s, colon + 1, plen); port_s[plen] = '\0'; }
                    if (hash) { size_t nlen = strlen(hash + 1);
                                if (nlen >= sizeof(lname)) nlen = sizeof(lname) - 1;
                                memcpy(lname, hash + 1, nlen); lname[nlen] = '\0'; }
                    if (!lname[0]) snprintf(lname, sizeof(lname), "%s_%s", proto, host);

                    /* Нормализовать имя для UCI */
                    for (char *c = lname; *c; c++) {
                        if (!(((*c>='a'&&*c<='z')||(*c>='A'&&*c<='Z')||
                               (*c>='0'&&*c<='9')||*c=='_'))) *c = '_';
                    }
                    if (uci_name_safe(lname)) {
                        static char i0[128],i1[80],i2[320],i3[80],i4[96],i5[96];
                        long pl = strtol(port_s, NULL, 10);
                        if (pl >= 1 && pl <= 65535) {
                            snprintf(i0,sizeof(i0),"4eburnet.%s=server",     lname);
                            snprintf(i1,sizeof(i1),"4eburnet.%s.protocol=%s",lname,proto);
                            snprintf(i2,sizeof(i2),"4eburnet.%s.address=%s", lname,host);
                            snprintf(i3,sizeof(i3),"4eburnet.%s.port=%ld",   lname,pl);
                            snprintf(i4,sizeof(i4),"4eburnet.%s.enabled=1",  lname);
                            snprintf(i5,sizeof(i5),"4eburnet.%s.uuid=%s",    lname,ustr);
                            const char *const a0[]={"uci","set",i0,NULL};
                            const char *const a1[]={"uci","set",i1,NULL};
                            const char *const a2[]={"uci","set",i2,NULL};
                            const char *const a3[]={"uci","set",i3,NULL};
                            const char *const a4[]={"uci","set",i4,NULL};
                            const char *const a5[]={"uci","set",i5,NULL};
                            exec_cmd_safe(a0,NULL,0); exec_cmd_safe(a1,NULL,0);
                            exec_cmd_safe(a2,NULL,0); exec_cmd_safe(a3,NULL,0);
                            exec_cmd_safe(a4,NULL,0);
                            if (ustr[0]) exec_cmd_safe(a5,NULL,0);
                            added++;
                        } else errors++;
                    } else errors++;
                } else errors++;
            } else errors++;
        }
        line = strtok(NULL, "\n");
    }

    const char *const vac[] = {"uci","commit","4eburnet",NULL};
    exec_cmd_safe(vac,NULL,0);
    if (added > 0) reload_daemon();

    static char resp[64];
    snprintf(resp,sizeof(resp),"{\"added\":%d,\"errors\":%d}", added, errors);
    http_send(conn, epoll_fd, 200, "application/json", resp, strlen(resp));
}

/* ── POST /api/rules — создать правило ───────────────────────────── */
static void route_api_rules_post(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) { http_send(conn, epoll_fd, 400, "application/json",
                              "{\"error\":\"no body\"}", 19); return; }
    const char *body = hdr_end + 4;

    static char rtype[32], rval[256], rtgt[64], rpri_s[8];
    http_json_get_str(body, "type",     rtype,  sizeof(rtype));
    http_json_get_str(body, "value",    rval,   sizeof(rval));
    http_json_get_str(body, "target",   rtgt,   sizeof(rtgt));
    if (!rtgt[0]) http_json_get_str(body, "policy", rtgt, sizeof(rtgt));
    /* priority может быть числом или строкой */
    long rpri = 500;
    {
        const char *pp = strstr(body, "\"priority\"");
        if (pp) { pp += 10; while (*pp == ' ' || *pp == ':') pp++; if (*pp == '"') pp++; rpri = strtol(pp, NULL, 10); }
    }
    (void)rpri_s;

    static const char *const valid_rtypes[] = {
        "DOMAIN","DOMAIN-SUFFIX","DOMAIN-KEYWORD","IP-CIDR","IP-CIDR6",
        "RULE-SET","MATCH","GEOIP","GEOSITE","DST-PORT","SRC-PORT",
        "PROCESS-NAME","REGEX","OR", NULL};
    bool rtype_ok = false;
    for (int k = 0; valid_rtypes[k]; k++)
        if (strcmp(rtype, valid_rtypes[k]) == 0) { rtype_ok = true; break; }
    /* OR не требует value — sub_conditions заменяет */
    bool need_value = (strcmp(rtype, "OR") != 0 && strcmp(rtype, "MATCH") != 0);
    if (!rtype_ok || !rtgt[0] || (need_value && !rval[0])) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"error\":\"invalid params\"}", 26); return;
    }

    static char rc2[80], rc3[320], rc4[128], rc5[80];
    snprintf(rc2, sizeof(rc2), "4eburnet.@traffic_rule[-1].type=%s",     rtype);
    snprintf(rc3, sizeof(rc3), "4eburnet.@traffic_rule[-1].value=%s",    rval);
    snprintf(rc4, sizeof(rc4), "4eburnet.@traffic_rule[-1].target=%s",   rtgt);
    snprintf(rc5, sizeof(rc5), "4eburnet.@traffic_rule[-1].priority=%ld",rpri);
    const char *const rra[] = {"uci","add","4eburnet","traffic_rule",NULL};
    const char *const rrt[] = {"uci","set",rc2,NULL};
    const char *const rrv[] = {"uci","set",rc3,NULL};
    const char *const rrg[] = {"uci","set",rc4,NULL};
    const char *const rrp[] = {"uci","set",rc5,NULL};
    const char *const rrc[] = {"uci","commit","4eburnet",NULL};
    exec_cmd_safe(rra,NULL,0); exec_cmd_safe(rrt,NULL,0);
    if (rval[0]) exec_cmd_safe(rrv,NULL,0);
    exec_cmd_safe(rrg,NULL,0); exec_cmd_safe(rrp,NULL,0);

    /* OR: добавить UCI list or_condition для каждого sub-условия.
     * Формат JSON: "or_conditions":[{"type":"DOMAIN-SUFFIX","value":".google.com"},...] */
    if (strcmp(rtype, "OR") == 0) {
        const char *oc = strstr(body, "\"or_conditions\"");
        if (oc) {
            oc = strchr(oc, '[');
            while (oc && *oc) {
                oc = strchr(oc, '{');
                if (!oc) break;
                static char oc_type[32], oc_val[256];
                oc_type[0] = oc_val[0] = '\0';
                http_json_get_str(oc, "type",  oc_type, sizeof(oc_type));
                http_json_get_str(oc, "value", oc_val,  sizeof(oc_val));
                if (oc_type[0] && oc_val[0]) {
                    static char oc_uci[512];
                    snprintf(oc_uci, sizeof(oc_uci),
                             "4eburnet.@traffic_rule[-1].or_condition=%s,%s",
                             oc_type, oc_val);
                    const char *const oа[] = {"uci","add_list",oc_uci,NULL};
                    exec_cmd_safe(oа,NULL,0);
                }
                oc = strchr(oc, '}');
                if (oc) oc++;
            }
        }
    }

    exec_cmd_safe(rrc,NULL,0);
    reload_daemon();
    http_send(conn, epoll_fd, 201, "application/json", "{\"ok\":true}", 11);
}

/* ── PATCH /api/rules/{sec_id} — обновить правило по UCI section ─── */
static void route_api_rules_patch(HttpConn *conn, int epoll_fd, const char *sec_id)
{
    /* sec_id = UCI section hash (например cfg1a2b3c) или "type:value" */
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) { http_send(conn, epoll_fd, 400, "application/json",
                              "{\"error\":\"no body\"}", 19); return; }
    const char *body = hdr_end + 4;

    /* Попробовать найти по type:value или прямо по section name */
    static char sec[32];
    const char *colon = strchr(sec_id, ':');
    if (colon) {
        /* Формат "TYPE:value" */
        static char dtype[32], dval[256];
        size_t tlen = (size_t)(colon - sec_id);
        if (tlen >= sizeof(dtype)) tlen = sizeof(dtype) - 1;
        memcpy(dtype, sec_id, tlen); dtype[tlen] = '\0';
        strncpy(dval, colon + 1, sizeof(dval) - 1); dval[sizeof(dval)-1] = '\0';
        if (uci_find_traffic_rule(dtype, dval, sec, sizeof(sec)) != 0) {
            http_send(conn, epoll_fd, 404, "application/json",
                      "{\"error\":\"not found\"}", 21); return;
        }
    } else {
        strncpy(sec, sec_id, sizeof(sec) - 1); sec[sizeof(sec)-1] = '\0';
    }

    static char kv[512];
    static const char *const flds[] = {"type","value","target","priority","enabled",NULL};
    for (int i = 0; flds[i]; i++) {
        static char val[256]; val[0] = '\0';
        http_json_get_str(body, flds[i], val, sizeof(val));
        if (val[0]) {
            snprintf(kv, sizeof(kv), "4eburnet.%s.%s=%s", sec, flds[i], val);
            const char *const av[] = {"uci","set",kv,NULL};
            exec_cmd_safe(av,NULL,0);
        }
    }

    /* OR: заменить UCI list or_condition.
     * Сначала удаляем старый список, затем добавляем новые элементы. */
    {
        static char new_rtype[32]; new_rtype[0] = '\0';
        http_json_get_str(body, "type", new_rtype, sizeof(new_rtype));
        const char *oc = strstr(body, "\"or_conditions\"");
        if (oc && (new_rtype[0] == '\0' || strcmp(new_rtype, "OR") == 0)) {
            /* Удалить старый список */
            static char del_key[80];
            snprintf(del_key, sizeof(del_key), "4eburnet.%s.or_condition", sec);
            const char *const da[] = {"uci","del_list",del_key,NULL};
            exec_cmd_safe(da,NULL,0);

            oc = strchr(oc, '[');
            while (oc && *oc) {
                oc = strchr(oc, '{');
                if (!oc) break;
                static char oc_type[32], oc_val[256];
                oc_type[0] = oc_val[0] = '\0';
                http_json_get_str(oc, "type",  oc_type, sizeof(oc_type));
                http_json_get_str(oc, "value", oc_val,  sizeof(oc_val));
                if (oc_type[0] && oc_val[0]) {
                    static char oc_uci[512];
                    snprintf(oc_uci, sizeof(oc_uci),
                             "4eburnet.%s.or_condition=%s,%s",
                             sec, oc_type, oc_val);
                    const char *const oа[] = {"uci","add_list",oc_uci,NULL};
                    exec_cmd_safe(oа,NULL,0);
                }
                oc = strchr(oc, '}');
                if (oc) oc++;
            }
        }
    }

    const char *const vc[] = {"uci","commit","4eburnet",NULL};
    exec_cmd_safe(vc,NULL,0);
    reload_daemon();
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── DELETE /api/rules/{sec_id} — удалить правило ────────────────── */
static void route_api_rules_delete(HttpConn *conn, int epoll_fd, const char *sec_id)
{
    static char sec[32];
    const char *colon = strchr(sec_id, ':');
    if (colon) {
        static char dtype[32], dval[256];
        size_t tlen = (size_t)(colon - sec_id);
        if (tlen >= sizeof(dtype)) tlen = sizeof(dtype) - 1;
        memcpy(dtype, sec_id, tlen); dtype[tlen] = '\0';
        strncpy(dval, colon + 1, sizeof(dval) - 1); dval[sizeof(dval)-1] = '\0';
        if (uci_find_traffic_rule(dtype, dval, sec, sizeof(sec)) != 0) {
            http_send(conn, epoll_fd, 404, "application/json",
                      "{\"error\":\"not found\"}", 21); return;
        }
    } else {
        strncpy(sec, sec_id, sizeof(sec) - 1); sec[sizeof(sec)-1] = '\0';
    }
    static char dsec[64];
    snprintf(dsec, sizeof(dsec), "4eburnet.%s", sec);
    const char *const vd[] = {"uci","delete",dsec,NULL};
    const char *const vc[] = {"uci","commit","4eburnet",NULL};
    exec_cmd_safe(vd,NULL,0); exec_cmd_safe(vc,NULL,0);
    reload_daemon();
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── POST /api/rules/test — матчинг правила через rules_engine_match ─ */
static void route_api_rules_test(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    const char *body = hdr_end ? hdr_end + 4 : "";
    static char target[256];
    http_json_get_str(body, "domain", target, sizeof(target));
    if (!target[0]) http_json_get_str(body, "target", target, sizeof(target));
    if (!target[0]) { http_send(conn, epoll_fd, 400, "application/json",
                                "{\"error\":\"missing target\"}", 26); return; }

    if (!s_re) { http_send(conn, epoll_fd, 503, "application/json",
                           "{\"error\":\"rules engine not ready\"}", 34); return; }

    /* Определяем: IPv4 / IPv6 / домен */
    struct sockaddr_storage dst;
    memset(&dst, 0, sizeof(dst));
    const char *domain = NULL;
    const struct sockaddr_storage *dst_ptr = NULL;

    struct in_addr  a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET6, target, &a6) == 1) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&dst;
        s6->sin6_family = AF_INET6;
        s6->sin6_addr   = a6;
        s6->sin6_port   = htons(443);
        dst_ptr = &dst;
    } else if (inet_pton(AF_INET, target, &a4) == 1) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&dst;
        s4->sin_family = AF_INET;
        s4->sin_addr   = a4;
        s4->sin_port   = htons(443);
        dst_ptr = &dst;
    } else {
        domain = target;
    }

    rule_match_result_t res = rules_engine_match(
        s_re, domain, dst_ptr, IPPROTO_TCP, 443, 0, NULL);

    /* Строка proxy: DIRECT / REJECT / имя группы */
    static char proxy_str[64];
    switch (res.type) {
    case RULE_TARGET_DIRECT: memcpy(proxy_str, "DIRECT", 7); break;
    case RULE_TARGET_REJECT: memcpy(proxy_str, "REJECT", 7); break;
    default:
        if (res.group_name[0])
            snprintf(proxy_str, sizeof(proxy_str), "%s", res.group_name);
        else
            memcpy(proxy_str, "PROXY", 6);
        break;
    }

    /* selected_server и latency из pgm */
    static char selected_server[128];
    uint32_t latency_ms = 0;
    selected_server[0] = '\0';
    if (res.type == RULE_TARGET_GROUP && res.group_name[0] && s_pgm && s_cfg) {
        proxy_group_state_t *gs = proxy_group_find(s_pgm, res.group_name);
        if (gs) {
            const char *srv_name = proxy_group_get_current(gs, s_cfg);
            if (srv_name && srv_name[0])
                snprintf(selected_server, sizeof(selected_server), "%s", srv_name);
            latency_ms = pgm_server_latency(s_pgm, gs->selected_idx);
            /* UINT32_MAX — сервер ещё не проверялся HC (init-значение) */
            if (latency_ms == UINT32_MAX) latency_ms = 0;
        }
    }

    bool matched = (res.matched_rule_type >= 0);
    const char *rt_str = matched
        ? rule_type_to_str((rule_type_t)res.matched_rule_type) : "MATCH";

    static char esc_target[512], esc_payload[256], esc_srv[256];
    json_escape_str(target,              esc_target,  sizeof(esc_target));
    json_escape_str(res.matched_payload, esc_payload, sizeof(esc_payload));
    json_escape_str(selected_server,     esc_srv,     sizeof(esc_srv));

    static char resp[768];
    int rlen;
    if (esc_srv[0]) {
        rlen = snprintf(resp, sizeof(resp),
            "{\"matched\":%s,\"target\":\"%s\","
            "\"rule_type\":\"%s\",\"payload\":\"%s\","
            "\"proxy\":\"%s\","
            "\"selected_server\":\"%s\","
            "\"latency_ms\":%u}",
            matched ? "true" : "false", esc_target,
            rt_str, esc_payload, proxy_str,
            esc_srv, latency_ms);
    } else {
        rlen = snprintf(resp, sizeof(resp),
            "{\"matched\":%s,\"target\":\"%s\","
            "\"rule_type\":\"%s\",\"payload\":\"%s\","
            "\"proxy\":\"%s\","
            "\"selected_server\":null,"
            "\"latency_ms\":%u}",
            matched ? "true" : "false", esc_target,
            rt_str, esc_payload, proxy_str,
            latency_ms);
    }
    http_send(conn, epoll_fd, 200, "application/json", resp, (size_t)rlen);
}

/* ── PATCH /api/providers/proxies/{name} — изменить proxy provider ── */
static void route_api_providers_proxies_patch(HttpConn *conn, int epoll_fd,
                                               const char *name)
{
    static char section[80];
    if (uci_find_provider_section("proxy_provider", name, section, sizeof(section)) != 0) {
        http_send(conn, epoll_fd, 404, "application/json",
                  "{\"error\":\"not found\"}", 21); return;
    }
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) { http_send(conn, epoll_fd, 400, "application/json",
                              "{\"error\":\"no body\"}", 19); return; }
    const char *body = hdr_end + 4;
    static char url[512], intv_s[16], max_s[8];
    http_json_get_str(body, "url",         url,    sizeof(url));
    /* interval и max_servers передаются как числа — http_json_get_val */
    http_json_get_val(body, "interval",    intv_s, sizeof(intv_s));
    http_json_get_val(body, "max_servers", max_s,  sizeof(max_s));
    bool changed = false;
    static char kv[640];
    if (url[0]) {
        snprintf(kv, sizeof(kv), "%s.url=%s", section, url);
        const char *const v[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(v, NULL, 0); changed = true;
    }
    if (intv_s[0]) {
        snprintf(kv, sizeof(kv), "%s.interval=%s", section, intv_s);
        const char *const v[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(v, NULL, 0); changed = true;
    }
    if (max_s[0]) {
        snprintf(kv, sizeof(kv), "%s.max_servers=%s", section, max_s);
        const char *const v[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(v, NULL, 0); changed = true;
    }
    if (changed) {
        const char *const vc[] = {"uci", "commit", "4eburnet", NULL};
        exec_cmd_safe(vc, NULL, 0);
        reload_daemon();
    }
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── PATCH /api/providers/rules/{name} — изменить rule provider ───── */
static void route_api_providers_rules_patch(HttpConn *conn, int epoll_fd,
                                             const char *name)
{
    static char section[80];
    if (uci_find_provider_section("rule_provider", name, section, sizeof(section)) != 0) {
        http_send(conn, epoll_fd, 404, "application/json",
                  "{\"error\":\"not found\"}", 21); return;
    }
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) { http_send(conn, epoll_fd, 400, "application/json",
                              "{\"error\":\"no body\"}", 19); return; }
    const char *body = hdr_end + 4;
    static char url[512], intv_s[16], behavior[16];
    http_json_get_str(body, "url",      url,      sizeof(url));
    /* interval передаётся как число — http_json_get_val */
    http_json_get_val(body, "interval", intv_s,   sizeof(intv_s));
    http_json_get_str(body, "behavior", behavior, sizeof(behavior));
    bool changed = false;
    static char kv[640];
    if (url[0]) {
        snprintf(kv, sizeof(kv), "%s.url=%s", section, url);
        const char *const v[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(v, NULL, 0); changed = true;
    }
    if (intv_s[0]) {
        snprintf(kv, sizeof(kv), "%s.interval=%s", section, intv_s);
        const char *const v[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(v, NULL, 0); changed = true;
    }
    if (behavior[0]) {
        snprintf(kv, sizeof(kv), "%s.behavior=%s", section, behavior);
        const char *const v[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(v, NULL, 0); changed = true;
    }
    if (changed) {
        const char *const vc[] = {"uci", "commit", "4eburnet", NULL};
        exec_cmd_safe(vc, NULL, 0);
        reload_daemon();
    }
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── PATCH /api/groups/{name} — изменить параметры proxy-group ──── */
/* Поля: type, url, interval, tolerance_ms, filter, load_balance_strategy.
 * UCI: анонимные секции @proxy_group[N] — переиспользуем uci_find_provider_section. */
static void route_api_groups_patch(HttpConn *conn, int epoll_fd, const char *name)
{
    static char dec_name[256];
    {
        const char *s = name; char *d = dec_name; char *end = dec_name + sizeof(dec_name) - 1;
        while (*s && d < end) {
            if (*s == '%' && s[1] && s[2]) {
                char h[3] = {s[1], s[2], 0}; *d++ = (char)strtol(h, NULL, 16); s += 3;
            } else { *d++ = (*s == '+') ? ' ' : *s; s++; }
        }
        *d = '\0';
    }
    static char section[80];
    if (uci_find_provider_section("proxy_group", dec_name, section, sizeof(section)) != 0) {
        http_send(conn, epoll_fd, 404, "application/json",
                  "{\"error\":\"not found\"}", 21); return;
    }
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) { http_send(conn, epoll_fd, 400, "application/json",
                              "{\"error\":\"no body\"}", 19); return; }
    const char *body = hdr_end + 4;
    static char url[512], filter[512], intv_s[16], tol_s[16], type_s[32], strategy_s[32];
    http_json_get_str(body, "url",                    url,        sizeof(url));
    http_json_get_str(body, "filter",                 filter,     sizeof(filter));
    http_json_get_str(body, "type",                   type_s,     sizeof(type_s));
    http_json_get_str(body, "load_balance_strategy",  strategy_s, sizeof(strategy_s));
    /* interval и tolerance_ms — числа без кавычек → http_json_get_val */
    http_json_get_val(body, "interval",     intv_s, sizeof(intv_s));
    http_json_get_val(body, "tolerance_ms", tol_s,  sizeof(tol_s));
    bool changed = false;
    static char kv[640];
    if (url[0]) {
        snprintf(kv, sizeof(kv), "%s.url=%s", section, url);
        const char *const v[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(v, NULL, 0); changed = true;
    }
    if (filter[0]) {
        snprintf(kv, sizeof(kv), "%s.filter=%s", section, filter);
        const char *const v[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(v, NULL, 0); changed = true;
    }
    if (intv_s[0]) {
        snprintf(kv, sizeof(kv), "%s.interval=%s", section, intv_s);
        const char *const v[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(v, NULL, 0); changed = true;
    }
    if (tol_s[0]) {
        snprintf(kv, sizeof(kv), "%s.tolerance_ms=%s", section, tol_s);
        const char *const v[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(v, NULL, 0); changed = true;
    }
    /* "type": kebab-case → UCI (underscore).
     * WHY: форма использует kebab (select/url-test/etc.), UCI требует underscore. */
    if (type_s[0]) {
        const char *uci_type = NULL;
        if      (strcmp(type_s, "select")            == 0) uci_type = "select";
        else if (strcmp(type_s, "url-test")          == 0) uci_type = "url_test";
        else if (strcmp(type_s, "fallback")          == 0) uci_type = "fallback";
        else if (strcmp(type_s, "load-balance")      == 0) uci_type = "load_balance";
        else if (strcmp(type_s, "fastest-whitelist") == 0) uci_type = "fastest_whitelist";
        if (uci_type) {
            snprintf(kv, sizeof(kv), "%s.type=%s", section, uci_type);
            const char *const v[] = {"uci", "set", kv, NULL};
            exec_cmd_safe(v, NULL, 0); changed = true;
        }
    }
    if (strategy_s[0]) {
        snprintf(kv, sizeof(kv), "%s.load_balance_strategy=%s", section, strategy_s);
        const char *const v[] = {"uci", "set", kv, NULL};
        exec_cmd_safe(v, NULL, 0); changed = true;
    }
    if (changed) {
        const char *const vc[] = {"uci", "commit", "4eburnet", NULL};
        exec_cmd_safe(vc, NULL, 0);
        reload_daemon();
    }
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── POST /api/providers/proxies — добавить proxy provider ─────────── */
static void route_api_providers_proxies_post(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) { http_send(conn, epoll_fd, 400, "application/json",
                              "{\"error\":\"no body\"}", 19); return; }
    const char *body = hdr_end + 4;
    static char pname[64], url[512], intv_s[16];
    http_json_get_str(body, "name",     pname,  sizeof(pname));
    http_json_get_str(body, "url",      url,    sizeof(url));
    http_json_get_str(body, "interval", intv_s, sizeof(intv_s));
    long intv = intv_s[0] ? strtol(intv_s, NULL, 10) : 86400;
    if (!pname[0] || !uci_name_safe(pname) || !url[0]) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"error\":\"invalid params\"}", 26); return;
    }
    static char pb0[128], pb1[640], pb2[80], pb3[80];
    snprintf(pb0, sizeof(pb0), "4eburnet.%s=proxy_provider", pname);
    snprintf(pb1, sizeof(pb1), "4eburnet.%s.url=%s",         pname, url);
    snprintf(pb2, sizeof(pb2), "4eburnet.%s.interval=%ld",   pname, intv);
    snprintf(pb3, sizeof(pb3), "4eburnet.%s.enabled=1",      pname);
    const char *const vp0[]={"uci","set",pb0,NULL};
    const char *const vp1[]={"uci","set",pb1,NULL};
    const char *const vp2[]={"uci","set",pb2,NULL};
    const char *const vp3[]={"uci","set",pb3,NULL};
    const char *const vpc[]={"uci","commit","4eburnet",NULL};
    exec_cmd_safe(vp0,NULL,0); exec_cmd_safe(vp1,NULL,0);
    exec_cmd_safe(vp2,NULL,0); exec_cmd_safe(vp3,NULL,0);
    exec_cmd_safe(vpc,NULL,0);
    reload_daemon();
    http_send(conn, epoll_fd, 201, "application/json", "{\"ok\":true}", 11);
}

/* ── DELETE /api/providers/proxies/{name} ────────────────────────── */
static void route_api_providers_proxies_delete(HttpConn *conn, int epoll_fd,
                                                const char *name)
{
    static char section[80];
    if (uci_find_provider_section("proxy_provider", name, section, sizeof(section)) != 0) {
        http_send(conn, epoll_fd, 404, "application/json",
                  "{\"error\":\"not found\"}", 21); return;
    }
    const char *const vd[]={"uci","delete",section,NULL};
    const char *const vc[]={"uci","commit","4eburnet",NULL};
    exec_cmd_safe(vd,NULL,0); exec_cmd_safe(vc,NULL,0);
    reload_daemon();
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── POST /api/providers/rules — добавить rule provider ─────────── */
static void route_api_providers_rules_post(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) { http_send(conn, epoll_fd, 400, "application/json",
                              "{\"error\":\"no body\"}", 19); return; }
    const char *body = hdr_end + 4;
    static char pname[64], url[512], behavior[16], intv_s[16];
    http_json_get_str(body, "name",     pname,    sizeof(pname));
    http_json_get_str(body, "url",      url,      sizeof(url));
    http_json_get_str(body, "behavior", behavior, sizeof(behavior));
    http_json_get_str(body, "interval", intv_s,   sizeof(intv_s));
    long intv = intv_s[0] ? strtol(intv_s, NULL, 10) : 86400;
    if (!pname[0] || !uci_name_safe(pname) || !url[0]) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"error\":\"invalid params\"}", 26); return;
    }
    static char rb0[128], rb1[640], rb2[64], rb3[80];
    snprintf(rb0, sizeof(rb0), "4eburnet.%s=rule_provider",  pname);
    snprintf(rb1, sizeof(rb1), "4eburnet.%s.url=%s",         pname, url);
    snprintf(rb2, sizeof(rb2), "4eburnet.%s.behavior=%s",    pname,
             behavior[0] ? behavior : "domain");
    snprintf(rb3, sizeof(rb3), "4eburnet.%s.interval=%ld",   pname, intv);
    const char *const vr0[]={"uci","set",rb0,NULL};
    const char *const vr1[]={"uci","set",rb1,NULL};
    const char *const vr2[]={"uci","set",rb2,NULL};
    const char *const vr3[]={"uci","set",rb3,NULL};
    const char *const vrc[]={"uci","commit","4eburnet",NULL};
    exec_cmd_safe(vr0,NULL,0); exec_cmd_safe(vr1,NULL,0);
    exec_cmd_safe(vr2,NULL,0); exec_cmd_safe(vr3,NULL,0);
    exec_cmd_safe(vrc,NULL,0);
    reload_daemon();
    http_send(conn, epoll_fd, 201, "application/json", "{\"ok\":true}", 11);
}

/* ── DELETE /api/providers/rules/{name} ─────────────────────────── */
static void route_api_providers_rules_delete(HttpConn *conn, int epoll_fd,
                                              const char *name)
{
    static char section[80];
    if (uci_find_provider_section("rule_provider", name, section, sizeof(section)) != 0) {
        http_send(conn, epoll_fd, 404, "application/json",
                  "{\"error\":\"not found\"}", 21); return;
    }
    const char *const vd[]={"uci","delete",section,NULL};
    const char *const vc[]={"uci","commit","4eburnet",NULL};
    exec_cmd_safe(vd,NULL,0); exec_cmd_safe(vc,NULL,0);
    reload_daemon();
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── PATCH /api/dns — изменить DNS настройки ─────────────────────── */
static void route_api_dns_patch(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) { http_send(conn, epoll_fd, 400, "application/json",
                              "{\"error\":\"no body\"}", 19); return; }
    const char *body = hdr_end + 4;

    /* Маппинг JSON ключей → UCI опции */
    static const struct { const char *jkey; const char *uopt; } dns_map[] = {
        {"upstream_default",  "dns.upstream_default"},
        {"upstream_bypass",   "dns.upstream_bypass"},
        {"upstream_fallback", "dns.upstream_fallback"},
        {"doh_url",           "dns.doh_url"},
        {"doh_enabled",       "dns.doh_enabled"},
        {"dot_enabled",       "dns.dot_enabled"},
        {"fake_ip_enabled",   "dns.fake_ip_enabled"},
        {"fake_ip_range",     "dns.fake_ip_range"},
        {"fake_ip6_enabled",  "dns.fake_ip6_enabled"},
        {"fake_ip_range_v6",  "dns.fake_ip6_range"},
        {"block_ads",               "dns.block_geosite_ads"},
        {"block_trackers",          "dns.block_geosite_trackers"},
        {"block_threats",           "dns.block_geosite_threats"},
        {"stale_while_revalidate",  "dns.stale_while_revalidate"},
        {"stale_grace_seconds",     "dns.stale_grace_seconds"},
        {"geo_profile",             "main.geo_profile"},
        {"cache_size",              "dns.cache_size"},
        /* DoH детали (v2.1.8) */
        {"doh_sni",                 "dns.doh_sni"},
        {"doh_ip",                  "dns.doh_ip"},
        {"doh_port",                "dns.doh_port"},
        /* DoT детали (v2.1.8) */
        {"dot_server_ip",           "dns.dot_server_ip"},
        {"dot_sni",                 "dns.dot_sni"},
        {"dot_port",                "dns.dot_port"},
        /* DoQ детали (v2.1.8) */
        {"doq_enabled",             "dns.doq_enabled"},
        {"doq_server_ip",           "dns.doq_server_ip"},
        {"doq_port",                "dns.doq_server_port"},
        {"doq_sni",                 "dns.doq_sni"},
        /* Fallback + Query opts (v2.1.8) */
        {"fallback_timeout_ms",     "dns.fallback_timeout_ms"},
        {"upstream_timeout_ms",     "dns.upstream_timeout_ms"},
        {"tolerance_ms",            "dns.tolerance_ms"},
        {"bogus_nxdomain",          "dns.bogus_nxdomain"},
        {"parallel_query",          "dns.parallel_query"},
        /* Cache TTL (v2.1.8) */
        {"cache_ttl_min",           "dns.cache_ttl_min"},
        {"cache_ttl_max",           "dns.cache_ttl_max"},
        {NULL, NULL}
    };
    static char kv[512];
    bool changed = false;
    for (int i = 0; dns_map[i].jkey; i++) {
        static char val[256]; val[0] = '\0';
        http_json_get_val(body, dns_map[i].jkey, val, sizeof(val));
        if (val[0]) {
            snprintf(kv, sizeof(kv), "4eburnet.%s=%s", dns_map[i].uopt, val);
            const char *const av[] = {"uci","set",kv,NULL};
            exec_cmd_safe(av, NULL, 0);
            changed = true;
        }
    }
    if (changed) {
        const char *const vc[] = {"uci","commit","4eburnet",NULL};
        exec_cmd_safe(vc,NULL,0);
        reload_daemon();
    }
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── POST /api/dns/cache/flush ────────────────────────────────────── */
static void route_api_dns_cache_flush(HttpConn *conn, int epoll_fd)
{
    /* WHY: Нет отдельной IPC_CMD_DNS_CACHE_FLUSH.
     * Удаляем кэш-файл — при следующем запросе DNS демон перезапрашивает.
     * SIGHUP перезапускает DNS стек, что сбрасывает кэш в памяти. */
    unlink("/tmp/4eburnet-dns-cache.json");
    reload_daemon();
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── POST /api/dns/fakeip/flush ───────────────────────────────────── */
static void route_api_dns_fakeip_flush(HttpConn *conn, int epoll_fd)
{
    /* WHY: SIGHUP вызывает полный reload DNS стека включая fake-IP пул. */
    reload_daemon();
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── GET /api/dns/query?name=X&type=Y — DNS probe ─────────────────── */
static void route_api_dns_query(HttpConn *conn, int epoll_fd)
{
    static char qname[256], qtype[8];
    parse_query_param(conn->path, "name", qname, sizeof(qname));
    parse_query_param(conn->path, "type", qtype, sizeof(qtype));
    if (!qname[0]) { http_send(conn, epoll_fd, 400, "application/json",
                               "{\"error\":\"missing name\"}", 24); return; }

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    bool want6 = (qtype[0] == 'A' && qtype[1] == 'A') ||
                 strcmp(qtype, "AAAA") == 0;
    hints.ai_family = want6 ? AF_INET6 : AF_INET;

    static char esc_name[512];
    json_escape_str(qname, esc_name, sizeof(esc_name));

    int rc = getaddrinfo(qname, NULL, &hints, &res);
    static char resp[1024];
    if (rc != 0 || !res) {
        snprintf(resp, sizeof(resp),
            "{\"name\":\"%s\",\"error\":\"%s\"}",
            esc_name, gai_strerror(rc));
        http_send(conn, epoll_fd, 200, "application/json", resp, strlen(resp));
        return;
    }

    static char ip[64];
    if (want6)
        inet_ntop(AF_INET6,
            &((struct sockaddr_in6*)res->ai_addr)->sin6_addr, ip, sizeof(ip));
    else
        inet_ntop(AF_INET,
            &((struct sockaddr_in*)res->ai_addr)->sin_addr, ip, sizeof(ip));
    freeaddrinfo(res);

    snprintf(resp, sizeof(resp),
        "{\"name\":\"%s\",\"type\":\"%s\",\"answers\":[{\"data\":\"%s\"}]}",
        esc_name, qtype[0] ? qtype : "A", ip);
    http_send(conn, epoll_fd, 200, "application/json", resp, strlen(resp));
}

/* ── GET /api/dns/test-upstream?upstream=X&type=Y — UDP DNS probe ─── */
static void route_api_dns_test_upstream(HttpConn *conn, int epoll_fd)
{
    static char upstream[128];
    static char resp[192];
    parse_query_param(conn->path, "upstream", upstream, sizeof(upstream));
    if (!upstream[0]) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"ok\":false,\"error\":\"missing upstream\"}", 39);
        return;
    }
    /* DNS запрос: A-запись для cloudflare.com (маленький, фиксированный) */
    static const uint8_t dns_q[] = {
        0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        0x0a,'c','l','o','u','d','f','l','a','r','e',
        0x03,'c','o','m', 0x00,
        0x00,0x01, 0x00,0x01
    };
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        http_send(conn, epoll_fd, 200, "application/json",
                  "{\"ok\":false,\"error\":\"socket\"}", 29); return;
    }
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(53);
    if (inet_pton(AF_INET, upstream, &sa.sin_addr) != 1) {
        close(sock);
        http_send(conn, epoll_fd, 200, "application/json",
                  "{\"ok\":false,\"error\":\"invalid upstream\"}", 39); return;
    }
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (sendto(sock, dns_q, sizeof(dns_q), 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(sock);
        http_send(conn, epoll_fd, 200, "application/json",
                  "{\"ok\":false,\"error\":\"send\"}", 27); return;
    }
    static uint8_t rbuf[512];
    ssize_t n = recvfrom(sock, rbuf, sizeof(rbuf), 0, NULL, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    close(sock);
    if (n < 0) {
        http_send(conn, epoll_fd, 200, "application/json",
                  "{\"ok\":false,\"error\":\"timeout\"}", 30); return;
    }
    long ms = (t1.tv_sec  - t0.tv_sec)  * 1000L +
              (t1.tv_nsec - t0.tv_nsec) / 1000000L;
    /* Парсим первый A-ответ из response: header(12) → вопрос → ответ */
    static char ip_str[24];
    ip_str[0] = '\0';
    if (n >= 12 && ((rbuf[6] << 8) | rbuf[7]) > 0) {
        int pos = 12;
        while (pos < (int)n && rbuf[pos]) pos += rbuf[pos] + 1;
        pos += 5; /* 0x00 + QTYPE(2) + QCLASS(2) */
        if (pos + 12 <= (int)n) {
            pos += 2; /* NAME (указатель) */
            int atype = (rbuf[pos] << 8) | rbuf[pos+1];
            pos += 8; /* TYPE + CLASS + TTL */
            int rdlen = (rbuf[pos] << 8) | rbuf[pos+1];
            pos += 2;
            if (atype == 1 && rdlen == 4 && pos + 4 <= (int)n)
                snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                         rbuf[pos], rbuf[pos+1], rbuf[pos+2], rbuf[pos+3]);
        }
    }
    if (ip_str[0])
        snprintf(resp, sizeof(resp),
                 "{\"ok\":true,\"latency_ms\":%ld,\"ip\":\"%s\"}", ms, ip_str);
    else
        snprintf(resp, sizeof(resp), "{\"ok\":true,\"latency_ms\":%ld}", ms);
    http_send(conn, epoll_fd, 200, "application/json", resp, strlen(resp));
}

/* ── GET /api/dns/stats — DNS статистика ─────────────────────────── */
static void route_api_dns_stats(HttpConn *conn, int epoll_fd)
{
    /* WHY: Счётчики живут в DNS демоне — они не доступны через IPC без
     * IPC_CMD_DNS_STATS (не реализована). Возвращаем ноли как stub,
     * который будет заполнен когда IPC команда появится. */
    static const char resp[] =
        "{\"queries\":0,\"cached\":0,\"blocked\":0,\"hit_rate\":0.0}";
    http_send(conn, epoll_fd, 200, "application/json",
              resp, sizeof(resp) - 1);
}

/* Проверить что uci вернул реальное значение, а не ошибку */
static bool uci_got_ok(const char *got)
{
    return got[0] != '\0' && strncmp(got, "uci:", 4) != 0;
}

/* ── GET /api/dns/policies — список dns_policy UCI секций ──────────── */
static void route_api_dns_policies_get(HttpConn *conn, int epoll_fd)
{
    static char resp[12288];
    static char get_key[80];
    static char got[256];
    static char pat[256], ustr[256], sni[256];
    int pos = 0, max = (int)sizeof(resp) - 4;
    pos += snprintf(resp + pos, (size_t)(max - pos), "{\"policies\":[");
    bool first = true;
    int seq = 0;
    for (int i = 0; i < 128 && seq < 64 && pos < max - 256; i++) {
        /* проверяем, существует ли секция вообще */
        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d]", i);
        const char *const aex[] = {"uci", "get", get_key, NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(aex, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        if (!uci_got_ok(got)) break;  /* конец списка */

        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d].pattern", i);
        const char *const a0[] = {"uci", "get", get_key, NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(a0, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        if (!uci_got_ok(got)) continue;  /* пустая секция без pattern — пропускаем */
        snprintf(pat, sizeof(pat), "%s", got);

        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d].upstream", i);
        const char *const a1[] = {"uci", "get", get_key, NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(a1, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        snprintf(ustr, sizeof(ustr), "%s", uci_got_ok(got) ? got : "");

        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d].type", i);
        const char *const a2[] = {"uci", "get", get_key, NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(a2, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        const char *tp = (uci_got_ok(got) && strcmp(got, "dot") == 0) ? "dot"
                       : (uci_got_ok(got) && strcmp(got, "doh") == 0) ? "doh" : "udp";

        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d].sni", i);
        const char *const a3[] = {"uci", "get", get_key, NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(a3, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        snprintf(sni, sizeof(sni), "%s", uci_got_ok(got) ? got : "");

        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d].priority", i);
        const char *const a4[] = {"uci", "get", get_key, NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(a4, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        int prio = (uci_got_ok(got) && got[0] >= '0' && got[0] <= '9')
                   ? (int)strtol(got, NULL, 10) : 100;

        if (!first) pos += snprintf(resp + pos, (size_t)(max - pos), ",");
        first = false;
        pos += snprintf(resp + pos, (size_t)(max - pos),
            "{\"id\":%d,\"type\":\"%s\",\"priority\":%d,\"pattern\":", seq, tp, prio);
        pos = json_append_str(resp, pos, max, pat);
        pos += snprintf(resp + pos, (size_t)(max - pos), ",\"upstream\":");
        pos = json_append_str(resp, pos, max, ustr);
        pos += snprintf(resp + pos, (size_t)(max - pos), ",\"sni\":");
        pos = json_append_str(resp, pos, max, sni);
        pos += snprintf(resp + pos, (size_t)(max - pos), "}");
        seq++;
    }
    pos += snprintf(resp + pos, (size_t)(max - pos), "]}");
    http_send(conn, epoll_fd, 200, "application/json", resp, (size_t)pos);
}

/* ── POST /api/dns/policies — добавить политику ─────────────────────── */
static void route_api_dns_policies_post(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"ok\":false,\"error\":\"bad request\"}", 34); return;
    }
    const char *body = hdr_end + 4;
    static char pattern[129], upstream[129], type_s[8], sni_s[257], prio_s[12];
    http_json_get_str(body, "pattern",  pattern,  sizeof(pattern));
    http_json_get_str(body, "upstream", upstream, sizeof(upstream));
    http_json_get_str(body, "type",     type_s,   sizeof(type_s));
    http_json_get_str(body, "sni",      sni_s,    sizeof(sni_s));
    http_json_get_val(body, "priority", prio_s,   sizeof(prio_s));
    if (!pattern[0] || !upstream[0]) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"ok\":false,\"error\":\"pattern and upstream required\"}", 52); return;
    }
    if (strcmp(type_s, "dot") != 0 && strcmp(type_s, "doh") != 0)
        snprintf(type_s, sizeof(type_s), "udp");
    if (!prio_s[0]) snprintf(prio_s, sizeof(prio_s), "100");

    static char kv[512];
    {
        const char *const aa[] = {"uci", "add", "4eburnet", "dns_policy", NULL};
        if (exec_cmd_safe(aa, NULL, 0) != 0) {
            http_send(conn, epoll_fd, 500, "application/json",
                      "{\"ok\":false,\"error\":\"uci add failed\"}", 37); return;
        }
    }
    snprintf(kv, sizeof(kv), "4eburnet.@dns_policy[-1].pattern=%s",  pattern);
    { const char *const a[] = {"uci","set",kv,NULL}; exec_cmd_safe(a,NULL,0); }
    snprintf(kv, sizeof(kv), "4eburnet.@dns_policy[-1].upstream=%s", upstream);
    { const char *const a[] = {"uci","set",kv,NULL}; exec_cmd_safe(a,NULL,0); }
    snprintf(kv, sizeof(kv), "4eburnet.@dns_policy[-1].type=%s",     type_s);
    { const char *const a[] = {"uci","set",kv,NULL}; exec_cmd_safe(a,NULL,0); }
    if (sni_s[0]) {
        snprintf(kv, sizeof(kv), "4eburnet.@dns_policy[-1].sni=%s", sni_s);
        const char *const asni[] = {"uci","set",kv,NULL};
        exec_cmd_safe(asni, NULL, 0);
    }
    snprintf(kv, sizeof(kv), "4eburnet.@dns_policy[-1].priority=%s", prio_s);
    { const char *const a[] = {"uci","set",kv,NULL}; exec_cmd_safe(a,NULL,0); }
    { const char *const a[] = {"uci","commit","4eburnet",NULL}; exec_cmd_safe(a,NULL,0); }
    reload_daemon();

    static char get_key[80], got[8];
    int new_id = 0;
    for (int i = 63; i >= 0; i--) {
        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d].pattern", i);
        const char *const ac[] = {"uci", "get", get_key, NULL};
        memset(got, 0, sizeof(got));
        if (exec_cmd_safe(ac, got, sizeof(got) - 1) == 0) { new_id = i; break; }
    }
    static char ok_resp[48];
    snprintf(ok_resp, sizeof(ok_resp), "{\"ok\":true,\"id\":%d}", new_id);
    http_send(conn, epoll_fd, 201, "application/json", ok_resp, strlen(ok_resp));
}

/* ── DELETE /api/dns/policies/{id} ──────────────────────────────────── */
static void route_api_dns_policies_delete(HttpConn *conn, int epoll_fd,
                                           const char *id_str)
{
    if (!id_str || !id_str[0]) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"ok\":false,\"error\":\"missing id\"}", 32); return;
    }
    char *ep;
    long seq_id = strtol(id_str, &ep, 10);
    if (ep == id_str || seq_id < 0 || seq_id > 255) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"ok\":false,\"error\":\"invalid id\"}", 32); return;
    }
    /* ищем UCI-индекс секции по последовательному seq_id (пустые пропускаем) */
    static char get_key[80], got[256];
    int seq = 0, uci_idx = -1;
    for (int i = 0; i < 128; i++) {
        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d]", i);
        const char *const aex[] = {"uci","get",get_key,NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(aex, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        if (!uci_got_ok(got)) break;
        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d].pattern", i);
        const char *const a0[] = {"uci","get",get_key,NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(a0, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        if (!uci_got_ok(got)) continue;
        if (seq == (int)seq_id) { uci_idx = i; break; }
        seq++;
    }
    if (uci_idx < 0) {
        http_send(conn, epoll_fd, 404, "application/json",
                  "{\"ok\":false,\"error\":\"not found\"}", 31); return;
    }
    static char sec[48];
    snprintf(sec, sizeof(sec), "4eburnet.@dns_policy[%d]", uci_idx);
    { const char *const ad[] = {"uci","delete",sec,NULL}; exec_cmd_safe(ad,NULL,0); }
    { const char *const ac2[] = {"uci","commit","4eburnet",NULL}; exec_cmd_safe(ac2,NULL,0); }
    reload_daemon();
    http_send(conn, epoll_fd, 200, "application/json", "{\"ok\":true}", 11);
}

/* ── PATCH /api/dns/policies/reorder ────────────────────────────────── */
static void route_api_dns_policies_reorder(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    if (!hdr_end) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"ok\":false,\"error\":\"bad request\"}", 34); return;
    }
    const char *body = hdr_end + 4;

    struct policy_entry {
        char pattern[256]; char upstream[256];
        char type[8];      char sni[256]; char priority[12];
    };
    static struct policy_entry entries[64];
    static char get_key[80], got[256];
    int count = 0;
    for (int i = 0; i < 128 && count < 64; i++) {
        /* секция существует? */
        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d]", i);
        const char *const aex[] = {"uci","get",get_key,NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(aex, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        if (!uci_got_ok(got)) break;  /* конец списка */

        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d].pattern", i);
        const char *const a0[] = {"uci","get",get_key,NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(a0, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        if (!uci_got_ok(got)) continue;  /* пустая секция — пропускаем */
        snprintf(entries[count].pattern, sizeof(entries[count].pattern), "%s", got);

        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d].upstream", i);
        const char *const a1[] = {"uci","get",get_key,NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(a1, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        snprintf(entries[count].upstream, sizeof(entries[count].upstream),
                 "%s", uci_got_ok(got) ? got : "");

        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d].type", i);
        const char *const a2[] = {"uci","get",get_key,NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(a2, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        if (uci_got_ok(got) && strcmp(got,"dot")==0)
            snprintf(entries[count].type,sizeof(entries[count].type),"dot");
        else if (uci_got_ok(got) && strcmp(got,"doh")==0)
            snprintf(entries[count].type,sizeof(entries[count].type),"doh");
        else
            snprintf(entries[count].type,sizeof(entries[count].type),"udp");

        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d].sni", i);
        const char *const a3[] = {"uci","get",get_key,NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(a3, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        snprintf(entries[count].sni, sizeof(entries[count].sni),
                 "%s", uci_got_ok(got) ? got : "");

        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d].priority", i);
        const char *const a4[] = {"uci","get",get_key,NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(a4, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        snprintf(entries[count].priority, sizeof(entries[count].priority),
                 "%s", (uci_got_ok(got) && got[0] >= '0' && got[0] <= '9') ? got : "100");
        count++;
    }
    if (count == 0) {
        http_send(conn, epoll_fd, 200, "application/json", "{\"ok\":true}", 11); return;
    }

    static int order[64];
    int ocnt = 0;
    const char *arr = strstr(body, "\"order\"");
    if (!arr || (arr = strchr(arr, '[')) == NULL) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"ok\":false,\"error\":\"missing order\"}", 36); return;
    }
    arr++;
    while (*arr && *arr != ']' && ocnt < 64) {
        while (*arr == ' ' || *arr == ',') arr++;
        if (*arr == ']') break;
        char *ep2;
        long v = strtol(arr, &ep2, 10);
        if (ep2 == arr) break;
        if (v >= 0 && v < count) order[ocnt++] = (int)v;
        arr = ep2;
    }
    if (ocnt != count) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"ok\":false,\"error\":\"order length mismatch\"}", 44); return;
    }

    static char sec[48], kv[512];
    /* удаляем ВСЕ dns_policy секции, включая пустые «призрачные» */
    for (int i = 127; i >= 0; i--) {
        snprintf(get_key, sizeof(get_key), "4eburnet.@dns_policy[%d]", i);
        const char *const ach[] = {"uci","get",get_key,NULL};
        memset(got, 0, sizeof(got));
        exec_cmd_safe(ach, got, sizeof(got) - 1);
        got[strcspn(got, "\r\n")] = '\0';
        if (!uci_got_ok(got)) continue;
        snprintf(sec, sizeof(sec), "4eburnet.@dns_policy[%d]", i);
        const char *const ad[] = {"uci","delete",sec,NULL};
        exec_cmd_safe(ad, NULL, 0);
    }
    for (int j = 0; j < ocnt; j++) {
        int src = order[j];
        { const char *const aa[] = {"uci","add","4eburnet","dns_policy",NULL}; exec_cmd_safe(aa,NULL,0); }
        snprintf(kv, sizeof(kv), "4eburnet.@dns_policy[-1].pattern=%s",  entries[src].pattern);
        { const char *const a[] = {"uci","set",kv,NULL}; exec_cmd_safe(a,NULL,0); }
        snprintf(kv, sizeof(kv), "4eburnet.@dns_policy[-1].upstream=%s", entries[src].upstream);
        { const char *const a[] = {"uci","set",kv,NULL}; exec_cmd_safe(a,NULL,0); }
        snprintf(kv, sizeof(kv), "4eburnet.@dns_policy[-1].type=%s",     entries[src].type);
        { const char *const a[] = {"uci","set",kv,NULL}; exec_cmd_safe(a,NULL,0); }
        if (entries[src].sni[0]) {
            snprintf(kv, sizeof(kv), "4eburnet.@dns_policy[-1].sni=%s", entries[src].sni);
            const char *const asni[] = {"uci","set",kv,NULL};
            exec_cmd_safe(asni, NULL, 0);
        }
        snprintf(kv, sizeof(kv), "4eburnet.@dns_policy[-1].priority=%s", entries[src].priority);
        { const char *const a[] = {"uci","set",kv,NULL}; exec_cmd_safe(a,NULL,0); }
    }
    { const char *const a[] = {"uci","commit","4eburnet",NULL}; exec_cmd_safe(a,NULL,0); }
    reload_daemon();
    http_send(conn, epoll_fd, 200, "application/json", "{\"ok\":true}", 11);
}

/* ── GET /api/dpi — DPI настройки через IPC ─────────────────────── */
static void route_api_dpi_get(HttpConn *conn, int epoll_fd)
{
#if CONFIG_EBURNET_DPI
    static char dpi_buf[16384];
    int n = ipc_send_command(IPC_CMD_DPI_GET, dpi_buf, sizeof(dpi_buf) - 1);
    if (n > 0) {
        dpi_buf[n] = '\0';
        http_send(conn, epoll_fd, 200, "application/json",
                  dpi_buf, (size_t)n);
    } else {
        http_send(conn, epoll_fd, 200, "application/json",
                  "{\"enabled\":false}", 17);
    }
#else
    http_send(conn, epoll_fd, 200, "application/json",
              "{\"enabled\":false}", 17);
#endif
}

/* ── PATCH /api/dpi — изменить DPI настройки через IPC ─────────── */
static void route_api_dpi_patch(HttpConn *conn, int epoll_fd)
{
#if CONFIG_EBURNET_DPI
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    const char *body = hdr_end ? hdr_end + 4 : "{}";
    static char dpi_resp[128];
    ipc_send_command_payload(IPC_CMD_DPI_SET, body,
                             dpi_resp, sizeof(dpi_resp) - 1);
    /* После изменения через IPC — commit UCI для persistence */
    static char kv[256];
    static char val[64];
    bool dpi_changed = false;
    static const struct { const char *jkey; const char *uopt; int is_bool; } dmap[] = {
        {"enabled",    "main.dpi_enabled",    1},
        {"split_pos",  "main.dpi_split_pos",  0},
        {"fake_ttl",   "main.dpi_fake_ttl",   0},
        {"fake_count", "main.dpi_fake_repeats",0},
        {"fake_sni",   "main.dpi_fake_sni",   0},
        {NULL, NULL, 0}
    };
    for (int i = 0; dmap[i].jkey; i++) {
        val[0] = '\0';
        http_json_get_str(body, dmap[i].jkey, val, sizeof(val));
        if (val[0]) {
            if (dmap[i].is_bool)
                snprintf(kv, sizeof(kv), "4eburnet.%s=%s", dmap[i].uopt,
                         (strcmp(val,"true")==0||strcmp(val,"1")==0) ? "1" : "0");
            else
                snprintf(kv, sizeof(kv), "4eburnet.%s=%s", dmap[i].uopt, val);
            const char *const av[] = {"uci","set",kv,NULL};
            exec_cmd_safe(av,NULL,0);
            dpi_changed = true;
        }
    }
    /* whitelist/blacklist: JSON array → uci del + uci add_list */
    static const struct { const char *jkey; const char *uopt; } lmap[] = {
        {"whitelist", "main.dpi_whitelist"},
        {"blacklist", "main.dpi_blacklist"},
        {NULL, NULL}
    };
    for (int i = 0; lmap[i].jkey; i++) {
        const char *lkey = strstr(body, lmap[i].jkey);
        if (!lkey) continue;
        const char *arr_start = strchr(lkey, '[');
        const char *arr_end   = arr_start ? strchr(arr_start, ']') : NULL;
        if (!arr_start || !arr_end) continue;
        snprintf(kv, sizeof(kv), "4eburnet.%s", lmap[i].uopt);
        const char *const vd[] = {"uci","del",kv,NULL};
        exec_cmd_safe(vd, NULL, 0);
        static char arr_copy[4096];
        size_t alen = (size_t)(arr_end - arr_start - 1);
        if (alen >= sizeof(arr_copy)) alen = sizeof(arr_copy) - 1;
        memcpy(arr_copy, arr_start + 1, alen);
        arr_copy[alen] = '\0';
        char *tok = strtok(arr_copy, ",");
        while (tok) {
            while (*tok == '"' || *tok == ' ' || *tok == '\t') tok++;
            char *eq = strrchr(tok, '"');
            if (eq) *eq = '\0';
            if (tok[0]) {
                snprintf(kv, sizeof(kv), "4eburnet.%s=%s", lmap[i].uopt, tok);
                const char *const va[] = {"uci","add_list",kv,NULL};
                exec_cmd_safe(va, NULL, 0);
            }
            tok = strtok(NULL, ",");
        }
        dpi_changed = true;
    }
    if (dpi_changed) {
        const char *const vc[] = {"uci","commit","4eburnet",NULL};
        exec_cmd_safe(vc,NULL,0);
    }
#endif
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── GET /api/sniffer — Sniffer настройки ─────────────────────────── */
static void route_api_sniffer_get(HttpConn *conn, int epoll_fd)
{
    static char buf[512];
    /* bypass_domains → JSON array */
    static char bypass_arr[512];
    bypass_arr[0] = '\0';
    if (s_cfg) {
        for (uint8_t i = 0; i < s_cfg->sniffer.bypass_count; i++) {
            if (i > 0) strncat(bypass_arr, ",", sizeof(bypass_arr) - 1);
            strncat(bypass_arr, "\"", sizeof(bypass_arr) - 1);
            strncat(bypass_arr, s_cfg->sniffer.bypass_domains[i],
                    sizeof(bypass_arr) - 1);
            strncat(bypass_arr, "\"", sizeof(bypass_arr) - 1);
        }
    }
    int n = snprintf(buf, sizeof(buf),
        "{\"tls_sni\":%s,\"http_host\":%s,\"quic_sni\":%s,"
        "\"override_dest\":%s,\"bypass_domains\":[%s]}",
        (s_cfg && s_cfg->sniffer.tls_sni)       ? "true" : "false",
        (s_cfg && s_cfg->sniffer.http_host)      ? "true" : "false",
        (s_cfg && s_cfg->sniffer.quic_sni)       ? "true" : "false",
        (s_cfg && s_cfg->sniffer.override_dest)  ? "true" : "false",
        bypass_arr);
    http_send(conn, epoll_fd, 200, "application/json", buf, (size_t)n);
}

/* ── PATCH /api/sniffer — изменить Sniffer настройки ──────────────── */
static void route_api_sniffer_patch(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    const char *body = hdr_end ? hdr_end + 4 : "{}";
    static char kv[256], val[64];
    static const struct { const char *jkey; const char *uopt; } smap[] = {
        {"tls_sni",       "main.sniffer_tls"},
        {"http_host",     "main.sniffer_http"},
        {"quic_sni",      "main.sniffer_quic"},
        {"override_dest", "main.sniffer_override_dest"},
        {NULL, NULL}
    };
    bool changed = false;
    for (int i = 0; smap[i].jkey; i++) {
        val[0] = '\0';
        http_json_get_val(body, smap[i].jkey, val, sizeof(val));
        if (val[0]) {
            snprintf(kv, sizeof(kv), "4eburnet.%s=%s", smap[i].uopt,
                     (strcmp(val,"true")==0||strcmp(val,"1")==0) ? "1" : "0");
            const char *const av[] = {"uci","set",kv,NULL};
            exec_cmd_safe(av,NULL,0);
            changed = true;
        }
    }
    /* bypass_domains: найти JSON array → uci delete + uci add_list */
    const char *bypass_key = strstr(body, "\"bypass_domains\"");
    if (bypass_key) {
        const char *arr_start = strchr(bypass_key, '[');
        const char *arr_end   = arr_start ? strchr(arr_start, ']') : NULL;
        if (arr_start && arr_end) {
            /* Сначала очистить старый список */
            const char *const vd[] = {"uci","del","4eburnet.main.sniffer_bypass",NULL};
            exec_cmd_safe(vd, NULL, 0);
            /* Парсить массив "item1","item2",... */
            static char arr_copy[1024];
            uint32_t alen = (uint32_t)(arr_end - arr_start - 1);
            if (alen >= sizeof(arr_copy)) alen = sizeof(arr_copy) - 1;
            memcpy(arr_copy, arr_start + 1, alen);
            arr_copy[alen] = '\0';
            char *tok = strtok(arr_copy, ",");
            while (tok) {
                while (*tok == '"' || *tok == ' ' || *tok == '\t') tok++;
                char *eq = strrchr(tok, '"');
                if (eq) *eq = '\0';
                if (tok[0]) {
                    snprintf(kv, sizeof(kv),
                             "4eburnet.main.sniffer_bypass=%s", tok);
                    const char *const va[] = {"uci","add_list",kv,NULL};
                    exec_cmd_safe(va, NULL, 0);
                }
                tok = strtok(NULL, ",");
            }
            changed = true;
        }
    }
    if (changed) {
        const char *const vc[] = {"uci","commit","4eburnet",NULL};
        exec_cmd_safe(vc,NULL,0);
    }
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── GET /api/sniffer/stats — Sniffer счётчики ─────────────────────── */
static void route_api_sniffer_stats(HttpConn *conn, int epoll_fd)
{
#if CONFIG_EBURNET_SNIFFER
    uint32_t total = 0, tls = 0, http_c = 0, bypassed = 0;
    dispatcher_get_sniffer_stats(&total, &tls, &http_c, &bypassed);
    static char buf[128];
    int n = snprintf(buf, sizeof(buf),
        "{\"total\":%u,\"tls\":%u,\"http\":%u,\"bypassed\":%u}",
        total, tls, http_c, bypassed);
    http_send(conn, epoll_fd, 200, "application/json", buf, (size_t)n);
#else
    http_send(conn, epoll_fd, 200, "application/json",
              "{\"total\":0,\"tls\":0,\"http\":0,\"bypassed\":0}", 43);
#endif
}

/* ── GET /api/network — сетевые параметры ────────────────────────── */
static void route_api_network_get(HttpConn *conn, int epoll_fd)
{
    static char buf[256];
    uint16_t mtu_val = (s_cfg && s_cfg->mtu) ? s_cfg->mtu : 1500;
    int n = snprintf(buf, sizeof(buf),
        "{\"flow_offload\":%s,\"tc_fast_path\":%s,\"mtu\":%u}",
        (s_cfg && s_cfg->flow_offload)      ? "true" : "false",
        (s_cfg && s_cfg->tc_fast_enabled)   ? "true" : "false",
        (unsigned)mtu_val);
    http_send(conn, epoll_fd, 200, "application/json", buf, (size_t)n);
}

/* ── PATCH /api/network — изменить сетевые параметры ─────────────── */
static void route_api_network_patch(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    const char *body = hdr_end ? hdr_end + 4 : "{}";
    static char val[32], kv[128];
    static const struct { const char *jkey; const char *uopt; } nmap[] = {
        {"flow_offload",  "main.flow_offload"},
        {"tc_fast_path",  "main.tc_fast_enabled"},
        {NULL, NULL}
    };
    bool changed = false;
    for (int i = 0; nmap[i].jkey; i++) {
        val[0] = '\0';
        http_json_get_val(body, nmap[i].jkey, val, sizeof(val));
        if (val[0]) {
            snprintf(kv, sizeof(kv), "4eburnet.%s=%s", nmap[i].uopt,
                     (strcmp(val,"true")==0||strcmp(val,"1")==0) ? "1" : "0");
            const char *const av[] = {"uci","set",kv,NULL};
            exec_cmd_safe(av,NULL,0);
            changed = true;
        }
    }
    /* MTU — числовое поле: 0 = убрать из UCI (авто), иначе 576..9000 */
    val[0] = '\0';
    http_json_get_val(body, "mtu", val, sizeof(val));
    if (val[0]) {
        uint32_t mv = (uint32_t)strtoul(val, NULL, 10);
        if (mv == 0 || (mv >= 576 && mv <= 9000)) {
            snprintf(kv, sizeof(kv), "4eburnet.main.mtu=%u", mv);
            const char *const av[] = {"uci","set",kv,NULL};
            exec_cmd_safe(av,NULL,0);
            changed = true;
        }
    }
    if (changed) {
        const char *const vc[] = {"uci","commit","4eburnet",NULL};
        exec_cmd_safe(vc,NULL,0);
        reload_daemon();
    }
    http_send(conn, epoll_fd, 204, "application/json", "", 0);
}

/* ── GET /api/cdn — CDN настройки из s_cfg ───────────────────────── */
static void route_api_cdn_get(HttpConn *conn, int epoll_fd)
{
    /* MIPS: static buf в BSS. 6 строк × ~270B = ~1620B → buf[1792] */
    static char buf[1792];
    int n = snprintf(buf, sizeof(buf),
        "{"
        "\"cdn_update_interval_days\":%d,"
        "\"cdn_cf_v4_url\":\"%s\","
        "\"cdn_cf_v6_url\":\"%s\","
        "\"cdn_fastly_url\":\"%s\","
        "\"opencck_url\":\"%s\","
        "\"opencck_update_interval_s\":%u"
        "}",
        s_cfg ? s_cfg->cdn_update_interval_days : 7,
        s_cfg ? s_cfg->cdn_cf_v4_url            : "",
        s_cfg ? s_cfg->cdn_cf_v6_url            : "",
        s_cfg ? s_cfg->cdn_fastly_url           : "",
        s_cfg ? s_cfg->opencck_url              : "",
        (unsigned)(s_cfg ? s_cfg->opencck_update_interval_s : 86400));
    http_send(conn, epoll_fd, 200, "application/json", buf, (size_t)n);
}

/* ── PATCH /api/cdn — сохранить CDN настройки в UCI + reload ─────── */
static void route_api_cdn_patch(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    const char *body    = hdr_end ? hdr_end + 4 : "{}";
    bool changed = false;

    /* Числовые поля */
    static char numval[16];
    static char numkv[64];
    numval[0] = '\0';
    http_json_get_val(body, "cdn_update_interval_days", numval, sizeof(numval));
    if (numval[0]) {
        int days = (int)strtol(numval, NULL, 10);
        if (days >= 0 && days <= 365) {
            snprintf(numkv, sizeof(numkv),
                     "4eburnet.main.cdn_update_interval_days=%d", days);
            const char *const av[] = {"uci","set",numkv,NULL};
            exec_cmd_safe(av,NULL,0);
            changed = true;
        }
    }
    numval[0] = '\0';
    http_json_get_val(body, "opencck_update_interval_s", numval, sizeof(numval));
    if (numval[0]) {
        uint32_t secs = (uint32_t)strtoul(numval, NULL, 10);
        if (secs <= 604800) {
            snprintf(numkv, sizeof(numkv),
                     "4eburnet.main.opencck_update_interval_s=%u", (unsigned)secs);
            const char *const av[] = {"uci","set",numkv,NULL};
            exec_cmd_safe(av,NULL,0);
            changed = true;
        }
    }

    /* Строковые URL поля — статический буфер 256B переиспользуется */
    static const struct { const char *jkey; const char *ukey; } cdn_map[] = {
        {"cdn_cf_v4_url",  "main.cdn_cf_v4_url"},
        {"cdn_cf_v6_url",  "main.cdn_cf_v6_url"},
        {"cdn_fastly_url", "main.cdn_fastly_url"},
        {"opencck_url",    "main.opencck_url"},
        {NULL, NULL}
    };
    static char urlval[256];
    static char urlkv[320];
    for (int i = 0; cdn_map[i].jkey; i++) {
        urlval[0] = '\0';
        if (http_json_get_str(body, cdn_map[i].jkey,
                              urlval, sizeof(urlval)) <= 0 || !urlval[0])
            continue;
        /* Принимаем пустую строку (сброс на default) или https:// URL */
        if (urlval[0] != '\0' &&
            strncmp(urlval, "https://", 8) != 0)
            continue;
        snprintf(urlkv, sizeof(urlkv), "4eburnet.%s=%s",
                 cdn_map[i].ukey, urlval);
        const char *const av[] = {"uci","set",urlkv,NULL};
        exec_cmd_safe(av,NULL,0);
        changed = true;
    }

    if (changed) {
        const char *const vc[] = {"uci","commit","4eburnet",NULL};
        exec_cmd_safe(vc,NULL,0);
        reload_daemon();
    }
    static const char ok[] = "{\"ok\":true}";
    http_send(conn, epoll_fd, 200, "application/json", ok, sizeof(ok) - 1);
}

/* ── POST /api/geo/update — запустить обновление geo баз async ──── */
static void route_api_geo_update(HttpConn *conn, int epoll_fd)
{
    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    const char *body = hdr_end ? hdr_end + 4 : "{}";
    static char profile[16];
    http_json_get_str(body, "profile", profile, sizeof(profile));
    if (!profile[0]) strncpy(profile, "full", sizeof(profile) - 1);

    /* WHY: fork + exec async — не блокируем epoll */
    pid_t pid = fork();
    if (pid == 0) {
        const char *const av[] = {"/usr/share/4eburnet/geo_update.sh",
                                   profile, NULL};
        execv("/usr/share/4eburnet/geo_update.sh", (char *const *)av);
        _exit(1);
    }
    /* parent не ждёт */
    static const char resp[] = "{\"status\":\"updating\"}";
    http_send(conn, epoll_fd, 202, "application/json",
              resp, sizeof(resp) - 1);
}

/* ── PATCH /api/devices/{mac} — установить per-device policy ─────── */
static void route_api_devices_patch(HttpConn *conn, int epoll_fd, const char *mac)
{
    /* Валидация MAC: ровно 17 символов XX:XX:XX:XX:XX:XX */
    int mac_ok = (strlen(mac) == 17);
    if (mac_ok) {
        for (int i = 0; i < 17; i++) {
            if (i % 3 == 2) { if (mac[i] != ':') { mac_ok = 0; break; } }
            else {
                char c = (char)tolower((unsigned char)mac[i]);
                if (!((c>='0'&&c<='9')||(c>='a'&&c<='f')))
                    { mac_ok = 0; break; }
            }
        }
    }
    if (!mac_ok) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"error\":\"invalid mac\"}", 23); return;
    }

    const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
    const char *body = hdr_end ? hdr_end + 4 : "{}";
    static char policy[32], grp[64], s_alias[128], s_comment[256];
    static char s_enabled[8], s_priority[16];
    http_json_get_str(body, "policy",   policy,     sizeof(policy));
    http_json_get_str(body, "group",    grp,        sizeof(grp));
    http_json_get_str(body, "alias",    s_alias,    sizeof(s_alias));
    http_json_get_str(body, "comment",  s_comment,  sizeof(s_comment));
    http_json_get_val(body, "enabled",  s_enabled,  sizeof(s_enabled));
    http_json_get_val(body, "priority", s_priority, sizeof(s_priority));
    if (!policy[0] && !grp[0] && !s_alias[0] && !s_comment[0]
        && !s_enabled[0] && !s_priority[0]) {
        http_send(conn, epoll_fd, 400, "application/json",
                  "{\"error\":\"no fields to update\"}", 31); return;
    }

    /* Нормализовать MAC → имя UCI секции */
    static char sec_name[32];
    int sn = 4; memcpy(sec_name, "dev_", 4);
    for (int i = 0; i < 17; i++) {
        if (mac[i] != ':')
            sec_name[sn++] = (char)tolower((unsigned char)mac[i]);
    }
    sec_name[sn] = '\0';

    static char us[64], up[64], um[64], ug[64];
    static char ua[196], uc[320], ue[64], upr[64];
    snprintf(us, sizeof(us), "4eburnet.%s=device_policy", sec_name);
    snprintf(um, sizeof(um), "4eburnet.%s.mac=%s",        sec_name, mac);
    const char *const av0[]={"uci","set",us,NULL};
    const char *const av2[]={"uci","set",um,NULL};
    const char *const avc[]={"uci","commit","4eburnet",NULL};
    exec_cmd_safe(av0,NULL,0);
    exec_cmd_safe(av2,NULL,0);
    if (policy[0]) {
        snprintf(up, sizeof(up), "4eburnet.%s.policy=%s", sec_name, policy);
        const char *const av1[]={"uci","set",up,NULL};
        exec_cmd_safe(av1,NULL,0);
    }
    if (grp[0]) {
        snprintf(ug, sizeof(ug), "4eburnet.%s.proxy_group=%s", sec_name, grp);
        const char *const av3[]={"uci","set",ug,NULL};
        exec_cmd_safe(av3,NULL,0);
    }
    if (s_alias[0]) {
        snprintf(ua, sizeof(ua), "4eburnet.%s.alias=%s", sec_name, s_alias);
        const char *const av4[]={"uci","set",ua,NULL};
        exec_cmd_safe(av4,NULL,0);
    }
    if (s_comment[0]) {
        snprintf(uc, sizeof(uc), "4eburnet.%s.comment=%s", sec_name, s_comment);
        const char *const av5[]={"uci","set",uc,NULL};
        exec_cmd_safe(av5,NULL,0);
    }
    if (s_enabled[0]) {
        bool en = (!strcmp(s_enabled, "true") || !strcmp(s_enabled, "1"));
        snprintf(ue, sizeof(ue), "4eburnet.%s.enabled=%d", sec_name, en ? 1 : 0);
        const char *const av6[]={"uci","set",ue,NULL};
        exec_cmd_safe(av6,NULL,0);
    }
    if (s_priority[0]) {
        snprintf(upr, sizeof(upr), "4eburnet.%s.priority=%s", sec_name, s_priority);
        const char *const av7[]={"uci","set",upr,NULL};
        exec_cmd_safe(av7,NULL,0);
    }
    exec_cmd_safe(avc,NULL,0);
    reload_daemon();
    static const char ok_resp[] = "{\"ok\":true}";
    http_send(conn, epoll_fd, 200, "application/json",
              ok_resp, sizeof(ok_resp) - 1);
}

/* Найти geo_category_t по имени файла (без расширения) в s_geo.
 * Имена категорий и файлов могут отличаться:
 *   geosite-ads.gbin → файл "geosite-ads", категория "ads"
 *   opencck-domains.gbin → файл "opencck-domains", категория "opencck"
 * Пробуем: точное имя → без "geosite-"/"geoip-" → суффикс после последнего '-'. */
static const geo_category_t *geo_find_cat_by_filename(const char *name)
{
    if (!s_geo) return NULL;
    /* Попытка 1: точное имя */
    for (int i = 0; i < s_geo->count; i++)
        if (strcmp(s_geo->categories[i].name, name) == 0)
            return &s_geo->categories[i];
    /* Попытка 2: без "geosite-"/"geoip-" префикса */
    const char *short_name = name;
    if (strncmp(name, "geosite-", 8) == 0) short_name = name + 8;
    else if (strncmp(name, "geoip-", 6) == 0) short_name = name + 6;
    if (short_name != name)
        for (int i = 0; i < s_geo->count; i++)
            if (strcmp(s_geo->categories[i].name, short_name) == 0)
                return &s_geo->categories[i];
    /* Попытка 3: суффикс после последнего '-' */
    const char *dash = strrchr(name, '-');
    if (dash && dash[1])
        for (int i = 0; i < s_geo->count; i++)
            if (strcmp(s_geo->categories[i].name, dash + 1) == 0)
                return &s_geo->categories[i];
    /* Попытка 4: часть до первого '-' (opencck-domains → opencck) */
    {
        static char prefix[64];
        const char *first_dash = strchr(name, '-');
        if (first_dash) {
            int plen = (int)(first_dash - name);
            if (plen > 0 && plen < (int)sizeof(prefix)) {
                memcpy(prefix, name, (size_t)plen);
                prefix[plen] = '\0';
                for (int i = 0; i < s_geo->count; i++)
                    if (strcmp(s_geo->categories[i].name, prefix) == 0)
                        return &s_geo->categories[i];
            }
        }
    }
    return NULL;
}

/* ── GET /api/geo — список .gbin файлов + hot-reload статус ─────── */
static void route_api_geo(HttpConn *conn, int epoll_fd)
{
    const char *geo_dir = "/etc/4eburnet/geo";
    if (s_cfg && s_cfg->geo_dir[0]) geo_dir = s_cfg->geo_dir;

    /* Метрики hot-reload из s_geo (прямой доступ, без IPC) */
    uint32_t reload_count  = s_geo ? s_geo->reload_count      : 0;
    long long last_reload  = s_geo ? (long long)s_geo->last_reload_time : 0LL;
    bool last_reload_ok    = s_geo ? s_geo->last_reload_ok    : false;
    const char *profile    = (s_cfg && s_cfg->geo_profile[0]) ? s_cfg->geo_profile : "normal";

    int pos = 0;
    int cap = (int)sizeof(s_ipc_buf);
    pos += snprintf(s_ipc_buf + pos, (size_t)(cap - pos),
        "{\"profile\":\"%s\","
        "\"reload_count\":%u,"
        "\"last_reload\":%lld,"
        "\"last_reload_ok\":%s,"
        "\"hot_reload_supported\":true,"
        "\"files\":[",
        profile, reload_count, last_reload,
        last_reload_ok ? "true" : "false");

    DIR *d = opendir(geo_dir);
    bool first = true;
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL && pos < cap - 256) {
            /* Только .gbin файлы */
            size_t nlen = strlen(e->d_name);
            if (nlen < 6 || strcmp(e->d_name + nlen - 5, ".gbin") != 0) continue;

            static char fullpath[256];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", geo_dir, e->d_name);
            static struct stat fst;
            if (stat(fullpath, &fst) != 0) continue;

            /* Имя без расширения */
            static char name[64];
            int namelen = (int)nlen - 5;
            if (namelen > (int)sizeof(name) - 1) namelen = (int)sizeof(name) - 1;
            memcpy(name, e->d_name, (size_t)namelen);
            name[namelen] = '\0';

            /* Найти категорию по имени файла для loaded/entries */
            bool f_loaded = false;
            int f_entries = 0;
            const geo_category_t *cat = geo_find_cat_by_filename(name);
            if (cat) {
                f_loaded  = cat->loaded;
                f_entries = cat->v4_count + cat->v6_count +
                            cat->domain_count + cat->suffix_count;
            }

            pos += snprintf(s_ipc_buf + pos, (size_t)(cap - pos),
                            "%s{\"name\":\"%s\",\"size\":%lld,"
                            "\"loaded\":%s,\"entries\":%d}",
                            first ? "" : ",", name,
                            (long long)fst.st_size,
                            f_loaded ? "true" : "false",
                            f_entries);
            first = false;
        }
        closedir(d);
    }

    if (pos < cap - 4) pos += snprintf(s_ipc_buf + pos, (size_t)(cap - pos), "]}");
    http_send(conn, epoll_fd, 200, "application/json",
              s_ipc_buf, (size_t)(pos > 0 ? pos : 0));
}

/* ── GET /api/logs — последние строки из лог-файла ─────────────────── */
static void route_api_logs(HttpConn *conn, int epoll_fd)
{
    int pos = 0;
    int cap = (int)sizeof(s_logs_buf);
    pos += snprintf(s_logs_buf + pos, (size_t)(cap - pos), "{\"lines\":[");

    FILE *f = fopen(EBURNET_LOG_FILE, "r");
    if (f) {
        /* Кольцевой буфер из 200 строк */
        static char lines[200][160];
        int head = 0, count = 0;
        static char ln[160];
        while (fgets(ln, sizeof(ln), f)) {
            /* Убрать \n */
            size_t ll = strlen(ln);
            if (ll > 0 && ln[ll - 1] == '\n') ln[ll - 1] = '\0';
            strncpy(lines[head], ln, 159);
            lines[head][159] = '\0';
            head = (head + 1) % 200;
            if (count < 200) count++;
        }
        fclose(f);

        /* Вывести в хронологическом порядке */
        bool first = true;
        int start = (count < 200) ? 0 : head;
        for (int i = 0; i < count && pos < cap - 256; i++) {
            int idx = (start + i) % 200;
            /* JSON-escape: заменить " на \", \ на \\ */
            static char esc[320];
            int ep = 0;
            for (const char *p = lines[idx]; *p && ep < 315; p++) {
                if (*p == '"' || *p == '\\') esc[ep++] = '\\';
                esc[ep++] = *p;
            }
            esc[ep] = '\0';
            pos += snprintf(s_logs_buf + pos, (size_t)(cap - pos),
                            "%s\"%s\"", first ? "" : ",", esc);
            first = false;
        }
    }

    if (pos < cap - 4) pos += snprintf(s_logs_buf + pos, (size_t)(cap - pos), "]}");
    http_send(conn, epoll_fd, 200, "application/json",
              s_logs_buf, (size_t)(pos > 0 ? pos : 0));
}

/* ── GET /api/logs/download — отдать /tmp/4eburnet.log как attachment ── */
static void route_api_logs_download(HttpConn *conn, int epoll_fd)
{
    struct stat st;
    if (stat(EBURNET_LOG_FILE, &st) != 0 || st.st_size <= 0) {
        static const char err404[] = "{\"error\":\"log file not found\"}";
        http_send(conn, epoll_fd, 404, "application/json",
                  err404, sizeof(err404) - 1);
        return;
    }

    FILE *f = fopen(EBURNET_LOG_FILE, "rb");
    if (!f) {
        static const char err404[] = "{\"error\":\"log file not found\"}";
        http_send(conn, epoll_fd, 404, "application/json",
                  err404, sizeof(err404) - 1);
        return;
    }

    /* MIPS: static буферы в BSS — не стек */
    static char dl_cors[384];
    cors_origin_hdr(conn->buf, dl_cors, sizeof(dl_cors));
    static char dl_hdr[896];
    int hlen = snprintf(dl_hdr, sizeof(dl_hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: %lld\r\n"
        "Content-Disposition: attachment; filename=\"4eburnet.log\"\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        (long long)st.st_size, dl_cors);

    if (hlen <= 0 || hlen >= (int)sizeof(dl_hdr)) {
        fclose(f);
        conn_close(conn, epoll_fd);
        return;
    }
    if (send(conn->fd, dl_hdr, (size_t)hlen, MSG_NOSIGNAL) < 0) {
        fclose(f);
        conn_close(conn, epoll_fd);
        return;
    }

    conn->send_file      = f;
    conn->send_offset    = 0;
    conn->send_remaining = st.st_size;

    int rc = http_send_file_continue(conn);
    if (rc == 1) {
        conn_close(conn, epoll_fd);
    } else if (rc == 0) {
        struct epoll_event ev;
        ev.events  = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
        ev.data.fd = conn->fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
    } else {
        conn_close(conn, epoll_fd);
    }
}

/* ── /api/devices — ARP + DHCP + UCI политики ────────────────────── */
static void route_api_devices(HttpConn *conn, int epoll_fd)
{
    /* Структуры в BSS — не стек, не heap (MIPS 8KB стек) */
    struct arp_entry {
        char ip[16];
        char mac[18];
        char iface[16];
    };
    struct lease_entry {
        char mac[18];
        char hostname[64];
    };
    static struct arp_entry   arp[64];
    static struct lease_entry leases[64];
    static char               out[65536];
    static char               esc_name[128];
    static char               esc_alias[128];
    static char               esc_comment[256];
    static char               esc_iface[32];
    static char               esc_mac[64];
    static char               esc_ip[32];

    int  narp    = 0;
    int  nleases = 0;
    char line[256];  /* 256 < 512B лимит MIPS стека */
    int  pos = 0;
    int  cap = (int)sizeof(out);

    /* --- 1. /proc/net/arp: MAC→IP маппинги (только COMPLETE=0x2) --- */
    FILE *f = fopen("/proc/net/arp", "r");
    if (f) {
        if (fgets(line, sizeof(line), f)) {  /* пропустить заголовок */
            while (narp < 64 && fgets(line, sizeof(line), f)) {
                char flags_str[8] = {0};
                /* Формат: IP HW_type Flags HW_addr Mask Device */
                if (sscanf(line, "%15s %*s %7s %17s %*s %15s",
                           arp[narp].ip, flags_str,
                           arp[narp].mac, arp[narp].iface) == 4) {
                    unsigned int flags =
                        (unsigned int)strtoul(flags_str, NULL, 16);
                    if (flags & 0x2)  /* ATF_COM = запись завершена */
                        narp++;
                }
            }
        }
        fclose(f);
    }

    /* --- 2. /tmp/dhcp.leases: IP→hostname --- */
    f = fopen("/tmp/dhcp.leases", "r");
    if (f) {
        while (nleases < 64 && fgets(line, sizeof(line), f)) {
            char hname[64] = {0};
            /* Формат: timestamp MAC IP hostname clientid */
            if (sscanf(line, "%*s %17s %*s %63s",
                       leases[nleases].mac, hname) == 2) {
                if (hname[0] != '*')
                    snprintf(leases[nleases].hostname,
                             sizeof(leases[nleases].hostname),
                             "%s", hname);
                nleases++;
            }
        }
        fclose(f);
    }

    /* --- 3. Собрать JSON: мердж ARP + DHCP + UCI политик --- */
    pos += snprintf(out + pos, (size_t)(cap - pos), "{\"devices\":[");

    for (int i = 0; i < narp && pos < cap - 256; i++) {
        /* Имя: сначала из device manager, затем из DHCP */
        const char *name = "";
        for (int j = 0; j < nleases; j++) {
            if (strcasecmp(leases[j].mac, arp[i].mac) == 0) {
                name = leases[j].hostname;
                break;
            }
        }

        const char *policy    = "default";
        bool        dev_enabled  = true;
        int         dev_priority = 0;
        esc_alias[0]   = '\0';
        esc_comment[0] = '\0';
        if (s_dm) {
            const device_config_t *dev =
                device_policy_find(s_dm, arp[i].mac);
            if (dev) {
                switch (dev->policy) {
                case DEVICE_POLICY_PROXY:  policy = "proxy";  break;
                case DEVICE_POLICY_BYPASS: policy = "bypass"; break;
                case DEVICE_POLICY_BLOCK:  policy = "block";  break;
                default:                   policy = "default"; break;
                }
                /* UCI name имеет приоритет над DHCP hostname */
                if (dev->name[0])    name = dev->name;
                dev_enabled  = dev->enabled;
                dev_priority = dev->priority;
                if (dev->alias[0])
                    json_escape_str(dev->alias,   esc_alias,   sizeof(esc_alias));
                if (dev->comment[0])
                    json_escape_str(dev->comment, esc_comment, sizeof(esc_comment));
            }
        }

        json_escape_str(name,         esc_name,  sizeof(esc_name));
        json_escape_str(arp[i].iface, esc_iface, sizeof(esc_iface));
        json_escape_str(arp[i].mac,   esc_mac,   sizeof(esc_mac));
        /* WHY: IP из /proc/net/arp теоретически [0-9.], но json_escape_str
         * обязателен для всех данных из внешних источников — defensive coding. */
        json_escape_str(arp[i].ip,    esc_ip,    sizeof(esc_ip));

        device_traffic_t zero_tr = {0};
        device_traffic_t *tr = s_dm
            ? device_traffic_get(s_dm, esc_mac) : &zero_tr;
        if (!tr) tr = &zero_tr;

        pos += snprintf(out + pos, (size_t)(cap - pos),
            "%s{\"mac\":\"%s\",\"ip\":\"%s\","
            "\"name\":\"%s\",\"alias\":\"%s\",\"policy\":\"%s\",\"iface\":\"%s\","
            "\"enabled\":%s,\"priority\":%d,\"comment\":\"%s\","
            "\"tx_bytes\":%llu,\"rx_bytes\":%llu,\"conn_count\":%llu}",
            i > 0 ? "," : "",
            esc_mac, esc_ip, esc_name, esc_alias, policy, esc_iface,
            dev_enabled ? "true" : "false", dev_priority, esc_comment,
            (unsigned long long)tr->tx_bytes,
            (unsigned long long)tr->rx_bytes,
            (unsigned long long)tr->conn_count);
    }

    pos += snprintf(out + pos, (size_t)(cap - pos), "]}");
    http_send(conn, epoll_fd, 200, "application/json",
              out, (size_t)(pos > 0 ? pos : 0));
}

/* ── http_server_init ─────────────────────────────────────────────── */
int http_server_init(HttpServer *srv)
{
    for (int i = 0; i < HTTP_MAX_CONN; i++)
        srv->conns[i].fd = -1;

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("http: socket");
        return -1;
    }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(HTTP_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),        /* 0.0.0.0 — LAN + localhost */
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("http: bind");
        close(fd);
        return -1;
    }

    if (listen(fd, HTTP_MAX_CONN) < 0) {
        perror("http: listen");
        close(fd);
        return -1;
    }

    srv->listen_fd = fd;

    /* Читать токен из UCI при инициализации */
    srv->api_token[0] = '\0';
    FILE *tf = popen("uci -q get 4eburnet.main.api_token 2>/dev/null", "r");
    if (tf) {
        if (fgets(srv->api_token, sizeof(srv->api_token), tf)) {
            size_t l = strlen(srv->api_token);
            if (l > 0 && srv->api_token[l-1] == '\n') srv->api_token[l-1] = '\0';
        }
        pclose(tf);
    }
    snprintf(s_api_token, sizeof(s_api_token), "%s", srv->api_token);

    /* WS /traffic stream — init prev snapshot текущими counter values,
     * чтобы первая delta после старта была 0 (не cumulative spike) */
    srv->traffic_prev_up = atomic_load_explicit(
        &g_stats.traffic_up_bytes, memory_order_relaxed);
    srv->traffic_prev_down = atomic_load_explicit(
        &g_stats.traffic_down_bytes, memory_order_relaxed);

    return 0;
}

/* ── http_server_register_epoll ──────────────────────────────────── */
void http_server_register_epoll(HttpServer *srv, int epoll_fd)
{
    /* Сохраняем для WS /logs хука */
    s_ws_srv      = srv;
    s_ws_epoll_fd = epoll_fd;
    log_set_hook(http_ws_log_hook);

    struct epoll_event ev;

    /* НАМЕРЕННО LT (level-triggered), не ET:
     * На listen-сокете ET требует цикла accept до EAGAIN в одном событии.
     * Пропуск соединения с ET — потеря клиента без возможности recover.
     * LT: событие повторяется пока есть pending connections — безопасно. */
    ev.events  = EPOLLIN;
    ev.data.fd = srv->listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, srv->listen_fd, &ev);

    for (int i = 0; i < HTTP_MAX_CONN; i++) {
        if (srv->conns[i].fd < 0)
            continue;
        ev.events  = EPOLLIN | EPOLLRDHUP;
        ev.data.fd = srv->conns[i].fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, srv->conns[i].fd, &ev);
    }
}

/* ── http_server_handle ───────────────────────────────────────────── */
int http_server_handle(HttpServer *srv, int fd, int epoll_fd, uint32_t evmask)
{
    /* ── SSH pty_master: вывод /bin/ash → WS клиент ─────────────── */
    if (s_ssh.active && fd == s_ssh.pty_master) {
        if (evmask & EPOLLIN)
            ssh_pty_on_output(epoll_fd);
        return 0;
    }

    /* ── Новое входящее соединение ──────────────────────────────── */
    if (fd == srv->listen_fd) {
        struct sockaddr_in peer_tmp;
        socklen_t peer_len = sizeof(peer_tmp);
        int new_fd = accept4(fd, (struct sockaddr *)&peer_tmp, &peer_len,
                             SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (new_fd < 0)
            return 0;

        HttpConn *slot = NULL;
        for (int i = 0; i < HTTP_MAX_CONN; i++) {
            if (srv->conns[i].fd < 0) {
                slot = &srv->conns[i];
                break;
            }
        }

        if (!slot) {
            close(new_fd);
            return 0;
        }

        slot->fd             = new_fd;
        slot->peer_addr      = peer_tmp;
        slot->connected_at   = time(NULL);
        slot->buf_len        = 0;
        slot->headers_done   = 0;
        slot->method_ok      = 0;
        slot->is_post        = 0;
        slot->is_put         = 0;
        slot->is_patch       = 0;
        slot->is_delete      = 0;
        slot->is_options     = 0;
        slot->content_length = 0;
        slot->path[0]        = '/';
        slot->path[1]        = '\0';
        slot->is_websocket   = 0;
        slot->ws_route       = WS_ROUTE_NONE;
        slot->send_buf       = NULL;
        slot->send_len       = 0;
        slot->send_pos       = 0;
        slot->send_file      = NULL;
        slot->send_offset    = 0;
        slot->send_remaining = 0;

        struct epoll_event ev;
        ev.events  = EPOLLIN | EPOLLRDHUP;  /* LT: ET на accept теряет запросы при race */
        ev.data.fd = new_fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &ev);

        return 0;
    }

    /* ── Данные от клиента ───────────────────────────────────────── */
    for (int i = 0; i < HTTP_MAX_CONN; i++) {
        HttpConn *conn = &srv->conns[i];
        if (conn->fd != fd)
            continue;

        /* ─── EPOLLOUT: async file send или drain send_buf ─── */
        if (evmask & EPOLLOUT) {
            if (conn->send_file != NULL) {
                /* Путь async file send: drain через fread+send */
                int rc = http_send_file_continue(conn);
                if (rc != 0)
                    conn_close(conn, epoll_fd);
                /* rc == 0: ждём следующий EPOLLOUT */
            } else {
                /* Путь send_buf: слить буфер и закрыть */
                if (conn_flush(conn, epoll_fd) < 0 || !conn->send_buf)
                    conn_close(conn, epoll_fd);
            }
            return 0;
        }

        /* ─── WebSocket path: другой read loop, другой dispatcher ─── */
        if (conn->is_websocket) {
            for (;;) {
                int space = HTTP_BUF_SIZE - 1 - conn->buf_len;
                if (space <= 0) {
                    /* Frame overflow — message too big */
                    ws_send_close(conn, epoll_fd, 1009);
                    conn_close(conn, epoll_fd);
                    return 0;
                }
                int n = (int)read(fd, conn->buf + conn->buf_len,
                                  (size_t)space);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    conn_close(conn, epoll_fd);
                    return 0;
                }
                if (n == 0) {
                    conn_close(conn, epoll_fd);
                    return 0;
                }
                conn->buf_len += n;
            }
            ws_handle_connection(conn, epoll_fd);
            return 0;
        }

        int space = HTTP_BUF_SIZE - 1 - conn->buf_len;
        if (space <= 0) {
            conn_close(conn, epoll_fd);
            return 0;
        }

        for (;;) {
            int n = (int)read(fd, conn->buf + conn->buf_len, (size_t)space);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                conn_close(conn, epoll_fd);
                return 0;
            }
            if (n == 0) {
                conn_close(conn, epoll_fd);
                return 0;
            }
            conn->buf_len += n;
            conn->buf[conn->buf_len] = '\0';
            if (strstr(conn->buf, "\r\n\r\n")) {
                conn->headers_done = 1;
                break;
            }
            space = HTTP_BUF_SIZE - 1 - conn->buf_len;
            if (space <= 0) {
                conn_close(conn, epoll_fd);
                return 0;
            }
        }

        if (!conn->headers_done) {
            if (conn->buf_len >= HTTP_BUF_SIZE - 1)
                conn_close(conn, epoll_fd);
            return 0;
        }

        /* ── Парсинг Request-Line ─────────────────────────────── */
        if (strncmp(conn->buf, "GET ", 4) == 0) {
            conn->method_ok = 1;

            const char *path_start = conn->buf + 4;
            const char *path_end   = strstr(path_start, " HTTP/");
            if (!path_end) path_end = strstr(path_start, "\r\n");
            if (!path_end) path_end = path_start;

            int path_len = (int)(path_end - path_start);
            if (path_len >= HTTP_PATH_MAX)
                path_len = HTTP_PATH_MAX - 1;

            memcpy(conn->path, path_start, (size_t)path_len);
            conn->path[path_len] = '\0';

            if (conn->path[0] == '\0') {
                conn->path[0] = '/';
                conn->path[1] = '\0';
            }
        } else if (strncmp(conn->buf, "POST ", 5) == 0) {
            conn->method_ok  = 1;
            conn->is_post    = 1;

            const char *ps = conn->buf + 5;
            const char *pe = strstr(ps, " HTTP/");
            if (!pe) pe = strstr(ps, "\r\n");
            if (!pe) pe = ps;

            int pl = (int)(pe - ps);
            if (pl >= HTTP_PATH_MAX) pl = HTTP_PATH_MAX - 1;
            memcpy(conn->path, ps, (size_t)pl);
            conn->path[pl] = '\0';
            if (!conn->path[0]) { conn->path[0] = '/'; conn->path[1] = '\0'; }

            /* Извлечь Content-Length */
            const char *cl = strstr(conn->buf, "Content-Length:");
            if (!cl) cl = strstr(conn->buf, "content-length:");
            if (cl) {
                long cl_val = strtol(cl + 15, NULL, 10);
                /* -1 = слишком большой (handler вернёт 413), 0 = не указан */
                if (cl_val > 0 && cl_val <= HTTP_MAX_BODY)
                    conn->content_length = (int)cl_val;
                else if (cl_val > HTTP_MAX_BODY)
                    conn->content_length = -1;
                else
                    conn->content_length = 0;
            } else {
                conn->content_length = 0;
            }

        } else if (strncmp(conn->buf, "PUT ", 4) == 0) {
            conn->method_ok = 1;
            conn->is_put    = 1;

            const char *ps = conn->buf + 4;
            const char *pe = strstr(ps, " HTTP/");
            if (!pe) pe = strstr(ps, "\r\n");
            if (!pe) pe = ps;

            int pl = (int)(pe - ps);
            if (pl >= HTTP_PATH_MAX) pl = HTTP_PATH_MAX - 1;
            memcpy(conn->path, ps, (size_t)pl);
            conn->path[pl] = '\0';
            if (!conn->path[0]) { conn->path[0] = '/'; conn->path[1] = '\0'; }

            /* Извлечь Content-Length (аналогично POST) */
            const char *pcl = strstr(conn->buf, "Content-Length:");
            if (!pcl) pcl = strstr(conn->buf, "content-length:");
            if (pcl) {
                long cl_val = strtol(pcl + 15, NULL, 10);
                if (cl_val > 0 && cl_val <= HTTP_MAX_BODY)
                    conn->content_length = (int)cl_val;
                else if (cl_val > HTTP_MAX_BODY)
                    conn->content_length = -1;
                else
                    conn->content_length = 0;
            } else {
                conn->content_length = 0;
            }

        } else if (strncmp(conn->buf, "DELETE ", 7) == 0) {
            conn->method_ok = 1;
            conn->is_delete = 1;

            const char *ps = conn->buf + 7;
            const char *pe = strstr(ps, " HTTP/");
            if (!pe) pe = strstr(ps, "\r\n");
            if (!pe) pe = ps;

            int pl = (int)(pe - ps);
            if (pl >= HTTP_PATH_MAX) pl = HTTP_PATH_MAX - 1;
            memcpy(conn->path, ps, (size_t)pl);
            conn->path[pl] = '\0';
            if (!conn->path[0]) { conn->path[0] = '/'; conn->path[1] = '\0'; }
            conn->content_length = 0;

        } else if (strncmp(conn->buf, "PATCH ", 6) == 0) {
            conn->method_ok  = 1;
            conn->is_patch   = 1;

            const char *ps = conn->buf + 6;
            const char *pe = strstr(ps, " HTTP/");
            if (!pe) pe = strstr(ps, "\r\n");
            if (!pe) pe = ps;

            int pl = (int)(pe - ps);
            if (pl >= HTTP_PATH_MAX) pl = HTTP_PATH_MAX - 1;
            memcpy(conn->path, ps, (size_t)pl);
            conn->path[pl] = '\0';
            if (!conn->path[0]) { conn->path[0] = '/'; conn->path[1] = '\0'; }

            const char *pcl = strstr(conn->buf, "Content-Length:");
            if (!pcl) pcl = strstr(conn->buf, "content-length:");
            if (pcl) {
                long cl_val = strtol(pcl + 15, NULL, 10);
                if (cl_val > 0 && cl_val <= HTTP_MAX_BODY)
                    conn->content_length = (int)cl_val;
                else if (cl_val > HTTP_MAX_BODY)
                    conn->content_length = -1;
                else
                    conn->content_length = 0;
            } else {
                conn->content_length = 0;
            }

        } else if (strncmp(conn->buf, "OPTIONS ", 8) == 0) {
            conn->method_ok  = 1;
            conn->is_options = 1;

            const char *ps = conn->buf + 8;
            const char *pe = strstr(ps, " HTTP/");
            if (!pe) pe = strstr(ps, "\r\n");
            if (!pe) pe = ps;

            int pl = (int)(pe - ps);
            if (pl >= HTTP_PATH_MAX) pl = HTTP_PATH_MAX - 1;
            memcpy(conn->path, ps, (size_t)pl);
            conn->path[pl] = '\0';
            if (!conn->path[0]) { conn->path[0] = '/'; conn->path[1] = '\0'; }
            conn->content_length = 0;

        } else {
            conn->method_ok = 0;
            conn->path[0]   = '\0';
        }

        /* POST/PATCH: дождаться полного тела (content_length байт после \r\n\r\n).
           Исключение: /api/restore — тело до 64KB не влезает в buf[4096],
           поэтому дочитывается в самом обработчике из conn->fd напрямую. */
        if ((conn->is_post || conn->is_patch || conn->is_put) && conn->content_length > 0 &&
            strcmp(conn->path, "/api/restore") != 0) {
            const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
            if (hdr_end) {
                int body_recv = conn->buf_len - (int)(hdr_end + 4 - conn->buf);
                if (body_recv < conn->content_length) {
                    return 0;
                }
            }
        }

        http_dispatch(conn, epoll_fd);
        return 0;
    }

    return -1;
}

/* ── http_server_tick ─────────────────────────────────────────────── */
void http_server_tick(HttpServer *srv, int epoll_fd)
{
    time_t now = time(NULL);
    for (int i = 0; i < HTTP_MAX_CONN; i++) {
        HttpConn *c = &srv->conns[i];
        if (c->fd < 0)
            continue;
        /* WS connections живут дольше (Part B keepalive через ping/pong) */
        int timeout = c->is_websocket ? 300 : HTTP_TIMEOUT_SEC;
        if (now - c->connected_at > timeout)
            conn_close(c, epoll_fd);
    }
}

/* ── Прочитать RSS (Resident Set Size) процесса из /proc/self/status.
 * Возвращает байты; 0 при ошибке. */
static long read_vmrss_bytes(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    long rss_kb = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "VmRSS: %ld kB", &rss_kb) == 1) break;
    }
    fclose(f);
    return rss_kb * 1024;
}

/* ── http_server_broadcast_tick ───────────────────────────────────────
 * Периодический broadcast для WS streams.
 * Вызывается из main loop каждую секунду (main.c tick % 100).
 * Part B: /memory. Future: /traffic, /logs, /connections. */
void http_server_broadcast_tick(HttpServer *srv, int epoll_fd)
{
    if (!srv) return;

    /* ─── /memory stream ─── */
    {
        /* Early exit: нет подписчиков — не тратимся на /proc read */
        int has_subs = 0;
        for (int i = 0; i < HTTP_MAX_CONN; i++) {
            HttpConn *c = &srv->conns[i];
            if (c->fd >= 0 && c->is_websocket &&
                c->ws_route == WS_ROUTE_MEMORY) {
                has_subs = 1;
                break;
            }
        }

        if (has_subs) {
            long rss = read_vmrss_bytes();
            char json[96];
            int n = snprintf(json, sizeof(json),
                             "{\"inuse\":%ld,\"oslimit\":0}", rss);
            if (n > 0 && (size_t)n < sizeof(json)) {
                for (int i = 0; i < HTTP_MAX_CONN; i++) {
                    HttpConn *c = &srv->conns[i];
                    if (c->fd < 0 || !c->is_websocket) continue;
                    if (c->ws_route != WS_ROUTE_MEMORY) continue;

                    if (ws_send_text(c, epoll_fd, json, (size_t)n) < 0) {
                        /* Write failed — client gone */
                        conn_close(c, epoll_fd);
                    }
                }
            }
        }
    }

    /* ─── /traffic stream (delta bytes/sec) ─── */
    {
        int has_subs = 0;
        for (int i = 0; i < HTTP_MAX_CONN; i++) {
            HttpConn *c = &srv->conns[i];
            if (c->fd >= 0 && c->is_websocket &&
                c->ws_route == WS_ROUTE_TRAFFIC) {
                has_subs = 1;
                break;
            }
        }

        if (has_subs) {
            uint64_t cur_up = atomic_load_explicit(
                &g_stats.traffic_up_bytes, memory_order_relaxed);
            uint64_t cur_down = atomic_load_explicit(
                &g_stats.traffic_down_bytes, memory_order_relaxed);

            /* Overflow-safe delta (unsigned wrap protection) */
            uint64_t d_up = (cur_up >= srv->traffic_prev_up)
                          ? (cur_up - srv->traffic_prev_up) : 0;
            uint64_t d_down = (cur_down >= srv->traffic_prev_down)
                            ? (cur_down - srv->traffic_prev_down) : 0;

            srv->traffic_prev_up = cur_up;
            srv->traffic_prev_down = cur_down;

            char json[96];
            int n = snprintf(json, sizeof(json),
                "{\"up\":%llu,\"down\":%llu}",
                (unsigned long long)d_up,
                (unsigned long long)d_down);

            if (n > 0 && (size_t)n < sizeof(json)) {
                for (int i = 0; i < HTTP_MAX_CONN; i++) {
                    HttpConn *c = &srv->conns[i];
                    if (c->fd < 0 || !c->is_websocket) continue;
                    if (c->ws_route != WS_ROUTE_TRAFFIC) continue;

                    if (ws_send_text(c, epoll_fd, json, (size_t)n) < 0) {
                        conn_close(c, epoll_fd);
                    }
                }
            }
        }
    }

    /* ─── /connections stream (snapshot каждую секунду) ─── */
    {
        int has_subs = 0;
        for (int i = 0; i < HTTP_MAX_CONN; i++) {
            HttpConn *c = &srv->conns[i];
            if (c->fd >= 0 && c->is_websocket &&
                c->ws_route == WS_ROUTE_CONNECTIONS) {
                has_subs = 1;
                break;
            }
        }

        if (has_subs) {
            char *json = build_connections_json();
            if (json) {
                size_t jlen = strlen(json);
                for (int i = 0; i < HTTP_MAX_CONN; i++) {
                    HttpConn *c = &srv->conns[i];
                    if (c->fd < 0 || !c->is_websocket) continue;
                    if (c->ws_route != WS_ROUTE_CONNECTIONS) continue;
                    if (ws_send_text(c, epoll_fd, json, jlen) < 0)
                        conn_close(c, epoll_fd);
                }
                free(json);
            }
        }
    }
}

/* ── http_server_close ────────────────────────────────────────────── */
void http_server_close(HttpServer *srv)
{
    for (int i = 0; i < HTTP_MAX_CONN; i++) {
        if (srv->conns[i].fd >= 0) {
            close(srv->conns[i].fd);
            srv->conns[i].fd = -1;
        }
    }

    if (srv->listen_fd >= 0) {
        close(srv->listen_fd);
        srv->listen_fd = -1;
    }
}

/* ── Экспортированные обёртки кэша ───────────────────────────────── */
void http_server_write_servers_cache(void) { write_servers_cache(); }
void http_server_write_dns_cache(void)     { write_dns_cache(); }

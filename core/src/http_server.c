#include "http_server.h"
#include "logo_png.h"
#include "4eburnet.h"
#include "config.h"
#include "net_utils.h"
#include "stats.h"
#include "routing/nftables.h"
#include "routing/tc_fast.h"
#if CONFIG_EBURNET_DPI
#include "dpi/dpi_adapt.h"
#endif
#include "proxy/dispatcher.h"

#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
static void http_dispatch(HttpConn *conn, int epoll_fd);
static void route_api_status(HttpConn *conn, int epoll_fd);
static void route_ipc_passthrough(HttpConn *conn, int epoll_fd, const char *cmd);
static void route_api_servers(HttpConn *conn, int epoll_fd);
static void route_api_dns(HttpConn *conn, int epoll_fd);
static void route_api_control(HttpConn *conn, int epoll_fd, const char *api_token);
static void route_api_geo(HttpConn *conn, int epoll_fd);
static void route_api_logs(HttpConn *conn, int epoll_fd);

/* ── Буферы для ответов — статические, не в стеке ────────────────── */
static char s_ipc_buf[4096];
static char s_logs_buf[8192];

/* ── Токен /api/control, инициализируется в http_server_init ─────── */
static char s_api_token[64];

/* ── Конфиг-указатель для toggle управления ──────────────────────── */
static const EburNetConfig *s_cfg = NULL;

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
static void conn_close(HttpConn *conn, int epoll_fd)
{
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    close(conn->fd);
    conn->fd = -1;
}

/* ── Записать все байты в fd, повторять при EINTR ────────────────── */
static int write_all(int fd, const void *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = write(fd, (const char *)buf + sent, n - sent);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        sent += (size_t)r;
    }
    return 0;
}

/* ── Отправить HTTP ответ: заголовок + тело, затем закрыть conn ───── */
static void http_send(HttpConn *conn, int epoll_fd,
                      int status, const char *ctype,
                      const void *body, size_t body_len)
{
    /* Переключить в блокирующий режим на время отправки ответа.
       Соединение закрывается сразу после — EAGAIN не страшен. */
    {
        int fl = fcntl(conn->fd, F_GETFL);
        if (fl != -1)
            fcntl(conn->fd, F_SETFL, fl & ~O_NONBLOCK);
    }

    const char *status_str;
    switch (status) {
        case 200: status_str = "OK";                    break;
        case 400: status_str = "Bad Request";           break;
        case 404: status_str = "Not Found";             break;
        case 405: status_str = "Method Not Allowed";    break;
        default:  status_str = "Internal Server Error"; break;
    }

    /* Собрать заголовок в стековом буфере */
    char hdr[256];
    int  hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.0 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: http://localhost\r\n"
        "\r\n",
        status, status_str, ctype, body_len);

    if (hdr_len > 0 && hdr_len < (int)sizeof(hdr))
        if (write_all(conn->fd, hdr, (size_t)hdr_len) < 0)
            log_msg(LOG_DEBUG, "HTTP: обрыв при отправке заголовка");

    if (body && body_len > 0)
        if (write_all(conn->fd, body, body_len) < 0)
            log_msg(LOG_DEBUG, "HTTP: обрыв при отправке тела");

    conn_close(conn, epoll_fd);
}

/* ── Отдать файл с диска как HTTP ответ ──────────────────────────── */
static void http_send_file(HttpConn *conn, int epoll_fd,
                           int status, const char *ctype,
                           const char *filepath)
{
    /* Переключить в блокирующий режим — chunk-отправка файла безопасна */
    {
        int fl = fcntl(conn->fd, F_GETFL);
        if (fl != -1)
            fcntl(conn->fd, F_SETFL, fl & ~O_NONBLOCK);
    }

    FILE *f = fopen(filepath, "rb");
    if (!f) {
        const char body404[] = "Not Found";
        http_send(conn, epoll_fd, 404, "text/plain",
                  body404, sizeof(body404) - 1);
        return;
    }

    /* Получить размер файла */
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < 0) fsize = 0;

    /* Отправить заголовок */
    const char *status_str = (status == 200) ? "OK" : "Not Modified";
    char hdr[256];
    int  hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.0 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: http://localhost\r\n"
        "\r\n",
        status, status_str, ctype, fsize);

    if (hdr_len > 0 && hdr_len < (int)sizeof(hdr))
        if (write_all(conn->fd, hdr, (size_t)hdr_len) < 0)
            log_msg(LOG_DEBUG, "HTTP: обрыв при отправке заголовка файла");

    /* static: single-threaded epoll, экономим стек MIPS */
    static char chunk[2048];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        if (write_all(conn->fd, chunk, n) < 0)
            break;
    }

    fclose(f);
    conn_close(conn, epoll_fd);
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
            if (mem_kb > 131072) profile = "FULL";
            else if (mem_kb < 65536) profile = "MICRO";
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
    int n = snprintf(s_ipc_buf, sizeof(s_ipc_buf),
        "{\"status\":\"%s\",\"version\":\"1.0.0\","
        "\"uptime\":%ld,\"mode\":\"%s\",\"profile\":\"%s\","
        "\"last_ja3\":\"%s\",\"ja3_expected\":\"%s\",\"ja3_match\":%s,"
        "\"flow_offload\":%s,\"tc_fast\":%s,"
        "\"dpi_enabled\":%s,"
        "\"dpi_adapt_count\":%u,\"dpi_adapt_hits\":%u,"
        "\"conn_active\":%llu,\"conn_total\":%llu,"
        "\"dns_queries\":%llu,\"dns_cached\":%llu,"
        "\"blocked_ads\":%llu,\"blocked_trackers\":%llu,\"blocked_threats\":%llu}",
        running ? "running" : "stopped",
        uptime, mode, profile,
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
        (unsigned long long)atomic_load(&g_stats.blocked_threats));

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

/* ── /api/servers — список серверов из UCI ───────────────────────── */
static void route_api_servers(HttpConn *conn, int epoll_fd)
{
    static char s_srv_buf[8192];
    int pos = 0;
    int max = (int)sizeof(s_srv_buf);

    FILE *f = popen("uci -q show 4eburnet 2>/dev/null", "r");
    if (!f) {
        const char err[] = "{\"error\":\"uci failed\"}";
        http_send(conn, epoll_fd, 500, "application/json",
                  err, sizeof(err) - 1);
        return;
    }

    char sec_name[64]   = {0};
    char fld_name[64]   = {0};
    char fld_type[32]   = {0};
    char fld_host[128]  = {0};
    char fld_port[8]    = {0};
    char fld_uuid[128]  = {0};
    char fld_pass[128]  = {0};
    char fld_tport[32]  = {0};
    char fld_tls[16]    = {0};
    char fld_sni[128]   = {0};
    char fld_fp[32]     = {0};
    char fld_pbk[128]   = {0};
    char fld_sid[64]    = {0};
    char fld_pubkey[64] = {0};
    int  fld_privkey    = 0;   /* флаг: 1 = ключ задан */
    char fld_mtu[8]     = {0};
    char fld_adns[64]   = {0};
    char fld_rsrv[64]   = {0};
    int  in_server_sec  = 0;

    s_srv_buf[pos++] = '[';
    int first = 1;
    char line[320];

    while (fgets(line, sizeof(line), f)) {
        size_t ll = strlen(line);
        if (ll > 0 && line[ll - 1] == '\n') line[--ll] = '\0';

        /* Строка вида: 4eburnet.SECNAME=TYPE (без точки в имени секции) */
        char sn[64], stype[32];
        if (sscanf(line, "4eburnet.%63[^.=]=%31s", sn, stype) == 2) {
            /* Записать предыдущую секцию server если была */
            if (in_server_sec && fld_name[0]) {
                if (!first && pos + 1 < max) s_srv_buf[pos++] = ',';
                first = 0;
                pos = serialize_server(s_srv_buf, pos, max,
                    fld_name, fld_type, fld_host, fld_port,
                    fld_uuid, fld_pass, fld_tport, fld_tls,
                    fld_sni, fld_fp, fld_pbk, fld_sid,
                    fld_pubkey, fld_privkey,
                    fld_mtu, fld_adns, fld_rsrv);
            }
            strncpy(sec_name, sn, sizeof(sec_name) - 1);
            in_server_sec = (strcmp(stype, "server") == 0);
            /* Сброс полей для новой секции */
            fld_name[0]   = fld_type[0]   = fld_host[0]   = fld_port[0] = '\0';
            fld_uuid[0]   = fld_pass[0]   = fld_tport[0]  = fld_tls[0]  = '\0';
            fld_sni[0]    = fld_fp[0]     = fld_pbk[0]    = fld_sid[0]  = '\0';
            fld_pubkey[0] = fld_mtu[0]    = fld_adns[0]   = fld_rsrv[0] = '\0';
            fld_privkey   = 0;
            continue;
        }

        if (!in_server_sec) continue;

        /* Строка вида: 4eburnet.SECNAME.FIELD='VALUE' */
        char fn[48], fv[200];
        if (sscanf(line, "4eburnet.%*[^.].%47[^=]='%199[^']'",
                   fn, fv) == 2) {
            if      (strcmp(fn, "name")           == 0)
                strncpy(fld_name,   fv, sizeof(fld_name)   - 1);
            else if (strcmp(fn, "type")           == 0)
                strncpy(fld_type,   fv, sizeof(fld_type)   - 1);
            else if (strcmp(fn, "server")         == 0)
                strncpy(fld_host,   fv, sizeof(fld_host)   - 1);
            else if (strcmp(fn, "port")           == 0)
                strncpy(fld_port,   fv, sizeof(fld_port)   - 1);
            else if (strcmp(fn, "uuid")           == 0)
                strncpy(fld_uuid,   fv, sizeof(fld_uuid)   - 1);
            else if (strcmp(fn, "password")       == 0)
                strncpy(fld_pass,   fv, sizeof(fld_pass)   - 1);
            else if (strcmp(fn, "transport")      == 0)
                strncpy(fld_tport,  fv, sizeof(fld_tport)  - 1);
            else if (strcmp(fn, "tls")            == 0)
                strncpy(fld_tls,    fv, sizeof(fld_tls)    - 1);
            else if (strcmp(fn, "sni")            == 0)
                strncpy(fld_sni,    fv, sizeof(fld_sni)    - 1);
            else if (strcmp(fn, "fingerprint")    == 0)
                strncpy(fld_fp,     fv, sizeof(fld_fp)     - 1);
            else if (strcmp(fn, "reality_pbk")    == 0)
                strncpy(fld_pbk,    fv, sizeof(fld_pbk)    - 1);
            else if (strcmp(fn, "reality_sid")    == 0)
                strncpy(fld_sid,    fv, sizeof(fld_sid)    - 1);
            else if (strcmp(fn, "awg_public_key") == 0)
                strncpy(fld_pubkey, fv, sizeof(fld_pubkey) - 1);
            else if (strcmp(fn, "awg_private_key") == 0)
                fld_privkey = (fv[0] != '\0') ? 1 : 0;
            else if (strcmp(fn, "awg_mtu")        == 0)
                strncpy(fld_mtu,    fv, sizeof(fld_mtu)    - 1);
            else if (strcmp(fn, "awg_dns")        == 0)
                strncpy(fld_adns,   fv, sizeof(fld_adns)   - 1);
            else if (strcmp(fn, "awg_reserved")   == 0)
                strncpy(fld_rsrv,   fv, sizeof(fld_rsrv)   - 1);
        }
    }
    pclose(f);

    /* Записать последнюю секцию */
    if (in_server_sec && fld_name[0]) {
        if (!first && pos + 1 < max) s_srv_buf[pos++] = ',';
        pos = serialize_server(s_srv_buf, pos, max,
            fld_name, fld_type, fld_host, fld_port,
            fld_uuid, fld_pass, fld_tport, fld_tls,
            fld_sni, fld_fp, fld_pbk, fld_sid,
            fld_pubkey, fld_privkey,
            fld_mtu, fld_adns, fld_rsrv);
    }

    if (pos + 2 < max) s_srv_buf[pos++] = ']';
    s_srv_buf[pos] = '\0';
    (void)sec_name;

    http_send(conn, epoll_fd, 200, "application/json",
              s_srv_buf, (size_t)pos);
}

/* ── /api/dns — DNS настройки из UCI секции 'dns' ────────────────── */
static void route_api_dns(HttpConn *conn, int epoll_fd)
{
    static char s_dns_buf[2048];
    int pos = 0;
    int max = (int)sizeof(s_dns_buf);

    FILE *f = popen("uci -q show 4eburnet.dns 2>/dev/null", "r");
    if (!f) {
        const char err[] = "{\"error\":\"uci failed\"}";
        http_send(conn, epoll_fd, 500, "application/json",
                  err, sizeof(err) - 1);
        return;
    }

    s_dns_buf[pos++] = '{';
    int first = 1;
    char line[256];

    while (fgets(line, sizeof(line), f)) {
        size_t ll = strlen(line);
        if (ll > 0 && line[ll - 1] == '\n') line[--ll] = '\0';

        /* Строка: 4eburnet.dns.FIELD='VALUE' */
        char fn[64], fv[128];
        if (sscanf(line, "4eburnet.dns.%63[^=]='%127[^']'",
                   fn, fv) != 2)
            continue;

        /* Пропустить служебные поля UCI */
        if (fn[0] == '.' || strcmp(fn, "option") == 0)
            continue;

        if (!first && pos + 4 < max) s_dns_buf[pos++] = ',';
        first = 0;

        pos = json_append_str(s_dns_buf, pos, max, fn);
        if (pos + 2 < max) s_dns_buf[pos++] = ':';
        pos = json_append_str(s_dns_buf, pos, max, fv);
    }
    pclose(f);

    if (pos + 2 < max) s_dns_buf[pos++] = '}';
    s_dns_buf[pos] = '\0';

    http_send(conn, epoll_fd, 200, "application/json",
              s_dns_buf, (size_t)pos);
}

/* ── http_dispatch — маршрутизация запросов ──────────────────────── */
/* Глобальный rate limit: не более 1 запроса в 200мс с любого клиента.
 * Сервер слушает только на loopback — все запросы от LuCI, один клиент. */
#define HTTP_RATE_MS  200

static void http_dispatch(HttpConn *conn, int epoll_fd)
{
    {
        struct timespec _ts;
        clock_gettime(CLOCK_MONOTONIC, &_ts);
        static long s_last_req_ms = 0;
        long now_ms = (long)(_ts.tv_sec * 1000 + _ts.tv_nsec / 1000000);
        if (s_last_req_ms && (now_ms - s_last_req_ms) < HTTP_RATE_MS) {
            http_send(conn, epoll_fd, 429, "application/json",
                      "{\"error\":\"rate limit\"}", 21);
            return;
        }
        s_last_req_ms = now_ms;
    }

    /* Метод не GET → 405 */
    if (!conn->method_ok) {
        const char body[] = "Method Not Allowed";
        http_send(conn, epoll_fd, 405, "text/plain",
                  body, sizeof(body) - 1);
        return;
    }

    const char *p = conn->path;

    /* GET / или GET /index.html → dashboard.html с диска */
    if (strcmp(p, "/") == 0 || strcmp(p, "/index.html") == 0) {
        http_send_file(conn, epoll_fd, 200, "text/html; charset=utf-8",
                       "/usr/share/4eburnet/dashboard.html");
        return;
    }

    /* GET /logo.png → embedded PNG массив */
    if (strcmp(p, "/logo.png") == 0) {
        http_send(conn, epoll_fd, 200, "image/png",
                  logo_png_data, (size_t)logo_png_size);
        return;
    }

    /* GET /api/status → JSON из --ipc status */
    if (strcmp(p, "/api/status") == 0) {
        route_api_status(conn, epoll_fd);
        return;
    }

    /* GET /api/groups → --ipc groups */
    if (strcmp(p, "/api/groups") == 0) {
        route_ipc_passthrough(conn, epoll_fd, "groups");
        return;
    }

    /* GET /api/stats → --ipc stats */
    if (strcmp(p, "/api/stats") == 0) {
        route_ipc_passthrough(conn, epoll_fd, "stats");
        return;
    }

    /* GET /api/servers → UCI парсинг */
    if (strcmp(p, "/api/servers") == 0) {
        route_api_servers(conn, epoll_fd);
        return;
    }

    /* GET /api/dns → UCI dns секция */
    if (strcmp(p, "/api/dns") == 0) {
        route_api_dns(conn, epoll_fd);
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

    /* GET /api/logs → лог-файл */
    if (strncmp(p, "/api/logs", 9) == 0 && !conn->is_post) {
        route_api_logs(conn, epoll_fd);
        return;
    }

    /* Всё остальное → 404 */
    const char body404[] = "{\"error\":\"not found\"}";
    http_send(conn, epoll_fd, 404, "application/json",
              body404, sizeof(body404) - 1);
}

/* ── POST /api/control — управление демоном ──────────────────────── */
/* Принимает {"action":"start|stop|reload"}, выполняет через init.d.
   system() вызывается с & — не блокирует epoll-цикл демона.          */
static void route_api_control(HttpConn *conn, int epoll_fd, const char *api_token)
{
    /* Если токен задан — требовать Authorization: Bearer <token> */
    if (api_token[0] != '\0') {
        bool auth_ok = false;
        const char *auth = strstr(conn->buf, "Authorization: Bearer ");
        if (!auth) auth = strstr(conn->buf, "authorization: bearer ");
        if (auth) {
            auth += strlen("Authorization: Bearer ");
            size_t tlen = strlen(api_token);
            auth_ok = (strncmp(auth, api_token, tlen) == 0 &&
                       (auth[tlen] == '\r' || auth[tlen] == '\n' ||
                        auth[tlen] == '\0'));
        }
        if (!auth_ok) {
            const char err[] = "{\"ok\":false,\"error\":\"unauthorized\"}";
            http_send(conn, epoll_fd, 401, "application/json",
                      err, sizeof(err) - 1);
            return;
        }
    } else {
        const char err[] = "{\"ok\":false,\"error\":\"api_token not configured\"}";
        http_send(conn, epoll_fd, 403, "application/json",
                  err, sizeof(err) - 1);
        return;
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
        system("/etc/init.d/4eburnet start >/dev/null 2>&1 &");
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "stop", 4) == 0) {
        system("/etc/init.d/4eburnet stop >/dev/null 2>&1 &");
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
                system("/etc/init.d/4eburnet reload >/dev/null 2>&1 &");
            fclose(pf);
        } else {
            system("/etc/init.d/4eburnet reload >/dev/null 2>&1 &");
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
        nft_flow_offload_enable();
        log_msg(LOG_INFO, "flow offload: включён из dashboard");
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "flow_offload_off", 16) == 0) {
        nft_flow_offload_disable();
        log_msg(LOG_INFO, "flow offload: выключен из dashboard");
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "tc_fast_on", 10) == 0) {
        if (s_cfg) {
            const char *iface = s_cfg->lan_interface[0]
                                ? s_cfg->lan_interface : "br-lan";
            tc_fast_enable(iface, s_cfg->lan_prefix, s_cfg->lan_mask);
        }
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "tc_fast_off", 11) == 0) {
        const char *iface = (s_cfg && s_cfg->lan_interface[0])
                            ? s_cfg->lan_interface : "br-lan";
        tc_fast_disable(iface);
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "dpi_on", 6) == 0) {
        /* uci commit синхронный — SIGHUP только после завершения */
        system("uci set 4eburnet.main.dpi_enabled=1;"
               "uci commit 4eburnet >/dev/null 2>&1");
        FILE *pf = fopen("/var/run/4eburnet.pid", "r");
        if (pf) {
            int _pid = 0;
            if (fscanf(pf, "%d", &_pid) == 1 && _pid > 0) kill(_pid, SIGHUP);
            fclose(pf);
        }
        http_send(conn, epoll_fd, 200, "application/json",
                  ok_resp, strlen(ok_resp));
    } else if (strncmp(val, "dpi_off", 7) == 0) {
        system("uci set 4eburnet.main.dpi_enabled=0;"
               "uci commit 4eburnet >/dev/null 2>&1");
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
    } else {
        http_send(conn, epoll_fd, 400, "application/json",
                  err_resp, strlen(err_resp));
    }
}

/* ── GET /api/geo — список .gbin файлов с размерами и bloom статусом ── */
static void route_api_geo(HttpConn *conn, int epoll_fd)
{
    const char *geo_dir = "/etc/4eburnet/geo";
    if (s_cfg && s_cfg->geo_dir[0]) geo_dir = s_cfg->geo_dir;

    int pos = 0;
    int cap = (int)sizeof(s_ipc_buf);
    pos += snprintf(s_ipc_buf + pos, (size_t)(cap - pos), "{\"files\":[");

    DIR *d = opendir(geo_dir);
    bool first = true;
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL && pos < cap - 128) {
            /* Только .gbin файлы */
            size_t nlen = strlen(e->d_name);
            if (nlen < 6 || strcmp(e->d_name + nlen - 5, ".gbin") != 0) continue;

            static char fullpath[256];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", geo_dir, e->d_name);
            static struct stat st;
            if (stat(fullpath, &st) != 0) continue;

            /* Имя без расширения */
            static char name[64];
            int namelen = (int)nlen - 5;
            if (namelen > (int)sizeof(name) - 1) namelen = (int)sizeof(name) - 1;
            memcpy(name, e->d_name, (size_t)namelen);
            name[namelen] = '\0';

            /* Есть ли .bloom файл? */
            static char bloom_path[256];
            snprintf(bloom_path, sizeof(bloom_path), "%s/%.*s.bloom",
                     geo_dir, namelen, e->d_name);
            bool has_bloom = (access(bloom_path, F_OK) == 0);

            pos += snprintf(s_ipc_buf + pos, (size_t)(cap - pos),
                            "%s{\"name\":\"%s\",\"size_kb\":%ld,\"bloom\":%s}",
                            first ? "" : ",", name,
                            (long)(st.st_size / 1024),
                            has_bloom ? "true" : "false");
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
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),  /* 127.0.0.1 — только локально */
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

    return 0;
}

/* ── http_server_register_epoll ──────────────────────────────────── */
void http_server_register_epoll(HttpServer *srv, int epoll_fd)
{
    struct epoll_event ev;

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
int http_server_handle(HttpServer *srv, int fd, int epoll_fd)
{
    /* ── Новое входящее соединение ──────────────────────────────── */
    if (fd == srv->listen_fd) {
        int new_fd = accept4(fd, NULL, NULL,
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
        slot->connected_at   = time(NULL);
        slot->buf_len        = 0;
        slot->headers_done   = 0;
        slot->method_ok      = 0;
        slot->is_post        = 0;
        slot->content_length = 0;
        slot->path[0]        = '/';
        slot->path[1]        = '\0';

        struct epoll_event ev;
        ev.events  = EPOLLIN | EPOLLRDHUP | EPOLLET;
        ev.data.fd = new_fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &ev);

        return 0;
    }

    /* ── Данные от клиента ───────────────────────────────────────── */
    for (int i = 0; i < HTTP_MAX_CONN; i++) {
        HttpConn *conn = &srv->conns[i];
        if (conn->fd != fd)
            continue;

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
                conn->content_length = (cl_val > 0 && cl_val <= HTTP_MAX_BODY)
                                       ? (int)cl_val : 0;
            } else {
                conn->content_length = 0;
            }

        } else {
            conn->method_ok = 0;
            conn->path[0]   = '\0';
        }

        /* POST: дождаться полного тела (content_length байт после \r\n\r\n) */
        if (conn->is_post && conn->content_length > 0) {
            const char *hdr_end = strstr(conn->buf, "\r\n\r\n");
            if (hdr_end) {
                int body_recv = conn->buf_len - (int)(hdr_end + 4 - conn->buf);
                if (body_recv < conn->content_length) {
                    /* Тело ещё не полностью получено — ждём следующего read */
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
        if (srv->conns[i].fd < 0)
            continue;
        if (now - srv->conns[i].connected_at > HTTP_TIMEOUT_SEC)
            conn_close(&srv->conns[i], epoll_fd);
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

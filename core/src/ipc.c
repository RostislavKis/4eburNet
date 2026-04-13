#include "ipc.h"
#include "config.h"
#include "constants.h"
#include "stats.h"
#include "net_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>

/* Размер буфера для ответов */
#define IPC_RESPONSE_MAX 2048

/* Таймаут блокирующего чтения payload (мс) */
#define IPC_RECV_TIMEOUT_MS 500

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

/* Прочитать ровно n байт с таймаутом IPC_RECV_TIMEOUT_MS.
 * Возвращает количество прочитанных байт или -1 при ошибке/таймауте. */
static ssize_t ipc_recv_payload(int fd, char *buf, size_t n)
{
    if (n == 0) return 0;

    /* Установить receive timeout */
    struct timeval tv = {
        .tv_sec  = IPC_RECV_TIMEOUT_MS / 1000,
        .tv_usec = (IPC_RECV_TIMEOUT_MS % 1000) * 1000,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        log_msg(LOG_WARN, "ipc: SO_RCVTIMEO: %s", strerror(errno));

    size_t received = 0;
    while (received < n) {
        ssize_t r = recv(fd, buf + received, n - received, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            /* EAGAIN/EWOULDBLOCK = таймаут SO_RCVTIMEO */
            log_msg(LOG_WARN, "IPC: таймаут при чтении payload (%zu/%zu)",
                    received, n);
            return -1;
        }
        if (r == 0) return -1;  /* соединение закрыто */
        received += (size_t)r;
    }
    return (ssize_t)received;
}

/* Отправка строки в подключённый сокет */
static void ipc_respond(int client_fd, const char *json)
{
    size_t resp_len = strlen(json);
    if (resp_len > UINT16_MAX) {
        log_msg(LOG_WARN, "IPC: ответ обрезан %zu → %d", resp_len, UINT16_MAX);
        resp_len = UINT16_MAX;
    }
    ipc_header_t resp = {
        .version    = EBURNET_IPC_VERSION,
        .command    = 0,
        .length     = (uint16_t)resp_len,
        .request_id = 0,
    };

    /* Отправляем заголовок, затем тело */
    if (write(client_fd, &resp, sizeof(resp)) < 0)
        return;
    if (write(client_fd, json, resp.length) < 0)
        return;
}

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
 * ipc_process — обработчик всех IPC команд в одной функции.
 * Единый switch минимизирует overhead диспетчеризации.
 * Каждая команда независима — таблица handler-указателей не оправдана.
 */
void ipc_process(int server_fd, EburNetState *state)
{
    /* Неблокирующий accept + client_fd (H-02) */
    int client_fd = accept4(server_fd, NULL, NULL,
                            SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (client_fd < 0)
        return;

    /* Только root может управлять демоном через IPC */
    struct ucred cred = {0};
    socklen_t cred_len = sizeof(cred);
    /* Fail-secure: если PEERCRED недоступен — отклоняем */
    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED,
                   &cred, &cred_len) != 0) {
        log_msg(LOG_WARN,
            "IPC: SO_PEERCRED недоступен, соединение отклонено");
        close(client_fd);
        return;
    }
    if (cred.uid != 0) {
        log_msg(LOG_WARN,
            "IPC: отклонён non-root клиент (uid=%u)",
            (unsigned)cred.uid);
        close(client_fd);
        return;
    }

    /* Читаем заголовок команды (MSG_DONTWAIT — не блокируем) (H-10) */
    ipc_header_t hdr;
    ssize_t n = recv(client_fd, &hdr, sizeof(hdr), MSG_DONTWAIT);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        /* Данные ещё не прибыли — не ошибка */
        close(client_fd);
        return;
    }
    if (n != (ssize_t)sizeof(hdr)) {
        log_msg(LOG_WARN, "IPC: неполный заголовок (%zd байт)", n);
        close(client_fd);
        return;
    }

    /* Проверка длины payload (H-10) */
    if (hdr.length > IPC_RESPONSE_MAX) {
        log_msg(LOG_WARN, "IPC: payload слишком большой (%u байт)", hdr.length);
        close(client_fd);
        return;
    }

    /* Проверка версии протокола */
    if (hdr.version != EBURNET_IPC_VERSION) {
        log_msg(LOG_WARN, "IPC: неизвестная версия протокола %u", hdr.version);
        ipc_respond(client_fd, "{\"error\":\"version mismatch\"}");
        close(client_fd);
        return;
    }

    /* M-03: heap вместо 2048B на MIPS стеке */
    char *buf = malloc(IPC_RESPONSE_MAX);
    if (!buf) {
        ipc_respond(client_fd, "{\"error\":\"OOM\"}");
        close(client_fd);
        return;
    }

    switch ((ipc_command_t)hdr.command) {
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
        snprintf(buf, IPC_RESPONSE_MAX,
                 "{\"status\":\"running\",\"version\":\"%s\","
                 "\"profile\":\"%s\",\"uptime\":%ld,"
                 "\"mode\":\"%s\",\"geo_loaded\":%s}",
                 EBURNET_VERSION, profile, (long)uptime,
                 mode, geo_ok ? "true" : "false");
        ipc_respond(client_fd, buf);
        break;
    }

    case IPC_CMD_RELOAD:
        state->reload = true;
        ipc_respond(client_fd, "{\"status\":\"ok\"}");
        log_msg(LOG_INFO, "IPC: запрошена перезагрузка конфига");
        break;

    case IPC_CMD_STOP:
        state->running = false;
        ipc_respond(client_fd, "{\"status\":\"stopping\"}");
        log_msg(LOG_INFO, "IPC: запрошена остановка");
        break;

    case IPC_CMD_STATS:
        snprintf(buf, IPC_RESPONSE_MAX,
                 "{\"connections_total\":%llu"
                 ",\"connections_active\":%llu"
                 ",\"dns_queries\":%llu"
                 ",\"dns_cached\":%llu}",
                 (unsigned long long)atomic_load(&g_stats.connections_total),
                 (unsigned long long)atomic_load(&g_stats.connections_active),
                 (unsigned long long)atomic_load(&g_stats.dns_queries_total),
                 (unsigned long long)atomic_load(&g_stats.dns_cached_total));
        ipc_respond(client_fd, buf);
        break;

    case IPC_CMD_GROUP_LIST:
        if (g_pgm) {
            /* Динамический буфер: ~200 на группу + ~80 на сервер */
            size_t gl_need = 64;
            for (int gi = 0; gi < g_pgm->count; gi++)
                gl_need += 200 + (size_t)g_pgm->groups[gi].server_count * 80;
            char *gbuf = malloc(gl_need);
            if (!gbuf) {
                ipc_respond(client_fd, "{\"error\":\"OOM\"}");
                break;
            }
            proxy_group_to_json(g_pgm, gbuf, gl_need);
            ipc_respond(client_fd, gbuf);
            free(gbuf);
        } else {
            ipc_respond(client_fd, "{\"groups\":[]}");
        }
        break;

    case IPC_CMD_GROUP_SELECT: {
        /* M-04: payload на heap (было 2049B на стеке) */
        char *payload = calloc(1, IPC_RESPONSE_MAX + 1);
        if (!payload) { ipc_respond(client_fd, "{\"error\":\"OOM\"}"); break; }
        if (hdr.length > 0) {
            ssize_t pr = ipc_recv_payload(client_fd, payload, hdr.length);
            if (pr < 0) {
                ipc_respond(client_fd,
                    "{\"status\":\"error\",\"msg\":\"payload read failed\"}");
                free(payload);
                break;
            }
            payload[pr] = '\0';
        }
        char grp[64] = {0}, srv[64] = {0};
        json_get_str(payload, "group",  grp, sizeof(grp));
        json_get_str(payload, "server", srv, sizeof(srv));
        free(payload);
        if (grp[0] && srv[0] && g_pgm) {
            /* Найти server_idx по имени сервера в cfg->servers[] */
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
            if (r == 0)
                ipc_respond(client_fd, "{\"status\":\"ok\"}");
            else
                ipc_respond(client_fd,
                    "{\"status\":\"error\",\"msg\":\"group or server not found\"}");
        } else if (!g_pgm) {
            ipc_respond(client_fd,
                "{\"status\":\"error\",\"msg\":\"no groups\"}");
        } else {
            ipc_respond(client_fd,
                "{\"status\":\"error\",\"msg\":\"missing group or server\"}");
        }
        break;
    }

    case IPC_CMD_GROUP_TEST:
        if (g_pgm) {
            proxy_group_tick(g_pgm);
            ipc_respond(client_fd, "{\"status\":\"ok\"}");
        } else {
            ipc_respond(client_fd, "{\"error\":\"no groups\"}");
        }
        break;

    case IPC_CMD_PROVIDER_LIST:
        if (g_rpm) {
            rule_provider_to_json(g_rpm, buf, IPC_RESPONSE_MAX);
            ipc_respond(client_fd, buf);
        } else {
            ipc_respond(client_fd, "{\"providers\":[]}");
        }
        break;

    case IPC_CMD_PROVIDER_UPDATE: {
        /* M-04: payload на heap */
        char *payload = calloc(1, IPC_RESPONSE_MAX + 1);
        if (!payload) { ipc_respond(client_fd, "{\"error\":\"OOM\"}"); break; }
        if (hdr.length > 0) {
            ssize_t pr = ipc_recv_payload(client_fd, payload, hdr.length);
            if (pr < 0) {
                ipc_respond(client_fd,
                    "{\"status\":\"error\",\"msg\":\"payload read failed\"}");
                free(payload);
                break;
            }
            payload[pr] = '\0';
        }
        char pname[64] = {0};
        json_get_str(payload, "name", pname, sizeof(pname));
        free(payload);
        if (pname[0] && g_rpm) {
            int r = rule_provider_update(g_rpm, pname);
            if (r == 0)
                ipc_respond(client_fd, "{\"status\":\"ok\"}");
            else
                ipc_respond(client_fd,
                    "{\"status\":\"error\",\"msg\":\"provider not found\"}");
        } else if (!g_rpm) {
            ipc_respond(client_fd,
                "{\"status\":\"error\",\"msg\":\"no providers\"}");
        } else {
            ipc_respond(client_fd,
                "{\"status\":\"error\",\"msg\":\"missing name\"}");
        }
        break;
    }

    case IPC_CMD_RULES_LIST:
        if (g_re && g_re->sorted_rules) {
            /* ~200 байт на правило + запас */
            size_t need = (size_t)g_re->rule_count * 200 + 64;
            if (need < 256) need = 256;
            char *rbuf = malloc(need);
            if (!rbuf) {
                ipc_respond(client_fd, "{\"error\":\"OOM\"}");
                break;
            }
            size_t pos = 0;
            int w;
#define IPC_SNPRINTF(fmt, ...) do { \
    w = snprintf(rbuf + pos, need - pos, fmt, ##__VA_ARGS__); \
    if (w < 0 || (size_t)w >= need - pos) goto rules_trunc; \
    pos += (size_t)w; \
} while(0)
            IPC_SNPRINTF("{\"rules\":[");
            for (int ri = 0; ri < g_re->rule_count; ri++) {
                const TrafficRule *tr = &g_re->sorted_rules[ri];
                char esc_val[512], esc_tgt[128];
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
            /* B6-01: при truncation — валидный JSON вместо обрезанного */
            log_msg(LOG_WARN, "ipc: rules list truncated");
            snprintf(rbuf, need,
                "{\"rules\":[],\"truncated\":true}");
rules_send:
#undef IPC_SNPRINTF
            if (pos > 0 && pos < need) rbuf[pos] = '\0';
            ipc_respond(client_fd, rbuf);
            free(rbuf);
        } else {
            ipc_respond(client_fd, "{\"rules\":[]}");
        }
        break;

    case IPC_CMD_GEO_STATUS:
        if (g_gm) {
            size_t p = 0;
            p += (size_t)snprintf(buf + p, IPC_RESPONSE_MAX - p,
                "{\"region\":\"%s\",\"categories\":[",
                geo_region_name(g_gm->current_region));
            /* B6-02: резерв 4 байта под "]}\0" — гарантия валидного JSON */
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
            /* Всегда закрыть JSON — место зарезервировано */
            if (p >= IPC_RESPONSE_MAX - geo_reserve)
                p = IPC_RESPONSE_MAX - geo_reserve;
            p += (size_t)snprintf(buf + p, IPC_RESPONSE_MAX - p, "]}");
            ipc_respond(client_fd, buf);
        } else {
            ipc_respond(client_fd, "{\"region\":\"UNKNOWN\",\"categories\":[]}");
        }
        break;

#if CONFIG_EBURNET_DPI
    case IPC_CMD_CDN_UPDATE:
        state->cdn_update_requested = true;
        ipc_respond(client_fd,
            "{\"status\":\"ok\",\"msg\":\"cdn update scheduled\"}");
        log_msg(LOG_INFO, "IPC: запрошено обновление CDN IP");
        break;

    case IPC_CMD_DPI_GET: {
        /* P6-01: вернуть текущие DPI настройки */
        const EburNetConfig *c = state->config;
        char esc_sni[512];
        json_escape_str(c->dpi_fake_sni, esc_sni, sizeof(esc_sni));
        snprintf(buf, IPC_RESPONSE_MAX,
            "{\"enabled\":%s,\"split_pos\":%d,\"fake_ttl\":%d,"
            "\"fake_count\":%d,\"fake_sni\":\"%s\"}",
            c->dpi_enabled ? "true" : "false",
            c->dpi_split_pos, c->dpi_fake_ttl,
            c->dpi_fake_repeats, esc_sni);
        ipc_respond(client_fd, buf);
        break;
    }

    case IPC_CMD_DPI_SET:
        /* DPI настройки меняются через UCI + reload — здесь только подтверждение */
        state->reload = true;
        ipc_respond(client_fd, "{\"status\":\"ok\",\"msg\":\"reload scheduled\"}");
        log_msg(LOG_INFO, "IPC: запрошено обновление DPI настроек (reload)");
        break;
#endif

    default:
        log_msg(LOG_WARN, "IPC: неизвестная команда %u", hdr.command);
        ipc_respond(client_fd, "{\"error\":\"unknown command\"}");
        break;
    }

    free(buf);
    close(client_fd);
}

void ipc_cleanup(int server_fd)
{
    if (server_fd >= 0) {
        close(server_fd);
        unlink(EBURNET_IPC_SOCKET);
        log_msg(LOG_INFO, "IPC сокет закрыт");
    }
}

int ipc_send_command(ipc_command_t cmd, char *buf, size_t buf_size)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    /* Таймаут 3с на connect/read/write — защита от зависшего демона */
    struct timeval tv = { .tv_sec = TIMEOUT_IPC_CLIENT_SEC, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        log_msg(LOG_WARN, "ipc client: SO_RCVTIMEO: %s", strerror(errno));
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        log_msg(LOG_WARN, "ipc client: SO_SNDTIMEO: %s", strerror(errno));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, EBURNET_IPC_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

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
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct timeval tv = { .tv_sec = TIMEOUT_IPC_CLIENT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, EBURNET_IPC_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }

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

#include "ipc.h"
#include "proxy/proxy_group.h"
#include "proxy/rule_provider.h"
#include "proxy/rules_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

/* Размер буфера для ответов */
#define IPC_RESPONSE_MAX 2048

/* Контекст для команд proxy_group/rule_provider/rules_engine */
static proxy_group_manager_t    *g_pgm = NULL;
static rule_provider_manager_t  *g_rpm = NULL;
static rules_engine_t           *g_re  = NULL;

void ipc_set_3x_context(void *pgm, void *rpm, void *re)
{
    g_pgm = pgm;
    g_rpm = rpm;
    g_re  = re;
}

/* Backlog для listen() — количество ожидающих подключений */
#define IPC_LISTEN_BACKLOG 8

/* Отправка строки в подключённый сокет */
static void ipc_respond(int client_fd, const char *json)
{
    size_t resp_len = strlen(json);
    if (resp_len > UINT16_MAX) {
        log_msg(LOG_WARN, "IPC: ответ обрезан %zu → %d", resp_len, UINT16_MAX);
        resp_len = UINT16_MAX;
    }
    ipc_header_t resp = {
        .version    = PHOENIX_IPC_VERSION,
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
    unlink(PHOENIX_IPC_SOCKET);

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_msg(LOG_ERROR, "Не удалось создать Unix-сокет");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, PHOENIX_IPC_SOCKET, sizeof(addr.sun_path) - 1);

    /* M-11: umask вместо chmod — избежать TOCTOU */
    mode_t old_umask = umask(0177);
    int bind_rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    umask(old_umask);

    if (bind_rc < 0) {
        log_msg(LOG_ERROR, "Не удалось привязать сокет: %s", PHOENIX_IPC_SOCKET);
        close(fd);
        return -1;
    }

    if (listen(fd, IPC_LISTEN_BACKLOG) < 0) {
        log_msg(LOG_ERROR, "listen() не удался");
        close(fd);
        unlink(PHOENIX_IPC_SOCKET);
        return -1;
    }

    /* Неблокирующий режим (M-18: проверка F_GETFL) */
    int flags = fcntl(fd, F_GETFL);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    log_msg(LOG_INFO, "IPC сокет создан: %s", PHOENIX_IPC_SOCKET);
    return fd;
}

void ipc_process(int server_fd, PhoenixState *state)
{
    /* Неблокирующий accept + client_fd (H-02) */
    int client_fd = accept4(server_fd, NULL, NULL,
                            SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (client_fd < 0)
        return;

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
    if (hdr.version != PHOENIX_IPC_VERSION) {
        log_msg(LOG_WARN, "IPC: неизвестная версия протокола %u", hdr.version);
        ipc_respond(client_fd, "{\"error\":\"version mismatch\"}");
        close(client_fd);
        return;
    }

    char buf[IPC_RESPONSE_MAX];

    switch ((ipc_command_t)hdr.command) {
    case IPC_CMD_STATUS: {
        time_t uptime = time(NULL) - state->start_time;
        const char *profile = "unknown";
        switch (state->profile) {
        case DEVICE_MICRO:  profile = "MICRO";  break;
        case DEVICE_NORMAL: profile = "NORMAL"; break;
        case DEVICE_FULL:   profile = "FULL";   break;
        }
        snprintf(buf, sizeof(buf),
                 "{\"status\":\"running\",\"profile\":\"%s\",\"uptime\":%ld}",
                 profile, (long)uptime);
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
        snprintf(buf, sizeof(buf),
                 "{\"connections\":%lu,\"bytes_in\":0,\"bytes_out\":0}",
                 (unsigned long)state->connections_total);
        ipc_respond(client_fd, buf);
        break;

    case IPC_CMD_GROUP_LIST:
        if (g_pgm) {
            proxy_group_to_json(g_pgm, buf, sizeof(buf));
            ipc_respond(client_fd, buf);
        } else {
            ipc_respond(client_fd, "{\"groups\":[]}");
        }
        break;

    case IPC_CMD_GROUP_SELECT:
        ipc_respond(client_fd, "{\"status\":\"not_implemented\"}");
        break;

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
            rule_provider_to_json(g_rpm, buf, sizeof(buf));
            ipc_respond(client_fd, buf);
        } else {
            ipc_respond(client_fd, "{\"providers\":[]}");
        }
        break;

    case IPC_CMD_PROVIDER_UPDATE:
        ipc_respond(client_fd, "{\"status\":\"not_implemented\"}");
        break;

    case IPC_CMD_RULES_LIST:
        if (g_re && g_re->sorted_rules) {
            int p = 0;
            p += snprintf(buf + p, sizeof(buf) - p, "{\"rules\":[");
            for (int ri = 0; ri < g_re->rule_count &&
                 p < (int)sizeof(buf) - 128; ri++) {
                const TrafficRule *tr = &g_re->sorted_rules[ri];
                if (ri > 0) p += snprintf(buf + p, sizeof(buf) - p, ",");
                p += snprintf(buf + p, sizeof(buf) - p,
                    "{\"type\":%d,\"value\":\"%s\",\"target\":\"%s\","
                    "\"priority\":%d}",
                    tr->type, tr->value, tr->target, tr->priority);
            }
            p += snprintf(buf + p, sizeof(buf) - p, "]}");
            ipc_respond(client_fd, buf);
        } else {
            ipc_respond(client_fd, "{\"rules\":[]}");
        }
        break;

    default:
        log_msg(LOG_WARN, "IPC: неизвестная команда %u", hdr.command);
        ipc_respond(client_fd, "{\"error\":\"unknown command\"}");
        break;
    }

    close(client_fd);
}

void ipc_cleanup(int server_fd)
{
    if (server_fd >= 0) {
        close(server_fd);
        unlink(PHOENIX_IPC_SOCKET);
        log_msg(LOG_INFO, "IPC сокет закрыт");
    }
}

int ipc_send_command(ipc_command_t cmd, char *buf, size_t buf_size)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, PHOENIX_IPC_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    /* Отправляем запрос */
    ipc_header_t hdr = {
        .version    = PHOENIX_IPC_VERSION,
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

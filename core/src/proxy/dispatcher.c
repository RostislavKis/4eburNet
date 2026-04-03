/*
 * Диспетчер прокси-соединений
 *
 * Принимает перехваченные соединения от tproxy,
 * логирует src → dst и закрывает.
 * Полная реализация (relay к upstream) — шаг 1.5.
 */

#include "proxy/dispatcher.h"
#include "phoenix.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

/* Форматирование адреса в строку */
static void fmt_addr(const struct sockaddr_storage *ss,
                     char *buf, size_t buflen)
{
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)ss;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof(ip));
        snprintf(buf, buflen, "%s:%u", ip, ntohs(s4->sin_port));
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ss;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof(ip));
        snprintf(buf, buflen, "[%s]:%u", ip, ntohs(s6->sin6_port));
    } else {
        snprintf(buf, buflen, "unknown");
    }
}

void dispatcher_handle_conn(tproxy_conn_t *conn)
{
    char src_str[64], dst_str[64];
    fmt_addr(&conn->src, src_str, sizeof(src_str));
    fmt_addr(&conn->dst, dst_str, sizeof(dst_str));

    log_msg(LOG_INFO, "TPROXY соединение: %s → %s", src_str, dst_str);

    /* Пока relay не написан — закрываем соединение */
    if (conn->fd >= 0)
        close(conn->fd);
}

void dispatcher_handle_udp(tproxy_conn_t *conn,
                           const uint8_t *data, size_t len)
{
    char src_str[64], dst_str[64];
    fmt_addr(&conn->src, src_str, sizeof(src_str));
    fmt_addr(&conn->dst, dst_str, sizeof(dst_str));

    log_msg(LOG_INFO, "TPROXY UDP: %s → %s (%zu байт)",
            src_str, dst_str, len);

    (void)data;
}

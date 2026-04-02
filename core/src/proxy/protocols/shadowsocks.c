/*
 * Обработчик протокола: shadowsocks
 *
 * TODO: подключение, рукопожатие и передача данных
 */

#include "proto_common.h"
#include <stdio.h>

static int shadowsocks_connect(const ProxyServer *server)
{
    /* TODO */
    return -1;
}

static int shadowsocks_handshake(int fd, const ProxyServer *server,
                              const char *host, uint16_t port)
{
    /* TODO */
    return -1;
}

static int shadowsocks_relay(int client_fd, int server_fd)
{
    /* TODO */
    return -1;
}

static void shadowsocks_cleanup(int fd)
{
    /* TODO */
}

ProtocolHandler shadowsocks_handler = {
    .type      = PROTO_SHADOWSOCKS,
    .name      = "shadowsocks",
    .connect   = shadowsocks_connect,
    .handshake = shadowsocks_handshake,
    .relay     = shadowsocks_relay,
    .cleanup   = shadowsocks_cleanup,
};

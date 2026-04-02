/*
 * Обработчик протокола: vless
 *
 * TODO: подключение, рукопожатие и передача данных
 */

#include "proto_common.h"
#include <stdio.h>

static int vless_connect(const ProxyServer *server)
{
    /* TODO */
    return -1;
}

static int vless_handshake(int fd, const ProxyServer *server,
                              const char *host, uint16_t port)
{
    /* TODO */
    return -1;
}

static int vless_relay(int client_fd, int server_fd)
{
    /* TODO */
    return -1;
}

static void vless_cleanup(int fd)
{
    /* TODO */
}

ProtocolHandler vless_handler = {
    .type      = PROTO_VLESS,
    .name      = "vless",
    .connect   = vless_connect,
    .handshake = vless_handshake,
    .relay     = vless_relay,
    .cleanup   = vless_cleanup,
};

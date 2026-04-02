/*
 * Обработчик протокола: trojan
 *
 * TODO: подключение, рукопожатие и передача данных
 */

#include "proto_common.h"
#include <stdio.h>

static int trojan_connect(const ProxyServer *server)
{
    /* TODO */
    return -1;
}

static int trojan_handshake(int fd, const ProxyServer *server,
                              const char *host, uint16_t port)
{
    /* TODO */
    return -1;
}

static int trojan_relay(int client_fd, int server_fd)
{
    /* TODO */
    return -1;
}

static void trojan_cleanup(int fd)
{
    /* TODO */
}

ProtocolHandler trojan_handler = {
    .type      = PROTO_TROJAN,
    .name      = "trojan",
    .connect   = trojan_connect,
    .handshake = trojan_handshake,
    .relay     = trojan_relay,
    .cleanup   = trojan_cleanup,
};

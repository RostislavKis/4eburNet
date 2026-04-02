/*
 * Межпроцессное взаимодействие
 *
 * Unix-сокет для связи между phoenix-core и LuCI.
 * Через него LuCI получает статистику и отправляет команды.
 */

#include <stdio.h>

int ipc_server_start(const char *socket_path)
{
    /* TODO: создать unix domain socket */
    return 0;
}

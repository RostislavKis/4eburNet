#ifndef IPC_H
#define IPC_H

#include "phoenix.h"

/* Создаёт Unix socket сервер, возвращает fd или -1 */
int  ipc_init(void);

/* Обрабатывает одно входящее IPC соединение (неблокирующий) */
void ipc_process(int server_fd, PhoenixState *state);

/* Закрывает сервер и удаляет socket-файл */
void ipc_cleanup(int server_fd);

/* Отправляет IPC команду запущенному демону, возвращает ответ в buf */
int  ipc_send_command(ipc_command_t cmd, char *buf, size_t buf_size);

#endif /* IPC_H */

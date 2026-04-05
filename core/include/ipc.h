#ifndef IPC_H
#define IPC_H

#include "phoenix.h"
#include "proxy/proxy_group.h"
#include "proxy/rule_provider.h"
#include "proxy/rules_engine.h"

/* Создаёт Unix socket сервер, возвращает fd или -1 */
int  ipc_init(void);

/* Обрабатывает одно входящее IPC соединение (неблокирующий) */
void ipc_process(int server_fd, PhoenixState *state);

/* Закрывает сервер и удаляет socket-файл */
void ipc_cleanup(int server_fd);

/* Отправляет IPC команду запущенному демону, возвращает ответ в buf */
int  ipc_send_command(ipc_command_t cmd, char *buf, size_t buf_size);

/* Установить контекст для IPC команд 20-25 */
void ipc_set_3x_context(proxy_group_manager_t *pgm,
                         rule_provider_manager_t *rpm,
                         rules_engine_t *re);

#endif /* IPC_H */

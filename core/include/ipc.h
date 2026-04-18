#ifndef IPC_H
#define IPC_H

#include "4eburnet.h"
#include "proxy/proxy_group.h"
#include "proxy/rule_provider.h"
#include "proxy/rules_engine.h"
#include "geo/geo_loader.h"

/* Создаёт Unix socket сервер, возвращает fd или -1 */
int  ipc_init(void);

/* Принять новое соединение и зарегистрировать в epoll ET */
void ipc_accept(int server_fd, EburNetState *state, int epoll_fd);

/* Обработать epoll-событие на IPC client fd (state machine) */
/* Возвращает 0 — продолжать, -1 — соединение закрыто */
int  ipc_client_event(void *client_ptr, uint32_t events,
                       EburNetState *state);

/* Проверить, принадлежит ли ptr пулу IPC клиентов */
bool ipc_is_client_ptr(const void *ptr);

/* Закрывает сервер и удаляет socket-файл */
void ipc_cleanup(int server_fd);

/* Отправляет IPC команду запущенному демону, возвращает ответ в buf */
int  ipc_send_command(ipc_command_t cmd, char *buf, size_t buf_size);

/* Отправляет IPC команду с payload (JSON строка), возвращает ответ в buf */
int  ipc_send_command_payload(ipc_command_t cmd, const char *payload,
                               char *buf, size_t buf_size);

/* Установить контекст для IPC команд 20-26 */
void ipc_set_3x_context(proxy_group_manager_t *pgm,
                         rule_provider_manager_t *rpm,
                         rules_engine_t *re,
                         geo_manager_t *gm);

#endif /* IPC_H */

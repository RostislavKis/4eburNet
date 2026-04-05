#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <sys/socket.h>
#include <stddef.h>
#include <stdbool.h>

/* Форматирование sockaddr_storage в строку "IP:порт" (M-01) */
void net_format_addr(const struct sockaddr_storage *ss,
                     char *buf, size_t buflen);

/* Валидация имени сетевого интерфейса (C-10, C-11) */
bool valid_ifname(const char *s);

/* --- Инкапсуляция popen (M-02) --- */

/* Выполнить команду, вызвать callback для каждой строки вывода.
   Строка передаётся без \n. Возвращает код выхода или -1. */
int exec_cmd_lines(const char *cmd,
                   void (*callback)(const char *line, void *ctx),
                   void *ctx);

/* Выполнить команду, игнорировать вывод. Возвращает код выхода. */
int exec_cmd(const char *cmd);

/* Выполнить команду, вернуть true если needle найден в выводе. */
bool exec_cmd_contains(const char *cmd, const char *needle);

/* Выполнить команду, прочитать вывод ошибок в буфер.
   Возвращает код выхода (0 = OK). err_buf заполняется при ошибке. */
int exec_cmd_capture(const char *cmd,
                     char *err_buf, size_t err_size);

/* Безопасное выполнение через posix_spawn без shell (H-07).
   argv — массив аргументов, NULL-terminated.
   out/outlen — опциональный буфер для stdout+stderr. */
int exec_cmd_safe(const char *const argv[], char *out, size_t outlen);

#endif /* NET_UTILS_H */

#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <sys/socket.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

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

/* Криптографически безопасные случайные байты (C-01).
   getrandom() с fallback на /dev/urandom. */
int net_random_bytes(uint8_t *buf, size_t len);

/* Экранирование строки для JSON (H-6).
   Копирует src в dst с заменой " → \", \ → \\, управляющих → \uXXXX.
   Возвращает количество записанных байт (без NUL). */
int json_escape_str(const char *src, char *dst, size_t dst_size);

/*
 * Скачать файл по HTTP/HTTPS URL.
 * dest_path: путь для сохранения (atomic через mkstemp + rename).
 * Возвращает 0 при успехе, -1 при ошибке.
 */
int net_http_fetch(const char *url, const char *dest_path);

/*
 * Разрешить hostname → IP строку.
 * inet_pton fast path: если host уже является IP — возвращает мгновенно (0мс).
 * Для доменных имён вызывает getaddrinfo (блокирует — только при старте).
 * При успехе записывает IP-строку в out_ip (минимум INET6_ADDRSTRLEN байт).
 * Возвращает 0 при успехе, -1 при ошибке.
 */
int net_resolve_host(const char *host, uint16_t port,
                     char *out_ip, size_t out_ip_size,
                     int *out_family);

/*
 * Парсить host и port из URL ("https://host:port/path" → host, port).
 * Возвращает 0 при успехе, -1 при ошибке.
 */
int net_parse_url_host(const char *url,
                       char *host, size_t host_size,
                       uint16_t *port);

/*
 * net_http_fetch_ip — скачать файл, соединяясь по уже известному IP.
 * url используется только для SNI (Host заголовок) и пути.
 * Пропускает getaddrinfo — 0мс при наличии IP кэша.
 */
int net_http_fetch_ip(const char *url,
                      const char *resolved_ip,
                      int         addr_family,
                      const char *dest_path);

/*
 * Запустить fetch в фоновом процессе (nonblocking для event loop).
 * Создаёт дочерний процесс через fork().
 * Возвращает read-end pipe fd (или -1 при ошибке).
 * Дочерний процесс: net_http_fetch(url, dest_path) → пишет "OK\n"
 * или "ERR\n" в pipe, затем завершается.
 * Caller: зарегистрировать fd в epoll, читать при EPOLLIN.
 */
int net_spawn_fetch(const char *url, const char *dest_path);

/*
 * Запустить TCP ping в фоновом процессе.
 * Дочерний: connect(ip, port) с timeout_ms → пишет
 *   "OK <latency_ms>\n" или "ERR\n" в pipe.
 * Возвращает read-end pipe fd или -1.
 */
int net_spawn_tcp_ping(const char *ip, uint16_t port, int timeout_ms);

#endif /* NET_UTILS_H */

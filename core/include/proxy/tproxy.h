#ifndef TPROXY_H
#define TPROXY_H

#include "4eburnet.h"

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <time.h>

/* Параметры сервера */
#define TPROXY_BACKLOG      128     /* очередь TCP listen */
#define TPROXY_MAX_CONNS    4096    /* максимум одновременных */
#define TPROXY_BUF_SIZE     65536   /* буфер relay (FULL профиль) */

/* Одно перехваченное соединение */
typedef struct {
    int                     fd;             /* дескриптор клиента (TCP) или -1 (UDP) */
    int                     proto;          /* IPPROTO_TCP или IPPROTO_UDP */
    struct sockaddr_storage src;            /* откуда пришёл пакет */
    struct sockaddr_storage dst;            /* оригинальный dst (куда шёл) */
    time_t                  accepted_at;    /* время принятия */
} tproxy_conn_t;

/* Состояние модуля TPROXY */
typedef struct {
    int         tcp4_fd;        /* IPv4 TCP listen сокет */
    int         tcp6_fd;        /* IPv6 TCP listen сокет */
    int         udp4_fd;        /* IPv4 UDP сокет */
    int         udp6_fd;        /* IPv6 UDP сокет */
    int         epoll_fd;       /* epoll для всех 4 сокетов */
    bool        running;
    uint64_t    accepted;       /* счётчик принятых соединений */
    uint64_t    rejected;       /* счётчик отброшенных */
} tproxy_state_t;

/* Инициализация: создать сокеты, настроить epoll */
int  tproxy_init(tproxy_state_t *ts, uint16_t port,
                 DeviceProfile profile);

/* Обработка: принять все ожидающие соединения (неблокирующий) */
void tproxy_process(tproxy_state_t *ts);

/* Обработать событие на конкретном fd (для master epoll) */
void tproxy_handle_event(tproxy_state_t *ts, int fd);

/* Очистка: закрыть все дескрипторы */
void tproxy_cleanup(tproxy_state_t *ts);

/* Статистика */
void tproxy_stats(const tproxy_state_t *ts,
                  uint64_t *accepted, uint64_t *rejected);

#endif /* TPROXY_H */

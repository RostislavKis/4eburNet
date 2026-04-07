#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include "dns/dns_cache.h"
#include "dns/dns_resolver.h"
#include "dns/dns_upstream_async.h"
#include "dns/fake_ip.h"
#include "config.h"

/* H-10/H-11: расширенный rate table для IPv4+IPv6 */
#define DNS_RATE_TABLE_SIZE 512

typedef struct {
    int               udp_fd;
    int               tcp_fd;
    int               master_epoll_fd;
    bool              initialized;    /* H-08: guard для epoll dispatch */
    dns_cache_t       cache;
    dns_pending_queue_t pending;
    const PhoenixConfig *cfg;
    /* Per-source rate limiting (H-10/H-11: IPv4+IPv6, 512 слотов) */
    struct {
        uint8_t  addr[16];    /* IPv4 (4 байта) или IPv6 (16 байт) */
        uint8_t  addr_len;    /* 4 = IPv4, 16 = IPv6 */
        uint32_t count;
        time_t   window_start;
    } rate_table[DNS_RATE_TABLE_SIZE];
    /* Async DoH/DoT pool (инициализируется в dns_server_register_epoll) */
    async_dns_pool_t async_pool;
    /* Fake-IP таблица (backlog_C4) */
    fake_ip_table_t  fake_ip;
    bool             fake_ip_ready;  /* инициализирована */
} dns_server_t;

int  dns_server_init(dns_server_t *ds, const PhoenixConfig *cfg);
void dns_server_cleanup(dns_server_t *ds);

/* Добавить fd в master epoll */
int  dns_server_register_epoll(dns_server_t *ds, int master_epoll_fd);

/* Обработать событие на dns fd */
void dns_server_handle_event(dns_server_t *ds, int fd, int master_epoll_fd);

/* Проверить, принадлежит ли fd ожидающему DNS запросу */
bool dns_server_is_pending_fd(const dns_server_t *ds, int fd);

/* Проверить принадлежность ptr к async DoH/DoT pool (epoll data.ptr) */
bool dns_server_is_async_ptr(const dns_server_t *ds, void *ptr);

/* Обработать async DoH/DoT epoll событие */
void dns_server_handle_async_event(dns_server_t *ds, void *ptr,
                                   uint32_t events);

/* Проверить таймауты async DNS соединений (~каждые 100ms) */
void dns_server_check_async_timeouts(dns_server_t *ds);

#endif /* DNS_SERVER_H */

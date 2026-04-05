#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include "dns/dns_cache.h"
#include "dns/dns_resolver.h"
#include "config.h"

typedef struct {
    int               udp_fd;
    int               tcp_fd;
    int               master_epoll_fd;
    dns_cache_t       cache;
    dns_pending_queue_t pending;
    const PhoenixConfig *cfg;
    /* Per-source rate limiting (H-13: DNS amplification) */
    struct {
        uint32_t ip;
        uint32_t count;
        time_t   window_start;
    } rate_table[256];
} dns_server_t;

int  dns_server_init(dns_server_t *ds, const PhoenixConfig *cfg);
void dns_server_cleanup(dns_server_t *ds);

/* Добавить fd в master epoll */
int  dns_server_register_epoll(dns_server_t *ds, int master_epoll_fd);

/* Обработать событие на dns fd */
void dns_server_handle_event(dns_server_t *ds, int fd, int master_epoll_fd);

/* Проверить, принадлежит ли fd ожидающему DNS запросу */
bool dns_server_is_pending_fd(const dns_server_t *ds, int fd);

#endif /* DNS_SERVER_H */

#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include "dns/dns_cache.h"
#include "config.h"

typedef struct {
    int               udp_fd;
    int               tcp_fd;
    dns_cache_t       cache;
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
void dns_server_handle_event(dns_server_t *ds, int fd);

#endif /* DNS_SERVER_H */

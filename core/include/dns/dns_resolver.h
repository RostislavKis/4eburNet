#ifndef PHOENIX_DNS_RESOLVER_H
#define PHOENIX_DNS_RESOLVER_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include "dns/dns_cache.h"
#include "dns/dns_packet.h"
#include "dns/dns_rules.h"

/* Максимальное число параллельных DNS запросов */
#define DNS_PENDING_MAX  64

/* Ожидающий DNS запрос */
typedef struct {
    bool      active;
    int       upstream_fd;          /* UDP сокет к upstream */
    uint8_t   query[DNS_MAX_PACKET];
    size_t    query_len;
    uint16_t  client_id;            /* оригинальный ID клиента */
    uint16_t  upstream_id;          /* ID который мы послали upstream */
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen;
    dns_action_t action;
    time_t    sent_at;              /* для таймаута */
    char      qname[256];
    uint16_t  qtype;
} dns_pending_t;

/* Очередь ожидающих запросов */
typedef struct {
    dns_pending_t slots[DNS_PENDING_MAX];
    int           count;
} dns_pending_queue_t;

void dns_pending_init(dns_pending_queue_t *q);

int dns_pending_add(dns_pending_queue_t *q,
                    const dns_query_t *query,
                    const uint8_t *pkt, size_t pkt_len,
                    const struct sockaddr_storage *client_addr,
                    socklen_t client_addrlen,
                    dns_action_t action,
                    const char *upstream_ip,
                    uint16_t upstream_port);

dns_pending_t *dns_pending_find_fd(dns_pending_queue_t *q, int fd);

void dns_pending_complete(dns_pending_queue_t *q, int idx);

void dns_pending_check_timeouts(dns_pending_queue_t *q, int epoll_fd);

#endif

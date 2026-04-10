#ifndef EBURNET_DNS_RESOLVER_H
#define EBURNET_DNS_RESOLVER_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>
#include "dns/dns_cache.h"
#include "dns/dns_packet.h"
#include "dns/dns_rules.h"

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
    struct timespec sent_at;        /* CLOCK_MONOTONIC (L-07) */
    char      qname[256];
    uint16_t  qtype;
    /* Fallback upstream (backlog_C3) */
    char     fallback_ip[256];      /* IP fallback upstream, "" = нет */
    uint16_t fallback_port;         /* порт fallback upstream */
    int      fallback_fd;           /* -1 = fallback не активен */
    bool     fallback_used;         /* true = уже используем fallback */
    /* Parallel query fd (backlog_C3 C5) */
    int      parallel_fd;           /* -1 = parallel не активен */
    uint16_t parallel_upstream_id;  /* ID для parallel запроса */
    /* TCP клиент (audit_v9: async TCP DNS state machine) */
    int      tcp_client_idx;        /* индекс в ds->tcp_clients[], -1 = UDP клиент */
} dns_pending_t;

/* Очередь ожидающих запросов (heap, capacity по профилю устройства) */
typedef struct {
    dns_pending_t *slots;    /* heap, capacity элементов */
    int            count;
    int            capacity;
} dns_pending_queue_t;

int  dns_pending_init(dns_pending_queue_t *q, int capacity);
void dns_pending_free(dns_pending_queue_t *q);

int dns_pending_add(dns_pending_queue_t *q,
                    const dns_query_t *query,
                    const uint8_t *pkt, size_t pkt_len,
                    const struct sockaddr_storage *client_addr,
                    socklen_t client_addrlen,
                    dns_action_t action,
                    const char *upstream_ip,
                    uint16_t upstream_port);

/* Вариант для TCP DNS клиентов — без client_addr, с tcp_client_idx */
int dns_pending_add_tcp(dns_pending_queue_t *q,
                        const dns_query_t *query,
                        const uint8_t *pkt, size_t pkt_len,
                        dns_action_t action,
                        const char *upstream_ip,
                        uint16_t upstream_port,
                        int tcp_client_idx);

dns_pending_t *dns_pending_find_fd(dns_pending_queue_t *q, int fd);

void dns_pending_complete(dns_pending_queue_t *q, int idx, int epoll_fd);


#endif

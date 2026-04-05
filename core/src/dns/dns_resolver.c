#define _XOPEN_SOURCE 700
#include "dns/dns_resolver.h"
#include "phoenix.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <time.h>

void dns_pending_init(dns_pending_queue_t *q)
{
    memset(q, 0, sizeof(*q));
    for (int i = 0; i < DNS_PENDING_MAX; i++)
        q->slots[i].upstream_fd = -1;
}

int dns_pending_add(dns_pending_queue_t *q,
                    const dns_query_t *query,
                    const uint8_t *pkt, size_t pkt_len,
                    const struct sockaddr_storage *client_addr,
                    socklen_t client_addrlen,
                    dns_action_t action,
                    const char *upstream_ip,
                    uint16_t upstream_port)
{
    /* Найти свободный слот */
    int idx = -1;
    for (int i = 0; i < DNS_PENDING_MAX; i++) {
        if (!q->slots[i].active) { idx = i; break; }
    }
    if (idx < 0) return -1;

    dns_pending_t *p = &q->slots[idx];
    p->active = true;
    p->client_id = query->id;
    /* Случайный upstream ID */
    uint16_t uid;
    /* Простой random из time + idx */
    uid = (uint16_t)((time(NULL) * 1103515245 + idx) & 0xFFFF);
    p->upstream_id = uid;

    if (pkt_len > sizeof(p->query)) pkt_len = sizeof(p->query);
    memcpy(p->query, pkt, pkt_len);
    /* Подменить ID в запросе */
    p->query[0] = (uid >> 8) & 0xFF;
    p->query[1] = uid & 0xFF;
    p->query_len = pkt_len;
    memcpy(&p->client_addr, client_addr, client_addrlen);
    p->client_addrlen = client_addrlen;
    p->action = action;
    p->sent_at = time(NULL);
    size_t qname_len = strlen(query->qname);
    if (qname_len >= sizeof(p->qname))
        qname_len = sizeof(p->qname) - 1;
    memcpy(p->qname, query->qname, qname_len);
    p->qname[qname_len] = '\0';
    p->qtype = query->qtype;

    /* Неблокирующий UDP сокет */
    p->upstream_fd = socket(AF_INET,
        SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (p->upstream_fd < 0) {
        p->active = false;
        return -1;
    }

    struct sockaddr_in uaddr = {
        .sin_family = AF_INET,
        .sin_port   = htons(upstream_port),
    };
    inet_pton(AF_INET, upstream_ip, &uaddr.sin_addr);

    sendto(p->upstream_fd, p->query, p->query_len, 0,
           (struct sockaddr *)&uaddr, sizeof(uaddr));

    q->count++;
    return idx;
}

dns_pending_t *dns_pending_find_fd(dns_pending_queue_t *q, int fd)
{
    for (int i = 0; i < DNS_PENDING_MAX; i++)
        if (q->slots[i].active && q->slots[i].upstream_fd == fd)
            return &q->slots[i];
    return NULL;
}

void dns_pending_complete(dns_pending_queue_t *q, int idx)
{
    dns_pending_t *p = &q->slots[idx];
    if (p->upstream_fd >= 0) {
        close(p->upstream_fd);
        p->upstream_fd = -1;
    }
    p->active = false;
    if (q->count > 0) q->count--;
}

void dns_pending_check_timeouts(dns_pending_queue_t *q, int epoll_fd)
{
    time_t now = time(NULL);
    for (int i = 0; i < DNS_PENDING_MAX; i++) {
        dns_pending_t *p = &q->slots[i];
        if (!p->active) continue;
        if (now - p->sent_at > 2) {
            log_msg(LOG_DEBUG, "DNS: upstream таймаут для %s", p->qname);
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, p->upstream_fd, NULL);
            dns_pending_complete(q, i);
        }
    }
}

#define _XOPEN_SOURCE 700
#include "dns/dns_resolver.h"
#include "net_utils.h"
#include "phoenix.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <time.h>
#include <errno.h>

void dns_pending_init(dns_pending_queue_t *q)
{
    memset(q, 0, sizeof(*q));
    for (int i = 0; i < DNS_PENDING_MAX; i++) {
        q->slots[i].upstream_fd = -1;
        q->slots[i].fallback_fd = -1;
        q->slots[i].parallel_fd = -1;
    }
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
    /* Случайный upstream ID (C-01: getrandom вместо предсказуемого LCG) */
    uint16_t uid;
    if (net_random_bytes((uint8_t *)&uid, sizeof(uid)) < 0)
        uid = (uint16_t)(time(NULL) ^ idx);  /* аварийный fallback */
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
    clock_gettime(CLOCK_MONOTONIC, &p->sent_at);
    size_t qname_len = strlen(query->qname);
    if (qname_len >= sizeof(p->qname))
        qname_len = sizeof(p->qname) - 1;
    memcpy(p->qname, query->qname, qname_len);
    p->qname[qname_len] = '\0';
    p->qtype = query->qtype;
    p->fallback_fd   = -1;
    p->parallel_fd   = -1;
    p->fallback_used = false;
    p->fallback_ip[0] = '\0';
    p->fallback_port  = 0;

    /* L-06: IPv6 поддержка upstream DNS */
    int af = strchr(upstream_ip, ':') ? AF_INET6 : AF_INET;
    p->upstream_fd = socket(af,
        SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (p->upstream_fd < 0) {
        p->active = false;
        return -1;
    }

    struct sockaddr_storage uaddr_ss;
    socklen_t uaddr_len;
    memset(&uaddr_ss, 0, sizeof(uaddr_ss));
    if (af == AF_INET6) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&uaddr_ss;
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(upstream_port);
        inet_pton(AF_INET6, upstream_ip, &a6->sin6_addr);
        uaddr_len = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *a4 = (struct sockaddr_in *)&uaddr_ss;
        a4->sin_family = AF_INET;
        a4->sin_port = htons(upstream_port);
        inet_pton(AF_INET, upstream_ip, &a4->sin_addr);
        uaddr_len = sizeof(struct sockaddr_in);
    }

    ssize_t sent = sendto(p->upstream_fd, p->query, p->query_len, 0,
                          (struct sockaddr *)&uaddr_ss, uaddr_len);
    if (sent < 0) {
        log_msg(LOG_DEBUG, "DNS pending: sendto: %s", strerror(errno));
        close(p->upstream_fd);
        p->upstream_fd = -1;
        p->active = false;
        return -1;
    }

    q->count++;
    return idx;
}

dns_pending_t *dns_pending_find_fd(dns_pending_queue_t *q, int fd)
{
    for (int i = 0; i < DNS_PENDING_MAX; i++) {
        if (!q->slots[i].active) continue;
        if (q->slots[i].upstream_fd == fd) return &q->slots[i];
        if (q->slots[i].fallback_fd  == fd) return &q->slots[i];
        if (q->slots[i].parallel_fd  == fd) return &q->slots[i];
    }
    return NULL;
}

void dns_pending_complete(dns_pending_queue_t *q, int idx, int epoll_fd)
{
    /* H-12: bounds check */
    if (idx < 0 || idx >= DNS_PENDING_MAX) return;
    dns_pending_t *p = &q->slots[idx];
    /* Закрыть fallback fd если активен */
    if (p->fallback_fd >= 0) {
        if (epoll_fd >= 0)
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, p->fallback_fd, NULL);
        close(p->fallback_fd);
        p->fallback_fd = -1;
    }
    /* Закрыть parallel fd если активен */
    if (p->parallel_fd >= 0) {
        if (epoll_fd >= 0)
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, p->parallel_fd, NULL);
        close(p->parallel_fd);
        p->parallel_fd = -1;
    }
    if (p->upstream_fd >= 0) {
        close(p->upstream_fd);
        p->upstream_fd = -1;
    }
    p->active = false;
    if (q->count > 0) q->count--;
}

void dns_pending_check_timeouts(dns_pending_queue_t *q, int epoll_fd)
{
    /* L-07: CLOCK_MONOTONIC — гранулярность ~1ms вместо ~1с */
    struct timespec now_mono;
    clock_gettime(CLOCK_MONOTONIC, &now_mono);

    #define DNS_TIMEOUT_SEC 2

    for (int i = 0; i < DNS_PENDING_MAX; i++) {
        dns_pending_t *p = &q->slots[i];
        if (!p->active) continue;
        long elapsed_sec = now_mono.tv_sec - p->sent_at.tv_sec;
        if (!(elapsed_sec > DNS_TIMEOUT_SEC ||
              (elapsed_sec == DNS_TIMEOUT_SEC &&
               now_mono.tv_nsec >= p->sent_at.tv_nsec)))
            continue;

        /* Таймаут — попробовать fallback если не использовали */
        if (!p->fallback_used && p->fallback_ip[0]) {
            int ffd = socket(AF_INET,
                             SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (ffd >= 0) {
                struct sockaddr_in fa = {
                    .sin_family = AF_INET,
                    .sin_port   = htons(p->fallback_port),
                };
                if (inet_pton(AF_INET, p->fallback_ip, &fa.sin_addr) == 1 &&
                    sendto(ffd, p->query, p->query_len, 0,
                           (struct sockaddr *)&fa, sizeof(fa)) >= 0) {
                    /* Убрать старый primary fd из epoll */
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, p->upstream_fd, NULL);
                    close(p->upstream_fd);
                    /* Переключить на fallback fd */
                    /* upstream_fd теперь указывает на ffd.
                       fallback_fd НЕ дублируем — иначе double close в complete. */
                    p->upstream_fd   = ffd;
                    p->fallback_fd   = -1;
                    p->fallback_used = true;
                    clock_gettime(CLOCK_MONOTONIC, &p->sent_at);
                    struct epoll_event ev = {
                        .events  = EPOLLIN,
                        .data.fd = ffd,
                    };
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ffd, &ev);
                    log_msg(LOG_DEBUG,
                        "DNS: %s timeout, retry via fallback %s",
                        p->qname, p->fallback_ip);
                    continue;  /* дать шанс fallback'у */
                }
                close(ffd);
            }
        }

        /* Fallback не помог или не настроен — удалить слот */
        log_msg(LOG_DEBUG, "DNS: upstream таймаут для %s", p->qname);
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, p->upstream_fd, NULL);
        dns_pending_complete(q, i, epoll_fd);
    }
}

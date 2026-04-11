/*
 * dpi_strategy.c — DPI bypass стратегии: fake+TTL + fragment (C.3)
 */

#if CONFIG_EBURNET_DPI

#include "dpi/dpi_strategy.h"
#include "dpi/dpi_payload.h"
#include "4eburnet.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

/* ── Конфигурация ───────────────────────────────────────────────── */

void dpi_strategy_config_init(dpi_strategy_config_t *cfg)
{
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->enabled      = true;
    cfg->split_pos    = 1;
    cfg->fake_ttl     = 5;
    cfg->fake_repeats = 8;
    snprintf(cfg->fake_sni, sizeof(cfg->fake_sni), "www.google.com");
}

/* ── Утилиты ────────────────────────────────────────────────────── */

void dpi_fragment_sizes(int data_len, int split_pos, int *p1, int *p2)
{
    if (!p1 || !p2) return;
    if (split_pos <= 0 || split_pos >= data_len) {
        *p1 = data_len;
        *p2 = 0;
    } else {
        *p1 = split_pos;
        *p2 = data_len - split_pos;
    }
}

int dpi_make_fake_payload(uint8_t *buf, int buf_size,
                           dpi_proto_t proto, const char *sni)
{
    if (proto == DPI_PROTO_UDP)
        return dpi_make_quic_initial(buf, buf_size);
    else
        return dpi_make_tls_clienthello(buf, buf_size, sni);
}

int dpi_set_ttl(int fd, int ttl)
{
    return setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
}

int dpi_set_nodelay(int fd, int on)
{
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
}

int dpi_raw_socket_create(int af)
{
    return socket(af, SOCK_RAW, IPPROTO_RAW);
}

void dpi_raw_socket_close(int fd)
{
    if (fd >= 0) close(fd);
}

/* ── Стратегии ──────────────────────────────────────────────────── */

int dpi_send_fake(int fd,
                  const uint8_t *payload, int payload_len,
                  int fake_ttl, int repeats)
{
    if (fd < 0 || !payload || payload_len <= 0) return -1;
    if (fake_ttl <= 0 || fake_ttl > 64)         return -1;
    if (repeats  <= 0 || repeats  > 20)          return -1;

    /* Сохранить текущий TTL для восстановления */
    int saved_ttl = 64;
    socklen_t slen = sizeof(saved_ttl);
    getsockopt(fd, IPPROTO_IP, IP_TTL, &saved_ttl, &slen);

    /* Установить fake TTL */
    if (setsockopt(fd, IPPROTO_IP, IP_TTL, &fake_ttl, sizeof(fake_ttl)) < 0) {
        log_msg(LOG_WARN, "dpi_send_fake: setsockopt IP_TTL=%d: %s",
                fake_ttl, strerror(errno));
        return -1;
    }

    /* Отправить fake payload × repeats */
    int rc = 0;
    for (int i = 0; i < repeats; i++) {
        ssize_t n = send(fd, payload, (size_t)payload_len, MSG_NOSIGNAL);
        if (n < 0) {
            log_msg(LOG_WARN, "dpi_send_fake: send[%d/%d]: %s",
                    i + 1, repeats, strerror(errno));
            rc = -1;
            break;
        }
    }

    /* Восстановить TTL в любом случае */
    setsockopt(fd, IPPROTO_IP, IP_TTL, &saved_ttl, sizeof(saved_ttl));

    return rc;
}

int dpi_send_fragment(int fd,
                      const uint8_t *data, int data_len,
                      int split_pos)
{
    if (fd < 0 || !data || data_len <= 0) return -1;

    /* Вычислить размеры фрагментов */
    int p1, p2;
    dpi_fragment_sizes(data_len, split_pos, &p1, &p2);

    /* TCP_NODELAY: запретить Nagle — иначе два send() сольются в один сегмент */
    dpi_set_nodelay(fd, 1);

    /* Первый фрагмент */
    ssize_t n1 = send(fd, data, (size_t)p1, MSG_NOSIGNAL);
    if (n1 < 0) {
        log_msg(LOG_WARN, "dpi_send_fragment: send part1: %s", strerror(errno));
        return -1;
    }

    /* Второй фрагмент (если есть) */
    ssize_t n2 = 0;
    if (p2 > 0) {
        n2 = send(fd, data + p1, (size_t)p2, MSG_NOSIGNAL);
        if (n2 < 0) {
            log_msg(LOG_WARN, "dpi_send_fragment: send part2: %s", strerror(errno));
            return -1;
        }
    }

    return (int)(n1 + n2);
}

#endif /* CONFIG_EBURNET_DPI */

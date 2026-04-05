/*
 * AmneziaWG 2.0 — обфускация поверх Noise_IK (WireGuard)
 *
 * H1-H4 header ranges, S1-S4 padding, Jc/Jmin/Jmax junk,
 * I1-I5 CPS signature packets.
 * UDP транспорт, все параметры из конфига.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/coding.h>

#include "proxy/protocols/awg.h"
#include "config.h"
#include "phoenix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------ */
/*  Вспомогательные                                                    */
/* ------------------------------------------------------------------ */

static int random_fill(uint8_t *buf, size_t len)
{
#ifdef __NR_getrandom
    ssize_t rc = syscall(__NR_getrandom, buf, len, 0);
    if (rc == (ssize_t)len) return 0;
#endif
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, buf + done, len - done);
        if (n <= 0) { close(fd); return -1; }
        done += (size_t)n;
    }
    close(fd);
    return 0;
}

static uint32_t random_u32(void)
{
    uint32_t v;
    if (random_fill((uint8_t *)&v, 4) != 0) {
        /* Fallback: обфускация ослаблена, но не нулевая (H-25) */
        log_msg(LOG_WARN, "AWG: random_fill ошибка — обфускация ослаблена");
        static uint32_t counter = 0;
        v = (uint32_t)time(NULL) ^ (++counter * 2654435761u);
    }
    return v;
}

static uint32_t rand_in_range(uint32_t min, uint32_t max)
{
    if (min >= max) return min;
    /* Modulo bias пренебрежимо мал для обфускации */
    return (random_u32() % (max - min + 1)) + min;
}

int awg_key_decode(const char *b64, uint8_t key[32])
{
    word32 out_len = 32;
    int rc = Base64_Decode((const byte *)b64, strlen(b64),
                           key, &out_len);
    return (rc == 0 && out_len == 32) ? 0 : -1;
}

void awg_parse_range(const char *str, uint32_t *min, uint32_t *max)
{
    *min = *max = 0;
    if (!str || !str[0]) return;
    char *dash = strchr(str, '-');
    if (dash) {
        *min = (uint32_t)strtoul(str, NULL, 10);
        *max = (uint32_t)strtoul(dash + 1, NULL, 10);
    } else {
        *min = *max = (uint32_t)strtoul(str, NULL, 10);
    }
}

/* ------------------------------------------------------------------ */
/*  CPS парсер (I1-I5 signature packets)                               */
/* ------------------------------------------------------------------ */

int awg_cps_build(const char *spec, uint8_t *out, size_t *outlen)
{
    if (!spec || !spec[0]) { *outlen = 0; return 0; }

    size_t pos = 0;
    const char *p = spec;
    size_t max = *outlen;

    while (*p) {
        /* Пропустить пробелы */
        while (*p == ' ') p++;
        if (*p != '<') { p++; continue; }
        p++;  /* пропустить '<' */

        if (p[0] == 'b' && p[1] == ' ' && p[2] == '0' && p[3] == 'x') {
            /* <b 0xHEX> — hex байты */
            p += 4;
            while (*p && *p != '>') {
                /* M-32: bounds check на p[1] */
                if (!p[0] || !p[1] || p[1] == '>') {
                    p++;
                    continue;
                }
                if (!isxdigit((unsigned char)p[0]) ||
                    !isxdigit((unsigned char)p[1])) {
                    p++;
                    continue;
                }
                char hex[3] = { p[0], p[1], '\0' };
                if (pos < max)
                    out[pos++] = (uint8_t)strtoul(hex, NULL, 16);
                p += 2;
            }
        } else if (p[0] == 'r' && p[1] == ' ') {
            /* <r N> — N случайных байт */
            int n = atoi(p + 2);
            for (int i = 0; i < n && pos < max; i++)
                out[pos++] = (uint8_t)(random_u32() & 0xFF);
        } else if (p[0] == 'r' && p[1] == 'd' && p[2] == ' ') {
            /* <rd N> — N цифр */
            int n = atoi(p + 3);
            for (int i = 0; i < n && pos < max; i++)
                out[pos++] = '0' + (random_u32() % 10);
        } else if (p[0] == 'r' && p[1] == 'c' && p[2] == ' ') {
            /* <rc N> — N букв */
            int n = atoi(p + 3);
            static const char alpha[] =
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            for (int i = 0; i < n && pos < max; i++)
                out[pos++] = alpha[random_u32() % 52];
        } else if (p[0] == 't') {
            /* <t> — timestamp uint32 LE */
            uint32_t ts = (uint32_t)time(NULL);
            if (pos + 4 <= max) {
                out[pos++] = (uint8_t)(ts);
                out[pos++] = (uint8_t)(ts >> 8);
                out[pos++] = (uint8_t)(ts >> 16);
                out[pos++] = (uint8_t)(ts >> 24);
            }
        }

        /* Пропустить до '>' */
        while (*p && *p != '>') p++;
        if (*p == '>') p++;
    }

    *outlen = pos;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  awg_init                                                           */
/* ------------------------------------------------------------------ */

int awg_init(awg_state_t *awg, const void *server_config)
{
    const ServerConfig *srv = server_config;
    memset(awg, 0, sizeof(*awg));
    awg->udp_fd = -1;

    /* Ключи */
    if (awg_key_decode(srv->awg_private_key,
                       awg->cfg.local_private_key) < 0) {
        log_msg(LOG_ERROR, "AWG: невалидный private key");
        return -1;
    }
    if (awg_key_decode(srv->awg_public_key,
                       awg->cfg.remote_public_key) < 0) {
        log_msg(LOG_ERROR, "AWG: невалидный public key");
        return -1;
    }
    if (srv->awg_psk[0]) {
        if (awg_key_decode(srv->awg_psk, awg->cfg.preshared_key) == 0)
            awg->cfg.has_psk = true;
    }

    /* Header диапазоны */
    awg_parse_range(srv->awg_h1, &awg->cfg.h1_min, &awg->cfg.h1_max);
    awg_parse_range(srv->awg_h2, &awg->cfg.h2_min, &awg->cfg.h2_max);
    awg_parse_range(srv->awg_h3, &awg->cfg.h3_min, &awg->cfg.h3_max);
    awg_parse_range(srv->awg_h4, &awg->cfg.h4_min, &awg->cfg.h4_max);

    /* Padding */
    awg->cfg.s1 = srv->awg_s1;
    awg->cfg.s2 = srv->awg_s2;
    awg->cfg.s3 = srv->awg_s3;
    awg->cfg.s4 = srv->awg_s4;

    /* Junk */
    awg->cfg.jc   = srv->awg_jc;
    awg->cfg.jmin = srv->awg_jmin;
    awg->cfg.jmax = srv->awg_jmax;

    /* CPS */
    snprintf(awg->cfg.i1, sizeof(awg->cfg.i1), "%s", srv->awg_i1);
    snprintf(awg->cfg.i2, sizeof(awg->cfg.i2), "%s", srv->awg_i2);
    snprintf(awg->cfg.i3, sizeof(awg->cfg.i3), "%s", srv->awg_i3);
    snprintf(awg->cfg.i4, sizeof(awg->cfg.i4), "%s", srv->awg_i4);
    snprintf(awg->cfg.i5, sizeof(awg->cfg.i5), "%s", srv->awg_i5);

    awg->cfg.keepalive = srv->awg_keepalive;

    /* Noise init */
    if (noise_init(&awg->noise,
                   awg->cfg.local_private_key,
                   awg->cfg.remote_public_key,
                   awg->cfg.preshared_key,
                   awg->cfg.has_psk) < 0)
        return -1;

    log_msg(LOG_DEBUG, "AWG: инициализирован (H1=%u-%u, Jc=%u, S1=%u)",
            awg->cfg.h1_min, awg->cfg.h1_max,
            awg->cfg.jc, awg->cfg.s1);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  AWG обфускация пакета                                              */
/* ------------------------------------------------------------------ */

/* Заменить msg_type на случайный из диапазона H */
static void awg_obfuscate_header(uint8_t *pkt,
                                 uint32_t h_min, uint32_t h_max)
{
    if (h_min == 0 && h_max == 0) return;
    uint32_t hdr = rand_in_range(h_min, h_max);
    pkt[0] = (uint8_t)(hdr);
    pkt[1] = (uint8_t)(hdr >> 8);
    pkt[2] = (uint8_t)(hdr >> 16);
    pkt[3] = (uint8_t)(hdr >> 24);
}

/* Добавить S padding с проверкой границ буфера */
static size_t awg_add_padding(uint8_t *pkt, size_t pkt_len,
                               uint16_t s_max, size_t buf_size)
{
    if (s_max == 0) return pkt_len;
    uint16_t pad = (uint16_t)(random_u32() % (s_max + 1));
    /* Проверка границ буфера */
    if (pkt_len + pad > buf_size)
        pad = (uint16_t)(buf_size - pkt_len);
    if (pad > 0)
        random_fill(pkt + pkt_len, pad);
    return pkt_len + pad;
}

/* ------------------------------------------------------------------ */
/*  awg_handshake_start                                                */
/* ------------------------------------------------------------------ */

int awg_handshake_start(awg_state_t *awg,
                        const char *server_ip, uint16_t server_port)
{
    /* UDP сокет с поддержкой IPv4 и IPv6 (H-09) */
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t ss_len;

    if (inet_pton(AF_INET, server_ip,
                  &((struct sockaddr_in *)&ss)->sin_addr) == 1) {
        ((struct sockaddr_in *)&ss)->sin_family = AF_INET;
        ((struct sockaddr_in *)&ss)->sin_port   = htons(server_port);
        ss_len = sizeof(struct sockaddr_in);
        awg->udp_fd = socket(AF_INET,
                             SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    } else if (inet_pton(AF_INET6, server_ip,
                         &((struct sockaddr_in6 *)&ss)->sin6_addr) == 1) {
        ((struct sockaddr_in6 *)&ss)->sin6_family = AF_INET6;
        ((struct sockaddr_in6 *)&ss)->sin6_port   = htons(server_port);
        ss_len = sizeof(struct sockaddr_in6);
        awg->udp_fd = socket(AF_INET6,
                             SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    } else {
        log_msg(LOG_ERROR, "AWG: невалидный IP: %s", server_ip);
        return -1;
    }

    if (awg->udp_fd < 0) return -1;

    if (connect(awg->udp_fd, (struct sockaddr *)&ss, ss_len) < 0 &&
        errno != EINPROGRESS) {
        close(awg->udp_fd); awg->udp_fd = -1;
        return -1;
    }

    /* Отправить I1-I5 CPS пакеты */
    const char *cps[] = {
        awg->cfg.i1, awg->cfg.i2, awg->cfg.i3,
        awg->cfg.i4, awg->cfg.i5
    };
    int cps_sent = 0;
    for (int i = 0; i < 5; i++) {
        if (!cps[i][0]) continue;
        uint8_t cpkt[512];
        size_t clen = sizeof(cpkt);
        awg_cps_build(cps[i], cpkt, &clen);
        if (clen > 0) {
            send(awg->udp_fd, cpkt, clen, 0);
            cps_sent++;
        }
    }
    if (cps_sent > 0)
        log_msg(LOG_DEBUG, "AWG: отправлены I-пакеты (%d)", cps_sent);

    /* Отправить Jc junk пакетов */
    for (int i = 0; i < awg->cfg.jc; i++) {
        uint16_t jlen = (awg->cfg.jmin < awg->cfg.jmax)
            ? (uint16_t)rand_in_range(awg->cfg.jmin, awg->cfg.jmax)
            : awg->cfg.jmin;
        if (jlen > 0) {
            uint8_t junk[1500];
            if (jlen > sizeof(junk)) jlen = sizeof(junk);
            random_fill(junk, jlen);
            send(awg->udp_fd, junk, jlen, 0);
        }
    }
    if (awg->cfg.jc > 0)
        log_msg(LOG_DEBUG, "AWG: отправлены junk пакеты (%u)", awg->cfg.jc);

    /* Noise Init handshake */
    uint8_t init_pkt[1536];  /* 148 + max S1 padding */
    size_t init_len = sizeof(init_pkt);
    if (noise_handshake_init_create(&awg->noise, init_pkt, &init_len) < 0) {
        log_msg(LOG_ERROR, "AWG: не удалось создать Init handshake");
        return -1;
    }

    /* AWG обфускация Init */
    awg_obfuscate_header(init_pkt, awg->cfg.h1_min, awg->cfg.h1_max);
    init_len = awg_add_padding(init_pkt, init_len, awg->cfg.s1,
                                sizeof(init_pkt));

    send(awg->udp_fd, init_pkt, init_len, 0);
    awg->last_handshake = time(NULL);

    log_msg(LOG_DEBUG, "AWG: Init handshake отправлен (%zu байт)", init_len);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  awg_process_incoming                                               */
/* ------------------------------------------------------------------ */

int awg_process_incoming(awg_state_t *awg)
{
    uint8_t pkt[2048];
    ssize_t n = recv(awg->udp_fd, pkt, sizeof(pkt), MSG_DONTWAIT);
    if (n <= 0) return (int)n;

    /* Определить тип по AWG header */
    if (n < 4) return -1;

    uint32_t hdr = (uint32_t)pkt[0] | ((uint32_t)pkt[1] << 8) |
                   ((uint32_t)pkt[2] << 16) | ((uint32_t)pkt[3] << 24);

    /* Handshake Response? */
    if (!awg->handshake_done &&
        ((awg->cfg.h2_min == 0 && hdr == 2) ||
         (hdr >= awg->cfg.h2_min && hdr <= awg->cfg.h2_max))) {

        /* Восстановить оригинальный WG header */
        pkt[0] = 2; pkt[1] = 0; pkt[2] = 0; pkt[3] = 0;

        /* Убрать S2 padding — Response = 92 байта WG */
        if (noise_handshake_response_process(&awg->noise, pkt, 92) == 0) {
            awg->handshake_done = true;
            awg->last_send = time(NULL);
            log_msg(LOG_DEBUG, "AWG: handshake завершён");
            return 1;  /* handshake done */
        }
        return -1;
    }

    /* Transport Data? */
    if (awg->handshake_done &&
        ((awg->cfg.h4_min == 0 && hdr == 4) ||
         (hdr >= awg->cfg.h4_min && hdr <= awg->cfg.h4_max))) {

        pkt[0] = 4; pkt[1] = 0; pkt[2] = 0; pkt[3] = 0;

        size_t out_len;
        if (noise_decrypt(&awg->noise, pkt, n, awg->recv_buf, &out_len) == 0) {
            awg->recv_len = out_len;
            return 2;  /* data available */
        }
    }

    return 0;  /* unknown/junk — игнорируем */
}

/* ------------------------------------------------------------------ */
/*  awg_send / awg_recv                                                */
/* ------------------------------------------------------------------ */

ssize_t awg_send(awg_state_t *awg, const uint8_t *data, size_t len)
{
    if (!awg->handshake_done) return -1;

    /* Ограничение по MTU: header(16) + data + tag(16) + S4 padding */
    if (len > 1420) len = 1420;

    uint8_t pkt[1536];
    size_t pkt_len;

    if (noise_encrypt(&awg->noise, data, len, pkt, &pkt_len) != 0)
        return -1;

    awg_obfuscate_header(pkt, awg->cfg.h4_min, awg->cfg.h4_max);
    pkt_len = awg_add_padding(pkt, pkt_len, awg->cfg.s4, sizeof(pkt));

    ssize_t sent = send(awg->udp_fd, pkt, pkt_len, 0);
    if (sent > 0) awg->last_send = time(NULL);
    return (sent > 0) ? (ssize_t)len : -1;
}

ssize_t awg_recv(awg_state_t *awg, uint8_t *buf, size_t buflen)
{
    if (awg->recv_len == 0) return -1;
    size_t copy = awg->recv_len;
    if (copy > buflen) copy = buflen;
    memcpy(buf, awg->recv_buf, copy);
    awg->recv_len = 0;
    return (ssize_t)copy;
}

/* ------------------------------------------------------------------ */
/*  awg_tick / awg_close                                               */
/* ------------------------------------------------------------------ */

void awg_tick(awg_state_t *awg)
{
    if (!awg->handshake_done) {
        /* Ретрай handshake каждые 5 сек */
        if (time(NULL) - awg->last_handshake > 5) {
            log_msg(LOG_DEBUG, "AWG: handshake ретрай");
            /* Переинициализировать noise для нового handshake */
            noise_init(&awg->noise,
                       awg->cfg.local_private_key,
                       awg->cfg.remote_public_key,
                       awg->cfg.preshared_key, awg->cfg.has_psk);

            uint8_t init[1536];
            size_t init_len = sizeof(init);
            if (noise_handshake_init_create(&awg->noise, init, &init_len) == 0) {
                awg_obfuscate_header(init, awg->cfg.h1_min, awg->cfg.h1_max);
                init_len = awg_add_padding(init, init_len, awg->cfg.s1,
                                            sizeof(init));
                send(awg->udp_fd, init, init_len, 0);
                awg->last_handshake = time(NULL);
            }
        }
        return;
    }

    /* Keepalive */
    if (awg->cfg.keepalive > 0 &&
        time(NULL) - awg->last_send > awg->cfg.keepalive) {
        /* Empty encrypted packet = keepalive */
        uint8_t pkt[64];
        size_t pkt_len;
        if (noise_encrypt(&awg->noise, NULL, 0, pkt, &pkt_len) == 0) {
            awg_obfuscate_header(pkt, awg->cfg.h4_min, awg->cfg.h4_max);
            send(awg->udp_fd, pkt, pkt_len, 0);
            awg->last_send = time(NULL);
        }
    }
}

void awg_close(awg_state_t *awg)
{
    if (awg->udp_fd >= 0) {
        close(awg->udp_fd);
        awg->udp_fd = -1;
    }
    log_msg(LOG_DEBUG, "AWG: соединение закрыто");
}

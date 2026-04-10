/*
 * Hysteria2 — TCP/UDP прокси поверх QUIC
 *
 * Этот файл: varint, TCPRequest/TCPResponse, каркас соединения.
 * UDP datagrams: hysteria2_udp.c (B.4, будущее)
 * Brutal CC: hysteria2_cc.c (B.5, будущее)
 *
 * QUIC transport: wolfSSL с WOLFSSL_QUIC_METHOD колбэками.
 * Salamander обфускация применяется на уровне UDP I/O.
 */

#ifdef CONFIG_EBURNET_QUIC

#include "proxy/hysteria2.h"
#include "crypto/quic_salamander.h"
#include "4eburnet.h"  /* log_msg */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* wolfSSL подключается здесь — не экспортируется через .h */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>

/* ── Внутренняя структура соединения ────────────────────────────────── */

struct hysteria2_conn {
    hysteria2_config_t  cfg;
    hysteria2_state_t   state;

    /* QUIC/TLS */
    WOLFSSL_CTX        *ssl_ctx;
    WOLFSSL            *ssl;
    int                 udp_fd;          /* UDP сокет к серверу */

    /* Salamander */
    salamander_ctx_t    salamander;
    bool                salamander_active;

    /* Stream ID счётчик: client-initiated bidi = 0, 4, 8, ... */
    uint64_t            next_stream_id;

    /* Диагностика */
    char                error_msg[256];
    uint32_t            rtt_ms;
};

/* ── Утилиты ─────────────────────────────────────────────────────────── */

/* Записать ошибку в conn->error_msg (используется в B.3.x) */
static void set_error(hysteria2_conn_t *conn, const char *fmt, ...)
    __attribute__((unused));
static void set_error(hysteria2_conn_t *conn, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(conn->error_msg, sizeof(conn->error_msg), fmt, ap);
    va_end(ap);
    conn->state = HY2_STATE_ERROR;
}

/* ── varint RFC 9000 §16 ─────────────────────────────────────────────── */

/*
 * Кодировка:
 *   0x00..0x3F         → 1 байт  (2 MSB = 00)
 *   0x40..0x3FFF       → 2 байта (2 MSB = 01)
 *   0x4000..0x3FFFFFFF → 4 байта (2 MSB = 10)
 *   0x40000000..2^62-1 → 8 байт  (2 MSB = 11)
 */

int hy2_varint_encode(uint8_t *buf, size_t buf_size, uint64_t value)
{
    if (value <= UINT64_C(0x3F)) {
        if (buf_size < 1) return -1;
        buf[0] = (uint8_t)value;
        return 1;
    }
    if (value <= UINT64_C(0x3FFF)) {
        if (buf_size < 2) return -1;
        buf[0] = (uint8_t)(0x40 | (value >> 8));
        buf[1] = (uint8_t)(value & 0xFF);
        return 2;
    }
    if (value <= UINT64_C(0x3FFFFFFF)) {
        if (buf_size < 4) return -1;
        buf[0] = (uint8_t)(0x80 | (value >> 24));
        buf[1] = (uint8_t)(value >> 16);
        buf[2] = (uint8_t)(value >>  8);
        buf[3] = (uint8_t)(value & 0xFF);
        return 4;
    }
    if (value <= UINT64_C(0x3FFFFFFFFFFFFFFF)) {
        if (buf_size < 8) return -1;
        buf[0] = (uint8_t)(0xC0 | (value >> 56));
        buf[1] = (uint8_t)(value >> 48);
        buf[2] = (uint8_t)(value >> 40);
        buf[3] = (uint8_t)(value >> 32);
        buf[4] = (uint8_t)(value >> 24);
        buf[5] = (uint8_t)(value >> 16);
        buf[6] = (uint8_t)(value >>  8);
        buf[7] = (uint8_t)(value & 0xFF);
        return 8;
    }
    return -1;  /* значение > 2^62-1: не допускается RFC 9000 */
}

int hy2_varint_decode(const uint8_t *buf, size_t buf_size, uint64_t *out)
{
    if (buf_size < 1 || !buf || !out) return -1;

    uint8_t prefix = buf[0] >> 6;  /* два старших бита */

    switch (prefix) {
    case 0:  /* 1 байт */
        *out = buf[0] & 0x3F;
        return 1;
    case 1:  /* 2 байта */
        if (buf_size < 2) return -1;
        *out = ((uint64_t)(buf[0] & 0x3F) << 8) | buf[1];
        return 2;
    case 2:  /* 4 байта */
        if (buf_size < 4) return -1;
        *out = ((uint64_t)(buf[0] & 0x3F) << 24)
             | ((uint64_t)buf[1] << 16)
             | ((uint64_t)buf[2] <<  8)
             |  (uint64_t)buf[3];
        return 4;
    case 3:  /* 8 байт */
        if (buf_size < 8) return -1;
        *out = ((uint64_t)(buf[0] & 0x3F) << 56)
             | ((uint64_t)buf[1] << 48)
             | ((uint64_t)buf[2] << 40)
             | ((uint64_t)buf[3] << 32)
             | ((uint64_t)buf[4] << 24)
             | ((uint64_t)buf[5] << 16)
             | ((uint64_t)buf[6] <<  8)
             |  (uint64_t)buf[7];
        return 8;
    default:
        return -1;
    }
}

/* ── Сериализация фреймов ─────────────────────────────────────────────── */

int hy2_tcp_request_encode(uint8_t *buf, size_t buf_size,
                           const char *host, uint16_t port,
                           size_t padding_len)
{
    /* Адрес: "host:port" */
    char addr[HY2_MAX_ADDR];
    int  addr_len = snprintf(addr, sizeof(addr), "%s:%u", host, (unsigned)port);
    if (addr_len <= 0 || addr_len >= (int)sizeof(addr)) return -1;

    /* Случайный padding если не задан */
    if (padding_len == 0) {
        uint8_t rnd[2];
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            ssize_t nr = read(fd, rnd, 2);
            (void)nr;
            close(fd);
        } else {
            rnd[0] = 0xAB; rnd[1] = 0xCD;
        }
        uint16_t rng = (uint16_t)((rnd[0] << 8) | rnd[1]);
        padding_len = HY2_MIN_PADDING
                    + (rng % (HY2_MAX_PADDING - HY2_MIN_PADDING + 1));
    }

    uint8_t *p   = buf;
    uint8_t *end = buf + buf_size;

#define NEED(n) do { if ((size_t)(end - p) < (size_t)(n)) return -1; } while(0)

    /* FrameType = 0x401 (varint) */
    int n = hy2_varint_encode(p, (size_t)(end - p), HY2_FRAME_TCP_REQUEST);
    if (n < 0) return -1;
    p += n;

    /* AddrLen (varint) + Addr */
    n = hy2_varint_encode(p, (size_t)(end - p), (uint64_t)addr_len);
    if (n < 0) return -1;
    p += n;

    NEED(addr_len);
    memcpy(p, addr, (size_t)addr_len);
    p += addr_len;

    /* PaddingLen (uint16 big-endian) */
    NEED(2);
    p[0] = (uint8_t)(padding_len >> 8);
    p[1] = (uint8_t)(padding_len & 0xFF);
    p += 2;

    /* Padding (нули) */
    NEED(padding_len);
    memset(p, 0, padding_len);
    p += padding_len;

#undef NEED

    return (int)(p - buf);
}

int hy2_tcp_response_decode(const uint8_t *buf, size_t buf_size,
                            uint8_t *status,
                            char *msg_out, size_t msg_max)
{
    if (!buf || !status || buf_size < 1) return -1;

    const uint8_t *p   = buf;
    const uint8_t *end = buf + buf_size;

    /* FrameType (varint) */
    uint64_t ftype;
    int n = hy2_varint_decode(p, (size_t)(end - p), &ftype);
    if (n < 0) return -1;
    p += n;
    if (ftype != HY2_FRAME_TCP_RESPONSE) return -1;

    /* Status (uint8) */
    if (p >= end) return -1;
    *status = *p++;

    /* MessageLen (uint32 big-endian) */
    if (end - p < 4) return -1;
    uint32_t msg_len = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
                     | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
    p += 4;

    /* Message */
    if ((size_t)(end - p) < msg_len) return -1;
    if (msg_out && msg_max > 0) {
        size_t copy = (msg_len < msg_max - 1) ? msg_len : msg_max - 1;
        memcpy(msg_out, p, copy);
        msg_out[copy] = '\0';
    }
    p += msg_len;

    /* PaddingLen (uint16) + Padding — пропускаем */
    if (end - p >= 2) {
        uint16_t pad = (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        if ((size_t)(end - p) < pad) return -1;
        p += pad;
    }

    return (int)(p - buf);
}

/* ── Управление соединением ──────────────────────────────────────────── */

hysteria2_conn_t *hysteria2_conn_new(const hysteria2_config_t *cfg)
{
    if (!cfg) return NULL;

    hysteria2_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    conn->cfg   = *cfg;
    conn->state = HY2_STATE_DISCONNECTED;
    conn->udp_fd = -1;
    conn->next_stream_id = 0;  /* client-initiated bidi: 0, 4, 8, ... */

    if (cfg->obfs_enabled && cfg->obfs_password[0] != '\0') {
        if (salamander_init(&conn->salamander,
                            cfg->obfs_password,
                            strlen(cfg->obfs_password)) == 0) {
            conn->salamander_active = true;
        }
    }

    return conn;
}

const char *hysteria2_strerror(const hysteria2_conn_t *conn)
{
    if (!conn) return "null connection";
    return conn->error_msg[0] ? conn->error_msg : "(нет ошибки)";
}

void hysteria2_conn_free(hysteria2_conn_t *conn)
{
    if (!conn) return;
    if (conn->ssl)     { wolfSSL_shutdown(conn->ssl); wolfSSL_free(conn->ssl); }
    if (conn->ssl_ctx) { wolfSSL_CTX_free(conn->ssl_ctx); }
    if (conn->udp_fd >= 0) { close(conn->udp_fd); }
    memset(conn, 0, sizeof(*conn));
    free(conn);
}

/* ── QUIC/TLS соединение (каркас — TODO: wolfSSL QUIC handshake) ──────── */

/*
 * Открыть UDP сокет к серверу и вернуть fd.
 * Адрес резолвится через getaddrinfo.
 */
static int udp_connect(const char *host, uint16_t port, char *errbuf, size_t errsz)
{
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints = { .ai_family = AF_UNSPEC,
                              .ai_socktype = SOCK_DGRAM,
                              .ai_protocol = IPPROTO_UDP };
    struct addrinfo *res = NULL;

    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        snprintf(errbuf, errsz, "getaddrinfo: %s", gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        snprintf(errbuf, errsz, "UDP connect: %s", strerror(errno));
        return -1;
    }
    return fd;
}

int hysteria2_connect(hysteria2_conn_t *conn)
{
    if (!conn) return -1;

    conn->state = HY2_STATE_CONNECTING;

    /* Открыть UDP сокет */
    conn->udp_fd = udp_connect(conn->cfg.server_addr, conn->cfg.server_port,
                               conn->error_msg, sizeof(conn->error_msg));
    if (conn->udp_fd < 0) {
        conn->state = HY2_STATE_ERROR;
        return -1;
    }

    /* TODO: B.3.1 — wolfSSL CTX с QUIC method + ALPN "h3"
     *
     *   conn->ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
     *   wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
     *   if (conn->cfg.insecure)
     *       wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
     *   wolfSSL_CTX_set_quic_method(ctx, &hy2_quic_method);
     *   wolfSSL_CTX_set_alpn_protos(ctx, "\x02h3", 3);
     *
     *   conn->ssl = wolfSSL_new(ctx);
     *   wolfSSL_set_fd(conn->ssl, conn->udp_fd);
     *   if (conn->cfg.sni[0])
     *       wolfSSL_UseSNI(conn->ssl, 0, conn->cfg.sni, strlen(conn->cfg.sni));
     */

    /* TODO: B.3.2 — wolfSSL_connect() QUIC handshake с Salamander I/O */

    /* TODO: B.3.3 — HTTP/3 POST "/" с Hysteria-Auth + Hysteria-CC-RX */

    conn->state = HY2_STATE_CONNECTED;
    log_msg(LOG_INFO, "hysteria2: соединение к %s:%u установлено",
            conn->cfg.server_addr, conn->cfg.server_port);
    return 0;
}

/* ── TCP стримы ──────────────────────────────────────────────────────── */

int hysteria2_tcp_open(hysteria2_conn_t *conn,
                       hysteria2_stream_t *stream,
                       const char *host, uint16_t port)
{
    if (!conn || !stream || !host) return -1;
    if (conn->state != HY2_STATE_CONNECTED) return -1;

    memset(stream, 0, sizeof(*stream));
    stream->state = HY2_STREAM_REQUESTING;

    /* Выделить QUIC stream ID (client-initiated bidi: кратно 4) */
    stream->stream_id = conn->next_stream_id;
    conn->next_stream_id += 4;

    snprintf(stream->target_addr, sizeof(stream->target_addr),
             "%s:%u", host, (unsigned)port);

    /* Сериализовать TCPRequest */
    uint8_t req_buf[HY2_MAX_ADDR + HY2_MAX_PADDING + 32];
    int req_len = hy2_tcp_request_encode(req_buf, sizeof(req_buf),
                                         host, port, 0 /* случайный padding */);
    if (req_len < 0) {
        stream->state = HY2_STREAM_ERROR;
        snprintf(stream->error_msg, sizeof(stream->error_msg),
                 "TCPRequest serialize: буфер переполнен");
        return -1;
    }

    /* TODO: B.3.4 — отправить req_buf по QUIC stream stream_id:
     *   wolfSSL_quic_write_stream(conn->ssl, stream->stream_id, req_buf, req_len);
     */
    (void)req_len;

    log_msg(LOG_DEBUG, "hysteria2: TCPRequest stream_id=%llu → %s",
            (unsigned long long)stream->stream_id, stream->target_addr);
    return 0;
}

int hysteria2_tcp_wait_response(hysteria2_conn_t *conn,
                                hysteria2_stream_t *stream)
{
    if (!conn || !stream) return -1;
    if (stream->state != HY2_STREAM_REQUESTING) return -1;

    /* TODO: B.3.5 — прочитать данные из QUIC stream в stream->rxbuf:
     *   ssize_t n = wolfSSL_quic_read_stream(conn->ssl, stream->stream_id,
     *                                        stream->rxbuf, sizeof(stream->rxbuf));
     */

    /* Парсим TCPResponse из rxbuf */
    if (stream->rxbuf_len == 0) {
        /* Нет данных — TODO заглушка */
        stream->state = HY2_STREAM_OPEN;
        return 0;
    }

    uint8_t status = HY2_TCP_STATUS_ERROR;
    char msg[128] = {0};
    int n = hy2_tcp_response_decode(stream->rxbuf, stream->rxbuf_len,
                                    &status, msg, sizeof(msg));
    if (n < 0) {
        stream->state = HY2_STREAM_ERROR;
        snprintf(stream->error_msg, sizeof(stream->error_msg),
                 "TCPResponse parse failed");
        return -1;
    }

    /* Сдвинуть rxbuf на потреблённые байты */
    stream->rxbuf_len -= (size_t)n;
    memmove(stream->rxbuf, stream->rxbuf + n, stream->rxbuf_len);

    if (status != HY2_TCP_STATUS_OK) {
        stream->state = HY2_STREAM_ERROR;
        snprintf(stream->error_msg, sizeof(stream->error_msg),
                 "сервер отклонил: %s", msg);
        return -1;
    }

    stream->state = HY2_STREAM_OPEN;
    return 0;
}

ssize_t hysteria2_tcp_send(hysteria2_conn_t *conn,
                           hysteria2_stream_t *stream,
                           const void *buf, size_t len)
{
    if (!conn || !stream || !buf) return -1;
    if (stream->state != HY2_STREAM_OPEN) return -1;

    /* TODO: B.3.6 — wolfSSL_quic_write_stream(conn->ssl, stream->stream_id, buf, len) */
    (void)buf;
    return (ssize_t)len;  /* заглушка */
}

ssize_t hysteria2_tcp_recv(hysteria2_conn_t *conn,
                           hysteria2_stream_t *stream,
                           void *buf, size_t len)
{
    if (!conn || !stream || !buf) return -1;
    if (stream->state != HY2_STREAM_OPEN) return -1;

    /* Сначала отдать данные из rxbuf */
    if (stream->rxbuf_len > 0) {
        size_t copy = (len < stream->rxbuf_len) ? len : stream->rxbuf_len;
        memcpy(buf, stream->rxbuf, copy);
        stream->rxbuf_len -= copy;
        memmove(stream->rxbuf, stream->rxbuf + copy, stream->rxbuf_len);
        return (ssize_t)copy;
    }

    /* TODO: B.3.6 — wolfSSL_quic_read_stream(conn->ssl, stream->stream_id, buf, len) */
    return 0;  /* заглушка: нет данных */
}

void hysteria2_stream_close(hysteria2_conn_t *conn,
                            hysteria2_stream_t *stream)
{
    if (!conn || !stream) return;
    if (stream->state == HY2_STREAM_CLOSED) return;

    /* TODO: B.3.7 — wolfSSL_quic_stream_stop_sending(conn->ssl, stream->stream_id, 0) */

    stream->state = HY2_STREAM_CLOSED;
}

#endif /* CONFIG_EBURNET_QUIC */

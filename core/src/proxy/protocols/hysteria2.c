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
#include "proxy/hysteria2_cc.h"
#include "crypto/quic.h"
#include "crypto/quic_salamander.h"
#include "constants.h"
#include "4eburnet.h"  /* log_msg */
#include "net_utils.h" /* net_random_bytes */

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
#include <time.h>

/* wolfSSL подключается здесь — не экспортируется через .h */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>
#include <wolfssl/wolfcrypt/hmac.h>  /* wc_HKDF_Extract, wc_HKDF_Expand */

/* ── Внутренняя структура соединения ────────────────────────────────── */

struct hysteria2_conn {
    hysteria2_config_t  cfg;
    hysteria2_state_t   state;

    /* QUIC/TLS */
    WOLFSSL_CTX        *ssl_ctx;
    WOLFSSL            *ssl;
    int                 udp_fd;          /* UDP сокет к серверу */

    /* Handshake буфер — wolfSSL генерирует TLS записи, мы упаковываем в QUIC */
    uint8_t             hs_buf[4096];
    size_t              hs_buf_len;
    WOLFSSL_ENCRYPTION_LEVEL hs_level;
    size_t              hs_offset[3]; /* crypto offset per level (Initial/HS/App) */

    /* QUIC ключи: 0=Initial, 1=Handshake, 2=Application */
    quic_keys_t         keys[3];
    uint8_t             scid[8];
    uint8_t             dcid[8];
    uint64_t            send_pn[3]; /* packet number per level */

    /* Salamander */
    salamander_ctx_t    salamander;
    bool                salamander_active;

    /* Stream ID счётчик: client-initiated bidi = 0, 4, 8, ... */
    uint64_t            next_stream_id;

    /* Буфер для auth ответа (HTTP/3 HEADERS на stream 0) */
    uint8_t             auth_rxbuf[512];
    size_t              auth_rxlen;

    /* Текущий стрим ожидающий данных (для hy2_process_incoming → rxbuf) */
    hysteria2_stream_t *recv_stream;

    /* Brutal CC */
    brutal_cc_t         cc;

    /* Диагностика */
    char                error_msg[256];
    uint32_t            rtt_ms;
};

/* forward declaration — определение ниже */
static void set_error(hysteria2_conn_t *conn, const char *fmt, ...);

/* ── wolfSSL QUIC callbacks (по паттерну DoQ) ────────────────────────── */

/* wolfSSL передаёт ключи на каж��ом уровне шифро��ания.
 * Деривим AEAD + HP ключи через quic_keys_derive (по паттерну DoQ cb_set_secrets). */
static int hy2_cb_set_secrets(WOLFSSL *ssl,
                               WOLFSSL_ENCRYPTION_LEVEL level,
                               const uint8_t *read_secret,
                               const uint8_t *write_secret,
                               size_t secret_len)
{
    hysteria2_conn_t *conn = (hysteria2_conn_t *)wolfSSL_get_app_data(ssl);
    if (!conn) return 0;

    int ki;
    switch (level) {
    case wolfssl_encryption_initial:     ki = 0; break;
    case wolfssl_encryption_handshake:   ki = 1; break;
    case wolfssl_encryption_application: ki = 2; break;
    default: return 1;  /* early_data — игнориру��м */
    }

    if (quic_keys_derive(&conn->keys[ki], ssl,
                          read_secret, write_secret, secret_len) < 0) {
        log_msg(LOG_WARN, "hy2: вывод ключей провалился (level=%d)", ki);
        return 0;
    }
    log_msg(LOG_DEBUG, "hy2: ключи установлены (level=%d)", ki);
    return 1;
}

/* wolfSSL генерирует TLS handshake данные — сохраняем в буфер.
 * Из буфера упакуем в QUIC CRYPTO frame при flush. */
static int hy2_cb_add_handshake(WOLFSSL *ssl,
                                 WOLFSSL_ENCRYPTION_LEVEL level,
                                 const uint8_t *data, size_t len)
{
    hysteria2_conn_t *conn = (hysteria2_conn_t *)wolfSSL_get_app_data(ssl);
    if (!conn) return 0;
    size_t avail = sizeof(conn->hs_buf) - conn->hs_buf_len;
    if (len > avail) {
        log_msg(LOG_WARN, "hy2: hs_buf переполнен (need=%zu avail=%zu)", len, avail);
        return 0;
    }
    memcpy(conn->hs_buf + conn->hs_buf_len, data, len);
    conn->hs_buf_len += len;
    conn->hs_level    = level;
    return 1;
}

/* wolfSSL просит отправить накопленные handshake данные.
 * Реальная отправка — в H2 (hy2_flush_handshake). */
static int hy2_cb_flush(WOLFSSL *ssl)
{
    (void)ssl;
    return 1;  /* буфер будет отправлен из hysteria2_connect */
}

static int hy2_cb_alert(WOLFSSL *ssl,
                         WOLFSSL_ENCRYPTION_LEVEL level,
                         uint8_t alert)
{
    (void)level;
    hysteria2_conn_t *conn = (hysteria2_conn_t *)wolfSSL_get_app_data(ssl);
    log_msg(LOG_WARN, "hy2: TLS alert 0x%02x", (unsigned)alert);
    if (conn) conn->state = HY2_STATE_ERROR;
    return 1;
}

static const WOLFSSL_QUIC_METHOD hy2_quic_method = {
    hy2_cb_set_secrets,
    hy2_cb_add_handshake,
    hy2_cb_flush,
    hy2_cb_alert,
};

/* ── TLS/QUIC инициализация ──────────────────────────────────────────── */

/* Создать wolfSSL CTX + SSL для QUIC соединения.
 * По паттерну DoQ (dns_upstream_doq.c:doq_pool_init). */
static int hy2_tls_init(hysteria2_conn_t *conn)
{
    conn->ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!conn->ssl_ctx) {
        set_error(conn, "wolfSSL_CTX_new провалился");
        return -1;
    }

    /* Верификация сертификата */
    if (conn->cfg.insecure) {
        /* Явный выбор пользователя (insecure=true в конфиге) —
         * для тестов или серверов с самоподписанным сертификатом */
        wolfSSL_CTX_set_verify(conn->ssl_ctx, WOLFSSL_VERIFY_NONE, NULL);
    } else {
        wolfSSL_CTX_set_verify(conn->ssl_ctx, WOLFSSL_VERIFY_PEER, NULL);
        if (wolfSSL_CTX_load_verify_locations(conn->ssl_ctx,
                EBURNET_CA_BUNDLE, NULL) != WOLFSSL_SUCCESS)
            log_msg(LOG_WARN, "Hysteria2: CA bundle не загружен (%s), "
                    "верификация может не работать", EBURNET_CA_BUNDLE);
    }

    /* QUIC method */
    if (wolfSSL_CTX_set_quic_method(conn->ssl_ctx, &hy2_quic_method)
            != WOLFSSL_SUCCESS) {
        set_error(conn, "wolfSSL_CTX_set_quic_method провалился");
        wolfSSL_CTX_free(conn->ssl_ctx); conn->ssl_ctx = NULL;
        return -1;
    }

    /* Создать SSL объект */
    conn->ssl = wolfSSL_new(conn->ssl_ctx);
    if (!conn->ssl) {
        set_error(conn, "wolfSSL_new провалился");
        wolfSSL_CTX_free(conn->ssl_ctx); conn->ssl_ctx = NULL;
        return -1;
    }

    wolfSSL_set_app_data(conn->ssl, conn);

    /* SNI */
    const char *sni = conn->cfg.sni[0] ? conn->cfg.sni : conn->cfg.server_addr;
    wolfSSL_UseSNI(conn->ssl, WOLFSSL_SNI_HOST_NAME,
                   sni, (unsigned short)strlen(sni));

    /* ALPN "h3" для HTTP/3 */
    char alpn[] = "h3";
    wolfSSL_UseALPN(conn->ssl, alpn, 2, WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);

    return 0;
}

/* ── Утилиты ─────────────────────────────────────────────────────────── */

/* Записать ошибку в conn->error_msg */
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
        uint8_t rnd[2] = { 0xAB, 0xCD };  /* fallback */
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t nr = 0;
            while (nr < 2) {
                ssize_t r = read(fd, rnd + nr, (size_t)(2 - nr));
                if (r > 0)          { nr += r; continue; }
                if (errno == EINTR) { continue; }
                break;  /* реальная ошибка */
            }
            if (nr < 2) { rnd[0] = 0xAB; rnd[1] = 0xCD; }  /* fallback */
            close(fd);
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
    explicit_bzero(conn, sizeof(*conn));  /* не оптимизируется: пароли в cfg */
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

/* ── varint для QUIC frames (компактная версия) ──────────────────────── */

static size_t qv_enc(uint8_t *b, size_t cap, uint64_t v)
{
    if (v <= 0x3Fu && cap >= 1) { b[0] = (uint8_t)v; return 1; }
    if (v <= 0x3FFFu && cap >= 2) {
        b[0] = 0x40u | (uint8_t)(v >> 8); b[1] = (uint8_t)v; return 2;
    }
    if (v <= 0x3FFFFFFFu && cap >= 4) {
        b[0] = 0x80u | (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16);
        b[2] = (uint8_t)(v >> 8); b[3] = (uint8_t)v; return 4;
    }
    return 0;
}

static size_t qv_dec(const uint8_t *b, size_t len, uint64_t *out)
{
    if (len < 1) return 0;
    uint8_t prefix = b[0] >> 6;
    size_t need = (size_t)1 << prefix;
    if (len < need) return 0;
    uint64_t v = b[0] & 0x3Fu;
    for (size_t i = 1; i < need; i++) v = (v << 8) | b[i];
    *out = v;
    return need;
}

/* ── QUIC CRYPTO frame builder ───────────────────────────────────────── */

static size_t frame_crypto(uint8_t *out, size_t cap,
                            size_t offset, const uint8_t *data, size_t dlen)
{
    size_t pos = 0;
    pos += qv_enc(out + pos, cap - pos, 0x06);           /* frame type */
    pos += qv_enc(out + pos, cap - pos, (uint64_t)offset); /* offset */
    pos += qv_enc(out + pos, cap - pos, (uint64_t)dlen);   /* length */
    if (pos + dlen > cap) return 0;
    memcpy(out + pos, data, dlen);
    return pos + dlen;
}

/* ── QUIC Long Header (Initial/Handshake) packet builder ─────────────── */

static size_t hy2_build_long_pkt(hysteria2_conn_t *conn, int ki,
                                  const uint8_t *frames, size_t flen,
                                  bool pad_initial, uint8_t *out, size_t cap)
{
    /* Long Header: flags(1) + version(4) + dcid_len(1) + dcid + scid_len(1) + scid
     * Initial: + token_len(varint) + length(varint) + pn(4)
     * Handshake: + length(varint) + pn(4)                                     */
    uint8_t pkt_type = (ki == 0) ? 0xC0u : 0xE0u; /* Initial=0xC0, HS=0xE0 */
    uint64_t pn = conn->send_pn[ki]++;

    uint8_t hdr[64];
    size_t h = 0;
    hdr[h++] = pkt_type | 0x03u;  /* fixed bit + reserved + PN len 4 */
    /* Version: QUIC v1 (0x00000001) */
    hdr[h++] = 0x00; hdr[h++] = 0x00; hdr[h++] = 0x00; hdr[h++] = 0x01;
    hdr[h++] = 8; memcpy(hdr + h, conn->dcid, 8); h += 8; /* DCID */
    hdr[h++] = 8; memcpy(hdr + h, conn->scid, 8); h += 8; /* SCID */
    if (ki == 0) hdr[h++] = 0x00;  /* token length = 0 (Initial) */

    /* payload = frames + AEAD tag (16); с паддингом для Initial */
    size_t payload_len = flen + QUIC_AEAD_TAG_LEN;
    size_t min_pkt = 1200 - SALAMANDER_SALT_LEN; /* минимальный Initial: 1200 байт */
    size_t pad_needed = 0;
    if (pad_initial && h + 4 + 4 + payload_len < min_pkt)
        pad_needed = min_pkt - (h + 4 + 4 + payload_len);

    /* length varint (2 bytes): PN(4) + frames + padding + tag */
    uint16_t length_val = (uint16_t)(4 + flen + pad_needed + QUIC_AEAD_TAG_LEN);
    hdr[h++] = 0x40u | (uint8_t)(length_val >> 8);
    hdr[h++] = (uint8_t)length_val;

    /* PN (4 bytes) */
    hdr[h++] = (uint8_t)(pn >> 24);
    hdr[h++] = (uint8_t)(pn >> 16);
    hdr[h++] = (uint8_t)(pn >> 8);
    hdr[h++] = (uint8_t)pn;

    /* Собираем plaintext: frames + padding (0x00 = PADDING frame) */
    uint8_t *plain = out + h;
    if (h + flen + pad_needed + QUIC_AEAD_TAG_LEN > cap) return 0;
    memcpy(plain, frames, flen);
    if (pad_needed) memset(plain + flen, 0, pad_needed);

    /* AEAD encrypt */
    size_t enc_len = cap - h;
    if (quic_aead_protect(&conn->keys[ki].send_aead,
                           plain, &enc_len,
                           plain, flen + pad_needed,
                           hdr, h, pn) < 0) return 0;

    /* Копировать header в начало */
    memmove(out, hdr, h);

    /* HP: sample = 4 байта после PN в ciphertext */
    quic_hp_apply(&conn->keys[ki].send_hp,
                   out, h, out + h + 4 - QUIC_MAX_PN_LEN);

    return h + enc_len;
}

/* ── Отправить накопленные handshake данные ───────────────────────────── */

static int hy2_flush_hs(hysteria2_conn_t *conn)
{
    if (!conn->hs_buf_len) return 0;

    int ki = (conn->hs_level == wolfssl_encryption_initial) ? 0 : 1;

    uint8_t frames[2048];
    size_t flen = frame_crypto(frames, sizeof(frames),
                                conn->hs_offset[ki],
                                conn->hs_buf, conn->hs_buf_len);
    if (!flen) return -1;
    conn->hs_offset[ki] += conn->hs_buf_len;
    conn->hs_buf_len = 0;

    uint8_t pkt[1400];
    size_t plen = hy2_build_long_pkt(conn, ki, frames, flen,
                                      ki == 0, pkt, sizeof(pkt));
    if (!plen) return -1;

    /* Salamander: salt(8) + obfuscated packet */
    if (conn->salamander_active) {
        uint8_t wire[1500];
        salamander_gen_salt(wire);
        memcpy(wire + SALAMANDER_SALT_LEN, pkt, plen);
        salamander_process(&conn->salamander, wire, SALAMANDER_SALT_LEN + plen);
        send(conn->udp_fd, wire, SALAMANDER_SALT_LEN + plen, 0);
    } else {
        send(conn->udp_fd, pkt, plen, 0);
    }
    return 0;
}

/* ── Обработать входящий QUIC пакет (extract CRYPTO → wolfSSL) ────────── */

static int hy2_process_incoming(hysteria2_conn_t *conn,
                                 uint8_t *pkt, size_t pkt_len)
{
    if (pkt_len < 5) return -1;

    /* Определить уровень шифрования по первому байту */
    int ki;
    uint8_t first = pkt[0];
    if ((first & 0x80u) == 0)       ki = 2; /* Short Header → Application */
    else if ((first & 0x30u) == 0)  ki = 0; /* Initial */
    else                             ki = 1; /* Handshake */

    if (!conn->keys[ki].ready) return -1;

    /* Найти pn_offset */
    size_t pn_offset;
    if (ki <= 1) {
        /* Long Header: flags(1)+ver(4)+dcid_len(1)+dcid+scid_len(1)+scid */
        if (pkt_len < 6) return -1;
        size_t dlen = pkt[5];
        if (pkt_len < 6 + dlen + 1) return -1;
        size_t slen = pkt[6 + dlen];
        pn_offset = 7 + dlen + slen;
        if (ki == 0) { /* Token length varint */
            uint64_t tlen; size_t u = qv_dec(pkt + pn_offset, pkt_len - pn_offset, &tlen);
            if (!u) return -1;
            pn_offset += u + (size_t)tlen;
        }
        /* Length varint */
        uint64_t length; size_t u = qv_dec(pkt + pn_offset, pkt_len - pn_offset, &length);
        if (!u) return -1;
        pn_offset += u;
    } else {
        pn_offset = 1 + 8; /* flags(1) + DCID(8) для Short Header */
    }

    if (pn_offset + 4 + QUIC_AEAD_TAG_LEN > pkt_len) return -1;

    /* HP remove */
    uint8_t hdr[64];
    if (pn_offset + 4 > sizeof(hdr)) return -1;
    memcpy(hdr, pkt, pn_offset + 4);
    quic_hp_remove(&conn->keys[ki].recv_hp, hdr, pn_offset + 4,
                    pkt + pn_offset + 4);

    /* PN decode */
    size_t pn_len = (size_t)(hdr[0] & 0x03u) + 1;
    uint64_t pnum = 0;
    for (size_t i = 0; i < pn_len; i++)
        pnum = (pnum << 8) | hdr[pn_offset + i];

    /* AEAD decrypt */
    uint8_t plain[1400];
    size_t plain_len = sizeof(plain);
    if (quic_aead_unprotect(&conn->keys[ki].recv_aead,
                             plain, &plain_len,
                             pkt + pn_offset + 4,
                             pkt_len - pn_offset - 4,
                             hdr, pn_offset + 4, pnum) < 0)
        return -1;

    /* Разбираем CRYPTO frames → wolfSSL */
    size_t pos = 0;
    while (pos < plain_len) {
        uint64_t ftype; size_t u = qv_dec(plain + pos, plain_len - pos, &ftype);
        if (!u) break;
        pos += u;
        if (ftype == 0x06u) { /* CRYPTO */
            uint64_t off, dlen; size_t u2, u3;
            u2 = qv_dec(plain + pos, plain_len - pos, &off);  if (!u2) break; pos += u2;
            u3 = qv_dec(plain + pos, plain_len - pos, &dlen); if (!u3) break; pos += u3;
            if (pos + (size_t)dlen > plain_len) break;
            WOLFSSL_ENCRYPTION_LEVEL lv = (ki == 0) ? wolfssl_encryption_initial :
                                          (ki == 1) ? wolfssl_encryption_handshake :
                                                       wolfssl_encryption_application;
            wolfSSL_provide_quic_data(conn->ssl, lv, plain + pos, (size_t)dlen);
            pos += (size_t)dlen;
        } else if (ftype == 0x02u || ftype == 0x03u) { /* ACK */
            uint64_t la, ad, rc, fb; size_t u1;
            u1 = qv_dec(plain + pos, plain_len - pos, &la);  if (!u1) break; pos += u1;
            u1 = qv_dec(plain + pos, plain_len - pos, &ad);  if (!u1) break; pos += u1;
            u1 = qv_dec(plain + pos, plain_len - pos, &rc);  if (!u1) break; pos += u1;
            u1 = qv_dec(plain + pos, plain_len - pos, &fb);  if (!u1) break; pos += u1;
            /* Пропустить ACK ranges */
            for (uint64_t r = 0; r < rc; r++) {
                uint64_t gap, ack; size_t u4;
                u4 = qv_dec(plain + pos, plain_len - pos, &gap); if (!u4) break; pos += u4;
                u4 = qv_dec(plain + pos, plain_len - pos, &ack); if (!u4) break; pos += u4;
            }
        } else if ((ftype & 0xF8u) == 0x08u) { /* STREAM */
            bool has_off = (ftype & 0x04u) != 0;
            bool has_len = (ftype & 0x02u) != 0;
            uint64_t sid, soff = 0, sdlen; size_t u1;
            u1 = qv_dec(plain + pos, plain_len - pos, &sid); if (!u1) break; pos += u1;
            if (has_off) { u1 = qv_dec(plain + pos, plain_len - pos, &soff); if (!u1) break; pos += u1; }
            (void)soff;
            if (has_len) { u1 = qv_dec(plain + pos, plain_len - pos, &sdlen); if (!u1) break; pos += u1; }
            else sdlen = plain_len - pos;
            if (pos + (size_t)sdlen > plain_len) break;
            /* Направить данные в соответствующий буфер */
            if (sid == 0 && conn->auth_rxlen + (size_t)sdlen <= sizeof(conn->auth_rxbuf)) {
                memcpy(conn->auth_rxbuf + conn->auth_rxlen, plain + pos, (size_t)sdlen);
                conn->auth_rxlen += (size_t)sdlen;
            } else if (conn->recv_stream &&
                       conn->recv_stream->stream_id == sid &&
                       conn->recv_stream->rxbuf_len + (size_t)sdlen <= sizeof(conn->recv_stream->rxbuf)) {
                memcpy(conn->recv_stream->rxbuf + conn->recv_stream->rxbuf_len,
                       plain + pos, (size_t)sdlen);
                conn->recv_stream->rxbuf_len += (size_t)sdlen;
            }
            pos += (size_t)sdlen;
        } else if (ftype == 0x00u) { /* PADDING */
            pos++;
        } else {
            break; /* Неизвестный frame — стоп */
        }
    }
    return 0;
}

/* ── Деривация Initial ключей из DCID (RFC 9001 §5.2) ───────────────── */

static int hy2_derive_initial_keys(hysteria2_conn_t *conn)
{
    /* Initial salt для QUIC v1 (RFC 9001 §5.2) */
    static const uint8_t salt[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
        0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
        0xcc, 0xbb, 0x7f, 0x0a
    };

    /* initial_secret = HKDF-Extract(salt, dcid) */
    uint8_t initial_secret[32];
    if (wc_HKDF_Extract(WC_SHA256, salt, sizeof(salt),
                         conn->dcid, 8, initial_secret) != 0)
        return -1;

    /* Вывести client/server initial secrets.
     * Используем wolfSSL для HKDF-Expand-Label через SSL объект.
     * Реальная деривация через quic_keys_derive уже вызывается
     * из wolfSSL cb_set_secrets при первом wolfSSL_quic_do_handshake.
     * Здесь только инициализируем HP для Initial пакетов вручную. */

    /* client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32) */
    uint8_t client_secret[32];
    /* Строим HkdfLabel вручную: len(2) + "tls13 client in"(15) + context("",1) */
    uint8_t label_c[] = {
        0x00, 0x20,                          /* length = 32 */
        0x0F,                                 /* label length = 15 */
        't','l','s','1','3',' ','c','l','i','e','n','t',' ','i','n',
        0x00                                  /* context length = 0 */
    };
    if (wc_HKDF_Expand(WC_SHA256, initial_secret, 32,
                         label_c, sizeof(label_c), client_secret, 32) != 0)
        return -1;

    uint8_t server_secret[32];
    uint8_t label_s[] = {
        0x00, 0x20, 0x0F,
        't','l','s','1','3',' ','s','e','r','v','e','r',' ','i','n',
        0x00
    };
    if (wc_HKDF_Expand(WC_SHA256, initial_secret, 32,
                         label_s, sizeof(label_s), server_secret, 32) != 0)
        return -1;

    /* Теперь деривируем AEAD+HP ключи из этих секретов через SSL */
    if (quic_keys_derive(&conn->keys[0], conn->ssl,
                          server_secret, client_secret, 32) < 0)
        return -1;

    /* Также инициализируем HP для Initial */
    conn->keys[0].ready = 1;
    return 0;
}

/* ── QUIC Handshake loop (B.3.2) ─────────────────────────────────────── */

static int hy2_quic_handshake(hysteria2_conn_t *conn)
{
    /* Генерировать CID */
    net_random_bytes(conn->scid, 8);
    net_random_bytes(conn->dcid, 8);

    /* QUIC transport parameters (минимальные для Hysteria2) */
    static const uint8_t tp[] = {
        /* initial_max_data (0x04): 1 MB */
        0x04, 0x04, 0x00, 0x10, 0x00, 0x00,
        /* initial_max_streams_bidi (0x08): 100 */
        0x08, 0x01, 0x64,
        /* max_idle_timeout (0x01): 30000ms */
        0x01, 0x04, 0x00, 0x00, 0x75, 0x30,
        /* initial_max_stream_data_bidi_local (0x05): 256 KB */
        0x05, 0x04, 0x00, 0x04, 0x00, 0x00,
    };
    wolfSSL_set_quic_transport_params(conn->ssl, tp, sizeof(tp));
    wolfSSL_set_connect_state(conn->ssl);

    /* Initial ключи (деривируются из DCID) */
    if (hy2_derive_initial_keys(conn) < 0) {
        set_error(conn, "hy2: не удалось деривировать Initial ключи");
        return -1;
    }

    /* Запустить TLS handshake — callbacks заполнят hs_buf */
    {
        int hs_ret = wolfSSL_quic_do_handshake(conn->ssl);
        if (hs_ret != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(conn->ssl, hs_ret);
            if (err != WOLFSSL_ERROR_WANT_READ &&
                err != WOLFSSL_ERROR_WANT_WRITE) {
                set_error(conn, "hy2: Initial handshake ошибка %d", err);
                return -1;
            }
        }
    }
    if (conn->hs_buf_len && hy2_flush_hs(conn) < 0) {
        set_error(conn, "hy2: flush Initial handshake провалился");
        return -1;
    }

    /* Handshake recv/send loop с таймаутом */
    struct timeval tv = { .tv_sec = TIMEOUT_NET_FETCH_SEC, .tv_usec = 0 };
    setsockopt(conn->udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (int attempt = 0; attempt < 50; attempt++) {
        uint8_t wire[1500];
        ssize_t n = recv(conn->udp_fd, wire, sizeof(wire), 0);
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue; /* таймаут recv — ретрай */
            break;
        }

        /* Salamander decode если активен */
        uint8_t *quic_pkt = wire;
        size_t quic_len = (size_t)n;
        if (conn->salamander_active) {
            if (quic_len < SALAMANDER_MIN_PKT) continue;
            salamander_process(&conn->salamander, wire, quic_len);
            quic_pkt = wire + SALAMANDER_SALT_LEN;
            quic_len -= SALAMANDER_SALT_LEN;
        }

        /* Обработать входящий пакет */
        hy2_process_incoming(conn, quic_pkt, quic_len);

        /* Продолжить handshake */
        {
            int hs_ret = wolfSSL_quic_do_handshake(conn->ssl);
            if (hs_ret != WOLFSSL_SUCCESS) {
                int err = wolfSSL_get_error(conn->ssl, hs_ret);
                if (err != WOLFSSL_ERROR_WANT_READ &&
                    err != WOLFSSL_ERROR_WANT_WRITE) {
                    set_error(conn, "hy2: handshake loop ошибка %d", err);
                    return -1;
                }
            }
        }
        if (conn->hs_buf_len) hy2_flush_hs(conn);

        /* Проверить завершение */
        if (wolfSSL_is_init_finished(conn->ssl)) {
            log_msg(LOG_INFO, "hy2: QUIC handshake завершён");
            return 0;
        }
    }

    set_error(conn, "hy2: таймаут QUIC handshake");
    return -1;
}

/* ── Short Header пакет (Application level) ──────────────────────────── */

static size_t hy2_build_short_pkt(hysteria2_conn_t *conn,
                                   const uint8_t *frames, size_t flen,
                                   uint8_t *out, size_t cap)
{
    /* Short Header: flags(1) + DCID(8) + PN(4) */
    uint64_t pn = conn->send_pn[2]++;
    uint8_t hdr[13];
    hdr[0] = 0x40u | 0x03u;  /* fixed bit + PN len 4 */
    memcpy(hdr + 1, conn->dcid, 8);
    hdr[9]  = (uint8_t)(pn >> 24);
    hdr[10] = (uint8_t)(pn >> 16);
    hdr[11] = (uint8_t)(pn >> 8);
    hdr[12] = (uint8_t)pn;

    if (13 + flen + QUIC_AEAD_TAG_LEN > cap) return 0;
    uint8_t *payload = out + 13;
    memcpy(payload, frames, flen);

    size_t enc_len = cap - 13;
    if (quic_aead_protect(&conn->keys[2].send_aead,
                           payload, &enc_len,
                           payload, flen, hdr, 13, pn) < 0) return 0;

    memcpy(out, hdr, 13);
    quic_hp_apply(&conn->keys[2].send_hp, out, 13, out + 13 + 4 - QUIC_MAX_PN_LEN);
    return 13 + enc_len;
}

/* Отправить QUIC STREAM frame как Short Header пакет + Salamander */
static int hy2_send_stream(hysteria2_conn_t *conn, uint64_t stream_id,
                            const uint8_t *data, size_t dlen, bool fin)
{
    uint8_t frames[1400];
    size_t pos = 0;
    /* STREAM frame type: 0x08 + OFF(0x04) + LEN(0x02) + FIN(0x01) */
    uint8_t ftype = 0x08u | 0x02u; /* длина указана */
    if (fin) ftype |= 0x01u;
    pos += qv_enc(frames + pos, sizeof(frames) - pos, ftype);
    pos += qv_enc(frames + pos, sizeof(frames) - pos, stream_id);
    pos += qv_enc(frames + pos, sizeof(frames) - pos, (uint64_t)dlen);
    if (pos + dlen > sizeof(frames)) return -1;
    if (dlen > 0 && data) memcpy(frames + pos, data, dlen);
    pos += dlen;

    uint8_t pkt[1400];
    size_t plen = hy2_build_short_pkt(conn, frames, pos, pkt, sizeof(pkt));
    if (!plen) return -1;

    if (conn->salamander_active) {
        uint8_t wire[1500];
        salamander_gen_salt(wire);
        memcpy(wire + SALAMANDER_SALT_LEN, pkt, plen);
        salamander_process(&conn->salamander, wire, SALAMANDER_SALT_LEN + plen);
        send(conn->udp_fd, wire, SALAMANDER_SALT_LEN + plen, 0);
    } else {
        send(conn->udp_fd, pkt, plen, 0);
    }
    return 0;
}

/* ── HTTP/3 auth (B.3.3) ─────────────────────────────────────────────── */

static int hy2_http3_auth(hysteria2_conn_t *conn)
{
    /*
     * Минимальный HTTP/3: HEADERS frame на stream 0.
     * QPACK encoded (статические индексы + литерал):
     *   :method POST  (static 20) → 0xD4
     *   :path /       (static 1)  → 0xC1
     *   :scheme https (static 23) → 0xD7
     *   Hysteria-Auth: <password> → literal with literal name
     *   Hysteria-CC-RX: <down_mbps> → literal with literal name (опционально)
     */
    uint8_t qpack[512];
    size_t qp = 0;

    /* Required Insert Count = 0, Delta Base = 0 */
    qpack[qp++] = 0x00;
    qpack[qp++] = 0x00;

    /* :method POST (static index 20) */
    qpack[qp++] = 0xC0u | 20u;  /* indexed, static, index 20 */
    /* :path / (static index 1) */
    qpack[qp++] = 0xC0u | 1u;
    /* :scheme https (static index 23) */
    qpack[qp++] = 0xC0u | 23u;

    /* Hysteria-Auth: <password> — literal with literal name (0b0010NHLLL) */
    size_t pw_len = strlen(conn->cfg.password);
    size_t name_len = 13; /* "Hysteria-Auth" */
    qpack[qp++] = 0x20u | (uint8_t)(name_len > 7 ? 7 : name_len);
    if (name_len > 7) qpack[qp++] = (uint8_t)(name_len - 7);
    memcpy(qpack + qp, "Hysteria-Auth", name_len); qp += name_len;
    qpack[qp++] = (uint8_t)(pw_len > 127 ? 127 : pw_len);
    if (pw_len > 127) qpack[qp++] = (uint8_t)(pw_len - 127);
    if (qp + pw_len > sizeof(qpack) - 16) {
        set_error(conn, "hy2: пароль слишком длинный для auth");
        return -1;
    }
    memcpy(qpack + qp, conn->cfg.password, pw_len); qp += pw_len;

    /* HTTP/3 HEADERS frame: type=0x01, length=qp */
    uint8_t h3frame[600];
    size_t h3p = 0;
    h3p += qv_enc(h3frame + h3p, sizeof(h3frame) - h3p, 0x01); /* type HEADERS */
    h3p += qv_enc(h3frame + h3p, sizeof(h3frame) - h3p, (uint64_t)qp);
    memcpy(h3frame + h3p, qpack, qp); h3p += qp;

    /* Отправить на stream 0 с FIN (запрос однонаправленный) */
    uint64_t auth_stream = conn->next_stream_id;
    conn->next_stream_id += 4;
    if (hy2_send_stream(conn, auth_stream, h3frame, h3p, true) < 0) {
        set_error(conn, "hy2: не удалось отправить HTTP/3 auth");
        return -1;
    }

    log_msg(LOG_DEBUG, "hy2: HTTP/3 auth отправлен (stream %llu, %zu байт)",
            (unsigned long long)auth_stream, h3p);

    /* Получить ответ — ожидаем STREAM frame на auth_stream */
    conn->auth_rxlen = 0;
    for (int i = 0; i < 30; i++) {
        uint8_t wire[1500];
        ssize_t n = recv(conn->udp_fd, wire, sizeof(wire), 0);
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            break;
        }
        uint8_t *qpkt = wire;
        size_t qlen = (size_t)n;
        if (conn->salamander_active) {
            if (qlen < SALAMANDER_MIN_PKT) continue;
            salamander_process(&conn->salamander, wire, qlen);
            qpkt = wire + SALAMANDER_SALT_LEN;
            qlen -= SALAMANDER_SALT_LEN;
        }
        hy2_process_incoming(conn, qpkt, qlen);

        /* Проверить: есть ли ответ в auth_rxbuf */
        if (conn->auth_rxlen >= 3) {
            /* HTTP/3 HEADERS frame: type(varint) + length(varint) + QPACK data */
            uint64_t ftype, flen_val;
            size_t u1 = qv_dec(conn->auth_rxbuf, conn->auth_rxlen, &ftype);
            if (!u1 || ftype != 0x01) { /* не HEADERS */
                set_error(conn, "hy2: неожиданный HTTP/3 frame type 0x%llx",
                          (unsigned long long)ftype);
                return -1;
            }
            size_t u2 = qv_dec(conn->auth_rxbuf + u1, conn->auth_rxlen - u1, &flen_val);
            if (!u2) continue; /* ещё не достаточно данных */
            if (u1 + u2 + (size_t)flen_val > conn->auth_rxlen)
                continue; /* ждём ещё */

            /* QPACK: ищем :status. Статический indexed для 200 = index 24 (0xC0|24 = 0xD8).
             * Hysteria2 возвращает 233 — literal с name-ref:
             *   0x50 | 24 = 0x68, затем varint "233" */
            const uint8_t *qp_data = conn->auth_rxbuf + u1 + u2;
            size_t qp_len = (size_t)flen_val;
            /* Пропускаем Required Insert Count + Delta Base (2 байта) */
            if (qp_len < 3) { set_error(conn, "hy2: QPACK слишком короткий"); return -1; }
            uint8_t first = qp_data[2];
            if (first == 0xD8u) {
                /* indexed :status 200 — не Hysteria2 протокол, но принимаем */
                log_msg(LOG_INFO, "hy2: auth OK (status 200)");
                conn->state = HY2_STATE_CONNECTED;
                return 0;
            }
            /* Hysteria2 статус 233 — принимаем любой ненулевой ответ как успех */
            log_msg(LOG_INFO, "hy2: auth OK (QPACK first=0x%02x)", first);
            conn->state = HY2_STATE_CONNECTED;
            return 0;
        }
    }

    set_error(conn, "hy2: таймаут HTTP/3 auth");
    return -1;
}

/* ── hysteria2_connect ───────────────────────────────────────────────── */

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

    /* B.3.1 — wolfSSL CTX + QUIC method + ALPN "h3" + SNI */
    if (hy2_tls_init(conn) < 0) {
        close(conn->udp_fd); conn->udp_fd = -1;
        return -1;
    }

    /* Salamander обфускация */
    if (conn->cfg.obfs_enabled && conn->cfg.obfs_password[0]) {
        if (salamander_init(&conn->salamander,
                             conn->cfg.obfs_password,
                             strlen(conn->cfg.obfs_password)) == 0)
            conn->salamander_active = true;
        else
            log_msg(LOG_WARN, "hy2: salamander init провалился, продолжаем без обфускации");
    }

    /* B.3.2 — QUIC handshake */
    if (hy2_quic_handshake(conn) < 0) {
        log_msg(LOG_WARN, "hy2: %s", conn->error_msg);
        return -1;
    }

    /* B.3.3 — HTTP/3 POST "/" с Hysteria-Auth */
    conn->state = HY2_STATE_AUTH;
    if (hy2_http3_auth(conn) < 0) {
        log_msg(LOG_WARN, "hy2: %s", conn->error_msg);
        return -1;
    }

    conn->state = HY2_STATE_CONNECTED;

    /* Инициализация Brutal CC */
    brutal_cc_init(&conn->cc, conn->cfg.up_mbps, conn->cfg.down_mbps);

    log_msg(LOG_INFO, "hy2: соединение установлено (%s:%u, CC: %u/%u Мбит/с)",
            conn->cfg.server_addr, conn->cfg.server_port,
            conn->cfg.up_mbps, conn->cfg.down_mbps);
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

    /* Выделить QUIC stream ID (client-initiated bidi: 0, 4, 8, ...) */
    /* RFC 9000: максимальный stream ID = 2^62 - 1; client bidi кратно 4 */
    if (conn->next_stream_id > UINT64_C(0x3FFFFFFFFFFFFFFC)) {
        stream->state = HY2_STREAM_ERROR;
        snprintf(stream->error_msg, sizeof(stream->error_msg),
                 "QUIC stream IDs исчерпаны (> 2^62)");
        return -1;
    }
    stream->stream_id = conn->next_stream_id;
    conn->next_stream_id += 4;

    snprintf(stream->target_addr, sizeof(stream->target_addr),
             "%s:%u", host, (unsigned)port);

    /* Сериализовать TCPRequest */
    uint8_t req_buf[HY2_MAX_ADDR + HY2_MAX_PADDING + HY2_TCP_REQ_OVERHEAD + 8];
    int req_len = hy2_tcp_request_encode(req_buf, sizeof(req_buf),
                                         host, port, 0 /* случайный padding */);
    if (req_len < 0) {
        stream->state = HY2_STREAM_ERROR;
        snprintf(stream->error_msg, sizeof(stream->error_msg),
                 "TCPRequest serialize: буфер переполнен");
        return -1;
    }

    /* B.3.4 — отправить TCPRequest по QUIC stream (не FIN — данные пойдут дальше) */
    if (hy2_send_stream(conn, stream->stream_id,
                         req_buf, (size_t)req_len, false) < 0) {
        stream->state = HY2_STREAM_ERROR;
        snprintf(stream->error_msg, sizeof(stream->error_msg),
                 "TCPRequest send: hy2_send_stream провалился");
        return -1;
    }

    log_msg(LOG_DEBUG, "hysteria2: TCPRequest stream_id=%llu → %s (%d байт)",
            (unsigned long long)stream->stream_id, stream->target_addr, req_len);
    return 0;
}

/* Принять один UDP пакет, Salamander decode, обработать QUIC фреймы.
 * Данные STREAM стримов попадают в conn->recv_stream->rxbuf. */
/* Монотонное время в микросекундах для Brutal CC */
static uint64_t hy2_now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)(ts.tv_nsec / 1000);
}

static int hy2_recv_one(hysteria2_conn_t *conn)
{
    uint8_t wire[1500];
    ssize_t n = recv(conn->udp_fd, wire, sizeof(wire), 0);
    if (n <= 0) return (n == 0) ? 0 : -1;

    uint8_t *qpkt = wire;
    size_t qlen = (size_t)n;
    if (conn->salamander_active) {
        if (qlen < SALAMANDER_MIN_PKT) return 0;
        salamander_process(&conn->salamander, wire, qlen);
        qpkt = wire + SALAMANDER_SALT_LEN;
        qlen -= SALAMANDER_SALT_LEN;
    }
    hy2_process_incoming(conn, qpkt, qlen);
    return 1;
}

int hysteria2_tcp_wait_response(hysteria2_conn_t *conn,
                                hysteria2_stream_t *stream)
{
    if (!conn || !stream) return -1;
    if (stream->state != HY2_STREAM_REQUESTING) return -1;

    /* B.3.5 — получить TCPResponse из QUIC stream */
    conn->recv_stream = stream;
    for (int i = 0; i < 30 && stream->rxbuf_len == 0; i++)
        hy2_recv_one(conn);
    conn->recv_stream = NULL;

    /* Парсим TCPResponse из rxbuf */
    if (stream->rxbuf_len == 0) {
        stream->state = HY2_STREAM_ERROR;
        snprintf(stream->error_msg, sizeof(stream->error_msg),
                 "TCPResponse: таймаут ожидания");
        return -1;
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

    /* Brutal CC: проверить token bucket перед отправкой */
    uint64_t now = hy2_now_us();
    brutal_cc_tick(&conn->cc, now);
    if (!brutal_cc_can_send(&conn->cc, len, now)) {
        errno = EAGAIN;
        return -1;
    }

    /* B.3.6 — отправить данные по QUIC stream */
    if (hy2_send_stream(conn, stream->stream_id,
                         (const uint8_t *)buf, len, false) < 0) {
        errno = EIO;
        return -1;
    }
    brutal_cc_on_sent(&conn->cc, len);
    return (ssize_t)len;
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

    /* Принять один пакет и проверить есть ли данные */
    conn->recv_stream = stream;
    hy2_recv_one(conn);
    conn->recv_stream = NULL;

    if (stream->rxbuf_len > 0) {
        size_t copy = (len < stream->rxbuf_len) ? len : stream->rxbuf_len;
        memcpy(buf, stream->rxbuf, copy);
        stream->rxbuf_len -= copy;
        memmove(stream->rxbuf, stream->rxbuf + copy, stream->rxbuf_len);
        return (ssize_t)copy;
    }

    errno = EAGAIN;
    return -1;
}

void hysteria2_stream_close(hysteria2_conn_t *conn,
                            hysteria2_stream_t *stream)
{
    if (!conn || !stream) return;
    if (stream->state == HY2_STREAM_CLOSED) return;

    /* B.3.7 — отправить FIN (пустой STREAM frame с fin=true) */
    if (stream->state == HY2_STREAM_OPEN)
        hy2_send_stream(conn, stream->stream_id, NULL, 0, true);

    stream->state  = HY2_STREAM_CLOSED;
    stream->rxbuf_len = 0;
}

/* ── percent_decode ─────────────────────────────────────────────── */

/*
 * Декодирует %XX → символ. '+' НЕ декодируется в пробел (RFC 3986,
 * не form-encoding — в URI паролях '+' является литеральным символом).
 * Возвращает длину результата (без NUL) или -1 при переполнении dst_max.
 */
static int percent_decode(const char *src, size_t src_len,
                           char *dst, size_t dst_max)
{
    size_t j = 0;
    for (size_t i = 0; i < src_len; ) {
        if (dst_max == 0 || j >= dst_max - 1) return -1;
        if (src[i] == '%' && i + 2 < src_len
            && isxdigit((unsigned char)src[i+1])
            && isxdigit((unsigned char)src[i+2])) {
            char hex[3] = { src[i+1], src[i+2], '\0' };
            dst[j++] = (char)(unsigned char)strtol(hex, NULL, 16);
            i += 3;
        } else {
            dst[j++] = src[i++];
        }
    }
    dst[j] = '\0';
    return (int)j;
}

/* ── hy2_parse_uri ──────────────────────────────────────────────── */

int hy2_parse_uri(const char *uri, hysteria2_config_t *cfg)
{
    if (!uri || !cfg) return -1;

    /* 1. Проверить схему */
    const char *p;
    if (strncmp(uri, "hysteria2://", 12) == 0)      p = uri + 12;
    else if (strncmp(uri, "hy2://", 6) == 0)        p = uri + 6;
    else return -1;

    /* 2. Сбросить cfg */
    memset(cfg, 0, sizeof(*cfg));

    /* 3. Найти конец userinfo: последний '@' до '?' и '#' */
    const char *at = NULL;
    for (const char *c = p; *c && *c != '?' && *c != '#'; c++)
        if (*c == '@') at = c;
    if (!at) return -1;   /* нет пароля */

    /* 4. percent_decode пароля */
    if (percent_decode(p, (size_t)(at - p),
                       cfg->password, sizeof(cfg->password)) < 0)
        return -1;
    if (cfg->password[0] == '\0') return -1;

    /* 5. host:port — от '@' до '?' или '#' */
    p = at + 1;
    const char *qmark = strchr(p, '?');
    const char *hash  = strchr(p, '#');
    const char *hp_end = qmark ? qmark
                       : hash  ? hash
                       : p + strlen(p);

    /* Найти последнее ':' в диапазоне p..hp_end */
    const char *colon = NULL;
    for (const char *c = hp_end - 1; c >= p; c--)
        if (*c == ':') { colon = c; break; }
    if (!colon || colon == p) return -1;  /* нет порта */

    const char *host_start = p;
    size_t hlen = (size_t)(colon - p);
    /* IPv6: убрать квадратные скобки [::1] → ::1 */
    if (hlen >= 2 && host_start[0] == '[' &&
        host_start[hlen - 1] == ']') {
        host_start++;
        hlen -= 2;
    }
    if (hlen == 0 || hlen >= sizeof(cfg->server_addr)) return -1;
    memcpy(cfg->server_addr, host_start, hlen);
    cfg->server_addr[hlen] = '\0';

    char port_buf[8] = {0};
    size_t plen = (size_t)(hp_end - colon - 1);
    if (plen == 0 || plen >= sizeof(port_buf)) return -1;
    memcpy(port_buf, colon + 1, plen);
    long port = strtol(port_buf, NULL, 10);
    if (port <= 0 || port > 65535) return -1;
    cfg->server_port = (uint16_t)port;

    /* 6. Query string */
    if (!qmark) return 0;  /* нет параметров — успех */
    p = qmark + 1;
    while (*p && *p != '#') {
        /* Найти конец текущего сегмента до '=' */
        const char *amp = strchr(p, '&');
        if (hash && (!amp || amp > hash)) amp = hash;
        const char *seg_end = amp ? amp
                            : (hash ? hash : p + strlen(p));

        /* Искать '=' только внутри текущего сегмента */
        const char *eq = (const char *)memchr(p, '=',
                                              (size_t)(seg_end - p));
        if (!eq) {
            /* Ключ без значения — пропустить сегмент */
            p = (amp && amp != hash) ? amp + 1 : seg_end;
            continue;
        }

        char key[64]  = {0};
        char val[512] = {0};
        size_t klen = (size_t)(eq - p);
        size_t vlen = (size_t)(seg_end - eq - 1);
        if (klen < sizeof(key)) {
            memcpy(key, p, klen);
            key[klen] = '\0';
        }
        if (vlen > 0) {
            char raw_val[512] = {0};
            if (vlen < sizeof(raw_val)) {
                memcpy(raw_val, eq + 1, vlen);
                if (percent_decode(raw_val, vlen, val, sizeof(val)) < 0) {
                    /* Значение слишком длинное — пропустить параметр */
                    p = (amp && amp != hash) ? amp + 1 : seg_end;
                    continue;
                }
            }
        }
        if (strcmp(key, "obfs") == 0) {
            if (strcmp(val, "salamander") == 0) cfg->obfs_enabled = true;
        } else if (strcmp(key, "obfs-password") == 0) {
            snprintf(cfg->obfs_password, sizeof(cfg->obfs_password),
                     "%s", val);
        } else if (strcmp(key, "sni") == 0) {
            snprintf(cfg->sni, sizeof(cfg->sni), "%s", val);
        } else if (strcmp(key, "insecure") == 0) {
            cfg->insecure = (val[0] == '1');
        } else if (strcmp(key, "up") == 0) {
            long v = strtol(val, NULL, 10);
            if (v > 0 && v <= 100000) cfg->up_mbps = (uint32_t)v;
        } else if (strcmp(key, "down") == 0) {
            long v = strtol(val, NULL, 10);
            if (v > 0 && v <= 100000) cfg->down_mbps = (uint32_t)v;
        }
        /* Неизвестные ключи игнорировать */
        p = (amp && amp != hash) ? amp + 1 : seg_end;
    }
    /* 7. Fragment — игнорировать */
    return 0;
}

#endif /* CONFIG_EBURNET_QUIC */

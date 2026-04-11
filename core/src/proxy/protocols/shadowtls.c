/*
 * shadowtls.c — ShadowTLS v3 клиентский транспорт (D.2)
 *
 * Ручной TLS ClientHello с HMAC-подписанным SessionID.
 * Raw парсинг ServerHello для извлечения server_random.
 * AppData records с HMAC(password, counter || data)[0:4] тегом.
 */

#if CONFIG_EBURNET_STLS

#include "proxy/shadowtls.h"
#include "crypto/hmac_sha256.h"
#include "dpi/dpi_payload.h"
#include "4eburnet.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* TLS record header: type(1) + version(2) + length(2) = 5 байт */
#define TLS_RECORD_HDR  5
/* ShadowTLS HMAC тег в AppData: первые 4 байта HMAC-SHA256 */
#define STLS_TAG_LEN    4

/* ── Инициализация ─────────────────────────────────────────────── */

void stls_ctx_init(shadowtls_ctx_t *ctx, const char *password)
{
    memset(ctx, 0, sizeof(*ctx));
    if (password) {
        ctx->password_len = strlen(password);
        if (ctx->password_len > sizeof(ctx->password))
            ctx->password_len = sizeof(ctx->password);
        memcpy(ctx->password, password, ctx->password_len);
    }
}

/* ── ClientHello ───────────────────────────────────────────────── */

int stls_send_client_hello(int fd, shadowtls_ctx_t *ctx, const char *sni)
{
    if (fd < 0 || !ctx || !sni) return -1;

    /* Сгенерировать client_random из /dev/urandom */
    int rfd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (rfd < 0) return -1;
    ssize_t rn = 0;
    while (rn < 32) {
        ssize_t r = read(rfd, ctx->client_random + rn, (size_t)(32 - rn));
        if (r > 0) rn += r;
        else if (!(r < 0 && errno == EINTR)) break;
    }
    close(rfd);
    if (rn < 32) return -1;

    /* SessionID = HMAC(password, client_random) */
    uint8_t session_id[32];
    if (hmac_sha256(ctx->password, ctx->password_len,
                    ctx->client_random, 32, session_id) != 0)
        return -1;

    /* Собрать ClientHello с правильными random + session_id */
    uint8_t ch_buf[768];
    int ch_len = dpi_make_tls_clienthello_ex(ch_buf, sizeof(ch_buf),
                                              sni, ctx->client_random,
                                              session_id, NULL);
    if (ch_len < 0) return -1;

    ssize_t sent = send(fd, ch_buf, (size_t)ch_len, MSG_NOSIGNAL);
    if (sent != ch_len) {
        log_msg(LOG_WARN, "stls: ClientHello send %zd/%d", sent, ch_len);
        ctx->state = STLS_ERROR;
        return -1;
    }

    ctx->state = STLS_SEND_CH;
    log_msg(LOG_DEBUG, "stls: ClientHello отправлен (%d байт, sni=%s)",
            ch_len, sni);
    return 0;
}

/* ── ServerHello парсинг + handshake skip ──────────────────────── */

/*
 * Извлечь server_random из ServerHello Handshake message.
 * msg: начинается с HandshakeType (ожидаем 0x02 = ServerHello)
 * Возвращает 0 при успехе, -1 при ошибке.
 */
static int parse_server_hello(const uint8_t *msg, int msg_len,
                               uint8_t server_random[32])
{
    /* ServerHello:
     *   [0]    HandshakeType = 0x02
     *   [1..3] Length (3 байта)
     *   [4..5] ServerVersion (0x0303)
     *   [6..37] ServerRandom (32 байта)
     */
    if (msg_len < 38) return -1;
    if (msg[0] != 0x02) return -1;  /* не ServerHello */
    memcpy(server_random, msg + 6, 32);
    return 0;
}

int stls_recv_handshake(int fd, shadowtls_ctx_t *ctx)
{
    if (!ctx || fd < 0) return -1;

    /* Читаем в буфер сколько есть */
    int space = (int)sizeof(ctx->recv_buf) - ctx->recv_len;
    if (space <= 0) {
        log_msg(LOG_WARN, "stls: recv_buf переполнен");
        ctx->state = STLS_ERROR;
        return -1;
    }
    ssize_t n = recv(fd, ctx->recv_buf + ctx->recv_len,
                     (size_t)space, MSG_DONTWAIT);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        ctx->state = STLS_ERROR;
        return -1;
    }
    if (n == 0) { ctx->state = STLS_ERROR; return -1; }
    ctx->recv_len += (int)n;

    /* Обработать TLS records в буфере */
    int pos = 0;
    while (pos + TLS_RECORD_HDR <= ctx->recv_len) {
        uint8_t rtype = ctx->recv_buf[pos];
        int rlen = (ctx->recv_buf[pos + 3] << 8) | ctx->recv_buf[pos + 4];

        /* Ждём полную запись */
        if (pos + TLS_RECORD_HDR + rlen > ctx->recv_len) break;

        uint8_t *payload = ctx->recv_buf + pos + TLS_RECORD_HDR;

        if (ctx->state == STLS_SEND_CH && rtype == 0x16) {
            /* Handshake record → ищем ServerHello (type=0x02) */
            if (parse_server_hello(payload, rlen,
                                    ctx->server_random) == 0) {
                /* Верифицируем: server_random[0:4] == HMAC(pwd, client_random)[0:4] */
                if (!hmac_sha256_verify(ctx->password, ctx->password_len,
                                        ctx->client_random, 32,
                                        ctx->server_random, STLS_TAG_LEN)) {
                    log_msg(LOG_WARN, "stls: ServerRandom HMAC mismatch");
                    ctx->state = STLS_ERROR;
                    return -1;
                }
                log_msg(LOG_DEBUG, "stls: ServerRandom HMAC верифицирован");
                ctx->state = STLS_SKIP_HS;
            }
        } else if (ctx->state == STLS_SKIP_HS) {
            ctx->skip_hs_count++;
            if (rtype == 0x14) {
                /* ChangeCipherSpec → переход к Finished */
                ctx->state = STLS_WAIT_FINISHED;
                log_msg(LOG_DEBUG, "stls: ChangeCipherSpec получен");
            } else if (ctx->skip_hs_count >= 10) {
                /* Fallback: сервер не прислал CCS (TLS 1.3 без compat mode) */
                log_msg(LOG_WARN,
                        "stls: CCS не получен после %d records, ACTIVE",
                        ctx->skip_hs_count);
                ctx->state = STLS_ACTIVE;
                ctx->recv_len = 0;
                return 1;
            }
            /* Остальные records (Certificate, etc.) пропускаем */
        } else if (ctx->state == STLS_WAIT_FINISHED) {
            /* Record после CCS = Finished → переходим в ACTIVE */
            ctx->state = STLS_ACTIVE;
            ctx->recv_len = 0;  /* Finished record не нужен после handshake */
            log_msg(LOG_DEBUG, "stls: Finished получен, ACTIVE");
            return 1;
        }

        pos += TLS_RECORD_HDR + rlen;
    }

    /* Удалить обработанные records из буфера */
    if (pos > 0 && pos < ctx->recv_len) {
        memmove(ctx->recv_buf, ctx->recv_buf + pos,
                (size_t)(ctx->recv_len - pos));
        ctx->recv_len -= pos;
    } else if (pos >= ctx->recv_len) {
        ctx->recv_len = 0;
    }

    return 0;
}

/* ── wrap / unwrap ─────────────────────────────────────────────── */

int stls_wrap(shadowtls_ctx_t *ctx,
              const uint8_t *data, int len,
              uint8_t *out, int out_size)
{
    if (!ctx || !data || len <= 0 || !out) return -1;
    int total = TLS_RECORD_HDR + STLS_TAG_LEN + len;
    if (out_size < total) return -1;

    /* TLS record header: AppData (0x17), TLS 1.2 (0x0303) */
    out[0] = 0x17;
    out[1] = 0x03; out[2] = 0x03;
    int payload_len = STLS_TAG_LEN + len;
    out[3] = (uint8_t)(payload_len >> 8);
    out[4] = (uint8_t)(payload_len & 0xFF);

    /* HMAC тег: HMAC(password, counter_be8 || data)[0:4] */
    uint8_t counter_be[8];
    uint64_t cnt = ctx->send_counter;
    for (int i = 7; i >= 0; i--) {
        counter_be[i] = (uint8_t)(cnt & 0xFF);
        cnt >>= 8;
    }

    /* HMAC(password, counter_be || data) → первые 4 байта как тег */
    uint8_t hmac_out[32];
    hmac_sha256_2(ctx->password, ctx->password_len,
                  counter_be, 8, data, (size_t)len, hmac_out);

    memcpy(out + TLS_RECORD_HDR, hmac_out, STLS_TAG_LEN);
    memcpy(out + TLS_RECORD_HDR + STLS_TAG_LEN, data, (size_t)len);

    ctx->send_counter++;
    return total;
}

int stls_unwrap(shadowtls_ctx_t *ctx,
                const uint8_t *record, int record_len,
                uint8_t *out, int out_size)
{
    if (!ctx || !record || !out) return -1;
    if (record_len < TLS_RECORD_HDR + STLS_TAG_LEN) return -1;

    /* Проверить TLS record header */
    if (record[0] != 0x17) return -1;  /* не AppData */
    int payload_len = (record[3] << 8) | record[4];
    if (payload_len < STLS_TAG_LEN) return -1;
    if (TLS_RECORD_HDR + payload_len > record_len) return -1;

    int data_len = payload_len - STLS_TAG_LEN;
    if (out_size < data_len) return -1;

    const uint8_t *tag  = record + TLS_RECORD_HDR;
    const uint8_t *data = record + TLS_RECORD_HDR + STLS_TAG_LEN;

    /* Верифицировать HMAC тег */
    uint8_t counter_be[8];
    uint64_t cnt = ctx->recv_counter;
    for (int i = 7; i >= 0; i--) {
        counter_be[i] = (uint8_t)(cnt & 0xFF);
        cnt >>= 8;
    }

    uint8_t hmac_out[32];
    hmac_sha256_2(ctx->password, ctx->password_len,
                  counter_be, 8, data, (size_t)data_len, hmac_out);

    if (memcmp(tag, hmac_out, STLS_TAG_LEN) != 0) {
        log_msg(LOG_WARN, "stls: unwrap HMAC tag mismatch (counter=%lu)",
                (unsigned long)ctx->recv_counter);
        return -1;
    }

    memcpy(out, data, (size_t)data_len);
    ctx->recv_counter++;
    return data_len;
}

#endif /* CONFIG_EBURNET_STLS */

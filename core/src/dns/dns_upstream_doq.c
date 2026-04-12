#define _XOPEN_SOURCE 700
#include "dns/dns_upstream_doq.h"

#if CONFIG_EBURNET_DOQ

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>
#include <wolfssl/wolfcrypt/hmac.h>   /* wc_HKDF_Extract, wc_HKDF_Expand */
#include <wolfssl/openssl/evp.h>      /* wolfSSL_EVP_aes_128_gcm */

#include "4eburnet.h"
#include "net_utils.h"          /* net_random_bytes */
#include "resource_manager.h"   /* rm_detect_profile */

/* ── вспомогательные ─────────────────────────────────────────────── */

/* Монотонное время в миллисекундах */
static int64_t doq_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
}

/* Перевести наш ki (0=Initial,1=Handshake,2=Application) в wolfSSL level */
static WOLFSSL_ENCRYPTION_LEVEL ki_to_level(int ki)
{
    switch (ki) {
    case 0:  return wolfssl_encryption_initial;
    case 1:  return wolfssl_encryption_handshake;
    default: return wolfssl_encryption_application;
    }
}

/* ── wolfSSL QUIC callbacks ──────────────────────────────────────── */

static int doq_conn_flush_hs(doq_conn_t *dc);  /* forward declaration */

static int cb_set_secrets(WOLFSSL *ssl,
                           WOLFSSL_ENCRYPTION_LEVEL level,
                           const uint8_t *read_secret,
                           const uint8_t *write_secret,
                           size_t secret_len)
{
    doq_conn_t *dc = (doq_conn_t *)wolfSSL_get_app_data(ssl);
    if (!dc) return 0;

    /* Сопоставить wolfSSL level с нашим ki */
    int ki;
    switch (level) {
    case wolfssl_encryption_initial:     ki = 0; break;
    case wolfssl_encryption_handshake:   ki = 1; break;
    case wolfssl_encryption_application: ki = 2; break;
    default: return 1;   /* early_data игнорируем */
    }

    if (quic_keys_derive(&dc->keys[ki], ssl,
                          read_secret, write_secret,
                          secret_len) < 0) {
        log_msg(LOG_WARN, "DoQ: вывод ключей провалился (level=%d)", ki);
        return 0;
    }
    log_msg(LOG_DEBUG, "DoQ: ключи установлены (level=%d)", ki);
    return 1;
}

static int cb_add_handshake(WOLFSSL *ssl,
                             WOLFSSL_ENCRYPTION_LEVEL level,
                             const uint8_t *data, size_t len)
{
    doq_conn_t *dc = (doq_conn_t *)wolfSSL_get_app_data(ssl);
    if (!dc) return 0;
    size_t avail = sizeof(dc->hs_buf) - dc->hs_buf_len;
    if (len > avail) {
        log_msg(LOG_WARN, "DoQ: hs_buf переполнен (need=%zu avail=%zu)",
                len, avail);
        return 0;
    }
    memcpy(dc->hs_buf + dc->hs_buf_len, data, len);
    dc->hs_buf_len += len;
    dc->hs_level    = (quic_level_t)level;
    return 1;
}

static int cb_flush(WOLFSSL *ssl)
{
    doq_conn_t *dc = (doq_conn_t *)wolfSSL_get_app_data(ssl);
    if (!dc || !dc->hs_buf_len) return 1;
    doq_conn_flush_hs(dc);
    return 1;
}

static int cb_alert(WOLFSSL *ssl,
                     WOLFSSL_ENCRYPTION_LEVEL level,
                     uint8_t alert)
{
    (void)level;
    doq_conn_t *dc = (doq_conn_t *)wolfSSL_get_app_data(ssl);
    log_msg(LOG_WARN, "DoQ: TLS alert 0x%02x", (unsigned)alert);
    if (dc) dc->state = DOQ_CONN_CLOSING;
    return 1;
}

/* Статический QUIC method — lifetime = программа */
static const WOLFSSL_QUIC_METHOD g_doq_method = {
    cb_set_secrets,
    cb_add_handshake,
    cb_flush,
    cb_alert,
};

/* ── QUIC varint encode/decode (RFC 9000 §16) ───────────────────── */

static size_t varint_encode(uint8_t *b, size_t blen, uint64_t v)
{
    if (v <= 63u         && blen >= 1) { b[0] = (uint8_t)v; return 1; }
    if (v <= 16383u      && blen >= 2) {
        b[0] = 0x40u | (uint8_t)(v >> 8);
        b[1] = (uint8_t)v; return 2;
    }
    if (v <= 1073741823u && blen >= 4) {
        b[0] = 0x80u | (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16);
        b[2] = (uint8_t)(v >> 8);          b[3] = (uint8_t)v; return 4;
    }
    if (blen >= 8) {
        b[0] = 0xC0u | (uint8_t)(v >> 56); b[1] = (uint8_t)(v >> 48);
        b[2] = (uint8_t)(v >> 40);          b[3] = (uint8_t)(v >> 32);
        b[4] = (uint8_t)(v >> 24);          b[5] = (uint8_t)(v >> 16);
        b[6] = (uint8_t)(v >> 8);           b[7] = (uint8_t)v; return 8;
    }
    return 0;
}

static int varint_decode(const uint8_t *b, size_t blen,
                          uint64_t *v, size_t *used)
{
    if (!blen) return -1;
    switch (b[0] >> 6) {
    case 0:
        *v = b[0] & 0x3Fu; *used = 1; return 0;
    case 1:
        if (blen < 2) return -1;
        *v = ((uint64_t)(b[0] & 0x3Fu) << 8) | b[1];
        *used = 2; return 0;
    case 2:
        if (blen < 4) return -1;
        *v = ((uint64_t)(b[0] & 0x3Fu) << 24) | ((uint64_t)b[1] << 16)
           | ((uint64_t)b[2] << 8) | b[3];
        *used = 4; return 0;
    case 3:
        if (blen < 8) return -1;
        *v = ((uint64_t)(b[0] & 0x3Fu) << 56) | ((uint64_t)b[1] << 48)
           | ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32)
           | ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16)
           | ((uint64_t)b[6] << 8)  | b[7];
        *used = 8; return 0;
    default: return -1;
    }
}

/* ── CRYPTO frame (type 0x06) ───────────────────────────────────── */

static size_t frame_crypto(uint8_t *b, size_t blen,
                             uint64_t offset,
                             const uint8_t *data, size_t dlen)
{
    size_t p = 0;
    if (!blen) return 0;
    b[p++] = 0x06;
    p += varint_encode(b + p, blen - p, offset);
    p += varint_encode(b + p, blen - p, dlen);
    if (p + dlen > blen) return 0;
    memcpy(b + p, data, dlen);
    return p + dlen;
}

/* ── ACK frame (type 0x02), один диапазон ──────────────────────── */

static size_t frame_ack(uint8_t *b, size_t blen, uint64_t largest_pn)
{
    size_t p = 0;
    if (!blen) return 0;
    b[p++] = 0x02;
    p += varint_encode(b + p, blen - p, largest_pn);  /* Largest Acknowledged */
    p += varint_encode(b + p, blen - p, 0);           /* ACK Delay = 0 */
    p += varint_encode(b + p, blen - p, 0);           /* ACK Range Count = 0 */
    p += varint_encode(b + p, blen - p, 0);           /* First ACK Range = 0 */
    return p;
}

/* ── STREAM frame (type 0x0A: OFF+LEN+FIN) ──────────────────────── */

static size_t frame_stream(uint8_t *b, size_t blen,
                             uint64_t stream_id, uint64_t offset,
                             const uint8_t *data, size_t dlen, bool fin)
{
    uint8_t type = 0x08u | 0x04u | 0x02u | (fin ? 0x01u : 0x00u);
    size_t p = 0;
    if (!blen) return 0;
    b[p++] = type;
    p += varint_encode(b + p, blen - p, stream_id);
    p += varint_encode(b + p, blen - p, offset);
    p += varint_encode(b + p, blen - p, dlen);
    if (p + dlen > blen) return 0;
    memcpy(b + p, data, dlen);
    return p + dlen;
}

/* ── CONNECTION_CLOSE frame (type 0x1C) ─────────────────────────── */

static size_t frame_conn_close(uint8_t *b, size_t blen, uint64_t code)
{
    size_t p = 0;
    if (!blen) return 0;
    b[p++] = 0x1C;
    p += varint_encode(b + p, blen - p, code);
    p += varint_encode(b + p, blen - p, 0);  /* frame type = 0 */
    p += varint_encode(b + p, blen - p, 0);  /* reason length = 0 */
    return p;
}

/* ── PING frame (type 0x01) ─────────────────────────────────────── */

static size_t frame_ping(uint8_t *b, size_t blen)
{
    if (!blen) return 0;
    b[0] = 0x01;
    return 1;
}

/* ── PADDING frame (type 0x00) ──────────────────────────────────── */

static void frame_pad(uint8_t *b, size_t pad_len)
{
    memset(b, 0x00, pad_len);
}

/* ── max UDP payload (conservative MTU) ────────────────────────── */
#define DOQ_MAX_PKT  1350u

/* ── Long Header encode (Initial=0x00 / Handshake=0x02) ─────────── */
/*
 * Записывает готовый QUIC пакет в out[0..out_size].
 * Возвращает итоговую длину или 0 при ошибке.
 * add_padding: дополнить до 1200 байт (только Initial, anti-amplification).
 */
static size_t encode_long(doq_conn_t *dc,
                            uint8_t pkt_type, int ki,
                            const uint8_t *frames, size_t flen,
                            bool add_padding,
                            uint8_t *out, size_t out_size)
{
    if (!dc->keys[ki].ready) return 0;
    if (flen > DOQ_MAX_PKT) return 0;

    /* Plaintext с возможным padding */
    uint8_t plain[DOQ_MAX_PKT];
    size_t  plain_len = flen;
    memcpy(plain, frames, flen);

    if (add_padding) {
        /* ~60 байт header overhead + 16 tag */
        size_t overhead = 60 + QUIC_AEAD_TAG_LEN;
        if (plain_len + overhead < 1200u) {
            size_t pad = 1200u - overhead - plain_len;
            if (plain_len + pad <= sizeof(plain)) {
                frame_pad(plain + plain_len, pad);
                plain_len += pad;
            }
        }
    }

    /* ── сборка заголовка ── */
    uint8_t hdr[64];
    size_t  hdr_len = 0;

    /* First byte: 1 1 0 0 TT 1 1  (long, fixed=1, type, reserved=0, pn_len=4) */
    hdr[hdr_len++] = (uint8_t)(0xC0u | ((uint8_t)pkt_type << 4) | 0x03u);
    /* QUIC version 1 */
    hdr[hdr_len++] = 0x00; hdr[hdr_len++] = 0x00;
    hdr[hdr_len++] = 0x00; hdr[hdr_len++] = 0x01;
    /* DCID */
    hdr[hdr_len++] = 8;
    memcpy(hdr + hdr_len, dc->dcid, 8); hdr_len += 8;
    /* SCID */
    hdr[hdr_len++] = 8;
    memcpy(hdr + hdr_len, dc->scid, 8); hdr_len += 8;
    /* Token (только Initial: пустой) */
    if (pkt_type == 0x00u) hdr[hdr_len++] = 0x00;
    /* Length: varint (4 PN + plaintext + 16 AEAD tag) */
    uint64_t length = 4u + plain_len + QUIC_AEAD_TAG_LEN;
    hdr_len += varint_encode(hdr + hdr_len, sizeof(hdr) - hdr_len, length);
    /* Packet Number (4 байта big-endian) */
    uint64_t pnum = dc->send_pn[ki]++;
    hdr[hdr_len++] = (uint8_t)(pnum >> 24);
    hdr[hdr_len++] = (uint8_t)(pnum >> 16);
    hdr[hdr_len++] = (uint8_t)(pnum >> 8);
    hdr[hdr_len++] = (uint8_t)(pnum);

    if (hdr_len + plain_len + QUIC_AEAD_TAG_LEN > out_size) return 0;

    /* ── AEAD шифрование ── */
    memcpy(out, hdr, hdr_len);
    size_t clen = out_size - hdr_len;
    if (quic_aead_protect(&dc->keys[ki].send_aead,
                           out + hdr_len, &clen,
                           plain, plain_len,
                           hdr, hdr_len,
                           pnum) < 0) return 0;

    /* ── Header Protection ──
     * sample = первые 16 байт ciphertext (RFC 9001 §5.4.2).
     * quic_hp_apply ожидает hdr_len = pn_offset + 4. */
    quic_hp_apply(&dc->keys[ki].send_hp, out, hdr_len, out + hdr_len);

    return hdr_len + clen;
}

/* ── Short Header encode (1-RTT / Application keys) ─────────────── */
static size_t encode_short(doq_conn_t *dc,
                             const uint8_t *frames, size_t flen,
                             uint8_t *out, size_t out_size)
{
    if (!dc->keys[2].ready) return 0;

    uint8_t hdr[16];
    size_t  hdr_len = 0;

    /* First byte: 0 1 0 0 0 0 1 1  (short, fixed=1, spin=0, reserved=0, pn_len=4) */
    hdr[hdr_len++] = 0x40u | 0x03u;
    /* DCID */
    memcpy(hdr + hdr_len, dc->dcid, 8); hdr_len += 8;
    /* Packet Number (4 байта) */
    uint64_t pnum = dc->send_pn[2]++;
    hdr[hdr_len++] = (uint8_t)(pnum >> 24);
    hdr[hdr_len++] = (uint8_t)(pnum >> 16);
    hdr[hdr_len++] = (uint8_t)(pnum >> 8);
    hdr[hdr_len++] = (uint8_t)(pnum);

    if (hdr_len + flen + QUIC_AEAD_TAG_LEN > out_size) return 0;

    /* AEAD */
    memcpy(out, hdr, hdr_len);
    size_t clen = out_size - hdr_len;
    if (quic_aead_protect(&dc->keys[2].send_aead,
                           out + hdr_len, &clen,
                           frames, flen,
                           hdr, hdr_len,
                           pnum) < 0) return 0;

    /* Header Protection */
    quic_hp_apply(&dc->keys[2].send_hp, out, hdr_len, out + hdr_len);

    return hdr_len + clen;
}

/* Отправить сырые байты на UDP fd */
static void doq_send(doq_conn_t *dc, const uint8_t *pkt, size_t pkt_len)
{
    if (dc->udp_fd < 0 || !pkt_len) return;
    send(dc->udp_fd, pkt, pkt_len, MSG_DONTWAIT);
    dc->last_tx_ms = doq_now_ms();
}

/* ── Initial Keys (RFC 9001 §5.2) ───────────────────────────────── */
/*
 * Initial secrets детерминированы из DCID — не через TLS callback.
 * Шифр всегда AES-128-GCM, хэш SHA-256.
 */

/* Вспомогательная: HKDF-Expand-Label для SHA-256.
 * inKey/inKeyLen — PRK; label — метка; outLen — желаемая длина вывода. */
static int hkdf_expand_label_sha256(const uint8_t *prk, size_t prklen,
                                     const char *label,
                                     uint8_t *out, size_t outlen)
{
    /* HkdfLabel: uint16 length || uint8 label_len || label || uint8 ctx_len=0 */
    uint8_t info[64];
    size_t  pos  = 0;
    const char prefix[] = "tls13 ";
    size_t  plen = 6;
    size_t  llen = strlen(label);

    /* info = 2 + 1 + plen + llen + 1; max label в RFC 9001 = 15 байт → 25 */
    if (2 + 1 + plen + llen + 1 > sizeof(info)) return -1;

    info[pos++] = (uint8_t)(outlen >> 8);
    info[pos++] = (uint8_t)(outlen & 0xFFu);
    info[pos++] = (uint8_t)(plen + llen);
    memcpy(info + pos, prefix, plen); pos += plen;
    memcpy(info + pos, label,  llen); pos += llen;
    info[pos++] = 0x00;   /* context length = 0 */

    /* wc_HKDF_Expand: 0 = success */
    return wc_HKDF_Expand(WC_SHA256,
                           prk, (word32)prklen,
                           info, (word32)pos,
                           out, (word32)outlen);
}

static int derive_initial_keys(doq_conn_t *dc)
{
    /* Initial salt для QUIC v1 (RFC 9001 §5.2) */
    static const uint8_t SALT[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
        0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
        0xcc, 0xbb, 0x7f, 0x0a
    };

    /* initial_secret = HKDF-Extract(salt=SALT, IKM=DCID)
     * wc_HKDF_Extract(type, salt, saltSz, inKey, inKeySz, out) */
    uint8_t init_secret[32];
    if (wc_HKDF_Extract(WC_SHA256,
                         SALT, 20,
                         dc->dcid, 8,
                         init_secret) != 0) return -1;

    /* client_initial_secret / server_initial_secret */
    uint8_t csec[32], ssec[32];
    if (hkdf_expand_label_sha256(init_secret, 32, "client in", csec, 32) != 0) return -1;
    if (hkdf_expand_label_sha256(init_secret, 32, "server in", ssec, 32) != 0) return -1;

    /* quic key (16), iv (12), hp (16) для обоих направлений */
    uint8_t ckey[16], civ[12], chp[16];
    uint8_t skey[16], siv[12], shp[16];
    if (hkdf_expand_label_sha256(csec, 32, "quic key", ckey, 16) != 0) return -1;
    if (hkdf_expand_label_sha256(csec, 32, "quic iv",  civ,  12) != 0) return -1;
    if (hkdf_expand_label_sha256(csec, 32, "quic hp",  chp,  16) != 0) return -1;
    if (hkdf_expand_label_sha256(ssec, 32, "quic key", skey, 16) != 0) return -1;
    if (hkdf_expand_label_sha256(ssec, 32, "quic iv",  siv,  12) != 0) return -1;
    if (hkdf_expand_label_sha256(ssec, 32, "quic hp",  shp,  16) != 0) return -1;

    const WOLFSSL_EVP_CIPHER *aes128gcm = wolfSSL_EVP_aes_128_gcm();
    if (!aes128gcm) return -1;

    /* send = client keys (мы клиент), recv = server keys */
    dc->keys[0].send_aead.ctx = wolfSSL_quic_crypt_new(aes128gcm, ckey, civ, 1);
    if (!dc->keys[0].send_aead.ctx) return -1;
    memcpy(dc->keys[0].send_aead.iv_base, civ, QUIC_IV_LEN);
    dc->keys[0].send_aead.pn = 0;

    dc->keys[0].recv_aead.ctx = wolfSSL_quic_crypt_new(aes128gcm, skey, siv, 0);
    if (!dc->keys[0].recv_aead.ctx) return -1;
    memcpy(dc->keys[0].recv_aead.iv_base, siv, QUIC_IV_LEN);
    dc->keys[0].recv_aead.pn = 0;

    if (quic_hp_init(&dc->keys[0].send_hp, chp, 16) < 0) return -1;
    if (quic_hp_init(&dc->keys[0].recv_hp, shp, 16) < 0) return -1;
    dc->keys[0].ready = 1;

    /* Обнулить ключевой материал */
    memset(init_secret, 0, sizeof(init_secret));
    memset(csec, 0, sizeof(csec)); memset(ssec, 0, sizeof(ssec));
    memset(ckey, 0, sizeof(ckey)); memset(civ,  0, sizeof(civ));
    memset(chp,  0, sizeof(chp));  memset(skey, 0, sizeof(skey));
    memset(siv,  0, sizeof(siv));  memset(shp,  0, sizeof(shp));
    return 0;
}

/* ── Flush накопленных TLS handshake данных ──────────────────────── */

static int doq_conn_flush_hs(doq_conn_t *dc)
{
    if (!dc->hs_buf_len) return 0;

    /* Определить уровень и индекс ключей */
    int ki;
    switch (dc->hs_level) {
    case wolfssl_encryption_initial:     ki = 0; break;
    case wolfssl_encryption_handshake:   ki = 1; break;
    default:                             ki = 0; break;
    }

    uint8_t frames[2048];
    size_t  flen = 0;

    /* ACK если нужно */
    if (dc->recv_need_ack[ki]) {
        flen += frame_ack(frames + flen, sizeof(frames) - flen,
                           dc->recv_largest[ki]);
        dc->recv_need_ack[ki] = 0;
    }

    /* CRYPTO frame с TLS данными — offset накапливается per уровень */
    flen += frame_crypto(frames + flen, sizeof(frames) - flen,
                          dc->hs_offset[ki], dc->hs_buf, dc->hs_buf_len);
    dc->hs_offset[ki] += dc->hs_buf_len;
    dc->hs_buf_len = 0;

    uint8_t out[DOQ_MAX_PKT + 64u];
    uint8_t pkt_type = (ki == 0) ? 0x00u : 0x02u;
    size_t  plen = encode_long(dc, pkt_type, ki,
                                frames, flen,
                                ki == 0,   /* padding только для Initial */
                                out, sizeof(out));
    if (!plen) return -1;
    doq_send(dc, out, plen);
    return 0;
}

/* ── Число соединений по профилю ────────────────────────────────── */

static int doq_conn_count_by_profile(void)
{
    switch (rm_detect_profile()) {
    case DEVICE_MICRO:  return 0;   /* QUIC не поддерживается на MICRO */
    case DEVICE_NORMAL: return 2;
    default:            return 4;
    }
}

/* ── Установить UDP+TLS соединение к DoQ серверу ─────────────────── */

static int doq_connect(doq_conn_t *dc, WOLFSSL_CTX *ssl_ctx,
                        const DnsConfig *cfg, int epoll_fd)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_in srv = {0};
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(cfg->doq_server_port ? cfg->doq_server_port : 853u);
    if (inet_pton(AF_INET, cfg->doq_server_ip, &srv.sin_addr) != 1) {
        close(fd); return -1;
    }
    if (connect(fd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        close(fd); return -1;
    }
    memcpy(&dc->peer, &srv, sizeof(srv));
    dc->peer_len       = sizeof(srv);
    dc->udp_fd         = fd;
    dc->created_ms     = doq_now_ms();
    dc->next_stream_id = 0;

    net_random_bytes(dc->scid, 8);
    net_random_bytes(dc->dcid, 8);

    if (derive_initial_keys(dc) < 0) {
        close(fd); dc->udp_fd = -1; return -1;
    }

    WOLFSSL *ssl = wolfSSL_new(ssl_ctx);
    if (!ssl) { close(fd); dc->udp_fd = -1; return -1; }

    wolfSSL_set_app_data(ssl, dc);
    wolfSSL_set_connect_state(ssl);

    /* SNI */
    const char *sni = cfg->doq_sni[0] ? cfg->doq_sni : cfg->doq_server_ip;
    wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME,
                    sni, (unsigned short)strlen(sni));

    /* ALPN "doq" — UseALPN принимает char*, нужен не-const буфер */
    char alpn[] = "doq";
    wolfSSL_UseALPN(ssl, alpn, 3, WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);

    /* Минимальные QUIC transport parameters */
    static const uint8_t tp[] = {
        /* initial_max_data (0x04): value=262144 (256 KB) */
        0x04, 0x04, 0x00, 0x04, 0x00, 0x00,
        /* initial_max_streams_bidi (0x08): value=4 */
        0x08, 0x01, 0x04,
        /* max_idle_timeout (0x01): value=30000ms */
        0x01, 0x04, 0x00, 0x00, 0x75, 0x30,
    };
    wolfSSL_set_quic_transport_params(ssl, tp, sizeof(tp));

    dc->ssl   = ssl;
    dc->state = DOQ_CONN_HANDSHAKE;

    /* Запустить TLS handshake — callbacks заполнят hs_buf */
    wolfSSL_quic_do_handshake(ssl);
    if (dc->hs_buf_len)
        doq_conn_flush_hs(dc);

    /* Регистрация в epoll */
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = fd };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);

    log_msg(LOG_DEBUG, "DoQ: подключение к %s:%u",
            cfg->doq_server_ip,
            (unsigned)(cfg->doq_server_port ? cfg->doq_server_port : 853u));
    return 0;
}

/* ── Pool init/free ──────────────────────────────────────────────── */

int doq_pool_init(doq_pool_t *pool, int epoll_fd, const DnsConfig *cfg)
{
    (void)cfg;
    if (!pool) return -1;
    memset(pool, 0, sizeof(*pool));
    pool->epoll_fd = epoll_fd;
    pool->count    = doq_conn_count_by_profile();

    if (pool->count == 0) {
        log_msg(LOG_INFO, "DoQ: отключён (MICRO профиль)");
        return 0;
    }

    pool->ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!pool->ssl_ctx) return -1;

    wolfSSL_CTX_set_verify(pool->ssl_ctx, WOLFSSL_VERIFY_PEER, NULL);
    if (wolfSSL_CTX_load_verify_locations(pool->ssl_ctx,
            EBURNET_CA_BUNDLE, NULL) != WOLFSSL_SUCCESS)
        log_msg(LOG_WARN, "DoQ: CA bundle не загружен (%s), "
                "верификация может не работать", EBURNET_CA_BUNDLE);

    if (quic_ctx_init(pool->ssl_ctx, &g_doq_method) < 0) {
        wolfSSL_CTX_free(pool->ssl_ctx);
        pool->ssl_ctx = NULL;
        return -1;
    }

    pool->conns = calloc((size_t)pool->count, sizeof(doq_conn_t));
    if (!pool->conns) {
        wolfSSL_CTX_free(pool->ssl_ctx);
        return -1;
    }

    for (int i = 0; i < pool->count; i++) {
        pool->conns[i].state  = DOQ_CONN_IDLE;
        pool->conns[i].udp_fd = -1;
    }

    log_msg(LOG_INFO, "DoQ: пул %d соединений", pool->count);
    return 0;
}

void doq_pool_free(doq_pool_t *pool)
{
    if (!pool) return;
    for (int i = 0; i < pool->count; i++) {
        doq_conn_t *dc = &pool->conns[i];
        if (dc->ssl)      { wolfSSL_free(dc->ssl); dc->ssl = NULL; }
        if (dc->udp_fd >= 0) {
            epoll_ctl(pool->epoll_fd, EPOLL_CTL_DEL, dc->udp_fd, NULL);
            close(dc->udp_fd);
            dc->udp_fd = -1;
        }
        for (int k = 0; k < 3; k++)
            quic_keys_free(&dc->keys[k]);
    }
    free(pool->conns);
    pool->conns = NULL;
    if (pool->ssl_ctx) wolfSSL_CTX_free(pool->ssl_ctx);
    memset(pool, 0, sizeof(*pool));
}

bool doq_pool_owns_fd(const doq_pool_t *pool, int fd)
{
    for (int i = 0; i < pool->count; i++)
        if (pool->conns[i].udp_fd == fd) return true;
    return false;
}

/* ── Обработка входящих stream данных ────────────────────────────── */

static void process_stream_data(doq_conn_t *dc, int si,
                                 const uint8_t *data, size_t dlen,
                                 bool fin)
{
    doq_stream_t *st = &dc->streams[si];

    /* Накапливаем данные в rx_buf */
    size_t avail = sizeof(st->rx_buf) - st->rx_len;
    size_t copy  = dlen < avail ? dlen : avail;
    memcpy(st->rx_buf + st->rx_len, data, copy);
    st->rx_len += copy;

    /* Разобрать 2-byte length prefix (RFC 9250 §4.2) */
    if (!st->len_parsed && st->rx_len >= 2) {
        st->dns_len    = ((uint16_t)st->rx_buf[0] << 8) | st->rx_buf[1];
        st->len_parsed = true;
    }

    if (fin) st->state = DOQ_STREAM_DONE;

    /* Вызвать callback когда получен полный DNS ответ */
    if (st->len_parsed && st->rx_len >= 2u + (size_t)st->dns_len) {
        if (st->cb) {
            /* Восстановить оригинальный DNS Message ID (RFC 9250 §4.2.1) */
            uint8_t *resp = st->rx_buf + 2;
            resp[0] = (uint8_t)(st->orig_qid >> 8);
            resp[1] = (uint8_t)(st->orig_qid & 0xFFu);
            st->cb(st->cb_ctx, resp, st->dns_len, 0);
        }
        st->state = DOQ_STREAM_FREE;
        memset(st, 0, sizeof(*st));
    }
}

/* ── Разобрать входящий UDP датаграмм ───────────────────────────── */

static void decode_packet(doq_conn_t *dc,
                            const uint8_t *pkt, size_t pkt_len)
{
    if (!pkt || pkt_len < 5) return;
    bool is_long = (pkt[0] & 0x80u) != 0;
    int  ki;

    if (is_long) {
        /* Проверить QUIC version 1 */
        if (pkt_len < 9) return;
        uint32_t ver = ((uint32_t)pkt[1] << 24) | ((uint32_t)pkt[2] << 16)
                     | ((uint32_t)pkt[3] << 8)  |  (uint32_t)pkt[4];
        if (ver != 0x00000001u) return;
        /* Тип: Initial=0x00 → ki=0, Handshake=0x02 → ki=1 */
        uint8_t pt = (pkt[0] >> 4) & 0x03u;
        ki = (pt == 0x02u) ? 1 : 0;
    } else {
        ki = 2;  /* 1-RTT */
    }

    if (!dc->keys[ki].ready) return;

    /* ── Вычислить pn_offset ── */
    size_t pn_offset;
    if (is_long) {
        size_t pos = 5;   /* 1 flags + 4 version */
        if (pos + 1 > pkt_len) return;
        uint8_t dcil = pkt[pos++];
        if (pos + dcil > pkt_len) return;
        pos += dcil;
        if (pos + 1 > pkt_len) return;
        uint8_t scil = pkt[pos++];
        if (pos + scil > pkt_len) return;
        pos += scil;
        /* Initial: token (varint length + bytes) */
        if (ki == 0) {
            uint64_t tlen; size_t used;
            if (varint_decode(pkt + pos, pkt_len - pos, &tlen, &used) < 0) return;
            pos += used;
            if (pos + (size_t)tlen > pkt_len) return;
            pos += (size_t)tlen;
        }
        /* Length field */
        uint64_t length; size_t used;
        if (varint_decode(pkt + pos, pkt_len - pos, &length, &used) < 0) return;
        pos += used;
        pn_offset = pos;
    } else {
        pn_offset = 9;   /* 1 flags + 8 DCID */
    }

    /* Минимум: PN(4) + ciphertext(min 16 tag) */
    if (pn_offset + 4 + QUIC_AEAD_TAG_LEN > pkt_len) return;

    /* ── HP removal — копируем заголовок и снимаем маску ── */
    uint8_t hdr[64];
    if (pn_offset + 4 > sizeof(hdr)) return;
    memcpy(hdr, pkt, pn_offset + 4);
    /* sample = первые 16 байт ciphertext (offset 4 после PN, т.е. pkt[pn_offset+4]) */
    const uint8_t *sample = pkt + pn_offset + 4;
    quic_hp_remove(&dc->keys[ki].recv_hp, hdr, pn_offset + 4, sample);

    /* Декодировать PN (pn_len из восстановленного first byte) */
    size_t   pn_len = (size_t)(hdr[0] & 0x03u) + 1;
    uint64_t pnum   = 0;
    for (size_t i = 0; i < pn_len; i++)
        pnum = (pnum << 8) | hdr[pn_offset + i];

    /* ── AEAD расшифровка ── */
    const uint8_t *ciphertext = pkt + pn_offset + 4;
    size_t         cipher_len = pkt_len - pn_offset - 4;
    uint8_t        plain[DOQ_MAX_PKT];
    size_t         plain_len  = sizeof(plain);

    if (quic_aead_unprotect(&dc->keys[ki].recv_aead,
                             plain, &plain_len,
                             ciphertext, cipher_len,
                             hdr, pn_offset + 4,
                             pnum) < 0) return;

    /* Обновить ACK tracking */
    dc->recv_largest[ki]  = pnum;
    dc->recv_need_ack[ki] = 1;

    /* ── Разбор frames ── */
    size_t pos2 = 0;
    while (pos2 < plain_len) {
        uint64_t ftype; size_t used;
        if (varint_decode(plain + pos2, plain_len - pos2, &ftype, &used) < 0) break;
        pos2 += used;

        if (ftype == 0x06u) {
            /* CRYPTO: передать wolfSSL */
            uint64_t off, dlen; size_t u2, u3;
            if (varint_decode(plain + pos2, plain_len - pos2, &off,  &u2) < 0) break;
            pos2 += u2;
            if (varint_decode(plain + pos2, plain_len - pos2, &dlen, &u3) < 0) break;
            pos2 += u3;
            if (pos2 + (size_t)dlen > plain_len) break;
            wolfSSL_provide_quic_data(dc->ssl, ki_to_level(ki),
                                       plain + pos2, (size_t)dlen);
            wolfSSL_quic_do_handshake(dc->ssl);
            if (dc->hs_buf_len) doq_conn_flush_hs(dc);
            pos2 += (size_t)dlen;

        } else if ((ftype & 0xF8u) == 0x08u) {
            /* STREAM */
            bool has_off = (ftype & 0x04u) != 0;
            bool has_len = (ftype & 0x02u) != 0;
            bool fin     = (ftype & 0x01u) != 0;
            uint64_t sid, soff = 0, sdlen; size_t u;
            if (varint_decode(plain + pos2, plain_len - pos2, &sid, &u) < 0) break;
            pos2 += u;
            if (has_off) {
                if (varint_decode(plain + pos2, plain_len - pos2, &soff, &u) < 0) break;
                pos2 += u;
            }
            (void)soff;
            if (has_len) {
                if (varint_decode(plain + pos2, plain_len - pos2, &sdlen, &u) < 0) break;
                pos2 += u;
            } else {
                sdlen = plain_len - pos2;
            }
            if (pos2 + (size_t)sdlen > plain_len) break;
            /* Найти stream slot по stream_id */
            for (int s = 0; s < DOQ_MAX_STREAMS; s++) {
                if (dc->streams[s].stream_id == sid &&
                    dc->streams[s].state != DOQ_STREAM_FREE) {
                    process_stream_data(dc, s,
                                         plain + pos2, (size_t)sdlen, fin);
                    break;
                }
            }
            pos2 += (size_t)sdlen;

        } else if (ftype == 0x02u || ftype == 0x03u) {
            /* ACK: пропустить поля */
            uint64_t la, delay, cnt, fr; size_t u;
            if (varint_decode(plain+pos2, plain_len-pos2, &la,    &u)<0) break;
            pos2 += u;
            if (varint_decode(plain+pos2, plain_len-pos2, &delay, &u)<0) break;
            pos2 += u;
            if (varint_decode(plain+pos2, plain_len-pos2, &cnt,   &u)<0) break;
            pos2 += u;
            if (varint_decode(plain+pos2, plain_len-pos2, &fr,    &u)<0) break;
            pos2 += u;
            for (uint64_t r = 0; r < cnt && pos2 < plain_len; r++) {
                uint64_t gap, rng;
                if (varint_decode(plain+pos2, plain_len-pos2, &gap, &u)<0) break;
                pos2 += u;
                if (varint_decode(plain+pos2, plain_len-pos2, &rng, &u)<0) break;
                pos2 += u;
            }
            if (ftype == 0x03u && pos2 + 3 <= plain_len) pos2 += 3; /* ECN */

        } else if (ftype == 0x00u) {
            break;   /* PADDING — всё остальное нули */
        } else if (ftype == 0x01u) {
            /* PING — ACK уже запланирован */
        } else if (ftype == 0x1Cu || ftype == 0x1Du) {
            dc->state = DOQ_CONN_CLOSING;
            break;
        } else if (ftype == 0x1Eu) {
            /* HANDSHAKE_DONE */
            dc->state = DOQ_CONN_READY;
            log_msg(LOG_INFO, "DoQ: HANDSHAKE_DONE");
        } else {
            break;   /* неизвестный frame — прекратить разбор */
        }
    }

    /* Проверить завершение handshake через wolfSSL */
    if (dc->state == DOQ_CONN_HANDSHAKE &&
        wolfSSL_is_init_finished(dc->ssl)) {
        dc->state = DOQ_CONN_READY;
        log_msg(LOG_INFO, "DoQ: рукопожатие завершено");
    }
}

/* ── Public API ──────────────────────────────────────────────────── */

void doq_handle_event(doq_pool_t *pool, int fd, uint32_t events)
{
    (void)events;
    doq_conn_t *dc = NULL;
    for (int i = 0; i < pool->count; i++)
        if (pool->conns[i].udp_fd == fd) { dc = &pool->conns[i]; break; }
    if (!dc) return;

    uint8_t buf[DOQ_MAX_PKT];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
        decode_packet(dc, buf, (size_t)n);
        dc->last_rx_ms = doq_now_ms();
    }
}

int doq_query_start(doq_pool_t *pool, const DnsConfig *cfg,
                     const uint8_t *query, size_t query_len,
                     doq_response_cb_t cb, void *cb_ctx)
{
    /* Валидация входных данных до занятия stream slot */
    if (!query || query_len < 12 || query_len > 512) return -1;

    /* Найти READY соединение со свободным stream */
    doq_conn_t *dc = NULL;
    for (int i = 0; i < pool->count && !dc; i++) {
        doq_conn_t *c = &pool->conns[i];
        if (c->state != DOQ_CONN_READY) continue;
        for (int s = 0; s < DOQ_MAX_STREAMS; s++) {
            if (c->streams[s].state == DOQ_STREAM_FREE) { dc = c; break; }
        }
    }

    /* Нет READY — попытаться поднять IDLE соединение */
    if (!dc) {
        for (int i = 0; i < pool->count; i++) {
            if (pool->conns[i].state == DOQ_CONN_IDLE) {
                doq_connect(&pool->conns[i], pool->ssl_ctx, cfg, pool->epoll_fd);
                break;
            }
        }
        return -1;   /* ответим позже через handle_event + повтор вызова */
    }

    /* Найти свободный stream slot */
    int si = -1;
    for (int s = 0; s < DOQ_MAX_STREAMS; s++) {
        if (dc->streams[s].state == DOQ_STREAM_FREE) { si = s; break; }
    }
    if (si < 0) return -1;

    doq_stream_t *st = &dc->streams[si];
    st->stream_id   = dc->next_stream_id;
    dc->next_stream_id += 4;   /* bidirectional client: 0,4,8,... */
    st->state       = DOQ_STREAM_SENT;
    st->deadline_ms = doq_now_ms() + DOQ_QUERY_TIMEOUT_MS;
    st->cb          = cb;
    st->cb_ctx      = cb_ctx;
    if (query_len >= 2)
        st->orig_qid = ((uint16_t)query[0] << 8) | query[1];

    /* DoQ payload: 2-byte length + DNS с ID=0 (RFC 9250 §4.2.1) */
    uint8_t doq_buf[2 + 512];
    doq_buf[0] = (uint8_t)(query_len >> 8);
    doq_buf[1] = (uint8_t)(query_len & 0xFFu);
    memcpy(doq_buf + 2, query, query_len);
    doq_buf[2] = 0x00; doq_buf[3] = 0x00;   /* DNS ID → 0 */

    /* Собрать STREAM frame + возможный ACK */
    uint8_t frames[1500];
    size_t  flen = 0;
    if (dc->recv_need_ack[2]) {
        flen += frame_ack(frames + flen, sizeof(frames) - flen,
                           dc->recv_largest[2]);
        dc->recv_need_ack[2] = 0;
    }
    flen += frame_stream(frames + flen, sizeof(frames) - flen,
                          st->stream_id, 0,
                          doq_buf, 2 + query_len, true);

    uint8_t pkt[DOQ_MAX_PKT + 64u];
    size_t  plen = encode_short(dc, frames, flen, pkt, sizeof(pkt));
    if (!plen) return -1;
    doq_send(dc, pkt, plen);
    return 0;
}

void doq_check_timeouts(doq_pool_t *pool)
{
    int64_t now = doq_now_ms();

    for (int i = 0; i < pool->count; i++) {
        doq_conn_t *dc = &pool->conns[i];
        if (dc->state == DOQ_CONN_IDLE) continue;

        /* Handshake timeout */
        if (dc->state == DOQ_CONN_HANDSHAKE &&
            now - dc->created_ms > DOQ_HANDSHAKE_TIMEOUT_MS) {
            log_msg(LOG_WARN, "DoQ: таймаут рукопожатия");
            for (int s = 0; s < DOQ_MAX_STREAMS; s++) {
                if (dc->streams[s].state != DOQ_STREAM_FREE && dc->streams[s].cb)
                    dc->streams[s].cb(dc->streams[s].cb_ctx, NULL, 0, -1);
            }
            goto reset_conn;
        }

        /* Stream timeouts */
        for (int s = 0; s < DOQ_MAX_STREAMS; s++) {
            doq_stream_t *st = &dc->streams[s];
            if (st->state == DOQ_STREAM_FREE || now < st->deadline_ms) continue;
            log_msg(LOG_WARN, "DoQ: таймаут запроса stream %llu",
                    (unsigned long long)st->stream_id);
            if (st->cb) st->cb(st->cb_ctx, NULL, 0, -1);
            memset(st, 0, sizeof(*st));
        }

        /* Idle PING / close */
        if (dc->state == DOQ_CONN_READY) {
            int64_t idle = now - dc->last_rx_ms;
            if (idle > DOQ_IDLE_PING_MS && idle < DOQ_IDLE_CLOSE_MS) {
                uint8_t frames[8], pkt[64];
                size_t flen = frame_ping(frames, sizeof(frames));
                size_t plen = encode_short(dc, frames, flen,
                                            pkt, sizeof(pkt));
                if (plen) doq_send(dc, pkt, plen);
            } else if (idle >= DOQ_IDLE_CLOSE_MS) {
                uint8_t frames[32], pkt[128];
                size_t flen = frame_conn_close(frames, sizeof(frames), 0);
                size_t plen = encode_short(dc, frames, flen,
                                            pkt, sizeof(pkt));
                if (plen) doq_send(dc, pkt, plen);
                goto reset_conn;
            }
        }
        continue;

    reset_conn:
        if (dc->ssl) { wolfSSL_free(dc->ssl); dc->ssl = NULL; }
        epoll_ctl(pool->epoll_fd, EPOLL_CTL_DEL, dc->udp_fd, NULL);
        close(dc->udp_fd);
        for (int k = 0; k < 3; k++) quic_keys_free(&dc->keys[k]);
        memset(dc, 0, sizeof(*dc));
        dc->udp_fd = -1;
        dc->state  = DOQ_CONN_IDLE;
    }
}

#endif /* CONFIG_EBURNET_DOQ */

/* Подавить предупреждение empty translation unit при DOQ=0 */
typedef int dns_upstream_doq_empty_tu_;

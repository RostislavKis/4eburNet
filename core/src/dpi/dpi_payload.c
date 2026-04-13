/*
 * dpi_payload.c — нативная генерация fake TLS ClientHello + QUIC Initial
 *
 * TLS fingerprint: Chrome 120+ (17 cipher suites, 15 extensions).
 * QUIC: Long Header v1 + random DCID + PADDING payload.
 */

#if CONFIG_EBURNET_DPI || CONFIG_EBURNET_STLS

#include "4eburnet.h"
#include "dpi/dpi_payload.h"

#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

/* ── Случайные байты ────────────────────────────────────────────── */

static void fill_random(uint8_t *buf, int len)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = 0;
        while (n < len) {
            ssize_t r = read(fd, buf + n, (size_t)(len - n));
            if (r > 0)                    { n += r; continue; }
            if (r < 0 && errno == EINTR)  { continue; }
            break;
        }
        close(fd);
        if (n == len) return;
    }
    /* Fallback PRNG — /dev/urandom всегда есть на OpenWrt */
    static uint64_t state;
    if (!state)
        state = (uint64_t)(uintptr_t)buf ^ (uint64_t)time(NULL) ^ (uint64_t)getpid();
    for (int i = 0; i < len; i++) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        buf[i] = (uint8_t)(state & 0xFF);
    }
}

/* ── Вспомогательные write-макросы ─────────────────────────────── */

/* Записать uint8 */
#define W1(p, v)      do { *(p)++ = (uint8_t)(v); } while(0)
/* Записать uint16 big-endian */
#define W2(p, v)      do { *(p)++ = (uint8_t)((v)>>8); *(p)++ = (uint8_t)((v)&0xFF); } while(0)
/* Записать N байт */
#define WN(p, src, n) do { memcpy((p), (src), (size_t)(n)); (p) += (n); } while(0)

/* ── TLS ClientHello ────────────────────────────────────────────── */

int dpi_make_tls_clienthello_ex(uint8_t *buf, int buf_size,
                                 const char *sni,
                                 const uint8_t *client_random,
                                 const uint8_t *session_id,
                                 uint8_t *out_random)
{
    if (!buf || buf_size < 300) return -1;
    if (!sni || sni[0] == '\0') sni = EBURNET_DPI_DEFAULT_FAKE_SNI;

    int sni_len = 0;
    while (sni[sni_len] && sni_len < 253) sni_len++;

    /* Строим в стековом буфере (768 байт хватает для SNI до 253 символов),
     * затем копируем в buf пользователя */
    uint8_t tmp[768];
    uint8_t *p = tmp;

    /* ── [1] TLS Record Header ── */
    uint8_t *record_start = p;
    W1(p, 0x16);          /* ContentType: Handshake */
    W1(p, 0x03); W1(p, 0x01); /* Version: TLS 1.0 (backward compat, как Chrome) */
    uint8_t *record_len_ptr = p; p += 2;  /* RecordLength — патчим в конце */

    /* ── [2] Handshake Header ── */
    uint8_t *hs_start = p;
    W1(p, 0x01);               /* HandshakeType: ClientHello */
    uint8_t *hs_len_ptr = p; p += 3;  /* HandshakeLength (3 байта) — патчим в конце */

    /* ── [3] ClientVersion ── */
    W1(p, 0x03); W1(p, 0x03);  /* TLS 1.2 */

    /* ── [4] Random (32 байта) ── */
    if (client_random)
        WN(p, client_random, 32);
    else
        { fill_random(p, 32); p += 32; }
    if (out_random)
        memcpy(out_random, p - 32, 32);

    /* ── [5] SessionID (32 байта) ── */
    W1(p, 32);
    if (session_id)
        WN(p, session_id, 32);
    else
        { fill_random(p, 32); p += 32; }

    /* ── [6] CipherSuites: 17 Chrome суитов ── */
    static const uint8_t ciphers[] = {
        0x00, 0x22,  /* длина списка = 34 байта = 17 × 2 */
        0x13,0x01, 0x13,0x03, 0x13,0x02,           /* TLS 1.3 */
        0xc0,0x2b, 0xc0,0x2f, 0xcc,0xa9, 0xcc,0xa8,
        0xc0,0x2c, 0xc0,0x30, 0xc0,0x0a, 0xc0,0x09,
        0xc0,0x13, 0xc0,0x14, 0x00,0x9c, 0x00,0x9d,
        0x00,0x2f, 0x00,0x35
    };
    WN(p, ciphers, sizeof(ciphers));

    /* ── [7] Compression: null ── */
    W1(p, 1); W1(p, 0x00);

    /* ── [8] Extensions ── */
    uint8_t *ext_len_ptr = p; p += 2;   /* общая длина extensions — патчим в конце */
    uint8_t *ext_start   = p;

    /* ext 0x0000: server_name (SNI) */
    W2(p, 0x0000);
    int sni_ext_data = 2 + 1 + 2 + sni_len;  /* listlen(2) + type(1) + namelen(2) + name */
    W2(p, sni_ext_data);
    W2(p, sni_ext_data - 2);  /* ServerNameList length */
    W1(p, 0x00);               /* NameType: host_name */
    W2(p, sni_len);
    WN(p, sni, sni_len);

    /* ext 0x0017: extended_master_secret */
    W2(p, 0x0017); W2(p, 0);

    /* ext 0xff01: renegotiation_info */
    W2(p, 0xff01); W2(p, 1); W1(p, 0);

    /* ext 0x000a: supported_groups */
    static const uint8_t sg[] = {
        0x00,0x08,  /* список = 4 × 2 байта */
        0x00,0x1d,  /* x25519 */
        0x00,0x17,  /* secp256r1 */
        0x00,0x18,  /* secp384r1 */
        0x00,0x19,  /* secp521r1 */
    };
    W2(p, 0x000a); W2(p, sizeof(sg)); WN(p, sg, sizeof(sg));

    /* ext 0x000b: ec_point_formats */
    W2(p, 0x000b); W2(p, 2); W1(p, 1); W1(p, 0x00);

    /* ext 0x0023: session_ticket (пустой) */
    W2(p, 0x0023); W2(p, 0);

    /* ext 0x0010: ALPN — h2 + http/1.1 */
    static const uint8_t alpn[] = {
        0x00,0x0c,  /* protocol list length = 12 */
        0x02,'h','2',
        0x08,'h','t','t','p','/','1','.','1'
    };
    W2(p, 0x0010); W2(p, sizeof(alpn)); WN(p, alpn, sizeof(alpn));

    /* ext 0x0005: status_request (OCSP) */
    static const uint8_t sr[] = { 0x01, 0x00,0x00, 0x00,0x00 };
    W2(p, 0x0005); W2(p, sizeof(sr)); WN(p, sr, sizeof(sr));

    /* ext 0x0012: signed_certificate_timestamp */
    W2(p, 0x0012); W2(p, 0);

    /* ext 0x0033: key_share (x25519, 32 random байта — не нули, audit C.2 #1) */
    uint8_t ks[36];
    ks[0] = 0x00; ks[1] = 0x22;   /* ClientKeyShareList length = 34 */
    ks[2] = 0x00; ks[3] = 0x1d;   /* NamedGroup: x25519 */
    ks[4] = 0x00; ks[5] = 0x20;   /* KeyExchange length = 32 */
    fill_random(ks + 6, 32);       /* 32 random байта публичного ключа */
    W2(p, 0x0033); W2(p, sizeof(ks)); WN(p, ks, sizeof(ks));

    /* ext 0x002b: supported_versions — TLS 1.3, TLS 1.2 */
    static const uint8_t sv[] = {
        0x04,         /* список = 2 × 2 байта */
        0x03,0x04,    /* TLS 1.3 */
        0x03,0x03,    /* TLS 1.2 */
    };
    W2(p, 0x002b); W2(p, sizeof(sv)); WN(p, sv, sizeof(sv));

    /* ext 0x000d: signature_algorithms — 8 алгоритмов */
    static const uint8_t sa[] = {
        0x00,0x10,              /* список = 8 × 2 байта */
        0x04,0x03, 0x08,0x04, 0x04,0x01, 0x05,0x03,
        0x08,0x05, 0x05,0x01, 0x08,0x06, 0x06,0x01,
    };
    W2(p, 0x000d); W2(p, sizeof(sa)); WN(p, sa, sizeof(sa));

    /* ext 0x002d: psk_key_exchange_modes — psk_dhe_ke */
    W2(p, 0x002d); W2(p, 2); W1(p, 1); W1(p, 0x01);

    /* ext 0x001c: record_size_limit (audit C.2 #2) */
    W2(p, 0x001c); W2(p, 2); W2(p, 0x4001);

    /* ext 0x001b: compress_certificate — zlib (0x0002) */
    W2(p, 0x001b); W2(p, 3); W1(p, 2); W2(p, 0x0002);

    /* ── [9] Патчим длины ── */
    int ext_len = (int)(p - ext_start);
    ext_len_ptr[0] = (uint8_t)(ext_len >> 8);
    ext_len_ptr[1] = (uint8_t)(ext_len & 0xFF);

    int hs_body_len = (int)(p - hs_start - 4);
    hs_len_ptr[0] = (uint8_t)(hs_body_len >> 16);
    hs_len_ptr[1] = (uint8_t)(hs_body_len >> 8);
    hs_len_ptr[2] = (uint8_t)(hs_body_len & 0xFF);

    int record_body_len = (int)(p - record_start - 5);
    record_len_ptr[0] = (uint8_t)(record_body_len >> 8);
    record_len_ptr[1] = (uint8_t)(record_body_len & 0xFF);

    int total = (int)(p - tmp);
    if (buf_size < total) return -1;
    memcpy(buf, tmp, (size_t)total);
    return total;
}

#if CONFIG_EBURNET_DPI
int dpi_make_tls_clienthello(uint8_t *buf, int buf_size, const char *sni)
{
    return dpi_make_tls_clienthello_ex(buf, buf_size, sni, NULL, NULL, NULL);
}
#endif

/* ── QUIC Initial ───────────────────────────────────────────────── */

#if CONFIG_EBURNET_DPI
int dpi_make_quic_initial(uint8_t *buf, int buf_size)
{
    if (!buf || buf_size < 1200) return -1;

    memset(buf, 0, 1200);

    /* Long Header: bit7=1 (Long), bit6=1 (Fixed), bits4-5=00 (Initial),
     * bits0-1=11 (4-byte Packet Number) */
    buf[0] = 0xC3;

    /* Version: QUIC v1 */
    buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00; buf[4] = 0x01;

    /* DCIL = 8, случайный DCID (8 байт) */
    buf[5] = 0x08;
    fill_random(buf + 6, 8);

    /* SCIL = 0 */
    buf[14] = 0x00;

    /* Token Length = 0 */
    buf[15] = 0x00;

    /* Length (varint): PN(4) + payload(1178) = 1182 = 0x049E
     * 2-byte QUIC varint: prefix 01 → [0x44, 0x9E] */
    buf[16] = 0x44;
    buf[17] = 0x9E;

    /* Packet Number (4 байта): 0x00000000 (уже нули от memset) */

    /* Payload (байты 22..1199): PADDING frames = нули (RFC 9000 §19.1).
     * ПРИМЕЧАНИЕ: реальный QUIC Initial содержит зашифрованный AEAD payload
     * (HKDF + AES-128-GCM с ключами, производными от DCID).
     * Для стратегии fake+TTL это допущение: пакет не достигает сервера,
     * DPI инспектирует только заголовок (Long Header + Version + DCID).
     * При необходимости заменить нули на fill_random(). */

    return 1200;
}
#endif /* CONFIG_EBURNET_DPI */

#endif /* CONFIG_EBURNET_DPI || CONFIG_EBURNET_STLS */

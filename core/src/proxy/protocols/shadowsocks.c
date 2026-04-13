/*
 * Shadowsocks 2022 (2022-blake3-chacha20-poly1305)
 *
 * AEAD шифрование без TLS overhead.
 * BLAKE3 KDF для session key, ChaCha20-Poly1305 для AEAD.
 * Формат: [salt][encrypted_header+tag][encrypted_chunks...]
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/coding.h>

#include "proxy/protocols/shadowsocks.h"
#include "crypto/blake3.h"
#include "net_utils.h"
#include "4eburnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/syscall.h>

#define SS_CONTEXT "shadowsocks 2022 session subkey"

/* ------------------------------------------------------------------ */
/*  Вспомогательные                                                    */
/* ------------------------------------------------------------------ */

/* Инкремент nonce как little-endian counter */
static void nonce_increment(uint8_t nonce[SS_NONCE_LEN])
{
    for (int i = 0; i < SS_NONCE_LEN; i++) {
        if (++nonce[i] != 0)
            break;
    }
}

/* Генерация случайных байт: getrandom() + fallback /dev/urandom (H-26) */
static int random_bytes(uint8_t *buf, size_t len)
{
#ifdef __NR_getrandom
    size_t done = 0;
    while (done < len) {
        ssize_t r = syscall(__NR_getrandom, buf + done, len - done, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) goto fallback;
        done += (size_t)r;
    }
    return 0;
fallback:
#endif
    {
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return -1;
        size_t done2 = 0;
        while (done2 < len) {
            ssize_t n = read(fd, buf + done2, len - done2);
            if (n <= 0) { close(fd); return -1; }
            done2 += (size_t)n;
        }
        close(fd);
        return 0;
    }
}

/* KDF: session_key = Blake3DeriveKey(context, PSK || salt) */
static void ss_derive_key(const ss_psk_t *psk,
                          const uint8_t salt[SS_SALT_LEN],
                          uint8_t session_key[32])
{
    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, SS_CONTEXT);

    /* Вход KDF: PSK (32 байта) || salt (32 байта) = 64 байта */
    blake3_hasher_update(&hasher, psk->bytes, 32);
    blake3_hasher_update(&hasher, salt, SS_SALT_LEN);

    blake3_hasher_finalize(&hasher, session_key, 32);
}

/* AEAD encrypt: plaintext → ciphertext + tag, инкремент nonce */
static int ss_aead_encrypt(uint8_t key[32], uint8_t nonce[SS_NONCE_LEN],
                           const uint8_t *plain, size_t plain_len,
                           uint8_t *cipher, uint8_t tag[SS_TAG_LEN])
{
    int rc = wc_ChaCha20Poly1305_Encrypt(key, nonce,
                                          NULL, 0,
                                          plain, plain_len,
                                          cipher, tag);
    if (rc == 0) nonce_increment(nonce);
    return rc;
}

/* AEAD decrypt: ciphertext + tag → plaintext, инкремент nonce */
static int ss_aead_decrypt(uint8_t key[32], uint8_t nonce[SS_NONCE_LEN],
                           const uint8_t *cipher, size_t cipher_len,
                           const uint8_t tag[SS_TAG_LEN],
                           uint8_t *plain)
{
    int rc = wc_ChaCha20Poly1305_Decrypt(key, nonce,
                                          NULL, 0,
                                          cipher, cipher_len,
                                          tag, plain);
    if (rc == 0) nonce_increment(nonce);
    return rc;
}

/* ------------------------------------------------------------------ */
/*  ss_psk_decode — base64 PSK из конфига                              */
/* ------------------------------------------------------------------ */

int ss_psk_decode(const char *b64, ss_psk_t *out)
{
    word32 out_len = 32;
    int rc = Base64_Decode((const byte *)b64, strlen(b64),
                           out->bytes, &out_len);
    if (rc != 0 || out_len != 32) {
        log_msg(LOG_ERROR, "SS: невалидный PSK (base64, нужно 32 байта)");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  ss_handshake_start                                                 */
/* ------------------------------------------------------------------ */

int ss_handshake_start(ss_state_t *ss, int fd,
                       const struct sockaddr_storage *dst,
                       const char *psk_b64)
{
    memset(ss, 0, sizeof(*ss));

    /* Инициализировать overflow буфер (C-08) */
    ss->overflow_buf = NULL;
    ss->overflow_len = 0;
    ss->overflow_off = 0;

    /* Декодировать PSK */
    if (ss_psk_decode(psk_b64, &ss->psk) < 0)
        return -1;

    /* Генерировать salt */
    if (random_bytes(ss->salt, SS_SALT_LEN) < 0) {
        log_msg(LOG_ERROR, "SS: не удалось сгенерировать salt");
        return -1;
    }

    /* KDF: session key */
    ss_derive_key(&ss->psk, ss->salt, ss->session_key);

    /* Построить plaintext header */
    uint8_t header[128];
    int pos = 0;

    /* Timestamp (8 байт big-endian) */
    uint64_t ts = (uint64_t)time(NULL);
    for (int i = 7; i >= 0; i--)
        header[pos++] = (uint8_t)(ts >> (i * 8));

    /* Тип адреса + адрес + порт */
    if (dst->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)dst;
        header[pos++] = 0x01;
        memcpy(header + pos, &s4->sin_addr, 4);
        pos += 4;
        memcpy(header + pos, &s4->sin_port, 2);
        pos += 2;
    } else if (dst->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)dst;
        header[pos++] = 0x04;
        memcpy(header + pos, &s6->sin6_addr, 16);
        pos += 16;
        memcpy(header + pos, &s6->sin6_port, 2);
        pos += 2;
    } else {
        return -1;
    }

    /* Зашифровать header */
    uint8_t encrypted[128];
    uint8_t tag[SS_TAG_LEN];

    if (ss_aead_encrypt(ss->session_key, ss->send_nonce,
                        header, pos,
                        encrypted, tag) != 0) {
        log_msg(LOG_ERROR, "SS: ошибка шифрования header");
        return -1;
    }

    /* Отправить: [salt][encrypted_header][tag] */
    uint8_t packet[256];
    size_t pkt_len = 0;
    memcpy(packet, ss->salt, SS_SALT_LEN);
    pkt_len += SS_SALT_LEN;
    memcpy(packet + pkt_len, encrypted, pos);
    pkt_len += pos;
    memcpy(packet + pkt_len, tag, SS_TAG_LEN);
    pkt_len += SS_TAG_LEN;

    /* Write loop для nonblocking fd (H-01: EAGAIN = fatal для framed SS 2022) */
    size_t written = 0;
    while (written < pkt_len) {
        ssize_t w = write(fd, packet + written, pkt_len - written);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                log_msg(LOG_WARN, "SS: EAGAIN при handshake (partial frame)");
                return -1;
            }
            log_msg(LOG_WARN, "SS: не удалось отправить header (%zu/%zu)",
                    written, pkt_len);
            return -1;
        }
        written += (size_t)w;
    }

    ss->header_sent = true;

    char dst_str[64];
    net_format_addr(dst, dst_str, sizeof(dst_str));
    log_msg(LOG_DEBUG, "SS 2022: handshake отправлен (%zu байт), dst: %s",
            pkt_len, dst_str);

    return 0;
}

/* ------------------------------------------------------------------ */
/*  ss_send — AEAD chunk                                               */
/* ------------------------------------------------------------------ */

/* M-34: внутренняя функция для одного chunk ≤ 0x3FFF */
static ssize_t ss_send_chunk(ss_state_t *ss, int fd,
                             const uint8_t *data, size_t len)
{
    if (len == 0 || len > 0x3FFF)
        return -1;

    /* Шифруем длину (2 байта big-endian) */
    uint8_t len_plain[2] = {
        (uint8_t)((len >> 8) & 0xFF),
        (uint8_t)(len & 0xFF),
    };
    uint8_t len_cipher[2];
    uint8_t len_tag[SS_TAG_LEN];

    if (ss_aead_encrypt(ss->session_key, ss->send_nonce,
                        len_plain, 2, len_cipher, len_tag) != 0)
        return -1;

    /* Шифруем данные (C-04: malloc вместо 32KB стека) */
    if (len > SIZE_MAX - SS_TAG_LEN - 4) return -1;  /* M-10: overflow guard */
    uint8_t *data_cipher = malloc(len + SS_TAG_LEN);
    if (!data_cipher) return -1;
    uint8_t data_tag[SS_TAG_LEN];

    if (ss_aead_encrypt(ss->session_key, ss->send_nonce,
                        data, len, data_cipher, data_tag) != 0) {
        free(data_cipher);
        return -1;
    }

    /* Отправить: [len_cipher+tag][data_cipher+tag] */
    size_t total = 2 + SS_TAG_LEN + len + SS_TAG_LEN;
    uint8_t *packet = malloc(total);
    if (!packet) { free(data_cipher); return -1; }
    size_t pkt_len = 0;

    memcpy(packet + pkt_len, len_cipher, 2);    pkt_len += 2;
    memcpy(packet + pkt_len, len_tag, SS_TAG_LEN); pkt_len += SS_TAG_LEN;
    memcpy(packet + pkt_len, data_cipher, len); pkt_len += len;
    memcpy(packet + pkt_len, data_tag, SS_TAG_LEN); pkt_len += SS_TAG_LEN;

    /* Write loop (H-02: EAGAIN = fatal для framed SS 2022) */
    size_t written = 0;
    while (written < pkt_len) {
        ssize_t w = write(fd, packet + written, pkt_len - written);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                log_msg(LOG_WARN, "SS: EAGAIN при send_chunk (partial frame)");
                free(data_cipher);
                free(packet);
                return -1;
            }
            free(data_cipher);
            free(packet);
            return -1;
        }
        written += (size_t)w;
    }
    free(data_cipher); data_cipher = NULL;
    free(packet);      packet = NULL;

    return (ssize_t)len;
}

/* M-34: ss_send с разбиением на chunks при len > 0x3FFF */
ssize_t ss_send(ss_state_t *ss, int fd,
                const uint8_t *data, size_t len)
{
    size_t total = 0;
    while (len > 0) {
        size_t chunk = (len > 0x3FFF) ? 0x3FFF : len;
        ssize_t r = ss_send_chunk(ss, fd, data, chunk);
        if (r < 0) return (total > 0) ? (ssize_t)total : -1;
        data  += chunk;
        len   -= chunk;
        total += chunk;
    }
    return (ssize_t)total;
}

/* ------------------------------------------------------------------ */
/*  ss_recv — AEAD chunk decrypt                                       */
/* ------------------------------------------------------------------ */

ssize_t ss_recv(ss_state_t *ss, int fd,
                uint8_t *buf, size_t buflen)
{
    /* Проверить overflow от предыдущего вызова (C-08) */
    if (ss->overflow_buf && ss->overflow_len > 0) {
        size_t avail = ss->overflow_len - ss->overflow_off;
        size_t copy = avail < buflen ? avail : buflen;
        memcpy(buf, ss->overflow_buf + ss->overflow_off, copy);
        ss->overflow_off += copy;
        if (ss->overflow_off >= ss->overflow_len) {
            free(ss->overflow_buf);
            ss->overflow_buf = NULL;
            ss->overflow_len = 0;
            ss->overflow_off = 0;
        }
        return (ssize_t)copy;
    }

    /* Фаза 1: читаем length frame (18 байт) с accumulator */
    if (!ss->recv_len_done) {
        while (ss->recv_len_read < 18) {
            ssize_t n = read(fd,
                ss->recv_len_buf + ss->recv_len_read,
                18 - ss->recv_len_read);
            if (n <= 0) return n;
            ss->recv_len_read += n;
        }

        uint8_t len_plain[2];
        if (ss_aead_decrypt(ss->session_key, ss->recv_nonce,
                            ss->recv_len_buf, 2,
                            ss->recv_len_buf + 2,
                            len_plain) != 0) {
            log_msg(LOG_WARN, "SS: ошибка дешифрования длины");
            return -1;
        }

        uint16_t data_len = ((uint16_t)len_plain[0] << 8) | len_plain[1];
        if (data_len == 0 || data_len > 0x3FFF)
            return -1;

        ss->recv_data_need = data_len + SS_TAG_LEN;
        ss->recv_data_read = 0;
        ss->recv_len_done  = true;
        ss->recv_len_read  = 0;
    }

    /* Фаза 2: читаем data frame с accumulator */
    while (ss->recv_data_read < ss->recv_data_need) {
        ssize_t n = read(fd,
            ss->recv_data_buf + ss->recv_data_read,
            ss->recv_data_need - ss->recv_data_read);
        if (n <= 0) return n;
        ss->recv_data_read += n;
    }

    size_t data_len = ss->recv_data_need - SS_TAG_LEN;

    if (data_len > buflen) {
        /* Дешифруем полный блок во временный буфер, сохраняем остаток (C-08) */
        uint8_t *tmp = malloc(data_len);
        if (!tmp) return -1;

        if (ss_aead_decrypt(ss->session_key, ss->recv_nonce,
                            ss->recv_data_buf, data_len,
                            ss->recv_data_buf + data_len,
                            tmp) != 0) {
            free(tmp);
            log_msg(LOG_WARN, "SS: ошибка дешифрования данных");
            return -1;
        }
        memcpy(buf, tmp, buflen);
        /* Сохранить остаток в overflow буфер — tmp НЕ освобождаем */
        ss->overflow_buf = tmp;
        ss->overflow_len = data_len;
        ss->overflow_off = buflen;
        ss->recv_len_done = false;
        return (ssize_t)buflen;
    }

    if (ss_aead_decrypt(ss->session_key, ss->recv_nonce,
                        ss->recv_data_buf, data_len,
                        ss->recv_data_buf + data_len,
                        buf) != 0) {
        log_msg(LOG_WARN, "SS: ошибка дешифрования данных");
        return -1;
    }

    /* Сброс для следующего chunk */
    ss->recv_len_done = false;
    return (ssize_t)data_len;
}

/* ------------------------------------------------------------------ */
/*  ss_cleanup — освобождение ресурсов SS соединения                   */
/* ------------------------------------------------------------------ */

void ss_cleanup(ss_state_t *ss)
{
    if (ss->overflow_buf) {
        free(ss->overflow_buf);
        ss->overflow_buf = NULL;
        ss->overflow_len = 0;
        ss->overflow_off = 0;
    }
}

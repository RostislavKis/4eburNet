#ifndef SHADOWSOCKS_H
#define SHADOWSOCKS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

/* PSK — 32 байта (base64 в конфиге, бинарный в памяти) */
typedef struct {
    uint8_t bytes[32];
} ss_psk_t;

/* SS 2022 AEAD overhead */
#define SS_SALT_LEN    32
#define SS_TAG_LEN     16
#define SS_NONCE_LEN   12

/* Состояние SS 2022 соединения */
typedef struct ss_state {
    ss_psk_t    psk;
    uint8_t     session_key[32];    /* Blake3(PSK, salt) */
    uint8_t     salt[SS_SALT_LEN];  /* случайный salt */
    uint8_t     send_nonce[SS_NONCE_LEN]; /* counter для отправки */
    uint8_t     recv_nonce[SS_NONCE_LEN]; /* counter для приёма */
    bool        header_sent;
    /* Буферы неблокирующего чтения chunk */
    uint8_t     recv_len_buf[18];       /* length frame (2 + 16) */
    uint8_t     recv_len_read;          /* байт прочитано (0-18) */
    bool        recv_len_done;          /* length frame готов */
    uint8_t     recv_data_buf[16400];   /* data frame */
    size_t      recv_data_need;         /* байт нужно */
    size_t      recv_data_read;         /* байт прочитано */
} ss_state_t;

/* Декодировать base64 PSK из конфига */
int ss_psk_decode(const char *b64, ss_psk_t *out);

/* Начать SS 2022: генерация salt, KDF, отправка зашифрованного header */
int ss_handshake_start(ss_state_t *ss, int fd,
                       const struct sockaddr_storage *dst,
                       const char *psk_b64);

/* Отправить данные через SS 2022 AEAD chunk */
ssize_t ss_send(ss_state_t *ss, int fd,
                const uint8_t *data, size_t len);

/* Получить данные через SS 2022 AEAD chunk */
ssize_t ss_recv(ss_state_t *ss, int fd,
                uint8_t *buf, size_t buflen);

#endif /* SHADOWSOCKS_H */

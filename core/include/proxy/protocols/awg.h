#ifndef AWG_H
#define AWG_H

#include "crypto/noise.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

/* AWG 2.0 конфигурация обфускации */
typedef struct {
    uint8_t  local_private_key[32];
    uint8_t  remote_public_key[32];
    uint8_t  preshared_key[32];
    bool     has_psk;
    /* Header obfuscation ranges */
    uint32_t h1_min, h1_max;
    uint32_t h2_min, h2_max;
    uint32_t h3_min, h3_max;
    uint32_t h4_min, h4_max;
    /* Padding */
    uint16_t s1, s2, s3, s4;
    /* Junk packets */
    uint8_t  jc;
    uint16_t jmin, jmax;
    /* CPS signature packets */
    char     i1[256], i2[256], i3[256], i4[256], i5[256];
    /* Keepalive */
    uint16_t keepalive;
} awg_config_t;

/* Состояние AWG соединения */
typedef struct awg_state {
    awg_config_t  cfg;
    noise_state_t noise;
    int           udp_fd;
    uint32_t      local_index;
    uint32_t      remote_index;
    bool          handshake_done;
    time_t        last_handshake;
    time_t        last_send;
    /* Буфер приёма */
    uint8_t       recv_buf[2048];
    size_t        recv_len;
} awg_state_t;

/* Декодировать base64 ключ (44 символа → 32 байта) */
int awg_key_decode(const char *b64, uint8_t key[32]);

/* Парсить диапазон "100000-800000" → min, max */
void awg_parse_range(const char *str, uint32_t *min, uint32_t *max);

/* Построить CPS пакет по спецификации I1-I5 */
int awg_cps_build(const char *spec, uint8_t *out, size_t *outlen);

/* Инициализация из конфига сервера */
int awg_init(awg_state_t *awg, const void *server_config);

/* Начать AWG handshake (UDP) */
int awg_handshake_start(awg_state_t *awg,
                        const char *server_ip, uint16_t server_port);

/* Обработать входящий пакет (handshake response или data) */
int awg_process_incoming(awg_state_t *awg);

/* Отправить данные через AWG туннель */
ssize_t awg_send(awg_state_t *awg, const uint8_t *data, size_t len);

/* Принять данные из AWG туннеля */
ssize_t awg_recv(awg_state_t *awg, uint8_t *buf, size_t buflen);

/* Keepalive tick */
void awg_tick(awg_state_t *awg);

/* Закрыть */
void awg_close(awg_state_t *awg);

#endif /* AWG_H */

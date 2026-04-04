#ifndef NOISE_H
#define NOISE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Noise_IKpsk2 состояние (WireGuard) */
typedef struct {
    uint8_t  local_static_private[32];
    uint8_t  local_static_public[32];
    uint8_t  remote_static_public[32];
    uint8_t  local_ephemeral_private[32];
    uint8_t  local_ephemeral_public[32];
    uint8_t  preshared_key[32];
    bool     has_psk;
    /* Handshake state */
    uint8_t  chaining_key[32];
    uint8_t  hash[32];
    /* Результат handshake */
    uint8_t  send_key[32];
    uint8_t  recv_key[32];
    uint32_t send_counter;
    uint32_t recv_counter;
    uint32_t local_index;
    uint32_t remote_index;
    bool     handshake_complete;
} noise_state_t;

/* Размеры пакетов WireGuard (до AWG обфускации) */
#define NOISE_INIT_SIZE      148
#define NOISE_RESPONSE_SIZE   92
#define NOISE_TRANSPORT_OVERHEAD 32  /* header(16) + tag(16) */

/* Инициализация */
int noise_init(noise_state_t *ns,
               const uint8_t local_priv[32],
               const uint8_t remote_pub[32],
               const uint8_t psk[32], bool has_psk);

/* Создать Handshake Init сообщение */
int noise_handshake_init_create(noise_state_t *ns,
                                uint8_t *out, size_t *outlen);

/* Обработать Handshake Response */
int noise_handshake_response_process(noise_state_t *ns,
                                     const uint8_t *resp, size_t resp_len);

/* Зашифровать transport данные */
int noise_encrypt(noise_state_t *ns,
                  const uint8_t *plain, size_t plain_len,
                  uint8_t *out, size_t *out_len);

/* Расшифровать transport данные */
int noise_decrypt(noise_state_t *ns,
                  const uint8_t *cipher, size_t cipher_len,
                  uint8_t *out, size_t *out_len);

#endif /* NOISE_H */

/*
 * ChaCha20-Poly1305
 *
 * Шифрование для Shadowsocks AEAD.
 * На ARM-процессорах быстрее AES без аппаратного ускорения.
 */

#include <stdio.h>

int chacha20_encrypt(const void *key, const void *nonce,
                     const void *plaintext, int len, void *ciphertext)
{
    /* TODO: wolfSSL ChaCha20-Poly1305 */
    return -1;
}

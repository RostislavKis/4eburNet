#ifndef BLAKE3_H
#define BLAKE3_H

/*
 * Минимальная реализация BLAKE3 для SS 2022 KDF.
 * Поддерживает только derive_key mode и вход < 1024 байт.
 * На основе спецификации BLAKE3.
 */

#include <stdint.h>
#include <stddef.h>

#define BLAKE3_KEY_LEN    32
#define BLAKE3_OUT_LEN    32
#define BLAKE3_BLOCK_LEN  64
#define BLAKE3_CHUNK_LEN  1024

typedef struct {
    uint32_t cv[8];           /* chaining value */
    uint8_t  buf[BLAKE3_BLOCK_LEN];
    uint8_t  buf_len;
    uint8_t  blocks_compressed;
    uint8_t  flags;
    uint64_t chunk_counter;
} blake3_hasher;

/* Инициализация для derive_key mode */
void blake3_hasher_init_derive_key(blake3_hasher *self,
                                   const char *context);

/* Добавить данные */
void blake3_hasher_update(blake3_hasher *self,
                          const void *input, size_t input_len);

/* Финализация — записать хэш в out */
void blake3_hasher_finalize(const blake3_hasher *self,
                            uint8_t *out, size_t out_len);

#endif /* BLAKE3_H */

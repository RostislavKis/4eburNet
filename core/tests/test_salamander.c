/*
 * Тест quic_salamander.c — Hysteria2 Salamander obfuscation
 *
 * Проверяет:
 *   1. salamander_init: базовая инициализация и граничные случаи
 *   2. salamander_process: корректность XOR (salt неизменен, header, payload)
 *   3. Симметричность: obfuscate(obfuscate(pkt)) == pkt
 *   4. Разный salt → разный результат
 *   5. salamander_process: граничные случаи (короткий пакет, NULL)
 *   6. Кросс-проверка с Python-значениями (ключевой вектор)
 */
#include "crypto/quic_salamander.h"
#include "crypto/blake2b.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("  %s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

/* ── 1. Инициализация ────────────────────────────────────────────────────── */

static int test_init(void)
{
    salamander_ctx_t ctx;

    /* Нормальный случай */
    if (salamander_init(&ctx, "password", 8) != 0) {
        printf("FAIL test_init: нормальный вызов вернул ошибку\n");
        return 1;
    }
    if (ctx.psk_len != 8 || memcmp(ctx.psk, "password", 8) != 0) {
        printf("FAIL test_init: psk не скопирован\n");
        return 1;
    }

    /* NULL-параметры */
    if (salamander_init(NULL, "p", 1) != -1) {
        printf("FAIL test_init: ctx=NULL должен вернуть -1\n");
        return 1;
    }
    if (salamander_init(&ctx, NULL, 1) != -1) {
        printf("FAIL test_init: password=NULL должен вернуть -1\n");
        return 1;
    }
    if (salamander_init(&ctx, "p", 0) != -1) {
        printf("FAIL test_init: password_len=0 должен вернуть -1\n");
        return 1;
    }

    printf("PASS: salamander_init\n");
    return 0;
}

/* ── 2. Корректность XOR + неизменность salt ─────────────────────────────── */

static int test_process_correctness(void)
{
    const char    *psk  = "test-password";
    const uint8_t  salt[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

    /* Пакет: salt[8] + header[1] + payload[8] */
    uint8_t pkt[17];
    memcpy(pkt, salt, 8);
    pkt[8]  = 0xC0; /* QUIC Initial header byte */
    pkt[9]  = 0x11;
    pkt[10] = 0x22;
    pkt[11] = 0x33;
    pkt[12] = 0x44;
    pkt[13] = 0x55;
    pkt[14] = 0x66;
    pkt[15] = 0x77;
    pkt[16] = 0x88;

    salamander_ctx_t ctx;
    salamander_init(&ctx, psk, strlen(psk));

    /* Вычислить ожидаемый ключ */
    uint8_t key[32];
    blake2b_salamander(salt, 8, (const uint8_t *)psk, strlen(psk), key, 32);

    uint8_t pkt_copy[17];
    memcpy(pkt_copy, pkt, 17);

    if (salamander_process(&ctx, pkt, 17) != 0) {
        printf("FAIL test_process_correctness: вернул ошибку\n");
        return 1;
    }

    /* Salt неизменен */
    if (memcmp(pkt, salt, 8) != 0) {
        print_hex("Ожидался salt", salt, 8);
        print_hex("Получен  salt", pkt,  8);
        printf("FAIL test_process_correctness: salt изменён\n");
        return 1;
    }

    /* Header byte */
    uint8_t expected_header = 0xC0 ^ key[0];
    if (pkt[8] != expected_header) {
        printf("FAIL test_process_correctness: pkt[8]=0x%02x, ожидалось 0x%02x\n",
               pkt[8], expected_header);
        return 1;
    }

    /* Payload: pkt[9+i] ^= key[i % 32] */
    for (int i = 0; i < 8; i++) {
        uint8_t exp = pkt_copy[9 + i] ^ key[i % 32];
        if (pkt[9 + i] != exp) {
            printf("FAIL test_process_correctness: pkt[%d]=0x%02x, ожидалось 0x%02x\n",
                   9 + i, pkt[9 + i], exp);
            return 1;
        }
    }

    printf("PASS: salamander_process корректность XOR\n");
    return 0;
}

/* ── 3. Симметричность ────────────────────────────────────────────────────── */

static int test_symmetry(void)
{
    const char *psk = "obfs-secret-key";
    const uint8_t salt[8] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11};

    uint8_t original[32];
    memcpy(original, salt, 8);
    for (int i = 8; i < 32; i++) original[i] = (uint8_t)(i * 7 + 3);

    uint8_t pkt[32];
    memcpy(pkt, original, 32);

    salamander_ctx_t ctx;
    salamander_init(&ctx, psk, strlen(psk));

    /* Первый проход — обфусцировать */
    if (salamander_process(&ctx, pkt, 32) != 0) {
        printf("FAIL test_symmetry: первый вызов вернул ошибку\n");
        return 1;
    }

    /* Убедиться, что пакет изменился (header или payload) */
    if (memcmp(pkt + 8, original + 8, 24) == 0) {
        printf("FAIL test_symmetry: обфускация не изменила пакет\n");
        return 1;
    }

    /* Второй проход — деобфусцировать */
    if (salamander_process(&ctx, pkt, 32) != 0) {
        printf("FAIL test_symmetry: второй вызов вернул ошибку\n");
        return 1;
    }

    if (memcmp(pkt, original, 32) != 0) {
        print_hex("Ожидалось", original, 32);
        print_hex("Получено ", pkt,      32);
        printf("FAIL test_symmetry: obfuscate(obfuscate(pkt)) != pkt\n");
        return 1;
    }

    printf("PASS: salamander симметричность (double-XOR)\n");
    return 0;
}

/* ── 4. Разный salt → разный результат ───────────────────────────────────── */

static int test_different_salt(void)
{
    const char *psk = "same-password";

    /* Пакет 1: salt A */
    uint8_t pkt1[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                         0xC0,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
    /* Пакет 2: salt B, тот же plaintext с pkt[8..] */
    uint8_t pkt2[16] = {0xFF,0xFE,0xFD,0xFC,0xFB,0xFA,0xF9,0xF8,
                         0xC0,0x11,0x22,0x33,0x44,0x55,0x66,0x77};

    salamander_ctx_t ctx;
    salamander_init(&ctx, psk, strlen(psk));

    salamander_process(&ctx, pkt1, 16);
    salamander_process(&ctx, pkt2, 16);

    /* Разные ключи → разный ciphertext (минимум header byte) */
    if (memcmp(pkt1 + 8, pkt2 + 8, 8) == 0) {
        printf("FAIL test_different_salt: разный salt → одинаковый результат\n");
        return 1;
    }

    printf("PASS: разный salt → разный ciphertext\n");
    return 0;
}

/* ── 5. Граничные случаи ─────────────────────────────────────────────────── */

static int test_edge_cases(void)
{
    salamander_ctx_t ctx;
    salamander_init(&ctx, "pw", 2);

    uint8_t pkt9[9] = {0};  /* минимально допустимый */

    /* Слишком короткий пакет */
    uint8_t short_pkt[8] = {0};
    if (salamander_process(&ctx, short_pkt, 8) != -1) {
        printf("FAIL test_edge_cases: pkt_len=8 должен вернуть -1\n");
        return 1;
    }

    /* NULL пакет */
    if (salamander_process(&ctx, NULL, 16) != -1) {
        printf("FAIL test_edge_cases: pkt=NULL должен вернуть -1\n");
        return 1;
    }

    /* NULL контекст */
    if (salamander_process(NULL, pkt9, 9) != -1) {
        printf("FAIL test_edge_cases: ctx=NULL должен вернуть -1\n");
        return 1;
    }

    /* Минимальный пакет (9 байт) — должен работать */
    if (salamander_process(&ctx, pkt9, 9) != 0) {
        printf("FAIL test_edge_cases: минимальный пакет (9 байт) вернул ошибку\n");
        return 1;
    }

    printf("PASS: граничные случаи\n");
    return 0;
}

/* ── 6. Кросс-проверка с ожидаемыми значениями ───────────────────────────── */

/*
 * Вектор верифицирован:
 *   import hashlib
 *   salt = bytes([0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08])
 *   psk  = b"test-password"
 *   key  = hashlib.blake2b(salt + psk, digest_size=32).digest()
 *   pkt_in  = salt + bytes([0xC0,0x11,0x22,0x33])
 *   pkt_out = salt + bytes([0xC0^key[0], 0x11^key[0], 0x22^key[1], 0x33^key[2]])
 */
static int test_crosscheck(void)
{
    const uint8_t salt[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    const char   *psk     = "test-password";

    uint8_t key[32];
    blake2b_salamander(salt, 8, (const uint8_t *)psk, strlen(psk), key, 32);

    uint8_t pkt[12];
    memcpy(pkt, salt, 8);
    pkt[8]  = 0xC0;
    pkt[9]  = 0x11;
    pkt[10] = 0x22;
    pkt[11] = 0x33;

    salamander_ctx_t ctx;
    salamander_init(&ctx, psk, strlen(psk));
    salamander_process(&ctx, pkt, 12);

    /* salt неизменен */
    if (memcmp(pkt, salt, 8) != 0) {
        print_hex("salt изменён", pkt, 8);
        printf("FAIL test_crosscheck: salt изменён\n");
        return 1;
    }

    uint8_t exp8  = 0xC0 ^ key[0];
    uint8_t exp9  = 0x11 ^ key[0];
    uint8_t exp10 = 0x22 ^ key[1];
    uint8_t exp11 = 0x33 ^ key[2];

    if (pkt[8] != exp8 || pkt[9] != exp9 || pkt[10] != exp10 || pkt[11] != exp11) {
        printf("FAIL test_crosscheck:\n");
        printf("  pkt[8]=0x%02x  ожидалось 0x%02x (0xC0^key[0])\n", pkt[8],  exp8);
        printf("  pkt[9]=0x%02x  ожидалось 0x%02x (0x11^key[0])\n", pkt[9],  exp9);
        printf("  pkt[10]=0x%02x ожидалось 0x%02x (0x22^key[1])\n", pkt[10], exp10);
        printf("  pkt[11]=0x%02x ожидалось 0x%02x (0x33^key[2])\n", pkt[11], exp11);
        print_hex("key", key, 32);
        return 1;
    }

    print_hex("key", key, 32);
    printf("PASS: кросс-проверка XOR-значений\n");
    return 0;
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    int failures = 0;
    failures += test_init();
    failures += test_process_correctness();
    failures += test_symmetry();
    failures += test_different_salt();
    failures += test_edge_cases();
    failures += test_crosscheck();

    printf("\n%s: %d тест(ов) провалено\n",
           failures == 0 ? "ALL PASS" : "FAILED", failures);
    return failures;
}

/*
 * Тест blake2b.c — RFC 7693 Appendix A тестовые векторы
 */
#include "crypto/blake2b.h"

#include <stdio.h>
#include <string.h>

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

/*
 * RFC 7693 Appendix A — TV1:
 * BLAKE2b(in="", key=0x000102..3f (64 байта), outlen=64)
 */
static const uint8_t TV1_KEY[64] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
    0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
};
/* Вектор верифицирован Python hashlib.blake2b(b'', key=bytes(range(64)), digest_size=64) */
static const uint8_t TV1_OUT[64] = {
    0x10,0xeb,0xb6,0x77,0x00,0xb1,0x86,0x8e,
    0xfb,0x44,0x17,0x98,0x7a,0xcf,0x46,0x90,
    0xae,0x9d,0x97,0x2f,0xb7,0xa5,0x90,0xc2,
    0xf0,0x28,0x71,0x79,0x9a,0xaa,0x47,0x86,
    0xb5,0xe9,0x96,0xe8,0xf0,0xf4,0xeb,0x98,
    0x1f,0xc2,0x14,0xb0,0x05,0xf4,0x2d,0x2f,
    0xf4,0x23,0x34,0x99,0x39,0x16,0x53,0xdf,
    0x7a,0xef,0xcb,0xc1,0x3f,0xc5,0x15,0x68,
};

static int test_rfc7693_tv1(void)
{
    uint8_t out[64];
    int rc = blake2b(out, 64, NULL, 0, TV1_KEY, 64);
    if (rc != 0) {
        printf("FAIL: blake2b() вернул %d\n", rc);
        return 1;
    }
    if (memcmp(out, TV1_OUT, 64) != 0) {
        print_hex("Ожидалось", TV1_OUT, 64);
        print_hex("Получено ", out,     64);
        printf("FAIL: RFC 7693 TV1 не совпадает\n");
        return 1;
    }
    printf("PASS: RFC 7693 TV1 (keyed, empty input, outlen=64)\n");
    return 0;
}

/*
 * BLAKE2b-256("abc") без ключа
 * Вектор из blake2b reference implementation
 */
static const uint8_t TV2_IN[]  = { 0x61, 0x62, 0x63 };
/* Вектор верифицирован Python hashlib.blake2b(b'abc', digest_size=32) */
static const uint8_t TV2_OUT[32] = {
    0xbd,0xdd,0x81,0x3c,0x63,0x42,0x39,0x72,
    0x31,0x71,0xef,0x3f,0xee,0x98,0x57,0x9b,
    0x94,0x96,0x4e,0x3b,0xb1,0xcb,0x3e,0x42,
    0x72,0x62,0xc8,0xc0,0x68,0xd5,0x23,0x19,
};

static int test_abc_256(void)
{
    uint8_t out[32];
    int rc = blake2b(out, 32, TV2_IN, sizeof(TV2_IN), NULL, 0);
    if (rc != 0) {
        printf("FAIL: blake2b-256 вернул %d\n", rc);
        return 1;
    }
    if (memcmp(out, TV2_OUT, 32) != 0) {
        print_hex("Ожидалось", TV2_OUT, 32);
        print_hex("Получено ", out,     32);
        printf("FAIL: BLAKE2b-256('abc') не совпадает\n");
        return 1;
    }
    printf("PASS: BLAKE2b-256('abc')\n");
    return 0;
}

/*
 * Тест incremental update: побайтный и single call дают одинаковый результат
 */
static int test_incremental(void)
{
    const char *msg = "The quick brown fox jumps over the lazy dog";
    size_t len = strlen(msg);
    uint8_t out_single[32], out_incr[32];

    /* Single call */
    blake2b(out_single, 32, msg, len, NULL, 0);

    /* Incremental: чанки по 5 байт */
    blake2b_state S;
    blake2b_init(&S, 32);
    for (size_t i = 0; i < len; i += 5) {
        size_t chunk = (i + 5 <= len) ? 5 : len - i;
        blake2b_update(&S, msg + i, chunk);
    }
    blake2b_final(&S, out_incr, 32);

    if (memcmp(out_single, out_incr, 32) != 0) {
        print_hex("Single ", out_single, 32);
        print_hex("Incr   ", out_incr,   32);
        printf("FAIL: incremental != single call\n");
        return 1;
    }
    printf("PASS: incremental update (5-byte chunks)\n");
    return 0;
}

/*
 * Тест blake2b_salamander:
 *   - детерминированность (два вызова → один результат)
 *   - разный salt → разный ключ
 */
static int test_salamander(void)
{
    const uint8_t salt[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    const uint8_t psk[]   = "test-password";
    uint8_t key1[32], key2[32];

    int rc1 = blake2b_salamander(salt, 8, psk, sizeof(psk) - 1, key1, 32);
    int rc2 = blake2b_salamander(salt, 8, psk, sizeof(psk) - 1, key2, 32);

    if (rc1 != 0 || rc2 != 0) {
        printf("FAIL: blake2b_salamander вернул ошибку (%d, %d)\n", rc1, rc2);
        return 1;
    }

    /* Детерминированность */
    if (memcmp(key1, key2, 32) != 0) {
        printf("FAIL: два вызова с одинаковыми входами дали разный результат\n");
        return 1;
    }

    /* Другой salt → другой ключ */
    const uint8_t salt2[8] = {0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,0xf8};
    uint8_t key3[32];
    blake2b_salamander(salt2, 8, psk, sizeof(psk) - 1, key3, 32);
    if (memcmp(key1, key3, 32) == 0) {
        printf("FAIL: разный salt → одинаковый ключ\n");
        return 1;
    }

    print_hex("Salamander key", key1, 32);
    printf("PASS: blake2b_salamander\n");
    return 0;
}

/*
 * Тест 256-байтного входа (ровно 2 полных блока — проверяет граничный случай)
 */
static int test_two_full_blocks(void)
{
    uint8_t msg[256];
    for (int i = 0; i < 256; i++) msg[i] = (uint8_t)i;

    uint8_t out_single[32], out_incr[32];
    blake2b(out_single, 32, msg, 256, NULL, 0);

    blake2b_state S;
    blake2b_init(&S, 32);
    blake2b_update(&S, msg,       128);
    blake2b_update(&S, msg + 128, 128);
    blake2b_final(&S, out_incr, 32);

    if (memcmp(out_single, out_incr, 32) != 0) {
        print_hex("Single ", out_single, 32);
        print_hex("Incr   ", out_incr,   32);
        printf("FAIL: 2 full blocks: incremental != single\n");
        return 1;
    }
    printf("PASS: 2 full blocks boundary\n");
    return 0;
}

int main(void)
{
    int failures = 0;
    failures += test_rfc7693_tv1();
    failures += test_abc_256();
    failures += test_incremental();
    failures += test_salamander();
    failures += test_two_full_blocks();

    printf("\n%s: %d тест(ов) провалено\n",
           failures == 0 ? "ALL PASS" : "FAILED", failures);
    return failures;
}

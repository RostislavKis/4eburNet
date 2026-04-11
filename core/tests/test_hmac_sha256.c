/*
 * test_hmac_sha256.c — тесты HMAC-SHA256 (D.1)
 * RFC 4231 test vectors + verify ok/fail
 */

#include "crypto/hmac_sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fail_count = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fail_count++; } \
    else { printf("PASS: %s\n", msg); } \
} while(0)

/* Вспомогательная: hex → bytes */
static int hex2bin(const char *hex, uint8_t *out, size_t outlen)
{
    size_t hlen = strlen(hex);
    if (hlen / 2 > outlen) return -1;
    for (size_t i = 0; i < hlen / 2; i++) {
        unsigned hi, lo;
        if (sscanf(hex + i * 2, "%1x%1x", &hi, &lo) != 2) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(hlen / 2);
}

static void bin2hex(const uint8_t *bin, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++)
        sprintf(out + i * 2, "%02x", bin[i]);
}

/* RFC 4231 Case 1: key = 0x0b * 20, data = "Hi There" */
static void test_rfc4231_case1(void)
{
    uint8_t key[20];
    memset(key, 0x0b, 20);
    const uint8_t *data = (const uint8_t *)"Hi There";
    uint8_t out[32];

    int rc = hmac_sha256(key, 20, data, 8, out);
    ASSERT(rc == 0, "rfc4231_case1: hmac_sha256 вернул 0");

    uint8_t expected[32];
    hex2bin("b0344c61d8db38535ca8afceaf0bf12b"
            "881dc200c9833da726e9376c2e32cff7", expected, 32);
    ASSERT(memcmp(out, expected, 32) == 0, "rfc4231_case1: результат совпадает");
}

/* RFC 4231 Case 2: key = "Jefe", data = "what do ya want for nothing?" */
static void test_rfc4231_case2(void)
{
    const uint8_t *key = (const uint8_t *)"Jefe";
    const uint8_t *data = (const uint8_t *)"what do ya want for nothing?";
    uint8_t out[32];

    int rc = hmac_sha256(key, 4, data, 28, out);
    ASSERT(rc == 0, "rfc4231_case2: hmac_sha256 вернул 0");

    uint8_t expected[32];
    hex2bin("5bdcc146bf60754e6a042426089575c7"
            "5a003f089d2739839dec58b964ec3843", expected, 32);
    ASSERT(memcmp(out, expected, 32) == 0, "rfc4231_case2: результат совпадает");
}

/* Пустые данные (datalen=0) */
static void test_empty_data(void)
{
    const uint8_t key[] = "test-key";
    uint8_t out[32];
    int rc = hmac_sha256(key, 8, NULL, 0, out);
    ASSERT(rc == 0, "empty_data: hmac_sha256 с datalen=0 не упал");

    /* Проверяем что out не нули (HMAC пустых данных != все нули) */
    uint8_t zero[32] = {0};
    ASSERT(memcmp(out, zero, 32) != 0, "empty_data: результат не нулевой");
}

/* hmac_sha256_verify: корректный HMAC */
static void test_verify_ok(void)
{
    uint8_t key[20];
    memset(key, 0x0b, 20);
    const uint8_t *data = (const uint8_t *)"Hi There";

    uint8_t expected[32];
    hex2bin("b0344c61d8db38535ca8afceaf0bf12b"
            "881dc200c9833da726e9376c2e32cff7", expected, 32);

    int ok = hmac_sha256_verify(key, 20, data, 8, expected, 32);
    ASSERT(ok == 1, "verify_ok: полное совпадение 32 байт");

    /* Частичное совпадение первых 4 байт */
    ok = hmac_sha256_verify(key, 20, data, 8, expected, 4);
    ASSERT(ok == 1, "verify_ok: первые 4 байта совпадают");
}

/* hmac_sha256_verify: неверный HMAC */
static void test_verify_fail(void)
{
    uint8_t key[20];
    memset(key, 0x0b, 20);
    const uint8_t *data = (const uint8_t *)"Hi There";

    uint8_t wrong[32];
    memset(wrong, 0xff, 32);

    int ok = hmac_sha256_verify(key, 20, data, 8, wrong, 32);
    ASSERT(ok == 0, "verify_fail: неверный HMAC отклонён (32 байт)");

    ok = hmac_sha256_verify(key, 20, data, 8, wrong, 4);
    ASSERT(ok == 0, "verify_fail: неверный HMAC отклонён (4 байта)");
}

int main(void)
{
    printf("=== test_hmac_sha256 ===\n\n");

    test_rfc4231_case1();
    test_rfc4231_case2();
    test_empty_data();
    test_verify_ok();
    test_verify_fail();

    printf("\nALL PASS: %d тест(ов) провалено\n", fail_count);
    return fail_count ? 1 : 0;
}

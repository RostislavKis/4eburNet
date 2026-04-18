/*
 * test_bloom.c — тесты Bloom filter (bloom.h)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "geo/bloom.h"

#define PASS(msg) do { printf("  PASS: %s\n", msg); } while(0)
#define FAIL(msg) do { printf("  FAIL: %s\n", msg); failed++; } while(0)

static int failed = 0;

/* T1: нет false negative — всё добавленное находится */
static void test_no_false_negative(void)
{
    uint8_t bits[BLOOM_BYTES];
    memset(bits, 0, sizeof(bits));
    const uint32_t nbits = BLOOM_BYTES * 8u;

    const char *domains[] = {
        "google.com", "ya.ru", "instagram.com",
        "doubleclick.net", "facebook.com",
        "very-long-domain-name-that-exceeds-sixteen-bytes.example.com",
        "a.b.c.d.e.f.g", "localhost", "x",
        "0123456789abcdef0123456789abcdef",
    };
    const int n = (int)(sizeof(domains) / sizeof(domains[0]));

    for (int i = 0; i < n; i++)
        bloom_add(bits, nbits, domains[i]);

    for (int i = 0; i < n; i++) {
        if (!bloom_check(bits, nbits, domains[i])) {
            printf("  FAIL T1: false negative для '%s'\n", domains[i]);
            failed++;
            return;
        }
    }
    PASS("T1: нет false negative (10 доменов)");
}

/* T2: FPR < 5% при большой нагрузке */
static void test_fpr(void)
{
    uint8_t *bits = calloc(1, BLOOM_BYTES);
    if (!bits) { FAIL("T2: OOM"); return; }
    const uint32_t nbits = BLOOM_BYTES * 8u;

    /* Добавить 50000 "присутствующих" доменов */
    char buf[64];
    for (int i = 0; i < 50000; i++) {
        snprintf(buf, sizeof(buf), "domain-%d.example.com", i);
        bloom_add(bits, nbits, buf);
    }

    /* Проверить 10000 "отсутствующих" доменов */
    int fp = 0;
    for (int i = 100000; i < 110000; i++) {
        snprintf(buf, sizeof(buf), "absent-%d.test.org", i);
        if (bloom_check(bits, nbits, buf)) fp++;
    }
    free(bits);

    float fpr = (float)fp / 10000.0f;
    if (fpr < 0.05f) {
        printf("  PASS: T2: FPR=%.2f%% < 5%% (50K доменов, 512KB)\n",
               fpr * 100.0f);
    } else {
        printf("  FAIL: T2: FPR=%.2f%% >= 5%%\n", fpr * 100.0f);
        failed++;
    }
}

/* T3: bloom_check(NULL, 0, key) → true (нет filter = pass) */
static void test_null_filter(void)
{
    if (!bloom_check(NULL, 0, "google.com"))
        FAIL("T3: bloom_check(NULL,0) должен возвращать true");
    else
        PASS("T3: bloom_check(NULL, 0, key) = true");

    if (!bloom_check(NULL, 42, "test.com"))
        FAIL("T3b: bloom_check(NULL,42) должен возвращать true");
    else
        PASS("T3b: bloom_check(NULL, 42, key) = true");
}

/* T4: bits != NULL, nbits == 0 → true */
static void test_zero_nbits(void)
{
    uint8_t bits[64] = {0xFF};
    if (!bloom_check(bits, 0, "anything"))
        FAIL("T4: bloom_check(bits, 0, key) должен возвращать true");
    else
        PASS("T4: bloom_check(bits, 0, key) = true");
}

int main(void)
{
    printf("=== test_bloom ===\n");
    test_no_false_negative();
    test_fpr();
    test_null_filter();
    test_zero_nbits();
    printf("=== %s (%d failures) ===\n",
           failed == 0 ? "ALL PASS" : "FAILED", failed);
    return failed ? 1 : 0;
}

/*
 * test_simd_strcmp.c — тесты fast_strcmp (simd_strcmp.h)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "geo/simd_strcmp.h"

#define PASS(msg) do { printf("  PASS: %s\n", msg); } while(0)
#define FAIL(msg) do { printf("  FAIL: %s\n", msg); failed++; } while(0)

static int failed = 0;

/* Определить активный режим */
static const char *simd_mode(void)
{
#if defined(__ARM_NEON)
    return "NEON";
#elif defined(__SSE2__)
    return "SSE2";
#else
    return "SWAR";
#endif
}

/* T1: fast_strcmp == strcmp для коротких строк (< 16 байт) */
static void test_short_strings(void)
{
    const char *pairs[][2] = {
        { "google.com",    "google.com"    },
        { "ya.ru",         "ya.ru"         },
        { "a",             "b"             },
        { "abc",           "abd"           },
        { "instagram.com", "instagram.com" },
        { "",              ""              },
        { "x",             "x"             },
        { "abc",           "abc"           },
    };
    for (size_t i = 0; i < sizeof(pairs)/sizeof(pairs[0]); i++) {
        int r1 = strcmp(pairs[i][0], pairs[i][1]);
        int r2 = fast_strcmp(pairs[i][0], pairs[i][1]);
        int sign1 = (r1 > 0) - (r1 < 0);
        int sign2 = (r2 > 0) - (r2 < 0);
        if (sign1 != sign2) {
            printf("  FAIL T1: '%s' vs '%s': strcmp=%d fast=%d\n",
                   pairs[i][0], pairs[i][1], r1, r2);
            failed++;
            return;
        }
    }
    PASS("T1: fast_strcmp == strcmp для коротких строк");
}

/* T2: строки длиннее 16 байт (пересечение границы блока) */
static void test_long_strings(void)
{
    /* Статические массивы с 16-byte padding для NEON/SSE2 безопасности */
    static const char a[] =
        "abcdefghijklmnopqrstuvwxyz0123456789.com"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    static const char b[] =
        "abcdefghijklmnopqrstuvwxyz0123456789.com"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    static const char c[] =
        "abcdefghijklmnopqrstuvwxyz0123456789.net"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    if (fast_strcmp(a, b) != 0)
        FAIL("T2a: равные длинные строки → должно быть 0");
    else
        PASS("T2a: равные длинные строки = 0");

    int r1 = strcmp(a, c);
    int r2 = fast_strcmp(a, c);
    int s1 = (r1 > 0) - (r1 < 0);
    int s2 = (r2 > 0) - (r2 < 0);
    if (s1 != s2) {
        printf("  FAIL T2b: знаки не совпадают: strcmp=%d fast=%d\n", r1, r2);
        failed++;
    } else {
        PASS("T2b: длинные строки с различием → знак совпадает");
    }
}

/* T3: одинаковые строки → 0 */
static void test_equal(void)
{
    static const char s[] =
        "doubleclick.net"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    if (fast_strcmp(s, s) != 0)
        FAIL("T3: fast_strcmp(s, s) должно быть 0");
    else
        PASS("T3: fast_strcmp(s, s) = 0");
}

/* T4: порядок fast_strcmp совпадает со strcmp */
static void test_ordering(void)
{
    static const char p[][48] = {
        "apple.com\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        "banana.org\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        "cherry.net\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    };
    int ok = 1;
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            int r1 = strcmp(p[i], p[j]);
            int r2 = fast_strcmp(p[i], p[j]);
            int s1 = (r1 > 0) - (r1 < 0);
            int s2 = (r2 > 0) - (r2 < 0);
            if (s1 != s2) {
                printf("  FAIL T4: '%s' vs '%s'\n", p[i], p[j]);
                failed++; ok = 0;
            }
        }
    }
    if (ok) PASS("T4: порядок fast_strcmp совпадает со strcmp");
}

int main(void)
{
    printf("=== test_simd_strcmp (режим: %s) ===\n", simd_mode());
    test_short_strings();
    test_long_strings();
    test_equal();
    test_ordering();
    printf("=== %s (%d failures) ===\n",
           failed == 0 ? "ALL PASS" : "FAILED", failed);
    return failed ? 1 : 0;
}

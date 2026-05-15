/*
 * test_dispatcher_pure.c
 *
 * Тест чистых функций dispatcher.c без линковки dispatcher.c целиком.
 * map_fingerprint и dpi_list_match — скопированы inline из dispatcher.c.
 * WHY inline: обе функции static — недоступны из отдельной compile unit.
 */

/* dpi_list_match требует CONFIG_EBURNET_DPI */
#ifndef CONFIG_EBURNET_DPI
#define CONFIG_EBURNET_DPI 1
#endif

#include "crypto/tls.h"
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <stdbool.h>

/* ── Скопировано из src/proxy/dispatcher.c (строки 701-720) ─────────── */
static tls_fingerprint_t map_fingerprint(const char *s)
{
    if (!s || !s[0])                                return TLS_FP_CHROME120;
    if (strcmp(s, "firefox") == 0)                  return TLS_FP_FIREFOX121;
    if (strcmp(s, "safari") == 0 || strcmp(s, "ios") == 0)
                                                    return TLS_FP_IOS17;
    if (strcmp(s, "chrome") == 0)                   return TLS_FP_CHROME120;
    if (strcmp(s, "random") == 0) {
        static const tls_fingerprint_t profiles[3] = {
            TLS_FP_CHROME120,
            TLS_FP_FIREFOX121,
            TLS_FP_IOS17,
        };
        static atomic_uint _fp_counter = 0;
        unsigned idx = atomic_fetch_add_explicit(&_fp_counter, 1u,
                                                 memory_order_relaxed) % 3u;
        return profiles[idx];
    }
    return TLS_FP_CHROME120;
}

/* ── Скопировано из src/proxy/dispatcher.c (строки 2757-2773) ────────── */
#if CONFIG_EBURNET_DPI
static bool dpi_list_match(const DpiDomainList *list, const char *domain)
{
    if (!domain || !domain[0]) return false;
    for (int i = 0; i < list->count; i++) {
        const char *p = list->entries[i];
        if (p[0] == '*' && p[1] == '.') {
            size_t plen = strlen(p + 1);
            size_t dlen = strlen(domain);
            if (dlen > plen && strcmp(domain + dlen - plen, p + 1) == 0)
                return true;
        } else if (strcasecmp(domain, p) == 0) {
            return true;
        }
    }
    return false;
}
#endif

/* ── map_fingerprint тесты ────────────────────────────────────────────── */
static int test_map_fingerprint(void)
{
    int fail = 0;

    if (map_fingerprint("chrome") != TLS_FP_CHROME120) {
        fprintf(stderr, "FAIL [fp-1]: chrome → не TLS_FP_CHROME120\n"); fail = 1;
    }
    if (map_fingerprint("firefox") != TLS_FP_FIREFOX121) {
        fprintf(stderr, "FAIL [fp-2]: firefox → не TLS_FP_FIREFOX121\n"); fail = 1;
    }
    if (map_fingerprint("safari") != TLS_FP_IOS17) {
        fprintf(stderr, "FAIL [fp-3]: safari → не TLS_FP_IOS17\n"); fail = 1;
    }
    if (map_fingerprint("ios") != TLS_FP_IOS17) {
        fprintf(stderr, "FAIL [fp-4]: ios → не TLS_FP_IOS17\n"); fail = 1;
    }

    /* "random" — ротация по трём профилям; проверяем что значение корректное */
    tls_fingerprint_t r = map_fingerprint("random");
    if (r != TLS_FP_CHROME120 && r != TLS_FP_FIREFOX121 && r != TLS_FP_IOS17) {
        fprintf(stderr, "FAIL [fp-5]: random → некорректное значение %d\n", (int)r); fail = 1;
    }

    /* неизвестная строка → TLS_FP_CHROME120 (дефолт) */
    if (map_fingerprint("unknown_value") != TLS_FP_CHROME120) {
        fprintf(stderr, "FAIL [fp-6]: unknown_value → не TLS_FP_CHROME120\n"); fail = 1;
    }

    /* NULL → TLS_FP_CHROME120, не segfault */
    if (map_fingerprint(NULL) != TLS_FP_CHROME120) {
        fprintf(stderr, "FAIL [fp-7]: NULL → не TLS_FP_CHROME120\n"); fail = 1;
    }

    /* "" → TLS_FP_CHROME120 */
    if (map_fingerprint("") != TLS_FP_CHROME120) {
        fprintf(stderr, "FAIL [fp-8]: \"\" → не TLS_FP_CHROME120\n"); fail = 1;
    }

    if (!fail) printf("  [1] map_fingerprint PASS (8/8)\n");
    return fail;
}

/* ── dpi_list_match тесты ─────────────────────────────────────────────── */
#if CONFIG_EBURNET_DPI
static int test_dpi_list_match(void)
{
    int fail = 0;

    /* пустой список */
    DpiDomainList empty = {0};
    if (dpi_list_match(&empty, "example.com")) {
        fprintf(stderr, "FAIL [dpi-1]: пустой список дал true\n"); fail = 1;
    }

    /* NULL domain → false, не segfault */
    if (dpi_list_match(&empty, NULL)) {
        fprintf(stderr, "FAIL [dpi-2]: NULL domain дал true\n"); fail = 1;
    }

    /* "" domain → false */
    if (dpi_list_match(&empty, "")) {
        fprintf(stderr, "FAIL [dpi-3]: \"\" domain дал true\n"); fail = 1;
    }

    /* точное совпадение */
    DpiDomainList list = {0};
    snprintf(list.entries[0], sizeof(list.entries[0]), "example.com");
    snprintf(list.entries[1], sizeof(list.entries[1]), "test.org");
    list.count = 2;

    if (!dpi_list_match(&list, "example.com")) {
        fprintf(stderr, "FAIL [dpi-4]: example.com не найден\n"); fail = 1;
    }
    if (!dpi_list_match(&list, "EXAMPLE.COM")) {
        fprintf(stderr, "FAIL [dpi-5]: EXAMPLE.COM (case) не найден\n"); fail = 1;
    }

    /* отсутствующий домен → false */
    if (dpi_list_match(&list, "other.com")) {
        fprintf(stderr, "FAIL [dpi-6]: other.com ошибочно найден\n"); fail = 1;
    }

    /* sub.example.com при наличии example.com (без wildcard) → false */
    if (dpi_list_match(&list, "sub.example.com")) {
        fprintf(stderr, "FAIL [dpi-7]: sub.example.com дал true без wildcard\n"); fail = 1;
    }

    /* wildcard *.example.com матчит sub.example.com */
    DpiDomainList wc = {0};
    snprintf(wc.entries[0], sizeof(wc.entries[0]), "*.example.com");
    wc.count = 1;

    if (!dpi_list_match(&wc, "foo.example.com")) {
        fprintf(stderr, "FAIL [dpi-8]: foo.example.com не совпал с *.example.com\n"); fail = 1;
    }
    /* wildcard НЕ матчит сам домен без префикса */
    if (dpi_list_match(&wc, "example.com")) {
        fprintf(stderr, "FAIL [dpi-9]: example.com ошибочно совпал с *.example.com\n"); fail = 1;
    }

    if (!fail) printf("  [2] dpi_list_match PASS (9/9)\n");
    return fail;
}
#endif

int main(void)
{
    int fail = 0;
    printf("=== test-dispatcher-pure ===\n");
    fail += test_map_fingerprint();
#if CONFIG_EBURNET_DPI
    fail += test_dpi_list_match();
#endif
    if (fail)
        printf("FAIL — %d тест(а) провалено\n", fail);
    else
        printf("PASS — все тесты OK\n");
    return fail ? 1 : 0;
}

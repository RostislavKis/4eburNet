/*
 * test_dpi_filter.c — тесты dpi_filter.c (C.1)
 *
 * Компилируется с -DCONFIG_EBURNET_DPI=1.
 * Создаёт временные файлы ipset/whitelist/autohosts в /tmp/.
 */

#define CONFIG_EBURNET_DPI 1
#include "dpi/dpi_filter.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <unistd.h>

/* Заглушка log_msg */
void log_msg(int level, const char *fmt, ...) {
    (void)level;
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n");
}

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", (msg)); failures++; } \
    else         { printf("PASS: %s\n", (msg)); } \
} while(0)

/* ── Создать временные файлы для тестов ─────────────────────────── */

#define DPI_TEST_DIR "/tmp/test_dpi_4eburnet"

static void write_file(const char *name, const char *content)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", DPI_TEST_DIR, name);
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return; }
    fputs(content, f);
    fclose(f);
}

static void setup_test_files(void)
{
    /* Создать директорию */
    system("mkdir -p " DPI_TEST_DIR);

    /* ipset.txt: IPv4 + IPv6 диапазоны */
    write_file("ipset.txt",
        "# Cloudflare\n"
        "1.1.1.0/24\n"
        "104.16.0.0/13\n"
        "2606:4700::/32\n"
        "# Akamai\n"
        "23.0.0.0/12\n"
        "# Single host\n"
        "8.8.8.8\n"
        "# OVH\n"
        "51.75.0.0/16\n"
        "# Тест алгоритма: широкий /8 с 6 вложенными подсетями\n"
        "10.0.0.0/8\n"
        "10.1.0.0/24\n"
        "10.2.0.0/24\n"
        "10.3.0.0/24\n"
        "10.4.0.0/24\n"
        "10.5.0.0/24\n"
    );

    /* whitelist.txt: домены-исключения */
    write_file("whitelist.txt",
        "# Whitelist — не применять DPI\n"
        "google.com\n"
        "apple.com\n"
        "yandex.ru\n"
    );

    /* autohosts.txt: принудительный bypass */
    write_file("autohosts.txt",
        "# Autohosts — принудительный DPI bypass\n"
        "youtube.com\n"
        "instagram.com\n"
        "discord.com\n"
    );
}

static void cleanup_test_files(void)
{
    system("rm -rf " DPI_TEST_DIR);
}

/* ── Вспомогательные ─────────────────────────────────────────────── */

static uint32_t ip4(const char *s)
{
    struct in_addr a;
    inet_pton(AF_INET, s, &a);
    return ntohl(a.s_addr);
}

static void ip6(const char *s, uint8_t out[16])
{
    struct in6_addr a;
    inet_pton(AF_INET6, s, &a);
    memcpy(out, &a, 16);
}

/* ── Тест 1: init + stats ────────────────────────────────────────── */
static void test_init(void)
{
    int rc = dpi_filter_init(DPI_TEST_DIR);
    CHECK(rc == 0,              "init: rc == 0");
    CHECK(dpi_filter_is_ready(), "is_ready после init");

    dpi_filter_stats_t st;
    dpi_filter_get_stats(&st);
    CHECK(st.ipv4_ranges > 0, "stats: ipv4_ranges > 0");
    CHECK(st.ipv6_ranges > 0, "stats: ipv6_ranges > 0");
    CHECK(st.whitelist   == 3, "stats: whitelist == 3");
    CHECK(st.autohosts   == 3, "stats: autohosts == 3");
}

/* ── Тест 2: IPv4 match ──────────────────────────────────────────── */
static void test_ipv4_match(void)
{
    /* 1.1.1.1 → в 1.1.1.0/24 → BYPASS */
    CHECK(dpi_filter_match_ipv4(ip4("1.1.1.1"), 443) == DPI_MATCH_BYPASS,
          "ipv4: 1.1.1.1 в 1.1.1.0/24 → BYPASS");

    /* 1.1.1.0 → начало диапазона → BYPASS */
    CHECK(dpi_filter_match_ipv4(ip4("1.1.1.0"), 443) == DPI_MATCH_BYPASS,
          "ipv4: 1.1.1.0 (начало) → BYPASS");

    /* 1.1.1.255 → конец диапазона → BYPASS */
    CHECK(dpi_filter_match_ipv4(ip4("1.1.1.255"), 443) == DPI_MATCH_BYPASS,
          "ipv4: 1.1.1.255 (конец) → BYPASS");

    /* 1.1.2.1 → вне 1.1.1.0/24 → NONE */
    CHECK(dpi_filter_match_ipv4(ip4("1.1.2.1"), 443) == DPI_MATCH_NONE,
          "ipv4: 1.1.2.1 вне диапазона → NONE");

    /* 104.20.0.1 → в 104.16.0.0/13 → BYPASS */
    CHECK(dpi_filter_match_ipv4(ip4("104.20.0.1"), 443) == DPI_MATCH_BYPASS,
          "ipv4: 104.20.0.1 в 104.16.0.0/13 → BYPASS");

    /* 8.8.8.8 → single host /32 → BYPASS */
    CHECK(dpi_filter_match_ipv4(ip4("8.8.8.8"), 443) == DPI_MATCH_BYPASS,
          "ipv4: 8.8.8.8 single host → BYPASS");

    /* 8.8.4.4 → не в списке → NONE */
    CHECK(dpi_filter_match_ipv4(ip4("8.8.4.4"), 443) == DPI_MATCH_NONE,
          "ipv4: 8.8.4.4 не в списке → NONE");

    /* 192.168.1.1 → локальный → NONE */
    CHECK(dpi_filter_match_ipv4(ip4("192.168.1.1"), 443) == DPI_MATCH_NONE,
          "ipv4: 192.168.1.1 локальный → NONE");

    /* Алгоритм поиска: охватывающий /8 с 6 вложенными /24
     * ip=10.6.0.1: bsearch → hi указывает на 10.5.0.0 (или ближе),
     * нужно пройти назад до 10.0.0.0/8 (позиция hi-5 или далее) */
    CHECK(dpi_filter_match_ipv4(ip4("10.6.0.1"), 443) == DPI_MATCH_BYPASS,
          "ipv4: 10.6.0.1 в 10.0.0.0/8 (hi-5) → BYPASS");
    CHECK(dpi_filter_match_ipv4(ip4("10.1.0.1"), 443) == DPI_MATCH_BYPASS,
          "ipv4: 10.1.0.1 в 10.1.0.0/24 → BYPASS");
    CHECK(dpi_filter_match_ipv4(ip4("11.0.0.1"), 443) == DPI_MATCH_NONE,
          "ipv4: 11.0.0.1 вне 10.0.0.0/8 → NONE");
}

/* ── Тест 3: IPv6 match ──────────────────────────────────────────── */
static void test_ipv6_match(void)
{
    uint8_t a[16];

    /* 2606:4700::1 → в 2606:4700::/32 → BYPASS */
    ip6("2606:4700::1", a);
    CHECK(dpi_filter_match_ipv6(a, 443) == DPI_MATCH_BYPASS,
          "ipv6: 2606:4700::1 в 2606:4700::/32 → BYPASS");

    /* 2606:4700:ffff::1 → в том же /32 → BYPASS */
    ip6("2606:4700:ffff::1", a);
    CHECK(dpi_filter_match_ipv6(a, 443) == DPI_MATCH_BYPASS,
          "ipv6: 2606:4700:ffff::1 → BYPASS");

    /* 2607:4700::1 → вне диапазона → NONE */
    ip6("2607:4700::1", a);
    CHECK(dpi_filter_match_ipv6(a, 443) == DPI_MATCH_NONE,
          "ipv6: 2607:4700::1 вне диапазона → NONE");

    /* ::1 loopback → NONE */
    ip6("::1", a);
    CHECK(dpi_filter_match_ipv6(a, 443) == DPI_MATCH_NONE,
          "ipv6: ::1 loopback → NONE");

    /* NULL → NONE */
    CHECK(dpi_filter_match_ipv6(NULL, 443) == DPI_MATCH_NONE,
          "ipv6: NULL → NONE");
}

/* ── Тест 4: domain match ────────────────────────────────────────── */
static void test_domain_match(void)
{
    /* autohosts → BYPASS */
    CHECK(dpi_filter_match_domain("youtube.com") == DPI_MATCH_BYPASS,
          "domain: youtube.com → BYPASS");
    CHECK(dpi_filter_match_domain("discord.com") == DPI_MATCH_BYPASS,
          "domain: discord.com → BYPASS");

    /* whitelist → IGNORE */
    CHECK(dpi_filter_match_domain("google.com") == DPI_MATCH_IGNORE,
          "domain: google.com → IGNORE");
    CHECK(dpi_filter_match_domain("apple.com") == DPI_MATCH_IGNORE,
          "domain: apple.com → IGNORE");

    /* Неизвестный → NONE */
    CHECK(dpi_filter_match_domain("example.com") == DPI_MATCH_NONE,
          "domain: example.com → NONE");

    /* NULL и пустой → NONE */
    CHECK(dpi_filter_match_domain(NULL) == DPI_MATCH_NONE,
          "domain: NULL → NONE");
    CHECK(dpi_filter_match_domain("") == DPI_MATCH_NONE,
          "domain: пустой → NONE");

    /* Case-insensitive */
    CHECK(dpi_filter_match_domain("YouTube.COM") == DPI_MATCH_BYPASS,
          "domain: YouTube.COM case-insensitive → BYPASS");
    CHECK(dpi_filter_match_domain("GOOGLE.COM") == DPI_MATCH_IGNORE,
          "domain: GOOGLE.COM case-insensitive → IGNORE");
}

/* ── Тест 5: combined match (domain приоритет) ──────────────────── */
static void test_combined_match(void)
{
    /* whitelist домен + IP в CDN → IGNORE (домен приоритетнее) */
    CHECK(dpi_filter_match("google.com", ip4("1.1.1.1"), NULL, 443) == DPI_MATCH_IGNORE,
          "combined: whitelist домен + CDN IP → IGNORE");

    /* autohosts + IP в CDN → BYPASS */
    CHECK(dpi_filter_match("youtube.com", ip4("1.1.1.1"), NULL, 443) == DPI_MATCH_BYPASS,
          "combined: autohosts + CDN IP → BYPASS");

    /* Неизвестный домен + IP в CDN → BYPASS (IP проверка) */
    CHECK(dpi_filter_match("unknown.site", ip4("1.1.1.1"), NULL, 443) == DPI_MATCH_BYPASS,
          "combined: неизвестный домен + CDN IP → BYPASS");

    /* Неизвестный домен + НЕ CDN IP → NONE */
    CHECK(dpi_filter_match("unknown.site", ip4("172.31.0.1"), NULL, 443) == DPI_MATCH_NONE,
          "combined: неизвестный домен + не CDN IP → NONE");

    /* NULL домен + CDN IP → BYPASS */
    CHECK(dpi_filter_match(NULL, ip4("23.1.0.1"), NULL, 443) == DPI_MATCH_BYPASS,
          "combined: NULL домен + CDN IP → BYPASS");
}

/* ── Тест 6: free + повторный init ───────────────────────────────── */
static void test_free_reinit(void)
{
    dpi_filter_free();
    CHECK(!dpi_filter_is_ready(), "free: is_ready=0 после free");

    /* После free — все запросы возвращают NONE */
    CHECK(dpi_filter_match_ipv4(ip4("1.1.1.1"), 443) == DPI_MATCH_NONE,
          "free: match_ipv4 после free → NONE");

    /* Повторный init */
    int rc = dpi_filter_init(DPI_TEST_DIR);
    CHECK(rc == 0, "reinit: rc == 0");
    CHECK(dpi_filter_is_ready(), "reinit: is_ready=1");

    CHECK(dpi_filter_match_ipv4(ip4("1.1.1.1"), 443) == DPI_MATCH_BYPASS,
          "reinit: match_ipv4 после reinit → BYPASS");
}

/* ── Тест 7: отсутствующие файлы ─────────────────────────────────── */
static void test_missing_files(void)
{
    dpi_filter_free();

    /* Директория без файлов — init не должен падать */
    system("mkdir -p /tmp/test_dpi_empty");
    int rc = dpi_filter_init("/tmp/test_dpi_empty");
    CHECK(rc == 0, "missing_files: init с пустой директорией → 0");
    CHECK(dpi_filter_is_ready(), "missing_files: is_ready=1");

    /* Без ipset → все IP = NONE, но домены работают */
    dpi_filter_stats_t st;
    dpi_filter_get_stats(&st);
    CHECK(st.ipv4_ranges == 0, "missing_files: ipv4_ranges=0");
    CHECK(st.whitelist   == 0, "missing_files: whitelist=0");

    system("rm -rf /tmp/test_dpi_empty");

    /* Восстановить */
    dpi_filter_init(DPI_TEST_DIR);
}

/* ── main ────────────────────────────────────────────────────────── */
int main(void)
{
    printf("=== dpi_filter tests ===\n\n");

    setup_test_files();

    test_init();
    test_ipv4_match();
    test_ipv6_match();
    test_domain_match();
    test_combined_match();
    test_free_reinit();
    test_missing_files();

    dpi_filter_free();
    cleanup_test_files();

    printf("\n%s: %d тест(ов) провалено\n",
           failures == 0 ? "ALL PASS" : "FAILED", failures);
    return failures;
}

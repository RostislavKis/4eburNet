/*
 * test_cdn_updater.c — тесты cdn_updater.c (C.4)
 * Только unit-тесты без сети.
 * Сетевые тесты: CDN_NET_TESTS=1 make test-cdn-updater
 */
#define CONFIG_EBURNET_DPI 1
#include "dpi/cdn_updater.h"
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>

void log_msg(log_level_t level, const char *fmt, ...) {
    (void)level;
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n");
}

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", (msg)); failures++; } \
    else         { printf("PASS: %s\n", (msg)); } \
} while(0)

#define TMP_DIR "/tmp/test_cdn_4eburnet"

static void setup(void)   { system("mkdir -p " TMP_DIR); }
static void cleanup(void) { system("rm -rf "   TMP_DIR); }

/* Тест 1: cdn_is_stale — нет stamp файла → обновление нужно */
static void test_stale_no_stamp(void)
{
    CHECK(cdn_is_stale(TMP_DIR "/no_such.stamp", 7) == 1,
          "is_stale: нет stamp файла → stale=1");
}

/* Тест 2: cdn_is_stale — свежий stamp → не нужно */
static void test_stale_fresh(void)
{
    const char *path = TMP_DIR "/fresh.stamp";
    cdn_stamp_write(path);
    CHECK(cdn_is_stale(path, 7) == 0,
          "is_stale: только что записан → stale=0");
}

/* Тест 3: cdn_is_stale — старый stamp → нужно */
static void test_stale_old(void)
{
    const char *path = TMP_DIR "/old.stamp";
    long old_ts = (long)time(NULL) - 8 * 86400;
    FILE *f = fopen(path, "w");
    if (f) { fprintf(f, "%ld\n", old_ts); fclose(f); }
    CHECK(cdn_is_stale(path, 7) == 1,
          "is_stale: 8-дневный stamp при interval=7 → stale=1");
}

/* Тест 4: cdn_is_stale — interval=0 → выключено */
static void test_stale_disabled(void)
{
    CHECK(cdn_is_stale(TMP_DIR "/no_such.stamp", 0) == -1,
          "is_stale: interval=0 → -1 (выключено)");
}

/* Тест 5: cdn_stamp_write + cdn_stamp_read roundtrip */
static void test_stamp_roundtrip(void)
{
    const char *path = TMP_DIR "/stamp.txt";
    long before = (long)time(NULL);
    int rc = cdn_stamp_write(path);
    long after = (long)time(NULL);
    CHECK(rc == 0, "stamp_write: rc == 0");

    long ts = cdn_stamp_read(path);
    CHECK(ts >= before && ts <= after,
          "stamp_roundtrip: прочитанный ts в диапазоне [before, after]");
}

/* Тест 6: cdn_parse_text — Cloudflare IPv4 формат */
static void test_parse_text_cf(void)
{
    const char *mock =
        "# Cloudflare IPs\n"
        "103.21.244.0/22\n"
        "103.22.200.0/22\n"
        "103.31.4.0/22\n"
        "\n"
        "104.16.0.0/13\n"
        "# comment in middle\n"
        "104.24.0.0/14\n";

    char cidrs[16][64];
    int n = cdn_parse_text(mock, cidrs, 16, 64);
    CHECK(n == 5,
          "parse_text: 5 CIDR из 6 строк (1 коммент + 1 пустая)");
    CHECK(strcmp(cidrs[0], "103.21.244.0/22") == 0,
          "parse_text: первый CIDR корректен");
    CHECK(strcmp(cidrs[4], "104.24.0.0/14") == 0,
          "parse_text: последний CIDR корректен");
}

/* Тест 7: cdn_parse_text — IPv6 */
static void test_parse_text_ipv6(void)
{
    const char *mock =
        "2400:cb00::/32\n"
        "2606:4700::/32\n"
        "2803:f800::/32\n";

    char cidrs[8][64];
    int n = cdn_parse_text(mock, cidrs, 8, 64);
    CHECK(n == 3, "parse_text IPv6: n == 3");
    CHECK(strchr(cidrs[0], ':') != NULL,
          "parse_text IPv6: первый содержит ':'");
}

/* Тест 8: cdn_parse_text — пустой ввод */
static void test_parse_text_empty(void)
{
    char cidrs[8][64];
    CHECK(cdn_parse_text("", cidrs, 8, 64) == 0,
          "parse_text: пустая строка → 0");
    CHECK(cdn_parse_text("# only comments\n# another\n", cidrs, 8, 64) == 0,
          "parse_text: только комментарии → 0");
}

/* Тест 9: cdn_parse_fastly_json — формат Fastly */
static void test_parse_fastly_json(void)
{
    const char *mock_json =
        "{\"addresses\":[\"23.235.32.0/20\",\"43.249.72.0/22\","
        "\"103.244.50.0/24\"],\"ipv6_addresses\":"
        "[\"2a04:4e40::/32\",\"2a04:4e42::/32\"]}";

    char cidrs[16][64];
    int n = cdn_parse_fastly_json(mock_json, cidrs, 16, 64);
    CHECK(n == 5,
          "parse_fastly: 3 IPv4 + 2 IPv6 = 5");
    CHECK(strcmp(cidrs[0], "23.235.32.0/20") == 0,
          "parse_fastly: первый IPv4 корректен");
    CHECK(strcmp(cidrs[3], "2a04:4e40::/32") == 0,
          "parse_fastly: первый IPv6 корректен");
}

/* Тест 10: cdn_parse_fastly_json — пустые массивы */
static void test_parse_fastly_empty(void)
{
    const char *mock = "{\"addresses\":[],\"ipv6_addresses\":[]}";
    char cidrs[8][64];
    int n = cdn_parse_fastly_json(mock, cidrs, 8, 64);
    CHECK(n == 0, "parse_fastly: пустые массивы → 0");
}

/* Тест 11: cdn_merge_write — дедупликация */
static void test_merge_dedup(void)
{
    char all[8][64];
    /* src1 */
    strncpy(all[0], "103.21.244.0/22", 63);
    strncpy(all[1], "104.16.0.0/13",   63);
    strncpy(all[2], "1.1.1.0/24",      63);
    /* src2 — дубли + новые */
    strncpy(all[3], "103.21.244.0/22", 63);  /* дубль */
    strncpy(all[4], "104.24.0.0/14",   63);
    strncpy(all[5], "1.1.1.0/24",      63);  /* дубль */
    strncpy(all[6], "8.8.8.0/24",      63);

    const char *out = TMP_DIR "/merged.txt";
    int rc = cdn_merge_write(all, 7, out);
    CHECK(rc == 0, "merge_write: rc == 0");

    FILE *f = fopen(out, "r");
    CHECK(f != NULL, "merge_write: файл создан");
    int lines = 0;
    char line[64];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] != '#' && line[0] != '\n') lines++;
    }
    fclose(f);
    CHECK(lines == 5,
          "merge_dedup: 5 уникальных CIDR (7 всего - 2 дубля)");
}

/* Тест 12: cdn_merge_write — атомарная запись (rename) */
static void test_write_atomic(void)
{
    const char *out = TMP_DIR "/atomic.txt";
    unlink(out);

    char cidrs[3][64];
    strncpy(cidrs[0], "1.1.1.0/24", 63);
    strncpy(cidrs[1], "2.2.2.0/24", 63);
    strncpy(cidrs[2], "3.3.3.0/24", 63);

    int rc = cdn_merge_write(cidrs, 3, out);
    CHECK(rc == 0,               "write_atomic: rc == 0");
    CHECK(access(out, F_OK) == 0, "write_atomic: файл создан");

    char tmp_path[320];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", out);
    CHECK(access(tmp_path, F_OK) != 0,
          "write_atomic: .tmp файл удалён после rename");
}

/* Тест 13: cdn_is_stale — timestamp из будущего → stale=1 */
static void test_stale_future_timestamp(void)
{
    const char *path = TMP_DIR "/future.stamp";
    long future_ts = (long)time(NULL) + 7 * 86400;
    FILE *f = fopen(path, "w");
    if (f) { fprintf(f, "%ld\n", future_ts); fclose(f); }
    CHECK(cdn_is_stale(path, 7) == 1,
          "is_stale: timestamp из будущего → stale=1");
}

/* Тест 14: cdn_parse_text — граничные длины CIDR */
static void test_parse_text_boundary(void)
{
    /* CIDR 63 символа — принимается (len < 64) */
    char long_cidr[70];
    memset(long_cidr, '1', 63); long_cidr[63] = '\0';
    char text[80];
    snprintf(text, sizeof(text), "%s\n", long_cidr);
    char cidrs[4][64];
    int n = cdn_parse_text(text, cidrs, 4, 64);
    CHECK(n == 1, "parse_text: CIDR длиной 63 → принимается");

    /* CIDR 64 символа — отбрасывается (len >= 64) */
    char too_long[70];
    memset(too_long, '1', 64); too_long[64] = '\0';
    snprintf(text, sizeof(text), "%s\n", too_long);
    n = cdn_parse_text(text, cidrs, 4, 64);
    CHECK(n == 0, "parse_text: CIDR длиной 64 → отбрасывается");
}

/* Тест 15: cdn_parse_fastly_json — CIDR с backslash → отброшен */
static void test_parse_json_escape(void)
{
    /* Нормальный CIDR без escape — парсится */
    const char *mock = "{\"addresses\":[\"1.2.3.0/24\"]}";
    char cidrs[4][64];
    int n = cdn_parse_fastly_json(mock, cidrs, 4, 64);
    CHECK(n == 1, "parse_fastly: нормальный CIDR → 1");

    /* CIDR с backslash: невалидный символ '\\' → отбрасывается (A.8.5) */
    const char *bad = "{\"addresses\":[\"bad\\\\cidr\"]}";
    n = cdn_parse_fastly_json(bad, cidrs, 4, 64);
    CHECK(n == 0, "parse_fastly: CIDR с backslash → отброшен валидацией");
}

/* Тест 16: cdn_merge_write — count=0 → -1 */
static void test_merge_write_empty(void)
{
    char cidrs[1][64];
    CHECK(cdn_merge_write(cidrs, 0, TMP_DIR "/empty.txt") == -1,
          "merge_write: count=0 → -1");
}

/* Тест 17: cdn_stamp_write — несуществующий путь → -1 */
static void test_stamp_write_badpath(void)
{
    int rc = cdn_stamp_write("/tmp/no_such_dir_4eburnet/stamp.txt");
    CHECK(rc == -1, "stamp_write: несуществующий путь → -1");
}

/* Тест 18: cdn_updater_update — несуществующие URL → -1, файлы не создаются */
static void test_updater_no_network(void)
{
    /* Минимальный конфиг: URL на заведомо недоступный хост */
    EburNetConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.cdn_update_interval_days = 7;
    snprintf(cfg.dpi_dir, sizeof(cfg.dpi_dir), "%s", TMP_DIR "/dpi_no_net");
    /* URL на localhost:1 — немедленный ECONNREFUSED, без сети */
    snprintf(cfg.cdn_cf_v4_url, sizeof(cfg.cdn_cf_v4_url),
             "https://127.0.0.1:1/ips-v4");
    snprintf(cfg.cdn_cf_v6_url, sizeof(cfg.cdn_cf_v6_url),
             "https://127.0.0.1:1/ips-v6");
    snprintf(cfg.cdn_fastly_url, sizeof(cfg.cdn_fastly_url),
             "https://127.0.0.1:1/public-ip-list");

    system("mkdir -p " TMP_DIR "/dpi_no_net");

    int rc = cdn_updater_update(&cfg);
    CHECK(rc == -1, "updater_no_network: все источники недоступны → -1");

    /* ipset.txt не должен появиться (нечего записывать) */
    char ipset_path[320];
    snprintf(ipset_path, sizeof(ipset_path), "%s/dpi_no_net/ipset.txt", TMP_DIR);
    CHECK(access(ipset_path, F_OK) != 0,
          "updater_no_network: ipset.txt не создан при ошибке всех источников");

    /* stamp не должен появиться */
    char stamp_path[320];
    snprintf(stamp_path, sizeof(stamp_path),
             "%s/dpi_no_net/ipset.stamp", TMP_DIR);
    CHECK(access(stamp_path, F_OK) != 0,
          "updater_no_network: stamp не создан при ошибке");
}

/* main */
int main(void)
{
    printf("=== cdn_updater tests ===\n\n");
    setup();

    test_stale_no_stamp();
    test_stale_fresh();
    test_stale_old();
    test_stale_disabled();
    test_stamp_roundtrip();
    test_parse_text_cf();
    test_parse_text_ipv6();
    test_parse_text_empty();
    test_parse_fastly_json();
    test_parse_fastly_empty();
    test_merge_dedup();
    test_write_atomic();
    test_stale_future_timestamp();
    test_parse_text_boundary();
    test_parse_json_escape();
    test_merge_write_empty();
    test_stamp_write_badpath();
    test_updater_no_network();

    cleanup();
    printf("\n%s: %d тест(ов) провалено\n",
           failures == 0 ? "ALL PASS" : "FAILED", failures);
    return failures;
}

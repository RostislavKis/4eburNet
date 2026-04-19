/*
 * Тест dpi_adapt.c (v1.2-1)
 * Adaptive DPI: кэш стратегий bypass per-IP.
 */
#define CONFIG_EBURNET_DPI 1
#include "dpi/dpi_adapt.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

DpiAdaptTable g_dpi_adapt;

void log_msg(int level, const char *fmt, ...)
{
    (void)level;
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n");
}

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", (msg)); failures++; } \
    else         { printf("PASS: %s\n", (msg)); } \
} while(0)

/* T1: неизвестный IP → DPI_STRAT_NONE */
static void test_unknown_ip(void)
{
    DpiAdaptTable t;
    dpi_adapt_init(&t);

    dpi_strat_t s = dpi_adapt_get(&t, 0xC0A80101u); /* 192.168.1.1 */
    CHECK(s == DPI_STRAT_NONE, "T1: неизвестный IP → DPI_STRAT_NONE");
    CHECK(t.count == 0, "T1: count = 0 после get");
}

/* T2: report SUCCESS → get возвращает ту же стратегию */
static void test_success_preserves_strategy(void)
{
    DpiAdaptTable t;
    dpi_adapt_init(&t);

    uint32_t ip = 0x08080808u; /* 8.8.8.8 */
    dpi_adapt_report(&t, ip, DPI_STRAT_FRAGMENT, DPI_RESULT_SUCCESS);

    dpi_strat_t s = dpi_adapt_get(&t, ip);
    CHECK(s == DPI_STRAT_FRAGMENT, "T2: after SUCCESS FRAGMENT → get = FRAGMENT");
    CHECK(t.count == 1, "T2: count = 1 после первого report");

    /* Успех ещё раз с FAKE_TTL */
    dpi_adapt_report(&t, ip, DPI_STRAT_FAKE_TTL, DPI_RESULT_SUCCESS);
    s = dpi_adapt_get(&t, ip);
    CHECK(s == DPI_STRAT_FAKE_TTL, "T2: after SUCCESS FAKE_TTL → get = FAKE_TTL");
    CHECK(t.count == 1, "T2: count не меняется при обновлении существующего IP");
}

/* T3: report FAIL ×3 → get возвращает следующую стратегию */
static void test_fail_escalation(void)
{
    DpiAdaptTable t;
    dpi_adapt_init(&t);

    uint32_t ip = 0x01010101u; /* 1.1.1.1 */

    /* Зафиксировать начальную стратегию NONE через SUCCESS */
    dpi_adapt_report(&t, ip, DPI_STRAT_NONE, DPI_RESULT_SUCCESS);
    CHECK(dpi_adapt_get(&t, ip) == DPI_STRAT_NONE, "T3: базовая стратегия NONE");

    /* 3 отказа → эскалация к FRAGMENT */
    dpi_adapt_report(&t, ip, DPI_STRAT_NONE, DPI_RESULT_FAIL);
    dpi_adapt_report(&t, ip, DPI_STRAT_NONE, DPI_RESULT_FAIL);
    dpi_adapt_report(&t, ip, DPI_STRAT_NONE, DPI_RESULT_FAIL);
    CHECK(dpi_adapt_get(&t, ip) == DPI_STRAT_FRAGMENT,
          "T3: 3 FAIL при NONE → эскалация к FRAGMENT");

    /* Ещё 3 отказа при FRAGMENT → FAKE_TTL */
    dpi_adapt_report(&t, ip, DPI_STRAT_FRAGMENT, DPI_RESULT_SUCCESS);
    dpi_adapt_report(&t, ip, DPI_STRAT_FRAGMENT, DPI_RESULT_FAIL);
    dpi_adapt_report(&t, ip, DPI_STRAT_FRAGMENT, DPI_RESULT_FAIL);
    dpi_adapt_report(&t, ip, DPI_STRAT_FRAGMENT, DPI_RESULT_FAIL);
    CHECK(dpi_adapt_get(&t, ip) == DPI_STRAT_FAKE_TTL,
          "T3: 3 FAIL при FRAGMENT → эскалация к FAKE_TTL");

    /* Эскалация до BOTH и проверка что дальше не уходит */
    dpi_adapt_report(&t, ip, DPI_STRAT_FAKE_TTL, DPI_RESULT_SUCCESS);
    dpi_adapt_report(&t, ip, DPI_STRAT_FAKE_TTL, DPI_RESULT_FAIL);
    dpi_adapt_report(&t, ip, DPI_STRAT_FAKE_TTL, DPI_RESULT_FAIL);
    dpi_adapt_report(&t, ip, DPI_STRAT_FAKE_TTL, DPI_RESULT_FAIL);
    CHECK(dpi_adapt_get(&t, ip) == DPI_STRAT_BOTH,
          "T3: 3 FAIL при FAKE_TTL → эскалация к BOTH");

    /* При BOTH и 3 FAIL — остаётся BOTH, не регрессирует */
    dpi_adapt_report(&t, ip, DPI_STRAT_BOTH, DPI_RESULT_SUCCESS);
    dpi_adapt_report(&t, ip, DPI_STRAT_BOTH, DPI_RESULT_FAIL);
    dpi_adapt_report(&t, ip, DPI_STRAT_BOTH, DPI_RESULT_FAIL);
    dpi_adapt_report(&t, ip, DPI_STRAT_BOTH, DPI_RESULT_FAIL);
    CHECK(dpi_adapt_get(&t, ip) == DPI_STRAT_BOTH,
          "T3: при BOTH нет регрессии за пределы кэпа");
}

/* T4: save → load → данные сохранены */
static void test_save_load(void)
{
    const char *path = "/tmp/test_dpi_cache.bin";

    DpiAdaptTable t1;
    dpi_adapt_init(&t1);

    uint32_t ip1 = 0xAC100001u;  /* 172.16.0.1 */
    uint32_t ip2 = 0xAC100002u;  /* 172.16.0.2 */
    dpi_adapt_report(&t1, ip1, DPI_STRAT_FAKE_TTL, DPI_RESULT_SUCCESS);
    dpi_adapt_report(&t1, ip2, DPI_STRAT_BOTH,     DPI_RESULT_SUCCESS);

    int rc = dpi_adapt_save(&t1, path);
    CHECK(rc == 0, "T4: save вернул 0");
    CHECK(t1.count == 2, "T4: count = 2 перед save");

    DpiAdaptTable t2;
    dpi_adapt_init(&t2);
    rc = dpi_adapt_load(&t2, path);
    CHECK(rc == 0, "T4: load вернул 0");
    CHECK(t2.count == 2, "T4: count = 2 после load");

    CHECK(dpi_adapt_get(&t2, ip1) == DPI_STRAT_FAKE_TTL,
          "T4: ip1 стратегия сохранена");
    CHECK(dpi_adapt_get(&t2, ip2) == DPI_STRAT_BOTH,
          "T4: ip2 стратегия сохранена");

    unlink(path);
}

/* T5: полная таблица (4096 записей) → LRU eviction при переполнении */
static void test_full_table(void)
{
    DpiAdaptTable t;
    dpi_adapt_init(&t);

    /* Заполнить таблицу: IP от 1 до 4096 */
    for (uint32_t ip = 1; ip <= DPI_ADAPT_SLOTS; ip++)
        dpi_adapt_report(&t, ip, DPI_STRAT_NONE, DPI_RESULT_SUCCESS);

    CHECK(t.count == DPI_ADAPT_SLOTS, "T5: count = 4096 после заполнения");

    /* При переполнении LRU вытесняет старую запись — count не меняется */
    uint32_t before = t.count;
    dpi_adapt_report(&t, 0xFFFFFFFFu, DPI_STRAT_FRAGMENT, DPI_RESULT_SUCCESS);
    CHECK(t.count == before, "T5: count не меняется при переполнении");

    /* Новый IP доступен после LRU-вытеснения */
    dpi_strat_t s = dpi_adapt_get(&t, 0xFFFFFFFFu);
    CHECK(s == DPI_STRAT_FRAGMENT, "T5: get нового IP после LRU-вытеснения → FRAGMENT");
}

/* T6: dpi_adapt_stats → count и hits корректны */
static void test_stats(void)
{
    DpiAdaptTable t;
    dpi_adapt_init(&t);

    uint32_t ip1 = 0x0A000001u;  /* 10.0.0.1 */
    uint32_t ip2 = 0x0A000002u;  /* 10.0.0.2 */

    dpi_adapt_report(&t, ip1, DPI_STRAT_FRAGMENT, DPI_RESULT_SUCCESS);
    dpi_adapt_report(&t, ip1, DPI_STRAT_FRAGMENT, DPI_RESULT_SUCCESS);
    dpi_adapt_report(&t, ip2, DPI_STRAT_BOTH,     DPI_RESULT_SUCCESS);

    uint32_t count = 0, hits = 0;
    dpi_adapt_stats(&t, &count, &hits);

    CHECK(count == 2, "T6: stats count = 2");
    CHECK(hits  == 3, "T6: stats hits = 3 (ip1×2 + ip2×1)");

    /* Проверка с NULL аргументами — не должно падать */
    dpi_adapt_stats(&t, NULL, NULL);
    printf("PASS: T6: stats(NULL, NULL) не падает\n");
}

int main(void)
{
    printf("=== dpi_adapt tests ===\n\n");
    test_unknown_ip();
    test_success_preserves_strategy();
    test_fail_escalation();
    test_save_load();
    test_full_table();
    test_stats();
    printf("\n%s: %d тест(ов) провалено\n",
           failures == 0 ? "ALL PASS" : "FAILED", failures);
    return failures;
}

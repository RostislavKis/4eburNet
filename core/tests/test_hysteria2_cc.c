/*
 * Тест Brutal CC — контракт перед реализацией B.5
 * Компилируется без wolfSSL.
 */
#define CONFIG_EBURNET_QUIC 1
#include "proxy/hysteria2_cc.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

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

/* Тест 1: инициализация */
static void test_init(void)
{
    brutal_cc_t cc;
    brutal_cc_init(&cc, 100 /* up_mbps */, 100 /* down_mbps */);

    CHECK(cc.target_bps  == 100ULL * 1024 * 1024 / 8, "target_bps = 100 Мбит/с");
    CHECK(cc.actual_bps  == cc.target_bps,              "actual_bps = target при старте");
    CHECK(cc.loss_rate   == 0.0f,                       "loss_rate = 0 при старте");
    CHECK(cc.window_sent == 0,                          "window_sent = 0");
    CHECK(cc.window_lost == 0,                          "window_lost = 0");
}

/* Тест 2: без потерь — actual_bps = target_bps */
static void test_no_loss(void)
{
    brutal_cc_t cc;
    brutal_cc_init(&cc, 50, 50);

    /* 100 пакетов отправлено, все подтверждены */
    for (int i = 0; i < 100; i++)
        brutal_cc_on_sent(&cc, 1400);
    for (int i = 0; i < 100; i++)
        brutal_cc_on_acked(&cc, 1400);

    brutal_cc_update(&cc);

    CHECK(cc.loss_rate  < 0.001f,             "loss_rate ≈ 0 без потерь");
    CHECK(cc.actual_bps == cc.target_bps,     "actual_bps = target без потерь");
}

/* Тест 3: 10% потерь → actual_bps ≈ target / 0.9 (+11%) */
static void test_10pct_loss(void)
{
    brutal_cc_t cc;
    brutal_cc_init(&cc, 100, 100);

    /* 100 отправлено, 90 подтверждено, 10 потеряно */
    for (int i = 0; i < 100; i++)
        brutal_cc_on_sent(&cc, 1400);
    for (int i = 0; i < 10; i++)
        brutal_cc_on_lost(&cc, 1400);
    for (int i = 0; i < 90; i++)
        brutal_cc_on_acked(&cc, 1400);

    brutal_cc_update(&cc);

    float loss = cc.loss_rate;
    CHECK(loss > 0.08f && loss < 0.12f, "loss_rate ≈ 10%");

    /* actual ≈ target / (1 - 0.1) = target * 1.111 */
    uint64_t target   = cc.target_bps;
    uint64_t actual   = cc.actual_bps;
    uint64_t expected = (uint64_t)((float)target / 0.9f);

    CHECK(actual > target, "actual_bps > target при потерях");

    int64_t diff = (int64_t)actual - (int64_t)expected;
    if (diff < 0) diff = -diff;
    CHECK((uint64_t)diff < expected / 20, "actual ≈ target/0.9 (±5%)");
}

/* Тест 4: 50% потерь → actual_bps ≈ target * 2 */
static void test_50pct_loss(void)
{
    brutal_cc_t cc;
    brutal_cc_init(&cc, 100, 100);

    for (int i = 0; i < 100; i++)
        brutal_cc_on_sent(&cc, 1400);
    for (int i = 0; i < 50; i++)
        brutal_cc_on_lost(&cc, 1400);
    for (int i = 0; i < 50; i++)
        brutal_cc_on_acked(&cc, 1400);

    brutal_cc_update(&cc);

    uint64_t target   = cc.target_bps;
    uint64_t actual   = cc.actual_bps;
    uint64_t expected = target * 2;
    int64_t  diff     = (int64_t)actual - (int64_t)expected;
    if (diff < 0) diff = -diff;
    CHECK((uint64_t)diff < expected / 10, "50% потерь → actual ≈ target*2 (±10%)");
}

/* Тест 5: экстремальные потери → actual_bps ≤ target * MAX_MULTIPLIER */
static void test_loss_cap(void)
{
    brutal_cc_t cc;
    brutal_cc_init(&cc, 100, 100);

    /* 95% потерь */
    for (int i = 0; i < 100; i++)
        brutal_cc_on_sent(&cc, 1400);
    for (int i = 0; i < 95; i++)
        brutal_cc_on_lost(&cc, 1400);
    for (int i = 0; i < 5; i++)
        brutal_cc_on_acked(&cc, 1400);

    brutal_cc_update(&cc);

    CHECK(cc.actual_bps <= cc.target_bps * BRUTAL_MAX_MULTIPLIER,
          "actual_bps ≤ target * MAX_MULTIPLIER при экстремальных потерях");
    CHECK(cc.actual_bps >= cc.target_bps,
          "actual_bps ≥ target даже при экстремальных потерях");
}

/* Тест 6: token bucket */
static void test_token_bucket(void)
{
    brutal_cc_t cc;
    brutal_cc_init(&cc, 1, 1);  /* 1 Мбит/с = 131 072 байт/с */

    uint64_t t0 = 1000000ULL;   /* стартовый момент */

    /* Первый can_send — инициализирует tick */
    int can = brutal_cc_can_send(&cc, 1400, t0);
    CHECK(can, "can_send при пустом bucket (первый пакет)");

    /* Истратить весь bucket за один вызов on_sent */
    uint64_t cap = cc.bucket_capacity;
    cc.bucket_tokens = 0;       /* вручную обнулить для теста */

    /* После 1 секунды bucket восстанавливается */
    brutal_cc_tick(&cc, t0 + 1000000ULL);
    can = brutal_cc_can_send(&cc, 1400, t0 + 1000000ULL);
    CHECK(can, "can_send после 1с = true (bucket восстановлен)");

    /* Проверить что capacity разумный (≥ target в байтах) */
    CHECK(cap >= 1024ULL * 1024 / 8,
          "bucket_capacity ≥ 1 Мбит/с worth байт");
}

/* Тест 7: window reset после update */
static void test_window_reset(void)
{
    brutal_cc_t cc;
    brutal_cc_init(&cc, 100, 100);

    for (int i = 0; i < BRUTAL_WINDOW_SIZE; i++)
        brutal_cc_on_sent(&cc, 1400);
    for (int i = 0; i < BRUTAL_WINDOW_SIZE; i++)
        brutal_cc_on_acked(&cc, 1400);

    brutal_cc_update(&cc);

    /* После update счётчики должны быть сброшены */
    CHECK(cc.window_sent == 0,  "window_sent сброшен после update");
    CHECK(cc.window_lost == 0,  "window_lost сброшен после update");
    CHECK(cc.loss_rate >= 0.0f && cc.loss_rate <= 1.0f,
          "loss_rate в диапазоне [0.0, 1.0]");
}

/* Тест 8: RTT tracking */
static void test_rtt(void)
{
    brutal_cc_t cc;
    brutal_cc_init(&cc, 100, 100);

    brutal_cc_on_rtt(&cc, 50);
    CHECK(cc.min_rtt_ms == 50, "min_rtt_ms обновлён");

    brutal_cc_on_rtt(&cc, 200);
    CHECK(cc.min_rtt_ms == 50,        "min_rtt_ms не увеличился");
    CHECK(cc.rtt_ms     <  200,       "smoothed RTT < новому значению (EWMA)");
    CHECK(cc.rtt_ms     >= 50,        "smoothed RTT ≥ min RTT");
}

int main(void)
{
    printf("=== Brutal CC tests ===\n\n");
    test_init();
    test_no_loss();
    test_10pct_loss();
    test_50pct_loss();
    test_loss_cap();
    test_token_bucket();
    test_window_reset();
    test_rtt();

    printf("\n%s: %d тест(ов) провалено\n",
           failures == 0 ? "ALL PASS" : "FAILED", failures);
    return failures;
}

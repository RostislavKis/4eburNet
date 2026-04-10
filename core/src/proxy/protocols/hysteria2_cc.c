/*
 * Brutal CC — Hysteria2 congestion control
 *
 * actual_rate = target_rate / (1.0 - loss_rate)
 *
 * НЕ снижает скорость при потерях — компенсирует увеличением темпа.
 */

#ifdef CONFIG_EBURNET_QUIC

#include "proxy/hysteria2_cc.h"
#include "4eburnet.h"

#include <string.h>

/* ── Вспомогательные функции ────────────────────────────────────── */

static inline float f_clamp(float v, float lo, float hi)
{
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static inline uint64_t u64_min(uint64_t a, uint64_t b)
{
    return a < b ? a : b;
}

static inline uint64_t u64_max(uint64_t a, uint64_t b)
{
    return a > b ? a : b;
}

/* ── Инициализация ──────────────────────────────────────────────── */

void brutal_cc_init(brutal_cc_t *cc,
                    uint32_t up_mbps, uint32_t down_mbps)
{
    if (!cc) return;
    memset(cc, 0, sizeof(*cc));

    /* Перевести Мбит/с → байт/с */
    cc->target_bps = (uint64_t)up_mbps * 1024 * 1024 / 8;
    cc->max_bps    = cc->target_bps * BRUTAL_MAX_MULTIPLIER;

    /* Стартовая скорость = целевая (нет данных о потерях) */
    cc->actual_bps = cc->target_bps;
    cc->loss_rate  = 0.0f;

    /* Token bucket: ёмкость = 1 секунда при target_bps */
    cc->bucket_capacity = cc->target_bps * BRUTAL_BUCKET_SECONDS;
    cc->bucket_tokens   = cc->bucket_capacity;
    cc->last_tick_us    = 0;

    cc->rtt_ms     = 100;         /* оптимистичный начальный RTT */
    cc->min_rtt_ms = UINT32_MAX;

    (void)down_mbps;  /* используется для Hysteria-CC-RX — не здесь */

    if (cc->target_bps > 0) {
        log_msg(LOG_DEBUG,
                "Brutal CC: target=%llu Кбит/с max=%llu Кбит/с window=%d",
                (unsigned long long)(cc->target_bps * 8 / 1024),
                (unsigned long long)(cc->max_bps    * 8 / 1024),
                BRUTAL_WINDOW_SIZE);
    }
}

/* ── Sliding window ─────────────────────────────────────────────── */

void brutal_cc_on_sent(brutal_cc_t *cc, size_t bytes)
{
    if (!cc || bytes == 0) return;
    (void)bytes;      /* считаем пакеты, не байты */
    cc->window_sent++;
    /* Авто-обновление при заполнении скользящего окна */
    if (cc->window_sent >= BRUTAL_WINDOW_SIZE)
        brutal_cc_update(cc);
}

void brutal_cc_on_acked(brutal_cc_t *cc, size_t bytes)
{
    if (!cc || bytes == 0) return;
    (void)bytes;
    /* Не давать acked превышать sent (defensive) */
    if (cc->window_acked < cc->window_sent)
        cc->window_acked++;
}

void brutal_cc_on_lost(brutal_cc_t *cc, size_t bytes)
{
    if (!cc || bytes == 0) return;
    (void)bytes;
    /* Потерь не может быть больше чем отправлено (защита от double-report) */
    if (cc->window_lost < cc->window_sent)
        cc->window_lost++;
}

/* ── Пересчёт скорости ──────────────────────────────────────────── */

void brutal_cc_update(brutal_cc_t *cc)
{
    if (!cc) return;

    /* Нет данных — сбросить к целевой */
    if (cc->window_sent == 0) {
        cc->loss_rate  = 0.0f;
        cc->actual_bps = cc->target_bps;
        return;
    }

    /* loss_rate = window_lost / window_sent */
    float loss = (float)cc->window_lost / (float)cc->window_sent;
    loss = f_clamp(loss, 0.0f, 1.0f);

    /* Ниже порога — считать нулём (фоновый шум) */
    if (loss < BRUTAL_MIN_LOSS_RATE)
        loss = 0.0f;

    cc->loss_rate = loss;

    /* actual = target / (1 - loss_rate) */
    uint64_t new_actual;
    if (loss >= 1.0f - BRUTAL_MIN_LOSS_RATE) {
        /* Потеряно почти всё — ставить максимум */
        new_actual = cc->max_bps;
    } else {
        double denom  = 1.0 - (double)loss;
        double scaled = (double)cc->target_bps / denom;
        new_actual    = (uint64_t)scaled;
    }

    /* Ограничить: [target_bps, max_bps] */
    cc->actual_bps = u64_min(u64_max(new_actual, cc->target_bps),
                             cc->max_bps);

    /* Обновить bucket capacity под новую скорость */
    cc->bucket_capacity = cc->actual_bps * BRUTAL_BUCKET_SECONDS;
    if (cc->bucket_tokens > cc->bucket_capacity)
        cc->bucket_tokens = cc->bucket_capacity;

    /* Сбросить счётчики window */
    cc->window_sent  = 0;
    cc->window_acked = 0;
    cc->window_lost  = 0;

    log_msg(LOG_DEBUG,
            "Brutal CC: loss=%.1f%% actual=%llu Кбит/с",
            (double)(cc->loss_rate * 100.0f),
            (unsigned long long)(cc->actual_bps * 8 / 1024));
}

/* ── Token bucket ───────────────────────────────────────────────── */

void brutal_cc_tick(brutal_cc_t *cc, uint64_t now_us)
{
    if (!cc) return;
    if (cc->last_tick_us == 0) {
        cc->last_tick_us = now_us;
        return;
    }

    /* Защита от переполнения при backward clock */
    if (now_us <= cc->last_tick_us) {
        cc->last_tick_us = now_us;
        return;
    }

    uint64_t elapsed_us = now_us - cc->last_tick_us;

    /*
     * Прирост токенов: actual_bps байт/с × elapsed_s
     * Вычисление: total_us / 1000 × actual_bps / 1000
     * tick_remainder_us накапливает sub-millisecond остатки —
     * без него sub-ms тики не пополняли бы bucket вовсе.
     */
    uint64_t total_us   = elapsed_us + cc->tick_remainder_us;
    uint64_t new_tokens = (total_us / 1000ULL) * (cc->actual_bps / 1000ULL);
    cc->tick_remainder_us = total_us % 1000ULL;

    cc->bucket_tokens += new_tokens;
    if (cc->bucket_tokens > cc->bucket_capacity)
        cc->bucket_tokens = cc->bucket_capacity;

    cc->last_tick_us = now_us;
}

int brutal_cc_can_send(brutal_cc_t *cc, size_t bytes, uint64_t now_us)
{
    if (!cc) return 0;

    /* Без ограничения скорости */
    if (cc->target_bps == 0) return 1;

    /* Первый вызов — инициализировать tick */
    if (cc->last_tick_us == 0) {
        brutal_cc_tick(cc, now_us);
    }

    if (cc->bucket_tokens >= (uint64_t)bytes) {
        cc->bucket_tokens -= (uint64_t)bytes;
        return 1;
    }
    return 0;
}

/* ── Утилиты ────────────────────────────────────────────────────── */

uint64_t brutal_cc_get_rate(const brutal_cc_t *cc)
{
    if (!cc) return 0;
    return cc->actual_bps;
}

void brutal_cc_on_rtt(brutal_cc_t *cc, uint32_t rtt_ms)
{
    if (!cc || rtt_ms == 0) return;
    if (rtt_ms < cc->min_rtt_ms)
        cc->min_rtt_ms = rtt_ms;
    /* EWMA: smoothed = 7/8 × old + 1/8 × new */
    cc->rtt_ms = (cc->rtt_ms * 7 + rtt_ms) / 8;
}

#endif /* CONFIG_EBURNET_QUIC */

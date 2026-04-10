/*
 * Brutal CC — Hysteria2 congestion control
 *
 * Алгоритм:
 *   actual_rate = target_rate / (1.0 - loss_rate)
 *
 * Принцип: НЕ снижать скорость при потерях,
 * а компенсировать их увеличением темпа отправки.
 *
 * Компоненты:
 *   1. Sliding window — подсчёт sent/lost/acked за последние N пакетов
 *   2. Loss rate = window_lost / window_sent
 *   3. Rate compute: actual_bps = target_bps / (1.0 - loss_rate)
 *   4. Token bucket — rate limiting на отправку
 *   5. RTT tracking (EWMA)
 *
 * Компилируется при CONFIG_EBURNET_QUIC=1.
 * Интеграция: вызывается из QUIC send path после реализации B.3.x
 */

#ifndef EBURNET_HYSTERIA2_CC_H
#define EBURNET_HYSTERIA2_CC_H

#ifdef CONFIG_EBURNET_QUIC

#include <stdint.h>
#include <stddef.h>

/* ── Константы ───────────────────────────────────────────────────── */

/* Размер sliding window (пакеты) */
#define BRUTAL_WINDOW_SIZE       256

/* Максимальный множитель actual/target при экстремальных потерях */
#define BRUTAL_MAX_MULTIPLIER      8

/* Минимальная loss_rate для применения компенсации */
#define BRUTAL_MIN_LOSS_RATE    0.01f   /* < 1% — считать 0 */

/* Ёмкость token bucket (количество секунд actual_bps) */
#define BRUTAL_BUCKET_SECONDS      1

/* ── Состояние Brutal CC ─────────────────────────────────────────── */

/*
 * Один экземпляр на QUIC соединение.
 * ~66 байт — размещать в hysteria2_conn_t или на heap.
 */
typedef struct {
    /* Конфигурация */
    uint64_t  target_bps;         /* желаемая скорость байт/с (из up_mbps) */
    uint64_t  max_bps;            /* target * BRUTAL_MAX_MULTIPLIER */

    /* Текущая расчётная скорость */
    uint64_t  actual_bps;         /* = target_bps / (1 - loss_rate) */
    float     loss_rate;          /* [0.0, 1.0] за последний window */

    /* Sliding window — сбрасывается после brutal_cc_update() */
    uint32_t  window_sent;        /* пакетов отправлено */
    uint32_t  window_acked;       /* пакетов подтверждено */
    uint32_t  window_lost;        /* пакетов потеряно */

    /* Token bucket для rate limiting */
    uint64_t  bucket_tokens;      /* текущий уровень (байты) */
    uint64_t  bucket_capacity;    /* максимум = actual_bps * BRUTAL_BUCKET_SECONDS */
    uint64_t  last_tick_us;       /* время последнего tick (микросекунды) */
    uint64_t  tick_remainder_us;  /* накопленный sub-ms остаток для tick */

    /* RTT оценка */
    uint32_t  rtt_ms;             /* сглаженный RTT (EWMA 7/8 + 1/8) */
    uint32_t  min_rtt_ms;         /* минимальный наблюдённый RTT */
} brutal_cc_t;

/* ── API ─────────────────────────────────────────────────────────── */

/*
 * Инициализировать Brutal CC.
 * up_mbps:   целевая скорость отправки (из hysteria2_config_t.up_mbps)
 * down_mbps: желаемая скорость приёма (передаётся серверу в Hysteria-CC-RX)
 *            Сохраняется вызывающей стороной; здесь используется только up_mbps.
 */
void brutal_cc_init(brutal_cc_t *cc,
                    uint32_t up_mbps, uint32_t down_mbps);

/* Сообщить об отправке пакета */
void brutal_cc_on_sent(brutal_cc_t *cc, size_t bytes);

/* Сообщить о подтверждении пакета (ACK) */
void brutal_cc_on_acked(brutal_cc_t *cc, size_t bytes);

/* Сообщить о потере пакета (таймаут или NACK) */
void brutal_cc_on_lost(brutal_cc_t *cc, size_t bytes);

/*
 * Пересчитать loss_rate и actual_bps по текущим счётчикам window.
 * Сбрасывает window_sent/acked/lost.
 * Вызывать после каждого batch ACK или раз в RTT.
 */
void brutal_cc_update(brutal_cc_t *cc);

/*
 * Обновить token bucket по прошедшему времени.
 * now_us: монотонное время в микросекундах.
 * Вызывать в основном event loop (epoll/io_uring callback).
 */
void brutal_cc_tick(brutal_cc_t *cc, uint64_t now_us);

/*
 * Проверить, можно ли отправить bytes прямо сейчас (token bucket).
 * Если да — списывает bytes из bucket и возвращает 1.
 * Если нет — возвращает 0 (caller должен поставить в очередь).
 */
int brutal_cc_can_send(brutal_cc_t *cc, size_t bytes, uint64_t now_us);

/*
 * Текущая расчётная скорость в байт/с.
 * Для заголовка Hysteria-CC-RX нужно бит/с:
 *   brutal_cc_get_rate(cc) * 8  →  значение для Hysteria-CC-RX
 */
uint64_t brutal_cc_get_rate(const brutal_cc_t *cc);

/*
 * Обновить RTT оценку (вызывать из QUIC ACK обработчика).
 * rtt_ms: измеренный RTT в миллисекундах.
 */
void brutal_cc_on_rtt(brutal_cc_t *cc, uint32_t rtt_ms);

#endif /* CONFIG_EBURNET_QUIC */
#endif /* EBURNET_HYSTERIA2_CC_H */

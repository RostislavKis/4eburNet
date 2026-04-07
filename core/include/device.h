/*
 * device.h — профили устройств и лимиты ресурсов (DEC-013)
 *
 * DeviceProfile определён в phoenix.h — здесь только расширение:
 * константы relay_buf / max_conns / dns_pending по профилю.
 */

#ifndef DEVICE_H
#define DEVICE_H

#include "phoenix.h"   /* DeviceProfile, DEVICE_MICRO/NORMAL/FULL */
#include <stddef.h>

/* ── Буфер relay ──────────────────────────────────────────────────────────── */
#define RELAY_BUF_MICRO    (8   * 1024)   /* 8KB — WR840N и др. */
#define RELAY_BUF_NORMAL   (32  * 1024)   /* 32KB — EC330, GL-AR750 */
#define RELAY_BUF_FULL     (64  * 1024)   /* 64KB — Flint 2, AX3000 */

/* ── Максимум relay соединений ────────────────────────────────────────────── */
#define RELAY_CONNS_MICRO   64
#define RELAY_CONNS_NORMAL  256
#define RELAY_CONNS_FULL    1024

/* ── DNS pending queue ────────────────────────────────────────────────────── */
#define DNS_PENDING_MICRO   16
#define DNS_PENDING_NORMAL  32
#define DNS_PENDING_FULL    64

/* ── Inline утилиты ───────────────────────────────────────────────────────── */

static inline size_t device_relay_buf(DeviceProfile p)
{
    switch (p) {
    case DEVICE_MICRO:  return RELAY_BUF_MICRO;
    case DEVICE_NORMAL: return RELAY_BUF_NORMAL;
    default:            return RELAY_BUF_FULL;
    }
}

static inline int device_max_conns(DeviceProfile p)
{
    switch (p) {
    case DEVICE_MICRO:  return RELAY_CONNS_MICRO;
    case DEVICE_NORMAL: return RELAY_CONNS_NORMAL;
    default:            return RELAY_CONNS_FULL;
    }
}

static inline int device_dns_pending(DeviceProfile p)
{
    switch (p) {
    case DEVICE_MICRO:  return DNS_PENDING_MICRO;
    case DEVICE_NORMAL: return DNS_PENDING_NORMAL;
    default:            return DNS_PENDING_FULL;
    }
}

/* ── Определение профиля ─────────────────────────────────────────────────── */

/* Определить профиль по /proc/meminfo MemTotal.
 * Обёртка над rm_detect_profile() для единого API через device.h. */
DeviceProfile device_detect_profile(void);

/* Строковое имя профиля: "MICRO" / "NORMAL" / "FULL" */
const char *device_profile_name(DeviceProfile p);

#endif /* DEVICE_H */

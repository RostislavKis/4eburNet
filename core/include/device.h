/*
 * device.h — профили устройств и лимиты ресурсов (DEC-013)
 *
 * DeviceProfile определён в 4eburnet.h — здесь только расширение:
 * константы relay_buf / max_conns / dns_pending по профилю.
 */

#ifndef DEVICE_H
#define DEVICE_H

#include "4eburnet.h"   /* DeviceProfile, DEVICE_MICRO/NORMAL/FULL */
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
#define DNS_PENDING_MICRO   32
#define DNS_PENDING_NORMAL  64
#define DNS_PENDING_FULL    128

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

/* ── DNS TCP клиенты ─────────────────────────────────────────────── */
#define DNS_TCP_CLIENTS_MICRO   2
#define DNS_TCP_CLIENTS_NORMAL  4
#define DNS_TCP_CLIENTS_FULL    8

static inline int device_dns_tcp_clients(DeviceProfile p)
{
    switch (p) {
    case DEVICE_MICRO:  return DNS_TCP_CLIENTS_MICRO;
    case DEVICE_NORMAL: return DNS_TCP_CLIENTS_NORMAL;
    default:            return DNS_TCP_CLIENTS_FULL;
    }
}

/* ── Определение профиля ─────────────────────────────────────────────────── */

/* Определить профиль по /proc/meminfo MemTotal.
 * Обёртка над rm_detect_profile() для единого API через device.h. */
DeviceProfile device_detect_profile(void);

/* Строковое имя профиля: "MICRO" / "NORMAL" / "FULL" */
const char *device_profile_name(DeviceProfile p);

#endif /* DEVICE_H */

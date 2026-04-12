/*
 * Единые числовые константы проекта.
 *
 * Значения fwmark, routing table, таймаутов и порогов определяются
 * здесь и только здесь. Все модули ссылаются на эти define.
 */

#ifndef CONSTANTS_H
#define CONSTANTS_H

/* ── Сетевая маршрутизация ─────────────────────────────────────── */

/* fwmark для маркировки пакетов (ip rule + nftables) */
#define FWMARK_PROXY            0x01u
#define FWMARK_TUN              0x02u

/* Номера таблиц ip route (не пересекаться с OpenWrt: main=254, default=253) */
#define ROUTE_TABLE_PROXY       100
#define ROUTE_TABLE_TUN         200
#define ROUTE_TABLE_BYPASS      250

/* Приоритеты ip rule (OpenWrt: 0/32766/32767, мы 1000-1002) */
#define ROUTE_PRIO_PROXY        1000
#define ROUTE_PRIO_TUN          1001
#define ROUTE_PRIO_BYPASS       1002

/* Интерфейс TUN по умолчанию */
#define TUN_IFACE_DEFAULT       "tun0"

/* ── Таймауты ──────────────────────────────────────────────────── */

#define TIMEOUT_IPC_CLIENT_SEC  3       /* SO_RCVTIMEO/SO_SNDTIMEO для IPC клиента */
#define TIMEOUT_DNS_SEC         1       /* SO_RCVTIMEO/SO_SNDTIMEO для DoT */
#define TIMEOUT_DNS_PENDING_MS  500     /* Потолок ожидания DNS UDP ответа */
#define TIMEOUT_NET_FETCH_SEC   10      /* SO_RCVTIMEO/SO_SNDTIMEO для HTTP fetch */

/* ── Надёжность ────────────────────────────────────────────────── */

#define HEALTH_MAX_FAILURES     3       /* После N неудач сервер помечается недоступным */

#endif /* CONSTANTS_H */

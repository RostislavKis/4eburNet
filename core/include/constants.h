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
#define TIMEOUT_TLS_POLL_US     100000  /* 100ms TLS poll */
#define TIMEOUT_DNS_PROBE_SEC   2       /* DNS upstream probe при старте */
#define TIMEOUT_HEALTH_FIRST_SEC  3     /* первый health-check после старта */
#define TIMEOUT_PROVIDER_RETRY_SEC 60   /* retry провайдеров */
#define TIMEOUT_HEALTH_RESET_SEC  30    /* health reset интервал */

/* ── Размеры буферов ──────────────────────────────────────────── */

#define DPI_FAKE_PKT_SIZE     1300   /* DPI fake packet */
#define AWG_JUNK_MAX_SIZE     1500   /* AWG junk packet */
#define AWG_HANDSHAKE_SIZE    1536   /* AWG handshake init packet */
#define DNS_DOH_B64_SIZE      8192   /* DoH base64 / HTTP response buffer */
#define DNS_DOH_REQ_SIZE      2048   /* DoH HTTP request buffer */

/* ── Надёжность ────────────────────────────────────────────────── */

#define HEALTH_MAX_FAILURES     3       /* После N неудач сервер помечается недоступным */

#endif /* CONSTANTS_H */

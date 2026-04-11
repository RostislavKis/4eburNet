/*
 * dpi_strategy.h — DPI bypass стратегии (C.3)
 *
 * Стратегии:
 *   fragment   — TCP split на позиции split_pos (TCP_NODELAY + два send())
 *   fake+TTL   — отправить fake payload × repeats с TTL=fake_ttl
 *                перед реальными данными; DPI видит фейк, пропускает трафик
 *
 * dpi_fooling_ts (TCP timestamp) — добавляется в C.4 (требует raw TCP socket)
 *
 * Компилируется при CONFIG_EBURNET_DPI=1.
 */

#ifndef EBURNET_DPI_STRATEGY_H
#define EBURNET_DPI_STRATEGY_H

#if CONFIG_EBURNET_DPI

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>

/* Тип протокола для выбора fake payload */
typedef enum {
    DPI_PROTO_TCP = 0,  /* fake TLS ClientHello */
    DPI_PROTO_UDP = 1,  /* fake QUIC Initial */
} dpi_proto_t;

/*
 * Конфигурация стратегии.
 * Заполняется из EburNetConfig (config.h) — не из хардкода.
 * dpi_strategy_config_init() выставляет разумные defaults
 * только если config не переопределил значения.
 */
typedef struct {
    bool  enabled;        /* применять DPI bypass */
    int   split_pos;      /* байт разбиения TCP payload (≥ 1) */
    int   fake_ttl;       /* TTL fake пакета (1..64) */
    int   fake_repeats;   /* кол-во fake пакетов (1..20) */
    char  fake_sni[256];  /* SNI для fake TLS ClientHello */
} dpi_strategy_config_t;

/*
 * Заполнить defaults (используется до загрузки UCI конфига).
 * После загрузки конфига заменить значения из EburNetConfig.
 */
void dpi_strategy_config_init(dpi_strategy_config_t *cfg);

/* ── Утилиты ─────────────────────────────────────────────────────── */

/*
 * Вычислить размеры двух фрагментов для TCP split.
 * Если split_pos ≤ 0 или ≥ data_len: p1=data_len, p2=0 (нет split).
 */
void dpi_fragment_sizes(int data_len, int split_pos, int *p1, int *p2);

/*
 * Сгенерировать fake payload.
 * TCP → fake TLS ClientHello с sni (NULL → "www.google.com").
 * UDP → fake QUIC Initial (1200 байт, sni игнорируется).
 * Возвращает длину или -1.
 */
int dpi_make_fake_payload(uint8_t *buf, int buf_size,
                           dpi_proto_t proto, const char *sni);

/* Установить IP TTL на сокете (IPPROTO_IP, IP_TTL) */
int dpi_set_ttl(int fd, int ttl);

/* Установить/снять TCP_NODELAY */
int dpi_set_nodelay(int fd, int on);

/* Создать raw socket для UDP fake (требует CAP_NET_RAW / root) */
int  dpi_raw_socket_create(int af);
void dpi_raw_socket_close(int fd);

/* ── Стратегии ───────────────────────────────────────────────────── */

/*
 * fake+TTL: установить TTL=fake_ttl, отправить payload × repeats,
 * восстановить исходный TTL.
 * fd: подключённый TCP или UDP сокет.
 * Используется перед отправкой реальных данных.
 * Возвращает 0 при успехе, -1 при ошибке.
 */
int dpi_send_fake(int fd,
                  const uint8_t *payload, int payload_len,
                  int fake_ttl, int repeats);

/*
 * fragment: TCP_NODELAY + send(data[0..split_pos-1]) + send(data[split_pos..]).
 * Если split_pos ≥ data_len — отправляет всё целиком (без split).
 * Возвращает суммарно отправленных байт или -1.
 */
int dpi_send_fragment(int fd,
                      const uint8_t *data, int data_len,
                      int split_pos);

#endif /* CONFIG_EBURNET_DPI */
#endif /* EBURNET_DPI_STRATEGY_H */

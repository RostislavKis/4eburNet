/*
 * Hysteria2 UDP datagrams (v2 protocol)
 * Spec: https://v2.hysteria.network/docs/developers/Protocol/
 *
 * UDP messages идут как QUIC unreliable datagrams (RFC 9221).
 * НЕТ frame type prefix (0x403 — документация, не wire).
 *
 * Wire format датаграммы:
 *   [uint32 SessionID BE][uint16 PacketID BE]
 *   [uint8  FragID][uint8 FragCount]
 *   if FragID == 0:
 *     [uint16 HostLen BE][Host bytes][uint16 Port BE]
 *   [Data bytes...]   — до конца датаграммы (implicit length)
 *
 * Минимум frag_id > 0 : 8 байт
 * Минимум frag_id == 0: 8 + 2 + HostLen + 2 байт
 *
 * Компилируется при CONFIG_EBURNET_QUIC=1.
 */

#ifndef EBURNET_HYSTERIA2_UDP_H
#define EBURNET_HYSTERIA2_UDP_H

#ifdef CONFIG_EBURNET_QUIC

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include "proxy/hysteria2.h"  /* HY2_FRAME_UDP_MESSAGE, конфиг */

/* ── Константы ───────────────────────────────────────────────────────── */

/* Максимальный payload одного фрагмента (QUIC datagram ~1350 − overhead) */
#define HY2_UDP_FRAG_PAYLOAD  1200
/* Размер буфера для одного закодированного фрейма */
#define HY2_UDP_FRAG_SIZE     1300
/* Максимум фрагментов: ceil(65535 / 1200) = 55, с запасом */
#define HY2_UDP_MAX_FRAGS       64
/* Таблица сессий */
#define HY2_UDP_MAX_SESSIONS   256
/* Минимальный заголовок датаграммы (SessionID+PacketID+FragID+FragCount) */
#define HY2_UDP_HDR_MIN          8

/* ── Разобранное UDP сообщение ───────────────────────────────────────── */

typedef struct {
    uint32_t        session_id;
    uint16_t        packet_id;
    uint8_t         frag_id;
    uint8_t         frag_count;
    /* Адрес назначения — заполнено только если frag_id == 0 */
    char            host[256];
    uint16_t        port;
    /* Данные — zero-copy указатель в исходный буфер */
    const uint8_t  *data;
    size_t          data_len;
} hy2_udp_msg_t;

/* ── Один закодированный фрагмент ───────────────────────────────────── */

typedef struct {
    uint8_t *buf;        /* указатель в frag_bufs[i] из caller'а */
    size_t   buf_len;    /* фактическая длина закодированного фрейма */
    uint8_t  frag_id;
    uint8_t  frag_count;
} hy2_udp_fragment_t;

/* ── UDP сессия (session_id → host:port) ────────────────────────────── */

typedef struct {
    uint32_t session_id;
    char     host[256];
    uint16_t port;
    bool     active;
} hy2_udp_session_t;

typedef struct {
    hy2_udp_session_t sessions[HY2_UDP_MAX_SESSIONS];
} hy2_udp_session_mgr_t;

/* ── Encode / Decode ─────────────────────────────────────────────────── */

/*
 * Закодировать UDP message в buf.
 * host/port: адрес назначения (используется только при frag_id == 0).
 * Возвращает число записанных байт или -1.
 */
int hy2_udp_msg_encode(uint8_t *buf, size_t buf_size,
                       uint32_t session_id, uint16_t packet_id,
                       uint8_t frag_id, uint8_t frag_count,
                       const char *host, uint16_t port,
                       const uint8_t *data, size_t data_len);

/*
 * Разобрать UDP message из buf.
 * msg_out->data указывает в buf (zero-copy, src буфер должен жить дольше msg).
 * data_out/data_out_size: опциональное копирование payload.
 * Возвращает buf_size (потреблено всё) или -1 при ошибке формата.
 */
int hy2_udp_msg_decode(const uint8_t *buf, size_t buf_size,
                       hy2_udp_msg_t *msg_out,
                       uint8_t *data_out, size_t data_out_size);

/* ── Фрагментация ────────────────────────────────────────────────────── */

/*
 * Разбить data на фрагменты <= HY2_UDP_FRAG_PAYLOAD.
 * Каждый фрагмент кодируется в frag_bufs[i], метаданные в frags[i].
 * addr включается только в frag_id == 0.
 * Возвращает число фрагментов (>= 1) или -1 при ошибке.
 */
int hy2_udp_fragment(uint32_t session_id, uint16_t packet_id,
                     const char *host, uint16_t port,
                     const uint8_t *data, size_t data_len,
                     hy2_udp_fragment_t *frags,
                     uint8_t (*frag_bufs)[HY2_UDP_FRAG_SIZE],
                     int max_frags);

/* ── Session manager ─────────────────────────────────────────────────── */

void               hy2_udp_session_mgr_init(hy2_udp_session_mgr_t *mgr);

/*
 * Добавить или обновить сессию.
 * При дубликате session_id — обновляет host/port.
 * Возвращает 0 или -1 (таблица заполнена).
 */
int                hy2_udp_session_add(hy2_udp_session_mgr_t *mgr,
                                       uint32_t session_id,
                                       const char *host, uint16_t port);

hy2_udp_session_t *hy2_udp_session_find(hy2_udp_session_mgr_t *mgr,
                                         uint32_t session_id);

void               hy2_udp_session_remove(hy2_udp_session_mgr_t *mgr,
                                          uint32_t session_id);

/* Обнулить всю таблицу (нет heap-аллокаций, только memset) */
void               hy2_udp_session_mgr_free(hy2_udp_session_mgr_t *mgr);

#endif /* CONFIG_EBURNET_QUIC */
#endif /* EBURNET_HYSTERIA2_UDP_H */

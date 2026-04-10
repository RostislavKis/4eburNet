/*
 * Hysteria2 — TCP/UDP прокси поверх QUIC
 * Spec: https://v2.hysteria.network/docs/developers/Protocol/
 *
 * TCP: каждое соединение = QUIC bidirectional stream
 * Auth: HTTP/3 POST "/" + Hysteria-Auth заголовок
 * Salamander: BLAKE2b-256 XOR obfuscation (quic_salamander.c)
 *
 * Фреймы (varint RFC 9000):
 *   0x401 TCPRequest  [varint addr_len][addr][uint16 pad_len][padding]
 *   0x402 TCPResponse [uint8 status][uint32 msg_len][msg][uint16 pad_len][pad]
 *
 * quic.h НЕ включается: он для DoQ-криптопримитивов.
 * wolfSSL используется напрямую в hysteria2.c.
 *
 * Компилируется только при CONFIG_EBURNET_QUIC=1.
 */

#ifndef EBURNET_HYSTERIA2_H
#define EBURNET_HYSTERIA2_H

#ifdef CONFIG_EBURNET_QUIC

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>   /* ssize_t */
#include "crypto/quic_salamander.h"

/* ── Константы протокола ─────────────────────────────────────────────── */

#define HY2_FRAME_TCP_REQUEST   UINT64_C(0x401)
#define HY2_FRAME_TCP_RESPONSE  UINT64_C(0x402)
#define HY2_FRAME_UDP_MESSAGE   UINT64_C(0x403)

#define HY2_TCP_STATUS_OK    0x00
#define HY2_TCP_STATUS_ERROR 0x01

/* Минимальный padding для anti-fingerprint (в TCPRequest) */
#define HY2_MIN_PADDING  64
#define HY2_MAX_PADDING 512

/* Максимальный адрес host:port */
#define HY2_MAX_ADDR    272  /* 253 (FQDN) + ':' + 5 (port) + NUL */

/* Overhead TCPRequest = varint(FrameType 8b) + varint(AddrLen 2b) + uint16(PadLen) */
#define HY2_TCP_REQ_OVERHEAD  (8 + 2 + 2)

/* ── Конфигурация соединения ─────────────────────────────────────────── */

typedef struct {
    char     server_addr[256];  /* хост или IP сервера */
    uint16_t server_port;
    char     password[512];     /* Hysteria-Auth */
    char     sni[256];          /* TLS SNI (пусто → server_addr) */
    bool     insecure;          /* пропустить TLS верификацию */

    /* Salamander obfuscation (опционально) */
    bool     obfs_enabled;
    char     obfs_password[512];

    /* Bandwidth hints для Brutal CC */
    uint32_t up_mbps;    /* 0 = не задано */
    uint32_t down_mbps;  /* 0 = не задано */
} hysteria2_config_t;

/* ── Состояние соединения ─────────────────────────────────────────────── */

typedef enum {
    HY2_STATE_DISCONNECTED = 0,
    HY2_STATE_CONNECTING,
    HY2_STATE_AUTH,       /* ожидаем 200 от сервера */
    HY2_STATE_CONNECTED,
    HY2_STATE_ERROR,
} hysteria2_state_t;

/*
 * Соединение Hysteria2.
 * Опаковая структура — аллоцируется hysteria2_conn_new(), детали в .c.
 */
typedef struct hysteria2_conn hysteria2_conn_t;

/* ── Состояние TCP стрима ─────────────────────────────────────────────── */

typedef enum {
    HY2_STREAM_INIT = 0,
    HY2_STREAM_REQUESTING,  /* TCPRequest отправлен, ждём TCPResponse */
    HY2_STREAM_OPEN,        /* канал открыт, данные идут */
    HY2_STREAM_CLOSED,
    HY2_STREAM_ERROR,
} hysteria2_stream_state_t;

typedef struct {
    uint64_t                  stream_id;         /* QUIC stream ID */
    hysteria2_stream_state_t  state;
    char                      target_addr[HY2_MAX_ADDR];
    char                      error_msg[128];
    /* Внутреннее: буфер частично прочитанных данных стрима */
    uint8_t                   rxbuf[4096];
    size_t                    rxbuf_len;
} hysteria2_stream_t;

/* ── API соединения ──────────────────────────────────────────────────── */

/*
 * Создать новый контекст Hysteria2 (не подключает).
 * Возвращает NULL при ошибке выделения памяти.
 */
hysteria2_conn_t *hysteria2_conn_new(const hysteria2_config_t *cfg);

/*
 * Установить QUIC соединение и пройти auth (HTTP/3 POST "/").
 * Блокирующий вызов. Возвращает 0 при успехе, -1 при ошибке.
 */
int hysteria2_connect(hysteria2_conn_t *conn);

/*
 * Получить текстовое описание последней ошибки.
 */
const char *hysteria2_strerror(const hysteria2_conn_t *conn);

/* Закрыть соединение и освободить все ресурсы */
void hysteria2_conn_free(hysteria2_conn_t *conn);

/* ── API TCP стримов ──────────────────────────────────────────────────── */

/*
 * Открыть новый TCP канал к host:port.
 * Выделяет QUIC bidi stream, отправляет TCPRequest с padding.
 * Возвращает 0 при успехе.
 */
int hysteria2_tcp_open(hysteria2_conn_t *conn,
                       hysteria2_stream_t *stream,
                       const char *host, uint16_t port);

/*
 * Прочитать TCPResponse от сервера.
 * Блокирующий (с таймаутом соединения).
 * Возвращает 0 при статусе OK, -1 при ошибке или status != 0.
 */
int hysteria2_tcp_wait_response(hysteria2_conn_t *conn,
                                hysteria2_stream_t *stream);

/*
 * Relay данных: читать из src_fd, писать в QUIC stream.
 * Используется dispatcher для проксирования клиентского трафика.
 * Читает до len байт, возвращает число отправленных или -1.
 */
ssize_t hysteria2_tcp_send(hysteria2_conn_t *conn,
                           hysteria2_stream_t *stream,
                           const void *buf, size_t len);

ssize_t hysteria2_tcp_recv(hysteria2_conn_t *conn,
                           hysteria2_stream_t *stream,
                           void *buf, size_t len);

/* Закрыть TCP стрим (half-close исходящего направления) */
void hysteria2_stream_close(hysteria2_conn_t *conn,
                            hysteria2_stream_t *stream);

/* ── Утилиты — varint (RFC 9000 §16) ────────────────────────────────── */

/*
 * Записать varint в buf[0..buf_size).
 * Возвращает число записанных байт (1/2/4/8) или -1 если buf_size мал.
 */
int hy2_varint_encode(uint8_t *buf, size_t buf_size, uint64_t value);

/*
 * Прочитать varint из buf[0..buf_size).
 * Записывает результат в *out.
 * Возвращает число прочитанных байт или -1 при ошибке/неполном буфере.
 */
int hy2_varint_decode(const uint8_t *buf, size_t buf_size, uint64_t *out);

/*
 * Сериализовать TCPRequest в buf.
 * host:port → addr строка "host:port".
 * padding_len: 0 = выбрать случайный [HY2_MIN_PADDING, HY2_MAX_PADDING].
 * Возвращает число байт или -1 при переполнении буфера.
 */
int hy2_tcp_request_encode(uint8_t *buf, size_t buf_size,
                           const char *host, uint16_t port,
                           size_t padding_len);

/*
 * Разобрать TCPResponse из buf.
 * Заполняет *status (HY2_TCP_STATUS_OK / HY2_TCP_STATUS_ERROR).
 * msg_out и msg_max — для сообщения об ошибке.
 * Возвращает число потреблённых байт или -1.
 */
int hy2_tcp_response_decode(const uint8_t *buf, size_t buf_size,
                            uint8_t *status,
                            char *msg_out, size_t msg_max);

#endif /* CONFIG_EBURNET_QUIC */
#endif /* EBURNET_HYSTERIA2_H */

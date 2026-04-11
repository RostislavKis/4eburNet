/*
 * dpi_payload.h — нативная генерация fake TLS ClientHello + QUIC Initial (C.2)
 *
 * Независимость от внешних .bin файлов (zapret и т.д.).
 * Пакеты генерируются нативно при каждом вызове.
 *
 * Использование в fake+TTL стратегии (C.3):
 *   dpi_make_tls_clienthello(buf, sizeof(buf), sni) → отправить с TTL=3
 *   dpi_make_quic_initial(buf, sizeof(buf))         → отправить с TTL=3
 *   Пакет не достигает сервера, DPI его "видит" и пропускает.
 *
 * Компилируется при CONFIG_EBURNET_DPI=1.
 */

#ifndef EBURNET_DPI_PAYLOAD_H
#define EBURNET_DPI_PAYLOAD_H

#if CONFIG_EBURNET_DPI

#include <stdint.h>

/*
 * Сгенерировать fake TLS 1.3 ClientHello.
 *
 * Fingerprint близок к Chrome 120+:
 *   - Record version: TLS 1.0 (0x0301) для совместимости
 *   - Client hello version: TLS 1.2 (0x0303)
 *   - 17 cipher suites (Chrome набор)
 *   - SessionID: 32 random байта
 *   - Extensions (15): SNI, supported_groups, ALPN (h2/http1.1),
 *     supported_versions (TLS1.3+TLS1.2), signature_algorithms,
 *     key_share (x25519, 32 random байта), psk_key_exchange_modes,
 *     extended_master_secret, renegotiation_info, session_ticket,
 *     status_request, ec_point_formats, signed_cert_timestamp,
 *     record_size_limit, compress_certificate
 *   - Random: 32 байта из /dev/urandom
 *
 * buf:      выходной буфер (минимум 300 байт)
 * buf_size: размер буфера
 * sni:      TLS SNI (NULL → "www.google.com")
 * Возвращает: длину пакета или -1 при ошибке
 */
int dpi_make_tls_clienthello(uint8_t *buf, int buf_size, const char *sni);

/*
 * Сгенерировать fake QUIC Initial пакет (ровно 1200 байт).
 *
 * Long Header + Version 0x00000001 (QUIC v1) + DCID 8 random байт.
 * Payload: PADDING frames (0x00).
 *
 * ПРИМЕЧАНИЕ: payload = нули (не AEAD), что является допущением.
 * При fake+TTL пакет не достигает сервера → AEAD не нужен.
 * DPI проверяет только заголовок (Long Header + Version + DCID).
 * Если ТСПУ начнёт проверять энтропию payload — заменить на random.
 *
 * buf_size: минимум 1200 байт
 * Возвращает: 1200 или -1 при ошибке
 */
int dpi_make_quic_initial(uint8_t *buf, int buf_size);

#endif /* CONFIG_EBURNET_DPI */

/*
 * Расширенная версия ClientHello для ShadowTLS v3 (D.2).
 * Доступна при CONFIG_EBURNET_DPI=1 ИЛИ CONFIG_EBURNET_STLS=1.
 *
 * client_random[32]: если NULL — генерируется из /dev/urandom.
 * session_id[32]:    если NULL — генерируется случайно.
 * out_random[32]:    если != NULL — записывается использованный client_random.
 * Возвращает длину пакета или -1.
 */
#if CONFIG_EBURNET_DPI || CONFIG_EBURNET_STLS
int dpi_make_tls_clienthello_ex(uint8_t *buf, int buf_size,
                                 const char *sni,
                                 const uint8_t *client_random,
                                 const uint8_t *session_id,
                                 uint8_t *out_random);
#endif

#endif /* EBURNET_DPI_PAYLOAD_H */

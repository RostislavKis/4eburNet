#ifndef JA3_H
#define JA3_H

#include "proxy/sniffer.h"

/* ja3_compute — вычислить JA3 хэш из ClientHelloInfo.
 *
 * Строит строку: "{ver},{ciphers},{exts},{groups},{ecpf}"
 * Значения через '-', блоки через ','.
 * ja3_out:     буфер 33 байта (32 hex + \0), обязателен.
 * ja3_str_out: исходная строка до MD5, NULL если не нужна.
 * Использует static буфер — не реентерабелен
 * (безопасно: вызывается только из однопоточного epoll). */
int ja3_compute(const ClientHelloInfo *info,
                char ja3_out[33],
                char *ja3_str_out, size_t ja3_str_size);

/* ja4_compute — вычислить JA4 хэш.
 *
 * Формат (FoxIO spec):
 *   t{TLSver}{SNI}{cc}{ec}{alpn}_{cipher12}_{ext12}
 *   t       = TCP
 *   TLSver  = "13"/"12"/"11"/"10"
 *   SNI     = 'd' если SNI present, 'i' если нет
 *   cc      = cipher count, 2 цифры
 *   ec      = ext count, 2 цифры
 *   alpn    = первые 2 символа ALPN proto ("h2","h1","00" если нет)
 *   cipher12 = SHA-256(отсортированные ciphers hex), первые 12 символов
 *   ext12    = SHA-256(extensions без SNI(0x0000)/ALPN(0x0010)), первые 12
 * ja4_out: буфер 40 байт (реальная длина 36+\0).
 * Использует static буфер — не реентерабелен. */
int ja4_compute(const ClientHelloInfo *info, char ja4_out[40]);

/* Встроенный эталон браузера.
 * ja4_prefix: первые 6 символов JA4 (до cipher/ext hash). */
typedef struct {
    const char *name;
    const char *ja3_hash;
    const char *ja4_prefix;
} Ja3Reference;

/* ja3_get_references — NULL-terminated список встроенных эталонов.
 * Эталоны меняются с версией браузера — только для ориентира.
 * Ожидаемый хэш задаётся через /api/control action=ja3_expected (в памяти). */
const Ja3Reference *ja3_get_references(void);

/* ja3_match_reference — найти браузер по точному совпадению JA3 хэша.
 * Возвращает name или NULL если нет совпадения. */
const char *ja3_match_reference(const char *ja3_hash);

#endif /* JA3_H */

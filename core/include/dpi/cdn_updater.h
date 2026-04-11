/*
 * cdn_updater.h — автообновление CDN IP диапазонов (C.4)
 *
 * Скачивает официальные CIDR списки CDN-провайдеров,
 * дедуплицирует и атомарно обновляет ipset.txt.
 * После обновления вызывает dpi_filter_init() для горячей перезагрузки.
 *
 * Источники:
 *   Cloudflare: cloudflare.com/ips-v4 + ips-v6 (текст, один CIDR/строка)
 *   Fastly:     api.fastly.com/public-ip-list   (JSON)
 *
 * Компилируется при CONFIG_EBURNET_DPI=1.
 */

#ifndef EBURNET_CDN_UPDATER_H
#define EBURNET_CDN_UPDATER_H

#if CONFIG_EBURNET_DPI

/* ── Публичный API ───────────────────────────────────────────────── */

/*
 * Проверить нужно ли обновление и запустить его если да.
 * Вызывать при старте демона и раз в сутки из event loop.
 * Возвращает: 1 обновил, 0 актуально или выключено, -1 ошибка.
 */
struct EburNetConfig;
int cdn_updater_check(const struct EburNetConfig *cfg);

/*
 * Принудительное обновление (IPC команда "update-ipset").
 * NOT reentrant: использует PID-именованные /tmp файлы.
 * Вызывать только из однопоточного event loop.
 * Возвращает: 0 успех, -1 ошибка.
 */
int cdn_updater_update(const struct EburNetConfig *cfg);

/* ── Внутренние функции (экспортируются для тестирования) ─────────── */

/*
 * Проверить устаревший ли stamp.
 * interval_days == 0 → возвращает -1 (обновление выключено).
 * Возвращает: 1 устарел/нет файла, 0 свежий, -1 выключено.
 */
int  cdn_is_stale(const char *stamp_path, int interval_days);

/* Записать текущий timestamp. Возвращает 0 или -1. */
int  cdn_stamp_write(const char *stamp_path);

/* Прочитать timestamp. Возвращает значение или -1. */
long cdn_stamp_read(const char *stamp_path);

/*
 * Парсинг текстового формата (Cloudflare): один CIDR на строку,
 * строки начинающиеся с '#' и пустые игнорируются.
 * cidrs[][cidr_size] — выходной массив.
 * Возвращает количество CIDR или -1.
 */
int cdn_parse_text(const char *text,
                   char cidrs[][64], int max_count, int cidr_size);

/*
 * Парсинг JSON Fastly: {"addresses":[...],"ipv6_addresses":[...]}.
 * Ручной парсинг, без внешних зависимостей.
 * Возвращает количество CIDR или -1.
 */
int cdn_parse_fastly_json(const char *json,
                           char cidrs[][64], int max_count, int cidr_size);

/*
 * Дедупликация и атомарная запись CIDR в out_path.
 * Сортирует → убирает дубли → пишет в .tmp → rename().
 * Возвращает 0 или -1.
 */
int cdn_merge_write(char cidrs[][64], int count, const char *out_path);

#endif /* CONFIG_EBURNET_DPI */
#endif /* EBURNET_CDN_UPDATER_H */

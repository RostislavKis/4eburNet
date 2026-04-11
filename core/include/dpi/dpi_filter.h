/*
 * dpi_filter.h — DPI bypass фильтр (C.1)
 *
 * Загружает три файла при старте:
 *   ipset.txt    — IP/CIDR диапазоны CDN (IPv4 + IPv6), 8996 строк
 *   whitelist.txt — домены-исключения (без DPI), 2109 строк
 *   autohosts.txt — домены для принудительного DPI bypass, 103 строки
 *
 * Поиск: sorted array + bsearch, O(log N).
 * RAM: ~216 KB суммарно — вписывается в профиль MICRO.
 *
 * Компилируется при CONFIG_EBURNET_DPI=1.
 */

#ifndef EBURNET_DPI_FILTER_H
#define EBURNET_DPI_FILTER_H

#if CONFIG_EBURNET_DPI

#include <stdint.h>
#include <stddef.h>

/* Результат проверки */
typedef enum {
    DPI_MATCH_NONE   = 0,  /* обычная обработка (прокси или прямое) */
    DPI_MATCH_BYPASS = 1,  /* применить fake+split (C.2+) */
    DPI_MATCH_IGNORE = 2,  /* в whitelist — не применять DPI */
} dpi_match_t;

/*
 * Инициализировать фильтр.
 * dpi_dir: директория с ipset.txt / whitelist.txt / autohosts.txt
 *          (NULL → "/etc/4eburnet/dpi")
 * Возвращает 0 при успехе.
 * Ошибки: файлы отсутствуют, ОО памяти.
 * При ошибке — фильтр работает в режиме pass-through (все = NONE).
 */
int  dpi_filter_init(const char *dpi_dir);

/* Освободить память и сбросить состояние */
void dpi_filter_free(void);

/* Вернуть 1 если фильтр инициализирован */
int  dpi_filter_is_ready(void);

/*
 * Проверить IPv4 адрес (host byte order) против ipset.txt.
 * port: 0 = игнорировать порт (любой).
 * Возвращает DPI_MATCH_BYPASS если IP в CDN диапазоне, иначе NONE.
 */
dpi_match_t dpi_filter_match_ipv4(uint32_t ip, uint16_t port);

/*
 * Проверить IPv6 адрес (16 байт, network byte order) против ipset.txt.
 */
dpi_match_t dpi_filter_match_ipv6(const uint8_t ip6[16], uint16_t port);

/*
 * Проверить домен (из SNI или DNS) против whitelist + autohosts.
 * domain: NUL-terminated строка ("example.com").
 *
 * Возвращает:
 *   DPI_MATCH_BYPASS — домен в autohosts.txt (принудительный bypass)
 *   DPI_MATCH_IGNORE — домен в whitelist.txt (не применять DPI)
 *   DPI_MATCH_NONE   — домен неизвестен (использовать IP-правило)
 *
 * Поиск точного совпадения. Wildcard не поддерживается.
 */
dpi_match_t dpi_filter_match_domain(const char *domain);

/*
 * Комбинированная проверка: сначала домен, затем IP.
 * Приоритет: IGNORE > BYPASS > NONE.
 * ip6 может быть NULL если IPv6 недоступен.
 */
dpi_match_t dpi_filter_match(const char *domain,
                              uint32_t ipv4,
                              const uint8_t *ip6,
                              uint16_t port);

/* Статистика для диагностики */
typedef struct {
    int ipv4_ranges;   /* загружено IPv4 CIDR */
    int ipv6_ranges;   /* загружено IPv6 CIDR */
    int whitelist;     /* доменов в whitelist */
    int autohosts;     /* доменов в autohosts */
} dpi_filter_stats_t;

void dpi_filter_get_stats(dpi_filter_stats_t *stats);

#endif /* CONFIG_EBURNET_DPI */
#endif /* EBURNET_DPI_FILTER_H */

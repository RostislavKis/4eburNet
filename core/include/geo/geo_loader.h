/*
 * geo_loader.h — гео-базы: регионы, CIDR-списки, домены
 * Контракты этапа 3.5:
 *   C-1: определение региона через CIDR-lookup по IP устройства
 *   C-2: rule_provider фильтрует по region != UNKNOWN
 *   C-3: GEOIP / GEOSITE типы правил в rules_engine
 *   C-4: graceful degradation — при ошибке загрузки region = UNKNOWN
 *   C-5: hot-reload без перезапуска демона (IPC cmd)
 *   C-6: бинарный поиск по отсортированным CIDR4 + суффиксам
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>

/* Прямой инклюд config.h нежелателен в заголовке — используем forward decl */
struct PhoenixConfig;

/* ── Регионы ─────────────────────────────────────────────────────────────── */

typedef enum {
    GEO_REGION_UNKNOWN = 0,
    GEO_REGION_RU      = 1,
    GEO_REGION_CN      = 2,
    GEO_REGION_US      = 3,
    GEO_REGION_OTHER   = 99,
} geo_region_t;

/* ── CIDR структуры ──────────────────────────────────────────────────────── */

/* IPv4 CIDR — адреса в host byte order */
typedef struct {
    uint32_t net;   /* сетевой адрес */
    uint32_t mask;  /* маска (0xFFFFFFFF << (32 - prefix)) */
} geo_cidr4_t;

/* IPv6 CIDR */
typedef struct {
    uint8_t net[16]; /* сетевой адрес */
    uint8_t prefix;  /* длина префикса (0..128) */
} geo_cidr6_t;

/* Patricia trie для O(32) IPv4 CIDR lookup */
typedef struct ptrie_node {
    struct ptrie_node *child[2];  /* [0]=left, [1]=right */
    geo_region_t       region;    /* GEO_REGION_UNKNOWN = промежуточный */
    bool               terminal;  /* true = здесь есть CIDR запись */
} ptrie_node_t;

/* ── Категория (один файл/провайдер) ────────────────────────────────────── */

typedef struct {
    char        name[32];        /* имя категории, напр. "ru_cidr", "cn_domains" */
    char        path[256];       /* путь к файлу на диске — для geo_reload_category */
    geo_region_t region;         /* к какому региону относится */
    time_t      loaded_at;       /* unix timestamp последней загрузки */

    /* IPv4 CIDR: отсортированы по net для binary search */
    geo_cidr4_t *v4;
    int          v4_count;

    /* IPv6 CIDR */
    geo_cidr6_t *v6;
    int          v6_count;

    /* Домены точного совпадения (отсортированы для bsearch) */
    char       **domains;
    int          domain_count;

    /* Суффиксы (отсортированы для bsearch) */
    char       **suffixes;
    int          suffix_count;

    ptrie_node_t *trie_v4;  /* Patricia trie для IPv4 (NULL = не построен) */

    bool loaded;
} geo_category_t;

/* ── Менеджер гео-баз ───────────────────────────────────────────────────── */

typedef struct {
    geo_category_t          *categories;  /* динамический массив */
    int                      count;
    int                      capacity;
    geo_region_t             current_region; /* регион текущего устройства */
    const struct PhoenixConfig *cfg;
} geo_manager_t;

/* ── API ─────────────────────────────────────────────────────────────────── */

/*
 * geo_manager_init — инициализировать менеджер, загрузить все категории из cfg.
 * Возвращает 0 при успехе, -1 при OOM.
 * C-4: ошибки загрузки отдельных категорий не фатальны,
 *      провалившиеся категории помечаются loaded=false.
 */
int  geo_manager_init(geo_manager_t *gm, const struct PhoenixConfig *cfg);

/* geo_manager_free — освободить все ресурсы */
void geo_manager_free(geo_manager_t *gm);

/*
 * device_detect_region — определить регион по IP-адресу устройства.
 * Обходит все загруженные категории и ищет совпадение в CIDR.
 * C-1: при отсутствии совпадения возвращает GEO_REGION_UNKNOWN.
 * C-4: при незагруженных категориях тоже GEO_REGION_UNKNOWN.
 */
geo_region_t device_detect_region(geo_manager_t *gm,
                                   const struct sockaddr_storage *device_addr);

/* Утилиты для работы с enum */
const char  *geo_region_name(geo_region_t r);      /* "RU", "CN", "US", "OTHER", "UNKNOWN" */
geo_region_t geo_region_from_str(const char *str);  /* "RU" → GEO_REGION_RU, "" → UNKNOWN */

/*
 * geo_load_category — загрузить/обновить категорию из файла.
 * Создаёт новую запись если name не найден.
 * Возвращает 0 при успехе, -1 при ошибке (файл не найден / OOM).
 */
int geo_load_category(geo_manager_t *gm, const char *name,
                      geo_region_t region, const char *path);

/*
 * geo_reload_category — принудительно перечитать файл категории с диска.
 * C-5: вызывается из IPC hot-reload.
 * Возвращает 0 при успехе, -1 если категория не найдена или ошибка чтения.
 */
int geo_reload_category(geo_manager_t *gm, const char *name);

/*
 * geo_match_ip — найти регион по IP-адресу.
 * C-3: используется rules_engine для GEOIP правил.
 * Возвращает первый совпавший регион или GEO_REGION_UNKNOWN.
 */
geo_region_t geo_match_ip(const geo_manager_t *gm,
                           const struct sockaddr_storage *addr);

/*
 * geo_match_domain — найти регион по доменному имени.
 * C-3: используется rules_engine для GEOSITE правил.
 * C-6: сначала bsearch по точным доменам, затем bsearch по суффиксам.
 * Возвращает первый совпавший регион или GEO_REGION_UNKNOWN.
 */
geo_region_t geo_match_domain(const geo_manager_t *gm, const char *domain);

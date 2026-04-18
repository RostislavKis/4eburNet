/*
 * dpi_adapt.h — Adaptive DPI: кэш стратегий bypass по IP (v1.2-1)
 *
 * Хранит для каждого IPv4 адреса последнюю успешную стратегию bypass.
 * При повторном подключении использует кэшированную стратегию.
 * При отказах эскалирует: NONE → FRAGMENT → FAKE_TTL → BOTH.
 * Персистентность: /etc/4eburnet/dpi_cache.bin.
 */

#ifndef DPI_ADAPT_H
#define DPI_ADAPT_H

#if CONFIG_EBURNET_DPI

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Стратегии DPI bypass в порядке нарастающей агрессивности */
typedef enum {
    DPI_STRAT_NONE     = 0,  /* без обхода — прямое соединение */
    DPI_STRAT_FRAGMENT = 1,  /* только фрагментация первого пакета */
    DPI_STRAT_FAKE_TTL = 2,  /* только fake ClientHello + TTL */
    DPI_STRAT_BOTH     = 3,  /* fake TTL + фрагментация */
} dpi_strat_t;

/* Результат попытки */
typedef enum {
    DPI_RESULT_SUCCESS = 0,
    DPI_RESULT_FAIL    = 1,  /* RST или timeout без ответа upstream */
} dpi_result_t;

/*
 * Запись в кэше: 16 байт.
 * ip == 0 означает пустой слот.
 */
typedef struct __attribute__((packed)) {
    uint32_t    ip;           /* IPv4 адрес назначения (host byte order) */
    uint8_t     strategy;     /* dpi_strat_t последней успешной стратегии */
    uint8_t     fail_count;   /* неудач подряд текущей стратегии (cap 255) */
    uint16_t    reserved;     /* выравнивание */
    uint32_t    last_success; /* unix timestamp последнего успеха */
    uint32_t    hits;         /* счётчик успешных попаданий */
} DpiAdaptRecord;             /* = 16 байт */

/*
 * Хэш-таблица с open addressing (linear probe).
 * Без поддержки удаления — не нужно (записи только растут или обновляются).
 */
#define DPI_ADAPT_SLOTS  4096        /* степень 2, таблица = 64KB */
#define DPI_ADAPT_MAGIC  0xD4D10001u /* magic для dpi_cache.bin */

typedef struct {
    DpiAdaptRecord slots[DPI_ADAPT_SLOTS];  /* 64KB */
    uint32_t       count;                   /* занятых слотов */
    bool           dirty;                   /* нужна запись на диск */
} DpiAdaptTable;

/* Глобальный экземпляр, определён в dispatcher.c */
extern DpiAdaptTable g_dpi_adapt;

/* ── API ─────────────────────────────────────────────────────────── */

/* Инициализировать таблицу (обнулить) */
void dpi_adapt_init(DpiAdaptTable *t);

/*
 * Загрузить кэш из файла (при старте демона).
 * Возвращает 0 при успехе, -1 если файл не найден или повреждён.
 */
int dpi_adapt_load(DpiAdaptTable *t, const char *path);

/*
 * Сохранить кэш в файл (при SIGHUP или shutdown).
 * Атомарная запись: .tmp → rename.
 * Возвращает 0 при успехе, -1 при ошибке.
 */
int dpi_adapt_save(const DpiAdaptTable *t, const char *path);

/*
 * Получить стратегию для IP.
 * Неизвестный IP → DPI_STRAT_NONE (попробовать без обхода сначала).
 * fail_count >= 3 → следующая стратегия; кэп на DPI_STRAT_BOTH.
 */
dpi_strat_t dpi_adapt_get(const DpiAdaptTable *t, uint32_t ip);

/*
 * Сообщить результат попытки для IP.
 * SUCCESS: сохранить strategy, обнулить fail_count, инкрементировать hits.
 * FAIL: инкрементировать fail_count.
 */
void dpi_adapt_report(DpiAdaptTable *t, uint32_t ip,
                       dpi_strat_t strategy, dpi_result_t result);

/* Получить статистику для IPC/Dashboard */
void dpi_adapt_stats(const DpiAdaptTable *t,
                      uint32_t *out_count, uint32_t *out_hits);

#endif /* CONFIG_EBURNET_DPI */
#endif /* DPI_ADAPT_H */

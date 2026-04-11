/*
 * cdn_updater.c — автообновление CDN IP диапазонов (C.4)
 */

#if CONFIG_EBURNET_DPI

#include "dpi/cdn_updater.h"
#include "dpi/dpi_filter.h"
#include "config.h"
#include "net_utils.h"
#include "4eburnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

/* Максимум CIDR от одного источника */
#define CDN_MAX_CIDRS_PER_SOURCE  2048
/* Максимум CIDR суммарно (CF IPv4 ~15 + IPv6 ~6 + Fastly ~40 = ~60, запас ×30) */
#define CDN_MAX_CIDRS_TOTAL       2048
/* Макс. размер скачанного файла (защита от unbounded read) */
#define CDN_MAX_DOWNLOAD_BYTES   (512 * 1024)

/* ── stamp ───────────────────────────────────────────────────────── */

int cdn_stamp_write(const char *stamp_path)
{
    if (!stamp_path) return -1;
    FILE *f = fopen(stamp_path, "w");
    if (!f) {
        log_msg(LOG_WARN, "cdn_updater: не удалось записать stamp %s: %s",
                stamp_path, strerror(errno));
        return -1;
    }
    if (fprintf(f, "%ld\n", (long)time(NULL)) < 0) {
        log_msg(LOG_WARN, "cdn_stamp_write: ошибка записи %s: %s",
                stamp_path, strerror(errno));
        fclose(f);
        return -1;
    }
    if (fclose(f) != 0) {
        log_msg(LOG_WARN, "cdn_stamp_write: fclose %s: %s",
                stamp_path, strerror(errno));
        return -1;
    }
    return 0;
}

long cdn_stamp_read(const char *stamp_path)
{
    if (!stamp_path) return -1;
    FILE *f = fopen(stamp_path, "r");
    if (!f) return -1;
    long ts = -1;
    if (fscanf(f, "%ld", &ts) != 1)
        ts = -1;
    fclose(f);
    return ts;
}

int cdn_is_stale(const char *stamp_path, int interval_days)
{
    if (interval_days == 0) return -1;  /* обновление выключено */
    long ts = cdn_stamp_read(stamp_path);
    if (ts < 0) return 1;               /* нет файла или ошибка чтения = устарел */
    long age_sec = (long)time(NULL) - ts;
    return (age_sec > (long)interval_days * 86400) ? 1 : 0;
}

/* ── Парсинг текста (Cloudflare) ─────────────────────────────────── */

int cdn_parse_text(const char *text,
                   char cidrs[][64], int max_count, int cidr_size)
{
    if (!text || !cidrs || max_count <= 0 || cidr_size <= 0) return -1;
    int n = 0;
    const char *p = text;
    while (*p && n < max_count) {
        /* Пропустить пробелы в начале строки */
        while (*p == ' ' || *p == '\t') p++;
        /* Пропустить пустые строки и комментарии */
        if (*p == '\n' || *p == '\r' || *p == '#') {
            while (*p && *p != '\n') p++;
            if (*p == '\n') p++;
            continue;
        }
        if (*p == '\0') break;
        /* Скопировать токен до конца строки */
        const char *start = p;
        while (*p && *p != '\n' && *p != '\r') p++;
        int len = (int)(p - start);
        /* Убрать trailing пробелы */
        while (len > 0 && (start[len-1] == ' ' || start[len-1] == '\t'))
            len--;
        if (len > 0 && len < cidr_size) {
            memcpy(cidrs[n], start, (size_t)len);
            cidrs[n][len] = '\0';
            n++;
        }
        while (*p == '\n' || *p == '\r') p++;
    }
    return n;
}

/* ── Парсинг JSON Fastly ─────────────────────────────────────────── */

/*
 * Извлечь строки из JSON массива по ключу.
 * Ищет "key":[ и извлекает строки до закрывающей ].
 */
static int extract_json_array(const char *json, const char *key,
                               char cidrs[][64], int start,
                               int max_count, int cidr_size)
{
    /* Найти "key":[ */
    char search[96];
    snprintf(search, sizeof(search), "\"%s\":[", key);
    const char *arr = strstr(json, search);
    if (!arr) return 0;
    arr += strlen(search);

    int n = start;
    while (*arr && *arr != ']' && n < max_count) {
        /* Пропустить до следующей открывающей кавычки */
        while (*arr && *arr != '"' && *arr != ']') arr++;
        if (*arr != '"') break;
        arr++;  /* пропустить открывающую кавычку */

        const char *val_start = arr;
        while (*arr && *arr != '"') arr++;
        int len = (int)(arr - val_start);
        if (len > 0 && len < cidr_size) {
            memcpy(cidrs[n], val_start, (size_t)len);
            cidrs[n][len] = '\0';
            n++;
        }
        if (*arr == '"') arr++;  /* пропустить закрывающую кавычку */
    }
    return n - start;
}

int cdn_parse_fastly_json(const char *json,
                           char cidrs[][64], int max_count, int cidr_size)
{
    if (!json || !cidrs || max_count <= 0 || cidr_size <= 0) return -1;
    int n = 0;
    n += extract_json_array(json, "addresses",
                             cidrs, n, max_count, cidr_size);
    n += extract_json_array(json, "ipv6_addresses",
                             cidrs, n, max_count, cidr_size);
    return n;
}

/* ── Дедупликация и атомарная запись ─────────────────────────────── */

static int cmp_cidr_str(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

int cdn_merge_write(char cidrs[][64], int count, const char *out_path)
{
    if (!cidrs || count <= 0 || !out_path) return -1;

    /* Сортировка для дедупликации */
    qsort(cidrs, (size_t)count, 64, cmp_cidr_str);

    /* Временный файл рядом с целевым */
    char tmp_path[544];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", out_path);

    FILE *f = fopen(tmp_path, "w");
    if (!f) {
        log_msg(LOG_WARN, "cdn_merge_write: не удалось открыть %s: %s",
                tmp_path, strerror(errno));
        return -1;
    }

    fprintf(f, "# 4eburNet CDN ipset — обновлено %ld\n", (long)time(NULL));

    int written = 0;
    for (int i = 0; i < count; i++) {
        /* Пропустить дубли */
        if (i > 0 && strcmp(cidrs[i], cidrs[i-1]) == 0) continue;
        /* Пропустить пустые строки */
        if (cidrs[i][0] == '\0') continue;
        fprintf(f, "%s\n", cidrs[i]);
        written++;
    }
    fclose(f);

    /* Атомарная замена через rename */
    if (rename(tmp_path, out_path) < 0) {
        log_msg(LOG_WARN, "cdn_merge_write: rename %s → %s: %s",
                tmp_path, out_path, strerror(errno));
        unlink(tmp_path);
        return -1;
    }

    log_msg(LOG_INFO, "cdn_updater: записано %d уникальных CIDR в %s",
            written, out_path);
    return 0;
}

/* ── Скачать и распарсить источник ───────────────────────────────── */

static int fetch_and_parse(const char *url, const char *tmp_file,
                            char cidrs[][64], int max, int cidr_size,
                            int is_json)
{
    if (net_http_fetch(url, tmp_file) < 0) {
        log_msg(LOG_WARN, "cdn_updater: не удалось скачать %s", url);
        return 0;  /* не критично — продолжаем без этого источника */
    }

    FILE *f = fopen(tmp_file, "r");
    if (!f) { unlink(tmp_file); return 0; }

    char *buf = malloc(CDN_MAX_DOWNLOAD_BYTES);
    if (!buf) { fclose(f); unlink(tmp_file); return 0; }

    size_t total = fread(buf, 1, CDN_MAX_DOWNLOAD_BYTES - 1, f);
    buf[total] = '\0';
    fclose(f);
    unlink(tmp_file);

    int n = is_json
            ? cdn_parse_fastly_json(buf, cidrs, max, cidr_size)
            : cdn_parse_text(buf, cidrs, max, cidr_size);
    free(buf);

    return (n > 0) ? n : 0;
}

/* ── Публичный API ───────────────────────────────────────────────── */

int cdn_updater_update(const struct EburNetConfig *cfg)
{
    if (!cfg) return -1;

    const char *dpi_dir = cfg->dpi_dir[0] ? cfg->dpi_dir
                                           : "/etc/4eburnet/dpi";

    /* URL-ы: из конфига или встроенные defaults */
    const char *cf_v4_url = cfg->cdn_cf_v4_url[0]
                            ? cfg->cdn_cf_v4_url
                            : "https://www.cloudflare.com/ips-v4";
    const char *cf_v6_url = cfg->cdn_cf_v6_url[0]
                            ? cfg->cdn_cf_v6_url
                            : "https://www.cloudflare.com/ips-v6";
    const char *fastly_url = cfg->cdn_fastly_url[0]
                             ? cfg->cdn_fastly_url
                             : "https://api.fastly.com/public-ip-list";

    log_msg(LOG_INFO, "cdn_updater: начинаю обновление CDN IP...");

    char (*all)[64] = calloc(CDN_MAX_CIDRS_TOTAL, 64);
    if (!all) {
        log_msg(LOG_ERROR, "cdn_updater: нет памяти");
        return -1;
    }

    int total = 0;
    int n;

    /* Cloudflare IPv4 */
    n = fetch_and_parse(cf_v4_url, "/tmp/cdn_cf_v4.txt",
                        all + total, CDN_MAX_CIDRS_TOTAL - total, 64, 0);
    log_msg(LOG_INFO, "cdn_updater: Cloudflare IPv4: %d CIDR", n);
    total += n;

    /* Cloudflare IPv6 */
    n = fetch_and_parse(cf_v6_url, "/tmp/cdn_cf_v6.txt",
                        all + total, CDN_MAX_CIDRS_TOTAL - total, 64, 0);
    log_msg(LOG_INFO, "cdn_updater: Cloudflare IPv6: %d CIDR", n);
    total += n;

    /* Fastly */
    n = fetch_and_parse(fastly_url, "/tmp/cdn_fastly.json",
                        all + total, CDN_MAX_CIDRS_TOTAL - total, 64, 1);
    log_msg(LOG_INFO, "cdn_updater: Fastly: %d CIDR", n);
    total += n;

    if (total == 0) {
        log_msg(LOG_WARN, "cdn_updater: все источники вернули 0 CIDR, "
                "ipset.txt не обновляется");
        free(all);
        return -1;
    }

    /* Записать ipset.txt */
    char out_path[512];
    snprintf(out_path, sizeof(out_path), "%s/ipset.txt", dpi_dir);
    int rc = cdn_merge_write(all, total, out_path);
    free(all);

    if (rc < 0) return -1;

    /* Записать stamp */
    char stamp_path[512];
    snprintf(stamp_path, sizeof(stamp_path), "%s/ipset.stamp", dpi_dir);
    cdn_stamp_write(stamp_path);

    /* Горячая перезагрузка dpi_filter без рестарта демона */
    dpi_filter_init(dpi_dir);

    log_msg(LOG_INFO, "cdn_updater: обновление завершено (%d CIDR суммарно)",
            total);
    return 0;
}

int cdn_updater_check(const struct EburNetConfig *cfg)
{
    if (!cfg) return -1;
    if (cfg->cdn_update_interval_days == 0) return 0;  /* выключено */

    const char *dpi_dir = cfg->dpi_dir[0] ? cfg->dpi_dir
                                           : "/etc/4eburnet/dpi";
    char stamp_path[512];
    snprintf(stamp_path, sizeof(stamp_path), "%s/ipset.stamp", dpi_dir);

    int stale = cdn_is_stale(stamp_path, cfg->cdn_update_interval_days);
    if (stale <= 0) return 0;  /* актуально или выключено */

    return (cdn_updater_update(cfg) == 0) ? 1 : -1;
}

#endif /* CONFIG_EBURNET_DPI */

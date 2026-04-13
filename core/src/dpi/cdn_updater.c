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
#include <fcntl.h>
#include <sys/wait.h>

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
        log_msg(LOG_WARN, "cdn_stamp_write: не удалось открыть %s: %s",
                stamp_path, strerror(errno));
        return -1;
    }
    if (fprintf(f, "%ld\n", (long)time(NULL)) < 0) {
        log_msg(LOG_WARN, "cdn_stamp_write: ошибка записи %s: %s",
                stamp_path, strerror(errno));
        fclose(f);
        unlink(stamp_path);  /* удалить частично записанный файл */
        return -1;
    }
    if (fclose(f) != 0) {
        log_msg(LOG_WARN, "cdn_stamp_write: fclose %s: %s",
                stamp_path, strerror(errno));
        unlink(stamp_path);
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
    if (interval_days <= 0) return -1;  /* обновление выключено */
    long ts = cdn_stamp_read(stamp_path);
    if (ts < 0) return 1;               /* нет файла или ошибка чтения = устарел */

    long now = (long)time(NULL);

    /* Timestamp из будущего (NTP не синхронизирован при записи):
     * сравниваем до вычитания — иначе знаковое переполнение UB */
    if (ts > now) {
        log_msg(LOG_WARN,
                "cdn_is_stale: stamp timestamp (%ld) в будущем "
                "(сейчас %ld), считаем устаревшим", ts, now);
        return 1;
    }

    long age_sec = now - ts;
    return (age_sec > (long)interval_days * 86400) ? 1 : 0;
}

/* ── Парсинг текста (Cloudflare) ─────────────────────────────────── */

int cdn_parse_text(const char *text,
                   char cidrs[][CDN_CIDR_SIZE], int max_count)
{
    if (!text || !cidrs || max_count <= 0) return -1;
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
        if (len > 0 && len < CDN_CIDR_SIZE) {
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
 * Строки с невалидными символами (не [0-9a-fA-F:.\/]) отбрасываются.
 */
static int extract_json_array(const char *json, const char *key,
                               char cidrs[][CDN_CIDR_SIZE], int start,
                               int max_count)
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
        if (len > 0 && len < CDN_CIDR_SIZE) {
            memcpy(cidrs[n], val_start, (size_t)len);
            cidrs[n][len] = '\0';
            /* Базовая валидация: CIDR содержит только [0-9a-fA-F:.\/] */
            int valid = 1;
            for (int ci = 0; ci < len && valid; ci++) {
                char c = cidrs[n][ci];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                      (c >= 'A' && c <= 'F') || c == ':' || c == '.' || c == '/'))
                    valid = 0;
            }
            if (valid) n++;
        }
        if (*arr == '"') arr++;  /* пропустить закрывающую кавычку */
    }
    return n - start;
}

int cdn_parse_fastly_json(const char *json,
                           char cidrs[][CDN_CIDR_SIZE], int max_count)
{
    if (!json || !cidrs || max_count <= 0) return -1;
    int n = 0;
    n += extract_json_array(json, "addresses",
                             cidrs, n, max_count);
    n += extract_json_array(json, "ipv6_addresses",
                             cidrs, n, max_count);
    return n;
}

/* ── Дедупликация и атомарная запись ─────────────────────────────── */

static int cmp_cidr_str(const void *a, const void *b)
{
    /* Корректное приведение для char[64]: избегаем UB strict aliasing */
    return strcmp(*(const char (*)[64])a, *(const char (*)[64])b);
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

    int write_err = 0;
    if (fprintf(f, "# 4eburNet CDN ipset — обновлено %ld\n",
                (long)time(NULL)) < 0)
        write_err = 1;

    int written = 0;
    for (int i = 0; i < count && !write_err; i++) {
        /* Пропустить дубли */
        if (i > 0 && strcmp(cidrs[i], cidrs[i-1]) == 0) continue;
        /* Пропустить пустые строки */
        if (cidrs[i][0] == '\0') continue;
        if (fprintf(f, "%s\n", cidrs[i]) < 0) {
            write_err = 1;
            break;
        }
        written++;
    }

    if (!write_err && ferror(f)) write_err = 1;
    if (fclose(f) != 0)         write_err = 1;

    if (write_err) {
        log_msg(LOG_WARN, "cdn_merge_write: ошибка записи %s: %s",
                tmp_path, strerror(errno));
        unlink(tmp_path);
        return -1;
    }

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
                            char cidrs[][CDN_CIDR_SIZE], int max,
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
    if (ferror(f)) {
        log_msg(LOG_WARN, "cdn_updater: ошибка чтения %s: %s",
                tmp_file, strerror(errno));
        fclose(f);
        free(buf);
        unlink(tmp_file);
        return 0;
    }
    buf[total] = '\0';
    fclose(f);
    unlink(tmp_file);

    int n = is_json
            ? cdn_parse_fastly_json(buf, cidrs, max)
            : cdn_parse_text(buf, cidrs, max);
    free(buf);

    return (n > 0) ? n : 0;
}

/* ── Публичный API ───────────────────────────────────────────────── */

/*
 * Внутренняя реализация обновления CDN IP.
 * reload_filter=true → вызвать dpi_filter_init() после записи.
 * reload_filter=false → только скачать + записать (для fork child).
 */
static int cdn_do_update(const struct EburNetConfig *cfg, bool reload_filter)
{
    if (!cfg) return -1;

    const char *dpi_dir = cfg->dpi_dir[0] ? cfg->dpi_dir
                                           : EBURNET_DPI_DIR;

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

    /* S-05: mkstemp вместо PID-based — защита от symlink-атак */
    char tmp_v4[]  = "/tmp/cdn_cf_v4_XXXXXX";
    char tmp_v6[]  = "/tmp/cdn_cf_v6_XXXXXX";
    char tmp_fst[] = "/tmp/cdn_fastly_XXXXXX";
    int fd_v4  = mkstemp(tmp_v4);
    int fd_v6  = mkstemp(tmp_v6);
    int fd_fst = mkstemp(tmp_fst);
    if (fd_v4 < 0 || fd_v6 < 0 || fd_fst < 0) {
        log_msg(LOG_ERROR, "cdn_updater: mkstemp провалился");
        if (fd_v4  >= 0) { close(fd_v4);  unlink(tmp_v4); }
        if (fd_v6  >= 0) { close(fd_v6);  unlink(tmp_v6); }
        if (fd_fst >= 0) { close(fd_fst); unlink(tmp_fst); }
        return -1;
    }
    /* Закрыть fd — файлы будут заполнены http fetch */
    close(fd_v4); close(fd_v6); close(fd_fst);

    log_msg(LOG_INFO, "cdn_updater: начинаю обновление CDN IP...");

    char (*all)[64] = calloc(CDN_MAX_CIDRS_TOTAL, 64);
    if (!all) {
        log_msg(LOG_ERROR, "cdn_updater: нет памяти");
        return -1;
    }

    int total = 0;
    int n;

    /* Cloudflare IPv4 */
    n = fetch_and_parse(cf_v4_url, tmp_v4,
                        all + total, CDN_MAX_CIDRS_TOTAL - total, 0);
    log_msg(LOG_INFO, "cdn_updater: Cloudflare IPv4: %d CIDR", n);
    total += n;

    /* Cloudflare IPv6 */
    n = fetch_and_parse(cf_v6_url, tmp_v6,
                        all + total, CDN_MAX_CIDRS_TOTAL - total, 0);
    log_msg(LOG_INFO, "cdn_updater: Cloudflare IPv6: %d CIDR", n);
    total += n;

    /* Fastly */
    n = fetch_and_parse(fastly_url, tmp_fst,
                        all + total, CDN_MAX_CIDRS_TOTAL - total, 1);
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
    if (cdn_stamp_write(stamp_path) < 0) {
        log_msg(LOG_WARN,
                "cdn_updater: не удалось записать stamp %s, "
                "следующий старт повторит обновление", stamp_path);
    }

    /* Горячая перезагрузка dpi_filter (только в родительском процессе) */
    if (reload_filter)
        dpi_filter_init(dpi_dir);

    log_msg(LOG_INFO, "cdn_updater: обновление завершено (%d CIDR суммарно)",
            total);
    return 0;
}

int cdn_updater_update(const struct EburNetConfig *cfg)
{
    return cdn_do_update(cfg, true);
}

int cdn_updater_update_async(const struct EburNetConfig *cfg)
{
    if (!cfg) return -1;

    int fds[2];
    if (pipe2(fds, O_CLOEXEC) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]); close(fds[1]); return -1;
    }
    if (pid == 0) {
        /* Дочерний процесс: скачать + записать (без dpi_filter_init) */
        close(fds[0]);
        fcntl(fds[1], F_SETFD, 0);
        int rc = cdn_do_update(cfg, false);
        const char *msg = (rc == 0) ? "OK\n" : "ERR\n";
        (void)write(fds[1], msg, strlen(msg));
        close(fds[1]);
        _exit(0);
    }
    /* Родитель: закрыть write-end, вернуть read-end nonblocking */
    close(fds[1]);
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    return fds[0];
}

int cdn_updater_check(const struct EburNetConfig *cfg)
{
    if (!cfg) return -1;

    if (cfg->cdn_update_interval_days <= 0) {
        /* Проверить что ipset.txt существует, иначе предупредить */
        const char *ddir = cfg->dpi_dir[0] ? cfg->dpi_dir
                                            : EBURNET_DPI_DIR;
        char ipset_path[512];
        snprintf(ipset_path, sizeof(ipset_path), "%s/ipset.txt", ddir);
        if (access(ipset_path, F_OK) != 0)
            log_msg(LOG_WARN,
                    "cdn_updater: cdn_update_interval_days=0 и %s "
                    "не найден — DPI фильтрация IP отключена", ipset_path);
        return 0;
    }

    const char *dpi_dir = cfg->dpi_dir[0] ? cfg->dpi_dir
                                           : EBURNET_DPI_DIR;
    char stamp_path[512];
    snprintf(stamp_path, sizeof(stamp_path), "%s/ipset.stamp", dpi_dir);

    int stale = cdn_is_stale(stamp_path, cfg->cdn_update_interval_days);
    if (stale <= 0) return 0;  /* stale=0: актуально */

    return (cdn_updater_update(cfg) == 0) ? 1 : -1;
}

#endif /* CONFIG_EBURNET_DPI */

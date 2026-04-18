/*
 * geo_compile.c — компилятор geo списков .lst → бинарный формат .gbin
 * Использование: geo_compile <input.lst> <output.gbin> <region> <cat_type>
 *   region:   0=UNKNOWN 1=RU 2=CN 3=US 99=OTHER
 *   cat_type: 0=GENERIC 1=ADS 2=TRACKERS 3=THREATS
 *
 * Standalone: только libc + arpa/inet.h, никаких зависимостей от демона.
 * Собирается для хоста и кросс-компилируется для mipsel/aarch64.
 * При компиляции с -DGEO_COMPILE_LIB функция main() не включается.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "geo/geo_types.h"
#include "geo_compile.h"

/* Максимальная длина строки во входном файле */
#define MAX_LINE      256
/* Защита от чрезмерного string pool (32 MB) */
#define MAX_POOL_SIZE (32u * 1024u * 1024u)
/* Минимум записей — защита от пустых или битых файлов */
#define MIN_ENTRIES   100

/* ── Вспомогательные компараторы ── */

static int cmp_str_ptr(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int cmp_cidr4_compile(const void *a, const void *b)
{
    uint32_t na = ((const geo_cidr4_t *)a)->net;
    uint32_t nb = ((const geo_cidr4_t *)b)->net;
    return (na > nb) - (na < nb);
}

/* ── Парсеры CIDR ── */

static int parse_cidr4_c(const char *line, geo_cidr4_t *out)
{
    char buf[MAX_LINE];
    snprintf(buf, sizeof(buf), "%s", line);
    char *slash = strchr(buf, '/');
    int prefix = 32;
    if (slash) {
        *slash = '\0';
        char *ep;
        long pv = strtol(slash + 1, &ep, 10);
        if (ep == slash + 1 || *ep != '\0' || pv < 0 || pv > 32) return 0;
        prefix = (int)pv;
    }
    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return 0;
    out->net  = ntohl(addr.s_addr);
    out->mask = (prefix == 0) ? 0u : (~0u << (32 - prefix));
    out->net &= out->mask;
    return 1;
}

static int parse_cidr6_c(const char *line, geo_cidr6_t *out)
{
    char buf[MAX_LINE];
    snprintf(buf, sizeof(buf), "%s", line);
    char *slash = strchr(buf, '/');
    int prefix = 128;
    if (slash) {
        *slash = '\0';
        char *ep;
        long pv = strtol(slash + 1, &ep, 10);
        if (ep == slash + 1 || *ep != '\0' || pv < 0 || pv > 128) return 0;
        prefix = (int)pv;
    }
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, buf, &addr6) != 1) return 0;
    memcpy(out->net, &addr6, 16);
    out->prefix = (uint8_t)prefix;
    return 1;
}

/* ── Обрезать trailing пробелы и переносы ── */

static size_t trim_line(char *line)
{
    size_t len = strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' ||
                       line[len-1] == ' '))
        line[--len] = '\0';
    return len;
}

/* ── Основная функция компиляции ── */

int geo_compile_file(const char *in_path, const char *out_path,
                     uint32_t region, uint32_t cat_type)
{
    /* ── Проход 1: подсчёт ── */
    FILE *f = fopen(in_path, "r");
    if (!f) {
        fprintf(stderr, "geo_compile: не удалось открыть %s: %s\n",
                in_path, strerror(errno));
        return 1;
    }

    char line[MAX_LINE];
    uint32_t n_dom = 0, n_sfx = 0, n_v4 = 0, n_v6 = 0;
    size_t   pool_sz = 0;

    while (fgets(line, sizeof(line), f)) {
        size_t len = trim_line(line);
        if (len == 0 || line[0] == '#') continue;
        if (len > 253) {
            fprintf(stderr, "geo_compile: WARN: пропущена длинная строка (%zu байт)\n", len);
            continue;
        }
        if (strchr(line, ':'))       n_v6++;
        else if (strchr(line, '/'))  n_v4++;
        else if (line[0] == '.') { n_sfx++; pool_sz += len;      } /* len-1+'\0' = len */
        else                       { n_dom++; pool_sz += len + 1; } /* строка + '\0' */
    }
    rewind(f);

    uint32_t total = n_dom + n_sfx + n_v4 + n_v6;
    if (total < MIN_ENTRIES) {
        fprintf(stderr, "geo_compile: слишком мало записей: %u (мин. %d)\n",
                total, MIN_ENTRIES);
        fclose(f);
        return 1;
    }
    if (pool_sz > MAX_POOL_SIZE) {
        fprintf(stderr, "geo_compile: string pool слишком большой: %zu\n", pool_sz);
        fclose(f);
        return 1;
    }

    /* ── Выделить временные массивы ── */
    char       **domain_strs    = n_dom > 0 ? malloc((size_t)n_dom * sizeof(char *))    : NULL;
    char       **suffix_strs    = n_sfx > 0 ? malloc((size_t)n_sfx * sizeof(char *))    : NULL;
    geo_cidr4_t *v4             = n_v4 > 0  ? malloc((size_t)n_v4  * sizeof(geo_cidr4_t)) : NULL;
    geo_cidr6_t *v6             = n_v6 > 0  ? malloc((size_t)n_v6  * sizeof(geo_cidr6_t)) : NULL;
    uint32_t    *domain_offsets = n_dom > 0 ? malloc((size_t)n_dom * sizeof(uint32_t))  : NULL;
    uint32_t    *suffix_offsets = n_sfx > 0 ? malloc((size_t)n_sfx * sizeof(uint32_t))  : NULL;
    char        *pool           = pool_sz > 0 ? malloc(pool_sz)                          : NULL;

    int oom = (n_dom > 0 && (!domain_strs || !domain_offsets)) ||
              (n_sfx > 0 && (!suffix_strs || !suffix_offsets)) ||
              (n_v4  > 0 && !v4) || (n_v6 > 0 && !v6) ||
              (pool_sz > 0 && !pool);
    if (oom) {
        fprintf(stderr, "geo_compile: OOM\n");
        fclose(f);
        free(domain_strs); free(suffix_strs); free(v4); free(v6);
        free(domain_offsets); free(suffix_offsets); free(pool);
        return 1;
    }

    /* ── Проход 2: заполнение ── */
    uint32_t di = 0, si = 0, vi4 = 0, vi6 = 0;
    int oom2 = 0;

    while (fgets(line, sizeof(line), f)) {
        size_t len = trim_line(line);
        if (len == 0 || line[0] == '#' || len > 253) continue;

        if (strchr(line, ':')) {
            if (vi6 < n_v6 && parse_cidr6_c(line, &v6[vi6])) vi6++;
        } else if (strchr(line, '/')) {
            if (vi4 < n_v4 && parse_cidr4_c(line, &v4[vi4])) vi4++;
        } else if (line[0] == '.') {
            if (si < n_sfx) {
                char *dup = strdup(line + 1);
                if (!dup) { oom2 = 1; break; }
                suffix_strs[si++] = dup;
            }
        } else {
            if (di < n_dom) {
                char *dup = strdup(line);
                if (!dup) { oom2 = 1; break; }
                domain_strs[di++] = dup;
            }
        }
    }
    fclose(f);

    if (oom2) {
        fprintf(stderr, "geo_compile: OOM при strdup\n");
        for (uint32_t i = 0; i < di; i++) free(domain_strs[i]);
        for (uint32_t i = 0; i < si; i++) free(suffix_strs[i]);
        free(domain_strs); free(suffix_strs); free(v4); free(v6);
        free(domain_offsets); free(suffix_offsets); free(pool);
        return 1;
    }

    /* Скорректировать реальные счётчики (parse errors могли уменьшить) */
    n_dom = di; n_sfx = si; n_v4 = vi4; n_v6 = vi6;

    /* ── Сортировка ── */
    if (n_dom > 1) qsort(domain_strs, n_dom, sizeof(char *), cmp_str_ptr);
    if (n_sfx > 1) qsort(suffix_strs, n_sfx, sizeof(char *), cmp_str_ptr);
    if (n_v4  > 1) qsort(v4,          n_v4,  sizeof(geo_cidr4_t), cmp_cidr4_compile);

    /* ── Построить string pool + offsets ── */
    size_t pos = 0;
    for (uint32_t i = 0; i < n_dom; i++) {
        domain_offsets[i] = (uint32_t)pos;
        size_t slen = strlen(domain_strs[i]) + 1;
        memcpy(pool + pos, domain_strs[i], slen);
        pos += slen;
    }
    for (uint32_t i = 0; i < n_sfx; i++) {
        suffix_offsets[i] = (uint32_t)pos;
        size_t slen = strlen(suffix_strs[i]) + 1;
        memcpy(pool + pos, suffix_strs[i], slen);
        pos += slen;
    }
    uint32_t actual_pool = (uint32_t)pos;

    /* ── Заполнить заголовок ── */
    geo_bin_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, GEO_BIN_MAGIC, 4);
    hdr.version          = GEO_BIN_VERSION;
    hdr.region           = region;
    hdr.cat_type         = cat_type;
    hdr.domain_count     = n_dom;
    hdr.suffix_count     = n_sfx;
    hdr.v4_count         = n_v4;
    hdr.v6_count         = n_v6;
    hdr.string_pool_size = actual_pool;

    /* ── Атомарная запись: tmp → rename ── */
    size_t out_len = strlen(out_path);
    char  *tmp_path = malloc(out_len + 5);
    if (!tmp_path) {
        fprintf(stderr, "geo_compile: OOM tmp_path\n");
        for (uint32_t i = 0; i < n_dom; i++) free(domain_strs[i]);
        for (uint32_t i = 0; i < n_sfx; i++) free(suffix_strs[i]);
        free(domain_strs); free(suffix_strs); free(v4); free(v6);
        free(domain_offsets); free(suffix_offsets); free(pool);
        return 1;
    }
    snprintf(tmp_path, out_len + 5, "%s.tmp", out_path);

    FILE *out = fopen(tmp_path, "wb");
    if (!out) {
        fprintf(stderr, "geo_compile: не удалось открыть %s: %s\n",
                tmp_path, strerror(errno));
        free(tmp_path);
        for (uint32_t i = 0; i < n_dom; i++) free(domain_strs[i]);
        for (uint32_t i = 0; i < n_sfx; i++) free(suffix_strs[i]);
        free(domain_strs); free(suffix_strs); free(v4); free(v6);
        free(domain_offsets); free(suffix_offsets); free(pool);
        return 1;
    }

    int ok = 1;
    ok &= (fwrite(&hdr, sizeof(hdr), 1, out) == 1);
    if (n_dom > 0) ok &= (fwrite(domain_offsets, sizeof(uint32_t), n_dom, out) == n_dom);
    if (n_sfx > 0) ok &= (fwrite(suffix_offsets, sizeof(uint32_t), n_sfx, out) == n_sfx);
    if (n_v4  > 0) ok &= (fwrite(v4,  sizeof(geo_cidr4_t), n_v4, out) == n_v4);
    if (n_v6  > 0) ok &= (fwrite(v6,  sizeof(geo_cidr6_t), n_v6, out) == n_v6);
    if (actual_pool > 0)
        ok &= (fwrite(pool, 1, actual_pool, out) == (size_t)actual_pool);
    fclose(out);

    if (!ok) {
        fprintf(stderr, "geo_compile: ошибка записи в %s\n", tmp_path);
        unlink(tmp_path);
        free(tmp_path);
        for (uint32_t i = 0; i < n_dom; i++) free(domain_strs[i]);
        for (uint32_t i = 0; i < n_sfx; i++) free(suffix_strs[i]);
        free(domain_strs); free(suffix_strs); free(v4); free(v6);
        free(domain_offsets); free(suffix_offsets); free(pool);
        return 1;
    }

    if (rename(tmp_path, out_path) != 0) {
        fprintf(stderr, "geo_compile: rename %s → %s: %s\n",
                tmp_path, out_path, strerror(errno));
        unlink(tmp_path);
        free(tmp_path);
        for (uint32_t i = 0; i < n_dom; i++) free(domain_strs[i]);
        for (uint32_t i = 0; i < n_sfx; i++) free(suffix_strs[i]);
        free(domain_strs); free(suffix_strs); free(v4); free(v6);
        free(domain_offsets); free(suffix_offsets); free(pool);
        return 1;
    }
    free(tmp_path);

    /* ── Освобождение временных данных ── */
    for (uint32_t i = 0; i < n_dom; i++) free(domain_strs[i]);
    for (uint32_t i = 0; i < n_sfx; i++) free(suffix_strs[i]);
    free(domain_strs); free(suffix_strs);
    free(domain_offsets); free(suffix_offsets);
    free(v4); free(v6); free(pool);

    size_t total_sz = sizeof(hdr)
                      + (size_t)n_dom * sizeof(uint32_t)
                      + (size_t)n_sfx * sizeof(uint32_t)
                      + (size_t)n_v4  * sizeof(geo_cidr4_t)
                      + (size_t)n_v6  * sizeof(geo_cidr6_t)
                      + actual_pool;
    printf("geo_compile: %s → %s\n", in_path, out_path);
    printf("  домены: %u, суффиксы: %u, IPv4: %u, IPv6: %u\n",
           n_dom, n_sfx, n_v4, n_v6);
    printf("  string pool: %u Б, итого: %zu Б\n", actual_pool, total_sz);
    return 0;
}

/* ── Точка входа (не компилируется при -DGEO_COMPILE_LIB) ── */

#ifndef GEO_COMPILE_LIB
int main(int argc, char *argv[])
{
    if (argc != 5) {
        fprintf(stderr,
            "Использование: %s <input.lst> <output.gbin> <region> <cat_type>\n"
            "  region:   0=UNKNOWN 1=RU 2=CN 3=US 99=OTHER\n"
            "  cat_type: 0=GENERIC 1=ADS 2=TRACKERS 3=THREATS\n",
            argv[0]);
        return 1;
    }
    char *end3, *end4;
    long region_l   = strtol(argv[3], &end3, 10);
    long cat_type_l = strtol(argv[4], &end4, 10);
    if (*end3 || region_l < 0 || region_l > 99) {
        fprintf(stderr, "geo_compile: неверный region '%s' (0-99)\n", argv[3]);
        return 1;
    }
    if (*end4 || cat_type_l < 0 || cat_type_l > 3) {
        fprintf(stderr, "geo_compile: неверный cat_type '%s' (0-3)\n", argv[4]);
        return 1;
    }
    return geo_compile_file(argv[1], argv[2],
                            (uint32_t)region_l, (uint32_t)cat_type_l);
}
#endif /* GEO_COMPILE_LIB */

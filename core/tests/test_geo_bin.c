/*
 * test_geo_bin.c — тест бинарного формата .gbin vs .lst
 * Сравнивает результаты geo_match_domain_cat() для heap и mmap режимов.
 * Запуск: /tmp/test_geo_bin  (создаёт временные файлы в /tmp)
 */

#include "geo/geo_loader.h"
#include "geo_compile.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fail_count = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fail_count++; } \
    else         { printf("PASS: %s\n", msg); } \
} while (0)

#define LST_PATH  "/tmp/test_geo_bin_ads.lst"
#define GBIN_PATH "/tmp/test_geo_bin_ads.gbin"

/* Создать тестовый .lst с >= MIN_ENTRIES записей */
static int write_test_lst(const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    /* Известные домены из test_ads.lst */
    fprintf(f, "doubleclick.net\n");
    fprintf(f, "googlesyndication.com\n");
    fprintf(f, ".adnxs.com\n");           /* суффикс — без точки в pool */
    /* Дополнительные домены для MIN_ENTRIES=100 */
    for (int i = 0; i < 200; i++)
        fprintf(f, "ad-%d.testonly.invalid\n", i);
    fclose(f);
    return 0;
}

/* Создать простой geo_manager с одной категорией ADS */
static geo_manager_t make_manager_from_lst(void)
{
    geo_manager_t gm;
    memset(&gm, 0, sizeof(gm));
    gm.categories = calloc(4, sizeof(geo_category_t));
    gm.capacity   = 4;
    /* Загрузить через .lst (гарантированно heap режим — gbin удалён) */
    geo_load_category(&gm, "test_ads", GEO_REGION_UNKNOWN, LST_PATH);
    /* Вручную выставить cat_type — geo_load_category ставит по имени "test_ads" */
    if (gm.count > 0) gm.categories[0].cat_type = GEO_CAT_ADS;
    return gm;
}

static geo_manager_t make_manager_from_gbin(void)
{
    geo_manager_t gm;
    memset(&gm, 0, sizeof(gm));
    gm.categories = calloc(4, sizeof(geo_category_t));
    gm.capacity   = 4;
    /* Загрузить через .lst — geo_load_category() сам найдёт .gbin */
    geo_load_category(&gm, "test_ads", GEO_REGION_UNKNOWN, LST_PATH);
    if (gm.count > 0) gm.categories[0].cat_type = GEO_CAT_ADS;
    return gm;
}

int main(void)
{
    printf("=== test_geo_bin ===\n\n");

    /* ── Создать тестовый .lst ── */
    ASSERT(write_test_lst(LST_PATH) == 0, "write_test_lst: создан");

    /* ── Скомпилировать в .gbin ── */
    int rc = geo_compile_file(LST_PATH, GBIN_PATH, 0, 1);
    ASSERT(rc == 0, "geo_compile_file: rc == 0");

    /* Проверить что .gbin создан и не пустой */
    FILE *gf = fopen(GBIN_PATH, "rb");
    ASSERT(gf != NULL, "gbin: файл создан");
    if (gf) {
        fseek(gf, 0, SEEK_END);
        long gsz = ftell(gf);
        fclose(gf);
        ASSERT(gsz > (long)sizeof(geo_bin_header_t), "gbin: размер > header");
        printf("  .gbin размер: %ld байт\n", gsz);
    }

    /* ── Загрузить в mmap режиме (.gbin существует) ── */
    geo_manager_t gm_bin = make_manager_from_gbin();
    ASSERT(gm_bin.count == 1, "bin: 1 категория загружена");
    if (gm_bin.count > 0) {
        ASSERT(gm_bin.categories[0].mmap_addr != NULL, "bin: mmap_addr != NULL");
        ASSERT(gm_bin.categories[0].loaded,             "bin: loaded=true");
        printf("  bin: %d домен, %d суффикс\n",
               gm_bin.categories[0].domain_count,
               gm_bin.categories[0].suffix_count);
    }

    /* ── Удалить .gbin и загрузить в heap режиме ── */
    unlink(GBIN_PATH);
    geo_manager_t gm_heap = make_manager_from_lst();
    ASSERT(gm_heap.count == 1, "heap: 1 категория загружена");
    if (gm_heap.count > 0) {
        ASSERT(gm_heap.categories[0].mmap_addr == NULL, "heap: mmap_addr == NULL");
        ASSERT(gm_heap.categories[0].loaded,             "heap: loaded=true");
        printf("  heap: %d домен, %d суффикс\n",
               gm_heap.categories[0].domain_count,
               gm_heap.categories[0].suffix_count);
    }

    /* ── Сравнить количества ── */
    if (gm_bin.count > 0 && gm_heap.count > 0) {
        ASSERT(gm_bin.categories[0].domain_count ==
               gm_heap.categories[0].domain_count,
               "bin vs heap: domain_count совпадает");
        ASSERT(gm_bin.categories[0].suffix_count ==
               gm_heap.categories[0].suffix_count,
               "bin vs heap: suffix_count совпадает");
    }

    /* ── Сравнить результаты lookup ── */

    /* Точные домены из test_ads.lst */
    const char *block_exact[] = { "doubleclick.net", "googlesyndication.com", NULL };
    for (int i = 0; block_exact[i]; i++) {
        geo_cat_type_t r_bin  = geo_match_domain_cat(&gm_bin,  block_exact[i]);
        geo_cat_type_t r_heap = geo_match_domain_cat(&gm_heap, block_exact[i]);
        char msg[128];
        snprintf(msg, sizeof(msg), "bin:  %s → ADS", block_exact[i]);
        ASSERT(r_bin  == GEO_CAT_ADS, msg);
        snprintf(msg, sizeof(msg), "heap: %s → ADS", block_exact[i]);
        ASSERT(r_heap == GEO_CAT_ADS, msg);
        snprintf(msg, sizeof(msg), "bin==heap: %s", block_exact[i]);
        ASSERT(r_bin == r_heap, msg);
    }

    /* Суффикс .adnxs.com */
    const char *block_sfx[] = { "sub.adnxs.com", "ads.adnxs.com", NULL };
    for (int i = 0; block_sfx[i]; i++) {
        geo_cat_type_t r_bin  = geo_match_domain_cat(&gm_bin,  block_sfx[i]);
        geo_cat_type_t r_heap = geo_match_domain_cat(&gm_heap, block_sfx[i]);
        char msg[128];
        snprintf(msg, sizeof(msg), "bin:  суффикс %s → ADS", block_sfx[i]);
        ASSERT(r_bin  == GEO_CAT_ADS, msg);
        snprintf(msg, sizeof(msg), "heap: суффикс %s → ADS", block_sfx[i]);
        ASSERT(r_heap == GEO_CAT_ADS, msg);
        snprintf(msg, sizeof(msg), "bin==heap: суффикс %s", block_sfx[i]);
        ASSERT(r_bin == r_heap, msg);
    }

    /* Незаблокированные домены */
    const char *clean[] = { "google.com", "example.org", "yandex.ru", NULL };
    for (int i = 0; clean[i]; i++) {
        geo_cat_type_t r_bin  = geo_match_domain_cat(&gm_bin,  clean[i]);
        geo_cat_type_t r_heap = geo_match_domain_cat(&gm_heap, clean[i]);
        char msg[128];
        snprintf(msg, sizeof(msg), "bin:  %s → GENERIC", clean[i]);
        ASSERT(r_bin  == GEO_CAT_GENERIC, msg);
        snprintf(msg, sizeof(msg), "heap: %s → GENERIC", clean[i]);
        ASSERT(r_heap == GEO_CAT_GENERIC, msg);
    }

    /* ── Сравнить динамически сгенерированные домены ── */
    int mismatch = 0;
    for (int i = 0; i < 200; i++) {
        char domain[64];
        snprintf(domain, sizeof(domain), "ad-%d.testonly.invalid", i);
        if (geo_match_domain_cat(&gm_bin,  domain) !=
            geo_match_domain_cat(&gm_heap, domain))
            mismatch++;
    }
    ASSERT(mismatch == 0, "bin==heap: 200 динамических доменов совпадают");

    /* ── Reload: пересоздать .gbin и перегрузить ── */
    rc = geo_compile_file(LST_PATH, GBIN_PATH, 0, 1);
    ASSERT(rc == 0, "geo_compile_file: reload rc == 0");
    rc = geo_load_category(&gm_bin, "test_ads", GEO_REGION_UNKNOWN, LST_PATH);
    ASSERT(rc == 0, "geo_load_category: reload rc == 0");
    if (gm_bin.count > 0)
        ASSERT(gm_bin.categories[0].mmap_addr != NULL, "reload: mmap режим");

    /* ── Cleanup ── */
    geo_manager_free(&gm_bin);
    geo_manager_free(&gm_heap);
    unlink(LST_PATH);
    unlink(GBIN_PATH);

    printf("\n%s: %d тест(ов) провалено\n",
           fail_count == 0 ? "ALL PASS" : "FAIL",
           fail_count);
    return fail_count > 0 ? 1 : 0;
}

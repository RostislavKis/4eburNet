/*
 * test_dns_geosite.c — интеграционный тест DNS_TYPE_GEOSITE (Вариант B, 3.5.1)
 * Загружает реальный тестовый .lst через geo_loader, регистрирует правило,
 * проверяет dns_rules_match для заблокированных и незаблокированных доменов.
 */

#include "dns/dns_rules.h"
#include "geo/geo_loader.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fail_count = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fail_count++; } \
    else { printf("PASS: %s\n", msg); } \
} while(0)

/* Путь к тестовому файлу — передаётся через аргумент или дефолт */
static const char *g_lst_path = "tests/data/test_ads.lst";

int main(int argc, char **argv)
{
    if (argc > 1)
        g_lst_path = argv[1];

    printf("=== test_dns_geosite ===\n");
    printf("lst: %s\n\n", g_lst_path);

    /* 1. Инициализировать geo_manager */
    geo_manager_t gm = {0};
    gm.capacity   = 4;
    gm.categories = calloc((size_t)gm.capacity, sizeof(geo_category_t));
    ASSERT(gm.categories != NULL, "geo_manager: alloc categories");
    if (!gm.categories) return 1;

    /* 2. Загрузить тестовый .lst файл под именем "test_ads" → cat_type=GEO_CAT_ADS */
    int rc = geo_load_category(&gm, "test_ads", GEO_REGION_OTHER, g_lst_path);
    ASSERT(rc == 0, "geo_load_category: test_ads.lst загружен");
    if (rc != 0) {
        printf("HINT: запускай из core/ — нужен правильный CWD\n");
        geo_manager_free(&gm);
        return 1;
    }
    ASSERT(gm.count == 1, "geo_manager: 1 категория");
    ASSERT(gm.categories[0].cat_type == GEO_CAT_ADS,
           "geo_manager: cat_type = GEO_CAT_ADS (по имени 'test_ads')");
    ASSERT(gm.categories[0].domain_count >= 2,
           "geo_manager: загружены точные домены");

    /* 3. Зарегистрировать geo_manager (dns_rules_init не нужен — нет правил) */
    dns_rules_set_geo_manager(&gm);
    dns_rules_add_geosite(GEO_CAT_ADS, DNS_ACTION_BLOCK);

    /* 4. Точный домен из списка → BLOCK */
    dns_action_t act = dns_rules_match("doubleclick.net");
    ASSERT(act == DNS_ACTION_BLOCK,
           "dns_rules_match('doubleclick.net') = BLOCK");

    act = dns_rules_match("googlesyndication.com");
    ASSERT(act == DNS_ACTION_BLOCK,
           "dns_rules_match('googlesyndication.com') = BLOCK");

    /* 5. Суффикс из списка: sub.adnxs.com → .adnxs.com суффикс → BLOCK */
    act = dns_rules_match("sub.adnxs.com");
    ASSERT(act == DNS_ACTION_BLOCK,
           "dns_rules_match('sub.adnxs.com') = BLOCK (через суффикс .adnxs.com)");

    /* 6. Домен не из списка → DEFAULT */
    act = dns_rules_match("google.com");
    ASSERT(act == DNS_ACTION_DEFAULT,
           "dns_rules_match('google.com') = DEFAULT");

    act = dns_rules_match("example.org");
    ASSERT(act == DNS_ACTION_DEFAULT,
           "dns_rules_match('example.org') = DEFAULT");

    /* 7. Отключить geo_manager — после free g_gm должен вернуть DEFAULT */
    dns_rules_free();
    geo_manager_free(&gm);

    printf("\nALL: %d тест(ов) провалено\n", fail_count);
    return fail_count ? 1 : 0;
}

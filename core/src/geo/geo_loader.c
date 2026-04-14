/*
 * geo_loader.c — гео-базы: регионы, CIDR-списки, домены
 * Этап 3.5: init/free, определение региона, load/reload, match ip/domain.
 */

#include "geo/geo_loader.h"
#include "config.h"
#include "4eburnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp */
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

/* Начальная ёмкость массива категорий */
#define GEO_CATEGORIES_INITIAL 8

/* ── Утилиты региона ────────────────────────────────────────────────────── */

const char *geo_region_name(geo_region_t r)
{
    switch (r) {
    case GEO_REGION_RU:    return "RU";
    case GEO_REGION_CN:    return "CN";
    case GEO_REGION_US:    return "US";
    case GEO_REGION_OTHER: return "OTHER";
    default:               return "UNKNOWN";
    }
}

geo_region_t geo_region_from_str(const char *s)
{
    if (!s) return GEO_REGION_UNKNOWN;
    if (strcasecmp(s, "ru") == 0)    return GEO_REGION_RU;
    if (strcasecmp(s, "cn") == 0)    return GEO_REGION_CN;
    if (strcasecmp(s, "us") == 0)    return GEO_REGION_US;
    if (strcasecmp(s, "other") == 0) return GEO_REGION_OTHER;
    return GEO_REGION_UNKNOWN;
}

/* ── Вспомогательные (static) ───────────────────────────────────────────── */

/* Найти категорию по имени */
static geo_category_t *find_category(geo_manager_t *gm, const char *name)
{
    for (int i = 0; i < gm->count; i++)
        if (strcmp(gm->categories[i].name, name) == 0)
            return &gm->categories[i];
    return NULL;
}

/* Расширить массив категорий */
static int grow_categories(geo_manager_t *gm)
{
    int new_cap = gm->capacity * 2;
    geo_category_t *tmp = realloc(gm->categories,
                                  (size_t)new_cap * sizeof(geo_category_t));
    if (!tmp) return -1;
    /* Обнулить новые слоты */
    memset(tmp + gm->capacity, 0,
           (size_t)(new_cap - gm->capacity) * sizeof(geo_category_t));
    gm->categories = tmp;
    gm->capacity = new_cap;
    return 0;
}

/* Освободить содержимое категории (не саму структуру) */
static void ptrie_free(ptrie_node_t *n);  /* forward decl */

static void free_category_data(geo_category_t *c)
{
    ptrie_free(c->trie_v4); c->trie_v4 = NULL;
    free(c->v4); c->v4 = NULL; c->v4_count = 0;
    free(c->v6); c->v6 = NULL; c->v6_count = 0;
    for (int i = 0; i < c->domain_count; i++) free(c->domains[i]);
    free(c->domains); c->domains = NULL; c->domain_count = 0;
    for (int i = 0; i < c->suffix_count; i++) free(c->suffixes[i]);
    free(c->suffixes); c->suffixes = NULL; c->suffix_count = 0;
    c->loaded = false;
}

/* ── Patricia trie для IPv4 CIDR ── */

static ptrie_node_t *ptrie_alloc(void)
{
    ptrie_node_t *n = calloc(1, sizeof(ptrie_node_t));
    if (n) n->region = GEO_REGION_UNKNOWN;
    return n;
}

static void ptrie_free(ptrie_node_t *n)
{
    if (!n) return;
    ptrie_free(n->child[0]);
    ptrie_free(n->child[1]);
    free(n);
}

/* Вставить CIDR в trie */
static int ptrie_insert(ptrie_node_t *root, uint32_t net,
                        uint32_t mask, geo_region_t region)
{
    /* Считаем prefix length из маски */
    int prefix = 0;
    uint32_t m = mask;
    while (m & 0x80000000u) { prefix++; m <<= 1; }

    ptrie_node_t *cur = root;
    for (int bit = 31; bit >= (32 - prefix); bit--) {
        int b = (net >> bit) & 1;
        if (!cur->child[b]) {
            cur->child[b] = ptrie_alloc();
            if (!cur->child[b]) return -1;
        }
        cur = cur->child[b];
    }
    cur->terminal = true;
    cur->region   = region;
    return 0;
}

/* Поиск IP в trie — возвращает наиболее специфичный match */
static geo_region_t ptrie_lookup(const ptrie_node_t *root, uint32_t ip)
{
    const ptrie_node_t *cur = root;
    geo_region_t best = GEO_REGION_UNKNOWN;
    for (int bit = 31; bit >= 0 && cur; bit--) {
        if (cur->terminal) best = cur->region;
        int b = (ip >> bit) & 1;
        cur = cur->child[b];
    }
    if (cur && cur->terminal) best = cur->region;
    return best;
}

/* Компаратор для qsort/bsearch по geo_cidr4_t::net */
static int cmp_cidr4(const void *a, const void *b)
{
    uint32_t na = ((const geo_cidr4_t *)a)->net;
    uint32_t nb = ((const geo_cidr4_t *)b)->net;
    return (na > nb) - (na < nb);
}

/* Компаратор для qsort/bsearch строк */
static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Парсинг "1.2.3.0/24" → geo_cidr4_t */
static bool parse_cidr4(const char *line, geo_cidr4_t *out)
{
    char buf[48];
    snprintf(buf, sizeof(buf), "%s", line);
    char *slash = strchr(buf, '/');
    int prefix = 32;
    if (slash) {
        *slash = '\0';
        char *endptr;
        long pval = strtol(slash + 1, &endptr, 10);
        if (endptr == slash + 1 || *endptr != '\0') return false;
        prefix = (int)pval;
    }
    if (prefix < 0 || prefix > 32) return false;

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return false;

    out->net  = ntohl(addr.s_addr);
    out->mask = prefix == 0 ? 0u : (~0u << (32 - prefix));
    out->net &= out->mask;   /* нормализация */
    return true;
}

/* Парсинг "2001:db8::/32" → geo_cidr6_t */
static bool parse_cidr6(const char *line, geo_cidr6_t *out)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", line);
    char *slash = strchr(buf, '/');
    int prefix = 128;
    if (slash) {
        *slash = '\0';
        char *endptr;
        long pval = strtol(slash + 1, &endptr, 10);
        if (endptr == slash + 1 || *endptr != '\0') return false;
        prefix = (int)pval;
    }
    if (prefix < 0 || prefix > 128) return false;

    struct in6_addr addr6;
    if (inet_pton(AF_INET6, buf, &addr6) != 1) return false;

    memcpy(out->net, &addr6, 16);
    out->prefix = (uint8_t)prefix;
    return true;
}

/* ── Определение региона ────────────────────────────────────────────────── */

geo_region_t device_detect_region(geo_manager_t *gm,
                                   const struct sockaddr_storage *device_addr)
{
    /* device_addr зарезервирован для будущего IP lookup */
    (void)device_addr;

    /* Шаг 1: явный конфиг пользователя */
    if (gm->cfg && gm->cfg->geo_region[0]) {
        geo_region_t r = geo_region_from_str(gm->cfg->geo_region);
        if (r != GEO_REGION_UNKNOWN) {
            log_msg(LOG_INFO, "Регион: %s (из конфига)", geo_region_name(r));
            return r;
        }
    }

    /* Шаг 2: timezone из /etc/config/system */
    FILE *f = fopen("/etc/config/system", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (!strstr(line, "zonename")) continue;
            /* Значение между одинарными кавычками */
            char *q1 = strchr(line, '\'');
            if (!q1) continue;
            char *q2 = strchr(q1 + 1, '\'');
            if (!q2) continue;
            *q2 = '\0';
            const char *tz = q1 + 1;

            /* RU timezones — явный список, Europe-Berlin/Paris и пр. исключены */
            if (strncmp(tz, "Europe/Moscow",     13) == 0 ||
                strncmp(tz, "Europe/Kaliningrad", 17) == 0 ||
                strncmp(tz, "Europe/Samara",     13) == 0 ||
                strncmp(tz, "Europe/Ulyanovsk",  16) == 0 ||
                strncmp(tz, "Europe/Volgograd",  16) == 0 ||
                strncmp(tz, "Europe/Saratov",    14) == 0 ||
                strncmp(tz, "Europe/Kirov",      13) == 0 ||
                strncmp(tz, "Europe/Astrakhan",  16) == 0 ||
                strstr(tz, "Yekaterinburg")            ||
                strstr(tz, "Omsk")                     ||
                strstr(tz, "Novosibirsk")              ||
                strstr(tz, "Krasnoyarsk")              ||
                strstr(tz, "Irkutsk")                  ||
                strstr(tz, "Yakutsk")                  ||
                strstr(tz, "Vladivostok")              ||
                strstr(tz, "Magadan")                  ||
                strstr(tz, "Kamchatka")                ||
                strstr(tz, "Sakhalin")                 ||
                strstr(tz, "Moscow")) {
                fclose(f);
                log_msg(LOG_INFO, "Регион: RU (timezone %s)", tz);
                return GEO_REGION_RU;
            }

            /* CN timezones */
            if (strncmp(tz, "Asia/Shanghai",  13) == 0 ||
                strncmp(tz, "Asia/Beijing",   12) == 0 ||
                strncmp(tz, "Asia/Chongqing", 14) == 0 ||
                strncmp(tz, "Asia/Harbin",    11) == 0 ||
                strncmp(tz, "Asia/Urumqi",    11) == 0 ||
                strncmp(tz, "Asia/Chungking", 14) == 0) {
                fclose(f);
                log_msg(LOG_INFO, "Регион: CN (timezone %s)", tz);
                return GEO_REGION_CN;
            }

            /* US timezones */
            if (strncmp(tz, "America/", 8) == 0) {
                fclose(f);
                log_msg(LOG_INFO, "Регион: US (timezone %s)", tz);
                return GEO_REGION_US;
            }
        }
        fclose(f);
    }

    /* Шаг 3: fallback */
    log_msg(LOG_WARN,
        "Регион не определён — установите option region 'ru' "
        "в /etc/config/4eburnet");
    return GEO_REGION_UNKNOWN;
}

/* ── Init / Free ────────────────────────────────────────────────────────── */

int geo_manager_init(geo_manager_t *gm, const struct EburNetConfig *cfg)
{
    memset(gm, 0, sizeof(*gm));
    gm->cfg = cfg;

    gm->current_region = device_detect_region(gm, NULL);

    gm->categories = calloc(GEO_CATEGORIES_INITIAL, sizeof(geo_category_t));
    if (!gm->categories) return -1;
    gm->capacity = GEO_CATEGORIES_INITIAL;

    log_msg(LOG_INFO, "GeoIP менеджер: регион %s",
            geo_region_name(gm->current_region));
    return 0;
}

void geo_manager_free(geo_manager_t *gm)
{
    for (int i = 0; i < gm->count; i++)
        free_category_data(&gm->categories[i]);
    free(gm->categories);
    memset(gm, 0, sizeof(*gm));
}

/* ── geo_load_category ──────────────────────────────────────────────────── */

int geo_load_category(geo_manager_t *gm, const char *name,
                      geo_region_t region, const char *path)
{
    /* Найти или создать слот */
    geo_category_t *c = find_category(gm, name);
    if (!c) {
        if (gm->count >= gm->capacity && grow_categories(gm) < 0)
            return -1;
        c = &gm->categories[gm->count++];
        memset(c, 0, sizeof(*c));
        snprintf(c->name, sizeof(c->name), "%s", name);
    }

    /* Обновить метаданные */
    c->region = region;
    snprintf(c->path, sizeof(c->path), "%s", path);

    /* A2: определить adblock-категорию по имени */
    if (strstr(name, "ads"))          c->cat_type = GEO_CAT_ADS;
    else if (strstr(name, "tracker")) c->cat_type = GEO_CAT_TRACKERS;
    else if (strstr(name, "threat"))  c->cat_type = GEO_CAT_THREATS;
    else                              c->cat_type = GEO_CAT_GENERIC;

    /* Освободить старые данные если были */
    free_category_data(c);

    /* Открыть файл */
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        log_msg(LOG_WARN, "GeoIP: файл не найден: %s", path);
        return -1;
    }
    FILE *f = fdopen(fd, "r");
    if (!f) { close(fd); return -1; }

    /* Первый проход: подсчёт строк по типу */
    char line[256];
    int n_v4 = 0, n_v6 = 0, n_dom = 0, n_sfx = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' ||
                           line[len-1] == ' '))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;

        if (strchr(line, ':'))     n_v6++;
        else if (strchr(line, '/')) n_v4++;
        else if (line[0] == '.')   n_sfx++;
        else                        n_dom++;
    }
    rewind(f);

    /* Выделить массивы */
    if (n_v4 > 0) {
        c->v4 = malloc((size_t)n_v4 * sizeof(geo_cidr4_t));
        if (!c->v4) { fclose(f); free_category_data(c); return -1; }
    }
    if (n_v6 > 0) {
        c->v6 = malloc((size_t)n_v6 * sizeof(geo_cidr6_t));
        if (!c->v6) { fclose(f); free_category_data(c); return -1; }
    }
    if (n_dom > 0) {
        c->domains = malloc((size_t)n_dom * sizeof(char *));
        if (!c->domains) { fclose(f); free_category_data(c); return -1; }
    }
    if (n_sfx > 0) {
        c->suffixes = malloc((size_t)n_sfx * sizeof(char *));
        if (!c->suffixes) { fclose(f); free_category_data(c); return -1; }
    }

    /* Второй проход: заполнить */
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' ||
                           line[len-1] == ' '))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;

        if (strchr(line, ':')) {
            /* IPv6 CIDR */
            geo_cidr6_t e;
            if (parse_cidr6(line, &e))
                c->v6[c->v6_count++] = e;
        } else if (strchr(line, '/')) {
            /* IPv4 CIDR */
            geo_cidr4_t e;
            if (parse_cidr4(line, &e))
                c->v4[c->v4_count++] = e;
        } else if (line[0] == '.') {
            /* Суффикс (.example.com → без точки) */
            char *dup = strdup(line + 1);
            if (dup) c->suffixes[c->suffix_count++] = dup;
        } else {
            /* Точный домен */
            char *dup = strdup(line);
            if (dup) c->domains[c->domain_count++] = dup;
        }
    }
    fclose(f);

    /* Сортировать для binary search */
    if (c->v4_count > 1)
        qsort(c->v4, c->v4_count, sizeof(geo_cidr4_t), cmp_cidr4);
    if (c->domain_count > 1)
        qsort(c->domains, c->domain_count, sizeof(char *), cmp_str);
    if (c->suffix_count > 1)
        qsort(c->suffixes, c->suffix_count, sizeof(char *), cmp_str);

    /* Построить Patricia trie для быстрого IPv4 lookup */
    if (c->v4_count > 0) {
        c->trie_v4 = ptrie_alloc();
        if (c->trie_v4) {
            for (int j = 0; j < c->v4_count; j++) {
                if (ptrie_insert(c->trie_v4,
                                 c->v4[j].net,
                                 c->v4[j].mask,
                                 c->region) < 0) {
                    /* OOM — освободить trie, fallback на O(n) */
                    ptrie_free(c->trie_v4);
                    c->trie_v4 = NULL;
                    log_msg(LOG_WARN,
                        "GeoIP %s: trie OOM, fallback на линейный скан",
                        c->name);
                    break;
                }
            }
        }
    }

    c->loaded = true;
    c->loaded_at = time(NULL);

    log_msg(LOG_INFO,
        "GeoIP %s: %d IPv4, %d IPv6, %d домен, %d суффикс",
        name, c->v4_count, c->v6_count, c->domain_count, c->suffix_count);
    return 0;
}

/* ── geo_reload_category ────────────────────────────────────────────────── */

int geo_reload_category(geo_manager_t *gm, const char *name)
{
    geo_category_t *c = find_category(gm, name);
    if (!c) {
        log_msg(LOG_WARN, "GeoIP reload: категория '%s' не найдена", name);
        return -1;
    }
    if (!c->path[0]) {
        log_msg(LOG_WARN, "GeoIP reload: путь не задан для '%s'", name);
        return -1;
    }
    return geo_load_category(gm, name, c->region, c->path);
}

/* ── geo_match_ip ───────────────────────────────────────────────────────── */

geo_region_t geo_match_ip(const geo_manager_t *gm,
                           const struct sockaddr_storage *addr)
{
    if (!addr) return GEO_REGION_UNKNOWN;

    for (int i = 0; i < gm->count; i++) {
        const geo_category_t *c = &gm->categories[i];
        if (!c->loaded) continue;

        if (addr->ss_family == AF_INET && c->v4_count > 0) {
            const struct sockaddr_in *s4 = (const struct sockaddr_in *)addr;
            uint32_t ip = ntohl(s4->sin_addr.s_addr);

            if (c->trie_v4) {
                /* O(32) Patricia trie lookup */
                geo_region_t r = ptrie_lookup(c->trie_v4, ip);
                if (r != GEO_REGION_UNKNOWN) return r;
            } else {
                /* Fallback: O(n) линейный скан */
                for (int j = 0; j < c->v4_count; j++) {
                    if ((ip & c->v4[j].mask) == c->v4[j].net)
                        return c->region;
                }
            }
        }

        if (addr->ss_family == AF_INET6 && c->v6_count > 0) {
            const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)addr;
            for (int j = 0; j < c->v6_count; j++) {
                const geo_cidr6_t *e = &c->v6[j];
                int full = e->prefix / 8;
                int rem  = e->prefix % 8;
                if (memcmp(&s6->sin6_addr, e->net, full) != 0) continue;
                if (rem > 0) {
                    uint8_t m = (uint8_t)(0xFF << (8 - rem));
                    if ((s6->sin6_addr.s6_addr[full] & m) !=
                        (e->net[full] & m))
                        continue;
                }
                return c->region;
            }
        }
    }
    return GEO_REGION_UNKNOWN;
}

/* ── geo_match_domain ───────────────────────────────────────────────────── */

geo_region_t geo_match_domain(const geo_manager_t *gm, const char *domain)
{
    if (!domain) return GEO_REGION_UNKNOWN;

    for (int i = 0; i < gm->count; i++) {
        const geo_category_t *c = &gm->categories[i];
        if (!c->loaded) continue;

        /* 1. Точное совпадение — bsearch O(log n) */
        if (c->domain_count > 0) {
            const char *key = domain;
            if (bsearch(&key, c->domains, c->domain_count,
                        sizeof(char *), cmp_str))
                return c->region;
        }

        /* 2. Суффикс — bsearch по отсортированному массиву суффиксов.
              Перебираем все суффиксы домена:
              sub.example.com → example.com → com */
        if (c->suffix_count > 0) {
            const char *p = domain;
            while (p) {
                const char *key = p;
                if (bsearch(&key, c->suffixes, c->suffix_count,
                            sizeof(char *), cmp_str))
                    return c->region;
                p = strchr(p, '.');
                if (p) p++;
            }
        }
    }
    return GEO_REGION_UNKNOWN;
}

/* A2: найти adblock-категорию домена (для stats счётчиков) */
geo_cat_type_t geo_match_domain_cat(const geo_manager_t *gm, const char *domain)
{
    if (!gm || !domain) return GEO_CAT_GENERIC;
    for (int i = 0; i < gm->count; i++) {
        const geo_category_t *c = &gm->categories[i];
        if (!c->loaded || c->cat_type == GEO_CAT_GENERIC) continue;
        if (c->domain_count > 0) {
            const char *key = domain;
            if (bsearch(&key, c->domains, (size_t)c->domain_count,
                        sizeof(char *), cmp_str))
                return c->cat_type;
        }
        if (c->suffix_count > 0) {
            const char *p = domain;
            while (p) {
                const char *key = p;
                if (bsearch(&key, c->suffixes, (size_t)c->suffix_count,
                            sizeof(char *), cmp_str))
                    return c->cat_type;
                p = strchr(p, '.');
                if (p) p++;
            }
        }
    }
    return GEO_CAT_GENERIC;
}

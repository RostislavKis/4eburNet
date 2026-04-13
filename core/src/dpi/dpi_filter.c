/*
 * dpi_filter.c — DPI bypass фильтр (C.1)
 *
 * Три sorted array + bsearch:
 *   ipv4_ranges[]:   IPv4 CIDR, отсортированы по addr, binary search
 *   ipv6_ranges[]:   IPv6 CIDR, отсортированы лексикографически
 *   whitelist[]:     exact domain strings, qsort+bsearch
 *   autohosts[]:     exact domain strings, qsort+bsearch
 */

#if CONFIG_EBURNET_DPI

#include "dpi/dpi_filter.h"
#include "4eburnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <arpa/inet.h>

/* ── IPv4 CIDR ──────────────────────────────────────────────────── */

typedef struct {
    uint32_t addr;  /* сеть в host byte order */
    uint32_t mask;  /* маска в host byte order */
} ipv4_cidr_t;

/* ── IPv6 CIDR ──────────────────────────────────────────────────── */

typedef struct {
    uint8_t addr[16];
    uint8_t mask[16];
} ipv6_cidr_t;

/* ── Глобальное состояние ───────────────────────────────────────── */

static ipv4_cidr_t *g_ipv4    = NULL;
static int          g_ipv4_n  = 0;

static ipv6_cidr_t *g_ipv6    = NULL;
static int          g_ipv6_n  = 0;

static char       **g_white   = NULL;
static int          g_white_n = 0;

static char       **g_auto    = NULL;
static int          g_auto_n  = 0;

static int          g_ready   = 0;

/* ── Вспомогательные ────────────────────────────────────────────── */

static int cmp_ipv4(const void *a, const void *b)
{
    const ipv4_cidr_t *x = (const ipv4_cidr_t *)a;
    const ipv4_cidr_t *y = (const ipv4_cidr_t *)b;
    if (x->addr < y->addr) return -1;
    if (x->addr > y->addr) return  1;
    return 0;
}

static int cmp_ipv6(const void *a, const void *b)
{
    return memcmp(((const ipv6_cidr_t *)a)->addr,
                  ((const ipv6_cidr_t *)b)->addr, 16);
}

static int cmp_str(const void *a, const void *b)
{
    return strcasecmp(*(const char **)a, *(const char **)b);
}

/* Преобразовать prefix len в IPv4 маску host byte order */
static uint32_t prefix_to_mask4(int plen)
{
    if (plen <= 0)  return 0;
    if (plen >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - plen);
}

/* Преобразовать prefix len в IPv6 маску (16 байт) */
static void prefix_to_mask6(int plen, uint8_t mask[16])
{
    memset(mask, 0, 16);
    for (int i = 0; i < 16 && plen > 0; i++) {
        int bits = plen > 8 ? 8 : plen;
        mask[i] = (uint8_t)(0xFF << (8 - bits));
        plen -= bits;
    }
}

/* ── Парсинг ipset.txt ──────────────────────────────────────────── */

/*
 * Формат ipset.txt:
 *   # комментарий
 *   1.2.3.0/24        ← IPv4 CIDR
 *   2606:4700::/32    ← IPv6 CIDR
 *   1.2.3.4           ← host (без маски → /32 или /128)
 */
static int parse_ipset(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        log_msg(LOG_WARN, "dpi_filter: не удалось открыть %s", path);
        return 0;  /* не критично, работаем без ipset */
    }

    /* Первый проход — подсчитать строки */
    int n4 = 0, n6 = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        if (strchr(p, ':')) n6++;
        else                n4++;
    }
    rewind(f);

    g_ipv4 = calloc((size_t)(n4 + 1), sizeof(ipv4_cidr_t));
    g_ipv6 = calloc((size_t)(n6 + 1), sizeof(ipv6_cidr_t));
    if (!g_ipv4 || !g_ipv6) {
        free(g_ipv4); g_ipv4 = NULL;
        free(g_ipv6); g_ipv6 = NULL;
        fclose(f);
        return -1;
    }

    /* Второй проход — парсить */
    while (fgets(line, sizeof(line), f)) {
        /* Удалить перевод строки */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\0') continue;

        /* Найти / для prefix length */
        char *slash = strchr(p, '/');
        int plen = -1;
        if (slash) {
            *slash = '\0';
            /* strtol с endptr: отклоняем "1.2.3.0/" и "x/0abc" */
            char *endp;
            long pl_raw = strtol(slash + 1, &endp, 10);
            plen = (endp != slash + 1 && *endp == '\0') ? (int)pl_raw : -1;
        }

        if (strchr(p, ':')) {
            /* IPv6 */
            if (g_ipv6_n >= n6) continue;
            struct in6_addr a6;
            if (inet_pton(AF_INET6, p, &a6) != 1) continue;
            memcpy(g_ipv6[g_ipv6_n].addr, &a6, 16);
            /* plen > 0: /0 даёт mask=0 и матчит всё — трактовать как /128 */
            int pl = (plen > 0 && plen <= 128) ? plen : 128;
            prefix_to_mask6(pl, g_ipv6[g_ipv6_n].mask);
            /* Применить маску к адресу */
            for (int i = 0; i < 16; i++)
                g_ipv6[g_ipv6_n].addr[i] &= g_ipv6[g_ipv6_n].mask[i];
            g_ipv6_n++;
        } else {
            /* IPv4 */
            if (g_ipv4_n >= n4) continue;
            struct in_addr a4;
            if (inet_pton(AF_INET, p, &a4) != 1) continue;
            uint32_t addr = ntohl(a4.s_addr);
            /* plen > 0: /0 даёт mask=0 и матчит всё — трактовать как /32 */
            int pl = (plen > 0 && plen <= 32) ? plen : 32;
            uint32_t mask = prefix_to_mask4(pl);
            g_ipv4[g_ipv4_n].addr = addr & mask;
            g_ipv4[g_ipv4_n].mask = mask;
            g_ipv4_n++;
        }
    }
    fclose(f);

    qsort(g_ipv4, (size_t)g_ipv4_n, sizeof(ipv4_cidr_t), cmp_ipv4);
    qsort(g_ipv6, (size_t)g_ipv6_n, sizeof(ipv6_cidr_t), cmp_ipv6);

    log_msg(LOG_INFO, "dpi_filter: ipset IPv4=%d IPv6=%d", g_ipv4_n, g_ipv6_n);
    return 0;
}

/* ── Парсинг domain файлов (whitelist / autohosts) ─────────────── */

static char **load_domain_list(const char *path, int *out_count)
{
    *out_count = 0;
    FILE *f = fopen(path, "r");
    if (!f) {
        log_msg(LOG_DEBUG, "dpi_filter: %s отсутствует", path);
        return NULL;
    }

    /* Подсчитать строки */
    int n = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p != '#' && *p != '\n' && *p != '\0') n++;
    }
    rewind(f);

    char **arr = calloc((size_t)(n + 1), sizeof(char *));
    if (!arr) { fclose(f); return NULL; }

    int i = 0;
    while (fgets(line, sizeof(line), f) && i < n) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\0') continue;
        /* Удалить trailing пробелы */
        char *end = p + strlen(p) - 1;
        while (end > p && (*end == ' ' || *end == '\t')) *end-- = '\0';
        if (*p == '\0') continue;
        arr[i] = strdup(p);
        if (!arr[i]) break;
        i++;
    }
    fclose(f);

    *out_count = i;
    qsort(arr, (size_t)i, sizeof(char *), cmp_str);
    log_msg(LOG_DEBUG, "dpi_filter: %s: %d доменов", path, i);
    return arr;
}

static void free_domain_list(char **arr, int n)
{
    if (!arr) return;
    for (int i = 0; i < n; i++) free(arr[i]);
    free(arr);
}

/* ── Инициализация ──────────────────────────────────────────────── */

/*
 * NOT thread-safe: вызывать только из главного потока (epoll loop).
 * dpi_filter_free() + перезагрузка не защищены mutex.
 * parse_ipset: два прохода по файлу. При горячей замене ipset.txt
 * (reload в C.5+) заменить на однопроходный парсинг с realloc.
 */
int dpi_filter_init(const char *dpi_dir)
{
    dpi_filter_free();

    if (!dpi_dir || dpi_dir[0] == '\0')
        dpi_dir = EBURNET_DPI_DIR;

    char path[512];

    /* ipset.txt */
    snprintf(path, sizeof(path), "%s/ipset.txt", dpi_dir);
    if (parse_ipset(path) < 0) {
        log_msg(LOG_WARN, "dpi_filter: parse_ipset провалился, работаем без ipset");
    }

    /* whitelist.txt */
    snprintf(path, sizeof(path), "%s/whitelist.txt", dpi_dir);
    g_white = load_domain_list(path, &g_white_n);

    /* autohosts.txt */
    snprintf(path, sizeof(path), "%s/autohosts.txt", dpi_dir);
    g_auto = load_domain_list(path, &g_auto_n);

    g_ready = 1;
    log_msg(LOG_INFO,
            "dpi_filter: инициализирован (ipv4=%d ipv6=%d white=%d auto=%d)",
            g_ipv4_n, g_ipv6_n, g_white_n, g_auto_n);
    return 0;
}

void dpi_filter_free(void)
{
    free(g_ipv4); g_ipv4 = NULL; g_ipv4_n = 0;
    free(g_ipv6); g_ipv6 = NULL; g_ipv6_n = 0;
    free_domain_list(g_white, g_white_n); g_white = NULL; g_white_n = 0;
    free_domain_list(g_auto,  g_auto_n);  g_auto  = NULL; g_auto_n  = 0;
    g_ready = 0;
}

int dpi_filter_is_ready(void) { return g_ready; }

/* ── IP matching ────────────────────────────────────────────────── */

dpi_match_t dpi_filter_match_ipv4(uint32_t ip, uint16_t port)
{
    (void)port;
    if (!g_ready || g_ipv4_n == 0) return DPI_MATCH_NONE;

    /*
     * Бинарный поиск: найти крайний левый диапазон где addr <= ip.
     * Затем проверить что ip & mask == addr.
     */
    int lo = 0, hi = g_ipv4_n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (g_ipv4[mid].addr <= ip)
            lo = mid + 1;
        else
            hi = mid - 1;
    }
    /* Кандидаты: hi и hi-1..0 — нужно проверить все у которых addr <= ip */
    for (int i = hi; i >= 0; i--) {
        if (g_ipv4[i].addr > ip) continue;
        if ((ip & g_ipv4[i].mask) == g_ipv4[i].addr)
            return DPI_MATCH_BYPASS;
    }
    return DPI_MATCH_NONE;
}

dpi_match_t dpi_filter_match_ipv6(const uint8_t ip6[16], uint16_t port)
{
    (void)port;
    if (!g_ready || g_ipv6_n == 0 || !ip6) return DPI_MATCH_NONE;

    int lo = 0, hi = g_ipv6_n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (memcmp(g_ipv6[mid].addr, ip6, 16) <= 0)
            lo = mid + 1;
        else
            hi = mid - 1;
    }
    for (int i = hi; i >= 0; i--) {
        if (memcmp(g_ipv6[i].addr, ip6, 16) > 0) continue;
        /* Проверить ip6 & mask == addr */
        int match = 1;
        for (int b = 0; b < 16; b++) {
            if ((ip6[b] & g_ipv6[i].mask[b]) != g_ipv6[i].addr[b]) {
                match = 0;
                break;
            }
        }
        if (match) return DPI_MATCH_BYPASS;
    }
    return DPI_MATCH_NONE;
}

/* ── Domain matching ────────────────────────────────────────────── */

static int domain_search(char **arr, int n, const char *domain)
{
    if (!arr || n == 0 || !domain) return 0;
    const char *key = domain;
    void *res = bsearch(&key, arr, (size_t)n, sizeof(char *), cmp_str);
    return res != NULL;
}

dpi_match_t dpi_filter_match_domain(const char *domain)
{
    if (!g_ready || !domain || domain[0] == '\0') return DPI_MATCH_NONE;

    /* whitelist имеет приоритет над autohosts */
    if (domain_search(g_white, g_white_n, domain)) return DPI_MATCH_IGNORE;
    if (domain_search(g_auto,  g_auto_n,  domain)) return DPI_MATCH_BYPASS;

    return DPI_MATCH_NONE;
}

/* ── Комбинированная проверка ───────────────────────────────────── */

dpi_match_t dpi_filter_match(const char *domain,
                              uint32_t ipv4,
                              const uint8_t *ip6,
                              uint16_t port)
{
    /* 1. Домен */
    if (domain && domain[0]) {
        dpi_match_t dm = dpi_filter_match_domain(domain);
        if (dm == DPI_MATCH_IGNORE) return DPI_MATCH_IGNORE;  /* whitelist */
        if (dm == DPI_MATCH_BYPASS) return DPI_MATCH_BYPASS;  /* autohosts */
    }

    /* 2. IPv4 */
    if (ipv4 != 0) {
        dpi_match_t m = dpi_filter_match_ipv4(ipv4, port);
        if (m != DPI_MATCH_NONE) return m;
    }

    /* 3. IPv6 */
    if (ip6) {
        dpi_match_t m = dpi_filter_match_ipv6(ip6, port);
        if (m != DPI_MATCH_NONE) return m;
    }

    return DPI_MATCH_NONE;
}

/* ── Статистика ─────────────────────────────────────────────────── */

void dpi_filter_get_stats(dpi_filter_stats_t *stats)
{
    if (!stats) return;
    stats->ipv4_ranges = g_ipv4_n;
    stats->ipv6_ranges = g_ipv6_n;
    stats->whitelist   = g_white_n;
    stats->autohosts   = g_auto_n;
}

#endif /* CONFIG_EBURNET_DPI */

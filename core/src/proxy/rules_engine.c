/*
 * Rules engine — matching трафика и выбор целевой группы/действия
 * DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / RULE-SET / MATCH
 *
 * C-4: RULE_SET загружается в память при init (не fopen на каждый запрос).
 * Binary search O(log n) по доменам.
 */

#include "proxy/rules_engine.h"
#include "phoenix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

/* Максимум провайдеров с in-memory кэшем */
#define MAX_PROVIDER_CACHE 16

/* In-memory кэш одного rule-provider */
typedef struct {
    char   name[64];
    char **entries;       /* отсортированный массив строк (домены или CIDR) */
    int    count;
    bool   is_domain;     /* true=домены, false=CIDR */
} provider_cache_t;

/* Статический кэш (живёт между init/free) */
static provider_cache_t s_cache[MAX_PROVIDER_CACHE];
static int s_cache_count = 0;

/* Сортировка по priority ASC (M-05: без integer overflow) */
static int cmp_priority(const void *a, const void *b)
{
    int pa = ((const TrafficRule *)a)->priority;
    int pb = ((const TrafficRule *)b)->priority;
    return (pa > pb) - (pa < pb);
}

/* Сравнение строк для qsort/bsearch */
static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Загрузить файл правил в массив строк */
static int load_file_entries(const char *path, char ***out_entries, int *out_count)
{
    int fd_file = open(path, O_RDONLY | O_CLOEXEC);
    FILE *f = (fd_file >= 0) ? fdopen(fd_file, "r") : NULL;
    if (!f) {
        if (fd_file >= 0) close(fd_file);
        return -1;
    }

    /* Первый проход: подсчёт строк */
    int capacity = 256;
    int count = 0;
    char **entries = malloc((size_t)capacity * sizeof(char *));
    if (!entries) { fclose(f); return -1; }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;

        if (count >= capacity) {
            capacity *= 2;
            char **tmp = realloc(entries, (size_t)capacity * sizeof(char *));
            if (!tmp) break;
            entries = tmp;
        }
        entries[count] = strdup(line);
        if (!entries[count]) break;
        count++;
    }
    fclose(f);

    *out_entries = entries;
    *out_count = count;
    return 0;
}

/* Освободить массив строк */
static void free_entries(char **entries, int count)
{
    for (int i = 0; i < count; i++)
        free(entries[i]);
    free(entries);
}

/* Освободить весь кэш */
static void cache_free(void)
{
    for (int i = 0; i < s_cache_count; i++)
        free_entries(s_cache[i].entries, s_cache[i].count);
    s_cache_count = 0;
}

/* Загрузить провайдер в кэш */
static provider_cache_t *cache_load(const char *provider_name,
                                     rule_provider_manager_t *rpm)
{
    if (!rpm || s_cache_count >= MAX_PROVIDER_CACHE) return NULL;

    /* Уже в кэше? */
    for (int i = 0; i < s_cache_count; i++)
        if (strcmp(s_cache[i].name, provider_name) == 0)
            return &s_cache[i];

    /* Найти провайдер */
    int pi = -1;
    for (int i = 0; i < rpm->count; i++) {
        if (strcmp(rpm->providers[i].name, provider_name) == 0) {
            pi = i;
            break;
        }
    }
    if (pi < 0 || !rpm->providers[pi].loaded) return NULL;

    provider_cache_t *pc = &s_cache[s_cache_count];
    snprintf(pc->name, sizeof(pc->name), "%.63s", provider_name);

    if (load_file_entries(rpm->providers[pi].cache_path,
                          &pc->entries, &pc->count) < 0)
        return NULL;

    /* Определить тип: если есть '/' — CIDR, иначе домен */
    pc->is_domain = true;
    if (pc->count > 0 && strchr(pc->entries[0], '/'))
        pc->is_domain = false;

    /* Сортировать для binary search (только домены) */
    if (pc->is_domain)
        qsort(pc->entries, pc->count, sizeof(char *), cmp_str);

    s_cache_count++;
    log_msg(LOG_DEBUG, "Rules cache: %s загружен (%d записей, %s)",
            provider_name, pc->count,
            pc->is_domain ? "domain" : "cidr");
    return pc;
}

int rules_engine_init(rules_engine_t *re, const PhoenixConfig *cfg,
                      proxy_group_manager_t *pgm,
                      rule_provider_manager_t *rpm,
                      geo_manager_t *gm)
{
    memset(re, 0, sizeof(*re));
    re->cfg = cfg;
    re->pgm = pgm;
    re->rpm = rpm;
    re->gm  = gm;

    if (cfg->traffic_rule_count == 0) return 0;

    re->sorted_rules = malloc((size_t)cfg->traffic_rule_count *
                              sizeof(TrafficRule));
    if (!re->sorted_rules) return -1;

    memcpy(re->sorted_rules, cfg->traffic_rules,
           (size_t)cfg->traffic_rule_count * sizeof(TrafficRule));
    re->rule_count = cfg->traffic_rule_count;

    qsort(re->sorted_rules, re->rule_count, sizeof(TrafficRule),
          cmp_priority);

    /* C-4: загрузить RULE_SET провайдеры в кэш */
    for (int i = 0; i < re->rule_count; i++) {
        if (re->sorted_rules[i].type == RULE_TYPE_RULE_SET)
            cache_load(re->sorted_rules[i].value, rpm);
    }

    /* H-4: валидация target — проверить что группы существуют */
    for (int i = 0; i < re->rule_count; i++) {
        const char *t = re->sorted_rules[i].target;
        if (strcmp(t, "DIRECT") == 0 || strcmp(t, "REJECT") == 0)
            continue;
        if (pgm && !proxy_group_find(pgm, t))
            log_msg(LOG_WARN,
                "Rules engine: target '%s' не найден в proxy_groups", t);
    }

    log_msg(LOG_INFO, "Rules engine: %d правил загружено", re->rule_count);
    return 0;
}

void rules_engine_free(rules_engine_t *re)
{
    cache_free();
    free(re->sorted_rules);
    memset(re, 0, sizeof(*re));
}

/* Суффикс match: domain заканчивается на ".suffix" или равен suffix */
static bool suffix_match(const char *domain, const char *suffix)
{
    if (!domain || !suffix) return false;
    size_t dlen = strlen(domain);
    size_t slen = strlen(suffix);
    if (slen > dlen) return false;
    if (strcmp(domain + dlen - slen, suffix) == 0) {
        if (slen == dlen) return true;
        if (domain[dlen - slen - 1] == '.') return true;
    }
    return false;
}

/* CIDR match: IPv4 + IPv6 (H-05) */
static bool cidr_match(const struct sockaddr_storage *dst, const char *cidr)
{
    if (!dst) return false;

    char ip_str[64];
    int prefix = -1;
    snprintf(ip_str, sizeof(ip_str), "%s", cidr);

    char *slash = strchr(ip_str, '/');
    if (slash) { *slash = '\0'; prefix = atoi(slash + 1); }

    if (dst->ss_family == AF_INET) {
        if (prefix < 0) prefix = 32;
        if (prefix > 32) return false;
        struct in_addr net;
        if (inet_pton(AF_INET, ip_str, &net) != 1) return false;
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)dst;
        uint32_t mask = prefix == 0
            ? 0U : htonl(~((1U << (32 - prefix)) - 1));
        return (s4->sin_addr.s_addr & mask) == (net.s_addr & mask);
    }

    if (dst->ss_family == AF_INET6) {
        if (prefix < 0) prefix = 128;
        if (prefix > 128) return false;
        struct in6_addr net6;
        if (inet_pton(AF_INET6, ip_str, &net6) != 1) return false;
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)dst;
        /* Побайтовое сравнение с маской */
        int full_bytes = prefix / 8;
        int rem_bits   = prefix % 8;
        if (memcmp(&s6->sin6_addr, &net6, full_bytes) != 0)
            return false;
        if (rem_bits > 0) {
            uint8_t mask8 = (uint8_t)(0xFF << (8 - rem_bits));
            if ((s6->sin6_addr.s6_addr[full_bytes] & mask8) !=
                (net6.s6_addr[full_bytes] & mask8))
                return false;
        }
        return true;
    }

    return false;
}

/* C-4: проверить RULE-SET provider по домену — in-memory binary search */
static bool ruleset_match_domain(rules_engine_t *re,
                                 const char *provider_name,
                                 const char *domain)
{
    if (!domain) return false;

    /* Найти кэш */
    provider_cache_t *pc = NULL;
    for (int i = 0; i < s_cache_count; i++) {
        if (strcmp(s_cache[i].name, provider_name) == 0) {
            pc = &s_cache[i];
            break;
        }
    }
    if (!pc || !pc->is_domain) return false;

    /* Точное совпадение через bsearch */
    const char *key = domain;
    if (bsearch(&key, pc->entries, pc->count, sizeof(char *), cmp_str))
        return true;

    /* TODO 3.5: суффикс-поиск O(n) — при > 50K записей
       заменить на trie или отдельный sorted suffix array */
    for (int i = 0; i < pc->count; i++) {
        if (suffix_match(domain, pc->entries[i]))
            return true;
    }

    (void)re;
    return false;
}

/* C-4: проверить RULE-SET provider по IP — in-memory */
static bool ruleset_match_ip(rules_engine_t *re,
                             const char *provider_name,
                             const struct sockaddr_storage *dst)
{
    if (!dst) return false;

    provider_cache_t *pc = NULL;
    for (int i = 0; i < s_cache_count; i++) {
        if (strcmp(s_cache[i].name, provider_name) == 0) {
            pc = &s_cache[i];
            break;
        }
    }
    if (!pc || pc->is_domain) return false;

    for (int i = 0; i < pc->count; i++) {
        if (cidr_match(dst, pc->entries[i]))
            return true;
    }

    (void)re;
    return false;
}

static rule_match_result_t make_result(const char *target)
{
    rule_match_result_t r = {0};
    if (strcmp(target, "DIRECT") == 0) {
        r.type = RULE_TARGET_DIRECT;
    } else if (strcmp(target, "REJECT") == 0) {
        r.type = RULE_TARGET_REJECT;
    } else {
        r.type = RULE_TARGET_GROUP;
        snprintf(r.group_name, sizeof(r.group_name), "%s", target);
    }
    return r;
}

rule_match_result_t rules_engine_match(rules_engine_t *re,
                                       const char *domain,
                                       const struct sockaddr_storage *dst)
{
    for (int i = 0; i < re->rule_count; i++) {
        const TrafficRule *tr = &re->sorted_rules[i];
        bool matched = false;

        switch (tr->type) {
        case RULE_TYPE_DOMAIN:
            if (domain && strcmp(domain, tr->value) == 0)
                matched = true;
            break;
        case RULE_TYPE_DOMAIN_SUFFIX:
            if (domain && suffix_match(domain, tr->value))
                matched = true;
            break;
        case RULE_TYPE_DOMAIN_KEYWORD:
            if (domain && strstr(domain, tr->value))
                matched = true;
            break;
        case RULE_TYPE_IP_CIDR:
            if (dst && cidr_match(dst, tr->value))
                matched = true;
            break;
        case RULE_TYPE_RULE_SET:
            if (domain && ruleset_match_domain(re, tr->value, domain))
                matched = true;
            else if (dst && ruleset_match_ip(re, tr->value, dst))
                matched = true;
            break;
        case RULE_TYPE_MATCH:
            matched = true;
            break;
        case RULE_TYPE_GEOIP:
            /* value = "RU", target = "DIRECT" */
            if (re->gm && dst) {
                geo_region_t r    = geo_match_ip(re->gm, dst);
                geo_region_t want = geo_region_from_str(tr->value);
                if (r == want && want != GEO_REGION_UNKNOWN)
                    matched = true;
            }
            break;
        case RULE_TYPE_GEOSITE:
            /* value = "ru", target = "DIRECT" */
            if (re->gm && domain) {
                geo_region_t r    = geo_match_domain(re->gm, domain);
                geo_region_t want = geo_region_from_str(tr->value);
                if (r == want && want != GEO_REGION_UNKNOWN)
                    matched = true;
            }
            break;
        }

        if (matched) {
            log_msg(LOG_DEBUG, "Rules: matched %s → %s",
                    tr->value[0] ? tr->value : "MATCH", tr->target);
            return make_result(tr->target);
        }
    }

    /* Нет совпадений → DIRECT */
    rule_match_result_t direct = { .type = RULE_TARGET_DIRECT };
    return direct;
}

int rules_engine_get_server(rules_engine_t *re,
                            const char *domain,
                            const struct sockaddr_storage *dst)
{
    rule_match_result_t r = rules_engine_match(re, domain, dst);

    switch (r.type) {
    case RULE_TARGET_DIRECT: return -1;
    case RULE_TARGET_REJECT: return -2;
    case RULE_TARGET_GROUP:
        /* H-5: предупреждение если pgm не задан или группа недоступна */
        if (!re->pgm) {
            log_msg(LOG_WARN, "rules_engine: pgm не инициализирован");
            return -1;
        }
        {
            int srv = proxy_group_select_server(re->pgm, r.group_name);
            if (srv < 0)
                log_msg(LOG_WARN,
                    "rules_engine: группа '%s' недоступна → DIRECT",
                    r.group_name);
            return srv;
        }
    }
    return -1;
}

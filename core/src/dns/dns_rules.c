/*
 * DNS правила маршрутизации — matcher для доменов
 */

#include "dns/dns_rules.h"
#include "geo/geo_loader.h"
#include "4eburnet.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

/* Внутренний массив правил */
static struct {
    char        **patterns;
    dns_action_t *actions;
    int           count;
    int           capacity;
} g_rules = {0};

/* ── GEOSITE блокировка (Вариант B, 3.5.1) ── */
/* Указатель на geo_manager устанавливается после geo_manager_init() */
static const geo_manager_t *g_gm = NULL;

/* ── Traffic rules consultation (3.5.5) ── */
/* Callback: dns_action_t cb(const char *qname)
   Устанавливается из main.c через dns_rules_set_engine_cb().
   Не NULL-разыменовывается напрямую — всегда проверяем. */
static dns_action_t (*g_engine_cb)(const char *) = NULL;
/* Действие для каждой гео-категории: индекс = geo_cat_type_t */
static dns_action_t g_geosite_actions[4] = {
    [GEO_CAT_GENERIC]  = DNS_ACTION_DEFAULT,
    [GEO_CAT_ADS]      = DNS_ACTION_DEFAULT,
    [GEO_CAT_TRACKERS] = DNS_ACTION_DEFAULT,
    [GEO_CAT_THREATS]  = DNS_ACTION_DEFAULT,
};

void dns_rules_set_geo_manager(const geo_manager_t *gm)
{
    g_gm = gm;
    log_msg(LOG_DEBUG, "dns_rules: geo_manager %s",
            gm ? "подключён" : "отключён");
}

void dns_rules_set_engine(dns_action_t (*cb)(const char *))
{
    g_engine_cb = cb;
    log_msg(LOG_DEBUG, "dns_rules: engine callback %s",
            cb ? "подключён" : "отключён");
}

void dns_rules_add_geosite(geo_cat_type_t cat, dns_action_t action)
{
    if ((unsigned)cat >= 4) return;
    g_geosite_actions[(unsigned)cat] = action;
    const char *names[] = {"generic", "ads", "trackers", "threats"};
    log_msg(LOG_INFO, "dns_rules: geosite '%s' → %s",
            names[(unsigned)cat],
            action == DNS_ACTION_BLOCK ? "BLOCK" : "action");
}

/* Inline-помощник: проверить домен в geosite категориях */
static inline dns_action_t geosite_check(const char *qname, dns_action_t best)
{
    if (g_gm == NULL) return best;
    geo_cat_type_t ct = geo_match_domain_cat(g_gm, qname);
    if ((unsigned)ct >= 4 || ct == GEO_CAT_GENERIC) return best;
    dns_action_t gact = g_geosite_actions[(unsigned)ct];
    if (gact == DNS_ACTION_BLOCK) return DNS_ACTION_BLOCK;
    if (gact != DNS_ACTION_DEFAULT &&
        (best == DNS_ACTION_DEFAULT || (int)gact < (int)best))
        return gact;
    return best;
}

/* ── Sorted index для O(log n) поиска ── */

typedef struct {
    const char  *key;    /* для exact: сам паттерн
                            для suffix: паттерн + 2 (без "*.") */
    dns_action_t action;
} rule_idx_t;

static struct {
    rule_idx_t *exact;    /* sorted by key (strcmp) */
    int         exact_n;
    rule_idx_t *suffix;   /* sorted by key (strcmp), key = pat+2 */
    int         suffix_n;
    bool        ready;    /* true если индекс успешно построен */
} g_idx = {0};

static void idx_free(void)
{
    free(g_idx.exact);
    free(g_idx.suffix);
    memset(&g_idx, 0, sizeof(g_idx));
}

static int cmp_rule_idx(const void *a, const void *b)
{
    const rule_idx_t *ra = (const rule_idx_t *)a;
    const rule_idx_t *rb = (const rule_idx_t *)b;
    int c = strcmp(ra->key, rb->key);
    if (c != 0) return c;
    /* При совпадении ключа: block первым, затем bypass, proxy, default */
    static const int prio[4] = {1, 2, 0, 3};  /* indexed by dns_action_t */
    return prio[(int)ra->action] - prio[(int)rb->action];
}

void dns_rules_rebuild_index(void)
{
    idx_free();
    if (g_rules.count == 0) return;

    g_idx.exact  = malloc((size_t)g_rules.count * sizeof(rule_idx_t));
    g_idx.suffix = malloc((size_t)g_rules.count * sizeof(rule_idx_t));
    if (!g_idx.exact || !g_idx.suffix) {
        idx_free();
        log_msg(LOG_WARN,
            "DNS rules: не удалось создать индекс (OOM), fallback O(n)");
        return;
    }

    int en = 0, sn = 0;
    for (int i = 0; i < g_rules.count; i++) {
        const char *pat = g_rules.patterns[i];
        dns_action_t act = g_rules.actions[i];
        if (pat[0] == '*' && pat[1] == '.') {
            g_idx.suffix[sn++] = (rule_idx_t){
                .key    = pat + 2,
                .action = act,
            };
        } else {
            g_idx.exact[en++] = (rule_idx_t){
                .key    = pat,
                .action = act,
            };
        }
    }

    qsort(g_idx.exact,  (size_t)en, sizeof(rule_idx_t), cmp_rule_idx);
    qsort(g_idx.suffix, (size_t)sn, sizeof(rule_idx_t), cmp_rule_idx);

    g_idx.exact_n  = en;
    g_idx.suffix_n = sn;

    log_msg(LOG_DEBUG, "DNS rules index: %d exact + %d suffix (total %d)",
            en, sn, g_rules.count);
    g_idx.ready = true;
}

int dns_rules_init(const EburNetConfig *cfg)
{
    dns_rules_free();
    if (cfg->dns_rule_count == 0)
        return 0;

    if (cfg->dns_rule_count > INT_MAX - 256) {
        log_msg(LOG_ERROR, "DNS rules: слишком много правил");
        return -1;
    }
    g_rules.capacity = cfg->dns_rule_count + 256;
    g_rules.patterns = calloc(g_rules.capacity, sizeof(char *));
    if (!g_rules.patterns) return -1;
    g_rules.actions  = calloc(g_rules.capacity, sizeof(dns_action_t));
    if (!g_rules.actions) {
        free(g_rules.patterns);
        g_rules.patterns = NULL;
        return -1;
    }

    for (int i = 0; i < cfg->dns_rule_count; i++) {
        const DnsRule *r = &cfg->dns_rules[i];
        char *dup = strdup(r->pattern);
        if (!dup) break;  /* OOM — прекратить загрузку */
        g_rules.patterns[g_rules.count] = dup;

        if (strcmp(r->type, "bypass") == 0)
            g_rules.actions[g_rules.count] = DNS_ACTION_BYPASS;
        else if (strcmp(r->type, "proxy") == 0)
            g_rules.actions[g_rules.count] = DNS_ACTION_PROXY;
        else if (strcmp(r->type, "block") == 0)
            g_rules.actions[g_rules.count] = DNS_ACTION_BLOCK;
        else
            g_rules.actions[g_rules.count] = DNS_ACTION_DEFAULT;

        g_rules.count++;
    }

    log_msg(LOG_INFO, "DNS правила загружены: %d записей", g_rules.count);
    dns_rules_rebuild_index();
    return 0;
}

void dns_rules_free(void)
{
    idx_free();
    for (int i = 0; i < g_rules.count; i++)
        free(g_rules.patterns[i]);
    free(g_rules.patterns);
    free(g_rules.actions);
    memset(&g_rules, 0, sizeof(g_rules));
    /* Сбросить geosite и engine callback при перезагрузке конфига */
    g_gm = NULL;
    g_engine_cb = NULL;
    for (int i = 0; i < 4; i++)
        g_geosite_actions[i] = DNS_ACTION_DEFAULT;
}

/* Матч паттерна policy: exact, *.suffix, .suffix */
static bool policy_pattern_match(const char *pattern, const char *domain)
{
    if (!pattern[0] || !domain[0]) return false;

    /* *.suffix или .suffix — suffix match */
    const char *sfx = pattern;
    if (sfx[0] == '*' && sfx[1] == '.') sfx += 2;
    else if (sfx[0] == '.') sfx += 1;
    else {
        /* Точное совпадение (case-insensitive) */
        return (strcasecmp(pattern, domain) == 0);
    }

    /* Суффикс: domain должен совпадать с sfx или заканчиваться на ".sfx" */
    if (strcasecmp(domain, sfx) == 0)
        return true;
    size_t dlen = strlen(domain);
    size_t slen = strlen(sfx);
    if (dlen > slen + 1 &&
        domain[dlen - slen - 1] == '.' &&
        strcasecmp(domain + dlen - slen, sfx) == 0)
        return true;
    return false;
}

const DnsPolicy *dns_policy_match(const DnsPolicy *policies,
                                   int count,
                                   const char *domain)
{
    if (!policies || count <= 0 || !domain || !domain[0])
        return NULL;

    const DnsPolicy *best = NULL;
    for (int i = 0; i < count; i++) {
        if (!policies[i].pattern[0]) continue;
        if (!policy_pattern_match(policies[i].pattern, domain))
            continue;
        /* Выбрать с наименьшим priority */
        if (!best || policies[i].priority < best->priority)
            best = &policies[i];
    }
    return best;
}

/* Проверить суффикс: qname оканчивается на suffix */
static bool suffix_match(const char *qname, const char *suffix)
{
    size_t qlen = strlen(qname);
    size_t slen = strlen(suffix);
    if (slen > qlen) return false;
    if (strcmp(qname + qlen - slen, suffix) == 0) {
        /* Проверить граничный символ: перед суффиксом должна быть точка */
        if (slen == qlen) return true;
        if (qname[qlen - slen - 1] == '.') return true;
    }
    return false;
}

bool dns_is_bogus_response(const char *bogus_list,
                            const uint8_t *resp,
                            size_t resp_len)
{
    if (!bogus_list || !bogus_list[0] || !resp || resp_len < 12)
        return false;

    uint16_t ancount = ((uint16_t)resp[6] << 8) | resp[7];
    if (ancount == 0) return false;

    /* Пропустить заголовок + QNAME вопроса */
    size_t pos = 12;
    while (pos < resp_len) {
        uint8_t len = resp[pos++];
        if (len == 0) break;
        if ((len & 0xC0) == 0xC0) { pos++; break; } /* компрессия */
        pos += len;
    }
    pos += 4; /* QTYPE + QCLASS */

    /* Читать RR записи в секции ANSWER */
    for (int i = 0; i < ancount && pos < resp_len; i++) {
        /* Пропустить NAME */
        while (pos < resp_len) {
            uint8_t len = resp[pos];
            if (len == 0) { pos++; break; }
            if ((len & 0xC0) == 0xC0) { pos += 2; break; }
            pos += 1 + len;
        }
        if (pos + 10 > resp_len) break;

        uint16_t rtype = ((uint16_t)resp[pos] << 8) | resp[pos + 1];
        uint16_t rdlen = ((uint16_t)resp[pos + 8] << 8) | resp[pos + 9];
        pos += 10;

        if (rtype == 1 && rdlen == 4 && pos + 4 <= resp_len) {
            /* A запись — сформировать строку IP */
            char ipstr[16];
            snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u",
                     resp[pos], resp[pos + 1],
                     resp[pos + 2], resp[pos + 3]);

            /* Искать ipstr в bogus_list */
            size_t ilen = strlen(ipstr);
            const char *p = bogus_list;
            while (p && *p) {
                while (*p == ' ' || *p == '\t') p++;
                if (!*p) break;
                const char *end = p;
                while (*end && *end != ' ' && *end != '\t') end++;
                size_t tlen = (size_t)(end - p);
                if (tlen == ilen && memcmp(p, ipstr, tlen) == 0)
                    return true;
                p = end;
            }
        }
        pos += rdlen;
    }
    return false;
}

static dns_action_t idx_lookup(const rule_idx_t *arr, int n,
                                const char *key)
{
    if (!arr || n == 0) return DNS_ACTION_DEFAULT;
    rule_idx_t needle = { .key = key };
    const rule_idx_t *found = (const rule_idx_t *)bsearch(
        &needle, arr, (size_t)n, sizeof(rule_idx_t), cmp_rule_idx);
    if (!found) return DNS_ACTION_DEFAULT;
    /* bsearch может вернуть любой из дубликатов.
       Откатиться к первому — он имеет наивысший приоритет
       (cmp_rule_idx сортирует BLOCK первым). */
    while (found > arr &&
           strcmp((found - 1)->key, found->key) == 0)
        found--;
    return found->action;
}

/* Консультация traffic rules — вызывается когда DNS action ещё DEFAULT.
   Позволяет opencck_domains → MAIN-PROXY назначить fake-ip через DNS. */
static dns_action_t traffic_rules_consult(const char *qname, dns_action_t best)
{
    if (best != DNS_ACTION_DEFAULT || g_engine_cb == NULL)
        return best;
    return g_engine_cb(qname);
}

dns_action_t dns_rules_match(const char *qname)
{
    if (!qname || !qname[0]) return DNS_ACTION_DEFAULT;

    /* Если индекс не построен (OOM при init) — fallback O(n) */
    if (!g_idx.ready)
        goto fallback;

    dns_action_t best = DNS_ACTION_DEFAULT;

    /* 1. Exact lookup: O(log n) */
    {
        dns_action_t act = idx_lookup(g_idx.exact, g_idx.exact_n, qname);
        if (act == DNS_ACTION_BLOCK) return DNS_ACTION_BLOCK;
        if (act != DNS_ACTION_DEFAULT) {
            if (best == DNS_ACTION_DEFAULT || act < best) best = act;
        }
    }

    /* 2. Suffix lookup: проверить каждый уровень домена O(d × log n)
       Для "api.example.com" проверяем: "example.com", "com" */
    {
        const char *p = qname;
        while ((p = strchr(p, '.')) != NULL) {
            p++;  /* шаг за точку */
            if (!*p) break;  /* trailing dot */
            dns_action_t act = idx_lookup(g_idx.suffix,
                                           g_idx.suffix_n, p);
            if (act == DNS_ACTION_BLOCK) return DNS_ACTION_BLOCK;
            if (act != DNS_ACTION_DEFAULT) {
                if (best == DNS_ACTION_DEFAULT || act < best) best = act;
            }
        }
    }

    if (best != DNS_ACTION_DEFAULT)
        return traffic_rules_consult(qname, best);
    return traffic_rules_consult(qname, geosite_check(qname, best));

fallback:; /* OOM path: original O(n) */
    best = DNS_ACTION_DEFAULT;
    for (int i = 0; i < g_rules.count; i++) {
        const char *pat = g_rules.patterns[i];
        dns_action_t act = g_rules.actions[i];
        bool matched = false;
        if (pat[0] == '*' && pat[1] == '.')
            matched = suffix_match(qname, pat + 2);
        else
            matched = (strcmp(qname, pat) == 0);
        if (!matched) continue;
        if (act == DNS_ACTION_BLOCK) return DNS_ACTION_BLOCK;
        if (act < best || best == DNS_ACTION_DEFAULT) best = act;
    }
    if (best != DNS_ACTION_DEFAULT)
        return traffic_rules_consult(qname, best);
    return traffic_rules_consult(qname, geosite_check(qname, best));
}

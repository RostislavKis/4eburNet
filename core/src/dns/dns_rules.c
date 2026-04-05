/*
 * DNS правила маршрутизации — matcher для доменов
 */

#include "dns/dns_rules.h"
#include "phoenix.h"
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

int dns_rules_init(const PhoenixConfig *cfg)
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
    g_rules.actions  = calloc(g_rules.capacity, sizeof(dns_action_t));
    if (!g_rules.patterns || !g_rules.actions) return -1;

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
    return 0;
}

void dns_rules_free(void)
{
    for (int i = 0; i < g_rules.count; i++)
        free(g_rules.patterns[i]);
    free(g_rules.patterns);
    free(g_rules.actions);
    memset(&g_rules, 0, sizeof(g_rules));
}

int dns_rules_load_file(const char *path, dns_action_t action)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[256];
    int loaded = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;

        if (g_rules.count >= g_rules.capacity) {
            int new_cap = g_rules.capacity * 2;
            char **np = realloc(g_rules.patterns, new_cap * sizeof(char*));
            if (!np) break;
            g_rules.patterns = np;
            dns_action_t *na = realloc(g_rules.actions, new_cap * sizeof(dns_action_t));
            if (!na) break;  /* np уже сохранён — нет утечки */
            g_rules.actions = na;
            g_rules.capacity = new_cap;
        }

        char *dup = strdup(line);
        if (!dup) break;  /* OOM — прекратить загрузку */
        g_rules.patterns[g_rules.count] = dup;
        g_rules.actions[g_rules.count] = action;
        g_rules.count++;
        loaded++;
    }
    fclose(f);
    log_msg(LOG_INFO, "DNS правила из %s: %d записей", path, loaded);
    return loaded;
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

dns_action_t dns_rules_match(const char *qname)
{
    /* Приоритет: block > bypass > proxy > default
     * TODO v2: разделить exact/wildcard, qsort+bsearch для exact (M-29).
     * Текущий O(n) допустим при count < 10K, при 300K+ нужна оптимизация. */
    dns_action_t best = DNS_ACTION_DEFAULT;

    for (int i = 0; i < g_rules.count; i++) {
        const char *pat = g_rules.patterns[i];
        dns_action_t act = g_rules.actions[i];

        bool matched = false;
        if (pat[0] == '*' && pat[1] == '.') {
            /* Wildcard: *.example.com */
            matched = suffix_match(qname, pat + 2);
        } else {
            /* Точное совпадение */
            matched = (strcmp(qname, pat) == 0);
        }

        if (!matched) continue;

        /* Приоритет: block(2) > bypass(0) > proxy(1) > default(3) */
        if (act == DNS_ACTION_BLOCK) return DNS_ACTION_BLOCK;
        if (act < best || best == DNS_ACTION_DEFAULT) best = act;
    }

    return best;
}

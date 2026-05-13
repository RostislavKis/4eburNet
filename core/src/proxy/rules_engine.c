/*
 * Rules engine — matching трафика и выбор целевой группы/действия
 * DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / RULE-SET / MATCH / AND
 *
 * C-4: RULE_SET загружается в память при init (не fopen на каждый запрос).
 * Binary search O(log n) по доменам.
 */

#include "proxy/rules_engine.h"
#include "4eburnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <regex.h>
#include <stdatomic.h>

/* WHY: config.yaml содержит 34 rule-providers; 16 → 18 не загружаются.
 * 64 = разумный максимум с запасом на рост. */
#define MAX_PROVIDER_CACHE 64

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

/* Сортировка по priority ASC (Clash convention).
 *
 * Clash / mihomo / sing-box convention: первое правило в YAML имеет
 * МЕНЬШИЙ priority (обычно 200) и проверяется первым; catch-all (MATCH)
 * имеет БОЛЬШИЙ priority (231) и проверяется последним. sub_convert.py
 * при генерации UCI использует эту семантику напрямую: traffic_rule[0]
 * получает priority=200, последующие инкрементируются.
 *
 * rules_engine_match() линейно сканирует sorted_rules и возвращает
 * первое совпадение — значит первое правило в массиве после sort
 * должно быть самым специфичным, последнее — catch-all. Это ASC sort.
 *
 * Инвариант: MATCH catch-all (priority=231 в стандартном UCI от
 * sub_convert.py) должен быть ПОСЛЕДНИМ элементом массива после qsort,
 * иначе все более специфичные правила станут мёртвым кодом. */
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

/* WHY: Clash YAML rule-provider payload строки вида "  - 'domain.com'" или
 * "  - +.domain.com" — убрать ведущие пробелы, тире, кавычки.
 * Ref: mihomo proxy/provider/rule_provider.go parseRules() */
static const char *strip_yaml_entry(const char *line, char *buf, size_t bufsz)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (p[0] == '-') { p++; while (*p == ' ') p++; }
    if (*p == '\'' || *p == '"') p++;
    size_t i = 0;
    while (*p && *p != '\'' && *p != '"' && *p != '\n' && *p != '\r'
           && i < bufsz - 1)
        buf[i++] = *p++;
    buf[i] = '\0';
    return buf;
}

/* Загрузить файл правил в массив строк.
 * Поддерживает plain text (один домен/CIDR на строку)
 * и Clash YAML payload: формат. */
static int load_file_entries(const char *path, char ***out_entries, int *out_count)
{
    int fd_file = open(path, O_RDONLY | O_CLOEXEC);
    FILE *f = (fd_file >= 0) ? fdopen(fd_file, "r") : NULL;
    if (!f) {
        if (fd_file >= 0) close(fd_file);
        return -1;
    }

    /* Определить формат по первым строкам: YAML если есть "payload:" */
    bool is_yaml = false;
    char line[512];
    for (int i = 0; i < 5 && fgets(line, sizeof(line), f); i++) {
        if (strncmp(line, "payload:", 8) == 0) { is_yaml = true; break; }
    }
    rewind(f);

    int capacity = 256;
    int count = 0;
    char **entries = malloc((size_t)capacity * sizeof(char *));
    if (!entries) { fclose(f); return -1; }

    bool in_payload = !is_yaml;
    char stripped[256];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;

        const char *domain;
        if (is_yaml) {
            if (strncmp(line, "payload:", 8) == 0) { in_payload = true; continue; }
            if (!in_payload) continue;
            if (line[0] != ' ' && line[0] != '\t') break;  /* конец payload блока */
            domain = strip_yaml_entry(line, stripped, sizeof(stripped));
        } else {
            domain = line;
        }
        if (!domain || !domain[0]) continue;

        /* Clash classical format: "DOMAIN,host.com" / "DOMAIN-SUFFIX,host.com"
         * / "IP-CIDR,1.2.3.0/24" — убрать тип правила до запятой. */
        const char *comma = strchr(domain, ',');
        if (comma) {
            size_t type_len = (size_t)(comma - domain);
            /* Пропустить неподдерживаемые типы */
            if ((type_len == 12 && strncmp(domain, "PROCESS-NAME", 12) == 0) ||
                (type_len == 6  && strncmp(domain, "IP-ASN",       6)  == 0) ||
                (type_len == 14 && strncmp(domain, "DOMAIN-KEYWORD",14)== 0))
                continue;
            domain = comma + 1;
            while (*domain == ' ') domain++;
        }
        if (!domain[0]) continue;

        /* WHY: +.example.com = *.example.com = suffix match для example.com.
         * Clash convention: strip prefix, suffix_match() сработает через O(n). */
        if (domain[0] == '+' && domain[1] == '.') domain += 2;
        else if (domain[0] == '*' && domain[1] == '.') domain += 2;
        if (!domain[0]) continue;

        if (count >= capacity) {
            capacity *= 2;
            char **tmp = realloc(entries, (size_t)capacity * sizeof(char *));
            if (!tmp) break;
            entries = tmp;
        }
        entries[count] = strdup(domain);
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

/* Загрузить провайдер в кэш.
 * hint_format: RULE_FORMAT_DOMAIN / RULE_FORMAT_IPCIDR → явная типизация;
 *              RULE_FORMAT_CLASSICAL → автоопределение по первой строке. */
static provider_cache_t *cache_load(const char *provider_name,
                                     rule_provider_manager_t *rpm,
                                     rule_format_t hint_format)
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

    /* Определить тип: явный hint_format приоритетнее автоопределения */
    if (hint_format == RULE_FORMAT_DOMAIN) {
        pc->is_domain = true;
    } else if (hint_format == RULE_FORMAT_IPCIDR) {
        pc->is_domain = false;
    } else {
        /* RULE_FORMAT_CLASSICAL или неизвестен → автоопределение */
        pc->is_domain = true;
        if (pc->count > 0 && strchr(pc->entries[0], '/'))
            pc->is_domain = false;
    }

    /* Сортировать для binary search (только домены) */
    if (pc->is_domain)
        qsort(pc->entries, pc->count, sizeof(char *), cmp_str);

    s_cache_count++;
    log_msg(LOG_DEBUG, "Rules cache: %s загружен (%d записей, %s)",
            provider_name, pc->count,
            pc->is_domain ? "domain" : "cidr");
    return pc;
}

int rules_engine_init(rules_engine_t *re, const EburNetConfig *cfg,
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

    /* C-4: загрузить RULE_SET провайдеры в кэш с format из конфига */
    for (int i = 0; i < re->rule_count; i++) {
        if (re->sorted_rules[i].type != RULE_TYPE_RULE_SET) continue;

        /* Найти format в RuleProviderConfig для точной типизации */
        rule_format_t fmt = RULE_FORMAT_CLASSICAL;
        if (rpm && rpm->cfg) {
            for (int j = 0; j < rpm->cfg->rule_provider_count; j++) {
                if (strcmp(rpm->cfg->rule_providers[j].name,
                           re->sorted_rules[i].value) == 0) {
                    fmt = rpm->cfg->rule_providers[j].format;
                    break;
                }
            }
        }
        cache_load(re->sorted_rules[i].value, rpm, fmt);
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

    /* Суффикс-поиск O(n) — приемлемо при n < 50K (~5мс на MIPS).
     * При GeoSite 300K+ → patricia trie из geo_loader.c (DEC-031) */
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

/*
 * Сопоставить домен/IP с правилами маршрутизации (sorted по приоритету).
 * Почему линейный обход: правила отсортированы при загрузке, первое
 * совпадение — наивысший приоритет. O(n) допустим при n < 5000.
 *
 * proto: IPPROTO_TCP(6)/IPPROTO_UDP(17)/0(неизвестно)
 * dport: порт назначения (0 если неизвестно — AND+NETWORK правила не матчатся)
 * sport: порт источника (0 если неизвестен — SRC-PORT не матчится)
 * proc_name: имя процесса (NULL/"" — PROCESS-NAME не матчится)
 */
rule_match_result_t rules_engine_match(rules_engine_t *re,
                                       const char *domain,
                                       const struct sockaddr_storage *dst,
                                       uint8_t  proto,
                                       uint16_t dport,
                                       uint16_t sport,
                                       const char *proc_name)
{
    for (int i = 0; i < re->rule_count; i++) {
        TrafficRule *tr = &re->sorted_rules[i];
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
        case RULE_TYPE_DST_PORT:
            /* WHY port_min/port_max: strtoul("50000-65535") = 50000.
             * config.c заполняет port_min/port_max при парсинге value. */
            if (dport > 0) {
                uint16_t lo = tr->port_min ? tr->port_min
                                           : (uint16_t)strtoul(tr->value, NULL, 10);
                uint16_t hi = tr->port_max ? tr->port_max : lo;
                if (dport >= lo && dport <= hi)
                    matched = true;
            }
            break;
        case RULE_TYPE_SRC_PORT:
            /* WHY sport==0: порт источника недоступен (DNS запрос, inbound без src).
             * Не матчить — во избежание ложных срабатываний. */
            if (sport > 0) {
                uint16_t lo = tr->port_min ? tr->port_min
                                           : (uint16_t)strtoul(tr->value, NULL, 10);
                uint16_t hi = tr->port_max ? tr->port_max : lo;
                if (sport >= lo && sport <= hi)
                    matched = true;
            }
            break;
        case RULE_TYPE_PROCESS_NAME:
            /* WHY case-insensitive: имена процессов могут различаться (wget/WGET).
             * Substring match: "python" матчит "python3". */
            if (proc_name && proc_name[0] && tr->value[0]) {
                if (strcasecmp(proc_name, tr->value) == 0 ||
                    strcasestr(proc_name, tr->value) != NULL)
                    matched = true;
            }
            break;
        case RULE_TYPE_AND: {
            /* WHY: AND требует совпадения NETWORK (proto) И DST-PORT (диапазон).
             * network==0 → любой протокол; dport==0 → AND с портом не матчится.
             * Ref: Clash AND,((NETWORK,TCP),(DST-PORT,50000-65535)),DIRECT */
            bool match_net  = (tr->network == 0 || tr->network == proto);
            bool match_port = true;
            if (tr->port_min > 0) {
                match_port = (dport > 0 &&
                              dport >= tr->port_min &&
                              dport <= tr->port_max);
            }
            if (match_net && match_port)
                matched = true;
            break;
        }
        case RULE_TYPE_OR: {
            /* OR: short-circuit — совпадение при первом подходящем sub_rule.
             * WHY: OR,((DOMAIN-SUFFIX,.google.com),(DOMAIN-SUFFIX,.yt.be)),PROXY
             * позволяет группировать условия без дублирования target. */
            if (!tr->sub_rules || tr->sub_count == 0) break;
            for (uint8_t si = 0; si < tr->sub_count && !matched; si++) {
                const TrafficRule *sub = &tr->sub_rules[si];
                switch (sub->type) {
                case RULE_TYPE_DOMAIN:
                    if (domain && strcmp(domain, sub->value) == 0)
                        matched = true;
                    break;
                case RULE_TYPE_DOMAIN_SUFFIX:
                    if (domain && suffix_match(domain, sub->value))
                        matched = true;
                    break;
                case RULE_TYPE_DOMAIN_KEYWORD:
                    if (domain && strstr(domain, sub->value))
                        matched = true;
                    break;
                case RULE_TYPE_IP_CIDR:
                case RULE_TYPE_IP_CIDR6:
                    if (dst && cidr_match(dst, sub->value))
                        matched = true;
                    break;
                case RULE_TYPE_GEOIP:
                    if (re->gm && dst) {
                        geo_region_t gr   = geo_match_ip(re->gm, dst);
                        geo_region_t want = geo_region_from_str(sub->value);
                        if (gr == want && want != GEO_REGION_UNKNOWN)
                            matched = true;
                    }
                    break;
                case RULE_TYPE_GEOSITE:
                    if (re->gm && domain) {
                        geo_region_t gr   = geo_match_domain(re->gm, domain);
                        geo_region_t want = geo_region_from_str(sub->value);
                        if (gr == want && want != GEO_REGION_UNKNOWN)
                            matched = true;
                    }
                    break;
                default:
                    break;
                }
            }
            break;
        }
        case RULE_TYPE_REGEX: {
            /* POSIX extended regex (REG_ICASE) против domain.
             * WHY: compile при загрузке конфига → regexec() не компилирует.
             * compiled_re == NULL → graceful skip (плохой паттерн — не крашит). */
            if (!tr->compiled_re || !domain || !domain[0]) break;
            if (regexec((const regex_t *)tr->compiled_re,
                        domain, 0, NULL, 0) == 0)
                matched = true;
            break;
        }
        default:
            break;
        }

        if (matched) {
            atomic_fetch_add(&tr->hit_count, 1);
            log_msg(LOG_DEBUG, "Rules: matched %s → %s",
                    tr->value[0] ? tr->value : "MATCH", tr->target);
            rule_match_result_t r = make_result(tr->target);
            r.matched_rule_type = (int)tr->type;
            snprintf(r.matched_payload, sizeof(r.matched_payload),
                     "%s", tr->value[0] ? tr->value : "MATCH");
            return r;
        }
    }

    /* Нет совпадений → DIRECT */
    rule_match_result_t direct = {
        .type = RULE_TARGET_DIRECT,
        .matched_rule_type = -1,
    };
    snprintf(direct.matched_payload, sizeof(direct.matched_payload),
             "(no-match)");
    return direct;
}

int rules_engine_get_server(rules_engine_t *re,
                            const char *domain,
                            const struct sockaddr_storage *dst,
                            uint8_t  proto,
                            uint16_t dport,
                            uint16_t sport,
                            const char *proc_name)
{
    rule_match_result_t r = rules_engine_match(re, domain, dst, proto, dport,
                                               sport, proc_name);

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
    default:
        break;
    }
    return -1;
}

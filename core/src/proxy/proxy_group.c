/*
 * Proxy groups — выбор сервера по политике
 * SELECT / URL_TEST / FALLBACK / LOAD_BALANCE
 */

#include "proxy/proxy_group.h"
#include "proxy/hc_vless.h"
#include "net_utils.h"
#include "4eburnet.h"
#include "constants.h"
#include "resource_manager.h"
#include <regex.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <limits.h>
#include <sys/stat.h>

/* Persistent selection storage */
#define SELECTED_JSON_PATH  "/etc/4eburnet/selected.json"
#define SELECTED_JSON_MAX   4096

/* Минимальный JSON-парсер: ищет "key":"value" (UTF-8 as-is, без surrogate pairs) */
static size_t pgm_json_get_str(const char *json, const char *key,
                                char *out, size_t out_sz)
{
    if (!json || !key || !out || out_sz == 0) return 0;
    out[0] = '\0';
    char pat[128];
    int pn = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (pn <= 0 || (size_t)pn >= sizeof(pat)) return 0;
    const char *s = strstr(json, pat);
    if (!s) return 0;
    s += (size_t)pn;
    while (*s == ' ' || *s == '\t') s++;
    if (*s != ':') return 0;
    s++;
    while (*s == ' ' || *s == '\t') s++;
    if (*s != '"') return 0;
    s++;
    size_t i = 0;
    while (*s && i < out_sz - 1) {
        if (*s == '"') break;
        if (*s == '\\' && *(s + 1)) { s++; }  /* skip escape prefix */
        out[i++] = *s++;
    }
    out[i] = '\0';
    return i;
}

/* Записать "key":"value" в dst с escape " и \ в обоих полях.
 * Возвращает число записанных байт. */
static int pgm_json_write_kv(char *dst, int max,
                               const char *key, const char *val)
{
    int pos = 0;
    if (pos < max - 1) dst[pos++] = '"';
    for (const char *c = key; *c && pos < max - 2; c++) {
        if (*c == '"' || *c == '\\') { dst[pos++] = '\\'; }
        if (pos < max - 1) dst[pos++] = *c;
    }
    if (pos < max - 3) { dst[pos++] = '"'; dst[pos++] = ':'; dst[pos++] = '"'; }
    for (const char *c = val; *c && pos < max - 2; c++) {
        if (*c == '"' || *c == '\\') { dst[pos++] = '\\'; }
        if (pos < max - 1) dst[pos++] = *c;
    }
    if (pos < max - 1) dst[pos++] = '"';
    return pos;
}

/* Восстановить selected_idx SELECT-группы из SELECTED_JSON_PATH.
 * Вызывается после начального выбора — overrides автовыбор по transport. */
static void pgm_restore_selection(proxy_group_state_t *gs,
                                   const EburNetConfig *cfg)
{
    FILE *f = fopen(SELECTED_JSON_PATH, "r");
    if (!f) return;
    char buf[SELECTED_JSON_MAX];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) return;
    buf[n] = '\0';

    char saved[256] = {0};
    if (!pgm_json_get_str(buf, gs->name, saved, sizeof(saved)) || !saved[0]) return;

    for (int i = 0; i < gs->server_count; i++) {
        const ServerConfig *sc = config_get_server(cfg, gs->servers[i].server_idx);
        if (sc && strcmp(sc->name, saved) == 0) {
            gs->selected_idx = i;
            gs->pinned        = true;
            log_msg(LOG_INFO,
                "proxy_group %s: восстановлен выбор [%d] '%s' (pinned)",
                gs->name, i, saved);
            return;
        }
    }
    log_msg(LOG_WARN,
        "proxy_group %s: сохранённый сервер '%s' не найден в группе",
        gs->name, saved);
}

/* Вычислить глобальный лимит HC children по MemAvailable.
 * WHY: фиксированный лимит не учитывает разные устройства.
 * EC330 (116MB, ~14MB свободно при старте) → OOM при 16 × wolfSSL fork.
 * Flint2 (512MB) → может держать 32+ параллельных HC без проблем.
 * Формула: limit = max(2, min(free_ram_mb / 4, 32))
 * 4MB на fork = wolfSSL (~1MB) + стек + буферы + overhead. */
static int compute_hc_limit(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return PROXY_GROUP_GLOBAL_HC_LIMIT_DEFAULT;
    char line[128];
    long avail_kb = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "MemAvailable:", 13) == 0) {
            sscanf(line + 13, "%ld", &avail_kb);
            break;
        }
    }
    fclose(f);
    int avail_mb = (int)(avail_kb / 1024);
    /* WHY /8: OOM данные EC330 → каждый fork занимает ~5MB anon-rss (wolfSSL + стек).
     * Было /4 → 70MB MemAvailable = 17 форков → OOM. С /8: 70MB = 8 форков = 40MB
     * peak HC usage → безопасно. Cap=12: потолок даже на мощных роутерах (PIPE_SLOTS). */
    int limit = avail_mb / 8;
    if (limit < 2)  limit = 2;
    if (limit > 12) limit = 12;
    log_msg(LOG_INFO, "proxy_group: HC лимит = %d (MemAvailable=%dMB)",
            limit, avail_mb);
    return limit;
}

/* Найти индекс сервера по имени в cfg->servers[] */
static int find_server_by_name(const EburNetConfig *cfg, const char *name)
{
    for (int i = 0; i < cfg->server_count; i++)
        if (strcmp(cfg->servers[i].name, name) == 0)
            return i;
    return -1;
}

/* WHY: нереализованные транспорты (udp/QUIC для Hysteria2) пропускаются
 * при HC и начальном выборе — избегаем UINT32_MAX latency.
 * Централизованный helper чтобы не дублировать условие в 3 местах.
 * Реализованы: tcp/raw/reality (T0-01/02), grpc (T0-03), ws (T0-04),
 * xhttp (T0-05), httpupgrade (T0-06). */
static bool transport_is_implemented(const char *t)
{
    if (!t || !t[0])              return true;   /* raw/tcp */
    if (strcmp(t, "reality") == 0) return true;
    if (strcmp(t, "raw")     == 0) return true;
    if (strcmp(t, "tcp")     == 0) return true;
    if (strcmp(t, "grpc")    == 0) return true;  /* T0-03 */
    if (strcmp(t, "ws")          == 0) return true;  /* T0-04 */
    /* WHY xhttp/httpupgrade временно исключены из url-test:
     * HC через TCP ping показывает быстрый handshake (937ms к Switzerland),
     * url-test выбирает их как "лучшие" по latency. Но реальный throughput
     * H2-framed HTTP transport на mipsel хуже Trojan gRPC / Reality VLESS TCP.
     * Наблюдалось: GEMINI selected=Switzerland XHTTP → 23 Kbps fall (3 sec
     * YouTube buffer затем стоп). Trojan/Reality дают 100+ Kbps.
     * До переработки HC на честный throughput-test — пропускаем XHTTP. */
    if (strcmp(t, "xhttp")       == 0) return false;  /* T0-05 — отложено */
    if (strcmp(t, "httpupgrade") == 0) return false;  /* T0-06 — отложено */
    /* WHY: hysteria2/hy2 исключён из url-test групп.
     * HC для Hysteria2 требует QUIC handshake (UDP + H3 auth) — принципиально
     * отличается от TCP-based HC. child_do_hc_vless_hysteria2 не реализован
     * (T0-08, backlog). До реализации: Hy2 серверы в select-группах работают,
     * но в url-test пропускаются (penalty не начисляется, latency = N/A). */
    if (strcmp(t, "hysteria2") == 0) return false;  /* T0-08: QUIC HC не реализован */
    if (strcmp(t, "hy2")       == 0) return false;  /* T0-08: алиас */
    return false;
}

/* HC stagger window: при первом запуске все url-test группы стартуют HC
 * в течение этого окна. WHY: 4 url-test × 8 серверов = 32 fork → конкуренция
 * за PROXY_GROUP_GLOBAL_HC_LIMIT (16) при одновременном старте → первый
 * HC цикл удваивается по latency, selected_idx не выставляется ~120с.
 * 45 сек делит окно равномерно: 4 группы → slots 0/11/22/33 сек. */
#define HC_STAGGER_WINDOW_SEC 45u

int proxy_group_init(proxy_group_manager_t *pgm, const EburNetConfig *cfg,
                     bool first_start)
{
    memset(pgm, 0, sizeof(*pgm));
    pgm->cfg = cfg;
    pgm->hc_global_limit = compute_hc_limit();
    if (cfg->proxy_group_count == 0) return 0;

    /* M-07: считаем только enabled группы */
    int enabled = 0;
    for (int g = 0; g < cfg->proxy_group_count; g++)
        if (cfg->proxy_groups[g].enabled) enabled++;
    if (enabled == 0) return 0;

    pgm->groups = calloc(enabled, sizeof(proxy_group_state_t));
    if (!pgm->groups) return -1;

    /* Подсчёт enabled url-test групп для stagger расчёта (только при первом старте) */
    int url_test_total = 0;
    int url_test_idx = 0;
    if (first_start) {
        for (int g = 0; g < cfg->proxy_group_count; g++) {
            const ProxyGroupConfig *gc = &cfg->proxy_groups[g];
            if (gc->enabled && gc->type == PROXY_GROUP_URL_TEST)
                url_test_total++;
        }
    }

    for (int g = 0; g < cfg->proxy_group_count; g++) {
        const ProxyGroupConfig *gc = &cfg->proxy_groups[g];
        if (!gc->enabled) continue;
        proxy_group_state_t *gs = &pgm->groups[pgm->count];

        {   int _n = snprintf(gs->name, sizeof(gs->name), "%s", gc->name);
            if (_n < 0 || (size_t)_n >= sizeof(gs->name))
                log_msg(LOG_DEBUG, "snprintf truncated (non-critical): %s:%d", __FILE__, __LINE__);
        }
        gs->type = gc->type;
        {   int _n = snprintf(gs->test_url, sizeof(gs->test_url), "%s", gc->url);
            if (_n < 0 || (size_t)_n >= sizeof(gs->test_url))
                log_msg(LOG_DEBUG, "snprintf truncated (non-critical): %s:%d", __FILE__, __LINE__);
        }
        gs->timeout_ms = gc->timeout_ms > 0 ? gc->timeout_ms : 5000;
        /* Ограничить таймаут по профилю — защита event loop */
        {
            int max_ms;
            DeviceProfile prof = rm_detect_profile();
            switch (prof) {
            case DEVICE_MICRO:   max_ms = 1000; break;
            case DEVICE_NORMAL:  max_ms = 2000; break;
            default:             max_ms = 5000; break;
            }
            if (gs->timeout_ms > max_ms) {
                log_msg(LOG_WARN,
                    "proxy_group[%s]: timeout_ms %d > лимита %d, обрезан",
                    gs->name, gs->timeout_ms, max_ms);
                gs->timeout_ms = max_ms;
            }
        }
        gs->tolerance_ms = gc->tolerance_ms;
        gs->interval = gc->interval > 0 ? gc->interval : 300;
        /* WHY: при старте selected_idx=0 (первый сервер по алфавиту провайдера).
         * Без немедленного HC демон роутит трафик через него пока идёт первый
         * раунд (~60-120с). next_check=now запускает HC на первом же тике.
         *
         * KB-3 stagger: при first_start=true url-test группы получают
         * offset (0..HC_STAGGER_WINDOW_SEC) — иначе все 4 группы fork-ают
         * HC одновременно и конкурируют за hc_global_limit (16 слотов).
         * Reload (first_start=false) → next_check=now без stagger,
         * предположение: на reload HC уже отрабатывал, малая гонка приемлема. */
        time_t now_init = time(NULL);
        if (first_start && gs->type == PROXY_GROUP_URL_TEST
            && url_test_total > 1) {
            uint32_t offset_sec =
                (uint32_t)url_test_idx * HC_STAGGER_WINDOW_SEC
                / (uint32_t)url_test_total;
            gs->next_check = now_init + (time_t)offset_sec;
            log_msg(LOG_INFO,
                "proxy_group '%s': HC старт через %us (stagger slot %d/%d)",
                gs->name, offset_sec, url_test_idx + 1, url_test_total);
            url_test_idx++;
        } else {
            gs->next_check = now_init;
        }

        /* Итерировать массив серверов группы */
        int total_configured = 0;
        for (int si = 0; si < gc->server_count; si++) {
            const char *tok = gc->servers[si];
            int idx = find_server_by_name(cfg, tok);
            if (idx >= 0) {
                if (gs->server_count < PROXY_GROUP_MAX_SERVERS) {
                    gs->servers[gs->server_count].server_idx = idx;
                    /* WHY available=true до первого HC: mihomo показывает
                     * непротестированные серверы как alive — иначе zashboard
                     * прячет 70+ серверов на ~30 минут пока HC ползёт по
                     * 8 параллельных слотов × 10 раундов. available=false
                     * выставляется только после fail_count>=3 (handle_hc_event
                     * + mark_server_fail), что сохраняет защиту от broken
                     * серверов после реальных провалов HC. */
                    gs->servers[gs->server_count].available = true;
                    gs->servers[gs->server_count].latency_ms = UINT32_MAX;
                    gs->server_count++;
                } else if (total_configured == PROXY_GROUP_MAX_SERVERS) {
                    log_msg(LOG_WARN,
                        "Группа %s: превышен лимит %d серверов",
                        gs->name, PROXY_GROUP_MAX_SERVERS);
                }
                total_configured++;
            } else {
                log_msg(LOG_WARN, "Группа %s: сервер '%s' не найден", gs->name, tok);
            }
        }

        /* Добавить серверы из провайдеров (use: + filter) */
        if (gc->providers && gc->providers[0]) {
            /* Filter: попытаться POSIX ERE, fallback на exclude-list */
            regex_t fre;
            bool use_regex = false;
            bool use_exclude = false;
            char *exclude_words[64];
            int exclude_count = 0;

            memset(exclude_words, 0, sizeof(exclude_words));

            if (gc->filter[0]) {
                if (regcomp(&fre, gc->filter, REG_EXTENDED | REG_NOSUB) == 0) {
                    use_regex = true;
                } else {
                    /* Fallback: извлечь exclude-слова из (?!.*(w1|w2|...))
                     * Ищем самую внутреннюю группу (w1|w2|...) и split по | */
                    const char *inner = NULL;
                    int depth = 0, max_depth = 0;
                    for (const char *p = gc->filter; *p; p++) {
                        if (*p == '(') {
                            depth++;
                            if (depth > max_depth) {
                                max_depth = depth;
                                inner = p + 1;
                            }
                        } else if (*p == ')') {
                            depth--;
                        }
                    }
                    if (inner) {
                        /* Копируем содержимое внутренних скобок, split по | */
                        const char *end = strchr(inner, ')');
                        if (!end) end = inner + strlen(inner);
                        size_t ilen = (size_t)(end - inner);
                        char *ibuf = malloc(ilen + 1);
                        if (ibuf) {
                            memcpy(ibuf, inner, ilen);
                            ibuf[ilen] = '\0';
                            char *sp2 = NULL;
                            for (char *w = strtok_r(ibuf, "|", &sp2); w;
                                 w = strtok_r(NULL, "|", &sp2)) {
                                if (w[0] && exclude_count < 64) {
                                    char *ew = strdup(w);
                                    if (!ew) {
                                        log_msg(LOG_ERROR, "proxy_group: нет памяти для exclude word");
                                        break;
                                    }
                                    exclude_words[exclude_count++] = ew;
                                }
                            }
                            free(ibuf);
                        }
                    }
                    if (exclude_count > 0) {
                        use_exclude = true;
                        log_msg(LOG_DEBUG, "Группа %s: filter → %d exclude слов",
                                gc->name, exclude_count);
                    }
                }
            }

            char *pcopy = strdup(gc->providers);
            if (!pcopy) {
                log_msg(LOG_ERROR, "proxy_group: нет памяти для providers copy");
                continue;
            }
            char *sp = NULL;
            for (char *pn = strtok_r(pcopy, " ", &sp); pn;
                 pn = strtok_r(NULL, " ", &sp)) {
                for (int pi = 0; pi < cfg->provider_server_count; pi++) {
                    const ServerConfig *ps = &cfg->provider_servers[pi];
                    if (strcmp(ps->source_provider, pn) != 0) continue;
                    /* Применить filter */
                    if (use_regex &&
                        regexec(&fre, ps->name, 0, NULL, 0) != 0) continue;
                    if (use_exclude) {
                        bool excluded = false;
                        for (int ei = 0; ei < exclude_count; ei++) {
                            if (strstr(ps->name, exclude_words[ei])) {
                                excluded = true; break;
                            }
                        }
                        if (excluded) continue;
                    }
                    if (gs->server_count >= PROXY_GROUP_MAX_SERVERS) break;
                    gs->servers[gs->server_count].server_idx =
                        cfg->server_count + pi;
                    /* available=true до HC — см. WHY выше */
                    gs->servers[gs->server_count].available = true;
                    gs->servers[gs->server_count].latency_ms = UINT32_MAX;
                    gs->server_count++;
                }
            }
            free(pcopy);
            if (use_regex) regfree(&fre);
            for (int ei = 0; ei < exclude_count; ei++) free(exclude_words[ei]);
        }

        /* SELECT: при старте выбрать первый рабочий сервер.
         * WHY: servers[0] из UCI часто = Trojan gRPC (первый в конфиге),
         * транспорт не реализован → трафик падает молча с первого запуска.
         * Выбираем первый сервер с реализованным транспортом. */
        if (gs->type == PROXY_GROUP_SELECT && gs->server_count > 0) {
            gs->selected_idx = 0;
            for (int _j = 0; _j < gs->server_count; _j++) {
                const ServerConfig *_s = config_get_server(cfg, gs->servers[_j].server_idx);
                if (!_s) continue;
                if (transport_is_implemented(_s->transport)) {
                    gs->selected_idx = _j;
                    log_msg(LOG_INFO,
                        "proxy_group %s: начальный выбор [%d] %s (transport=%s)",
                        gs->name, _j, _s->name,
                        _s->transport[0] ? _s->transport : "tcp");
                    break;
                }
            }
            /* Восстановить persistent выбор поверх автовыбора по transport */
            pgm_restore_selection(gs, cfg);
        }

        /* URL_TEST: восстановить ручной pinned-выбор из selected.json */
        if (gs->type == PROXY_GROUP_URL_TEST && gs->server_count > 0)
            pgm_restore_selection(gs, cfg);

        /* WHY: -1 = свободный слот; проверяется в tick и owns_fd */
        for (int s = 0; s < PROXY_GROUP_HC_SLOTS; s++)
            gs->hc_slots[s].pipe_fd = -1;
        gs->hc_active = 0;

        log_msg(LOG_DEBUG, "Группа %s: тип %d, %d серверов",
                gs->name, gs->type, gs->server_count);
        pgm->count++;
    }

    log_msg(LOG_INFO, "Proxy groups: %d загружено", pgm->count);
    return 0;
}

/* Повторно применить persistent выбор для SELECT-групп у которых selected_idx==0.
 * Вызывается из proxy_provider_handle_fetch после успешного async retry.
 * Сценарий: провайдер не загрузился при старте (кэш отсутствовал, DNS не готов) →
 * group.server_count=0 при proxy_group_init → pgm_restore_selection не нашла сервер.
 * После retry serversзаполнены в cfg→ перебираем SELECT-группы с пустым выбором.
 * Guard: selected_idx>0 означает что сервер уже выбран (вручную или при старте). */
void proxy_group_restore_all_selections(proxy_group_manager_t *pgm)
{
    if (!pgm) return;
    for (int i = 0; i < pgm->count; i++) {
        proxy_group_state_t *gs = &pgm->groups[i];
        if (gs->type != PROXY_GROUP_SELECT && gs->type != PROXY_GROUP_URL_TEST) continue;
        if (gs->selected_idx > 0 || gs->pinned) continue;
        pgm_restore_selection(gs, pgm->cfg);
    }
}

void proxy_group_free(proxy_group_manager_t *pgm)
{
    for (int i = 0; i < pgm->count; i++) {
        for (int s = 0; s < PROXY_GROUP_HC_SLOTS; s++) {
            if (pgm->groups[i].hc_slots[s].pipe_fd >= 0) {
                close(pgm->groups[i].hc_slots[s].pipe_fd);
                pgm->groups[i].hc_slots[s].pipe_fd = -1;
            }
        }
        pgm->groups[i].hc_active = 0;
    }
    free(pgm->groups);
    memset(pgm, 0, sizeof(*pgm));
}

proxy_group_state_t *proxy_group_find(proxy_group_manager_t *pgm, const char *name)
{
    for (int i = 0; i < pgm->count; i++)
        if (strcmp(pgm->groups[i].name, name) == 0)
            return &pgm->groups[i];
    return NULL;
}

int proxy_group_select_server(proxy_group_manager_t *pgm, const char *group_name)
{
    proxy_group_state_t *g = proxy_group_find(pgm, group_name);
    if (!g || g->server_count == 0) return -1;

    /* WHY: AWG = VPN туннель (один на весь интерфейс), нельзя создавать отдельный
     * AWG handshake на каждое TCP соединение (Telegram, YouTube и т.д.).
     * AWG серверы допустимы только в "AWG Group" (type=select). */
    bool skip_awg = pgm->cfg && strcmp(group_name, "AWG Group") != 0;

    switch (g->type) {
    case PROXY_GROUP_SELECT: {
        /* WHY: pg_select_rotate обновляет selected_idx при N сбоях.
         * Между сбоем и ротацией selected может указывать на unavailable — найти первый доступный. */
        int _sel = g->selected_idx;
        bool _sel_ok = _sel >= 0 && _sel < g->server_count && g->servers[_sel].available;
        if (_sel_ok && skip_awg) {
            const ServerConfig *_sc = config_get_server(pgm->cfg,
                                                         g->servers[_sel].server_idx);
            if (_sc && strcmp(_sc->protocol, "awg") == 0) _sel_ok = false;
        }
        if (!_sel_ok) {
            for (int _j = 0; _j < g->server_count; _j++) {
                if (!g->servers[_j].available) continue;
                if (skip_awg) {
                    const ServerConfig *_sc = config_get_server(pgm->cfg,
                                                                 g->servers[_j].server_idx);
                    if (_sc && strcmp(_sc->protocol, "awg") == 0) continue;
                }
                _sel = _j;
                break;
            }
        }
        return (_sel >= 0 && _sel < g->server_count)
            ? g->servers[_sel].server_idx
            : g->servers[0].server_idx;
    }

    case PROXY_GROUP_URL_TEST: {
        int chosen = -1;
        uint32_t best_lat = UINT32_MAX;
        for (int i = 0; i < g->server_count; i++) {
            if (!g->servers[i].available) continue;
            if (skip_awg) {
                const ServerConfig *_sc = config_get_server(pgm->cfg,
                                                             g->servers[i].server_idx);
                if (_sc && strcmp(_sc->protocol, "awg") == 0) continue;
            }
            if (g->servers[i].latency_ms < best_lat) {
                best_lat = g->servers[i].latency_ms;
                chosen = i;
            }
        }
        if (chosen >= 0) return g->servers[chosen].server_idx;
        /* WHY: пока HC не измерил серверы (все latency=0), не зависать на servers[0].
         * Round-robin по available серверам — хуже не будет чем всегда Canada. */
        for (int i = 0; i < g->server_count; i++) {
            int idx = (g->rr_idx + i) % g->server_count;
            if (!g->servers[idx].available) continue;
            if (skip_awg) {
                const ServerConfig *_sc = config_get_server(pgm->cfg,
                                                             g->servers[idx].server_idx);
                if (_sc && strcmp(_sc->protocol, "awg") == 0) continue;
            }
            g->rr_idx = (idx + 1) % g->server_count;
            return g->servers[idx].server_idx;
        }
        return g->servers[0].server_idx;
    }

    case PROXY_GROUP_FALLBACK:
        for (int i = 0; i < g->server_count; i++) {
            if (!g->servers[i].available) continue;
            if (skip_awg) {
                const ServerConfig *_sc = config_get_server(pgm->cfg,
                                                             g->servers[i].server_idx);
                if (_sc && strcmp(_sc->protocol, "awg") == 0) continue;
            }
            return g->servers[i].server_idx;
        }
        return g->servers[0].server_idx;

    case PROXY_GROUP_LOAD_BALANCE: {
        int avail = 0;
        for (int i = 0; i < g->server_count; i++) {
            if (!g->servers[i].available) continue;
            if (skip_awg) {
                const ServerConfig *_sc = config_get_server(pgm->cfg,
                                                             g->servers[i].server_idx);
                if (_sc && strcmp(_sc->protocol, "awg") == 0) continue;
            }
            avail++;
        }
        if (avail == 0) return g->servers[0].server_idx;
        int target = g->rr_idx % avail;
        g->rr_idx++;
        int count = 0;
        for (int i = 0; i < g->server_count; i++) {
            if (!g->servers[i].available) continue;
            if (skip_awg) {
                const ServerConfig *_sc = config_get_server(pgm->cfg,
                                                             g->servers[i].server_idx);
                if (_sc && strcmp(_sc->protocol, "awg") == 0) continue;
            }
            if (count == target) return g->servers[i].server_idx;
            count++;
        }
        return g->servers[0].server_idx;
    }
    default:
        break;
    }

    return -1;
}

void proxy_group_update_result(proxy_group_manager_t *pgm,
                               const char *group_name,
                               int server_idx, bool success,
                               uint32_t latency_ms)
{
    proxy_group_state_t *g = proxy_group_find(pgm, group_name);
    if (!g) return;
    for (int i = 0; i < g->server_count; i++) {
        if (g->servers[i].server_idx != server_idx) continue;
        if (success) {
            g->servers[i].available = true;
            g->servers[i].latency_ms = latency_ms;
            g->servers[i].fail_count = 0;
        } else {
            g->servers[i].fail_count++;
            if (g->servers[i].fail_count >= 3)
                g->servers[i].available = false;
        }
        g->servers[i].last_check = time(NULL);
        return;
    }
}

/* Количество сбоев HS подряд до автопереключения Selector */
/* WHY 3 (компромисс между 6 и 2): 6 — слишком долгий retry-storm на broken
 * server, demon забивается; 2 — слишком агрессивно, transient сетевой блип
 * исключает рабочий сервер. 3 — успеваем 2 retry перед exclude. */
#define PROXY_GROUP_FAIL_THRESHOLD  3
/* Секунд тишины до восстановления сервера после failover */
#define PROXY_GROUP_RECOVERY_SECS   120

/* Переключить Selector на сервер с наименьшим fail_count (кроме failed_slot) */
static void pg_select_rotate(proxy_group_state_t *gs, int failed_slot,
                             const EburNetConfig *cfg)
{
    int best_slot  = -1;
    uint32_t least = UINT32_MAX;
    for (int j = 1; j < gs->server_count; j++) {
        int idx = (failed_slot + j) % gs->server_count;
        const ServerConfig *sc = config_get_server(cfg, gs->servers[idx].server_idx);
        if (!sc || !transport_is_implemented(sc->transport)) continue;
        if (gs->servers[idx].fail_count < least) {
            least     = gs->servers[idx].fail_count;
            best_slot = idx;
        }
    }
    if (best_slot < 0) return;
    gs->selected_idx = best_slot;
    const ServerConfig *s = config_get_server(cfg, gs->servers[best_slot].server_idx);
    log_msg(LOG_WARN, "proxy_group %s: failover → [%d] %s",
            gs->name, best_slot, s ? s->name : "?");
}

void proxy_group_mark_server_fail(proxy_group_manager_t *pgm, int server_idx)
{
    if (!pgm) return;
    for (int g = 0; g < pgm->count; g++) {
        proxy_group_state_t *gs = &pgm->groups[g];

        if (gs->type == PROXY_GROUP_URL_TEST) {
            for (int i = 0; i < gs->server_count; i++) {
                if (gs->servers[i].server_idx != server_idx) continue;
                gs->servers[i].fail_count++;
                gs->servers[i].last_check = time(NULL);
                if (gs->servers[i].fail_count >= PROXY_GROUP_FAIL_THRESHOLD &&
                    gs->servers[i].available) {
                    gs->servers[i].available = false;
                    const ServerConfig *s = config_get_server(pgm->cfg, server_idx);
                    log_msg(LOG_WARN,
                        "proxy_group %s: сервер %s исключён из url-test (%u сбоев HS)",
                        gs->name, s ? s->name : "?",
                        gs->servers[i].fail_count);
                    /* WHY: url-test продолжает отдавать недоступный сервер до следующего
                     * HC раунда. Переключаем selected_idx немедленно если упал текущий. */
                    if (i == gs->selected_idx) {
                        int _best = -1;
                        uint32_t _best_lat = UINT32_MAX;
                        for (int _j = 0; _j < gs->server_count; _j++) {
                            if (!gs->servers[_j].available) continue;
                            if (gs->servers[_j].latency_ms > 0 &&
                                gs->servers[_j].latency_ms < _best_lat) {
                                _best_lat = gs->servers[_j].latency_ms;
                                _best = _j;
                            }
                        }
                        if (_best >= 0) {
                            gs->pinned       = false;
                            gs->selected_idx = _best;
                            const ServerConfig *sn = config_get_server(
                                pgm->cfg, gs->servers[_best].server_idx);
                            log_msg(LOG_INFO,
                                "proxy_group %s: немедленный failover [%d]%s → [%d]%s (%ums)",
                                gs->name, i, s ? s->name : "?",
                                _best, sn ? sn->name : "?",
                                _best_lat);
                        }
                    }
                }
                break;
            }
            continue;
        }

        if (gs->type != PROXY_GROUP_SELECT) continue;
        for (int i = 0; i < gs->server_count; i++) {
            if (gs->servers[i].server_idx != server_idx) continue;
            gs->servers[i].fail_count++;
            gs->servers[i].last_check = time(NULL);
            if (gs->servers[i].fail_count >= PROXY_GROUP_FAIL_THRESHOLD &&
                gs->selected_idx == i) {
                log_msg(LOG_WARN,
                    "proxy_group %s: сервер [%d] недоступен (%u сбоев HS)",
                    gs->name, i, gs->servers[i].fail_count);
                pg_select_rotate(gs, i, pgm->cfg);
            }
            break; /* сервер уникален в группе; идём к следующей группе */
        }
    }
}

void proxy_group_mark_server_fail_immediate(proxy_group_manager_t *pgm, int server_idx)
{
    if (!pgm) return;
    const ServerConfig *s = config_get_server(pgm->cfg, server_idx);
    for (int g = 0; g < pgm->count; g++) {
        proxy_group_state_t *gs = &pgm->groups[g];

        if (gs->type == PROXY_GROUP_URL_TEST) {
            for (int i = 0; i < gs->server_count; i++) {
                if (gs->servers[i].server_idx != server_idx) continue;
                if (!gs->servers[i].available) break;  /* уже исключён */
                gs->servers[i].fail_count = PROXY_GROUP_FAIL_THRESHOLD;
                gs->servers[i].available  = false;
                gs->servers[i].last_check = time(NULL);
                log_msg(LOG_WARN,
                    "proxy_group %s: сервер %s исключён немедленно (HS fail)",
                    gs->name, s ? s->name : "?");
                if (i == gs->selected_idx) {
                    int _best = -1;
                    uint32_t _best_lat = UINT32_MAX;
                    for (int _j = 0; _j < gs->server_count; _j++) {
                        if (!gs->servers[_j].available) continue;
                        if (gs->servers[_j].latency_ms > 0 &&
                            gs->servers[_j].latency_ms < _best_lat) {
                            _best_lat = gs->servers[_j].latency_ms;
                            _best     = _j;
                        }
                    }
                    if (_best >= 0) {
                        gs->pinned       = false;
                        gs->selected_idx = _best;
                        const ServerConfig *sn = config_get_server(
                            pgm->cfg, gs->servers[_best].server_idx);
                        log_msg(LOG_INFO,
                            "proxy_group %s: немедленный failover [%d]%s → [%d]%s (%ums)",
                            gs->name, i, s ? s->name : "?",
                            _best, sn ? sn->name : "?", _best_lat);
                    }
                }
                break;
            }
            continue;
        }

        if (gs->type != PROXY_GROUP_SELECT) continue;
        for (int i = 0; i < gs->server_count; i++) {
            if (gs->servers[i].server_idx != server_idx) continue;
            gs->servers[i].fail_count = PROXY_GROUP_FAIL_THRESHOLD;
            gs->servers[i].last_check = time(NULL);
            if (gs->selected_idx == i) {
                log_msg(LOG_WARN,
                    "proxy_group %s: сервер %s недоступен, немедленная ротация",
                    gs->name, s ? s->name : "?");
                pg_select_rotate(gs, i, pgm->cfg);
            }
            break;
        }
    }
}

void proxy_group_mark_server_fail_for_group(proxy_group_manager_t *pgm,
                                             int server_idx,
                                             const char *group_name)
{
    if (!pgm) return;
    if (!group_name || !group_name[0]) {
        /* Без имени группы — fallback на полный mark */
        proxy_group_mark_server_fail_immediate(pgm, server_idx);
        return;
    }
    const ServerConfig *s = config_get_server(pgm->cfg, server_idx);
    for (int g = 0; g < pgm->count; g++) {
        proxy_group_state_t *gs = &pgm->groups[g];
        if (strcmp(gs->name, group_name) != 0) continue;

        if (gs->type == PROXY_GROUP_URL_TEST) {
            for (int i = 0; i < gs->server_count; i++) {
                if (gs->servers[i].server_idx != server_idx) continue;
                if (!gs->servers[i].available) break;
                gs->servers[i].fail_count = PROXY_GROUP_FAIL_THRESHOLD;
                gs->servers[i].available  = false;
                gs->servers[i].last_check = time(NULL);
                log_msg(LOG_WARN,
                    "proxy_group %s: сервер %s исключён (HS fail в этой группе)",
                    gs->name, s ? s->name : "?");
                if (i == gs->selected_idx) {
                    int _best = -1;
                    uint32_t _best_lat = UINT32_MAX;
                    for (int _j = 0; _j < gs->server_count; _j++) {
                        if (!gs->servers[_j].available) continue;
                        if (gs->servers[_j].latency_ms > 0 &&
                            gs->servers[_j].latency_ms < _best_lat) {
                            _best_lat = gs->servers[_j].latency_ms;
                            _best     = _j;
                        }
                    }
                    if (_best >= 0) {
                        gs->pinned       = false;
                        gs->selected_idx = _best;
                        const ServerConfig *sn = config_get_server(
                            pgm->cfg, gs->servers[_best].server_idx);
                        log_msg(LOG_INFO,
                            "proxy_group %s: немедленный failover [%d]%s → [%d]%s (%ums)",
                            gs->name, i, s ? s->name : "?",
                            _best, sn ? sn->name : "?", _best_lat);
                    }
                }
                break;
            }
            return;
        }

        if (gs->type == PROXY_GROUP_SELECT) {
            for (int i = 0; i < gs->server_count; i++) {
                if (gs->servers[i].server_idx != server_idx) continue;
                gs->servers[i].fail_count = PROXY_GROUP_FAIL_THRESHOLD;
                gs->servers[i].last_check = time(NULL);
                if (gs->selected_idx == i) {
                    log_msg(LOG_WARN,
                        "proxy_group %s: сервер %s исключён (HS fail в этой группе)",
                        gs->name, s ? s->name : "?");
                    pg_select_rotate(gs, i, pgm->cfg);
                }
                break;
            }
            return;
        }
        return;
    }
}

void proxy_group_mark_server_ok(proxy_group_manager_t *pgm, int server_idx)
{
    if (!pgm) return;
    for (int g = 0; g < pgm->count; g++) {
        proxy_group_state_t *gs = &pgm->groups[g];
        for (int i = 0; i < gs->server_count; i++) {
            if (gs->servers[i].server_idx != server_idx) continue;
            /* WHY: градуальный сброс (декремент, не обнуление) — согласован
             * с handle_hc_event OK. available восстанавливает только HC когда
             * fail_count достигает 0 (≥3 consecutive HC success после исключения). */
            if (gs->servers[i].fail_count > 0) gs->servers[i].fail_count--;
            break;
        }
    }
}

/* H-1: неблокирующий health-check — максимум 1 группа, 1 сервер за tick.
 * При 3 группах × 3 сервера × 5с таймаут = 5с блок вместо 45с. */
/*
 * Health-check один сервер за вызов (round-robin cursor).
 * Почему по одному: fork() для TCP/UDP ping блокирует на timeout_ms,
 * проверка всех серверов разом создаст N форков одновременно.
 */
void proxy_group_tick(proxy_group_manager_t *pgm)
{
    time_t now = time(NULL);
    for (int g = 0; g < pgm->count; g++) {
        proxy_group_state_t *gs = &pgm->groups[g];
        if (now < gs->next_check) continue;
        if (gs->type == PROXY_GROUP_SELECT) {
            /* Восстановление серверов после PROXY_GROUP_RECOVERY_SECS тишины */
            for (int i = 0; i < gs->server_count; i++) {
                if (gs->servers[i].fail_count > 0 &&
                    gs->servers[i].last_check > 0 &&
                    now - gs->servers[i].last_check >= PROXY_GROUP_RECOVERY_SECS) {
                    gs->servers[i].fail_count = 0;
                    const ServerConfig *s = config_get_server(pgm->cfg,
                                               gs->servers[i].server_idx);
                    log_msg(LOG_INFO, "proxy_group %s: сервер [%d] %s восстановлен",
                            gs->name, i, s ? s->name : "?");
                }
            }
            gs->next_check = now + gs->interval;
            continue;
        }
        if (gs->server_count == 0) {
            gs->next_check = now + gs->interval;
            continue;
        }

        /* WHY: SO_SNDTIMEO не влияет на connect() — дочерний процесс может висеть
         * до ~75с (kernel TCP SYN retry). Зависший слот блокирует round-complete
         * → url-test не обновляет selected_idx. 25с > реального HC (~5с),
         * < tick interval (30с) → безопасная экспирация зависших дочерних. */
        int _expired = 0;
        for (int s = 0; s < PROXY_GROUP_HC_SLOTS; s++) {
            if (gs->hc_slots[s].pipe_fd < 0) continue;
            if (now - gs->hc_slots[s].spawn_time < 25) continue;
            int si = gs->hc_slots[s].server_idx;
            close(gs->hc_slots[s].pipe_fd);
            gs->hc_slots[s].pipe_fd    = -1;
            gs->hc_slots[s].registered = false;
            gs->hc_active--;
            if (pgm->hc_total_active > 0) pgm->hc_total_active--;
            _expired++;
            if (si >= 0 && si < gs->server_count) {
                gs->servers[si].fail_count++;
                if (gs->servers[si].fail_count >= 3)
                    gs->servers[si].available = false;
            }
            log_msg(LOG_DEBUG, "proxy_group[%s] слот %d: HC таймаут 25с, принудительное закрытие",
                    gs->name, s);
        }
        /* WHY: если экспирация освободила последний слот на границе раунда —
         * round-complete наступил. Без этой проверки dispatch немедленно запустит
         * новый раунд и round-complete в handle_hc_event никогда не сработает. */
        if (_expired > 0 && gs->hc_active == 0 && gs->server_count > 0 &&
            gs->check_cursor % gs->server_count == 0) {
            if (gs->type == PROXY_GROUP_URL_TEST) {
                int _ei = -1; uint32_t _el = UINT32_MAX;
                for (int _j = 0; _j < gs->server_count; _j++) {
                    if (!gs->servers[_j].available) continue;
                    if (gs->servers[_j].latency_ms > 0 &&
                        gs->servers[_j].latency_ms < _el) {
                        _el = gs->servers[_j].latency_ms; _ei = _j;
                    }
                }
                if (_ei >= 0) {
                    uint32_t _tol = gs->tolerance_ms > 0
                                    ? (uint32_t)gs->tolerance_ms : 30u;
                    bool _cur_ok  = gs->selected_idx >= 0 &&
                                    gs->selected_idx < gs->server_count &&
                                    gs->servers[gs->selected_idx].available &&
                                    gs->servers[gs->selected_idx].latency_ms > 0 &&
                                    gs->servers[gs->selected_idx].latency_ms != UINT32_MAX;
                    uint32_t _cl  = _cur_ok
                                    ? gs->servers[gs->selected_idx].latency_ms
                                    : UINT32_MAX;
                    if (!gs->pinned && _ei != gs->selected_idx && (!_cur_ok || _el + _tol < _cl)) {
                        gs->selected_idx = _ei;
                        const ServerConfig *sc = config_get_server(
                            pgm->cfg, gs->servers[_ei].server_idx);
                        log_msg(LOG_INFO, "url-test: %s → %s (%ums)",
                                gs->name,
                                (sc && sc->name[0]) ? sc->name : "?",
                                _el);
                    }
                }
            }
            pgm->first_round_done = true;
            gs->next_check = time(NULL) + gs->interval;
            continue;
        }

        /* WHY: mihomo запускает goroutine на каждый сервер одновременно (errgroup limit=10).
         * checked < server_count гарантирует один полный проход без _round_end.
         * Убран _round_end: ограничение hc_active/hc_global_limit остановит loop
         * раньше границы раунда — cursor не пересечёт её случайно. */
        int _cur0   = gs->check_cursor;
        int started = 0;
        int checked = 0;
        /* WHY: убран burst mode (!first_round_done → 16). Burst игнорировал
         * hc_global_limit и позволял 2 группам совместно запустить 16 форков
         * независимо от compute_hc_limit(). Первый раунд с limit=8 и
         * HC_SLOTS=8 занимает ~12 партий × 2с = ~24с — приемлемо. */
        int _eff_limit = pgm->hc_global_limit;
        while (checked < gs->server_count &&
               gs->hc_active < PROXY_GROUP_HC_SLOTS &&
               pgm->hc_total_active < _eff_limit) {
            int i = gs->check_cursor % gs->server_count;
            const ServerConfig *srv = config_get_server(pgm->cfg,
                                                         gs->servers[i].server_idx);
            if (!srv || !transport_is_implemented(srv->transport)) {
                gs->servers[i].latency_ms = UINT32_MAX;
                gs->servers[i].available  = false;
                gs->check_cursor++;
                checked++;
                continue;
            }
            int slot = -1;
            for (int s = 0; s < PROXY_GROUP_HC_SLOTS; s++)
                if (gs->hc_slots[s].pipe_fd < 0) { slot = s; break; }
            if (slot < 0) break;
            int pfd;
#if CONFIG_EBURNET_AWG
            if (strcmp(srv->protocol, "awg") == 0)
                pfd = net_spawn_awg_check(srv, pgm->cfg->tai_utc_offset,
                                          gs->timeout_ms);
            else
#endif
            if (strcmp(srv->protocol, "hysteria2") == 0)
                pfd = net_spawn_udp_ping(srv->address, srv->port,
                                         gs->timeout_ms);
            /* WHY: убрано !srv->source_provider[0] — HC нужен для провайдерных серверов
             * (PrivateVPN, ARZA) так же как для статических. Без этого провайдерные
             * VLESS/Trojan проходили через net_spawn_tcp_ping → fake-ip DNS → 2ms. */
            else if (gs->type == PROXY_GROUP_URL_TEST &&
                     (strcmp(srv->protocol, "vless")  == 0 ||
                      strcmp(srv->protocol, "trojan") == 0)) {
                char hc_host[256] = "cp.cloudflare.com";
                uint16_t hc_port  = 80;
                if (gs->test_url[0])
                    net_parse_url_host(gs->test_url, hc_host,
                                       sizeof(hc_host), &hc_port);
                pfd = hc_vless_spawn(srv, hc_host, hc_port, gs->timeout_ms);
            } else
                pfd = net_spawn_tcp_ping(srv->address, srv->port,
                                         gs->timeout_ms);
            if (pfd >= 0) {
                gs->hc_slots[slot].pipe_fd    = pfd;
                gs->hc_slots[slot].server_idx = i;
                gs->hc_slots[slot].registered = false;
                gs->hc_slots[slot].spawn_time = now;
                gs->hc_active++;
                pgm->hc_total_active++;
                gs->servers[i].last_check     = now;
                started++;
            }
            gs->check_cursor++;
            checked++;
            /* WHY: нельзя пересекать границу раунда — round-complete
             * детектируется по cursor % server_count == 0 в handle_hc_event
             * и expiry check. Без этого break cursor уходит в следующий раунд
             * и условие round-complete никогда не выполняется при hc_active=0. */
            if (gs->check_cursor % gs->server_count == 0)
                break;
        }
        if (started > 0)
            log_msg(LOG_DEBUG, "proxy_group[%s]: HC spawn +%d total=%d/%d",
                    gs->name, started,
                    pgm->hc_total_active, pgm->hc_global_limit);
        /* Все серверы нереализованы → round complete прямо в tick */
        if (gs->hc_active == 0 && gs->server_count > 0 &&
            gs->check_cursor > _cur0 &&
            gs->check_cursor % gs->server_count == 0) {
            if (gs->type == PROXY_GROUP_URL_TEST) {
                int _bi = -1; uint32_t _bl = UINT32_MAX;
                for (int _j = 0; _j < gs->server_count; _j++) {
                    if (!gs->servers[_j].available) continue;
                    if (gs->servers[_j].latency_ms > 0 &&
                        gs->servers[_j].latency_ms < _bl) {
                        _bl = gs->servers[_j].latency_ms;
                        _bi = _j;
                    }
                }
                if (_bi >= 0) {
                    uint32_t _tol = gs->tolerance_ms > 0
                                    ? (uint32_t)gs->tolerance_ms : 30u;
                    bool _cur_ok  = gs->selected_idx >= 0 &&
                                    gs->selected_idx < gs->server_count &&
                                    gs->servers[gs->selected_idx].available &&
                                    gs->servers[gs->selected_idx].latency_ms > 0 &&
                                    gs->servers[gs->selected_idx].latency_ms != UINT32_MAX;
                    uint32_t _cl  = _cur_ok
                                    ? gs->servers[gs->selected_idx].latency_ms
                                    : UINT32_MAX;
                    if (!gs->pinned && _bi != gs->selected_idx && (!_cur_ok || _bl + _tol < _cl)) {
                        gs->selected_idx = _bi;
                        const ServerConfig *sc = config_get_server(
                            pgm->cfg, gs->servers[_bi].server_idx);
                        log_msg(LOG_INFO, "url-test: %s → %s (%ums)",
                                gs->name, (sc && sc->name[0]) ? sc->name : "?",
                                _bl);
                    }
                }
            }
            pgm->first_round_done = true;
            gs->next_check = time(NULL) + gs->interval;
        }
    }
}

void proxy_group_handle_hc_event(proxy_group_manager_t *pgm,
                                  proxy_group_state_t *gs,
                                  int fd, uint32_t events,
                                  const EburNetConfig *cfg)
{
    /* Найти слот по fd */
    int slot = -1;
    for (int s = 0; s < PROXY_GROUP_HC_SLOTS; s++) {
        if (gs->hc_slots[s].pipe_fd == fd) { slot = s; break; }
    }
    if (slot < 0) return;
    (void)events;

    char buf[32] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);

    int i = gs->hc_slots[slot].server_idx;

    /* Освободить слот; cursor уже сдвинут в tick при запуске HC */
    close(gs->hc_slots[slot].pipe_fd);
    gs->hc_slots[slot].pipe_fd    = -1;
    gs->hc_slots[slot].registered = false;
    gs->hc_active--;
    if (pgm->hc_total_active > 0) pgm->hc_total_active--;
    log_msg(LOG_DEBUG, "proxy_group[%s]: HC done slot=%d total=%d/%d",
            gs->name, slot, pgm->hc_total_active, pgm->hc_global_limit);

    if (n > 0 && i >= 0 && i < gs->server_count) {
        buf[n] = '\0';
        if (strncmp(buf, "OK", 2) == 0) {
            long long ms = 0;
            sscanf(buf, "OK %lld", &ms);
            /* WHY: ms == 0 → результат невалиден (отрицательный diff зажат в 0
             * в child) или измерение быстрее 1мс (аномально). ms > 9999 → child
             * не применил clamp (баг защиты) или реальный таймаут 10с+. Оба случая
             * не меняют available — не штрафуем и не восстанавливаем сервер. */
            if (ms > 0 && ms <= 9999) {
                gs->servers[i].latency_ms = (uint32_t)ms;
                /* WHY градуальный сброс: полный fail_count=0 при первом OK позволял
                 * осциллирующему серверу никогда не накопить 3 сбоя. Теперь один
                 * успех снимает один штраф — нужно столько же успехов сколько сбоев
                 * (≥3 consecutive OK чтобы восстановить available после исключения). */
                if (gs->servers[i].fail_count > 0) gs->servers[i].fail_count--;
                if (gs->servers[i].fail_count == 0) gs->servers[i].available = true;
                log_msg(LOG_DEBUG, "proxy_group[%s] server[%d] latency=%lldms fail=%u",
                        gs->name, i, ms, gs->servers[i].fail_count);
            } else {
                log_msg(LOG_WARN,
                    "proxy_group[%s] server[%d] невалидная latency=%lldms — пропуск",
                    gs->name, i, ms);
            }
        } else {
            gs->servers[i].fail_count++;
            if (gs->servers[i].fail_count >= 3)
                gs->servers[i].available = false;
            log_msg(LOG_DEBUG, "proxy_group[%s] server[%d] недоступен fail=%u",
                    gs->name, i, gs->servers[i].fail_count);
        }
    }

    /* Round complete: все слоты свободны И cursor прошёл полный цикл.
     * WHY: cursor сдвигается в tick при запуске; когда hc_active падает
     * до 0 и cursor кратен server_count — все серверы раунда проверены. */
    if (gs->hc_active == 0 && gs->server_count > 0 &&
        gs->check_cursor % gs->server_count == 0) {

        if (gs->type == PROXY_GROUP_URL_TEST) {
            int best_i    = -1;
            uint32_t best = UINT32_MAX;
            for (int j = 0; j < gs->server_count; j++) {
                if (!gs->servers[j].available) continue;
                if (gs->servers[j].latency_ms > 0 &&
                    gs->servers[j].latency_ms < best) {
                    best   = gs->servers[j].latency_ms;
                    best_i = j;
                }
            }
            if (best_i >= 0) {
                uint32_t tol     = gs->tolerance_ms > 0
                                   ? (uint32_t)gs->tolerance_ms : 30u;
                bool cur_ok      = gs->selected_idx >= 0 &&
                                   gs->selected_idx < gs->server_count &&
                                   gs->servers[gs->selected_idx].available &&
                                   gs->servers[gs->selected_idx].latency_ms > 0 &&
                                   gs->servers[gs->selected_idx].latency_ms != UINT32_MAX;
                uint32_t cur_lat = cur_ok
                                   ? gs->servers[gs->selected_idx].latency_ms
                                   : UINT32_MAX;
                /* WHY tolerance: гистерезис — переключаться только если новый быстрее
                 * более чем на tol мс. Аналог mihomo fastNode stability guard. */
                if (!gs->pinned && best_i != gs->selected_idx &&
                    (!cur_ok || best + tol < cur_lat)) {
                    gs->selected_idx = best_i;
                    const ServerConfig *sc =
                        cfg ? config_get_server(cfg, gs->servers[best_i].server_idx)
                            : NULL;
                    log_msg(LOG_INFO, "url-test: %s → %s TCP (%ums)",
                            gs->name,
                            (sc && sc->name[0]) ? sc->name : "?",
                            best);
                }
            }
        }

        pgm->first_round_done = true;
        gs->next_check = time(NULL) + gs->interval;
    }
}

bool proxy_group_owns_fd(const proxy_group_state_t *gs, int fd)
{
    for (int s = 0; s < PROXY_GROUP_HC_SLOTS; s++)
        if (gs->hc_slots[s].pipe_fd == fd) return true;
    return false;
}

int proxy_group_select_manual(proxy_group_manager_t *pgm,
                              const char *group_name, int server_idx)
{
    proxy_group_state_t *g = proxy_group_find(pgm, group_name);
    if (!g) return -1;
    for (int i = 0; i < g->server_count; i++) {
        if (g->servers[i].server_idx == server_idx) {
            g->selected_idx = i;
            return 0;
        }
    }
    return -1;
}

const char *proxy_group_get_current(const proxy_group_state_t *gs,
                                    const EburNetConfig *cfg)
{
    if (!gs || !cfg || gs->server_count <= 0) return "";
    int si = (gs->selected_idx >= 0 && gs->selected_idx < gs->server_count)
             ? gs->selected_idx : 0;
    const ServerConfig *sc = config_get_server(cfg, gs->servers[si].server_idx);
    return (sc && sc->name[0]) ? sc->name : "";
}

int proxy_group_to_json(const proxy_group_manager_t *pgm,
                        char *buf, size_t buflen)
{
    if (!buflen) return 0;
    int pos = 0;

    /* H-01: guard — snprintf только если есть место */
#define JS(fmt, ...) do { \
    if ((size_t)pos < buflen - 1) \
        pos += snprintf(buf + pos, buflen - (size_t)pos, fmt, ##__VA_ARGS__); \
} while(0)

    JS("{\"groups\":[");
    for (int g = 0; g < pgm->count && (size_t)pos < buflen - 1; g++) {
        const proxy_group_state_t *gs = &pgm->groups[g];
        if (g > 0) JS(",");
        char esc_name[128];
        json_escape_str(gs->name, esc_name, sizeof(esc_name));
        /* P4: ограничить серверы в JSON (IPC 64KB лимит при 122+ серверах) */
        int json_max_srv = gs->server_count < 16 ? gs->server_count : 16;
        JS("{\"name\":\"%s\",\"type\":%d,\"selected\":%d,\"total_servers\":%d,\"servers\":[",
            esc_name, gs->type, gs->selected_idx, gs->server_count);
        for (int i = 0; i < json_max_srv && (size_t)pos < buflen - 1; i++) {
            if (i > 0) JS(",");
            const ServerConfig *sc = config_get_server(pgm->cfg,
                                         gs->servers[i].server_idx);
            char esc_sname[128];
            json_escape_str(sc ? sc->name : "", esc_sname, sizeof(esc_sname));
            JS("{\"idx\":%d,\"name\":\"%s\",\"available\":%s,\"latency_ms\":%u,\"fails\":%u}",
                gs->servers[i].server_idx,
                esc_sname,
                gs->servers[i].available ? "true" : "false",
                gs->servers[i].latency_ms,
                gs->servers[i].fail_count);
        }
        JS("]}");
    }
    JS("]}");
#undef JS
    return pos;
}

/* Сохранить selected_idx всех SELECT-групп в SELECTED_JSON_PATH.
 * Вызывается из http_server.c при PUT /proxies/{group}. */
void proxy_group_save_all_selections(const proxy_group_manager_t *pgm,
                                      const EburNetConfig *cfg)
{
    if (!pgm || !cfg || pgm->count == 0) return;

    char buf[SELECTED_JSON_MAX];
    int pos = 0, max = (int)sizeof(buf) - 2;

    buf[pos++] = '{';
    bool first = true;
    for (int i = 0; i < pgm->count; i++) {
        const proxy_group_state_t *gs = &pgm->groups[i];
        if (gs->type != PROXY_GROUP_SELECT && !gs->pinned) continue;
        if (gs->selected_idx < 0 || gs->selected_idx >= gs->server_count) continue;
        const ServerConfig *sc = config_get_server(cfg,
            gs->servers[gs->selected_idx].server_idx);
        if (!sc) continue;
        if (!first && pos < max) buf[pos++] = ',';
        first = false;
        pos += pgm_json_write_kv(buf + pos, max - pos, gs->name, sc->name);
    }
    buf[pos++] = '}';
    buf[pos]   = '\0';

    mkdir("/etc/4eburnet", 0755);
    FILE *f = fopen(SELECTED_JSON_PATH, "w");
    if (!f) {
        log_msg(LOG_WARN,
            "proxy_group: не удалось сохранить selection: %s", strerror(errno));
        return;
    }
    fwrite(buf, 1, (size_t)pos, f);
    fclose(f);
    log_msg(LOG_DEBUG, "proxy_group: selection сохранён в %s", SELECTED_JSON_PATH);
}

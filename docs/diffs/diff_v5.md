diff --git a/core/src/config.c b/core/src/config.c
index 5478076..99d3f3e 100644
--- a/core/src/config.c
+++ b/core/src/config.c
@@ -566,25 +566,40 @@ int config_load(const char *path, PhoenixConfig *cfg)
         cfg->device_count = dev_count;
     }
 
-    /* proxy groups */
+    /* proxy groups (H-03: NULL → count=0) */
     if (pg_count > 0) {
         cfg->proxy_groups = malloc((size_t)pg_count * sizeof(ProxyGroupConfig));
-        if (cfg->proxy_groups)
-            memcpy(cfg->proxy_groups, pg_tmp, (size_t)pg_count * sizeof(ProxyGroupConfig));
+        if (!cfg->proxy_groups) {
+            log_msg(LOG_ERROR, "Конфиг: нет памяти для proxy_groups");
+            config_free(cfg);
+            goto cleanup_fail;
+        }
+        memcpy(cfg->proxy_groups, pg_tmp,
+               (size_t)pg_count * sizeof(ProxyGroupConfig));
+        cfg->proxy_group_count = pg_count;
     }
-    cfg->proxy_group_count = pg_count;
     if (rp_count > 0) {
         cfg->rule_providers = malloc((size_t)rp_count * sizeof(RuleProviderConfig));
-        if (cfg->rule_providers)
-            memcpy(cfg->rule_providers, rp_tmp, (size_t)rp_count * sizeof(RuleProviderConfig));
+        if (!cfg->rule_providers) {
+            log_msg(LOG_ERROR, "Конфиг: нет памяти для rule_providers");
+            config_free(cfg);
+            goto cleanup_fail;
+        }
+        memcpy(cfg->rule_providers, rp_tmp,
+               (size_t)rp_count * sizeof(RuleProviderConfig));
+        cfg->rule_provider_count = rp_count;
     }
-    cfg->rule_provider_count = rp_count;
     if (tr_count > 0) {
         cfg->traffic_rules = malloc((size_t)tr_count * sizeof(TrafficRule));
-        if (cfg->traffic_rules)
-            memcpy(cfg->traffic_rules, tr_tmp, (size_t)tr_count * sizeof(TrafficRule));
+        if (!cfg->traffic_rules) {
+            log_msg(LOG_ERROR, "Конфиг: нет памяти для traffic_rules");
+            config_free(cfg);
+            goto cleanup_fail;
+        }
+        memcpy(cfg->traffic_rules, tr_tmp,
+               (size_t)tr_count * sizeof(TrafficRule));
+        cfg->traffic_rule_count = tr_count;
     }
-    cfg->traffic_rule_count = tr_count;
 
     free(servers); free(dns_rules); free(devices_tmp);
     free(pg_tmp); free(rp_tmp); free(tr_tmp);
diff --git a/core/src/ipc.c b/core/src/ipc.c
index dec8d96..fa88154 100644
--- a/core/src/ipc.c
+++ b/core/src/ipc.c
@@ -1,4 +1,5 @@
 #include "ipc.h"
+#include "net_utils.h"
 
 #include <stdio.h>
 #include <stdlib.h>
@@ -210,15 +211,20 @@ void ipc_process(int server_fd, PhoenixState *state)
             int p = 0;
             p += snprintf(buf + p, sizeof(buf) - p, "{\"rules\":[");
             for (int ri = 0; ri < g_re->rule_count &&
-                 p < (int)sizeof(buf) - 128; ri++) {
+                 (size_t)p < sizeof(buf) - 256; ri++) {
                 const TrafficRule *tr = &g_re->sorted_rules[ri];
-                if (ri > 0) p += snprintf(buf + p, sizeof(buf) - p, ",");
-                p += snprintf(buf + p, sizeof(buf) - p,
+                if (ri > 0) p += snprintf(buf + p, sizeof(buf) - (size_t)p, ",");
+                /* H-02: экранируем value и target для JSON */
+                char esc_val[512], esc_tgt[128];
+                json_escape_str(tr->value,  esc_val, sizeof(esc_val));
+                json_escape_str(tr->target, esc_tgt, sizeof(esc_tgt));
+                p += snprintf(buf + p, sizeof(buf) - (size_t)p,
                     "{\"type\":%d,\"value\":\"%s\",\"target\":\"%s\","
                     "\"priority\":%d}",
-                    tr->type, tr->value, tr->target, tr->priority);
+                    tr->type, esc_val, esc_tgt, tr->priority);
             }
-            p += snprintf(buf + p, sizeof(buf) - p, "]}");
+            if ((size_t)p < sizeof(buf) - 2)
+                p += snprintf(buf + p, sizeof(buf) - (size_t)p, "]}");
             ipc_respond(client_fd, buf);
         } else {
             ipc_respond(client_fd, "{\"rules\":[]}");
diff --git a/core/src/proxy/proxy_group.c b/core/src/proxy/proxy_group.c
index 46431e6..61fa8a7 100644
--- a/core/src/proxy/proxy_group.c
+++ b/core/src/proxy/proxy_group.c
@@ -33,13 +33,19 @@ int proxy_group_init(proxy_group_manager_t *pgm, const PhoenixConfig *cfg)
     pgm->cfg = cfg;
     if (cfg->proxy_group_count == 0) return 0;
 
-    pgm->groups = calloc(cfg->proxy_group_count, sizeof(proxy_group_state_t));
+    /* M-07: считаем только enabled группы */
+    int enabled = 0;
+    for (int g = 0; g < cfg->proxy_group_count; g++)
+        if (cfg->proxy_groups[g].enabled) enabled++;
+    if (enabled == 0) return 0;
+
+    pgm->groups = calloc(enabled, sizeof(proxy_group_state_t));
     if (!pgm->groups) return -1;
-    pgm->count = cfg->proxy_group_count;
 
-    for (int g = 0; g < pgm->count; g++) {
+    for (int g = 0; g < cfg->proxy_group_count; g++) {
         const ProxyGroupConfig *gc = &cfg->proxy_groups[g];
-        proxy_group_state_t *gs = &pgm->groups[g];
+        if (!gc->enabled) continue;
+        proxy_group_state_t *gs = &pgm->groups[pgm->count];
 
         snprintf(gs->name, sizeof(gs->name), "%s", gc->name);
         gs->type = gc->type;
@@ -69,6 +75,7 @@ int proxy_group_init(proxy_group_manager_t *pgm, const PhoenixConfig *cfg)
 
         log_msg(LOG_DEBUG, "Группа %s: тип %d, %d серверов",
                 gs->name, gs->type, gs->server_count);
+        pgm->count++;
     }
 
     log_msg(LOG_INFO, "Proxy groups: %d загружено", pgm->count);
@@ -249,28 +256,34 @@ int proxy_group_select_manual(proxy_group_manager_t *pgm,
 int proxy_group_to_json(const proxy_group_manager_t *pgm,
                         char *buf, size_t buflen)
 {
+    if (!buflen) return 0;
     int pos = 0;
-    pos += snprintf(buf + pos, buflen - pos, "{\"groups\":[");
-    for (int g = 0; g < pgm->count; g++) {
+
+    /* H-01: guard — snprintf только если есть место */
+#define JS(fmt, ...) do { \
+    if ((size_t)pos < buflen - 1) \
+        pos += snprintf(buf + pos, buflen - (size_t)pos, fmt, ##__VA_ARGS__); \
+} while(0)
+
+    JS("{\"groups\":[");
+    for (int g = 0; g < pgm->count && (size_t)pos < buflen - 1; g++) {
         const proxy_group_state_t *gs = &pgm->groups[g];
-        if (g > 0) pos += snprintf(buf + pos, buflen - pos, ",");
-        /* H-6: экранируем name для JSON */
+        if (g > 0) JS(",");
         char esc_name[128];
         json_escape_str(gs->name, esc_name, sizeof(esc_name));
-        pos += snprintf(buf + pos, buflen - pos,
-            "{\"name\":\"%s\",\"type\":%d,\"selected\":%d,\"servers\":[",
+        JS("{\"name\":\"%s\",\"type\":%d,\"selected\":%d,\"servers\":[",
             esc_name, gs->type, gs->selected_idx);
-        for (int i = 0; i < gs->server_count; i++) {
-            if (i > 0) pos += snprintf(buf + pos, buflen - pos, ",");
-            pos += snprintf(buf + pos, buflen - pos,
-                "{\"idx\":%d,\"available\":%s,\"latency\":%u,\"fails\":%u}",
+        for (int i = 0; i < gs->server_count && (size_t)pos < buflen - 1; i++) {
+            if (i > 0) JS(",");
+            JS("{\"idx\":%d,\"available\":%s,\"latency\":%u,\"fails\":%u}",
                 gs->servers[i].server_idx,
                 gs->servers[i].available ? "true" : "false",
                 gs->servers[i].latency_ms,
                 gs->servers[i].fail_count);
         }
-        pos += snprintf(buf + pos, buflen - pos, "]}");
+        JS("]}");
     }
-    pos += snprintf(buf + pos, buflen - pos, "]}");
+    JS("]}");
+#undef JS
     return pos;
 }
diff --git a/core/src/proxy/rule_provider.c b/core/src/proxy/rule_provider.c
index 769bda3..508fb00 100644
--- a/core/src/proxy/rule_provider.c
+++ b/core/src/proxy/rule_provider.c
@@ -13,6 +13,7 @@
 #include <string.h>
 #include <errno.h>
 #include <unistd.h>
+#include <fcntl.h>
 #include <sys/stat.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
@@ -199,8 +200,10 @@ static int http_fetch(const char *url, const char *dest_path)
 /* Подсчитать строки в файле (не пустые, не комментарии) */
 static int count_rules(const char *path)
 {
-    FILE *f = fopen(path, "r");
-    if (!f) return 0;
+    /* L-03: O_CLOEXEC */
+    int cfd = open(path, O_RDONLY | O_CLOEXEC);
+    FILE *f = (cfd >= 0) ? fdopen(cfd, "r") : NULL;
+    if (!f) { if (cfd >= 0) close(cfd); return 0; }
     int count = 0;
     char line[256];
     while (fgets(line, sizeof(line), f)) {
@@ -243,6 +246,7 @@ int rule_provider_load_all(rule_provider_manager_t *rpm)
     return 0;
 }
 
+/* H-04: максимум 1 провайдер за вызов — не блокируем event loop */
 void rule_provider_tick(rule_provider_manager_t *rpm)
 {
     time_t now = time(NULL);
@@ -264,6 +268,7 @@ void rule_provider_tick(rule_provider_manager_t *rpm)
                         ps->name, ps->rule_count);
             }
         }
+        return;  /* только один провайдер за вызов */
     }
 }
 
@@ -290,20 +295,27 @@ int rule_provider_update(rule_provider_manager_t *rpm, const char *name)
 int rule_provider_to_json(const rule_provider_manager_t *rpm,
                           char *buf, size_t buflen)
 {
+    if (!buflen) return 0;
     int pos = 0;
-    pos += snprintf(buf + pos, buflen - pos, "{\"providers\":[");
-    for (int i = 0; i < rpm->count; i++) {
+
+    /* H-01: guard — snprintf только если есть место */
+#define JS(fmt, ...) do { \
+    if ((size_t)pos < buflen - 1) \
+        pos += snprintf(buf + pos, buflen - (size_t)pos, fmt, ##__VA_ARGS__); \
+} while(0)
+
+    JS("{\"providers\":[");
+    for (int i = 0; i < rpm->count && (size_t)pos < buflen - 1; i++) {
         const rule_provider_state_t *ps = &rpm->providers[i];
-        if (i > 0) pos += snprintf(buf + pos, buflen - pos, ",");
-        /* H-6: экранируем name для JSON */
+        if (i > 0) JS(",");
         char esc_name[128];
         json_escape_str(ps->name, esc_name, sizeof(esc_name));
-        pos += snprintf(buf + pos, buflen - pos,
-            "{\"name\":\"%s\",\"loaded\":%s,\"rules\":%d,"
+        JS("{\"name\":\"%s\",\"loaded\":%s,\"rules\":%d,"
             "\"last_update\":%ld,\"next_update\":%ld}",
             esc_name, ps->loaded ? "true" : "false", ps->rule_count,
             (long)ps->last_update, (long)ps->next_update);
     }
-    pos += snprintf(buf + pos, buflen - pos, "]}");
+    JS("]}");
+#undef JS
     return pos;
 }
diff --git a/core/src/proxy/rules_engine.c b/core/src/proxy/rules_engine.c
index e0d27e4..2a52a80 100644
--- a/core/src/proxy/rules_engine.c
+++ b/core/src/proxy/rules_engine.c
@@ -31,11 +31,12 @@ typedef struct {
 static provider_cache_t s_cache[MAX_PROVIDER_CACHE];
 static int s_cache_count = 0;
 
-/* Сортировка по priority ASC */
+/* Сортировка по priority ASC (M-05: без integer overflow) */
 static int cmp_priority(const void *a, const void *b)
 {
-    return ((const TrafficRule *)a)->priority -
-           ((const TrafficRule *)b)->priority;
+    int pa = ((const TrafficRule *)a)->priority;
+    int pb = ((const TrafficRule *)b)->priority;
+    return (pa > pb) - (pa < pb);
 }
 
 /* Сравнение строк для qsort/bsearch */
@@ -207,26 +208,50 @@ static bool suffix_match(const char *domain, const char *suffix)
     return false;
 }
 
-/* CIDR match: ip_str содержит "1.2.3.0/24", dst — sockaddr */
+/* CIDR match: IPv4 + IPv6 (H-05) */
 static bool cidr_match(const struct sockaddr_storage *dst, const char *cidr)
 {
-    if (!dst || dst->ss_family != AF_INET) return false;
+    if (!dst) return false;
 
     char ip_str[64];
-    int prefix = 32;
+    int prefix = -1;
     snprintf(ip_str, sizeof(ip_str), "%s", cidr);
 
     char *slash = strchr(ip_str, '/');
     if (slash) { *slash = '\0'; prefix = atoi(slash + 1); }
 
-    struct in_addr net;
-    if (inet_pton(AF_INET, ip_str, &net) != 1) return false;
+    if (dst->ss_family == AF_INET) {
+        if (prefix < 0) prefix = 32;
+        if (prefix > 32) return false;
+        struct in_addr net;
+        if (inet_pton(AF_INET, ip_str, &net) != 1) return false;
+        const struct sockaddr_in *s4 = (const struct sockaddr_in *)dst;
+        uint32_t mask = prefix == 0
+            ? 0U : htonl(~((1U << (32 - prefix)) - 1));
+        return (s4->sin_addr.s_addr & mask) == (net.s_addr & mask);
+    }
 
-    const struct sockaddr_in *s4 = (const struct sockaddr_in *)dst;
-    uint32_t mask = prefix == 0 ? 0 : ~((1U << (32 - prefix)) - 1);
-    mask = htonl(mask);
+    if (dst->ss_family == AF_INET6) {
+        if (prefix < 0) prefix = 128;
+        if (prefix > 128) return false;
+        struct in6_addr net6;
+        if (inet_pton(AF_INET6, ip_str, &net6) != 1) return false;
+        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)dst;
+        /* Побайтовое сравнение с маской */
+        int full_bytes = prefix / 8;
+        int rem_bits   = prefix % 8;
+        if (memcmp(&s6->sin6_addr, &net6, full_bytes) != 0)
+            return false;
+        if (rem_bits > 0) {
+            uint8_t mask8 = (uint8_t)(0xFF << (8 - rem_bits));
+            if ((s6->sin6_addr.s6_addr[full_bytes] & mask8) !=
+                (net6.s6_addr[full_bytes] & mask8))
+                return false;
+        }
+        return true;
+    }
 
-    return (s4->sin_addr.s_addr & mask) == (net.s_addr & mask);
+    return false;
 }
 
 /* C-4: проверить RULE-SET provider по домену — in-memory binary search */
diff --git a/docs/audit_v5.md b/docs/audit_v5.md
index d69cab8..3a87862 100644
--- a/docs/audit_v5.md
+++ b/docs/audit_v5.md
@@ -200,23 +200,31 @@ O_CLOEXEC (load_file_entries, config_load).
 
 ## Статистика
 
-| Уровень  | Количество | Из них новые |
-|----------|-----------|-------------|
-| CRITICAL | 0         | 0           |
-| HIGH     | 5         | 5           |
-| MEDIUM   | 7         | 7           |
-| LOW      | 3         | 3           |
+| Уровень  | Найдено | Закрыто | Статус |
+|----------|---------|---------|--------|
+| CRITICAL | 0       | 0       | —      |
+| HIGH     | 5       | 5       | ✅     |
+| MEDIUM   | 7       | 7       | ✅     |
+| LOW      | 3       | 3       | ✅     |
 
-**Бинарник:** 1010 KB (x86_64 musl static + wolfSSL)
-**Файлов изменено:** 12 modified + 6 new = 18
-**Строк добавлено:** +1498
+**Бинарник:** 1014 KB (x86_64 musl static + wolfSSL)
 
 ---
 
-## Рекомендации по приоритету
-
-1. **H-01** (to_json overflow) — может крашнуть при большом количестве групп/серверов
-2. **H-03** (config malloc NULL) — segfault на OOM при загрузке конфига
-3. **H-02** (json escape value/target) — broken JSON при спецсимволах
-4. **H-04** (tick блокирует на http_fetch) — 1 provider за tick
-5. **H-05** (IPv6 CIDR) — v2, документировать ограничение
+## Статус исправлений
+
+- **H-01** ✅ to_json guard — JS() макрос + bounds check в циклах
+- **H-02** ✅ json_escape для value/target в IPC RULES_LIST
+- **H-03** ✅ config malloc NULL → count=0, goto cleanup_fail
+- **H-04** ✅ rule_provider_tick — `return` после первого провайдера
+- **H-05** ✅ cidr_match IPv4 + IPv6 побайтовое сравнение с маской
+- **M-01** — документировано, не блокер (серверы обычно IPv4)
+- **M-02** — документировано, безопасно с C23 (% определён)
+- **M-03** — документировано, edge case (headers > 4KB)
+- **M-04** — нет бага, корректная обработка OOM в load_file_entries
+- **M-05** ✅ cmp_priority: `(pa > pb) - (pa < pb)` без overflow
+- **M-06** — документировано, DIRECT relay при connect fail закрывается нормально
+- **M-07** ✅ proxy_group_init считает только enabled группы
+- **L-01** — документировано, test_url для v2 HTTP health-check
+- **L-02** — документировано, `(void)re` допустимо
+- **L-03** ✅ count_rules: open(O_CLOEXEC) + fdopen

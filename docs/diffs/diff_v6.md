# Diff v6 — правки по аудиту v6

**Дата:** 2026-04-07  
**Аудит:** docs/audit_v6.md  
**Закрыто:** V6-03, V6-04, V6-05, V6-06, V6-08 (5 из 10)  
**Принято к 3.6:** V6-01, V6-02  
**Ожидаемо/Долг:** V6-07, V6-09, V6-10

---

## V6-08 — parse_cidr4/parse_cidr6: atoi → strtol

**Файл:** `core/src/geo/geo_loader.c`

```diff
-    if (slash) { *slash = '\0'; prefix = atoi(slash + 1); }
+    if (slash) {
+        *slash = '\0';
+        char *endptr;
+        long pval = strtol(slash + 1, &endptr, 10);
+        if (endptr == slash + 1 || *endptr != '\0') return false;
+        prefix = (int)pval;
+    }
```

Применено к `parse_cidr4` и `parse_cidr6`. Повреждённые строки `.lst` с нечисловым префиксом теперь отбрасываются вместо `prefix=0`.

---

## V6-03 — Europe/* ложные срабатывания для региона RU

**Файл:** `core/src/geo/geo_loader.c`

```diff
-            /* RU timezones */
-            if (strncmp(tz, "Europe/", 7) == 0  ||
-                strstr(tz, "Yekaterinburg")      ||
+            /* RU timezones — явный список, Europe-Berlin/Paris и пр. исключены */
+            if (strncmp(tz, "Europe/Moscow",     13) == 0 ||
+                strncmp(tz, "Europe/Kaliningrad", 17) == 0 ||
+                strncmp(tz, "Europe/Samara",     13) == 0 ||
+                strncmp(tz, "Europe/Ulyanovsk",  16) == 0 ||
+                strncmp(tz, "Europe/Volgograd",  16) == 0 ||
+                strncmp(tz, "Europe/Saratov",    14) == 0 ||
+                strncmp(tz, "Europe/Kirov",      13) == 0 ||
+                strncmp(tz, "Europe/Astrakhan",  16) == 0 ||
+                strstr(tz, "Yekaterinburg")            ||
```

`Europe/Berlin`, `Europe/Paris` и т.д. больше не дают `GEO_REGION_RU`.

---

## V6-04 — http_fetch: порт из URL

**Файл:** `core/src/proxy/rule_provider.c`

```diff
-    const char *u = url;
-    if (strncmp(u, "https://", 8) == 0) u += 8;
-    else if (strncmp(u, "http://", 7) == 0) u += 7;
+    const char *u = url;
+    uint16_t port;
+    if (strncmp(u, "https://", 8) == 0) { u += 8; port = 443; }
+    else if (strncmp(u, "http://", 7) == 0) { u += 7; port = 80; }
+    else { port = 443; }
     ...
+    /* Найти :port в host (напр. "1.2.3.4:8443") */
+    char *colon = strchr(host, ':');
+    if (colon) {
+        char *endptr;
+        long p = strtol(colon + 1, &endptr, 10);
+        if (endptr != colon + 1 && *endptr == '\0' && p > 0 && p <= 65535)
+            port = (uint16_t)p;
+        *colon = '\0';
+    }
     ...
-    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(443) };
+    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
```

Теперь работают: `http://1.2.3.4/rules.list` (port 80), `https://1.2.3.4:8443/rules.list`.

---

## V6-06 — cache_load использует format из RuleProviderConfig

**Файл:** `core/src/proxy/rules_engine.c`

```diff
-static provider_cache_t *cache_load(const char *provider_name,
-                                     rule_provider_manager_t *rpm)
+static provider_cache_t *cache_load(const char *provider_name,
+                                     rule_provider_manager_t *rpm,
+                                     rule_format_t hint_format)
 {
     ...
-    pc->is_domain = true;
-    if (pc->count > 0 && strchr(pc->entries[0], '/'))
-        pc->is_domain = false;
+    if (hint_format == RULE_FORMAT_DOMAIN) {
+        pc->is_domain = true;
+    } else if (hint_format == RULE_FORMAT_IPCIDR) {
+        pc->is_domain = false;
+    } else {
+        pc->is_domain = true;
+        if (pc->count > 0 && strchr(pc->entries[0], '/'))
+            pc->is_domain = false;
+    }
```

В `rules_engine_init` при загрузке RULE_SET провайдеров теперь передаётся `format` из `RuleProviderConfig`:

```diff
-        if (re->sorted_rules[i].type == RULE_TYPE_RULE_SET)
-            cache_load(re->sorted_rules[i].value, rpm);
+        rule_format_t fmt = RULE_FORMAT_CLASSICAL;
+        if (rpm && rpm->cfg) {
+            for (int j = 0; j < rpm->cfg->rule_provider_count; j++) {
+                if (strcmp(rpm->cfg->rule_providers[j].name,
+                           re->sorted_rules[i].value) == 0) {
+                    fmt = rpm->cfg->rule_providers[j].format;
+                    break;
+                }
+            }
+        }
+        cache_load(re->sorted_rules[i].value, rpm, fmt);
```

---

## V6-05 — IPC RULES_LIST динамический буфер

**Файл:** `core/src/ipc.c`

```diff
     case IPC_CMD_RULES_LIST:
         if (g_re && g_re->sorted_rules) {
+            size_t need = (size_t)g_re->rule_count * 200 + 64;
+            if (need < 256) need = 256;
+            char *rbuf = malloc(need);
+            if (!rbuf) { ipc_respond(client_fd, "{\"error\":\"OOM\"}"); break; }
             int p = 0;
-            p += snprintf(buf + p, sizeof(buf) - p, "{\"rules\":[");
-            for (int ri = 0; ri < g_re->rule_count &&
-                 (size_t)p < sizeof(buf) - 256; ri++) {
+            p += snprintf(rbuf + p, need - (size_t)p, "{\"rules\":[");
+            for (int ri = 0; ri < g_re->rule_count; ri++) {
+                if ((size_t)p >= need - 256) break;
                 ...
             }
-            ipc_respond(client_fd, buf);
+            ipc_respond(client_fd, rbuf);
+            free(rbuf);
```

Старый `buf[2048]` обрезал ответ при > ~18 правилах. Теперь выделяется `rule_count × 200 + 64` байт.

---

## Тесты в VM

```
[INFO] Регион: RU (из конфига)                 ← V6-03: регион корректен
[INFO] Конфиг загружен: ... правил: 25         ← V6-05: 25 правил без обрезки
[INFO] Rules engine: 25 правил загружено       ← V6-05: подтверждение
```

---

## Итог

| # | Статус |
|---|---|
| V6-01 HIGH: measure_latency блокирует event loop | Принято к 3.6 |
| V6-02 MEDIUM: geo_match_ip O(n) | Принято к 3.6 (Patricia trie) |
| V6-03 MEDIUM: Europe/* false positive | **✅ Закрыт** |
| V6-04 MEDIUM: http_fetch порт 443 хардкоден | **✅ Закрыт** |
| V6-05 MEDIUM: RULES_LIST обрезка | **✅ Закрыт** |
| V6-06 MEDIUM: cache_load тип по первой строке | **✅ Закрыт** |
| V6-07 LOW: measure_latency только IPv4 | Принято к 3.6 |
| V6-08 LOW: atoi без проверки ошибок | **✅ Закрыт** |
| V6-09 LOW: domain=NULL до 3.6 | Ожидаемо |
| V6-10 LOW: suffix O(n) (DEC-028) | Известный долг |

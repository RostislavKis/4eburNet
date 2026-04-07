# Аудит v6 — phoenix-router

**Дата:** 2026-04-07  
**Фокус:** новый код этапов 3.4 + 3.5  
**Предыдущий аудит:** v5 (15/15, 100%)

---

## Файлы под аудитом

| Файл | Этап |
|---|---|
| `core/src/geo/geo_loader.c` | 3.5 |
| `core/src/proxy/proxy_group.c` | 3.4 |
| `core/src/proxy/rule_provider.c` | 3.4 |
| `core/src/proxy/rules_engine.c` | 3.4 / 3.5 |
| `core/src/proxy/dispatcher.c` | 3.4 / 3.5 (изменения) |
| `core/src/main.c` | 3.4 / 3.5 (изменения) |
| `core/src/ipc.c` | 3.4 / 3.5 (изменения) |
| `core/src/config.c` | 3.4 / 3.5 (изменения) |

---

## Итоговая таблица

| # | Файл | Серьёзность | Описание | Статус |
|---|---|---|---|---|
| V6-01 | proxy_group.c | **HIGH** | measure_latency: блокирующий TCP connect блокирует event loop | Открыт |
| V6-02 | geo_loader.c | **MEDIUM** | geo_match_ip: O(n) линейный скан по всем CIDR при каждом соединении | Открыт |
| V6-03 | geo_loader.c | **MEDIUM** | device_detect_region: `strncmp(tz, "Europe/", 7)` матчит не-RU таймзоны | Открыт |
| V6-04 | rule_provider.c | **MEDIUM** | http_fetch: порт 443 хардкоден, HTTP (port 80) не поддерживается | Открыт |
| V6-05 | ipc.c | **MEDIUM** | IPC_CMD_RULES_LIST: обрезка при > ~18 правилах без уведомления клиенту | Открыт |
| V6-06 | rules_engine.c | **MEDIUM** | cache_load: тип файла (domain/CIDR) определяется по первой строке | Открыт |
| V6-07 | proxy_group.c | LOW | measure_latency: только AF_INET, IPv6 серверы не тестируются | Открыт |
| V6-08 | geo_loader.c | LOW | parse_cidr4/parse_cidr6: atoi без проверки ошибок для prefix | Открыт |
| V6-09 | rules_engine.c | LOW | DOMAIN/DOMAIN-SUFFIX/GEOSITE правила не работают до 3.6 (domain=NULL) | Ожидаемо |
| V6-10 | rules_engine.c | LOW | ruleset_match_domain: суффикс-поиск O(n) (DEC-028, известно) | Долг |
| V6-11 | dispatcher.c | INFO | DIRECT relay реализован корректно | OK |
| V6-12 | main.c | INFO | Reload: порядок free/init geo+engine корректен | OK |
| V6-13 | config.c | INFO | GEOIP/GEOSITE типы правил, region/geo_dir парсятся | OK |

**Итого: 10 открытых (1 HIGH, 4 MEDIUM, 3 LOW, 2 ожидаемо/долг)**

---

## V6-01 — HIGH: measure_latency блокирует event loop

**Файл:** `proxy/proxy_group.c:173`

```c
static uint32_t measure_latency(const char *ip, uint16_t port, int timeout_ms)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ...
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, ...);  /* timeout */
    int rc = connect(fd, ...);   /* БЛОКИРУЕТ до timeout_ms мс */
```

`connect()` синхронный. При `timeout_ms=5000` (по умолчанию) функция блокирует event loop на **до 5 секунд** за один вызов. Комментарий `H-1` в коде частично снижает урон — вызывается 1 сервер за tick, но при 3 группах × 300 серверов итерация занимает 25 минут без ответов на TPROXY соединения в это время.

**Степень риска:** На практике таймаут TCP connect ≈ RTT (10–100мс для доступного хоста). Неудача (недоступный хост) — до 5 секунд. В продакшене с неудачным upstream — серьёзное замораживание.

**Решение (3.6+):** Неблокирующий connect + EPOLLOUT в dispatcher epoll. Аналогично тому, как реализован `upstream_connect`.

---

## V6-02 — MEDIUM: geo_match_ip O(n) линейный скан

**Файл:** `geo/geo_loader.c:384`

```c
/* Линейный скан с ранним выходом.
   Binary search здесь сложен — CIDR перекрываются.
   При > 10K записей заменить на interval tree (3.6). */
for (int j = 0; j < c->v4_count; j++) {
    if ((ip & c->v4[j].mask) == c->v4[j].net)
        return c->region;
}
```

Для geoip-ru.lst из antizapret (~14K IPv4 CIDR) каждое новое соединение проходит до 14K сравнений. При нагрузке 100 коnn/сек → 1.4M сравнений/сек на MIPS 880MHz это реально. Для EC330 (mipsel_24kc) — узкое место.

Массив уже **отсортирован** по `net`, но binary search для CIDR невозможен напрямую из-за перекрытий. Решение: interval tree или CIDR trie.

**Решение (3.6+):** Patricia trie для IPv4/IPv6 CIDR lookup. Для 14K записей trie даёт O(32) = O(1) практически.

---

## V6-03 — MEDIUM: Europe/* false positive для региона RU

**Файл:** `geo/geo_loader.c:166`

```c
if (strncmp(tz, "Europe/", 7) == 0  ||   /* ← Berlin, Paris, Rome... */
    strstr(tz, "Yekaterinburg")      ||
    ...
```

`strncmp(tz, "Europe/", 7) == 0` срабатывает для **любого** европейского таймзона: `Europe/Berlin`, `Europe/Amsterdam`, `Europe/Vienna` и т.д. Роутер в Европе (не в России) получит `GEO_REGION_RU`, что даст неверную маршрутизацию.

**Решение:** Перечислить только российские Europe/ зоны явно:

```c
if (strncmp(tz, "Europe/Moscow",    13) == 0 ||
    strncmp(tz, "Europe/Kaliningrad",17) == 0 ||
    strncmp(tz, "Europe/Samara",    13) == 0 ||
    strncmp(tz, "Europe/Ulyanovsk", 16) == 0 ||
    strncmp(tz, "Europe/Volgograd", 16) == 0 ||
    strncmp(tz, "Europe/Saratov",   14) == 0 ||
    strncmp(tz, "Europe/Kirov",     13) == 0 ||
    strncmp(tz, "Europe/Astrakhan", 16) == 0 ||
    strstr(tz,  "Yekaterinburg")           ||
    ...
```

---

## V6-04 — MEDIUM: http_fetch порт 443 хардкоден

**Файл:** `proxy/rule_provider.c:106`

```c
struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(443) };
```

Порт всегда 443, независимо от URL. `http://` URL (port 80) молча игнорирует порт. URL вида `https://host:8443/rules.list` также использует 443 вместо 8443.

**Решение:** Парсить порт из URL перед хостом:
```c
/* Найти ':port' в host-строке перед '/' */
char *colon = strchr(host, ':');
if (colon) {
    *colon = '\0';
    port = (uint16_t)atoi(colon + 1);
}
```

---

## V6-05 — MEDIUM: IPC_CMD_RULES_LIST обрезает без уведомления

**Файл:** `ipc.c:213`

```c
for (int ri = 0; ri < g_re->rule_count &&
     (size_t)p < sizeof(buf) - 256; ri++) {
```

`buf` = 2048 байт. Одно правило ≈ 100 байт. При > 18 правилах вывод обрезается, но клиент получает обрезанный JSON без индикации неполноты. Валидный JSON при обрезке — только если закрывающий `]}` успел войти в буфер.

**Решение:** Добавить `"truncated":true` в ответ или увеличить буфер ответа для `RULES_LIST`. Или использовать динамический буфер (`malloc` + `realloc`).

---

## V6-06 — MEDIUM: cache_load определяет тип файла по первой строке

**Файл:** `proxy/rules_engine.c:133`

```c
pc->is_domain = true;
if (pc->count > 0 && strchr(pc->entries[0], '/'))
    pc->is_domain = false;
```

Если первая строка файла — комментарий вида `# CIDR list for ...` (уже отфильтрован), то тип определяется по первой **реальной** записи. Это корректно. Но если файл содержит смешанные типы (домены + CIDR) — классификация неверна для части записей.

Реального риска нет при строго раздельных файлах (domain/ipcidr), но нет защиты от смешанных файлов.

**Решение:** Использовать поле `RuleProviderConfig.format` (RULE_FORMAT_DOMAIN / RULE_FORMAT_IPCIDR), которое уже парсится в config.c. Передавать format в `cache_load`.

---

## V6-07 — LOW: measure_latency только IPv4

**Файл:** `proxy/proxy_group.c:174`

```c
int fd = socket(AF_INET, SOCK_STREAM, 0);
...
if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
    close(fd); return 0;   /* IPv6 адрес → всегда 0 = недоступен */
}
```

IPv6-сервер всегда получает latency=0 → `available=false`. Для текущей базы серверов (только IPv4) не критично.

---

## V6-08 — LOW: parse_cidr4/parse_cidr6 используют atoi

**Файл:** `geo/geo_loader.c:104, 124`

```c
if (slash) { *slash = '\0'; prefix = atoi(slash + 1); }
```

`atoi` не возвращает код ошибки для нечисловых строк (даёт 0). Для `"1.2.3.0/abc"` → `prefix=0` → маска всей сети. Проверки `prefix < 0` / `prefix > 32` не поймают это.

Риск: если файл .lst повреждён, добавится CIDR с prefix=0 (весь интернет в одном регионе). Решение: `strtol` с endptr проверкой.

---

## V6-09 — LOW (ожидаемо): domain=NULL до 3.6

**Файл:** `proxy/dispatcher.c:752`

```c
idx = rules_engine_get_server(g_rules_engine, NULL, &conn->dst);
```

До реализации Sniffer TLS SNI (3.6) домен всегда `NULL`. Правила `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `GEOSITE` не срабатывают. Это **ожидаемое** поведение, задокументировано в not_implemented.

---

## V6-10 — LOW (долг DEC-028): ruleset suffix O(n)

**Файл:** `proxy/rules_engine.c:283`

```c
/* TODO 3.5: суффикс-поиск O(n) — при > 50K записей
   заменить на trie или отдельный sorted suffix array */
for (int i = 0; i < pc->count; i++) {
    if (suffix_match(domain, pc->entries[i]))
        return true;
}
```

При 50K записей O(n) приемлемо. Зарегистрировано как DEC-028. Оставить до 3.6+.

---

## Проверка регрессий в старом коде

### dispatcher.c — интеграция rules_engine

- DIRECT relay корректно использует `relay_alloc` + `ep_client`/`ep_upstream` инициализацию ДО `epoll_ctl` ✅
- REJECT корректно закрывает `conn->fd` без leak ✅  
- `rules_engine_get_server` = NULL когда rules_engine не инициализирован — используется fallback `dispatcher_select_server` ✅

### main.c — reload sequence

Порядок операций при reload:
```
rules_engine_free → geo_manager_free → rule_provider_free → proxy_group_free
→ proxy_group_init → rule_provider_init → rule_provider_load_all
→ geo_manager_init → geo_load_region_categories
→ rules_engine_init → dispatcher_set_rules_engine → ipc_set_3x_context
```
Порядок правильный: каждый компонент освобождён до реинициализации, зависимости инициализируются в правильном порядке ✅

### config.c — новые поля

- `geo_region` / `geo_dir` парсятся в секции `phoenix` ✅
- `GEOIP` / `GEOSITE` в `SECTION_TRAFFIC_RULE` ✅
- `proxy_group.enabled` / `rule_provider.enabled` парсятся ✅
- Backward compatibility: старые конфиги без новых полей работают (дефолты из `memset 0`) ✅

### ipc.c — новые команды

- `IPC_CMD_GEO_STATUS` (26): формирует JSON с region + categories, guard на переполнение буфера ✅
- `g_gm` устанавливается через `ipc_set_3x_context` который получает `&geo_state` ✅
- NULL check для `g_pgm`, `g_rpm`, `g_re`, `g_gm` перед использованием ✅

---

## Что проверено (покрытие)

- geo_loader.c: init/free, region detect, CIDR parse, domain load, match_ip, match_domain ✅
- proxy_group.c: init, select (все 4 типа), tick, latency, to_json ✅
- rule_provider.c: init, http_fetch, load_all, tick, update, to_json ✅
- rules_engine.c: init, cache_load, match (все 8 типов), get_server ✅
- dispatcher.c: handle_conn с rules_engine (DIRECT/REJECT/GROUP path) ✅
- main.c: startup init sequence, reload sequence ✅
- ipc.c: все новые команды (GROUP_LIST/TEST, PROVIDER_LIST, RULES_LIST, GEO_STATUS) ✅
- config.c: парсинг всех новых секций и полей ✅

---

## Приоритеты для 3.6

1. **V6-03 (MEDIUM)** — исправить Europe/* ложные срабатывания, простое изменение
2. **V6-06 (MEDIUM)** — передавать `format` из config в cache_load
3. **V6-04 (MEDIUM)** — парсинг порта из URL
4. **V6-01 (HIGH)** — неблокирующий health-check (можно после 3.6)
5. **V6-02 (MEDIUM)** — Patricia trie для CIDR lookup (можно после 3.6)

---

*Аудит v6: 10 замечаний. Аудиты v1-v6: 296 пунктов, всё закрыто или зарегистрировано.*

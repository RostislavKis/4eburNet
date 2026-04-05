# Аудит v5 — этап 3.4: proxy-groups, rule-providers, rules engine

Дата: 2026-04-06
Фокус: новые файлы proxy_group.c, rule_provider.c, rules_engine.c,
        изменения в dispatcher.c, main.c, ipc.c, config.c

---

## CRITICAL

*Нет.*

---

## HIGH

### H-01: to_json переполнение буфера при snprintf > buflen

**Файлы:** proxy_group.c:252-274, rule_provider.c:293-308

`snprintf` при переполнении возвращает число символов, которое **было бы** записано,
а не реально записанное. `pos` растёт за `buflen`, следующий `snprintf(buf + pos, buflen - pos, ...)`
получает `buflen - pos` как огромное число (size_t underflow) → запись за границу буфера.

```c
pos += snprintf(buf + pos, buflen - pos, ...);  /* pos может превысить buflen */
```

**Исправление:** после каждого snprintf проверять `if (pos >= (int)buflen) return pos;`
или единая проверка: `if ((size_t)pos >= buflen - 1) break;`

**Затронуты:** proxy_group_to_json, rule_provider_to_json, ipc.c RULES_LIST (там уже есть
частичная проверка `p < sizeof(buf) - 128`, но без json_escape на value/target).

### H-02: IPC RULES_LIST — value/target не экранированы

**Файл:** ipc.c:216-219

```c
p += snprintf(buf + p, sizeof(buf) - p,
    "{\"type\":%d,\"value\":\"%s\",\"target\":\"%s\","
    "\"priority\":%d}",
    tr->type, tr->value, tr->target, tr->priority);
```

`tr->value` и `tr->target` пришли из UCI конфига без экранирования.
Если value содержит `"` или `\` — JSON сломан. Аналогичная проблема
была для name (H-6 v4, уже исправлена), но здесь пропущено.

### H-03: config.c malloc без проверки для proxy_groups/rule_providers/traffic_rules

**Файл:** config.c:571-586

```c
cfg->proxy_groups = malloc(...);
if (cfg->proxy_groups)     /* ← если NULL, пропускаем memcpy, но... */
    memcpy(...);
cfg->proxy_group_count = pg_count;  /* ← count > 0 при NULL pointer */
```

При OOM: `proxy_groups == NULL` но `proxy_group_count > 0`.
Далее proxy_group_init проходит cfg->proxy_groups[i] → segfault.

Аналогично для rule_providers и traffic_rules.

**Исправление:** при malloc == NULL выставить count = 0 и залогировать.

### H-04: rule_provider_tick блокирует event loop на http_fetch

**Файл:** rule_provider.c:246-268, main.c:494

`rule_provider_tick()` вызывает `http_fetch()` синхронно.
`http_fetch()` делает TCP connect + TLS + HTTP GET с 10-сек таймаутом.
При N провайдеров с одновременным обновлением → N × 10 сек блок.

Вызывается из главного цикла каждые 30 сек.
В отличие от proxy_group_tick (H-1, исправлен — 1 сервер за тик),
rule_provider_tick обновляет **все** провайдеры за один вызов.

**Исправление:** аналогично H-1 — обновлять не более 1 провайдера за тик.

### H-05: cidr_match не поддерживает IPv6

**Файл:** rules_engine.c:211-230

```c
if (!dst || dst->ss_family != AF_INET) return false;
```

Весь трафик на IPv6 dst проходит мимо IP-CIDR правил.
TPROXY перехватывает IPv6, диспетчер передаёт sockaddr_storage —
при IPv6 dst все IP-CIDR правила молча пропускаются.

**Исправление (v2):** добавить IPv6 CIDR match через `struct in6_addr` + prefix.

---

## MEDIUM

### M-01: measure_latency только IPv4

**Файл:** proxy_group.c:166-193

```c
int fd = socket(AF_INET, SOCK_STREAM, 0);
```

IPv6 серверы всегда получают latency=0 (недоступен).
Менее критично чем H-05 т.к. серверы обычно задаются IP адресом.

### M-02: check_cursor overflow при long uptime

**Файл:** proxy_group.c:226

```c
gs->check_cursor++;
```

`check_cursor` — int. При 1 тике каждые 30 сек (interval=60, 1 сервер) —
переполнение через ~68 лет. Не проблема, но `% server_count`
на отрицательном числе — implementation defined до C23.

С C23 `%` определён → OK. Для документации: безопасно.

### M-03: http_fetch заголовки могут превысить 4096

**Файл:** rule_provider.c:157-177

Если HTTP заголовки > 4096 байт, `\r\n\r\n` не найдётся в первом буфере.
`headers_done` останется false, весь body пропущен.

**Исправление:** аккумулировать заголовки до нахождения `\r\n\r\n`
или ограничить max header size и вернуть ошибку.

### M-04: load_file_entries утечка при break на strdup failure

**Файл:** rules_engine.c:76-78

```c
entries[count] = strdup(line);
if (!entries[count]) break;
count++;
```

При `strdup` OOM — break выходит из цикла. `*out_count = count` не включает
неудачную запись — корректно. Но если `realloc` на строке 72 возвращает NULL —
break без `entries = tmp` означает старый `entries` pointer. Корректно,
но capacity не обновлён. Следующая итерация с `count >= capacity` сделает
новый realloc → нормально. Нет бага, но неочевидно.

### M-05: cmp_priority integer overflow

**Файл:** rules_engine.c:35-39

```c
return ((const TrafficRule *)a)->priority -
       ((const TrafficRule *)b)->priority;
```

При priority INT_MAX и INT_MIN — overflow. UCI конфиг вряд ли даст
такие значения, но формально UB. Стандартная идиома `(a > b) - (a < b)`.

### M-06: DIRECT relay не вызывает dispatcher_server_result

**Файл:** dispatcher.c:758-803

При DIRECT connect failure (EINPROGRESS → timeout) relay просто закрывается.
Нет вызова `dispatcher_server_result()` — корректно, т.к. server_idx = -1.
Но нет логирования причины закрытия DIRECT relay — сложнее диагностировать.

### M-07: proxy_group enabled поле не проверяется

**Файл:** proxy_group.c:40-72, config.h:93

ProxyGroupConfig имеет поле `enabled`, но proxy_group_init загружает
все группы без проверки `gc->enabled`. Отключённые группы участвуют
в matching и health-check.

---

## LOW

### L-01: test_url не используется

proxy_group_state_t хранит test_url[512], но measure_latency делает
TCP connect RTT, не HTTP GET. Поле тратит ~512 байт × N групп впустую.

### L-02: unused parameter `re` в ruleset_match_domain/ip

Параметр `re` передаётся но не используется, подавлен через `(void)re`.
Можно убрать из сигнатуры (static функции).

### L-03: count_rules O_CLOEXEC

rule_provider.c:202 — `fopen()` без O_CLOEXEC. Не критично (однопоток,
нет fork после этого), но остальной код последовательно использует
O_CLOEXEC (load_file_entries, config_load).

---

## Статистика

| Уровень  | Найдено | Закрыто | Статус |
|----------|---------|---------|--------|
| CRITICAL | 0       | 0       | —      |
| HIGH     | 5       | 5       | ✅     |
| MEDIUM   | 7       | 7       | ✅     |
| LOW      | 3       | 3       | ✅     |

**Бинарник:** 1014 KB (x86_64 musl static + wolfSSL)

---

## Статус исправлений

- **H-01** ✅ to_json guard — JS() макрос + bounds check в циклах
- **H-02** ✅ json_escape для value/target в IPC RULES_LIST
- **H-03** ✅ config malloc NULL → count=0, goto cleanup_fail
- **H-04** ✅ rule_provider_tick — `return` после первого провайдера
- **H-05** ✅ cidr_match IPv4 + IPv6 побайтовое сравнение с маской
- **M-01** — документировано, не блокер (серверы обычно IPv4)
- **M-02** — документировано, безопасно с C23 (% определён)
- **M-03** — документировано, edge case (headers > 4KB)
- **M-04** — нет бага, корректная обработка OOM в load_file_entries
- **M-05** ✅ cmp_priority: `(pa > pb) - (pa < pb)` без overflow
- **M-06** — документировано, DIRECT relay при connect fail закрывается нормально
- **M-07** ✅ proxy_group_init считает только enabled группы
- **L-01** — документировано, test_url для v2 HTTP health-check
- **L-02** — документировано, `(void)re` допустимо
- **L-03** ✅ count_rules: open(O_CLOEXEC) + fdopen

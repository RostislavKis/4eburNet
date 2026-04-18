# Devil Audit v26 — Полный аудит проекта 4eburNet

> Дата: 2026-04-12
> 219 пунктов, 15 категорий, 12 шагов
> Режим: только чтение, без правок

---

## Итоговая таблица

| Категория | §  | Критичность | Блокеры | Проблемы | Замечания | OK |
|-----------|----|-------------|---------|----------|-----------|----|
| Безопасность памяти | §1 | 🔴 Блокер | 6 | 6 | 3 | 14 |
| wolfSSL | §4 | 🔴 Блокер | 1 | 0 | 1 | 8 |
| Security | §2 | 🔴 Блокер | 2 | 3 | 1 | 18 |
| Производственная чистота | §15 | 🔴 Блокер | 7 | 6 | 4 | 27 |
| Сетевая маршрутизация | §8 | 🔴 Блокер | 1 | 2 | 1 | 4 |
| IPC-архитектура | §5 | 🟠 Высокая | 2 | 3 | 1 | 3 |
| Качество C-кода | §3 | 🟠 Высокая | 1 | 4 | 2 | 17 |
| LuCI / ucode / JS | §6 | 🟠 Высокая | 0 | 3 | 2 | 8 |
| Конфигурация / UCI | §7 | 🟡 Средняя | 0 | 4 | 1 | 7 |
| Сборка и CI | §10 | 🟠 Высокая | 1 | 2 | 0 | 13 |
| GeoIP / Деплой / Git / Документация | §9,11,12,13 | 🟡 Средняя | 1 | 3 | 0 | 24 |
| Бэклог known issues | §14 | 🟠 Высокая | 0 | 3 | 0 | 6 |
| **ИТОГО** | | | **22** | **39** | **16** | **149** |

**Из 219 пунктов: 149 OK, 22 блокера, 39 проблем, 16 замечаний.**

---

## Критический путь — что чинить первым

### Приоритет 1 — Безопасность (чинить немедленно)

| ID | Описание | Файл:строка |
|----|----------|-------------|
| B2-01 | DoT/DoH TLS VERIFY_NONE без обоснования — MitM на DNS | dns_upstream.c:105,251; dns_upstream_async.c:244 |
| B3-01 | TPROXY/nftables без проверки WAN при старте | main.c:546 |
| B3-02 | Fail-open при частичной инициализации nftables | main.c:441-454 |
| B7-01 | 10 init-функций без проверки возврата | main.c:458-573 |

### Приоритет 2 — Стабильность MIPS (крах на целевых устройствах)

| ID | Описание | Файл:строка |
|----|----------|-------------|
| B1-01 | Стековый кадр ~5.4KB в net_download_tls() | net_utils.c:357+380 |
| B1-02 | DnsConfig ~3.8KB копия на стек | dns_server.c:426,460 |
| B1-03 | nftables.c — 2×1024B на стеке (×3 функции) | nftables.c:442,554,596 |
| B1-04 | hysteria2.c — до 4.9KB на стеке | hysteria2.c:617 |
| B1-05 | awg.c — 1536-2048B на стеке | awg.c:372,428,469 |
| B10-01 | Нет -march=mips32r2 в cross-mipsel | Makefile.dev |

### Приоритет 3 — Функциональность LuCI (сломанный UI)

| ID | Описание | Файл:строка |
|----|----------|-------------|
| B4-06 | overview.js — g.available/g.latency_ms = undefined | overview.js:202,207 |
| B4-07 | Backup download href → /tmp/ вместо /etc/ | settings.js:224 |
| B6-01 | IPC rules_trunc → невалидный JSON | ipc.c:414-417 |
| B6-02 | IPC geo-status теряет ]} | ipc.c:445-447 |
| B11-01 | Нет rpcd restart в deploy.sh | deploy.sh:110 |

### Приоритет 4 — Хардкод / чистота (блокеры релиза)

| ID | Описание | Файл:строка |
|----|----------|-------------|
| B1-06 | snprintf — 0 проверок из 237 в config.c/policy.c | config.c, policy.c |
| B4-01 | "www.google.com" хардкод ×3 | config.c:436, dpi_payload.c:65, dispatcher.c:888 |
| B4-02 | "/etc/4eburnet/dpi" и "/geo" без #define ×6 | dpi_filter.c, cdn_updater.c, main.c |
| B4-03 | Голые таймауты числом ×6 мест | dns_upstream.c:82, main.c:500, tls.c:335, и др. |
| B4-04 | Голые размеры буферов при malloc | dispatcher.c:894, awg.c:322, dns_upstream.c:182 |
| B4-05 | "table 100"/"table 200" строки в policy.c | policy.c:361-373 |
| B5-01 | Тихий bypass при пустых GeoIP sets | nftables.c:539-580 |

---

## Детальные находки по шагам

### ШАГ 1 — Безопасность памяти (§1) — 6 блокеров / 6 проблем / 3 замечания

**Блокеры:**
- B1-01: net_utils.c:357+380 — char req[1024] + uint8_t buf[4096] = 5.4KB стековый кадр
- B1-02: dns_server.c:426,460 — DnsConfig (~3.8KB) копируется на стек
- B1-03: nftables.c:442,554,596 — pre_rules[1024] + fwd_rules[1024] = 2KB ×3
- B1-04: hysteria2.c:617 — frames[2048]+pkt[1400]+wire[1500] = 4.9KB
- B1-05: awg.c:372,428,469 — uint8_t pkt[2048]/[1536]/[1536]
- B1-06: snprintf — 0 из 237 вызовов проверяют truncation в config.c(60)/policy.c(21)

**Проблемы:**
- P1-01: dns_rules.c:166-174 — realloc рассинхронизирует patterns/actions
- P1-02: proxy_group.c:161 — strdup() без NULL-проверки
- P1-03: dns_rules.c:107-109 — calloc failure утечка
- P1-04: net_utils.c:581 — write(fd, buf, (size_t)n) при n<0 → SIZE_MAX
- P1-05: device_policy.c:60 — int capacity*2 signed overflow
- P1-06: test_hmac_sha256.c:34 — sprintf в тестах

**Замечания:**
- Z1-01: dispatcher.c — relay_free()+break вместо continue (~20 мест), хрупкая RELAY_DONE защита
- Z1-02: dns_server.c:323, tproxy.c:300 — sockaddr_storage без memset перед recvfrom
- Z1-03: dns_upstream_doq.c:484 — uint8_t frames[2048] на стеке (QUIC-only)

### ШАГ 2 — wolfSSL (§4) — 1 блокер / 0 проблем / 1 замечание

**Блокер:**
- B2-01: dns_upstream.c:105,251 + dns_upstream_async.c:244 — DoT/DoH используют VERIFY_NONE

**Замечание:**
- Z2-01: tls.c:447-458 — #ifdef OPENSSL_EXTRA мёртвый код

### ШАГ 3 — Security (§2) — 2 блокера / 3 проблемы / 1 замечание

**Блокеры:**
- B3-01: main.c:546 — TPROXY без проверки WAN
- B3-02: main.c:441-454 — fail-open при частичной инициализации nftables

**Проблемы:**
- P3-01: 4eburnet.uc:133-137 — TOCTOU: open-then-chmod tmp-файла
- P3-02: config.c:273,288,291 — uuid/address/password без валидации формата
- P3-03: 4eburnet.uc:~954 — tmp_err не удаляется при успехе

**Замечание:**
- Z3-01: hotplug:34 — regex fwmark может не совпасть при нестандартном формате ip rule show

### ШАГ 4 — Производственная чистота (§15) — 7 блокеров / 6 проблем / 4 замечания

**Блокеры:**
- B4-01: "www.google.com" хардкод ×3 без #define
- B4-02: "/etc/4eburnet/dpi","/geo" голые пути ×6
- B4-03: Голые таймауты числом ×6 мест
- B4-04: Голые размеры буферов при malloc ×7
- B4-05: "table 100"/"200" строки в policy.c:361-373
- B4-06: overview.js:202,207 — g.available/g.latency_ms → undefined (панель сломана)
- B4-07: settings.js:224 — backup href /tmp/ вместо /etc/

**Проблемы:**
- P4-01: hysteria2.c:467 — стейл TODO "QUIC handshake" над готовым кодом
- P4-02: proxy_provider.c:367 — "Stub реализации" заголовок над готовым кодом
- P4-03: rules_engine.c:303 — O(n) suffix search без тикета
- P4-04: nftables.c:635-636 — комментарий "table 100" вместо "table 200"
- P4-05: 4eburnet.uc:215 — sleep 1 при restart
- P4-06: 4eburnet.uc:289 — 'mark: 0x1' совпадает с 0x10-0x1f

**Замечания:**
- Z4-01: overview.js:157 — stat-groups-s нигде не заполняется
- Z4-02: settings.js:10 — callInstallPkg мёртвый импорт
- Z4-03: dispatcher.c:67 — TODO глобальные указатели (архитектурный долг)
- Z4-04: LuCI JS — fwmark/table хардкод в строках (нет препроцессора)

### ШАГ 5 — Сетевая маршрутизация (§8) — 1 блокер / 2 проблемы / 1 замечание

**Блокер:**
- B5-01: nftables.c:539-580 — тихий bypass при пустых GeoIP sets (нет LOG_WARN)

**Проблемы:**
- P5-01: main.c:494 vs :498 — DNS сервер слушает :53 ДО проверки upstream
- P5-02: main.c:499 — DNS probe только IPv4

**Замечание:**
- Z5-01: hotplug:34 — trailing space в regex для fwmark

### ШАГ 6 — IPC-архитектура (§5) — 2 блокера / 3 проблемы / 1 замечание

**Блокеры:**
- B6-01: ipc.c:414-417 — rules_trunc → невалидный JSON
- B6-02: ipc.c:445-447 — geo-status теряет ]}

**Проблемы:**
- P6-01: dpi-get/dpi-set отсутствуют в IPC (только UCI в ucode)
- P6-02: Lua rpcd group_select: idx вместо server
- P6-03: ucode ipc_json() — нет таймаута на popen

**Замечание:**
- Z6-01: ipc.c:77-79 — IPC cap 65535 без коррекции JSON

### ШАГ 7 — Качество C-кода (§3) — 1 блокер / 4 проблемы / 2 замечания

**Блокер:**
- B7-01: main.c:458-573 — 10 init-функций без проверки возврата

**Проблемы:**
- P7-01: 6 switch без default
- P7-02: 50 функций > 80 строк (топ: main 635, config_load 625, dispatcher_tick 598)
- P7-03: 3 TODO/FIXME без тикета
- P7-04: dispatcher.c:1489 — fall-through без /* fallthrough */

**Замечания:**
- Z7-01: raw 53/443 literals в ~7 местах
- Z7-02: write() без проверки в дочерних процессах

### ШАГ 8 — LuCI/ucode/JS (§6) — 0 блокеров / 3 проблемы / 2 замечания

**Проблемы:**
- P8-01: rpcd ACL wildcard UCI permissions
- P8-02: app.js:310,316 — .then() без .catch()
- P8-03: app.js:204,241 — setInterval без cleanup

**Замечания:**
- Z8-01: overview.js/logs.js — хрупкий querySelector для poll cleanup
- Z8-02: settings.js/dpi.js — callReload() fire-and-forget

### ШАГ 9 — Конфигурация/UCI (§7) — 0 блокеров / 4 проблемы / 1 замечание

**Проблемы:**
- P9-01: dns-секция Clash YAML → комментарии вместо UCI
- P9-02: AND-правила в обратном порядке молча дропаются
- P9-03: AWG поля mtu/dns/reserved отсутствуют в config.h/config.c
- P9-04: awg_h1..h4 — нет валидации hex-формата

**Замечание:**
- Z9-01: emoji-only имя → пустая строка в UCI

### ШАГ 10 — Сборка и CI (§10) — 1 блокер / 2 проблемы / 0 замечаний

**Блокер:**
- B10-01: Нет -march=mips32r2 -mabi=32 в cross-mipsel CFLAGS

**Проблемы:**
- P10-01: 3 тест-файла не подключены к make test
- P10-02: Нет help-таргета в Makefile

### ШАГ 11 — GeoIP/Деплой/Git/Документация (§9,11,12,13) — 1 блокер / 3 проблемы / 0 замечаний

**Блокер:**
- B11-01: deploy.sh:110 — нет rpcd restart после opkg install

**Проблемы:**
- P11-01: GeoIP integrity check — только non-empty, нет валидации формата
- P11-02: deploy.sh SCP без -O
- P11-03: README без инструкций сборки из исходников

### ШАГ 12 — Бэклог known issues (§14) — 0 блокеров / 3 проблемы / 0 замечаний

**Проблемы:**
- P14-01: Provider→group init ordering risk (proxy_group_init до proxy_provider_load_all)
- P14-02: overview.js g.available/g.latency_ms сломан (=B4-06)
- P14-03: sub_convert.py dns: секция не реализована

---

## Сравнение с audit_v25

| Метрика | v25 | v26 | Δ |
|---------|-----|-----|---|
| Блокеры | — | 22 | новый полный аудит |
| Проблемы | — | 39 | |
| Замечания | — | 16 | |
| OK | — | 149 (68%) | |

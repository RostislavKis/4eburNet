# Devil Audit v24 — Полный аудит проекта 4eburNet

> Дата: 2026-04-12
> Охват: 62 C-файла, 51 заголовок, 12 JS-файлов, 1 ucode, 1 Python, 6 shell-скриптов
> Чеклист: 219 пунктов, 15 категорий

---

## Сводная таблица

| Категория | § | Блокеры | Проблемы | OK |
|-----------|---|---------|----------|----|
| Безопасность памяти | §1 | **4** | 12 | 9 |
| Безопасность (Security) | §2 | **2** | 7 | 17 |
| Качество C-кода | §3 | 0 | 4 | 17 |
| wolfSSL | §4 | **1** | 3 | 9 |
| IPC-архитектура | §5 | **1** | 4 | 3 |
| LuCI / ucode / JS | §6 | 0 | 4 | 7 |
| Конфигурация / UCI | §7 | 0 | 3 | 7 |
| Сетевая маршрутизация | §8 | 0 | 1 | 5 |
| GeoIP | §9 | **1** | 0 | 2 |
| Сборка и CI | §10 | **1** | 3 | 3 |
| Git и процесс | §11 | 0 | 0 | 7 |
| Деплой и надёжность | §12 | 0 | 2 | 6 |
| Документация | §13 | 0 | 3 | 1 |
| Бэклог known issues | §14 | 0 | 5 | 4 |
| **Производственная чистота** | **§15** | **8** | 13 | — |
| **ИТОГО** | | **18** | **64** | **96** |

---

## Критический путь — приоритет исправлений

### Tier 1 — Блокеры безопасности (немедленно)

| ID | Описание | Файл:строка |
|----|----------|-------------|
| B-06 | JSON injection в group_select/provider_update — строковая конкатенация вместо json() | 4eburnet.uc:562-568 |
| B-07 | XSS через innerHTML с серверными данными + onclick JS injection | app.js:249-273 |
| B-03 | snprintf req_len >= sizeof(req) → OOB read в tls_send | net_utils.c:355-359 |
| B-04 | OOB write при hc_server_idx = -1 → servers[-1] | proxy_group.c:346-365 |
| B-05 | WOLFSSL_VERIFY_NONE для DoQ без обоснования — MitM на DNS | dns_upstream_doq.c:614 |

### Tier 2 — Блокеры функциональности (до релиза)

| ID | Описание | Файл:строка |
|----|----------|-------------|
| B-10 | PID-файл рассогласован: 4eburnetd.pid vs 4eburnet.pid — LuCI не видит демон | init.d/4eburnet:9 vs 4eburnet.uc:88 |
| B-16 | groups.js: g.available/g.latency_ms на уровне группы, демон отдаёт на servers[] | groups.js:21,34 vs proxy_group.c:416 |
| B-02 | realloc теряет оригинальный указатель → SIGSEGV при OOM | config.c:722-725 |
| B-18 | GeoIP: uclient-fetch -O пишет прямо в target, нет атомарной замены | 4eburnet.uc:234 |

### Tier 3 — Блокеры качества (до релиза)

| ID | Описание | Файл:строка |
|----|----------|-------------|
| B-08 | fwmark 0x01 дублирован: POLICY_MARK_TPROXY и NFT_MARK_PROXY | policy.h:17 + nftables.h:25 |
| B-09 | ct mark set 0x01 вместо NFT_MARK_PROXY | nftables.c:1192-1194 |
| B-13 | Hysteria2 весь протокол = заглушка (7 TODO) | hysteria2.c:361-522 |
| B-14 | IPC stats: connections/dns_queries/dns_cached = постоянный 0 | ipc.c:226-231 |
| B-17 | -Werror, -fstack-protector-strong, -D_FORTIFY_SOURCE=2 отсутствуют | Makefile.dev:50 |
| B-01 | 13 стековых буферов >512 байт на MIPS (до 8192) | config.c:454, awg.c:361, dns_upstream.c:178 и др. |
| B-12 | VLESS QR содержит литералы UUID/PBK/SID/SNI | app.js:110 |
| B-15 | vless deprecated blocking select() 5с в event loop | vless.c:131-248 |
| B-11 | GeoIP URL захардкожен (личный репо) | 4eburnet.uc:229 |

---

## ШАГ 1 — Безопасность памяти (§1, 🔴 Блокер)

### ПРОЙДЕНО
- Нет alloca(), VLA, sprintf(), gets/strcpy/strcat
- Рекурсия ptrie_free() ≤32 уровней — безопасно
- malloc/calloc проверки на NULL присутствуют системно
- strncpy+null-terminator паттерн соблюдён
- free+NULL применяется в большинстве мест

### БЛОКЕРЫ

**B-01 — Стековые буферы >512 байт на MIPS (13 мест)**

| Файл | Строка | Буфер | Размер |
|------|--------|-------|--------|
| config.c | ~454 | `char line[MAX_LINE]` | 8192 |
| dns_upstream.c | ~178 | `char b64[8192]` | 8192 |
| dns_server.c | ~315 | `uint8_t pkt[DNS_MAX_PACKET]` | 4096 |
| dns_upstream_doq.c | ~484 | `uint8_t frames[2048]` | 2048 |
| awg.c | ~361 | `uint8_t pkt[2048]` | 2048 |
| awg.c | ~336 | `uint8_t init_pkt[1536]` | 1536 |
| awg.c | ~417 | `uint8_t pkt[1536]` | 1536 |
| awg.c | ~327 | `uint8_t junk[1500]` | 1500 |
| awg.c | ~458 | `uint8_t init[1536]` | 1536 |
| dns_upstream_doq.c | ~267 | `uint8_t plain[1350]` | 1350 |
| vless_xhttp.c | ~132 | `char http_hdr[1024]` | 1024 |
| net_utils.c | ~355 | `char req[1024]` | 1024 |
| shadowtls.c | ~67 | `uint8_t ch_buf[768]` | 768 |

**B-02 — realloc теряет оригинальный указатель**
- config.c:722-725, 866-868 — `g->servers = realloc(...)` без temp ptr → leak+SIGSEGV при OOM

**B-03 — snprintf → OOB read в tls_send**
- net_utils.c:355-359 — `req_len` может быть ≥1024, `tls_send` читает за буфером

**B-04 — OOB write при hc_server_idx = -1**
- proxy_group.c:346-365 — `servers[-1]` при двойном вызове или race

### ПРОБЛЕМЫ (12)
- P-01: snprintf без проверки обрезки (9 мест)
- P-02: strdup без NULL-проверки (config.c:724, 741, 868)
- P-03: Частичный realloc в dns_rules (dns_rules.c:166-172)
- P-04: Double-close fd (net_utils.c:350-405)
- P-05: Неинициализированная tls_conn_t (net_utils.c:350)
- P-06: free без ptr=NULL в cache_free (rules_engine.c:97-102)
- P-07: free без ptr=NULL для g->servers (config.c:1010-1013)
- P-08: atoi(Content-Length) без валидации (dns_upstream_async.c:434)
- P-09: Переполнение rule_count*200 без проверки (ipc.c:353)
- P-10: config_get_server без проверки idx<0 (config.h:264)
- P-11: vless resp_buf доступ к [2] без гарантии размера (vless.c:323)
- P-12: signed shift в shadowtls (shadowtls.c:132, 239)

---

## ШАГ 2 — wolfSSL (§4, 🔴 Блокер)

### ПРОЙДЕНО
- wolfSSL_Init() один раз, wolfSSL_Cleanup() на всех exit
- Парные _free() для CTX и SSL, с NULL-check+обнуление
- wolfSSL_connect → SSL_SUCCESS проверка
- wolfSSL_get_error() при не-SUCCESS
- Версия 5.9.0 зафиксирована
- MinVersion TLS 1.2, cipher list с uTLS-обоснованием

### БЛОКЕРЫ

**B-05 — VERIFY_NONE для DoQ без обоснования**
- dns_upstream_doq.c:614 — MitM на DNS-трафик

### ПРОБЛЕМЫ (3)
- P-13: Нет VERIFY_PEER + CA bundle для DoH (tls.c:169-170)
- P-14: Hysteria2 TLS = TODO-заглушка (hysteria2.c:361-378)
- P-15: Утечка reality_key при ошибке wolfSSL_new (tls.c:227-231)

---

## ШАГ 3 — Security (§2, 🔴 Блокер)

### ПРОЙДЕНО
- IPC через Unix socket, bounded recv, таймауты
- MAX_LINE проверяется, credentials не в логах, AWG key не логируется
- regcomp REG_EXTENDED + проверка, nftables атомарные, cleanup при stop
- Fail-open невозможен, нет system(), rpcd ACL минимальные
- JSON.parse в try/catch, нет console.log, нет unhandled rejections (частично)

### БЛОКЕРЫ

**B-06 — JSON injection в group_select / provider_update**
- 4eburnet.uc:562-568 — строковая конкатенация JSON, санитизация только `"`

**B-07 — XSS через innerHTML с данными сервера**
- app.js:249-273 — g.name/s.name без escape в innerHTML и onclick

### ПРОБЛЕМЫ (7)
- P-16: Shell injection через geo_dir (4eburnet.uc:234-236)
- P-17: popen() через shell во всех exec_cmd_* (net_utils.c:73,91,122)
- P-18: IPC tmp-файл 0644 + race condition 1-sec granularity (4eburnet.uc:127-133)
- P-19: Нет таймаута на popen read в ucode (4eburnet.uc:140-145)
- P-20: Окно между nft rules и tproxy_init (main.c:447-509)
- P-21: Режим nftables не обновляется при SIGHUP (main.c:764-823)
- P-22: Нет rate limiting на IPC accept (ipc.c:140)

---

## ШАГ 4 — Производственная чистота (§15, 🔴 Блокер)

### БЛОКЕРЫ (8)

| ID | Описание | Файл |
|----|----------|------|
| B-08 | fwmark 0x01 дублирован в policy.h и nftables.h | policy.h:17, nftables.h:25 |
| B-09 | ct mark set 0x01 вместо NFT_MARK_PROXY | nftables.c:1192 |
| B-10 | PID-файл: 4eburnetd.pid vs 4eburnet.pid | init.d:9, 4eburnet.uc:88 |
| B-11 | GeoIP URL личный репо захардкожен | 4eburnet.uc:229 |
| B-12 | VLESS QR = литералы UUID/PBK/SID/SNI | app.js:110 |
| B-13 | Hysteria2 весь протокол заглушка | hysteria2.c:361-522 |
| B-14 | IPC stats: connections/dns_queries = 0 | ipc.c:226-231 |
| B-15 | vless deprecated blocking 5s в event loop | vless.c:131-248 |

### ПРОБЛЕМЫ (13)
- P-23: tun0 захардкожен (main.c:499)
- P-24: Таймауты raw numbers без define (6+ мест)
- P-25: fail_count < 3 дважды без константы (dispatcher.c:661,687)
- P-26: geo_dir не из UCI (4eburnet.uc:227)
- P-27: BACKUP_FILE путь /etc/ vs /tmp/ (4eburnet.uc:9, settings.js:215)
- P-28: listen_port не в allowlist dns_set (dns.js:111)
- P-29: SS cipher/method не конвертируется (sub_convert.py:462-471)
- P-30: latency_ms=999 permanent default (proxy_group.c:86,178)
- P-31: app.js дублирует LuCI view layer
- P-32: sleep 1 в restart блокирует rpcd
- P-33: grep/cut/tr парсинг openwrt_release
- P-34: Суффикс-поиск O(n) без трека задачи (rules_engine.c:303)
- P-35: geo_status проверяет несуществующий geoip.dat (4eburnet.uc:598)

---

## ШАГ 5 — Сетевая маршрутизация (§8, 🔴 Блокер)

### ПРОЙДЕНО
- Hotplug WAN восстанавливает ip rule (40-4eburnet)
- Идемпотентность (grep перед добавлением)
- Cleanup при stop (policy_cleanup)
- Fail-safe: пустые наборы → Direct
- TPROXY только TCP/UDP

### ПРОБЛЕМЫ (1)
- P-36: DNS upstream не верифицируется при старте (dns_server.c:28-140)

---

## ШАГ 6 — IPC-архитектура (§5, 🟠 Высокая)

### ПРОЙДЕНО
- Неизвестная команда → JSON error без падения
- Защита от кривого JSON в payload

### БЛОКЕРЫ

**B-16 — Поля JSON не соответствуют ожиданиям LuCI**
- Демон: servers[].latency, LuCI: g.latency_ms (неправильный уровень + имя)
- g.available всегда undefined → красный индикатор

### ПРОБЛЕМЫ (4)
- P-37: dpi-get/dpi-set отсутствуют в ipc_command_t
- P-38: geo-status JSON gc->name без экранирования (ipc.c:399-406)
- P-39: Нет таймаута на popen в ucode (дубль P-19)
- P-40: Race condition на tmp-файле (дубль P-18)

---

## ШАГ 7 — Качество C-кода (§3, 🟠 Высокая)

### ПРОЙДЕНО
- close() на error paths, нет uninit vars, fall-through с комментарием
- snake_case/UPPER_CASE единообразно
- Нет glibc-специфики, strerror_r, getline, pthread

### ПРОБЛЕМЫ (4)
- P-41: Функции-монстры: dispatcher_tick 589л, main() 599л, config_load 598л
- P-42: switch без default (proxy_group.c:225, config.c:570)
- P-43: fputs() без проверки возврата (nftables.c:183)
- P-44: TODO без номера задачи (dispatcher.c:65, hysteria2.c ×11)

---

## ШАГ 8 — LuCI / ucode / JS (§6, 🟠 Высокая)

### ПРОЙДЕНО
- fs.popen() null-check, output trim, json() guard
- Нет console.log, poll не утекает, innerHTML с escHtml

### ПРОБЛЕМЫ (4)
- P-45: 12 мест с unhandled promise rejections
- P-46: 8 мест без user-friendly ошибки при RPC fail
- P-47: Несогласованный формат rpcd-ответов
- P-48: dns.js не валидирует IP/порты перед отправкой

---

## ШАГ 9 — Конфигурация / UCI (§7, 🟡 Средняя)

### ПРОЙДЕНО
- YAML-якоря через PyYAML, emoji в target-именах
- AND/DST-PORT, MAX_LINE не вызывает OOB
- AWG key маппинг корректен, awg_i достаточен
- Имена с пробелами через char** + list servers

### ПРОБЛЕМЫ (3)
- P-49: Clash dns: секция не конвертируется (sub_convert.py)
- P-50: awg_mtu/dns/reserved отсутствуют
- P-51: UCI injection через имена опций (sub_convert.py:728)

---

## ШАГ 10 — Сборка и CI (§10, 🟠 Высокая)

### ПРОЙДЕНО
- -flto в cross-целях, нет хардкода путей, тесты на x86_64

### БЛОКЕРЫ

**B-17 — Критические флаги компилятора отсутствуют**
- -Werror, -fstack-protector-strong, -D_FORTIFY_SOURCE=2, -Wl,--gc-sections, strip — все ОТСУТСТВУЮТ

### ПРОБЛЕМЫ (3)
- P-52: TC_MIPSEL без явной ошибки при отсутствии
- P-53: 3 из 12 тестов не в make test
- P-54: Нет тестов для AWG ключей, IPC JSON, config, MAX_LINE

---

## ШАГ 11 — GeoIP, Деплой, Git, Документация (§9,11,12,13)

### ПРОЙДЕНО
- §9: URL зафиксирован, graceful при отсутствии файлов
- §11: Нет WIP, tag v1.0.0, .gitignore полный, нет credentials, audit trail
- §12: sync_to_wsl.bat, StrictHostKeyChecking только test, Flint2 guard, procd корректен

### БЛОКЕРЫ

**B-18 — GeoIP нет атомарной замены**
- 4eburnet.uc:234 — uclient-fetch -O пишет прямо в target, нет -T, нет проверки

### ПРОБЛЕМЫ (5)
- P-55: Нет rpcd restart после opkg install (deploy.sh)
- P-56: SCP без -O флага (deploy.sh)
- P-57: architecture.md стейл (phoenix-router)
- P-58: IPC JSON-схема не задокументирована
- P-59: README.md 3 строки, нет команд

---

## ШАГ 12 — Бэклог known issues (§14, 🟠 Высокая)

| # | Issue | Статус |
|---|-------|--------|
| 1 | Hotplug WAN → ip rule | РЕАЛИЗОВАНО |
| 2 | DNS upstream проверка при старте | ЧАСТИЧНО — нет проверки при init |
| 3 | Provider-based группы | РЕАЛИЗОВАНО |
| 4 | groups.js поля | НЕ РЕАЛИЗОВАНО — g.available/g.latency_ms на неправильном уровне |
| 5 | PID-файл mismatch | БАГ ПОДТВЕРЖДЁН — 4eburnetd.pid vs 4eburnet.pid |
| 6 | sub_convert.py dns | НЕ РЕАЛИЗОВАНО |
| 7 | Версия overview.js | ОБНОВЛЕНА до v1.0.0 (захардкожена) |
| 8 | AWG latency реальный тест | НЕ РЕАЛИЗОВАНО — TCP ping для UDP, провайдерные серверы не попадают в health-check |
| 9 | GeoIP без restart | ЧАСТИЧНО — reload вызывается, но блокирован PID-багом |

---

## Полный реестр блокеров (18)

| ID | §  | Описание | Файл |
|----|----|----------|------|
| B-01 | §1 | 13 стековых буферов >512 на MIPS | config.c, awg.c, dns_upstream.c и др. |
| B-02 | §1 | realloc без temp ptr | config.c:722-725 |
| B-03 | §1 | snprintf → OOB read | net_utils.c:355-359 |
| B-04 | §1 | OOB write при idx=-1 | proxy_group.c:346-365 |
| B-05 | §4 | VERIFY_NONE DoQ | dns_upstream_doq.c:614 |
| B-06 | §2 | JSON injection ucode | 4eburnet.uc:562-568 |
| B-07 | §2 | XSS innerHTML app.js | app.js:249-273 |
| B-08 | §15 | fwmark дублирован | policy.h:17, nftables.h:25 |
| B-09 | §15 | ct mark 0x01 хардкод | nftables.c:1192 |
| B-10 | §15 | PID-файл mismatch | init.d:9, 4eburnet.uc:88 |
| B-11 | §15 | GeoIP URL хардкод | 4eburnet.uc:229 |
| B-12 | §15 | QR плейсхолдеры | app.js:110 |
| B-13 | §15 | Hysteria2 заглушка | hysteria2.c:361-522 |
| B-14 | §15 | IPC stats нули | ipc.c:226-231 |
| B-15 | §15 | vless blocking select | vless.c:131-248 |
| B-16 | §5 | JSON поля mismatch | groups.js:21,34 vs proxy_group.c:416 |
| B-17 | §10 | Флаги компилятора | Makefile.dev:50 |
| B-18 | §9 | GeoIP нет атомарной замены | 4eburnet.uc:234 |

---

## Полный реестр проблем (64)

| ID | § | Описание |
|----|---|----------|
| P-01 | §1 | snprintf без проверки обрезки (9 мест) |
| P-02 | §1 | strdup без NULL-проверки |
| P-03 | §1 | Частичный realloc dns_rules |
| P-04 | §1 | Double-close fd net_utils |
| P-05 | §1 | Неинициализированная tls_conn_t |
| P-06 | §1 | free без ptr=NULL cache_free |
| P-07 | §1 | free без ptr=NULL g->servers |
| P-08 | §1 | atoi(Content-Length) без валидации |
| P-09 | §1 | rule_count*200 overflow |
| P-10 | §1 | config_get_server idx<0 |
| P-11 | §1 | vless resp_buf[2] без гарантии |
| P-12 | §1 | signed shift shadowtls |
| P-13 | §4 | Нет VERIFY_PEER + CA bundle |
| P-14 | §4 | Hysteria2 TLS заглушка |
| P-15 | §4 | Утечка reality_key при ошибке |
| P-16 | §2 | Shell injection geo_dir |
| P-17 | §2 | popen через shell exec_cmd_* |
| P-18 | §2 | IPC tmp 0644 + race |
| P-19 | §2 | Нет таймаута popen ucode |
| P-20 | §2 | Окно nft rules → tproxy_init |
| P-21 | §2 | nft mode не обновляется при SIGHUP |
| P-22 | §2 | Нет rate limiting IPC |
| P-23 | §15 | tun0 захардкожен |
| P-24 | §15 | Таймауты raw numbers (6+ мест) |
| P-25 | §15 | fail_count<3 дважды |
| P-26 | §15 | geo_dir не из UCI |
| P-27 | §15 | BACKUP_FILE путь рассогласован |
| P-28 | §15 | listen_port не в allowlist |
| P-29 | §15 | SS cipher не конвертируется |
| P-30 | §15 | latency_ms=999 permanent |
| P-31 | §15 | app.js дублирует views |
| P-32 | §15 | sleep 1 блокирует rpcd |
| P-33 | §15 | grep парсинг openwrt_release |
| P-34 | §15 | O(n) суффикс без трека |
| P-35 | §15 | geo_status проверяет .dat |
| P-36 | §8 | DNS upstream не верифицирован |
| P-37 | §5 | dpi-get/dpi-set отсутствуют |
| P-38 | §5 | geo-status JSON без экранирования |
| P-39 | §5 | Нет таймаута popen (дубль P-19) |
| P-40 | §5 | Race tmp-файл (дубль P-18) |
| P-41 | §3 | Функции 500+ строк |
| P-42 | §3 | switch без default (2 места) |
| P-43 | §3 | fputs без проверки nftables |
| P-44 | §3 | TODO без номера задачи |
| P-45 | §6 | 12 unhandled promise rejections |
| P-46 | §6 | 8 мест без user-friendly ошибки |
| P-47 | §6 | Несогласованный rpcd формат |
| P-48 | §6 | dns.js без валидации IP/портов |
| P-49 | §7 | Clash dns не конвертируется |
| P-50 | §7 | awg_mtu/dns/reserved отсутствуют |
| P-51 | §7 | UCI injection через option key |
| P-52 | §10 | TC_MIPSEL без ошибки |
| P-53 | §10 | 3 теста не в make test |
| P-54 | §10 | Нет тестов AWG/IPC/config |
| P-55 | §12 | Нет rpcd restart после install |
| P-56 | §12 | SCP без -O флага |
| P-57 | §13 | architecture.md стейл |
| P-58 | §13 | IPC схема не задокументирована |
| P-59 | §13 | README 3 строки |
| P-60 | §14 | DNS upstream частично |
| P-61 | §14 | groups.js поля не исправлены |
| P-62 | §14 | sub_convert dns не реализован |
| P-63 | §14 | AWG latency не тестируется |
| P-64 | §14 | GeoIP reload блокирован PID-багом |

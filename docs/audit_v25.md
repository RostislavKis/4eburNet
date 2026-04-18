# Devil Audit v25 — Полный аудит проекта 4eburNet

> Дата: 2026-04-12
> 219 пунктов, 15 категорий, 12 шагов
> Режим: только чтение, без правок

---

## Итоговая таблица

| Категория | §  | Блокеры | Проблемы | Замечания | OK |
|-----------|----|---------|----------|-----------|----|
| Безопасность памяти | 1 | **3** | 4 | 2 | 16 |
| Безопасность (Security) | 2 | **3** | 6 | 2 | 13 |
| Качество C-кода | 3 | 0 | 3 | 2 | 19 |
| wolfSSL | 4 | 0 | 4 | 2 | 5 |
| IPC-архитектура | 5 | 0 | 4 | 2 | 5 |
| LuCI / ucode / JS | 6 | 0 | 2 | 2 | 8 |
| Конфигурация / UCI | 7 | 0 | 4 | 1 | 7 |
| Сетевая маршрутизация | 8 | **2** | 2 | 0 | 4 |
| GeoIP | 9 | 0 | 0 | 0 | 6 |
| Сборка и CI | 10 | 0 | 4 | 0 | 12 |
| Git и процесс | 11 | 0 | 0 | 0 | 7 |
| Деплой и надёжность | 12 | 0 | 0 | 0 | 9 |
| Документация | 13 | 0 | 2 | 0 | 4 |
| Бэклог known issues | 14 | 0 | 4 | 1 | 4 |
| **Производственная чистота** | **15** | **1** | **8** | **2** | **33** |
| **ИТОГО** | | **9** | **47** | **16** | **152** |

---

## Критический путь (что чинить первым)

### Приоритет 1 — Блокеры безопасности (B-01..B-06)

| ID | Категория | Описание | Файл:строка |
|----|-----------|----------|-------------|
| B-01 | §1 Память | strdup() без NULL-check — awg_i | config.c:351 |
| B-02 | §1 Память | strdup() без NULL-check — providers | config.c:758 |
| B-03 | §1 Память | Стековые буферы 4096B на MIPS 8KB стеке | main.c:235,266; dns_server.c:316,1027 |
| B-04 | §2 Security | Shell injection через geo_url (UCI → system()) | 4eburnet.uc:229,242-243 |
| B-05 | §2 Security | IPC tmp-файл без 0600, предсказуемое имя time() | 4eburnet.uc:132-137 |
| B-06 | §2 Security | Subscription tmp-файлы с фиксированными именами | 4eburnet.uc:868-870 |

### Приоритет 2 — Блокеры маршрутизации (B-08..B-09)

| ID | Категория | Описание | Файл:строка |
|----|-----------|----------|-------------|
| B-07 | §15 Чистота | latency_ms=999 permanent default без измерения | proxy_group.c:86,178 |
| B-08 | §8 Маршрут. | Нет hotplug WAN скрипта — ip rule не пересоздаётся | отсутствует файл |
| B-09 | §8 Маршрут. | DNS upstream не проверяется до старта | main.c:484-488 |

### Приоритет 3 — Проблемы высокой важности

| ID | Категория | Описание | Файл:строка |
|----|-----------|----------|-------------|
| P-01 | §1 Память | Стековые буферы 768-1536B (vless_xhttp, shadowtls, nftables, doq) | множество файлов |
| P-02 | §1 Память | snprintf без проверки truncation — массовая проблема | ~30 мест |
| P-03 | §1 Память | Integer overflow при умножении без проверки | ipc.c:361; fake_ip.c:57; rules_engine.c:72 |
| P-04 | §1 Память | Частичная инициализация dns_query_t | dns_server.c:1247 |
| P-05 | §4 wolfSSL | VERIFY_NONE для Reality без комментария WHY | tls.c:176 |
| P-06 | §4 wolfSSL | load_verify_locations без проверки возврата (Hysteria2) | hysteria2.c:181 |
| P-07 | §4 wolfSSL | strdup без NULL-check для reality_short_id → UB в tls_close | tls.c:214 |
| P-08 | §4 wolfSSL | wolfSSL_quic_do_handshake без проверки возврата | hysteria2.c:845,878 |
| P-09 | §2 Security | fchmod(0644) на скачанных файлах вместо 0600 | net_utils.c:371 |
| P-12 | §2 Security | Нет WAN hotplug мониторинга (= B-08) | — |
| P-13 | §2 Security | Error paths не чистят все tmp-файлы в subscription_import | 4eburnet.uc:873-908 |
| P-14 | §2 Security | popen() доступен наряду с exec_cmd_safe() | net_utils.c:73-138 |
| P-25 | §5 IPC | Гонка на tmp-файле в ucode (time()-based name) | 4eburnet.uc:132 |
| P-26 | §5 IPC | GROUP_LIST buf[2048] может переполниться → invalid JSON | ipc.c:242-244 |
| P-27 | §5 IPC | Ручной JSON-парсинг IPC payload — хрупкий | ipc.c:263-276 |
| P-28 | §5 IPC | (size_t)snprintf() cast без проверки на -1 | ipc.c:370-387 |
| P-29 | §3 Качество | switch без default — rules_engine.c (2 места) | rules_engine.c:361,425 |
| P-30 | §3 Качество | 7+ функций > 80 строк (config_load 618, main 599) | config.c, main.c и др. |
| P-32 | §6 LuCI | Unhandled promise rejections — 27+ мест во всех view JS | все view/*.js |
| P-33 | §6 LuCI | innerHTML без ebEsc — ebWanIp (minor XSS) | app.js:156 |

### Приоритет 4 — Проблемы средней важности

| ID | Категория | Описание | Файл:строка |
|----|-----------|----------|-------------|
| P-15 | §15 Чистота | TODO без тикета (3 места) | dispatcher.c:67; rules_engine.c:303; hysteria2.c:462 |
| P-16 | §15 Чистота | Версия v1.0.0 захардкожена в overview.js | overview.js:81 |
| P-17 | §15 Чистота | Hardcoded buffer sizes (dns_upstream, tproxy, dns_server) | множество файлов |
| P-18 | §15 Чистота | Routing table numbers в debug-строках policy.c | policy.c:361,365,372-373 |
| P-19 | §15 Чистота | Magic sleep(1) при restart демона | 4eburnet.uc:213 |
| P-20 | §15 Чистота | Конфиг-опции сверх лимита молча отбрасываются | config.c |
| P-21 | §15 Чистота | IPC GROUP_TEST не проверяет результат tick() | ipc.c:304-311 |
| P-22 | §15 Чистота | config.yaml с example credentials в корне репо | config.yaml:22,248-249 |
| P-23 | §8 Маршрут. | nft_init() failure = soft warning, не hard fail | main.c:434-448 |
| P-24 | §8 Маршрут. | policy_check_conflicts() не блокирует старт | main.c:497 |
| P-35 | §7 Config | Clash DNS-секция не конвертируется | sub_convert.py:217-265 |
| P-36 | §7 Config | Emoji в именах серверов не фильтруются | sub_convert.py:700-708 |
| P-37 | §7 Config | AWG psk и keepalive не парсятся из Clash | sub_convert.py:483-510 |
| P-38 | §7 Config | Clash field mapping захардкожен | sub_convert.py:425-514 |
| P-39 | §10 Сборка | TC_MIPSEL/WOLFSSL_MIPSEL нет ошибки при отсутствии | Makefile.dev:214-217 |
| P-40 | §10 Сборка | Нет теста на MAX_LINE (8192) граничное значение | — |
| P-41 | §10 Сборка | Нет негативного теста на кривой IPC JSON | — |
| P-42 | §10 Сборка | Нет теста на серверы с пробелами в именах | — |
| P-43 | §13 Документ. | IPC JSON-схема не задокументирована | — |
| P-44 | §13 Документ. | WHY-комментарии не на всех нетривиальных функциях | config.c, dispatcher.c |

---

## Детальные результаты по шагам

---

### ШАГ 1 — Безопасность памяти (§1) ⚠️

**ПРОЙДЕНО:**
- alloca() — не найден
- VLA — не найдены
- sprintf — не найден (везде snprintf)
- gets/strcpy/strcat — не используются
- strncat/strncpy — везде sizeof()-1 + ручной \0 (config.c:132,272,290; ipc.c:109)
- malloc/calloc NULL-check — все основные аллокации проверяются (config.c:443-449; ipc.c:363-366)
- realloc temp pointer — паттерн с tmp переменной (config.c:734,882; proxy_provider.c:537)
- free + NULL — config_free и cleanup-функции обнуляют
- double-free — не обнаружен
- use-after-free — не обнаружен
- signed/unsigned сравнения — корректные касты
- off-by-one — границы циклов корректны
- рекурсия — Patricia trie ограничена глубиной IPv4 prefix (geo_loader.c:95)
- криптомодули — explicit_bzero для ключей, фиксированные буферы

**НАЙДЕНО: 3 блокера, 4 проблемы, 2 замечания** (B-01..B-03, P-01..P-04, Z-01..Z-02)

---

### ШАГ 2 — wolfSSL (§4) ⚠️

**ПРОЙДЕНО:**
- wolfSSL_Init() один раз — tls.c:85 через tls_global_init(), main.c:351
- wolfSSL_Cleanup() на всех exit — tls.c:112, main.c:369,376,390,425,876
- Парные _free() для CTX/SSL — tls.c:106-111,396; hysteria2.c:455-456; doq.c:646,657
- wolfSSL_connect → SSL_SUCCESS — tls.c:282-298
- wolfSSL_get_error() при не-SUCCESS — tls.c:291,351,372; dns_upstream_async.c:356,479
- VERIFY_PEER включён — tls.c:170; doq.c:614; hysteria2.c:180
- Версия 5.9.0 зафиксирована — dev-setup.sh:18
- TLS 1.2 минимум — tls.c:167
- Cipher list обоснован — tls.c:37-74 (Chrome120/Firefox121/iOS17 профили)

**НАЙДЕНО: 0 блокеров, 4 проблемы, 2 замечания** (P-05..P-08, Z-03..Z-04)

---

### ШАГ 3 — Security (§2) ⚠️

**ПРОЙДЕНО:**
- IPC через Unix socket — ipc.c:109-124, umask(0177)+chmod(0600)+SO_PEERCRED uid==0
- UCI integer validation — strtol с проверкой диапазона
- AWG private key не в логах — подтверждено
- POSIX ERE regex — proxy_group.c:111: REG_EXTENDED|REG_NOSUB, regcomp проверяется
- MAX_LINE 8192 — config.c:458
- Bounded recv — все с явным maxlen
- Таймауты — IPC 3s, DNS 1s, net_fetch 10s, relay 60s
- Rate limiting DNS — dns_server.c:310-365: 100 q/s per source
- nftables explicit chains — nftables.c:260-329: 3 chain, приоритеты -200/-150
- nftables cleanup при stop — nftables.c:352-365: delete table
- Fail-open — атомарное nft -f
- Lua restore path allowlist — rpcd/4eburnet:707-714
- Lua pkg validation — rpcd/4eburnet:626
- subscription_import sh_quote() — 4eburnet.uc:887-905

**НАЙДЕНО: 3 блокера, 6 проблем, 2 замечания** (B-04..B-06, P-09..P-14, Z-05..Z-06)

---

### ШАГ 4 — Производственная чистота (§15) ⚠️

**ПРОЙДЕНО (ключевое):**
- fwmark — FWMARK_PROXY/TUN в constants.h:14-15
- Routing tables — ROUTE_TABLE_PROXY/TUN/BYPASS в constants.h:18-20
- Таймауты — constants.h:32-35
- Файловые пути — 4eburnet.h
- Версия — EBURNET_VERSION в 4eburnet.h
- Device profiles — device.h
- Compiler flags — Makefile.dev:50-57 (полный набор)
- Hysteria2 — полная реализация QUIC, не заглушка
- VLESS blocking select — ИСПРАВЛЕНО (B-15), неблокирующий API
- IPC stats — инкрементируются (dispatcher.c:538, dns_server.c:325)
- GeoIP atomic — mv -f = rename(2)
- groups.js <> daemon — поля совпадают
- chmod 777 — не найден
- kill -9 — не используется (SIGTERM)
- Mock wolfSSL — нет в production build
- #ifdef DEBUG — только логирование

**НАЙДЕНО: 1 блокер, 8 проблем, 2 замечания** (B-07, P-15..P-22, Z-07..Z-08)

---

### ШАГ 5 — Сетевая маршрутизация (§8) ⚠️

**ПРОЙДЕНО:**
- ip rule fwmark 0x01 table 100 — policy.c:198-244
- Idempotent — policy_rule_exists() перед добавлением
- Удаляется при stop — policy.c:320-349
- Порядок cleanup — rules→dispatcher→tproxy→policy→nftables
- TPROXY после policy — main.c:504 перед 509
- TPROXY TCP/UDP only — 4 сокета
- Fail-safe при отсутствии GeoIP — graceful
- GEOIP,RU,DIRECT проверка — main.c:397-416
- procd init скрипт — USE_PROCD=1, respawn 5/5/5

**НАЙДЕНО: 2 блокера, 2 проблемы** (B-08..B-09, P-23..P-24)

---

### ШАГ 6 — IPC-архитектура (§5) ⚠️

**ПРОЙДЕНО:**
- Все команды задокументированы — enum ipc_command_t
- Неизвестная команда → ошибка — ipc.c:433-436
- JSON-ответ всегда валиден — все ветки switch возвращают JSON
- groups.js поля совпадают с daemon — proxy_group.c:419 ↔ groups.js:19,21
- Timeout на ответ демона — rpcd/4eburnet:73,109: IPC_TIMEOUT=3
- Защита от кривого JSON — ручной парсинг через strstr/strchr
- SO_PEERCRED uid=0 — ipc.c:150-167

**НАЙДЕНО: 0 блокеров, 4 проблемы, 2 замечания** (P-25..P-28, Z-09..Z-10)

---

### ШАГ 7 — Качество C-кода (§3) ⚠️

**ПРОЙДЕНО:**
- Возвраты ошибок проверяются — повсеместно
- close() на всех путях — 299 вызовов в 35 файлах
- Нет неинициализированных переменных — {0} и memset
- Fall-through — все с break/return/goto
- UB сдвигов — нет
- Нет magic numbers (кроме P-17)
- Нет закомментированного кода
- snake_case / UPPER_CASE единый стиль
- Include guards — все 51 .h файл
- Нет glibc-специфики — musl совместимость подтверждена
- Stripped binary — LTO + gc-sections

**НАЙДЕНО: 0 блокеров, 3 проблемы, 2 замечания** (P-29..P-31, Z-11..Z-12)

---

### ШАГ 8 — LuCI / ucode / JS (§6) ⚠️

**ПРОЙДЕНО:**
- fs.popen() проверяет null — 4eburnet.uc:140-143
- json() обработка ошибок — 4eburnet.uc:152
- rpcd методы стандартный формат — { ok, error }
- Нет console.log — 0 вхождений
- ebEsc/escHtml используются — app.js:243; logs.js:7
- LuCI E() DOM builder — безопасен от XSS
- rpcd ACL — read/write разделение
- sh_quote() — 4eburnet.uc:887-891
- Poll cleanup — timer ID сохраняется и чистится

**НАЙДЕНО: 0 блокеров, 2 проблемы, 2 замечания** (P-32..P-33, Z-13..Z-14)

---

### ШАГ 9 — Конфигурация / UCI (§7) ⚠️

**ПРОЙДЕНО:**
- YAML-якоря — yaml.safe_load()
- AND/DST-PORT — regex корректно
- AWG ключи mapping — совпадают
- awg_i hex — strdup, MAX_LINE достаточен
- Серверы с пробелами — list servers через char**
- UCI injection — strcmp whitelist

**НАЙДЕНО: 0 блокеров, 4 проблемы, 1 замечание** (P-35..P-38, Z-15)

---

### ШАГ 10 — Сборка и CI (§10) ✅

**ПРОЙДЕНО:**
- Все compiler flags на месте
- Strip автоматический
- 12 test файлов, 9 суитов
- make test работает
- Нет хардкода путей

**НАЙДЕНО: 0 блокеров, 4 проблемы** (P-39..P-42)

---

### ШАГ 11 — GeoIP, Деплой, Git, Документация (§9,§11,§12,§13) ✅

**ПРОЙДЕНО:**
- GeoIP: таймаут, non-empty check, atomic mv, graceful degradation
- Деплой: 192.168.1.1 заблокирован, нет chmod 777, procd correct
- Git: .gitignore полный, нет credentials
- Документация: README с build/deploy

**НАЙДЕНО: 0 блокеров, 2 проблемы** (P-43..P-44)

---

### ШАГ 12 — Бэклог known issues (§14) ⚠️

| # | Пункт | Статус |
|---|-------|--------|
| 1 | Hotplug WAN | НЕ РЕАЛИЗОВАНО |
| 2 | DNS upstream check | ЧАСТИЧНО |
| 3 | Provider-based группы | РЕАЛИЗОВАНО |
| 4 | groups.js поля | ИСПРАВЛЕНО |
| 5 | ubus "daemon not running" | РЕШЕНО |
| 6 | sub_convert.py dns | НЕ РЕАЛИЗОВАНО |
| 7 | Версия overview.js | НЕ ИСПРАВЛЕНО |
| 8 | AWG latency тест | НЕ РЕАЛИЗОВАНО |
| 9 | GeoIP без restart | РЕАЛИЗОВАНО |

**Из 9 пунктов: 4 реализованы, 1 частично, 4 не реализованы.**

---

## Общий вердикт

**Кодовая база на высоком уровне** для проекта этой стадии:
- Криптомодули — отлично (explicit_bzero, фиксированные буферы, нет UB)
- nftables — атомарные обновления, explicit chains, cleanup
- IPC — бинарный протокол, uid check, timeout
- Compiler flags — полный набор security hardening

**Критический путь до релиза (9 блокеров):**
1. **B-01, B-02, P-07:** strdup NULL-check (config.c:351,758; tls.c:214) — 15 мин
2. **B-03:** Стековые буферы 4KB → malloc (main.c, dns_server.c) — 30 мин
3. **B-04:** Shell injection geo_url → добавить валидацию regex (4eburnet.uc) — 15 мин
4. **B-05, B-06:** tmp-файлы → mktemp + chmod 0600 (4eburnet.uc) — 30 мин
5. **B-07:** latency_ms=999 → initial health check при старте (proxy_group.c) — 1 час
6. **B-08:** Hotplug WAN скрипт (новый файл) — 2 часа
7. **B-09:** DNS upstream check перед стартом (main.c) — 30 мин

**После блокеров — приоритетные проблемы:**
- P-02: snprintf truncation check — системный проход по всем файлам
- P-32: .catch() на все promise chains в JS
- P-26: IPC GROUP_LIST буфер → динамический malloc
- P-29: default в switch rules_engine.c

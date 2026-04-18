# Devil Audit v27 — 4eburNet

> Дата: 2026-04-13
> Аудитор: Claude Code (Opus 4.6)
> Чеклист: 4eburNet_audit_checklist.md (219 пунктов, 15 категорий)
> Предыдущий аудит: v26

---

## Итоговая таблица

| # | Категория | Пунктов | Блокеры | Проблемы | OK | Статус |
|---|-----------|---------|---------|----------|-----|--------|
| 1 | Безопасность памяти | 25 | **7** | 7 | 14 | 🔴 |
| 2 | Безопасность (Security) | 24 | 0 | 7 | 17 | ⚠️ |
| 3 | Качество C-кода | 24 | **3** | 6 | 15 | 🔴 |
| 4 | wolfSSL | 9 | 0 | 1 | 8 | ✅ |
| 5 | IPC-архитектура | 7 | **2**¹ | 1 | 5 | 🔴 |
| 6 | LuCI / ucode / JS | 11 | **2**¹ | 3 | 7 | ⚠️ |
| 7 | Конфигурация / UCI | 12 | **1** | 1 | 10 | ⚠️ |
| 8 | Сетевая маршрутизация | 8 | 0 | 1 | 7 | ✅ |
| 9 | GeoIP | 6 | 0 | 0 | 6 | ✅ |
| 10 | Сборка и CI | 16 | 0 | 1 | 15 | ✅ |
| 11 | Git и процесс | 7 | 0 | 0 | 7 | ✅ |
| 12 | Деплой и надёжность | 9 | 0 | 1 | 8 | ✅ |
| 13 | Документация | 6 | 0 | 2 | 4 | ⚠️ |
| 14 | Бэклог known issues | 9 | 0 | 4 | 5 | ⚠️ |
| 15 | Производственная чистота | 44 | **4** | 5 | 35 | 🔴 |
| | **ИТОГО** | **219** | **19**² | **40** | **163** | |

¹ Дубликаты из §15 (P-01..P-04)
² Уникальных блокеров: **14** (5 дубликатов между категориями)

---

## Уникальные блокеры (14)

### Критический приоритет (security/correctness)

| ID | Описание | Файл:строка | Категория |
|----|----------|-------------|-----------|
| C-01 | DNS_ACTION_BLOCK unreachable (default: перед case BLOCK) | dns_server.c:298-303 | §3 Качество |
| M-06 | snprintf без проверки → чтение за границами буфера (XHTTP upload) | vless_xhttp.c:133-140 | §1 Память |
| M-07 | snprintf без проверки → чтение за границами буфера (XHTTP download) | vless_xhttp.c:171-176 | §1 Память |
| C-02 | Утечка памяти xhttp при SNI truncation | dispatcher.c:326→339 | §3 Качество |
| U-01 | log.warning() undefined → NameError crash в sub_convert.py | sub_convert.py:595 | §7 Конфиг |
| M-05 | strdup() без NULL-check → NULL dereference при OOM | proxy_group.c:149→179 | §1 Память |

### Высокий приоритет (UI/data integrity)

| ID | Описание | Файл:строка | Категория |
|----|----------|-------------|-----------|
| P-03/I-02 | JSON field "latency" vs JS expects "latency_ms" | proxy_group.c:441 vs app.js:315 | §15/§5 |
| P-04/I-01 | JSON groups не содержит server name | proxy_group.c:441 vs app.js:312 | §15/§5 |
| P-01/L-01 | Версия v0.1.0 захардкожена в LuCI HTML | base.htm:35, overview.htm:13 | §15/§6 |
| P-02/L-02 | AWG форма в LuCI пустая (0 полей) | servers.js:140, 207-241 | §15/§6 |

### Средний приоритет (stack/complexity)

| ID | Описание | Файл:строка | Категория |
|----|----------|-------------|-----------|
| M-01 | Локальный буфер 1024 байт на MIPS стеке | vless_xhttp.c:132 | §1 Память |
| M-02 | Локальный буфер 1024 байт на MIPS стеке | vless_xhttp.c:170 | §1 Память |
| M-03 | Локальный буфер 2048 байт (IPC_RESPONSE_MAX) | ipc.c:238 | §1 Память |
| C-06 | dispatcher_tick() 546 строк, CC > 25 | dispatcher.c:1280-1826 | §3 Качество |

---

## Критический путь (порядок исправления)

1. **C-01** — DNS блокировка не работает. Переставить case BLOCK перед default.
2. **M-06, M-07** — Чтение за границами буфера в XHTTP. Добавить `if (hdr_len < 0 || hdr_len >= (int)sizeof(http_hdr)) return -1;`.
3. **C-02** — Утечка xhttp. Добавить `free(relay->xhttp); relay->xhttp = NULL;` перед return -1.
4. **U-01** — NameError crash. Заменить `log.warning(...)` на `print(..., file=sys.stderr)`.
5. **M-05** — strdup NULL check. Добавить проверку перед записью в exclude_words.
6. **P-03/P-04** — JSON mismatch. Добавить "name" и переименовать "latency" → "latency_ms" в groups_to_json.
7. **P-01** — Версия. Заменить хардкод v0.1.0 на динамическое получение через RPC.
8. **P-02** — AWG форма. Добавить AWG-специфичные поля или скрыть опцию до реализации.
9. **M-01, M-02** — 1024-byte буферы → malloc или уменьшить до 512.
10. **M-03** — 2048-byte IPC буфер → heap allocation.
11. **C-06** — dispatcher_tick рефакторинг (долгосрочно).

---

## Проблемы (40 уникальных)

<details>
<summary>Развернуть полный список</summary>

### Безопасность памяти (M-08..M-14)
- M-08: snprintf не проверен для pg_name/rp_name — config.c:625,644
- M-09: char host[512] на грани лимита — dns_upstream.c:195
- M-10: Нет overflow check при malloc size — shadowsocks.c:258,269
- M-11: snprintf не проверен для SNI — tls.c:229
- M-12: label length не проверен в HKDF — quic.c:40
- M-13: free без NULL assignment — shadowsocks.c:297
- M-14: snprintf не проверен в policy_dump — policy.c:463

### Security (S-01..S-07)
- S-01: PID в shell-строке is_running() — 4eburnet.uc:93
- S-02: system() без кавычек в geo_update — 4eburnet.uc:244,252
- S-03: Shell chars в address/password warn но не reject — config.c:301,327
- S-04: UCI option name не валидируется — config.c:693
- S-05: CDN updater PID-based tmp files — cdn_updater.c:311
- S-06: Нет SO_RCVTIMEO на TPROXY TCP — tproxy.c:252
- S-07: popen() вместо exec_cmd_safe() для ip команд — net_utils.c:71-140

### Качество C-кода (C-03..C-09)
- C-03: sendto() без проверки (×3) — dns_server.c:263,599,1124
- C-04: epoll_ctl ADD/MOD без проверки — dispatcher.c:473,1171,1174,1330
- C-05: setsockopt без проверки — ipc.c:56,535; dns_server.c:54,76
- C-07: handle_udp_query() 435 строк CC~20 — dns_server.c:319-753
- C-08: config_load() ~760 строк CC~30 — config.c:499-1257
- C-09: geo_loader.h #pragma once vs #ifndef — geo_loader.h:12

### wolfSSL (W-01)
- W-01: Версия не зафиксирована runtime — tls.c:95

### IPC (I-03)
- I-03: tmp-файл 24-bit entropy — 4eburnet.uc:136

### LuCI/JS (L-03..L-05)
- L-03: Пустые .catch() — overview.js:191,266
- L-04: innerHTML в app.js dashboard — app.js:183,242,269,296
- L-05: latency/latency_ms mismatch — app.js:315 vs 187

### Конфигурация (U-02)
- U-02: fake_ip_cidr vs fake_ip_range — sub_convert.py:284

### Маршрутизация (R-01)
- R-01: DNS probe non-blocking — main.c:545

### Производственная чистота (P-05..P-09)
- P-05: sleep(1) в rpcd restart — rpcd/4eburnet:295
- P-06: innerHTML паттерн — app.js (множество строк)
- P-07: Lua+ucode дублирование — rpcd/4eburnet + 4eburnet.uc
- P-08: Пустые .catch() — overview.js:191,266
- P-09: StrictHostKeyChecking=no глобально — deploy.sh:53

### Сборка (B-01)
- B-01: Нет теста unterminated JSON — test_ipc_safety.c

### Документация
- D-01: README.md заглушка — docs/README.md
- D-02: WHY-комментарии редки

### Бэклог
- BL-01: Provider groups без ожидания DNS
- BL-02: is_running() race condition (нет /proc/PID/comm)
- BL-03: AWG Noise handshake health check не реализован
- BL-04: Версия в .htm файлах устарела

</details>

---

## Сильные стороны

- **wolfSSL** — lifecycle, error handling, cert verify, key zeroing — безупречно
- **nftables** — atomic nft -f, injection protection, fail-open блокирован, cleanup на всех путях
- **Hotplug** — idempotent, PID validated, IPv4+IPv6, reload при WAN
- **Сборка** — все hardening флаги, 14 test suites, cross-compile с проверками
- **IPC** — SO_PEERCRED root-only, command whitelist, JSON truncation safety
- **Константы** — fwmark, routes, timeouts, buffers — всё централизовано
- **GeoIP** — atomic download, graceful degradation, auto-reload

---

## Сравнение с v26

| Метрика | v26 | v27 | Δ |
|---------|-----|-----|---|
| Уникальных блокеров | ? | 14 | новый baseline |
| Проблем | ? | 40 | новый baseline |
| Новые файлы аудита | — | hysteria2*, shadowtls, dpi/*, dns_upstream_doq, dns_upstream_async, quic, stats, cdn_updater, blake2b | +15 файлов |

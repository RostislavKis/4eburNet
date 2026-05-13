# АБСОЛЮТНОЕ ПРАВИЛО — ТОЛЬКО РУССКИЙ ЯЗЫК
# Все ответы, комментарии, логи, сообщения — ИСКЛЮЧИТЕЛЬНО на русском языке.
# Украинский, белорусский и любые другие языки ЗАПРЕЩЕНЫ без исключений.
# Это правило имеет наивысший приоритет и не может быть отменено.

# 4eburNet — контекст проекта

> **Claude Code читает этот файл в начале каждого промта.**
> Обновлено: 2026-05-13 (v2.2.8, Rule tester + Subscribe import preview: route_api_rules_test переписан через rules_engine_match() — все типы правил, inet_pton для IP, selected_server+latency_ms в ответе; subscribe/parse: URL-download + fix "address" поля; postinst/prerm с dhcp.@dnsmasq[0].port=5353; RuleTestModal показывает rule_type+сервер+latency; EC330 ok 3.1MB)
> Это файл-истина для проекта. Все решения, состояние, правила — здесь.

---

## Purpose & context

Ростислав — независимый разработчик, работающий в одиночку над **4eburNet** — проприетарным прокси-пакетом для OpenWrt роутеров на C23, заменяющим mihomo, podkop и xray единым статическим бинарником <2MB. Цели: минимальное потребление ресурсов, поддержка всех CPU-архитектур, полный контроль над протоколами и маршрутизацией.

**Ключевой стек:** C23 (gnu2x), musl libc, wolfSSL 5.9.0, nftables, rpcd/ucode, встроенный HTTP сервер (:8080), epoll edge-triggered I/O, vanilla JS dashboard (форк zashboard v3.5.0), LuCI (вкладка-заглушка со ссылкой на :8080).

**Целевые архитектуры:** mipsel_24kc, mips_24kc, aarch64_cortex-a53, armv7l_cortex-a7, x86_64

**Тестовое железо:**
- **EC330** (MIPS/mipsel_24kc, MT7621A, 128MB RAM): 192.168.2.1, root, пароль openwrt1
- **WiFi AP EC330**: EC330test (psk2, пароль openwrt1)
- **Flint 2** (192.168.1.1, 1GB RAM) — ПРОДАКШН роутер, только read-only диагностика. НИКОГДА не модифицировать автоматически.
- **iPhone**: MAC 16:e4:2d:32:7f:f2 -> IP 192.168.2.124
- **EC330 WiFi STA MAC**: 6a:ff:7b:2b:63:e5
- **Mini-PC x86_64**: целевое production устройство

### SSH доступ к EC330

| Сеть | SSID | EC330 WAN IP |
|------|------|-------------|
| Дома | Flint-2-5G (sae-mixed, 4NYZRMZB8X) | 192.168.1.249 |
| Работа | StroiExpert (psk2, 59133339) | 192.168.1.129 (DHCP) |
| Кабель | — | 192.168.2.1 (LAN, всегда) |

SSH ключ: C:\Users\Rosti\.ssh\id_ed25519

```bash
# Windows (EC330 LAN):
ssh -o StrictHostKeyChecking=no root@192.168.2.1

# WSL (только через копию ключа):
cp /mnt/c/Users/Rosti/.ssh/id_ed25519 /tmp/ec330_key && chmod 600 /tmp/ec330_key
ssh -i /tmp/ec330_key -o StrictHostKeyChecking=no root@192.168.1.249
```

**Критичные файлы:**
- D:\Проекты\4eburNet\.claude\skills\p2p\user_context.md — этот файл
- D:\Проекты\4eburNet\config.yaml — РАБОЧИЙ Clash YAML от Flint2 mihomo
- D:\Проекты\4eburNet\DASHBOARD_PLAN.md
- D:\Проекты\4eburNet\WS_ARCHITECTURE.md

---

## КРИТИЧНЫЕ ПРАВИЛА (неизменяемые)

### Production-grade ONLY (priority: ABSOLUTE)

ВСЕГДА только production-grade код с максимальным качеством с первой попытки.

ЗАПРЕЩЕНО:
- static function-local state для persistent данных (вместо — state в owner struct)
- Скрытое состояние без явного owner'а
- Mock'и, заглушки, placeholder'ы, "временные" решения
- Упрощённые версии с TODO
- Пропуск unit-тестов для новых модулей

ТРЕБУЕТСЯ:
- Explicit memory order для atomics (memory_order_relaxed минимум)
- Overflow-safe арифметика ((cur >= prev) ? (cur - prev) : 0)
- Init state в правильной lifecycle точке
- Явный owner для каждого поля
- Unit tests (host compile + RFC reference vectors)
- Intent документирован в комментариях

### Flint2 SAFETY (priority: ABSOLUTE)

- Разрешено: nft list, cat, ps, uci show (read-only)
- ЗАПРЕЩЕНО без явного согласования: nft add/delete, uci set, uci commit, /etc/init.d/* restart
- Любые изменения — отдельный явный промт с STOP перед execute

### ДЕПЛОЙ UCI — ТОЛЬКО С WINDOWS (не WSL)

- ssh/scp на роутер: ТОЛЬКО из PowerShell/cmd (WSL 2 NAT не видит 192.168.x.x)
- UCI скрипт: `python tools\sub_convert.py -i config.yaml -o generated_uci.sh` → scp с Windows → `sh /tmp/generated_uci.sh`
- generated_uci.sh — shell-скрипт с `uci import` heredoc, НЕ raw UCI формат
- После `uci import` ВСЕГДА восстанавливать: `uci set 4eburnet.main='4eburnet' && uci set 4eburnet.main.enabled='1' && uci set 4eburnet.dns.upstream_bypass='1.1.1.1'`
- prebuilt/mipsel в Windows: бинарник появляется автоматически — WSL пишет в /mnt/d/Проекты/4eburNet/prebuilt/mipsel/ напрямую (rsync не нужен)
- Документация: docs/DEPLOY.md

### Архитектурные ограничения MIPS

- Stack limit 8 KB -> все локальные буферы <=512 байт
- Большие структуры -> static или heap
- static function-local state для persistent данных ЗАПРЕЩЁН

### Архитектурные правила v1.5.79+ (G15)

- mem_tier (runtime, по MemAvailable): LOW < 64MB / MID 64-256MB / HIGH > 256MB
  Лимиты: dispatcher_max_events (8/32/64), relay_drain_per_call (4/16/32),
  dns_cache_size (512/2048/8192), MAP_POPULATE (только HIGH)
- HC CTX: session_cache=OFF, WOLFSSL_OP_NO_TICKET, WOLFSSL_VERIFY_NONE
  В HC fork tls_global_init() не вызывать — CTX наследуется через COW
- geo_compile: только на host (CI). Роутер только mmap готовых .gbin
- cdn_updater: скачивает .gbin, валидирует GEO_BIN_MAGIC, SIGHUP демону
- dns_policy UCI: pattern + upstream + type(doh|dot|udp) + sni + priority
  dns_rule устарел — поля domain/upstream игнорируются
- ip_cidr vs ip_cidr6: sub_convert.py v1.5.79 эмитит ip_cidr6 для значений с ':'

---

## Current state (2026-05-13, v2.2.5)

### Dashboard v2.2.5 (gRPC CLOSE-WAIT drain + SS2022/VMess/ShadowTLS в ServerFormModal)

- ✅ grpc.c — grpc_tls_drain: wolfSSL_shutdown + drain loop (SO_RCVTIMEO=2с, 16 iter) в обоих teardown путях (pool_tick + pool_free)
- ✅ config.h — vmess_security[16] в ServerConfig; config.c — чтение UCI vmess_security
- ✅ http_server.c — POST/PUT /api/servers читают и сохраняют ss_method + vmess_security
- ✅ ServerFormModal.vue — ss: cipher→ss_method + Legacy optgroup; vmess: badge Alter ID 0 + security select; shadowtls: v-tooltip вместо title=""
- ✅ i18n/ru.ts + en.ts — 5 ключей: server_ss_method, server_vmess_alter_id, server_vmess_security, server_stls_password, server_stls_sni
- ✅ EC330 ok 2026-05-13 (3.1MB mipsel)

### Dashboard v2.2.4 (proxies buffer overflow + AWG serialization)

- ✅ route_clash_proxies: buf[65536]→buf[262144]; awg_kv для protocol=awg/wg
- ✅ EC330 ok 2026-05-13: 116 прокси видны

### Dashboard v2.2.1 (Logs download + log_level runtime + CDN config)

- ✅ GET /api/logs/download: отдаёт /tmp/4eburnet.log как async file attachment (507KB EC330)
- ✅ PATCH /configs log-level: SIGHUP применяет новый уровень без перезапуска демона
- ✅ GET/PATCH /api/cdn: 6 полей CDN настроек + UCI (cdn_update_interval_days, opencck_url, ...)
- ✅ LogsCtrl.tsx: кнопка DocumentArrowDownIcon (fetch+Blob+Bearer), onChange → PATCH /configs
- ✅ CDNConfig.vue: новый компонент в Settings → BackendSettings.vue секция CDN Auto-Update
- ✅ api/index.ts: getCDNConfigAPI + patchCDNConfigAPI
- ✅ i18n: 7 новых ключей (ru+en): logs_log_level_runtime, adv_cdn_*, downloadFullLog
- ✅ EC330 ok 2026-05-13

### F1 блок ЗАВЕРШЁН (v1.5.185–v1.5.191)

- ✅ F1-4+F1-5 SOCKS5+HTTP mixed-port inbound (v1.5.185)
- ✅ F1-6a CUBIC CC для TUIC v5 (v1.5.186)
- ✅ F1-6b BBR v1 для TUIC v5 — windowed max BW filter (v1.5.187)
- ✅ F1-6c BBR v2 для TUIC v5 — PROBE_UP/DOWN/CRUISE + inflight_hi/lo (v1.5.188)
- ✅ F1-2 ShadowTLS v3 server-side + Aparecium defense (v1.5.189)
- ✅ F1-1 SS2022 AES-128/256-GCM варианты (v1.5.190)
- ✅ F1-3 VMess AEAD — KDF13B + AuthID + ChunkMasking (v1.5.191)

### Следующий приоритет: Dashboard Фаза 1

Единственный блокер: async http_send_file (~200 LoC, EPOLLOUT+offset state)
После — Фаза 2: Core Clash API (zashboard vanilla работает)

### Текущий бинарник на EC330

4eburnetd v1.5.191 (stripped mipsel, 3.1MB, задеплоен 2026-05-12)

- Запуск: /etc/init.d/4eburnet start|stop|restart (procd-managed)
- КРИТИЧНО при stop: init.d stop не убивает HC-детей (таймаут); если "Text file busy" → kill $(pgrep 4eburnetd) + sleep 1
- UCI state: 397 traffic_rules (в т.ч. 22 AND), 6 dns_policy. config 4eburnet 'main' + enabled='1' обязательны
- GEMINI: тип URLTest (UCI type=url_test), pinned=Switzerland, Geneva · Trojan, gRPC (переживает рестарт)
- GRPC_SEND_CHUNK=16384 (heap malloc, стабильно)
- DNS: ya.ru → реальный IP (upstream_bypass=1.1.1.1); doubleclick.net → NXDOMAIN ✅
- Конфиг: /etc/config/4eburnet
- selected.json: {"GEMINI":"🇨🇭 Switzerland, Geneva · Trojan, gRPC","AWG Group":"AWG 1.5 (1 Вариант)"}
- Деплой: wsl bash -c "cd '/mnt/d/Проекты/4eburNet/core' && make mipsel" → PowerShell scp -O root@192.168.2.1:/usr/sbin/4eburnetd
- dnsmasq: UCI port=5353 (критично — иначе bind :53 конфликт при старте 4eburnetd)
- КРИТИЧНО при uci import: потеря config 4eburnet 'main' + upstream_bypass → добавить вручную после импорта

### Что реально работает (v1.5.163)

**gRPC stream: EAGAIN race + WINDOW_UPDATE guard ✅ ЗАКРЫТ (v1.5.158, EC330 ok 2026-05-10):**

- ✅ `grpc_stream_recv`: `ret==0` (EAGAIN из recv_dispatch) → проверка pending перед возвратом.
  `goto deliver` + метка `deliver:` перед шагом 4 устраняет дублирование.
- ✅ `grpc_connection_recv_dispatch`: `H2_WINDOW_UPDATE` с `length != 4` → `GRPC_CONN_GOAWAY + EPROTO`
  вместо тихого drain произвольного числа байт.

**gRPC рефакторинг Steps 1-3 ✅ ЗАКРЫТ (v1.5.157, EC330 ok 2026-05-10):**

- ✅ Step 1: `grpc_build_hpack_raw(svc, auth, out, out_size)` — монолит и multiplex сведены к thin-wrapper'ам.
- ✅ Step 2: `grpc_hs_drain_payload` удалена (16 строк). Все 7 call-site заменены inline-паттерном через `grpc_drain`.
- ✅ Step 3: `pending_to_client` — pre-alloc `GRPC_PENDING_TO_CLIENT_THRESHOLD` в `grpc_pool_acquire_stream`
  (оба пути). `GRPC_RECV_DATA`: bounds-check + memmove вместо realloc; `grpc_stream_recv` только len/pos=0.

**T0-07 Hysteria2 ✅ ЗАКРЫТ (v1.5.155-156, EC330 ok 2026-05-10):**

- ✅ A-D (v1.5.155): errno маскировка в connect_step/wait_response_step + EPOLLERR в dispatcher.
- ✅ E (v1.5.156): `hy2_cb_add_handshake` — per-level flush: Initial/Handshake/Application не смешиваются.
- ✅ F (v1.5.156): `RELAY_HY2_CONNECT` HS timeout 10с через `upstream_first_byte_deadline`.
- ✅ G (v1.5.156): `auth_rxbuf` overflow → `set_error` + return -1 вместо молчаливого дропа.
- ✅ H (v1.5.156): `relay_free` → `RELAY_FAIL_OR_RETRY` в двух точках (HS fail + TCPResponse fail).

**T0-06 http_upgrade буферизованное чтение ✅ ЗАКРЫТ (v1.5.154, EC330 ok 2026-05-10):**

- ✅ Побайтовое чтение (1 TLS syscall на байт) → порционное (до 256 байт за recv_fn).
  memmem(buf, len, "\r\n\r\n", 4) по накопленному буферу вместо tail-match.
- ✅ Добавлена проверка Connection: upgrade в ответе сервера.
  Поиск ограничен одной строкой заголовка (strpbrk + null-terminate).

**T0-05 XHTTP/SplitHTTP ✅ ЗАКРЫТ (v1.5.151-153, EC330 ok 2026-05-10):**

- ✅ Полный VLESS header + VLESS_SEND / VLESS_RESP states в XHTTP транспорте.
- ✅ Immediate recv: VLESS header отправляется немедленно в DN_REQ (не ждёт EPOLLOUT).
  Фикс EPOLLET-зависания: recv loop стартует не откладывая первый recv на следующий тик.
- ✅ Buffered read 256 байт + memmem для разбора HTTP/2 ответа сервера.

**T0-04 ws_client.c полная реализация ✅ ЗАКРЫТ (v1.5.149-v1.5.150, EC330 ok 2026-05-10):**

- ✅ PING/PONG control frames (Баг A): WS_RECV_CTRL + WS_RECV_PONG_SEND states.
  Сервер PING → читаем payload (≤125 байт) → отправляем PONG с тем же payload.
  send_fn добавлен параметром в ws_client_recv во всех 4 call sites.
- ✅ CSPRNG masking key (Баг E): wc_InitRng + wc_RNG_GenerateBlock вместо rand().
  WC_RNG embedded в ws_client_conn_t; ws_client_free() с guard rng_initialized.
  Fallback на rand() при сбое wc_InitRng (с srand(time^ptr)).
- ✅ Sec-WebSocket-Accept верификация (Баг D): SHA1(key+GUID)→base64 через wolfCrypt wc_Sha.
  ws_verify_accept() вызывается в ws_client_handshake_step после 101 проверки.
- ✅ 64-bit extended length в send (Баг C): payload length=127 + 8 байт big-endian.
  Убрано молчаливое обрезание len→65535. Cast uint64_t для MIPS (size_t=32-bit).
- ✅ CLOSE frame при teardown (Баг H): ws_client_close() — opcode=0x8, status=1000.
  ws_client_free() в relay_free + cb_ws_free; hc_vless.c ws_client_free после tls_close.
- ✅ Custom headers (Баг F): поле extra_headers[512] в ws_client_conn_t.
  Вставляется в HTTP GET если не пусто (формат: "Header: value\r\n").
- ✅ split-send fix (v1.5.150): ws_client_send единый malloc(hdr_len+len) буфер вместо
  двух send_fn. Исключает race при EAGAIN между заголовком и payload.
- ✅ CLOSE return 0 (v1.5.150): WS_RECV_CTRL CLOSE → return 0 (было -1 + ECONNRESET).
  Caller отличает нормальное закрытие от ошибки.
- ✅ Base64_Encode newline fix (v1.5.150): ws_verify_accept убирает \n/\r
  из Base64_Encode перед strncmp (было случайное совпадение при 29-байтном выводе).

**T0-03 h2.c framing + grpc multiplex bugs (сессия 2026-05-10, v1.5.144-v1.5.148):**

- ✅ h2.c/h2.h (v1.5.144): standalone HTTP/2 framing library без зависимостей. 8 функций:
  h2_write/read_frame_hdr, h2_varint_encode/decode, h2_grpc_lpm_write/parse, h2_pb_field1_write/parse.
  h2_read_frame_hdr — int (return), size_t len (buffer guard).
- ✅ grpc.c интеграция (v1.5.145): удалены дублирующие static функции + #define (H2_DATA..ACK_FLAG),
  grpc_send переписан через h2_pb_field1_write + h2_grpc_lpm_write + единый malloc буфер.
- ✅ h2_read_frame_hdr buffer guard (v1.5.146): 4 call site в grpc.c получили реальный len.
- ✅ grpc_stream_send single send (v1.5.147): заменён split (два send_fn) на единый malloc буфер.
  grpc_hs_drain_payload — лимит 256 итераций + EAGAIN при превышении.
- ✅ PING desync fix + pending_stream_id rename (v1.5.148):
  pending_ctrl_got (cursor) + buf[9]=2 (mid-PING signal) → возобновление при EAGAIN с 0 байт.
  Шаг 2б в recv_dispatch. goaway_last_stream_id переименован в pending_stream_id (WHY-комментарий).

**Релизные итеры v1.5.140-v1.5.143 (сессия 2026-05-09):**

- ✅ TLS session cache OFF + WOLFSSL_OP_NO_TICKET в relay CTX (v1.5.140): предотвращает session reuse между разными серверами.
- ✅ Vision flow: удалён пустой probe-пакет при старте (v1.5.140): XTLS Vision теперь не посылает empty record.
- ✅ GRPC_SEND_CHUNK=16384 heap (v1.5.142): отдельный malloc-буфер вместо стека — стабильно на MIPS 8KB stack.
- ✅ GEMINI Selector + pinned selected.json (v1.5.143): proxy_group_state_t.pinned, PUT /proxies/{group} → pinned=true →
  selected.json → восстановление при рестарте. HC round не перезаписывает selected при pinned. Failover сбрасывает pinned.

**Релизные итеры v1.5.130-v1.5.139 (сессия 2026-05-09):**

- ✅ pending queue 64 + GLOBAL_RESOLVE_CACHE 4→64 (v1.5.137-139): тики 1693ms→135ms
- ✅ GEMINI pinned (v1.5.143): proxy_group_state_t.pinned флаг. PUT /proxies/{group} →
  pinned=true → сохраняется в /etc/4eburnet/selected.json → восстанавливается при рестарте.
  HC round-complete не перезаписывает selected_idx если pinned. При failover pinned сбрасывается.
  Логи старта: "начальный выбор [0] Bulgaria" → "восстановлен выбор [8] 'Switzerland' (pinned)" ✅

**Релизные итеры v1.5.115-v1.5.129 (сессия 2026-05-08):**

- ✅ XUDP UDP relay needs_io=1 + wake_fd reply path + relay_owned (v1.5.115) — step 3
- ✅ grpc_conn_teardown: убран raw recv() drain (v1.5.127) — raw drain уничтожал
  зашифрованные DATA frames → premature EOS на iOS → серый экран YouTube.
  Новый teardown: только wake_fd пинг для живых streams, tcp_fd не трогается,
  wolfSSL продолжает работать через существующий fd; googlevideo.com lifetime 113s ✅
- ✅ GEMINI переключён на URLTest (UCI type=url_test) → auto-best: Bulgaria, Sofia · Trojan, gRPC
- ✅ url-test latency=0 захват fixed (v1.5.129): `latency_ms=UINT32_MAX` при init
  (было 0) + проверка `> 0` в best-поиске во всех 4 точках (url-test ×3 +
  immediate failover). Сервер с latency=0/UINT32_MAX больше не "выигрывает"
  выбор url-test вечно.

**Релизные итеры v1.5.99-v1.5.114 (одна сессия 2026-05-07):**

- ✅ Mux.Cool/XUDP transport-agnostic I/O (v1.5.99) — transport_ctx/send/recv/free
  на TLS/Reality/WS/XHTTP/gRPC. cb_* polymorphic dispatch.
- ✅ TCP relay через Mux.Cool отключён (v1.5.100) — `if(false)` guard, packet-encoding=xudp
- ✅ HC latency overflow fix (v1.5.101) — hc_clamp_ms [0,9999] в 7+3 местах
- ✅ UINT32_MAX init для latency_ms — устраняет 4294967295 в JSON (v1.5.101-v1.5.102)
- ✅ PROXY_GROUP_MAX_SERVERS 32→256 (v1.5.103) — провайдер ~80 серверов вмещается
- ✅ QUIC UDP 443 drop в исходниках nftables.c:730-731 (v1.5.103) — iPhone YouTube
  фоллбэк на TCP+TLS вместо серого экрана
- ✅ xudp:true тег в /proxies JSON (v1.5.103) — zashboard видит XUDP support
- ✅ Dashboard zashboard v3.5.1 cdn-fonts (v1.5.105) — идентичный Flint2 mihomo,
  /usr/share/4eburnet/dashboard/, раздача на / + mihomo-compat /ui/ + 307 redirect
- ✅ Init available=true в proxy_group.c (v1.5.106) — серверы видимы до первого HC
  (mihomo-семантика, было available=false → 30 минут "пустоты" в zashboard)
- ✅ Batch HC /group/{name}/delay (v1.5.106-v1.5.114) — параллельный fork с лимитом
  GROUP_HC_BATCH_MAX=8 (v1.5.114, downgrade с 24 после OOM на EC330), deadline 20с,
  finished_real flag — недотестированные серверы не штрафуются.
  JSON fallback на pgm_server_latency для всех известных RTT.
- ✅ ServerConfig.name 64→128 + HTTP_PATH_MAX 256→1024 (v1.5.108) — длинные UTF-8
  имена серверов (97+ байт) с emoji + кириллица
- ✅ /proxies/{name}/delay cached only (v1.5.109) — никогда не форкает HC,
  возвращает cached pgm_server_latency или 0 (НЕ 408)
- ✅ AWG real RTT через handshake probe (v1.5.112) — child_do_awg_handshake
  использует awg_handshake_start с junks/CPS, измеряет RTT при первом UDP
  ответе (Cloudflare WARP error пакет тоже = валидный RTT 206-307ms)
- ✅ pgm_server_latency возвращает first non-zero (v1.5.111) — корректное
  отображение AWG в /proxies snapshot когда сервер в нескольких группах
- ✅ CORS echo Origin + Allow-Methods/Headers + OPTIONS preflight 204 (v1.5.107)
- ✅ Group_HC OOM fix (v1.5.114) — 24 параллельных fork держали 70+ child из-за
  AWG UDP poll 3s timeout, EC330 116MB → OOM, dropbear/uhttpd не форкались.
  Снизил BATCH_MAX 24→8 (32MB worst), DEADLINE 30→20, CAP 3000→2000

**Ядро / TPROXY:**
- TPROXY + nft mark + ip rule (fwmark 0x1 -> table 100) + ip route local -> :7893
- nftables: inet eburnet + eburnet_nat
- IPv6 fake-ip: fd00::/120, AAAA -> fd00::1
- mem_tier runtime: LOW/MID/HIGH по MemAvailable
- DeviceProfile compile-time: MICRO/NORMAL/FULL по MemTotal

**DNS:**
- DNS fake-ip 198.18.0.0/16 -> 198.18.0.1
- DoH через TLS к 8.8.8.8
- dnsmasq на :5353, 4eburnetd на :53
- dns_policy UCI: domain-паттерн -> upstream (DoH/DoT/UDP + приоритет)
- GeoIP: geoip-ru.dat (12662 IPv4, 8786 IPv6)
- DNS RFC 8767 stale-while-revalidate + singleflight dedup + rate linear probing
- DNS Cookie RFC 7873+9018 (dns_cookie.c)
- PTR resolver RFC 1035 (ptr_resolver.c)
- AD bit cleanup RFC 4035 §3.2.3
- AAAA NODATA для DIRECT/BYPASS (предотвращает IPv6 leak)
- DHCP option 6 автоматизация в init script
- Adblock через DNS (regex-паттерны, DNS_ACTION_BLOCK)

**Протоколы:**
- VLESS/TCP plain (туннельный HC через www.gstatic.com:443)
- VLESS/Reality (TLS 1.3, x25519, shortId) — собственный TLS-стек на wolfCrypt
- VLESS/gRPC (HTTP/2 + HPACK + LPM + protobuf + flow control, ~780 LoC)
- VLESS/WebSocket (TLS + HTTP Upgrade, MASK=1)
- VLESS/XHTTP / SplitHTTP (HTTP/2, ALPN=h2, session ID в path)
- VLESS/HTTPUpgrade (raw TCP после 101, без Sec-WebSocket-Key)
- XTLS Vision flow (v1.5.2-v1.5.3)
- Trojan + Trojan/gRPC (YouTube стабильно, lifetimes 43-79s)
- AmneziaWireGuard (Jc/Jmin/Jmax, H1-H4, S1-S4, i1-i5) — crypto fixed v1.5.93-v1.5.96
- Hysteria2 async (QUIC HS+H3 auth + TCPResponse)

**gRPC pool архитектура (v1.5.87 + v1.5.97):**

- `grpc_conn_pool_t` — N TCP+TLS+H2 соединений, GRPC_POOL_CONNS_MAX=8
- Multiplexing: GRPC_STREAMS_PER_CONN_MAX потоков на одном conn
- `grpc_pool_acquire_stream` — создаёт новое conn (needs_io=1) или присоединяется к существующему (needs_io=0)
- `wake_fd` (eventfd) у всех streams — primary и secondary унифицированы (v1.5.97)
- `grpc_conn_ep_t` watcher — persistent EPOLL_EP_GRPC_CONN tag на conn->tcp_fd, ставится на RELAY_GRPC_HS → ACTIVE через EPOLL_CTL_MOD (v1.5.97)
- `ep_type` int первое поле relay_ep_t/grpc_conn_ep_t — полиморфный диспатч в epoll loop через `*(int*)data.ptr`
- Watcher cleanup: `grpc_pool_tick` (idle 60s timeout) + `grpc_pool_free`
- Снимает limitation: secondary streams теперь не stall после смерти primary relay
- `grpc_drain` лимит 256 iter (v1.5.85), `RELAY_GRPC_HS` do/while лимит 64 iter (v1.5.85)
- `grpc_flush_pending_windows` для pending_wnd_conn/pending_wnd_stream (v1.5.86)

**Proxy Providers / Groups:**
- proxy-providers: Clash YAML + base64/URI list загрузка
- PrivateVPN (~94 серверов) + ARZA (8 серверов)
- Группы: url_test, fallback, select
- Честный туннельный HC для каждого транспорта
- Немедленный failover при available=false
- HC немедленно при старте (next_check=now)
- PROXY_GROUP_GLOBAL_HC_LIMIT=16 (OOM фикс)
- transport_is_implemented() — ~40+ серверов WS/XHTTP в url-test

**Dashboard / API:**
- Dashboard zashboard v3.5.1 cdn-fonts (upstream, идентичный Flint2 mihomo) на :8080
- REST Clash-совместимый: /version, /configs, /proxies, /rules, /providers/*
- PUT /proxies/{group} по имени в g->servers[] — URL_TEST + SELECT
- /proxies/{name}/delay (cached only, никогда не форкает HC, всегда 200)
- /group/{name}/delay (batch HC: 8 параллельных fork, deadline 20с, fallback на
  pgm_server_latency для недотестированных, finished_real flag)
- /api/dns/upstream GET/PATCH/POST
- WS /logs ring buffer 500 строк
- WS /memory + /traffic (1 сек)
- CORS echo Origin + Allow-Credentials/Methods/Headers + OPTIONS 204 preflight
- LuCI вкладка-заглушка со ссылкой на :8080
- /ui/ mihomo-compat: 307 redirect /ui → /ui/, strip prefix → / роуты

**v1.5.89-v1.5.97 (одной сессией 2026-05-07):**

- v1.5.89: UCI cleanup — удалены 3 дубля Telegram CIDR с low-priority в MAIN-PROXY
   (149.154.160.0/20, apple-dns.net, facetime.apple.com — мусор от sub_convert)
- v1.5.93: AWG noise_init — `wc_curve25519_make_pub` (вместо broken import_private+export_public).
   Корень: wolfSSL 5.9.0 BAD_FUNC_ARG -173 на export_public когда private импортирован отдельно
- v1.5.94: AWG x25519_generate — random_bytes + clamp + make_pub (заменён make_key+export_public)
- v1.5.96: AWG x25519_shared — `wc_curve25519_generic` (прямой scalar mult).
   import_private_ex не настраивает curve25519_key.dp поле → shared_secret_ex видит
   нерабочий ключ → -173. wc_curve25519_generic работает на raw bytes без struct
- v1.5.97: gRPC pool watcher — persistent grpc_conn_ep_t на conn->tcp_fd через EPOLL_CTL_MOD.
   Снимает limitation "secondary stall после смерти primary". ep_type=int первое поле
   relay_ep_t/grpc_conn_ep_t для полиморфного диспатча в epoll loop. wake_fd теперь у всех
   streams (был только у secondary). Установка: RELAY_GRPC_HS → ACTIVE transition
- UCI: TELEGRAM группа переключена с AWG на providers='PrivateVPN ARZA' (Cloudflare WARP
   на 162.159.192.1:4500 не понимает AmneziaWG, возвращает 16-байтные error пакеты)

**v1.5.87:**

- gRPC мультиплекс CONFIG_EBURNET_GRPC_MULTIPLEX=1: pool + wake_fd (eventfd) + needs_io=0/1 paths
- Множество stream'ов (id=3,5,7...25) через одно TCP+TLS+H2 соединение на EC330 ✅
- wolfssl/options.h фикс в grpc.c (до этого -Werror=cpp на mipsel gcc-12.3.0)

**v1.5.84-v1.5.85:**
- HC OOM fix: compute_hc_limit avail/8+cap12, burst mode убран
- fail_count gradual recovery: fail_count-- при OK вместо =0
- grpc_drain лимит 256 итераций (16KB/tick), EAGAIN при превышении
- RELAY_GRPC_HS: do/while лимит 64 итерации — устраняет 3.94s freeze
- child_do_hc_vless_ws: честный туннельный HC (VLESS через WS)
- GEMINI UCI type=select, now=Canada Trojan/gRPC

**v1.5.81-v1.5.83:**
- Reality TLS rbuf/ptbuf 32768B — Certificate chain 25958B вмещается
- relay REALITY_VLESS->ACTIVE стабильно, record слишком большой исчез
- json_get_str: \uXXXX surrogate pairs -> UTF-8, пробелы вокруг ':'
- Finland Helsinki VLESS/TCP 171ms, YouTube работает

**Инфраструктура:**
- SIGHUP reload (v1.5.67): безусловная регистрация sigaction
- sub_convert.py: proxies, proxy-groups, rules, dns, proxy-providers, port, dns_policy, ip_cidr6
- Кросс-компиляция: mipsel_24kc + aarch64 + x86_64
- GitHub Release IPK

### Ключевые файлы gRPC

- core/src/proxy/protocols/grpc.c (~780 LoC)
- core/include/proxy/protocols/grpc.h — grpc_conn_t, state enum, API
- refs/mihomo/transport/gun/gun.go — LPM+protobuf framing reference
- refs/xray-core/transport/internet/grpc/ — server side reference

### Известные проблемы (v1.5.143)

- ⚠️ YouTube видео медленно буферизируется — причина неизвестна (GRPC_SEND_CHUNK=16384
   нормально работал на v1.5.142; возможно server-side throttle ch1.xxee.ru).
- ⚠️ WS relay — Connection reset на xxee.ru серверах (server-side проблема).
- ⚠️ grpc_conn_teardown не закрывает tcp_fd → CLOSE-WAIT может накапливаться при
   длительной работе. Правильное решение: graceful drain через wolfSSL (читать до
   EOF, потом close). Текущий workaround: watcher остаётся в epoll → stream'ы сами
   завершатся через wolfSSL_read → EBADF/EOF. Следующая сессия.
- ⚠️ AWG endpoint 162.159.192.1:4500 = Cloudflare WARP, **не поддерживает AmneziaWG**:
   плата за 4500 IPSec/IKEv2, WARP стандарт = порт 2408. Cloudflare возвращает
   16-байтный error на наш AmneziaWG i1+junks+init поток. Нужен реальный AmneziaVPN
   сервер (с jc/h1-h4 поддержкой) ИЛИ переключение на plain WG на правильном порту
   с зарегистрированными WARP credentials (`wgcf register`). Временный workaround:
   TELEGRAM группа использует providers='PrivateVPN ARZA' вместо AWG.
- ⚠️ gRPC pool watcher (v1.5.97) — реализован и работает на EC330, но требует
   audit (T2-09): edge-cases lifetime, поведение при конкурентном teardown
   primary+conn, EPOLL_CTL_MOD race window между watcher install и первым
   событием на conn->tcp_fd.
- GEMINI + MAIN-PROXY дублирование — оба url_test по одним 32 серверам. HC лимит 16. Желательно stagger или merge.
- Finland fi1, Estonia ee2, GB gb1 — Reality HS -> EPOLLRDHUP (серверная проблема).
- Rules engine: RULE-SET matching работает (v1.5.183, EC330 verified t.me→fake-IP ✅).
- GeoSite не скопированы — geosite-ru/ads/trackers -> WARN в логе. geoip-ru работает.
- SIGHUP race — иногда bind(TCP :53): Address in use. Workaround: killall -9 + start.
- Dashboard показывает только ~32/66 серверов после нажатия молнии — фундаментальное
   ограничение MIPS: 8 параллельных HC × 3с = ~25с для 66 серверов batch HC. Остальные
   34 сервера либо реально dead (Reality endpoints не отвечают), либо появятся после
   фонового HC раунда (каждые 5 минут). Это норма для EC330, не баг.
- AWG TELEGRAM endpoint — Cloudflare WARP отвергает наши credentials, handshake
   failed → fallback на providers='PrivateVPN ARZA' в TELEGRAM/DISCORD. AWG в чисто
   AWG Group работает только для RTT (не для туннеля).
- XUDP muxcool отключён (`if(false)` guard в v1.5.100, packet-encoding=xudp игнорируется
   в TCP relay) — архитектура transport_ctx готова, нужна верификация без TCP relay leak.
- Sub_convert.py НЕ создаёт low-priority duplicates — но в EC330 UCI были 3 мусорных
   правила с priority=5/315/316 (TELEGRAM CIDR→MAIN-PROXY, apple-dns/facetime→TELEGRAM).
   Источник неизвестен (возможно ручная правка или старая версия sub_convert). Удалены
   в v1.5.89.

### Критичные UCI / сборочные gotcha (ОБЯЗАТЕЛЬНО)

- **UCI провайдеры** — анонимные секции `@proxy_provider[N]`, не именованные. `uci_find_provider_section` итерирует через `uci get @proxy_provider[N].name`.
- **http_json_get_str** не читает числа без кавычек → для числовых полей (`interval`, `max_servers`) использовать `http_json_get_val`.
- **Кросс-компиляция** — `make -f Makefile.dev cross-mipsel` (не `make mipsel` — SDK Makefile не инкрементально пересобирает при изменениях).

### MIPS-специфичный паттерн (ОБЯЗАТЕЛЬНО)

```c
/* log_msg на MIPS вызывает localtime() -> затирает errno */
ssize_t result = some_syscall(...);
int saved_errno = errno;   /* ВСЕГДА до log_msg */
log_msg(LOG_INFO, "...", result, saved_errno);
if (saved_errno != EAGAIN) { ... }
```

### Серверы в конфиге EC330

```
Статические (UCI) — только AWG:
[0-3] AWG 1/2/3  awg  162.159.192.1:4500

Провайдеры:
PrivateVPN -> ~94 серверов (VLESS TCP/WS/XHTTP/gRPC, Trojan gRPC)
ARZA       ->   8 серверов (V2Ray URI list, base64)

Группы:
[0] GEMINI           url_test  PrivateVPN+ARZA, фильтр без RU/CIS/DE/EE/LV
[1] MAIN-PROXY       url_test  PrivateVPN+ARZA, фильтр без RU/CIS
[2] PrvtVPN All Auto url_test  PrivateVPN все
[3] ARZA Auto        url_test  ARZA
[4] TELEGRAM         url_test  AWG 1/2/3
[5] DISCORD          url_test  AWG 1/2/3
[6] AWG Group        select    AWG 1/2/3

Рабочие Reality: bg1.xxee.ru:443 (Bulgaria) — 87.229.34.26
НЕ работают: ee1.xxee.ru, nl2.xxee.ru
```

### Критичные UCI настройки (после каждого деплоя)

```bash
uci set 4eburnet.dns.fake_ip_enabled='1'
uci set 4eburnet.dns.doh_url='https://dns.google/dns-query'
uci set 4eburnet.dns.doh_ip='8.8.8.8'
uci set 4eburnet.dns.upstream_default='8.8.8.8'
uci commit 4eburnet && /etc/init.d/4eburnet restart
```

### Следующий приоритет

1. P0  F0-4: AND/OR logical rules в rules engine
2. P0  F0-5: AWG endpoint — найти рабочий AmneziaVPN сервер
3. P0  F0-6: YouTube gRPC GOAWAY диагностика (ch1.xxee.ru throttle?)
4. P1  F1-1..F1-7: транспортные протоколы (следующая группа фич)
5. P2  Dashboard Фаза 1 (async http_send_file — текущий блокер)

---

## Pending Roadmap (приоритет по порядку)

### P1 — restart race bind(:53) [HOTFIX]

- Проблема: `/etc/init.d/4eburnet restart` иногда падает с `bind(:53): Address already in use`
- Причина: race между stop и start — сокет не успевает освободиться
- Fix: loop-wait в init.d пока порт 53 не освободится (max 3с)
- Файл: `package/4eburnet/files/4eburnet.init`

### P2 — T0-01 Reality/XTLS bug [CRITICAL]

- Файл: `core/src/dispatcher.c`
- L404: `cfg.sni = server->address` — игнорирует `reality_sni`
- L410: `cfg.fingerprint` хардкод — игнорирует `reality_fingerprint`
- `reality_pbk` не декодируется в `cfg.reality_key` (base64url → 32 байта)
- Fix: SNI fallback chain + `map_fingerprint()` + pbk base64url decode

### P3 — T0-02 XTLS Vision addons [HIGH]

- Файл: `core/src/vless.c:93`
- XTLS Vision addons не реализованы
- Блокирует работу VLESS + XTLS Vision серверов

### P4 — grpc.c standalone H2 hardening [Transport]

- Архитектура: собственный HPACK + H2 frame parser (standalone, без nghttp2)
  CHANGELOG L1664: "standalone вместо nghttp2" — осознанное решение
- Текущие проблемы ручного парсера:
  - frame boundary bugs при фрагментации TCP
  - desync при ошибках потока
  - HPACK decoder не реализован (только encoder, строки 43-135)
- Задача: hardening существующего grpc.c — добавить HPACK decoder,
  robust frame boundary handling, stream error recovery
- Файл: `core/src/proxy/protocols/grpc.c`

### P5 — audit_v48 pending items [QUALITY]

- Файл: `docs/audit_v48.md` — прочитать и выписать все незакрытые пункты
- Актуальный аудит (v43-v47 закрыты)
- Запустить после закрытия P1-P3

---

## ROADMAP — нереализованное (по приоритету)

### Tier 0 — Критичные фиксы (ближайший спринт)

| # | Задача | Примечание |
|---|--------|------------|
| ~~T0-R1~~ | ✅ Rules engine: RULE-SET матчинг | ЗАКРЫТ v1.5.183: classical strip + YAML parse |
| T0-R2 | /proxies endpoint читает runtime pgm | сейчас static s_cfg -> all_count=1 |
| ~~T0-R3~~ | ✅ sub_convert.py: rule-providers | ЗАКРЫТ F0-2+F0-3 (v1.5.181) |
| ~~T0-R4~~ | ✅ sub_convert.py: fake_ip_enabled + doh_url | ЗАКРЫТ F0-2+F0-3 (v1.5.181) |
| T0-R5 | GeoSite файлы на роутер | geosite-ru/ads/trackers не скопированы |

### Tier 1 — Feature parity с mihomo (W3-W8)

| # | Задача | Примечание |
|---|--------|------------|
| ~~T1-01~~ | ✅ rule-providers URL загрузка + RULE-SET | ЗАКРЫТ v1.5.182-183, EC330 ok |
| T1-02 | Proxy groups: load_balance | select/url_test/fallback есть |
| T1-03 | Per-device routing по MAC (3.3) | UCI MAC -> proxy group |
| T1-04 | GeoSite полный (3.5) | v2fly lists, mmap |
| T1-05 | Sniffer TLS SNI (3.6) | peek ClientHello в TPROXY |
| T1-06 | Clash YAML парсер в демоне | сейчас только sub_convert.py |
| T1-07 | Reload без сброса соединений | SIGHUP есть, но соединения рвутся |
| T1-08 | Shadowsocks 2022 | AES-256-GCM, ChaCha20 |
| T1-09 | /connections WS stream | tracking TPROXY connections, ~500 строк |
| T1-10 | nameserver-policy fallback DNS + filter | dns_policy есть, fallback нет |
| T1-11 | cdn_updater горячее обновление geo баз | архитектура в G15, не реализована |
| T1-12 | sub_convert.py: sniffer, tun, mode, hosts | не парсятся |

### Tier 2 — Дифференциаторы (W7-W10)

| # | Задача | Примечание |
|---|--------|------------|
| T2-01 | Adaptive DPI bypass (Block C) | fragment -> fake+TTL -> disorder; кэш стратегий по IP |
| T2-02 | TC Ingress Fast Path | TC_FAST_MARK=0x20 есть как константа; функционал нет |
| T2-03 | nftables Flow Offload | DIRECT -> hardware fast path |
| T2-04 | JA3/JA4 fingerprint контроль | TLS fingerprint в дашборде |
| T2-05 | ShadowTLS v3 (Block D, низкий приоритет) | HMAC chain per AppData frame |
| T2-06 | ✅ h2.c framing (T0-03) | standalone h2.c вместо nghttp2; 4 multiplex bug fix |
| T2-07 | per-device traffic logs | логи трафика по MAC |
| T2-08 | eBPF для Flint2 | после согласования |

### Tier 3 — Релиз (W11-W12)

| # | Задача | Примечание |
|---|--------|------------|
| T3-01 | LuCI полный (4.1-4.2) | сейчас заглушка; 11 вкладок план |
| T3-02 | SDK + audit3 + v1.0 | |
| T3-03 | Tests покрытие >80% | |
| T3-04 | CI/CD публичный | |

### Transport roadmap

- [x] gRPC (v1.5.32-1.5.59)
- [x] WebSocket (v1.5.62)
- [x] XHTTP (v1.5.63)
- [x] HTTPUpgrade (v1.5.64)
- [x] Hysteria2 (v1.5.65)
- [ ] Shadowsocks 2022 (T1-08)
- [ ] ShadowTLS v3 (T2-05, низкий приоритет)

---

## DNS критичные фиксы (НЕ УДАЛЯТЬ)

```c
// ФИКС 1: LT без EPOLLET в dns_server_register_epoll
struct epoll_event ev = { .events = EPOLLIN };   // НЕ EPOLLIN|EPOLLET!

// ФИКС 2: форс-дрейн после epoll_ctl ADD
epoll_ctl(master_epoll_fd, EPOLL_CTL_ADD, ds->udp_fd, &ev);
handle_udp_query(ds);

// ФИКС 3: for(;;) без лимита в handle_udp_query
for (;;) {
    ssize_t n = recvfrom(...);
    if (n < 0) break;
}
```

```makefile
# ФИКС 4: AWG во всех профилях
-DCONFIG_EBURNET_AWG=1
```

```c
// ФИКС 5: relay_free — сбросить awg->udp_fd
if (r->upstream_fd >= 0) {
    epoll_ctl(ds->epoll_fd, EPOLL_CTL_DEL, r->upstream_fd, NULL);
    close(r->upstream_fd);
    r->upstream_fd = -1;
#if CONFIG_EBURNET_AWG
    if (r->awg) r->awg->udp_fd = -1;
#endif
}

// ФИКС 6: async_dns_on_event — orphaned epoll fd guard
if (conn && conn->fd >= 0 && conn->pool && conn->pool->epoll_fd >= 0) {
    epoll_ctl(conn->pool->epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
}
```

---

## WS архитектура

### Реализовано (Part A)

- ws_handshake.c — RFC 6455 §1.3, 4/4 unit tests PASS
- ws_frame.c — RFC 6455 §5.7, 7/7 unit tests PASS
- WS upgrade в http_server.c: MEMORY / TRAFFIC / LOGS routes
- http_server_broadcast_tick() — /memory + /traffic, 1 сек
- Stats: atomic traffic_up/down_bytes в stats.h
- Hooks в dispatcher.c: 5 мест в relay loops

### Scheduled (Part B)

- /connections stream (T1-09): tracking TPROXY connections, ~500 строк
- WS subsystem (WS_ARCHITECTURE.md): вынести когда >8 одновременных WS

---

## Key learnings

### Типовые критические баги

- MIPS errno clobber: log_msg -> localtime() -> errno (сохранять до log_msg)
- Reality TLS буфер мал для Certificate chain (фикс: 32768B)
- JSON emoji surrogate pairs ломают strcmp (фикс: \uXXXX -> UTF-8)
- Fake-IP рассинхрон DNS <-> DNAT (UCI fake_ip_range должен совпадать с hardcode)
- Query string ломает strcmp(p, "/path") (фикс: strchr до '?')
- DHCP option 6 отсутствует когда dnsmasq не на :53
- EPOLLET race в HTTP -> CLOSE_WAIT (фикс: LT без EPOLLET)

### Важные технические факты

- TC_FAST_MARK = 0x20 (не 0x10 — коллизия с FWMARK_DEVICE_PROXY)
- SIGHUP = reload; SIGUSR1 = убивает процесс (нет обработчика)
- Все UCI операции через exec_cmd_safe() с argv, никогда system()
- json_escape_str() обязателен для строк из ARP/DHCP/UCI
- TPROXY: mark 0x01 + ip rule table 100, kmod-nft-tproxy удалён
- IPv6 fake-ip: fd00::/120
- Auth token в localStorage: '4eb_token'

---

## Approach & patterns

## РАБОЧИЙ ПОРЯДОК Claude Code (ФИНАЛЬНЫЙ, v2)

### Редактирование кода
Все правки — ТОЛЬКО через file tools напрямую в D:\Проекты\4eburNet\
НЕ через WSL. НЕ через rsync. Файлы на Windows = единственный источник правды.

### Компиляция (WSL — только для этого)
```bash
wsl bash -c "cd '/mnt/d/Проекты/4eburNet/core' && make clean && make mipsel 2>&1"
```
НЕТ rsync. НЕТ копирования. WSL читает /mnt/d/ напрямую.
Бинарник появляется в D:\Проекты\4eburNet\prebuilt\mipsel\4eburnetd автоматически.

### Деплой бинарника (Windows PowerShell/cmd)
```powershell
scp -O D:\Проекты\4eburNet\prebuilt\mipsel\4eburnetd root@192.168.2.1:/usr/sbin/
ssh root@192.168.2.1 "/etc/init.d/4eburnet restart"
```

### SSH на роутеры (Windows SSH, не WSL)
```powershell
ssh root@192.168.2.1   # EC330 (dev)
ssh root@192.168.1.1   # Flint2 (prod, read-only!)
```

### ЗАПРЕЩЕНО НАВСЕГДА
- rsync Windows → WSL (никогда, ни при каких условиях)
- cp/shutil.copytree проекта
- wsl -e python3 / wsl bash -c с Python для копирования
- Редактировать файлы внутри WSL
- ~/phoenix-router-dev/ или любой другой WSL путь для проекта

### Роль этого ассистента

ТОЛЬКО готовые промты для Claude Code в блоке кода.
Без рассуждений, без таблиц если/то, без альтернатив.
Разрешено: краткий анализ результата этапа.

### Версионирование

- +0.0.1 = любое изменение кода
- +0.1.0 = roadmap блок
- +1.0.0 = мажорная архитектура
- Обновлять: Makefile.dev (EBURNET_VERSION) + core/include/4eburnet.h + root Makefile

### Правило конца сессии (ОБЯЗАТЕЛЬНО)

1. Обновить D:\Проекты\4eburNet\.claude\skills\p2p\user_context.md
2. `git add docs/CHANGELOG.md` + commit (без Co-Authored-By, только RostislavKis)
3. git tag vX.Y.Z HEAD (после audit_v47 → 0 блокеров)
4. git push origin master && git push origin vX.Y.Z

Без явного подтверждения верификации от Ростислава — не коммитить, не пушить.
НИКОГДА НЕ добавлять core/, prebuilt/ в git — только docs/CHANGELOG.md из отслеживаемых файлов.

---

## Git состояние

- Последний коммит: v2.2.5 (docs/CHANGELOG.md)
- Последний тег: v2.2.5 (2026-05-13)
- Текущий бинарник: v2.2.5 на EC330 (задеплоен 2026-05-13, 3.1MB)
- В git: .gitignore + 4eburNet.png + README.md + .github/workflows/build.yml + docs/CHANGELOG.md
- Исходники: закрыты (.gitignore + git rm --cached применён в cleanup v1.5.152)
- CHANGELOG: docs/CHANGELOG.md

## ПРАВИЛА РЕПОЗИТОРИЯ (АБСОЛЮТНЫЕ)

- Публично: ТОЛЬКО README.md + 4eburNet.png + .gitignore + docs/CHANGELOG.md + .github/workflows/build.yml
- НИКОГДА НЕ добавлять: core/, luci-app-4eburnet/, tools/, scripts/, prebuilt/, build/, Makefile
- git add — ТОЛЬКО конкретные публичные файлы по имени (например: `git add docs/CHANGELOG.md`)
- НИКОГДА git add -u / git add . / git add -A — затащит core/ и prebuilt/
- git config user.name = "RostislavKis" (настроен локально, не менять)
- НИКАКИХ "Co-Authored-By: Claude" в коммитах — нарушение правила "без следов AI"
- Коммиты только от имени RostislavKis, без AI-трейлеров
- НИКОГДА не пушить исходники: core/, tools/, luci-app-4eburnet/ — gitignored и закрыты

---

## Tools & resources

### Dashboard архитектура

- LuCI = вкладка-заглушка со ссылкой на :8080
- Dashboard = :8080 в 4eburnetd, форк zashboard v3.5.0
- QR-код: vless://uuid@host:port?security=tls&sni=...#name или wireguard://
- 11 вкладок план: Overview, Proxies, Providers, Connections, Rules, DNS, Advanced, Logs, SSH Console, Settings, Setup

### SDK окружение в WSL

```
~/4eburnet-dev/sdk/
├── aarch64/       OpenWrt SDK 25.12.0 mediatek-filogic gcc-14.3.0
├── mipsel-mt7621/ OpenWrt SDK 23.05.5 ramips-mt7621 gcc-12.3.0
├── mipsel/        OpenWrt SDK 23.05.5 ramips-mt76x8 gcc-12.3.0
└── x86_64/        OpenWrt SDK 23.05.5
```

wolfSSL: /usr/local/musl-wolfssl{,-mipsel,-aarch64}/

### refs/ — эталонные реализации

```
refs/mihomo/    — mihomo v1.19.24 (Go), полные исходники
refs/sing-box/  — sing-box (Go)
refs/xray-core/ — xray-core (Go), server-side reference
```

Правило: перед реализацией нового транспорта — читать refs/.

### Структура проекта

```
D:\Проекты\4eburNet\
├── 4eburNet.png / README.md / .gitignore
├── config.yaml          <- РАБОЧИЙ Clash YAML от Flint2
├── DASHBOARD_PLAN.md / WS_ARCHITECTURE.md
├── .claude/skills/p2p/
│   ├── user_context.md  <- ЭТОТ ФАЙЛ
│   └── p2p.config.md + 24 модуля P2P
├── core/                <- gitignored (C23 исходники)
│   ├── Makefile.dev
│   ├── include/ (4eburnet.h, ws.h, stats.h, http_server.h)
│   ├── src/ (dns/, proxy/protocols/, ws_*.c, http_server.c, dispatcher.c, main.c)
│   └── tests/
├── luci-app-4eburnet/   <- gitignored
├── dashboard-src/       <- zashboard v3.5.0 fork, gitignored
├── tools/sub_convert.py
├── docs/CHANGELOG.md    <- в git
├── prebuilt/mipsel/4eburnetd  <- gitignored
├── build/               <- gitignored
└── refs/ (mihomo/, sing-box/, xray-core/)
```

---

## История сессий

### 2026-04-19–20 — v1.5.0 закрыт и tagged
audit_v42 0/0/0. IPv6 fake-ip fd00::/120.

### 2026-04-21 — v1.5.1 DNS Client Compatibility
PTR resolver RFC 1035, AD bit cleanup RFC 4035, DNS Cookie RFC 7873+9018, AAAA NODATA, UDP bind LAN IP, DHCP option 6. Фикс iPhone WiFi icon.

### 2026-04-22 — Phase 1 + Phase 2 Group 1 + WS Part A
v1.5.1 release 3 архитектуры. Dashboard zashboard fork. Clash REST endpoints. WS Part A (ws_handshake + ws_frame, 11/11 unit tests). /memory + /traffic streams. sub_convert.py UCI refresh. Инцидент: bypass на Flint2 -> быстрый откат.

### 2026-05-01 — v1.5.27–v1.5.30: MIPS Reality debug
MIPS errno clobber: log_msg -> localtime() -> errno=EAGAIN -> RELAY_CLOSING. Фикс: saved_errno. Reality -> ACTIVE.

### 2026-05-02 — v1.5.32–v1.5.59: gRPC полный + YouTube
gRPC ~780 LoC: H2+HPACK+LPM+protobuf+flow control. Trojan/gRPC дедлок исправлен. YouTube стабильно. refs/mihomo+xray+sing-box загружены.

### 2026-05-03 — v1.5.60–v1.5.67: транспорты + OOM + SIGHUP
v1.5.60: честный HC url-test (child_do_hc_trojan_grpc). OOM фикс PROXY_GROUP_GLOBAL_HC_LIMIT=16.
v1.5.61: grpc_recv state machine (5 goto -> switch/case).
v1.5.62: WebSocket T0-04 (~200 LoC), честный HC 170ms.
v1.5.63: XHTTP T0-05 (переписан, ~390 LoC), HTTP/2 ALPN=h2.
v1.5.64: HTTPUpgrade T0-06 (~110 LoC).
v1.5.65: Hysteria2 T0-07 async.
v1.5.66: DNS RFC 8767 stale-while-revalidate + XHTTP HC честный.
v1.5.67: SIGHUP фикс — безусловная регистрация sigaction.

### 2026-05-04 — v1.5.72–v1.5.76: SIGSEGV + failover + VLESS/TCP HC
relay_free NULL tls fix (SIGSEGV). Немедленный failover. Честный туннельный HC VLESS/TCP через gstatic.com:443. Finland Helsinki 171ms. YouTube работает.

### 2026-05-06 — v1.5.79+: G15 + json unicode + PUT group + Reality буферы
G15: mem_tier, HC CTX, dns_policy, ip_cidr6.
v1.5.81: json_get_str \uXXXX surrogate pairs + пробелы вокруг ':', 7/7 tests.
v1.5.82: PUT /proxies/{group} поиск по g->servers[].name, URL_TEST + SELECT.
v1.5.83: Reality TLS rbuf/ptbuf 16400->32768. Certificate chain 25958B. REALITY_VLESS->ACTIVE стабильно.

### 2026-05-07 — v1.5.99–v1.5.114: Mux.Cool + dashboard + batch HC + OOM fix
v1.5.99-v1.5.100: Mux.Cool transport-agnostic I/O (transport_ctx/send/recv/free на TLS/Reality/WS/XHTTP/gRPC), TCP relay через Mux.Cool отключён (`if(false)` guard).
v1.5.101-v1.5.103: hc_clamp_ms [0,9999] в 7+3 местах. PROXY_GROUP_MAX_SERVERS 32→256 (вмещает ~80 серверов провайдера). QUIC UDP 443 drop в nftables.c (iPhone YouTube fallback на TCP). xudp:true тег в /proxies JSON.
v1.5.105: Dashboard zashboard v3.5.1 cdn-fonts (upstream, идентичный Flint2 mihomo). /usr/share/4eburnet/dashboard/, mihomo-compat /ui/ + 307 redirect. http_send_redirect helper.
v1.5.106-v1.5.107: Init available=true в proxy_group.c (mihomo-семантика, серверы видимы до первого HC). Batch HC /group/{name}/delay (параллельный fork с лимитом). CORS echo Origin + OPTIONS preflight 204 + Allow-Methods/Headers.
v1.5.108: ServerConfig.name 64→128 (длинные UTF-8 имена с emoji + кириллица). HTTP_PATH_MAX 256→1024. /proxies/{name}/delay instant cached.
v1.5.109: route_clash_proxy_delay никогда не форкает HC, только cached (cached>0 → ms, cached=0 → 0, AWG → 0). Никаких 408.
v1.5.110-v1.5.111: BATCH_MAX 4→16, deadline 25→60. AWG fake delay=1 → реальный TCP 443 ping → реальный AWG handshake. pgm_server_latency возвращает first non-zero.
v1.5.112: child_do_awg_handshake → RTT probe (без awg_process_incoming, измеряем RTT при первом UDP ответе). Cloudflare WARP error пакет = валидный RTT 206-307ms.
v1.5.113: BATCH_MAX 16→24, deadline 60→30, per_server cap 5000→3000. JSON ответ с fallback на pgm_server_latency для недотестированных серверов.
v1.5.114 (OOM fix): BATCH_MAX 24→8 (32MB worst), deadline 30→20, cap 3000→2000. Причина: 24 параллельных AWG fork × 3с UDP poll = 70+ живых child → 116MB EC330 OOM → dropbear/uhttpd не форкались (LuCI/dashboard 502). 8 параллельных безопасно.

### 2026-05-08 — v1.5.115–v1.5.129: XUDP step 3 + gRPC teardown + url-test fix

v1.5.115: XUDP UDP relay step 3 — needs_io=1 + wake_fd reply path + relay_owned.
v1.5.127: grpc_conn_teardown переписан. Убраны: raw recv() drain (уничтожал DATA frames),
close(tcp_fd), epoll_ctl(DEL), state=IDLE, streams_count=0. Оставлен только wake_fd пинг
живых streams. Эффект: googlevideo.com lifetime 113s (был 1-3s premature EOS → серый экран
YouTube на iOS). GEMINI переключён на URLTest через UCI.
v1.5.129: url-test latency=0 захват fixed. Сервер с `latency_ms=0` при инициализации
выбирался как best (0 < UINT32_MAX) и никогда не заменялся (best+tol < 0 = false).
Фикс: init=UINT32_MAX + `> 0` guard в 4 точках best-поиска.

### 2026-05-09 — v1.5.130–v1.5.143: retry + failover + AWG + Reality throttle + pinned

v1.5.130-132: mihomo-style retry при HS fail (до 3 retry в группе), upstream 10с timeout,
mark_server_fail_immediate (1 HS fail = available=false немедленно).
v1.5.133-135: connect_deadline 5с, gRPC retry acquire stream, group-scoped fail,
WS ALPN http/1.1 override, AWG→TELEGRAM UCI.
v1.5.136: awg_hs_epollin_count>50→FAIL_OR_RETRY, skip_awg в proxy_group_select_server.
v1.5.137-139: pending queue 64 + GLOBAL_RESOLVE_CACHE 4→64; тики 1693ms→135ms.
v1.5.143: proxy_group_state_t.pinned — ручной выбор url-test/select переживает рестарт.
PUT /proxies/{group} → pinned=true → selected.json → pgm_restore_selection при старте.
HC round-complete не меняет selected_idx при pinned. Failover сбрасывает pinned.
Старт: "начальный выбор [0] Bulgaria" → "восстановлен выбор [8] Switzerland (pinned)".

### 2026-05-10 — v1.5.149: T0-04 ws_client.c полная реализация (6 багов)

Баги A/C/D/E/F/H закрыты:
- Баг A: PING/PONG — ws_send_ctrl() + WS_RECV_CTRL + WS_RECV_PONG_SEND states;
  send_fn добавлен в ws_client_recv (4 call sites: dispatcher×3 + hc_vless×1).
- Баг C: 64-bit extended length в send (uint64_t cast для MIPS 32-bit size_t).
- Баг D: ws_verify_accept() — SHA1(key+GUID)→base64 через wolfCrypt wc_Sha.
- Баг E: WC_RNG embedded, wc_InitRng в ws_client_init, ws_client_free с guard.
- Баг F: extra_headers[512] в ws_client_conn_t, вставляется в HTTP GET.
- Баг H: ws_client_close() — CLOSE frame opcode=0x8 status=1000;
  ws_client_free в relay_free + cb_ws_free + hc_vless.c.
  MIPS fix: len>>56 → uint64_t cast (was: shift-count-overflow -Werror).

### 2026-05-10 — v1.5.155–v1.5.158: T0-07 Hysteria2 + gRPC рефакторинг

v1.5.155: T0-07/A-D: errno маскировка в `hysteria2_connect_step` (фаза CONNECTING + AUTH) и
  `hysteria2_wait_response_step` → реальный errno вместо принудительного EAGAIN. EPOLLERR
  без EPOLLIN в RELAY_HY2_CONNECT теперь обрабатывается отдельной веткой.
v1.5.156: T0-07/E-H: per-level flush в `hy2_cb_add_handshake` (Initial/Handshake/Application);
  HS timeout 10с через `upstream_first_byte_deadline`; `auth_rxbuf` overflow → set_error;
  `RELAY_FAIL_OR_RETRY` вместо relay_free в двух точках.
v1.5.157: gRPC рефакторинг Steps 1-3 — `grpc_build_hpack_raw`, удаление `grpc_hs_drain_payload`
  (7 call-site → inline grpc_drain), pre-alloc `pending_to_client` в `grpc_pool_acquire_stream`.
v1.5.158: `grpc_stream_recv` EAGAIN race (`goto deliver` при pending после recv_dispatch);
  `H2_WINDOW_UPDATE` length != 4 → GRPC_CONN_GOAWAY + EPROTO.

### 2026-05-10 — v1.5.151–v1.5.154: T0-05 XHTTP + T0-06 HTTPUpgrade

v1.5.151-153: XHTTP полный: VLESS header + VLESS_SEND/VLESS_RESP states; immediate recv
  (VLESS header в DN_REQ без ожидания EPOLLOUT); буферизованное чтение ответа.
v1.5.154: T0-06 HTTPUpgrade: буферизованное чтение (256 байт за recv_fn) вместо побайтового;
  memmem по накопленному буферу; проверка Connection: upgrade в ответе сервера.

### 2026-05-10 — v1.5.159–v1.5.163: audit_v47 закрыт

5 блокеров MIPS stack (static hdr[768]/cors[384] в http_send/redirect/file/OPTIONS,
qpack[540] в hy2_h3_auth_send), 2 pre-existing FAIL в tls13_hs_unit (fd+flags zeroing),
DNS_DRAIN_BATCH=32 cap, fake_ip CIDR→FAKE_IP_RANGE_DEFAULT/FAKE_IP6_RANGE_DEFAULT,
PKG_VERSION sync 1.5.127→1.5.163, NFT_TPROXY_PORT вместо literal 7893,
docs/BUILD.md создан (535 строк, 4 arch), константы централизованы в constants.h
(TC_FAST_MARK, IPC_MAX_CLIENTS, DNS_DRAIN_BATCH), popen→exec_cmd_safe в route_set_dns_upstream,
wolfSSL_Cleanup idempotency guard, hy2_ensure_level_flushed wrapper, README badge v1.5.163.
Итог: 0/0/0. commit 096c8e7, tag v1.5.163.

### 2026-05-11 — v1.5.174–v1.5.183: audit_v48 + geo pipeline + rule-providers

**audit_v48 (v1.5.178-179):** 11 блокеров + 9 проблем + 10 замечаний закрыты.
CRASH: relay_release_upstream AnyTLS USE-AFTER-FREE + WS RNG leak.
DATA_LOSS: TUIC EPOLLET drain loops + defrag_tick в dispatcher_tick.
MIPS stack: h3frame[600]×2 + tmp[8192] + stack_buf[1500] → static.
HC: hc_anytls.c + hc_tuic.c + proxy_group dispatch. Dashboard: AnyTLS/TUIC type + /ws/logs /ws/connections.

**F0-1 geo pipeline (v1.5.180-181):** scripts/geo_update_repos.ps1 (Windows).
filter repo (RostislavKis/filter) — 5 категорий, 2.1M доменов, .gbin формат.
geo_compile host/mipsel/aarch64 в Makefile.dev. mmap: RSS 52MB→5.8MB (9x).
DNS adblock: block_geosite_ads/trackers/threats=true by default → doubleclick.net/ads.google.com → NXDOMAIN.

**F0-2+F0-3 sub_convert.py (v1.5.181):** rule-providers file_format поле.
fake_ip_enabled + fake_ip_filter (50 доменов). doh_url + doh_fallback из nameserver/fallback.
mode (rule/global/direct). hosts[:20] → dns_static_hosts. sniffer/tun → WARNING.

**T1-01 rule-providers (v1.5.182-183):** RULE-SET telegram/steam/instagram работает EC330.
MAX_PROVIDER_CACHE 16→64. first-boot next_update=0. YAML payload auto-detect + strip.
classical format: DOMAIN-SUFFIX,t.me → t.me (strip TYPE, prefix). EC330: t.me→fake-IP ✅.

### 2026-05-10 — v1.5.172: TUIC v5 П-3 (dispatcher integration + sub_convert)

dispatcher.h/c + sub_convert.py:
- RELAY_TUIC_HS=29 + RELAY_TUIC_ACTIVE=30 в relay_state_t enum
- relay_conn_t: void *tuic_conn + void *tuic_stream (под CONFIG_EBURNET_QUIC)
- tuic_protocol_start: resolver → UDP socket → tuic_conn_create → epoll EPOLLIN|EPOLLET
- RELAY_TUIC_HS: recv UDP → tuic_conn_hs_step → tuic_send_auth → tuic_conn_open_tcp → wake_fd
  - ep_download.relay=r установлен явно (guard против NULL dereference)
  - wake_fd зарегистрирован как download_fd → ep_download → EPOLLIN|EPOLLET
- RELAY_TUIC_ACTIVE: 3 ветки: client(EPOLLIN), ep_download(wake), ep_upstream(UDP recv)
- relay_free + relay_release_upstream: tuic_conn_invalidate_fd + stream wake_fd=-1 + pool_remove
  - WHY wake_fd=-1 перед pool_remove: relay_free уже закрыл download_fd; pool_remove guard
- relay_try_retry: tuic/tuic5 добавлены в skip list (UDP, другая логика)
- protocol_find_for_server: tuic/tuic5 → proto_tuic
- tuic_conn_get_fd + tuic_conn_invalidate_fd добавлены в tuic_v5.h/conn.c
- sub_convert.py: tuic/tuic5/tuic-v5 → UCI (uuid, password, udp_relay_mode)
- mipsel binary: 3.0MB, 99 PASS 0 FAIL

### 2026-05-10 — v1.5.171: TUIC v5 П-2 (QUIC HS + Authenticate + TCP relay)

tuic_v5_conn.c (840 LoC) + tuic_v5.h расширен + config.h/c TUIC поля:
- wolfSSL QUIC callbacks: tuic_cb_set_secrets/add_handshake/flush/alert (паттерн hy2)
- tuic_conn_create: TLS init + Initial keys + ClientHello flush (sync UDP send)
- tuic_conn_hs_step: EPOLLIN-driven: process_incoming → wolfSSL_quic_do_handshake → flush
- tuic_gen_token: TLS-Exporter (raw 16 UUID bytes как label, НЕ строка — так в mihomo)
- tuic_send_auth: Authenticate на client uni-stream (ID=2), FIN закрывает стрим
- tuic_conn_open_tcp: stream_pool_open + Connect frame на bidi stream
- tuic_stream_tcp_send/recv: pending буфер + wake_fd (eventfd)
- tuic_conn_recv_dispatch: recv(MSG_DONTWAIT) + process_incoming + ACK Short Header
- config.h: tuic_uuid[37] + tuic_password[128] + tuic_udp_relay_mode в ServerConfig
- mipsel binary: 3.1MB (лимит 4MB OK)
- Не задеплоен (wire protocol + HS lib; П-3 = dispatcher интеграция следующий)

### 2026-05-10 — v1.5.170: TUIC v5 П-1 (wire protocol + stream pool + NewReno CC)

tuic_v5.h + tuic_v5_proto.c (455 LoC) + test_tuic_v5.c (99 PASS, 0 FAIL):
- Address encode/decode: Domain=0x00, IPv4=0x01, IPv6=0x02, None=0xFF (из mihomo protocol.go)
  WHY: задание перепутало IPv4/Domain — исправлено по refs/mihomo
- Commands: Authenticate(50B), Connect, Packet hdr encode/decode, Dissociate(4B), Heartbeat(2B)
- deFragger: per-frag indexed storage (frag_bufs[TUIC_MAX_FRAG_TOTAL]) — сборка in-order
  как mihomo bag.frags[frag_id]; LRU eviction oldest по ts
- Stream pool: hash table, stream_id 0/4/8... (client bidi QUIC §2.1), eventfd wake_fd
- NewReno CC: slow-start cwnd++/ACK → CA mode cwnd+=1/cwnd/RTT → on_loss ssthresh=max(cwnd/2,2)
- mipsel binary: 3.0MB (без изменений, tuic_v5_proto.c добавлен в SOURCES)
- Не задеплоен на EC330 (wire format lib, П-2 = QUIC handshake следующий)

### 2026-05-10 — v1.5.144–v1.5.148: T0-03 h2.c HTTP/2 framing + grpc multiplex fixes

T0-03 закрыт: standalone h2.c/h2.h вместо nghttp2. 8 функций framing primitives.
v1.5.144: h2.c/h2.h — h2_write/read_frame_hdr (с len guard), h2_varint_encode/decode,
  h2_grpc_lpm_write/parse, h2_pb_field1_write/parse. Добавлен в Makefile.dev.
v1.5.145: grpc.c интеграция — удалены дублирующие static функции + 13 #define,
  grpc_send переписан: h2_pb_field1_write + h2_grpc_lpm_write + единый malloc буфер.
v1.5.146: h2_read_frame_hdr: return int, size_t len → 4 call site обновлены.
v1.5.147: grpc_stream_send — split send_fn×2 → единый malloc + один send_fn.
  grpc_hs_drain_payload — лимит 256 итераций + EAGAIN (аналог grpc_drain).
v1.5.148: PING mid-read desync fix — pending_ctrl_got (cursor) + buf[9]=2 (mid-PING signal).
  Шаг 2б в recv_dispatch: resume при EAGAIN с 0 байт. PING ACK send_fn check исправлен
  (== 0 → >= 0). goaway_last_stream_id → pending_stream_id + WHY-комментарий.

---

## P2P v7C.2 Integration

Доступные команды:
- /p2p — главное меню 32 пунктов
- /p2p-quorum <task> — multi-agent council
- /p2p-scope <project> — декомпозиция проекта
- /p2p-feedback <prompt> — отладка промта
- /p2p-explore <territory> — разведка неизвестного
- /p2p-capsule — handoff между сессиями
- /p2p-metrics — отчёт сессии
- /p2p-chain <pipeline> — Chain Mode
- /p2p-atlas — audit модулей P2P

Settings: Host: Claude, ENV: code, Output: ru, Cortex: true, Scope helm: auto.
Конфигурация: D:\Проекты\4eburNet\.claude\skills\p2p\p2p.config.md

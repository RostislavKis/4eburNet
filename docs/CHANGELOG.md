# Changelog

## [1.5.22] — 2026-04-30

### gRPC/WS transport penalty + /api/dns/upstream/test fix + dashboard DnsUpstream

- `proxy_provider.c`: парсер VLESS URI и Clash YAML теперь распознают transport=grpc и
  transport=ws; YAML: добавлен ключ `network:` (grpc/ws/xhttp/httpupgrade); `flow:` не
  перезаписывает transport если `network` уже выставил grpc/ws
- `proxy_group.c`: penalty для серверов с transport=grpc/ws — `latency_ms=60000,
  available=false` без запуска HC; url-test не выбирает их до реализации T0-03/T0-04;
  cursor и таймер продвигаются inline (без pipe)
- `http_server.c`: `POST /api/dns/upstream/test` — если тело запроса пустое (нет поля
  `"ip"`), тестирует текущий `s_cfg->dns.upstream_bypass` из конфига; ранее возвращал 400
- `dashboard-src/DnsUpstream.vue`: новый компонент "Proxy-server nameserver" в
  BackendSettings — поле IP, кнопка «Проверить» (latency зелёный/красный),
  кнопка «Сохранить» (PATCH без перезапуска); заполняется при монтировании через GET
- `api/index.ts`: три API-функции — `getDnsUpstreamAPI`, `patchDnsUpstreamAPI`,
  `testDnsUpstreamAPI`; деплой dashboard на EC330 (index-B0buw7U1.js)

## [1.5.21] — 2026-04-30

### proxy-server nameserver via upstream_bypass

- `config.h` / `config.c`: поле `DnsConfig.upstream_bypass` было уже реализовано;
  `dispatcher_resolve_server()` использует его как primary DNS для резолвинга адресов
  прокси-серверов (bg1.xxee.ru и т.п.), обходя fake-IP DNS и избегая рекурсии
- `4eburnet.init`: добавлена функция `detect_wan_dns()` — при старте автоматически
  определяет WAN DNS из `/tmp/resolv.conf.d/resolv.conf.auto` (netifd) и записывает
  в `4eburnet.dns.upstream_bypass` если поле пустое; EC330: автодетект → 192.168.1.1
- `http_server.c`: три новых REST эндпоинта —
  - `GET /api/dns/upstream` → `{"ip":"..."}` текущий upstream_bypass из памяти
  - `PATCH /api/dns/upstream` → `{"ip":"..."}` обновляет UCI + в памяти без перезапуска;
    добавлен парсинг PATCH метода (`is_patch` в HttpConn)
  - `POST /api/dns/upstream/test` → `{"ok":true,"latency_ms":N}` fork + `net_resolve_host_direct`
    + poll(5000ms); блокирующий, но endpoint не критический (admin tool)
- `dashboard.html`: новая карточка "Proxy-server nameserver" на вкладке DNS —
  поле IP с кнопками «Проверить» и «Сохранить»; заполняется при открытии вкладки
- WHY: `dispatcher_resolve` не мог резолвить bg1.xxee.ru — upstream_bypass был пуст,
  `upstream_default=8.8.8.8` недоступен с EC330 (вероятно, firewall Flint2);
  с `upstream_bypass=192.168.1.1` relay ошибок нет, latency test 6ms

## [1.5.20] — 2026-04-30

### Vision HC + VLESS+WS fix

- `hc_vless.c`: Vision flow detection — если `srv->reality_flow` содержит "vision",
  строим addons через `vision_build_addons()` и передаём в `vless_handshake_start_reality`;
  для Vision серверов `ok=1` сразу после Reality HS + VLESS request (без ожидания
  VLESS response — xray с Vision не отвечает пока не придёт inner-TLS ClientHello)
- `hc_vless.c`: убран wolfSSL fallback для VLESS без Reality — теперь TCP connect = ping;
  WHY: VLESS+WS/XHTTP/gRPC требуют HTTP Upgrade или специфичный framing, без которого
  сервер отвечает HTTP 400 (0x48), ломая VLESS response parse; TCP ping достаточен
  для проверки доступности non-Reality VLESS серверов
- Верификация на EC330: Bulgaria/Canada/Switzerland VLESS+Reality+Vision → `delay>0`
  через `/proxies/{name}/delay`; нулевые WARN от нового daemon (v1.5.20)

## [1.5.19] — 2026-04-30

### hc_vless для не-VLESS (Trojan без UUID)

- `hc_vless.c`: для протоколов, отличных от VLESS, делать только TCP connect (не VLESS HS)
- WHY: Trojan и другие протоколы без UUID вызывали "VLESS: невалидный UUID" при HC

## [1.5.18] — 2026-04-29

### latency в /proxies, hc_vless для /delay, /storage endpoint

- `http_server.c`: `pgm_server_latency()` — поиск latency_ms сервера по unified
  index во всех группах pgm; секция серверов `/proxies` теперь возвращает
  `"history":[{"time":"...","delay":N}]` если latency_ms > 0 после health-check
- `http_server.c`: `/proxies/{name}/delay` для VLESS/Trojan серверов вызывает
  `hc_vless_spawn()` вместо прямого TCP ping (ТСПУ блокирует прямые соединения);
  `url=` из query string парсится через `net_parse_url_host()`
- `http_server.c`: HTTP-парсер теперь читает `Content-Length` для PUT запросов
  (ранее только POST); без этого `/storage` PUT возвращал 413
- `http_server.c`: `route_storage()` + `/storage/{key}` routing — in-memory
  key-value хранилище (8 слотов × 4KB) для zashboard настроек;
  GET → `{"key":"...","data":"..."}` или 404, PUT → сохранение + echo

## [1.5.17] — 2026-04-29

### Health-check через реальный VLESS/Reality туннель

- `core/src/proxy/hc_vless.c` (новый): `hc_vless_spawn()` — fork+pipe health-check
  через реальный VLESS или VLESS+Reality туннель вместо прямого TCP connect;
  child: DNS resolve → TCP connect → Reality TLS handshake (`reality_conn_new` +
  poll loop) → VLESS header → HTTP GET cp.cloudflare.com → проверка `"HTTP/"` в
  ответе → `"OK <ms>\n"` или `"ERR\n"` в pipe; для серверов без Reality — wolfSSL
  fallback path; read-end pipe возвращается для регистрации в epoll
- `proxy_group.c`: для `url-test` групп с протоколом `vless`/`trojan` заменён
  `net_spawn_tcp_ping` на `hc_vless_spawn`; хост/порт берётся из `gs->test_url`
  через `net_parse_url_host`, дефолт `cp.cloudflare.com:80`
- `test_hc_vless.c` (новый): 8/8 PASS — T1 NULL guard, T2 ECONNREFUSED→ERR,
  T3 timeout 400ms→ERR за 422ms (RFC 5737 TEST-NET 192.0.2.1)
- Верификация на EC330: серверы PrivateVPN реально отвечают через Reality
  туннель (`reality_recv Alert`, `VLESS response`) вместо `"недоступен"`
  при прямом TCP (ТСПУ блокировка)

## [1.5.16] — 2026-04-29

### Proxy Groups — url-test autoselect

- `proxy_group_handle_hc_event`: принимает `const EburNetConfig *cfg` (для логирования имени лучшего сервера); после завершения полного цикла проверки всех серверов для групп типа `url-test` выбирается сервер с минимальной задержкой → `selected_idx` обновляется атомарно; лог INFO: `"url-test: %s → %s TCP (%ums)"`
- `config.c`: парсер типов групп принимает `"url_test"` (underscore, OpenWrt uci формат) наравне с `"url-test"` (dash, Clash YAML формат); аналогично `"load_balance"` / `"load-balance"`
- До этого фикса: `type=url_test` в `/etc/config/4eburnet` → группа считалась `select` → autoselect не работал, всегда `servers[0]`

## [1.5.15] — 2026-04-29

### Dashboard / WebSocket

- WS `/logs` endpoint: `ws://host/logs` принимает подписчиков; при подключении отдаёт историю (ring buffer 100×256B); новые строки пушатся реалтайм через `http_ws_log_hook` — хук из `log_msg`; формат Clash: `{"type":"info|warning|error|debug","payload":"..."}`
- WS `/connections` endpoint: `ws://host/connections` — snapshot `{"downloadTotal":N,"uploadTotal":N,"connections":[],"memory":N}` каждую секунду через `broadcast_tick`
- `log_set_hook()`: новый API в log.c — регистрирует callback для каждой записанной строки лога; `log_msg` переформатирован в единый буфер 512B (устранено двойное `va_list`)
- `ws_route` enum: добавлены `WS_ROUTE_LOGS=4`, `WS_ROUTE_CONNECTIONS=5`
- Ping concurrency guard: `atomic_int s_ping_active`, `PING_MAX_CONCURRENT=4` — не более 4 одновременных `fork()` для TCP ping на MIPS; при перегрузке → HTTP 408

## [1.5.14] — 2026-04-29

### Dashboard / Clash API

- `route_clash_proxy_delay`: новый endpoint `GET|PUT /proxies/{name}/delay?timeout=N` — TCP ping для любого сервера (UCI + proxy-providers); fork+pipe, блокирующий `poll(timeout+1000ms)`; percent-decode имён с эмодзи/кириллицей; ответ `{"delay":N}` 200 или `{"message":"..."}` 408
- `route_clash_connections`: новый endpoint `GET /connections` — возвращает `{"downloadTotal":N,"uploadTotal":N,"connections":[],"memory":N}` из `g_stats` + RSS `/proc/self/status`
- `url_pct_decode`: вспомогательная функция декодирования URL-encoded компонент пути (UTF-8 имена серверов PrivateVPN)
- `HttpConn.is_put`: новое поле; PUT-запросы парсируются и маршрутизируются; инициализация слота `is_put = 0` добавлена

## [1.5.13] — 2026-04-29

### Dashboard / API

- `route_clash_proxies`: `"all"[]` теперь строится из runtime state (`gs->servers[].server_idx` unified индекс) вместо `grp->servers[]` (только UCI-статические серверы) — proxy-группы видят серверы из proxy-providers (PrivateVPN: 64, ARZA: 8)
- `route_clash_proxies`: буфер увеличен с 32KB до 64KB — покрывает конфиги с 64+ provider серверами

## [1.5.12] — 2026-04-29

### nftables / Routing

- `nft_init`: добавлена цепочка `output_allow` (`type filter hook output priority -1; policy accept`) — разрешает исходящий WAN-трафик самого роутера до fw4 filter chain (priority 0), которая ошибочно блокировала все OUTPUT соединения роутера через `reject_to_wan`
- `nft_ensure_output_allow`: новая idempotent функция — вызывается если таблица уже существует (обновление с предыдущей версии), атомарно добавляет chain через `add chain`

### DNS

- `dns_server.c`: `resolve_upstream_addr` fail (action PROXY, `upstream_proxy` не настроен) → больше не дропает запрос молча, использует `upstream_fallback` (8.8.8.8) — устраняет timeout для роутерских DNS-запросов к proxy-доменам

### Proxy Providers / DNS

- `child_do_fetch` и `child_do_fetch_h`: прямой DNS-резолвинг (`net_resolve_host_direct` → 1.1.1.1/8.8.8.8) вынесен ПЕРЕД uclient-fetch — устраняет circular dependency (провайдер→4eburnetd DNS→прокси→провайдер) без 15с ожидания uclient-fetch timeout
- Если прямой DNS разрезолвил IP → wolfSSL fetch напрямую, uclient-fetch используется только как fallback (системный DNS + CA cert bundle)

## [1.5.11] — 2026-04-29

### Proxy Providers

- `base64_decode`: null byte (0x00) трактуется как whitespace (skip) — устраняет ARZA parse failure (null byte в позиции 3063 в ответе сервера)
- ARZA: загружено 8 серверов (было 0 из-за провала base64 decode)
- `child_do_fetch_h`: добавлен `stat(tmp_path)` после `uclient-fetch` exit 0 — если файл не создан, сразу переходим в wolfSSL fallback вместо ENOENT rename loop
- `child_do_fetch`: аналогичный stat-check для провайдеров без кастомных заголовков

## [1.5.10] — 2026-04-29

### DNS

- `dns_server_init`: дефолт `listen_port = 53` когда UCI не задаёт `option listen_port` — без этого демон завершался сразу после старта (возврат -1 из init)

### Proxy Providers / HTTP

- `http_do_tls_get`: добавлены параметры `redirect_buf/redirect_size`; при HTTP 3xx парсится заголовок `Location`, результат пишется в буфер, функция возвращает -2
- `net_http_fetch_ip_h`: реализован redirect-loop до 3 переходов — re-resolve нового хоста через 1.1.1.1/8.8.8.8, повтор TLS-соединения
- `accessbyme.com`: HTTP 301 → `sub.accessbyme.com` теперь следуется автоматически

## [1.5.9] — 2026-04-28

### HTTP / Dashboard

- Убран `Content-Length` из `http_send_file` — устранён `ERR_CONTENT_LENGTH_MISMATCH` при неполной передаче файла
- `http_send_file`: добавлен `while(!send_buf && send_file)` цикл — без него loopback-сокет (буфер 4MB+) никогда не давал EAGAIN, файл обрезался после первых 4096 байт
- EPOLLOUT handler: заменён одиночный `conn_feed_file` на цикл до EOF/EAGAIN — файлы >4KB теперь передаются полностью
- Dashboard zashboard загружается полностью (JS 1.5MB → был 4096 байт)

## [1.5.8] — 2026-04-28

### HTTP / EPOLLET fix

- EPOLLET race fix: HTTP-соединения переведены на Level-Triggered (`EPOLLIN | EPOLLRDHUP` без `EPOLLET`) в трёх точках — устранены CLOSE_WAIT накопления и зависание дашборда (чёрный экран)
- `/api/status` возвращал `"status":"stopped"` — диагностика: PID-файл создаётся только при старте через procd init script, не при ручном запуске

### DNS / Эпоксидные фиксы (задокументировано)

- `CONFIG_EBURNET_AWG=1` во всех профилях (micro/normal/full) — AWG не компилировался в MICRO профиле
- DNS LT mode: `EPOLLIN` без `EPOLLET` на UDP fd — устранён CPU 100% spin
- Форс-дрейн сразу после `epoll_ctl(ADD)` — не теряем запросы накопившиеся до ADD
- `for(;;)` без batch-лимита в `handle_udp_query` — дрейним всё до EAGAIN

## [1.5.6] — 2026-04-27

### Безопасность
- Constant-time сравнение api_token (заменён strncmp на volatile diff loop)
- api_token fresh-install: localhost bypass вместо 403 для всех

### MIPS / стек
- conn_feed_file: char chunk[4096] → static BSS
- dns_server: malloc(4096) в hot-path → static BSS
- tls13_keys: uint8_t lbl[320] → static BSS

### Reality TLS
- Б4 T0-03: deferred Curve25519 keygen в dispatcher_tick с throttle
- ET stall fix: throttled RELAY_REALITY_HS временно LT для re-fire
- RELAY_REALITY_VLESS: убран избыточный throttle (нет Curve25519)
- wc_HmacInit добавлен перед wc_HmacSetKey в tls13_hs.c и reality_auth.c
- AES-128/AES-256 ограничение задокументировано (0x1302 принят, не работает)

### DNS
- opencck_updater: kill(SIGHUP) после rename → geo reload активируется
- child fork: close_range(3, ~0U) перед net_http_fetch

### Безопасность JSON
- json_escape_str для mode в http_server.c + ipc.c (3 места)
- json_escape_str для gc->name в ipc.c

### HTTP / WebSocket
- CORS: динамический Origin header (localhost любой порт)
- ws_send_*: убран blocking ws_write_all, async через conn_queue_write/conn_flush
- WebSocket API: HttpConn* вместо fd в сигнатурах

### Сборка / CI
- .github/workflows/build.yml: wolfSSL --enable-all --enable-static-ephemeral
- Makefile.dev: 12 test-таргетов в .PHONY, help 37 суитов, $(error) вместо exit 1

### Документация
- CONSTRAINTS.md: Reality per-connection RAM ~33KB + http_server BSS ~440KB
- docs/WS_ARCHITECTURE.md + docs/DASHBOARD_PLAN.md Phase 2 актуализированы
- README.md badge: < 2 МБ → < 3 МБ (реальный 2.7MB mipsel stripped)
- net_utils.c: htons(53) → DNS_PORT, добавлены DNS_PORT/DNSMASQ_PORT в constants.h
- dashboard.html: 192.168.2.1 hardcode → location.hostname

## [1.5.5] — 2026-04-27

### MIPS / стек

- 11 больших буферов переведены в BSS (`static`): `reality_conn`, `tls13_hs`, `dns_server`, `dns_upstream_doq`, `http_server`, `dpi_payload`, `shadowtls` — устранение потенциального stack overflow на MIPS (лимит 8 KB).

### Reality TLS

- Cipher whitelist сужен до `0x1301 / 0x1302 / 0x1303` (TLS 1.3 only) — сервер не получает TLS 1.2 ciphers в ClientHello.
- `eph_priv` инициализируется нулями сразу при объявлении (early zero).
- Vision `#if CONFIG_EBURNET_VLESS` guard — Vision-код не компилируется при отключённом VLESS.

### HTTP / WebSocket

- `http_send` async EPOLLOUT: убран блокирующий `fcntl`, добавлены `conn_queue_write` / `conn_flush` / `conn_feed_file` для неблокирующей отправки.
- `ws_frame`: UTF-8 DFA валидация RFC 6455 §8.1, Close frame 1007 при невалидном тексте.

### Rate limit

- Per-IP hash table (64 слота, FNV-1a, LRU eviction) — защита от DoS на HTTP/WS интерфейс.

### IPC / Статус

- `group_test` — async fork вместо синхронного блокирующего вызова.
- Status JSON: поля `ech_connections` и `last_ech_type`.

### DNS

- SOA record в NXDOMAIN ответах (AA flag, RFC 2308).
- `dns_cookie_verify`: BADCOOKIE / SLIP обработка по RFC 7873 §5.2.3.
- Cookie secret persistence: secret сохраняется в `/tmp/4eburnet_cookie.secret` при перезапуске.

### Clash API (совместимость с Mihomo)

- `/proxies`: runtime-выбранный сервер через `proxy_group_get_current()` вместо `servers[0]`.
- `/rules`: реальные данные из `s_cfg->traffic_rules[]` (формат Clash).
- `/providers/proxies` + `/providers/rules`: реальные данные провайдеров.
- `system()` → `run_initd()` (fork+execv, без shell) в 4 точках.

### /api/control — новые actions

- `cdn_update` — асинхронное обновление CDN IP списков.
- `server_add`, `server_delete` — добавление/удаление серверов через UCI.
- `provider_add`, `provider_delete`, `provider_update` — управление провайдерами.
- `rule_add`, `rule_delete`, `rule_reorder` — управление traffic rules.

### config.c — валидация

- AWG: `awg_private_key` и `awg_public_key` — проверка base64 длины 44 символа.
- AWG: `awg_i[]` и `awg_j1` — `strndup` с `AWG_BLOB_MAX 8192` вместо unbounded `strdup`.
- Proxy groups: лимит `MAX_GROUP_SERVERS 256` перед realloc (оба пути парсинга UCI).

### Инфраструктура

- `deploy.sh`: `check_memory()` — проверка RAM перед scp/opkg (`<5 MB` → exit 2, `<15 MB` → exit 1).
- `tools/sub_convert.py` → `luci-app-4eburnet/files/usr/share/4eburnet/sub_convert.py` синхронизирован.
- `Makefile`: target `install-tools` для ручной синхронизации sub_convert.py.
- `BUILD.md`: пошаговая инструкция сборки и деплоя (требования, x86_64 dev, кросс-сборка, тесты, деплой, known limitations).
- `docs/CONSTRAINTS.md`: обновлён раздел Reality TLS crypto + добавлен раздел Static buffers (BSS).
- `test_tls13_wire.c` (60 PASS) + `test_reality_pbk_decode.c` (12 PASS).

## [1.5.4] — 2026-04-26

### Исправление VLESS+Reality: fake-IP → VLESS_ADDR_DOMAIN

**Корневая причина**: VLESS request header кодировал адрес назначения как
`VLESS_ADDR_IPV4 + 198.51.100.x` (fake-IP из пула DNS-intercept). xray-core
получал запрос на подключение к RFC 5737 TEST-NET-2 адресу, который
недоступен, и закрывал соединение тремя padding records + close_notify
без VLESS response.

- `dispatcher.c`: поднял `relay_domain` в область видимости функции;
  сохраняет домен из fake-ip reverse lookup (или SNI sniffer) в `r->domain`.
- `dispatcher.h`: добавлено поле `char domain[256]` в `relay_conn_t`.
- `vless.c`: `vless_build_request` принимает опциональный `const char *domain`;
  при `domain != NULL` кодирует `VLESS_ADDR_DOMAIN` + 1-byte len + домен
  вместо IP-адреса. Порт берётся из `dst` (fake-IP порт корректен).
- `vless.h`: `VLESS_HEADER_MAX` увеличен 96 → 300 (поддержка 255-char domain).
- Все вызывающие стороны обновлены (`vless_xhttp.c`, тесты).

### Исправление errno clobber в VLESS+Reality ответе (MIPS)

**Корневая причина**: `log_msg()` на MIPS musl вызывает `localtime()`/
`clock_gettime()`, которые затирают `errno=EAGAIN(11)` значением `131`
(ENOTRECOVERABLE) до проверки условия. EAGAIN трактовался как ошибка →
relay закрывался сразу вместо ожидания следующего EPOLLIN.

- `vless.c` `vless_read_response_step_reality`: сохраняем `errno` в
  `saved_errno` перед `log_msg`, проверяем `saved_errno` вместо `errno`.

### Исправление busy-wait freeze в reality_send (КРИТИЧНО)

**Корневая причина**: `reality_send` при EAGAIN mid-record (частично отправленный
TLS record) уходил в `continue` — бесконечный busy-wait. Single-threaded epoll
демон полностью замораживался: DNS переставал отвечать (182 KB в UDP буфере),
новые соединения не обрабатывались, CPU 20-23%.

- `reality_conn.c` `reality_send`: три исхода вместо `continue`:
  - `sent == 0 && total == 0`: return -1 EAGAIN (ничего не ушло)
  - `sent > 0`: return -1 ECONNRESET (TLS framing нарушен → закрыть соединение)
  - `sent == 0 && total > 0`: return total (граница record → caller решит)

### Исправление дедлока RELAY_REALITY_VLESS (Vision flow)

**Корневая причина**: xray с `xtls-rprx-vision` не отправляет VLESS response
пока не получит inner-TLS данные (ClientHello) от клиента. Relay в состоянии
`RELAY_REALITY_VLESS` слушал только `upstream_fd`, игнорировал client_fd →
дедлок 60 сек → idle таймаут.

- `dispatcher.c`: новая функция `reality_vless_drain_client` — дренирует
  client_fd и пробрасывает данные через Vision+Reality к xray.
  Вызывается при переходе в `RELAY_REALITY_VLESS` (немедленный дренаж,
  EPOLLET-safe) и при последующих client EPOLLIN в этом состоянии.
  `relay_handle_reality` обрабатывает `ep->is_client` в RELAY_REALITY_VLESS
  вместо немедленного return.

- `reality_conn.c`: при получении TLS Alert немедленно возвращаем -1 с
  `ECONNRESET` (логируем level/desc) вместо бесконечного цикла → EAGAIN.

## [1.5.3] — 2026-04-25

### T0-01 Reality pbk decode fix (wolfSSL Base64_Decode bug)

**Корневая причина**: wolfSSL `Base64_Decode` декодировал base64url ключ
`CWYzhoFO6oRp2idZaO48eBk9jIn8nfLS7HpC-ET1cT0` некорректно —
вместо `09663386...` выдавал `41c4b783...`. Следствие: неверный ECDH →
неверный auth_key → AEAD tag mismatch → сервер не верифицировал SessionId
→ всегда возвращал decoy-сертификат.

- `dispatcher.c`: `reality_pbk_decode` переписан с нуля — собственный
  RFC 4648 §5 base64url декодер (`b64url_val` + inline 43-char → 32 bytes).
  wolfSSL `Base64_Decode` и `coding.h` не используются.
- `reality_auth.c`: удалены verbose hex-дампы (eph_pub/srv_pub/shared/
  auth_key/session_plain/sid_ct/sid_tag) из горячего пути — остался
  только краткий `init` лог `server_pub[0:8]` для диагностики.
- Заголовочный комментарий: AES-128-GCM → AES-256-GCM (32-byte key).

### Verified

- Unit test: `reality_pbk_decode("CWYzhoFO6...T0") == 09663386814eea84...` ✓
- Бинарник собран, задеплоен на EC330 (mipsel, 2.6 MB stripped)

## [1.5.2] — 2026-04-25

### T0-01 VLESS Reality params parser fix

- T0-01: VLESS Reality SNI теперь берётся из `servername` поля YAML/UCI
  (`reality_sni`), а не из адреса сервера — устранена причина сброса
  Reality handshake при несовпадении SNI
- T0-01: `client-fingerprint` из YAML/UCI передаётся в wolfSSL динамически
  через `map_fingerprint()` вместо hardcode TLS_FP_CHROME120
- T0-01: `reality-opts.public-key` (base64url) декодируется в 32-байтовый
  ключ x25519 и передаётся в tls_config через `reality_pbk_decode()`
- T0-01: XHTTP ветка — SNI chain `xhttp_host → reality_sni → address`
- config.c: UCI parser принимает ключи `reality_sni`, `reality_flow`,
  `reality_fingerprint`, `reality_pbk` для серверов из основного конфига

### Verified on EC330

- Live test с bg1.xxee.ru: TLS 1.3 Reality handshake успешен,
  relay активен (youtubei.googleapis.com через fake-IP → VLESS Reality)

### audit_v43 fixes

- B64URL_MAX 64 → 63 (off-by-one: strnlen bound = buffer size − NUL slot)
- `_Static_assert` синхронизация B64URL_MAX с `sizeof(ServerConfig.reality_pbk)`
- XHTTP ветка: `reality_pbk` decode → `cfg.reality_key` (Step C.6, симметрия с VLESS)

## [1.5.1] — 2026-04-22

### DNS Client Compatibility Pass

Версия фокусируется на полной совместимости с современными клиентами (iOS 16+, macOS 13+, Android, Windows, IoT) при работе 4eburnetd как основного DNS-сервера на `:53`.

Корневая проблема: iOS скрывал значок WiFi и переключался на LTE при активном 4eburnetd, потому что dnsmasq (переведённый на `:5353`) переставал автоматически прописывать себя в DHCP option 6. Без Domain-Name-Server в DHCP ACK iOS считал сеть «без интернета».

### Added

- **PTR resolver (RFC 1035)** — авторитетный reverse DNS для RFC1918 диапазонов (10/8, 172.16/12, 192.168/16). Хосты читаются из `/tmp/dhcp.leases` и router IPs. Ответы с AA flag, суффикс `.lan`.
- **DNS Cookie (RFC 7873 + RFC 9018 §4.2)** — interoperable server cookie 16 байт (version + reserved + timestamp + HMAC-SHA256-8). Server secret 32 байта, ротация каждые 24ч. Защита от spoofing, предотвращает iOS «DNS non-compliant» detection. `hmac_sha256` вынесен из `#if CONFIG_EBURNET_STLS` как базовый primitive.
- **DHCP option 6 автоматизация** в init script. Функции `configure_dhcp_dns()` и `remove_dhcp_dns()` автоматически прописывают `dhcp.lan.dhcp_option='6,<LAN_IP>'` при старте сервиса (и удаляют при стопе). LAN IP читается динамически через `uci get network.lan.ipaddr`. Idempotent: уважает существующие пользовательские option 6 настройки.
- **AAAA NODATA для DIRECT/BYPASS** — предотвращает IPv6 leak когда прокси работает только через IPv4.

### Fixed

- **AD bit cleanup (RFC 4035 §3.2.3)** — forwarder больше не утверждает DNSSEC валидацию которую не делает. Очистка в 3 точках: `dns_packet.c::dns_build_forward_reply`, `dns_server.c::pending_complete`, `async_doh_dot_cb`.
- **UDP bind на LAN interface IP** через `lan_interface='br-lan'` UCI. Раньше bind на `0.0.0.0:53` мог приводить к source/destination IP mismatch при multi-home конфигурациях. Теперь bind на конкретный LAN IP.

### Changed

- **Объединение в единый пакет**: `4eburnet-core` + `luci-app-4eburnet` объединены в один IPK `4eburnet`. Установка одной командой. `Conflicts: 4eburnet-core luci-app-4eburnet` для чистого upgrade.
- **Поддержка 3 архитектур**: mipsel_24kc (MT7621), aarch64_cortex-a53 (mediatek-filogic), x86_64.
- **Build infrastructure**: `scripts/build.sh` переписан под единый пакет + добавлен target `x86_64`. SDK переключён с `mipsel/` на `mipsel-mt7621/` (соответствует MT7621A на EC330).

### Technical

- 9 UDP DNS callsites покрыты cookie wrapper (`dns_reply_send`)
- 4 TCP DNS callsites покрыты `tcp_client_queue_reply` с getpeername fallback
- 146 unit-тестов PASS (48 sniffer + 43 http_devices + 55 ptr_resolver)
- Бинарник: 1.64–1.77 MB stripped (mipsel/aarch64/x86_64)
- IPK: 1.42–1.55 MB

### Verified on hardware

- **TP-Link EC330** (MT7621A, OpenWrt 24.10): полная runtime верификация, iPhone WiFi значок появляется, DNS Cookie 24 bytes RFC 9018, PTR с AA, DHCP option 6 авто-настройка, dashboard :8080 работает.
- **aarch64 / x86_64**: бинарники собраны, IPK сформированы, ещё не проверены на железе.

---

## [1.0.0] — 2026-04-11

Первый стабильный релиз. 30000+ строк C, 239 тестов, 7 devil audits.

### Протоколы

- VLESS + XTLS-Reality (TCP, Vision flow)
- VLESS + XHTTP транспорт (HTTP chunked + padding)
- Trojan (SHA224 auth, IPv4/IPv6)
- Shadowsocks 2022 (AEAD-2022, HKDF, relay)
- AmneziaWG (WireGuard + obfuscation, kernel-space UDP)
- Hysteria2 (QUIC + Brutal CC + Salamander obfs)
- ShadowTLS v3 (transport wrapper, HMAC SessionID + AppData framing)

### DNS

- Свой DNS сервер на :53 (dnsmasq → :5353 fallback)
- Split DNS: bypass/proxy/block per domain
- DNS over HTTPS (async nonblocking, wolfSSL)
- DNS over TLS (async nonblocking)
- Fake-IP (LRU eviction, /15 CIDR пул, 131K адресов)
- Bogus NXDOMAIN фильтр
- Parallel query + TC-bit TCP retry
- Nameserver-policy routing
- GeoIP + GeoSite (Patricia trie, region categories)

### DPI bypass

- TCP fragment (split at configurable position)
- Fake+TTL (raw socket, TTL-limited fake TLS ClientHello)
- Chrome 120+ fingerprint (15 extensions, 17 cipher suites)
- CDN IP ipset (Cloudflare + Fastly, async fork+pipe update)
- Whitelist + autohosts доменов
- LuCI DPI страница (настройки, CDN обновление, статистика)

### Маршрутизация

- TPROXY + nftables (fw4, verdict maps для 300K+ записей)
- Per-device routing (MAC → политика: proxy/bypass/block)
- Hardware Offload bypass (forward chain)
- Proxy groups (select / url-test / fallback / load-balance)
- Rule providers (URL-подписки правил, async fetch)
- Proxy providers (подписки серверов, Clash YAML + URI)
- Traffic rules (domain, domain_suffix, ip_cidr, geoip, geosite, match)
- Health-check failover (30s интервал)

### Инфраструктура

- C23 + musl static (бинарник ~1.6MB)
- Compile-time Kconfig (12 флагов, 3 профиля: micro/normal/full)
- Async epoll event loop (10ms tick, nonblocking I/O)
- IPC (UNIX socket, chmod 600, SO_PEERCRED root-only)
- NTP Bootstrap (HTTP Date header перед wolfSSL init)
- Hotplug WAN (автоматический перезапуск при смене IP)
- Atomic nftables updates (nft -f)
- posix_spawnp для nft/ip (не shell)

### LuCI (ucode JS)

- Обзор (статус демона, uptime, профиль)
- Серверы (все протоколы + ShadowTLS v3)
- Группы (select/url-test/fallback)
- Правила маршрутизации
- DNS настройки (DoH/DoT/Fake-IP)
- Устройства (MAC → политика)
- DPI Bypass (настройки, CDN IP, статистика)
- Блокировка рекламы (geosite-ads)
- Логи (realtime)
- Настройки + бэкап/восстановление
- Импорт подписок (Clash YAML, URI, base64)

### Совместимость

- EC330 (MIPS MT7621, mipsel_24kc, 128MB RAM)
- Flint 2 (MT6000, aarch64, 512MB RAM)
- x86_64 (QEMU VM, разработка)
- OpenWrt 23.05+ (fw4 / nftables)

### Тесты

- 239 тестов в 9 суитах (ALL PASS)
- 7 devil audits (v17-v23), 0 открытых проблем

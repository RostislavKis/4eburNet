# Changelog

## [1.5.66] — 2026-05-03

### Added

- `dns_cache.h`: `dns_cache_result_t` enum (HIT / MISS / STALE / STALE_REVALIDATING)
- `dns_cache.h`: поля `stale_until` + `revalidating` в `dns_cache_entry_t` (RFC 8767)
- `dns_cache.c`: stale-while-revalidate — при истёкшем TTL отдаём stale с TTL=30, триггерим async refresh
- `dns_cache.c`: `dns_patch_answer_ttl()` — wire-format патч TTL всех answer RR (без heap alloc)
- `dns_resolver.h`: поля `query_key` + `is_leader` + `is_cache_refresh` в `dns_pending_t`
- `dns_resolver.c`: `dns_pending_add_follower()` — follower ожидает ответа leader без upstream запроса
- `dns_server.c`: singleflight dedup — одна upstream query на N одинаковых запросов (leader/follower)
- `dns_server.c`: форс-дрейн `handle_udp_query(ds)` сразу после `epoll_ctl ADD udp_fd` (ФИКС 2)
- `dns_server.c`: rate table linear probing `RATE_PROBE_LIMIT=4` вместо collision miss
- `hc_vless.c`: `child_do_hc_vless_xhttp` — полный TLS(ALPN=h2)+HTTP/2 HC для VLESS/XHTTP
- `proxy_group.h`: `PROXY_GROUP_GLOBAL_HC_LIMIT=16` (было 8)
- `proxy_group.c`: `transport_is_implemented("xhttp")` → true (T0-05 разблокирован в url-test)

### Fixed

- `dns_server.c`: удалён мёртвый `tcp_buf` (объявление + free)
- `dns_server.c`: исправлен ложный комментарий EPOLLET в `accept_tcp_client` (режим LT, не ET)
- `dns_server.c`: убран const-cast в `dns_server_is_pending_fd`
- XHTTP серверы: `latency_ms=UINT32_MAX` → реальный TLS+H2 HC 843–1259ms (bg1/ca1/ch1/de2 ✅)
- `proxy_group.c`: стале комментарий `transport_is_implemented` обновлён

## [1.5.65] — 2026-05-03

### Added

- hysteria2.c: `hysteria2_connect_step` — неблокирующий шаг QUIC handshake
- hysteria2.c: `hysteria2_wait_response_step` — неблокирующий шаг TCPResponse
- dispatcher: `RELAY_HY2_CONNECT` — полноценный async state (2 фазы: QUIC HS + TCP stream)
- dispatcher: `hysteria2_protocol_start` — инициализация без блокировки event loop
- dispatcher: регистрация UDP fd в epoll для `RELAY_HY2_CONNECT`

### Changed

- Hysteria2 интеграция переработана: синхронный connect заменён на async state machine
  (аналог `RELAY_GRPC_HS` / `RELAY_REALITY_HS`)

## [1.5.64] — 2026-05-03

### Added

- `http_upgrade.h` + `http_upgrade.c`: HTTPUpgrade transport T0-06 (~110 LoC)
  - HTTP GET без `Sec-WebSocket-Key` (IsV2rayHttpUpdate по xray-core/mihomo)
  - После 101 Switching Protocols: raw TCP (нет WS frame framing, нет маскировки)
  - `hc_vless.c`: `child_do_hc_http_upgrade` — полный TLS+HTTP Upgrade HC
- `dispatcher.c`: `RELAY_HTTP_UG_HS=20`, после 101 → `RELAY_VLESS_SHAKE` (raw TCP path)
- `proxy_group.c`: `transport_is_implemented("httpupgrade")` → true

### Fixed

- `proxy_provider.c`: `httpupgrade` транспорт больше не маппится в `xhttp` (2 места: URI parser + YAML network field). HTTPUpgrade и XHTTP — разные протоколы.

### Notes

- E2E верификация требует сервера с `network: httpupgrade` в конфиге провайдера

## [1.5.63] — 2026-05-03

### Added

- `vless_xhttp.c`: полная переработка XHTTP transport (T0-05)
  - HTTP/2 (ALPN=h2) вместо HTTP/1.1+chunked
  - Content-Type: application/grpc (как xray-core)
  - Session ID в URL path (/path/{sessionID}/) вместо заголовка
  - stream-one режим: один H2 bidirectional stream (для Reality)
  - stream-up режим: GET(download) + POST(upload) на двух соединениях
  - switch/case recv state machine без goto (XHTTP_RECV_H2_HDR/CTRL/DATA)
  - WINDOW_UPDATE, PING ACK, SETTINGS ACK
- `dispatcher.c`: stream-one интеграция (dl_fd=-1 при Reality)

### Changed

- `vless_xhttp.h`: новый API совместимый с dispatcher, xhttp_state_t переработан

### Notes

- Верификация end-to-end требует XHTTP сервера в конфиге провайдера

## [1.5.62] — 2026-05-03

### Added

- `ws_client.h` + `ws_client.c`: WebSocket client transport T0-04 (HTTP Upgrade, MASK=1, switch/case recv)
- `hc_vless.c`: `child_do_hc_vless_ws` — полный TLS+HTTP Upgrade HC для VLESS/WS
- `proxy_provider.c`: парсинг `ws-opts.path` и `ws-opts.headers.Host` из Clash YAML
- `config.h`: поля `ws_path[256]`, `ws_host[256]` в `ServerConfig`
- `transport_is_implemented`: `"ws"` → разблокированы ~20 Vless/ws серверов в url-test

### Fixed

- WS url-test latency: TCP-only RTT 2ms → реальный TLS+HTTP Upgrade 170ms
- `hc_vless_ws`: устранено 17-минутное зависание (blocking socket + SO_RCVTIMEO)

## [1.5.61] — 2026-05-03

### Changed

- `grpc.c`: `grpc_recv` переписан как явный switch/case state machine
  (5 состояний: `FRAME_HDR`/`CTRL_DATA`/`LPM_HDR`/`PB_HDR`/`DATA`) без единого goto.
- `grpc.h`: `grpc_recv_state_t` enum + поля `ctrl_buf[8]`, `lpm_hdr[5]`,
  `pb_varint_done`, `data_rem`, `recv_state` в `grpc_conn_t`.
  Убраны `msg_hdr`, `msg_hdr_len`, `msg_content_rem`, `pb_done` (флаг-хак `0xFF`).

### Fixed

- `proxy_group`: `PROXY_GROUP_GLOBAL_HC_LIMIT=8` — глобальный лимит HC child
  процессов по всем группам одновременно (счётчик `hc_total_active` в
  `proxy_group_manager_t`).
- OOM на EC330 (116MB) при старте: GEMINI+MAIN-PROXY×8 слотов = 32 fork
  одновременно → watchdog reboot. После фикса: uptime 8+ минут, url-test
  результаты стабильно появляются.
- `grpc_recv` re-entry при EAGAIN: детерминированный по state (не goto).

## [1.5.60] — 2026-05-03

### Added

- `proxy_group`: параллельный HC (`hc_slot_t × 8`, spawn_time expiry 25с).
- `proxy_group`: `PROXY_GROUP_HC_SLOTS=8`, глобальный cursor.
- `hc_vless.c`: полный TLS+gRPC HC для Trojan/gRPC (вместо TCP-only RTT=1ms).
  Измеряет TCP+TLS(ALPN=h2)+HTTP/2 handshake+Trojan header — как mihomo url-test.
- `proxy_group_init`: `next_check=now` — немедленный HC при старте
  (вместо `time(NULL) + 3s`, иначе 60-120с трафик шёл через `selected_idx=0` вслепую).
- `proxy_group`: tolerance=150ms при выборе `best_i` (гистерезис как в mihomo).

### Fixed

- `return→continue` баг (proxy_group.c строка 465): группы `1..N` не обслуживались
  при active HC в группе 0.
- Bulgaria Trojan gRPC `latency_ms=1ms` → честные 182-432ms после полного TLS HC.

### Changed

- UCI: GEMINI и MAIN-PROXY → `url_test`, PROXY группа удалена.
- TELEGRAM/DISCORD/AWG Group → только AWG серверы.

## [1.5.59] — 2026-05-02

### Fixed
- `grpc_recv`: удалён `LOG_INFO` из hot path — `log_msg→localtime()` на MIPS затирал
  `errno` после `recv_fn()` на каждый H2 frame → ложный ECONNRESET/EAGAIN → relay
  закрывался с lifetime 1-2s. После фикса Trojan/gRPC lifetimes 18-79s, out до 334KB.
- `grpc_recv`: cross-frame gRPC message boundary — `msg_content_rem` ограничен
  остатком текущего DATA frame; при его исчерпании переход к следующему frame header.
- `grpc_drain`: передаётся по указателю `uint32_t *n` для корректного resume
  при EAGAIN — остаток сохраняется в `g->drain_rem` без overdrain в следующий фрейм.

## [1.5.58] — 2026-05-02

### Added
- `grpc_conn_t`: `recv_consumed_conn` / `recv_consumed_stream` — счётчики потреблённых
  байт для периодической отправки WINDOW_UPDATE серверу каждые 32KB.
- gRPC transport: `grpc_send_initial_window` — расширение recv window до 1MB при
  первом 200 OK; `GRPC_INITIAL_WINDOW_EXPAND=983040` (1MB − 65535 начального окна).

### Fixed
- Trojan/gRPC дедлок: `grpc_handle_hs_frame` возвращает `2` после отправки HEADERS;
  dispatcher для Trojan немедленно шлёт proto header — xray присылает 200 OK только
  после получения первого DATA frame, ожидать 200 OK до отправки = взаимный deadlock.
- `grpc_handle_hs_frame` WINDOW_UPDATE/PING: `while`-цикл вместо одиночного `recv_fn`
  (wolfSSL может вернуть < 4/8 байт без EAGAIN — частичное чтение из TLS record).

## [1.5.35..1.5.57] — 2026-05-02

### Added/Fixed
- gRPC transport полная реализация (~780 LoC): H2 connection preface, SETTINGS ACK,
  HPACK minimal encoder, HEADERS frame (POST /{svc}/Tun), DATA frame с LPM+protobuf,
  PING PONG, WINDOW_UPDATE flow control, GOAWAY/RST_STREAM handling, drain resume.
- `grpc_recv` for(;;) loop: обработка wolfSSL pre-fetched TLS records без повторного
  EPOLLIN — WINDOW_UPDATE / PING / SETTINGS обрабатываются inline, не прерывая recv.
- `grpc-service-name` парсинг из YAML proxy-provider; URL-escape service name
  для xray-core compat (path `/56169%2FjYYkwHZR/Tun`).
- ALPN `h2` для TLS при gRPC транспорте (wolfSSL `SSL_CTX_set_alpn_protos`).
- `grpc_path_escape`: URL-encode service name по RFC 3986 pchar rules.
- `grpc_conn_init` / `grpc_conn_t` полная структура состояния с MIPS stack-safe
  буферами (локальные ≤512 байт).
- `transport_is_implemented()`: grpc добавлен в список реализованных транспортов.
- `proxy_group` MAIN-PROXY/GEMINI: начальный выбор реализованных транспортов при
  старте (пропуск ws/xhttp/httpupgrade).

## [1.5.49] — 2026-05-02

### fix: gRPC Trojan — откат path-fix + forced drain + GOAWAY диагностика

- `grpc.c` `grpc_build_hpack`: **откат v1.5.48 path-fix** — оказалась регрессией.
  С путём `"/56169/jYYkwHZR"` (без `/Tun`) xray не отвечал вообще (lifetime=61s).
  Сервер xray ожидает `"/56169/jYYkwHZR/Tun"` — subscr. хранит имя с ведущим `/`
  для совместимости с mihomo, который его стрипает перед добавлением `/Tun`.
  Восстановлено: `strip('/')` + `/{name}/Tun` для всех service-name.
- `dispatcher.c` RELAY_GRPC_HS Trojan branch: добавлен forced drain после
  `RELAY_ACTIVE` перехода (upstream + client side), как у VLESS+Reality.
  Причина: с `EPOLLET` кадры (`WINDOW_UPDATE`, `SETTINGS`) из HS-burst остаются
  в wolfSSL buffer — `EPOLLIN` не придёт до новых TCP байт → flow control окна
  не обновляются, iPhone ClientHello не доходит до xray.
- `grpc.c` `grpc_recv`: `GOAWAY`/`RST_STREAM` log поднят с `LOG_DEBUG` → `LOG_INFO`
  для диагностики `out=0` кейса.

## [1.5.48] — 2026-05-02 [ОТКАТ в v1.5.49]

### fix: gRPC — неверный HTTP/2 path для кастомных service-name (оказалась регрессией)

- `grpc.c` `grpc_build_hpack`: реализована логика mihomo `ServiceNameToPath`.
  Если `grpc-service-name` начинается с `/` — путь используется как есть, без `/Tun`.
  Оказалось: сервер xray зарегистрирован на `/{name}/Tun`, leading `/` в подписке
  только для совместимости → v1.5.49 откатил.

## [1.5.46] — 2026-05-02

### fix: gRPC — отсутствовала protobuf Hunk{data=1} обёртка (root cause out=0)

- `grpc.c`: `grpc_send` теперь оборачивает payload в protobuf `Hunk{bytes data=1}`:
  LPM message = `\x0a` + `varint(len)` + `data`. xray-core GunService.Tun ожидает
  именно protobuf stream<Hunk>. Без обёртки `proto.Unmarshal` возвращал пустой
  Hunk.Data → xray форвардил nil → keepalive timeout 15s → GOAWAY → `out=0`.
- `grpc.c`: `grpc_recv` теперь стрипает protobuf prefix перед форвардингом в TLS:
  читает `\x0a` (field tag) + varint (длина данных), затем возвращает только чистые
  байты. Состояние парсера (`pb_hdr_len`, `pb_done`, `pb_data_len`) хранится в
  `grpc_conn_t` — корректно переживает EAGAIN/re-entry.
- `GRPC_SEND_CHUNK` уменьшен с 498 до 495 байт: 3 байта protobuf prefix вписываются
  в стековый лимит 512 байт (`GRPC_PB_HDR_MAX = 3`).
- `grpc.h`: добавлены поля `pb_hdr_len`, `pb_done`, `pb_data_len` в `grpc_conn_t`.

## [1.5.45] — 2026-05-02

### fix: gRPC content-type application/grpc+proto → application/grpc

- `grpc.c`: заголовок `content-type` изменён с `application/grpc+proto` на
  `application/grpc`. Ряд серверных реализаций grpc-go (включая xray-core) используют
  `strings.HasPrefix(ct, "application/grpc")` для проверки типа, однако
  `mime.ParseMediaType("application/grpc+proto").type != "application/grpc"` в
  некоторых версиях приводит к `415 Unsupported Media Type` → `out=0`.
  Mihomo, sing-box и официальный grpc-go клиент используют `application/grpc` без суффикса.

## [1.5.44] — 2026-05-02

### fix: gRPC out=0 — два корневых дефекта устранены

**Дефект 1 — обрезка данных в grpc_send (relay_transfer):**
- `dispatcher.c`: `relay_transfer` читала `n` байт из `client_fd`, но `grpc_send`
  отправляла только первые 498 байт (`GRPC_SEND_CHUNK`), остаток терялся при
  следующем `read()`. TLS ClientHello iPhone обычно 500-600 байт → сервер получал
  обрезанный ClientHello → не мог распарсить TLS record → `out=0`.
- Исправлено: вызов `grpc_send` заменён на цикл до отправки всех `n` байт.

**Дефект 2 — отсутствие SETTINGS ACK в active фазе (grpc_recv):**
- `grpc.c`: в `grpc_recv` все не-DATA фреймы дрейнились без обработки; при
  получении `H2_SETTINGS` от сервера в active фазе (после handshake) ACK не
  отправлялся. По RFC 7540 §6.5 сервер (xray/v2ray) ждёт ACK, при timeout (~15s)
  шлёт GOAWAY → relay закрывается с `out=0 lifetime=15s`.
- Исправлено: `H2_SETTINGS` в `grpc_recv` явно обрабатывается: drain payload +
  отправить `SETTINGS_ACK` если флаг ACK не выставлен.

*Оба дефекта одновременно объясняли картину `in=498 out=0 lifetime=15s`.*

## [1.5.43] — 2026-05-02

### fix: gRPC Trojan client_sent_first + cascade failover reduction

- `dispatcher.c`: при переходе `GRPC_HS→ACTIVE` для Trojan устанавливается
  `r->client_sent_first = true`, чтобы upstream→client forwarding не блокировался
  guard'ом при первом EPOLLIN от сервера
- `proxy_group.c`: `PROXY_GROUP_FAIL_THRESHOLD` поднят с 3 до 6 — burst из 5
  EPOLLRDHUP при старте не вызывает мгновенный failover
- `proxy_group.c`: добавлен `proxy_group_mark_server_ok` — сбрасывает `fail_count`
  при успешном Reality/VLESS HS, предотвращая накопление счётчика от смешанных
  burst
- `dispatcher.c`: убраны два debug лога в gRPC upstream path

## [1.5.32] — 2026-05-02

### fix: начальный выбор SELECT-группы + url-test failover + убраны диагностические логи

- `proxy_group.c`: начальный выбор SELECT-группы при старте теперь корректно
  вызывается для каждой группы; ранее блок `selected_idx = 0` пропускал итерацию
  по серверам из-за отсутствующего `i++` или неверного условия — GEMINI выбирал
  `[1] VLESS Reality` вместо `[0] Trojan gRPC`, потому что transport_is_implemented
  для "grpc" вернул false (до v1.5.31 grpc отсутствовал в списке реализованных)
- `proxy_group.c`: добавлен url-test failover в `proxy_group_mark_server_fail`:
  при 3+ ошибках HS сервер выставляется `available=false` в URL_TEST группах
- `proxy_group.c`: убраны временные диагностические WARN логи `SELECT_INIT`,
  `начальный_проверка`, `начальный_транспорт`, `mark_fail`
- `dispatcher.c`: упрощён лог EPOLLRDHUP в Reality HS (убраны `srv=%d pgm=%p`)

## [1.5.31] — 2026-05-01

### failover Selector при EPOLLRDHUP + transport_is_implemented

- `proxy_group.c`: добавлен `proxy_group_mark_server_fail` — при EPOLLRDHUP во время
  Reality HS dispatcher уведомляет proxy_group о сбое сервера; после 3 сбоев подряд
  SELECT-группа автоматически переключает `selected_idx` на следующий рабочий сервер
- `proxy_group.c`: добавлен `pg_select_rotate` — выбирает сервер с наименьшим
  `fail_count` среди реализованных транспортов; пропускает grpc/ws/xhttp/udp
- `proxy_group.c`: добавлен `transport_is_implemented` — централизованный helper;
  используется в трёх местах: начальный выбор при старте, `pg_select_rotate`,
  url-test HC пропуск; заменил разрозненные inline сравнения transport полей
- `proxy_group.c`: SELECT-группы теперь участвуют в `proxy_group_tick`;
  через 120 секунд тишины fail_count сбрасывается, сервер восстанавливается
- `dispatcher.c`, `dispatcher.h`, `proxy_group.h`, `main.c`: добавлен
  `dispatcher_set_pgm` — связывает dispatcher и proxy_group_manager для failover;
  вызов добавлен в init-путь и reload-путь main.c
- `dispatcher.c`: убраны debug логи `relay→client: n=...` и `vless_connect: domain=...`

## [1.5.30] — 2026-05-01

### fix: MIPS errno clobber в drain:D + убраны debug логи

- `dispatcher.c`: фикс errno clobber на MIPS в петле upstream→client drain;
  `log_msg` вызывает `localtime()` внутри, что затирает errno через glibc TZ lookup;
  добавлен `saved_errno_d = errno` до вызова `log_msg` — без этого `errno != EAGAIN`
  срабатывал ложно → `RELAY_CLOSING` → `relay_free` после первого же drain EAGAIN;
  симптом: YouTube открывал соединение, доставлял TLS ServerHello (out≈4600 байт),
  затем relay умирал не дождавшись ClientHello → сессия обрывалась
- `dispatcher.c`: убраны временные диагностические логи сессии отладки:
  `drain:A/B/C/D/E/F`, `vdc:`, `relay closed: in=...`, `relay half-close: ...`
- `vision.c`: убран диагностический лог `unpad: in=... out=... cmd=...`
- `vision.c`: `vision_unpad: invalid cmd=...` и `TLS passthrough detected`
  переведены с `LOG_INFO` на `LOG_WARN`

## [1.5.26] — 2026-04-30

### gRPC penalty UINT32_MAX + PUT /proxies/{group} + Trojan transport fix

- `proxy_group.c`: gRPC/WS penalty 60000→`UINT32_MAX`, `return`→`continue`
  (применять penalty без прерывания tick-цикла по другим группам)
- `http_server.c`: `PUT /proxies/{group}` — стандартный Clash API endpoint;
  тело `{"name":"server-name"}`, ответ 204; доступен с любого IP (нет localhost restriction)
- `sub_convert.py`: Trojan YAML parser теперь ставит `transport: proxy.get('network','raw')`;
  после re-import UCI Trojan gRPC серверы получат transport=grpc → penalty сработает
- `main.c`: reload path — добавлены `http_server_set_config(cfg_ptr)` и
  `http_server_set_pgm(&pgm_state)` после перестройки конфига;
  без этого `s_cfg` в http_server указывал на освобождённую память после WAN-reload

## [1.5.25] — 2026-04-30

### debug: relay connect IP logging

- `dispatcher.c`: добавлен `LOG_INFO` лог перед `connect()` в `upstream_connect()`;
  формат: `relay connect: <name> → <addr>:<port> (resolved: <ip>)`
  позволяет определить реальный IP соединения (fake-IP петля vs реальный)

## [1.5.24] — 2026-04-30

### dispatcher_resolve LOG_DEBUG→LOG_INFO + dashboard CSS fix

- `dispatcher.c`: `dispatcher_resolve_server` success лог переведён с `LOG_DEBUG` на
  `LOG_INFO` — теперь видим в `logread` и WS /logs при реальном relay трафике;
  формат: `dispatcher_resolve: bg1.xxee.ru -> <IP> (via 192.168.1.1, cached=yes/no)`
- Dashboard: задеплоен `index-BfjAd6uo.css` (был пропущен при деплое v1.5.23);
  теперь index.html ссылается на корректные хэши JS+CSS

## [1.5.23] — 2026-04-30

### log ring 500, /zashboard-settings.json, /group/delay, network field

- `http_server.c`: `LOG_RING_SIZE` 100→500 (BSS 25KB→128KB); WS /logs хранит больше
  истории при подключении нового клиента
- `http_server.c`: `GET /zashboard-settings.json` → `{}` (ранее 404 в консоли браузера)
- `http_server.c`: `GET /group/{name}/delay?url=...&timeout=...` — zashboard compat;
  берёт текущий выбранный сервер группы через `proxy_group_get_current`, делегирует
  в `route_clash_proxy_delay`; возвращает 404 если группа не найдена или пуста
- `http_server.c`: `transport_to_clash_network()` — преобразует внутренний transport
  (raw/reality→tcp, grpc, ws, xhttp) в Clash `"network"` поле; добавлено в
  `/proxies` JSON для каждого сервера рядом с `"type"`
- `dashboard-src/types/index.d.ts`: добавлено поле `network?: string` в тип `Proxy`
- `dashboard-src/ProxyNodeCard.vue`: `typeDescription` показывает реальный транспорт
  из `network` поля вместо статического "udp": "trojan/grpc" вместо "trojan/udp"

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

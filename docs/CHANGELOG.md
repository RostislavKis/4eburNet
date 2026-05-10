# Changelog

## [1.5.155] — 2026-05-10

### Fixed

- **[BUG/hysteria2.c]** `hysteria2_connect_step` фаза CONNECTING: `errno = EAGAIN`
  перезаписывал реальную ошибку из `recv()` (ECONNREFUSED, ENETUNREACH и т.п.).
  Реле навсегда застревало в `RELAY_HY2_CONNECT` до idle timeout. Фикс: проверка
  `errno == EAGAIN || EWOULDBLOCK` перед возвратом 0; иначе `set_error` + return -1. (T0-07/A)
- **[BUG/hysteria2.c]** `hysteria2_connect_step` фаза AUTH: то же самое — маскировка
  UDP recv-ошибок под EAGAIN. Фикс аналогичный. (T0-07/B)
- **[BUG/hysteria2.c]** `hysteria2_wait_response_step`: то же самое — при ошибке
  recv() relay получал EAGAIN вместо -1, ждал бесконечно. Фикс: `stream->state = ERROR`,
  `strerror(errno)` в `stream->error_msg`, return -1. (T0-07/C)
- **[BUG/dispatcher.c]** `RELAY_HY2_CONNECT`: не обрабатывался `EPOLLERR` без `EPOLLIN`.
  ICMP unreachable на UDP вызывал `EPOLLERR` без `EPOLLIN` → `!(ev & EPOLLIN) break`
  → relay висел до idle timeout. Фикс: `if (ev & EPOLLERR) && !(ev & EPOLLIN)` →
  log + `dispatcher_server_result(false)` + `relay_free`. (T0-07/D)

## [1.5.154] — 2026-05-10

### Fixed

- **[PERF/http_upgrade.c]** `http_upgrade_step`: заменено побайтовое чтение HTTP response
  на порционное (до 256 байт за вызов recv_fn). Было 100-150 TLS read syscalls на
  короткий заголовок, стало 1-2. Поиск конца заголовков через `memmem(..., "\r\n\r\n", 4)`
  по накопленному буферу. (v1.5.154)
- **[MINOR/http_upgrade.c]** Добавлена проверка `Connection: upgrade` в ответе сервера
  (mihomo ref: `response.Header.Get("Connection")`). Проверка ограничена одной строкой
  заголовка через `strpbrk(c+11, "\r\n")` — исключает ложное срабатывание на последующих
  заголовках. (v1.5.154)

## [1.5.153] — 2026-05-10

### Fixed

- **[BUG/dispatcher.c]** `RELAY_XHTTP_VLESS_RESP`: после отправки VLESS header демон
  переходил в состояние VLESS_RESP и ждал `EPOLLIN`, который никогда не приходил.
  Причина: сервер мог прислать 2-байтовый VLESS response одновременно с 200 OK —
  EPOLLET уже сработал при 200 OK, новый edge-переход не генерируется.
  Фикс: `goto xhttp_vless_resp_read` сразу после перехода в VLESS_RESP из DN_REQ и
  VLESS_SEND — немедленный `xhttp_recv_chunk` до EAGAIN без ожидания epoll. (v1.5.153)

## [1.5.152] — 2026-05-10

### Fixed

- **[BUG/dispatcher.c]** `RELAY_XHTTP_VLESS_SEND`: после получения 200 OK (EPOLLIN)
  сокет уже writable, но EPOLLET не повторит EPOLLOUT без нового edge-перехода.
  Демон зависал в VLESS_SEND навсегда. Фикс: немедленный `xhttp_send_chunk` в DN_REQ
  handler сразу после `prc==0`; EAGAIN → fallback на ожидание EPOLLOUT. (v1.5.152)

## [1.5.150] — 2026-05-10

### Fixed

- **[BUG/ws_client.c]** `ws_client_send`: два вызова `send_fn` (заголовок + payload)
  заменены единым `malloc(hdr_len + len)` буфером → один `wolfSSL_write` = один TLS record.
  Исключает race при EAGAIN между отправкой заголовка и payload. (v1.5.150)
- **[BUG/ws_client.c]** `WS_RECV_CTRL` CLOSE: `return -1` + `ECONNRESET` заменён на
  `return 0` — нормальное завершение сессии по инициативе сервера. (v1.5.150)
- **[BUG/ws_client.c]** `ws_verify_accept`: `Base64_Encode` добавлял `\n` в конец
  (b64len=29), а `strncmp` сравнивал 28 символов — результат был случаен.
  Добавлен цикл обрезки `\r\n` перед сравнением. (v1.5.150)

## [1.5.148] — 2026-05-10

### Added

- **[h2.c/h2.h]** Автономная библиотека HTTP/2 framing primitives без внешних зависимостей.
  8 функций: `h2_write/read_frame_hdr` (с len guard, return int), `h2_varint_encode/decode`,
  `h2_grpc_lpm_write/parse`, `h2_pb_field1_write/parse`. Добавлен в Makefile.dev.
  Закрывает T0-03 / T2-06 (standalone вместо nghttp2).

### Fixed

- **[BUG/grpc.c]** `grpc_send` (монолит): удалены дублирующие static `h2_write/read_frame_hdr`
  и 13 `#define` (H2_DATA..H2_FLAG_ACK); теперь приходят из h2.h.
  `grpc_send`: ручной PB varint + ручной LPM write заменены на `h2_pb_field1_write` +
  `h2_grpc_lpm_write` + единый `malloc` буфер. (v1.5.145-146)
- **[BUG/grpc.c]** `grpc_stream_send` (multiplex): два `send_fn` вызова (header + payload)
  заменены единым `malloc` буфером → один `wolfSSL_write` = один TLS record. (v1.5.147)
- **[BUG/grpc.c]** `grpc_hs_drain_payload`: добавлен лимит 256 итераций + `errno=EAGAIN`
  при превышении (аналог `grpc_drain`). (v1.5.147)
- **[BUG/grpc.c]** `grpc_connection_recv_dispatch`: PING mid-read desync при EAGAIN.
  `got` (локальная) заменена на `conn->pending_ctrl_got` (cursor в структуре).
  `pending_ctrl_buf[9]=2` выставляется ДО первого `recv_fn` — фиксирует вход в PING ветку
  даже при EAGAIN с 0 прочитанных байт. Добавлен Шаг 2б (resume). (v1.5.148)
- **[BUG/grpc.c]** PING ACK send check: `== 0` (никогда не true) исправлен на `>= 0`. (v1.5.148)

### Changed

- **[grpc.h]** `goaway_last_stream_id` переименован в `pending_stream_id` + WHY-комментарий:
  это cursor прерванного stream frame read, не lastStreamID из GOAWAY. (v1.5.148)

## [1.5.143] — 2026-05-09

### Added

- **[proxy_group]** `proxy_group_state_t.pinned` — флаг ручного выбора через PUT.
  Сохраняет выбор url-test и select групп в `/etc/4eburnet/selected.json` и
  восстанавливает при рестарте. HC-раунды не перезаписывают `selected_idx` пока
  `pinned=true`. При вынужденном failover (сервер недоступен) `pinned` сбрасывается.
  `proxy_group_save_all_selections`: теперь сохраняет pinned url-test наряду с select.
  `pgm_restore_selection`: после восстановления ставит `pinned=true`.
  `proxy_group_init`: вызывает `pgm_restore_selection` и для URL_TEST групп.
  http_server.c PUT `/proxies/{group}`: ставит `g->pinned=true`.

## [1.5.129] — 2026-05-08

### Fixed

- **[BUG/url-test]** `proxy_group.c`: исправлен баг "нулевая latency захватывает
  url-test навсегда". При инициализации сервера `latency_ms` устанавливался в `0`.
  Во всех трёх точках выбора best в url-test (`% server_count == 0` в tick,
  `handle_hc_event`, `_all_unimplemented` path) условие `latency_ms < UINT32_MAX`
  выбирало сервер с `latency_ms = 0` как "лучший" (0 < UINT32_MAX), а в cur_ok
  `latency_ms != UINT32_MAX` давало `cur_ok = true` при `latency_ms = 0` → `cur_lat
  = 0` → `best + tolerance < 0` никогда не выполнялось → сервер с latency=0
  (Bulgaria Sofia · Trojan, gRPC) оставался selected навсегда, Finland 103ms
  игнорировался. Фикс: `latency_ms = UINT32_MAX` при инициализации (строки 290/393)
  и `latency_ms > 0` в поиске best и cur_ok во всех 4 точках (url-test ×3,
  immediate failover).

## [1.5.114] — 2026-05-07

### Fixed

- **[CRIT/OOM]** `http_server.c route_clash_group_delay_batch`: Снижен
  `GROUP_HC_BATCH_MAX` 24 → **8**, `GROUP_HC_DEADLINE_SEC` 30 → 20,
  `GROUP_HC_TIMEOUT_CAP_MS` 3000 → 2000. WHY: 24 параллельных fork в batch HC,
  каждый AWG `child_do_awg_handshake` зависает на UDP `poll()` 3000мс. После
  parent close pipe — child не убивается (poll ждёт UDP socket). 70+ live child
  накапливалось при повторных нажатиях молнии → 116MB EC330 OOM → dropbear/uhttpd
  не форкались, LuCI :80 502, dashboard :8080 unresponsive. 8 fork × 4MB = 32MB
  worst-case, безопасно для EC330.

## [1.5.113] — 2026-05-07

### Changed

- **[FEAT]** `route_clash_group_delay_batch`: BATCH_MAX 16 → 24, deadline 60 → 30,
  per_server formula `client * 2` (было `* 3`), CAP 5000 → 3000.
- **[FEAT]** JSON ответ с fallback на `pgm_server_latency()` для серверов которые
  не успели пройти batch HC за deadline. Возвращает все известные RTT (batch +
  background HC), не только batch results.

## [1.5.112] — 2026-05-07

### Fixed

- **[FIX]** `net_utils.c child_do_awg_handshake`: Удалён `awg_process_incoming()`
  call. Раньше функция возвращала ERR если handshake не валиден (Cloudflare WARP
  отвечает 16-байт error пакетом → не handshake response → ERR). Теперь измеряем
  RTT при первом UDP ответе (`pr > 0`). AWG показывает реальный RTT 206-307мс.
- **[FIX]** `gd_spawn_one` (http_server.c): AWG → `net_spawn_awg_check` (был
  TCP 443 fallback v1.5.111). Реальный AmneziaWG handshake (148 байт + junks/CPS).

## [1.5.111] — 2026-05-07

### Fixed

- **[FIX]** `pgm_server_latency()`: возвращает первое **ненулевое** значение из
  любой группы где встречается `srv_idx`. Раньше первая match (часто 0) скрывала
  реальный RTT записанный другой группой при batch HC.

## [1.5.110] — 2026-05-07

### Changed

- **[FEAT]** `route_clash_group_delay_batch`: BATCH_MAX 4 → 16, deadline 25 → 60.
  body buffer 16K → 64K (для 100+ серверов). per_server = `min(client*3, 5000)`.
- **[FEAT]** AWG fake delay=1 в batch результате → real RTT в v1.5.111+.

## [1.5.109] — 2026-05-07

### Changed

- **[BREAK]** `route_clash_proxy_delay`: Полный rewrite. **Никогда не форкает HC**,
  только cached `pgm_server_latency`. Возвращает `{"delay":N}` 200 OK всегда
  (cached>0 → ms; cached=0 или AWG → 0; never 408). Браузер не таймаутит,
  серверы не пропадают. Удалены `s_ping_active`/`PING_MAX_CONCURRENT`.

## [1.5.108] — 2026-05-07

### Fixed

- **[FIX]** `config.h ServerConfig.name` 64 → **128**. Длинные UTF-8 имена с
  emoji + кириллица (97+ байт) обрезались в середине sequence → `%EF%BF%BD`
  в JSON, strcmp не матчил → 404 для `/proxies/{name}/delay`.
- **[FIX]** `http_server.h HTTP_PATH_MAX` 256 → **1024**. URL `/proxies/<191 enc
  bytes>/delay?timeout=1500` ≈ 280 байт — обрезалось query string или `/delay`
  суффикс терялся → 405 Method Not Allowed.
- **[FEAT]** `route_clash_proxy_delay`: instant cached latency (до v1.5.109).

## [1.5.107] — 2026-05-07

### Added

- **[FEAT]** `cors_origin_hdr`: echo Origin + `Access-Control-Allow-Credentials: true`
  + `Allow-Methods: GET,POST,PUT,PATCH,DELETE,OPTIONS` + `Allow-Headers: Content-Type,
  Authorization` + `Vary: Origin`. Раньше allow только localhost/127.0.0.1.
- **[FEAT]** OPTIONS preflight: 204 No Content + CORS + `Access-Control-Max-Age: 600`.
  Без preflight браузер блокировал PUT/PATCH/DELETE с custom headers.
- **[FIX]** `route_clash_group_delay_batch`: добавлен `finished_real` flag в
  `gd_slot_t`. Серверы прерванные deadline не штрафуются (не fail_count++) —
  нажатие молнии больше не выкидывает серверы из группы после 3-х timeout.

## [1.5.106] — 2026-05-07

### Fixed

- **[CRIT]** `proxy_group.c init`: `available=true` (было `false`) при загрузке
  группы. mihomo-семантика: серверы видимы до первого HC. Раньше при старте
  324 серверов имели `available=false` → 30 минут пустой dashboard пока HC
  ползёт по 8 параллельных слотов × 10 раундов.
- **[FEAT]** `route_clash_group_delay_batch`: новый endpoint, параллельный fork
  HC всех серверов группы (mihomo-compat /group/:name/delay).

## [1.5.105] — 2026-05-07

### Added

- **[FEAT]** Dashboard zashboard **v3.5.1 cdn-fonts** (upstream, идентичный
  Flint2 mihomo). 3 MB, 5 ассетов (index js/css + Noto/Twemoji woff2 + jpg).
- **[FEAT]** Раздача под `/` и `/ui/` (mihomo-compat). 307 redirect `/ui` → `/ui/`.
  `http_send_redirect()` helper. luci-app Makefile installs dashboard в IPK.

## [1.5.103] — 2026-05-07

### Fixed

- **[FIX]** `PROXY_GROUP_MAX_SERVERS` 32 → **256**. Провайдер ~80 серверов
  обрезался до 32 → недоступные группы.
- **[FIX]** `nftables.c`: QUIC UDP 443 drop в исходниках (было временно через
  ручной nft). iPhone YouTube fallback на TCP+TLS вместо серого экрана.
- **[FEAT]** `xudp:true` тег в /proxies JSON для серверов с packet-encoding=xudp.

## [1.5.101] — 2026-05-07

### Fixed

- **[FIX]** `hc_vless.c`: Добавлен `hc_clamp_ms()` — inline helper для безопасного
  приведения `int64_t` latency к `uint32_t`. Применён во всех 7 местах вычисления
  `ms` (Trojan/gRPC, WS, HTTPUpgrade, XHTTP, TCP-tunnel, TCP-RTT fallback, Reality).
  `CLOCK_MONOTONIC` на MIPS с низким разрешением может дать отрицательный diff →
  child писал `"OK -N\n"` → parent делал `(uint32_t)(-N) = 4294967295 = UINT32_MAX`.

- **[FIX]** `net_utils.c`: Аналогичный `if (ms < 1) ms = 0; if (ms > 9999) ms = 9999`
  в `child_do_tcp_ping`, `child_do_udp_ping`, `child_do_awg_handshake`.

- **[FIX]** `proxy_group.c handle_hc_event`: Валидация ms от child-процесса.
  Только `0 < ms <= 9999` меняет `latency_ms` и `available`. `ms == 0 || ms > 9999`
  → `LOG_WARN "невалидная latency"` без изменения `available` (defence-in-depth
  против переполнения в child). Серверы с `delay=UINT32_MAX` больше не получают
  `available=true` и не попадают в displayed list zashboard с аномальным значением.

- **[CLARIFY]** `hc_vless.c child_do_hc_vless`: Добавлен комментарий — `packet_encoding`
  (`xudp`/`packetaddr`) не используется в HC. HC всегда отправляет VLESS CMD=TCP
  независимо от конфига relay. RELAY_MUXCOOL не вызывается из fork() child.

## [1.5.100] — 2026-05-07

### Fixed

- **[FIX]** `dispatcher.c`: TCP relay с `packet-encoding: xudp` ошибочно
  направлялся через Mux.Cool (CMD=Mux). Серверы PrivateVPN (~176 серверов с
  `packet-encoding: xudp`) не поддерживают CMD=Mux → TLS close_notify alert,
  `errno=131` (ECONNRESET). `REALITY_HS→MUXCOOL_HS` срабатывал для всех
  xudp-серверов включая YouTube/youtubei.googleapis.com.
  Фикс: `if (false && server->packet_encoding...)` — полное отключение TCP
  через Mux.Cool. `packet-encoding: xudp` в mihomo = UDP-инкапсуляция только,
  не TCP-мультиплексирование. TCP→Mux.Cool зарезервирован под отдельный
  config-флаг (`mux: true`) в будущем.

## [1.5.99] — 2026-05-07

### Added

- **[FEAT]** Mux.Cool transport-agnostic I/O abstraction. `muxcool_conn_t`
  заменяет `void *tls` (WOLFSSL*) на триаду `transport_ctx / transport_send /
  transport_recv / transport_free`. Статический inline accessor
  `muxcool_conn_set_transport()` в muxcool.h. `MUXCOOL_POOL_CONNS_MAX`: 4 → 8.

- **[FEAT]** `dispatcher.c`: 5 семейств transport callbacks для Mux.Cool:
  `cb_tls_*` (plain WOLFSSL*), `cb_reality_*` (reality_conn_t*),
  `cb_ws_*` + `muxcool_ws_ctx_t{ws, tls}` (WS+TLS composite),
  `cb_xhttp_*` (xhttp_state_t*), `cb_grpc_*` + `muxcool_grpc_ctx_t{stream, ssl}`.
  Forward-декларации перед relay_handle_tls для разрешения forward-reference.

- **[FEAT]** Wiring Mux.Cool на 4 транспорта:
  TLS: `TLS_SHAKE` → `muxcool_conn_set_transport(mc, ssl, cb_tls_*)`, ssl nulled.
  Reality: `REALITY_HS` rc==1 → перехват до Vision/VLESS, `r->reality` передаётся
  во владение muxcool через `cb_reality_*`, free = `reality_conn_free`.
  WS: `WS_HS` ret==1 → создаётся `muxcool_ws_ctx_t`, `r->ws/tls` nulled,
  `cb_ws_*` управляет lifetime. XHTTP: `XHTTP_DN_REQ` prc==0 →
  `mc->tcp_fd = r->xhttp->upload.fd`, `cb_xhttp_*`, `r->xhttp = NULL`.
  gRPC (MULTIPLEX): `GRPC_HS` H2 done → `muxcool_grpc_ctx_t` до
  `grpc_stream_send_proto_header`, ssl pool-owned.

- **[FEAT]** `RELAY_MUXCOOL_HS`: wolfSSL_write/read заменены на
  `mc->transport_send/recv(mc->transport_ctx, ...)`. Guard `conn->tls` →
  `conn->transport_ctx`. RELAY_MUXCOOL_ACTIVE: аналогично.

- **[FEAT]** Epoll watcher dispatch: `mconn->tls` → `mconn->transport_ctx`,
  `muxcool_tls_send_cb/recv_cb` → `mconn->transport_send/recv`.

### Changed

- **[BREAK]** `muxcool.c`: удалены `#include <wolfssl/…>`. `muxcool_conn_destroy`:
  вместо `wolfSSL_free(conn->tls)` — `transport_free(transport_ctx)`.
  `muxcool_pool_tick` keepalive + `muxcool_stream_release` END frame:
  `transport_send` вместо `wolfSSL_write`.

## [1.5.97] — 2026-05-07

### Added

- **[FEAT]** `dispatcher.c` + `grpc.h` + `grpc.c`: persistent gRPC pool watcher.
  `grpc_conn_ep_t` — отдельный epoll-tag для разделяемого `conn->tcp_fd`,
  устанавливается в RELAY_GRPC_HS → ACTIVE через `EPOLL_CTL_MOD`. Снимает
  documented limitation "secondary streams stall after primary relay closed".
  `int ep_type` первое поле `relay_ep_t`/`grpc_conn_ep_t` для полиморфного
  диспатча в epoll loop через `*(int*)data.ptr`. `wake_fd` (eventfd) теперь
  у всех streams включая primary. Watcher cleanup в `grpc_pool_tick` (idle
  conn timeout) + `grpc_pool_free`. Архитектурное улучшение T2-09.

## [1.5.96] — 2026-05-07

### Fixed

- **[FIX]** `noise.c::x25519_shared`: `wc_curve25519_shared_secret_ex`
  возвращал BAD_FUNC_ARG (-173) при импортированных через `import_private_ex`
  ключах — функция требует `curve25519_key.dp` поле, которое import не
  настраивает (только `make_key` настраивает полностью). Замена на
  `wc_curve25519_generic` — прямой scalar mult на raw bytes без struct.

## [1.5.94] — 2026-05-07

### Fixed

- **[FIX]** `noise.c::x25519_generate`: `wc_curve25519_make_key` +
  `export_public` — та же endianness/dp проблема что в `x25519_shared`.
  Замена на `random_bytes` + `clamp_curve25519_key` + `wc_curve25519_make_pub`
  (низкоуровневая scalar mult без struct).

## [1.5.93] — 2026-05-07

### Fixed

- **[FIX]** `noise.c::noise_init`: `wc_curve25519_export_public` после
  `wc_curve25519_import_private` возвращал BAD_FUNC_ARG (-173) — wolfSSL
  5.9.0 не настраивает `pubSet` при импорте только private. AWG handshake
  silently failил на `awg_init` для всех серверов (`alive: false` у всех
  AWG в /proxies). Замена на `wc_curve25519_make_pub(pub, priv)` — прямой
  scalarmult с basepoint без struct/import цикла.

## [1.5.89] — 2026-05-07

### Fixed

- **[CONFIG]** EC330 UCI: удалены 3 мусорных traffic_rule с low-priority
  (priority=5/315/316), которые перебивали легитимные TELEGRAM правила:
  - `IP-CIDR 149.154.160.0/20 → MAIN-PROXY priority=5` (дубликат TELEGRAM
    CIDR с другим target и приоритетом 5 — выигрывал в ASC-sort)
  - `DOMAIN-SUFFIX apple-dns.net → ✈️ TELEGRAM priority=316` (Apple Private
    Relay ошибочно классифицировался как Telegram)
  - `DOMAIN-SUFFIX facetime.apple.com → ✈️ TELEGRAM priority=315`
  Источник правил неясен (не sub_convert.py, который генерирует priority
  с 200 ASC). Возможно ручная UCI-правка или старая версия конвертера.
- **[FEAT]** `dispatcher.c`: новый INFO log `relay route TCP: dst=X domain=D
  rule=TYPE payload='V' group=G idx=I` — диагностика какое правило выбрало
  какую группу. Расширен `rule_match_result_t` диагностическими полями
  `matched_rule_type`/`matched_payload`.

## [1.5.85] — 2026-05-06

### Fixed

- **[FIX]** `dispatcher.c`: `RELAY_GRPC_HS` — добавлен лимит 64 итерации
  в `do {} while (ret == 0)`. При аномальном H2 frame burst (OOM, нестандартный
  сервер) цикл без лимита монополизировал `dispatcher_tick` на 3.94s (наблюдалось
  2026-05-06). При достижении лимита `errno=EAGAIN; break` — остаёмся в
  `RELAY_GRPC_HS`, следующий epoll event продолжит handshake.
- **[FIX]** `grpc.c`: `grpc_drain` — лимит 256 итераций (16KB/tick). При
  `drain_rem > 16KB` возвращаем `-1+EAGAIN` — state machine продолжит со следующего
  epoll события через `g->drain_rem` (сохраняется между вызовами). Предотвращает
  монополизацию при большом GOAWAY payload.
- **[FIX]** `hc_vless.c`: `child_do_hc_vless_ws` — честный туннельный HC.
  После WS 101 отправляем VLESS header (`www.gstatic.com:443`) через
  `ws_client_send`, ждём VLESS response (`ws_client_recv`, ≥2 байта). Серверы
  принимающие WS upgrade но режущие VLESS трафик (fig.xxee.ru — "Connection
  reset by peer") получают HC fail → `fail_count++` × 3 → `available=false` →
  url-test больше не выбирает сломанный сервер.

## [1.5.84] — 2026-05-06

### Fixed

- **[FIX]** `proxy_group.c`: `compute_hc_limit` — лимит `avail/8`, cap 12
  (было `avail/4`, cap 32). Burst mode при первом раунде убран. Предотвращает
  OOM при одновременном запуске HC для всех групп (18 форков наблюдалось).
- **[FIX]** `proxy_group.c`: gradual recovery — `fail_count--` при OK вместо
  `fail_count=0`. Нестабильные серверы не реабилитируются мгновенно.

## [1.5.83] — 2026-05-06

### Fixed

- **[FIX]** `tls13_hs.h`: `rbuf` и `ptbuf` увеличены с 16400 до 32768 байт.
  Certificate chain 25958B вмещается; `record слишком большой` исчез из лога.
  `relay REALITY_VLESS→ACTIVE` появляется стабильно — Reality серверы участвуют в url-test.

## [1.5.82] — 2026-05-06

### Fixed

- **[FIX]** `http_server.c`: PUT `/proxies/{group}` — поиск сервера по имени
  в `g->servers[]` вместо глобального `s_cfg` индекса. Provider-серверы
  теперь находятся корректно.
- **[FIX]** `proxy_group.c`: `proxy_group_select_manual` принимает URL_TEST
  группы (убрана проверка `g->type != PROXY_GROUP_SELECT`).
- **[FIX]** `http_server.c`: `/api/action group_select` — аналогичный фикс
  поиска по `g->servers[]`.

## [1.5.81] — 2026-05-06

### Fixed

- **[FIX]** `http_server.c`: `json_get_str` — поддержка `\uXXXX` surrogate
  pairs (эмодзи флаги страны → UTF-8) и пробелов вокруг `:` в JSON.
  PUT `/proxies/{group}` с именем сервера `🇫🇮 Finland, Helsinki · VLESS, TCP`
  теперь парсируется корректно.


## [1.5.80] — 2026-05-05

### Security

- **[SECURITY/G1]** `http_server.c`: `/ws/*` WebSocket и `GET /api/*`
  защищены api_token когда настроен в UCI. Backward compat: пустой
  api_token = открытый режим (no-auth). Endpoint'ы `/version`, `/proxies`,
  `/rules` и dashboard HTML по-прежнему публичны.

- **[SECURITY/G3]** `reality_auth.c`: `memcmp` → constant-time volatile XOR
  для сравнения HMAC тегов (устранён timing oracle). `tls13_keys.c`:
  `early_secret` и `derived_early` обнуляются через `explicit_bzero`
  сразу после вывода ключей.

- **[SECURITY/G3]** `reality_auth.c`: `auth_key` исключён из
  `LOG_DEBUG` при мисматче HMAC — предотвращает утечку ключа в лог.
  Cipher `0x1302`/`0x1303` принимаются с `LOG_WARN` (не hard reject) —
  совместимость с non-standard TLS 1.3 handshake.

### Fixed

- **[FIX/G2]** `dns_server.c`: `SO_REUSEPORT` на TCP DNS fd —
  устраняет crash loop `bind(TCP :53): Address in use` при перезапуске
  через procd. TTL fake_ip A-ответа: 60s → 10s (mihomo-совместимо).
  `mem_tier_dns_drain_batch()`: DNS drain batch cap через mem_tier
  (LOW=32, MID=128) вместо хардкода.

- **[FIX/G2]** `dns_upstream_async.c`: async DoH/DoT callback добавляет
  DNS Cookie через `dns_reply_send()` — RFC 7873 совместимость для всех
  upstream ответов.

- **[FIX/G4]** `tc_fast.c`: nft mark строка хардкодом `"0x10"` вместо
  `TC_FAST_MARK=0x20`. LAN TC Ingress Fast Path не работал с момента
  введения `TC_FAST_MARK=0x20` в v1.5.x. Исправлено подстановкой
  `snprintf(mark_hex, ...)` из константы.

- **[FIX/G5]** `geo_loader.c`: Bloom фильтр суффиксов использовал
  `bloom_nbits` вместо `suffix_bloom_nbits` (copy-paste баг) — суффиксные
  lookup давали ложные negative. `opencck_updater.c`: `kill(getpid(), SIGHUP)`
  заменён на `g_reload_flag = 1` — устранён crash при CDN обновлении.

- **[FIX/G6]** `http_server.c`: `api_token` читается из `cfg` struct
  (не через `popen("uci get ...")`) — нет subprocess overhead на каждый
  запрос. `ja3_expected` валидирует длину == 32, HTTP 400 при нарушении.
  `http_send_file` отдаёт управление epoll после 8 chunks (32KB) —
  устранён starvation relay loop при больших файлах.

### Tests

- **[TESTS/G7]** 7 новых файлов unit-тестов для Reality TLS crypto:
  `test_reality_auth.c`, `test_reality_aes_seal.c`, `test_reality_ecdh.c`,
  `test_reality_hkdf.c`, `test_reality_hmac.c`, `test_reality_roundtrip.c`,
  `test_tls13_wire.c`. Все PASS на host compile с musl-gcc.

### Build / Docs

- **[BUILD/G8]** `scripts/build.sh`: mipsel SDK путь синхронизирован
  с `Makefile.dev` (`mipsel/sdk-mipsel`), параметризован через `$MIPSEL_SDK`.
- **[DOCS/G8]** `CONSTRAINTS.md`: `reality_conn_t` RAM ~68KB (было ~33KB) —
  детальная таблица полей `hs.rbuf/ptbuf/sbuf + outer rbuf + recv_acc`.
- **[DOCS/G8]** `IPC_SCHEMA.md`: `dpi-get` (cmd 40) и `dpi-set` (cmd 41)
  задокументированы с реальными полями из `ipc.c`.
- **[DOCS/G8]** `dashboard_api_contract.md`: Clash API секция добавлена
  (`/proxies`, `/rules`, `/providers/*`, WS `/logs`/`/traffic`/`/memory`);
  нативный `/api/*` помечен `[Deprecated as of v1.5.x]`.
- **[FIX/G8]** `4eburnet.h:51`: исправлен двойной `/*/* ...` → `/* ...`
  (-Wcomment предупреждение устранено).

### Notes

- **EC330 deploy** 2026-05-05: mipsel 2.8MB stripped, mem_tier=LOW
  (MemAvailable=27MB при старте), 0 nft ошибок, 0 bind(TCP :53) ошибок,
  DNS работает (ya.ru → 77.88.55.242 direct, google.com → fake-IP).

## [1.5.79] — 2026-05-05

### Added

- **[PERF/G15-1]** `crypto/tls.c`: облегчённый WOLFSSL_CTX `s_hc_ctx`
  для health-check fork процессов. Session cache OFF, `WOLFSSL_OP_NO_TICKET`,
  `WOLFSSL_VERIFY_NONE`. WHY: основной кэш CTX держит ~1.5MB session cache
  для долгоживущих relay-соединений, в HC fork процессах между разными
  PID она не разделяется — выделенная память бесполезна. На EC330 (128MB)
  при 6 параллельных HC fork это ~9MB пустой памяти. На 512MB+ устройствах
  поведение идентично. Cold latency точнее (как mihomo url-test без
  фоновой prewarming). API: `tls_hc_ctx_init/free`, `tls_hc_connect`.
  Lazy init guard `tls_hc_connect`: если `s_hc_ctx == NULL` — создаётся
  на лету с LOG_WARN (defensive для тестов; production main.c init
  делает явно).

- **[PERF/G15-2]** `mem_tier.c/.h`: runtime адаптация лимитов по
  `MemAvailable` при старте. Tier'ы: LOW (<64MB), MID (64-256MB),
  HIGH (>256MB). Один бинарник оптимален для EC330 128MB и Flint2 512MB+.
  Используется в:
  - `dispatcher.c`: `g_dispatcher_max_events` (LOW=8, MID=32, HIGH=64) —
    заменяет MIPS-only хардкод 8 на универсальный механизм.
  - `dispatcher.c`: `g_relay_drain_per_call` (LOW=4, MID=16, HIGH=32) —
    заменяет 3 дублирующих `#ifdef __mips__` блока.
  - `dns_server.c`: `dns_cache_size` fallback с 256 → tier-зависимый
    (LOW=512, MID=2048, HIGH=8192).
  - `geo_loader.c`: `MAP_POPULATE` flag для mmap только на HIGH —
    preload page tables, нет page faults при первом lookup.

- **[FEATURE/G15-3]** `dpi/cdn_updater.c`: `cdn_geo_update()` скачивает
  pre-built `.gbin` базы с GitHub Releases (`geo-latest` tag), валидирует
  magic header (`GEO_BIN_MAGIC` + version), atomic rename через tmp,
  отправляет SIGHUP демону для горячей перезагрузки без рестарта.
  6 файлов: geoip-ru, geosite-ru/ads/trackers/threats, opencck-domains.

- **[FEATURE/G15-3]** Корневой `Makefile`: пакет `4eburnet-geo`
  (PKGARCH:=all). `.gbin` — данные, не код, один пакет на mipsel/aarch64/
  x86_64. Обновляется независимо от 4eburnet через cdn_updater или
  переустановку пакета.

- **[FEATURE/G15-3]** `core/Makefile.dev`: target `geo-compile-host` —
  host x86_64 компилятор `geo_compile` для CI/Releases pipeline.
  Роутер никогда не компилирует `.gbin` — только mmap готовых.

### Fixed

- **[FIX/G15-4]** `tools/sub_convert.py`: `nameserver-policy` Clash YAML
  теперь генерирует `config dns_policy` секции
  (pattern, upstream, type, sni) вместо старых `config dns_rule`
  (domain, upstream). Демон
  парсит `SECTION_DNS_RULE` только как (type, pattern) — поле upstream
  игнорировалось, маршрутизация домен→upstream через `dns_rule` НЕ
  работала. Правильная семантика — `SECTION_DNS_POLICY` с поддержкой
  DoH/DoT/UDP. Helper `_classify_dns_upstream` определяет тип по схеме URL:
  `https://...` → type=doh + полный URL + sni из hostname; `tls://`/`dot://`
  → type=dot; иначе → type=udp.

- **[FIX/G15-4]** EC330 UCI миграция: 6 `dns_rule` (старый игнорируемый
  формат, 2 битые `https:` записи от обрезки `_extract_ip`) → 6
  `dns_policy` (правильный). Маршрутизация `+.ru/+.su/+.yandex.ru/+.рф`
  → 1.1.1.1 UDP теперь работает; `+.google.com/+.generativelanguage`
  → DoH `https://dns.google/dns-query`.

- **[FIX/G15-5]** EC330 UCI миграция: 7 `traffic_rule` записей с IPv6
  значениями (4 Telegram `2001:b28:*`, 3 Yandex `2a02:6b8:*`) переключены
  с `type=ip_cidr` на `type=ip_cidr6`. Раньше main.c вызывал
  `nft_dnat_add_cidr4()` для IPv6 CIDR → 8 `nft: Could not resolve hostname`
  ERROR + 4 `DNAT ip_cidr ... ошибка применения правила` WARN при каждом
  старте. После миграции — 0 nft ошибок.

### Notes

- **EC330 deploy** 2026-05-05: mipsel 2.8MB, mem_tier=LOW
  (MemAvailable=37MB при старте), TLS HC CTX готов, 6 dns_policy +
  7 ip_cidr6 в UCI, 0 nft ошибок, DNS работает (ya.ru direct,
  google.com fake-IP).

### Known limitation

- `_extract_ip` обрезает top-level DoH nameserver URL до `'https:'`
  (только для `dns.nameserver`/`dns.fallback`, не для `nameserver-policy`).
  На EC330 не затронуто (`upstream_default='8.8.8.8'` выставлен руками).
  Fix: v1.5.80.

## [1.5.78] — 2026-05-05

### Fixed

- **[FUNCTIONAL/KB-1]** `http_server.c`: `/proxies` JSON теперь содержит
  поле `"alive": true|false` для каждого сервера и группы — стандарт
  Clash API. Источник: runtime `proxy_group_manager_t.groups[].servers[].available`
  (выставляется async health-check). Без `alive` zashboard скрывал
  серверы как "недоступные" даже когда HC отрабатывал успешно.
  Helper `pgm_server_alive()`: до первого HC сервер считается живым
  (mihomo behaviour) — иначе zashboard скрывал бы все серверы при старте.
  Helper `pgm_group_alive()`: группа alive если хотя бы один сервер
  available. DIRECT/REJECT/GLOBAL — `"alive":true` хардкод (Clash convention).
  `now`, `history[0].delay`, runtime `s_pgm->groups[]` уже использовались
  в /proxies handler — дополнения не требовалось.

- **[FEATURE/KB-5]** `tools/sub_convert.py`: rule-providers Clash YAML
  конвертируются в UCI секции `config rule_provider` — name, type
  (http/file), url, path, format (Clash behavior: domain/ipcidr/classical),
  interval, enabled. Раньше игнорировались молча, RULE-SET правила
  указывали на несуществующие провайдеры → cache_load() возвращал NULL,
  matching MISS → весь трафик падал в MATCH catch-all (DIRECT).
  Валидация: type ∉ {http,file} → пропуск с WARNING; type=http без url
  или type=file без path → пропуск; неизвестный behavior → fallback
  classical с WARNING.
- **[FEATURE/KB-5]** `tools/sub_convert.py`: секции `sniffer`, `tun`, `mode`
  больше не игнорируются молча — выводят `[WARNING]` или `[INFO]` на stderr.
  `sniffer.enable=true` → WARNING (4eburnet использует адаптивный DPI
  через UCI `dpi_enabled`, маппинг 1-в-1 невозможен).
  `tun.enable=true` → WARNING (4eburnet использует nftables TPROXY,
  виртуальный TUN не нужен).
  `mode != 'rule'` → WARNING (4eburnet поддерживает только rule-based
  маршрутизацию). Fallback парсер без PyYAML предупреждает если эти
  секции присутствуют, но не парсятся (нужен `pip3 install pyyaml`).

- **[PERF/KB-3]** `proxy_group.c`: HC stagger при первом старте для url-test групп.
  4 url-test группы теперь стартуют HC с offset = `idx * 45 / total` сек
  (4 группы → slots 0/11/22/33 сек) вместо одновременного next_check=now.
  Предотвращает конкуренцию за `PROXY_GROUP_GLOBAL_HC_LIMIT=16`: при
  4 группах × 8 серверов = 32 fork → раньше 16 встают в очередь, первый
  HC цикл удваивался по latency, selected_idx не выставлялся ~120с.
  Сигнатура `proxy_group_init(pgm, cfg, bool first_start)`: `true` при
  старте демона, `false` при SIGHUP reload — на reload stagger не
  применяется (краткосрочная гонка приемлема, зашборду нужны свежие
  данные сразу после reload). Non-url-test группы (Selector / Fallback /
  LoadBalance) всегда `next_check=now` — stagger релевантен только для
  периодических HC. `HC_STAGGER_WINDOW_SEC=45` именованная константа.

### Known gap

- **[KB-6/deferred]** GeoSite `.gbin` файлы на EC330 — отложено до G15
  (HC CTX + dynamic limits + geo IPK). Текущее состояние EC330:
  `/etc/4eburnet/geo/geoip-ru.dat` (22.5MB Xray .dat) присутствует —
  GEOIP правила работают. `geo_compile` бинарник не установлен на
  роутере, прямой http fetch с EC330 заблокирован TPROXY (`uclient-fetch
  → Operation not permitted`). Workflow .lst → .gbin требует host-side
  сборки (Windows/WSL `make geo-compile-mipsel` → scp на роутер) либо
  IPK с pre-built .gbin — оба варианта в G15. До закрытия GEOSITE
  правила (домены ads/trackers) деградированы, GEOIP полностью работает.

### Verified (no-op)

- **[KB-2]** `rules_engine.c`: `RULE_TYPE_RULE_SET` матчинг **уже реализован**
  (строки 397–402): `ruleset_match_domain` (bsearch + suffix fallback)
  и `ruleset_match_ip` (CIDR linear). `cache_load` вызывается в
  `rules_engine_init` для каждого RULE_SET правила. Порядок init в
  `main.c`: `rule_provider_init` → `rule_provider_load_all` →
  `rules_engine_init` — корректен. Отдельных правок не требуется;
  29226 правил активны при наличии cache-файлов в `/etc/4eburnet/rules/`.

## [1.5.77] — 2026-05-05

### Fixed

- **[FEATURE/T0-02]** `vision.c`: Vision (XTLS) FSM — закрыт T0-02.
  `vision_unpad`: при cmd=Direct/End в UUID-prefix record (первый record сервера)
  `read_direct` и `splice_read` не устанавливались. Причина: после обработки
  UUID-заголовка сбрасывалось `read_hdr_len=0`, а record-complete check требовал
  `read_hdr_len==hdr_need(5)` → условие не выполнялось. Фикс: `hdr_need=0`
  после UUID-сброса — `0==0` гарантирует срабатывание transition.
  `test_vision_state`: все 18 тестов PASS, включая `splice_read_on_direct`
  и `no_splice_on_end`. `test_vision_addons`: 5/5 PASS.
- **[DATA_CORRUPTION/P2]** `dispatcher.c`: OOM при partial write в `relay_transfer`
  больше не теряет данные TCP stream — relay закрывается немедленно с LOG_WARN.
  Предотвращает HTTP/2 framing corruption при нехватке памяти. `errno=EAGAIN`
  устанавливается после `relay_free` чтобы call sites не вызывали повторный `relay_free`.
- **[HANG/P2]** `dispatcher.c`: `RELAY_CONNECTING` теперь обрабатывает
  `EPOLLRDHUP` без `EPOLLOUT` — relay закрывается немедленно вместо 60s таймаута.
  Покрывает FIN-only path (SYN-ACK + FIN без RST); EPOLLERR/EPOLLHUP закрыты выше.
- **[FUNCTIONAL/P2]** IPv6 CIDR маршрутизация: `IP-CIDR6` правила из
  Clash-подписок теперь корректно добавляются в `ip6 eburnet_nat6`
  через `nft_dnat_add_cidr6`. Ранее попадали в `ip eburnet_nat` (IPv4)
  → nft ERROR при старте → Telegram/WhatsApp по IPv6 не перехватывались.
  Исправлено в: `sub_convert.py`, `config.c`, `main.c`, `nftables.c`.
- **[DOCS]** `dashboard.html`: tooltip fake-IP пула обновлён
  (убран хардкод `198.51.100.0/24`, заменён на ссылку на UCI `fake_ip_range`).

### Geo Quality (fix-geo-quality — audit_v45)

- **[CRASH/P3]** `geo_loader.c`: overflow-safe умножение при валидации .gbin на
  MIPS 32-bit. `domain_count * sizeof(uint32_t)` теперь проверяется через
  `count > SIZE_MAX / sizeof(T)` ДО умножения — предотвращает wrap → bsearch
  за пределами mmap при повреждённом/вредоносном .gbin файле.
  Добавлен `GEO_ERR_OVERFLOW` (-6) в geo_loader.h.
- **[FUNCTIONAL/P3]** `geo_loader.c`: domain и suffix bloom фильтры используют
  корректные независимые nbits (`suffix_bloom_nbits` в `geo_category_t`).
  Ранее оба вызова `bloom_check` использовали `bloom_nbits` domain-фильтра, тогда
  как domain и suffix bloom могут иметь разный размер (разные пулы записей).
- **[FEATURE]** `cdn_updater.c`: `cdn_updater_tick()` — автоматическое
  обновление CDN IP каждые 6 часов (`CDN_UPDATE_INTERVAL_SEC=21600`),
  первый запуск через 5 мин после старта (`CDN_UPDATE_DELAY_SEC=300`).
  Вызывается из main event loop, не блокирует (внутри time(NULL) + cdn_is_stale).
  State хранится в `EburNetState.cdn_next_check` (не static local).
- **[CLEANUP]** `geo_loader.c`: `device_detect_region()` читает timezone через
  `uci get system.@system[0].zonename` (popen) вместо fopen /etc/config/system.
  UCI — стабильный API OpenWrt в отличие от raw UCI file format.

### DNS Quality (fix-dns-quality — audit_v45)

- **[FUNCTIONAL/P2]** `dns_cache.c`: hard evict и LRU evict теперь используют tombstone
  (`DNS_CACHE_SLOT_DELETED`) вместо `used=false`. Исправляет разрыв probe chain при
  linear probing: запись B с хэшем h на слоте h+1 была недостижима если слот h
  освобождался → false cache miss под нагрузкой. `dns_cache_put` запоминает первый
  DELETED слот для вставки, продолжая поиск USED-дубликата.
- **[PERF/P3]** `dns_server.c`: per-callback `malloc(DNS_MAX_PACKET)` в `async_doh_dot_cb`
  заменён на `static uint8_t s_doh_reply_buf[DNS_MAX_PACKET]` (single-threaded epoll,
  re-entrancy невозможна).
- **[SECURITY/P3]** `dns_cookie.c:585`: `memcmp` при HMAC verify заменён на
  constant-time compare (`volatile uint8_t diff |= a^b`) — предотвращает timing oracle.
- **[CLEANUP]** `dns_upstream.c:285,298,299`: хардкод `2048` → `DNS_DOH_REQ_SIZE` (3 места).
- **[CLEANUP]** `dns_resolver.c:197`: `upstream_fd` close — добавлен `epoll_ctl DEL`
  для единообразия с fallback_fd/parallel_fd.
- **[CLEANUP]** `dns_server.c:471`: WHY-комментарий drain loop исправлен
  (LT mode, не EPOLLET).
- **[CLEANUP]** Литерал `53` → `DNS_PORT` в `dns_server.c` (8 мест) и `main.c` (1 место).
- **[CLEANUP]** `constants.h`: добавлены `FAKE_IP_RANGE_DEFAULT "198.18.0.0/16"` и
  `FAKE_IP6_RANGE_DEFAULT "fd00::/120"`; `fake_ip.c` fallback заменён на константу.

### Crypto Quality (fix-crypto-quality — audit_v45)

- **[SECURITY/P3]** `tls13_hs.c`: Finished MAC verify — `memcmp` заменён на
  constant-time compare (`volatile uint8_t diff |= a^b`). Устраняет timing oracle
  в MITM сценарии; консистентно с паттерном в `hmac_sha256.c`.
- **[MEMORY/P3]** `tls13_hs.c`: `wc_Sha256Free(&snap)` вызывается на ВСЕХ путях
  после успешного `wc_Sha256Copy` — 3 места (~431, ~584, ~713). При WOLFSSL_SMALL_STACK
  SHA256 state аллоцируется динамически — предотвращает heap leak на error path.
- **[CORRECTNESS/P3]** `tls13_hs.c`: cipher 0x1302/0x1303 → явный `LOG_WARN` и
  `return -1` вместо silent wrong keys. Key schedule деривирует только SHA256/AES-128 —
  принятие другого cipher → corruption. xray всегда выбирает 0x1301 → behaviour
  на практике не изменится.
- **[CORRECTNESS/P4]** `reality_conn.h`: `recv_acc[16404]` → `recv_acc[REALITY_RECV_ACC_SIZE]`
  (= 5+16384+16 = 16405). Off-by-one fix: граничный 16385-байтный TLS record
  ошибочно отклонялся как "too large" через `sizeof(c->recv_acc)` проверку.

### Config API (fix-config-api — audit_v45)

- **[FUNCTIONAL/P4]** `config.c`: `reality_pbk` валидируется при загрузке —
  длина 43, алфавит base64url RFC 4648 §5 (A-Za-z0-9-_). `LOG_WARN` при
  невалидном значении: ошибка обнаруживается при загрузке конфига, а не
  молча при первом соединении с wolfSSL error без контекста.
- **[FUNCTIONAL/P4]** `config.c`: `reality_fingerprint` проверяется по
  whitelist (`"chrome"`, `"chrome120"`). `LOG_WARN` при неизвестном значении
  вместо silent Chrome120 fallback.
- **[VERSION]** `Makefile`: postinst echo `v1.5.5` → `v$(PKG_VERSION)` — теперь
  версия в сообщении установки всегда совпадает с реальной.
- **[UI/P4]** `http_server.c`: поле `"geo_loaded"` добавлено в `/api/status` →
  Dashboard корректно отображает статус гео-баз.
- **[CLEANUP]** `http_server.c`: `api_token` обновляется при SIGHUP reload
  через `http_server_reload_token()` — смена токена в UCI без рестарта демона.
- **[CLEANUP]** `dns_cookie.c`: путь к cookie secret передаётся через UCI
  `dns_cookie_secret_path` в `dns_cookie_init(s, path)` вместо хардкода.
  Дефолт `/var/lib/4eburnet/cookie.secret` если UCI-поле не задано.
- **[CLEANUP]** `nftables.c`: flowtable devices использует `lan_interface` из
  конфига вместо хардкода `"br-lan"`. Дефолт `"br-lan"` если UCI-поле пустое.
- **[DOCS]** `README.md`: badge обновлён до v1.5.77.

### Code Quality (fix-code-quality — audit_v45)

- **[CLEANUP]** `dpi_filter.c`: dead code `addr > ip` в backward scan удалён —
  после lower_bound binary search все `g_ipv4[0..hi].addr <= ip`, условие логически
  невозможно (sorted array, invariant нарушен быть не может).
- **[CORRECTNESS]** `dpi_strategy.c`: EAGAIN в `dpi_send_fragment` → `return -1`
  вместо `break` (ложный успех). Предотвращает тихую потерю байт TCP stream
  при переполнении send-буфера в DPI фрагментации.
- **[CORRECTNESS]** `ws_handshake.c`: `ws_send_101()` обрабатывает EAGAIN через
  `poll(POLLOUT, 100ms)` × 3 retry вместо прямого `return -1`.
- **[SECURITY]** `dashboard.html`: `p.updated` теперь через `escHtml()` —
  defensive coding: все поля из API-ответов экранируются единообразно.
- **[FEATURE]** `dns_server.c`: `g_dns_recv_q_max` реализован — CAS high-watermark
  обновляется в DNS drain loop после каждого `handle_udp_query` вызова.
  Доступен в `/api/status` как `"dns_recv_q_max"` — метрика для диагностики DNS flood.
- **[CLEANUP]** `hc_vless.c`: `socket()` с `SOCK_CLOEXEC` — HC дочерние процессы
  не наследуют epoll/IPC/upstream fd родителя.
- **[CLEANUP]** `ja3.c`: `static char str[640]` → `str[768]` — margin для
  adversarial ClientHello (guard в `append_u16_list` уже корректен).
- **[SECURITY]** `http_server.c`: IP из `/proc/net/arp` теперь через `json_escape_str()`
  в `/api/devices` — defensive coding: все внешние данные экранируются.
- **[DOCS]** `proxy_group.c`: hysteria2/hy2 исключение из `transport_is_implemented`
  задокументировано — явный `return false` с WHY T0-08 (QUIC HC не реализован).

### Build & Tests (fix-build-tests — audit_v45 §12 + §16)

- **[BUILD]** `scripts/wolfssl_build_aarch64.sh`: новый параметризованный
  скрипт сборки wolfSSL 5.9.0 для aarch64_cortex-a53. Без hardcoded путей
  разработчика — обязательные переменные окружения `WOLFSSL_SRC`,
  `TC_AARCH64`, `WOLFSSL_AARCH64`. По образцу `wolfssl_build_mipsel.sh`,
  но переносимый между машинами. Ранее aarch64 сборка велась вручную или
  по приватным заметкам — отсутствовала в репозитории.
- **[BUILD]** `Makefile.dev` `TEST_FLAGS`: добавлены `-Wsign-compare`,
  `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`. Тесты теперь
  компилируются с теми же security guards что и production-код.
  Усиление сразу нашло реальный баг: `-Wformat-truncation` в
  `hc_vless.c:312` (`host[130]` мал для `address[256]`) — расширено до
  `host[260]`.
- **[TESTS]** `test-hc-vless` добавлен в `test:` composite target. Target
  расширен зависимостями: `trojan.c`, `grpc.c`, `ws_client.c`,
  `http_upgrade.c`, `vision.c` — раньше hc_vless.c имел только VLESS
  зависимости, после T0-04…T0-06 + Trojan/gRPC оброс multi-transport
  вызовами. Тест не требует сети (`127.0.0.2:59999` ECONNREFUSED +
  `192.0.2.1:443` TEST-NET timeout) — годен для composite. 8 PASS, 0 FAIL.
- **[TESTS]** Orphaned тесты подключены к `make`:
  `test-ws-handshake` (RFC 6455 vector), `test-ecdh-wolfssl`
  (X25519 KAT vector), `test-reality-roundtrip` (полная Reality crypto
  цепочка). Все три — unit tests без сети, добавлены в composite.
- **[TESTS]** `test_dns_cookie.c`: создан, закрыт §21 known gap.
  6 тестов покрывают `dns_cookie_compute_server` + `dns_cookie_verify`:
  формат RFC 9018 §4.2 (version=1, reserved=0, timestamp BE, HMAC-SHA256-8),
  generate→verify→OK, испорченный HMAC→BAD, устаревший timestamp→SLIP,
  constant-time structural (модификация любого байта hash возвращает BAD),
  ротация secret (cross-verify→BAD). 6 PASS, 0 FAIL.
- **[TESTS]** `make test` composite расширен с 37 до 42 суит
  (`+test-hc-vless +test-ws-handshake +test-ecdh-wolfssl
  +test-reality-roundtrip +test-dns-cookie`). Все 42 проходят на musl-gcc
  x86_64 с обновлённым `TEST_FLAGS`.

## [1.5.76] — 2026-05-04

### Fixed

- `hc_vless.c`: HC URL изменён на `https://www.gstatic.com/generate_204` (HTTPS:443)
  как в mihomo — серверы не блокируют :443, в отличие от :80 (Finland Helsinki, Switzerland Geneva)
- `hc_vless.c`: `child_do_hc_vless_tcp` заменён на `child_do_hc_vless_tcp_tunnel` —
  VLESS/TCP plain теперь идёт через полный туннельный HC (outer TLS + VLESS header +
  VLESS response check) аналогично mihomo URLTest; HTTP round-trip не нужен — сервер
  отвечает на VLESS header немедленно (до установки inner-соединения)
- `hc_vless.c`: добавлен `transport="raw"` в условие туннельного HC (URI парсер при
  `type=tcp` выставляет `transport="raw"` в else-ветке, а не `""` / `"tcp"`)
- `proxy_group.c`: убран guard `!srv->source_provider[0]` перед `hc_vless_spawn` —
  провайдерные серверы (PrivateVPN, ARZA) теперь попадают в честный туннельный HC

### Result

- Finland Helsinki VLESS/TCP: **171ms** (туннельный HC) — стабильно выбирается лучшим
- YouTube через VLESS/TCP работает стабильно

## [1.5.75] — 2026-05-04

### Added

- `hc_vless.c`: `child_do_hc_vless_tcp` — TLS HC для VLESS/TCP plain как промежуточный шаг

### Notes

- Заменён в v1.5.76 на `child_do_hc_vless_tcp_tunnel` (полный туннельный HC)

## [1.5.74] — 2026-05-04

### Added

- `hc_vless.c` / `child_do_hc_vless_tcp`: TLS handshake HC для VLESS/TCP plain (без Reality).
  Аналог `child_do_hc_vless_ws` — только без HTTP Upgrade. Измеряет реальную latency туннеля
  (50-400ms) вместо TCP RTT (1-2ms через fake-ip redirect)

### Fixed

- `proxy_group.c`: убран guard `!srv->source_provider[0]` перед вызовом `hc_vless_spawn`.
  Guard блокировал честный HC для всех провайдерных серверов (PrivateVPN, ARZA) — они шли
  через `net_spawn_tcp_ping` → fake-ip DNS → 2ms для любого сервера в мире
- `hc_vless.c` / VLESS/TCP условие: добавлен `transport="raw"` в фильтр TLS HC.
  URI парсер при `type=tcp` ставит `transport="raw"` (else-ветка), не `"tcp"` / `""`
- `hc_vless.c` / TCP RTT path: восстановлено условие `if (!vless || !reality_pbk)`
  перед `_exit(0)` — новый безусловный блок `{}` обрывал Reality HC для VLESS/Reality серверов

### Result

- Finland Helsinki² VLESS/TCP: **164ms** (TLS HC) — выбирается справедливо
- Canada Toronto VLESS/TCP: **400ms** (TLS HC)
- VLESS/TCP plain больше не побеждает url-test с нечестными 2ms

## [1.5.73] — 2026-05-04

### Fixed

- `proxy_group.c`: немедленный пересчёт `selected_idx` при `available=false` для URL_TEST —
  при `proxy_group_mark_server_fail` group сразу переключается на лучший доступный сервер
  без ожидания следующего HC цикла
- `proxy_group.c`: `proxy_group_get_server` проверяет `available` перед возвратом сервера —
  SELECT-группа не отдаёт недоступный сервер даже если `selected_idx` ещё не пересчитан

## [1.5.72] — 2026-05-04

### Fixed

- `dispatcher.c` / `relay_free`: добавлена проверка `r->tls != NULL` перед
  `tls_close()` — XHTTP протокол устанавливает `use_tls=true` но не заполняет
  `relay->tls` (TLS внутри `xhttp_state`), что вызывало SIGSEGV при освобождении
  реле (`do_page_fault: invalid read access from 00000000` в `tls_close`)
- `dispatcher.c` / XHTTP state machine: добавлены NULL-guard проверки `r->xhttp`
  в обработчиках `RELAY_XHTTP_UP_TLS`, `RELAY_XHTTP_DN_TLS`, `RELAY_XHTTP_DN_REQ`,
  `RELAY_XHTTP_ACTIVE` (защита от гонки при досрочном освобождении xhttp_state)
- `dispatcher.c` / RELAY_WS_HS + RELAY_HTTP_UG_HS: убрана немедленная блокирующая
  отправка после TLS handshake; вместо этого добавлен `EPOLLOUT` в `epoll_ctl MOD`
  — решает deadlock при EPOLLET когда граница TLS Finished уже потреблена

### Result

- Устранён систематический SIGSEGV в `4eburnetd` на EC330 при XHTTP соединениях
  (крэш каждые 5-30 минут, epc=0x411914/0x411e28 в зависимости от сборки)
- WS и HTTPUpgrade транспорты теперь инициируют handshake корректно через EPOLL

## [1.5.71] — 2026-05-04

### Fixed

- `net_utils.c` / `child_do_tcp_ping`: добавлен `getaddrinfo()` fallback — TCP ping
  теперь работает с именами хостов (ранее `inet_pton` возвращал ERR для всех
  провайдерских серверов с доменными адресами → url-test никогда не завершался)
- `proxy_group.c` / `proxy_group_tick` + `proxy_group_handle_hc_event`: tolerance
  снижен с 150ms до 30ms во всех трёх точках выбора; при 150ms разрыв Finland(43ms)
  vs Canada(184ms)=141ms не превышал порог → группа навсегда оставалась на Canada
- `proxy_group.c` / spawn loop: добавлен `break` при пересечении границы раунда
  (`cursor % server_count == 0`) — без этого cursor уходил в следующий раунд и
  round-complete (`hc_active==0 && cursor%N==0`) никогда не срабатывал
- `proxy_group_tick`: параллельный HC по всем серверам раунда за один вызов (аналог
  mihomo errgroup), ограниченный `hc_global_limit` (динамически по MemAvailable)

### Result

- GEMINI url-test: переключился с Canada,Toronto(184ms) на Finland,Helsinki²(44ms)
- PrvtVPN url-test: переключился на Estonia(30ms)
- Все провайдерские серверы теперь получают реальные латентности через TCP ping

## [1.5.70] — 2026-05-04

### Fixed

- `main.c` + `nftables.c` + `nftables.h`: ip_cidr правила нацеленные на прокси теперь
  автоматически добавляются в `proxy_addrs` set и DNAT redirect при старте демона
- `nft_dnat_add_cidr4()`: новая функция для добавления одного IPv4 CIDR в `ip eburnet_nat`
  prerouting — redirect to :7893 без пересоздания всей таблицы
- Telegram (149.154.160.0/20, 91.108.x.x) и любые будущие ip_cidr правила теперь
  перехватываются TPROXY автоматически без ручного `nft add rule` после каждого перезапуска

## [1.5.69] — 2026-05-04

### Added

- `core/src/geo/geo_dat_parser.c` + `core/include/geo/geo_dat_parser.h`: потоковый парсер
  v2fly GeoIPList/GeoSiteList .dat встроен в демон напрямую (не только tools/)
- `core/src/geo/geo_mmdb_parser.c` + `core/include/geo/geo_mmdb_parser.h`: MaxMind .mmdb
  парсер встроен в демон напрямую
- `geo_loader.c`: 4 новые функции — `geo_load_category_text`, `dat_extract_code`,
  `geo_load_category_dat`, `geo_load_category_mmdb`; dispatch по расширению файла
  (.dat → streaming protobuf, .mmdb → DFS mmap, .gbin → binary mmap, .lst → text)
- `main.c`: `geo_find_path()` — авто-детект формата (приоритет: .gbin → .dat → .mmdb → .lst)
  для категорий `geoip-{region}` и `geosite-{region}`

### Notes

- Промежуточный .lst пишется в /tmp (tmpfs) и сразу удаляется после загрузки
- EC330 тест: `geoip-ru.dat` → `загружено из .dat [RU]: 12662 IPv4, 8786 IPv6` (21448 итого) ✅
- geosite-ru, ads, trackers, threats — не скопированы на EC330 (не в scope этой задачи)

## [1.5.68] — 2026-05-03

### Added

- `tools/geo_dat_parser.c` + `geo_dat_parser.h`: потоковый parser v2fly GeoIP/GeoSite .dat
  - Читает только нужную страну/категорию без загрузки всего файла в RAM
  - RAM ≤ max_entry_size (~320KB для RU), не 23MB
  - Тест: RU GeoIP = 21448 CIDR, CATEGORY-RU GeoSite = 803 доменов
- `tools/geo_mmdb_parser.c` + `geo_mmdb_parser.h`: MaxMind .mmdb reader
  - mmap + DFS traverse B-tree, экспорт одной страны в .lst
  - Без libmaxminddb (нет внешних зависимостей)
  - Тест: RU = 13117 CIDR из GeoLite2-Country.mmdb
- `tools/update_geo.py`: `extract_from_dat` + `extract_from_mmdb` + Python fallback
  - `--refs-geo` параметр для использования локальных .dat/.mmdb файлов

### Notes

- `geo_loader.c` и `.gbin` формат не изменены — существующий пайплайн совместим
- Пайплайн: `.dat`/`.mmdb` → `geo_dat_parser`/`geo_mmdb_parser` → `.lst` → `geo_compile` → `.gbin`
- geosite.dat коды uppercase: RU домены = `CATEGORY-RU` (803 записи)

## [1.5.67] — 2026-05-03

### Fixed

- `main.c`: SIGHUP теперь всегда регистрируется как reload (было: `if (!daemon_mode) → shutdown`)
  Root cause: procd запускает без `-d` → `daemon_mode=false` → SIGHUP убивал процесс
  Фикс: безусловная регистрация `sigaction(SIGHUP, &sa_reload, NULL)`

### Notes

- T0-01/T0-02 Reality params и Vision — реализованы в v1.5.2–v1.5.3 (не баги)
- Fake-ip рассинхрон P0.1 — устарел, UCI корректен (`198.18.0.0/16`)
- RULE-SET engine — реализован, `ruleset_match_domain`/`ruleset_match_ip` работают

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
  формат: `dispatcher_resolve: <reality-sni> -> <IP> (via 192.168.1.1, cached=yes/no)`
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
  прокси-серверов (<reality-sni> и т.п.), обходя fake-IP DNS и избегая рекурсии
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
- WHY: `dispatcher_resolve` не мог резолвить <reality-sni> — upstream_bypass был пуст,
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
`<reality-pbk>` некорректно —
вместо `<reality-pbk-hex>...` выдавал `<redacted-hex>...`. Следствие: неверный ECDH →
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

- Unit test: `reality_pbk_decode("<reality-pbk>") == <reality-pbk-hex>...` ✓
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

- Live test с <reality-sni>: TLS 1.3 Reality handshake успешен,
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

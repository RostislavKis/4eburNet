# Changelog

## v2.5.0 (2026-05-16) — AWG WireGuard working: 97 Telegram via WARP, 36+ min stable

- fix(awg): blake2s_hmac вызывал blake2s_keyed вместо настоящего HMAC (ipad/opad)
  Следствие: все KDF-ключи noise-протокола были неверными → handshake failure
- fix(awg): отсутствовал шаг MixKey(Ci, Ei_pub) в noise_handshake_initiation_create
  Согласно WireGuard noise spec §5.4.2: Ck,k = KDF2(Ck, DH(Ei,Sr))
  без предшествующего KDF1(Ci, Ei_pub) цепочка ключей расходится
- fix(awg): hash/chainKey не сбрасывались между повторными попытками handshake
  При retry использовалось накопленное состояние предыдущей попытки → failure
- fix(awg): EPOLLET→EPOLLIN LT + принудительный drain после epoll_ctl ADD для peer fd
  Edge-trigger пропускал данные при наличии байт до первого epoll_wait
- feat(awg): singleton peer pool (awg_pool.c/h)
  Один udp_fd на peer вместо fd-per-relay; awg_pool_tick retransmit из dispatcher_tick
- feat(awg): awg_send_handshake_sequence — полный CPS+junk+Init при каждом retry
- feat(awg): userspace IPv4/TCP stack (awg_ipstack.c/h, 370 LoC)
  Encap/decap WireGuard tunnel → TCP relay без kmod; поддержка awg_local_ip UCI
- feat(config): UCI поле awg_local_ip + clash_yaml парсер поля ip:

## v2.4.7 (2026-05-15) — тест-сюита: 58/58 PASS (+1 новая сюита)

- feat(tests): test_proxy_provider — 9 проверок URI парсеров, inline-.c паттерн
  Подход: #include "../src/proxy/proxy_provider.c" для доступа к static функциям;
  7 заглушек (log_msg/clash_yaml/hy2_parse_uri/http_emit/net_spawn/rm_detect)
  в tests/stubs/proxy_provider_stubs.c; proxy_provider.c не компилируется отдельно
  [1] base64_decode: "hello"(5B), "test"(4B), пустая строка(0B), некорректный '!'→-1
  [2] url_decode: %2F%40%3A→"/@:", %20→" ", без кодирования, '+' не декодируется
  [3] parse_vless_uri_basic: Reality — addr/port/uuid/sni/pbk/sid/fp/name/transport=raw
  [4] parse_vless_uri_ws_transport: type=ws → transport="ws"
  [5] parse_vless_uri_invalid: unknown:// / "" / NULL → все возвращают -1
  [6] parse_ss_uri_sip002: YWVzLTI1Ni1nY206cGFzc3dvcmQ=→password; addr/port/name
  [7] parse_trojan_uri: password123/host/443/TrojanServer
  [8] parse_server_uri_dispatch: vless/ss/trojan→proto; unknown://→-1
  [9] proxy_provider_max_servers: NORMAL=1024, override=50, FULL=4096

## v2.4.6 (2026-05-15) — тест-сюита: 57/57 PASS (+3 новых сюита)

- feat(tests): test_proxy_group — 7 проверок LB-алгоритмов inline-паттерн (без production headers)
  [1] round_robin 0→1→2→3→4→0; [2] round_robin_skip_unavailable только 0,2,4;
  [3] consistent_hashing_deterministic (все 10 → сервер 1);
  [4] consistent_hashing_distribution (hits: 21 21 18 22 18 по 100 dst_ip);
  [5] sticky_same_src (все 10 → сервер 0);
  [6] sticky_different_src (hits: 4 4 4 4 4 по 20 src_ip);
  [7] sticky_lru_eviction (slot 202: ip_a=0xef→0 ip_b=0x100→1 re-a→2)
  коллизия: pg_fnv1a32(0xef,4)%256 == pg_fnv1a32(0x100,4)%256 = 202
- feat(tests): test_net_utils — 50 проверок net_utils.c (T1-T8)
  T1: valid_ifname (11 кейсов); T2-T3: net_format_addr IPv4/IPv6;
  T4: json_escape_str; T5: net_parse_url_host; T6: fallback DNS getters/setters;
  T7: resolve IP fast path; T8: net_random_bytes
  заглушки: tls_connect/send/recv/close
- feat(tests): test_proxy_group_lb — 27 проверок proxy_group.c LB-логики (T1-T6)
  T1: pg_fnv1a32 детерминизм + FNV offset basis; T2: round-robin wrap-around;
  T3: consistent-hashing детерминированность; T4: sticky-sessions аффинити;
  T5: URL_TEST mark_fail_immediate available=false + SELECT fallback logic;
  T6: mark_server_ok градуальный декремент без underflow
  заглушки: http_server_emit_event, hc_*_spawn, rm_detect_profile,
            dispatcher_notify_anytls_rtt, tls_*
- fix: config_get_server — добавлен NULL guard (cfg=NULL → return NULL)
  WHY: тесты передают pgm->cfg=NULL; pg_select_rotate → crash без guard
- fix: proxy_group.c ev_mf_sw/ev_mi_sw/ev_fg_sw/ev_ut 256→512 байт
  WHY: group(63) + server(127) + server(127) = 317 > 256; -Wformat-truncation

## v2.4.5 (2026-05-15) — тест-сюита: 54/54 PASS

- fix(tests): Makefile.dev test-ja3 — добавлен src/crypto/hmac_sha256.c
  sniffer.c с -DCONFIG_EBURNET_QUIC=1 вызывает hmac_sha256/hmac_sha256_2;
  в test-sniffer файл был, в test-ja3 отсутствовал → ld error
- fix(tests): test_tuic_v5.c — 14 вызовов tuic_defrag_add обновлены до 12-param API
  расширение сигнатуры: +addr_in/port_in/addr_out/addr_out_sz/port_out;
  тест передаёт NULL/0 (адреса для дефрагментации не нужны)
- result: все 54 таргета make test PASS; 0 Error впервые

## v2.4.4 (2026-05-15) — T-AND-01 + T-LB-01 UI

- feat(dashboard): RuleFormModal — AND builder полностью реализован
  AND option в select + builder секция (аналог OR) + addAndCond/removeAndCond
  submit payload: and_conditions[] при type=AND; guard расширен (!== 'AND')
  buildInitialForm: инициализация из rule?.and_conditions (поддержка edit)
- feat(dashboard): ProxyGroupEditModal — consistent-hashing и sticky-sessions возвращены
  consistent-hashing: hash по dst IP (один destination → один сервер)
  sticky-sessions: hash по src IP (один клиент → один сервер)
  оба option с v-tooltip через lbConsistentHashingDesc / lbStickySessionsDesc
- feat(api): RuleConfig.and_conditions?: OrCondition[] добавлено в api/index.ts
- feat(i18n): 7 ключей ru.ts+en.ts: ruleAndDesc, ruleAndConditions,
  rule_add_and_condition, lbConsistentHashing/Desc, lbStickySessions/Desc

## v2.4.3 (2026-05-15) — T-AND-01 + T-LB-01 backend

- feat(rules): AND правило полностью реализовано
  RULE_TYPE_NETWORK=15 добавлен в enum (sub-условие для AND)
  config.c: UCI list and_condition парсинг → sub_rules[] (ALL MUST MATCH)
  rules_engine.c: AND case переписан — sub_rules loop вместо захардкоженного
    NETWORK+DST-PORT; поддержка DOMAIN/IP-CIDR/GEOIP/GEOSITE/DST-PORT/NETWORK
  http_server.c: "AND" добавлен в valid_rtypes[] POST+PATCH; AND block UCI handler;
    GET возвращает sub_conditions для AND правил
- feat(proxy_group): три стратегии load-balance
  round-robin: rr_idx % avail (дефолт, без изменений)
  consistent-hashing: fnv1a32(dst_ip4) % avail — детерминированный по destination
  sticky-sessions: fnv1a32(src_ip4) → LRU таблица 256 слотов per-group;
    fallback на RR при первом запросе или после eviction
- feat(proxy_group): proxy_group_select_server +src_ip4, +dst_ip4 параметры
  dispatcher.c: 3 call sites обновлены; src_ip4 извлекается из conn->src
- feat(proxy_group): pg_fnv1a32, pg_sticky_entry_t, sticky_table[256] в proxy_group.h
  577 тестов PASS; бинарник 3.12 MB

## v2.4.2 (2026-05-15) — T3-01 LuCI Enhanced integration

- feat(luci): Overview вкладка — статус демона (version/uptime/mode/profile), кнопки
  start/stop/reload, ссылка на Dashboard :8080, poll аптайма каждые 5с
- feat(luci): Settings вкладка — mixed_port, tproxy_port, upstream DNS (default/bypass/fallback),
  fake_ip_enabled; применяется через /api/network + /api/dns демона
- feat(luci): Logs вкладка — последние 80 строк logread | grep 4eburnet, poll каждые 10с
- feat(luci): rpcd ucode +4 метода: control, config_get, config_set, logs
- feat(luci): ACL write права: control + config_set
- feat(luci): menu.d +2 пункта: Настройки (order:20), Логи (order:30)
- feat(luci): po/ru +33 строки перевода

## v2.4.1 (2026-05-15) — T3-03 CI/CD GitHub Actions

- feat(ci): .github/workflows/build.yml — 4 jobs: test + build (matrix mipsel/aarch64/x86_64) + dashboard + release
- feat(ci): wolfSSL 5.9.0 кэш по arch+version+sdk, SDK кэш ~150MB/arch
- feat(ci): check-src guard — зелёный статус в публичном репо без исходников
- feat(ci): release job — автоматический GitHub Release на тег v* с CHANGELOG секцией
- fix(makefile): PKG_VERSION динамически читается из Makefile.dev (был рассинхронизирован
  1.5.180 vs 2.3.30)
- fix(build.sh): добавлена архитектура armv7 (4-я целевая платформа)

## v2.4.1+1 (2026-05-15) — fix: CI dashboard job — check-src guard (dashboard-src gitignored в публичном репо)

- fix(ci): dashboard job — добавлен check-src guard: `[ -d dashboard-src ]` → has_source
  все шаги пропускаются если dashboard-src/ отсутствует; поведение симметрично test/build jobs

## v2.4.1 (2026-05-14) — feat: T3-03 CI/CD GitHub Actions — build×3arch + tests + dashboard + release на v*

- feat: .github/workflows/build.yml — CI/CD pipeline: jobs test + build(mipsel/aarch64/x86_64) + dashboard + release
- feat(ci): test job — wolfSSL host (musl-gcc) + make -f Makefile.dev test
- feat(ci): build job — matrix×3arch: OpenWrt SDK download + wolfSSL cross-compile + 4eburnetd + IPK
- feat(ci): dashboard job — Node 22 + npm ci + npm run build (параллельно с build)
- feat(ci): release job — GitHub Release на тег v* с IPK × 3arch + dashboard_assets.tar.gz
- fix(ci): guard has_source — все шаги пропускаются если core/ отсутствует (публичное репо без исходников)
- feat(scripts): armv7 добавлен в scripts/build.sh — ARMV7_SDK + SDK_PATH + OPENWRT_ARCH + case + all loop
- fix(makefile): PKG_VERSION динамический — grep из Makefile.dev (устранён рассинхрон 1.5.180 vs 2.3.30)

## v2.4.0+1 (2026-05-14) — docs: ROADMAP.md актуализирован — v2.4.0, audit_v50 архив, T-AND-01 + T-LB-01

- docs: ROADMAP.md — версия и дата обновлены до v2.4.0 / 2026-05-14
- docs: Tier 1 помечен закрытым (v2.3.30); добавлена метка "Все задачи Tier 1 закрыты"
- docs: Tier 3 — добавлена таблица BLOCKED: T-AND-01 (AND builder) + T-LB-01 (lb стратегии)
- docs: новая секция "Архив закрытых задач" — таблица Audits + Dashboard/API (14 строк, P1–P14)
- docs: Status log — запись audit_v50 ЗАКРЫТ (14/29/36 → 0/0/0, P1–P14)

## v2.4.0 / v2.3.44 (2026-05-14) — feat: SSHConsolePage xterm.js — FitAddon + JSON resize + exit/error handling + i18n

- feat(dashboard): SSHConsolePage.vue — полная замена dumb terminal на xterm.js
  Terminal + FitAddon (авто cols/rows) + WebLinksAddon (кликабельные ссылки)
  ResizeObserver следит за контейнером — FitAddon.fit() + sendResize() при каждом resize
  onData перехватывает все нажатия (Ctrl+C ETX, Ctrl+D EOT, Tab, стрелки) напрямую
  theme: #1d232a/e5e7eb/a6e3a1 совместимо с DaisyUI night theme
- fix(dashboard): JSON resize вместо ANSI escape — backend (http_server.c:567) ожидает
  {"type":"resize","rows":N,"cols":M}, НЕ \x1b[8;rows;colst
- fix(dashboard): WS URL через activeBackend + getUrlFromBackend — паттерн как в api/index.ts:517
  ?token=password, arraybuffer mode, auto-reconnect ×5 с 2с задержкой
- fix(dashboard): парсинг {"type":"exit"} от backend — корректное завершение без реконнекта
- fix(dashboard): 2 hardcoded строки ошибок → t('sshError')/t('sshWsError')
- feat(i18n): 2 новых ключа: sshError, sshWsError в ru.ts и en.ts
- fix(pwa): vite.config.ts — maximumFileSizeToCacheInBytes 4MB (xterm.js ~400KB overhead)
  Установлены: @xterm/xterm@6, @xterm/addon-fit, @xterm/addon-web-links
  TypeScript 0 ошибок; build 1.51s ok

## v2.3.43 (2026-05-14) — fix: TopologyCharts 14 CN→RU + 4 tooltips; ProxyGroupEditModal rm sticky/consistent-hashing; docs: T-LB-01

- fix(dashboard): TopologyCharts.vue — 14 китайских комментариев переведены на русский
  addNode: цикл в Sankey; initialNodes/nodesByLayer/sortedLayers: формирование/группировка/сортировка
  idMapping: старый id → новый id; переназначение id; обновление links после переназначения
  логарифмическое масштабирование + формула; originalValue tooltip; tooltip pause/fullscreen handlers
- fix(dashboard): TopologyCharts.vue — v-tooltip на 4 кнопках (2 pause + 2 fullscreen)
  WHY: закон "КАЖДЫЙ button → tooltip". Две пары кнопок (normal + fullscreen Teleport layout)
  добавлены import useTooltip + const { tip } = useTooltip() в script setup
- feat(i18n): 2 новых tooltip-ключа в ru.ts и en.ts
  topology_pause, topology_fullscreen
- fix(dashboard): ProxyGroupEditModal.vue — удалены options consistent-hashing и sticky-sessions
  proxy_group.c реализует только round-robin (строка 269); consistent/sticky grep → 0 = мок
- docs: зафиксирован tech debt T-LB-01 в audit_v50.md — lb стратегии до v2.5.0
  Файлы: TopologyCharts.vue, ProxyGroupEditModal.vue, ru.ts, en.ts, audit_v50.md
  TypeScript 0 ошибок; build ok

## v2.3.42 (2026-05-14) — fix: RuleFormModal 4 hardcoded labels → i18n; docs: T-AND-01 tech debt

- fix(dashboard): RuleFormModal.vue — 4 hardcoded label-text заменены на t()
  'Тип правила' → t('ruleTypeLabel'), 'Условия OR' → t('ruleOrConditions')
  'Значение' → t('ruleValueLabel'), 'Направить через' → t('ruleTargetLabel')
- feat(i18n): 4 новых ключа в ru.ts и en.ts (основная секция)
  ruleTypeLabel, ruleOrConditions, ruleValueLabel, ruleTargetLabel
- docs: зафиксирован tech debt T-AND-01 — AND builder требует backend доработки
  valid_rtypes[] (http_server.c:5530) не содержит "AND" → POST вернёт HTTP 400
  rules_engine.c:526 поддерживает только NETWORK+DST-PORT, не and_conditions через API
  Milestone: v2.5.0
  Файлы: RuleFormModal.vue, ru.ts, en.ts, audit_v50.md; TypeScript 0 ошибок; build ok

## v2.3.41 (2026-05-14) — fix: SnifferSection QUIC SNI enable + quic stats + saveMessage i18n + bypass tooltip

- fix(dashboard): SnifferSection.vue — QUIC SNI toggle разблокирован (реализован в v2.3.28, RFC 9001 §5)
  удалены: opacity-50 с контейнера, disabled с input, badge comingSoon; добавлен @change="save"
- feat(dashboard): SnifferSection.vue — stat-блок QUIC SNI добавлен рядом с total/tls/http/bypassed
  backend возвращает поле "quic" напрямую; Object.assign работает без маппинга
- feat(api): SnifferStats — добавлено поле quic: number; инициализация stats с quic: 0
- fix(dashboard): saveMessage hardcoded 'Сохранено'/'Ошибка сохранения' → t('snifferSaved'/'snifferSaveError')
  добавлены import useI18n + const { t } = useI18n() в script setup
- fix(dashboard): newDomain input — добавлен v-tooltip="tip('sniffer_bypass_input')"
  добавлены import useTooltip + const { tip } = useTooltip() в script setup
- feat(i18n): 5 новых ключей в ru.ts и en.ts
  основная секция: snifferSaved, snifferSaveError
  tooltips: sniffer_bypass_input
  Файлы: SnifferSection.vue, api/index.ts, ru.ts, en.ts; TypeScript 0 ошибок; build ok

## v2.3.40 (2026-05-14) — fix: ConnectionCtrl tooltips Pause/Close-All + ConnectionTable 7 китайских комментариев → русский

- fix(dashboard): ConnectionCtrl.tsx — кнопки Pause и Close-All получили onMouseenter tooltip
  Pause: t(isPaused ? 'play' : 'conn_pause'); Close-All: t('conn_close_all')
  паттерн showTip({ appendTo: 'parent' }) — совпадает с FilterButton
- feat(i18n): ключ play: 'Продолжить' / 'Resume' добавлен в ru.ts и en.ts
- fix(dashboard): ConnectionTable.vue — 7 китайских комментариев/строк переведены на русский
  完整显示所有代理链 → Показываем полную цепочку прокси
  只处理左键 → Обрабатываем только левую кнопку мыши
  检查是否超过拖动阈值 → Проверяем превышение порога перетаскивания
  延迟重置拖动状态 → Отложенный сброс drag — предотвращает срабатывание click
  复制功能 → Функция копирования в буфер обмена
  降级处理 → Fallback для старых браузеров
  console.error('复制失败:') → console.error('Ошибка копирования:')
  Файлы: ConnectionCtrl.tsx, ConnectionTable.vue, ru.ts, en.ts; TypeScript 0 ошибок; build ok

## v2.3.39 (2026-05-14) — fix: i18n RuleTestModal + ImportSubModal×12 + SSHConsolePage — useI18n + 33 ключа

- fix(dashboard): RuleTestModal.vue — добавлен useI18n; все 10 hardcoded строк заменены на t()
  ruleTestTitle/Hint/Btn/Found/Miss/Rule/Direction/Server/History/Close
- fix(dashboard): ImportSubModal.vue — 12 hardcoded строк заменены на t()
  importSubUrl/OrPaste/Raw/Found/Servers/SelectAll/ClearAll/Group/Back/Add/Added/Errors/Done
  строки с интерполяцией: importSubAdd {n}, importSubAdded {added}, importSubErrors {errors}
- fix(dashboard): SSHConsolePage.vue — добавлен useI18n; 9 строк заменены на t()
  шаблон: sshDisconnect/Connect, sshClear, sshConnected/Disconnected, :placeholder, sshSend
  JS callbacks: sshSessionOpened/Closed/ConnectionClosed в appendOutput через template literals
- feat(i18n): 33 новых ключа в ru.ts и en.ts (основная секция, не tooltips)
  Файлы: RuleTestModal.vue, ImportSubModal.vue, SSHConsolePage.vue, ru.ts, en.ts
  TypeScript 0 ошибок; build ok

## v2.3.38 (2026-05-14) — fix: tooltips DNSFullConfig×7 + GeoConfig×4 + ImportSubModal×4 + DevicesConfig×9 + 18 i18n ключей

- fix(dashboard): DNSFullConfig.vue — 4 кнопки "Тест" (fallback/doh/dot/doq) получили v-tooltip
  dns_test_fallback/doh/dot/doq; кнопки без tooltip не объясняли тип теста и цель
- fix(dashboard): DNSFullConfig.vue — 3 label-text без tooltip: Grace период, IPv4/IPv6 диапазон
  dns_stale_grace, dns_fake_ip_range_v4, dns_fake_ip_range_v6
- fix(dashboard): GeoConfig.vue — 3 th без tooltip (Файл/Записей/Размер) + Статус title= → v-tooltip
  geo_file, geo_records, geo_size, geo_status; импорт useTooltip добавлен в script setup
- fix(dashboard): ImportSubModal.vue — 4 th без tooltip (Имя/Протокол/Адрес/Порт)
  import_name, import_proto, import_addr, import_port; импорт useTooltip добавлен
- fix(dashboard): DevicesConfig.vue — кнопка 🔄 + 9 th без tooltip
  device_reload; device_mac, device_name_ip, device_policy_col, device_proxy_group,
  device_tx, device_rx, device_conn_count, device_status
- feat(i18n): 18 новых tooltip-ключей добавлены в ru.ts и en.ts (секция tooltips)
  Файлы: DNSFullConfig.vue, GeoConfig.vue, ImportSubModal.vue, DevicesConfig.vue, ru.ts, en.ts
  TypeScript 0 ошибок; build 1.52s ok

## v2.3.37 (2026-05-14) — fix: ServerFormModal 21× title= → v-tooltip + 14 i18n ключей + serverName tooltip

- fix(dashboard): ServerFormModal.vue — все 21 вхождение title= заменены на v-tooltip="tip('ключ')"
  native title= не поддерживает tippy.js positioning, mobile touch, overflow control
  httpupgrade <option> title= удалён (tippy к <option> невозможен; Transport label уже имел v-tooltip)
- fix(dashboard): serverName label span — добавлен v-tooltip="tip('server_name')" (B4 закрыт)
- feat(i18n): 14 новых tooltip-ключей в ru.ts и en.ts (секция tooltips)
  Transport: server_grpc_service_name, server_xhttp_path, server_xhttp_host, server_httpupgrade_path
  AmneziaWG: awg_h1, awg_h2, awg_h3, awg_h4, awg_psk, awg_keepalive, awg_mtu, awg_dns_tunnel,
             awg_reserved
  Hysteria2: server_hy2_skip_tls
  Файлы: ServerFormModal.vue, ru.ts, en.ts; TypeScript 0 ошибок; build ok

## v2.3.36 (2026-05-14) — fix: DPI i18n quoted-dot keys + device policy values proxy/bypass/block/default

- fix(i18n): DPI tooltip ключи с quoted-dot синтаксом переименованы в underscore
  'dpi.fake_ttl_value' → dpi_fake_ttl_value; аналогично whitelist_input, blacklist_input
  normalizeKey() конвертирует tip('dpi.fake_ttl_value') → tooltips.dpi_fake_ttl_value;
  quoted-dot ключ не находился через Object property access → tooltip был пустым
- fix(dashboard): DevicesConfig.vue — option values DIRECT/PROXY/REJECT → proxy/bypass/block/default
  backend device_policy_valid() принимает proxy/bypass/block/default (не mihomo-значения)
  HTTP 400 на каждый PATCH /api/devices/{mac} устранён
- fix(dashboard): v-if guard DIRECT/REJECT → default/block (proxy_group input visibility)
- fix(dashboard): badge colors: default/bypass=success, proxy=primary, block=error, группы=neutral
- feat(i18n): policyDefault/Proxy/Bypass/Block добавлены в ru.ts и en.ts (основная секция)
  Файлы: ru.ts, en.ts, DevicesConfig.vue

## v2.3.35 (2026-05-14) — feat: i18n tooltip keys — Overview/Conn/Rules/Devices/Transport/Settings/DNS (33 ключа)

- feat(i18n): добавлены 33 отсутствующих tooltip-ключа в ru.ts и en.ts
  Все ключи вставлены в секцию tooltips: после существующих server_stls_* записей
- feat(i18n/Overview ×5): overview_traffic_chart, overview_rule_hits, overview_topology,
  overview_dpi_toggle, overview_adblock_toggle
- feat(i18n/Connections ×5): conn_close_one, conn_close_all, conn_search, conn_pause,
  conn_destination
- feat(i18n/Rules ×7): rule_type, rule_value, rule_target, rule_enabled, rule_test,
  rule_test_input, rule_delete
- feat(i18n/Devices ×5): device_mac, device_proxy_group, device_tx, device_rx,
  device_conn_count
- feat(i18n/Transport ×7): server_name, server_ws_path, server_ws_host, server_reality_fp,
  server_tuic_cc_profile, server_hy2_obfs, server_hy2_obfs_password
- feat(i18n/Settings ×2): settings_mixed_port, settings_tproxy_port
- feat(i18n/DNS ×1): dns_fake_ip_enable
  TypeScript 0 ошибок; ru.ts и en.ts — паритет ключей

## v2.3.34 (2026-05-14) — fix: vTooltip directive → tippy.js + shift middleware + mobile touch

- fix(dashboard): vTooltip directive переведён с native title= на tippy.js
  native title= не поддерживает позиционирование и не работает на мобильных (hover недоступен)
  tippy.js уже присутствует в зависимостях (package.json), единая система для всех tooltip
- fix(dashboard): добавлен shift modifier (padding: 8px) — tooltip не уходит за край viewport
  при placement='top' на узком экране или у края страницы tooltip сдвигается горизонтально
- fix(dashboard): touch: ['hold', 500] — отображение tooltip на iOS/Android через 500ms удержание
- fix(dashboard): beforeUnmount — destroy() снимает event listeners, устраняет memory leak
- fix(dashboard): updated — реактивное обновление контента при смене языка i18n
  preventOverflow + flip модификаторы: boundary='clippingParents', fallback top/bottom/right/left
  Файл: dashboard-src/src/composables/useTooltip.ts; helper/tooltip.ts — не изменён

## v2.3.33 (2026-05-14) — fix: hardcoded DNS 1.1.1.1/8.8.8.8 → net_get_fallback_dns1/2() в HC-файлах

- fix(net_utils): добавлены net_get_fallback_dns1/2() — getter'ы статических переменных s_fb_dns1/s_fb_dns2
  HC-функции принимают только ServerConfig* и не имеют доступа к g_config;
  getter'ы позволяют получить актуальные UCI-значения без прямой зависимости от config.h
- fix(hc_anytls, hc_tuic, hc_vmess): net_resolve_host_direct — "1.1.1.1"/"8.8.8.8" → getter'ы
- fix(hc_vless): net_resolve_host_direct (строки 490-491) → getter'ы;
  inet_pton строки 158/239 — placeholder IP в протокольном заголовке, сервер игнорирует; не DNS
- fix(dispatcher): inline "8.8.8.8" в fallback ветке upstream_bypass → net_get_fallback_dns2()
  Затронутые файлы: net_utils.h, net_utils.c, dispatcher.c, hc_anytls.c, hc_tuic.c, hc_vless.c, hc_vmess.c
  13 вхождений устранено; 0 hardcoded DNS вне net_utils.c (last-resort дефолт); все тесты ALL PASS; 3.2MB

## v2.3.32 (2026-05-14) — fix: AnyTLS RTT guard + active relay + retry owner_cfg + grpc :status

- fix(anytls): guard rtt_ms > 60000 в anytls_session_update_rtt()
  Патологическое значение (таймаут HC / overflow uint32) фиксировало EWMA на ~64000ms
  → padding lo×2 постоянно упирался в cap=1400; инвариант: RTT > 60с невалиден
- fix(dispatcher): dispatcher_notify_anytls_rtt — обновление активных relay
  Добавлен цикл по conns[]: relay_conn_t с state != RELAY_DONE и совпадающим server_idx
  обновляют собственный anytls_session; CHANGELOG v2.3.29 "active relay update" выполнен
- fix(dispatcher): relay_try_retry — g_config → r->owner_cfg при server lookup
  Инвариант T1-26 "owner_cfg = snapshot": config_get_server(r->owner_cfg, new_idx) вместо
  g_config; после SIGHUP g_config меняется в том же тике dispatcher_tick
- fix(grpc): grpc_header_cb — обработка псевдо-заголовка :status
  grpc_conn_t + grpc_hdr_cb_ctx_t: поле http_status (int, -1=неизвестен)
  При :status != 200 (404/502/503) — errno=ECONNRESET, return -1 без ожидания DATA
  Multiplex path (grpc_stream_t): http_status=NULL — поведение не изменено

## v2.3.31 (2026-05-14) — fix: geo_loader path[264] + WS Bearer auth

- fix(geo): geo_cat_t.path[256] → path[264]
  bin_path[264] в geo_loader.c; musl-gcc -Werror=format-truncation → FAIL при несовпадении;
  устраняет падение test-dns-geosite в cross-mipsel сборке
- fix(http): Bearer auth для /ws/events до WebSocket 101 upgrade
  s_api_token проверяется через header + ?token= QS; 401 до handshake
- fix(http): Bearer + LAN double guard для /ws/console (/ssh) до 101 upgrade
  Bearer check первым; ssh_is_lan_client — вторым; 403 при не-LAN; оба — pre-upgrade

## v2.3.30 (2026-05-14) — docs: ROADMAP + user_context актуализированы

- docs: ROADMAP.md — T1-26/T1-07/T2-06 → ✅ архив; версия v2.3.29
- docs: user_context.md — версия v2.3.29, current state обновлён

## v2.3.29 (2026-05-14) — T2-06 AnyTLS RTT-aware padding

- feat(anytls): BBR-aware RTT-adaptive padding
  anytls_session_t: observed_rtt_ms (EWMA α=0.25 из HC результатов)
  anytls_session_update_rtt(): обновление из HC и активных relay
  anytls_pad_get_size(): +rtt_ms параметр; lo ×1.5 при RTT>100ms, ×2 при RTT>200ms, cap=hi
  anytls_pool_update_rtt(): обновление idle сессий пула
  dispatcher_notify_anytls_rtt(): forward extern — обход circular dep
  proxy_group_handle_hc_event(): вызов notify при каждом успешном HC
  61 тест ALL PASS

## audit_v49 ЗАКРЫТ — 2026-05-14 — все §1–§43, 0 открытых блокеров

Итог v2.3.7–v2.3.25:

- HPACK decoder RFC 7541 нативный (static+dynamic table, Huffman, 6 форматов)
- TUIC v5 DATAGRAM recv (frag reassembly, ring-buffer queue, dispatcher drain)
- DNS TC+EDNS0+SOA NXDOMAIN RFC compliance; dns_static_hosts UCI+API+dashboard
- WS server Ping keepalive 45s/15s timeout
- HTTP keep-alive для REST; DELETE /connections; IPC full-read/write loop
- RELAY_TIMEOUT_CHECK CLOCK_MONOTONIC 1s; DPI_STRAT_DISORDER=4
- IPv6 fake-ip default fd00::/120; bloom OOB fix geo:956
- 25 atomics → memory_order_relaxed; hit_count saturation; sentinel selected_idx=-1
- MIPS stack guards; snprintf truncation; Bearer fix; global rate limit
- Trojan+AnyTLS map_fingerprint() unhard-coded; grpc-status parsing HEADERS frame
- Vision cipher filter 0x1301–0x1304; procd restart без дублей; /ws/events ring buffer

## [2.3.25] — 2026-05-14 — audit_v49 §40

- feat(tuic): TUIC v5 DATAGRAM recv path — UDP relay через QUIC DATAGRAM (RFC 9221)
  tuic_v5.h: tuic_frag_entry_t +addr_str/frag_port; tuic_udp_pkt_t/tuic_udp_queue_t (ring-8);
  tuic_conn_t +udp_q; tuic_conn_recv_udp_datagram() API
  tuic_v5_proto.c: tuic_defrag_add расширен — addr_in/port_in при frag_id==0 сохраняется
  в entry; addr_out/port_out возвращаются при сборке до reset
  tuic_v5_conn.c: tuic_addr_fmt() + tuic_udp_queue_push() helpers;
  tuic_process_incoming() ветка ftype 0x30/0x31 (QUIC DATAGRAM): decode CMD_PACKET,
  frag_total==1 → прямой push; frag_total>1 → defrag + push; tuic_conn_recv_udp_datagram()
  dispatcher.c: RELAY_TUIC_ACTIVE else-ветка — drain udp_q после recv_dispatch →
  write(client_fd) для каждого собранного UDP пакета
  WHY: ранее ftype 0x30/0x31 → else{break} — все QUIC DATAGRAM frames игнорировались;
  UDP relay в native mode не работал

## [2.3.24] — 2026-05-14 — audit_v49 §34

- feat(h2): нативный HPACK decoder RFC 7541 без внешних зависимостей
  h2.h: hpack_dyn_table_t + hpack_header_cb + 4 функции API
  h2.c: static table 61 запись (RFC 7541 Appendix A), Huffman table 257 символов,
  dynamic table ring buffer, decode_int §5.1, huffman_decode §5.2,
  decode_header_block §6 (все 6 форматов: indexed/lit-inc/lit-no-idx/lit-never/size-update)
  callback-API без heap аллокаций (MIPS-safe)
- feat(grpc): HPACK decode в HEADERS frame handler (монолитный + multiplex режимы)
  grpc_conn_t + grpc_stream_t: поля hpack_dyn + grpc_status
  grpc_header_cb: :status + grpc-status; grpc_status != 0 → LOG_WARN
  WHY: ранее payload HEADERS frame дренировался без парсинга — grpc-status игнорировался

## [2.3.23] — 2026-05-14 — audit_v49 §25

- fix(dispatcher): RELAY_TIMEOUT_CHECK — tick_count % N заменён на CLOCK_MONOTONIC порог
  WHY: при нагрузке тик = 1041мс → 100 тиков = ~100с вместо ~1с; зависшие соединения
  обнаруживались с опозданием до 100×; теперь проверка каждые 1000мс реального времени
  RELAY_TIMEOUT_CHECK_INTERVAL_MS=1000 в constants.h
  dispatcher_state_t.last_timeout_check_ms инициализируется при старте (CLOCK_MONOTONIC)
  EC330 ok 2026-05-14

## [2.3.22] — 2026-05-14 — audit_v49 §23-24

- fix(dispatcher): Trojan + AnyTLS — map_fingerprint(server->reality_fingerprint)
  вместо TLS_FP_CHROME120 хардкода (dispatcher.c:1048, 1373)
  NULL-guard в map_fingerprint: пустая строка → TLS_FP_CHROME120 дефолт
- feat(dashboard): dns_static_hosts UI — DNSFullConfig.vue секция hostname→IP
  add/remove строк, PATCH на сохранении, i18n en+ru, tooltips на каждом поле
- feat(api): GET /api/dns → static_hosts JSON array (write_dns_cache)
  PATCH /api/dns → UCI delete+add_list+commit+kill -HUP
- fix(api): убран лишний ,, перед static_hosts блоком в JSON ответе
- fix(dashboard): tooltips на DPI полях: fake_ttl, whitelist_input, blacklist_input

## [2.3.20] — 2026-05-14

### Fixed (audit_v49 §21-22)

**fix(dns): EDNS0 udp_payload_size — согласование UDP MTU (RFC 6891 §6.2.3)**

- `dns_packet.h:31-32` — поля `has_edns` / `edns_udp_size` в `dns_query_t`.
- `dns_cookie.h` — расширена сигнатура `dns_cookie_parse_query` двумя out-параметрами.
- `dns_cookie.c` — при TYPE=41 (OPT RR): CLASS field → `edns_udp_size`, min 512.
- `dns_packet.c` — `dns_parse_query` передаёт `&q->has_edns`, `&q->edns_udp_size`.
- WHY: без EDNS0 сервер слепо отвечал в 512 байт; при EDNS0 можно до 4096 (DNS_MAX_PACKET).

**fix(dns): TC truncation — RFC 1035 §4.2.1**

- `dns_server.c:429-439` — перед `sendto()`: если `final_len > max_udp` → `buf[2] |= 0x02` (TC=1), ответ усекается до `max_udp`.
- `max_udp`: 512 без EDNS0, `min(edns_udp_size, DNS_MAX_PACKET)` с EDNS0.
- WHY: без TC=1 клиент считает ответ полным и не переспрашивает по TCP.

**fix(dns): SOA в Authority section для NXDOMAIN (RFC 2308 §3)**

- `dns_packet.c` `dns_build_nxdomain` — добавлена SOA RR в authority section (NSCOUNT=1).
- SOA: MNAME=localhost, RNAME=hostmaster.localhost, TTL=300, minimum=300.
- Graceful: если буфера (512 B) не хватает — ответ без SOA, NSCOUNT=0.
- WHY: RFC 2308 требует SOA для отрицательного кэширования (negative TTL).

**feat(ws): server-initiated Ping keepalive (RFC 6455 §5.5.2)**

- `ws.h` — объявлен `ws_send_ping(HttpConn*, int epoll_fd)`.
- `ws_frame.c:129-136` — пустой Ping-фрейм (FIN=1, opcode=0x9, payload=0).
- `http_server.h:21-22` — `WS_PING_INTERVAL_S=45`, `WS_PONG_TIMEOUT_S=15`.
- `http_server.h:71-73` — поля `ws_last_ping_ms`, `ws_last_pong_ms`, `ws_ping_pending`.
- `http_server.c` — `WS_OP_PONG` обработчик обновляет `ws_last_pong_ms`; `http_server_tick` отправляет Ping каждые 45 с, закрывает 1001 если нет Pong за 15 с.
- WHY: без keepalive NAT-таблица (idle 60-120 с) рвёт WS-соединение молча.

**EC330 deploy 2026-05-14:** version 2.3.20, 3.2MB ✅
- EDNS0 neg-cache TTL согласован, TC=1 при усечении ✅
- NXDOMAIN содержит SOA в Authority (NSCOUNT=1) ✅
- WS Ping/Pong keepalive активен ✅

## [2.3.19] — 2026-05-14

### Fixed (audit_v49 §20)

**fix(api): PATCH /api/devices — валидация policy**

- `http_server.c:6932` — добавлен хелпер `device_policy_valid(const char *p)`:
  допустимые значения строго: `"proxy"`, `"bypass"`, `"block"`, `"default"`.
- `http_server.c:6972` — ранний return HTTP 400 `{"error":"invalid policy"}` при невалидном значении.
- WHY: произвольная строка из JSON тела записывалась в UCI без проверки через `exec_cmd_safe` (не shell injection, но мусор в конфиге при отсутствии валидации).

**fix(devices): device_traffic_get() — raw MAC вместо escaped**

- `http_server.c:7365` — `device_traffic_get(s_dm, esc_mac)` → `device_traffic_get(s_dm, arp[i].mac)`.
- WHY: функция lookup ожидает оригинальный ключ; esc_mac идемпотентен для MAC, но семантически неверно передавать escaped строку в lookup.

**EC330 deploy 2026-05-14:** version 2.3.19, 3.2MB ✅
- `PATCH {"policy":"bypass"}` → HTTP 200 ✅
- `PATCH {"policy":"hacked_value"}` → HTTP 400 ✅
- `PATCH {"policy":"default"}` → HTTP 200 (откат) ✅

## [2.3.18] — 2026-05-14

### Docs / Chore (audit_v49 §17-19)

**docs: актуализирован CHANGELOG.md v2.3.7–v2.3.17**

- Заполнены записи §3–§16 в CHANGELOG.md.

**chore: .gitignore — репо содержит только README + лого + CHANGELOG**

- `.gitignore`: `*` + исключения `!README.md !CHANGELOG.md !4eburNet.png !.gitignore`.

## [2.3.17] — 2026-05-14

### Added (audit_v49 §16)

**feat(test): smoke-тесты HC — vmess, anytls, tuic**

- `core/tests/test_hc_vmess.c` — 6 PASS: T1-T3 NULL guards (ctx/host/group=NULL), T4 ECONNREFUSED реальный TCP.
- `core/tests/test_hc_anytls.c` — 4 PASS: T1 NULL guards, T2 ECONNREFUSED.
- `core/tests/test_hc_tuic.c` — 4 PASS: T1 NULL guards, T2 QUIC недоступный UDP-сервер.
- `Makefile.dev`: цели `test-hc-vmess`, `test-hc-anytls`, `test-hc-tuic` добавлены в `test:` и `.PHONY`.
- fix: `tuic_uuid strncpy n=sizeof` (не n-1) — поле ровно 37 байт с нуль-терминатором.

**EC330 deploy 2026-05-14:** version 2.3.17, 3.2MB, 0 warnings ✅

## [2.3.16] — 2026-05-14

### Fixed (audit_v49 §15)

**fix(config): fallback DNS UCI-configurable**

- `config.h` — `DnsConfig`: поля `fallback_dns1[46]`, `fallback_dns2[46]`.
- `config.c` — defaults: `1.1.1.1` / `8.8.8.8`; UCI-парсинг `dns.fallback_dns1` / `dns.fallback_dns2`.
- `net_utils.c` — `s_fb_dns1/s_fb_dns2` + `net_set_fallback_dns()`; 6 хардкодов `1.1.1.1`/`8.8.8.8` заменены.
- `net_utils.h` — объявление `void net_set_fallback_dns(const char*, const char*)`.
- `main.c` — `net_set_fallback_dns()` при старте и SIGHUP reload; `write_dns_cache()` немедленно после reload.
- `http_server.c` — `write_dns_cache` + `dns_map`: поля `fallback_dns1/2` в `GET/PATCH /api/dns`.
- dashboard: поля Fallback DNS 1/2 в `DNSFullConfig.vue`; `ru.ts` + `en.ts` tooltips.

**EC330 deploy 2026-05-14:** version 2.3.16 ✅
- `PATCH /api/dns {fallback_dns1:"9.9.9.9"}` → `GET /api/dns` возвращает новое значение ✅

## [2.3.15] — 2026-05-14

### Fixed (audit_v49 §13)

**fix(config): parse_int_uci — замена strtoul без проверки**

- `config.c` — `mixed_port`, `awg_itime`: заменены `strtoul(..., NULL, 10)` на `parse_int_uci()`.
  WHY: `strtoul` принимал 0 и >65535 без предупреждения; `parse_int_uci` проверяет диапазон и логирует.
- `config.c` — `port_min`/`port_max` в `traffic_rule`: `parse_int_uci` с временным нуль-терминатором
  на позиции разделителя `"-"` диапазона `"50000-65535"`.
  WHY: беззнаковое переполнение давало `port_min=65535` при неверном парсинге.

**fix(config): OOB write при переполнении MAX_DNS_RULES / MAX_DNS_POLICIES**

- `config.c` — при `dns_rule_count >= MAX_DNS_RULES`: `section = SECTION_NONE` (не оставлять `SECTION_DNS_RULE`).
  WHY: последующие `option`-строки писали за пределами `dns_rules[MAX_DNS_RULES]`.
- Добавлен `LOG_WARN` при достижении лимита для обоих массивов.
- note: `MAX_SERVERS=64` — hard error намеренно; для >64 серверов использовать `proxy_provider`.

**EC330 deploy 2026-05-14:** version 2.3.15, 3.2MB ✅

## [2.3.14] — 2026-05-14

### Added (audit_v49 §12)

**feat(dpi): DPI_STRAT_DISORDER=4 — TTL disorder стратегия**

- `dpi_strategy.c/h` — `DPI_STRAT_DISORDER=4`; функция `dpi_disorder()`:
  TTL save → split первых `disorder_split` байт с TTL=`disorder_ttl` → restore → full send.
  WHY: DPI на промежуточном хопе видит первые байты с TTL=1 (не доходят до сервера),
  сервер получает корректный поток с нормальным TTL.
  defaults: `disorder_enabled=false`, `disorder_split=1`, `disorder_ttl=1`.
- `config.c/h` — UCI поля `dpi_disorder_enabled` / `dpi_disorder_split` / `dpi_disorder_ttl`.
- `ipc.c` — `IPC_CMD_DPI_GET` возвращает disorder поля; `IPC_CMD_DPI_SET` применяет их.
- `http_server.c` — `PATCH /api/dpi`: поля `disorder_enabled` / `disorder_split` / `disorder_ttl`.
- `main.c` — `dpi-set` добавлен в `handle_ipc_with_payload` map (payload не передавался).
- docs: `user_context.md` — sniffer активен по умолчанию (`cfg->sniffer.tls_sni=true`).

## [2.3.13] — 2026-05-14

### Fixed / Added (audit_v49 §11)

**feat(dns): реализован механизм dns_static_hosts**

- `config.h:80–89` — `dns_static_host_t { hostname[256], addr[64], is_ipv6 }` +
  `#define DNS_STATIC_HOSTS_MAX 20`; поля `static_hosts[20]` + `static_hosts_count` в `DnsConfig`.
- `config.c` list-блок — добавлена ветка `SECTION_DNS + static_hosts`:
  парсит `domain=ip` из UCI `list static_hosts`; валидирует `inet_pton`; лимит 20 записей.
- `dns_server.c:654` — lookup до cache/upstream: A→IPv4 TTL=300, AAAA→IPv6 TTL=300,
  NODATA для отсутствующего типа; флаг `_sh_answered` + `continue` для skip upstream.
- **Дефект**: первоначальный код вставлен в `option`-блок парсера; `list`-строки
  обрабатываются отдельным блоком → исправлено добавлением ветки в `list`-блок (L1581+).

**fix(ipc): ipc_read_full() + ipc_write_full() — EINTR-safe loop**

- `ipc.c:597` — добавлены `static ssize_t ipc_read_full(fd, buf, n)` и
  `ipc_write_full(fd, buf, n)` с циклом `while (done < n)` и обработкой `EINTR`.
- Заменены все одиночные `read/write` в `ipc_send_command` и `ipc_send_command_payload`.
- WHY: SOCK_STREAM не гарантирует доставку за один вызов — short-read мог молча
  обрезать payload JSON без ошибки.

**fix(dns): дефолт `fake_ip6_range = "fd00::/120"`**

- `config.c:774` — в блоке defaults: `strncpy(cfg->dns.fake_ip6_range, "fd00::/120", ...)`.
- UCI может переопределить; если нет — IPv6 fake-ip пул готов к включению.
- EC330 подтверждено: лог `DNAT redirect: 198.18.0.0/16 и fd00::/120 → :7893` ✅

**fix(config): LOG_WARN при наличии устаревших dns_rule секций**

- `config.c:1620` — `log_msg(LOG_WARN, "config: обнаружено %d секций dns_rule — формат устарел…")`.
- WHY: dns_rule устарел с v1.5.79; без warn пользователь не знает что секции игнорируются.

**EC330 deploy 2026-05-14:** version 2.3.13, 3.1MB ✅
- `test.local=1.2.3.4` → A 1.2.3.4 ✅
- `ntc.party=130.255.77.28` → A 130.255.77.28 (из static_hosts, не fake-ip) ✅
- `jackett=127.0.0.1` → A 127.0.0.1 ✅
- AAAA для IPv4-only хоста → NODATA ✅
- fd00::/120 в DNAT redirect ✅

## [2.3.12] — 2026-05-14

### Added (audit_v49 §10)

**feat(api): реализован DELETE /connections — dispatcher_close_all_relays()**

- `dispatcher.c:~1789` — новая функция `dispatcher_close_all_relays()`: итерирует все
  relay-слоты `[0, conns_max)`, пропускает `RELAY_DONE` (=0, свободные), вызывает
  `relay_free()` для всех активных relay включая UDP.
- `dispatcher.h:402` — добавлено публичное объявление.
- `http_server.c:~3497` — заглушка (204 без действия) заменена реальным вызовом.

**feat(http): HTTP/1.1 keep-alive для REST эндпоинтов**

- `http_server.h` — константы `HTTP_KEEPALIVE_TIMEOUT_S=15`, `HTTP_KEEPALIVE_MAX_REQS=100`;
  поля `HttpConn`: `keepalive`, `req_count`, `keepalive_idle_ms`.
- `http_server.c` — `conn_reset_request(conn, epoll_fd)`: сбрасывает request-поля,
  убирает EPOLLOUT через `epoll_ctl MOD`, записывает `keepalive_idle_ms`.
- `http_dispatch()` — парсинг `Connection:` header; HTTP/1.1 keep-alive по умолчанию;
  инкремент `req_count`.
- `http_send()` — при keepalive: `HTTP/1.1` + `Connection: keep-alive` +
  `Keep-Alive: timeout=15, max=N`; после sync flush → `conn_reset_request()`.
- EPOLLOUT handler — при async flush завершении: keepalive → reset, иначе → close.
- `http_server_tick()` — idle timeout 15с для keepalive соединений; WS исключены.
- `http_send()` — добавлен `case 204: "No Content"` (ранее возвращалось "Error").

**EC330 deploy 2026-05-14:** version 2.3.12, 3.1MB ✅

## [2.3.11] — 2026-05-14

### Fixed (audit_v49 §9)

**fix(geo): OOB access в geo_match_domain_cat — bloom_nbits → suffix_bloom_nbits**

- `geo_loader.c:956` (функция `geo_match_domain_cat`) — `bloom_check` для суффиксного
  bloom передавал `c->bloom_nbits` (размер domain bloom) вместо `c->suffix_bloom_nbits`.
  WHY: если `bloom_domain_size > bloom_suffix_size` в .gbin заголовке — bits[] индекс
  выходит за границы суффиксного bloom массива → OOB read.
  Эталон: `geo_match_domain()` строка 907 — правильно использовала `suffix_bloom_nbits`.
  Также: при синхронизации WSL обнаружено отставание `geo_loader.h` — добавлены
  поля `reload_count`, `last_reload_time`, `last_reload_ok` в `geo_manager_t`.

## [2.3.10] — 2026-05-14

### Fixed (audit_v49 §8)

**fix(package): убраны +kmod-nft-tproxy и +kmod-nft-fib из DEPENDS**

- `Makefile:39` — удалены `+kmod-nft-tproxy` и `+kmod-nft-fib`; добавлен `+kmod-nft-nat`.
  WHY: демон использует mark-based TPROXY (ip rule fwmark 0x01 → table 100 + SO_ORIGINAL_DST),
  `nft tproxy` statement не встречается нигде в nftables.c;
  `fib` expression также не используется.
  `kmod-nft-nat` добавлен явно: `type nat hook prerouting + redirect to :%u`
  используется в `nft_dnat_setup()` для DNAT fake-IP CIDRs.
  `kmod-nft-ct` не добавлен в прямые зависимости: ct-правила активируются только
  в flow offload path (условный, `has_flowtable=true`), kmod-nft-offload транзитивно
  предоставляет ct поддержку при необходимости.

## [2.3.9] — 2026-05-14

### Fixed (audit_v49 §7)

**fix(epoll): DIRECT relay upstream — убран EPOLLOUT из начального EPOLL_CTL_ADD**

- `dispatcher.c:2513-2528` — убран флаг `EPOLLOUT` из `EPOLL_CTL_ADD` при создании relay.
  WHY: upstream уже подключён при переходе в `RELAY_ACTIVE` → `EPOLLOUT` в `ADD`
  вызывал spurious event сразу, до появления данных для записи.
  `EPOLL_CTL_MOD` с `EPOLLOUT` добавляется теперь только при получении `EAGAIN` от `write()`.

**fix(epoll): DIRECT relay — добавлен EPOLLRDHUP на client_fd и upstream_fd**

- `dispatcher.c` — флаг `EPOLLRDHUP` добавлен в маску для обоих fd при `RELAY_ACTIVE`.
  WHY: без `EPOLLRDHUP` half-close детектируется только через `recv()=0`,
  что требует ожидания следующего read-события; `EPOLLRDHUP` позволяет
  немедленно закрыть соединение при TCP FIN от peer.

**fix(vision): удалён raw_fd splice dead code из vision.c/vision.h**

- `vision.c`, `vision.h` — удалён параметр `raw_fd` из `vision_raw_send()`,
  обновлены 4 call-site в dispatcher.c.
  WHY: dispatcher всегда передавал `raw_fd=-1`, код splice-пути никогда
  не активировался, создавал ложное ощущение поддержки zero-copy.

## [2.3.8] — 2026-05-13

### Fixed (audit_v49 §4)

**Производительность: atomics → memory_order_relaxed**

- 25 вызовов `atomic_*` без явного `memory_order` → `_explicit(..., memory_order_relaxed)`
  в `http_server.c`, `ipc.c`, `main.c`, `rules_engine.c` (`g_stats.*`, `hit_count`).
  WHY: seq_cst по умолчанию добавляет лишние memory barrier на MIPS, избыточные
  для счётчиков статистики, где нет зависимости порядка между потоками.

**Корректность: hit_count saturation guard**

- `rules_engine.c:603` — guard против wrap-around `hit_count` при UINT32_MAX.
  WHY: без насыщения счётчик оборачивается в 0 → dashboard показывает 0 для
  активно срабатывающего правила с 4B+ совпадениями.

**Корректность: monotonic timeout в http_server_tick**

- `connected_at`: `time_t` → `uint64_t connected_at_ms` + `CLOCK_MONOTONIC`
  (`http_server.h:39`, `http_server.c`).
  WHY: NTP-прыжок назад сбрасывал elapsed → отрицательное время → соединения
  никогда не тайм-аутили; CLOCK_MONOTONIC устойчив к корректировкам системного времени.

**Корректность: proxy_group selected_idx sentinel 0 → -1**

- `proxy_group.c`: sentinel `selected_idx = 0` заменён на `-1`; guard `> 0` → `!= -1`.
  WHY: 0 — валидный индекс первого сервера; `calloc` инициализировал поле в 0,
  маскируя отсутствие выбора при первом сервере в группе.

**`core/Makefile.dev`:**

- `EBURNET_VERSION := 2.3.8`.

**Верификация EC330 (192.168.2.1, mipsel_24kc, 3.1MB):**

- `version: 2.3.8`, uptime 26s, нет FAIL/panic в логах.
- proxy_group начальный выбор `[0]` → корректен (sentinel -1 скрыт внутри, [0] — реальный выбор).

---

## [2.3.6] — 2026-05-13

### Fixed (T0-02 XTLS Vision Block 1 — P3 закрыт)

**`core/src/proxy/dispatcher.c`:**

- `wolfssl_vless_drain_client()` — аналог `reality_vless_drain_client()` для
  wolfSSL TLS path. Форвардит client→server (inner TLS ClientHello) через
  `vision_write()` пока сервер не ответит VLESS response.
  WHY: xray с xtls-rprx-vision ждёт inner TLS ClientHello перед VLESS response.
  Без drain — deadlock: сервер ждёт ClientHello, dispatcher ждёт VLESS response.
- Forward declaration `wolfssl_vless_drain_client` перед `relay_handle_tls`
  (определение ниже в файле рядом с `reality_vless_drain_client`).
- `RELAY_VLESS_SHAKE` handler — при `ep->is_client && r->vision && (ev & EPOLLIN)`
  вызывает drain (вместо безусловного `return` как раньше).
- Explicit drain после установки `r->state = RELAY_VLESS_SHAKE` (EPOLLET edge
  на client_fd мог быть consumed во время TLS handshake фазы).
- `#if CONFIG_VISION_ENABLED` guard на новые функции и точки вызова.

**`core/Makefile.dev`:**

- `-DCONFIG_VISION_ENABLED=1` добавлен в профили `normal` И `full`.
  WHY: `cross-mipsel` target использует `PROFILE=normal` (L717),
  предыдущий v2.3.5 binary собирался без Vision из-за этого.
- `EBURNET_VERSION ?= 2.3.6`.

**Верификация EC330 (82.202.197.2:52006, Germany #71, VLESS+TLS+Vision без Reality):**

- curl → HTTP/1.1 200 OK + полный HTML Example Domain
- logread:
  - `VLESS: Vision flow активирован (xtls-rprx-vision)` — Block 1 init
  - `TLS_SHAKE→VLESS_SHAKE` → `VLESS handshake завершён` → `VLESS_SHAKE→ACTIVE`
  - `vup_entry: len=1184 cr=0 pr=0 hl=0 fi=1 b[0..7]=75807638 6f190bb8`
    — UUID server prefix совпадает с user_uuid в state
- `relay закрыт Vision: in=667 out=5659 lifetime=4s eof_up=1 eof_cli=1`
- Нет `EOF при чтении ответа`, нет `passthrough detected`, нет `invalid cmd`.

## [2.3.5] — 2026-05-13

### Fixed (T0-02 XTLS Vision Block 1 hardening — P3)

**`core/include/proxy/protocols/vision.h`:**

- `vision_state_t`: добавлены поля:
  - `enable_xtls` (bool) — gate для cmd=Direct: TLS 1.3 И cipher ∈ {0x1301..0x1304}
  - `cipher_suite` (uint16_t) — TLS 1.3 cipher из ServerHello (0 = unknown)
  - `remaining_srv_hello` (uint16_t) — окно парсинга split ServerHello records

**`core/src/proxy/protocols/vision.c`:**

- `vision_filter_tls()` — добавлен парсинг cipher_suite из ServerHello:
  при детекте record header 0x16 0x03 0x03 + handshake type 0x02 (SH)
  читаем cipher на offset 43 + session_id_length + 1 (по mihomo
  filter.go:46 / xray proxy.go аналог). enable_xtls выставляется при
  is_tls12_above=true И cipher ∈ whitelist TLS 1.3 ciphers исключая
  0x1305 (TLS_AES_128_CCM_8_SHA256, как xray proxy.go:507).

- `vision_write()` — три исправления для production-readiness Block 1:

  **1) enableXTLS gate перед cmd=Direct:**
  cmd=Direct устанавливается только когда `v->enable_xtls=true`.
  При AppData в TLS 1.2 / CCM_8 cipher → cmd=End (как mihomo
  conn.go:209-216 для enableXTLS=false).
  WHY: xray-server закрывает соединение при cmd=Direct на TLS 1.2 —
  state-machine на сервере ожидает cmd=End для non-XTLS режима.

  **2) isCompleteRecord проверка:**
  TLS record header (5 байт: 0x17 0x03 0x03 + length BE на offset 3..4)
  парсится перед выставлением cmd=Direct; при partial record (total > remaining)
  → chunk_len=remaining без перехода в Direct. Аналог xray
  IsCompleteRecord (proxy.go:407) и vision_write_ex L576-589.
  WHY: partial AppData + cmd=Direct → сервер читает мусор → close
  соединения после неполного record.

  **3) XTLS splice removed:**
  После cmd=Direct остаток данных идёт через `vision_raw_send(... -1, ...)`
  (wolfSSL_write), а не через `tls_raw_fd()` (raw TCP). Поле
  `splice_write` в struct оставлено для совместимости sizeof, но
  больше не выставляется.
  WHY: wolfSSL может иметь pending TLS record write в kernel buffer.
  Прямой raw TCP send попадал посередине незавершённого outer TLS
  record → corrupted stream → server close после первых ~55-57 байт
  raw данных (вероятная природа исторического "plateau"). vision_write_ex
  (Reality path) уже делал это правильно (всё через reality_send).

**`core/src/proxy/dispatcher.c`:**

- L4175-4177 комментарий обновлён: Block 1 hardened, ожидает тестового
  VLESS+TLS+Vision сервера (без Reality) для верификации.

**Поведение:**

- `CONFIG_VISION_ENABLED` остаётся 0 — Block 1 ВЫКЛЮЧЕН в runtime.
- Block 2 (Reality + Vision) не затронут — vision_write_ex используется там.
- Новые поля enable_xtls / cipher_suite будут заполняться и для Reality
  path (vision_filter_tls общая), но vision_write_ex их не читает —
  поведение Reality неизменно.
- Бинарник: 3.1MB mipsel, `-Werror` пройден.

## [2.3.3] — 2026-05-13

### Fixed (restart race bind(:53) — P1)

**`luci-app-4eburnet/files/4eburnet.init`:**

- `port_wait(port, max_iter)` — новый helper: опрашивает `/proc/net/udp[6]` каждые 1с
  (busybox sleep не поддерживает дробные секунды). При таймауте — `logger` daemon.warn.
- `tcp_port_wait(port, max_iter)` — аналог для TCP через `/proc/net/tcp[6]`.
- `stop_service()` — убран `kill -TERM` и `sleep 1`. Только cleanup: dhcp_option 6,
  nft table, ip rule. Сигнал не отправляем: preemptive kill вызывал procd respawn
  (procd расценивал смерть как crash) → orphan процесс захватывал :53 раньше нового.
- `start_service()` — pre-flight проверка: если `:dns_port` занят (UDP или TCP) →
  `port_wait` + `tcp_port_wait` с диагностическим логом. Страховка на случай задержки
  ядра при освобождении сокета.
- `restart()` — новый override rc.common restart():
  1. `stop_service` (cleanup без сигнала)
  2. `ubus call service delete` — halt=true в procd, respawn отключён
  3. `pgrep 4eburnetd` poll max 15с — ждём завершения ВСЕХ экземпляров включая orphan
  4. `killall -9 4eburnetd` если процессы ещё живы после 15с
  5. `port_wait` + `tcp_port_wait` (страховка сокетов)
  6. `start` — создаёт новый procd instance
  WHY: `procd_kill` в rc.common `stop()` асинхронный; `start()` вызывается до реального
  завершения процесса → два экземпляра конкурируют за :53. `ubus delete` + pgrep-wait
  гарантирует что порт свободен до `start`.

**Верификация EC330 (2026-05-13):**

- restart × 5 (sleep 1): ровно 1 процесс на каждый перезапуск ✓
- Ни одной ошибки `bind(TCP :53): Address in use` ✓
- reload (SIGHUP): PID не меняется ✓

## [2.3.2] — 2026-05-13

### Added (PWA + мобильная адаптация)

**Dashboard (`dashboard-src/`):**
- `vite.config.ts` — VitePWA manifest: `name="4eburNet Dashboard"`, `short_name="4eburNet"`,
  `theme_color="#1d232a"`, `background_color="#1d232a"`, `display="standalone"`,
  `orientation="portrait"`, `start_url="/"`;
  Workbox: `globPatterns` кеш статики (js/css/html/ico/png/svg/woff2),
  `NetworkOnly` для `/api|proxies|connections|rules|providers|configs|traffic|logs` и `/ws/`
  (предотвращает кеширование API-ответов при установке PWA),
  `cleanupOutdatedCaches: true`.
- `index.html` — мета-теги PWA: `mobile-web-app-capable`, `apple-mobile-web-app-capable`,
  `apple-mobile-web-app-status-bar-style: black-translucent`,
  `apple-mobile-web-app-title: 4eburNet`, `theme-color: #1d232a`.
- `dist/` — `manifest.webmanifest`, `sw.js`, `workbox-*.js`, иконки
  `pwa-192x192.png` / `pwa-512x512.png` / `pwa-maskable-*.png` (все уже были в `public/`).

*Примечание: мобильная навигация (bottom dock bar при max-width:768px, sidebar скрыт,
safe-area-inset-bottom, swipe-жесты) уже реализована в апстриме zashboard.*

## [2.3.1] — 2026-05-13

### Added (5 типов прокси-групп + load_balance strategy + fastest-whitelist)

**Backend (`core/`):**
- `include/config.h` — `PROXY_GROUP_FASTEST_WHITELIST = 4` в `proxy_group_type_t`;
  поле `load_balance_strategy[32]` в `ProxyGroupConfig`.
- `include/proxy/proxy_group.h` — `load_balance_strategy[32]` в `proxy_group_state_t`
  для O(1) доступа при выборе сервера без обращения к массиву конфигов.
- `src/config.c` — парсинг типов `"fastest-whitelist"` / `"fastest_whitelist"`;
  парсинг поля `load_balance_strategy` с обрезкой до 31 символа.
- `src/proxy/proxy_group.c`:
  - `is_cdn_server()` — эвристика по SNI/address (cloudflare.com, fastly.net, akamai.net,
    akamaiedge.net, edgekey.net, edgesuite.net, cloudfront.net, googlevideo.com);
    не требует резолвинга IP, мгновенная проверка.
  - `PROXY_GROUP_FASTEST_WHITELIST` в `proxy_group_select_server()`: из доступных серверов
    выбирает CDN-сервер с наименьшей задержкой; fallback — лучший из всех серверов.
  - HC stagger, `proxy_group_restore_all_selections`, все три failover функции,
    HC spawn condition обновлены: `FASTEST_WHITELIST` трактуется как `URL_TEST`.
  - `proxy_group_init`: копирование `load_balance_strategy` из конфига в состояние.
- `src/http_server.c`:
  - `uci_group_to_clash()` — `case 4` → `"fastest-whitelist"`.
  - GET `/proxies` — поле `"strategy"` в JSON для `LOAD_BALANCE` групп.
  - PATCH `/api/groups/{name}` — приём полей `"type"` (kebab-case → UCI маппинг:
    select/url-test/fallback/load-balance/fastest-whitelist) и `"load_balance_strategy"`.

**Dashboard (`dashboard-src/src/`):**
- `components/proxies/ProxyGroupEditModal.vue` — переписан: `<select>` из 5 типов;
  условные поля URL/interval/tolerance/filter/strategy в зависимости от типа;
  inline-описание каждого типа; `v-tooltip` на всех полях; `clashToFormType()` маппинг
  Clash API типов → form-значения; `showUrlField`, `showIntervalField`,
  `showToleranceField`, `showStrategyField` computed-свойства.
- `components/proxies/ProxyGroup.vue` — кнопка Edit расширена на все 5 типов
  (включая Selector и fastest-whitelist); в `initial` переданы `type` и `strategy`.
- `i18n/ru.ts` + `i18n/en.ts` — 6 новых tooltip-ключей в секции `tooltips`:
  `proxy_group_type`, `proxy_group_strategy`, `proxy_group_edit_url`,
  `proxy_group_edit_interval`, `proxy_group_edit_tolerance`, `proxy_group_edit_filter`.

## [2.2.9] — 2026-05-13

### Added (Events WebSocket stream + Toast notifications)

**Backend (`core/`):**
- `include/ws.h` — `WS_ROUTE_EVENTS = 7` для нового `/ws/events` маршрута.
- `include/http_server.h` — публичный API `http_server_emit_event(json)`.
- `src/http_server.c` — статический ring buffer `s_events_ring[10][256]`;
  `ws_events_broadcast()`, `ws_events_send_history()`, `http_server_emit_event()`;
  `/ws/events` WS upgrade routing; при подключении клиент получает историю 10 событий.
- `src/proxy/proxy_group.c` — 6 точек emit:
  `server_down`/`server_up` в `proxy_group_update_result`, `proxy_group_handle_hc_event`,
  `proxy_group_mark_server_fail`, `proxy_group_mark_server_fail_immediate`,
  `proxy_group_mark_server_fail_for_group`; guard `was_available != available` исключает
  спам при каждом HC раунде; `proxy_switched` (reason: url-test / failover) в
  `handle_hc_event` round-complete и немедленных failover точках.
- `src/proxy/proxy_provider.c` — emit `provider_updated` с `total/added/removed`
  счётчиками (old_cnt из `ps->server_count` до парсинга).
- `src/main.c` — emit `geo_reloaded` (categories, count) и `daemon_reload` (reason: sighup).

**Dashboard (`dashboard-src/src/`):**
- `api/index.ts` — `fetchEventsAPI<T>()` через `createWebSocket<T>('ws/events')`.
- `composables/useEventStream.ts` — синглтон-composable; глобальный `eventLog` ref
  (до 50 событий); toast через `showNotification` с i18n; вызывается один раз из App.vue.
- `i18n/ru.ts` + `i18n/en.ts` — 8 новых ключей: `events_log`, `events_empty`,
  `evt_server_down/up`, `evt_provider_updated`, `evt_geo_reloaded`,
  `evt_daemon_reload`, `evt_proxy_switched`.
- `constant/index.ts` — `EventsLog = 'EventsLog'` в `OVERVIEW_CARD` enum.
- `components/overview/EventsLog.vue` — карточка Overview: иконка + цвет по типу
  события, `formatEvent()` через i18n с параметрами, max-h-48 scroll.
- `views/OverviewPage.vue` — импорт и регистрация `EventsLog` в `cardComponents`.
- `App.vue` — `useEventStream()` при старте приложения.

## [2.2.8] — 2026-05-13

### Fixed + Added (Rule tester + Subscription import preview)

**Backend (`core/src/http_server.c`):**
- `route_api_rules_test()` — полностью переписан через `rules_engine_match()`:
  поддержка всех типов правил (DOMAIN, IP-CIDR, GEOIP, GEOSITE, RULE-SET,
  AND/OR, REGEX, SRC/DST-PORT, PROCESS-NAME); определение домен vs IP через
  `inet_pton`; ответ расширен: `rule_type` + `payload` + `selected_server` +
  `latency_ms` (UINT32_MAX → 0 guard для непроверенных серверов).
  Удалён UCI-парсинг-костыль (131KB буфер, поддержка только 4 типов).
- `route_api_subscribe_parse()` — добавлен URL-download: если `data` пустой,
  скачивает подписку по `url` через `net_http_fetch()` в `/tmp/`; YAML-ветка:
  исправлено поле `"server"` → `"address"` (несоответствие с ParsedServer type).
- `config.h` / `config.c` — поле `vmess_security` в `ServerConfig` + парсинг
  в `apply_server_option()` (из v2.2.7, не попало в предыдущий коммит).

**Dashboard (`dashboard-src/src/`):**
- `api/index.ts` — `RuleTestResult`: `rule` → `rule_type`, добавлены
  `selected_server: string | null` и `latency_ms: number`.
- `components/rules/RuleTestModal.vue` — показывает `rule_type + payload`,
  сервер + latency badge; история тестов обновлена под новый формат.

**Пакет (`luci-app-4eburnet/Makefile`):**
- `postinst` — при установке: переводит dnsmasq с :53 на :5353 (idempotent),
  запускает 4eburnetd и добавляет в автозагрузку; путь UCI исправлен:
  `dhcp.@dnsmasq[0].port` (не `dnsmasq.@dnsmasq[0].port`).
- `prerm` — при удалении: останавливает демон, возвращает dnsmasq на :53.

## [2.2.6] — 2026-05-13

### Added (Latency sparklines + Topology placeholder)

**Backend (`core/`):**

- `proxy_group.h` — `group_server_state_t`: поля `latency_ring[20]` (uint16_t,
  кольцевой буфер последних 20 HC результатов) и `latency_ring_pos` (uint8_t,
  позиция следующей записи). 0 = таймаут/неизвестно. 41 байт на сервер.
- `proxy_group.c` — `proxy_group_handle_hc_event()`: запись в ring buffer при
  каждом HC результате — success → latency_ms, fail → 0.
- `proxy_group.c` — `proxy_group_update_result()`: аналогичная запись для
  дополнительного пути обновления latency.
- `http_server.c` — добавлена `pgm_server_state()`: возвращает первую
  `group_server_state_t` для сервера с непустым ring buffer.
- `http_server.c` — `route_clash_proxies()`: поле `"history"` для серверов
  теперь содержит до 20 точек из ring buffer с приближёнными таймштампами
  (шаг 30с). Заменяет прежнюю единственную точку.

**Dashboard (`dashboard-src/src/`):**

- `components/proxies/LatencySparkline.vue` — новый компонент: SVG polyline
  60×20px из `proxy.history[]`; цвет по последней задержке (≤200ms зелёный,
  ≤500ms жёлтый, >500ms/таймаут красный); tooltip с последними 5 значениями.
  Скрывается при `proxyCardSize === SMALL` и когда history < 2 точек.
- `components/proxies/ProxyNodeCard.vue` — встроен `LatencySparkline` слева
  от `LatencyTag` в строке с typeDescription; обёрнут в flex-gap контейнер.
- `components/overview/TopologyCharts.vue` — placeholder при отсутствии
  соединений заменён на информативный: заголовок "Нет активных соединений" +
  подсказка "Схема появится при наличии трафика через прокси".
- `components/overview/TopologyCharts.vue` — Sankey узлы источника используют
  `sourceAlias` (alias устройства из device policy) вместо всегда-пустого
  `sourceIP`.
- `i18n/ru.ts` + `en.ts` — 3 новых ключа: `topologyNoDataTitle`,
  `topologyNoDataHint`, `unknownDevice`.

## [2.2.5] — 2026-05-13

### Fixed (gRPC CLOSE-WAIT накопление)

**Backend (`core/`):**

- `grpc.c` — добавлена `grpc_tls_drain(WOLFSSL *ssl, int tcp_fd)`: вызывает
  `wolfSSL_shutdown` (отправляет TLS close_notify), затем drain loop
  (SO_RCVTIMEO=2с, лимит 16 итераций, static drain_buf[512]).
  WHY: без drain удалённый сервер продолжает слать данные после close_notify
  → ядро не может завершить TCP → CLOSE-WAIT накапливается при долгой работе.
- `grpc.c` — `grpc_pool_tick` (idle timeout teardown): вызов `grpc_tls_drain`
  перед `wolfSSL_free` + `close(tcp_fd)`.
- `grpc.c` — `grpc_pool_free` (полное освобождение пула): аналогичный вызов
  `grpc_tls_drain` для консистентности teardown обоих путей.
- `grpc.c` — добавлены `#include <sys/socket.h>` и `#include <sys/time.h>`
  для `setsockopt` + `struct timeval`.

### Added (SS2022/VMess/ShadowTLS в ServerFormModal)

**Backend (`core/`):**

- `config.h` — `vmess_security[16]` в `ServerConfig`
  (VMess AEAD security: "auto"/"aes-128-gcm"/"chacha20-poly1305"/"none").
- `config.c` — чтение UCI ключа `vmess_security` в `ServerConfig`.
- `http_server.c` — `route_api_servers_post`: добавлены чтение и UCI set
  для `ss_method` и `vmess_security`.
- `http_server.c` — `route_api_servers_put` (flds[]): добавлены
  `"ss_method"` и `"vmess_security"`.

**Dashboard (`dashboard-src/src/`):**

- `ServerFormModal.vue` — тип `ss` (Shadowsocks): поле `cipher` переименовано
  в `ss_method`; добавлена группа Legacy (aes-128-gcm, aes-256-gcm,
  chacha20-ietf-poly1305) рядом с SS2022; tooltip `server_ss_method`.
- `ServerFormModal.vue` — тип `vmess`: добавлен badge "Alter ID: 0 (VMess AEAD)"
  с tooltip и select `vmess_security` (auto/aes-128-gcm/chacha20-poly1305/none).
- `ServerFormModal.vue` — тип `shadowtls`: замена `title=""` на
  `v-tooltip="tip('server_stls_*')"` для обоих полей.
- `i18n/ru.ts` + `en.ts` — 5 новых ключей: `server_ss_method`,
  `server_vmess_alter_id`, `server_vmess_security`,
  `server_stls_password`, `server_stls_sni`.

**Верификация EC330 (2026-05-13):**

- Демон жив после деплоя ✓
- CLOSE-WAIT = 0 сразу после рестарта ✓
- Требуется проверка в браузере (:8080 → Proxies → Add Server)

## [2.2.4] — 2026-05-13

### Fixed (/proxies buffer overflow + AWG serialization)

**Backend (`core/`):**

- `http_server.c` — `route_clash_proxies`: `static char buf[65536]` → `buf[262144]`.
  WHY: при >~150 серверах (провайдеры + статика) `pos >= max-256` молча обрезало
  оставшиеся серверы — в дашборде пропадали десятки серверов.
- `http_server.c` — `route_clash_proxies`: добавлен `awg_kv = ",\"awg\":true"` для
  серверов с `protocol="awg"/"wg"` по паттерну `tuic_kv`/`anytls_kv`.
  WHY: zashboard распознаёт `"awg":true` как тег протокола (аналогично xudp/tuic).

**Верификация EC330 (2026-05-13):**
- GET /proxies: 116 прокси (10 групп + 104 сервера) — все видны ✓
- AWG: 5 серверов (WARP-IPv4, AWG 1.5 ×2 и др.) отображаются с `"awg":true` ✓

## [2.2.3] — 2026-05-13

### Added (OR builder + Rule hit counter)

**Backend (`core/`):**

- `config.h` — `TrafficRule.value[256]` → `value[1024]` (OR conditions при 256 ограничивались ~3-5 условиями)
- `config.h` — `_Atomic uint32_t hit_count` в `TrafficRule` (thread-safe счётчик срабатываний, сбрасывается при reload)
- `config.h` — `#include <stdatomic.h>`
- `rules_engine.h` / `rules_engine.c` — `atomic_fetch_add(&tr->hit_count, 1)` при каждом match; `tr` стал non-const для записи счётчика
- `http_server.h` — `http_server_set_re(rules_engine_t *re)` — передача указателя на rules_engine для hit_count в GET /rules
- `http_server.c` — `s_re` глобальный указатель на `rules_engine_t`
- `http_server.c` — `rule_type_to_str()` — добавлены case для `IP-CIDR6`, `SRC-PORT`, `PROCESS-NAME`, `AND`, `OR`, `REGEX` (ранее возвращали `"UNKNOWN"`)
- `http_server.c` — `route_clash_rules()` — добавлены `sub_conditions` (для OR) и `extra.hitCount/hitAt/missAt/missCount/disabled` для каждого правила; буфер 32KB → 128KB (399 правил × ~200 байт)
- `http_server.c` — `route_api_rules_post()` — добавлены `OR`, `REGEX`, `PROCESS-NAME` в valid_rtypes; парсинг JSON массива `or_conditions[]` → UCI `add_list or_condition`
- `http_server.c` — `route_api_rules_patch()` — парсинг `or_conditions[]` → удаление старого UCI list + добавление нового
- `main.c` — `http_server_set_re(&re_state)` при старте и при SIGHUP reload

**Dashboard (`dashboard-src/src/`):**

- `components/rules/RuleFormModal.vue` — динамический OR builder: строки `select(type) + input(value) + ✕`, кнопка "+ Добавить условие"; при открытии OR правила на редактирование заполняется из `rule.sub_conditions`; тип OR больше не требует поля value
- `views/RulesPage.vue` — polling `fetchRules()` каждые 10 секунд через `setInterval/clearInterval` (для обновления hit_count в badge)
- `api/index.ts` — `OrCondition` interface + `or_conditions?: OrCondition[]` в `RuleConfig`
- `i18n/ru.ts` + `en.ts` — 2 ключа: `rule_add_or_condition`, `rule_hits`

### Fixed (v2.2.3)

- `rule_type_to_str()` возвращал `"UNKNOWN"` для OR/AND/REGEX/SRC-PORT/PROCESS-NAME — dashboard показывал неправильный тип правила

---

## [2.2.2] — 2026-05-13

### Added (Device CRUD: alias / comment / enabled / priority)

**Backend (`core/`):**

- `Makefile.dev` — версия 2.2.2
- `http_server.c` — `GET /api/devices`: возвращает все устройства из `device_state` в формате JSON
  (`mac`, `alias`, `comment`, `policy`, `group`, `enabled`, `priority`)
- `http_server.c` — `PATCH /api/devices/{mac}`: принимает любое подмножество полей
  (`alias`, `comment`, `policy`, `group`, `enabled`, `priority`), обновляет UCI секцию
  типа `device_policy`, вызывает `reload_daemon()`

**Dashboard (`dashboard-src/src/`):**

- `components/settings/DevicesConfig.vue` — таблица устройств: 12 колонок, инлайн-редактирование
  `alias`, `comment`, `policy`, `group`, `enabled`, `priority`; ARP-lookup; `PATCH` on blur/change
- `api/index.ts` — `getDevicesAPI()`, расширенный `patchDeviceAPI` с полями alias/comment/enabled/priority
- `types/index.d.ts` — `sourceAlias: string` в `ConnectionRawMessage.metadata`
- `components/connections/ConnectionTable.vue` — колонка `Source`: показывает `sourceAlias` если задан,
  иначе `sourceIP`
- `i18n/ru.ts` + `en.ts` — 5 новых ключей: `dev_alias`, `dev_comment`, `dev_enabled`,
  `dev_priority`, `dev_policy`

### Fixed

**Backend (`core/`):**

- `main.c` — `device_policy_init` теперь вызывается при `device_count > 0`
  без требования `lan_interface` (WHY: без этого device_state.count=0,
  alias/priority никогда не загружались — корневая причина пустого alias в GET /api/devices)
- `main.c` — SIGHUP reload handler: аналогичное исправление — init выполняется всегда,
  `device_policy_apply` — только если `lan_interface` задан
- `http_server.c` — тип UCI секции исправлен с `device_config` на `device_policy`
  (WHY: config.c распознаёт только `device_policy`; старый тип → секции
  не читались при перезагрузке демона)
- `config.c` — добавлен `devices: %d` в лог "Конфиг загружен" (диагностика)

**Верификация EC330 (2026-05-13):**

- `GET /api/devices` → `"alias":"iPhone","priority":1` ✓
- `PATCH /api/devices/e8:80:88:77:4c:b0` `{"alias":"iPhone"}` → UCI сохранён ✓
- Лог: "Устройства загружены: 1" при старте и SIGHUP ✓

---

## [2.2.1] — 2026-05-13

### Added (Logs download + log_level runtime + CDN config)

**Backend (`core/`):**
- `Makefile.dev` — версия 2.2.1
- `http_server.c` — `GET /api/logs/download`: отдаёт `/tmp/4eburnet.log` как file attachment
  (`Content-Disposition: attachment; filename="4eburnet.log"`); async chunked через
  `http_send_file_continue`; 404 JSON если файл не найден
- `http_server.c` — `PATCH /configs`: поле `"log-level"` уже принималось; `changed=true` →
  `kill(SIGHUP)` → `config_load` читает новый `log_level` из UCI — без перезапуска демона
- `http_server.c` — `GET /api/cdn`: возвращает все 6 CDN полей из `s_cfg`
  (`cdn_update_interval_days`, `cdn_cf_v4_url`, `cdn_cf_v6_url`, `cdn_fastly_url`,
  `opencck_url`, `opencck_update_interval_s`)
- `http_server.c` — `PATCH /api/cdn`: принимает JSON, обновляет UCI поля `main` секции,
  `uci commit` + `reload_daemon()`; строковые URL поля валидируются (пусто или `https://`)

**Dashboard (`dashboard-src/src/`):**
- `components/controls/LogsCtrl.tsx` — кнопка `DocumentArrowDownIcon`: скачивает полный
  `/tmp/4eburnet.log` через `fetch()` + `Blob` + Bearer header (token не попадает в URL)
- `components/controls/LogsCtrl.tsx` — `onChange` levelSelect: `PATCH /configs {"log-level"}`
  → 500ms → `initLogs()` (WS переподключается уже с новым уровнем); `onMounted` синхронизирует
  `logLevel` из `GET /configs`
- `components/settings/CDNConfig.vue` — новый компонент: 6 полей CDN настроек с tooltips,
  `@change` автосохранение через `PATCH /api/cdn`
- `components/settings/backend/BackendSettings.vue` — встроена секция CDN Auto-Update
- `api/index.ts` — `getCDNConfigAPI()` + `patchCDNConfigAPI()`
- `i18n/ru.ts` + `en.ts` — 7 новых ключей: `logs_log_level_runtime`, `adv_cdn_interval`,
  `adv_opencck_url`, `adv_opencck_interval`, `downloadMemLogs`, `downloadFullLog`

**Верификация EC330 (2026-05-13):**
- `GET /api/logs/download` → 507744 байт полного лога ✓
- `PATCH /configs {"log-level":"debug"}` → SIGHUP → PID жив ✓
- `GET /api/cdn` → все 6 полей JSON ✓
- `PATCH /api/cdn` → `cdn_update_interval_days='7'` + `opencck_update_interval_s='86400'` в UCI ✓

---

## [2.2.0.1] — 2026-05-12

### Fixed (SIGHUP DNS rebind crash-loop)

**Backend (`core/`):**

- `main.c` — SIGHUP при неизменном DNS порту больше не вызывает EADDRINUSE crash-loop.
  Сохраняем `old_dns_port` до `config_free()`, сравниваем с `new_dns_port`: если порт не изменился
  и DNS включён — обновляем `dns_state.cfg`/cache-настройки без close/rebind сокета.
  Полный rebind только при смене порта или отключении DNS.
- `main.c` — В ветке `dns_port_unchanged` обновляется `dns_state.fake_ip.cfg = cfg_ptr`
  (WHY: `fake_ip_table_t` хранит raw `EburNetConfig*` и читает `cfg->dns.fake_ip_ttl` при каждом
  запросе — без обновления → dangling pointer → SIGSEGV).
- `http_server.c` — `route_clash_configs_patch`: возвращён `changed = true` для блоков
  `inbound_auth`, `inbound_username`, `inbound_password` (был убран как workaround crash-loop).
  Все PATCH-endpoints теперь безопасно вызывают `reload_daemon()`.
- `Makefile.dev` — версия 2.2.0.1

---

## [2.2.0] — 2026-05-12

### Added (JA4 column + Status summary card + Inbound auth)

**Backend (`core/`):**
- `Makefile.dev` — версия 2.2.0
- `http_server.c` — `GET /configs`: добавлены поля `inbound_auth` (bool) и `inbound_username` в ответ; буфер 768→896 байт
- `http_server.c` — `PATCH /configs`: обработка `inbound_auth` (via `http_json_get_val`, unquoted bool), `inbound_username`, `inbound_password`; UCI commit + live s_cfg update без SIGHUP (избегает race на bind :53)
- `http_server.c` — `GET /connections`: поле `ja4` присутствовало, подтверждено

**Dashboard (`dashboard-src/src/`):**
- `constant/index.ts` — `CONNECTIONS_TABLE_ACCESSOR_KEY.JA4 = 'ja4'`; `OVERVIEW_CARD.StatusSummaryCard`
- `components/connections/ConnectionTable.vue` — колонка JA4 (hidden-by-default, как JA3); entry в columnWidthMap
- `components/overview/StatusSummaryCard.vue` — новый компонент: 4 tiles (conn_active + uptime + upload + download); polling `/api/status` каждые 5s; clearInterval в onUnmounted; upload/download из `store/connections`
- `components/overview/ChartsCard.vue` — исправлен баг: `active_relay_count` → `conn_active`
- `views/OverviewPage.vue` — импорт + регистрация StatusSummaryCard в cardComponents
- `store/settings.ts` — StatusSummaryCard первой в defaultOverviewCardOrder
- `components/settings/backend/BackendSettings.vue` — секция Inbound Auth: toggle + v-if поля username/password; `useTooltip` + tooltips на каждом элементе
- `types/index.d.ts` — `Config.inbound_auth?: boolean`, `Config.inbound_username?: string`
- `store/config.ts` — defaults: `inbound_auth: false, inbound_username: ''`
- `i18n/ru.ts` + `en.ts` — 11 новых ключей: `ja4`, `uptime`, `statusSummaryCard` + 8 tooltip ключей (`conn_ja4`, `overview_*`, `settings_inbound_*`)

---

## [2.1.7] — 2026-05-12

### Added (Proxy Group Edit Modal)

**Backend (`core/src/http_server.c`):**

- **`GET /proxies`** — добавлены поля `interval`, `tolerance`, `testUrl`, `filter` для URLTest/Fallback/LoadBalance групп
- **`PATCH /api/groups/{name}`** — изменить url/interval/tolerance_ms/filter proxy-group; UCI uci_set + commit + reload_daemon
- **URL-decode в `route_api_groups_patch`** — `%20` → ` ` (пробелы в именах групп)
- **`uci_find_provider_section`** — убрана проверка `uci_name_safe` (заменена на strlen): группы с пробелами теперь находятся

**Dashboard (`dashboard-src/src/`):**

- **`components/proxies/ProxyGroupEditModal.vue`** — новый модал: поля Healthcheck URL / Интервал / Tolerance / Filter, tooltips, `updateProxyGroupAPI`
- **`components/proxies/ProxyGroup.vue`** — кнопка ✏️ (`PencilSquareIcon`) только для URLTest/Fallback/LoadBalance + `<ProxyGroupEditModal>`
- **`api/index.ts`** — `updateProxyGroupAPI(name, data)` → `PATCH /api/groups/{name}`
- **`types/index.d.ts`** — `Proxy` + `testUrl?/interval?/tolerance?/filter?`
- **`i18n/ru.ts` + `en.ts`** — ключи `editProxyGroup`

**Gotchas:**

- `scp -O` прямо в `/usr/sbin/4eburnetd` при запущенном демоне молча не обновляет файл (inode держится). Правильный путь: scp → `/tmp/` → `cp` → `chmod +x` → restart
- Сборки OpenWrt SDK детерминированные: одинаковый код → одинаковый md5 бинарника
- `uci_name_safe` запрещает пробелы → имена групп типа "ARZA Auto" не проходили

---

## [2.1.6] — 2026-05-12

### Added (Provider Edit Modal)

**Backend (`core/src/http_server.c`):**

- **`PATCH /api/providers/proxies/{name}`** — изменить url/interval/max_servers; поддержка именованных и анонимных UCI секций через итерацию `uci get @proxy_provider[N].name`
- **`PATCH /api/providers/rules/{name}`** — изменить url/interval/behavior
- **`GET /providers/proxies`** — добавлены поля `url` и `interval` в JSON ответ
- **`GET /providers/rules`** — добавлены поля `url` и `interval` в JSON ответ
- **`uci_find_provider_section`** — расширена: поддержка анонимных секций (`@proxy_provider[N]`) через цикл `uci get`, не только именованных

**Dashboard (`dashboard-src/src/`):**

- **`components/providers/ProviderEditModal.vue`** — новый модал: поля url/interval/behavior(rule)/max_servers(proxy), tooltips, `updateProviderConfigAPI`
- **`components/proxies/ProxyProvider.vue`** — кнопка ✏️ (`PencilSquareIcon`) + `<ProviderEditModal>`
- **`components/rules/RuleProvider.vue`** — кнопка ✏️ + `<ProviderEditModal>`
- **`api/index.ts`** — `updateProviderConfigAPI(kind, name, data)` → PATCH
- **`types/index.d.ts`** — `ProxyProvider` + `url?/interval?`, `RuleProvider` + `url?/interval?`
- **`i18n/ru.ts` + `en.ts`** — ключи `editProxyProvider`, `editRuleProvider`

**Диагностика / gotchas:**

- `uci_name_safe` проверяет только [a-zA-Z0-9_-] — провайдеры из sub_convert.py хранятся как `@proxy_provider[N]`, не как именованные секции
- `http_json_get_str` не читает числа без кавычек → для `interval` использован `http_json_get_val`
- `make -f Makefile.dev cross-mipsel` — правильная команда полной пересборки; `make mipsel` использует SDK Makefile и не инкрементально пересобирает при изменениях

---

## [2.1.5] — 2026-05-12

### Added (AWG расширенные поля в ServerFormModal)

**Backend (`core/src/http_server.c`):**

- **`route_api_servers_post`** — парсинг 9 новых AWG полей: `awg_h1-h4`, `awg_psk`, `awg_dns`, `awg_reserved`, `awg_keepalive`, `awg_mtu`; буферы `sd0-sd8` + `SRV_SET_OPT` для каждого
- **`route_api_servers_put`** — добавлены те же 9 полей в массив `flds[]`
- **`server_config_to_uci_anon`** — изменений не требовалось (уже имел UCI_SET для всех AWG полей)

**Dashboard (`dashboard-src/src/components/proxies/ServerFormModal.vue`):**

- **AWG блок** — подсекция «Обфускация заголовков»: H1/H2/H3/H4 (числовые, 2×2 grid, tooltips)
- **AWG блок** — подсекция «Дополнительные параметры»: PSK (base64), Keepalive (сек), MTU, DNS, Reserved (base64/массив)
- **form ref** — 9 новых полей с дефолтами (awg_h1-h4=0, awg_keepalive=0, awg_mtu=0, awg_psk/dns/reserved='')
- **optStr** — добавлены `awg_psk`, `awg_dns`, `awg_reserved`
- **optNum** — добавлены `awg_h1-h4`, `awg_keepalive`, `awg_mtu`
- Tooltips на каждом новом поле

## [2.1.4] — 2026-05-12

### Added (Reality fp + HY2 obfs + ShadowTLS поля в ServerFormModal)

**Backend (`core/src/http_server.c`):**

- **`route_api_servers_post`** — парсинг 6 новых полей: `reality_fingerprint`, `hy2_obfs_enabled`, `hy2_obfs_password`, `hy2_insecure`, `stls_password`, `stls_sni`; буферы `sc0-sc5` + `SRV_SET_OPT` для каждого
- **`route_api_servers_put`** — добавлены те же 6 полей в массив `flds[]`
- **`server_config_to_uci_anon`** — добавлены `hy2_obfs_enabled` (if-блок), `UCI_SET("hy2_obfs_password")`, `UCI_SET("stls_password")`, `UCI_SET("stls_sni")` — поля теперь сохраняются при импорте Clash YAML

**Dashboard (`dashboard-src/src/components/proxies/ServerFormModal.vue`):**

- **Reality блок** (`v-if="form.protocol === 'vless'"`): `<select v-model="form.reality_fingerprint">` с 8 вариантами (chrome/firefox/safari/ios/android/edge/random/randomized)
- **Hysteria2 блок** (`v-if="form.protocol === 'hysteria2'"`): Salamander toggle (`hy2_obfs_enabled`) + пароль (v-if obfs) + Skip TLS verify toggle (`hy2_insecure`)
- **ShadowTLS блок** (`v-if="form.protocol === 'shadowtls'"`): поля `stls_password` (type=password) + `stls_sni`
- **`form` ref**: добавлены `reality_fingerprint:''`, `hy2_obfs_enabled:false`, `hy2_obfs_password:''`, `hy2_insecure:false`, `stls_password:''`, `stls_sni:''`
- **`optStr`**: 4 строковых поля (`reality_fingerprint`, `hy2_obfs_password`, `stls_password`, `stls_sni`)
- **`submit`**: явная обработка булевых — `hy2_insecure`/`hy2_obfs_enabled` → `'1'` если включены
- **Tooltips** на всех новых полях с объяснением назначения

## [2.1.3] — 2026-05-12

### Added (транспортные поля в ServerFormModal)

**Backend (`core/src/http_server.c`):**

- **`route_api_servers_post`** — парсинг 5 новых полей: `ws_path`, `ws_host`, `xhttp_path`, `xhttp_host`, `grpc_service_name`; статические буферы `sb0-sb4` + `SRV_SET_OPT` для каждого
- **`route_api_servers_put`** — добавлены те же 5 полей в массив `flds[]` — теперь обновляются при редактировании
- **`server_config_to_uci_anon`** — добавлен `UCI_SET("grpc_service_name", srv->grpc_service_name)` — фикс потери поля при импорте Clash YAML

**Dashboard (`dashboard-src/src/components/proxies/ServerFormModal.vue`):**

- **Transport select**: добавлен вариант `HTTPUpgrade` (с title-tooltip)
- **WS блок** (`v-if="form.transport === 'ws'"`): поля `ws_path` + `ws_host` с tooltips
- **gRPC блок** (`v-if="form.transport === 'grpc'"`): поле `grpc_service_name` (placeholder `GunService`)
- **XHTTP блок** (`v-if="form.transport === 'xhttp'"`): поля `xhttp_path` + `xhttp_host` с tooltips
- **HTTPUpgrade блок** (`v-if="form.transport === 'httpupgrade'"`): поле `ws_path` (путь для Upgrade запроса)
- **`form` ref**: добавлены `ws_path`, `ws_host`, `grpc_service_name`, `xhttp_path`, `xhttp_host` = `''`
- **`optStr`**: 5 новых полей — включаются в POST/PUT payload если непусты
- **Редактирование**: спред `props.initial` автоматически заполняет поля из существующего сервера

## [2.1.2] — 2026-05-12

### Added (MTU в backend + Delete server кнопка)

**Backend:**

- **[core/include/config.h]** `EburNetConfig.mtu` (uint16_t, 0 = не менять, диапазон 576-9000)
- **[core/src/config.c]** UCI парсинг `mtu`: валидация диапазона + default `cfg->mtu = 0`
- **[core/src/http_server.c]** GET `/api/network`: `mtu` из реального `s_cfg->mtu` (fallback 1500 если 0 / нет конфига); PATCH: числовая обработка `mtu` (0 = убрать UCI, 576-9000 = сохранить)
- **[core/src/main.c]** `#include "net_utils.h"` добавлен; `ip link set dev <lan_iface> mtu <val>` при старте если `mtu > 0`; то же при SIGHUP reload

**Dashboard:**

- **[dashboard-src/src/components/proxies/ProxyNodeCard.vue]** проп `deletable?: boolean`; кнопка ✕ (`opacity-0 group-hover:opacity-100`, позиционирована в top-right); `handleDelete` — confirm + `deleteServerAPI` + `emit('deleted', name)` + `fetchProxies()`; `group` класс на корневом div

## [2.1.1] — 2026-05-12

### Changed (Tooltips в 4 компонентах настроек)

- **[dashboard-src/src/components/settings/DNSFullConfig.vue]** `v-tooltip` на 9 полях: upstream/bypass/DoH/DoT/Fake-IP/Adblock/Trackers/Threats/SWR
- **[dashboard-src/src/components/settings/DPIConfig.vue]** `v-tooltip` на 5 полях: Fragment/FakeTTL/Disorder/Whitelist/Blacklist; inline title на enabled toggle
- **[dashboard-src/src/components/settings/NetworkConfig.vue]** `v-tooltip` на Flow Offload/TC Fast Path; inline title на BBR/MTU
- **[dashboard-src/src/components/providers/AddProviderModal.vue]** inline title на URL/Behavior/Интервал

## [2.1.0] — 2026-05-12

### Added (T1-11 Geo hot-reload + полный dashboard UI)

**Backend:**

- **[core/include/geo/geo_loader.h]** `geo_manager_t`: новые поля `last_reload_time`, `reload_count`, `last_reload_ok`; объявлены `geo_files_changed()` и `geo_hot_reload()`
- **[core/src/geo/geo_loader.c]** `geo_files_changed()`: stat().st_mtime vs loaded_at, O(n) по категориям; `geo_hot_reload()`: итерирует `geo_reload_category()` для каждой категории + обновляет метрики; fix `c->path` обновляется на реальный `.gbin` путь при `.lst`→`.gbin` fallback
- **[core/src/main.c]** Блок `if (state.reload)` — geo hot-reload с проверкой `geo_files_changed()` (пропускает reload если файлы не изменились); обновление счётчиков `last_reload_time/count/ok`; вызовы `http_server_set_geo_manager()` при первом старте и при reload
- **[core/src/ipc.c]** `IPC_CMD_GEO_STATUS`: добавлены поля `reload_count`, `last_reload` (unix ts), `last_reload_ok`, `hot_reload_supported:true` в JSON ответ
- **[core/include/http_server.h]** `http_server_set_geo_manager(const geo_manager_t *gm)` — прямой доступ без IPC (IPC deadlock в single-threaded epoll)
- **[core/src/http_server.c]** `route_api_geo` полностью переработан: прямой доступ через `s_geo`, `geo_find_cat_by_filename()` с 4-шаговым поиском (точное → без-prefix → suffix→ prefix); ответ содержит `profile`, `reload_count`, `last_reload`, `last_reload_ok`, `hot_reload_supported`, `loaded`, `entries` для каждого файла

**Dashboard (полное управление geo):**

- **[dashboard-src/src/components/settings/GeoConfig.vue]** Badge статуса (OK/ERROR) с tooltip; профили с border highlight + tooltip ⓘ; кнопка обновления с tooltip ⓘ; `doUpdate()` с updateStep прогрессом (3 шага: скачиваем → ожидаем → проверяем); hot-reload счётчик (N×) + `formatRelTime()`; автообновление каждые 30 сек через `setInterval`; очистка interval в `onUnmounted`

## [2.0.9] — 2026-05-12

### Added (Clash YAML парсер в демоне — /api/subscribe/import + /api/subscribe/parse)

- **[core/include/sub_parser/clash_yaml.h]** Новый публичный заголовок: `clash_yaml_parse_proxies`, `ClashRule`, `ClashGroup`, `ClashProvider`, `ClashConfig`, `clash_yaml_parse_full`, `clash_config_free`
- **[core/src/sub_parser/clash_yaml.c]** Новый модуль: вынесен `parse_clash_yaml_proxies` из `proxy_provider.c` + расширен `clash_yaml_parse_full` (rules/proxy-groups/rule-providers/proxy-providers/dns/mixed-port/mode); `vbcopy` helper (нет `-Wformat-truncation`); fix двойной flush при break; fix DNS список с `://` URL
- **[core/src/proxy/proxy_provider.c]** Удалён P1 блок (~314 строк), добавлен `#include "sub_parser/clash_yaml.h"`, вызов переименован в `clash_yaml_parse_proxies`
- **[core/src/http_server.c]** `server_config_to_uci_anon()` helper (анонимные UCI секции для всех полей ServerConfig); YAML ветка в `route_api_subscribe_parse` (`proxies:` → preview JSON); YAML ветка в `route_api_subscribe_import` (`proxies:` → UCI import); `net_http_fetch` вместо wget fork; fix `http_json_get_str`: `\n`/`\r`/`\t`/`\b`/`\f` JSON escape → реальные символы
- **[core/Makefile.dev]** Добавлен `sub_parser/clash_yaml.c` в SOURCES; добавлен `test-clash-yaml` таргет
- **[core/tests/test_clash_yaml.c]** 8 тестов: T1 минимальный прокси, T2 VLESS+Reality, T3 Shadowsocks, T4 rules, T5 proxy-groups, T6 MATCH, T7 полный конфиг, T8 пустой ввод (8/8 PASS)

## [2.0.8] — 2026-05-12

### Added (SRC-PORT + PROCESS-NAME + DPI whitelist/blacklist + DNS stale-while-revalidate)

- **[core/include/config.h]** `RULE_TYPE_SRC_PORT=13`, `RULE_TYPE_PROCESS_NAME=14`; `DpiDomainList` (64 записи × 128 байт); поля `dpi_whitelist`/`dpi_blacklist` в `EburNetConfig`; поля `stale_while_revalidate`/`stale_grace_seconds` в `DnsConfig`
- **[core/include/proxy/dispatcher.h]** `src_port: uint16_t` и `proc_name[64]` в `relay_conn_t`; флаг `has_process_name_rules` в `dispatcher_state_t`
- **[core/include/proxy/rules_engine.h]** Добавлены параметры `sport`, `proc_name` в `rules_engine_match` и `rules_engine_get_server`
- **[core/include/dns/dns_cache.h]** `grace_seconds: uint32_t` и `stale_enabled: bool` в `dns_cache_t`
- **[core/src/proxy/rules_engine.c]** `RULE_TYPE_SRC_PORT` (port_min/max), `RULE_TYPE_PROCESS_NAME` (strcasecmp + strcasestr)
- **[core/src/proxy/dispatcher.c]** `dpi_list_match()` helper; `get_proc_name_by_src_port()` (/proc/net/tcp→inode→pid→comm); `conn_sport`/`conn_proc_name` extraction; DPI whitelist/blacklist override; `has_process_name_rules` в `dispatcher_set_context`; заполнение `r->src_port`/`r->proc_name`; обновлены все вызовы `rules_engine_match`/`rules_engine_get_server`
- **[core/src/config.c]** Парсинг `SRC-PORT`/`PROCESS-NAME` типов правил; парсинг UCI list `dpi_whitelist`/`dpi_blacklist`; парсинг `dns_stale_while_revalidate`/`dns_stale_grace_seconds`; defaults: `stale_while_revalidate=true`, `stale_grace_seconds=3600`
- **[core/src/dns/dns_cache.c]** `stale_enabled` guard для stale path; configurable `grace_seconds`
- **[core/src/dns/dns_server.c]** Init `cache.stale_enabled` и `cache.grace_seconds` из `cfg->dns`
- **[core/src/ipc.c]** `IPC_CMD_DPI_GET` включает `whitelist`/`blacklist` JSON-массивы
- **[core/src/http_server.c]** `route_api_dpi_get` буфер 16KB; `route_api_dpi_patch` UCI add_list для whitelist/blacklist; `write_dns_cache` + `dns_map` для SWR полей
- **[tools/sub_convert.py]** `SRC-PORT` → `src_port` UCI; `PROCESS-NAME` → `process_name` UCI
- **[core/tests/test_rules_sport.c]** 7 standalone тестов: SRC-PORT ×4 + PROCESS-NAME ×3 (7/7 PASS)
- **[dashboard-src]** `RuleFormModal`: опция PROCESS-NAME + placeholder; `DPIConfig`: whitelist/blacklist таблицы; `DNSFullConfig`: SWR toggle + grace period; `useTooltip`: 5 новых записей

## [2.0.7] — 2026-05-12

### Added (OR-правила + DOMAIN-REGEX + JA3/JA4 в connections + per-device traffic stats)

- **[core/include/config.h]** `RULE_TYPE_OR = 11`, `RULE_TYPE_REGEX = 12`; `TrafficRule` расширен `sub_rules`/`sub_count` (heap) и `compiled_re` (regex_t*, heap)
- **[core/include/proxy/dispatcher.h]** `ja4[72]` в `relay_conn_t`
- **[core/src/config.c]** Парсинг `type=OR`/`REGEX`, UCI list `or_condition`, финализирующий pass: calloc sub_rules + regcomp; config_free loop для cleanup
- **[core/src/proxy/rules_engine.c]** `case RULE_TYPE_OR` (short-circuit по sub_rules) и `case RULE_TYPE_REGEX` (regexec)
- **[core/src/http_server.c]** `ja3`/`ja4` поля в JSON для GET /connections
- **[tools/sub_convert.py]** Парсинг Clash `OR((...))` и `DOMAIN-REGEX` правил → UCI `type=OR`/`REGEX` + `list or_condition`
- **[core/tests/test_or_regex.c]** 4×REGEX + 3×OR standalone тесты (7/7 PASS)
- **[dashboard-src]** RuleFormModal: опции OR/REGEX + подсказки; DevicesConfig: колонки tx/rx/conn_count; ConnectionTable: колонка JA3; i18n ключ `ja3`

## [2.0.6] — 2026-05-12

### Added (P3 UX — TUIC BBR profile + active_relay_count)

- **[dashboard/components/proxies/ServerFormModal.vue]** BBR профиль для TUIC:
  - Поле `tuic_cc_profile` (conservative/standard/aggressive)
  - Показывается только при `tuic_cc === 'bbr1'` или `bbr2`
  - Включается в submit payload

- **[dashboard/api/index.ts]** `getStatusAPI()` → `GET /api/status`

- **[dashboard/components/overview/ChartsCard.vue]** Карточка `active_relay_count`:
  - Polling `/api/status` каждые 5 секунд
  - Показывается только если `active_relay_count > 0`

- **[dashboard/i18n]** Ключ `activeConnections`

## [2.0.5] — 2026-05-12

### Added (P1 Providers CRUD + P2 Расширенные настройки)

- **[dashboard/api/index.ts]** +14 новых функций:
  - Providers CRUD: `addProxyProviderAPI`, `deleteProxyProviderAPI`, `addRuleProviderAPI`, `deleteRuleProviderAPI`
  - DNS full: `getDNSConfigAPI`, `patchDNSConfigAPI`, `getDNSStatsAPI`
  - DPI: `getDPIConfigAPI`, `patchDPIConfigAPI`
  - Network: `getNetworkConfigAPI`, `patchNetworkConfigAPI`
  - Geo: `getGeoStatusAPI`, `triggerGeoUpdateAPI`
  - Devices: `getDevicesAPI`, `patchDeviceAPI`
  - Backup/Restore: `downloadBackupAPI`, `uploadRestoreAPI`

- **[dashboard/components/providers/AddProviderModal.vue]** Модал добавления провайдера:
  - Поддержка proxy и rule типов (behavior/url/interval)
  - Используется из ProxiesPage (вкладка PROVIDER) и RulesPage (вкладка PROVIDER)

- **[dashboard/components/proxies/ProxyProvider.vue]** Кнопка удаления провайдера (TrashIcon)
- **[dashboard/components/rules/RuleProvider.vue]** Кнопка удаления провайдера (TrashIcon)

- **[dashboard/views/ProxiesPage.vue]** Кнопка "Добавить Proxy Provider" в PROVIDER вкладке
- **[dashboard/views/RulesPage.vue]** Кнопка "Добавить Rule Provider" в PROVIDER вкладке (оба режима)

- **[dashboard/components/settings/DNSFullConfig.vue]** Полная DNS конфигурация:
  - upstream_default / upstream_bypass / DoH / DoT toggles
  - Fake-IP: enable toggle + IPv4/IPv6 диапазоны
  - Adblock: block_ads / block_trackers / block_threats
  - DNS stats виджет (queries / cached / blocked / hit-rate)

- **[dashboard/components/settings/DPIConfig.vue]** DPI Bypass UI:
  - enabled / fragment_enabled / fake_ttl (toggle + number) / disorder

- **[dashboard/components/settings/NetworkConfig.vue]** Сетевые оптимизации:
  - flow_offload / tc_fast_path / bbr / mtu

- **[dashboard/components/settings/GeoConfig.vue]** Geo базы:
  - Профиль minimal/normal/full с radio buttons
  - Таблица .gbin файлов (name/entries/size/loaded)
  - Кнопка "Обновить базы" → `triggerGeoUpdateAPI`

- **[dashboard/components/settings/DevicesConfig.vue]** Per-device routing:
  - Таблица устройств по MAC с выбором policy + proxy_group
  - Использует `proxyGroupList` из store/proxies

- **[dashboard/components/settings/backend/BackendSettings.vue]** Новые секции:
  - Backup/Restore: download tar.gz + upload restore с авто-перезагрузкой страницы
  - Подключены: DNSFullConfig, DPIConfig, NetworkConfig, GeoConfig, DevicesConfig

- **[dashboard/i18n/ru.ts + en.ts]** Новые ключи: `addProxyProvider`, `addRuleProvider`,
  `deleteProvider`, `dpiBypass`, `networkOptimizations`, `geoBases`, `devicesRouting`,
  `backupRestore`, `geoProfileMinimal/Normal/Full`

- EC330 deploy 2026-05-12 ✓

## [2.0.4] — 2026-05-12

### Added (P1 — Dashboard: Rules CRUD + Rule Test UI)

- **[dashboard/api/index.ts]** Rules API:
  - `createRuleAPI(data)` — POST /api/rules
  - `updateRuleAPI(id, data)` — PATCH /api/rules/{id}
  - `deleteRuleAPI(id)` — DELETE /api/rules/{id}
  - `testRuleAPI(target)` — POST /api/rules/test → `{matched, rule, payload, proxy}`
  - Интерфейсы: `RuleConfig`, `RuleTestResult`

- **[dashboard/components/rules/RuleFormModal.vue]** Форма добавления/редактирования правила:
  - Все типы: DOMAIN/SUFFIX/KEYWORD, IP-CIDR/v6, GEOIP, GEOSITE, RULE-SET, DST-PORT, SRC-PORT, NETWORK, MATCH
  - Динамический placeholder для значения по типу
  - Выбор политики: DIRECT/PROXY/REJECT + список proxy-групп
  - Опция no-resolve для IP-CIDR
  - Tooltips через `useTooltip` на типах правил

- **[dashboard/components/rules/RuleTestModal.vue]** Тестер правил:
  - Ввод домена/IP → результат: правило, payload, proxy с цветовой индикацией
  - История последних 10 тестов с повторным запуском по клику

- **[dashboard/views/RulesPage.vue]** Кнопки "Добавить правило" и "Тест правил"
  в обоих режимах (normal + VirtualScroller); модальные окна RuleFormModal × 2 + RuleTestModal

- **[dashboard/i18n/en.ts + ru.ts]** Новые ключи: `addRule`, `editRule`, `testRules`

- EC330 deploy 2026-05-12 ✓

---

## [2.0.3] — 2026-05-12

### Added (P1 — Dashboard: Servers CRUD + Import подписки)

- **[dashboard/api/index.ts]** API функции для серверов:
  - `createServerAPI(config)` — POST /api/servers
  - `updateServerAPI(name, config)` — PUT /api/servers/{name}
  - `deleteServerAPI(name)` — DELETE /api/servers/{name}
  - `parseSubscribeAPI(payload)` — POST /api/subscribe/parse
  - `importSubscribeAPI(payload)` — POST /api/subscribe/import
  - Типы: `ServerConfig`, `ParsedServer`

- **[dashboard/components/proxies/ServerFormModal.vue]** Динамическая форма сервера:
  - Поддержка всех протоколов: VLESS+Reality, VMess, Trojan, SS2022, HY2, AnyTLS, TUIC v5, AWG, ShadowTLS v3
  - Динамические секции: UUID/password/cipher/transport/SNI/pbk+sid+flow (Reality)/TUIC CC/AWG Jc-Jmin-Jmax/HY2 bandwidth
  - Tooltips через `useTooltip` на всех технических полях
  - POST (создание) и PUT (редактирование) через единый компонент

- **[dashboard/components/proxies/ImportSubModal.vue]** 3-шаговый импорт подписки:
  - Шаг 1: URL или raw URI-list (vless://... trojan://... ss://...)
  - Шаг 2: таблица preview с checkbox-выбором, целевая группа
  - Шаг 3: результат (добавлено/ошибок)
  - POST /api/subscribe/parse → POST /api/subscribe/import

- **[dashboard/views/ProxiesPage.vue]** Кнопки "Добавить сервер" и "Импорт подписки"
  в верхней панели страницы Прокси; модальные окна ServerFormModal × 2 + ImportSubModal

- **[dashboard/i18n/en.ts + ru.ts]** Новые ключи:
  `addServer`, `editServer`, `importSub`, `parsePreview`, `serverAddress`, `serverName`

- EC330 deploy 2026-05-12 ✓

---

## [2.0.2] — 2026-05-12

### Fixed (P0 — Dashboard: connections + traffic counters)

- **[proxy/dispatcher.h]** `relay_conn_t` — добавлены 6 полей для Clash API:
  - `rule_type[32]`, `rule_payload[128]` — тип и значение сработавшего правила
  - `proxy_chain[2][64]`, `proxy_chain_len` — цепочка прокси (group+server или DIRECT)
  - `is_udp` — флаг UDP relay для поля "network" в Clash JSON
  - `close_requested` — soft-close через `/connections/{id}` DELETE
  - `dispatcher_close_relay()` — публичный wrapper над `relay_free()` для HTTP сервера

- **[proxy/dispatcher.c]** 8 пропущенных вызовов `stats_traffic_up/down()`:
  - Reality HS: bytes_in (upload) → `stats_traffic_up()`
  - XUDP client→upstream: `stats_traffic_up()`
  - XUDP upstream→client: `stats_traffic_down()`
  - XUDP TCP upstream→client: `stats_traffic_down()`
  - AnyTLS client→upstream: `stats_traffic_up()`
  - AnyTLS upstream→client: `stats_traffic_down()`
  - TUIC client→upstream: `stats_traffic_up()`
  - TUIC upstream→client: `stats_traffic_down()`

- **[proxy/dispatcher.c]** `pending_rule_type`/`pending_rule_payload` — сохранение
  результата `rules_engine_match()` до аллокации relay; копирование в `relay_conn_t`
  при создании GROUP и DIRECT relay. `is_udp = 1` для XUDP/TUIC UDP relay.

- **[http_server.c]** `build_connections_json()` — Clash-совместимый JSON из relay pool:
  - `s_ds->conns[]` итерация, пропуск RELAY_DONE
  - metadata: network(tcp/udp), type(TPROXY), destinationIP/Port, host, dnsMode
  - upload/download (bytes_in/bytes_out), start (ISO 8601), chains, rule, rulePayload
  - Используется в `GET /connections` и WS `/connections`

- **[http_server.c]** `DELETE /connections/{id}` — вызывает `dispatcher_close_relay()`

- **[main.c]** `http_server_set_dispatcher(&dispatcher_state)` — связь HTTP сервера
  с диспетчером; без этого `s_ds == NULL` и connections всегда пустые

- **Deploy:** EC330 (192.168.2.1) — 4.4MB mipsel, `/connections` возвращает
  `{downloadTotal, uploadTotal, connections:[...]}` ✓

## [2.0.1] — 2026-05-12

### Added (P2 Sniffer — TLS SNI + HTTP Host + Dashboard интеграция)

- **[NEW/proxy/sniffer.c]** `sniffer_parse_http_host()` — парсер HTTP Host заголовка:
  - CONNECT метод: `host:port` из первой строки запроса
  - GET/POST/PUT/etc.: case-insensitive поиск `Host:` заголовка
  - Автоматическое отрезание порта (`:port` → только hostname)
  - Отклонение IP-адресов: IPv4 (all-digits+dots) и IPv6 (`[`) → -1
  - Ref: mihomo `component/sniffer/http_sniffer.go`

- **[NEW/proxy/sniffer.c]** `sniffer_peek_unified()` — единая точка снифинга:
  - TLS (0x16) → `sniffer_peek_sni()` → SNI
  - Остальное → `sniffer_parse_http_host()` → Host
  - Статический буфер `s_sniff_buf[512]` в BSS (MIPS stack safety)

- **[NEW/proxy/sniffer.c]** `sniffer_in_bypass()` — проверка bypass списка:
  - Wildcard: `*.suffix.com` → host оканчивается на `.suffix.com`
  - Exact match: прямое сравнение строк

- **[NEW/proxy/sniffer.h]** `sniff_result_t` + `sniff_type_t` (NONE/TLS/HTTP/QUIC):
  - `sniff_result_t { char host[256]; sniff_type_t type; }`
  - Декларации `sniffer_parse_http_host`, `sniffer_peek_unified`, `sniffer_in_bypass`

- **[NEW/config.h + config.c]** `SnifferConfig` структура:
  - `tls_sni` (default: true), `http_host` (default: false), `quic_sni` (false)
  - `override_dest` (default: true) — заменять Fake-IP hostname в роутинге
  - `bypass_domains[32][128]` + `bypass_count` (default: `["*.local"]`)
  - Парсинг UCI ключей: `sniffer_tls`, `sniffer_http`, `sniffer_bypass`, `sniffer_override_dest`

- **[proxy/dispatcher.c]** HTTP Host снифинг интегрирован рядом с TLS SNI:
  - `cfg->sniffer.http_host` flag контролирует HTTP снифинг
  - bypass проверка через `sniffer_in_bypass()` — при bypass `sniffer_bypassed++`
  - Статический `s_http_sniff_buf[512]` в BSS

- **[proxy/dispatcher.h + dispatcher.c]** Счётчики снифинга:
  - `sniffer_total`, `sniffer_tls`, `sniffer_http`, `sniffer_bypassed` в `dispatcher_state_t`
  - `dispatcher_get_sniffer_stats()` getter для http_server.c

- **[http_server.c]** Sniffer API расширен:
  - `GET /api/sniffer` — читает реальные значения из UCI + строит `bypass_domains` JSON массив
  - `PATCH /api/sniffer` — поддержка `bypass_domains` (uci del + add_list), `override_dest`
  - `GET /api/sniffer/stats` — новый endpoint: `{total, tls, http, bypassed}`

- **[tests/test_sniffer.c]** 5 новых тестов (T8–T12), итого 12 тестов:
  - T8: `GET / HTTP/1.1\r\nHost: example.com` → host="example.com"
  - T9: `CONNECT example.com:443 HTTP/1.1` → host="example.com" (порт отрезан)
  - T10: `Host: example.com:8080` → host="example.com"
  - T11: TLS байты → -1 (не HTTP)
  - T12: `sniffer_in_bypass` — wildcard + exact match + negative; все PASS

- **[dashboard-src]** `SnifferSection.vue` — новый компонент настроек снифера:
  - TLS SNI / HTTP Host / QUIC SNI (disabled) / Override dest toggles
  - Bypass list: теги с удалением + input + кнопка Add
  - Stats: total / TLS / HTTP / bypassed (DaisyUI `stats` блок)
  - Загрузка из `GET /api/sniffer` + `GET /api/sniffer/stats` при mount

- **[dashboard-src]** `BackendSettings.vue` — `SnifferSection` встроен после DnsUpstream

- **[dashboard-src/api/index.ts]** Sniffer API клиент:
  - `SnifferConfig`, `SnifferStats` типы
  - `getSnifferAPI`, `patchSnifferAPI`, `getSnifferStatsAPI`

- **[dashboard-src/i18n/en.ts + ru.ts]** Ключи локализации: `snifferTitle`, `snifferTlsSni`, `snifferHttpHost`, `snifferQuicSni`, `snifferOverrideDest`, `snifferBypassList`, `snifferTotal`, `snifferBypassed`, `comingSoon`, `add`

### Build

- Бинарник mipsel: 3.1MB ✅
- 12/12 тестов PASS ✅
- EC330 (192.168.2.1) deploy 2026-05-12 ✅
- `GET /api/sniffer` → `{"tls_sni":true,"http_host":false,"quic_sni":false,"override_dest":true,"bypass_domains":["*.local"]}` ✅
- `GET /api/sniffer/stats` → `{"total":0,"tls":0,"http":0,"bypassed":0}` ✅

## [2.0.0] — 2026-05-12

### Added (Dashboard v2 — production release)

- Vite production build интегрирован в сборку
- DaisyUI компоненты финализированы
- README обновлён

## [1.5.196] — 2026-05-12

### Added (Dashboard Фаза 4 — SSH Console + Monitor окно)

- **[NEW/http_server.c + ws.h + ws_frame.c]** WS `/ssh` — pty bridge:
  - `ssh_session_start()`: `openpty` + `fork` + `/bin/ash -l`; pty_master в epoll
  - `ssh_pty_on_output()`: EPOLLIN на pty_master → `ws_send_binary` → клиент
  - `ws_ssh_on_input()`: WS frame → `write(pty_master)` + resize `TIOCSWINSZ`
  - `ssh_is_lan_client()`: RFC 1918 проверка по `peer_addr.sin_addr` (LAN-only guard)
  - `ssh_session_stop()`: SIGHUP к ash + EPOLL_CTL_DEL + close pty_master
  - Одиночный глобальный сеанс (`s_ssh` + `s_ssh_conn`) — ограничение MIPS
  - `WS_ROUTE_SSH = 6` в enum; `ws_send_binary()` добавлен в ws_frame.c

- **[NEW/http_server.c]** GET `/monitor` — standalone HTML страница:
  - Инлайн HTML (~3.6KB) с WS `/logs` + `/traffic` + `/connections`
  - Метрики: скорость трафика, кол-во соединений, DNS queries/blocked
  - Pause/Resume + Clear кнопки; автообновление DNS stats каждые 5s
  - Открывается в новом окне: `http://router:8080/monitor`

- **[NEW/dashboard-src]** Vue SSH Console вкладка (`SSHConsolePage.vue`):
  - WS binary frames → `TextDecoder` → `<pre>` вывод терминала
  - Ctrl+C/D, Tab, стрелки → ANSI escape sequences → pty
  - Resize JSON `{"type":"resize","rows":N,"cols":M}` при изменении окна
  - `ROUTE_NAME.ssh` + `CommandLineIcon` в сайдбаре

- **[NEW/dashboard-src]** Кнопка Monitor в SidebarButtons:
  - `ChartBarSquareIcon` → `window.open('/monitor', ...)` 900×700

### Fixed

- Рестарт процесса после деплоя: `killall` перед `init.d start` (inode gotcha)

## [1.5.195] — 2026-05-12

### Added (Dashboard Фаза 3 — CRUD + расширенные endpoints)

- **[NEW/http_server.c]** Server CRUD:
  - `POST /api/servers` — создать named UCI секцию `4eburnet.NAME=server`;
    парсит `name/protocol/address/port/uuid/password/transport/sni/pbk/sid/flow/tls`;
    201 Created
  - `PUT /api/servers/{name}` — обновить поля существующего сервера; 204
  - `DELETE /api/servers/{name}` — удалить UCI секцию; 204

- **[NEW/http_server.c]** Subscribe:
  - `POST /api/subscribe/parse` — preview URI-листа (vless://trojan://ss://);
    без сохранения, возвращает JSON-массив объектов
  - `POST /api/subscribe/import` — wget загрузка или inline-парсинг, батч UCI add

- **[NEW/http_server.c]** Rules CRUD:
  - `POST /api/rules` — добавить `@traffic_rule[-1]` с type/value/policy/priority;
    поддерживает ключ `policy` как псевдоним `target`; 201
  - `PATCH /api/rules/{id}` — обновить правило по UCI section hash; 204
  - `DELETE /api/rules/{id}` — удалить; 204
  - `POST /api/rules/test` — тест совпадения по домену; ключ `domain` или `target`;
    парсит весь UCI вывод (128KB static buf) для поиска по DOMAIN/SUFFIX/KEYWORD/MATCH

- **[NEW/http_server.c]** Providers CRUD:
  - `POST /api/providers/proxies` — добавить proxy_provider; 201
  - `DELETE /api/providers/proxies/{name}` — удалить; 204
  - `POST /api/providers/rules` — добавить rule_provider; 201
  - `DELETE /api/providers/rules/{name}` — удалить; 204

- **[NEW/http_server.c]** DNS расширенный API:
  - `PATCH /api/dns` — изменить DNS настройки; маппинг 15 JSON-ключей → UCI;
    поддерживает boolean `true/false` через `http_json_get_val` (не только строки)
  - `POST /api/dns/cache/flush` — удалить кэш-файл + SIGHUP; 204
  - `POST /api/dns/fakeip/flush` — SIGHUP (перезапуск fake-IP пула); 204
  - `GET /api/dns/query?name=X&type=Y` — getaddrinfo probe → JSON answers
  - `GET /api/dns/stats` — stub (`queries/cached/blocked/hit_rate`)

- **[NEW/http_server.c]** DPI/Sniffer/Network:
  - `GET /api/dpi` — IPC_CMD_DPI_GET → JSON
  - `PATCH /api/dpi` — IPC_CMD_DPI_SET + UCI commit; поддерживает boolean
  - `GET /api/sniffer` — stub (tls_sni/http_host/quic_sni из UCI)
  - `PATCH /api/sniffer` — UCI set main.sniffer_{tls,http,quic}; 204
  - `GET /api/network` — flow_offload/tc_fast_path из s_cfg
  - `PATCH /api/network` — UCI set main.flow_offload/tc_fast_enabled; 204

- **[NEW/http_server.c]** Geo/Devices:
  - `POST /api/geo/update` — async fork+execv geo_update.sh; 202 Accepted
  - `PATCH /api/devices/{mac}` — UCI device_config секция с policy/proxy_group; 204

### Fixed

- **[FIX/http_server.c]** Dispatch ordering — GET /api/servers и GET /api/dns без
  метода перехватывали POST/PATCH запросы. Добавлены guards
  `!is_post && !is_put && !is_delete && !is_patch`.

- **[FIX/http_server.c]** `route_api_servers_post`: ключ `"server"` → `"address"`;
  парсинг порта как JSON-числа (не только строки).

- **[FIX/http_server.c]** `uci_find_server_section` / `uci_find_provider_section`:
  `uci show 4eburnet` даёт 123KB; буфер был 8KB → section не находилась.
  Заменено на `uci show 4eburnet.{name}` (таргетированный запрос, <512B).

- **[NEW/http_server.c]** `http_json_get_val` — извлечение JSON-примитивов без
  кавычек (true/false/число); используется в dns_patch/sniffer_patch/network_patch.

### Verified on EC330 (2026-05-12)

- 17/17 PASS PowerShell тест: GET×7, POST servers 201, PUT servers 204,
  DELETE servers 204, POST rules 201, PATCH dns 204, POST dns/cache/flush 204,
  GET dns/query, POST rules/test, PATCH network 204, PATCH sniffer 204
- 35/35 unit tests PASS (no regression)
- Бинарник 3.1MB (в рамках 4MB)

---

## [1.5.194] — 2026-05-12

### Fixed (UCI дубль + PATCH /configs reload)

- **[FIX/http_server.c]** `PATCH /configs`: добавлен `kill(getpid(), SIGHUP)` после
  UCI commit — теперь `s_cfg` пересчитывается из UCI при каждом изменении режима
  или log-level. Ранее SIGHUP не вызывался из-за анонимного блока `@4eburnet[1]`
  который перезаписывал mode при `config_load`.

- **[FIX/EC330]** Удалён дублирующий anonymous UCI блок `@4eburnet[1]`
  (`config 4eburnet` без имени) — источник конфликта mode при SIGHUP reload.
  Теперь `/etc/config/4eburnet` содержит только `config 4eburnet 'main'`.

- **[NOOP/tools/sub_convert.py]** Проверено: `config 4eburnet 'main'` уже
  корректно генерируется. Дубль возник при ручном `uci import` без `--merge`.

### Verified on EC330 (2026-05-12)

- PATCH mode=global → GET mode=global ✓
- PATCH mode=rule → GET mode=rule ✓
- Только одна `config 4eburnet 'main'` секция ✓

---

## [1.5.193] — 2026-05-12

### Added (Dashboard Фаза 2 — Core Clash API завершён)

- **[NEW/http_server.c]** `PATCH /configs`: изменить `mode`/`log-level` → UCI set
  + in-memory обновление `s_cfg`; `reload_daemon()` не вызывается (дублирующиеся
  блоки `config 4eburnet` в UCI конфиге — `named` vs `@4eburnet[1]`).

- **[NEW/http_server.c]** `DELETE /proxies/{group}`: снять pinned выбор сервера
  → `g->pinned = false` + `proxy_group_save_all_selections`; 204 No Content.

- **[NEW/http_server.c]** `DELETE /connections`: закрыть все relay; 204 No Content
  (GET /connections возвращает `connections:[]`, реальный список не экспортируется).

- **[NEW/http_server.c]** `DELETE /connections/{id}`: закрыть конкретный relay; 204.

- **[NEW/http_server.c]** `PATCH /rules/disable`: toggle UCI `rules_enabled`
  (0↔1) → `uci commit` + `reload_daemon()`; 204 No Content.

- **[FWD-DECL]** `static void reload_daemon(void)` forward declaration добавлена
  в блок объявлений (необходима для функций определённых до строки 3009).

### Verified on EC330 (2026-05-12)

- `GET /version` → `{"version":"4eburnet-1.5.191","premium":false,"meta":true}` ✅
- `PATCH /configs {"mode":"global"}` → 204, GET /configs возвращает `mode=global` ✅
- `DELETE /connections` → 204 ✅
- `DELETE /connections/abc123` → 204 ✅
- `PATCH /rules/disable` → 204 ✅
- `DELETE /proxies/GEMINI` → 204 ✅
- `GET /proxies` → 115 proxies ✅ | `GET /rules` → 397 rules ✅
- Размер бинарника: 3.1MB ✅ (лимит 4MB)

## [1.5.192] — 2026-05-12

### Fixed

- **[FIX/http_server.c]** async http_send_file: устранён ERR_CONNECTION_RESET
  при загрузке >1MB JS bundle через WiFi.
  - `send_offset` + `send_remaining` в HttpConn
  - Удалён `conn_feed_file` (лишний memcpy pipeline)
  - `http_send_file_continue`: drain loop при EPOLLOUT (46 строк)
  - HTTP/1.1 с `Content-Length` вместо HTTP/1.0
  - EPOLLOUT MOD/DEL через epoll_ctl
  - Результат: dashboard 200 ✅, JS 1.58MB ✅, CSS 653KB ✅

- **[FIX/deploy]** scp на занятый inode молча не обновляет файл.
  Рабочий паттерн: scp → /tmp/4eburnetd_new → cp → killall → start
  (зафиксировано в docs/DEPLOY.md)

## [1.5.191] — 2026-05-12

### Added (F1-3: VMess AEAD — полная реализация ~900 LoC)

- **[NEW/core/include/crypto/vmess_kdf.h]** Тип `vmess_kdf_path_t` + макросы
  `VMESS_KDF_PATH_STR/BIN/NONE`. Функции `vmess_kdf16/32` — nested HMAC-SHA256
  KDF по алгоритму xray-core Go: h0=HMAC(key,""), hN=HMAC(h(N-1),pathN).
  Поддержка 1/2/3-level путей; лишние `NONE`-пути игнорируются.

- **[NEW/core/src/crypto/vmess_kdf.c]** Реализация KDF через `hmac_sha256`
  (wolfSSL). `kdf_level` → двухшаговый HMAC, `kdf_two_levels` → три шага,
  `vmess_kdf16/32` — dispatch по числу ненулевых путей + truncate до 16/32 байт.

- **[NEW/core/include/proxy/protocols/vmess.h]** Константы `VMESS_SEC_AES_128_GCM=3`,
  `VMESS_SEC_CHACHA20_POLY1305=4`. Структура `vmess_conn_t`: cmd_key[16], auth_id[16],
  nonce[8], body_key[16], body_iv[16], resp_auth, resp_body_key/iv[16], send_count,
  recv_count, security, `shake_enc/dec` (heap: `wc_Shake`).
  API: `vmess_conn_init/free`, `vmess_encode_request_header`,
  `vmess_decode_response_header`, `vmess_encode/decode_chunk`.

- **[NEW/core/src/proxy/protocols/vmess.c]** Полная реализация протокола:
  `vmess_fnv1a32` + `vmess_crc32_ieee` хелперы.
  `vmess_create_auth_id`: timestamp(8 BE)+rand(4)+CRC32(12)(4 BE) → AES-128-ECB
  (`wc_AesSetKeyDirect` + `wc_AesEcbEncrypt`).
  `vmess_conn_init`: MD5(uuid+magic)→cmdKey, random nonce/body_key/body_iv/resp_auth,
  SHA256 resp keys, heap `wc_Shake` с `Shake128_Update(body_iv)`.
  `vmess_encode_request_header`: сборка hdr[], 3-path KDF для len_key/iv + hdr_key/iv,
  wire: AuthID[16]+EncLen[18]+nonce[8]+EncHdr[N+16].
  `vmess_decode_response_header`: 1-path KDF, AES-128-GCM decode, resp_auth verify.
  `vmess_encode/decode_chunk`: ChunkMasking (SHAKE-128 squeeze 2 байта/чанк),
  AES-128-GCM или ChaCha20-Poly1305; ChaCha ключ 16→32 через MD5(key)||MD5(MD5(key)).

- **[NEW/core/include/proxy/hc_vmess.h]** `hc_vmess_spawn(srv, target_host, port, ms)`
  — non-blocking HC для VMess серверов.

- **[NEW/core/src/proxy/hc_vmess.c]** `child_do_hc_vmess`: fork+pipe паттерн
  как в `hc_vless.c`. DNS→TCP→TLS→vmess_conn_init→encode_request→recv_response→RTT.
  Target: `www.gstatic.com:443` (стандарт mihomo). Pipe: `OK <ms>\n` / `ERR\n`.

- **[MOD/core/Makefile.dev]** Добавлены `vmess_kdf.c`, `vmess.c`, `hc_vmess.c`
  в SOURCES. Цель `test-vmess`: 10 тестов, 35 PASS. `EBURNET_VERSION ?= 1.5.191`.

- **[NEW/core/tests/test_vmess.c]** T1-T3: KDF детерминизм + cross-path.
  T4: conn_init все поля. T5: encode_request_header длины. T6: response header
  roundtrip (ручная AES-GCM через wolfSSL). T7: chunk enc→dec + SHAKE sync.
  T8: ChunkMasking enc_len XOR. T9-T10: send_count/recv_count инкремент. 35 PASS.

## [1.5.190] — 2026-05-11

### Added (F1-1: SS2022 AES-128/256-GCM варианты)

- **[MOD/core/include/proxy/protocols/shadowsocks.h]** Новый enum `ss_cipher_t`:
  `SS_CIPHER_CHACHA20_POLY1305=0` (существующий), `SS_CIPHER_AES_128_GCM=1`,
  `SS_CIPHER_AES_256_GCM=2`.
  В `ss_state_t`: поля `cipher`, `psk_len` (16 или 32), `Aes aes_enc`, `Aes aes_dec`.
  WHY отдельные enc/dec: wolfSSL Aes не reentrant при concurrent enc+dec в одной сессии.
  Добавлен `#include <wolfssl/wolfcrypt/aes.h>`.
  Сигнатуры обновлены: `ss_psk_decode(b64, out, out_len)`,
  `ss_handshake_start(..., cipher)`.

- **[MOD/core/src/proxy/protocols/shadowsocks.c]** Реализация AES-GCM ветвей:
  `ss_psk_decode`: принимает 16B (AES-128) или 32B (AES-256/ChaCha20).
  `ss_derive_key`: параметры `psk_len` и `key_len` — BLAKE3 KDF с переменной длиной
  выхода (16B для AES-128, 32B для остальных).
  `ss_aead_encrypt/decrypt`: switch по `st->cipher`:
  AES → `wc_AesGcmEncrypt/Decrypt(&st->aes_enc/dec, ..., nonce, 12, tag, 16, NULL, 0)`;
  default → `wc_ChaCha20Poly1305_Encrypt/Decrypt`.
  AES key schedule: `wc_AesInit + wc_AesGcmSetKey` при `ss_handshake_start`, один раз.
  `ss_cleanup`: `wc_AesFree` для AES cipher типов.

- **[MOD/core/include/config.h]** Поле `char ss_method[32]` в `ServerConfig`
  (рядом с `password`): хранит cipher string из UCI/подписки.

- **[MOD/core/src/config.c]** Парсинг ключа `ss_method` (strncpy pattern).

- **[MOD/core/src/proxy/dispatcher.c]** `ss_protocol_start`: маппинг
  `server->ss_method` → `ss_cipher_t` перед вызовом `ss_handshake_start`.
  Default: `SS_CIPHER_CHACHA20_POLY1305` при пустом/неизвестном ss_method.

- **[MOD/tools/sub_convert.py]** SS cipher propagation в трёх местах:
  `parse_ss_uri`: добавлен `'ss_method': method` в возвращаемый dict.
  `_clash_proxy_to_server` (YAML): `'ss_method': proxy.get('cipher', '...')`.
  `parse_singbox_json`: `'ss_method': ob.get('method', '...')`.
  Default fallback: `2022-blake3-chacha20-poly1305`.

- **[FIX/core/include/proxy/shadowtls.h]** Добавлен `#include <stdbool.h>` —
  missing include, обнаруженный при добавлении wolfSSL AES в shadowsocks.h.

- EC330 deploy 2026-05-11: 3.1MB mipsel, 99 PASS 0 FAIL, VmRSS 3.1MB.

## [1.5.189] — 2026-05-11

### Added (F1-2: ShadowTLS v3 server-side + Aparecium defense)

- **[NEW/core/include/proxy/shadowtls.h]** Типы server-side:
  `stls_srv_state_t` enum: `WAIT_CH/PROXY_HS/RELAY/BYPASS`.
  `stls_srv_ctx_t`: state, authorized, embedded `shadowtls_ctx_t inner`
  (переиспользует wrap/unwrap логику без дублирования HMAC кода).
  Объявления: `stls_srv_ctx_init`, `stls_srv_check_client_hello`,
  `stls_srv_unwrap`, `stls_srv_wrap`.

- **[NEW/core/src/proxy/protocols/shadowtls.c]** Реализация server-side:
  `stls_srv_ctx_init`: инициализирует inner ctx + state=WAIT_CH.
  `stls_srv_check_client_hello`: парсит TLS ClientHello (offset 11=random,
  43=sid_len, 44=sid); верифицирует SessionID = HMAC-SHA256(pwd,random) первые 32 байта.
  Constant-time `memcmp` предотвращает timing attack при авторизации.
  `stls_srv_unwrap`: делегирует в `stls_unwrap(&ctx->inner, ...)`.
  `stls_srv_wrap`: делегирует в `stls_wrap(&ctx->inner, ...)`.
  Aparecium bypass: неверный HMAC → STLS_SRV_BYPASS (прозрачный проброс без drop).
  WHY dispatcher интеграция pending: inbound listener требует отдельного accept loop
  и проксирования HS к реальному TLS backend.

- **[NEW/core/include/proxy/dispatcher.h]** `RELAY_STLS_SERVER = 32`
  в relay_state_t под `#if CONFIG_EBURNET_STLS`.

- **[FIX/core/src/proxy/dispatcher.c]** Минимальный `case RELAY_STLS_SERVER`
  (relay_free + pending comment) — убирает предупреждение компилятора.

- **[FIX/core/tests/test_shadowtls.c]** +3 теста:
  T8: `stls_srv_check_client_hello` верный HMAC → true.
  T9: `stls_srv_check_client_hello` неверный HMAC → false.
  T10: `stls_srv_wrap` + `stls_srv_unwrap` roundtrip.

- Aparecium defense: `dpi_make_tls_clienthello_ex` уже включает ALPN h2+http/1.1
  (15 extensions, Chrome 120+ fingerprint) — отдельного кода не потребовалось.

- Ref: mihomo transport/shadowtls/shadowtls.go (v2); v3 SHA256 уже реализован.

- EC330 deploy 2026-05-11: 3.0MB mipsel, 99 PASS 0 FAIL, VmRSS 2.8MB.

## [1.5.188] — 2026-05-11

### Added (F1-6c: BBR v2 для TUIC v5)

- **[NEW/core/include/proxy/protocols/tuic_v5.h]** BBR v2 константы:
  `BBR2_HIGH_GAIN_X100=289` (2/ln(2)·100 = 2.885·100, quiche/Google, не 277).
  `BBR2_STARTUP_FULL_LOSS_COUNT=8` (quicBbr2: exit STARTUP после 8 потерь).
  `BBR2_BETA_X100=70`, `BBR2_HEADROOM_X100=85`, `BBR2_PROBE_RTT_CWND_GAIN_X100=50`.
  `BBR2_LOSS_THRESH_X1000=20` (2%, quicBbr2DefaultLossThreshold).
  Profile gains: `BBR2_PROBE_UP_GAIN_STD=125`, `CONS=110`, `AGG=150`.
  `BBR2_CWND_GAIN_STD=200`, `CONS=150`, `AGG=250`.
  `bbr2_ack_phase_t` enum: `INIT`, `PROBE_STARTING`, `PROBE_FEEDBACK`, `PROBE_STOPPING`.
  `bbr2_probe_bw_phase_t` enum: `PROBE_UP`, `PROBE_DOWN`, `PROBE_CRUISE`.
  Новые поля в `tuic_cc_t`: `bbr2_inflight_hi/lo`, `bbr2_ack_phase`,
  `bbr2_probe_phase`, `bbr2_probe_up_gain_x100`, `bbr2_probe_up_cnt`,
  `bbr2_loss_round_delivered`, `bbr2_loss_in_round`, `bbr2_loss_events`,
  `bbr2_startup_losses`.

- **[NEW/core/src/proxy/protocols/tuic_v5_proto.c]** BBR v2 реализация:
  `bbr2_is_inflight_too_high`: loss_events/round_count > 2% → перегрузка.
  `bbr2_handle_inflight_too_high`: inflight_hi = beta·in_flight (0.7); PROBE_UP→DOWN.
  `bbr2_probe_bw_advance_phase`: PROBE_UP(gain=probe_up_gain, ≤4 раунда)→
  PROBE_DOWN(gain=0.9, дренаж до BDP)→PROBE_CRUISE(gain=1.0, период=10·RTprop)→цикл.
  WHY: в отличие от v1 8-фазного цикла, v2 зондирует только вверх и даёт буферу
  опуститься, предотвращая buffer bloat (Cardwell 2019).
  `bbr2_set_cwnd`: target=BDP·cwnd_gain; clamp inflight_hi; PROBE_RTT=0.5·BDP.
  `bbr_v2_on_ack`: state machine с loss-aware STARTUP exit + PROBE_BW v2 фазы.
  `bbr_v2_on_loss`: loss_events++; startup_losses++; проверяет is_inflight_too_high.
  `tuic_cc_init`: BBR v2 поля инициализируются (inflight_hi=UINT32_MAX, phase=CRUISE).
  `tuic_cc_on_ack`/`tuic_cc_on_loss`: ветки `TUIC_CC_BBR_V2`.
  `tuic_cc_probe_rtt_tick`: расширен для `TUIC_CC_BBR_V2`.

- **[NEW/core/include/config.h]** поле `tuic_cc_profile[16]`
  ("conservative"/"standard"/"aggressive", default="standard").

- **[NEW/core/src/config.c]** парсинг UCI `tuic_cc_profile`.

- **[FIX/core/src/proxy/dispatcher.c]** `tuic_cc=bbr2` → `TUIC_CC_BBR_V2`.
  Profile mapping после init: conservative (cwnd=1.5, probe_up=1.1),
  standard (cwnd=2.0, probe_up=1.25 — default), aggressive (cwnd=2.5, probe_up=1.5).

- Ref: Cardwell et al. netdev0x13 2019 + IETF BBRv2 draft + Google quiche.

- EC330 deploy 2026-05-11: 3.1MB mipsel, 33 PASS 0 FAIL, VmRSS 2.1MB.

## [1.5.187] — 2026-05-11

### Added (F1-6b: BBR v1 для TUIC v5)

- **[NEW/core/include/proxy/protocols/tuic_v5.h]** BBR константы:
  `BBR_HIGH_GAIN_X100=277` (4·ln(2)·100, Google quiche/mihomo, не 289),
  `BBR_DRAIN_GAIN_X100=36`, `BBR_CWND_GAIN_X100=200`, `BBR_PROBE_RTT_CWND=4`,
  `BBR_RTPROP_EXPIRE_MS=10000`, `BBR_PROBE_RTT_DUR_MS=200`, `BBR_BW_WINDOW_SIZE=10`.
  `bbr_state_t` enum: `BBR_STARTUP`, `BBR_DRAIN`, `BBR_PROBE_BW`, `BBR_PROBE_RTT`.
  Новые поля в `tuic_cc_t`: `bbr_state`, `bbr_btl_bw`, `bbr_rt_prop`,
  `bbr_rt_prop_stamp`, `bbr_cycle_stamp/idx`, `bbr_delivered/stamp`,
  `bbr_pacing_gain_x100`, `bbr_cwnd_gain_x100`, `bbr_filled_pipe`,
  `bbr_bw_samples[10]`, `bbr_bw_idx`, `bbr_round_count`, `bbr_round_start`.
  Добавлена функция `tuic_cc_probe_rtt_tick(cc, now_ms)`.

- **[NEW/core/src/proxy/protocols/tuic_v5_proto.c]** BBR v1 реализация:
  `bbr_update_btl_bw`: windowed max за 10 RTT раундов через кольцевой буфер.
  WHY: windowed max (не EMA) — BBR берёт МАКСИМУМ BW, не среднее. O(1) без heap.
  `bbr_update_rt_prop`: min RTT filter с 10s expiry → вход в PROBE_RTT.
  `bbr_bdp`: BDP = BtlBw·RTprop/mss (пакеты).
  `bbr_set_cwnd`: cwnd = BDP·cwnd_gain (2.0) в PROBE_BW; min cwnd=4 в PROBE_RTT.
  `bbr_advance_cycle_phase`: 8-фазный gain cycle [1.25, 0.75, 1×6] по 1 RTprop.
  `bbr_check_startup_done`: STARTUP→DRAIN когда cwnd≥BDP (bbr_filled_pipe).
  `bbr_v1_on_ack`: диспетчер state machine + BtlBw + RTprop update.
  `bbr_v1_on_loss`: no-op (BBR не реагирует cwnd-ом на потери — Cardwell 2016).
  `tuic_cc_init`: инициализация BBR полей с `clock_gettime` (избегает elapsed=uptime).
  `tuic_cc_on_ack`/`tuic_cc_on_loss`: добавлены ветки `TUIC_CC_BBR_V1`.
  `tuic_cc_probe_rtt_tick`: запускает PROBE_RTT если RTprop_stamp устарел >10s.

- **[FIX/core/src/proxy/dispatcher.c]** Парсинг UCI `tuic_cc=bbr1` → `TUIC_CC_BBR_V1`.
  В цикле `tuic_defrag_tick` добавлен вызов `tuic_cc_probe_rtt_tick` с `now_ms`
  из `ts_start` (CLOCK_MONOTONIC мс).

- EC330 deploy 2026-05-11: 3.1MB mipsel, 99 PASS 0 FAIL, VmRSS 3.6MB.

## [1.5.186] — 2026-05-11

### Added (F1-6a: CUBIC CC для TUIC v5)

- **[NEW/core/include/proxy/protocols/tuic_v5.h]** `tuic_cc_algo_t` enum:
  `NEWRENO=0`, `CUBIC=1`, `BBR_V1=2`, `BBR_V2=3` (BBR pending).
  Новые поля в `tuic_cc_t`: `algo`, `cubic_w_max`, `cubic_k`,
  `cubic_epoch_start`, `cubic_w_est`, `cubic_ack_cnt`.
  Сигнатура `tuic_cc_on_ack` расширена параметром `uint64_t now_ms`
  (CUBIC W(t) = C*(t-K)^3 + W_max требует время с начала эпохи).

- **[NEW/core/src/proxy/protocols/tuic_v5_proto.c]** CUBIC реализация:
  `cubic_compute_k`: K = cbrt(W\_max·(1-β)/C) через `pow(x, 1/3)` из libm.
  `cubic_w_cubic`: W_cubic(t) = C*(t-K)³ + W_max.
  `cubic_on_ack`: W_cubic + TCP-friendliness W_est (RFC 8312 §5.1).
  `cubic_on_loss`: W_max snapshot + β=0.7 (vs 0.5 NewReno → меньший откат).
  Диспетчеры `tuic_cc_on_ack`/`tuic_cc_on_loss` переключаются по `algo`.
  WHY: CUBIC быстрее восстанавливает cwnd после потери на high-RTT каналах
  по сравнению с NewReno; является дефолтным CC в Linux kernel.

- **[FIX/core/src/proxy/protocols/tuic_v5_conn.c]** ACK handler:
  `tuic_cc_on_ack(&conn->cc, 1200)` → добавлен `now_ms` из `CLOCK_MONOTONIC`.

- **[NEW/core/include/config.h]** `char tuic_cc[16]` в `ServerConfig`.
  WHY: UCI-опция для выбора CC алгоритма per-server.

- **[FIX/core/src/config.c]** Дефолт `"cubic"` и парсинг `option tuic_cc`.

- **[FIX/core/src/proxy/dispatcher.c]** После `tuic_conn_create`:
  `((tuic_conn_t *)relay->tuic_conn)->cc.algo = algo` по значению `server->tuic_cc`.
  Default: CUBIC; `tuic_cc=newreno` → NEWRENO.

- EC330 deploy 2026-05-11: 3.1MB mipsel, 99 PASS 0 FAIL, VmRSS 6.8MB.

## [1.5.184] — 2026-05-11

### Added (F0-4: AND/OR logical rules в rules engine)

- **[NEW/core/include/config.h]** `RULE_TYPE_AND = 10` в `rule_type_t` enum.
  Новые поля в `TrafficRule`: `port_min`, `port_max` (uint16_t), `network` (uint8_t).
  WHY: AND,((NETWORK,TCP),(DST-PORT,50000-65535)) требует хранить протокол и диапазон.

- **[FIX/core/src/config.c]** Парсинг `type='and'` → `RULE_TYPE_AND`.
  Парсинг `option network 'tcp'/'udp'` → `tr->network=6/17`.
  Парсинг `option port '50000-65535'` → `tr->port_min=50000, tr->port_max=65535`.
  Парсинг `option value '50000-65535'` для `RULE_TYPE_DST_PORT` также заполняет
  port_min/port_max (ранее `strtoul` обрезал диапазон до первого числа).

- **[FIX/core/src/proxy/rules_engine.c]** `RULE_TYPE_DST_PORT`: использует
  `port_min/port_max` вместо `strtoul(value)`. Поддержка диапазона портов.
  `RULE_TYPE_AND`: новый case — `match_net && match_port`.
  `network==0` → любой протокол; `dport==0` → AND с портом не матчится.

- **[FIX/core/include/proxy/rules_engine.h]** Сигнатуры `rules_engine_match` и
  `rules_engine_get_server` расширены параметрами `uint8_t proto, uint16_t dport`.

- **[FIX/core/src/proxy/dispatcher.c]** Извлечение `conn_proto` (из `conn->proto`)
  и `conn_dport` (из `conn->dst`) перед вызовом rules engine.
  Добавлен `RULE_TYPE_AND` в switch `_rule_kind`.

- **[FIX/core/src/main.c]** DNS callback `dns_engine_consult`: `proto=0, dport=0`.

- **[FIX/tools/sub_convert.py]** `_parse_clash_rule`: AND-блок переписан.
  Новый парсер `re.finditer(r'\(([^()]+)\)')` извлекает все sub-conditions.
  NETWORK (tcp/udp) сохраняется в `network` поле UCI. Тип правила `'and'`.
  `generate_uci`: AND-правила эмитируют `option network` и `option port`.
  EC330 deploy 2026-05-11: 3.0MB, 99 PASS 0 FAIL, VmRSS 3440 kB.

- **[FIX/tools/sub_convert.py]** `generate_uci`: секция `config main 'main'` исправлена
  на `config 4eburnet 'main'` (init script ищет тип '4eburnet', не 'main').
  Добавлен `option enabled '1'` в секцию main.
  Генерация переведена на shell-скрипт формат: `#!/bin/sh` / `uci import 4eburnet <<'UCIEOF'`
  / footer с `uci commit`. Применять через `sh /tmp/generated_uci.sh`.

- **[NEW/docs/DEPLOY.md]** Правила деплоя: Windows-only scp, UCI gotchas,
  восстановление после uci import, чеклист проверки.

## [1.5.183] — 2026-05-11

### Fixed (T1-01: rule-providers YAML parsing + classical format fix)

- **[FIX/core/src/proxy/rules_engine.c]** `load_file_entries`: убрана обработка
  записей Clash classical format без стрипа типа правила. Записи вида
  `DOMAIN-SUFFIX,t.me` теперь корректно стриплись до `t.me`.
  Пропускаются `PROCESS-NAME,`, `IP-ASN,`, `DOMAIN-KEYWORD,`.
  WHY: suffix_match("t.me", "DOMAIN-SUFFIX,t.me") → false; после fix → true.
  EC330 deploy 2026-05-11: t.me → 198.18.0.1 (fake-IP) ✓, ya.ru → real IP ✓.

- **[FIX/core/src/proxy/rules_engine.c]** `MAX_PROVIDER_CACHE` 16 → 64.
  WHY: конфиг содержит 34 rule-provider; при MAX=16 часть не загружалась.

- **[FIX/core/src/proxy/rule_provider.c]** first-boot: `next_update=0` если
  cache file отсутствует. WHY: `now + interval` = 24ч ожидание без файла.

- **[FIX/core/src/proxy/rules_engine.c]** YAML payload parsing: auto-detect
  по "payload:" строке, rewind + парсинг с поддержкой `+./×.` prefix.

- **[FIX/core/src/proxy/rule_provider.c]** `fetch_with_ip_cache`: упрощена
  сигнатура (3 параметра), добавлен mkdir для директории кэша.

- **[NEW/core/include/config.h]** `rp_file_format_t` enum (AUTO/TEXT/YAML).
  `RuleProviderConfig.file_format` — поле для хранения формата файла.

- **[FIX/core/src/config.c]** парсинг `file_format` (yaml/text) в
  SECTION_RULE_PROVIDER.

## [1.5.181] — 2026-05-11

### Fixed / Added (F0-1: geo pipeline + DNS adblock)

- **[FIX/core/src/config.c]** `block_geosite_ads/trackers/threats` = true по умолчанию.
  WHY: без явных defaults `dns_rules_add_geosite` не вызывался → adblock не работал.
  Домены рекламных категорий получали fake-IP вместо NXDOMAIN. Теперь `doubleclick.net`,
  `ads.google.com`, `mc.yandex.ru` → NXDOMAIN без UCI `list block_geosite`.

- **[NEW/tools/Makefile.dev]** target `geo-compile-host` — сборка geo_compile для x86_64
  через musl-gcc. Результат: `prebuilt/host/geo_compile` (23KB).

- **[NEW]** .gbin формат geo баз: mmap() вместо текстового HashSet.
  EC330 RSS: 52MB → 5.8MB (9x экономия). 5 категорий: geosite-ru (1.2M),
  geosite-ads (220K), geosite-trackers (41K), geosite-threats (310K),
  opencck-domains (382K). Развёрнуто на EC330 2026-05-11.

- **[FIX/scripts/geo_update_repos.ps1]** Исправлены источники geo списков:
  geosite-ru: 1andrevich + antifilter (замена недоступных URLs).
  TLS protocol: Tls12 | Tls13. Добавлена pre-check функция `Test-Url`.

- **[FIX/tools/sub_convert.py]** F0-2+F0-3 — полный парсинг Clash YAML:
  - rule-providers: добавлено поле `file_format` (text/yaml/mrs) в UCI `rule_provider`.
    WHY: ранее `format` (кодировка файла) игнорировался; загрузчик не знал как декодировать.
  - Orphan warning: rule-providers без RULE-SET ссылок теперь выводят WARNING с именами.
  - Nameserver/fallback: `_classify_dns_upstream()` вместо `_extract_ip()` →
    DoH серверы → `upstream_doh`, DoT → `upstream_dot`, UDP → `upstream_default`.
    Fallback аналогично: `upstream_doh_fallback` / `upstream_dot_fallback`.
  - `enhanced-mode: fake-ip` → UCI `config main: option fake_ip_enabled '1'`.
  - `fake-ip-filter` (до 50 записей) → `config main: list fake_ip_filter`.
  - `hosts` (до 20 записей) → `config dns: list static_hosts 'domain=ip'`.
  - `mode` (rule/global/direct) → `config main: option mode 'rules/global/direct'`.
  - `_warn_unsupported_sections`: mode warning только для нераспознанных значений.

## [1.5.178] — 2026-05-10

### Fixed (audit_v48)

- **[FIX/proxy/dispatcher.c]** relay_release_upstream: добавлен AnyTLS cleanup
  (anytls_stream_close + pool_return) — устранён USE-AFTER-FREE при AnyTLS failover.
  relay_try_retry: "anytls" добавлен в skip list. ws_client_free добавлен перед
  free(r->ws) в relay_release_upstream — устранён /dev/urandom fd leak при WS retry.

- **[FIX/proxy/protocols/tuic_v5_conn.c + dispatcher.c]** TUIC EPOLLET drain loop:
  RELAY_TUIC_HS и tuic_conn_recv_dispatch — один recv() → for(;;) до EAGAIN.
  tuic_defrag_tick вызывается в dispatcher_tick (итерация по ds->conns[]).

- **[FIX/proxy/protocols/hysteria2.c]** h3frame[600] → static в hy2_http3_auth() и
  hy2_h3_auth_send(). Устранены 2 MIPS stack блокера.

- **[FIX/proxy/protocols/anytls_session.c]** tmp[8192] → static s_anytls_pad_scheme_buf.
  Устранён MIPS stack блокер (8KB >> 512B лимит).

- **[FIX/proxy/protocols/muxcool.c]** stack_buf[1500] → static s_muxcool_stream_buf.
  Устранён MIPS stack блокер на горячем пути UDP relay.

- **[FIX/http_server.c]** cors[384] → static в route_api_backup(). uci_type_to_clash():
  "anytls"/"tuic"/"tuic5" маппинг добавлен. /proxies JSON: anytls_kv + tuic_kv теги.
  WS роутер: /ws/logs + /ws/connections добавлены (как /ws/memory, /ws/traffic).

- **[NEW/proxy/hc_anytls.c + hc_tuic.c]** Честные туннельные HC для AnyTLS (TLS+auth+stream)
  и TUIC v5 (QUIC HS+TLS-Exporter+stream). proxy_group.c: dispatch добавлен для anytls/tuic.
  transport_is_implemented: явные ветки anytls=true, tuic=true с WHY.

- **[FIX/Makefile + README.md]** PKG_VERSION синхронизирован с EBURNET_VERSION.
  README badge обновлён. nftables.h комментарий: старые default значения исправлены.

## [1.5.173] — 2026-05-10

### Added

- **[NEW/proxy/protocols/tuic_v5_proto.c|h]** TUIC v5 wire-протокол: Address encode/decode
  (IPv4/IPv6/domain/None), команды Auth/Connect/Pkt/Dissociate/Heartbeat. deFragger
  (reassembly UDP-фрагментов, TTL-вытеснение). Stream pool (bidi-ID +4, find/remove).
  NewReno CC: slow start, congestion avoidance, loss recovery, `can_send` gate. (~455 LoC)

- **[NEW/proxy/protocols/tuic_v5_conn.c]** QUIC-соединение TUIC v5: wolfSSL QUIC callbacks
  (`cb_set_secrets`, `cb_add_handshake`, `cb_flush`, `cb_recv`). TLS-Exporter auth-token
  (raw UUID bytes → HMAC-SHA256, mihomo-совместимо). `tuic_conn_create/hs_step/send_auth`.
  `tuic_conn_open_tcp` → открытие TCP stream поверх QUIC. `tuic_stream_tcp_send/recv`.
  `tuic_conn_recv_dispatch` (UDP EPOLLIN → deFragger → wake_fd). `tuic_conn_get_fd` +
  `tuic_conn_invalidate_fd` (паттерн HY2, защита от double-close). (~851 LoC)

- **[NEW/proxy/dispatcher.c]** Интеграция TUIC v5 в event loop:
  `RELAY_TUIC_HS = 29` — UDP QUIC HS → `tuic_conn_hs_step` → `tuic_send_auth` →
  `tuic_conn_open_tcp` → регистрация wake_fd (`ep_download.relay = r` явно).
  `RELAY_TUIC_ACTIVE = 30` — 3-way dispatch: client_fd (→ stream_tcp_send),
  ep_download wake_fd (← stream_tcp_recv → write), upstream UDP (← recv_dispatch).
  `tuic_protocol_start`: `dispatcher_resolve_server` → UDP socket + connect →
  `tuic_conn_create` → epoll. `relay_free` cleanup: `tuic_conn_invalidate_fd` +
  `tuic_stream_pool_remove` (wake_fd=-1 guard). `relay_try_retry` skip (tuic/tuic5 UDP).

- **[NEW/include/proxy/dispatcher.h]** `RELAY_TUIC_HS = 29`, `RELAY_TUIC_ACTIVE = 30`
  в `relay_state_t` (под `#if CONFIG_EBURNET_QUIC`). Поля `tuic_conn` + `tuic_stream`
  в `relay_conn_t`.

- **[NEW/include/config.h + src/config.c]** Поля `tuic_uuid[37]`, `tuic_password[128]`,
  `tuic_udp_relay_mode` в `ServerConfig`. Парсинг UCI-опций `tuic_uuid`, `tuic_password`,
  `tuic_udp_relay_mode` (quic=1 / native=0).

- **[NEW/tools/sub_convert.py]** Парсинг `type: tuic/tuic5/tuic-v5` из Clash YAML подписок.
  Поля: uuid, password, udp-relay-mode → UCI `tuic_uuid`, `tuic_password`, `tuic_udp_relay_mode`.

- **[NEW/tests/test_tuic_v5.c]** 99 юнит-тестов: A=wire encode/decode, B=команды,
  C=deFragger (in-order, OOO, multi-pkt, TTL-evict), D=stream pool, E=NewReno CC (ALL PASS).

## [1.5.169] — 2026-05-10

### Added

- **[NEW/proxy/protocols/anytls_frame.c|h]** Wire format encode/decode AnyTLS-кадров.
  7-байтовый заголовок (type, flags, stream_id, length). Функции `anytls_frame_encode`,
  `anytls_frame_decode_header`. (~150 LoC)

- **[NEW/proxy/protocols/anytls_padding.c|h]** Парсер адаптивных схем дополнения (`paddingScheme`).
  Поддержка `writeConn` padding при отправке. Функции `anytls_pad_parse`,
  `anytls_pad_get_size`, `anytls_pad_is_off`, `ANYTLS_DEFAULT_SCHEME`. (~120 LoC)

- **[NEW/proxy/protocols/anytls_session.c|h]** RX state-machine AnyTLS-сессии.
  11 команд протокола (CMD_AUTH, CMD_NEW_STREAM, CMD_DATA, CMD_FIN, CMD_PADDING…).
  TX coalesce + padding через writeConn. Transport-agnostic: `cb_send/cb_recv/cb_free` callbacks.
  SHA256-аутентификация (password → hash → CMD_AUTH). (~600 LoC)

- **[NEW/proxy/protocols/anytls_pool.c|h]** Idle-pool AnyTLS-сессий с TTL.
  `anytls_pool_init/get_idle/return/tick/free`. TTL вытеснение устаревших сессий.
  Индексация по `server_idx`. (~150 LoC)

- **[NEW/proxy/protocols/hc_anytls.c]** Health-check AnyTLS: TCP-connect → TLS-handshake →
  CMD_AUTH → open_stream → send VLESS header → recv response. Честная проверка туннеля. (~120 LoC)

- **[NEW/proxy/dispatcher.c]** Интеграция AnyTLS в event loop:
  `RELAY_ANYTLS_ACTIVE = 26` (dual-fd: upstream_fd=TLS socket, download_fd=stream wake_fd).
  `anytls_pool_init/tick/free` в `dispatcher_init/tick/cleanup`.
  `anytls_protocol_start` (.start fn) + `anytls_install_stream_watcher`.
  TLS_SHAKE dispatch hook: SHA256(password) → session_create → send_auth → open_stream.
  `relay_free` cleanup: stream_close → pool_return или session_free по stream_count.
  `cb_tls_send/recv/free` вынесены из `#if CONFIG_EBURNET_XUDP` в unconditional секцию
  (WHY: используются также AnyTLS и Mux.Cool).

- **[NEW/include/config.h + src/config.c]** Поля `anytls_password[128]` и `anytls_sni[256]`
  в `ServerConfig`. Парсинг UCI-опций `anytls_password`, `anytls_sni`.

- **[NEW/tools/sub_convert.py]** Парсинг `type: anytls` из Clash YAML подписок.
  Поля: password, sni, host, port.

- **[NEW/tests/test_anytls.c]** 54 юнит-теста: frame encode/decode, padding parse,
  session create/auth/stream/recv, pool idle/TTL (ALL PASS).

## [1.5.164] — 2026-05-10

### Removed

- **[REMOVE/include/4eburnet.h]** `DEVICE_MICRO` удалён из enum `DeviceProfile`.
  Константы `MICRO_MAX_CONNECTIONS`, `MICRO_BUFFER_SIZE`, `MICRO_MAX_RULES`, `MICRO_DNS_CACHE_SIZE` удалены.
  Минимальная целевая платформа — EC330 116 МБ RAM → `DEVICE_NORMAL`.
- **[REMOVE/include/device.h]** `RELAY_BUF_MICRO`, `RELAY_CONNS_MICRO`, `DNS_PENDING_MICRO`,
  `DNS_TCP_CLIENTS_MICRO` удалены. Ветки `case DEVICE_MICRO:` удалены из 4 inline-функций.
- **[REMOVE/include/dns/dns_server.h]** `DNS_RATE_TABLE_MICRO` удалён.
- **[REMOVE/src/resource_manager.c]** Ветка `MemTotal < 64MB → DEVICE_MICRO` удалена.
  Fallback при ошибке `/proc/meminfo` → `DEVICE_NORMAL`. Граница NORMAL/FULL: 256 МБ.
  `case DEVICE_MICRO:` удалён из `rm_profile_name`, `rm_max_connections`, `rm_buffer_size`.
- **[REMOVE/src/dns/dns_upstream_doq.c]** Ветка `DEVICE_MICRO: return 0` удалена.
  DoQ (DNS-over-QUIC) теперь доступен на всех поддерживаемых платформах.
  Лог `"DoQ: отключён (MICRO профиль)"` удалён.
- **[REMOVE/src/dns/dns_server.c]** `case DEVICE_MICRO: DNS_RATE_TABLE_MICRO` удалён.
- **[REMOVE/src/dns/fake_ip.c]** `case DEVICE_MICRO: limit = 512` удалён.
- **[REMOVE/src/http_server.c]** Ветка `mem_kb < 65536 → profile = "MICRO"` удалена.
- **[REMOVE/src/ipc.c]** `case DEVICE_MICRO: profile = "MICRO"` удалён.
- **[REMOVE/src/proxy/dispatcher.c]** `case DEVICE_MICRO: MICRO_MAX_CONNECTIONS` удалён.
- **[REMOVE/src/proxy/proxy_group.c]** `case DEVICE_MICRO: max_ms = 1000` удалён.
- **[REMOVE/src/proxy/proxy_provider.c]** `case DEVICE_MICRO: return 256` удалён.
- **[REMOVE/src/proxy/tproxy.c]** `case DEVICE_MICRO: rcvbuf = 64KB` удалён.
- **[REMOVE/core/Kconfig]** Упоминания MICRO в help-текстах удалены.
- **[IMPROVE/README.md]** Badge → v1.5.164; таблица DeviceProfile: строка MICRO удалена,
  описание обновлено: минимальная платформа 116 МБ (EC330).

## [1.5.163] — 2026-05-10

### Changed

- **[IMPROVE/crypto/tls.c]** `tls_global_cleanup()`: добавлен `static bool s_cleaned_up` guard.
  `wolfSSL_Cleanup()` не идемпотентен — повторный вызов возвращает ошибку.
  Guard защищает при будущем рефакторинге main.c и signal handlers. (audit_v47 #5)
- **[IMPROVE/proxy/ja3.c]** Массив `g_references`: добавлена дата верификации `2026-04-22`
  к каждой записи (Chrome 120 / Firefox 121 / Safari 17 / curl 7.x).
  Обновлён комментарий: ритм Chrome-обновлений (~6 недель), назначение массива. (audit_v47 #19)
- **[IMPROVE/proxy/protocols/hysteria2.c]** Добавлен `hy2_ensure_level_flushed()` inline wrapper
  вокруг `hy2_flush_hs()`. В `hy2_cb_add_handshake` условный прямой вызов заменён на wrapper.
  Четыре принудительных вызова (строки ~889/932/1623/1658) помечены WHY-комментарием. (audit_v47 #29)
- **[IMPROVE/README.md]** Badge версии обновлён: `v1.5.97` → `v1.5.163`. (audit_v47 #33)

## [1.5.162] — 2026-05-10

### Changed

- **[IMPROVE/core/include/constants.h]** Централизованы три константы из локальных define:
  `TC_FAST_MARK=0x20U` (из `tc_fast.c`), `IPC_MAX_CLIENTS=8` (из `ipc.c`),
  `DNS_DRAIN_BATCH=32` (из `dns_server.c`). Добавлен блок `Лимиты подсистем`. (audit_v47 #25, #26)
- **[IMPROVE/routing/tc_fast.c]** Удалён локальный `#define TC_FAST_MARK`, добавлен
  `#include "constants.h"`. (audit_v47 #25)
- **[IMPROVE/http_server.c]** `route_set_dns_upstream`: `popen(cmd, "r")` с shell pipeline
  заменён на два последовательных `exec_cmd_safe()` вызова с argv.
  Устраняет риск shell injection, согласуется с остальными UCI вызовами. (audit_v47 #15)

## [1.5.158] — 2026-05-10

### Fixed

- **[BUG/grpc.c]** `grpc_stream_recv` — ложный EAGAIN при заполненном `pending_to_client`.
  После `grpc_connection_recv_dispatch` возвращал `EAGAIN` не проверив, что `feed_data`
  успел заполнить `pending_to_client` текущего stream. Данные оставались в буфере до
  следующего epoll-события. Фикс: `if (pending) goto deliver; errno=EAGAIN; return -1`.
  Метка `deliver:` перед шагом 4 устраняет дублирование проверки (БАГ 1 + БАГ 3).
- **[BUG/grpc.c]** `grpc_connection_recv_dispatch` — `H2_WINDOW_UPDATE` с `length != 4`
  не обрабатывался: попадал в ветку `else` и выполнял тихий drain произвольного числа
  байт вместо завершения соединения. Фикс: явная проверка `length != 4` →
  `conn->state = GRPC_CONN_GOAWAY; errno = EPROTO; return -1`. (БАГ 2)

## [1.5.157] — 2026-05-10

### Changed

- **[REFACTOR/grpc.c]** Унификация `grpc_drain` (Step 1-3 из рефакторинга gRPC):
  - **Step 1**: введена `grpc_build_hpack_raw(svc, auth, out, out_size)` — общая реализация
    HPACK-кодирования для монолит (`grpc_conn_t`) и multiplex (`grpc_connection_t`).
    Оба старых wrapper'а сведены к thin-вызовам.
  - **Step 2**: удалена `grpc_hs_drain_payload` (16 строк). Все 7 call-site заменены
    inline-паттерном `{ uint32_t _n = length; grpc_drain(recv_fn, io_ctx, &_n); }`.
  - **Step 3**: `pending_to_client` предварительно выделяется в `grpc_pool_acquire_stream`
    (оба пути: existing conn + new conn) вместо `realloc` при каждом чтении.
    `GRPC_RECV_DATA` заменяет `realloc` на bounds-check + `memmove`-компактирование
    при нехватке места; `grpc_stream_recv` сбрасывает `len/pos=0` без `free`.

## [1.5.156] — 2026-05-10

### Fixed

- **[BUG/hysteria2.c]** `hy2_cb_add_handshake`: данные разных уровней шифрования
  (Initial/Handshake/Application) смешивались в одном `hs_buf`. При смене уровня
  flush не вызывался, и предыдущие данные отправлялись с неверным ключом.
  Фикс: `if (hs_buf_len && hs_level != level) hy2_flush_hs(conn)` до записи новых данных.
  Добавлен forward-declaration `hy2_flush_hs`. (T0-07/E)
- **[BUG/dispatcher.c]** `RELAY_HY2_CONNECT`: отсутствовал явный HS timeout.
  Глобальный first-byte timeout срабатывает только в `RELAY_ACTIVE`, поэтому зависший
  QUIC handshake мог ждать до общего idle timeout (60с). Фикс: `upstream_first_byte_deadline`
  выставляется в `hysteria2_protocol_start` + проверка в начале `RELAY_HY2_CONNECT`.
  Timeout → `dispatcher_server_result(false)` + `relay_free`. (T0-07/F)
- **[BUG/hysteria2.c]** `hy2_process_incoming`: при `sid == 0` переполнение `auth_rxbuf`
  (512 байт) молча игнорировалось — сервер мог отправить длинный H3 HEADERS frame,
  который бы обрезался без ошибки. Фикс: проверка переполнения → `set_error` + return -1. (T0-07/G)
- **[IMPROVE/dispatcher.c]** `RELAY_HY2_CONNECT`: заменён `relay_free` на `RELAY_FAIL_OR_RETRY`
  в двух точках (HS fail + TCPResponse fail). Hysteria2 теперь участвует в общем
  механизме retry (до 3 попыток в группе), как все остальные транспорты. (T0-07/H)

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

### v2.3.7 (2026-05-13) — audit_v49 §3

- fix(MIPS): `static char entry[1760]` в route_api_connections — превышение лимита 512Б локального буфера на стеке (http_server.c:2978)
- fix(security): snprintf truncation check в route_api_status — при n >= sizeof(s_ipc_buf) возвращает HTTP 500 вместо over-read (http_server.c:1155)
- fix(security): централизованный rate_limit_check для всех /api/* без Bearer токена (http_server.c:3056/3170); удалён дублирующий вызов из route_api_control
- fix(security): Bearer pointer bug — strstr возвращал начало заголовка, а не значение токена; исправлено `auth += strlen("Authorization: Bearer ")` (http_server.c:3157)
- docs: IPC_SCHEMA.md — добавлены dpi-get (cmd 40), dpi-set (cmd 41), таблица HTTP-only эндпоинтов
- docs: user_context.md — исправлена устаревшая запись 4eb_token → setup/api-list[].password

### v2.3.26 (2026-05-14) — ROADMAP актуализирован

- docs: ROADMAP.md полностью переписан (v1.5.178 → v2.3.25)
  Все реализованные фичи перенесены в архив закрытых задач
  Открытые (10 позиций, ~5200 LoC):
  T1-07 QUIC SNI, T1-23 YAML parser, T1-26 graceful reload,
  T2-03 eBPF Flint2, T2-06 AnyTLS BBR padding,
  T3-01 LuCI, T3-02 coverage, T3-03 CI/CD, T3-04 benchmarks, T3-05 release

### v2.3.29 (2026-05-14) — T2-06 AnyTLS BBR-aware RTT-adaptive padding

- feat(anytls): BBR-aware RTT-адаптация padding нижней границы
  anytls.h: observed_rtt_ms в anytls_session_t (EWMA α=0.25);
  anytls_pad_get_size() +rtt_ms: >200ms → lo×2, >100ms → lo×3/2, зажим в hi
  anytls_session.c: anytls_session_update_rtt(); два call site передают sess->observed_rtt_ms
  anytls_pool.c: anytls_pool_update_rtt() — EWMA-обновление idle сессий по server_idx
  dispatcher.c: dispatcher_notify_anytls_rtt() — через g_dispatcher → pool_update_rtt
  dispatcher.h: объявление dispatcher_notify_anytls_rtt()
  proxy_group.c: forward extern + вызов в proxy_group_update_result() и handle_hc_event()
  test_anytls.c: группа E (E1-E6, RTT-адаптация и EWMA); 61 тест ALL PASS
  mipsel binary 3.2MB (unchanged)

### v2.3.27 (2026-05-14) — T1-26 config ref-count UAF fix

- fix(config): атомарный ref-count на EburNetConfig (_Atomic uint32_t ref_count)
  config.h: eburnet_config_ref() / eburnet_config_unref() — acquire/release семантика
  config.c: config_unref() вызывает free только при ref_count==0
  dispatcher.c: config_ref() при старте relay, config_unref() в relay_free()
  main.c: SIGHUP — старый конфиг unref после атомарной замены указателя
  WHY: graceful reload (T1-26) — воркеры держат ссылку на конфиг пока активны;
  без ref-count SIGHUP вызывал UAF при обращении к освобождённому конфигу

### v2.3.28 (2026-05-14) — T1-07 Sniffer QUIC SNI (RFC 9001)

- feat(sniffer): полная расшифровка QUIC Initial packet для SNI extraction (RFC 9001 §5)
  sniffer.h: sniffer_quic_test_derive_keys() под #ifdef EBURNET_TEST; обновлён docstring
  sniffer.c: quic_hkdf_expand_label() — HKDF-Expand-Label (RFC 8446 §7.1) через hmac_sha256_2()
  sniffer.c: quic_derive_initial_keys() — key/iv/hp из DCID; salt QUICv1 RFC 9001 §5.2
  sniffer.c: sniffer_parse_quic_sni() переписан — AES-ECB header protection removal,
  AES-128-GCM payload decrypt, CRYPTO frame scan → sniffer_parse_tls_sni_from_buf()
  test_sniffer.c: T16 (RFC 9001 Appendix A.1 test vectors), T17 (round-trip encrypt→sniff)
  Makefile.dev: test-sniffer — wolfSSL включён в компиляцию тестов
  42 тестов ALL PASS; mipsel binary 3.2MB

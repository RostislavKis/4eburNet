// ================================================================
// USER CONTEXT — Персональный файл пользователя
// P2P v7C.1 · Claude Edition
// ================================================================

[О СЕБЕ]
> ИМЯ: "Ростислав"
> РОЛЬ: "Разработчик и владелец проекта"
> КОНТЕКСТ РАБОТЫ: "Частный проект, разработка в одиночку с AI-ассистентами"
> ЧТО ВАЖНО: "Качество и стабильность кода важнее скорости. Минимум зависимостей."

[ТЕХНИЧЕСКИЙ СТЕК]
> ОСНОВНОЙ СТЕК: "C23 + musl libc + wolfSSL + nftables + LuCI Lua + OpenWrt SDK"
> ИНСТРУМЕНТЫ: "VS Code + Claude Code + Claude Max + Gemini Pro + NotebookLM + Git"
> ОГРАНИЧЕНИЯ: "Без внешних runtime зависимостей. Бинарник ≤4MB. Поддержка слабого железа от 32MB Flash."

[ПРЕДПОЧТЕНИЯ ПО СТИЛЮ]
> ТОНАЛЬНОСТЬ: "технический, как коллега-разработчик, без воды"
> ЧТО НЕ НРАВИТСЯ В ОТВЕТАХ AI: "Лишние объяснения очевидного. Вводные фразы. Повторение того что уже решено."
> ФОРМАТ ПО УМОЛЧАНИЮ: "Сначала суть, потом детали. Код с комментариями на русском. Таблицы где уместно."

[ТЕКУЩИЙ ПРОЕКТ]
> ПРОЕКТ: "phoenix-router"
> ЦЕЛЬ: "Универсальный прокси-пакет для OpenWrt: замена mihomo+podkop+xray одним решением на C"
> ФАЗА: "Аудит v7 завершён → выбор следующего приоритета"
> РЕШЕНИЯ: "C23 + musl static. wolfSSL. nftables only. epoll. DNS async resolver. Compile-time Kconfig флаги."

// ================================================================
// MEMORY BLOCK
// ================================================================
[MEMORY BLOCK]
<memory_block session="phoenix-router-v7-complete" date="2026-04-07">
  <project_state>
    PROJECT: phoenix-router
    STACK: C23 + musl libc + wolfSSL 5.9.0 + nftables + LuCI Lua
    PHASE: Аудит v7 завершён → выбор следующего приоритета из backlog
    LAST_ACTION: Аудит v7 5/5 (09acac5), 62 коммита, ~1020KB
    NEXT_ACTION: см. backlog — много незавершённого перед LuCI
  </project_state>

  <test_devices>
    EC330 (TP-Link EC330-G5u v1) — ВОССТАНОВЛЕН ✅
      CPU: MediaTek MT7621A, MIPS 1004Kc, 2 ядра 880MHz
      RAM: 128MB (116MB доступно)
      Flash: 128MB (46MB свободно)
      Профиль: DEVICE_NORMAL
      OpenWrt: 24.10.0, Kernel 6.6.73
      LuCI: 192.168.2.1, root/openwrt
      Arch: mipsel_24kc (SDK target: ramips/mt7621)
      Примечание: QEMU VM нет nftables/сетевых интерфейсов — это норма

    Flint 2 (GL.iNet GL-MT6000) — НЕ ТРОГАТЬ (192.168.1.1)
      Профиль: DEVICE_FULL
  </test_devices>

  <roadmap>
    ✅ 3.3  MAC per-device routing
    ✅ 3.4  rule-providers + proxy-groups + rules engine
    ✅ 3.5  GeoIP + GeoSite (гибридная архитектура)
    ✅ 3.6  Sniffer TLS SNI
    ✅ DEC-013/025/027 закрыты
    ✅ v1-v7 Аудиты (100%)
    ⏳ backlog_A  Улучшения proxy_group (неблокирующий health-check, IPv6)
    ⏳ backlog_B  Geo инфраструктура (tools/geo_convert.py, antizapret)
    ⏳ backlog_C  DNS улучшения (async DoH/DoT, nameserver-policy, fake-ip)
    ⏳ backlog_D  Patricia trie для CIDR lookup
    ⏳ backlog_E  proxy-providers (URL загрузка серверов/подписки)
    ⏳ backlog_F  DoQ (DEC-026, после QUIC стека)
    ⏳ backlog_G  postinstall.sh + Kconfig интеграция
    ⏳ 4.x  LuCI дашборд — ВЕСЬ (после всего бэкенда)
    ⏳ 5.1  SDK кросс-компиляция aarch64 + mipsel → EC330 + Flint 2
    ⏳ 5.2  Финальное тестирование на железе
  </roadmap>

  <backlog>
    /* ── A: proxy_group улучшения ── */
    V6-01 | Неблокирующий health-check в proxy_group_tick
           | сейчас: TCP connect синхронный, timeout=5s блокирует loop
           | решение: nonblock connect + EPOLLOUT как upstream_connect
    V6-07 | measure_latency IPv6 поддержка
           | сейчас: socket(AF_INET) → IPv6 серверы always unavailable
    V6-02 | Patricia trie для CIDR lookup в geo_match_ip
           | сейчас: O(n) scan, при 14K CIDR узкое место на MIPS 880MHz
           | решение: Patricia trie O(32) ≈ O(1)

    /* ── B: Geo инфраструктура ── */
    tools/geo_convert.py | build-time конвертер geoip.dat/geosite.dat → .lst
                         | нужен для подготовки файлов перед SDK сборкой
    postinstall.sh       | первичная настройка при opkg install
                         | определение региона + загрузка нужных .lst
    antizapret           | интеграция РКН-списков через rule_provider
                         | URL: ежедневное обновление, interval=86400
                         | формат: ipcidr + domain смешанный

    /* ── C: DNS улучшения ── */
    async DoH/DoT resolver | сейчас синхронный с таймаутом 1с
                           | блокирует при каждом DoH/DoT запросе
    nameserver-policy      | DNS routing по домену к конкретному upstream
                           | нужен для разделения RU/иностранных доменов
    fallback DNS + filter  | secondary upstream при таймауте primary
    fake-ip               | виртуальные IP для domain-based routing

    /* ── D: Производительность ── */
    Patricia trie | geo_match_ip O(n→1) для 14K+ CIDR
    suffix bsearch | RULE_SET суффикс O(n→log n) DEC-028

    /* ── E: proxy-providers ── */
    proxy-providers | URL загрузка серверов (подписки)
                    | форматы: vless://, ss://, trojan://, awg://
                    | парсинг Base64 URI → ServerConfig
                    | автообновление через rule_provider механизм

    /* ── F: Протоколы ── */
    DoQ | DNS over QUIC (DEC-026)
        | требует QUIC стек (libngtcp2 или аналог)
        | большая задача, отложена

    /* ── G: Инфраструктура ── */
    Kconfig интеграция | compile-time флаги -DCONFIG_PHOENIX_SS и т.д.
                       | нужен для минимизации бинарника на MICRO
    postinstall.sh     | опkg post-install wizard
    DEC-031            | async getaddrinfo в rule_provider (4.x)
  </backlog>

  <decisions>
    DEC-001 | C23 + musl static
    DEC-002 | wolfSSL 5.9.0 с uTLS fingerprint
    DEC-003 | epoll + io_uring fallback
    DEC-004 | Kconfig compile-time флаги
    DEC-005 | Свой DNS :53, dnsmasq → :5353 ✅
    DEC-006 | nftables ONLY, fw4
    DEC-007 | Логи только tmpfs
    DEC-008 | QEMU VM для тестов
    DEC-009 | Deploy SSH :2222
    DEC-010 | nft subprocess v1 (exec_cmd_safe через posix_spawn)
    DEC-011 | nft -f файл атомарно (mkstemp + 0600)
    DEC-012 | ip subprocess v1
    DEC-013 | device.h профили MICRO/NORMAL/FULL ✅ ЗАКРЫТ
    DEC-014 | dispatcher отдельный epoll
    DEC-015 | epoll data.ptr O(1)
    DEC-016 | half-close shutdown(SHUT_WR) ✅
    DEC-017 | Verdict Maps без auto-merge
    DEC-018 | HW Offload bypass priority -300
    DEC-019 | NTP Bootstrap raw TCP
    DEC-020 | MAC per-device routing ✅
    DEC-021 | VLESS+Reality ✅
    DEC-022 | connect() O_NONBLOCK ✅
    DEC-023 | wolfSSL тег 5.9.0 ✅
    DEC-024 | wolfSSL без OpenSSL compat
    DEC-025 | Reality shortId диагностика ✅ ЗАКРЫТ
    DEC-026 | DoQ после QUIC стека (backlog_F)
    DEC-027 | getaddrinfo для rule_provider URL ✅ ЗАКРЫТ
    DEC-028 | RULE_SET suffix-match O(n) → trie (backlog_D)
    DEC-029 | GeoIP гибридная архитектура ✅
    DEC-030 | LuCI = первый класс UX ✅
    DEC-031 | async getaddrinfo в rule_provider (4.x, backlog_G)
  </decisions>

  <constraints_active>
    - Бинарник ≤4MB (сейчас ~1020KB, запас ~3MB)
    - wolfSSL: /usr/local/musl-wolfssl/ (без BLAKE2s — своя blake2s.c)
    - master epoll в main.c (epoll_wait 10ms)
    - splice отключён (data corruption)
    - popen ТОЛЬКО через exec_cmd_safe (posix_spawn) в net_utils.c
    - nft verdict maps: NO auto-merge
    - DNS/AWG: все параметры из конфига, NO хардкод
    - tai_utc_offset из конфига (default 37)
    - Flint 2 (192.168.1.1) — НЕ ТРОГАТЬ
    - WOLFSSL_PREFIX параметризован в Makefile.dev
    - proxy_group: max 32 серверов, только enabled группы
    - rule_provider: max 16 провайдеров, getaddrinfo, port из URL
    - traffic_rules: max 512 правил, priority ASC
    - geo: .lst файлы в /etc/phoenix/geo/, регион авто
    - device.h: MICRO(<48MB)/NORMAL(<192MB)/FULL — из /proc/meminfo
    - sniffer: MSG_PEEK+MSG_DONTWAIT, никогда не блокирует
    - SNI с null-байтом → отклоняется (RFC 6066)
    - QEMU VM: nftables ошибки при старте — это норма (нет интерфейсов)
  </constraints_active>

  <metrics>
    Бинарник: ~1020 KB (x86_64, не stripped)
    Коммитов: 62 (2893acd → 09acac5)
    Строк кода: ~14800
    Файлов: 67
    Аудит v1: 38/38   (100%)
    Аудит v2: 50/50   (100%)
    Аудит v3: 127/127 (100%)
    Аудит v4: 56/56   (100%)
    Аудит v5: 15/15   (100%)
    Аудит v6: 10/10   (100%)
    Аудит v7: 5/5     (100%)
  </metrics>

  <module_status>
    /* ─── ЯДРО ─── */
    ✅ resource_manager.c  — device_detect_profile()
    ✅ config.c            — все секции + geo/region + reality_short_id
    ✅ ipc.c               — команды 1-4, 10-14, 20-26
    ✅ main.c              — профиль устройства, лимиты из device.h
    ✅ net_utils.c         — exec_cmd_safe, net_random_bytes, json_escape_str
    ✅ ntp_bootstrap.c
    ✅ device.h            — MICRO/NORMAL/FULL профили

    /* ─── МАРШРУТИЗАЦИЯ ─── */
    ✅ routing/nftables.c, policy.c, rules_loader.c, device_policy.c

    /* ─── ПРОКСИ ─── */
    ✅ proxy/tproxy.c
    ✅ proxy/dispatcher.c   — DIRECT relay, SNI sniffer, rules_engine
    ✅ proxy/sniffer.c      — RFC 5246/6066 парсер, null-байт защита
    ✅ proxy/proxy_group.c  — SELECT/URL_TEST/FALLBACK/LOAD_BALANCE
    ✅ proxy/rule_provider.c — HTTP+TLS, getaddrinfo, port из URL
    ✅ proxy/rules_engine.c  — 8 типов правил (DOMAIN..GEOSITE)

    /* ─── ПРОТОКОЛЫ ─── */
    ✅ vless.c, vless_xhttp.c, trojan.c, shadowsocks.c, awg.c

    /* ─── КРИПТО ─── */
    ✅ tls.c (tls_get_client_random), blake3.c, blake2s.c, noise.c

    /* ─── DNS ─── */
    ✅ dns_packet.c, dns_cache.c, dns_rules.c, dns_upstream.c
    ✅ dns_server.c (async UDP, rate limit)
    ✅ dns_resolver.c (pending queue, CLOCK_MONOTONIC, IPv6)

    /* ─── GEO ─── */
    ✅ geo/geo_loader.c — CIDR+domain, binary search, region detect,
                          Europe/* явный список, strtol prefix, hot-reload

    /* ─── НЕ РЕАЛИЗОВАНО ─── */
    ⏳ proxy/proxy_group.c  — nonblock health-check (backlog_A V6-01)
    ⏳ geo/geo_loader.c     — Patricia trie (backlog_D V6-02)
    ⏳ tools/geo_convert.py — build-time dat→lst (backlog_B)
    ⏳ postinstall.sh       — opkg wizard (backlog_B/G)
    ⏳ 4.x luci-app-phoenix — полный дашборд (последнее)
    ⏳ 5.1 SDK ipk          — кросс-компиляция
  </module_status>

  <audit_history>
    v1: 38/38   CRITICAL/HIGH/MEDIUM/LOW
    v2: 50/50   stub файлы, popen инкапсулирован
    v3: 127/127 async DNS, getrandom, exec_cmd_safe, TAI64N
    v4: 56/56   DNS cache poisoning, Noise replay, stream fixes
    v5: 15/15   to_json overflow, IPv6 CIDR, config OOM
    v6: 10/10   Europe/* fix, http port, RULES_LIST buffer, cache format
    v7: 5/5     sniffer UB (V7-01/02), null-SNI bypass (V7-03), errno.h
  </audit_history>

  <key_architecture_notes>
    - blake2s_hmac = keyed BLAKE2s (WG spec, не RFC 2104)
    - verify_cert=false для DoT/DoH — намеренно для РФ
    - DNS upstream UDP — async через pending queue + epoll
    - SS 2022 framed protocol — EAGAIN = fatal
    - tai_utc_offset = 37 (обновить при новых leap seconds)
    - rules_engine: s_cache глобальный — безопасно (однопоток)
    - proxy_group_tick: 1 сервер за вызов (H-1 fix v5)
    - rule_provider_tick: 1 провайдер за вызов (H-4 fix v5)
    - DIRECT relay: relay_alloc + nonblock connect(dst) + epoll
    - sniffer: MSG_PEEK+MSG_DONTWAIT, partial ClientHello ok (V7-01)
    - SNI null-байт → return 0, domain=NULL (V7-03 RFC 6066)
    - geo: регион из конфига → timezone (явные RU зоны) → UNKNOWN
    - device.h: профиль из /proc/meminfo MemTotal
    - LuCI = главный UI (DEC-030), UCI/SSH для опытных
    - EC330: DEVICE_NORMAL (116MB RAM, 46MB disk, mipsel_24kc)
    - QEMU VM: nftables errors при старте — норма (нет интерфейсов)
  </key_architecture_notes>
</memory_block>

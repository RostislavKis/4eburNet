// ================================================================
// USER CONTEXT — Персональный файл пользователя
// P2P v7C.1 · Claude Edition
// Обновлено: 2026-04-11 (4eburNet v2.0 — C.5 dispatcher DPI)
// ================================================================

[О СЕБЕ]
> ИМЯ: "Ростислав"
> РОЛЬ: "Разработчик и владелец проекта"
> КОНТЕКСТ РАБОТЫ: "Частный проект, разработка в одиночку с AI-ассистентами"
> ЧТО ВАЖНО: "Качество и стабильность кода важнее скорости. Никаких заглушек, хардкода, хвостов."

[ТЕХНИЧЕСКИЙ СТЕК]
> ОСНОВНОЙ СТЕК: "C23 + musl libc + wolfSSL + nftables + LuCI (ucode/JS) + OpenWrt SDK"
> ИНСТРУМЕНТЫ: "VS Code + Claude Code + Claude Max + Gemini Pro + NotebookLM + Git"
> ОГРАНИЧЕНИЯ: "Без внешних runtime зависимостей. Бинарник ≤4MB. MIPS стек 8KB. musl static."

[ПРЕДПОЧТЕНИЯ ПО СТИЛЮ]
> ТОНАЛЬНОСТЬ: "технический, как коллега-разработчик, без воды"
> ЧТО НЕ НРАВИТСЯ В ОТВЕТАХ AI: "Лишние объяснения очевидного. Вводные фразы. Повторение того что уже решено."
> ФОРМАТ ПО УМОЛЧАНИЮ: "Сначала суть, потом детали. Код с комментариями на русском. Таблицы где уместно."

[ТЕКУЩИЙ ПРОЕКТ]
> ПРОЕКТ: "4eburNet (переименован из phoenix-router)"
> ЦЕЛЬ: "Универсальный прокси + DPI bypass для OpenWrt. Замена mihomo+podkop+xray одним бинарником на C."
> ФАЗА: "v2.0 — C.5 выполнен, переход к C.6 (UCI конфиг + LuCI dpi.js)"
> БИНАРНИК: "1.6MB (лимит 4MB)"
> КОММИТОВ: "~200+"
> СТРОК: "~27000+"

// ================================================================
// MEMORY BLOCK — 4eburNet v2.0
// ================================================================
[MEMORY BLOCK]
<memory_block session="4eburnet-v2-c5-complete" date="2026-04-11">

  <project_state>
    PROJECT: 4eburNet
    STACK: C23 + musl libc + wolfSSL + nftables + LuCI (ucode + JS)
    REPO: /home/rosti/phoenix-router-dev/project/4eburNet/
    BUILD: cd core && make -f Makefile.dev (PROFILE=micro|normal|full)
    BINARY: 1.6MB (target ≤4MB)
    LAST_COMMIT: 25903cd (fix: audit_v18 — все 🟡 закрыты)
    TEST_DEVICE: EC330 (192.168.2.1, mipsel_24kc) — тестирование
    FLINT2: 192.168.1.1 — НЕ ТРОГАТЬ
    QEMU: 127.0.0.1:2222 (SSH root, make install-vm)
  </project_state>

  <roadmap_v2>
    БЛОК A (инфра — ЗАВЕРШЁН):
      ✅ A.1 Hotplug WAN detect
      ✅ A.2 TPROXY mark 0x01 + ip rule table 100
      ✅ A.3 sub_convert.py (Clash YAML → UCI)

    БЛОК B (Hysteria2 — ПОЛНОСТЬЮ ЗАВЕРШЁН):
      ✅ B.1 blake2b.c (RFC 7693)
      ✅ B.2 quic_salamander.c (unified XOR counter i=0..N)
      ✅ B.3 hysteria2.c (TCP streams, HTTP/3 CONNECT + Hysteria-Auth)
      ✅ B.4 hysteria2_udp.c (UDP v2 wire format, 33 теста)
      ✅ B.5 brutal_cc.c (actual=target/(1-loss), token bucket, EWMA RTT)
      ✅ B.6 hysteria2:// URI парсер + proxy_provider интеграция (43 теста)
      ✅ B.7 LuCI Hysteria2 UI (servers.js + 4eburnet.uc + config.c)
      ✅ audit_v9..v13: все закрыты

    БЛОК C (DPI bypass — В ПРОЦЕССЕ):
      ✅ C.1 dpi_filter.c (ipset/whitelist/autohosts, sorted array + bsearch, 41 тест)
      ✅ C.2 dpi_payload.c (fake TLS Chrome120+ + QUIC Initial, 19 тестов)
      ✅ C.3 dpi_strategy.c (fragment + fake+TTL, retry loops, TCP_NODELAY save/restore)
      ✅ C.4 cdn_updater.c (Cloudflare+Fastly автообновление, 30 тестов)
      ✅ C.5 dispatcher интеграция (DIRECT-only DPI, IPv6 matching, malloc не стек)
      ✅ audit_v14..v18: все закрыты, все 🔴🟡 исправлены
      ⏳ C.6 UCI конфиг + LuCI dpi.js ← СЛЕДУЮЩИЙ
      ⏳ D ShadowTLS v3 (низкий приоритет — Aparecium detection)
      ⏳ E SDK + audit3 + v1.0.0
  </roadmap_v2>

  <test_suites>
    9 тест-суитов, ALL PASS (~215+ тестов):
      test_blake2b          —  4 теста
      test_salamander       —  6 тестов
      test_hysteria2_uri    — 43 теста
      test_hysteria2_udp    — 33 теста
      test_hysteria2_cc     — 31 тест
      test_dpi_filter       — 41 тест
      test_dpi_payload      — 19 тестов
      test_dpi_strategy     —  8 функций
      test_cdn_updater      — 30 тестов
  </test_suites>

  <dpi_architecture>
    Принцип:
      DPI bypass ТОЛЬКО для DIRECT соединений (server_idx=-1).
      Proxy соединения (VLESS/Trojan/SS/AWG/Hysteria2) без DPI (трафик в туннеле).
      Пользователь управляет только routing: домен → proxy / DPI bypass / direct.
      Всё остальное автоматически.

    Источники CDN IP (автообновление, default раз в 7 дней):
      Cloudflare IPv4: https://www.cloudflare.com/ips-v4
      Cloudflare IPv6: https://www.cloudflare.com/ips-v6
      Fastly:          https://api.fastly.com/public-ip-list (JSON)

    Стратегия TCP 443 (запрет-совместимая):
      1. dpi_send_fake:     8× fake TLS ClientHello с TTL=5 (не достигает CDN)
      2. dpi_send_fragment: split_pos=1, TCP_NODELAY, два send() с retry loop

    Файлы DPI подсистемы:
      core/include/dpi/: dpi_filter.h, dpi_payload.h, dpi_strategy.h, cdn_updater.h
      core/src/dpi/:     dpi_filter.c, dpi_payload.c, dpi_strategy.c, cdn_updater.c
      core/tests/:       test_dpi_filter.c, test_dpi_payload.c,
                         test_dpi_strategy.c, test_cdn_updater.c
      luci-app-4eburnet/files/etc/4eburnet/dpi/:
                         ipset.txt (CDN CIDR), whitelist.txt, autohosts.txt
                         ipset.stamp (timestamp последнего обновления)
  </dpi_architecture>

  <config_fields_dpi>
    В EburNetConfig (config.h):
      bool    dpi_enabled               /* default true */
      int     dpi_split_pos             /* default 1 */
      int     dpi_fake_ttl              /* default 5 */
      int     dpi_fake_repeats          /* default 8 */
      char    dpi_fake_sni[256]         /* default "www.google.com" */
      char    dpi_dir[256]              /* default "/etc/4eburnet/dpi" */
      int     cdn_update_interval_days  /* default 7, 0=выкл */
      char    cdn_cf_v4_url[256]        /* "" = встроенный default */
      char    cdn_cf_v6_url[256]
      char    cdn_fastly_url[256]

    UCI пример:
      config eburnet 'main'
          option dpi_enabled '1'
          option dpi_split_pos '1'
          option dpi_fake_ttl '5'
          option dpi_fake_repeats '8'
          option dpi_fake_sni 'www.google.com'
          option cdn_update_interval_days '7'
  </config_fields_dpi>

  <audit_history>
    audit_v9:  B.1 blake2b — чистый
    audit_v10: B.2 salamander — чистый
    audit_v11: B.3 hysteria2 TCP — закрыт
    audit_v12: B.4-B.5 UDP+CC — закрыт
    audit_v13: B.7 LuCI Hysteria2 UI — закрыт (auth slot fix, NUL terminators)
    audit_v14: C.1 dpi_filter — закрыт (hi-4 bug, strtol endptr, тест deep search)
    audit_v15: C.3 dpi_strategy + config fixes — закрыт (TCP_NODELAY restore,
               partial send, getsockopt, DoQ UCI, dpi int fields LOG_WARN)
    audit_v16: C.4 cdn_updater — закрыт (PID tmp, strict aliasing, stamp_write,
               ferror, fclose before rename, CIDR валидация, future timestamp)
    audit_v17: cdn_updater финальный — закрыт (interval<=0, cidr_size API,
               ts>now UB, комментарий)
    audit_v18: C.5 dispatcher — закрыт (partial send retry, IPv6 match,
               double-log, double init strat)
    Следующий: audit_v19 (после C.6)
  </audit_history>

  <key_decisions>
    ТСПУ bypass:
      - fake+TTL: IP_TTL=5, fake TLS ClientHello × repeats (не достигает CDN)
      - fragment: TCP_NODELAY split_pos=1 (DPI видит неполный ClientHello)
      - Только DIRECT path (не proxy туннели)

    cdn_updater:
      - PID-суффикс в /tmp/cdn_*_PID.txt (не race condition)
      - malloc(1300) для fake payload (не стек MIPS 8KB)
      - CDN_CIDR_SIZE=64 константа, cidr_size убран из публичного API
      - timestamp из будущего в stamp → stale=1 (защита от NTP desync)
      - interval_days <= 0 → выключено (defence-in-depth)
      - Горячая перезагрузка: dpi_filter_init() после обновления ipset.txt

    dispatcher:
      - IPv6 dst6 извлекается, передаётся в dpi_filter_match
      - retry loop в dpi_send_fragment (как в relay_transfer)
      - dpi_first_done=true ДО отправки (защита от повтора)
      - dpi_bypass=false для proxy, IGNORE, NONE — только BYPASS+DIRECT

    config.c:
      - Все bool: if/elif/else + LOG_WARN (не тихий false)
      - Все int: strtol с endptr + валидация диапазона + LOG_WARN
      - DoQ поля парсятся из UCI (4 ветви добавлены)
  </key_decisions>

  <constraints_active>
    - nft table: "eburnet" (не "4eburnet")
    - posix_spawnp для nft/ip (не shell)
    - wolfSSL /usr/local/musl-wolfssl/
    - Salamander: unified XOR counter i=0..N
    - explicit_bzero() для паролей
    - MIPS stack: нет VLAs, malloc для буферов > ~512 байт
    - Kconfig: #if CONFIG_EBURNET_X (не #ifdef)
    - dpi_send_fragment: retry loop (не single send)
    - Makefile: все 9 Kconfig флагов во всех профилях (micro/normal/full)
    - EC330 (192.168.2.1) — тест; Flint2 (192.168.1.1) — НЕ ТРОГАТЬ
    - Бинарник: 1.6MB текущий, лимит 4MB
    - NOT thread-safe: dpi_filter_init / cdn_updater_update — только epoll loop
    - IPC: /var/run/4eburnet.sock, chmod 600, только root (SO_PEERCRED fail-secure)
    - DNS BYPASS: НИКОГДА через DoH/DoT (только UDP bypass upstream)
    - VMess: не реализовывать (устаревший протокол)
  </constraints_active>

  <prompting_rules>
    1. Шаги ≤50 строк → компиляция → следующий шаг
    2. Тесты ПЕРЕД реализацией (контракты до кода)
    3. Проверки конкретные — сценарии, не "0 ошибок"
    4. Если Claude Code хочет код ОТ СЕБЯ — ПЛАН + ожидание одобрения
    5. После каждого блока roadmap: devil audit → docs/audit_vN.md → исправления
    6. Никаких заглушек, хардкода, хвостов, моков
    7. Продакшен проект — код должен быть идеальным
    8. Текущий номер аудита: v18 (следующий: v19 после C.6)
  </prompting_rules>

  <file_structure>
    core/
      include/
        config.h, 4eburnet.h, net_utils.h, 4eburnet_config.h
        proxy/dispatcher.h, tproxy.h, sniffer.h
        dpi/dpi_filter.h, dpi_payload.h, dpi_strategy.h, cdn_updater.h
        crypto/tls.h, blake2b.h, quic_salamander.h, quic.h
        proxy/hysteria2.h, hysteria2_udp.h, hysteria2_cc.h
      src/
        config.c, main.c, log.c, ipc.c, net_utils.c, ntp_bootstrap.c
        proxy/dispatcher.c, tproxy.c, sniffer.c
        dpi/dpi_filter.c, dpi_payload.c, dpi_strategy.c, cdn_updater.c
        crypto/tls.c, blake2b.c, quic_salamander.c, quic.c
        proxy/protocols/hysteria2.c, hysteria2_udp.c, hysteria2_cc.c
        routing/nftables.c, policy.c, device_policy.c, rules_loader.c
        dns/dns_packet.c, dns_cache.c, dns_rules.c, dns_upstream.c,
             dns_upstream_async.c, dns_upstream_doq.c, dns_server.c,
             dns_resolver.c, fake_ip.c
        geo/geo_loader.c
      tests/
        test_blake2b.c, test_salamander.c, test_hysteria2_uri.c,
        test_hysteria2_udp.c, test_hysteria2_cc.c,
        test_dpi_filter.c, test_dpi_payload.c,
        test_dpi_strategy.c, test_cdn_updater.c
      Kconfig, Makefile.dev
    luci-app-4eburnet/
      htdocs/.../view/4eburnet/servers.js
      root/.../ucode/4eburnet.uc
      files/etc/4eburnet/dpi/
    docs/
      audit_v9.md .. audit_v18.md
    tools/
      dpi_assets/zapret_strategies_2026-04.txt
      sub_convert.py
  </file_structure>

</memory_block>

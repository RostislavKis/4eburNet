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
> ФАЗА: "Этап 1 — реализация phoenixd (управляющий демон)"
> РЕШЕНИЯ: "C23 + musl static. wolfSSL. nftables only. io_uring + epoll fallback. DNS свой демон. Compile-time Kconfig флаги для протоколов."

// ================================================================
// MEMORY BLOCK
// ================================================================

[MEMORY BLOCK]
<memory_block session="phoenix-router-016" date="2026-04-04">
  <project_state>
    PROJECT: phoenix-router
    STACK: C23 + musl libc + wolfSSL 5.9.0 + nftables + LuCI Lua
    PHASE: Этап 3 продолжение — per-device routing или AWG
    LAST_ACTION: DNS демон реализован, 32 коммита, 949KB
    NEXT_ACTION: "3.3" per-device MAC routing / "awg" / "audit2" / "sdk"
  </project_state>
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
    DEC-010 | nft subprocess v1
    DEC-011 | nft -f файл атомарно
    DEC-012 | ip subprocess v1
    DEC-013 | DeviceProfile → device.h (долг)
    DEC-014 | dispatcher отдельный epoll
    DEC-015 | epoll data.ptr O(1)
    DEC-016 | half-close shutdown(SHUT_WR) ✅
    DEC-017 | Verdict Maps без auto-merge
    DEC-018 | HW Offload bypass priority -300
    DEC-019 | NTP Bootstrap raw TCP
    DEC-020 | MAC per-device routing (в 3.3)
    DEC-021 | VLESS+Reality первый протокол ✅
    DEC-022 | connect() O_NONBLOCK + select retry ✅
    DEC-023 | wolfSSL тег 5.9.0 в dev-setup.sh ✅
    DEC-024 | wolfSSL без OpenSSL compat, ошибки через get_error
    DEC-025 | Reality HMAC аутентификация — v2.x
    DEC-026 | DoQ реализовать вместе с QUIC стеком (после AWG)
  </decisions>
  <constraints_active>
    - Бинарник ≤4MB (сейчас 949KB)
    - wolfSSL: /usr/local/musl-wolfssl/
    - master epoll в main.c
    - splice отключён
    - popen ТОЛЬКО в net_utils.c
    - nft verdict maps: NO auto-merge
    - DNS: все upstream/правила/порты из конфига, NO хардкод
    - Flint 2 (192.168.1.1) — НЕ ТРОГАТЬ
  </constraints_active>
  <metrics>
    Бинарник: 949 KB (x86_64, не stripped)
    Коммитов: 32 (2893acd → bbb93ba)
    Строк кода: ~9100
    Аудит v1: 38/38 (100%)
  </metrics>
  <module_status>
    ✅ resource_manager.c
    ✅ config.c (DnsConfig + DnsRule)
    ✅ ipc.c
    ✅ main.c
    ✅ net_utils.c
    ✅ routing/nftables.c
    ✅ routing/policy.c
    ✅ routing/rules_loader.c
    ✅ proxy/tproxy.c
    ✅ proxy/dispatcher.c
    ✅ ntp_bootstrap.c
    ✅ crypto/tls.c + blake3.c
    ✅ proxy/protocols/vless.c
    ✅ proxy/protocols/vless_xhttp.c
    ✅ proxy/protocols/trojan.c
    ✅ proxy/protocols/shadowsocks.c
    ✅ dns/dns_packet.c
    ✅ dns/dns_cache.c
    ✅ dns/dns_rules.c
    ✅ dns/dns_upstream.c (UDP + DoT + DoH)
    ✅ dns/dns_server.c
    ✅ scripts/dev-setup.sh
    ⏳ per-device routing (3.3, DEC-020)
    ⏳ awg (crypto/noise.c + proxy/protocols/awg.c)
    ⏳ luci-app-phoenix/*
  </module_status>
  <dns_config_note>
    DNS конфиг — пример без хардкода:
    option upstream_bypass '77.88.8.1'  ← провайдерский или Яндекс
    option upstream_proxy  '8.8.8.8'   ← через прокси
    option upstream_default '77.88.8.1'
    DoH: doh_url + doh_sni (IP адрес для connect)
    DoT: dot_server_ip + dot_port + dot_sni
  </dns_config_note>
</memory_block>
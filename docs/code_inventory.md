# Code Inventory — 4eburNet
## Дата: 2026-04-18

## Реализованные модули

| Файл | Строк | Ключевые функции |
|------|-------|-----------------|
| **main.c** | 1109 | main(), handle_reload(), geo_load_region_categories() |
| **config.c** | 1358 | config_load(), config_free(), config_dump() |
| **ipc.c** | 682 | ipc_server_init(), ipc_process(), ipc_send_command(), ipc_connect_nonblock() |
| **http_server.c** | 954 | http_server_init(), http_server_handle(), route_api_status(), route_api_control() |
| **net_utils.c** | 913 | tcp_connect_nonblock(), tls_connect_wrap(), resolve_hostname() |
| **log.c** | ~80 | log_msg(), log_set_level() |
| **ntp_bootstrap.c** | ~120 | ntp_http_bootstrap() |
| **resource_manager.c** | ~150 | resource_manager_init(), resource_manager_free() |
| **stats.c** | ~100 | stats_init(), atomic counters |
| **proxy/dispatcher.c** | 1944 | dispatcher_init(), relay_free(), vless_protocol_start(), trojan_protocol_start(), SNI sniffer интеграция (3.6) |
| **proxy/tproxy.c** | 497 | tproxy_init(), tproxy_get_orig_dst() |
| **proxy/rules_engine.c** | 467 | rules_engine_init(), rules_engine_match(), traffic_rules_consult() |
| **proxy/proxy_group.c** | 472 | proxy_group_init(), proxy_group_select(), health_check() |
| **proxy/proxy_provider.c** | 921 | proxy_provider_init(), proxy_provider_load_all() |
| **proxy/rule_provider.c** | 276 | rule_provider_init(), rule_provider_load_all() |
| **proxy/sniffer.c** | ~120 | sniffer_peek_sni() — MSG_PEEK TLS ClientHello → SNI |
| **proxy/protocols/vless.c** | ~350 | vless_protocol_start(), vless_handshake_start(), vless_read_response_step() |
| **proxy/protocols/vless_xhttp.c** | 380 | vless_xhttp_start(), relay_handle_xhttp() |
| **proxy/protocols/trojan.c** | ~300 | trojan_protocol_start(), trojan_handshake_start() |
| **proxy/protocols/shadowsocks.c** | 429 | ss_protocol_start(), ss_2022_handshake() |
| **proxy/protocols/awg.c** | 518 | awg_handshake(), noise_handshake WireGuard |
| **proxy/protocols/shadowtls.c** | 280 | shadowtls_connect(), shadowtls_relay() |
| **proxy/protocols/hysteria2.c** | 1506 | hysteria2_connect(), QUIC transport |
| **proxy/protocols/hysteria2_udp.c** | 283 | hysteria2_udp_send(), hysteria2_udp_recv() |
| **proxy/protocols/hysteria2_cc.c** | ~180 | BBR congestion control |
| **dns/dns_server.c** | 1357 | dns_server_init(), handle_udp_query(), dns_server_handle_event() |
| **dns/dns_rules.c** | 461 | dns_rules_init(), dns_rules_match(), geosite_check(), dns_rules_rebuild_index() |
| **dns/dns_cache.c** | ~155 | dns_cache_init(), dns_cache_get(), dns_cache_put() — LRU 256×512B |
| **dns/dns_packet.c** | ~230 | dns_parse_query(), dns_build_a_reply(), dns_build_nxdomain() |
| **dns/dns_resolver.c** | ~200 | dns_pending_init(), dns_pending_add(), dns_pending_complete() |
| **dns/dns_upstream.c** | 348 | dns_upstream_query_dot(), dns_upstream_query_doh() |
| **dns/dns_upstream_async.c** | 668 | async_dns_dot_start(), async_dns_doh_start(), async_dns_pool_tick() |
| **dns/dns_upstream_doq.c** | 1051 | doq_pool_init(), doq_query_start(), doq_pool_free() |
| **dns/fake_ip.c** | 520 | fake_ip_init(), fake_ip_assign(), fake_ip_lookup_by_ip() |
| **geo/geo_loader.c** | 581 | geo_manager_init(), geo_load_category(), geo_match_ip(), geo_match_domain() |
| **routing/nftables.c** | 1210 | nftables_apply_rules(), nftables_add_verdict_map(), nftables_flush() |
| **routing/policy.c** | 338 | policy_init(), policy_apply(), ip_rule_add() |
| **routing/rules_loader.c** | ~250 | rules_load_file(), rules_apply_bypass() |
| **routing/device_policy.c** | 313 | device_policy_init(), device_policy_apply() |
| **dpi/dpi_filter.c** | 411 | dpi_filter_init(), dpi_filter_match() |
| **dpi/dpi_payload.c** | 273 | dpi_build_fake_payload(), dpi_fragment_packet() |
| **dpi/dpi_strategy.c** | ~200 | dpi_strategy_select(), dpi_strategy_apply() |
| **dpi/cdn_updater.c** | 449 | cdn_updater_init(), cdn_fetch_list(), cdn_apply() |
| **crypto/tls.c** | 467 | tls_global_init(), tls_connect_start(), tls_connect_step(), tls_close() |
| **crypto/noise.c** | 577 | noise_init(), noise_handshake_init_create(), noise_encrypt(), noise_decrypt() |
| **crypto/quic.c** | 299 | quic_keys_derive(), quic_aead_protect(), quic_hp_apply() |
| **crypto/quic_salamander.c** | ~150 | salamander_init(), salamander_process() |
| **crypto/blake2b.c** | 316 | blake2b(), blake2b_salamander() |
| **crypto/blake2s.c** | ~160 | blake2s_hash(), blake2s_hmac() |
| **crypto/blake3.c** | ~200 | blake3_hasher_init_derive_key(), blake3_hasher_finalize() |
| **crypto/hmac_sha256.c** | ~80 | hmac_sha256(), hmac_sha256_verify() |

**Итого: 51 .c файл, ~25 387 строк**

## Статус блоков

| Блок | Статус | Что реализовано |
|------|--------|----------------|
| **D (Dashboard)** | ✅ | http_server.c, dashboard.html, /api/status /api/servers /api/control, Bearer auth, CORS fix |
| **3.5 (GeoIP/GeoSite)** | ✅ | geo_loader.c, dns_rules GEOSITE, opencck provider, fake-ip 198.51.100.0/24 |
| **3.6.1 (SNI Sniffer)** | ✅ | sniffer.c → sniffer_peek_sni() — MSG_PEEK, MIPS-safe стек 512B, null-byte защита |
| **3.6.2 (Dispatcher интеграция)** | ✅ | dispatcher.c:1103 — fake-ip → SNI fallback → rules_engine |
| **3.6.3 (audit_v30)** | ✅ | 15 блокеров + 33 проблемы закрыты |
| **VLESS+Reality** | ✅ | vless.c + tls.c + wolfSSL uTLS fingerprint |
| **VLESS+XHTTP** | ✅ | vless_xhttp.c — HTTP-чанки + padding |
| **AmneziaWG** | ✅ | awg.c + noise.c — Noise_IKpsk2, обфускация jc/jmin/jmax |
| **Trojan** | ✅ | trojan.c + TLS |
| **Shadowsocks 2022** | ✅ | shadowsocks.c — AEAD-2022 |
| **ShadowTLS** | ✅ | shadowtls.c |
| **Hysteria2** | ✅ | hysteria2.c + QUIC + BBR CC |
| **DNS :53** | ✅ | dns_server.c — UDP+TCP, DoH, DoT, DoQ, кэш LRU |
| **DPI bypass** | ✅ | dpi_filter/payload/strategy, fake-TTL, fragmentation |
| **CDN auto-update** | ✅ | cdn_updater.c — opencck 6h cron |
| **nftables routing** | ✅ | nftables.c — Verdict Maps, TPROXY, device per-MAC |
| **NTP bootstrap** | ✅ | ntp_bootstrap.c — HTTP Date перед wolfSSL |
| **sub_convert** | ✅ | sub_convert.py — Clash YAML → UCI, AWG, DST-PORT |
| **CI/CD** | ✅ | .github/workflows/build.yml |
| **test-sniffer** | ❌ | тест test_sniffer.c не написан — нет в Makefile.dev |

## Незавершённые функции

Grep по TODO/FIXME/DEBT/STUB в `core/src/`:

**Результат: 0 — все технические долги закрыты в audit_v30.**

## Следующие шаги

| Задача | Приоритет | Файлы |
|--------|-----------|-------|
| test_sniffer.c — юнит-тест sniffer_peek_sni() | Medium | core/tests/, Makefile.dev |
| audit_v31 | После теста | docs/ |
| v1.1-1: Binary geo + mmap (877K доменов, 38MB RSS → ~5MB) | High | geo_loader.c, geo_compile.sh |
| v1.1-2: io_uring IPC | Medium | ipc.c, main.c |
| v1.1-3: nftables flow offload | Medium | nftables.c |

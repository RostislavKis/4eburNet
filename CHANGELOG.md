# Changelog

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

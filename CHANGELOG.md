# Changelog

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

<div align="center">
  <img src="4eburNet.png" width="200" alt="4eburNet">
  <h1>4eburNet</h1>
  <p>Прокси-маршрутизатор для OpenWrt — один бинарник вместо mihomo + xray + podkop</p>
  <p>
    <img src="https://img.shields.io/badge/версия-v1.5.163-brightgreen?style=flat-square">
    <img src="https://img.shields.io/badge/OpenWrt-23.05%20%2F%2024.10%20%2F%2025.12-blue?style=flat-square">
    <img src="https://img.shields.io/badge/arch-mipsel%20%7C%20aarch64%20%7C%20x86__64-green?style=flat-square">
    <img src="https://img.shields.io/badge/бинарник-3.0%20МБ-orange?style=flat-square">
    <img src="https://img.shields.io/badge/wolfSSL-5.9.0-blue?style=flat-square">
    <img src="https://img.shields.io/badge/license-GPLv2-lightgrey?style=flat-square">
  </p>
</div>

---

Демон написан на C23, статически слинкован с musl libc и wolfSSL, устанавливается одним `.ipk` пакетом. Никаких зависимостей — ни Python, ни Go runtime, ни Node.js. Весь трафик с устройств в сети маршрутизируется автоматически: российские ресурсы идут напрямую, заблокированные — через прокси.

Работает на роутерах с 128 МБ RAM (TP-Link EC330 с MT7621A) без тюнинга. Тот же бинарник запускается на 512 МБ Flint 2 и автоматически адаптирует лимиты под доступную память через `/proc/meminfo` при старте.

---

## Зачем это нужно, если есть mihomo/xray

Mihomo и xray написаны на Go — их бинарники от 15 до 20 МБ, они требуют отдельной настройки каждого компонента и не умеют в некоторые вещи, которые здесь работают из коробки.

| | 4eburNet | mihomo | xray |
|---|:---:|:---:|:---:|
| Размер бинарника | **2.8 МБ** | ~15 МБ | ~20 МБ |
| Зависимости | нет | Go runtime | Go runtime |
| Встроенный DNS | ✅ | ✅ | ❌ |
| Adaptive DPI bypass | ✅ | ❌ | ❌ |
| TC Fast Path для LAN | ✅ | ❌ | ❌ |
| JA3/JA4 fingerprint контроль | ✅ | ❌ | ❌ |
| nftables Flow Offload | ✅ | ❌ | ❌ |
| GeoIP/GeoSite (mmap, Bloom filter) | ✅ | ✅ | ✅ |
| DNS RAM при 462 000 доменов | **5 МБ** (mmap) | ~38 МБ | ~30 МБ |
| AmneziaWireGuard | ✅ | ❌ | ❌ |
| VLESS + Reality | ✅ | ✅ | ✅ |
| Hysteria2 | ✅ | ✅ | ✅ |
| Per-device routing по MAC | ✅ | ❌ | ❌ |
| Веб-дашборд | ✅ :8080 | отдельный | ❌ |

---

## Протоколы

**VLESS:**
- Reality (TLS 1.3 masquerade, x25519, shortId) — собственный TLS 1.3 стек на wolfCrypt, потому что wolfSSL не поддерживает x25519 static ephemeral для Reality ECDH
- gRPC (HTTP/2 + HPACK + LPM + protobuf + flow control, async state machine)
- WebSocket (TLS + HTTP Upgrade, MASK=1)
- XHTTP / SplitHTTP (HTTP/2, ALPN=h2, session ID в path)
- HTTPUpgrade (HTTP GET без Sec-WebSocket-Key, raw TCP после 101)
- TCP plain с туннельным HC через `www.gstatic.com:443`

**Остальные:**
- Trojan и Trojan+gRPC
- Shadowsocks 2022 (AES-256-GCM, ChaCha20)
- AmneziaWireGuard (полная реализация: Jc/Jmin/Jmax, H1-H4, S1-S4, i1-i5)
- Hysteria2 (QUIC, Brutal CC, Salamander XOR)
- ShadowTLS v3

---

## Фичи которых нет у конкурентов

### Adaptive DPI Bypass

При первом соединении с хостом 4eburNet пробует прямое подключение. Если провайдер блокирует — автоматически поднимает уровень обхода: фрагментация TCP → поддельный ClientHello с TTL → оба метода вместе. Результат запоминается для каждого IP и применяется сразу при следующем соединении.

```
Соединение с 1.2.3.4:
  попытка 1: без обхода      → RST
  попытка 2: TCP fragment    → RST
  попытка 3: fake+TTL        → OK
  запомнено: 1.2.3.4 → FAKE_TTL

Следующее соединение → сразу fake+TTL, без лишних попыток
```

### TC Ingress Fast Path

LAN-трафик помечается в TC hook до netfilter. Пакеты получают fwmark раньше, чем nftables начинает их обрабатывать. На MT7621A (EC330) это даёт около 25% снижения нагрузки на CPU для внутрисетевых соединений.

### JA3/JA4 Fingerprint

Дашборд показывает JA3-хэш каждого TLS-соединения и сразу говорит, на что это похоже: Chrome 120, Firefox 121, Safari 17 или curl. Можно задать "ожидаемый" хэш и получать предупреждение, если прокси-клиент выдаёт себя.

### nftables Flow Offload

Прямые соединения (российские сайты) после первого пакета уходят в hardware fast-path nftables. На MT7621A это снижает CPU примерно на 30%, на MT7986 (Flint 2) — до 95%.

---

## DNS

Собственный DNS-сервер на `:53` (dnsmasq уходит на :5353):

- DoH и DoT с async nonblocking обращением к upstream
- Fake-IP пул с LRU eviction
- DNS Policy — разные upstream по паттерну домена (`+.ru` → 1.1.1.1 UDP, `+.google.com` → DoH)
- Блокировка по GeoSite базам с двухуровневым Bloom filter
- DNS Cookie RFC 7873 + 9018 — без этого iOS 16+ помечает DNS-сервер как non-compliant
- PTR authoritative для RFC1918 с AA flag — нужно macOS Bonjour и Windows name resolution
- DHCP option 6 auto-config — без этого iOS показывает значок WiFi без интернета
- AD bit cleanup RFC 4035 §3.2.3 — форвардер не утверждает DNSSEC который не проверяет
- AAAA NODATA для DIRECT/BYPASS — предотвращает IPv6 leak через IPv4-only прокси

462 000 доменов в GeoSite базах занимают 5 МБ через mmap. Bloom filter убирает 98% запросов до обращения к Patricia trie.

---

## Маршрутизация

- По доменам: DOMAIN, DOMAIN_SUFFIX, DOMAIN_KEYWORD, GEOSITE
- По IP: IP_CIDR, IP_CIDR6, GEOIP
- По портам: DST_PORT
- По MAC-адресу устройства в сети
- Rule Providers: внешние списки правил по URL
- Proxy Providers: подписки серверов (Clash YAML, base64, URI)
- Proxy Groups: url_test, fallback, select, load_balance
- nftables Verdict Maps: 300 000+ CIDR, O(1) lookup

---

## Адаптация под железо

Два уровня, работают одновременно:

**DeviceProfile (compile-time, по MemTotal)** — задаёт ёмкость структур при сборке:

| Профиль | RAM | Fake-IP пул | DNS кэш | Соединения |
|---|---|---|---|---|
| MICRO | < 48 МБ | 512 | 128 | 256 |
| NORMAL | < 192 МБ | 4 096 | 512 | 1 024 |
| FULL | ≥ 192 МБ | 65 536 | 2 048 | 4 096 |

**mem_tier (runtime, по MemAvailable при старте)** — один бинарник, оптимален на любом железе:

| Tier | MemAvailable | epoll batch | relay drain | DNS кэш | geo mmap |
|---|---|---|---|---|---|
| LOW | < 64 МБ | 8 | 4 | 512 | MAP_NORESERVE |
| MID | 64–256 МБ | 32 | 16 | 2 048 | MAP_NORESERVE |
| HIGH | > 256 МБ | 64 | 32 | 8 192 | MAP_POPULATE |

---

## Установка

В [Releases](../../releases/latest) два пакета:

- `4eburnet_VERSION_ARCH.ipk` — демон (per-arch: mipsel/aarch64/x86_64)
- `4eburnet-geo_VERSION_all.ipk` — GeoSite/GeoIP базы в бинарном формате (один пакет для всех архитектур, обновляется независимо от демона)

```sh
# Скопировать на роутер
scp 4eburnet_*.ipk 4eburnet-geo_*.ipk root@192.168.1.1:/tmp/

# Установить (geo сначала — базы будут готовы при первом старте)
ssh root@192.168.1.1 "opkg install /tmp/4eburnet-geo_*.ipk /tmp/4eburnet_*.ipk"

# Перезапустить LuCI
ssh root@192.168.1.1 "rm -rf /tmp/luci-* && /etc/init.d/uhttpd restart"
```

После установки: LuCI → Services → 4eburNet или напрямую `http://192.168.1.1:8080`

---

## Быстрый старт

```sh
# Включить, режим по правилам
uci set 4eburnet.main.enabled=1
uci set 4eburnet.main.mode=rules

# Добавить VLESS + Reality сервер
uci add 4eburnet server
uci set 4eburnet.@server[-1].name='my-server'
uci set 4eburnet.@server[-1].protocol='vless'
uci set 4eburnet.@server[-1].address='1.2.3.4'
uci set 4eburnet.@server[-1].port='443'
uci set 4eburnet.@server[-1].uuid='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
uci set 4eburnet.@server[-1].reality_pbk='ваш_x25519_public_key_43_символа'
uci set 4eburnet.@server[-1].reality_sid='12345678'

# Российские ресурсы — напрямую
uci add 4eburnet traffic_rule
uci set 4eburnet.@traffic_rule[-1].type='geoip'
uci set 4eburnet.@traffic_rule[-1].value='RU'
uci set 4eburnet.@traffic_rule[-1].target='DIRECT'
uci set 4eburnet.@traffic_rule[-1].priority='100'

# Остальное — через прокси
uci add 4eburnet traffic_rule
uci set 4eburnet.@traffic_rule[-1].type='match'
uci set 4eburnet.@traffic_rule[-1].target='my-server'
uci set 4eburnet.@traffic_rule[-1].priority='9999'

uci commit 4eburnet
/etc/init.d/4eburnet start
```

---

## Как работает

```
Устройства в сети
      │ TCP / UDP
      ▼
nftables TPROXY :7893
Verdict Maps: bypass / block / proxy  ←  300K+ CIDR, O(1)
      │
      ▼
4eburnetd  (epoll, один поток, 2.8 МБ бинарник)
  ├── TC Fast Path ── LAN трафик → mark до netfilter
  ├── Flow Offload ── DIRECT → hardware fast path
  ├── DNS :53 ── Fake-IP, DoH/DoT, adblock, 462K доменов / 5 МБ RAM
  ├── Sniffer ── TLS SNI peek + JA3/JA4 fingerprint
  ├── Adaptive DPI ── кэш стратегий обхода по IP
  ├── Rules Engine ── DOMAIN / GEOIP / GEOSITE / IP_CIDR / MAC
  └── Proxy Groups ── url_test / fallback / select / load_balance
      │
      ▼
Upstream
VLESS+Reality · gRPC · WebSocket · XHTTP · Trojan · AWG · Hysteria2
```

---

## Поддерживаемые платформы

| Устройство | Чипсет | Архитектура | RAM |
|---|---|---|---|
| TP-Link EC330-G5u | MediaTek MT7621A | mipsel_24kc | 128 МБ |
| GL-iNet Flint 2 | MediaTek Filogic 880 | aarch64_cortex-a53 | 512 МБ |
| любое устройство | MIPS / ARM / x86 | mipsel / aarch64 / armv7 / x86_64 | от 32 МБ flash |

---

## Лицензия

GPLv2 — совместимо с OpenWrt.

---

<div align="center">
  <img src="4eburNet.png" width="64" alt="4eburNet">
</div>

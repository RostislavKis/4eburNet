<div align="center">
  <img src="4eburNet.png" width="220" alt="4eburNet">
  <h1>4eburNet</h1>
  <p>
    Универсальный прокси-маршрутизатор для OpenWrt<br>
    Полная замена mihomo + podkop + xray — <strong>один статический бинарник</strong>
  </p>

  <p>
    <img src="https://img.shields.io/badge/версия-v1.5.178-brightgreen?style=flat-square" alt="version">
    <img src="https://img.shields.io/badge/OpenWrt-23.05%20%2F%2024.10%20%2F%2025.12-blue?style=flat-square" alt="OpenWrt">
    <img src="https://img.shields.io/badge/arch-mipsel%20%7C%20aarch64%20%7C%20armv7%20%7C%20x86__64-green?style=flat-square" alt="arch">
    <img src="https://img.shields.io/badge/бинарник-3.1%20МБ-orange?style=flat-square" alt="size">
    <img src="https://img.shields.io/badge/зависимости-ноль-brightgreen?style=flat-square" alt="deps">
    <img src="https://img.shields.io/badge/TLS-wolfSSL%205.9-blue?style=flat-square" alt="wolfssl">
    <img src="https://img.shields.io/badge/license-GPLv2-lightgrey?style=flat-square" alt="license">
  </p>
</div>

---

## Что это

**4eburNet** — прокси-демон для роутеров на OpenWrt. Написан на C23, статически скомпилирован с musl libc и wolfSSL. Устанавливается одним `.ipk` пакетом, не требует Python, Node.js, Lua или отдельных сервисов. После установки весь трафик с устройств в сети автоматически маршрутизируется — российские сайты идут напрямую, заблокированные — через прокси.

---

## Чем 4eburNet лучше mihomo / podkop / xray

| | 4eburNet | mihomo | podkop | xray |
|---|:---:|:---:|:---:|:---:|
| Один бинарник без зависимостей | ✅ | ❌ Go runtime | ❌ Shell + Lua | ❌ Go runtime |
| Размер бинарника | ✅ 3.1 МБ | ❌ ~15 МБ | — | ❌ ~20 МБ |
| Нет GC пауз | ✅ | ❌ | ✅ | ❌ |
| Встроенный DNS-сервер | ✅ | ✅ | ❌ | ❌ |
| **Adaptive DPI** — адаптивный обход | ✅ **уникально** | ❌ | ❌ | ❌ |
| **TC Fast Path** — LAN ускорение | ✅ **уникально** | ❌ | ❌ | ❌ |
| **JA3/JA4 fingerprint** контроль | ✅ **уникально** | ❌ | ❌ | ❌ |
| **nftables Flow Offload** | ✅ | ❌ | ❌ | ❌ |
| GeoIP/GeoSite с Bloom filter | ✅ 6× быстрее | ✅ | ❌ | ✅ |
| DNS RAM при 462 000 доменов | ✅ **5 МБ** (mmap) | ❌ ~38 МБ heap | — | ❌ ~30 МБ |
| AmneziaWireGuard | ✅ | ❌ | ✅ через kmod | ❌ |
| VLESS + Reality | ✅ custom TLS stack | ✅ | ✅ | ✅ |
| Hysteria2 | ✅ | ✅ | ✅ | ✅ |
| **AnyTLS** — adaptive padding | ✅ | ✅ | ❌ | ❌ |
| **TUIC v5** — NewReno CC | ✅ | ✅ | ❌ | ❌ |
| Маршрутизация по MAC-адресу | ✅ | ❌ | ❌ | ❌ |
| Встроенный веб-дашборд | ✅ :8080 | ✅ отдельный | ❌ | ❌ |

---

## Уникальные функции

### 🧠 Adaptive DPI Bypass
Единственный прокси-пакет для OpenWrt с **адаптивной памятью стратегий обхода**.

При первом соединении с сайтом 4eburNet пробует прямое подключение. Если провайдер блокирует — автоматически эскалирует: фрагментация TCP → поддельный ClientHello → оба метода вместе. Результат запоминается для каждого IP-адреса и применяется при следующем соединении. Кэш сохраняется между перезапусками.

Прогрессия стратегий: `NONE → FRAGMENT → FAKE_TTL → BOTH`

### ⚡ TC Ingress Fast Path
LAN-трафик обрабатывается через TC-hook до netfilter. Пакеты получают метку до того, как nftables начнёт их проверять — снижение нагрузки на CPU **~25%** для внутрисетевого трафика.

### 🔍 TLS Fingerprint (JA3/JA4)
Дашборд показывает JA3-хэш каждого TLS-соединения и автоматически определяет браузер (Chrome 120 / Firefox 121 / Safari 17 / curl). Позволяет проверить, маскируется ли прокси-клиент под настоящий браузер.

### 📊 nftables Flow Offload
Прямые соединения после первого пакета передаются в hardware fast-path. Последующие пакеты не проходят через netfilter. Эффект: **~30% снижение CPU** на MT7621A, **~95%** на MT7986.

### 🗺 Geo-базы с Bloom Filter (6× быстрее)
Patricia trie + двухуровневый Bloom filter (512 КБ на базу). Для 98% DNS-запросов поиск завершается за ~45 операций без обращения к trie. 462 000 доменов — **5 МБ RAM** через mmap.

### 🛡 AnyTLS — Anti-Fingerprinting Transport
Собственная реализация AnyTLS транспорта (~1400 LoC). Адаптивная схема padding подгоняет размеры TLS application records под профиль легитимного HTTPS-трафика. Single-RTT: settings + SYN + первый PSH идут в одном TLS-record. Idle session pool снижает задержку переключения серверов.

### 🚀 TUIC v5 — QUIC с адаптивным CC
TUIC v5 (~2100 LoC): QUIC v1, TLS-Exporter аутентификация, NewReno congestion control (адаптивный, в отличие от Brutal в Hysteria2), фрагментация UDP датаграмм, multi-stream мультиплексирование. Ref: mihomo v1.19.24.

---

## Протоколы

| Протокол | Транспорты | Особенности |
|----------|-----------|-------------|
| **VLESS** | TCP, gRPC, WebSocket, XHTTP, HTTPUpgrade | Reality (custom TLS 1.3 stack), Vision (XTLS-rprx-vision), x25519, JA3 fingerprint |
| **Trojan** | TCP, gRPC | Маскировка под HTTPS |
| **AmneziaWireGuard** | UDP | Jc/Jmin/Jmax, H1-H4, S1-S4, i1-i5, MTU/DNS/reserved |
| **Hysteria2** | QUIC | Brutal CC, Salamander XOR, URI парсер, UDP relay |
| **AnyTLS** | TLS | Adaptive padding scheme, single-RTT, idle pool, SHA256 auth |
| **TUIC v5** | QUIC | TLS-Exporter auth, NewReno CC, DATAGRAM RFC 9221, stream pool |
| **ShadowTLS v3** | TCP | SessionID=HMAC, HMAC chain per AppData frame |

---

## DNS

Собственный DNS-сервер на порту `:53`:

- **Fake-IP режим** — пул IPv4 `198.18.0.0/16` + IPv6 `fd00::/120`, LRU eviction
- **DoH / DoT / DoQ** — DNS over HTTPS/TLS/QUIC
- **DNS Cookie** RFC 7873 + RFC 9018 — защита от off-path атак
- **PTR resolver** — обратный DNS через `/tmp/dhcp.leases` + router IPs
- **Stale-while-revalidate** RFC 8767 — быстрый ответ из кэша + фоновое обновление
- **AD bit cleanup** RFC 4035 — корректный форвардер без валидации DNSSEC
- **Nameserver Policy** — разные upstream по паттерну домена
- **Adblock** — geosite-ads (~460K), trackers (~42K), threats через DNS

---

## Маршрутизация

- **По доменам**: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, GEOSITE
- **По IP**: IP-CIDR, IP-CIDR6, GEOIP (базы `.gbin` с Bloom filter)
- **По портам**: DST-PORT
- **По MAC-адресу**: индивидуальная политика для каждого устройства
- **Rule Providers**: загрузка правил по URL с интервалом обновления
- **Proxy Providers**: подписки из URL (base64, vless://, ss://, trojan://)
- **Proxy Groups**: URL-TEST (автовыбор лучшего), FALLBACK, SELECT
- nftables Verdict Maps — 300 000+ CIDR, O(1) поиск

---

## Блокировка рекламы

- DNS-блокировка по базам: **geosite-ads**, **geosite-trackers**, **geosite-threats**
- opencck.org — актуальные списки РКН (обновление каждые 6 часов)
- Базы обновляются автоматически через cdn_updater → SIGHUP демону
- Статистика в реальном времени в дашборде

---

## Веб-дашборд

Встроенный HTTP-сервер на порту `:8080`. Открывается с любого устройства в сети.

| Раздел | Что показывает |
|--------|----------------|
| **Статус** | Uptime, соединения, DNS-запросы, dispatcher tick, geo статус |
| **Прокси** | Серверы, группы, latency тесты, ручной выбор сервера |
| **Сеть** | Flow Offload, TC Fast Path ON/OFF |
| **DPI** | Adaptive DPI ON/OFF, кэш стратегий, счётчик попаданий |
| **TLS** | JA3-хэш, определение браузера, ожидаемый хэш |
| **DNS** | Статистика, Fake-IP, разбивка блокировок по категориям |
| **GEO** | Загруженные базы, размеры, статус Bloom filter |
| **Устройства** | ARP + DHCP + политики по MAC |
| **Логи** | Живые логи с фильтрацией, цветовая разметка |

---

## Поддерживаемые платформы

| Устройство | Чипсет | Архитектура | RAM |
|------------|--------|-------------|-----|
| TP-Link EC330-G5u | MediaTek MT7621A | mipsel_24kc | 128 МБ |
| GL-iNet Flint 2 | MediaTek Filogic 880 | aarch64_cortex-a53 | 512 МБ |
| Любое устройство OpenWrt | MIPS / ARM / x86 | mipsel / aarch64 / armv7 / x86_64 | ≥ 116 МБ RAM |

---

## Установка

Скачать актуальный `.ipk` из [Releases](../../releases/latest).

```sh
# Копировать на роутер
scp 4eburnet_*.ipk root@192.168.1.1:/tmp/

# Установить
opkg install /tmp/4eburnet_*.ipk

# Настроить и запустить
uci commit 4eburnet
/etc/init.d/4eburnet start
```

Веб-дашборд:
```
http://<IP роутера>:8080
```

---

## Быстрый старт

```sh
# Включить и выбрать режим маршрутизации
uci set 4eburnet.main.enabled=1
uci set 4eburnet.main.mode=rules

# Добавить сервер VLESS + Reality
uci add 4eburnet server
uci set 4eburnet.@server[-1].name='Мой сервер'
uci set 4eburnet.@server[-1].protocol='vless'
uci set 4eburnet.@server[-1].address='1.2.3.4'
uci set 4eburnet.@server[-1].port='443'
uci set 4eburnet.@server[-1].uuid='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
uci set 4eburnet.@server[-1].reality_pbk='ваш_public_key_base64url'
uci set 4eburnet.@server[-1].reality_sni='example.com'

# Российский трафик — напрямую
uci add 4eburnet traffic_rule
uci set 4eburnet.@traffic_rule[-1].type='geoip'
uci set 4eburnet.@traffic_rule[-1].value='RU'
uci set 4eburnet.@traffic_rule[-1].target='DIRECT'
uci set 4eburnet.@traffic_rule[-1].priority='100'

# Остальное — через прокси
uci add 4eburnet traffic_rule
uci set 4eburnet.@traffic_rule[-1].type='match'
uci set 4eburnet.@traffic_rule[-1].target='Мой сервер'
uci set 4eburnet.@traffic_rule[-1].priority='9999'

uci commit 4eburnet
/etc/init.d/4eburnet start
```

---

## Как это работает

```
Устройства в сети
      │ TCP / UDP
      ▼
nftables TPROXY :7893
Verdict Maps: bypass / block / proxy  ←  300K+ CIDR, O(1) поиск
      │
      ▼
4eburnetd  (epoll ET, один поток, 3.1 МБ)
  ├── TC Fast Path ── LAN трафик → mark до netfilter
  ├── Flow Offload ── DIRECT трафик → hardware fast path
  ├── DNS :53 ── Fake-IP, DoH/DoT/DoQ, adblock, 462K доменов / 5 МБ mmap
  ├── Sniffer ── TLS SNI peek + JA3/JA4 fingerprint
  ├── Adaptive DPI ── кэш стратегий обхода по IP
  ├── Rules Engine ── DOMAIN / GEOIP / GEOSITE / IP-CIDR / MAC
  └── Proxy Groups ── url_test / fallback / select
      │
      ▼
Upstream серверы
VLESS+Reality · VLESS+gRPC · VLESS+WS · VLESS+XHTTP · Trojan+gRPC
AmneziaWG · Hysteria2 · AnyTLS · TUIC v5 · ShadowTLS v3
```

---

## Лицензия

GPLv2 — совместимо с OpenWrt.

---

<div align="center">
  <img src="4eburNet.png" width="80" alt="4eburNet">
</div>

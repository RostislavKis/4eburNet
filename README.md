<div align="center">
  <img src="4eburNet.png" width="220" alt="4eburNet">
  <h1>4eburNet</h1>
  <p>
    Универсальный прокси-маршрутизатор для OpenWrt<br>
    Полная замена mihomo + podkop + xray — <strong>один статический бинарник</strong>
  </p>

  <p>
    <img src="https://img.shields.io/badge/версия-v1.5.5-brightgreen?style=flat-square" alt="version">
    <img src="https://img.shields.io/badge/OpenWrt-24.10%20%2F%2025.12-blue?style=flat-square" alt="OpenWrt">
    <img src="https://img.shields.io/badge/arch-mipsel%20%7C%20aarch64%20%7C%20x86__64-green?style=flat-square" alt="arch">
    <img src="https://img.shields.io/badge/бинарник-< 3 МБ-orange?style=flat-square" alt="size">
    <img src="https://img.shields.io/badge/зависимости-ноль-brightgreen?style=flat-square" alt="deps">
    <img src="https://img.shields.io/badge/TLS-wolfSSL%205.9-blue?style=flat-square" alt="wolfssl">
    <img src="https://img.shields.io/badge/license-GPLv2-lightgrey?style=flat-square" alt="license">
  </p>
</div>

---

## Что это

**4eburNet** — прокси-демон для роутеров на OpenWrt. Написан на C23, статически скомпилирован с musl libc и wolfSSL. Устанавливается одним `.ipk` пакетом, не требует Python, Node.js, Lua или отдельных сервисов. После установки весь трафик с устройств в вашей сети автоматически маршрутизируется — российские сайты идут напрямую, заблокированные — через прокси.

---

## Чем 4eburNet лучше mihomo / podkop / xray

| | 4eburNet | mihomo | podkop | xray |
|---|:---:|:---:|:---:|:---:|
| Один бинарник без зависимостей | ✅ | ❌ Go runtime | ❌ Shell + Lua | ❌ Go runtime |
| Бинарник < 2 МБ | ✅ ~1.7 МБ | ❌ ~15 МБ | — | ❌ ~20 МБ |
| Работает на 32 МБ Flash | ✅ | ❌ | ✅ | ❌ |
| Встроенный DNS-сервер | ✅ | ✅ | ❌ | ❌ |
| **Adaptive DPI** — адаптивный обход | ✅ **уникально** | ❌ | ❌ | ❌ |
| **TC Fast Path** — LAN ускорение | ✅ **уникально** | ❌ | ❌ | ❌ |
| **JA3/JA4 fingerprint** контроль | ✅ **уникально** | ❌ | ❌ | ❌ |
| **nftables Flow Offload** | ✅ | ❌ | ❌ | ❌ |
| GeoIP/GeoSite с Bloom filter | ✅ 6× быстрее | ✅ | ❌ | ✅ |
| DNS RAM при 462 000 доменов | ✅ **5 МБ** (mmap) | ❌ ~38 МБ heap | — | ❌ ~30 МБ |
| AmneziaWireGuard | ✅ | ❌ | ✅ через kmod | ❌ |
| VLESS + Reality | ✅ | ✅ | ✅ | ✅ |
| Hysteria2 | ✅ | ✅ | ✅ | ✅ |
| Маршрутизация по MAC-адресу | ✅ | ❌ | ❌ | ❌ |
| Встроенный веб-дашборд | ✅ :8080 | ✅ отдельный | ❌ | ❌ |

---

## Уникальные функции

### 🧠 Adaptive DPI Bypass
Единственный прокси-пакет для OpenWrt с **адаптивной памятью стратегий обхода**.

При первом соединении с сайтом 4eburNet пробует прямое подключение. Если провайдер блокирует — автоматически эскалирует: фрагментация TCP → поддельный ClientHello → оба метода вместе. Результат запоминается для каждого IP-адреса и применяется немедленно при следующем соединении. Кэш сохраняется между перезапусками роутера.

Прогрессия стратегий: `NONE → FRAGMENT → FAKE_TTL → BOTH`

```
Соединение с 1.2.3.4
  → Попытка 1: без обхода — RST от провайдера
  → Попытка 2: TCP фрагментация — RST
  → Попытка 3: fake ClientHello + TTL — успех ✓
  → Запомнено: 1.2.3.4 → FAKE_TTL
  
Следующее соединение с 1.2.3.4
  → Сразу: fake ClientHello + TTL → успех ✓ (без лишних попыток)
```

### ⚡ TC Ingress Fast Path
LAN-трафик (устройство ↔ устройство внутри сети) обрабатывается через TC-hook до netfilter. Пакеты получают метку ещё до того, как nftables начнёт их проверять — это снижает нагрузку на CPU **на ~25%** для внутрисетевого трафика. Модули загружаются автоматически при включении.

### 🔍 TLS Fingerprint (JA3/JA4)
4eburNet вычисляет JA3-хэш каждого TLS-соединения — цифровую подпись набора cipher/extensions/groups. Это позволяет проверить, действительно ли ваш прокси-клиент маскируется под браузер.

Дашборд показывает:
- Последний вычисленный JA3-хэш
- Автоматическое определение: Chrome 120 / Firefox 121 / Safari 17 / curl
- Поле для ввода «ожидаемого» хэша — если не совпадает, появляется предупреждение

### 📊 nftables Flow Offload
Прямые соединения (российские сайты без прокси) после первого пакета передаются в аппаратный fast-path nftables. Последующие пакеты не проходят через netfilter вообще.

Эффект: **~30% снижение CPU** на MT7621A (TP-Link EC330), **~95%** на MT7986 (Flint 2).

### 🗺 Geo-базы с Bloom Filter (6× быстрее)
Базы GeoIP/GeoSite хранятся в бинарном формате с Patricia trie и двухуровневым Bloom filter (512 КБ на базу). Для 98% DNS-запросов (домен не в базе блокировок) поиск завершается за ~45 операций вместо 270 — без обращения к trie. Загрузка через mmap: 462 000 доменов занимают **5 МБ RAM** вместо 38 МБ.

---

## Протоколы

| Протокол | Особенности |
|----------|-------------|
| **VLESS + Reality** | TLS 1.3 masquerade, x25519, shortId, fingerprint (chrome/firefox/safari/random) |
| **VLESS + XHTTP** | HTTP upgrade транспорт, chunked streaming, обход DPI через легитимный HTTP |
| **Trojan** | Маскировка под HTTPS, поддержка мультиплексирования |
| **Shadowsocks 2022** | AEAD шифрование (AES-256-GCM, ChaCha20), TCP и UDP |
| **AmneziaWireGuard** | Полная реализация AWG: Jc/Jmin/Jmax, H1-H4, S1-S4, i1-i5, MTU/DNS/reserved |
| **Hysteria2** | QUIC-based, Brutal CC, Salamander XOR обфускация, URI парсер |
| **ShadowTLS v3** | SessionID=HMAC, HMAC chain per AppData frame |

---

## DNS

Собственный DNS-сервер на порту `:53` с поддержкой всех современных протоколов:

- **DoH** — DNS over HTTPS (RFC 8484)
- **DoT** — DNS over TLS, порт 853
- **DoQ** — DNS over QUIC (RFC 9250)
- **Fake-IP режим** — адаптивный пул под профиль устройства, LRU eviction
- **Nameserver Policy** — разные upstream серверы по паттерну домена
- **Bogus NXDOMAIN** — защита от DNS-подмены провайдером
- **Параллельные запросы** — primary + fallback одновременно
- **LRU кэш** с настраиваемым Min/Max TTL
- Российские домены (`*.ru`, `*.рф`) — **только** к российскому DNS, без утечек

---

## Маршрутизация

- **По доменам**: DOMAIN, DOMAIN_SUFFIX, DOMAIN_KEYWORD, GEOSITE
- **По IP**: IP_CIDR, GEOIP (базы обновляются автоматически)
- **По портам**: DST_PORT
- **По MAC-адресу**: индивидуальная политика для каждого устройства в сети
- **Rule Providers**: загрузка списков правил по URL с автообновлением
- **Proxy Providers**: загрузка серверов из URL-подписок (base64, vless://, ss://, trojan://)
- **Proxy Groups**: URL_TEST (автовыбор лучшего), FALLBACK, SELECT, LOAD_BALANCE
- nftables Verdict Maps — **300 000+ CIDR** записей, O(1) поиск

---

## Профили устройств

Демон автоматически определяет объём RAM и выбирает профиль:

| Профиль | RAM | Fake-IP пул | DNS кэш | Соединения |
|---------|-----|-------------|---------|------------|
| MICRO | < 48 МБ | 512 записей | 128 | 256 |
| NORMAL | < 192 МБ | 4 096 записей | 512 | 1 024 |
| FULL | ≥ 192 МБ | 65 536 записей | 2 048 | 4 096 |

---

## Блокировка рекламы

- DNS-блокировка по базам: **geosite-ads** (~460 000 доменов), **geosite-trackers** (~42 000), **geosite-threats**
- Базы обновляются автоматически из [RostislavKis/filter](https://github.com/RostislavKis/filter)
- opencck.org интеграция — актуальные списки заблокированных РКН сайтов (обновление каждые 6 часов)
- Статистика в реальном времени: счётчики рекламы / трекеров / угроз на дашборде

---

### 🔐 Совместимость с клиентами (RFC compliance)

4eburNet полностью совместим с поведением dnsmasq и BIND для современных клиентов (iOS 16+, macOS 13+, Android, Windows, IoT). При первой установке в среду где DNS перенесён с `:53` на `:5353` и заменён на 4eburnetd — автоматически настраивается всё необходимое для бесшовной работы клиентов.

- **DNS Cookie** (RFC 7873 + 9018 §4.2) — 16-байтный server cookie с timestamp для защиты от spoofing. Без неё iOS помечает DNS-сервер как «non-compliant» и игнорирует.
- **PTR authoritative** (RFC 1035) — reverse DNS для RFC1918 диапазонов из `/tmp/dhcp.leases` с AA flag. Это нужно macOS Bonjour, Windows NetBIOS resolution и многим IoT.
- **DHCP option 6 auto-config** — автоматически прописывает LAN IP как DNS сервер при старте сервиса. Критично для iOS WiFi icon: без option 6 в DHCP ACK iOS считает сеть «без интернета» и уходит на cellular.
- **AD bit compliance** (RFC 4035 §3.2.3) — forwarder не утверждает DNSSEC валидацию которую не выполняет.
- **AAAA NODATA для DIRECT/BYPASS** — предотвращает IPv6 leak когда прокси-канал работает только через IPv4.

---

## Веб-дашборд

Встроенный HTTP-сервер на порту `:8080`. Открывается с любого устройства в сети без установки дополнительных компонентов.

| Раздел | Что показывает и контролирует |
|--------|------------------------------|
| **Статус** | Uptime, активные соединения, DNS-запросы, статистика блокировок |
| **Сеть** | Flow Offload ON/OFF, TC Fast Path ON/OFF с объяснением каждой функции |
| **DPI** | Adaptive DPI ON/OFF, счётчик IP в кэше, количество попаданий, очистка кэша |
| **TLS** | Последний JA3-хэш, определение браузера, ввод ожидаемого хэша |
| **DNS** | Статистика, Fake-IP статус, разбивка блокировок по категориям |
| **GEO** | Таблица загруженных баз с размерами и статусом Bloom filter |
| **Логи** | Живые логи с фильтрацией по уровню, цветовая разметка |

Каждая функция сопровождается кнопкой **[?]** — нажатие открывает карточку с объяснением: что это, зачем нужно и как работает.

---

## Поддерживаемые платформы

| Устройство | Чипсет | Архитектура | RAM |
|------------|--------|-------------|-----|
| TP-Link EC330-G5u | MediaTek MT7621A | mipsel_24kc | 128 МБ |
| GL-iNet Flint 2 | MediaTek Filogic 880 | aarch64_cortex-a53 | 512 МБ |
| Любое устройство | MIPS / ARM / x86 | mipsel / aarch64 / armv7 / x86_64 | ≥ 32 МБ Flash |

---

## Установка

Скачать актуальный `.ipk` из [Releases](../../releases/latest).

```sh
# Копировать на роутер
scp 4eburnet_*.ipk root@192.168.1.1:/tmp/

# Установить
ssh root@192.168.1.1 "opkg install /tmp/4eburnet_*.ipk"

# Перезапустить LuCI
ssh root@192.168.1.1 "rm -rf /tmp/luci-* && /etc/init.d/uhttpd restart"
```

После установки открыть LuCI → **Services → 4eburNet** или веб-дашборд напрямую:
```
http://<IP роутера>:8080
```

---

## Быстрый старт

```sh
# Включить и выбрать режим маршрутизации по правилам
uci set 4eburnet.main.enabled=1
uci set 4eburnet.main.mode=rules

# Добавить сервер (пример VLESS + Reality)
uci add 4eburnet server
uci set 4eburnet.@server[-1].name='Мой сервер'
uci set 4eburnet.@server[-1].protocol='vless'
uci set 4eburnet.@server[-1].address='1.2.3.4'
uci set 4eburnet.@server[-1].port='443'
uci set 4eburnet.@server[-1].uuid='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
uci set 4eburnet.@server[-1].reality_pbk='ваш_public_key'
uci set 4eburnet.@server[-1].reality_sid='12345678'

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
4eburnetd  (epoll, один поток, < 2 МБ RAM на сам процесс)
  ├── TC Fast Path ── LAN трафик → mark до netfilter
  ├── Flow Offload ── DIRECT трафик → hardware fast path
  ├── DNS :53 ── Fake-IP, DoH/DoT/DoQ, adblock, 462K доменов в 5 МБ
  ├── Sniffer ── TLS SNI peek + JA3/JA4 fingerprint
  ├── Adaptive DPI ── кэш стратегий обхода по IP
  ├── Rules Engine ── DOMAIN / GEOIP / GEOSITE / IP_CIDR / MAC
  └── Proxy Groups ── url_test / fallback / select / load_balance
      │
      ▼
Upstream серверы
VLESS+Reality · VLESS+XHTTP · Trojan · SS2022 · AmneziaWG · Hysteria2
```

---

## Лицензия

GPLv2 — совместимо с OpenWrt.

---

<div align="center">
  <img src="4eburNet.png" width="80" alt="4eburNet">
  <br>
  <sub>Сделано для тех, кому важна свобода интернета</sub>
</div>

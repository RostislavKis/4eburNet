<div align="center">
  <img src="4eburNet.png" width="220" alt="4eburNet">
  <h1>4eburNet</h1>
  <p>
    Универсальный прокси-маршрутизатор для OpenWrt<br>
    Полная замена mihomo + podkop + xray — <strong>один статический бинарник</strong>
  </p>

  <p>
    <img src="https://img.shields.io/badge/OpenWrt-24.10%20%2F%2025.12-blue?style=flat-square" alt="OpenWrt">
    <img src="https://img.shields.io/badge/arch-mipsel%20%7C%20aarch64%20%7C%20x86__64-green?style=flat-square" alt="arch">
    <img src="https://img.shields.io/badge/binary-%3C2MB-orange?style=flat-square" alt="size">
    <img src="https://img.shields.io/badge/зависимости-ноль-brightgreen?style=flat-square" alt="deps">
    <img src="https://img.shields.io/badge/TLS-wolfSSL%205.9-blue?style=flat-square" alt="wolfssl">
    <img src="https://img.shields.io/badge/license-GPLv2-lightgrey?style=flat-square" alt="license">
  </p>
</div>

---

## Что это

**4eburNet** — прокси-демон для роутеров на OpenWrt. Написан на C23, статически собран с musl libc и wolfSSL. Работает без внешних runtime зависимостей: не требует Python, Node.js или отдельного DNS-сервера. Поддерживает слабое железо от 32 МБ Flash.

Устанавливается одним `.ipk` пакетом. Управление — через веб-интерфейс LuCI или UCI командную строку.

---

## Возможности

### Прокси протоколы

| Протокол | Детали |
|----------|--------|
| **VLESS + Reality** | TLS 1.3 masquerade, x25519, shortId, fingerprint (chrome/firefox/safari) |
| **VLESS + XHTTP** | HTTP upgrade транспорт, обход глубокой инспекции пакетов (DPI) |
| **Trojan** | Маскировка под HTTPS трафик |
| **Shadowsocks 2022** | AEAD шифрование, TCP и UDP |
| **AmneziaWG** | Обфусцированный WireGuard: Jc/Jmin/Jmax, H1-H4 (magic headers), S1-S4 (scramble) |

### DNS

- Собственный DNS-сервер на порту `:53` (epoll, до 2048 соединений)
- **DoH** — DNS over HTTPS (RFC 8484), неблокирующий
- **DoT** — DNS over TLS, порт 853
- **DoQ** — DNS over QUIC (RFC 9250), собственная реализация QUIC subset
- **Fake-IP** режим — пул 198.18.0.0/16, LRU eviction, адаптивный размер по профилю
- **Nameserver Policy** — разные upstream серверы по паттерну домена
- **Bogus NXDOMAIN** фильтр — защита от DNS hijacking провайдером
- **TC-bit TCP retry** — автоматический fallback на TCP при усечённых UDP ответах
- Параллельные запросы к primary и fallback серверам одновременно
- LRU кэш с настраиваемым Min TTL
- BYPASS домены (*.ru, *.рф) **никогда** не идут через зарубежный DNS

### Маршрутизация трафика

- nftables Verdict Maps — 300 000+ CIDR записей в оперативной памяти
- Типы правил: `DOMAIN`, `DOMAIN_SUFFIX`, `DOMAIN_KEYWORD`, `IP_CIDR`, `GEOIP`, `GEOSITE`, `RULE_SET`, `MATCH`
- **Per-device маршрутизация по MAC** — индивидуальная политика для каждого устройства в сети
- **Proxy Groups**: `URL_TEST` — автовыбор лучшего, `FALLBACK` — резерв, `SELECT` — ручной, `LOAD_BALANCE`
- **Rule Providers** — загрузка списков правил по URL с автообновлением
- **Proxy Providers** — загрузка серверов из URL-подписок (base64, vless://, ss://, trojan://)
- **GeoIP / GeoSite** базы — Patricia trie, O(32) поиск
- **Sniffer TLS SNI** — определение домена по ClientHello без расшифровки

### Профили устройств

Демон автоматически определяет объём RAM и выбирает профиль:

| Профиль | RAM | Fake-IP пул | DNS кэш | Соединения |
|---------|-----|-------------|---------|------------|
| MICRO | < 48 МБ | 512 записей | 128 | 256 |
| NORMAL | < 192 МБ | 4 096 записей | 512 | 1024 |
| FULL | ≥ 192 МБ | 65 536 записей | 2048 | 4096 |

### Блокировка рекламы

- DNS-блокировка по базе `geosite-ads.lst` (ответ NXDOMAIN)
- Пользовательские чёрные и белые списки через LuCI
- REJECT правила для отдельных доменов и wildcard паттернов (*.tracker.com)

### Безопасность

- IPC сокет: `chmod 600` + `SO_PEERCRED` — fail-secure, отклоняет при ошибке getsockopt
- DNS split enforcement: BYPASS домены **только** UDP, никогда через DoH/DoT upstream
- Все nftables операции через `posix_spawnp` без shell
- Предупреждение при отсутствии правила `GEOIP,RU,DIRECT` — защита от раскрытия IP сервера

### LuCI веб-интерфейс

Меню **4eburNet** в навигации между System и Network. Совместим с OpenWrt 21.02–25.12.

| Страница | Возможности |
|----------|-------------|
| **Обзор** | Статус, аптайм, статистика соединений и DNS, VLESS QR-код |
| **Серверы** | Список, добавление через URI (vless:// ss:// trojan://), удаление |
| **Группы** | Proxy groups, выбор сервера, задержка в реальном времени |
| **Подписки** | URL-подписки с автообновлением |
| **Правила** | Таблица правил с добавлением и удалением |
| **Устройства** | ARP/DHCP список, политика proxy/bypass/block/default по MAC |
| **DNS** | Upstream серверы, DoH/DoT/DoQ, Fake-IP, кэш — полное редактирование |
| **Блокировка рекламы** | Статистика, чёрные и белые списки |
| **Настройки** | Параметры демона, резервное копирование и восстановление конфига |
| **Логи** | Живые логи с фильтрацией по уровню и поиском |

---

## Поддерживаемые платформы

| Устройство | Чипсет | Архитектура | RAM | OpenWrt |
|------------|--------|-------------|-----|---------|
| TP-Link EC330-G5u | MediaTek MT7621 | mipsel_24kc | 128 МБ | 24.10 |
| GL-iNet Flint 2 | MediaTek Filogic 880 | aarch64_cortex-a53 | 512 МБ | 25.12 |

Любое устройство с **OpenWrt 21.02+** на архитектурах MIPS, ARM, x86.

---

## Установка

```sh
# OpenWrt ≤ 24.10.x
opkg update
opkg install luci-app-4eburnet_*.ipk

# OpenWrt ≥ 25.12.0
apk update
apk add luci-app-4eburnet_*.ipk
```

После установки открыть в браузере:

```
http://192.168.1.1/cgi-bin/luci/admin/services/4eburnet
```

Если меню не появилось — сбросить кэш LuCI:

```sh
rm -rf /tmp/luci-* && /etc/init.d/uhttpd restart
```

---

## Начальная настройка

### Минимальная конфигурация

```sh
uci set 4eburnet.main.enabled=1
uci set 4eburnet.main.mode=rules
uci set 4eburnet.main.region=ru
uci commit 4eburnet
/etc/init.d/4eburnet start
```

### Добавить сервер VLESS + Reality

```sh
uci add 4eburnet server
uci set 4eburnet.@server[-1].name='DE-Frankfurt-01'
uci set 4eburnet.@server[-1].protocol='vless'
uci set 4eburnet.@server[-1].address='1.2.3.4'
uci set 4eburnet.@server[-1].port='443'
uci set 4eburnet.@server[-1].uuid='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
uci set 4eburnet.@server[-1].reality_pbk='ваш_public_key'
uci set 4eburnet.@server[-1].reality_sid='12345678'
uci commit 4eburnet
```

### Обязательное правило — RU трафик напрямую

```sh
# RU трафик — напрямую (без этого правила демон выдаст предупреждение)
uci add 4eburnet traffic_rule
uci set 4eburnet.@traffic_rule[-1].type='geoip'
uci set 4eburnet.@traffic_rule[-1].value='RU'
uci set 4eburnet.@traffic_rule[-1].target='DIRECT'
uci set 4eburnet.@traffic_rule[-1].priority='100'

# Всё остальное — через прокси
uci add 4eburnet traffic_rule
uci set 4eburnet.@traffic_rule[-1].type='match'
uci set 4eburnet.@traffic_rule[-1].target='MAIN-PROXY'
uci set 4eburnet.@traffic_rule[-1].priority='9999'

uci commit 4eburnet
/etc/init.d/4eburnet reload
```

### DNS с DoH

```sh
uci set 4eburnet.dns.upstream_bypass='77.88.8.8'
uci set 4eburnet.dns.upstream_proxy='8.8.8.8'
uci set 4eburnet.dns.doh_enabled='1'
uci set 4eburnet.dns.doh_url='https://dns.google/dns-query'
uci set 4eburnet.dns.doh_ip='8.8.8.8'
uci commit 4eburnet
/etc/init.d/4eburnet reload
```

---

## Управление

```sh
# Статус
4eburnetd status

# Статистика (соединения, DNS, кэш)
4eburnetd stats

# Перезагрузить конфиг без обрыва соединений
4eburnetd reload

# Остановить / Запустить
/etc/init.d/4eburnet stop
/etc/init.d/4eburnet start

# Логи в реальном времени
tail -f /tmp/4eburnet.log
```

---

## Как это работает

```
Устройства в сети (192.168.x.x)
          │ TCP / UDP
          ▼
    nftables TPROXY (порт 7893)
    Verdict Maps: bypass / block / proxy  ←  300K+ CIDR
          │
          ▼
    4eburnetd  (epoll, async I/O)
    ├── DNS :53 ── fake-ip, DoH/DoT/DoQ, nameserver-policy
    ├── Sniffer ── TLS SNI peek
    ├── Rules Engine ── DOMAIN / GEOIP / GEOSITE / IP_CIDR
    ├── Proxy Groups ── url_test / fallback / select / load_balance
    └── IPC /var/run/4eburnet.sock ── LuCI ↔ демон
          │
          ▼
    Upstream серверы
    VLESS+Reality · VLESS+XHTTP · Trojan · SS 2022 · AmneziaWG
```

---

## Файлы на роутере

```
/usr/sbin/4eburnetd              — демон
/etc/config/4eburnet             — UCI конфигурация
/etc/init.d/4eburnet             — автозапуск (procd)
/etc/4eburnet/geo/               — GeoIP/GeoSite базы
  ├── geoip-ru.lst
  ├── geosite-ru.lst
  └── geosite-ads.lst
/etc/4eburnet/backup.tar.gz      — резервная копия конфига
/var/run/4eburnet.sock           — IPC сокет (chmod 600)
/tmp/4eburnet.log                — лог (tmpfs)
```

---

## Лицензия

GPLv2 — совместимо с OpenWrt.

---

<div align="center">
  <sub>Сделано для тех, кому важна свобода интернета</sub>
</div>

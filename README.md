<div align="center">
  <img src="4eburNet.png" width="220" alt="4eburNet">
  <h1>4eburNet</h1>
  <p>
    Универсальный прокси-маршрутизатор для OpenWrt<br>
    Полная замена mihomo + podkop + xray — <strong>один статический бинарник на C23</strong>
  </p>

  <p>
    <img src="https://img.shields.io/badge/OpenWrt-24.10%20%2F%2025.12-blue?style=flat-square" alt="OpenWrt">
    <img src="https://img.shields.io/badge/arch-mipsel%20%7C%20aarch64%20%7C%20x86__64-green?style=flat-square" alt="arch">
    <img src="https://img.shields.io/badge/binary-%3C2MB-orange?style=flat-square" alt="size">
    <img src="https://img.shields.io/badge/deps-zero-brightgreen?style=flat-square" alt="deps">
    <img src="https://img.shields.io/badge/license-GPLv2-lightgrey?style=flat-square" alt="license">
    <img src="https://img.shields.io/badge/TLS-wolfSSL%20v5.9-blue?style=flat-square" alt="wolfssl">
  </p>
</div>

---

## Что это такое

**4eburNet** (`4eburnetd`) — прокси-демон для роутеров на OpenWrt. Написан на C23, статически собран с musl libc и wolfSSL. Работает без внешних зависимостей: не требует Python, Node.js, Lua-интерпретатора или отдельного DNS-сервера.

Цель: заменить связку mihomo + podkop + xray одним бинарником с предсказуемым потреблением памяти, понятной конфигурацией через UCI и полноценным LuCI-интерфейсом.

---

## Возможности

### Прокси протоколы
| Протокол | Транспорт | Примечания |
|----------|-----------|-----------|
| VLESS | Reality (TLS 1.3 masquerade) | x25519, fingerprint, shortId |
| VLESS | XHTTP (HTTP upgrade) | Обход DPI через HTTP |
| Trojan | TLS | Маскировка под HTTPS |
| Shadowsocks 2022 | TCP/UDP | AEAD шифрование |
| AmneziaWG | UDP | Обфусцированный WireGuard: Jc/Jmin/Jmax, H1-H4, S1-S4 |

### DNS
- Собственный DNS-сервер на порту `:53` (epoll, до 2048 соединений)
- **DoH** (DNS over HTTPS, RFC 8484) — wolfSSL, nonblocking
- **DoT** (DNS over TLS, порт 853)
- **DoQ** (DNS over QUIC, RFC 9250) — опционально, требует `CONFIG_EBURNET_DOQ=1`
- **Fake-IP** режим (пул 198.18.0.0/16, LRU eviction, адаптивный размер)
- **Nameserver Policy** — разные upstream по паттерну домена
- **Bogus NXDOMAIN** фильтр — защита от DNS hijacking провайдером
- **TC-bit TCP retry** — автоматический fallback на TCP при обрезанных UDP ответах
- Параллельные запросы к primary + fallback
- Кэш с LRU eviction, настраиваемый Min TTL
- BYPASS домены (*.ru, *.рф) **никогда** не идут через зарубежный DNS

### Маршрутизация трафика
- nftables Verdict Maps — до 300 000+ CIDR записей в памяти
- Правила по типам: `DOMAIN`, `DOMAIN_SUFFIX`, `DOMAIN_KEYWORD`, `IP_CIDR`, `GEOIP`, `GEOSITE`, `RULE_SET`, `MATCH`
- **Per-device маршрутизация** по MAC-адресу: `proxy` / `bypass` / `block` / `default`
- Proxy Groups: `URL_TEST` (авто-выбор), `FALLBACK`, `SELECT` (ручной), `LOAD_BALANCE`
- Rule Providers — загрузка правил из URL (async fetch)
- Proxy Providers — загрузка серверов из URL-подписок
- GeoIP / GeoSite базы (MaxMind-совместимый формат)

### Безопасность
- IPC сокет: `chmod 600` + `SO_PEERCRED` fail-secure (отклоняет при ошибке getsockopt)
- DNS split enforcement: BYPASS домены не достигают DoH/DoT upstream
- Все nft-операции через `posix_spawnp` без shell
- Валидация CIDR через whitelist символов
- Предупреждение при отсутствии правила `GEOIP,RU,DIRECT`

### LuCI веб-интерфейс
- Меню **4eburNet** между System и Network (order=55)
- Совместим с OpenWrt 21.02–25.12 (rpcd + JS views, без Lua dispatcher)
- Страницы: Обзор, Серверы, Группы, Подписки, Правила, Устройства, DNS, Блокировка рекламы, Настройки, Логи
- Polling статуса каждые 3 секунды (IPC → rpcd → JS)
- Тёмная тема, шрифты Inter + JetBrains Mono
- Импорт серверов из `vless://` `ss://` `trojan://` URI
- Резервное копирование и восстановление UCI конфига

### Системное
- Профили устройств по RAM: `MICRO` (≤32MB) / `NORMAL` (≤128MB) / `FULL`
- Адаптивный размер пула соединений, DNS кэша, Fake-IP пула
- Graceful degradation при отсутствии `kmod-nft-tproxy`
- Автоопределение пакетного менеджера: `opkg` (≤24.10) / `apk` (≥25.12)
- Горячая перезагрузка конфига через SIGHUP или IPC без обрыва соединений
- procd init.d скрипт с respawn

---

## Поддерживаемые платформы

| Устройство | Чипсет | Архитектура | RAM | Flash | OpenWrt |
|------------|--------|-------------|-----|-------|---------|
| TP-Link EC330 | MediaTek MT7621 | mipsel_24kc | 128 MB | 32 MB | 24.10 |
| GL-iNet Flint 2 | MediaTek Filogic 880 | aarch64_cortex-a53 | 512 MB | 8 GB | 25.12 |
| QEMU x86 VM | x86_64 | x86_64 | — | — | 23.05+ |

Любое устройство с OpenWrt 21.02+ и архитектурой MIPS / ARM / x86 / RISC-V.

---

## Быстрый старт

### Установка готового .ipk

```sh
# OpenWrt <= 24.10.x
opkg update
opkg install luci-app-4eburnet_*.ipk

# OpenWrt >= 25.12.0
apk update
apk add luci-app-4eburnet_*.ipk
```

После установки открыть в браузере:
```
http://192.168.1.1/cgi-bin/luci/admin/services/4eburnet
```

### Минимальная конфигурация UCI

```sh
# Включить демон
uci set 4eburnet.main.enabled=1

# Режим маршрутизации
uci set 4eburnet.main.mode=rules

# LAN интерфейс
uci set 4eburnet.main.lan_interface=br-lan

# Регион (для GeoIP/GeoSite баз)
uci set 4eburnet.main.region=ru

uci commit 4eburnet
/etc/init.d/4eburnet start
```

---

## Сборка из исходников

### Зависимости

```sh
sudo apt-get install -y musl-tools build-essential \
  git autoconf automake libtool pkg-config
```

### Первичная настройка (wolfSSL + окружение)

```sh
git clone https://github.com/RostislavKis/4eburNet.git
cd 4eburNet
./scripts/dev-setup.sh
```

### Сборка для разработки (x86_64, musl)

```sh
# Профиль NORMAL (рекомендуется для разработки)
make -f core/Makefile.dev PROFILE=normal

# Профиль FULL (все функции включая fake-ip, proxy providers)
make -f core/Makefile.dev PROFILE=full

# С поддержкой DoQ (требует wolfSSL --enable-quic)
make -f core/Makefile.dev PROFILE=full EXTRA_CFLAGS="-DCONFIG_EBURNET_DOQ=1"
```

### Кросс-компиляция через OpenWrt SDK

```sh
# Собрать для всех поддерживаемых архитектур
./scripts/build.sh all

# Только для конкретной архитектуры
./scripts/build.sh mipsel     # EC330
./scripts/build.sh aarch64    # Flint 2
```

### Деплой в QEMU VM (разработка)

```sh
~/phoenix-router-dev/qemu/start-vm.sh
./scripts/deploy.sh full
ssh -p 2222 root@localhost "4eburnetd status"
```

### Деплой на роутер

```sh
# Бинарник
scp build/4eburnetd root@192.168.1.1:/usr/sbin/
# LuCI пакет
scp luci-app-4eburnet_*.ipk root@192.168.1.1:/tmp/
ssh root@192.168.1.1 "opkg install --force-reinstall /tmp/luci-app-4eburnet_*.ipk \
  && rm -rf /tmp/luci-* && /etc/init.d/uhttpd restart"
```

---

## Конфигурация

Конфиг хранится в UCI: `/etc/config/4eburnet`

### Основные параметры

```sh
config main '4eburnet'
    option enabled      '1'         # запускать демон
    option mode         'rules'     # rules | global | direct
    option log_level    'info'      # debug | info | warn | error
    option lan_interface 'br-lan'   # LAN bridge интерфейс
    option region       'ru'        # регион GeoIP баз
    option geo_dir      '/etc/4eburnet/geo'
```

### DNS

```sh
config dns 'dns'
    option enabled          '1'
    option listen_port      '53'
    option upstream_bypass  '77.88.8.8'   # DNS для RU доменов (Yandex)
    option upstream_proxy   '8.8.8.8'     # DNS для PROXY доменов
    option upstream_default '1.1.1.1'
    option upstream_fallback '9.9.9.9'
    option cache_size       '512'
    option parallel_query   '1'
    option fake_ip_enabled  '0'
    option fake_ip_range    '198.18.0.0/16'
    option doh_enabled      '1'
    option doh_url          'https://dns.google/dns-query'
    option doh_ip           '8.8.8.8'
    option doh_sni          'dns.google'
```

### Добавить сервер VLESS

```sh
uci add 4eburnet server
uci set 4eburnet.@server[-1].name='DE-Frankfurt-01'
uci set 4eburnet.@server[-1].protocol='vless'
uci set 4eburnet.@server[-1].address='1.2.3.4'
uci set 4eburnet.@server[-1].port='443'
uci set 4eburnet.@server[-1].uuid='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
uci set 4eburnet.@server[-1].transport='raw'
uci set 4eburnet.@server[-1].reality_pbk='base64pubkey'
uci set 4eburnet.@server[-1].reality_sid='12345678'
uci commit 4eburnet
```

### Правила маршрутизации

```sh
# RU трафик напрямую (обязательно)
uci add 4eburnet traffic_rule
uci set 4eburnet.@traffic_rule[-1].type='geoip'
uci set 4eburnet.@traffic_rule[-1].value='RU'
uci set 4eburnet.@traffic_rule[-1].target='DIRECT'
uci set 4eburnet.@traffic_rule[-1].priority='100'

# Финальное правило
uci add 4eburnet traffic_rule
uci set 4eburnet.@traffic_rule[-1].type='match'
uci set 4eburnet.@traffic_rule[-1].target='MAIN-PROXY'
uci set 4eburnet.@traffic_rule[-1].priority='9999'

uci commit 4eburnet
```

---

## Управление демоном

```sh
# Статус
4eburnetd status

# Перезагрузить конфиг (без обрыва соединений)
4eburnetd reload
# или через init.d
/etc/init.d/4eburnet reload

# Статистика
4eburnetd stats

# Остановить
/etc/init.d/4eburnet stop

# Логи
tail -f /tmp/4eburnet.log
```

---

## Архитектура

```
Клиенты LAN (192.168.x.x)
        │ TCP/UDP
        ▼
   nftables TPROXY (порт 7893)
   Verdict Maps: bypass_v4/v6, block_v4/v6, proxy_v4/v6
        │
        ▼
   4eburnetd (epoll, max 2048 conn)
   ├── DNS сервер (:53) — fake-ip, DoH/DoT/DoQ, nameserver-policy
   ├── TPROXY handler — приём перехваченных соединений
   ├── Dispatcher — маршрутизация по правилам
   ├── Rules Engine — DOMAIN/IP_CIDR/GEOIP/GEOSITE/RULE_SET
   ├── Proxy Groups — url_test/fallback/select/load_balance
   ├── Proxy Providers — async fetch подписок
   └── IPC сокет (/var/run/4eburnet.sock) — LuCI/CLI
        │
        ▼
   Upstream серверы (VLESS / Trojan / SS / AWG)
```

```
LuCI браузер
     │ HTTP → /cgi-bin/luci/admin/services/4eburnet
     ▼
  rpcd backend (/usr/libexec/rpcd/4eburnet)
  nixio Unix socket
     │
     ▼
  /var/run/4eburnet.sock → 4eburnetd
```

---

## Файловая структура

```
/usr/sbin/4eburnetd              — основной бинарник
/etc/config/4eburnet             — UCI конфигурация
/etc/init.d/4eburnet             — procd init скрипт
/etc/4eburnet/geo/               — GeoIP/GeoSite базы
  ├── geoip-ru.lst               — IP-диапазоны России
  ├── geosite-ru.lst             — домены России
  └── geosite-ads.lst            — база блокировки рекламы
/var/run/4eburnet.sock           — IPC Unix socket (chmod 600)
/var/run/4eburnet.pid            — PID файл
/tmp/4eburnet.log                — лог (tmpfs)
/usr/libexec/rpcd/4eburnet       — rpcd backend для LuCI
/www/luci-static/resources/
  └── view/4eburnet/*.js         — LuCI JS views
```

---

## Блокировка рекламы

4eburNet блокирует рекламные домены на уровне DNS (NXDOMAIN) через базу `geosite-ads.lst`.

```sh
# Проверить количество доменов в базе
wc -l /etc/4eburnet/geo/geosite-ads.lst

# Добавить домен в блокировку через UCI
uci add 4eburnet traffic_rule
uci set 4eburnet.@traffic_rule[-1].type='domain_suffix'
uci set 4eburnet.@traffic_rule[-1].value='ads.example.com'
uci set 4eburnet.@traffic_rule[-1].target='REJECT'
uci set 4eburnet.@traffic_rule[-1].priority='50'
uci commit 4eburnet
```

---

## Известные ограничения

| Ограничение | Статус |
|-------------|--------|
| `kmod-nft-tproxy` нет в EC330 по умолчанию | Graceful degradation — демон работает, TPROXY отключён |
| DoQ требует wolfSSL `--enable-quic` | Опциональная сборка с `CONFIG_EBURNET_DOQ=1` |
| GeoIP/GeoSite из MaxMind `.mmdb` | В планах — сейчас используется текстовый формат `.lst` |
| Sniffer TLS SNI | В планах (3.6) |
| proxy-groups/rule-providers UI | В разработке (4.2+) |

---

## Roadmap

- [x] Базовая маршрутизация (nftables, tproxy)
- [x] DNS сервер с DoH/DoT/Fake-IP/nameserver-policy
- [x] Per-device MAC routing
- [x] Proxy Groups (url_test/fallback/select)
- [x] Rule Providers + Proxy Providers (async fetch)
- [x] GeoIP/GeoSite базы
- [x] LuCI 4.x (rpcd + JS views, ucode-compatible)
- [ ] Sniffer TLS SNI (peek ClientHello в tproxy)
- [ ] rule-providers полный UI
- [ ] GeoIP MaxMind `.mmdb` формат
- [ ] SDK кросс-компиляция (5.1)
- [ ] DoQ production (5.x)

---

## Разработка

### Структура репозитория

```
core/
├── include/         — заголовочные файлы (4eburnet.h, config.h, ...)
├── src/             — исходный код C23
│   ├── dns/         — DNS сервер (DoH/DoT/DoQ/fake-ip)
│   ├── proxy/       — прокси протоколы, dispatcher, groups
│   ├── routing/     — nftables, rules engine, device policy
│   ├── geo/         — GeoIP/GeoSite загрузчик
│   └── crypto/      — TLS (wolfSSL wrapper)
├── Makefile         — OpenWrt SDK сборка
├── Makefile.dev     — локальная разработка (musl)
└── Kconfig          — конфигурация фич
luci-app-4eburnet/
├── htdocs/luci-static/resources/
│   └── view/4eburnet/*.js   — JS views
├── root/usr/libexec/rpcd/   — rpcd backend (Lua)
├── root/usr/share/luci/menu.d/  — меню
└── files/           — UCI конфиг, init.d скрипт
scripts/             — dev-setup, build, deploy
```

### Соглашения по именованию

| Контекст | Имя |
|----------|-----|
| Бренд / UI | `4eburNet` |
| Бинарник | `4eburnetd` |
| Пути, пакеты | `/etc/4eburnet/`, `luci-app-4eburnet` |
| C макросы | `EBURNET_*`, `CONFIG_EBURNET_*` |
| C структуры | `EburNetConfig`, `EburNetState` |

---

## Лицензия

GPLv2 — совместимо с OpenWrt.

---

<div align="center">
  <sub>Сделано с ❤️ для тех кому важна свобода интернета</sub>
</div>

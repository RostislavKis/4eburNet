# phoenix-router

Прокси-пакет для OpenWrt. Замена связки mihomo + podkop + xray одним статическим бинарником.

> **Статус:** активная разработка, pre-release. API конфига может меняться.

---

## Что это

**phoenix-router** — демон маршрутизации трафика для роутеров на OpenWrt. Перехватывает соединения через TPROXY на уровне ядра и направляет их через настроенные прокси-серверы по правилам.

Ключевые отличия от существующих решений:
- **Один бинарник** — нет зависимостей от xray, sing-box, mihomo и других рантаймов
- **Нет SOCKS5** — TPROXY на уровне ядра, spyware не может обойти маршрутизацию
- **Адаптивный** — автоматически подстраивается под железо (32MB flash / 128MB RAM)
- **Интегрированный DNS** — встроенный резолвер с fake-ip, DoH/DoT, split DNS, защитой от богус-ответов ISP

---

## Поддерживаемые протоколы

| Протокол | Статус |
|----------|--------|
| VLESS + Reality (xtls-rprx-vision) | ✅ |
| VLESS + XHTTP | ✅ |
| Trojan | ✅ |
| Shadowsocks 2022 | ✅ |
| AmneziaWG (AWG) | ✅ |

---

## Возможности DNS

- **Fake-IP** — виртуальные IP для domain-based routing без SNI sniffer
- **DoH / DoT** — async, неблокирующий, wolfSSL
- **Nameserver-policy** — разные upstream для разных доменов
- **Split DNS** — RU/bypass домены никогда не уходят через прокси upstream
- **Fallback upstream** — автоматический переход при таймауте
- **Parallel query** — запрос на primary + fallback одновременно
- **Bogus NXDOMAIN filter** — замена redirect IP (Ростелеком и др.) на NXDOMAIN
- **TTL min/max enforcement** — контроль кэширования
- **TC retry** — повтор через TCP при truncated UDP ответе

---

## Поддерживаемое железо

| Устройство | CPU | RAM | Flash | Профиль |
|-----------|-----|-----|-------|---------|
| TP-Link EC330-G5u v1 | MIPS 1004Kc 880MHz | 128MB | 128MB | NORMAL |
| GL.iNet Flint 2 | Cortex-A53 1.8GHz | 512MB | 8GB | FULL |
| Роутеры с 32MB Flash | любой | от 32MB | от 32MB | MICRO |

Бинарник: **~1.1MB** (stripped, musl static). Влезает в 4MB Flash с запасом.

Профиль определяется автоматически из `/proc/meminfo`:
- **MICRO** — до 48MB RAM: DNS пул 512 записей, лимиты снижены
- **NORMAL** — до 192MB RAM: DNS пул 4096, стандартные лимиты
- **FULL** — 192MB+: DNS пул 65536, максимальные возможности

---

## Установка

### Из готового пакета (рекомендуется)

```sh
# Скачать актуальный .ipk для вашей архитектуры со страницы Releases
opkg install phoenix-router_*_mipsel_24kc.ipk

# Постустановка (определение региона, загрузка geo-файлов)
sh /usr/share/phoenix-router/postinstall.sh
```

Поддерживаемые архитектуры в релизах: `mipsel_24kc`, `aarch64_cortex-a53`.

### Управление

```sh
/etc/init.d/phoenix-router start
/etc/init.d/phoenix-router stop
/etc/init.d/phoenix-router restart

# Перечитать конфиг без рестарта
phoenixd reload

# Статус
phoenixd status
```

---

## Конфигурация

Конфиг в формате UCI: `/etc/config/phoenix`

Управление через LuCI (веб-интерфейс) после установки пакета `luci-app-phoenix` (в разработке).

Минимальный пример для РФ:

```uci
config phoenix 'main'
    option enabled '1'
    option region 'ru'
    option log_level 'info'

config server
    option name 'my-vless'
    option enabled '1'
    option protocol 'vless'
    option address '1.2.3.4'
    option port '443'
    option uuid 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    option transport 'raw'
    option reality_short_id 'abcdef01'

config dns
    option enabled '1'
    option listen_port '53'
    option upstream_bypass '77.88.8.8'
    option upstream_proxy '8.8.8.8'
    option upstream_default '1.1.1.1'
    option bogus_nxdomain '212.48.0.118 212.48.0.4'
    option cache_ttl_min '60'

config traffic_rule
    option type 'GEOIP'
    option value 'RU'
    option target 'DIRECT'
    option priority '200'

config traffic_rule
    option type 'MATCH'
    option target 'my-vless'
    option priority '999'
```

Полная документация по конфигу: [`docs/config.md`](docs/config.md) *(в разработке)*

---

## Безопасность

**phoenix-router не имеет уязвимости CVE runetfreedom (2026-04-07)**

Затронутые пакеты (xray/sing-box mobile) запускают SOCKS5 без авторизации, что позволяет spyware обойти VpnService и раскрыть IP сервера. phoenix-router использует TPROXY на уровне ядра — нет SOCKS5, нет обхода.

Дополнительные меры защиты:
- IPC сокет только для root (`chmod 600` + `SO_PEERCRED`)
- RU/bypass домены принудительно через UDP upstream, никогда через DoH/DoT
- Предупреждение при старте если отсутствует правило `GEOIP,RU,DIRECT`

**Важно для пользователей:** заблокируйте на вашем VPN-сервере исходящие соединения в `geoip:ru`. Без этого сервисы (Яндекс, Ozon и др.) могут раскрыть IP вашего сервера через паттерн трафика. В xray/3x-ui: routing rule `geoip:ru → block` или `→ WARP`.

---

## Структура проекта

```
phoenix-router/
├── core/               # Исходный код демона (C23)
│   ├── src/
│   │   ├── dns/        # DNS резолвер, fake-ip, upstream async
│   │   ├── proxy/      # dispatcher, tproxy, протоколы, sniffer
│   │   ├── routing/    # nftables, policy, rules engine
│   │   ├── crypto/     # TLS, BLAKE2s/3, Noise
│   │   └── geo/        # GeoIP/GeoSite loader
│   └── include/
├── tools/
│   └── geo_convert.py  # Конвертер geo-файлов (dat/list/yaml → .lst)
├── scripts/
│   ├── postinstall.sh  # Мастер первичной настройки
│   └── init.d/         # OpenWrt init script
└── docs/               # Документация (в разработке)
```

---

## Roadmap

- [x] TPROXY перехват (TCP + UDP)
- [x] VLESS Reality, XHTTP, Trojan, SS2022, AWG
- [x] DNS: async DoH/DoT, fake-ip, split DNS, bogus filter
- [x] GeoIP + GeoSite (Patricia trie)
- [x] Proxy-groups (select/url-test/fallback/load-balance)
- [x] Rule-providers (HTTP с автообновлением)
- [x] Rules engine (DOMAIN/SUFFIX/KEYWORD/IP-CIDR/GEOIP/GEOSITE/MATCH)
- [x] Per-device routing по MAC
- [x] geo_convert.py + postinstall.sh
- [ ] Proxy-providers (подписки vless://, ss://, trojan://)
- [ ] LuCI дашборд (`luci-app-phoenix`)
- [ ] SDK пакеты для всех архитектур
- [ ] DoQ (DNS over QUIC)

---

## Сборка из исходников

> Исходный код закрыт. Принимаются сообщения об ошибках через Issues.

Если вы хотите собрать под нестандартную архитектуру — создайте Issue.

---

## Лицензия

Проприетарная. Использование в личных некоммерческих целях разрешено.
Распространение, форки и коммерческое использование — по запросу.

---

## Обратная связь

Issues: сообщения об ошибках, запросы функций, вопросы по совместимости.

При сообщении об ошибке приложите:
- Версию пакета (`phoenixd --version`)
- Модель роутера и архитектуру
- Вывод `/tmp/phoenix.log` (уровень debug)

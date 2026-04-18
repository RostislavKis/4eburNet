# 4eburNet

Универсальный прокси-пакет для OpenWrt — замена mihomo/podkop/xray
единым статическим бинарником без runtime зависимостей.

## Возможности

- **Протоколы:** VLESS (Reality/TLS), Trojan, Shadowsocks,
  AmneziaWG, Hysteria2, ShadowTLS
- **DNS:** fake-ip, DoH, DoT, DoQ, adblock (ads/trackers/threats),
  geosite фильтрация
- **Маршрутизация:** rules/global/direct, GeoIP, GeoSite,
  rule-providers, proxy-groups (select/url-test/fallback)
- **DPI bypass:** фрагментация, fake TTL, SNI sniffer
- **Dashboard:** встроенный HTTP сервер :8080, без CDN зависимостей
- **Подписки:** Clash YAML / URI list конвертация

## Поддерживаемые устройства

| Архитектура | Чипы | Примеры |
|-------------|------|---------|
| mipsel_24kc | MT7621A | TP-Link EC330, Xiaomi 4A |
| mips_24kc | MT7628, AR9xxx | Бюджетные роутеры |
| aarch64_cortex-a53 | MT7986 Filogic | GL.iNet Flint 2 |
| x86_64 | — | NAS, мини-ПК |

## Установка

```sh
# Скачать IPK из раздела Releases
opkg install 4eburnet-core_*.ipk
opkg install luci-app-4eburnet_*.ipk

# Обновить geo базы
/usr/share/4eburnet/geo_update.sh

# Запустить
/etc/init.d/4eburnet enable
/etc/init.d/4eburnet start
```

Dashboard доступен по адресу `http://IP_роутера:8080`

## Конфигурация

Конфиг: `/etc/config/4eburnet` (UCI формат)

Добавить сервер:
```sh
uci set 4eburnet.myserver=server
uci set 4eburnet.myserver.name='MyServer'
uci set 4eburnet.myserver.type='vless'
uci set 4eburnet.myserver.server='example.com'
uci set 4eburnet.myserver.port='443'
uci set 4eburnet.myserver.uuid='your-uuid-here'
uci commit 4eburnet
```

Конвертация Clash YAML подписки:
```sh
python3 /usr/share/4eburnet/sub_convert.py \
  --input subscription.yaml --output /etc/config/4eburnet
```

## Версия

v1.0.0 — первый production релиз

## Лицензия

MIT

# 4eburNet

Универсальный прокси-маршрутизатор для OpenWrt. Один бинарник на C заменяет mihomo + podkop + xray. Поддержка VLESS+Reality, XHTTP, Trojan, Shadowsocks 2022, AmneziaWG, Hysteria2, ShadowTLS v3. Минимальное потребление ресурсов, работа на MIPS роутерах с 64MB RAM.

## Требования

- OpenWrt 22.03+ (fw4/nftables)
- wolfSSL 5.9.0 (статически слинкован)
- Архитектуры: mipsel_24kc, aarch64, x86_64
- RAM: от 64MB (MICRO), рекомендуется 128MB+ (NORMAL/FULL)

## Быстрый старт

```sh
# Сборка (dev, x86_64)
cd core && make -f Makefile.dev

# Тесты
make -f Makefile.dev test

# Cross-compile для MIPS
make -f Makefile.dev cross-mipsel \
  TC_MIPSEL=/path/to/toolchain/bin \
  WOLFSSL_MIPSEL=/usr/local/musl-wolfssl-mipsel

# Деплой на роутер
scp -O prebuilt/mipsel/4eburnetd root@192.168.2.1:/usr/sbin/
ssh root@192.168.2.1 "/etc/init.d/4eburnet restart"
```

## Структура проекта

```
core/             C23 демон (musl static)
  src/            исходники
  include/        заголовки
  tests/          14 тест-суитов
  Makefile.dev    сборочная система

luci-app-4eburnet/  LuCI веб-интерфейс
  htdocs/           JS (overview, groups, servers, dns, dpi, ...)
  luasrc/           Lua шаблоны
  root/             rpcd ucode бэкенд
  files/            init.d, hotplug, UCI defaults

tools/            sub_convert.py (Clash YAML → UCI)
scripts/          deploy.sh, dev-setup.sh
docs/             документация
```

## Конфигурация

UCI файл: `/etc/config/4eburnet`

Основные секции:
- `config main` — enabled, mode (rules/global/direct), log_level
- `config server` — протокол, адрес, порт, ключи
- `config proxy_group` — тип (select/url-test/fallback), серверы, filter
- `config traffic_rule` — DOMAIN-SUFFIX, IP-CIDR, RULE-SET, GEOIP
- `config dns` — upstream, DoH/DoT, fake-ip, кэш

Импорт из Clash YAML:
```sh
python3 tools/sub_convert.py --input config.yaml --output /etc/config/4eburnet
```

## Документация

- [IPC Schema](IPC_SCHEMA.md) — JSON протокол демона (14 команд)
- [Архитектура](architecture.md) — компоненты и взаимодействие

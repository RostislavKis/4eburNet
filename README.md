# phoenix-router

Прокси-маршрутизатор для OpenWrt. Автоматическая маршрутизация трафика
через прокси-серверы по спискам доменов и IP-адресов.

## Возможности

- Протоколы: Shadowsocks, VLESS, Trojan
- Выборочная маршрутизация через nftables
- DNS-перехват с классификацией доменов
- Блокировка рекламы
- Веб-интерфейс через LuCI
- Автоматический выбор профиля по ресурсам устройства

## Целевые платформы

| Устройство | Чипсет          | Архитектура     | OpenWrt |
|------------|-----------------|-----------------|---------|
| Flint 2    | MediaTek Filogic| aarch64_cortex-a53 | 25.12.0 |
| EC330      | ramips/mt76x8   | mipsel_24kc     | 23.05.5 |

## Быстрый старт (разработка)

### Зависимости (Ubuntu/Debian)
```sh
sudo apt-get install -y musl-tools build-essential \
  git autoconf automake libtool pkg-config
```

### Первичная настройка
```sh
git clone <repo> && cd phoenix-router
./scripts/dev-setup.sh          # wolfSSL 5.9.0 + верификационная сборка
```

### Пересборка
```sh
make -f core/Makefile.dev
```

### VM для тестов
```sh
~/phoenix-router-dev/qemu/start-vm.sh
./scripts/deploy.sh full        # deploy в VM
ssh -p 2222 root@localhost "phoenixd -v"
```

### Целевые платформы
| Платформа      | Архитектура   | Команда                    |
|----------------|---------------|----------------------------|
| QEMU VM        | x86_64        | make -f core/Makefile.dev  |
| Flint 2        | aarch64       | scripts/build.sh aarch64   |
| EC330          | mipsel_24kc   | scripts/build.sh mipsel    |

## Сборка через OpenWrt SDK

```sh
./scripts/dev-setup.sh    # настройка окружения + симлинки SDK
./scripts/build.sh all    # собрать для обоих архитектур
```

## Лицензия

GPLv2 — совместимо с OpenWrt.

<div align="center">
  <img src="4eburNet.png" width="200" alt="4eburNet logo">
  <h1>4eburNet</h1>
  <p>Универсальный прокси-маршрутизатор для OpenWrt<br>
  Замена mihomo + podkop + xray — один статический бинарник на C</p>
  <img src="https://img.shields.io/badge/OpenWrt-24.10%20%2F%2025.12-blue" alt="OpenWrt">
  <img src="https://img.shields.io/badge/arch-mipsel%20%7C%20aarch64%20%7C%20x86-green" alt="arch">
  <img src="https://img.shields.io/badge/binary-%3C2MB-orange" alt="size">
</div>

---

## Возможности

- Протоколы: VLESS+Reality, VLESS+XHTTP, Trojan, Shadowsocks 2022, AmneziaWG
- Выборочная маршрутизация через nftables (Verdict Maps, 300K+ записей)
- DNS-демон на :53 с DoH, Fake-IP и защитой от утечек
- Веб-интерфейс через LuCI
- Профили устройств: MICRO / NORMAL / FULL по объёму RAM
- Автоматический failover между серверами без обрыва соединений

## Целевые платформы

| Устройство | Чипсет               | Архитектура        | OpenWrt |
|------------|----------------------|--------------------|---------|
| Flint 2    | MediaTek Filogic     | aarch64_cortex-a53 | 25.12.0 |
| EC330      | ramips/mt76x8        | mipsel_24kc        | 23.05.5 |
| QEMU VM    | x86_64               | x86_64             | 23.05.5 |

## Быстрый старт (разработка)

### Зависимости (Ubuntu/Debian)
```sh
sudo apt-get install -y musl-tools build-essential \
  git autoconf automake libtool pkg-config
```

### Первичная настройка
```sh
git clone <repo> && cd 4eburnet
./scripts/dev-setup.sh          # wolfSSL + верификационная сборка
```

### Пересборка
```sh
make -f core/Makefile.dev
```

### Деплой в QEMU VM
```sh
~/phoenix-router-dev/qemu/start-vm.sh
./scripts/deploy.sh full        # deploy в VM
ssh -p 2222 root@localhost "4eburnetd -v"
```

### Целевые платформы
| Платформа | Архитектура | Команда                   |
|-----------|-------------|---------------------------|
| QEMU VM   | x86_64      | make -f core/Makefile.dev |
| Flint 2   | aarch64     | scripts/build.sh aarch64  |
| EC330     | mipsel_24kc | scripts/build.sh mipsel   |

## Сборка через OpenWrt SDK

```sh
./scripts/dev-setup.sh    # настройка окружения + симлинки SDK
./scripts/build.sh all    # собрать для обоих архитектур
```

## Лицензия

GPLv2 — совместимо с OpenWrt.

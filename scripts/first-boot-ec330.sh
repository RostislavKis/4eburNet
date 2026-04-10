#!/bin/sh
# Первичная настройка EC330 после прошивки OpenWrt 23.05.5
# Запускать по SSH: ssh root@192.168.1.1 'sh /tmp/first-boot-ec330.sh'

set -e

echo "=== Первичная настройка EC330 ==="
echo "OpenWrt: $(cat /etc/openwrt_release | grep DISTRIB_RELEASE | cut -d= -f2 | tr -d "'")"

# 1. Смена IP на 192.168.2.1 (чтобы не конфликтовать с Flint 2)
echo "[1/6] Смена IP на 192.168.2.1..."
uci set network.lan.ipaddr='192.168.2.1'
uci commit network

# 2. Настройка DNS
echo "[2/6] Настройка DNS..."
uci set network.lan.dns='1.1.1.1 8.8.8.8'
uci commit network

# 3. Отключение IPv6 (временно)
echo "[3/6] Отключение IPv6..."
uci delete network.lan.ip6assign 2>/dev/null || true
uci set network.lan.ipv6='0'
uci delete network.wan6 2>/dev/null || true
uci commit network

# 4. Перезапуск сети (IP сменится!)
echo "[4/6] Перезапуск сети..."
echo "    ВНИМАНИЕ: IP сменится на 192.168.2.1"
echo "    Переподключись: ssh root@192.168.2.1"
/etc/init.d/network restart &
sleep 5

# 5. Установка пакетов
echo "[5/6] Установка пакетов..."
opkg update
opkg install openssh-sftp-server nano

# 6. Включение и запуск SSH (dropbear уже есть по умолчанию)
echo "[6/6] Проверка SSH..."
/etc/init.d/dropbear enable
/etc/init.d/dropbear restart

echo ""
echo "==============================="
echo "  EC330 готов к разработке"
echo "==============================="
echo "IP:       192.168.2.1"
echo "SSH:      ssh root@192.168.2.1"
echo "LuCI:     http://192.168.2.1"
echo "Flint 2:  192.168.1.1 (не затронут)"
echo ""
echo "Не забудь установить пароль root: passwd"

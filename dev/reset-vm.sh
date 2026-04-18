#!/bin/sh
# Сброс VM к чистому состоянию
# Удаляет openwrt-dev.qcow2 и создаёт новый из base

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PIDFILE="$SCRIPT_DIR/vm.pid"
BASE="$SCRIPT_DIR/images/openwrt-base.qcow2"
DEV="$SCRIPT_DIR/openwrt-dev.qcow2"

# Останавливаем VM если запущена
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "Останавливаю VM (PID $(cat "$PIDFILE"))..."
    kill "$(cat "$PIDFILE")"
    sleep 2
    rm -f "$PIDFILE"
fi

if [ ! -f "$BASE" ]; then
    echo "Базовый образ не найден: $BASE"
    exit 1
fi

# Удаляем и пересоздаём
rm -f "$DEV"
qemu-img create -f qcow2 -b images/openwrt-base.qcow2 -F qcow2 "$DEV"

echo "VM сброшена к чистому состоянию"
echo "Запусти: ./start-vm.sh"

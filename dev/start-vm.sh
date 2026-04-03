#!/bin/sh
# Запуск OpenWrt VM для разработки phoenix-router
#
# Режимы:
#   ./start-vm.sh          → headless + VNC на :5900
#   ./start-vm.sh console  → серийная консоль в терминале

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK="$SCRIPT_DIR/openwrt-dev.qcow2"
PIDFILE="$SCRIPT_DIR/vm.pid"
QMP_SOCK="/tmp/phoenix-vm-qmp.sock"
MODE="${1:-headless}"

if [ ! -f "$DISK" ]; then
    echo "Диск не найден: $DISK"
    echo "Создай: ./reset-vm.sh"
    exit 1
fi

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "VM уже запущена (PID $(cat "$PIDFILE"))"
    echo "SSH:  ssh -p 2222 -o StrictHostKeyChecking=no root@localhost"
    echo "LuCI: http://localhost:8080"
    echo "VNC:  localhost:5900"
    echo "Стоп: kill $(cat "$PIDFILE")"
    exit 0
fi

# Убираем старый QMP сокет если остался
rm -f "$QMP_SOCK"

# Общие параметры
COMMON="-m 256M -smp 2 \
    -drive file=$DISK,format=qcow2,if=virtio \
    -bios /usr/share/qemu/OVMF.fd \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-10.0.2.15:22,hostfwd=tcp:127.0.0.1:8080-10.0.2.15:80 \
    -device virtio-net-pci,netdev=net0 \
    -qmp unix:$QMP_SOCK,server,nowait"

case "$MODE" in
    console)
        echo "Запуск OpenWrt VM (консоль)..."
        echo "Выход: Ctrl+A, X"
        qemu-system-x86_64 $COMMON \
            -nographic \
            -serial mon:stdio \
            -pidfile "$PIDFILE"
        rm -f "$PIDFILE"
        exit 0
        ;;
    *)
        echo "Запуск OpenWrt VM (фон + VNC)..."
        qemu-system-x86_64 $COMMON \
            -display none \
            -vnc :0 \
            -serial file:/tmp/openwrt-console.log \
            -daemonize \
            -pidfile "$PIDFILE" \
            2>&1
        ;;
esac

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    PID=$(cat "$PIDFILE")
    echo ""
    echo "================================="
    echo "  OpenWrt VM запущена (PID $PID)"
    echo "================================="
    echo "SSH:   ssh -p 2222 -o StrictHostKeyChecking=no root@localhost"
    echo "LuCI:  http://localhost:8080  <- открой в браузере Windows"
    echo "VNC:   localhost:5900         <- TigerVNC/RealVNC"
    echo "Лог:   tail -f /tmp/openwrt-console.log"
    echo "Стоп:  kill $PID"
    echo "Сброс: ./reset-vm.sh"
    echo ""
    echo "Подожди ~30 сек пока OpenWrt загрузится"
else
    echo "Ошибка запуска VM"
    exit 1
fi

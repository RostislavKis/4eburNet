#!/bin/sh
# Управление снапшотами VM
#
# Поддерживает живые снапшоты через QMP (VM запущена)
# и офлайн через qemu-img (VM остановлена).
#
# ./snapshot.sh save [имя]
# ./snapshot.sh load [имя]
# ./snapshot.sh list
# ./snapshot.sh delete [имя]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEV="$SCRIPT_DIR/openwrt-dev.qcow2"
QMP_SOCK="/tmp/phoenix-vm-qmp.sock"

if [ ! -f "$DEV" ]; then
    echo "Диск не найден: $DEV"
    exit 1
fi

# Проверяем, запущена ли VM (QMP сокет существует и рабочий)
vm_is_running() {
    [ -S "$QMP_SOCK" ]
}

# Отправить QMP команду через socat
qmp_cmd() {
    if ! command -v socat >/dev/null 2>&1; then
        echo "socat не найден. Установи: sudo apt install -y socat"
        exit 1
    fi
    printf '{"execute":"qmp_capabilities"}\n{"execute":"human-monitor-command","arguments":{"command-line":"%s"}}\n' "$1" \
        | socat - "unix-connect:$QMP_SOCK" 2>/dev/null
}

# Извлечь return из QMP ответа (вторая строка с return)
qmp_result() {
    qmp_cmd "$1" | grep '"return"' | tail -1 | sed 's/.*"return":"\{0,1\}//;s/"\{0,1\}\}$//' | sed 's/\\r\\n/\n/g'
}

case "${1:-}" in
    save)
        NAME="${2:-snap-$(date +%Y%m%d-%H%M%S)}"
        if vm_is_running; then
            qmp_cmd "savevm $NAME" >/dev/null
            echo "Снапшот $NAME сохранён (VM запущена, QMP)"
        else
            qemu-img snapshot -c "$NAME" "$DEV"
            echo "Снапшот $NAME сохранён (VM остановлена)"
        fi
        ;;
    load)
        if [ -z "$2" ]; then
            echo "Укажи имя: ./snapshot.sh load <имя>"
            exit 1
        fi
        if vm_is_running; then
            qmp_cmd "loadvm $2" >/dev/null
            echo "Снапшот $2 загружен без перезапуска VM"
        else
            qemu-img snapshot -a "$2" "$DEV"
            echo "Снапшот $2 применён"
        fi
        ;;
    list)
        if vm_is_running; then
            echo "Снапшоты (VM запущена, QMP):"
            qmp_result "info snapshots"
        else
            echo "Снапшоты $DEV:"
            qemu-img snapshot -l "$DEV"
        fi
        ;;
    delete)
        if [ -z "$2" ]; then
            echo "Укажи имя: ./snapshot.sh delete <имя>"
            exit 1
        fi
        if vm_is_running; then
            echo "Нельзя удалить снапшот пока VM запущена"
            exit 1
        fi
        qemu-img snapshot -d "$2" "$DEV"
        echo "Снапшот $2 удалён"
        ;;
    *)
        echo "Управление снапшотами OpenWrt VM"
        echo ""
        echo "Использование: $0 <команда> [имя]"
        echo ""
        echo "Команды:"
        echo "  save [имя]    сохранить текущее состояние"
        echo "  load <имя>    загрузить состояние"
        echo "  list          список снапшотов"
        echo "  delete <имя>  удалить снапшот"
        echo ""
        if vm_is_running; then
            echo "Режим: QMP (VM запущена)"
        else
            echo "Режим: офлайн (VM остановлена)"
        fi
        ;;
esac

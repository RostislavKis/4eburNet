#!/bin/sh
# Деплой 4eburnet на тестовый роутер EC330
# Использование: ./scripts/deploy.sh {check|build|push|install|restart|logs|full|shell}

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONF="$SCRIPT_DIR/deploy.conf"
LOG="/tmp/4eburnet-deploy.log"

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo "[$(date '+%H:%M:%S')] $*" >> "$LOG"; }
msg_ok()   { printf "${GREEN}[OK]${NC} %s\n" "$*"; log "OK: $*"; }
msg_fail() { printf "${RED}[ОШИБКА]${NC} %s\n" "$*"; log "FAIL: $*"; }
msg_warn() { printf "${YELLOW}[!]${NC} %s\n" "$*"; log "WARN: $*"; }
msg_info() { printf "    %s\n" "$*"; }

# Загрузка конфига
if [ ! -f "$CONF" ]; then
    msg_fail "Файл $CONF не найден"
    msg_info ""
    msg_info "Создай конфиг:"
    msg_info "  cp scripts/deploy.conf.example scripts/deploy.conf"
    msg_info "  nano scripts/deploy.conf"
    msg_info ""
    exit 1
fi

. "$CONF"

# === РЕЖИМ VM ===
VM_MODE=false
if [ "$ROUTER_PORT" = "2222" ] && [ "$ROUTER_IP" = "localhost" ]; then
    VM_MODE=true
fi

# === ЗАЩИТА ОТ ДЕПЛОЯ НА БОЕВОЙ РОУТЕР ===
if [ "$ROUTER_IP" = "192.168.1.1" ]; then
    printf "\n${RED}██████████████████████████████████████████████████${NC}\n"
    printf "${RED}  СТОП: попытка деплоя на боевой Flint 2 заблокирована${NC}\n"
    printf "${RED}  ROUTER_IP=192.168.1.1 запрещён в deploy.conf${NC}\n"
    printf "${RED}██████████████████████████████████████████████████${NC}\n\n"
    log "BLOCKED: попытка деплоя на 192.168.1.1"
    exit 99
fi

SSH_CMD="ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -p $ROUTER_PORT ${ROUTER_USER}@${ROUTER_IP}"
SCP_CMD="scp -o ConnectTimeout=5 -o StrictHostKeyChecking=no -P $ROUTER_PORT"

# Проверка доступности роутера
check_router() {
    printf "Проверка связи с EC330 (%s)..." "$ROUTER_IP"
    if ping -c 1 -W 3 "$ROUTER_IP" > /dev/null 2>&1; then
        msg_ok "ping OK"
    else
        msg_fail "EC330 недоступен ($ROUTER_IP)"
        msg_info "EC330 ещё не прошит или недоступен"
        return 1
    fi

    printf "Проверка SSH..."
    if $SSH_CMD "echo ok" > /dev/null 2>&1; then
        msg_ok "SSH OK"
        REMOTE_VER=$($SSH_CMD "cat /etc/openwrt_release 2>/dev/null | grep DISTRIB_RELEASE | cut -d= -f2 | tr -d \"'\"" 2>/dev/null || echo "?")
        REMOTE_ARCH=$($SSH_CMD "uname -m" 2>/dev/null || echo "?")
        msg_info "OpenWrt $REMOTE_VER, arch: $REMOTE_ARCH"
    else
        msg_fail "SSH не отвечает"
        return 1
    fi
}

# Сборка
do_build() {
    msg_info "Сборка 4eburnet-core для $ROUTER_ARCH..."
    "$SCRIPT_DIR/build.sh" mipsel
}

# Отправка ipk на роутер
do_push() {
    check_router || exit 1

    IPK=$(find "$BUILD_DIR/mipsel/" -name "4eburnet-core*.ipk" -type f 2>/dev/null | sort -t_ -k2 -V | tail -1)
    if [ -z "$IPK" ]; then
        msg_fail "ipk не найден в $BUILD_DIR/mipsel/"
        msg_info "Сначала собери: ./scripts/deploy.sh build"
        return 1
    fi

    SIZE=$(du -h "$IPK" | cut -f1)
    msg_info "Файл: $(basename "$IPK") ($SIZE)"

    printf "Отправка на EC330..."
    $SCP_CMD "$IPK" "${ROUTER_USER}@${ROUTER_IP}:/tmp/" 2>/dev/null
    msg_ok "загружен в /tmp/"
}

# Установка
do_install() {
    do_push || exit 1

    IPK_NAME=$(basename "$(find "$BUILD_DIR/mipsel/" -name "4eburnet-core*.ipk" -type f | sort -t_ -k2 -V | tail -1)")
    printf "Установка пакета..."
    $SSH_CMD "opkg install /tmp/$IPK_NAME --force-reinstall" 2>/dev/null
    msg_ok "$IPK_NAME установлен"

    # B11-01: rpcd restart для применения ucode изменений в LuCI
    printf "Перезапуск rpcd..."
    $SSH_CMD "rpcd restart 2>/dev/null || /etc/init.d/rpcd restart 2>/dev/null" && \
        msg_ok "rpcd перезапущен — LuCI ucode обновлён" || \
        msg_warn "rpcd restart не удался (LuCI может использовать старый ucode)"
}

# Перезапуск
do_restart() {
    check_router || exit 1
    printf "Перезапуск 4eburnet..."
    $SSH_CMD "/etc/init.d/4eburnet restart" 2>/dev/null && msg_ok "перезапущен" || msg_warn "init.d скрипт не найден (ещё не создан?)"
}

# Логи
do_logs() {
    check_router || exit 1
    msg_info "Логи 4eburnet на EC330:"
    echo "---"
    $SSH_CMD "logread | grep -i 4eburnet | tail -30" 2>/dev/null || msg_warn "записей не найдено"
    echo "---"
}

# Полный цикл
do_full() {
    do_build
    do_install
    do_restart
    sleep 2
    do_logs
}

# SSH-сессия
do_shell() {
    check_router || exit 1
    msg_info "Подключение к EC330..."
    $SSH_CMD
}

# Справка
usage() {
    echo "4eburNet — деплой на EC330"
    echo ""
    echo "Использование: $0 <команда>"
    echo ""
    echo "Команды:"
    echo "  check     проверка SSH-соединения с EC330"
    echo "  build     сборка ipk для mipsel"
    echo "  push      отправка ipk на роутер в /tmp/"
    echo "  install   push + opkg install"
    echo "  restart   /etc/init.d/4eburnet restart"
    echo "  logs      logread | grep 4eburnet"
    echo "  full      build + install + restart + logs"
    echo "  shell     открыть SSH-сессию на EC330"
    echo ""
    echo "Конфиг: scripts/deploy.conf"
    echo "Лог:    $LOG"
    echo ""
    printf "${YELLOW}Целевой роутер: ${ROUTER_IP}:${ROUTER_PORT}${NC}\n"
    printf "${RED}Защита: деплой на 192.168.1.1 (Flint 2) заблокирован${NC}\n"
}

case "${1:-}" in
    check)   check_router ;;
    build)   do_build ;;
    push)    do_push ;;
    install) do_install ;;
    restart) do_restart ;;
    logs)    do_logs ;;
    full)    do_full ;;
    shell)   do_shell ;;
    *)       usage ;;
esac

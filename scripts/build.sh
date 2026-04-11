#!/bin/bash
# Сборка 4eburnet через OpenWrt SDK
# Использование: ./scripts/build.sh {mipsel|aarch64|clean}

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

msg_ok()   { printf "${GREEN}[OK]${NC} %s\n" "$*"; }
msg_fail() { printf "${RED}[ОШИБКА]${NC} %s\n" "$*"; }
msg_warn() { printf "${YELLOW}[!]${NC} %s\n" "$*"; }

# Пути к SDK (переопределить через переменные окружения)
SDK_BASE="${SDK_BASE:-$HOME/phoenix-router-dev/sdk}"
SDK_MIPSEL="${SDK_MIPSEL:-$SDK_BASE/mipsel/sdk-mipsel}"
SDK_AARCH64="${SDK_AARCH64:-$SDK_BASE/aarch64/sdk-aarch64}"

setup_symlinks() {
    local sdk="$1"

    if [ ! -d "$sdk" ]; then
        msg_fail "SDK не найден: $sdk"
        exit 1
    fi

    # core пакет
    local core_dir="$sdk/package/4eburnet-core"
    if [ ! -L "$core_dir" ] || [ "$(readlink -f "$core_dir")" != "$(readlink -f "$PROJECT_DIR/core")" ]; then
        rm -rf "$core_dir"
        ln -sfn "$PROJECT_DIR/core" "$core_dir"
        msg_ok "Симлинк: $core_dir -> core/"
    fi

    # LuCI пакет
    local luci_dir="$sdk/package/luci-app-4eburnet"
    if [ ! -L "$luci_dir" ] || [ "$(readlink -f "$luci_dir")" != "$(readlink -f "$PROJECT_DIR/luci-app-4eburnet")" ]; then
        rm -rf "$luci_dir"
        ln -sfn "$PROJECT_DIR/luci-app-4eburnet" "$luci_dir"
        msg_ok "Симлинк: $luci_dir -> luci-app-4eburnet/"
    fi
}

build_target() {
    local arch="$1"
    local sdk=""

    case "$arch" in
        mipsel)  sdk="$SDK_MIPSEL" ;;
        aarch64) sdk="$SDK_AARCH64" ;;
        *)
            msg_fail "Неизвестная архитектура: $arch"
            exit 1
            ;;
    esac

    echo "=== Сборка 4eburnet для $arch ==="

    # Маппинг arch → cross target
    local cross_arch=""
    case "$arch" in
        mipsel)  cross_arch="mipsel_24kc" ;;
        aarch64) cross_arch="aarch64" ;;
    esac

    # Шаг 1: cross-compile бинарника если нет prebuilt
    local prebuilt="$PROJECT_DIR/prebuilt/${cross_arch}/4eburnetd"
    if [ ! -f "$prebuilt" ]; then
        msg_warn "prebuilt/${cross_arch}/4eburnetd не найден — cross-compile..."
        cd "$PROJECT_DIR/core"
        make -f Makefile.dev "cross-${cross_arch}"
        cd "$PROJECT_DIR"
    else
        msg_ok "prebuilt/${cross_arch}/4eburnetd найден ($(du -h "$prebuilt" | cut -f1))"
    fi

    # Симлинки пакетов в SDK
    setup_symlinks "$sdk"

    # Сборка core + LuCI (pipefail прерывает при ошибке)
    cd "$sdk"
    printf "Компиляция core...\n"
    make package/4eburnet-core/compile V=s 2>&1 | tee /tmp/4eburnet-build-$arch.log
    printf "Компиляция luci...\n"
    make package/luci-app-4eburnet/compile V=s 2>&1 | tee -a /tmp/4eburnet-build-$arch.log
    msg_ok "сборка завершена (лог: /tmp/4eburnet-build-$arch.log)"

    # Копируем ipk в build/
    mkdir -p "$BUILD_DIR/$arch"
    for pkg in 4eburnet-core luci-app-4eburnet; do
        IPK=$(find "$sdk/bin/" -name "${pkg}*.ipk" -type f 2>/dev/null | head -1)
        if [ -n "$IPK" ]; then
            cp "$IPK" "$BUILD_DIR/$arch/"
            local size=$(du -h "$IPK" | cut -f1)
            local size_bytes=$(stat -c%s "$IPK")
            msg_ok "$(basename "$IPK") ($size)"
            if [ "$size_bytes" -gt 4194304 ]; then
                msg_warn "Размер $pkg >4 МБ!"
            fi
        else
            msg_warn "$pkg ipk не найден"
        fi
    done

    echo ""
    echo "Результат: $BUILD_DIR/$arch/"
    ls -lh "$BUILD_DIR/$arch/" 2>/dev/null
}

do_clean() {
    printf "Очистка build/..."
    rm -rf "$BUILD_DIR"
    msg_ok "build/ удалён"

    for sdk in "$SDK_MIPSEL" "$SDK_AARCH64"; do
        if [ -d "$sdk" ]; then
            cd "$sdk"
            make package/4eburnet-core/clean 2>/dev/null || true
            make package/luci-app-4eburnet/clean 2>/dev/null || true
        fi
    done
    msg_ok "SDK очищен"
}

usage() {
    echo "4eburNet — сборка пакетов"
    echo ""
    echo "Использование: $0 <команда>"
    echo ""
    echo "Команды:"
    echo "  mipsel    сборка для EC330 (ramips/mt7621)"
    echo "  aarch64   сборка для Flint 2 (mediatek/filogic)"
    echo "  clean     очистка build/ и SDK"
    echo ""
    echo "SDK mipsel:  $SDK_MIPSEL"
    echo "SDK aarch64: $SDK_AARCH64"
    echo "Результат:   $BUILD_DIR/<arch>/"
}

case "${1:-}" in
    mipsel)  build_target mipsel ;;
    aarch64) build_target aarch64 ;;
    clean)   do_clean ;;
    all)     build_target mipsel && build_target aarch64 ;;
    *)       usage ;;
esac

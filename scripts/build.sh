#!/bin/sh
# Сборка 4eburnet через OpenWrt SDK
# Использование: ./scripts/build.sh {mipsel|aarch64|clean}

set -e

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

# Пути к SDK
SDK_MIPSEL="$HOME/4eburnet-dev/sdk/mipsel-mt7621/sdk-mipsel-mt7621"
SDK_AARCH64="$HOME/4eburnet-dev/sdk/aarch64/sdk-aarch64"

setup_symlink() {
    local sdk="$1"
    local pkg_dir="$sdk/package/4eburnet-core"

    if [ ! -d "$sdk" ]; then
        msg_fail "SDK не найден: $sdk"
        exit 1
    fi

    if [ -L "$pkg_dir" ]; then
        # Симлинк уже есть — проверим что ведёт куда надо
        local target=$(readlink -f "$pkg_dir")
        if [ "$target" = "$(readlink -f "$PROJECT_DIR/core")" ]; then
            return 0
        fi
        rm "$pkg_dir"
    elif [ -d "$pkg_dir" ]; then
        rm -rf "$pkg_dir"
    fi

    ln -sfn "$PROJECT_DIR/core" "$pkg_dir"
    msg_ok "Симлинк: $pkg_dir -> core/"
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

    echo "=== Сборка 4eburnet-core для $arch ==="

    # Симлинк пакета в SDK
    setup_symlink "$sdk"

    # Сборка
    printf "Компиляция..."
    cd "$sdk"
    make package/4eburnet-core/compile V=s 2>&1 | tee /tmp/4eburnet-build-$arch.log

    if [ $? -eq 0 ]; then
        msg_ok "сборка завершена"
    else
        msg_fail "ошибка сборки"
        printf "    Лог: /tmp/4eburnet-build-$arch.log\n"
        exit 1
    fi

    # Копируем ipk в build/
    mkdir -p "$BUILD_DIR/$arch"
    IPK=$(find "$sdk/bin/packages/" -name "4eburnet-core*.ipk" -type f 2>/dev/null | head -1)

    if [ -z "$IPK" ]; then
        IPK=$(find "$sdk/bin/" -name "4eburnet-core*.ipk" -type f 2>/dev/null | head -1)
    fi

    if [ -n "$IPK" ]; then
        cp "$IPK" "$BUILD_DIR/$arch/"
        local size=$(du -h "$IPK" | cut -f1)
        local size_bytes=$(stat -c%s "$IPK")
        msg_ok "$(basename "$IPK") ($size)"

        # Предупреждение если >4MB
        if [ "$size_bytes" -gt 4194304 ]; then
            msg_warn "Размер пакета >4 МБ — слишком большой для роутера!"
        fi
    else
        msg_warn "ipk не найден в bin/"
        printf "    Проверь вывод сборки: /tmp/4eburnet-build-$arch.log\n"
    fi

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

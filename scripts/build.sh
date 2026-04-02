#!/bin/sh
# Сборка phoenix-router для обоих SDK
#
# Использование:
#   ./build.sh aarch64    — собрать для Flint 2
#   ./build.sh mipsel     — собрать для EC330
#   ./build.sh all        — собрать для обоих

SDK_BASE="$HOME/phoenix-router-dev/sdk"

build_target() {
    local arch="$1"
    local sdk_dir="$SDK_BASE/$arch/sdk-$arch"

    if [ ! -d "$sdk_dir" ]; then
        echo "SDK не найден: $sdk_dir"
        return 1
    fi

    echo "Сборка для $arch..."
    # TODO: копирование пакета в SDK, запуск make
}

case "${1:-all}" in
    aarch64) build_target aarch64 ;;
    mipsel)  build_target mipsel ;;
    all)     build_target aarch64 && build_target mipsel ;;
    *)       echo "Использование: $0 {aarch64|mipsel|all}" ;;
esac

#!/bin/sh
# Настройка симлинков пакета в SDK
#
# Создаёт символические ссылки из директории проекта
# в package/ директории обоих SDK, чтобы не копировать
# файлы вручную при каждом изменении.

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SDK_BASE="$HOME/phoenix-router-dev/sdk"

setup_sdk() {
    local arch="$1"
    local sdk="$SDK_BASE/$arch/sdk-$arch"
    local pkg_dir="$sdk/package/phoenix-core"

    if [ ! -d "$sdk" ]; then
        echo "SDK не найден: $sdk"
        return 1
    fi

    mkdir -p "$sdk/package"
    ln -sfn "$PROJECT_DIR/core" "$pkg_dir"
    echo "Симлинк создан: $pkg_dir -> $PROJECT_DIR/core"
}

setup_sdk aarch64
setup_sdk mipsel

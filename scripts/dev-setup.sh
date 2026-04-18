#!/usr/bin/env bash
# Настройка окружения разработки 4eburnet
#
# Проверяет зависимости, собирает wolfSSL с musl-gcc,
# запускает верификационную сборку 4eburnetd.
#
# Использование:
#   ./scripts/dev-setup.sh               # полная настройка
#   ./scripts/dev-setup.sh --check       # только проверка
#   ./scripts/dev-setup.sh --skip-wolfssl # пропустить wolfSSL

set -euo pipefail

# ------------------------------------------------------------------ #
#  Константы                                                          #
# ------------------------------------------------------------------ #

WOLFSSL_VERSION="5.9.0"
WOLFSSL_TAG="v${WOLFSSL_VERSION}-stable"
WOLFSSL_PREFIX="/usr/local/musl-wolfssl"
WOLFSSL_BUILD_DIR="/tmp/wolfssl-build-$$"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_DIR="$PROJECT_DIR/core"

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

START_TIME=$(date +%s)

# ------------------------------------------------------------------ #
#  Вспомогательные                                                    #
# ------------------------------------------------------------------ #

msg_ok()   { printf "${GREEN}[OK]${NC} %s\n" "$*"; }
msg_err()  { printf "${RED}[ERROR]${NC} %s\n" "$*"; }
msg_warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
msg_head() { printf "\n${BOLD}=== %s ===${NC}\n" "$*"; }

elapsed() {
    local now=$(date +%s)
    echo $(( now - START_TIME ))
}

# ------------------------------------------------------------------ #
#  Флаги                                                              #
# ------------------------------------------------------------------ #

FLAG_CHECK=false
FLAG_SKIP_WOLFSSL=false

for arg in "$@"; do
    case "$arg" in
        --check)        FLAG_CHECK=true ;;
        --skip-wolfssl) FLAG_SKIP_WOLFSSL=true ;;
        --help|-h)
            echo "Использование: $0 [--check] [--skip-wolfssl]"
            echo ""
            echo "  --check         только проверка зависимостей"
            echo "  --skip-wolfssl  пропустить сборку wolfSSL"
            exit 0
            ;;
        *)
            msg_err "Неизвестный флаг: $arg"
            exit 1
            ;;
    esac
done

# ------------------------------------------------------------------ #
#  1. Проверка зависимостей                                           #
# ------------------------------------------------------------------ #

msg_head "Проверка зависимостей"

MISSING=()

check_cmd() {
    local cmd="$1"
    local pkg="${2:-$1}"
    if command -v "$cmd" >/dev/null 2>&1; then
        msg_ok "$cmd"
    else
        msg_err "$cmd не найден (пакет: $pkg)"
        MISSING+=("$pkg")
    fi
}

check_cmd musl-gcc    musl-tools
check_cmd git         git
check_cmd make        build-essential
check_cmd autoconf    autoconf
check_cmd automake    automake
check_cmd libtoolize  libtool
check_cmd pkg-config  pkg-config

if [ ${#MISSING[@]} -gt 0 ]; then
    echo ""
    msg_err "Не хватает пакетов. Установи:"
    echo "  sudo apt-get install -y ${MISSING[*]}"
    if $FLAG_CHECK; then
        exit 1
    fi
    exit 1
fi

msg_ok "Все зависимости на месте"

if $FLAG_CHECK; then
    # Проверить wolfSSL
    msg_head "Проверка wolfSSL"
    if [ -f "$WOLFSSL_PREFIX/lib/libwolfssl.a" ]; then
        msg_ok "libwolfssl.a найден ($WOLFSSL_PREFIX/lib/)"
        if [ -f "$WOLFSSL_PREFIX/include/wolfssl/version.h" ]; then
            local_ver=$(grep '#define LIBWOLFSSL_VERSION_STRING' \
                "$WOLFSSL_PREFIX/include/wolfssl/version.h" 2>/dev/null \
                | sed 's/.*"\(.*\)".*/\1/')
            msg_ok "версия: ${local_ver:-unknown}"
        fi
    else
        msg_warn "wolfSSL не установлен"
    fi

    # Проверить сборку
    msg_head "Проверка сборки"
    if [ -f "$PROJECT_DIR/../build/4eburnetd" ]; then
        local size=$(ls -lh "$PROJECT_DIR/../build/4eburnetd" | awk '{print $5}')
        msg_ok "4eburnetd существует ($size)"
    else
        msg_warn "4eburnetd не собран"
    fi

    echo ""
    echo "Готово за $(elapsed) сек"
    exit 0
fi

# ------------------------------------------------------------------ #
#  2. Сборка wolfSSL                                                  #
# ------------------------------------------------------------------ #

if $FLAG_SKIP_WOLFSSL; then
    msg_head "wolfSSL (пропущено --skip-wolfssl)"
else
    msg_head "wolfSSL $WOLFSSL_VERSION"

    # Проверить уже установленную версию
    NEED_BUILD=true
    if [ -f "$WOLFSSL_PREFIX/lib/libwolfssl.a" ]; then
        if [ -f "$WOLFSSL_PREFIX/include/wolfssl/version.h" ]; then
            INSTALLED_VER=$(grep '#define LIBWOLFSSL_VERSION_STRING' \
                "$WOLFSSL_PREFIX/include/wolfssl/version.h" 2>/dev/null \
                | sed 's/.*"\(.*\)".*/\1/')
            if [ "$INSTALLED_VER" = "$WOLFSSL_VERSION" ]; then
                msg_ok "wolfSSL $WOLFSSL_VERSION уже установлен, пропускаем"
                NEED_BUILD=false
            else
                msg_warn "Установлена версия $INSTALLED_VER, нужна $WOLFSSL_VERSION"
            fi
        fi
    fi

    if $NEED_BUILD; then
        echo "Клонирование wolfSSL $WOLFSSL_TAG..."
        rm -rf "$WOLFSSL_BUILD_DIR"
        git clone --depth=1 --branch "$WOLFSSL_TAG" \
            https://github.com/wolfSSL/wolfssl.git \
            "$WOLFSSL_BUILD_DIR" 2>&1 | tail -1

        cd "$WOLFSSL_BUILD_DIR"

        echo "Запуск autogen..."
        ./autogen.sh >/dev/null 2>&1

        echo "Конфигурация с musl-gcc..."
        CC=musl-gcc ./configure \
            --prefix="$WOLFSSL_PREFIX" \
            --enable-static \
            --disable-shared \
            --enable-tls13 \
            --enable-sni \
            --enable-curve25519 \
            --enable-chacha \
            --enable-poly1305 \
            --enable-aesgcm \
            --enable-harden \
            --enable-tlsx \
            --enable-supportedcurves \
            --enable-session-ticket \
            --enable-alpn \
            --enable-quic \
            --silent >/dev/null 2>&1

        echo "Компиляция ($(nproc) потоков)..."
        make -j"$(nproc)" >/dev/null 2>&1

        echo "Установка в $WOLFSSL_PREFIX..."
        sudo make install >/dev/null 2>&1

        rm -rf "$WOLFSSL_BUILD_DIR"
        msg_ok "wolfSSL $WOLFSSL_VERSION установлен"
    fi

    # Верификация
    if [ -f "$WOLFSSL_PREFIX/lib/libwolfssl.a" ]; then
        LIB_SIZE=$(ls -lh "$WOLFSSL_PREFIX/lib/libwolfssl.a" | awk '{print $5}')
        msg_ok "libwolfssl.a ($LIB_SIZE)"
    else
        msg_err "libwolfssl.a не найден после установки"
        exit 1
    fi
fi

# ------------------------------------------------------------------ #
#  3. Симлинки SDK (если SDK присутствует)                            #
# ------------------------------------------------------------------ #

msg_head "OpenWrt SDK"

SDK_BASE="$HOME/4eburnet-dev/sdk"
SDK_FOUND=false

for arch in aarch64 mipsel; do
    SDK_DIR="$SDK_BASE/$arch/sdk-$arch"
    if [ -d "$SDK_DIR" ]; then
        PKG_DIR="$SDK_DIR/package/4eburnet-core"
        mkdir -p "$SDK_DIR/package"
        if [ ! -L "$PKG_DIR" ] || \
           [ "$(readlink -f "$PKG_DIR")" != "$(readlink -f "$CORE_DIR")" ]; then
            ln -sfn "$CORE_DIR" "$PKG_DIR"
            msg_ok "SDK $arch: симлинк создан"
        else
            msg_ok "SDK $arch: симлинк актуален"
        fi
        SDK_FOUND=true
    fi
done

if ! $SDK_FOUND; then
    msg_warn "SDK не найден в $SDK_BASE/ (не обязательно для x86_64)"
fi

# ------------------------------------------------------------------ #
#  4. Верификационная сборка                                          #
# ------------------------------------------------------------------ #

msg_head "Верификационная сборка"

cd "$CORE_DIR"
make -f Makefile.dev clean >/dev/null 2>&1 || true

echo "Компиляция 4eburnetd..."
if make -f Makefile.dev 2>&1 | tail -3; then
    BINARY="$PROJECT_DIR/../build/4eburnetd"
    if [ -f "$BINARY" ]; then
        BIN_SIZE=$(ls -lh "$BINARY" | awk '{print $5}')
        BIN_BYTES=$(stat -c%s "$BINARY")
        msg_ok "4eburnetd ($BIN_SIZE)"

        if [ "$BIN_BYTES" -gt 4194304 ]; then
            msg_warn "Размер >4 МБ — превышает лимит для роутеров!"
        fi
    else
        msg_err "Бинарник не найден"
        exit 1
    fi
else
    msg_err "Сборка провалилась"
    exit 1
fi

# ------------------------------------------------------------------ #
#  Готово                                                             #
# ------------------------------------------------------------------ #

echo ""
printf "${GREEN}${BOLD}Окружение готово за $(elapsed) сек${NC}\n"
echo ""
echo "Следующие шаги:"
echo "  make -f core/Makefile.dev          # пересборка"
echo "  scripts/deploy.sh full             # деплой в VM"
echo "  ssh -p 2222 root@localhost         # SSH в VM"

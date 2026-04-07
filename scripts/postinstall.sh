#!/bin/sh
# postinstall.sh — первичная настройка phoenix-router после opkg install
# Запускается: /etc/uci-defaults/99-phoenix-router (один раз при boot)
# или вручную: sh /usr/share/phoenix-router/postinstall.sh

set -e

PHOENIX_CONF="/etc/config/phoenix"
GEO_DIR="/etc/phoenix/geo"
PHOENIX_BIN="/usr/sbin/phoenixd"
GEO_CONVERT="/usr/share/phoenix-router/geo_convert.py"
LOG_TAG="phoenix-postinstall"

log() { logger -t "$LOG_TAG" "$1"; echo "[$LOG_TAG] $1"; }
warn() { logger -t "$LOG_TAG" "WARN: $1"; echo "[$LOG_TAG] WARN: $1" >&2; }

# ── Шаг 1: определить регион ──────────────────────────────────────────────

detect_region() {
    # Приоритет 1: уже задан в конфиге
    if [ -f "$PHOENIX_CONF" ]; then
        R=$(uci -q get phoenix.@phoenix[0].region 2>/dev/null || true)
        if [ -n "$R" ]; then
            echo "$R"; return
        fi
    fi

    # Приоритет 2: timezone из /etc/config/system
    TZ=$(uci -q get system.@system[0].zonename 2>/dev/null || true)
    case "$TZ" in
        Europe/Moscow|Europe/Kaliningrad|Europe/Samara|\
        Europe/Ulyanovsk|Europe/Volgograd|Europe/Saratov|\
        Europe/Kirov|Europe/Astrakhan|Asia/Yekaterinburg|\
        Asia/Omsk|Asia/Novosibirsk|Asia/Krasnoyarsk|\
        Asia/Irkutsk|Asia/Yakutsk|Asia/Vladivostok|\
        Asia/Magadan|Asia/Kamchatka|Asia/Sakhalin)
            echo "ru"; return ;;
        Asia/Shanghai|Asia/Beijing|Asia/Chongqing|\
        Asia/Harbin|Asia/Urumqi)
            echo "cn"; return ;;
        America/*)
            echo "us"; return ;;
    esac

    # Приоритет 3: спросить пользователя если интерактивный терминал
    if [ -t 0 ]; then
        echo ""
        echo "Не удалось определить регион автоматически."
        echo "Выберите регион:"
        echo "  1) RU — Россия"
        echo "  2) CN — Китай"
        echo "  3) US — США"
        echo "  4) OTHER — другой (минимальный набор)"
        printf "Ваш выбор [1-4]: "
        read -r CHOICE
        case "$CHOICE" in
            1) echo "ru"; return ;;
            2) echo "cn"; return ;;
            3) echo "us"; return ;;
        esac
    fi

    echo "other"
}

# ── Шаг 2: создать базовый конфиг если нет ───────────────────────────────

create_default_config() {
    REGION="$1"
    log "Создание базового конфига для региона: $REGION"

    # Не перезаписывать существующий конфиг
    if [ -f "$PHOENIX_CONF" ]; then
        log "Конфиг уже существует, пропуск"
        return
    fi

    cat > "$PHOENIX_CONF" << EOF
# phoenix-router configuration
# Управление через LuCI: Services → Phoenix Router

config phoenix 'main'
    option enabled '1'
    option region '$REGION'
    option geo_dir '$GEO_DIR'
    option log_level 'info'
    option log_file '/tmp/phoenix.log'
    option dns_port '53'
    option tproxy_port '7893'
    option api_socket '/var/run/phoenix.sock'
    option tai_utc_offset '37'

EOF

    # Добавить rule_provider для антирекламы (для всех регионов)
    cat >> "$PHOENIX_CONF" << EOF
config rule_provider 'geosite_ads'
    option name 'geosite-ads'
    option type 'http'
    option url 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
    option path '$GEO_DIR/geosite-ads.lst'
    option format 'domain'
    option interval '259200'
    option enabled '1'

EOF

    # Добавить rule_provider специфичные для региона
    case "$REGION" in
        ru)
            # ВАЖНО: заблокируйте на VPN сервере доступ обратно в geoip:ru
            # Это предотвращает идентификацию вашего IP через паттерн трафика
            # xray/3x-ui routing rule: geoip:ru → block (или direct через WARP)
            cat >> "$PHOENIX_CONF" << EOF
config rule_provider 'geoip_ru'
    option name 'geoip-ru'
    option type 'http'
    option url 'https://raw.githubusercontent.com/nicholasstephan/russia-ip-list/main/russia.list'
    option path '$GEO_DIR/geoip-ru.lst'
    option format 'ipcidr'
    option interval '2592000'
    option enabled '1'
    option region 'ru'

config rule_provider 'geosite_ru'
    option name 'geosite-ru'
    option type 'http'
    option url 'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/ru'
    option path '$GEO_DIR/geosite-ru.lst'
    option format 'domain'
    option interval '604800'
    option enabled '1'
    option region 'ru'

config rule_provider 'antizapret'
    option name 'antizapret'
    option type 'http'
    option url 'https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv'
    option path '$GEO_DIR/antizapret.lst'
    option format 'ipcidr'
    option interval '86400'
    option enabled '1'
    option region 'ru'

config traffic_rule 'rule_antizapret'
    option type 'RULE-SET'
    option value 'antizapret'
    option target 'proxy'
    option priority '100'
    option enabled '1'

config traffic_rule 'rule_geoip_ru'
    option type 'GEOIP'
    option value 'RU'
    option target 'DIRECT'
    option priority '200'
    option enabled '1'

config traffic_rule 'rule_geosite_ru'
    option type 'GEOSITE'
    option value 'ru'
    option target 'DIRECT'
    option priority '210'
    option enabled '1'

config traffic_rule 'rule_geosite_ads'
    option type 'GEOSITE'
    option value 'ads'
    option target 'REJECT'
    option priority '50'
    option enabled '1'

config traffic_rule 'rule_match'
    option type 'MATCH'
    option target 'proxy'
    option priority '999'
    option enabled '1'

EOF
            ;;
        cn)
            cat >> "$PHOENIX_CONF" << EOF
config rule_provider 'geoip_cn'
    option name 'geoip-cn'
    option type 'http'
    option url 'https://raw.githubusercontent.com/nicholasstephan/china-ip-list/main/china.list'
    option path '$GEO_DIR/geoip-cn.lst'
    option format 'ipcidr'
    option interval '2592000'
    option enabled '1'
    option region 'cn'

config traffic_rule 'rule_geoip_cn'
    option type 'GEOIP'
    option value 'CN'
    option target 'DIRECT'
    option priority '200'
    option enabled '1'

config traffic_rule 'rule_match'
    option type 'MATCH'
    option target 'proxy'
    option priority '999'
    option enabled '1'

EOF
            ;;
        *)
            cat >> "$PHOENIX_CONF" << EOF
config traffic_rule 'rule_match'
    option type 'MATCH'
    option target 'proxy'
    option priority '999'
    option enabled '1'

EOF
            ;;
    esac

    log "Конфиг создан: $PHOENIX_CONF"
}

# ── Шаг 3: скачать начальные geo файлы ───────────────────────────────────

download_geo_files() {
    REGION="$1"
    mkdir -p "$GEO_DIR"

    log "Загрузка гео-файлов для региона: $REGION"

    # Попробовать через geo_convert.py
    if [ -f "$GEO_CONVERT" ] && command -v python3 >/dev/null 2>&1; then
        log "Используем geo_convert.py"
        python3 "$GEO_CONVERT" --source "geosite-ads" \
            --output "$GEO_DIR" 2>/dev/null && \
            log "geosite-ads.lst загружен" || \
            warn "geosite-ads.lst не загружен"

        case "$REGION" in
            ru)
                python3 "$GEO_CONVERT" --source "geoip-ru" \
                    --output "$GEO_DIR" 2>/dev/null && \
                    log "geoip-ru.lst загружен" || \
                    warn "geoip-ru.lst не загружен"
                python3 "$GEO_CONVERT" --source "geosite-ru" \
                    --output "$GEO_DIR" 2>/dev/null && \
                    log "geosite-ru.lst загружен" || \
                    warn "geosite-ru.lst не загружен"
                ;;
            cn)
                python3 "$GEO_CONVERT" --source "geoip-cn" \
                    --output "$GEO_DIR" 2>/dev/null && \
                    log "geoip-cn.lst загружен" || \
                    warn "geoip-cn.lst не загружен"
                ;;
        esac
        return
    fi

    # Fallback: wget напрямую
    if command -v wget >/dev/null 2>&1; then
        log "geo_convert.py недоступен, используем wget"
        case "$REGION" in
            ru)
                wget -q -O "$GEO_DIR/geoip-ru.lst" \
                    "https://raw.githubusercontent.com/nicholasstephan/russia-ip-list/main/russia.list" \
                    2>/dev/null && log "geoip-ru.lst загружен (raw)" || \
                    warn "geoip-ru.lst не загружен"
                ;;
        esac
    else
        warn "Нет python3 и wget — geo файлы не загружены"
        warn "Загрузите вручную или через rule_provider после старта"
    fi
}

# ── Шаг 4: включить и запустить службу ───────────────────────────────────

enable_service() {
    if [ -f /etc/init.d/phoenix-router ]; then
        /etc/init.d/phoenix-router enable 2>/dev/null || true
        log "Служба phoenix-router включена в автозагрузку"
    fi
}

# ── Главная логика ────────────────────────────────────────────────────────

main() {
    log "=== phoenix-router postinstall ==="
    log "Версия: $(${PHOENIX_BIN} --version 2>/dev/null || echo 'unknown')"

    REGION=$(detect_region)
    log "Регион: $REGION"

    create_default_config "$REGION"
    download_geo_files "$REGION"
    enable_service

    log "=== Настройка завершена ==="
    log "Откройте LuCI: Services → Phoenix Router для настройки серверов"
}

main "$@"

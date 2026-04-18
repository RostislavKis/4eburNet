#!/bin/sh
# geo_update.sh — обновление всех GeoIP/GeoSite списков
# Вызывается вручную или из cron
# Запускается на роутере (busybox ash)

GEO_DIR="/etc/4eburnet/geo"
SHARE_DIR="/usr/share/4eburnet"
GEO_CONVERT="${SHARE_DIR}/geo_convert.sh"
LOG_TAG="4eburnet-geo"

# Базовый URL для прямых списков
BASE_URL="https://raw.githubusercontent.com/RostislavKis/filter/master/geo"

mkdir -p "$GEO_DIR"

logger -t "$LOG_TAG" "Запуск обновления geo списков..."
echo "=== geo_update: $(date) ==="

# Вспомогательная: скачать прямой файл
fetch_direct() {
    local name="$1"
    local url="$2"
    local out="${GEO_DIR}/${name}"
    local tmp="${out}.tmp"

    echo "Скачиваю $name..."
    if uclient-fetch -T 60 -O "$tmp" "$url" 2>/dev/null; then
        COUNT=$(grep -c '^[^#]' "$tmp" 2>/dev/null || echo 0)
        if [ "$COUNT" -lt 100 ]; then
            echo "WARN: $name слишком мал ($COUNT строк), пропускаю"
            rm -f "$tmp"
            return 1
        fi
        mv "$tmp" "$out"
        logger -t "$LOG_TAG" "$name: $COUNT записей"
        echo "OK: $name ($COUNT записей)"
    else
        rm -f "$tmp"
        echo "FAIL: $name — скачивание не удалось"
        logger -t "$LOG_TAG" "WARN: не удалось обновить $name"
        return 1
    fi
}

# 1. geoip-ru.lst — CIDR списки РФ
fetch_direct "geoip-ru.lst" "${BASE_URL}/geoip-ru.lst"

# 2. geosite-ru.lst — домены в зоне .ru
fetch_direct "geosite-ru.lst" "${BASE_URL}/geosite-ru.lst"

# 3. geosite-ads.lst — рекламные домены
fetch_direct "geosite-ads.lst" "${BASE_URL}/geosite-ads.lst"

# 4. geosite-trackers.lst — трекеры (EasyPrivacy adblock формат)
if [ -x "$GEO_CONVERT" ]; then
    echo "Конвертирую trackers (EasyPrivacy)..."
    "$GEO_CONVERT" trackers \
        "https://easylist.to/easylist/easyprivacy.txt" \
        "${GEO_DIR}/geosite-trackers.lst" \
        && logger -t "$LOG_TAG" "geosite-trackers.lst обновлён" \
        || logger -t "$LOG_TAG" "WARN: geosite-trackers.lst не обновлён"
else
    echo "WARN: geo_convert.sh не найден, trackers пропущен"
fi

# 5. geosite-threats.lst — угрозы (URLhaus hosts формат)
if [ -x "$GEO_CONVERT" ]; then
    echo "Конвертирую threats (URLhaus)..."
    "$GEO_CONVERT" threats \
        "https://urlhaus.abuse.ch/downloads/hostfile/" \
        "${GEO_DIR}/geosite-threats.lst" \
        && logger -t "$LOG_TAG" "geosite-threats.lst обновлён" \
        || logger -t "$LOG_TAG" "WARN: geosite-threats.lst не обновлён"
else
    echo "WARN: geo_convert.sh не найден, threats пропущен"
fi

# 6. opencck-domains.lst — актуальный список РКН (домены)
echo "Обновляю opencck-domains (РКН домены)..."
RULES_DIR="/etc/4eburnet/rules"
mkdir -p "$RULES_DIR"
TMP_OPENCCK="${RULES_DIR}/opencck-domains.tmp"
if uclient-fetch -T 60 \
    -O "$TMP_OPENCCK" \
    "https://iplist.opencck.org/?format=text&type=domains&data=domains" \
    2>/dev/null; then
    COUNT=$(grep -c '^[^#]' "$TMP_OPENCCK" 2>/dev/null || echo 0)
    if [ "$COUNT" -gt 1000 ]; then
        mv "$TMP_OPENCCK" "${RULES_DIR}/opencck-domains.lst"
        logger -t "$LOG_TAG" "opencck-domains.lst: $COUNT доменов"
        echo "OK: opencck-domains ($COUNT доменов)"
    else
        rm -f "$TMP_OPENCCK"
        echo "WARN: opencck-domains слишком мал ($COUNT), пропущено"
    fi
else
    rm -f "$TMP_OPENCCK"
    echo "FAIL: opencck-domains — скачивание не удалось"
    logger -t "$LOG_TAG" "WARN: opencck-domains не обновлён"
fi

# 7. opencck-cidr.lst — актуальный список РКН (IP диапазоны)
echo "Обновляю opencck-cidr (РКН IP)..."
TMP_CIDR="${RULES_DIR}/opencck-cidr.tmp"
if uclient-fetch -T 60 \
    -O "$TMP_CIDR" \
    "https://iplist.opencck.org/?format=text&type=cidr&data=cidr4" \
    2>/dev/null; then
    COUNT=$(grep -c '^[^#]' "$TMP_CIDR" 2>/dev/null || echo 0)
    if [ "$COUNT" -gt 100 ]; then
        mv "$TMP_CIDR" "${RULES_DIR}/opencck-cidr.lst"
        logger -t "$LOG_TAG" "opencck-cidr.lst: $COUNT CIDR"
        echo "OK: opencck-cidr ($COUNT CIDR)"
    else
        rm -f "$TMP_CIDR"
        echo "WARN: opencck-cidr слишком мал ($COUNT), пропущено"
    fi
else
    rm -f "$TMP_CIDR"
    echo "FAIL: opencck-cidr — скачивание не удалось"
    logger -t "$LOG_TAG" "WARN: opencck-cidr не обновлён"
fi

echo "=== geo_update: завершено ==="
logger -t "$LOG_TAG" "Обновление geo списков завершено"

# Перечитать конфиг демона если запущен
if [ -f /var/run/4eburnet.pid ]; then
    PID=$(cat /var/run/4eburnet.pid)
    if kill -0 "$PID" 2>/dev/null; then
        kill -HUP "$PID" 2>/dev/null && \
            echo "Демон перечитал конфиг (SIGHUP)" || true
    fi
fi

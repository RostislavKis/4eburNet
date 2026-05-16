#!/bin/sh
# WHY: скачивает готовые .gbin из filter репо (RostislavKis/filter).
# Компиляция .lst -> .gbin выполняется на dev машине через update_geo.bat.
# Роутер скачивает только финальные бинарные файлы — никакой компиляции.

BASE="https://github.com/RostislavKis/filter/raw/master"
GEO_DIR="/etc/4eburnet/geo"
PROFILE="${1:-$(uci get 4eburnet.main.geo_profile 2>/dev/null || echo 'normal')}"
TMP="/tmp/4eburnet-geo-update"
UPDATED=0
ERRORS=0

mkdir -p "$TMP" "$GEO_DIR"
logger -t 4eburnet "geo_update: старт профиль=$PROFILE"

# Скачать манифест профиля
if ! wget -q -T 30 -O "$TMP/manifest.json" "${BASE}/geo/${PROFILE}.json"; then
    logger -t 4eburnet "geo_update: ошибка загрузки манифеста ${PROFILE}.json"
    rm -rf "$TMP"
    exit 1
fi

# Скачать checksums для проверки (необязательно — не прерываем при ошибке)
wget -q -T 30 -O "$TMP/checksums.sha256" "${BASE}/checksums.sha256" || true

# Извлечь имена файлов из поля "name" (без jq — grep + sed)
FILES=$(grep '"name"' "$TMP/manifest.json" | sed 's/.*"name": *"\([^"]*\)".*/\1/')

if [ -z "$FILES" ]; then
    logger -t 4eburnet "geo_update: манифест пуст или невалиден"
    rm -rf "$TMP"
    exit 1
fi

for FILE in $FILES; do
    LOCAL="$GEO_DIR/$FILE"
    REMOTE="${BASE}/geo/${FILE}"

    # Пропустить если sha256 совпадает
    if [ -f "$TMP/checksums.sha256" ] && [ -f "$LOCAL" ]; then
        EXPECTED=$(grep "  ${FILE}$" "$TMP/checksums.sha256" | awk '{print $1}')
        if [ -n "$EXPECTED" ]; then
            CURRENT=$(sha256sum "$LOCAL" 2>/dev/null | awk '{print $1}')
            if [ "$CURRENT" = "$EXPECTED" ]; then
                logger -t 4eburnet "geo_update: $FILE актуален, пропуск"
                continue
            fi
        fi
    fi

    logger -t 4eburnet "geo_update: скачиваю $FILE"
    if wget -q -T 60 -O "${LOCAL}.tmp" "$REMOTE"; then
        mv "${LOCAL}.tmp" "$LOCAL"
        UPDATED=$((UPDATED + 1))
        logger -t 4eburnet "geo_update: $FILE обновлён"
    else
        rm -f "${LOCAL}.tmp"
        ERRORS=$((ERRORS + 1))
        logger -t 4eburnet "geo_update: ошибка скачивания $FILE"
    fi
done

rm -rf "$TMP"

# Hot-reload демона (SIGHUP = reload geo, не restart)
if [ -f /var/run/4eburnetd.pid ]; then
    kill -HUP "$(cat /var/run/4eburnetd.pid)" 2>/dev/null && \
        logger -t 4eburnet "geo_update: SIGHUP отправлен"
fi

logger -t 4eburnet "geo_update: завершено updated=$UPDATED errors=$ERRORS"
echo "geo_update: профиль=$PROFILE обновлено=$UPDATED ошибок=$ERRORS"
exit "$ERRORS"

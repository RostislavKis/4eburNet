#!/bin/sh
# WHY: скачивает .gbin из RostislavKis/filter по manifest.
# Production: прямой выход в интернет через WAN роутера.
# Dev (EC330 за NAT): нет WAN-доступа — деплоить .gbin через scp вручную.

BASE="https://github.com/RostislavKis/filter/raw/master"
GEO_DIR="/etc/4eburnet/geo"
PROFILE="${1:-$(uci get 4eburnet.main.geo_profile 2>/dev/null || echo 'normal')}"
TMP="/tmp/4eburnet-geo-update"
UPDATED=0
ERRORS=0

mkdir -p "$TMP" "$GEO_DIR"
logger -t 4eburnet "geo_update: старт профиль=$PROFILE"

# _fetch url outfile — busybox wget всегда возвращает 0,
# поэтому проверяем что файл непустой после скачивания
_fetch() {
    _url="$1"; _out="$2"
    wget -qT 30 -O "$_out" "$_url" 2>/dev/null
    [ -s "$_out" ] && return 0
    rm -f "$_out"
    # fallback: uclient-fetch (другой SSL backend)
    uclient-fetch -qT 30 -O "$_out" "$_url" 2>/dev/null
    [ -s "$_out" ] && return 0
    rm -f "$_out"
    return 1
}

# Скачать манифест профиля
if ! _fetch "${BASE}/geo/${PROFILE}.json" "$TMP/manifest.json"; then
    logger -t 4eburnet "geo_update: ошибка загрузки манифеста ${PROFILE}.json"
    rm -rf "$TMP"
    exit 1
fi

# Скачать checksums (не прерываем при ошибке)
_fetch "${BASE}/checksums.sha256" "$TMP/checksums.sha256" || true

# Извлечь имена файлов из поля "name" (без jq)
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
    if _fetch "$REMOTE" "${LOCAL}.tmp"; then
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

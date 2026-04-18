#!/bin/sh
# geo_convert.sh — загрузка и конвертация geo списков в формат демона
# Использование: geo_convert.sh <category> <url> <output>
# category: trackers | threats | direct (один домен на строку)
# Запускается на роутере (busybox ash)

set -e

CATEGORY="$1"
URL="$2"
OUTPUT="$3"
TMP="${OUTPUT}.tmp"

if [ -z "$CATEGORY" ] || [ -z "$URL" ] || [ -z "$OUTPUT" ]; then
    echo "Использование: $0 <category> <url> <output>" >&2
    exit 1
fi

# Создать директорию если нет
OUTPUT_DIR="$(dirname "$OUTPUT")"
[ -d "$OUTPUT_DIR" ] || mkdir -p "$OUTPUT_DIR"

# Скачать во временный файл (таймаут 60 сек)
uclient-fetch -T 60 -O "$TMP" "$URL" 2>/dev/null || {
    echo "geo_convert: не удалось скачать $URL" >&2
    rm -f "$TMP"
    exit 1
}

# Конвертировать в зависимости от формата
case "$CATEGORY" in
    trackers)
        # EasyPrivacy adblock формат: ||domain.com^
        # Извлечь домены из строк вида ||domain.com^
        # Исключить: @@..., /regex/, IP-адреса, wildcard
        grep '^||' "$TMP" | \
            grep '\^$' | \
            sed 's/^||//; s/\^$//' | \
            grep -v '/' | \
            grep -v '\*' | \
            grep -E '^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$' \
            > "${OUTPUT}.new"
        ;;
    threats)
        # URLhaus hosts формат: 0.0.0.0 domain.com или 127.0.0.1 domain.com
        grep -E '^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]' "$TMP" | \
            awk '{print $2}' | \
            grep -v '^localhost' | \
            grep -v '^local$' | \
            grep -E '^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$' \
            > "${OUTPUT}.new"
        ;;
    *)
        # Прямой формат: один домен/суффикс на строку, # — комментарий
        grep -v '^#' "$TMP" | \
            grep -v '^[[:space:]]*$' | \
            grep -E '^[.a-zA-Z0-9_-]+$' \
            > "${OUTPUT}.new"
        ;;
esac

rm -f "$TMP"

# Проверить что результат не пустой
COUNT=$(wc -l < "${OUTPUT}.new")
if [ "$COUNT" -lt 100 ]; then
    echo "geo_convert: результат слишком мал ($COUNT строк), старый файл сохранён" >&2
    rm -f "${OUTPUT}.new"
    exit 1
fi

# Атомарная замена
mv "${OUTPUT}.new" "$OUTPUT"
echo "geo_convert: $CATEGORY: $COUNT доменов → $OUTPUT"

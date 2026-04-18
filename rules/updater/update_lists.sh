#!/bin/sh
# Обновление списков маршрутизации
# Скачивает geosite/geoip и конвертирует в формат nftables sets

RULES_DIR="/etc/phoenix/rules"
SOURCES_CONF="$(dirname "$0")/sources.conf"

# TODO: чтение sources.conf, скачивание, конвертация
echo "Обновление списков маршрутизации..."

/*
 * Парсер конфигурации UCI
 *
 * Читает /etc/config/phoenix и заполняет внутренние структуры.
 * UCI — стандартный формат конфигов в OpenWrt.
 */

#include "config.h"
#include <stdio.h>

int phoenix_config_load(const char *path)
{
    /* TODO: подключить libuci и прочитать секции:
     * - phoenix.global    (общие настройки)
     * - phoenix.server    (список прокси-серверов)
     * - phoenix.routing   (правила маршрутизации)
     * - phoenix.dns       (настройки DNS)
     */
    printf("Загрузка конфига: %s\n", path);
    return 0;
}

int phoenix_config_reload(void)
{
    /* TODO: перечитать конфиг по сигналу SIGHUP */
    return 0;
}

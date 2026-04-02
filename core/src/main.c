/*
 * phoenix-router — точка входа
 *
 * Порядок запуска:
 * 1. Определяем профиль устройства по доступной RAM
 * 2. Читаем конфигурацию из UCI (/etc/config/phoenix)
 * 3. Запускаем подсистемы: DNS, маршрутизация, прокси
 * 4. Активируем watchdog для мониторинга процессов
 * 5. Входим в основной цикл обработки событий
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysinfo.h>

#include "phoenix.h"
#include "config.h"

/* Определяем профиль по объёму оперативной памяти */
static DeviceProfile detect_profile(void)
{
    struct sysinfo info;
    if (sysinfo(&info) != 0)
        return DEVICE_MICRO;

    unsigned long ram_mb = info.totalram / (1024 * 1024);

    if (ram_mb < 96)
        return DEVICE_MICRO;
    if (ram_mb < 384)
        return DEVICE_NORMAL;

    return DEVICE_FULL;
}

int main(int argc, char *argv[])
{
    printf("%s v%s запускается\n", PHOENIX_NAME, PHOENIX_VERSION);

    DeviceProfile profile = detect_profile();
    const char *profile_names[] = {"MICRO", "NORMAL", "FULL"};
    printf("Профиль устройства: %s\n", profile_names[profile]);

    /*
     * TODO: чтение конфига через UCI
     * phoenix_config_load(PHOENIX_CONFIG_PATH);
     */

    /*
     * TODO: запуск DNS-резолвера
     * dns_resolver_start(profile);
     */

    /*
     * TODO: настройка nftables правил
     * routing_setup(profile);
     */

    /*
     * TODO: запуск прокси-диспетчера
     * proxy_dispatcher_start(profile);
     */

    /*
     * TODO: запуск watchdog
     * watchdog_start();
     */

    printf("phoenix-router остановлен\n");
    return 0;
}

/*
 * Политики маршрутизации
 *
 * Определяет, какой трафик направлять через прокси:
 * - по домену (geosite)
 * - по IP (geoip)
 * - по порту
 * - по пользователю/группе
 */

#include <stdio.h>

int policy_match(const char *domain, const char *ip, int port)
{
    /* TODO: проверка по загруженным спискам правил */
    return 0;
}

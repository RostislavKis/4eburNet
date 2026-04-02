/*
 * Классификатор доменов
 *
 * Определяет категорию домена по загруженным спискам:
 * - прямой доступ (bypass)
 * - через прокси (proxy)
 * - заблокировать (block)
 */

#include <stdio.h>

int dns_classify(const char *domain)
{
    /* TODO: поиск домена по спискам geosite */
    return 0;
}

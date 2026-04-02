/*
 * DNS-кеш
 *
 * Хранит результаты DNS-запросов в памяти.
 * Размер кеша зависит от профиля устройства.
 */

#include <stdio.h>

int dns_cache_init(int max_entries)
{
    /* TODO: аллокация хеш-таблицы для кеша */
    return 0;
}

int dns_cache_lookup(const char *domain, void *result)
{
    /* TODO */
    return -1;
}

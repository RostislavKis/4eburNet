/*
 * DNS-резолвер
 *
 * Перехватывает DNS-запросы и направляет их:
 * - внутренние домены → локальный DNS
 * - заблокированные домены → DNS через прокси (DoH/DoT)
 * - остальные → системный DNS
 */

#include <stdio.h>

int dns_resolver_start(int cache_size)
{
    /* TODO: запуск UDP/TCP слушателя на порту 5353 */
    return 0;
}

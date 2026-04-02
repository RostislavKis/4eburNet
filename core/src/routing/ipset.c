/*
 * Управление IP-списками (nftables sets)
 *
 * Загружает списки IP-адресов и доменов для выборочной
 * маршрутизации: какой трафик идёт через прокси, какой — напрямую.
 */

#include <stdio.h>

int ipset_load(const char *path)
{
    /* TODO: загрузить IP-список из файла в nftables set */
    return 0;
}

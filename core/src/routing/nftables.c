/*
 * Управление правилами nftables
 *
 * Создаёт таблицы и цепочки для перенаправления трафика
 * через прокси. Работает через libnftables или вызов nft.
 */

#include <stdio.h>

int nftables_setup(void)
{
    /* TODO: создать таблицу phoenix и цепочки prerouting/output */
    return 0;
}

int nftables_cleanup(void)
{
    /* TODO: удалить все правила phoenix при остановке */
    return 0;
}

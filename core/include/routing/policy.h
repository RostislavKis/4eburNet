#ifndef POLICY_H
#define POLICY_H

#include <stdint.h>

/* Таблицы маршрутизации (не пересекаться с OpenWrt: main=254, default=253) */
#define POLICY_TABLE_TPROXY     100
#define POLICY_TABLE_TUN        200
#define POLICY_TABLE_BYPASS     250

/* Приоритеты ip rule (OpenWrt: 0/32766/32767, мы в диапазоне 1000-1002) */
#define POLICY_PRIO_TPROXY      1000
#define POLICY_PRIO_TUN         1001
#define POLICY_PRIO_BYPASS      1002

/* Метки fwmark (совпадают с NFT_MARK_PROXY / NFT_MARK_TUN из nftables.h) */
#define POLICY_MARK_TPROXY      0x01
#define POLICY_MARK_TUN         0x02

/* Результат операции */
typedef enum {
    POLICY_OK           = 0,
    POLICY_ERR_EXEC     = 1,   /* ошибка запуска ip */
    POLICY_ERR_EXISTS   = 2,   /* правило уже существует */
    POLICY_ERR_NOTFOUND = 3,   /* правило не найдено */
    POLICY_ERR_CONFLICT = 4,   /* конфликт с существующим правилом */
} policy_result_t;

/* Инициализация: ip rule + ip route для TPROXY (IPv4 + IPv6) */
policy_result_t policy_init_tproxy(void);

/* Инициализация для TUN режима (dev — имя интерфейса, например "tun0") */
policy_result_t policy_init_tun(const char *dev);

/* Удалить все наши правила и маршруты */
void policy_cleanup(void);

/* Проверка конфликтов с существующими правилами */
policy_result_t policy_check_conflicts(void);

/* Вывод текущих правил в лог (отладка) */
void policy_dump(void);

/* Текстовое описание ошибки */
const char *policy_strerror(policy_result_t err);

#endif /* POLICY_H */

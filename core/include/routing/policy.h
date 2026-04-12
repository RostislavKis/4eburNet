#ifndef POLICY_H
#define POLICY_H

#include <stdint.h>
#include "constants.h"

/* Псевдонимы для обратной совместимости — единый источник в constants.h */
#define POLICY_TABLE_TPROXY     ROUTE_TABLE_PROXY
#define POLICY_TABLE_TUN        ROUTE_TABLE_TUN
#define POLICY_TABLE_BYPASS     ROUTE_TABLE_BYPASS
#define POLICY_PRIO_TPROXY      ROUTE_PRIO_PROXY
#define POLICY_PRIO_TUN         ROUTE_PRIO_TUN
#define POLICY_PRIO_BYPASS      ROUTE_PRIO_BYPASS
#define POLICY_MARK_TPROXY      FWMARK_PROXY
#define POLICY_MARK_TUN         FWMARK_TUN

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

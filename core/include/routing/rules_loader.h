#ifndef RULES_LOADER_H
#define RULES_LOADER_H

#include <stdint.h>
#include <time.h>

/* Тип списка правил */
typedef enum {
    RULES_BYPASS = 0,   /* идти напрямую */
    RULES_PROXY  = 1,   /* идти через прокси */
    RULES_BLOCK  = 2,   /* блокировать */
} rules_type_t;

/* Один источник правил (файл) */
typedef struct {
    char         path[256];
    rules_type_t type;
    time_t       mtime;          /* время изменения файла при загрузке */
    uint32_t     loaded_count;   /* загружено записей */
} rules_source_t;

/* Менеджер правил */
typedef struct {
    rules_source_t  sources[16];    /* до 16 источников */
    int             source_count;
    time_t          last_update;
} rules_manager_t;

/* Инициализация (создаёт директорию правил если нет) */
int  rules_init(rules_manager_t *rm);

/* Очистка */
void rules_cleanup(rules_manager_t *rm);

/* Добавить источник правил (файл) */
int  rules_add_source(rules_manager_t *rm,
                      const char *path, rules_type_t type);

/* Загрузить все источники в nftables verdict maps */
int  rules_load_all(rules_manager_t *rm);

/* Проверить mtime файлов и перезагрузить изменённые */
int  rules_check_update(rules_manager_t *rm);

/* Создать тестовый файл с реальными CIDR блоками */
int  rules_create_test_file(const char *path, rules_type_t type);

#endif /* RULES_LOADER_H */

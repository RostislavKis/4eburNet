#ifndef CONFIG_H
#define CONFIG_H

#include "phoenix.h"

/* Загрузка конфигурации из UCI */
int phoenix_config_load(const char *path);

/* Перечитывание конфигурации без перезапуска */
int phoenix_config_reload(void);

#endif /* CONFIG_H */

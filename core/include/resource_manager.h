#ifndef RESOURCE_MANAGER_H
#define RESOURCE_MANAGER_H

#include "phoenix.h"

/* Определяет профиль устройства по объёму оперативной памяти */
DeviceProfile rm_detect_profile(void);

/* Возвращает строковое имя профиля */
const char *rm_profile_name(DeviceProfile profile);

/* Параметры профиля */
uint32_t rm_max_connections(DeviceProfile profile);
size_t   rm_buffer_size(DeviceProfile profile);
bool     rm_quic_enabled(DeviceProfile profile);

/* Настраивает OOM score — чтобы ядро убило нас раньше системных процессов */
void rm_apply_oom_settings(void);

#endif /* RESOURCE_MANAGER_H */

#include "resource_manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DeviceProfile rm_detect_profile(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) {
        log_msg(LOG_WARN, "Не удалось прочитать /proc/meminfo, профиль MICRO");
        return DEVICE_MICRO;
    }

    char line[256];
    unsigned long mem_kb = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            /* Парсим значение в килобайтах */
            char *p = line + 9;
            while (*p == ' ' || *p == '\t')
                p++;
            mem_kb = strtoul(p, NULL, 10);
            break;
        }
    }
    fclose(f);

    unsigned long mem_mb = mem_kb / 1024;
    log_msg(LOG_INFO, "Обнаружено RAM: %lu МБ", mem_mb);

    if (mem_mb < 64)
        return DEVICE_MICRO;
    if (mem_mb <= 128)
        return DEVICE_NORMAL;
    return DEVICE_FULL;
}

const char *rm_profile_name(DeviceProfile profile)
{
    switch (profile) {
    case DEVICE_MICRO:  return "MICRO";
    case DEVICE_NORMAL: return "NORMAL";
    case DEVICE_FULL:   return "FULL";
    }
    return "UNKNOWN";
}

uint32_t rm_max_connections(DeviceProfile profile)
{
    switch (profile) {
    case DEVICE_MICRO:  return MICRO_MAX_CONNECTIONS;
    case DEVICE_NORMAL: return NORMAL_MAX_CONNECTIONS;
    case DEVICE_FULL:   return FULL_MAX_CONNECTIONS;
    }
    return MICRO_MAX_CONNECTIONS;
}

size_t rm_buffer_size(DeviceProfile profile)
{
    switch (profile) {
    case DEVICE_MICRO:  return MICRO_BUFFER_SIZE;
    case DEVICE_NORMAL: return NORMAL_BUFFER_SIZE;
    case DEVICE_FULL:   return FULL_BUFFER_SIZE;
    }
    return MICRO_BUFFER_SIZE;
}

bool rm_quic_enabled(DeviceProfile profile)
{
    switch (profile) {
    case DEVICE_MICRO:  return false;
    case DEVICE_NORMAL: return true;
    case DEVICE_FULL:   return true;
    }
    return false;
}

void rm_apply_oom_settings(void)
{
    /* Повышаем OOM score — лучше убить роутер, чем системные процессы */
    FILE *f = fopen("/proc/self/oom_score_adj", "w");
    if (!f) {
        log_msg(LOG_WARN, "Не удалось записать oom_score_adj");
        return;
    }
    fprintf(f, "500\n");
    fclose(f);
    log_msg(LOG_DEBUG, "OOM score adj установлен в 500");
}

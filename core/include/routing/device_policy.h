#ifndef DEVICE_POLICY_H
#define DEVICE_POLICY_H

#include "config.h"

/* fwmark для per-device routing (netdev → inet pipeline) */
#define FWMARK_DEVICE_PROXY   0x10
#define FWMARK_DEVICE_BYPASS  0x11
#define FWMARK_DEVICE_BLOCK   0x12

/* Менеджер устройств */
typedef struct {
    device_config_t *devices;
    int              count;
    int              capacity;
} device_manager_t;

int  device_policy_init(device_manager_t *dm,
                        const EburNetConfig *cfg);
void device_policy_free(device_manager_t *dm);

/* CRUD */
int  device_policy_add(device_manager_t *dm,
                       const device_config_t *dev);
int  device_policy_del(device_manager_t *dm,
                       const char *mac_str);
const device_config_t *device_policy_find(
                       const device_manager_t *dm,
                       const char *mac_str);

/* Применить все правила в nftables (атомарно) */
int  device_policy_apply(device_manager_t *dm,
                         const char *lan_iface);

/* Удалить netdev таблицу (при остановке) */
void device_policy_cleanup_nft(void);

/* JSON для IPC */
int  device_policy_to_json(const device_manager_t *dm,
                           char *buf, size_t buflen);

#endif /* DEVICE_POLICY_H */

/*
 * Per-device routing через netdev MAC verdict map (DEC-020)
 *
 * Pipeline: netdev ingress (ether saddr → fwmark)
 *         → inet prerouting (fwmark → TPROXY/accept/drop)
 */

#include "routing/device_policy.h"
#include "net_utils.h"
#include "phoenix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Временный файл для атомарных nft операций */
#define DEVICE_NFT_TMP  "/tmp/phoenix_dev.nft"

/* ------------------------------------------------------------------ */
/*  device_policy_init / free                                          */
/* ------------------------------------------------------------------ */

int device_policy_init(device_manager_t *dm, const PhoenixConfig *cfg)
{
    memset(dm, 0, sizeof(*dm));
    if (cfg->device_count == 0)
        return 0;

    dm->capacity = cfg->device_count + 16;
    dm->devices = malloc((size_t)dm->capacity * sizeof(device_config_t));
    if (!dm->devices) return -1;

    memcpy(dm->devices, cfg->devices,
           (size_t)cfg->device_count * sizeof(device_config_t));
    dm->count = cfg->device_count;

    log_msg(LOG_INFO, "Устройства загружены: %d", dm->count);
    return 0;
}

void device_policy_free(device_manager_t *dm)
{
    if (dm->devices) {
        free(dm->devices);
        dm->devices = NULL;
    }
    dm->count = 0;
    dm->capacity = 0;
}

/* ------------------------------------------------------------------ */
/*  CRUD                                                               */
/* ------------------------------------------------------------------ */

int device_policy_add(device_manager_t *dm, const device_config_t *dev)
{
    if (dm->count >= dm->capacity) {
        int new_cap = dm->capacity + 16;
        device_config_t *n = realloc(dm->devices,
            (size_t)new_cap * sizeof(device_config_t));
        if (!n) return -1;
        dm->devices = n;
        dm->capacity = new_cap;
    }
    dm->devices[dm->count++] = *dev;
    return 0;
}

int device_policy_del(device_manager_t *dm, const char *mac_str)
{
    for (int i = 0; i < dm->count; i++) {
        if (strcmp(dm->devices[i].mac_str, mac_str) == 0) {
            dm->devices[i] = dm->devices[dm->count - 1];
            dm->count--;
            return 0;
        }
    }
    return -1;
}

const device_config_t *device_policy_find(const device_manager_t *dm,
                                          const char *mac_str)
{
    for (int i = 0; i < dm->count; i++)
        if (strcmp(dm->devices[i].mac_str, mac_str) == 0)
            return &dm->devices[i];
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  nftables — netdev таблица с MAC verdict map                        */
/* ------------------------------------------------------------------ */

static const char *policy_chain(device_policy_t p)
{
    switch (p) {
    case DEVICE_POLICY_PROXY:  return "dev_proxy";
    case DEVICE_POLICY_BYPASS: return "dev_bypass";
    case DEVICE_POLICY_BLOCK:  return "dev_block";
    default:                   return NULL;
    }
}

static int write_device_nft(device_manager_t *dm,
                            const char *lan_iface, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;

    fprintf(f, "table netdev phoenix_dev {\n");

    fprintf(f, "    chain dev_proxy {\n");
    fprintf(f, "        meta mark set 0x%08x;\n", FWMARK_DEVICE_PROXY);
    fprintf(f, "    }\n");
    fprintf(f, "    chain dev_bypass {\n");
    fprintf(f, "        meta mark set 0x%08x;\n", FWMARK_DEVICE_BYPASS);
    fprintf(f, "    }\n");
    fprintf(f, "    chain dev_block {\n");
    fprintf(f, "        meta mark set 0x%08x;\n", FWMARK_DEVICE_BLOCK);
    fprintf(f, "        drop;\n");
    fprintf(f, "    }\n");

    fprintf(f, "    map mac_map {\n");
    fprintf(f, "        type ether_addr : verdict;\n");

    int count = 0;
    for (int i = 0; i < dm->count; i++) {
        const device_config_t *d = &dm->devices[i];
        if (!d->enabled || !d->mac_str[0]) continue;
        if (d->policy == DEVICE_POLICY_DEFAULT) continue;
        if (!policy_chain(d->policy)) continue;
        count++;
    }

    if (count > 0) {
        fprintf(f, "        elements = {");
        int first = 1;
        for (int i = 0; i < dm->count; i++) {
            const device_config_t *d = &dm->devices[i];
            if (!d->enabled || !d->mac_str[0]) continue;
            if (d->policy == DEVICE_POLICY_DEFAULT) continue;
            const char *chain = policy_chain(d->policy);
            if (!chain) continue;
            if (!first) fprintf(f, ",");
            fprintf(f, " %s : goto %s", d->mac_str, chain);
            first = 0;
        }
        fprintf(f, " };\n");
    }

    fprintf(f, "    }\n");

    fprintf(f, "    chain ingress {\n");
    fprintf(f, "        type filter hook ingress"
               " device \"%s\" priority -300;\n", lan_iface);
    if (count > 0)
        fprintf(f, "        ether saddr vmap @mac_map;\n");
    fprintf(f, "    }\n");
    fprintf(f, "}\n");

    fclose(f);
    return 0;
}

int device_policy_apply(device_manager_t *dm, const char *lan_iface)
{
    if (!lan_iface || !lan_iface[0]) {
        log_msg(LOG_WARN, "Device policy: lan_interface не задан");
        return -1;
    }

    exec_cmd("nft delete table netdev phoenix_dev 2>/dev/null");

    if (write_device_nft(dm, lan_iface, DEVICE_NFT_TMP) < 0)
        return -1;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nft -f %s 2>&1", DEVICE_NFT_TMP);
    char err[512] = {0};
    int rc = exec_cmd_capture(cmd, err, sizeof(err));
    unlink(DEVICE_NFT_TMP);

    if (rc != 0) {
        size_t elen = strlen(err);
        if (elen > 0 && err[elen-1] == '\n') err[elen-1] = '\0';
        log_msg(LOG_ERROR, "Device policy nft: %s", err);
        return -1;
    }

    int active = 0;
    for (int i = 0; i < dm->count; i++)
        if (dm->devices[i].enabled && dm->devices[i].mac_str[0] &&
            dm->devices[i].policy != DEVICE_POLICY_DEFAULT)
            active++;

    log_msg(LOG_INFO, "Device policy: %d устройств активно (%s)",
            active, lan_iface);
    return 0;
}

void device_policy_cleanup_nft(void)
{
    exec_cmd("nft delete table netdev phoenix_dev 2>/dev/null");
    log_msg(LOG_DEBUG, "Device policy: netdev таблица удалена");
}

/* ------------------------------------------------------------------ */
/*  JSON для IPC                                                       */
/* ------------------------------------------------------------------ */

int device_policy_to_json(const device_manager_t *dm,
                          char *buf, size_t buflen)
{
    int pos = 0;
    pos += snprintf(buf + pos, buflen - pos, "{\"devices\":[");

    for (int i = 0; i < dm->count; i++) {
        const device_config_t *d = &dm->devices[i];
        const char *pol = "default";
        if (d->policy == DEVICE_POLICY_PROXY) pol = "proxy";
        else if (d->policy == DEVICE_POLICY_BYPASS) pol = "bypass";
        else if (d->policy == DEVICE_POLICY_BLOCK) pol = "block";

        if (i > 0) pos += snprintf(buf + pos, buflen - pos, ",");
        pos += snprintf(buf + pos, buflen - pos,
            "{\"name\":\"%s\",\"alias\":\"%s\","
            "\"mac\":\"%s\",\"policy\":\"%s\","
            "\"server_group\":\"%s\","
            "\"enabled\":%s,\"priority\":%d,"
            "\"comment\":\"%s\"}",
            d->name, d->alias, d->mac_str, pol,
            d->server_group,
            d->enabled ? "true" : "false", d->priority,
            d->comment);
    }

    pos += snprintf(buf + pos, buflen - pos, "]}");
    return pos;
}

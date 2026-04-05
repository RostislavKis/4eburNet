/*
 * Управление политикой маршрутизации Linux (ip rule / ip route)
 *
 * Связывает fwmark из nftables с таблицами маршрутизации ядра:
 *   fwmark 0x01 → таблица 100 → TPROXY (local 0/0 dev lo)
 *   fwmark 0x02 → таблица 200 → TUN (default dev tun0)
 *
 * DEC-012: ip subprocess v1, RTNETLINK v2 позже
 */

#include "routing/policy.h"
#include "net_utils.h"
#include "phoenix.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

/* Максимальный размер команды ip */
#define POLICY_CMD_MAX  512

/* Максимальный размер вывода ошибки */
#define POLICY_ERR_BUF  512

/* ------------------------------------------------------------------ */
/*  policy_exec — выполнить команду ip, логировать результат           */
/* ------------------------------------------------------------------ */

static policy_result_t policy_exec(const char *cmd)
{
    char full_cmd[POLICY_CMD_MAX];
    int n = snprintf(full_cmd, sizeof(full_cmd), "ip %s 2>&1", cmd);
    if (n < 0 || (size_t)n >= sizeof(full_cmd)) {
        log_msg(LOG_ERROR, "ip: команда слишком длинная (%d байт)", n);
        return POLICY_ERR_EXEC;
    }

    log_msg(LOG_DEBUG, "ip: %s", cmd);

    char err_buf[POLICY_ERR_BUF] = {0};
    int status = exec_cmd_capture(full_cmd, err_buf, sizeof(err_buf));
    if (status != 0) {
        size_t len = strlen(err_buf);
        if (len > 0 && err_buf[len - 1] == '\n')
            err_buf[len - 1] = '\0';

        if (strstr(err_buf, "File exists"))
            return POLICY_ERR_EXISTS;

        log_msg(LOG_ERROR, "ip: ошибка (код %d): %s", status, err_buf);
        return POLICY_ERR_EXEC;
    }

    return POLICY_OK;
}

/* ------------------------------------------------------------------ */
/*  policy_exec_quiet — то же, но без логирования ошибок (для cleanup) */
/* ------------------------------------------------------------------ */

static void policy_exec_quiet(const char *cmd)
{
    char full_cmd[POLICY_CMD_MAX];
    snprintf(full_cmd, sizeof(full_cmd), "ip %s 2>/dev/null", cmd);
    exec_cmd(full_cmd);
}

/* ------------------------------------------------------------------ */
/*  policy_rule_exists — проверить наличие ip rule                     */
/* ------------------------------------------------------------------ */

struct rule_search { const char *mark; const char *table; bool found; };
static void rule_search_cb(const char *line, void *ctx) {
    struct rule_search *s = ctx;
    if (!s->found && strstr(line, s->mark) && strstr(line, s->table))
        s->found = true;
}

static bool policy_rule_exists(uint32_t mark, int table, bool ipv6)
{
    char cmd[POLICY_CMD_MAX];
    snprintf(cmd, sizeof(cmd), "ip %s rule show 2>/dev/null",
             ipv6 ? "-6" : "");

    char needle_mark[32], needle_table[32];
    snprintf(needle_mark, sizeof(needle_mark), "fwmark 0x%x", mark);
    snprintf(needle_table, sizeof(needle_table), "lookup %d", table);

    struct rule_search s = { needle_mark, needle_table, false };
    exec_cmd_lines(cmd, rule_search_cb, &s);
    return s.found;
}

/* ------------------------------------------------------------------ */
/*  policy_route_exists — проверить наличие маршрута в таблице         */
/* ------------------------------------------------------------------ */

static bool policy_route_exists(int table, const char *prefix, bool ipv6)
{
    char cmd[POLICY_CMD_MAX];
    snprintf(cmd, sizeof(cmd),
             "ip %s route show table %d 2>/dev/null",
             ipv6 ? "-6" : "", table);

    return exec_cmd_contains(cmd, prefix);
}

/* ------------------------------------------------------------------ */
/*  policy_strerror                                                    */
/* ------------------------------------------------------------------ */

const char *policy_strerror(policy_result_t err)
{
    switch (err) {
    case POLICY_OK:           return "успех";
    case POLICY_ERR_EXEC:     return "ошибка запуска ip";
    case POLICY_ERR_EXISTS:   return "правило уже существует";
    case POLICY_ERR_NOTFOUND: return "правило не найдено";
    case POLICY_ERR_CONFLICT: return "конфликт с существующим правилом";
    }
    return "неизвестная ошибка";
}

/* ------------------------------------------------------------------ */
/*  policy_check_conflicts                                             */
/* ------------------------------------------------------------------ */

policy_result_t policy_check_conflicts(void)
{
    bool conflict = false;

    /*
     * Проверяем что таблицы 100 и 200 не содержат чужих маршрутов.
     * Наши маршруты: "local" (TPROXY) или "default dev tun" (TUN).
     * Если есть другие — предупреждаем.
     */
    if (policy_route_exists(POLICY_TABLE_TPROXY, "default", false)) {
        log_msg(LOG_WARN,
            "Таблица %d уже содержит маршруты, возможен конфликт",
            POLICY_TABLE_TPROXY);
        conflict = true;
    }

    if (policy_route_exists(POLICY_TABLE_TUN, "default", false)) {
        log_msg(LOG_WARN,
            "Таблица %d уже содержит маршруты, возможен конфликт",
            POLICY_TABLE_TUN);
        conflict = true;
    }

    return conflict ? POLICY_ERR_CONFLICT : POLICY_OK;
}

/* ------------------------------------------------------------------ */
/*  policy_init_tproxy                                                 */
/* ------------------------------------------------------------------ */

policy_result_t policy_init_tproxy(void)
{
    policy_result_t rc;

    /* IPv4: ip rule fwmark 0x01 → table 100 */
    if (!policy_rule_exists(POLICY_MARK_TPROXY, POLICY_TABLE_TPROXY, false)) {
        rc = policy_exec("rule add fwmark 0x01 table 100 prio 1000");
        if (rc != POLICY_OK && rc != POLICY_ERR_EXISTS)
            return rc;
    }

    /* IPv4: весь помеченный трафик → loopback (для TPROXY перехвата) */
    if (!policy_route_exists(POLICY_TABLE_TPROXY, "local", false)) {
        rc = policy_exec("route add local 0.0.0.0/0 dev lo table 100");
        if (rc != POLICY_OK && rc != POLICY_ERR_EXISTS)
            return rc;
    }

    /* IPv6: ip -6 rule fwmark 0x01 → table 100 */
    if (!policy_rule_exists(POLICY_MARK_TPROXY, POLICY_TABLE_TPROXY, true)) {
        rc = policy_exec("-6 rule add fwmark 0x01 table 100 prio 1000");
        if (rc != POLICY_OK && rc != POLICY_ERR_EXISTS)
            log_msg(LOG_WARN, "IPv6 rule для TPROXY не создан: %s",
                    policy_strerror(rc));
    }

    /* IPv6: local ::/0 dev lo table 100 */
    if (!policy_route_exists(POLICY_TABLE_TPROXY, "local", true)) {
        rc = policy_exec("-6 route add local ::/0 dev lo table 100");
        if (rc != POLICY_OK && rc != POLICY_ERR_EXISTS)
            log_msg(LOG_WARN, "IPv6 route для TPROXY не создан: %s",
                    policy_strerror(rc));
    }

    log_msg(LOG_INFO, "Политика маршрутизации TPROXY настроена");
    return POLICY_OK;
}

/* ------------------------------------------------------------------ */
/*  policy_init_tun                                                    */
/* ------------------------------------------------------------------ */

policy_result_t policy_init_tun(const char *dev)
{
    if (!valid_ifname(dev)) {
        log_msg(LOG_ERROR, "policy: невалидное имя интерфейса: %s",
                dev ? dev : "(null)");
        return POLICY_ERR_EXEC;
    }

    policy_result_t rc;

    /* IPv4: ip rule fwmark 0x02 → table 200 */
    if (!policy_rule_exists(POLICY_MARK_TUN, POLICY_TABLE_TUN, false)) {
        rc = policy_exec("rule add fwmark 0x02 table 200 prio 1001");
        if (rc != POLICY_OK && rc != POLICY_ERR_EXISTS)
            return rc;
    }

    /* IPv4: default dev [dev] table 200 */
    char cmd[POLICY_CMD_MAX];
    snprintf(cmd, sizeof(cmd),
             "route add default dev %s table 200", dev);

    /* Проверяем что интерфейс существует */
    char check[POLICY_CMD_MAX];
    snprintf(check, sizeof(check), "ip link show %s 2>/dev/null", dev);
    char out[64] = {0};
    exec_cmd_capture(check, out, sizeof(out));
    bool dev_exists = (out[0] != '\0');

    if (dev_exists) {
        rc = policy_exec(cmd);
        if (rc != POLICY_OK && rc != POLICY_ERR_EXISTS)
            return rc;
    } else {
        log_msg(LOG_WARN,
            "TUN интерфейс %s не найден, маршрут отложен", dev);
    }

    /* IPv6 */
    if (!policy_rule_exists(POLICY_MARK_TUN, POLICY_TABLE_TUN, true)) {
        rc = policy_exec("-6 rule add fwmark 0x02 table 200 prio 1001");
        if (rc != POLICY_OK && rc != POLICY_ERR_EXISTS)
            log_msg(LOG_WARN, "IPv6 rule для TUN не создан: %s",
                    policy_strerror(rc));
    }

    if (dev_exists) {
        snprintf(cmd, sizeof(cmd),
                 "-6 route add default dev %s table 200", dev);
        rc = policy_exec(cmd);
        if (rc != POLICY_OK && rc != POLICY_ERR_EXISTS)
            log_msg(LOG_WARN, "IPv6 route для TUN не создан: %s",
                    policy_strerror(rc));
    }

    log_msg(LOG_INFO,
        "Политика маршрутизации TUN настроена (dev: %s)", dev);
    return POLICY_OK;
}

/* ------------------------------------------------------------------ */
/*  policy_cleanup                                                     */
/* ------------------------------------------------------------------ */

void policy_cleanup(void)
{
    /* Таблица 100 (TPROXY) — IPv6 сначала, потом IPv4 */
    policy_exec_quiet("-6 route del local ::/0 dev lo table 100");
    policy_exec_quiet("-6 rule del fwmark 0x01 table 100 prio 1000");
    policy_exec_quiet("route del local 0.0.0.0/0 dev lo table 100");
    policy_exec_quiet("rule del fwmark 0x01 table 100 prio 1000");

    /* Таблица 200 (TUN) */
    policy_exec_quiet("-6 route flush table 200");
    policy_exec_quiet("-6 rule del fwmark 0x02 table 200 prio 1001");
    policy_exec_quiet("route flush table 200");
    policy_exec_quiet("rule del fwmark 0x02 table 200 prio 1001");

    log_msg(LOG_INFO, "Политика маршрутизации очищена");
}

/* ------------------------------------------------------------------ */
/*  policy_dump                                                        */
/* ------------------------------------------------------------------ */

static void dump_rule_cb(const char *line, void *ctx) {
    (void)ctx;
    log_msg(LOG_DEBUG, "  rule: %s", line);
}
static void dump_t100_cb(const char *line, void *ctx) {
    (void)ctx;
    log_msg(LOG_DEBUG, "  table 100: %s", line);
}
static void dump_t200_cb(const char *line, void *ctx) {
    (void)ctx;
    log_msg(LOG_DEBUG, "  table 200: %s", line);
}

void policy_dump(void)
{
    log_msg(LOG_DEBUG, "=== Политика маршрутизации ===");
    exec_cmd_lines("ip rule show 2>/dev/null", dump_rule_cb, NULL);
    exec_cmd_lines("ip route show table 100 2>/dev/null", dump_t100_cb, NULL);
    exec_cmd_lines("ip route show table 200 2>/dev/null", dump_t200_cb, NULL);

    log_msg(LOG_DEBUG, "==============================");
}

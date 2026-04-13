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
#include "4eburnet.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

/* Максимальный размер команды ip */
#define POLICY_CMD_MAX  512

/* Максимальный размер вывода ошибки */
#define POLICY_ERR_BUF  512

/* Максимальное количество аргументов для exec_cmd_safe */
#define POLICY_MAX_ARGV 16

/* ------------------------------------------------------------------ */
/*  policy_build_argv — разбить строку команды на argv (без shell)    */
/* ------------------------------------------------------------------ */

/*
 * Заполняет argv: argv[0]="ip", argv[1..n]=слова из cmd.
 * buf — рабочий буфер для токенизации (min POLICY_CMD_MAX байт).
 * Возвращает количество аргументов или -1 при переполнении.
 */
static int policy_build_argv(const char *cmd, char *buf, size_t bufsz,
                              const char *argv[], int max_argv)
{
    size_t len = strlen(cmd);
    if (len >= bufsz) return -1;
    memcpy(buf, cmd, len + 1);

    int n = 0;
    argv[n++] = "ip";

    char *p = buf;
    while (*p && n < max_argv - 1) {
        while (*p == ' ') p++;
        if (!*p) break;
        argv[n++] = p;
        while (*p && *p != ' ') p++;
        if (*p) *p++ = '\0';
    }
    argv[n] = NULL;
    return n;
}

/* ------------------------------------------------------------------ */
/*  policy_exec — выполнить команду ip, логировать результат           */
/* ------------------------------------------------------------------ */

static policy_result_t policy_exec(const char *cmd)
{
    char buf[POLICY_CMD_MAX];
    const char *argv[POLICY_MAX_ARGV];

    log_msg(LOG_DEBUG, "ip: %s", cmd);

    if (policy_build_argv(cmd, buf, sizeof(buf), argv, POLICY_MAX_ARGV) < 0) {
        log_msg(LOG_ERROR, "ip: команда слишком длинная (%zu байт)", strlen(cmd));
        return POLICY_ERR_EXEC;
    }

    char err_buf[POLICY_ERR_BUF] = {0};
    int status = exec_cmd_safe(argv, err_buf, sizeof(err_buf));
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
    char buf[POLICY_CMD_MAX];
    const char *argv[POLICY_MAX_ARGV];

    if (policy_build_argv(cmd, buf, sizeof(buf), argv, POLICY_MAX_ARGV) < 0)
        return;

    exec_cmd_safe(argv, NULL, 0);
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
    {   int _n = snprintf(cmd, sizeof(cmd), "ip %s rule show 2>/dev/null",
                          ipv6 ? "-6" : "");
        if (_n < 0 || (size_t)_n >= sizeof(cmd))
            log_msg(LOG_DEBUG, "policy: обрезано (диагностика): %d", __LINE__);
    }

    char needle_mark[32], needle_table[32];
    {   int _n = snprintf(needle_mark, sizeof(needle_mark), "fwmark 0x%x", mark);
        if (_n < 0 || (size_t)_n >= sizeof(needle_mark))
            log_msg(LOG_DEBUG, "policy: обрезано (диагностика): %d", __LINE__);
    }
    {   int _n = snprintf(needle_table, sizeof(needle_table), "lookup %d", table);
        if (_n < 0 || (size_t)_n >= sizeof(needle_table))
            log_msg(LOG_DEBUG, "policy: обрезано (диагностика): %d", __LINE__);
    }

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
    {   int _n = snprintf(cmd, sizeof(cmd),
                          "ip %s route show table %d 2>/dev/null",
                          ipv6 ? "-6" : "", table);
        if (_n < 0 || (size_t)_n >= sizeof(cmd))
            log_msg(LOG_DEBUG, "policy: обрезано (диагностика): %d", __LINE__);
    }

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

    char cmd[128];

    /* IPv4: ip rule fwmark → table */
    if (!policy_rule_exists(POLICY_MARK_TPROXY, POLICY_TABLE_TPROXY, false)) {
        {   int _n = snprintf(cmd, sizeof(cmd), "rule add fwmark 0x%02x table %d prio %d",
                              POLICY_MARK_TPROXY, POLICY_TABLE_TPROXY, POLICY_PRIO_TPROXY);
            if (_n < 0 || (size_t)_n >= sizeof(cmd)) {
                log_msg(LOG_ERROR, "policy: команда обрезана");
                return POLICY_ERR_EXEC;
            }
        }
        rc = policy_exec(cmd);
        if (rc != POLICY_OK && rc != POLICY_ERR_EXISTS)
            return rc;
    }

    /* IPv4: весь помеченный трафик → loopback (для TPROXY перехвата) */
    if (!policy_route_exists(POLICY_TABLE_TPROXY, "local", false)) {
        {   int _n = snprintf(cmd, sizeof(cmd), "route add local 0.0.0.0/0 dev lo table %d",
                              POLICY_TABLE_TPROXY);
            if (_n < 0 || (size_t)_n >= sizeof(cmd)) {
                log_msg(LOG_ERROR, "policy: команда обрезана");
                return POLICY_ERR_EXEC;
            }
        }
        rc = policy_exec(cmd);
        if (rc != POLICY_OK && rc != POLICY_ERR_EXISTS)
            return rc;
    }

    /* IPv6: ip -6 rule fwmark → table */
    if (!policy_rule_exists(POLICY_MARK_TPROXY, POLICY_TABLE_TPROXY, true)) {
        {   int _n = snprintf(cmd, sizeof(cmd), "-6 rule add fwmark 0x%02x table %d prio %d",
                              POLICY_MARK_TPROXY, POLICY_TABLE_TPROXY, POLICY_PRIO_TPROXY);
            if (_n < 0 || (size_t)_n >= sizeof(cmd)) {
                log_msg(LOG_ERROR, "policy: команда обрезана");
                return POLICY_ERR_EXEC;
            }
        }
        rc = policy_exec(cmd);
        if (rc != POLICY_OK && rc != POLICY_ERR_EXISTS)
            log_msg(LOG_WARN, "IPv6 rule для TPROXY не создан: %s",
                    policy_strerror(rc));
    }

    /* IPv6: local ::/0 dev lo table */
    if (!policy_route_exists(POLICY_TABLE_TPROXY, "local", true)) {
        {   int _n = snprintf(cmd, sizeof(cmd), "-6 route add local ::/0 dev lo table %d",
                              POLICY_TABLE_TPROXY);
            if (_n < 0 || (size_t)_n >= sizeof(cmd)) {
                log_msg(LOG_ERROR, "policy: команда обрезана");
                return POLICY_ERR_EXEC;
            }
        }
        rc = policy_exec(cmd);
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

    /* IPv4: ip rule fwmark → table */
    if (!policy_rule_exists(POLICY_MARK_TUN, POLICY_TABLE_TUN, false)) {
        char rcmd[128];
        {   int _n = snprintf(rcmd, sizeof(rcmd), "rule add fwmark 0x%02x table %d prio %d",
                              POLICY_MARK_TUN, POLICY_TABLE_TUN, POLICY_PRIO_TUN);
            if (_n < 0 || (size_t)_n >= sizeof(rcmd)) {
                log_msg(LOG_ERROR, "policy: команда обрезана");
                return POLICY_ERR_EXEC;
            }
        }
        rc = policy_exec(rcmd);
        if (rc != POLICY_OK && rc != POLICY_ERR_EXISTS)
            return rc;
    }

    /* IPv4: default dev [dev] table */
    char cmd[POLICY_CMD_MAX];
    {   int _n = snprintf(cmd, sizeof(cmd),
                          "route add default dev %s table %d", dev, POLICY_TABLE_TUN);
        if (_n < 0 || (size_t)_n >= sizeof(cmd)) {
            log_msg(LOG_ERROR, "policy: команда обрезана");
            return POLICY_ERR_EXEC;
        }
    }

    /* Проверяем что интерфейс существует */
    char check[POLICY_CMD_MAX];
    {   int _n = snprintf(check, sizeof(check), "ip link show %s 2>/dev/null", dev);
        if (_n < 0 || (size_t)_n >= sizeof(check)) {
            log_msg(LOG_ERROR, "policy: команда обрезана");
            return POLICY_ERR_EXEC;
        }
    }
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
        char rcmd[128];
        {   int _n = snprintf(rcmd, sizeof(rcmd), "-6 rule add fwmark 0x%02x table %d prio %d",
                              POLICY_MARK_TUN, POLICY_TABLE_TUN, POLICY_PRIO_TUN);
            if (_n < 0 || (size_t)_n >= sizeof(rcmd)) {
                log_msg(LOG_ERROR, "policy: команда обрезана");
                return POLICY_ERR_EXEC;
            }
        }
        rc = policy_exec(rcmd);
        if (rc != POLICY_OK && rc != POLICY_ERR_EXISTS)
            log_msg(LOG_WARN, "IPv6 rule для TUN не создан: %s",
                    policy_strerror(rc));
    }

    if (dev_exists) {
        {   int _n = snprintf(cmd, sizeof(cmd),
                              "-6 route add default dev %s table %d", dev, POLICY_TABLE_TUN);
            if (_n < 0 || (size_t)_n >= sizeof(cmd)) {
                log_msg(LOG_ERROR, "policy: команда обрезана");
                return POLICY_ERR_EXEC;
            }
        }
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
    char cmd[128];

    /* Таблица TPROXY — IPv6 сначала, потом IPv4 */
    {   int _n = snprintf(cmd, sizeof(cmd), "-6 route del local ::/0 dev lo table %d", POLICY_TABLE_TPROXY);
        if (_n < 0 || (size_t)_n >= sizeof(cmd))
            log_msg(LOG_ERROR, "policy: cleanup команда обрезана");
        else
            policy_exec_quiet(cmd);
    }
    {   int _n = snprintf(cmd, sizeof(cmd), "-6 rule del fwmark 0x%02x table %d prio %d",
                          POLICY_MARK_TPROXY, POLICY_TABLE_TPROXY, POLICY_PRIO_TPROXY);
        if (_n < 0 || (size_t)_n >= sizeof(cmd))
            log_msg(LOG_ERROR, "policy: cleanup команда обрезана");
        else
            policy_exec_quiet(cmd);
    }
    {   int _n = snprintf(cmd, sizeof(cmd), "route del local 0.0.0.0/0 dev lo table %d", POLICY_TABLE_TPROXY);
        if (_n < 0 || (size_t)_n >= sizeof(cmd))
            log_msg(LOG_ERROR, "policy: cleanup команда обрезана");
        else
            policy_exec_quiet(cmd);
    }
    {   int _n = snprintf(cmd, sizeof(cmd), "rule del fwmark 0x%02x table %d prio %d",
                          POLICY_MARK_TPROXY, POLICY_TABLE_TPROXY, POLICY_PRIO_TPROXY);
        if (_n < 0 || (size_t)_n >= sizeof(cmd))
            log_msg(LOG_ERROR, "policy: cleanup команда обрезана");
        else
            policy_exec_quiet(cmd);
    }

    /* Таблица TUN */
    {   int _n = snprintf(cmd, sizeof(cmd), "-6 route flush table %d", POLICY_TABLE_TUN);
        if (_n < 0 || (size_t)_n >= sizeof(cmd))
            log_msg(LOG_ERROR, "policy: cleanup команда обрезана");
        else
            policy_exec_quiet(cmd);
    }
    {   int _n = snprintf(cmd, sizeof(cmd), "-6 rule del fwmark 0x%02x table %d prio %d",
                          POLICY_MARK_TUN, POLICY_TABLE_TUN, POLICY_PRIO_TUN);
        if (_n < 0 || (size_t)_n >= sizeof(cmd))
            log_msg(LOG_ERROR, "policy: cleanup команда обрезана");
        else
            policy_exec_quiet(cmd);
    }
    {   int _n = snprintf(cmd, sizeof(cmd), "route flush table %d", POLICY_TABLE_TUN);
        if (_n < 0 || (size_t)_n >= sizeof(cmd))
            log_msg(LOG_ERROR, "policy: cleanup команда обрезана");
        else
            policy_exec_quiet(cmd);
    }
    {   int _n = snprintf(cmd, sizeof(cmd), "rule del fwmark 0x%02x table %d prio %d",
                          POLICY_MARK_TUN, POLICY_TABLE_TUN, POLICY_PRIO_TUN);
        if (_n < 0 || (size_t)_n >= sizeof(cmd))
            log_msg(LOG_ERROR, "policy: cleanup команда обрезана");
        else
            policy_exec_quiet(cmd);
    }

    log_msg(LOG_INFO, "Политика маршрутизации очищена");
}

/* ------------------------------------------------------------------ */
/*  policy_dump                                                        */
/* ------------------------------------------------------------------ */

static void dump_rule_cb(const char *line, void *ctx) {
    (void)ctx;
    log_msg(LOG_DEBUG, "  rule: %s", line);
}
static void dump_tproxy_cb(const char *line, void *ctx) {
    (void)ctx;
    log_msg(LOG_DEBUG, "  table %d: %s", POLICY_TABLE_TPROXY, line);
}
static void dump_tun_cb(const char *line, void *ctx) {
    (void)ctx;
    log_msg(LOG_DEBUG, "  table %d: %s", POLICY_TABLE_TUN, line);
}

void policy_dump(void)
{
    log_msg(LOG_DEBUG, "=== Политика маршрутизации ===");
    exec_cmd_lines("ip rule show 2>/dev/null", dump_rule_cb, NULL);

    char cmd_tproxy[64], cmd_tun[64];
    int _n1 = snprintf(cmd_tproxy, sizeof(cmd_tproxy),
             "ip route show table %d 2>/dev/null", POLICY_TABLE_TPROXY);
    int _n2 = snprintf(cmd_tun, sizeof(cmd_tun),
             "ip route show table %d 2>/dev/null", POLICY_TABLE_TUN);
    if (_n1 < 0 || (size_t)_n1 >= sizeof(cmd_tproxy) ||
        _n2 < 0 || (size_t)_n2 >= sizeof(cmd_tun))
        log_msg(LOG_DEBUG, "policy_dump: cmd обрезан");
    exec_cmd_lines(cmd_tproxy, dump_tproxy_cb, NULL);
    exec_cmd_lines(cmd_tun, dump_tun_cb, NULL);

    log_msg(LOG_DEBUG, "==============================");
}

/*
 * Управление правилами nftables через subprocess (nft)
 *
 * Создаёт таблицу inet phoenix с цепочками и наборами
 * для перенаправления трафика через прокси.
 *
 * DEC-010: subprocess через nft (v1), netlink (v2 позже)
 * DEC-011: nft -f - для атомарных операций, nft_exec для одиночных
 */

#include "routing/nftables.h"
#include "phoenix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

/* Максимальный размер команды nft */
#define NFT_CMD_MAX     4096

/* Максимальный размер атомарного конфига для nft -f - */
#define NFT_ATOMIC_MAX  8192

/* Максимальный размер вывода ошибки от nft */
#define NFT_ERR_BUF     512

/* Временный файл для атомарных операций (tmpfs, не Flash) */
#define NFT_TMP_CONF    "/tmp/phoenix_nft.conf"

/* ------------------------------------------------------------------ */
/*  nft_exec — выполнить одиночную команду nft                        */
/* ------------------------------------------------------------------ */

nft_result_t nft_exec(const char *cmd)
{
    char full_cmd[NFT_CMD_MAX];
    int n = snprintf(full_cmd, sizeof(full_cmd), "nft %s 2>&1", cmd);
    if (n < 0 || (size_t)n >= sizeof(full_cmd)) {
        log_msg(LOG_ERROR, "nft: команда слишком длинная (%d байт)", n);
        return NFT_ERR_EXEC;
    }

    log_msg(LOG_DEBUG, "nft: %s", cmd);

    FILE *fp = popen(full_cmd, "r");
    if (!fp) {
        log_msg(LOG_ERROR, "nft: не удалось запустить: %s", strerror(errno));
        return NFT_ERR_EXEC;
    }

    /* Читаем вывод (stderr перенаправлен в stdout) */
    char err_buf[NFT_ERR_BUF] = {0};
    size_t total = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (total + len < sizeof(err_buf) - 1) {
            memcpy(err_buf + total, line, len);
            total += len;
        }
    }
    err_buf[total] = '\0';

    int status = pclose(fp);
    if (status != 0) {
        /* Убираем завершающий перенос строки из вывода */
        if (total > 0 && err_buf[total - 1] == '\n')
            err_buf[total - 1] = '\0';
        log_msg(LOG_ERROR, "nft: ошибка (код %d): %s", status, err_buf);
        return NFT_ERR_RULE;
    }

    return NFT_OK;
}

/* ------------------------------------------------------------------ */
/*  nft_exec_atomic — выполнить конфиг атомарно через nft -f -        */
/* ------------------------------------------------------------------ */

static nft_result_t nft_exec_atomic(const char *config)
{
    log_msg(LOG_DEBUG, "nft: атомарное применение (%zu байт)", strlen(config));

    /* Записываем конфиг во временный файл (tmpfs — не Flash) */
    FILE *f = fopen(NFT_TMP_CONF, "w");
    if (!f) {
        log_msg(LOG_ERROR, "nft: не удалось создать %s: %s",
                NFT_TMP_CONF, strerror(errno));
        return NFT_ERR_EXEC;
    }
    fputs(config, f);
    fclose(f);

    /* Запускаем nft -f с файлом — stderr доступен через popen "r" */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nft -f %s 2>&1", NFT_TMP_CONF);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        log_msg(LOG_ERROR, "nft: не удалось запустить: %s", strerror(errno));
        unlink(NFT_TMP_CONF);
        return NFT_ERR_EXEC;
    }

    /* Читаем вывод ошибок */
    char err_buf[NFT_ERR_BUF] = {0};
    size_t total = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (total + len < sizeof(err_buf) - 1) {
            memcpy(err_buf + total, line, len);
            total += len;
        }
    }
    err_buf[total] = '\0';

    int status = pclose(fp);
    unlink(NFT_TMP_CONF);  /* всегда удаляем */

    if (status != 0) {
        if (total > 0 && err_buf[total - 1] == '\n')
            err_buf[total - 1] = '\0';
        log_msg(LOG_ERROR, "nft: атомарное применение провалилось (код %d): %s",
                status, err_buf);
        return NFT_ERR_RULE;
    }

    return NFT_OK;
}

/* ------------------------------------------------------------------ */
/*  nft_strerror                                                       */
/* ------------------------------------------------------------------ */

const char *nft_strerror(nft_result_t err)
{
    switch (err) {
    case NFT_OK:           return "успех";
    case NFT_ERR_EXEC:     return "ошибка запуска nft";
    case NFT_ERR_RULE:     return "ошибка применения правила";
    case NFT_ERR_EXISTS:   return "уже существует";
    case NFT_ERR_NOTFOUND: return "не найдено";
    }
    return "неизвестная ошибка";
}

/* ------------------------------------------------------------------ */
/*  nft_table_exists                                                   */
/* ------------------------------------------------------------------ */

bool nft_table_exists(void)
{
    FILE *fp = popen("nft list tables 2>/dev/null", "r");
    if (!fp)
        return false;

    /* Точное совпадение: "table inet phoenix\n", не "phoenix_backup" */
    char expected[64];
    snprintf(expected, sizeof(expected), "table inet %s", NFT_TABLE_NAME);

    bool found = false;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, expected)) {
            found = true;
            break;
        }
    }

    pclose(fp);
    return found;
}

/* ------------------------------------------------------------------ */
/*  nft_init — создание таблицы inet phoenix атомарно                  */
/* ------------------------------------------------------------------ */

nft_result_t nft_init(void)
{
    if (nft_table_exists()) {
        log_msg(LOG_INFO, "Таблица nftables уже существует");
        return NFT_OK;
    }

    /*
     * Атомарная инициализация: вся таблица создаётся одной транзакцией.
     * Если хоть одно правило неверно — ничего не применится.
     *
     * Структура:
     *   6 наборов (bypass/proxy/block x IPv4/IPv6)
     *   3 цепочки (prerouting, forward, output)
     *   Статические правила: block → локальные → bypass → accept
     *   Динамические правила (proxy/tproxy) добавляются через mode_set_*
     */
    char config[NFT_ATOMIC_MAX];
    int n = snprintf(config, sizeof(config),
        "table inet " NFT_TABLE_NAME " {\n"
        "\n"
        "    set " NFT_SET_BYPASS " {\n"
        "        type ipv4_addr\n"
        "        flags interval\n"
        "        auto-merge\n"
        "    }\n"
        "\n"
        "    set " NFT_SET_BYPASS6 " {\n"
        "        type ipv6_addr\n"
        "        flags interval\n"
        "        auto-merge\n"
        "    }\n"
        "\n"
        "    set " NFT_SET_PROXY " {\n"
        "        type ipv4_addr\n"
        "        flags interval\n"
        "        auto-merge\n"
        "    }\n"
        "\n"
        "    set " NFT_SET_PROXY6 " {\n"
        "        type ipv6_addr\n"
        "        flags interval\n"
        "        auto-merge\n"
        "    }\n"
        "\n"
        "    set " NFT_SET_BLOCK " {\n"
        "        type ipv4_addr\n"
        "        flags interval\n"
        "        auto-merge\n"
        "    }\n"
        "\n"
        "    set " NFT_SET_BLOCK6 " {\n"
        "        type ipv6_addr\n"
        "        flags interval\n"
        "        auto-merge\n"
        "    }\n"
        "\n"
        "    chain " NFT_CHAIN_PRE " {\n"
        "        type filter hook prerouting priority %d; policy accept;\n"
        "\n"
        "        ip daddr @" NFT_SET_BLOCK " drop\n"
        "        ip6 daddr @" NFT_SET_BLOCK6 " drop\n"
        "\n"
        "        ip daddr { 127.0.0.0/8, 10.0.0.0/8, "
                    "172.16.0.0/12, 192.168.0.0/16, "
                    "169.254.0.0/16, 224.0.0.0/4 } accept\n"
        "        ip6 daddr { ::1, fe80::/10, fc00::/7 } accept\n"
        "\n"
        "        ip daddr @" NFT_SET_BYPASS " accept\n"
        "        ip6 daddr @" NFT_SET_BYPASS6 " accept\n"
        "    }\n"
        "\n"
        "    chain " NFT_CHAIN_FWD " {\n"
        "        type filter hook forward priority %d; policy accept;\n"
        "\n"
        "        ip daddr @" NFT_SET_BLOCK " drop\n"
        "        ip6 daddr @" NFT_SET_BLOCK6 " drop\n"
        "\n"
        "        ip daddr @" NFT_SET_BYPASS " accept\n"
        "        ip6 daddr @" NFT_SET_BYPASS6 " accept\n"
        "    }\n"
        "\n"
        "    chain " NFT_CHAIN_OUT " {\n"
        "        type route hook output priority %d; policy accept;\n"
        "    }\n"
        "}\n",
        NFT_PRIO_PREROUTING,
        NFT_PRIO_FORWARD,
        NFT_PRIO_OUTPUT);

    if (n < 0 || (size_t)n >= sizeof(config)) {
        log_msg(LOG_ERROR, "nft: конфиг таблицы не поместился в буфер");
        return NFT_ERR_EXEC;
    }

    nft_result_t rc = nft_exec_atomic(config);
    if (rc == NFT_OK)
        log_msg(LOG_INFO, "Таблица nftables создана");
    else
        log_msg(LOG_ERROR, "Не удалось создать таблицу nftables: %s",
                nft_strerror(rc));

    return rc;
}

/* ------------------------------------------------------------------ */
/*  nft_cleanup                                                        */
/* ------------------------------------------------------------------ */

void nft_cleanup(void)
{
    if (!nft_table_exists()) {
        log_msg(LOG_DEBUG, "nft: таблица уже удалена, пропускаем cleanup");
        return;
    }

    nft_result_t rc = nft_exec("delete table inet " NFT_TABLE_NAME);
    if (rc == NFT_OK)
        log_msg(LOG_INFO, "Таблица nftables удалена");
    else
        log_msg(LOG_WARN, "Не удалось удалить таблицу nftables: %s",
                nft_strerror(rc));
}

/* ------------------------------------------------------------------ */
/*  Управление наборами IP-адресов                                     */
/* ------------------------------------------------------------------ */

nft_result_t nft_set_add_addr(const char *set_name, const char *cidr)
{
    char cmd[NFT_CMD_MAX];
    snprintf(cmd, sizeof(cmd),
             "add element inet " NFT_TABLE_NAME " %s { %s }",
             set_name, cidr);
    return nft_exec(cmd);
}

nft_result_t nft_set_del_addr(const char *set_name, const char *cidr)
{
    char cmd[NFT_CMD_MAX];
    snprintf(cmd, sizeof(cmd),
             "delete element inet " NFT_TABLE_NAME " %s { %s }",
             set_name, cidr);
    return nft_exec(cmd);
}

nft_result_t nft_set_flush(const char *set_name)
{
    char cmd[NFT_CMD_MAX];
    snprintf(cmd, sizeof(cmd),
             "flush set inet " NFT_TABLE_NAME " %s", set_name);
    return nft_exec(cmd);
}

/* Прототип — определение ниже, в секции режимов */
static nft_result_t apply_mode(const char *pre_suffix,
                               const char *fwd_suffix);

/* ------------------------------------------------------------------ */
/*  TPROXY                                                             */
/* ------------------------------------------------------------------ */

nft_result_t nft_tproxy_enable(uint16_t port, nft_proto_t proto)
{
    /*
     * Включает TPROXY с указанным портом и протоколом.
     * Обновляет ОБЕ цепочки (prerouting + forward) через apply_mode():
     *   prerouting — tproxy + mark (перехват трафика)
     *   forward    — mark (маркировка транзитного трафика)
     */
    const char *proto_match;
    switch (proto) {
    case NFT_PROTO_TCP: proto_match = "tcp dport 1-65535"; break;
    case NFT_PROTO_UDP: proto_match = "udp dport 1-65535"; break;
    case NFT_PROTO_ALL: /* fallthrough */
    default:            proto_match = "meta l4proto { tcp, udp }"; break;
    }

    char pre_rules[1024];
    snprintf(pre_rules, sizeof(pre_rules),
        "\n"
        "        ip daddr @" NFT_SET_PROXY " %s"
            " tproxy ip to 127.0.0.1:%u"
            " meta mark set 0x%02x accept\n"
        "        ip6 daddr @" NFT_SET_PROXY6 " %s"
            " tproxy ip6 to [::1]:%u"
            " meta mark set 0x%02x accept\n",
        proto_match, port, NFT_MARK_PROXY,
        proto_match, port, NFT_MARK_PROXY);

    char fwd_rules[1024];
    snprintf(fwd_rules, sizeof(fwd_rules),
        "\n"
        "        ip daddr @" NFT_SET_PROXY " %s"
            " meta mark set 0x%02x accept\n"
        "        ip6 daddr @" NFT_SET_PROXY6 " %s"
            " meta mark set 0x%02x accept\n",
        proto_match, NFT_MARK_PROXY,
        proto_match, NFT_MARK_PROXY);

    nft_result_t rc = apply_mode(pre_rules, fwd_rules);
    if (rc == NFT_OK)
        log_msg(LOG_INFO, "TPROXY включён (порт %u)", port);
    return rc;
}

nft_result_t nft_tproxy_disable(void)
{
    /*
     * Выключает TPROXY — возвращает обе цепочки
     * в состояние после nft_init() (только block + bypass)
     */
    nft_result_t rc = apply_mode(NULL, NULL);
    if (rc == NFT_OK)
        log_msg(LOG_INFO, "TPROXY выключен");
    return rc;
}

/* ------------------------------------------------------------------ */
/*  Режимы маршрутизации                                               */
/* ------------------------------------------------------------------ */

/*
 * Вспомогательная: пересоздание базовых правил prerouting + forward
 * с опциональным суффиксом (динамические правила режима).
 *
 * pre_suffix  — правила в конец prerouting (после bypass)
 * fwd_suffix  — правила в конец forward (после bypass)
 */
static nft_result_t apply_mode(const char *pre_suffix,
                               const char *fwd_suffix)
{
    char config[NFT_ATOMIC_MAX];
    int n = snprintf(config, sizeof(config),
        "flush chain inet " NFT_TABLE_NAME " " NFT_CHAIN_PRE "\n"
        "flush chain inet " NFT_TABLE_NAME " " NFT_CHAIN_FWD "\n"
        "\n"
        "table inet " NFT_TABLE_NAME " {\n"
        "    chain " NFT_CHAIN_PRE " {\n"
        "        ip daddr @" NFT_SET_BLOCK " drop\n"
        "        ip6 daddr @" NFT_SET_BLOCK6 " drop\n"
        "\n"
        "        ip daddr { 127.0.0.0/8, 10.0.0.0/8, "
                    "172.16.0.0/12, 192.168.0.0/16, "
                    "169.254.0.0/16, 224.0.0.0/4 } accept\n"
        "        ip6 daddr { ::1, fe80::/10, fc00::/7 } accept\n"
        "\n"
        "        ip daddr @" NFT_SET_BYPASS " accept\n"
        "        ip6 daddr @" NFT_SET_BYPASS6 " accept\n"
        "%s"
        "    }\n"
        "\n"
        "    chain " NFT_CHAIN_FWD " {\n"
        "        ip daddr @" NFT_SET_BLOCK " drop\n"
        "        ip6 daddr @" NFT_SET_BLOCK6 " drop\n"
        "\n"
        "        ip daddr @" NFT_SET_BYPASS " accept\n"
        "        ip6 daddr @" NFT_SET_BYPASS6 " accept\n"
        "%s"
        "    }\n"
        "}\n",
        pre_suffix  ? pre_suffix  : "",
        fwd_suffix  ? fwd_suffix  : "");

    if (n < 0 || (size_t)n >= sizeof(config)) {
        log_msg(LOG_ERROR, "nft: конфиг режима не поместился в буфер");
        return NFT_ERR_EXEC;
    }

    return nft_exec_atomic(config);
}

nft_result_t nft_mode_set_rules(void)
{
    /*
     * Режим "по правилам":
     * - block_addrs → drop
     * - локальные   → accept
     * - bypass      → accept
     * - proxy       → mark + tproxy
     * - остальное   → accept (напрямую)
     *
     * Порядок правил в prerouting:
     *   block → local → bypass → proxy+tproxy → accept
     */
    char pre_rules[1024];
    snprintf(pre_rules, sizeof(pre_rules),
        "\n"
        "        ip daddr @" NFT_SET_PROXY
            " meta l4proto { tcp, udp }"
            " tproxy ip to 127.0.0.1:%u"
            " meta mark set 0x%02x accept\n"
        "        ip6 daddr @" NFT_SET_PROXY6
            " meta l4proto { tcp, udp }"
            " tproxy ip6 to [::1]:%u"
            " meta mark set 0x%02x accept\n",
        NFT_TPROXY_PORT, NFT_MARK_PROXY,
        NFT_TPROXY_PORT, NFT_MARK_PROXY);

    char fwd_rules[1024];
    snprintf(fwd_rules, sizeof(fwd_rules),
        "\n"
        "        ip daddr @" NFT_SET_PROXY
            " meta l4proto { tcp, udp }"
            " meta mark set 0x%02x accept\n"
        "        ip6 daddr @" NFT_SET_PROXY6
            " meta l4proto { tcp, udp }"
            " meta mark set 0x%02x accept\n",
        NFT_MARK_PROXY, NFT_MARK_PROXY);

    nft_result_t rc = apply_mode(pre_rules, fwd_rules);
    if (rc == NFT_OK)
        log_msg(LOG_INFO, "Режим маршрутизации: rules");
    return rc;
}

nft_result_t nft_mode_set_global(void)
{
    /*
     * Режим "глобальный":
     * - block_addrs  → drop
     * - локальные    → accept
     * - bypass       → accept
     * - ВСЁ остальное → mark + tproxy
     *
     * Порядок правил в prerouting:
     *   block → local → bypass → tproxy (всё)
     */
    char pre_rules[1024];
    snprintf(pre_rules, sizeof(pre_rules),
        "\n"
        "        meta l4proto { tcp, udp }"
            " tproxy ip to 127.0.0.1:%u"
            " meta mark set 0x%02x accept\n"
        "        meta l4proto { tcp, udp }"
            " tproxy ip6 to [::1]:%u"
            " meta mark set 0x%02x accept\n",
        NFT_TPROXY_PORT, NFT_MARK_PROXY,
        NFT_TPROXY_PORT, NFT_MARK_PROXY);

    char fwd_rules[1024];
    snprintf(fwd_rules, sizeof(fwd_rules),
        "\n"
        "        meta l4proto { tcp, udp }"
            " meta mark set 0x%02x accept\n",
        NFT_MARK_PROXY);

    nft_result_t rc = apply_mode(pre_rules, fwd_rules);
    if (rc == NFT_OK)
        log_msg(LOG_INFO, "Режим маршрутизации: global");
    return rc;
}

nft_result_t nft_mode_set_direct(void)
{
    /*
     * Режим "напрямую":
     * Цепочки содержат только block + bypass, без tproxy.
     * Весь незаблокированный трафик идёт напрямую (policy accept).
     */
    nft_result_t rc = apply_mode(NULL, NULL);
    if (rc == NFT_OK)
        log_msg(LOG_INFO, "Режим маршрутизации: direct");
    return rc;
}

nft_result_t nft_mode_set_tun(void)
{
    /*
     * Режим TUN (заготовка для шага 1.3):
     * Вместо tproxy ставим только fwmark.
     * Трафик перехватывается через ip rule:
     *   ip rule add fwmark 0x02 table 100
     *   ip route add default dev tun0 table 100
     *
     * Порядок правил:
     *   block → local → bypass → mark (всё остальное)
     */
    char pre_rules[512];
    snprintf(pre_rules, sizeof(pre_rules),
        "\n"
        "        meta l4proto { tcp, udp }"
            " meta mark set 0x%02x accept\n",
        NFT_MARK_TUN);

    char fwd_rules[512];
    snprintf(fwd_rules, sizeof(fwd_rules),
        "\n"
        "        meta l4proto { tcp, udp }"
            " meta mark set 0x%02x accept\n",
        NFT_MARK_TUN);

    nft_result_t rc = apply_mode(pre_rules, fwd_rules);
    if (rc == NFT_OK)
        log_msg(LOG_INFO, "Режим маршрутизации: tun");
    return rc;
}

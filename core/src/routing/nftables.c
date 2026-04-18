/*
 * Управление правилами nftables через subprocess (nft)
 *
 * Создаёт таблицу inet 4eburnet с цепочками и наборами
 * для перенаправления трафика через прокси.
 *
 * DEC-010: subprocess через nft (v1), netlink (v2 позже)
 * DEC-011: nft -f - для атомарных операций, nft_exec для одиночных
 */

#include "routing/nftables.h"
#include "net_utils.h"
#include "4eburnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

/* Максимальный размер команды nft */
#define NFT_CMD_MAX     4096

/* Максимальный размер атомарного конфига для nft -f - */
/* Batch загрузка (vmap/set) использует nft_exec_file() без этого лимита (M-08) */
#define NFT_ATOMIC_MAX  16384

/* Максимальный размер вывода ошибки от nft */
#define NFT_ERR_BUF     512

/* Временный файл для атомарных операций (tmpfs, не Flash) */
#define NFT_TMP_CONF    "/tmp/4eburnet_nft.conf"

/* ------------------------------------------------------------------ */
/*  nft_exec — выполнить одиночную команду nft                        */
/* ------------------------------------------------------------------ */

/* Валидация CIDR строки — только безопасные символы (S-02, L-26) */
static bool validate_cidr(const char *cidr)
{
    if (!cidr || !cidr[0])
        return false;

    size_t len = strlen(cidr);
    /* IPv6 + /128 = максимум 43 символа */
    if (len > 43)
        return false;

    int slash_count = 0;
    bool after_slash = false;
    for (const char *p = cidr; *p; p++) {
        char c = *p;
        /* Пробелы запрещены */
        if (c == ' ' || c == '\t')
            return false;
        if (c == '/') {
            slash_count++;
            if (slash_count > 1)
                return false;
            after_slash = true;
            continue;
        }
        /* После '/' — только цифры (длина маски) */
        if (after_slash) {
            if (!(c >= '0' && c <= '9'))
                return false;
            continue;
        }
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F') ||
              c == '.' || c == ':'))
            return false;
    }
    if (!strpbrk(cidr, "0123456789"))
        return false;

    /* M-12/M-13: проверка prefix length */
    const char *slash = strchr(cidr, '/');
    if (slash) {
        if (*(slash + 1) == '\0') return false;  /* trailing slash */
        int prefix = atoi(slash + 1);
        bool is_ipv6 = (strchr(cidr, ':') != NULL);
        if (is_ipv6) {
            if (prefix < 0 || prefix > 128) return false;
        } else {
            if (prefix < 0 || prefix > 32) return false;
        }
    }

    return true;
}

/* Валидация nft команды — запрет shell-метасимволов (S-01, H-27) */
static bool validate_nft_cmd(const char *cmd)
{
    /* {} необходимы для nft синтаксиса (set elements).
     * Защита от injection через {} — на уровне validate_cidr() и valid_nft_name(). */
    const char *forbidden = "|&;`$()<>'\"#\n\r\\";
    for (const char *p = forbidden; *p; p++)
        if (strchr(cmd, *p))
            return false;
    return true;
}

/* Валидация имён set/map для nft (C-13) */
static bool valid_nft_name(const char *s)
{
    if (!s || !s[0]) return false;
    if (!isalpha((unsigned char)s[0]) && s[0] != '_') return false;
    for (const char *p = s + 1; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '_') return false;
    return true;
}


nft_result_t nft_exec(const char *cmd)
{
    if (!validate_nft_cmd(cmd)) {
        log_msg(LOG_ERROR, "nft: опасные символы в команде");
        return NFT_ERR_EXEC;
    }

    /* Копия для strtok (разрушает строку) */
    char cmd_copy[NFT_CMD_MAX];
    int n = snprintf(cmd_copy, sizeof(cmd_copy), "%s", cmd);
    if (n < 0 || (size_t)n >= sizeof(cmd_copy)) {
        log_msg(LOG_ERROR, "nft: команда слишком длинная (%d байт)", n);
        return NFT_ERR_EXEC;
    }

    /* Разбить на argv токены (нет shell — N1) */
#define NFT_MAX_ARGV 34
    const char *argv[NFT_MAX_ARGV];
    argv[0] = "nft";
    int argc = 1;
    char *tok = strtok(cmd_copy, " ");
    while (tok && argc < NFT_MAX_ARGV - 1) {
        argv[argc++] = tok;
        tok = strtok(NULL, " ");
    }
    argv[argc] = NULL;

    log_msg(LOG_DEBUG, "nft: %s", cmd);

    char err_buf[NFT_ERR_BUF] = {0};
    int status = exec_cmd_safe(argv, err_buf, sizeof(err_buf));
    if (status != 0) {
        size_t len = strlen(err_buf);
        if (len > 0 && err_buf[len - 1] == '\n')
            err_buf[len - 1] = '\0';
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

    /* mkstemp для безопасного создания tmp файла (H-28) */
    char tmppath[] = "/tmp/4eburnet_nft_XXXXXX";
    int tmpfd = mkstemp(tmppath);
    if (tmpfd < 0) {
        log_msg(LOG_ERROR, "nft: mkstemp: %s", strerror(errno));
        return NFT_ERR_EXEC;
    }
    fchmod(tmpfd, 0600);
    FILE *f = fdopen(tmpfd, "w");
    if (!f) {
        close(tmpfd);
        unlink(tmppath);
        return NFT_ERR_EXEC;
    }
    fputs(config, f);
    fclose(f);

    /* Запускаем nft -f через posix_spawn без shell (H-07) */
    const char *const nft_argv[] = {"nft", "-f", tmppath, NULL};
    char err_buf[NFT_ERR_BUF] = {0};
    int status = exec_cmd_safe(nft_argv, err_buf, sizeof(err_buf));
    unlink(tmppath);

    if (status != 0) {
        size_t len = strlen(err_buf);
        if (len > 0 && err_buf[len - 1] == '\n')
            err_buf[len - 1] = '\0';
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
    /* posix_spawn без shell (DEC-010): rc==0 → таблица существует */
    const char *const argv[] = {
        "nft", "list", "table", "inet", NFT_TABLE_NAME, NULL
    };
    char err_buf[64] = {0};
    int rc = exec_cmd_safe(argv, err_buf, sizeof(err_buf));
    return (rc == 0);
}

/* ------------------------------------------------------------------ */
/*  nft_init — создание таблицы inet 4eburnet атомарно                  */
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
    /* M-35: heap вместо 16KB стека */
    char *config = malloc(NFT_ATOMIC_MAX);
    if (!config) return NFT_ERR_EXEC;
    int n = snprintf(config, NFT_ATOMIC_MAX,
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

    if (n < 0 || (size_t)n >= NFT_ATOMIC_MAX) {
        log_msg(LOG_ERROR, "nft: конфиг таблицы не поместился в буфер");
        free(config);
        return NFT_ERR_EXEC;
    }

    nft_result_t rc = nft_exec_atomic(config);
    free(config);
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
    if (!valid_nft_name(set_name)) {
        log_msg(LOG_ERROR, "nft: невалидное имя set: %s", set_name);
        return NFT_ERR_EXEC;
    }
    if (!validate_cidr(cidr)) {
        log_msg(LOG_ERROR, "nft: невалидный CIDR: %s", cidr);
        return NFT_ERR_EXEC;
    }
    char cmd[NFT_CMD_MAX];
    snprintf(cmd, sizeof(cmd),
             "add element inet " NFT_TABLE_NAME " %s { %s }",
             set_name, cidr);
    return nft_exec(cmd);
}

nft_result_t nft_set_del_addr(const char *set_name, const char *cidr)
{
    if (!valid_nft_name(set_name)) {
        log_msg(LOG_ERROR, "nft: невалидное имя set: %s", set_name);
        return NFT_ERR_EXEC;
    }
    if (!validate_cidr(cidr)) {
        log_msg(LOG_ERROR, "nft: невалидный CIDR: %s", cidr);
        return NFT_ERR_EXEC;
    }
    char cmd[NFT_CMD_MAX];
    snprintf(cmd, sizeof(cmd),
             "delete element inet " NFT_TABLE_NAME " %s { %s }",
             set_name, cidr);
    return nft_exec(cmd);
}

nft_result_t nft_set_flush(const char *set_name)
{
    if (!valid_nft_name(set_name)) {
        log_msg(LOG_ERROR, "nft: невалидное имя set: %s", set_name);
        return NFT_ERR_EXEC;
    }
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

    /* B1-03: буферы на heap — 2×1024 = 2KB на MIPS стеке */
    char *pre_rules = malloc(1024);
    char *fwd_rules = malloc(1024);
    if (!pre_rules || !fwd_rules) {
        free(pre_rules); free(fwd_rules);
        return NFT_ERR_EXEC;
    }

    snprintf(pre_rules, 1024,
        "\n"
        "        ip daddr @" NFT_SET_PROXY " %s"
            " meta mark set 0x%02x accept\n"
        "        ip6 daddr @" NFT_SET_PROXY6 " %s"
            " meta mark set 0x%02x accept\n",
        proto_match, NFT_MARK_PROXY,
        proto_match, NFT_MARK_PROXY);

    snprintf(fwd_rules, 1024,
        "\n"
        "        ip daddr @" NFT_SET_PROXY " %s"
            " meta mark set 0x%02x accept\n"
        "        ip6 daddr @" NFT_SET_PROXY6 " %s"
            " meta mark set 0x%02x accept\n",
        proto_match, NFT_MARK_PROXY,
        proto_match, NFT_MARK_PROXY);

    nft_result_t rc = apply_mode(pre_rules, fwd_rules);
    free(pre_rules); free(fwd_rules);
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
    /* M-35: heap вместо 16KB стека */
    char *config = malloc(NFT_ATOMIC_MAX);
    if (!config) return NFT_ERR_EXEC;
    int n = snprintf(config, NFT_ATOMIC_MAX,
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

    if (n < 0 || (size_t)n >= NFT_ATOMIC_MAX) {
        log_msg(LOG_ERROR, "nft: конфиг режима не поместился в буфер");
        free(config);
        return NFT_ERR_EXEC;
    }

    nft_result_t rc = nft_exec_atomic(config);
    free(config);
    return rc;
}

nft_result_t nft_mode_set_rules(const char *fake_ip_range)
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

    const char *fip = (fake_ip_range && fake_ip_range[0])
                      ? fake_ip_range : "198.51.100.0/24";

    /* B1-03: буферы на heap — 2×1024 = 2KB на MIPS стеке */
    char *pre_rules = malloc(1024);
    char *fwd_rules = malloc(1024);
    if (!pre_rules || !fwd_rules) {
        free(pre_rules); free(fwd_rules);
        return NFT_ERR_EXEC;
    }

    snprintf(pre_rules, 1024,
        "\n"
        /* fake-ip: всегда через прокси (диспетчер делает reverse lookup) */
        "        ip daddr %s"
            " meta l4proto { tcp, udp }"
            " meta mark set 0x%02x accept\n"
        "        ip daddr @" NFT_SET_PROXY
            " meta l4proto { tcp, udp }"
            " meta mark set 0x%02x accept\n"
        "        ip6 daddr @" NFT_SET_PROXY6
            " meta l4proto { tcp, udp }"
            " meta mark set 0x%02x accept\n",
        fip, NFT_MARK_PROXY, NFT_MARK_PROXY, NFT_MARK_PROXY);

    snprintf(fwd_rules, 1024,
        "\n"
        "        ip daddr %s"
            " meta l4proto { tcp, udp }"
            " meta mark set 0x%02x accept\n"
        "        ip daddr @" NFT_SET_PROXY
            " meta l4proto { tcp, udp }"
            " meta mark set 0x%02x accept\n"
        "        ip6 daddr @" NFT_SET_PROXY6
            " meta l4proto { tcp, udp }"
            " meta mark set 0x%02x accept\n",
        fip, NFT_MARK_PROXY, NFT_MARK_PROXY, NFT_MARK_PROXY);

    nft_result_t rc = apply_mode(pre_rules, fwd_rules);
    free(pre_rules); free(fwd_rules);
    if (rc == NFT_OK)
        log_msg(LOG_INFO, "Режим маршрутизации: rules (mark+iproute2)");
    return rc;
}

nft_result_t nft_mode_set_global(void)
{
    /*
     * Режим "глобальный":
     * - block_addrs  → drop
     * - локальные    → accept
     * - bypass       → accept
     * - ВСЁ остальное → meta mark → ip rule → table 100 → lo
     *
     * Порядок правил в prerouting:
     *   block → local → bypass → mark (всё)
     */

    /* B1-03: буферы на heap */
    char *pre_rules = malloc(1024);
    char *fwd_rules = malloc(1024);
    if (!pre_rules || !fwd_rules) {
        free(pre_rules); free(fwd_rules);
        return NFT_ERR_EXEC;
    }

    snprintf(pre_rules, 1024,
        "\n"
        "        meta l4proto { tcp, udp }"
            " meta mark set 0x%02x accept\n",
        NFT_MARK_PROXY);

    snprintf(fwd_rules, 1024,
        "\n"
        "        meta l4proto { tcp, udp }"
            " meta mark set 0x%02x accept\n",
        NFT_MARK_PROXY);

    nft_result_t rc = apply_mode(pre_rules, fwd_rules);
    free(pre_rules); free(fwd_rules);
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

/* nft_mode_set_tun удалён — TPROXY покрывает все use-cases (DEC-035) */

/* ------------------------------------------------------------------ */
/*  nft_exec_file — атомарное применение через запись напрямую в файл   */
/*  Для batch загрузки: fprintf в открытый FILE*, затем nft -f         */
/* ------------------------------------------------------------------ */

static nft_result_t nft_exec_file(const char *path)
{
    /* posix_spawn без shell (H-07) */
    const char *const nft_argv[] = {"nft", "-f", path, NULL};
    char err_buf[NFT_ERR_BUF] = {0};
    int status = exec_cmd_safe(nft_argv, err_buf, sizeof(err_buf));
    if (status != 0) {
        size_t len = strlen(err_buf);
        if (len > 0 && err_buf[len - 1] == '\n')
            err_buf[len - 1] = '\0';
        log_msg(LOG_ERROR, "nft: batch провалился (код %d): %s",
                status, err_buf);
        return NFT_ERR_RULE;
    }

    return NFT_OK;
}

/* ------------------------------------------------------------------ */
/*  nft_set_load_file — batch загрузка в обычный set (H-06)            */
/* ------------------------------------------------------------------ */

nft_result_t nft_set_load_file(const char *set_name,
                               const char *filepath,
                               nft_load_result_t *result)
{
    if (result) {
        result->loaded = 0;
        result->skipped = 0;
        result->errors = 0;
    }

    if (!valid_nft_name(set_name)) {
        log_msg(LOG_ERROR, "nft: невалидное имя set: %s", set_name);
        return NFT_ERR_EXEC;
    }

    FILE *f = fopen(filepath, "r");
    if (!f) {
        log_msg(LOG_WARN, "nft: файл не найден: %s", filepath);
        return NFT_ERR_NOTFOUND;
    }

    /* mkstemp для batch файла (H-28) */
    char batchpath[] = "/tmp/4eburnet_nft_XXXXXX";
    int batchfd = mkstemp(batchpath);
    if (batchfd < 0) { fclose(f); return NFT_ERR_EXEC; }
    fchmod(batchfd, 0600);
    FILE *batch = fdopen(batchfd, "w");
    if (!batch) { close(batchfd); unlink(batchpath); fclose(f); return NFT_ERR_EXEC; }

    fprintf(batch, "add element inet " NFT_TABLE_NAME " %s {\n",
            set_name);

    char line[256];
    size_t batch_count = 0;
    uint32_t total_loaded = 0, total_skipped = 0, total_errors = 0;

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#') { total_skipped++; continue; }
        if (!validate_cidr(line)) { total_errors++; continue; }

        fprintf(batch, "    %s,\n", line);
        batch_count++;

        if (batch_count >= NFT_BATCH_MAX) {
            fprintf(batch, "}\n");
            fclose(batch);
            nft_result_t rc = nft_exec_file(batchpath);
            unlink(batchpath);
            if (rc != NFT_OK) total_errors += batch_count;
            else total_loaded += batch_count;

            char newpath[] = "/tmp/4eburnet_nft_XXXXXX";
            int newfd = mkstemp(newpath);
            if (newfd < 0) {
                /* batch уже закрыт выше — закрываем только основной файл */
                fclose(f);
                if (result) {
                    result->loaded  = total_loaded;
                    result->skipped = total_skipped;
                    result->errors  = total_errors;
                }
                return NFT_ERR_EXEC;
            }
            fchmod(newfd, 0600);
            FILE *new_batch = fdopen(newfd, "w");
            if (!new_batch) {
                close(newfd);
                unlink(newpath);  /* newpath ещё не скопирован в batchpath */
                fclose(f);
                if (result) {
                    result->loaded  = total_loaded;
                    result->skipped = total_skipped;
                    result->errors  = total_errors;
                }
                return NFT_ERR_EXEC;
            }
            /* Всё OK — переключаем batch */
            memcpy(batchpath, newpath, sizeof(batchpath));
            batch = new_batch;
            fprintf(batch, "add element inet " NFT_TABLE_NAME " %s {\n",
                    set_name);
            batch_count = 0;
        }
    }
    fclose(f);

    if (batch_count > 0) {
        fprintf(batch, "}\n");
        fclose(batch);
        nft_result_t rc = nft_exec_file(batchpath);
        unlink(batchpath);
        if (rc != NFT_OK) total_errors += batch_count;
        else total_loaded += batch_count;
    } else {
        fclose(batch);
        unlink(batchpath);
    }

    if (result) {
        result->loaded = total_loaded;
        result->skipped = total_skipped;
        result->errors = total_errors;
    }

    log_msg(LOG_INFO, "Файл %s → %s: загружено %u, пропущено %u, ошибок %u",
            filepath, set_name, total_loaded, total_skipped, total_errors);
    return total_errors > 0 ? NFT_ERR_RULE : NFT_OK;
}

/* ------------------------------------------------------------------ */
/*  Verdict Maps (DEC-017)                                             */
/* ------------------------------------------------------------------ */

nft_result_t nft_vmap_create(void)
{
    /*
     * Verdict maps для масштабируемой фильтрации 300K+ записей.
     * block_map  → : drop    (блокировка)
     * bypass_map → : accept  (пропуск напрямую)
     *
     * proxy_addrs остаётся обычным set — tproxy нельзя в verdict map.
     */
    /* M-35: heap вместо 16KB стека */
    char *config = malloc(NFT_ATOMIC_MAX);
    if (!config) return NFT_ERR_EXEC;
    int n = snprintf(config, NFT_ATOMIC_MAX,
        "table inet " NFT_TABLE_NAME " {\n"
        "    map " NFT_VMAP_BLOCK " {\n"
        "        type ipv4_addr : verdict\n"
        "        flags interval\n"
        "    }\n"
        "    map " NFT_VMAP_BLOCK6 " {\n"
        "        type ipv6_addr : verdict\n"
        "        flags interval\n"
        "    }\n"
        "    map " NFT_VMAP_BYPASS " {\n"
        "        type ipv4_addr : verdict\n"
        "        flags interval\n"
        "    }\n"
        "    map " NFT_VMAP_BYPASS6 " {\n"
        "        type ipv6_addr : verdict\n"
        "        flags interval\n"
        "    }\n"
        "}\n");

    if (n < 0 || (size_t)n >= NFT_ATOMIC_MAX) {
        free(config);
        return NFT_ERR_EXEC;
    }

    nft_result_t rc = nft_exec_atomic(config);
    free(config);
    if (rc == NFT_OK)
        log_msg(LOG_INFO, "Verdict maps созданы (block/bypass x IPv4/IPv6)");
    else
        log_msg(LOG_ERROR, "Не удалось создать verdict maps: %s",
                nft_strerror(rc));
    return rc;
}

nft_result_t nft_vmap_flush_all(void)
{
    /* M-35: heap */
    char *config = malloc(NFT_ATOMIC_MAX);
    if (!config) return NFT_ERR_EXEC;
    snprintf(config, NFT_ATOMIC_MAX,
        "flush map inet " NFT_TABLE_NAME " " NFT_VMAP_BLOCK "\n"
        "flush map inet " NFT_TABLE_NAME " " NFT_VMAP_BLOCK6 "\n"
        "flush map inet " NFT_TABLE_NAME " " NFT_VMAP_BYPASS "\n"
        "flush map inet " NFT_TABLE_NAME " " NFT_VMAP_BYPASS6 "\n");

    nft_result_t rc = nft_exec_atomic(config);
    free(config);
    if (rc == NFT_OK)
        log_msg(LOG_INFO, "Verdict maps очищены");
    return rc;
}

/* ------------------------------------------------------------------ */
/*  nft_vmap_load_batch — загрузка массива CIDR в verdict map          */
/* ------------------------------------------------------------------ */

nft_result_t nft_vmap_load_batch(const char *map_name,
                                 const char *verdict,
                                 const char **cidrs, size_t count,
                                 nft_load_result_t *result)
{
    if (result) {
        result->loaded = 0;
        result->skipped = 0;
        result->errors = 0;
    }

    if (!valid_nft_name(map_name)) {
        log_msg(LOG_ERROR, "nft: невалидное имя map: %s", map_name);
        return NFT_ERR_EXEC;
    }

    if (count == 0)
        return NFT_OK;

    /* Загружаем порциями по NFT_BATCH_MAX */
    size_t offset = 0;
    while (offset < count) {
        size_t batch = count - offset;
        if (batch > NFT_BATCH_MAX)
            batch = NFT_BATCH_MAX;

        /* mkstemp для batch файла (H-28) */
        char tmppath[] = "/tmp/4eburnet_nft_XXXXXX";
        int tmpfd = mkstemp(tmppath);
        if (tmpfd < 0) {
            log_msg(LOG_ERROR, "nft: mkstemp: %s", strerror(errno));
            return NFT_ERR_EXEC;
        }
        fchmod(tmpfd, 0600);
        FILE *f = fdopen(tmpfd, "w");
        if (!f) {
            close(tmpfd); unlink(tmppath);
            return NFT_ERR_EXEC;
        }

        fprintf(f, "add element inet " NFT_TABLE_NAME " %s {\n",
                map_name);

        size_t written = 0;
        for (size_t i = 0; i < batch; i++) {
            const char *cidr = cidrs[offset + i];
            if (!cidr || cidr[0] == '\0' || cidr[0] == '#') {
                if (result) result->skipped++;
                continue;
            }
            if (!validate_cidr(cidr)) {
                if (result) result->skipped++;
                continue;
            }
            fprintf(f, "    %s : %s,\n", cidr, verdict);
            written++;
        }

        fprintf(f, "}\n");
        fclose(f);

        if (written > 0) {
            nft_result_t rc = nft_exec_file(tmppath);
            unlink(tmppath);
            if (rc != NFT_OK) {
                if (result) result->errors += written;
                log_msg(LOG_ERROR,
                    "nft: batch %s провалился на offset %zu",
                    map_name, offset);
                return rc;
            }
            if (result) result->loaded += written;
        } else {
            unlink(tmppath);
        }

        offset += batch;

        /* Прогресс каждые 50K */
        if (result && result->loaded > 0 &&
            result->loaded % 50000 < NFT_BATCH_MAX)
            log_msg(LOG_INFO, "Загрузка %s: %u/%zu...",
                    map_name, result->loaded, count);
    }

    if (result)
        log_msg(LOG_INFO, "%s: загружено %u, пропущено %u, ошибок %u",
                map_name, result->loaded, result->skipped, result->errors);

    return NFT_OK;
}

/* ------------------------------------------------------------------ */
/*  nft_vmap_load_file — загрузка CIDR из файла                        */
/* ------------------------------------------------------------------ */

nft_result_t nft_vmap_load_file(const char *map_name,
                                const char *verdict,
                                const char *filepath,
                                nft_load_result_t *result)
{
    if (result) {
        result->loaded = 0;
        result->skipped = 0;
        result->errors = 0;
    }

    if (!valid_nft_name(map_name)) {
        log_msg(LOG_ERROR, "nft: невалидное имя map: %s", map_name);
        return NFT_ERR_EXEC;
    }

    FILE *f = fopen(filepath, "r");
    if (!f) {
        log_msg(LOG_WARN, "nft: файл не найден: %s", filepath);
        return NFT_ERR_NOTFOUND;
    }

    /*
     * Читаем построчно, накапливаем batch в tmp файл.
     * При достижении NFT_BATCH_MAX — применяем и начинаем новый.
     */
    /* mkstemp для batch файла (H-28) */
    char batchpath[] = "/tmp/4eburnet_nft_XXXXXX";
    int batchfd = mkstemp(batchpath);
    if (batchfd < 0) { fclose(f); return NFT_ERR_EXEC; }
    fchmod(batchfd, 0600);
    FILE *batch = fdopen(batchfd, "w");
    if (!batch) { close(batchfd); unlink(batchpath); fclose(f); return NFT_ERR_EXEC; }

    fprintf(batch, "add element inet " NFT_TABLE_NAME " %s {\n",
            map_name);

    char line[256];
    size_t batch_count = 0;
    uint32_t total_loaded = 0;
    uint32_t total_skipped = 0;
    uint32_t total_errors = 0;

    while (fgets(line, sizeof(line), f)) {
        /* Убрать перенос строки */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        /* Пропустить пустые и комментарии */
        if (len == 0 || line[0] == '#') {
            total_skipped++;
            continue;
        }

        /* Минимальная валидация: должна содержать цифру */
        if (line[0] < '0' || line[0] > '9') {
            /* IPv6 начинается с hex, но не с # и не пустая — пропускаем */
            if (line[0] != ':' && !(line[0] >= 'a' && line[0] <= 'f')
                               && !(line[0] >= 'A' && line[0] <= 'F')) {
                total_errors++;
                continue;
            }
        }

        /* Валидация CIDR — защита от nft injection (S-02) */
        if (!validate_cidr(line)) {
            total_errors++;
            continue;
        }

        fprintf(batch, "    %s : %s,\n", line, verdict);
        batch_count++;

        if (batch_count >= NFT_BATCH_MAX) {
            fprintf(batch, "}\n");
            fclose(batch);

            nft_result_t rc = nft_exec_file(batchpath);
            unlink(batchpath);
            if (rc != NFT_OK) {
                total_errors += batch_count;
                log_msg(LOG_ERROR, "nft: batch из файла %s провалился",
                        filepath);
            } else {
                total_loaded += batch_count;
            }

            /* Прогресс каждые 50K */
            if (total_loaded > 0 && total_loaded % 50000 < NFT_BATCH_MAX)
                log_msg(LOG_INFO, "Загрузка %s из %s: %u...",
                        map_name, filepath, total_loaded);

            /* Начать новый batch */
            char newpath[] = "/tmp/4eburnet_nft_XXXXXX";
            int newfd = mkstemp(newpath);
            if (newfd < 0) {
                fclose(f);
                if (result) {
                    result->loaded = total_loaded;
                    result->skipped = total_skipped;
                    result->errors = total_errors;
                }
                return NFT_ERR_EXEC;
            }
            fchmod(newfd, 0600);
            memcpy(batchpath, newpath, sizeof(batchpath));
            batch = fdopen(newfd, "w");
            if (!batch) {
                close(newfd); unlink(batchpath); fclose(f);
                if (result) {
                    result->loaded = total_loaded;
                    result->skipped = total_skipped;
                    result->errors = total_errors;
                }
                return NFT_ERR_EXEC;
            }
            fprintf(batch, "add element inet " NFT_TABLE_NAME " %s {\n",
                    map_name);
            batch_count = 0;
        }
    }

    fclose(f);

    /* Финальный flush остатка */
    if (batch_count > 0) {
        fprintf(batch, "}\n");
        fclose(batch);

        nft_result_t rc = nft_exec_file(batchpath);
        unlink(batchpath);
        if (rc != NFT_OK)
            total_errors += batch_count;
        else
            total_loaded += batch_count;
    } else {
        fclose(batch);
        unlink(batchpath);
    }

    if (result) {
        result->loaded = total_loaded;
        result->skipped = total_skipped;
        result->errors = total_errors;
    }

    log_msg(LOG_INFO, "Файл %s → %s: загружено %u, пропущено %u, ошибок %u",
            filepath, map_name, total_loaded, total_skipped, total_errors);

    return total_errors > 0 ? NFT_ERR_RULE : NFT_OK;
}

/* ------------------------------------------------------------------ */
/*  nft_vmap_stats — вывод количества записей в лог                    */
/* ------------------------------------------------------------------ */

/* Контекст для подсчёта ':' в выводе nft list map */
struct vmap_count_ctx { long count; };
static void vmap_count_cb(const char *line, void *ctx)
{
    struct vmap_count_ctx *c = ctx;
    for (const char *p = line; *p; p++)
        if (*p == ':') c->count++;
}

static void vmap_count(const char *map_name)
{
    /* N2: подсчёт в C без shell pipe к grep */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "nft list map inet " NFT_TABLE_NAME " %s 2>/dev/null",
             map_name);
    struct vmap_count_ctx ctx = {0};
    exec_cmd_lines(cmd, vmap_count_cb, &ctx);
    log_msg(LOG_INFO, "  %s: %ld записей", map_name, ctx.count);
}

void nft_vmap_stats(void)
{
    log_msg(LOG_INFO, "=== Verdict Maps ===");
    vmap_count(NFT_VMAP_BLOCK);
    vmap_count(NFT_VMAP_BLOCK6);
    vmap_count(NFT_VMAP_BYPASS);
    vmap_count(NFT_VMAP_BYPASS6);
    log_msg(LOG_INFO, "====================");
}

/* ------------------------------------------------------------------ */
/*  HW Offload bypass (DEC-018)                                        */
/* ------------------------------------------------------------------ */

nft_result_t nft_offload_bypass_init(void)
{
    /*
     * Трафик направленный через прокси не должен попадать в HW offload.
     * Если flowtable активен — offloaded пакеты обходят netfilter,
     * и TPROXY их не видит.
     *
     * Решение: цепочка с приоритетом -300 (раньше всех наших)
     * помечает ct mark для proxy трафика. Ядро не offload-ит
     * соединения с ct mark != 0.
     */

    /* Проверяем наличие flowtable в fw4 */
    bool has_flowtable = exec_cmd_contains(
        "nft list flowtables 2>/dev/null", "flowtable");

    if (!has_flowtable) {
        log_msg(LOG_INFO,
            "HW Offload не обнаружен, bypass не требуется");
        return NFT_OK;
    }

    /* M-35: heap */
    char *config = malloc(NFT_ATOMIC_MAX);
    if (!config) return NFT_ERR_EXEC;
    int n = snprintf(config, NFT_ATOMIC_MAX,
        "table inet " NFT_TABLE_NAME " {\n"
        "    chain " NFT_CHAIN_OFFLOAD " {\n"
        "        type filter hook forward priority %d; policy accept;\n"
        "\n"
        "        ip daddr @" NFT_SET_PROXY
            " ct mark set 0x%02x\n"
        "        ip6 daddr @" NFT_SET_PROXY6
            " ct mark set 0x%02x\n"
        "    }\n"
        "}\n",
        NFT_PRIO_OFFLOAD, NFT_MARK_PROXY, NFT_MARK_PROXY);

    if (n < 0 || (size_t)n >= NFT_ATOMIC_MAX) {
        free(config);
        return NFT_ERR_EXEC;
    }

    nft_result_t rc = nft_exec_atomic(config);
    free(config);
    if (rc == NFT_OK)
        log_msg(LOG_INFO,
            "HW Offload bypass инициализирован (priority %d)",
            NFT_PRIO_OFFLOAD);
    else
        log_msg(LOG_WARN, "Не удалось создать offload bypass: %s",
                nft_strerror(rc));

    return rc;
}

/* ------------------------------------------------------------------ */
/*  Flow offload для DIRECT трафика (v1.1-3)                          */
/* ------------------------------------------------------------------ */

static int get_wan_iface(char *buf, size_t buflen)
{
    FILE *f = popen("ip route show default | awk '{print $5}' | head -1", "r");
    if (!f) return -1;
    if (!fgets(buf, (int)buflen, f)) { pclose(f); return -1; }
    pclose(f);
    size_t l = strlen(buf);
    if (l > 0 && buf[l-1] == '\n') buf[--l] = '\0';
    return l > 0 ? 0 : -1;
}

int nft_flow_offload_enable(void)
{
    char wan_iface[32] = {0};
    if (get_wan_iface(wan_iface, sizeof(wan_iface)) < 0) {
        log_msg(LOG_WARN, "flow offload: не могу определить WAN интерфейс");
        return -1;
    }

    if (access("/sys/module/nft_flow_offload", F_OK) != 0) {
        const char *const modprobe[] = {"modprobe", "nft_flow_offload", NULL};
        char errbuf[64] = {0};
        exec_cmd_safe(modprobe, errbuf, sizeof(errbuf));
        if (access("/sys/module/nft_flow_offload", F_OK) != 0) {
            log_msg(LOG_WARN, "flow offload: nft_flow_offload.ko не загружен");
            return -1;
        }
    }

    /* Удаляем старые объекты — идемпотентность */
    nft_flow_offload_disable();

    char *config = malloc(NFT_ATOMIC_MAX);
    if (!config) return -1;

    int n = snprintf(config, NFT_ATOMIC_MAX,
        "add table inet " NFT_TABLE_NAME "\n"
        "add flowtable inet " NFT_TABLE_NAME " " NFT_FLOWTABLE_NAME
            " { hook ingress priority 0 ; "
            "devices = { %s, br-lan } ; }\n"
        "add chain inet " NFT_TABLE_NAME " " NFT_CHAIN_FLOW
            " { type filter hook forward priority %d ; policy accept ; }\n"
        "add rule inet " NFT_TABLE_NAME " " NFT_CHAIN_FLOW
            " ct state { established, related }"
            " meta l4proto { tcp, udp }"
            " meta mark != 0x%08x"
            " flow add @" NFT_FLOWTABLE_NAME "\n",
        wan_iface, NFT_PRIO_FLOW, NFT_MARK_PROXY);

    if (n < 0 || (size_t)n >= NFT_ATOMIC_MAX) {
        free(config); return -1;
    }

    nft_result_t rc = nft_exec_atomic(config);
    free(config);

    if (rc == NFT_OK)
        log_msg(LOG_INFO,
            "flow offload: активирован (WAN=%s, br-lan)", wan_iface);
    else
        log_msg(LOG_WARN,
            "flow offload: не активирован: %s", nft_strerror(rc));

    return rc == NFT_OK ? 0 : -1;
}

void nft_flow_offload_disable(void)
{
    const char *const flush_chain[] = {
        "nft", "flush", "chain", "inet", NFT_TABLE_NAME,
        NFT_CHAIN_FLOW, NULL
    };
    const char *const del_chain[] = {
        "nft", "delete", "chain", "inet", NFT_TABLE_NAME,
        NFT_CHAIN_FLOW, NULL
    };
    const char *const del_ft[] = {
        "nft", "delete", "flowtable", "inet", NFT_TABLE_NAME,
        NFT_FLOWTABLE_NAME, NULL
    };
    char errbuf[64] = {0};
    exec_cmd_safe(flush_chain, errbuf, sizeof(errbuf));
    exec_cmd_safe(del_chain,   errbuf, sizeof(errbuf));
    exec_cmd_safe(del_ft,      errbuf, sizeof(errbuf));
    log_msg(LOG_INFO, "flow offload: деактивирован");
}

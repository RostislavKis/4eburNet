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
#include <sys/utsname.h>

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

/* ------------------------------------------------------------------ */
/*  Проверка и загрузка kmod-nft-tproxy                                */
/* ------------------------------------------------------------------ */

/* Попытка загрузить nft_tproxy, вернуть 0 если OK, -1 если нет.
 * Результат кешируется — повторные вызовы не запускают modprobe. */
static int try_load_nft_tproxy(void)
{
    static int cached = -2;  /* -2 = не проверялось */
    if (cached != -2) return cached;

    /* Сначала проверить: уже загружен? */
    FILE *f = fopen("/sys/module/nft_tproxy/refcnt", "r");
    if (f) { fclose(f); cached = 0; return 0; }

    /* Попробовать modprobe */
    const char *const modprobe_argv[] = {"modprobe", "nft_tproxy", NULL};
    int rc = exec_cmd_safe(modprobe_argv, NULL, 0);
    if (rc == 0) { cached = 0; return 0; }

    /* Попробовать insmod с полным путём к модулю */
    struct utsname uts;
    if (uname(&uts) == 0) {
        char ko_path[256];
        snprintf(ko_path, sizeof(ko_path),
                 "/lib/modules/%s/kernel/net/netfilter/nft_tproxy.ko",
                 uts.release);
        const char *const insmod_argv[] = {"insmod", ko_path, NULL};
        rc = exec_cmd_safe(insmod_argv, NULL, 0);
        if (rc == 0) { cached = 0; return 0; }
    }

    cached = -1;
    return -1;
}

nft_result_t nft_exec(const char *cmd)
{
    if (!validate_nft_cmd(cmd)) {
        log_msg(LOG_ERROR, "nft: опасные символы в команде");
        return NFT_ERR_EXEC;
    }

    char full_cmd[NFT_CMD_MAX];
    int n = snprintf(full_cmd, sizeof(full_cmd), "nft %s 2>&1", cmd);
    if (n < 0 || (size_t)n >= sizeof(full_cmd)) {
        log_msg(LOG_ERROR, "nft: команда слишком длинная (%d байт)", n);
        return NFT_ERR_EXEC;
    }

    log_msg(LOG_DEBUG, "nft: %s", cmd);

    char err_buf[NFT_ERR_BUF] = {0};
    int status = exec_cmd_capture(full_cmd, err_buf, sizeof(err_buf));
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
    char expected[64];
    snprintf(expected, sizeof(expected), "table inet %s", NFT_TABLE_NAME);
    return exec_cmd_contains("nft list tables 2>/dev/null", expected);
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
    if (try_load_nft_tproxy() < 0) {
        log_msg(LOG_WARN,
            "kmod-nft-tproxy недоступен на этом устройстве. "
            "TPROXY перехват трафика отключён. "
            "Установите: opkg install kmod-nft-tproxy");
        return NFT_OK;
    }

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

    /* Без kmod-nft-tproxy правила загружаются без перехвата трафика */
    if (try_load_nft_tproxy() < 0) {
        log_msg(LOG_WARN,
            "kmod-nft-tproxy недоступен на этом устройстве. "
            "TPROXY перехват трафика отключён. "
            "Установите: opkg install kmod-nft-tproxy");
        nft_result_t rc = apply_mode(NULL, NULL);
        if (rc == NFT_OK)
            log_msg(LOG_INFO, "Режим маршрутизации: rules (без TPROXY)");
        return rc;
    }

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

    /* Без kmod-nft-tproxy правила загружаются без перехвата трафика */
    if (try_load_nft_tproxy() < 0) {
        log_msg(LOG_WARN,
            "kmod-nft-tproxy недоступен на этом устройстве. "
            "TPROXY перехват трафика отключён. "
            "Установите: opkg install kmod-nft-tproxy");
        nft_result_t rc = apply_mode(NULL, NULL);
        if (rc == NFT_OK)
            log_msg(LOG_INFO, "Режим маршрутизации: global (без TPROXY)");
        return rc;
    }

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
            if (newfd < 0) { fclose(f); break; }
            fchmod(newfd, 0600);
            memcpy(batchpath, newpath, sizeof(batchpath));
            batch = fdopen(newfd, "w");
            if (!batch) { close(newfd); unlink(batchpath); fclose(f); break; }
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

    /*
     * Определяем вердикт по имени map:
     * block_map/block_map6 → drop
     * bypass_map/bypass_map6 → accept
     */
    const char *verdict = "accept";
    if (strstr(map_name, "block"))
        verdict = "drop";

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

    const char *verdict = "accept";
    if (strstr(map_name, "block"))
        verdict = "drop";

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

static void vmap_count(const char *map_name)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "nft list map inet " NFT_TABLE_NAME " %s 2>/dev/null"
             " | grep -c ':'", map_name);

    char out[32] = {0};
    exec_cmd_capture(cmd, out, sizeof(out));
    char *endptr;
    long count = strtol(out, &endptr, 10);
    if (endptr == out) count = 0;
    log_msg(LOG_INFO, "  %s: %ld записей", map_name, count);
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
            " ct mark set 0x01\n"
        "        ip6 daddr @" NFT_SET_PROXY6
            " ct mark set 0x01\n"
        "    }\n"
        "}\n",
        NFT_PRIO_OFFLOAD);

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

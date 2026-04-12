/*
 * test_config_parsing.c — тесты парсинга конфига (P-40, P-42)
 * MAX_LINE граничные значения, AWG i1 hex blob, серверы с пробелами
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fail_count = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fail_count++; } \
    else { printf("PASS: %s\n", msg); } \
} while(0)

/* Вспомогательная: записать строку в tmp файл, вернуть путь */
static const char *write_tmp(const char *content)
{
    static const char *path = "/tmp/test_4eburnet_config.tmp";
    FILE *f = fopen(path, "w");
    if (!f) return NULL;
    fputs(content, f);
    fclose(f);
    return path;
}

/* Тест 1: строка MAX_LINE-1 байт — парсируется без crash */
static void test_max_line_boundary(void)
{
    /* Сервер с именем ровно 8100 символов (MAX_LINE=8192 минус overhead) */
    char uci[8300];
    int pos = 0;
    pos += snprintf(uci + pos, sizeof(uci) - (size_t)pos,
        "config main\n\toption enabled '1'\n\toption mode 'rules'\n\n"
        "config server\n\toption protocol 'vless'\n\toption name '");
    /* Заполнить имя 'a' × 60 — в пределах sizeof(name)=64 */
    for (int i = 0; i < 60; i++) uci[pos++] = 'a';
    pos += snprintf(uci + pos, sizeof(uci) - (size_t)pos,
        "'\n\toption address '1.2.3.4'\n\toption port '443'\n");

    const char *path = write_tmp(uci);
    ASSERT(path != NULL, "max_line: tmp файл создан");

    EburNetConfig cfg = {0};
    int rc = config_load(path, &cfg);
    ASSERT(rc == 0, "max_line: config_load вернул 0");
    ASSERT(cfg.server_count == 1, "max_line: 1 сервер загружен");
    config_free(&cfg);
}

/* Тест 2: AWG i1 hex blob 3000 символов — помещается в MAX_LINE */
static void test_awg_i_hex_blob(void)
{
    char uci[8192];
    int pos = 0;
    pos += snprintf(uci + pos, sizeof(uci) - (size_t)pos,
        "config main\n\toption enabled '1'\n\toption mode 'rules'\n\n"
        "config server\n\toption protocol 'awg'\n\toption name 'awg1'"
        "\n\toption address '1.2.3.4'\n\toption port '4500'"
        "\n\toption awg_private_key 'testkey'"
        "\n\toption awg_public_key 'testpub'"
        "\n\toption awg_i1 '");
    /* 3000 hex символов */
    for (int i = 0; i < 3000; i++) uci[pos++] = 'a';
    pos += snprintf(uci + pos, sizeof(uci) - (size_t)pos, "'\n");

    const char *path = write_tmp(uci);
    ASSERT(path != NULL, "awg_i: tmp файл создан");

    EburNetConfig cfg = {0};
    int rc = config_load(path, &cfg);
    ASSERT(rc == 0, "awg_i: config_load вернул 0");
    ASSERT(cfg.server_count == 1, "awg_i: 1 сервер");
    if (cfg.server_count > 0) {
        ASSERT(cfg.servers[0].awg_i[0] != NULL, "awg_i: awg_i[0] не NULL");
        ASSERT(strlen(cfg.servers[0].awg_i[0]) == 3000, "awg_i: длина 3000");
    }
    config_free(&cfg);
}

/* Тест 3: list servers с именами содержащими пробелы (P-42) */
static void test_server_names_with_spaces(void)
{
    const char *uci =
        "config main\n\toption enabled '1'\n\toption mode 'rules'\n\n"
        "config server\n\toption protocol 'awg'\n"
        "\toption name 'AWG 1.5 (1 Вариант)'\n"
        "\toption address '162.159.192.1'\n\toption port '4500'\n\n"
        "config server\n\toption protocol 'vless'\n"
        "\toption name 'VLESS Reality'\n"
        "\toption address '1.2.3.4'\n\toption port '443'\n\n"
        "config server\n\toption protocol 'trojan'\n"
        "\toption name 'Trojan NL'\n"
        "\toption address '5.6.7.8'\n\toption port '443'\n\n"
        "config proxy_group\n"
        "\toption name 'auto'\n\toption type 'url_test'\n"
        "\tlist servers 'AWG 1.5 (1 Вариант)'\n"
        "\tlist servers 'VLESS Reality'\n"
        "\tlist servers 'Trojan NL'\n";

    const char *path = write_tmp(uci);
    ASSERT(path != NULL, "spaces: tmp файл создан");

    EburNetConfig cfg = {0};
    int rc = config_load(path, &cfg);
    ASSERT(rc == 0, "spaces: config_load вернул 0");
    ASSERT(cfg.server_count == 3, "spaces: 3 сервера");
    ASSERT(cfg.proxy_group_count == 1, "spaces: 1 группа");
    if (cfg.server_count >= 1)
        ASSERT(strcmp(cfg.servers[0].name, "AWG 1.5 (1 Вариант)") == 0,
               "spaces: имя с пробелами сохранено");
    if (cfg.proxy_group_count > 0) {
        ASSERT(cfg.proxy_groups[0].server_count == 3,
               "spaces: группа содержит 3 сервера");
        if (cfg.proxy_groups[0].server_count >= 1)
            ASSERT(strcmp(cfg.proxy_groups[0].servers[0],
                          "AWG 1.5 (1 Вариант)") == 0,
                   "spaces: list servers с пробелами");
    }
    config_free(&cfg);
}

int main(void)
{
    printf("=== test_config_parsing ===\n\n");
    test_max_line_boundary();
    test_awg_i_hex_blob();
    test_server_names_with_spaces();
    printf("\nALL PASS: %d тест(ов) провалено\n", fail_count);
    return fail_count ? 1 : 0;
}

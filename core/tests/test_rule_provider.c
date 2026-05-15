/*
 * test_rule_provider.c
 *
 * Тест публичного API rule_provider.c:
 * init/free, owns_fd, count_rules (через load_all), to_json.
 * count_rules — static, тестируется косвенно через rule_provider_load_all
 * с файлом на диске → providers[i].rule_count.
 */

#include "proxy/rule_provider.h"
#include "4eburnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Создать tmpfile с заданным содержимым, вернуть путь (caller free()). */
static char *make_tmpfile(const char *content)
{
    char *path = strdup("/tmp/test_rp_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) { free(path); return NULL; }
    if (content && content[0])
        write(fd, content, strlen(content));
    close(fd);
    return path;
}

/* ── [1] rule_provider_init_free ─────────────────────────────────────── */
static int test_rule_provider_init_free(void)
{
    EburNetConfig cfg = {0};
    cfg.rule_provider_count = 0;

    rule_provider_manager_t mgr;
    int r = rule_provider_init(&mgr, &cfg);
    if (r != 0) {
        fprintf(stderr, "FAIL [1]: init вернул %d\n", r);
        return 1;
    }
    if (mgr.count != 0) {
        fprintf(stderr, "FAIL [1]: count=%d != 0\n", mgr.count);
        return 1;
    }
    rule_provider_free(&mgr);
    printf("  [1] rule_provider_init_free PASS\n");
    return 0;
}

/* ── [2] rule_provider_owns_fd ───────────────────────────────────────── */
static int test_rule_provider_owns_fd(void)
{
    EburNetConfig cfg = {0};
    cfg.rule_provider_count = 2;
    cfg.rule_providers = calloc(2, sizeof(RuleProviderConfig));
    snprintf(cfg.rule_providers[0].name, 64, "p1");
    snprintf(cfg.rule_providers[0].path, 256, "/tmp/rp_stub_p1.list");
    snprintf(cfg.rule_providers[1].name, 64, "p2");
    snprintf(cfg.rule_providers[1].path, 256, "/tmp/rp_stub_p2.list");

    rule_provider_manager_t mgr;
    rule_provider_init(&mgr, &cfg);
    free(cfg.rule_providers);

    /* Устанавливаем оба fd в ненулевые значения: owns_fd(-1) должен вернуть
     * false только если ни у одного провайдера нет fetch_pipe_fd == -1.
     * WHY: owns_fd сравнивает fd напрямую без guards — тест учитывает это. */
    mgr.providers[0].fetch_pipe_fd = 42;
    mgr.providers[1].fetch_pipe_fd = 7;

    int fail = 0;
    if (!rule_provider_owns_fd(&mgr, 42)) {
        fprintf(stderr, "FAIL [2]: 42 не распознан как owned\n"); fail = 1;
    }
    if (rule_provider_owns_fd(&mgr, 99)) {
        fprintf(stderr, "FAIL [2]: 99 ошибочно считается owned\n"); fail = 1;
    }
    if (rule_provider_owns_fd(&mgr, -1)) {
        fprintf(stderr, "FAIL [2]: -1 ошибочно считается owned\n"); fail = 1;
    }

    /* сбросить до free() — чтобы rule_provider_free не закрывал несвои fd */
    mgr.providers[0].fetch_pipe_fd = -1;
    mgr.providers[1].fetch_pipe_fd = -1;
    rule_provider_free(&mgr);

    if (!fail) printf("  [2] rule_provider_owns_fd PASS\n");
    return fail;
}

/* ── [3] count_rules: только комментарии и пустые строки → 0 ─────────── */
static int test_count_rules_empty_file(void)
{
    char *tmp = make_tmpfile("# comment\n\n# another\n");
    if (!tmp) { fprintf(stderr, "FAIL [3]: mkstemp\n"); return 1; }

    EburNetConfig cfg = {0};
    cfg.rule_provider_count = 1;
    cfg.rule_providers = calloc(1, sizeof(RuleProviderConfig));
    snprintf(cfg.rule_providers[0].name, 64, "empty");
    snprintf(cfg.rule_providers[0].path, 256, "%s", tmp);
    cfg.rule_providers[0].type = RULE_PROVIDER_FILE;

    rule_provider_manager_t mgr;
    rule_provider_init(&mgr, &cfg);
    rule_provider_load_all(&mgr);

    int count = mgr.providers[0].rule_count;
    free(cfg.rule_providers);
    rule_provider_free(&mgr);
    unlink(tmp); free(tmp);

    if (count != 0) {
        fprintf(stderr, "FAIL [3]: count=%d != 0\n", count);
        return 1;
    }
    printf("  [3] count_rules_empty_file PASS\n");
    return 0;
}

/* ── [4] count_rules: смешанный контент → 3 ─────────────────────────── */
static int test_count_rules_mixed(void)
{
    char *tmp = make_tmpfile(
        "# header\ndomain1.com\ndomain2.com\n# comment\ndomain3.com\n");
    if (!tmp) { fprintf(stderr, "FAIL [4]: mkstemp\n"); return 1; }

    EburNetConfig cfg = {0};
    cfg.rule_provider_count = 1;
    cfg.rule_providers = calloc(1, sizeof(RuleProviderConfig));
    snprintf(cfg.rule_providers[0].name, 64, "mixed");
    snprintf(cfg.rule_providers[0].path, 256, "%s", tmp);
    cfg.rule_providers[0].type = RULE_PROVIDER_FILE;

    rule_provider_manager_t mgr;
    rule_provider_init(&mgr, &cfg);
    rule_provider_load_all(&mgr);

    int count = mgr.providers[0].rule_count;
    free(cfg.rule_providers);
    rule_provider_free(&mgr);
    unlink(tmp); free(tmp);

    if (count != 3) {
        fprintf(stderr, "FAIL [4]: count=%d != 3\n", count);
        return 1;
    }
    printf("  [4] count_rules_mixed PASS\n");
    return 0;
}

/* ── [5] rule_provider_load_all: 5 доменов → loaded=true, count=5 ────── */
static int test_rule_provider_load_tmpfile(void)
{
    char *tmp = make_tmpfile(
        "domain1.com\ndomain2.com\ndomain3.com\ndomain4.com\ndomain5.com\n");
    if (!tmp) { fprintf(stderr, "FAIL [5]: mkstemp\n"); return 1; }

    EburNetConfig cfg = {0};
    cfg.rule_provider_count = 1;
    cfg.rule_providers = calloc(1, sizeof(RuleProviderConfig));
    snprintf(cfg.rule_providers[0].name, 64, "five");
    snprintf(cfg.rule_providers[0].path, 256, "%s", tmp);
    cfg.rule_providers[0].type = RULE_PROVIDER_FILE;

    rule_provider_manager_t mgr;
    rule_provider_init(&mgr, &cfg);
    rule_provider_load_all(&mgr);

    bool  loaded = mgr.providers[0].loaded;
    int   count  = mgr.providers[0].rule_count;
    free(cfg.rule_providers);
    rule_provider_free(&mgr);
    unlink(tmp); free(tmp);

    if (!loaded) { fprintf(stderr, "FAIL [5]: loaded=false\n"); return 1; }
    if (count != 5) { fprintf(stderr, "FAIL [5]: count=%d != 5\n", count); return 1; }
    printf("  [5] rule_provider_load_tmpfile PASS\n");
    return 0;
}

/* ── [6] rule_provider_to_json ───────────────────────────────────────── */
static int test_rule_provider_to_json(void)
{
    EburNetConfig cfg = {0};
    cfg.rule_provider_count = 1;
    cfg.rule_providers = calloc(1, sizeof(RuleProviderConfig));
    snprintf(cfg.rule_providers[0].name, 64, "test");
    snprintf(cfg.rule_providers[0].path, 256, "/tmp/rp_json_stub.list");
    cfg.rule_providers[0].type = RULE_PROVIDER_FILE;

    rule_provider_manager_t mgr;
    rule_provider_init(&mgr, &cfg);
    free(cfg.rule_providers);

    mgr.providers[0].rule_count = 3;
    mgr.providers[0].loaded     = true;

    char buf[1024];
    rule_provider_to_json(&mgr, buf, sizeof(buf));
    rule_provider_free(&mgr);

    int fail = 0;
    if (!strstr(buf, "\"name\":\"test\"")) {
        fprintf(stderr, "FAIL [6]: нет name:test в '%s'\n", buf); fail = 1;
    }
    if (!strstr(buf, "\"rules\":3")) {
        fprintf(stderr, "FAIL [6]: нет rules:3 в '%s'\n", buf); fail = 1;
    }
    if (!strstr(buf, "\"loaded\":true")) {
        fprintf(stderr, "FAIL [6]: нет loaded:true в '%s'\n", buf); fail = 1;
    }
    if (!fail) printf("  [6] rule_provider_to_json PASS\n");
    return fail;
}

int main(void)
{
    int fail = 0;
    printf("=== test-rule-provider ===\n");
    fail += test_rule_provider_init_free();
    fail += test_rule_provider_owns_fd();
    fail += test_count_rules_empty_file();
    fail += test_count_rules_mixed();
    fail += test_rule_provider_load_tmpfile();
    fail += test_rule_provider_to_json();
    if (fail)
        printf("FAIL — %d/6 провалено\n", fail);
    else
        printf("PASS — 6/6 OK\n");
    return fail ? 1 : 0;
}

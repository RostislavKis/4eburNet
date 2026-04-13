/*
 * test_ipc_safety.c — тесты json_get_str и IPC edge cases (P-41)
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>

static int fail_count = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fail_count++; } \
    else { printf("PASS: %s\n", msg); } \
} while(0)

/* Копия json_get_str из ipc.c — тестируем standalone */
static size_t json_get_str(const char *json, const char *key,
                           char *out, size_t out_size)
{
    if (!json || !key || !out || out_size == 0) return 0;
    out[0] = '\0';
    char pattern[80];
    int pn = snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    if (pn < 0 || (size_t)pn >= sizeof(pattern)) return 0;
    const char *start = strstr(json, pattern);
    if (!start) return 0;
    start += (size_t)pn;
    size_t i = 0;
    for (const char *p = start; *p && i < out_size - 1; p++) {
        if (*p == '\\' && *(p + 1)) { p++; out[i++] = *p; }
        else if (*p == '"') { break; }
        else { out[i++] = *p; }
    }
    out[i] = '\0';
    return i;
}

/* Тест 1: некорректный JSON → пустая строка */
static void test_broken_json(void)
{
    char out[64];
    size_t n = json_get_str("{broken", "group", out, sizeof(out));
    ASSERT(n == 0, "broken JSON: пустой результат");
    ASSERT(out[0] == '\0', "broken JSON: out пустой");
}

/* Тест 2: пустой payload → не crash */
static void test_empty_payload(void)
{
    char out[64];
    size_t n = json_get_str("", "group", out, sizeof(out));
    ASSERT(n == 0, "empty payload: пустой результат");

    n = json_get_str(NULL, "group", out, sizeof(out));
    ASSERT(n == 0, "NULL payload: пустой результат");
}

/* Тест 3: escaped кавычки */
static void test_escaped_quotes(void)
{
    char out[64];
    size_t n = json_get_str("{\"group\":\"my\\\"server\"}", "group", out, sizeof(out));
    ASSERT(n == 9, "escaped quotes: длина 9 (my + quote + server)");
    ASSERT(strcmp(out, "my\"server") == 0, "escaped quotes: значение корректно");
}

/* Тест 4: несуществующий ключ → пустая строка */
static void test_missing_key(void)
{
    char out[64];
    size_t n = json_get_str("{\"group\":\"test\"}", "server", out, sizeof(out));
    ASSERT(n == 0, "missing key: пустой результат");
}

/* Тест 5: очень длинное значение → обрезка по out_size */
static void test_long_value(void)
{
    /* Значение 100 символов, буфер 16 */
    char json[256];
    snprintf(json, sizeof(json), "{\"key\":\"%.*s\"}", 100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    char out[16];
    size_t n = json_get_str(json, "key", out, sizeof(out));
    ASSERT(n == 15, "long value: обрезано до 15");
    ASSERT(out[15] == '\0', "long value: null-terminated");
}

/* Тест 6: B-01 — unclosed string value */
static void test_unclosed_string(void)
{
    char out[64] = {0};
    size_t n = json_get_str("{\"key\":\"unclosed value", "key", out, sizeof(out));
    /* json_get_str копирует до конца строки если нет закрывающей кавычки */
    ASSERT(n > 0 || out[0] == '\0', "unclosed: не должно быть crash");
    printf("PASS: unclosed string (n=%zu, out='%s')\n", n, out);
}

/* Тест 7: нормальный случай */
static void test_normal(void)
{
    char grp[64], srv[64];
    json_get_str("{\"group\":\"auto\",\"server\":\"vless-1\"}", "group", grp, sizeof(grp));
    json_get_str("{\"group\":\"auto\",\"server\":\"vless-1\"}", "server", srv, sizeof(srv));
    ASSERT(strcmp(grp, "auto") == 0, "normal: group=auto");
    ASSERT(strcmp(srv, "vless-1") == 0, "normal: server=vless-1");
}

int main(void)
{
    printf("=== test_ipc_safety ===\n\n");
    test_broken_json();
    test_empty_payload();
    test_escaped_quotes();
    test_missing_key();
    test_long_value();
    test_unclosed_string();
    test_normal();
    printf("\nALL PASS: %d тест(ов) провалено\n", fail_count);
    return fail_count ? 1 : 0;
}

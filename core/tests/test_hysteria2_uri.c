/*
 * Тест парсера hysteria2:// URI — контракт перед реализацией B.6
 * Компилируется без wolfSSL.
 *
 * Формат URI (официальный spec):
 *   hysteria2://[password@]host:port[?params][#name]
 *   hy2://...   — псевдоним
 *
 * Параметры:
 *   obfs=salamander       — включить Salamander obfuscation
 *   obfs-password=...     — пароль obfs (только при obfs=salamander)
 *   sni=...               — TLS SNI override
 *   insecure=1            — пропустить TLS верификацию
 *   up=N / down=N         — bandwidth hints (Мбит/с)
 *
 * #fragment → игнорируется (имя сервера — не часть hysteria2_config_t)
 */

#define CONFIG_EBURNET_QUIC 1
#include "proxy/hysteria2.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

/* Заглушка логгера (hysteria2.h тянет 4eburnet.h → log_msg) */
void log_msg(int level, const char *fmt, ...) {
    (void)level;
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n");
}

/* Заглушка net_random_bytes для тестов */
void net_random_bytes(void *buf, size_t len) { memset(buf, 0xAB, len); }

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", (msg)); failures++; } \
    else         { printf("PASS: %s\n", (msg)); } \
} while(0)

/* ── Тест 1: минимальный URI ─────────────────────────────────────── */
static void test_basic(void)
{
    hysteria2_config_t cfg;
    int rc = hy2_parse_uri("hysteria2://secret@example.com:443", &cfg);

    CHECK(rc == 0,                              "basic: rc == 0");
    CHECK(strcmp(cfg.password, "secret") == 0,  "basic: password");
    CHECK(strcmp(cfg.server_addr, "example.com") == 0, "basic: server_addr");
    CHECK(cfg.server_port == 443,               "basic: server_port");
    CHECK(!cfg.insecure,                        "basic: insecure = false");
    CHECK(!cfg.obfs_enabled,                    "basic: obfs = off");
}

/* ── Тест 2: схема hy2:// — псевдоним hysteria2:// ──────────────── */
static void test_hy2_alias(void)
{
    hysteria2_config_t cfg;
    int rc = hy2_parse_uri("hy2://pass123@10.0.0.1:8080", &cfg);

    CHECK(rc == 0,                              "hy2 alias: rc == 0");
    CHECK(strcmp(cfg.password, "pass123") == 0, "hy2 alias: password");
    CHECK(strcmp(cfg.server_addr, "10.0.0.1") == 0, "hy2 alias: server_addr");
    CHECK(cfg.server_port == 8080,              "hy2 alias: server_port");
}

/* ── Тест 3: Salamander obfuscation ─────────────────────────────── */
static void test_salamander(void)
{
    hysteria2_config_t cfg;
    int rc = hy2_parse_uri(
        "hysteria2://auth@vpn.example.com:443"
        "?obfs=salamander&obfs-password=my_obfs_pass",
        &cfg);

    CHECK(rc == 0,                                   "salamander: rc == 0");
    CHECK(cfg.obfs_enabled,                          "salamander: obfs_enabled");
    CHECK(strcmp(cfg.obfs_password, "my_obfs_pass") == 0,
          "salamander: obfs_password");
    CHECK(strcmp(cfg.password, "auth") == 0,         "salamander: password");
}

/* ── Тест 4: SNI override + insecure ────────────────────────────── */
static void test_sni_insecure(void)
{
    hysteria2_config_t cfg;
    int rc = hy2_parse_uri(
        "hysteria2://pw@1.2.3.4:4430?sni=cdn.example.com&insecure=1",
        &cfg);

    CHECK(rc == 0,                                    "sni: rc == 0");
    CHECK(strcmp(cfg.sni, "cdn.example.com") == 0,    "sni: sni field");
    CHECK(cfg.insecure,                               "sni: insecure = true");
    CHECK(strcmp(cfg.server_addr, "1.2.3.4") == 0,   "sni: server_addr = IP");
}

/* ── Тест 5: bandwidth hints ─────────────────────────────────────── */
static void test_bandwidth(void)
{
    hysteria2_config_t cfg;
    int rc = hy2_parse_uri(
        "hysteria2://pw@srv.net:443?up=100&down=500",
        &cfg);

    CHECK(rc == 0,              "bw: rc == 0");
    CHECK(cfg.up_mbps == 100,   "bw: up_mbps = 100");
    CHECK(cfg.down_mbps == 500, "bw: down_mbps = 500");
}

/* ── Тест 6: #fragment (имя сервера) — разобрать без ошибки ─────── */
static void test_name_fragment(void)
{
    hysteria2_config_t cfg;
    int rc = hy2_parse_uri(
        "hysteria2://secret@host.com:443#MyProxyServer",
        &cfg);

    CHECK(rc == 0,                                    "fragment: rc == 0");
    CHECK(strcmp(cfg.server_addr, "host.com") == 0,   "fragment: server_addr");
    CHECK(strcmp(cfg.password, "secret") == 0,        "fragment: password");
    /* fragment — только для UI, в hysteria2_config_t не хранится */
}

/* ── Тест 7: percent-encoded пароль ─────────────────────────────── */
static void test_encoded_password(void)
{
    hysteria2_config_t cfg;
    /* "p@ss:w/rd" → "p%40ss%3Aw%2Frd" */
    int rc = hy2_parse_uri(
        "hysteria2://p%40ss%3Aw%2Frd@host.com:443",
        &cfg);

    CHECK(rc == 0,                                       "encoded: rc == 0");
    CHECK(strcmp(cfg.password, "p@ss:w/rd") == 0,        "encoded: password decoded");
}

/* ── Тест 8: полный URI со всеми параметрами ─────────────────────── */
static void test_full_uri(void)
{
    hysteria2_config_t cfg;
    int rc = hy2_parse_uri(
        "hysteria2://SuperSecret@vpn.example.org:8443"
        "?obfs=salamander&obfs-password=ObfsKey"
        "&sni=real.host.net&insecure=0"
        "&up=50&down=200"
        "#HomeVPN",
        &cfg);

    CHECK(rc == 0,                                         "full: rc == 0");
    CHECK(strcmp(cfg.password, "SuperSecret") == 0,        "full: password");
    CHECK(strcmp(cfg.server_addr, "vpn.example.org") == 0, "full: server_addr");
    CHECK(cfg.server_port == 8443,                         "full: server_port");
    CHECK(cfg.obfs_enabled,                                "full: obfs_enabled");
    CHECK(strcmp(cfg.obfs_password, "ObfsKey") == 0,       "full: obfs_password");
    CHECK(strcmp(cfg.sni, "real.host.net") == 0,           "full: sni");
    CHECK(!cfg.insecure,                                   "full: insecure=0");
    CHECK(cfg.up_mbps == 50,                               "full: up_mbps");
    CHECK(cfg.down_mbps == 200,                            "full: down_mbps");
}

/* ── Тест 9: невалидные URI → rc != 0 ────────────────────────────── */
static void test_invalid(void)
{
    hysteria2_config_t cfg;

    /* Неверная схема */
    CHECK(hy2_parse_uri("vless://pw@host:443", &cfg) != 0,
          "invalid: wrong scheme");

    /* Нет пароля (userinfo отсутствует) */
    CHECK(hy2_parse_uri("hysteria2://host.com:443", &cfg) != 0,
          "invalid: no password");

    /* Нет порта */
    CHECK(hy2_parse_uri("hysteria2://pw@host.com", &cfg) != 0,
          "invalid: no port");

    /* NULL URI */
    CHECK(hy2_parse_uri(NULL, &cfg) != 0,
          "invalid: NULL uri");

    /* NULL cfg */
    CHECK(hy2_parse_uri("hysteria2://pw@host.com:443", NULL) != 0,
          "invalid: NULL cfg");

    /* Порт 0 */
    CHECK(hy2_parse_uri("hysteria2://pw@host.com:0", &cfg) != 0,
          "invalid: port 0");

    /* Порт > 65535 */
    CHECK(hy2_parse_uri("hysteria2://pw@host.com:99999", &cfg) != 0,
          "invalid: port > 65535");
}

int main(void)
{
    printf("=== hysteria2:// URI parser tests ===\n\n");
    test_basic();
    test_hy2_alias();
    test_salamander();
    test_sni_insecure();
    test_bandwidth();
    test_name_fragment();
    test_encoded_password();
    test_full_uri();
    test_invalid();

    printf("\n%s: %d тест(ов) провалено\n",
           failures == 0 ? "ALL PASS" : "FAILED", failures);
    return failures;
}

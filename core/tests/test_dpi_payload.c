/*
 * Тест dpi_payload.c (C.2)
 * Нативная генерация fake TLS ClientHello + QUIC Initial
 */
#define CONFIG_EBURNET_DPI 1
#include "dpi/dpi_payload.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

void log_msg(int level, const char *fmt, ...) {
    (void)level;
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n");
}

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", (msg)); failures++; } \
    else         { printf("PASS: %s\n", (msg)); } \
} while(0)

/* Тест 1: TLS ClientHello — структура */
static void test_tls_clienthello(void)
{
    uint8_t buf[1024];
    int len = dpi_make_tls_clienthello(buf, sizeof(buf), "www.google.com");

    CHECK(len > 0,               "tls: len > 0");
    CHECK(len >= 100,            "tls: минимальный размер (100 байт)");
    CHECK(buf[0] == 0x16,        "tls: ContentType = Handshake (0x16)");
    CHECK(buf[1] == 0x03,        "tls: Version major = 3");
    CHECK(buf[5] == 0x01,        "tls: HandshakeType = ClientHello (0x01)");

    /* Проверить что SNI присутствует в пакете */
    const uint8_t *p = (const uint8_t *)memmem(buf, (size_t)len,
                                                 "www.google.com", 14);
    CHECK(p != NULL, "tls: SNI 'www.google.com' присутствует в пакете");

    /* key_share x25519 не должен быть нулевым — DPI-fingerprint сигнал */
    static const uint8_t ks_marker[] = {0x00, 0x1d, 0x00, 0x20};
    const uint8_t *ks = (const uint8_t *)memmem(buf, (size_t)len, ks_marker, 4);
    if (ks) {
        const uint8_t *key = ks + 4;
        int all_zero = 1;
        for (int i = 0; i < 32; i++) if (key[i]) { all_zero = 0; break; }
        CHECK(!all_zero, "tls: key_share x25519 не нулевой");
    } else {
        printf("SKIP: key_share marker не найден\n");
    }
}

/* Тест 2: TLS — два вызова дают разные Random */
static void test_tls_random(void)
{
    uint8_t buf1[512], buf2[512];
    dpi_make_tls_clienthello(buf1, sizeof(buf1), "www.google.com");
    dpi_make_tls_clienthello(buf2, sizeof(buf2), "www.google.com");

    /* Random field: байты 11..42 (32 байта) */
    CHECK(memcmp(buf1 + 11, buf2 + 11, 32) != 0,
          "tls: Random поле отличается при каждом вызове");
}

/* Тест 3: TLS — разные SNI дают разные пакеты */
static void test_tls_sni_varies(void)
{
    uint8_t buf1[512], buf2[512];
    int l1 = dpi_make_tls_clienthello(buf1, sizeof(buf1), "www.google.com");
    int l2 = dpi_make_tls_clienthello(buf2, sizeof(buf2), "example.com");

    CHECK(l1 > 0 && l2 > 0, "tls: разные SNI — оба успешны");

    const uint8_t *p = (const uint8_t *)memmem(buf2, (size_t)l2,
                                                 "example.com", 11);
    CHECK(p != NULL, "tls: SNI 'example.com' присутствует");
}

/* Тест 4: QUIC Initial — структура */
static void test_quic_initial(void)
{
    uint8_t buf[1280];
    int len = dpi_make_quic_initial(buf, sizeof(buf));

    CHECK(len > 0,            "quic: len > 0");
    CHECK(len >= 1200,        "quic: минимум 1200 байт (QUIC padding requirement)");
    CHECK((buf[0] & 0x80),    "quic: Long Header bit (bit 7 = 1)");
    CHECK(buf[1] == 0x00 && buf[2] == 0x00 &&
          buf[3] == 0x00 && buf[4] == 0x01, "quic: Version = 0x00000001 (QUIC v1)");
}

/* Тест 5: QUIC — два вызова дают разные Connection ID */
static void test_quic_connid_random(void)
{
    uint8_t buf1[1280], buf2[1280];
    dpi_make_quic_initial(buf1, sizeof(buf1));
    dpi_make_quic_initial(buf2, sizeof(buf2));

    /* DCIL байт 5, DCID байты 6..(6+DCIL-1) */
    int dcil = buf1[5];
    if (dcil > 0 && dcil <= 20) {
        CHECK(memcmp(buf1 + 6, buf2 + 6, (size_t)dcil) != 0,
              "quic: DCID отличается при каждом вызове");
    } else {
        printf("SKIP: quic DCID random (DCIL=%d)\n", dcil);
    }
}

/* Тест 6: буфер слишком мал → -1 */
static void test_buffer_too_small(void)
{
    uint8_t small[10];
    CHECK(dpi_make_tls_clienthello(small, sizeof(small), "www.google.com") == -1,
          "tls: buf_size=10 → -1");
    CHECK(dpi_make_quic_initial(small, sizeof(small)) == -1,
          "quic: buf_size=10 → -1");
}

/* Тест 7: NULL buf → -1 */
static void test_null_buf(void)
{
    CHECK(dpi_make_tls_clienthello(NULL, 512, "www.google.com") == -1,
          "tls: NULL buf → -1");
    CHECK(dpi_make_quic_initial(NULL, 1280) == -1,
          "quic: NULL buf → -1");
}

int main(void)
{
    printf("=== dpi_payload tests ===\n\n");
    test_tls_clienthello();
    test_tls_random();
    test_tls_sni_varies();
    test_quic_initial();
    test_quic_connid_random();
    test_buffer_too_small();
    test_null_buf();
    printf("\n%s: %d тест(ов) провалено\n",
           failures == 0 ? "ALL PASS" : "FAILED", failures);
    return failures;
}

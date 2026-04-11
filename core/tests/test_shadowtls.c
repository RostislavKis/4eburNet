/*
 * test_shadowtls.c — тесты ShadowTLS v3 wrap/unwrap + session_id (D.2)
 */

#include "proxy/shadowtls.h"
#include "crypto/hmac_sha256.h"
#include "dpi/dpi_payload.h"
#include <stdio.h>
#include <string.h>

static int fail_count = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fail_count++; } \
    else { printf("PASS: %s\n", msg); } \
} while(0)

/* Тест 1: stls_ctx_init */
static void test_ctx_init(void)
{
    shadowtls_ctx_t ctx;
    stls_ctx_init(&ctx, "test-password");
    ASSERT(ctx.state == STLS_INIT, "ctx_init: state = INIT");
    ASSERT(ctx.password_len == 13, "ctx_init: password_len = 13");
    ASSERT(memcmp(ctx.password, "test-password", 13) == 0,
           "ctx_init: password скопирован");
    ASSERT(ctx.send_counter == 0, "ctx_init: send_counter = 0");
    ASSERT(ctx.recv_counter == 0, "ctx_init: recv_counter = 0");
}

/* Тест 2: SessionID = HMAC(password, client_random) */
static void test_session_id(void)
{
    uint8_t password[] = "my-secret-psk";
    uint8_t client_random[32];
    memset(client_random, 0xAA, 32);

    /* Вычислить SessionID вручную */
    uint8_t expected[32];
    hmac_sha256(password, 13, client_random, 32, expected);

    /* dpi_make_tls_clienthello_ex с session_id = expected должен содержать
     * эти байты в позиции SessionID (offset 44 от начала record:
     * record_hdr(5) + handshake_hdr(4) + version(2) + random(32) + sid_len(1) = 44) */
    uint8_t buf[768];
    int len = dpi_make_tls_clienthello_ex(buf, sizeof(buf),
                                           "example.com",
                                           client_random, expected, NULL);
    ASSERT(len > 44 + 32, "session_id: ClientHello достаточно длинный");
    ASSERT(memcmp(buf + 44, expected, 32) == 0,
           "session_id: SessionID = HMAC(pwd, random) на правильной позиции");
}

/* Тест 3: wrap + unwrap roundtrip */
static void test_wrap_unwrap(void)
{
    shadowtls_ctx_t send_ctx, recv_ctx;
    stls_ctx_init(&send_ctx, "shared-secret");
    stls_ctx_init(&recv_ctx, "shared-secret");

    uint8_t data[] = "Hello ShadowTLS v3!";
    int data_len = (int)strlen((char *)data);

    uint8_t record[256];
    int rec_len = stls_wrap(&send_ctx, data, data_len, record, sizeof(record));
    ASSERT(rec_len == 5 + 4 + data_len, "wrap: длина = hdr(5) + tag(4) + data");
    ASSERT(record[0] == 0x17, "wrap: ContentType = AppData (0x17)");
    ASSERT(record[1] == 0x03 && record[2] == 0x03, "wrap: version = TLS 1.2");

    uint8_t out[256];
    int out_len = stls_unwrap(&recv_ctx, record, rec_len, out, sizeof(out));
    ASSERT(out_len == data_len, "unwrap: длина данных совпадает");
    ASSERT(memcmp(out, data, (size_t)data_len) == 0,
           "unwrap: данные совпадают");
}

/* Тест 4: counter increment — два wrap дают разные теги */
static void test_counter_increment(void)
{
    shadowtls_ctx_t ctx;
    stls_ctx_init(&ctx, "secret");

    uint8_t data[] = "same data";
    int data_len = 9;

    uint8_t rec1[64], rec2[64];
    int len1 = stls_wrap(&ctx, data, data_len, rec1, sizeof(rec1));
    int len2 = stls_wrap(&ctx, data, data_len, rec2, sizeof(rec2));

    ASSERT(len1 == len2, "counter: одинаковая длина");
    /* Теги (байты 5..8) должны отличаться (разные counters) */
    ASSERT(memcmp(rec1 + 5, rec2 + 5, 4) != 0,
           "counter: HMAC теги разные (counter++)");
    ASSERT(ctx.send_counter == 2, "counter: send_counter = 2");
}

/* Тест 5: unwrap с повреждённым тегом → -1 */
static void test_unwrap_invalid_tag(void)
{
    shadowtls_ctx_t send_ctx, recv_ctx;
    stls_ctx_init(&send_ctx, "secret");
    stls_ctx_init(&recv_ctx, "secret");

    uint8_t data[] = "test";
    uint8_t record[64];
    int rec_len = stls_wrap(&send_ctx, data, 4, record, sizeof(record));
    ASSERT(rec_len > 0, "invalid_tag: wrap OK");

    /* Повредить тег */
    record[5] ^= 0xFF;

    uint8_t out[64];
    int out_len = stls_unwrap(&recv_ctx, record, rec_len, out, sizeof(out));
    ASSERT(out_len == -1, "invalid_tag: unwrap отклонил повреждённый тег");
}

/* Тест 6: unwrap с неправильным паролем → -1 */
static void test_unwrap_wrong_password(void)
{
    shadowtls_ctx_t send_ctx, recv_ctx;
    stls_ctx_init(&send_ctx, "correct");
    stls_ctx_init(&recv_ctx, "wrong");

    uint8_t data[] = "data";
    uint8_t record[64];
    int rec_len = stls_wrap(&send_ctx, data, 4, record, sizeof(record));

    uint8_t out[64];
    int out_len = stls_unwrap(&recv_ctx, record, rec_len, out, sizeof(out));
    ASSERT(out_len == -1, "wrong_password: unwrap отклонил чужой пароль");
}

int main(void)
{
    printf("=== test_shadowtls ===\n\n");

    test_ctx_init();
    test_session_id();
    test_wrap_unwrap();
    test_counter_increment();
    test_unwrap_invalid_tag();
    test_unwrap_wrong_password();

    printf("\nALL PASS: %d тест(ов) провалено\n", fail_count);
    return fail_count ? 1 : 0;
}

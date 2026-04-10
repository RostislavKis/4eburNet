/*
 * Тест UDP message encode/decode — контракт перед реализацией B.4
 * Компилируется без wolfSSL (только утилитные функции).
 */

#define CONFIG_EBURNET_QUIC 1
#include "proxy/hysteria2_udp.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

void log_msg(int level, const char *fmt, ...)
{
    (void)level;
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n");
}

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", (msg)); failures++; } \
    else         { printf("PASS: %s\n", (msg)); } \
} while(0)

/* ── 1. Encode + decode roundtrip без фрагментации ───────────────────── */

static void test_udp_msg_roundtrip(void)
{
    uint8_t buf[512];
    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};

    int n = hy2_udp_msg_encode(buf, sizeof(buf),
                                0xDEADBEEF,       /* session_id */
                                42,               /* packet_id */
                                0, 1,             /* frag_id=0, frag_count=1 */
                                "8.8.8.8", 53,
                                data, sizeof(data));
    CHECK(n > 0, "udp_msg_encode OK");

    hy2_udp_msg_t msg;
    int consumed = hy2_udp_msg_decode(buf, (size_t)n, &msg, NULL, 0);
    CHECK(consumed == n,              "udp_msg_decode потребил все байты");
    CHECK(msg.session_id == 0xDEADBEEF, "session_id верный");
    CHECK(msg.packet_id  == 42,         "packet_id верный");
    CHECK(msg.frag_id    == 0,          "frag_id=0");
    CHECK(msg.frag_count == 1,          "frag_count=1");
    CHECK(msg.data_len   == sizeof(data), "data_len верный");
    CHECK(strcmp(msg.host, "8.8.8.8") == 0, "host верный после decode");
    CHECK(msg.port == 53,                   "port верный после decode");
}

/* ── 2. Фрагментация — frag_id=2, frag_count=3 ───────────────────────── */

static void test_udp_fragmentation(void)
{
    uint8_t buf[256];
    int n = hy2_udp_msg_encode(buf, sizeof(buf),
                                0x1234, 7,
                                2, 3,             /* frag_id=2, frag_count=3 */
                                "example.com", 80,
                                (uint8_t[]){0xAA, 0xBB}, 2);
    CHECK(n > 0, "frag encode OK");

    hy2_udp_msg_t msg;
    hy2_udp_msg_decode(buf, (size_t)n, &msg, NULL, 0);
    CHECK(msg.frag_id    == 2, "frag_id=2");
    CHECK(msg.frag_count == 3, "frag_count=3");
}

/* ── 3. Разбиение большого пакета на фрагменты ───────────────────────── */

static void test_udp_fragment_split(void)
{
    /* Данные размером > HY2_UDP_FRAG_PAYLOAD → несколько фрагментов */
    uint8_t big_data[2000];
    memset(big_data, 0xCC, sizeof(big_data));

    hy2_udp_fragment_t frags[HY2_UDP_MAX_FRAGS];
    uint8_t frag_bufs[HY2_UDP_MAX_FRAGS][HY2_UDP_FRAG_SIZE];

    int count = hy2_udp_fragment(0x5678, 1,
                                  "1.1.1.1", 53,
                                  big_data, sizeof(big_data),
                                  frags, frag_bufs,
                                  HY2_UDP_MAX_FRAGS);

    CHECK(count > 1,                    "2000 байт → несколько фрагментов");
    CHECK(count <= HY2_UDP_MAX_FRAGS,   "не превышен лимит фрагментов");

    /* Все фрагменты одинаковый frag_count */
    for (int i = 0; i < count; i++)
        CHECK(frags[i].frag_count == (uint8_t)count,
              "frag_count одинаков у всех фрагментов");

    /* frag_id последовательный */
    for (int i = 0; i < count; i++)
        CHECK(frags[i].frag_id == (uint8_t)i,
              "frag_id последовательный");

    /* Буфер каждого фрагмента не пуст */
    for (int i = 0; i < count; i++)
        CHECK(frags[i].buf_len > 0, "фрагмент не пустой");

    /* Декодировать первый фрагмент и проверить содержимое данных */
    hy2_udp_msg_t first_msg;
    int dc = hy2_udp_msg_decode(frags[0].buf, frags[0].buf_len,
                                 &first_msg, NULL, 0);
    CHECK(dc > 0, "decode первого фрагмента OK");
    CHECK(first_msg.data_len == HY2_UDP_FRAG_PAYLOAD,
          "первый фрагмент содержит HY2_UDP_FRAG_PAYLOAD байт");
    if (first_msg.data_len > 0)
        CHECK(first_msg.data[0] == 0xCC, "данные первого фрагмента = 0xCC");
}

/* ── 4. Decode с обрезанным буфером → -1 ────────────────────────────── */

static void test_udp_decode_truncated(void)
{
    /* Полный пакет, затем обрезаем до 4 байт */
    uint8_t buf[256];
    const uint8_t data[] = {0xAB};
    int n = hy2_udp_msg_encode(buf, sizeof(buf), 1, 1, 0, 1,
                                "a.com", 80, data, 1);
    (void)n;

    hy2_udp_msg_t msg;
    int rc = hy2_udp_msg_decode(buf, 4, &msg, NULL, 0);
    CHECK(rc == -1, "обрезанный буфер (4 байта) → -1");

    /* Нулевой буфер */
    rc = hy2_udp_msg_decode(NULL, 0, &msg, NULL, 0);
    CHECK(rc == -1, "NULL буфер → -1");
}

/* ── 5. Session manager ───────────────────────────────────────────────── */

static void test_udp_session_manager(void)
{
    hy2_udp_session_mgr_t mgr;
    hy2_udp_session_mgr_init(&mgr);

    int rc = hy2_udp_session_add(&mgr, 0xABCD1234, "google.com", 443);
    CHECK(rc == 0, "session_add OK");

    hy2_udp_session_t *s = hy2_udp_session_find(&mgr, 0xABCD1234);
    CHECK(s != NULL,                    "session_find нашёл");
    CHECK(strcmp(s->host, "google.com") == 0, "host корректный");
    CHECK(s->port == 443,               "port корректный");

    /* Несуществующая сессия */
    CHECK(hy2_udp_session_find(&mgr, 0x00000000) == NULL,
          "session_find несуществующий → NULL");

    /* Дубликат: должен обновить или вернуть 0 */
    rc = hy2_udp_session_add(&mgr, 0xABCD1234, "update.com", 80);
    CHECK(rc == 0, "session_add дубликат OK");

    hy2_udp_session_remove(&mgr, 0xABCD1234);
    CHECK(hy2_udp_session_find(&mgr, 0xABCD1234) == NULL,
          "session_find после remove → NULL");

    /* Добавить несколько */
    for (int i = 0; i < 10; i++) {
        char host[32];
        snprintf(host, sizeof(host), "host%d.test", i);
        hy2_udp_session_add(&mgr, (uint32_t)i, host, (uint16_t)(1000 + i));
    }
    s = hy2_udp_session_find(&mgr, 5);
    CHECK(s != NULL && s->port == 1005, "session_find из 10 сессий");

    hy2_udp_session_mgr_free(&mgr);
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(void)
{
    test_udp_msg_roundtrip();
    test_udp_fragmentation();
    test_udp_fragment_split();
    test_udp_decode_truncated();
    test_udp_session_manager();

    printf("\n%s: %d тест(ов) провалено\n",
           failures == 0 ? "ALL PASS" : "FAILED", failures);
    return failures;
}

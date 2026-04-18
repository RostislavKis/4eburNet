/*
 * test_sniffer.c — юнит-тесты sniffer_peek_sni() (3.6.3)
 *
 * Покрывает: корректный SNI, MSG_PEEK, не-TLS, TLS без SNI,
 * пустой сокет (EAGAIN), null-байт, усечение по размеру буфера.
 */

#include "proxy/sniffer.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

static int fail_count = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fail_count++; } \
    else          { printf("PASS: %s\n", msg); } \
} while (0)

/*
 * Строит минимальный TLS ClientHello с одним SNI extension.
 * sni_data/sni_len — сырые байты имени (может содержать \0 для теста 6).
 * Если sni_len == 0 — собирает ClientHello без extensions.
 * Возвращает длину пакета в out.
 */
static size_t build_clienthello(const uint8_t *sni_data, size_t sni_len,
                                uint8_t *out, size_t out_size)
{
    uint8_t tmp[512];
    size_t pos = 9;   /* пропускаем record(5) + hs_header(4) — заполним в конце */

    /* ClientHello body */
    /* version: TLS 1.2 */
    tmp[pos++] = 0x03; tmp[pos++] = 0x03;
    /* random: 32 нулевых байта */
    memset(tmp + pos, 0, 32); pos += 32;
    /* session_id_len: 0 */
    tmp[pos++] = 0x00;
    /* cipher_suites_len: 2 байта, один suite */
    tmp[pos++] = 0x00; tmp[pos++] = 0x02;
    tmp[pos++] = 0x00; tmp[pos++] = 0x2F;  /* TLS_RSA_WITH_AES_128_CBC_SHA */
    /* compression_methods_len: 1, null */
    tmp[pos++] = 0x01; tmp[pos++] = 0x00;

    if (sni_len > 0) {
        /*
         * SNI extension layout (RFC 6066):
         *   ext_type(2) ext_data_len(2)
         *     ServerNameList len(2)
         *       name_type(1=0x00) name_len(2) name_bytes
         */
        uint16_t name_len_u16  = (uint16_t)sni_len;
        uint16_t sni_list_len  = (uint16_t)(3 + sni_len);   /* type+len+name */
        uint16_t ext_data_len  = (uint16_t)(2 + sni_list_len); /* list_len field + list */
        uint16_t ext_total     = (uint16_t)(4 + ext_data_len); /* type(2)+len(2)+data */

        /* extensions_total */
        tmp[pos++] = (uint8_t)(ext_total >> 8);
        tmp[pos++] = (uint8_t)(ext_total & 0xFF);
        /* SNI extension type 0x0000 */
        tmp[pos++] = 0x00; tmp[pos++] = 0x00;
        /* ext data len */
        tmp[pos++] = (uint8_t)(ext_data_len >> 8);
        tmp[pos++] = (uint8_t)(ext_data_len & 0xFF);
        /* ServerNameList len */
        tmp[pos++] = (uint8_t)(sni_list_len >> 8);
        tmp[pos++] = (uint8_t)(sni_list_len & 0xFF);
        /* name_type: host_name */
        tmp[pos++] = 0x00;
        /* name_len */
        tmp[pos++] = (uint8_t)(name_len_u16 >> 8);
        tmp[pos++] = (uint8_t)(name_len_u16 & 0xFF);
        /* name bytes */
        memcpy(tmp + pos, sni_data, sni_len);
        pos += sni_len;
    } else {
        /* Нет extensions */
        tmp[pos++] = 0x00; tmp[pos++] = 0x00;
    }

    /* Заполняем Handshake header */
    size_t hs_body_len = pos - 9;
    tmp[5] = 0x01;                                          /* ClientHello */
    tmp[6] = (uint8_t)(hs_body_len >> 16);
    tmp[7] = (uint8_t)(hs_body_len >> 8);
    tmp[8] = (uint8_t)(hs_body_len & 0xFF);

    /* Заполняем TLS Record header */
    uint16_t rec_len = (uint16_t)(4 + hs_body_len);
    tmp[0] = 0x16;                                          /* Handshake */
    tmp[1] = 0x03; tmp[2] = 0x01;                          /* TLS 1.0 legacy */
    tmp[3] = (uint8_t)(rec_len >> 8);
    tmp[4] = (uint8_t)(rec_len & 0xFF);

    if (pos > out_size) return 0;
    memcpy(out, tmp, pos);
    return pos;
}

/* Создаёт socketpair, пишет данные в fds[1], возвращает для чтения fds[0] */
static int write_to_socket(const uint8_t *data, size_t len, int fds[2])
{
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) return -1;
    ssize_t written = write(fds[1], data, len);
    return (written == (ssize_t)len) ? 0 : -1;
}

/* ------------------------------------------------------------------ */

static void test1_valid_sni(void)
{
    /* PASS: корректный ClientHello с SNI "example.com" */
    uint8_t pkt[256];
    const uint8_t *sni = (const uint8_t *)"example.com";
    size_t pkt_len = build_clienthello(sni, 11, pkt, sizeof(pkt));
    ASSERT(pkt_len > 0, "test1: build_clienthello вернул > 0");

    int fds[2];
    ASSERT(write_to_socket(pkt, pkt_len, fds) == 0, "test1: write_to_socket");

    char out[64] = {0};
    int ret = sniffer_peek_sni(fds[0], out, sizeof(out));

    ASSERT(ret == 11,                  "test1: возвращает длину 11");
    ASSERT(strcmp(out, "example.com") == 0, "test1: SNI == \"example.com\"");

    close(fds[0]); close(fds[1]);
}

static void test2_peek_preserves_data(void)
{
    /* PASS: MSG_PEEK — данные остаются в сокете после вызова */
    uint8_t pkt[256];
    const uint8_t *sni = (const uint8_t *)"peek.test";
    size_t pkt_len = build_clienthello(sni, 9, pkt, sizeof(pkt));

    int fds[2];
    ASSERT(write_to_socket(pkt, pkt_len, fds) == 0, "test2: write_to_socket");

    char out[64] = {0};
    sniffer_peek_sni(fds[0], out, sizeof(out));

    /* Читаем нормально — должны получить те же данные */
    uint8_t readbuf[256];
    ssize_t n = read(fds[0], readbuf, sizeof(readbuf));
    ASSERT(n == (ssize_t)pkt_len,           "test2: данные не потреблены (n == pkt_len)");
    ASSERT(memcmp(readbuf, pkt, pkt_len) == 0, "test2: содержимое совпадает");

    close(fds[0]); close(fds[1]);
}

static void test3_non_tls_data(void)
{
    /* PASS: не-TLS данные (HTTP GET) → 0 */
    const char *http = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    int fds[2];
    ASSERT(write_to_socket((const uint8_t *)http, strlen(http), fds) == 0,
           "test3: write_to_socket");

    char out[64] = {0};
    int ret = sniffer_peek_sni(fds[0], out, sizeof(out));
    ASSERT(ret == 0, "test3: не-TLS → возвращает 0");

    close(fds[0]); close(fds[1]);
}

static void test4_no_sni_extension(void)
{
    /* PASS: TLS ClientHello без SNI extension → 0 */
    uint8_t pkt[256];
    size_t pkt_len = build_clienthello(NULL, 0, pkt, sizeof(pkt));

    int fds[2];
    ASSERT(write_to_socket(pkt, pkt_len, fds) == 0, "test4: write_to_socket");

    char out[64] = {0};
    int ret = sniffer_peek_sni(fds[0], out, sizeof(out));
    ASSERT(ret == 0, "test4: без SNI → возвращает 0");

    close(fds[0]); close(fds[1]);
}

static void test5_empty_socket(void)
{
    /* PASS: пустой сокет — EAGAIN → 0 */
    int fds[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "test5: socketpair");

    char out[64] = {0};
    int ret = sniffer_peek_sni(fds[0], out, sizeof(out));
    ASSERT(ret == 0, "test5: пустой сокет → возвращает 0");

    close(fds[0]); close(fds[1]);
}

static void test6_null_byte_in_sni(void)
{
    /* PASS: null-байт в SNI — невалидный hostname (RFC 6066) → 0 */
    /* "exam\0le.com" — 11 байт, содержит \0 в позиции 4 */
    static const uint8_t bad_sni[] = "exam\x00le.com";  /* 11 байт с null */
    uint8_t pkt[256];
    size_t pkt_len = build_clienthello(bad_sni, 11, pkt, sizeof(pkt));

    int fds[2];
    ASSERT(write_to_socket(pkt, pkt_len, fds) == 0, "test6: write_to_socket");

    char out[64] = {0};
    int ret = sniffer_peek_sni(fds[0], out, sizeof(out));
    ASSERT(ret == 0, "test6: null-байт в SNI → возвращает 0");

    close(fds[0]); close(fds[1]);
}

static void test7_small_output_buffer(void)
{
    /* PASS: outlen=5, SNI "example.com" → усечение до "exam", возвращает 4 */
    uint8_t pkt[256];
    const uint8_t *sni = (const uint8_t *)"example.com";
    size_t pkt_len = build_clienthello(sni, 11, pkt, sizeof(pkt));

    int fds[2];
    ASSERT(write_to_socket(pkt, pkt_len, fds) == 0, "test7: write_to_socket");

    char out[5] = {0};
    int ret = sniffer_peek_sni(fds[0], out, sizeof(out));
    ASSERT(ret == 4,                  "test7: возвращает 4 (sni_buflen-1)");
    ASSERT(strcmp(out, "exam") == 0,  "test7: out == \"exam\"");

    close(fds[0]); close(fds[1]);
}

/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== test_sniffer ===\n\n");

    test1_valid_sni();
    test2_peek_preserves_data();
    test3_non_tls_data();
    test4_no_sni_extension();
    test5_empty_socket();
    test6_null_byte_in_sni();
    test7_small_output_buffer();

    printf("\n%s (%d провал(ов))\n",
           fail_count == 0 ? "OK" : "FAILED", fail_count);
    return fail_count == 0 ? 0 : 1;
}

/*
 * test_ja3.c — тесты JA3/JA4 fingerprint (v1.2-3)
 *
 * T1: ja3_is_grease — все 16 GREASE значений
 * T2: MD5("") — RFC 1321 контрольный вектор
 * T3: MD5("abc") — RFC 1321 контрольный вектор
 * T4: ja3_compute — формат и детерминизм
 * T5: ja3_match_reference — Chrome 120
 * T6: ja4_compute — формат строки
 * T7: sniffer_parse_hello — синтетический ClientHello через socketpair
 */

#define CONFIG_EBURNET_SNIFFER 1

#include "proxy/sniffer.h"
#include "proxy/ja3.h"
#include "crypto/tiny_md5.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_pass = 0, g_fail = 0;

#define ASSERT(cond, msg) do { \
    if (cond) { g_pass++; printf("  PASS: %s\n", (msg)); } \
    else      { g_fail++; printf("  FAIL: %s\n", (msg)); } \
} while (0)

/* T1: ja3_is_grease */
static void t1_grease(void)
{
    printf("T1: ja3_is_grease\n");
    static const uint16_t grease[16] = {
        0x0a0a,0x1a1a,0x2a2a,0x3a3a,0x4a4a,0x5a5a,0x6a6a,0x7a7a,
        0x8a8a,0x9a9a,0xaaaa,0xbaba,0xcaca,0xdada,0xeaea,0xfafa,
    };
    for (int i = 0; i < 16; i++)
        ASSERT(ja3_is_grease(grease[i]), "GREASE value detected");
    ASSERT(!ja3_is_grease(0x0000), "0x0000 не GREASE");
    ASSERT(!ja3_is_grease(0xC02B), "0xC02B не GREASE");
    ASSERT(!ja3_is_grease(0xffff), "0xffff не GREASE");
}

/* T2: MD5("") — RFC 1321 */
static void t2_md5_empty(void)
{
    printf("T2: tiny_md5_hex empty string\n");
    char hex[33];
    tiny_md5_hex("", hex);
    ASSERT(strcmp(hex, "d41d8cd98f00b204e9800998ecf8427e") == 0,
           "MD5(\"\") == RFC1321");
}

/* T3: MD5("abc") — RFC 1321 */
static void t3_md5_abc(void)
{
    printf("T3: tiny_md5_hex abc\n");
    char hex[33];
    tiny_md5_hex("abc", hex);
    ASSERT(strcmp(hex, "900150983cd24fb0d6963f7d28e17f72") == 0,
           "MD5(\"abc\") == RFC1321");
}

/* T4: ja3_compute — формат и детерминизм */
static void t4_ja3_format(void)
{
    printf("T4: ja3_compute format\n");
    ClientHelloInfo info = {0};
    info.tls_version   = 0x0303;       /* TLS 1.2 legacy = 771 */
    info.ciphers[0]    = 0xC02B;
    info.ciphers[1]    = 0xC02C;
    info.cipher_count  = 2;
    info.extensions[0] = 0x0000;
    info.extensions[1] = 0x000a;
    info.ext_count     = 2;
    info.groups[0]     = 0x001D;
    info.group_count   = 1;
    info.ecpf[0]       = 0x00;
    info.ecpf_count    = 1;

    char ja3[33]      = {0};
    char ja3_str[256] = {0};
    int rc = ja3_compute(&info, ja3, ja3_str, sizeof(ja3_str));

    ASSERT(rc == 0,                        "ja3_compute returns 0");
    ASSERT(strlen(ja3) == 32,              "JA3 — 32 hex символа");
    ASSERT(strncmp(ja3_str, "771,", 4) == 0, "JA3 строка начинается с tls_version");

    /* Детерминизм: повторный вызов → тот же хэш */
    char ja3b[33] = {0};
    ja3_compute(&info, ja3b, NULL, 0);
    ASSERT(strcmp(ja3, ja3b) == 0, "JA3 хэш детерминирован");

    /* Структура: ровно 4 запятые (5 блоков) */
    int commas = 0;
    for (const char *p = ja3_str; *p; p++) if (*p == ',') commas++;
    ASSERT(commas == 4, "JA3 строка содержит 4 запятые");
}

/* T5: ja3_match_reference */
static void t5_match_ref(void)
{
    printf("T5: ja3_match_reference\n");
    const char *name =
        ja3_match_reference("cd08e31494f9531f560d64c695473da9");
    ASSERT(name != NULL && strcmp(name, "Chrome 120") == 0, "Chrome 120 matched");
    ASSERT(ja3_match_reference(NULL) == NULL, "NULL hash → NULL");
    ASSERT(ja3_match_reference("") == NULL,   "empty hash → NULL");
    ASSERT(ja3_match_reference("00000000000000000000000000000000") == NULL,
           "unknown hash → NULL");
}

/* T6: ja4_compute — формат строки */
static void t6_ja4_format(void)
{
    printf("T6: ja4_compute format\n");
    ClientHelloInfo info = {0};
    info.tls_version       = 0x0303;
    info.supported_version = 0x0304;   /* TLS 1.3 */
    for (int i = 0; i < 5; i++)
        info.ciphers[i] = (uint16_t)(0x1301 + i);
    info.cipher_count  = 5;
    info.extensions[0] = 0x0000;
    info.extensions[1] = 0x000a;
    info.extensions[2] = 0x000b;
    info.ext_count     = 3;
    info.sni_found     = true;
    strncpy(info.sni, "test.example.com", sizeof(info.sni) - 1);
    memcpy(info.alpn, "h2", 3);
    info.alpn_found = true;

    char ja4[40] = {0};
    int rc = ja4_compute(&info, ja4);

    ASSERT(rc == 0,                       "ja4_compute returns 0");
    ASSERT(ja4[0] == 't',                 "JA4 начинается с 't'");
    ASSERT(strncmp(ja4, "t13d", 4) == 0, "JA4 префикс t13d");

    int underscores = 0;
    for (const char *p = ja4; *p; p++) if (*p == '_') underscores++;
    ASSERT(underscores == 2,       "JA4 содержит 2 разделителя '_'");
    ASSERT(strlen(ja4) == 36,      "JA4 длина == 36");
}

/* T7: sniffer_parse_hello через socketpair с реальным ClientHello */
static void t7_socketpair(void)
{
    printf("T7: sniffer_parse_hello socketpair\n");

    /* TLS ClientHello: version=0x0303, ciphers=[C02B,C02C],
     * SNI="example.com", groups=[x25519], ecpf=[uncompressed] */
    static const uint8_t hello[] = {
        /* TLS Record: type=Handshake, ver=TLS1.0, len=83 */
        0x16, 0x03, 0x01, 0x00, 0x53,
        /* Handshake: type=ClientHello, len=79 */
        0x01, 0x00, 0x00, 0x4F,
        /* ClientHello: legacy_version=TLS1.2 */
        0x03, 0x03,
        /* random (32 байта) */
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        /* session_id_len=0 */
        0x00,
        /* cipher_suites_len=4, suites=[C02B,C02C] */
        0x00, 0x04, 0xC0, 0x2B, 0xC0, 0x2C,
        /* compression_methods_len=1, method=null */
        0x01, 0x00,
        /* extensions_total_len=34 */
        0x00, 0x22,
        /* SNI: type=0000, ext_len=16 */
        0x00, 0x00, 0x00, 0x10,
        0x00, 0x0E,              /* ServerNameList.length=14 */
        0x00,                    /* name_type=host_name */
        0x00, 0x0B,              /* name_len=11 */
        'e','x','a','m','p','l','e','.','c','o','m',
        /* supported_groups: type=000a, ext_len=4, list_len=2, x25519 */
        0x00, 0x0A, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1D,
        /* ec_point_formats: type=000b, ext_len=2, count=1, uncompressed */
        0x00, 0x0B, 0x00, 0x02, 0x01, 0x00,
    };

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        printf("  SKIP: socketpair недоступен\n");
        return;
    }

    ssize_t sent = send(sv[1], hello, sizeof(hello), 0);
    ASSERT(sent == (ssize_t)sizeof(hello), "ClientHello отправлен");

    ClientHelloInfo *info = calloc(1, sizeof(ClientHelloInfo));
    ASSERT(info != NULL, "calloc ClientHelloInfo");

    if (info) {
        int rc = sniffer_parse_hello(sv[0], info);
        ASSERT(rc == 0,                               "sniffer_parse_hello == 0");
        ASSERT(info->tls_version == 0x0303,           "tls_version == 0x0303");
        ASSERT(info->sni_found,                       "SNI найден");
        ASSERT(strcmp(info->sni, "example.com") == 0, "SNI == example.com");
        ASSERT(info->cipher_count == 2,               "cipher_count == 2");
        ASSERT(info->ciphers[0] == 0xC02B,            "ciphers[0] == 0xC02B");
        ASSERT(info->ext_count == 3,                  "ext_count == 3");
        ASSERT(info->group_count == 1,                "group_count == 1");
        ASSERT(info->groups[0] == 0x001D,             "groups[0] == x25519");
        ASSERT(info->ecpf_count == 1,                 "ecpf_count == 1");
        ASSERT(info->ecpf[0] == 0x00,                 "ecpf[0] == uncompressed");
        free(info);
    }

    close(sv[0]);
    close(sv[1]);
}

int main(void)
{
    printf("=== test_ja3 ===\n");
    t1_grease();
    t2_md5_empty();
    t3_md5_abc();
    t4_ja3_format();
    t5_match_ref();
    t6_ja4_format();
    t7_socketpair();
    printf("\n%d/%d PASS\n", g_pass, g_pass + g_fail);
    return g_fail ? 1 : 0;
}

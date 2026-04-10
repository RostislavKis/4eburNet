/*
 * Тест varint и TCPRequest/TCPResponse функций из hysteria2.c
 * Компилируется без wolfSSL — только утилитные функции.
 */

/* Отключаем wolfSSL части через предопределённый флаг */
#define CONFIG_EBURNET_QUIC 1

/* hysteria2.h не включает wolfssl — они только в hysteria2.c */

#include "proxy/hysteria2.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

/* Заглушка log_msg — нужна для линковки hysteria2.c */
void log_msg(int level, const char *fmt, ...)
{
    (void)level;
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

/* ── Тест varint encode/decode ───────────────────────────────────────── */

static int test_varint_roundtrip(void)
{
    const uint64_t cases[] = {
        0, 1, 0x3F,                          /* 1-байтные */
        0x40, 0x100, 0x3FFF,                 /* 2-байтные */
        0x4000, 0x10000, 0x3FFFFFFF,         /* 4-байтные */
        0x40000000, 0x3FFFFFFFFFFFFFFF,      /* 8-байтные */
        0x401,                               /* FrameTypeTCPRequest */
        0x402,                               /* FrameTypeTCPResponse */
    };

    int failures = 0;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        uint64_t v = cases[i];
        uint8_t  buf[8];
        int      enc = hy2_varint_encode(buf, sizeof(buf), v);
        if (enc < 0) {
            printf("FAIL varint_encode(%llu): вернул -1\n", (unsigned long long)v);
            failures++;
            continue;
        }
        uint64_t got = 0;
        int dec = hy2_varint_decode(buf, (size_t)enc, &got);
        if (dec < 0 || got != v) {
            printf("FAIL varint roundtrip %llu: enc=%d dec=%d got=%llu\n",
                   (unsigned long long)v, enc, dec, (unsigned long long)got);
            failures++;
        }
    }
    if (!failures) printf("PASS: varint encode/decode roundtrip (%zu значений)\n",
                          sizeof(cases)/sizeof(cases[0]));
    return failures;
}

/* ── Тест длин varint ────────────────────────────────────────────────── */

static int test_varint_lengths(void)
{
    struct { uint64_t v; int expected_len; } cases[] = {
        { 0,                          1 },
        { 0x3F,                       1 },
        { 0x40,                       2 },
        { 0x3FFF,                     2 },
        { 0x4000,                     4 },
        { 0x3FFFFFFF,                 4 },
        { 0x40000000,                 8 },
        { 0x3FFFFFFFFFFFFFFF,         8 },
        { 0x401,                      2 },  /* TCP request frame type */
    };

    int failures = 0;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        uint8_t buf[8];
        int len = hy2_varint_encode(buf, sizeof(buf), cases[i].v);
        if (len != cases[i].expected_len) {
            printf("FAIL varint_len(%llu): ожидалось %d, получено %d\n",
                   (unsigned long long)cases[i].v, cases[i].expected_len, len);
            failures++;
        }
    }
    if (!failures) printf("PASS: varint длины\n");
    return failures;
}

/* ── Тест буфер слишком мал ──────────────────────────────────────────── */

static int test_varint_buf_too_small(void)
{
    uint8_t buf[1];
    /* 2-байтное значение в 1-байтный буфер */
    if (hy2_varint_encode(buf, 1, 0x40) != -1) {
        printf("FAIL: encode 0x40 в buf[1] должно вернуть -1\n");
        return 1;
    }
    /* decode из пустого буфера */
    uint64_t out;
    if (hy2_varint_decode(buf, 0, &out) != -1) {
        printf("FAIL: decode из buf_size=0 должно вернуть -1\n");
        return 1;
    }
    printf("PASS: varint граничные случаи (маленький буфер)\n");
    return 0;
}

/* ── Тест TCPRequest encode ──────────────────────────────────────────── */

static int test_tcp_request_encode(void)
{
    uint8_t  buf[1024];
    const char *host = "example.com";
    uint16_t port    = 443;

    /* padding = 100 байт (фиксированный для детерминированности) */
    int n = hy2_tcp_request_encode(buf, sizeof(buf), host, port, 100);
    if (n < 0) {
        printf("FAIL tcp_request_encode: вернул -1\n");
        return 1;
    }

    /* Разобрать вручную */
    uint8_t *p = buf;

    /* FrameType = 0x401 */
    uint64_t ftype;
    int step = hy2_varint_decode(p, (size_t)(buf + n - p), &ftype);
    if (step < 0 || ftype != HY2_FRAME_TCP_REQUEST) {
        printf("FAIL tcp_request: неверный FrameType %llu\n",
               (unsigned long long)ftype);
        return 1;
    }
    p += step;

    /* AddrLen */
    uint64_t addr_len;
    step = hy2_varint_decode(p, (size_t)(buf + n - p), &addr_len);
    if (step < 0) { printf("FAIL tcp_request: AddrLen decode\n"); return 1; }
    p += step;

    /* Addr = "example.com:443" */
    char expected_addr[] = "example.com:443";
    if (addr_len != strlen(expected_addr) ||
        memcmp(p, expected_addr, addr_len) != 0) {
        char got[64] = {0};
        memcpy(got, p, addr_len < 63 ? addr_len : 63);
        printf("FAIL tcp_request: addr='%s', ожидалось '%s'\n",
               got, expected_addr);
        return 1;
    }
    p += addr_len;

    /* PaddingLen = 100 */
    if (buf + n - p < 2) { printf("FAIL tcp_request: нет PaddingLen\n"); return 1; }
    uint16_t pad_len = (uint16_t)((p[0] << 8) | p[1]);
    if (pad_len != 100) {
        printf("FAIL tcp_request: PaddingLen=%u, ожидалось 100\n", pad_len);
        return 1;
    }
    p += 2 + pad_len;

    if (p != buf + n) {
        printf("FAIL tcp_request: лишние байты в конце (%td)\n", buf + n - p);
        return 1;
    }

    printf("PASS: tcp_request_encode (host=%s port=%u pad=100 total=%d байт)\n",
           host, port, n);
    return 0;
}

/* ── Тест TCPResponse decode ─────────────────────────────────────────── */

static int test_tcp_response_decode_ok(void)
{
    /* Построить вручную: FrameType=0x402 + status=0 + msg_len=0 + pad_len=0 */
    uint8_t buf[32];
    uint8_t *p = buf;

    /* FrameType 0x402 (varint: 2 байта) */
    int n = hy2_varint_encode(p, sizeof(buf), HY2_FRAME_TCP_RESPONSE);
    p += n;
    /* Status = 0 (OK) */
    *p++ = HY2_TCP_STATUS_OK;
    /* MessageLen uint32 = 0 */
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
    /* PaddingLen uint16 = 0 */
    *p++ = 0; *p++ = 0;

    size_t buf_len = (size_t)(p - buf);

    uint8_t status = 0xFF;
    char    msg[64] = {0};
    int consumed = hy2_tcp_response_decode(buf, buf_len, &status, msg, sizeof(msg));

    if (consumed < 0) {
        printf("FAIL tcp_response_decode OK: вернул -1\n");
        return 1;
    }
    if (status != HY2_TCP_STATUS_OK) {
        printf("FAIL tcp_response_decode OK: status=0x%02x, ожидалось 0x00\n", status);
        return 1;
    }
    printf("PASS: tcp_response_decode (status OK, %d байт потреблено)\n", consumed);
    return 0;
}

static int test_tcp_response_decode_error(void)
{
    uint8_t buf[64];
    uint8_t *p = buf;

    const char *errmsg = "connection refused";
    uint32_t   msglen  = (uint32_t)strlen(errmsg);

    int n = hy2_varint_encode(p, sizeof(buf), HY2_FRAME_TCP_RESPONSE);
    p += n;
    *p++ = HY2_TCP_STATUS_ERROR;
    /* MessageLen uint32 big-endian */
    *p++ = (uint8_t)(msglen >> 24);
    *p++ = (uint8_t)(msglen >> 16);
    *p++ = (uint8_t)(msglen >>  8);
    *p++ = (uint8_t)(msglen & 0xFF);
    memcpy(p, errmsg, msglen);
    p += msglen;
    /* PaddingLen = 0 */
    *p++ = 0; *p++ = 0;

    uint8_t status = 0;
    char    msg[64] = {0};
    int consumed = hy2_tcp_response_decode(buf, (size_t)(p - buf),
                                           &status, msg, sizeof(msg));
    if (consumed < 0) {
        printf("FAIL tcp_response_decode ERROR: вернул -1\n");
        return 1;
    }
    if (status != HY2_TCP_STATUS_ERROR) {
        printf("FAIL tcp_response_decode ERROR: status=0x%02x\n", status);
        return 1;
    }
    if (strcmp(msg, errmsg) != 0) {
        printf("FAIL tcp_response_decode ERROR: msg='%s'\n", msg);
        return 1;
    }
    printf("PASS: tcp_response_decode (status ERROR, msg='%s')\n", msg);
    return 0;
}

/* ── 7. Byte-level RFC 9000 §16 соответствие ────────────────────────── */

static int test_varint_bytes(void)
{
    uint8_t buf[8];
    int n;

    /* 0x00 → [0x00] */
    n = hy2_varint_encode(buf, 8, 0);
    if (n != 1 || buf[0] != 0x00) {
        printf("FAIL: 0 → len=%d buf[0]=0x%02x (ожидалось 1, 0x00)\n", n, buf[0]);
        return 1;
    }

    /* 0x3F → [0x3F] */
    n = hy2_varint_encode(buf, 8, 0x3F);
    if (n != 1 || buf[0] != 0x3F) {
        printf("FAIL: 0x3F → len=%d buf[0]=0x%02x\n", n, buf[0]);
        return 1;
    }

    /* 0x40 → [0x40][0x40]
     * prefix=01 | top6=0b000000=0, byte1=0b0100_0000=0x40 */
    n = hy2_varint_encode(buf, 8, 0x40);
    if (n != 2 || buf[0] != 0x40 || buf[1] != 0x40) {
        printf("FAIL: 0x40 → len=%d [0x%02x 0x%02x] (ожидалось 2, [0x40 0x40])\n",
               n, buf[0], buf[1]);
        return 1;
    }

    /* 0x401 (TCPRequest) → [0x44][0x01] */
    n = hy2_varint_encode(buf, 8, 0x401);
    if (n != 2 || buf[0] != 0x44 || buf[1] != 0x01) {
        printf("FAIL: 0x401 → len=%d [0x%02x 0x%02x] (ожидалось 2, [0x44 0x01])\n",
               n, buf[0], buf[1]);
        return 1;
    }

    /* 0x402 (TCPResponse) → [0x44][0x02] */
    n = hy2_varint_encode(buf, 8, 0x402);
    if (n != 2 || buf[0] != 0x44 || buf[1] != 0x02) {
        printf("FAIL: 0x402 → len=%d [0x%02x 0x%02x] (ожидалось 2, [0x44 0x02])\n",
               n, buf[0], buf[1]);
        return 1;
    }

    /* 0x3FFF → [0x7F][0xFF] */
    n = hy2_varint_encode(buf, 8, 0x3FFF);
    if (n != 2 || buf[0] != 0x7F || buf[1] != 0xFF) {
        printf("FAIL: 0x3FFF → len=%d [0x%02x 0x%02x]\n", n, buf[0], buf[1]);
        return 1;
    }

    /* 0x4000 → [0x80][0x00][0x40][0x00] */
    n = hy2_varint_encode(buf, 8, 0x4000);
    if (n != 4 || buf[0] != 0x80 || buf[1] != 0x00 ||
                  buf[2] != 0x40 || buf[3] != 0x00) {
        printf("FAIL: 0x4000 → len=%d [0x%02x 0x%02x 0x%02x 0x%02x]\n",
               n, buf[0], buf[1], buf[2], buf[3]);
        return 1;
    }

    printf("PASS: varint byte-level RFC 9000 соответствие (7 значений)\n");
    return 0;
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(void)
{
    int failures = 0;
    failures += test_varint_roundtrip();
    failures += test_varint_lengths();
    failures += test_varint_buf_too_small();
    failures += test_tcp_request_encode();
    failures += test_tcp_response_decode_ok();
    failures += test_tcp_response_decode_error();
    failures += test_varint_bytes();

    printf("\n%s: %d тест(ов) провалено\n",
           failures == 0 ? "ALL PASS" : "FAILED", failures);
    return failures;
}

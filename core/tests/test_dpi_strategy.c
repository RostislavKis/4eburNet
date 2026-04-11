/*
 * Тест dpi_strategy.c (C.3)
 * fake+TTL + fragment стратегии
 * Компилируется без wolfSSL.
 */
#define CONFIG_EBURNET_DPI 1
#include "dpi/dpi_strategy.h"
#include "dpi/dpi_payload.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

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

/* Тест 1: dpi_strategy_config defaults */
static void test_config_defaults(void)
{
    dpi_strategy_config_t cfg;
    dpi_strategy_config_init(&cfg);

    CHECK(cfg.enabled,             "default: enabled=true");
    CHECK(cfg.split_pos == 1,      "default: split_pos=1");
    CHECK(cfg.fake_ttl >= 3 &&
          cfg.fake_ttl <= 8,       "default: fake_ttl в диапазоне [3,8]");
    CHECK(cfg.fake_repeats >= 6 &&
          cfg.fake_repeats <= 11,  "default: fake_repeats в диапазоне [6,11]");
    CHECK(cfg.fake_sni[0] != '\0', "default: fake_sni не пустой");
}

/* Тест 2: fragment — корректное разделение данных */
static void test_fragment_split(void)
{
    const char *data = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    int dlen = (int)strlen(data);

    dpi_strategy_config_t cfg;
    dpi_strategy_config_init(&cfg);
    cfg.split_pos = 1;

    int part1, part2;
    dpi_fragment_sizes(dlen, cfg.split_pos, &part1, &part2);

    CHECK(part1 == 1,            "fragment: part1 = split_pos = 1");
    CHECK(part2 == dlen - 1,     "fragment: part2 = len - split_pos");
    CHECK(part1 + part2 == dlen, "fragment: part1 + part2 = total");
}

/* Тест 3: fragment — split_pos > len → корректная обработка */
static void test_fragment_edge(void)
{
    int part1, part2;
    dpi_fragment_sizes(5, 10, &part1, &part2);  /* split_pos > len */
    CHECK(part1 == 5 && part2 == 0, "fragment: split_pos > len → всё в part1");

    dpi_fragment_sizes(5, 0, &part1, &part2);   /* split_pos = 0 */
    CHECK(part1 == 5 && part2 == 0, "fragment: split_pos=0 → всё в part1");
}

/* Тест 4: fake payload генерируется корректно для TCP/UDP */
static void test_fake_payload_tcp(void)
{
    dpi_strategy_config_t cfg;
    dpi_strategy_config_init(&cfg);

    uint8_t buf[768];
    int len = dpi_make_fake_payload(buf, sizeof(buf),
                                     DPI_PROTO_TCP, cfg.fake_sni);
    CHECK(len > 0,        "fake_payload TCP: len > 0");
    CHECK(buf[0] == 0x16, "fake_payload TCP: TLS ContentType = 0x16");
}

static void test_fake_payload_udp(void)
{
    dpi_strategy_config_t cfg;
    dpi_strategy_config_init(&cfg);

    uint8_t buf[1280];
    int len = dpi_make_fake_payload(buf, sizeof(buf),
                                     DPI_PROTO_UDP, cfg.fake_sni);
    CHECK(len == 1200,    "fake_payload UDP: len = 1200");
    CHECK(buf[0] == 0xC3, "fake_payload UDP: QUIC Long Header = 0xC3");
}

/* Тест 5: raw socket создаётся (root не нужен для SOCK_RAW AF_INET) */
static void test_raw_socket_create(void)
{
    int fd = dpi_raw_socket_create(AF_INET);
    if (fd < 0) {
        printf("SKIP: raw socket недоступен (не root или нет прав): %s\n",
               strerror(errno));
        return;  /* Не ошибка — тест пропускается */
    }
    CHECK(fd >= 0, "raw socket: создан успешно");
    dpi_raw_socket_close(fd);
    printf("PASS: raw socket создан и закрыт\n");
}

/* Тест 6: dpi_set_ttl применяется к сокету */
static void test_set_ttl(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { printf("SKIP: socket недоступен\n"); return; }

    int rc = dpi_set_ttl(fd, 5);
    CHECK(rc == 0, "set_ttl(5): rc == 0");

    int ttl = 0;
    socklen_t len = sizeof(ttl);
    getsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, &len);
    CHECK(ttl == 5, "set_ttl(5): getsockopt подтверждает TTL=5");

    close(fd);
}

/* Тест 7: TCP_NODELAY устанавливается для fragment */
static void test_tcp_nodelay(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { printf("SKIP\n"); return; }

    int rc = dpi_set_nodelay(fd, 1);
    CHECK(rc == 0, "set_nodelay(1): rc == 0");

    int val = 0;
    socklen_t len = sizeof(val);
    getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, &len);
    CHECK(val != 0, "set_nodelay(1): TCP_NODELAY установлен");

    close(fd);
}

int main(void)
{
    printf("=== dpi_strategy tests ===\n\n");
    test_config_defaults();
    test_fragment_split();
    test_fragment_edge();
    test_fake_payload_tcp();
    test_fake_payload_udp();
    test_raw_socket_create();
    test_set_ttl();
    test_tcp_nodelay();
    printf("\n%s: %d тест(ов) провалено\n",
           failures == 0 ? "ALL PASS" : "FAILED", failures);
    return failures;
}

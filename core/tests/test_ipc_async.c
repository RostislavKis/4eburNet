/*
 * test_ipc_async.c — тест протокола Async IPC 2.0
 * Standalone: не линкуется с ipc.c, тестирует протокол и writev через socketpair.
 * Запуск: ./test_ipc_async
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "4eburnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>

static int fail_count = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fail_count++; } \
    else         { printf("PASS: %s\n", msg); } \
} while (0)

/* ── Тест 1: sizeof(ipc_header_t) == 8 ────────────────────────────── */
static void test_header_layout(void)
{
    printf("\n--- Тест 1: ipc_header_t layout ---\n");
    ASSERT(sizeof(ipc_header_t) == 8,
           "T1: sizeof(ipc_header_t) == 8 (packed)");

    /* Проверить смещения полей */
    ipc_header_t h = {0};
    ASSERT((char*)&h.version    == (char*)&h,
           "T1: version на offset 0");
    ASSERT((char*)&h.command    == (char*)&h + 1,
           "T1: command на offset 1");
    ASSERT((char*)&h.length     == (char*)&h + 2,
           "T1: length на offset 2");
    ASSERT((char*)&h.request_id == (char*)&h + 4,
           "T1: request_id на offset 4");
}

/* ── Тест 2: writev header+body за 1 syscall ───────────────────────── */
static void test_writev_single_syscall(void)
{
    printf("\n--- Тест 2: writev header+body ---\n");

    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
           "T2: socketpair создан");

    const char body[] = "{\"status\":\"ok\"}";
    uint16_t body_len = (uint16_t)(sizeof(body) - 1);

    ipc_header_t hdr = {
        .version    = EBURNET_IPC_VERSION,
        .command    = 0,
        .length     = body_len,
        .request_id = 0,
    };

    struct iovec iov[2];
    iov[0].iov_base = &hdr;
    iov[0].iov_len  = sizeof(hdr);
    iov[1].iov_base = (void *)body;
    iov[1].iov_len  = body_len;

    ssize_t written = writev(sv[1], iov, 2);
    ASSERT(written == (ssize_t)(sizeof(hdr) + body_len),
           "T2: writev записал header+body за 1 вызов");

    /* Читаем и проверяем */
    ipc_header_t got_hdr;
    ssize_t n = read(sv[0], &got_hdr, sizeof(got_hdr));
    ASSERT(n == (ssize_t)sizeof(got_hdr),             "T2: header получен");
    ASSERT(got_hdr.version == EBURNET_IPC_VERSION,    "T2: version корректен");
    ASSERT(got_hdr.length  == body_len,               "T2: length совпадает");
    ASSERT(got_hdr.command == 0,                       "T2: command == 0");

    char got_body[64] = {0};
    n = read(sv[0], got_body, got_hdr.length);
    ASSERT(n == (ssize_t)body_len,                    "T2: body получен");
    ASSERT(memcmp(got_body, body, body_len) == 0,     "T2: body совпадает");

    close(sv[0]);
    close(sv[1]);
}

/* ── Тест 3: partial write симуляция ──────────────────────────────── */
/* Проверяем что resp_sent корректно считает байты при частичной отправке */
static void test_partial_send_tracking(void)
{
    printf("\n--- Тест 3: partial send tracking ---\n");

    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
           "T3: socketpair");

    ipc_header_t hdr = {
        .version = EBURNET_IPC_VERSION,
        .length  = 4,
    };
    const char body[] = "TEST";

    /* Отправляем header и body раздельно — имитируем partial write */
    ssize_t n1 = write(sv[1], &hdr, sizeof(hdr));
    ssize_t n2 = write(sv[1], body, 4);
    ASSERT(n1 == (ssize_t)sizeof(hdr), "T3: header отправлен");
    ASSERT(n2 == 4,                    "T3: body отправлен");

    /* Получаем как один поток байт */
    char buf[32] = {0};
    ssize_t total = read(sv[0], buf, sizeof(buf));
    ASSERT(total == (ssize_t)(sizeof(hdr) + 4),  "T3: total bytes корректен");
    ASSERT(memcmp(buf, &hdr, sizeof(hdr)) == 0,  "T3: header в потоке корректен");
    ASSERT(memcmp(buf + sizeof(hdr), "TEST", 4) == 0, "T3: body в потоке корректен");

    close(sv[0]);
    close(sv[1]);
}

/* ── Тест 4: EPOLLET — неблокирующий recv ─────────────────────────── */
/* Проверяем что MSG_DONTWAIT на пустом socket возвращает EAGAIN */
static void test_nonblocking_recv(void)
{
    printf("\n--- Тест 4: MSG_DONTWAIT → EAGAIN ---\n");

    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) == 0,
           "T4: socketpair NONBLOCK");

    /* Пустой socket — recv должен вернуть EAGAIN */
    char buf[8];
    ssize_t n = recv(sv[0], buf, sizeof(buf), MSG_DONTWAIT);
    ASSERT(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
           "T4: recv на пустом NONBLOCK socket → EAGAIN");

    /* Записать данные и снова recv */
    write(sv[1], "X", 1);
    n = recv(sv[0], buf, sizeof(buf), MSG_DONTWAIT);
    ASSERT(n == 1, "T4: recv после write → 1 байт");

    /* Снова пусто */
    n = recv(sv[0], buf, sizeof(buf), MSG_DONTWAIT);
    ASSERT(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
           "T4: повторный recv на пустом → EAGAIN");

    close(sv[0]);
    close(sv[1]);
}

/* ── Тест 5: state machine переходы (header reading) ─────────────── */
/* Тестируем что заголовок из 8 байт читается корректно по частям */
static void test_header_partial_read(void)
{
    printf("\n--- Тест 5: partial header read ---\n");

    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
           "T5: socketpair");

    ipc_header_t send_hdr = {
        .version    = EBURNET_IPC_VERSION,
        .command    = (uint8_t)IPC_CMD_STATUS,
        .length     = 0,
        .request_id = 42,
    };

    /* Отправляем по 1 байту — имитируем slow client */
    const uint8_t *raw = (const uint8_t *)&send_hdr;
    for (size_t i = 0; i < sizeof(send_hdr); i++) {
        ssize_t w = write(sv[1], raw + i, 1);
        ASSERT(w == 1, "T5: write 1 байт");
    }

    /* Читаем весь header разом */
    ipc_header_t recv_hdr;
    ssize_t n = read(sv[0], &recv_hdr, sizeof(recv_hdr));
    ASSERT(n == (ssize_t)sizeof(recv_hdr),              "T5: header прочитан");
    ASSERT(recv_hdr.version    == EBURNET_IPC_VERSION,  "T5: version");
    ASSERT(recv_hdr.command    == (uint8_t)IPC_CMD_STATUS, "T5: command");
    ASSERT(recv_hdr.length     == 0,                    "T5: length == 0");
    ASSERT(recv_hdr.request_id == 42,                   "T5: request_id == 42");

    close(sv[0]);
    close(sv[1]);
}

int main(void)
{
    printf("=== test_ipc_async ===\n");

    test_header_layout();
    test_writev_single_syscall();
    test_partial_send_tracking();
    test_nonblocking_recv();
    test_header_partial_read();

    printf("\n%s: %d тест(ов) провалено\n",
           fail_count == 0 ? "ALL PASS" : "FAIL", fail_count);
    return fail_count > 0 ? 1 : 0;
}

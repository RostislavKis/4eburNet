/*
 * test_tproxy.c
 *
 * Тест graceful failure tproxy.c при отсутствии CAP_NET_ADMIN / root.
 * Проверяем что tproxy_init не segfault'ит и корректно возвращает -1 или 0,
 * а tproxy_cleanup идемпотентна.
 *
 * Стабы dispatcher_handle_conn/dispatcher_handle_udp — здесь, в файле.
 */

#include "proxy/tproxy.h"
#include "proxy/dispatcher.h"
#include "crypto/tls.h"
#include "4eburnet.h"

#include <stdio.h>
#include <string.h>

/* ── Стабы tls_* (net_utils.c ссылается, но http_do_tls_get недостижима) */
int     tls_connect(tls_conn_t *c, int fd, const tls_config_t *cfg)
    { (void)c; (void)fd; (void)cfg; return -1; }
ssize_t tls_send(tls_conn_t *c, const void *buf, size_t len)
    { (void)c; (void)buf; (void)len; return -1; }
ssize_t tls_recv(tls_conn_t *c, void *buf, size_t len)
    { (void)c; (void)buf; (void)len; return -1; }
void    tls_close(tls_conn_t *c) { (void)c; }

/* ── Стабы dispatcher (tproxy.c вызывает их при приёме пакетов) ─────── */
void dispatcher_handle_conn(tproxy_conn_t *conn)
{
    (void)conn;
}

void dispatcher_handle_udp(tproxy_conn_t *conn,
                            const uint8_t *buf, size_t len)
{
    (void)conn; (void)buf; (void)len;
}

/* ── [1] TCP сокет: init с port=0, проверка graceful error ────────────── */
static int test_tproxy_tcp_no_root(void)
{
    tproxy_state_t ts;
    int r = tproxy_init(&ts, 0, DEVICE_NORMAL);

    /* PASS если: вернул 0 (WSL с достаточными правами) ИЛИ -1 (нет CAP_NET_ADMIN).
     * FAIL если segfault или мусорное значение. */
    if (r == 0) {
        /* Если успех — tcp4_fd должен быть валидным */
        if (ts.tcp4_fd < 0) {
            fprintf(stderr, "FAIL [1]: init OK но tcp4_fd=%d\n", ts.tcp4_fd);
            tproxy_cleanup(&ts);
            return 1;
        }
        tproxy_cleanup(&ts);
    } else if (r != -1) {
        fprintf(stderr, "FAIL [1]: неожиданный возврат %d\n", r);
        return 1;
    }
    /* r == -1 → tproxy_init уже вызвал cleanup внутри */

    printf("  [1] test_tproxy_tcp_no_root PASS (r=%d)\n", r);
    return 0;
}

/* ── [2] UDP сокет: аналогично через tproxy_init ───────────────────────── */
static int test_tproxy_udp_no_root(void)
{
    tproxy_state_t ts;
    int r = tproxy_init(&ts, 0, DEVICE_NORMAL);

    if (r == 0) {
        if (ts.udp4_fd < 0) {
            fprintf(stderr, "FAIL [2]: init OK но udp4_fd=%d\n", ts.udp4_fd);
            tproxy_cleanup(&ts);
            return 1;
        }
        tproxy_cleanup(&ts);
    } else if (r != -1) {
        fprintf(stderr, "FAIL [2]: неожиданный возврат %d\n", r);
        return 1;
    }

    printf("  [2] test_tproxy_udp_no_root PASS (r=%d)\n", r);
    return 0;
}

/* ── [3] tproxy_cleanup идемпотентна: вызов дважды не segfault ─────────── */
static int test_tproxy_double_cleanup(void)
{
    tproxy_state_t ts;
    int r = tproxy_init(&ts, 0, DEVICE_NORMAL);

    if (r == 0) {
        tproxy_cleanup(&ts);
        /* второй вызов: все fd уже -1, должен пройти без ошибок */
        tproxy_cleanup(&ts);
    } else {
        /* init вернул -1 → внутри уже вызвал cleanup.
         * Вызовем cleanup вручную на "чистом" состоянии. */
        memset(&ts, 0, sizeof(ts));
        ts.tcp4_fd = ts.tcp6_fd = ts.udp4_fd = ts.udp6_fd = ts.epoll_fd = -1;
        tproxy_cleanup(&ts);
        tproxy_cleanup(&ts);
    }

    printf("  [3] test_tproxy_double_cleanup PASS\n");
    return 0;
}

int main(void)
{
    int fail = 0;
    printf("=== test-tproxy ===\n");
    fail += test_tproxy_tcp_no_root();
    fail += test_tproxy_udp_no_root();
    fail += test_tproxy_double_cleanup();
    if (fail)
        printf("FAIL — %d/3 провалено\n", fail);
    else
        printf("PASS — 3/3 OK\n");
    return fail ? 1 : 0;
}

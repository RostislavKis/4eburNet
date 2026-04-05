/*
 * VLESS XHTTP транспорт
 *
 * Псевдо-дуплексный канал через HTTP POST (upload) + GET (download)
 * поверх TLS. Chunked transfer encoding для маскировки под HTTP.
 * DPI видит легитимный HTTP — не может заблокировать без ущерба.
 */

#include "proxy/protocols/vless_xhttp.h"
#include "proxy/protocols/vless.h"
#include "phoenix.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/syscall.h>

/* ------------------------------------------------------------------ */
/*  xhttp_session_id_gen                                               */
/* ------------------------------------------------------------------ */

void xhttp_session_id_gen(xhttp_session_id_t *sid)
{
    uint8_t bytes[16];

    /* getrandom() — без открытия fd (Linux 3.17+) */
#ifdef __NR_getrandom
    if (syscall(__NR_getrandom, bytes, sizeof(bytes), 0) == (ssize_t)sizeof(bytes))
        goto encode;
#endif

    /* Fallback: /dev/urandom с O_CLOEXEC */
    {
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t n = read(fd, bytes, sizeof(bytes));
            close(fd);
            if (n == (ssize_t)sizeof(bytes))
                goto encode;
        }
    }

    /* Аварийный fallback: pid + time + counter (M-31) */
    {
        static uint32_t fallback_seq = 0;
        snprintf(sid->hex, sizeof(sid->hex),
                 "%08x%08x%08x%08x",
                 (unsigned)getpid(), (unsigned)time(NULL),
                 ++fallback_seq, (unsigned)getpid() ^ 0xDEADBEEF);
    }
    return;

encode:
    for (int i = 0; i < 16; i++)
        snprintf(sid->hex + i * 2, 3, "%02x", bytes[i]);
}

/* ------------------------------------------------------------------ */
/*  xhttp_start                                                        */
/* ------------------------------------------------------------------ */

int xhttp_start(xhttp_state_t *xh, int upload_fd, int download_fd,
                const tls_config_t *tls_cfg,
                const char *path, const char *host)
{
    memset(xh, 0, sizeof(*xh));

    xhttp_session_id_gen(&xh->session_id);
    snprintf(xh->path, sizeof(xh->path), "%s", path[0] ? path : "/");
    snprintf(xh->host, sizeof(xh->host), "%s",
             host[0] ? host : tls_cfg->sni);

    if (tls_connect_start(&xh->upload, upload_fd, tls_cfg) < 0)
        return -1;

    if (tls_connect_start(&xh->download, download_fd, tls_cfg) < 0) {
        tls_close(&xh->upload);
        return -1;
    }

    log_msg(LOG_DEBUG, "XHTTP: начато (session %s, path %s, host %s)",
            xh->session_id.hex, xh->path, xh->host);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  TLS handshake шаги                                                 */
/* ------------------------------------------------------------------ */

tls_step_result_t xhttp_upload_tls_step(xhttp_state_t *xh)
{
    tls_step_result_t r = tls_connect_step(&xh->upload);
    if (r == TLS_OK) {
        xh->upload_ready = true;
        log_msg(LOG_DEBUG, "XHTTP: upload TLS установлен");
    }
    return r;
}

tls_step_result_t xhttp_download_tls_step(xhttp_state_t *xh)
{
    tls_step_result_t r = tls_connect_step(&xh->download);
    if (r == TLS_OK) {
        xh->download_ready = true;
        log_msg(LOG_DEBUG, "XHTTP: download TLS установлен");
    }
    return r;
}

/* ------------------------------------------------------------------ */
/*  HTTP POST (upload) — заголовки + VLESS header в первом chunk       */
/* ------------------------------------------------------------------ */

int xhttp_send_upload_request(xhttp_state_t *xh,
                              const struct sockaddr_storage *dst,
                              const char *uuid_str)
{
    /* Построить VLESS request header */
    uint8_t vless_hdr[VLESS_HEADER_MAX];
    vless_uuid_t uuid;
    if (vless_uuid_parse(uuid_str, &uuid) < 0)
        return -1;
    int vless_len = vless_build_request(vless_hdr, sizeof(vless_hdr),
                                        &uuid, dst, VLESS_CMD_TCP);
    if (vless_len < 0)
        return -1;

    /* HTTP POST заголовки */
    char http_hdr[1024];
    int hdr_len = snprintf(http_hdr, sizeof(http_hdr),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Transfer-Encoding: chunked\r\n"
        "X-Session-ID: %s\r\n"
        "\r\n",
        xh->path, xh->host, xh->session_id.hex);

    /* Отправить HTTP заголовки */
    if (tls_send(&xh->upload, http_hdr, hdr_len) != hdr_len) {
        log_msg(LOG_WARN, "XHTTP: не удалось отправить POST заголовки");
        return -1;
    }

    /* Первый chunk — VLESS header */
    char chunk_hdr[32];
    int ch_len = snprintf(chunk_hdr, sizeof(chunk_hdr),
                          "%x\r\n", vless_len);
    if (tls_send(&xh->upload, chunk_hdr, ch_len) != ch_len ||
        tls_send(&xh->upload, vless_hdr, vless_len) != vless_len ||
        tls_send(&xh->upload, "\r\n", 2) != 2) {
        log_msg(LOG_WARN, "XHTTP: не удалось отправить VLESS header chunk");
        return -1;
    }

    log_msg(LOG_DEBUG, "XHTTP: POST запрос отправлен (%d байт VLESS header)",
            vless_len);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  HTTP GET (download) — запрос                                       */
/* ------------------------------------------------------------------ */

int xhttp_send_download_request(xhttp_state_t *xh)
{
    char http_req[1024];
    int len = snprintf(http_req, sizeof(http_req),
        "GET %s?session=%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Accept: application/octet-stream\r\n"
        "\r\n",
        xh->path, xh->session_id.hex, xh->host);

    if (tls_send(&xh->download, http_req, len) != len) {
        log_msg(LOG_WARN, "XHTTP: не удалось отправить GET запрос");
        return -1;
    }

    log_msg(LOG_DEBUG, "XHTTP: GET запрос отправлен");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Парсинг HTTP response (200 OK) — неблокирующий                     */
/* ------------------------------------------------------------------ */

int xhttp_parse_response_step(xhttp_state_t *xh)
{
    if (xh->headers_parsed)
        return 0;

    /* Читаем в буфер пока не найдём \r\n\r\n */
    while (xh->resp_len < sizeof(xh->resp_buf) - 1) {
        ssize_t n = tls_recv(&xh->download,
                             xh->resp_buf + xh->resp_len, 1);
        if (n <= 0) {
            if (n == 0)
                return -1;  /* EOF */
            if (errno == EAGAIN)
                return 1;   /* повторить */
            return -1;
        }
        xh->resp_len++;

        /* Ищем конец заголовков */
        if (xh->resp_len >= 4 &&
            xh->resp_buf[xh->resp_len - 4] == '\r' &&
            xh->resp_buf[xh->resp_len - 3] == '\n' &&
            xh->resp_buf[xh->resp_len - 2] == '\r' &&
            xh->resp_buf[xh->resp_len - 1] == '\n') {
            xh->resp_buf[xh->resp_len] = '\0';

            /* Проверить статус 200 */
            if (!strstr((char *)xh->resp_buf, " 200")) {
                log_msg(LOG_WARN, "XHTTP: HTTP ответ не 200: %.32s",
                        (char *)xh->resp_buf);
                return -1;
            }

            xh->headers_parsed = true;
            log_msg(LOG_DEBUG, "XHTTP: HTTP 200 OK получен");
            return 0;
        }
    }

    log_msg(LOG_WARN, "XHTTP: HTTP заголовки слишком длинные");
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Chunked encoding — отправка                                        */
/* ------------------------------------------------------------------ */

ssize_t xhttp_send_chunk(xhttp_state_t *xh,
                         const uint8_t *data, size_t len)
{
    if (len == 0)
        return 0;

    /* chunk header: hex_length\r\n */
    char hdr[32];
    int hdr_len = snprintf(hdr, sizeof(hdr), "%zx\r\n", len);

    ssize_t sent = tls_send(&xh->upload, hdr, hdr_len);
    if (sent != hdr_len)
        return -1;

    sent = tls_send(&xh->upload, data, len);
    if (sent != (ssize_t)len)
        return -1;

    if (tls_send(&xh->upload, "\r\n", 2) != 2)
        return -1;

    return (ssize_t)len;
}

/* ------------------------------------------------------------------ */
/*  Chunked decoding — приём                                           */
/* ------------------------------------------------------------------ */

ssize_t xhttp_recv_chunk(xhttp_state_t *xh,
                         uint8_t *buf, size_t buflen)
{
    /* Ожидание trailing \r\n после chunk data (неблокирующее) */
    if (xh->chunk_awaiting_crlf) {
        while (xh->chunk_crlf_read < 2) {
            uint8_t b;
            ssize_t n = tls_recv(&xh->download, &b, 1);
            if (n <= 0) return n;
            xh->chunk_crlf_read++;
        }
        xh->chunk_awaiting_crlf = false;
        xh->chunk_in_data = false;
        xh->chunk_hdr_len = 0;
    }

    /* Чтение данных текущего chunk */
    if (xh->chunk_in_data && xh->chunk_remaining > 0) {
        size_t to_read = xh->chunk_remaining;
        if (to_read > buflen)
            to_read = buflen;

        ssize_t n = tls_recv(&xh->download, buf, to_read);
        if (n <= 0)
            return n;

        xh->chunk_remaining -= n;

        if (xh->chunk_remaining == 0) {
            xh->chunk_awaiting_crlf = true;
            xh->chunk_crlf_read = 0;
        }

        return n;
    }

    /* Читаем chunk header: hex_length\r\n */
    while (xh->chunk_hdr_len < sizeof(xh->chunk_hdr) - 1) {
        ssize_t n = tls_recv(&xh->download,
                             (uint8_t *)xh->chunk_hdr + xh->chunk_hdr_len, 1);
        if (n <= 0)
            return n;
        xh->chunk_hdr_len++;

        if (xh->chunk_hdr_len >= 2 &&
            xh->chunk_hdr[xh->chunk_hdr_len - 2] == '\r' &&
            xh->chunk_hdr[xh->chunk_hdr_len - 1] == '\n') {
            xh->chunk_hdr[xh->chunk_hdr_len - 2] = '\0';
            xh->chunk_remaining = strtoul(xh->chunk_hdr, NULL, 16);
            xh->chunk_hdr_len = 0;

            /* M-30: upper bound на chunk size */
            if (xh->chunk_remaining > 65536) {
                log_msg(LOG_WARN, "XHTTP: слишком большой chunk: %zu",
                        xh->chunk_remaining);
                return -1;
            }

            if (xh->chunk_remaining == 0)
                return 0;  /* final chunk */

            xh->chunk_in_data = true;

            size_t to_read = xh->chunk_remaining;
            if (to_read > buflen)
                to_read = buflen;

            ssize_t rd = tls_recv(&xh->download, buf, to_read);
            if (rd <= 0)
                return rd;

            xh->chunk_remaining -= rd;
            if (xh->chunk_remaining == 0) {
                xh->chunk_awaiting_crlf = true;
                xh->chunk_crlf_read = 0;
            }
            return rd;
        }
    }

    log_msg(LOG_WARN, "XHTTP: chunk header слишком длинный");
    return -1;
}

/* ------------------------------------------------------------------ */
/*  xhttp_close                                                        */
/* ------------------------------------------------------------------ */

void xhttp_close(xhttp_state_t *xh)
{
    tls_close(&xh->upload);
    tls_close(&xh->download);
    log_msg(LOG_DEBUG, "XHTTP: соединения закрыты");
}

/*
 * DNS upstream resolver: UDP, DoT (RFC 7858), DoH (RFC 8484)
 */

#include "dns/dns_upstream.h"
#include "crypto/tls.h"
#include "phoenix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------ */
/*  Обычный UDP DNS                                                    */
/* ------------------------------------------------------------------ */

ssize_t dns_upstream_query(const char *server_ip, uint16_t server_port,
                           const uint8_t *query, size_t query_len,
                           uint8_t *response, size_t resp_buflen,
                           int timeout_ms)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    /* Жёсткий потолок 500ms для защиты event loop (C-02) */
    if (timeout_ms > 500) timeout_ms = 500;
    struct timeval tv = {
        .tv_sec  = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(server_port),
    };
    if (inet_pton(AF_INET, server_ip, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (sendto(fd, query, query_len, 0,
               (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    ssize_t n = recvfrom(fd, response, resp_buflen, 0, NULL, NULL);
    close(fd);

    if (n < 12) return -1;

    /* Проверить что ID совпадает и QR=1 */
    if (response[0] != query[0] || response[1] != query[1])
        return -1;
    if (!(response[2] & 0x80))
        return -1;

    return n;
}

/* ------------------------------------------------------------------ */
/*  DoT — DNS over TLS (RFC 7858)                                      */
/* ------------------------------------------------------------------ */

ssize_t dns_dot_query(const char *server_ip, uint16_t server_port,
                      const char *sni,
                      const uint8_t *query, size_t query_len,
                      uint8_t *response, size_t resp_buflen)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    /* Таймаут 1 сек для защиты event loop (C-02) */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(server_port),
    };
    if (inet_pton(AF_INET, server_ip, &addr.sin_addr) != 1) {
        close(fd); return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }

    tls_config_t cfg = {0};
    if (sni && sni[0])
        snprintf(cfg.sni, sizeof(cfg.sni), "%s", sni);
    cfg.fingerprint = TLS_FP_NONE;
    cfg.verify_cert = false;

    tls_conn_t tls;
    if (tls_connect(&tls, fd, &cfg) < 0) {
        close(fd); return -1;
    }

    /* DNS over TLS: [2 bytes length][DNS message] */
    uint8_t len_buf[2] = {
        (uint8_t)((query_len >> 8) & 0xFF),
        (uint8_t)(query_len & 0xFF),
    };
    if (tls_send(&tls, len_buf, 2) != 2 ||
        tls_send(&tls, query, query_len) != (ssize_t)query_len) {
        tls_close(&tls); close(fd); return -1;
    }

    /* Читаем ответ: [2 bytes length][DNS response] */
    uint8_t resp_len_buf[2];
    if (tls_recv(&tls, resp_len_buf, 2) != 2) {
        tls_close(&tls); close(fd); return -1;
    }
    uint16_t resp_len = ((uint16_t)resp_len_buf[0] << 8) | resp_len_buf[1];
    if (resp_len > resp_buflen || resp_len < 12) {
        tls_close(&tls); close(fd); return -1;
    }

    ssize_t total = 0;
    while ((size_t)total < resp_len) {
        ssize_t n = tls_recv(&tls, response + total, resp_len - total);
        if (n <= 0) break;
        total += n;
    }

    tls_close(&tls);
    close(fd);

    return (total == resp_len) ? total : -1;
}

/* ------------------------------------------------------------------ */
/*  DoH — DNS over HTTPS (RFC 8484)                                    */
/* ------------------------------------------------------------------ */

/* Base64url encode (без padding) */
static int base64url_encode(const uint8_t *in, size_t in_len,
                            char *out, size_t out_size)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    size_t pos = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t val = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) val |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < in_len) val |= in[i + 2];

        if (pos < out_size) out[pos++] = tbl[(val >> 18) & 0x3F];
        if (pos < out_size) out[pos++] = tbl[(val >> 12) & 0x3F];
        if (i + 1 < in_len && pos < out_size) out[pos++] = tbl[(val >> 6) & 0x3F];
        if (i + 2 < in_len && pos < out_size) out[pos++] = tbl[val & 0x3F];
    }
    if (pos < out_size) out[pos] = '\0';
    return (int)pos;
}

ssize_t dns_doh_query(const DnsConfig *cfg,
                      const uint8_t *query, size_t query_len,
                      uint8_t *response, size_t resp_buflen)
{
    if (!cfg->doh_url[0]) return -1;

    /* M-22: CRLF injection check */
    for (const char *p = cfg->doh_url; *p; p++)
        if (*p == '\r' || *p == '\n') return -1;

    /* Base64url encode DNS запроса */
    char b64[8192];
    base64url_encode(query, query_len, b64, sizeof(b64));

    /* Парсить URL: https://host/path */
    const char *url = cfg->doh_url;
    if (strncmp(url, "https://", 8) == 0) url += 8;

    char host[512] = {0};
    char path[256] = "/dns-query";
    const char *slash = strchr(url, '/');
    if (slash) {
        size_t hlen = slash - url;
        if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
        memcpy(host, url, hlen);
        snprintf(path, sizeof(path), "%s", slash);
    } else {
        snprintf(host, sizeof(host), "%s", url);
    }

    /* TCP + TLS подключение */
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    /* Таймаут 1 сек для защиты event loop (C-02) */
    {
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(443),
    };
    /* DoH IP адрес из doh_sni (не hostname — без getaddrinfo) */
    if (!cfg->doh_sni[0]) {
        log_msg(LOG_WARN,
            "DNS DoH: doh_sni (IP адрес) не настроен в конфиге");
        close(fd);
        return -1;
    }
    if (inet_pton(AF_INET, cfg->doh_sni, &addr.sin_addr) != 1) {
        log_msg(LOG_WARN, "DNS DoH: невалидный IP в doh_sni: %s",
                cfg->doh_sni);
        close(fd); return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }

    tls_config_t tls_cfg = {0};
    snprintf(tls_cfg.sni, sizeof(tls_cfg.sni), "%s", host);
    tls_cfg.fingerprint = TLS_FP_NONE;
    tls_cfg.verify_cert = false;

    tls_conn_t tls;
    if (tls_connect(&tls, fd, &tls_cfg) < 0) {
        close(fd); return -1;
    }

    /* HTTP GET запрос (L-15: heap вместо стека) */
    char *http_req = malloc(2048);
    uint8_t *http_buf = malloc(8192);
    if (!http_req || !http_buf) {
        free(http_req); free(http_buf);
        tls_close(&tls); close(fd);
        return -1;
    }

    int req_len = snprintf(http_req, 2048,
        "GET %s?dns=%s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Accept: application/dns-message\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, b64, host);

    if (tls_send(&tls, http_req, req_len) != req_len) {
        free(http_req); free(http_buf);
        tls_close(&tls); close(fd); return -1;
    }

    /* Читаем HTTP ответ */
    ssize_t total = 0;
    while (total < 8191) {
        ssize_t n = tls_recv(&tls, http_buf + total, 8191 - total);
        if (n <= 0) break;
        total += n;
    }
    tls_close(&tls);
    close(fd);
    free(http_req);

    /* H-14: NUL-терминация перед strstr (буфер 8192, total < 8191) */
    http_buf[total] = '\0';

    /* M-27: chunked encoding не поддерживается */
    if (strstr((char *)http_buf, "Transfer-Encoding: chunked")) {
        log_msg(LOG_WARN, "DoH: chunked encoding не поддерживается");
        free(http_buf);
        return -1;
    }

    /* Найти конец HTTP заголовков */
    uint8_t *body = NULL;
    for (ssize_t i = 0; i < total - 3; i++) {
        if (http_buf[i] == '\r' && http_buf[i+1] == '\n' &&
            http_buf[i+2] == '\r' && http_buf[i+3] == '\n') {
            body = http_buf + i + 4;
            break;
        }
    }
    if (!body) { free(http_buf); return -1; }

    size_t body_len = total - (body - http_buf);
    if (body_len < 12 || body_len > resp_buflen) { free(http_buf); return -1; }

    memcpy(response, body, body_len);
    free(http_buf);
    return (ssize_t)body_len;
}

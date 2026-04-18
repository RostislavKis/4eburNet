/*
 * DNS upstream resolver: UDP, DoT (RFC 7858), DoH (RFC 8484)
 */

#include "dns/dns_upstream.h"
#include "crypto/tls.h"
#include "constants.h"
#include "4eburnet.h"

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
    if (timeout_ms > TIMEOUT_DNS_PENDING_MS) timeout_ms = TIMEOUT_DNS_PENDING_MS;
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
    struct timeval tv = { .tv_sec = TIMEOUT_DNS_SEC, .tv_usec = 0 };
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
    if (sni && sni[0]) {
        int _n = snprintf(cfg.sni, sizeof(cfg.sni), "%s", sni);
        if (_n < 0 || (size_t)_n >= sizeof(cfg.sni))
            log_msg(LOG_WARN, "DoT: SNI обрезан: %s", sni);
    }
    cfg.fingerprint = TLS_FP_NONE;
    /* DoT серверы имеют валидные CA-сертификаты.
     * VERIFY_PEER обязателен — иначе ТСПУ может подменить DNS через MitM */
    cfg.verify_cert = true;

    tls_conn_t *tls = malloc(sizeof(*tls));
    if (!tls) { close(fd); return -1; }
    if (tls_connect(tls, fd, &cfg) < 0) {
        free(tls); close(fd); return -1;
    }

    /* DNS over TLS: [2 bytes length][DNS message] */
    uint8_t len_buf[2] = {
        (uint8_t)((query_len >> 8) & 0xFF),
        (uint8_t)(query_len & 0xFF),
    };
    if (tls_send(tls, len_buf, 2) != 2 ||
        tls_send(tls, query, query_len) != (ssize_t)query_len) {
        tls_close(tls); free(tls); close(fd); return -1;
    }

    /* Читаем ответ: [2 bytes length][DNS response] */
    uint8_t resp_len_buf[2];
    if (tls_recv(tls, resp_len_buf, 2) != 2) {
        tls_close(tls); free(tls); close(fd); return -1;
    }
    uint16_t resp_len = ((uint16_t)resp_len_buf[0] << 8) | resp_len_buf[1];
    if (resp_len > resp_buflen || resp_len < 12) {
        tls_close(tls); free(tls); close(fd); return -1;
    }

    ssize_t total = 0;
    while ((size_t)total < resp_len) {
        ssize_t n = tls_recv(tls, response + total, resp_len - total);
        if (n <= 0) break;
        total += n;
    }

    tls_close(tls);
    free(tls);
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

    /* Base64url encode DNS запроса (heap — стек MIPS 8KB) */
    char *b64 = malloc(DNS_DOH_B64_SIZE);
    if (!b64) {
        log_msg(LOG_ERROR, "dns_doh: нет памяти для b64");
        return -1;
    }
    base64url_encode(query, query_len, b64, 8192);

    /* Парсить URL: https://host/path */
    const char *url = cfg->doh_url;
    if (strncmp(url, "https://", 8) == 0) url += 8;

    /* M-09: heap вместо 768B на MIPS стеке */
    #define DOH_HOST_SIZE 512
    #define DOH_PATH_SIZE 256
    char *host = calloc(1, DOH_HOST_SIZE);
    char *path = calloc(1, DOH_PATH_SIZE);
    if (!host || !path) {
        log_msg(LOG_ERROR, "dns_doh: нет памяти для host/path");
        free(host); free(path); free(b64);
        return -1;
    }
    snprintf(path, DOH_PATH_SIZE, "/dns-query");

    const char *slash = strchr(url, '/');
    if (slash) {
        size_t hlen = slash - url;
        if (hlen >= DOH_HOST_SIZE) hlen = DOH_HOST_SIZE - 1;
        memcpy(host, url, hlen);
        {   int _n = snprintf(path, DOH_PATH_SIZE, "%s", slash);
            if (_n < 0 || (size_t)_n >= DOH_PATH_SIZE)
                log_msg(LOG_WARN, "DoH: path обрезан: %s", slash);
        }
    } else {
        {   int _n = snprintf(host, DOH_HOST_SIZE, "%s", url);
            if (_n < 0 || (size_t)_n >= DOH_HOST_SIZE)
                log_msg(LOG_WARN, "DoH: host обрезан: %s", url);
        }
    }

    /* TCP + TLS подключение */
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { free(b64); free(host); free(path); return -1; }

    /* Таймаут 1 сек для защиты event loop (C-02) */
    {
        struct timeval tv = { .tv_sec = TIMEOUT_DNS_SEC, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    /* IP: doh_ip из конфига, или doh_sni (legacy), или host из URL */
    const char *doh_ip = cfg->doh_ip[0]  ? cfg->doh_ip  :
                         cfg->doh_sni[0] ? cfg->doh_sni : host;
    uint16_t doh_port = cfg->doh_port > 0 ? cfg->doh_port : 443;

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(doh_port),
    };
    if (!doh_ip[0]) {
        log_msg(LOG_WARN, "DNS DoH: IP адрес не задан (doh_ip/doh_sni)");
        free(b64); free(host); free(path); close(fd);
        return -1;
    }
    if (inet_pton(AF_INET, doh_ip, &addr.sin_addr) != 1) {
        log_msg(LOG_WARN, "DNS DoH: невалидный IP: %s", doh_ip);
        free(b64); free(host); free(path); close(fd); return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        free(b64); free(host); free(path); close(fd); return -1;
    }

    tls_config_t tls_cfg = {0};
    {   int _n = snprintf(tls_cfg.sni, sizeof(tls_cfg.sni), "%s", host);
        if (_n < 0 || (size_t)_n >= sizeof(tls_cfg.sni))
            log_msg(LOG_WARN, "DoH: TLS SNI обрезан: %s", host);
    }
    tls_cfg.fingerprint = TLS_FP_NONE;
    /* DoH серверы имеют валидные CA-сертификаты.
     * VERIFY_PEER обязателен — иначе ТСПУ может подменить DNS через MitM */
    tls_cfg.verify_cert = true;

    tls_conn_t *tls = malloc(sizeof(*tls));
    if (!tls) { free(b64); free(host); free(path); close(fd); return -1; }
    if (tls_connect(tls, fd, &tls_cfg) < 0) {
        free(tls); free(b64); free(host); free(path); close(fd); return -1;
    }

    /* HTTP GET запрос (L-15: heap вместо стека) */
    char *http_req = malloc(DNS_DOH_REQ_SIZE);
    uint8_t *http_buf = malloc(DNS_DOH_B64_SIZE);
    if (!http_req || !http_buf) {
        free(http_req); free(http_buf); free(b64);
        free(host); free(path);
        tls_close(tls); free(tls); close(fd);
        return -1;
    }

    int req_len = snprintf(http_req, 2048,
        "GET %s?dns=%s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Accept: application/dns-message\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, b64, host);
    free(b64);
    b64 = NULL;
    /* host/path больше не нужны — HTTP запрос уже сформирован */
    free(host); host = NULL;
    free(path); path = NULL;

    if (req_len < 0 || req_len >= 2048) {
        log_msg(LOG_ERROR, "dns_doh: HTTP запрос обрезан (%d >= 2048)", req_len);
        free(http_req); free(http_buf);
        tls_close(tls); free(tls); close(fd); return -1;
    }

    if (tls_send(tls, http_req, req_len) != req_len) {
        free(http_req); free(http_buf);
        tls_close(tls); free(tls); close(fd); return -1;
    }

    /* Читаем HTTP ответ */
    ssize_t total = 0;
    while (total < 8191) {
        ssize_t n = tls_recv(tls, http_buf + total, 8191 - total);
        if (n <= 0) break;
        total += n;
    }
    tls_close(tls);
    free(tls);
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

#define _XOPEN_SOURCE 700  /* strptime — до всех include (M-04) */

/*
 * NTP Bootstrap через HTTP Date: заголовок (DEC-019)
 *
 * При холодном старте роутера время = 1970.
 * wolfSSL/Reality не стартует — TLS cert validation fails.
 * Решение: HEAD запрос к HTTP серверу, парсинг Date: заголовка,
 * установка времени через settimeofday().
 *
 * Без curl/wget — только raw TCP сокеты.
 */

#include "ntp_bootstrap.h"
#include "phoenix.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* HTTP хосты для bootstrap (IP, без DNS) — из ntp_bootstrap.h */
static const struct {
    const char *ip;
    const char *host;
} bootstrap_hosts[] = NTP_BOOTSTRAP_HOSTS;

/* HTTP порт для bootstrap */
#define NTP_HTTP_PORT   80

/* Размер буфера для HTTP ответа */
#define HTTP_BUF_SIZE   1024

/* HTTP запрос (HEAD — минимальный ответ) */
#define HTTP_REQ_FMT    "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n"

/* ------------------------------------------------------------------ */
/*  ntp_time_is_valid                                                  */
/* ------------------------------------------------------------------ */

bool ntp_time_is_valid(void)
{
    return time(NULL) >= NTP_MIN_VALID_TIME;
}

/* ------------------------------------------------------------------ */
/*  Парсинг HTTP Date: заголовка                                       */
/* ------------------------------------------------------------------ */

/*
 * Парсить RFC 7231 дату: "Wed, 04 Apr 2026 15:30:00 GMT"
 * Возвращает time_t или -1 при ошибке.
 */
static time_t parse_http_date(const char *date_str)
{
    struct tm tm = {0};

    /* strptime есть в musl libc */
    char *p = strptime(date_str, "%a, %d %b %Y %H:%M:%S", &tm);
    if (!p)
        return -1;

    /* timegm — UTC без учёта локальной timezone */
    return timegm(&tm);
}

/* ------------------------------------------------------------------ */
/*  Попытка получить время от одного хоста                              */
/* ------------------------------------------------------------------ */

static int try_host(const char *ip, const char *host)
{
    /* Создаём TCP сокет */
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    /* Таймаут на send/recv */
    struct timeval tv = { .tv_sec = NTP_CONNECT_TIMEOUT, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Адрес сервера */
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(NTP_HTTP_PORT),
    };
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    /* Подключение */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_msg(LOG_DEBUG, "NTP bootstrap: %s (%s): connect: %s",
                host, ip, strerror(errno));
        close(fd);
        return -1;
    }

    /* Отправляем HTTP HEAD */
    char req[256];
    int req_len = snprintf(req, sizeof(req), HTTP_REQ_FMT, host);
    /* Цикл partial write */
    size_t sent = 0;
    while (sent < (size_t)req_len) {
        ssize_t n = send(fd, req + sent, (size_t)req_len - sent, 0);
        if (n <= 0) { close(fd); return -1; }
        sent += (size_t)n;
    }

    /* Читаем ответ (HEAD не содержит тела, но читаем буфер
       целиком — некоторые серверы могут отправить лишнее) */
    char buf[HTTP_BUF_SIZE] = {0};
    ssize_t total = 0;
    while (total < (ssize_t)(sizeof(buf) - 1)) {
        ssize_t n = recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (n <= 0)
            break;
        total += n;

        /* Ищем конец заголовков */
        if (strstr(buf, "\r\n\r\n"))
            break;
    }
    buf[total] = '\0';
    close(fd);

    if (total <= 0)
        return -1;

    /* Ищем Date: заголовок */
    const char *date_hdr = strstr(buf, "Date: ");
    if (!date_hdr)
        date_hdr = strstr(buf, "date: ");
    if (!date_hdr) {
        log_msg(LOG_DEBUG, "NTP bootstrap: %s: нет Date: заголовка", host);
        return -1;
    }

    date_hdr += 6;  /* пропустить "Date: " */

    /* Парсим дату */
    time_t t = parse_http_date(date_hdr);
    if (t < NTP_MIN_VALID_TIME) {
        log_msg(LOG_DEBUG, "NTP bootstrap: %s: невалидная дата", host);
        return -1;
    }

    /* Sanity check: время должно быть разумным (H-11) */
    if (t < 1700000000 || t > 2000000000) {
        log_msg(LOG_WARN, "NTP: подозрительное время %ld, пропускаем",
                (long)t);
        return -1;
    }

    /* Устанавливаем время */
    struct timeval new_time = { .tv_sec = t, .tv_usec = 0 };
    if (settimeofday(&new_time, NULL) < 0) {
        if (errno == EPERM)
            log_msg(LOG_WARN,
                "NTP bootstrap: нет прав на settimeofday");
        else
            log_msg(LOG_WARN,
                "NTP bootstrap: settimeofday: %s", strerror(errno));
        return -1;
    }

    /* Форматируем для лога */
    struct tm tm;
    gmtime_r(&t, &tm);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S UTC", &tm);
    log_msg(LOG_INFO,
        "Время установлено: %s (HTTP bootstrap от %s)", ts, host);

    log_msg(LOG_WARN,
        "NTP: время получено из неаутентифицированного HTTP "
        "(возможен MITM). Используйте только для первоначальной синхронизации.");

    return 0;
}

/* ------------------------------------------------------------------ */
/*  ntp_bootstrap                                                      */
/* ------------------------------------------------------------------ */

int ntp_bootstrap(void)
{
    /* Если время уже корректно — ничего не делать */
    if (ntp_time_is_valid())
        return 0;

    log_msg(LOG_INFO, "Системное время некорректно, запуск HTTP bootstrap");

    /* Перебираем хосты до первого успеха */
    for (int i = 0; bootstrap_hosts[i].ip != NULL; i++) {
        if (try_host(bootstrap_hosts[i].ip,
                     bootstrap_hosts[i].host) == 0)
            return 0;
    }

    log_msg(LOG_WARN,
        "NTP bootstrap: все попытки провалились, "
        "TLS может не работать");
    return -1;
}

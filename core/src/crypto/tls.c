/*
 * TLS модуль на wolfSSL (DEC-002)
 *
 * Поддержка uTLS fingerprint для маскировки Reality handshake
 * под легитимные клиенты (Chrome/Firefox/iOS).
 * x25519 key share, SNI, ALPN.
 */

/* wolfSSL options.h — ПЕРВЫМ, до остальных wolfSSL headers */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include "crypto/tls.h"
#include "4eburnet.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>  /* explicit_bzero */
#include <errno.h>
#include <sys/select.h>

/* Буфер для строки ошибки */
/* Однопоточная архитектура — статический буфер безопасен (M-06).
   При переходе на многопоток заменить на _Thread_local. */
static char tls_err_buf[256];

/* ------------------------------------------------------------------ */
/*  Fingerprint профили — cipher suites для каждого клиента            */
/* ------------------------------------------------------------------ */

/*
 * Chrome 120: TLS 1.3 + TLS 1.2 fallback
 * Порядок cipher suites соответствует реальному Chrome ClientHello
 */
static const char *fp_chrome120_ciphers =
    "TLS13-AES128-GCM-SHA256:"
    "TLS13-AES256-GCM-SHA384:"
    "TLS13-CHACHA20-POLY1305-SHA256:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305";

/*
 * Firefox 121: похож на Chrome, другой порядок TLS 1.2
 */
static const char *fp_firefox121_ciphers =
    "TLS13-AES128-GCM-SHA256:"
    "TLS13-CHACHA20-POLY1305-SHA256:"
    "TLS13-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384";

/*
 * Safari iOS 17: предпочитает AES256 и ChaCha20
 */
static const char *fp_ios17_ciphers =
    "TLS13-AES128-GCM-SHA256:"
    "TLS13-AES256-GCM-SHA384:"
    "TLS13-CHACHA20-POLY1305-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256";

/* ALPN протоколы (Chrome/Firefox: h2 + http/1.1) */
static const char *alpn_protocols = "h2,http/1.1";

/* ------------------------------------------------------------------ */
/*  tls_global_init / cleanup                                          */
/* ------------------------------------------------------------------ */

int tls_global_init(void)
{
    int ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        log_msg(LOG_ERROR, "wolfSSL_Init провалился: %d", ret);
        return -1;
    }

    /* Отключаем встроенное логирование — используем свою систему */
    wolfSSL_Debugging_OFF();

    log_msg(LOG_INFO, "wolfSSL инициализирован (v%s)",
            wolfSSL_lib_version());
    return 0;
}

/* Предварительное объявление кэша CTX (определён ниже)
   Ключ кэша: fingerprint * 2 + verify_cert (H-06) */
static WOLFSSL_CTX *g_ctx_cache[8];

void tls_global_cleanup(void)
{
    /* Освободить кэш CTX (H-04, H-06) */
    for (int i = 0; i < 8; i++) {
        if (g_ctx_cache[i]) {
            wolfSSL_CTX_free(g_ctx_cache[i]);
            g_ctx_cache[i] = NULL;
        }
    }
    wolfSSL_Cleanup();
    log_msg(LOG_DEBUG, "wolfSSL очищен");
}

/* ------------------------------------------------------------------ */
/*  Fingerprint — CTX часть (cipher suites) и SSL часть (key share)    */
/* ------------------------------------------------------------------ */

/* Cipher suites на CTX (H-04: применяется один раз при создании кэша) */
static void apply_ctx_fingerprint(WOLFSSL_CTX *ctx, tls_fingerprint_t fp)
{
    const char *ciphers = NULL;
    switch (fp) {
    case TLS_FP_CHROME120:  ciphers = fp_chrome120_ciphers;  break;
    case TLS_FP_FIREFOX121: ciphers = fp_firefox121_ciphers; break;
    case TLS_FP_IOS17:      ciphers = fp_ios17_ciphers;      break;
    default: return;
    }
    if (ciphers)
        wolfSSL_CTX_set_cipher_list(ctx, ciphers);
}

/* Key share + ALPN на каждый SSL объект */
static void apply_ssl_fingerprint(WOLFSSL *ssl, tls_fingerprint_t fp)
{
    if (fp == TLS_FP_NONE) return;

    wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_X25519);
    wolfSSL_UseALPN(ssl, (char *)alpn_protocols,
                    strlen(alpn_protocols),
                    WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);

    log_msg(LOG_DEBUG, "TLS fingerprint: %s",
            fp == TLS_FP_CHROME120  ? "Chrome120" :
            fp == TLS_FP_FIREFOX121 ? "Firefox121" :
            fp == TLS_FP_IOS17      ? "iOS17" : "unknown");
}

/* ------------------------------------------------------------------ */
/*  WOLFSSL_CTX кэш по fingerprint (H-04: один CTX на все соединения)  */
/* ------------------------------------------------------------------ */

static WOLFSSL_CTX *get_or_create_ctx(tls_fingerprint_t fp,
                                      bool verify_cert)
{
    /* Ключ кэша учитывает verify_cert (H-06) */
    int idx = (int)fp * 2 + (verify_cert ? 1 : 0);
    if (idx < 0 || idx >= 8) return NULL;

    if (g_ctx_cache[idx])
        return g_ctx_cache[idx];

    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (!ctx) return NULL;

    wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2);

    if (!verify_cert)
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

    apply_ctx_fingerprint(ctx, fp);

    g_ctx_cache[idx] = ctx;
    log_msg(LOG_DEBUG, "TLS: CTX кэш создан (fingerprint %d)", idx);
    return ctx;
}

/* ------------------------------------------------------------------ */
/*  tls_connect_start — подготовка TLS без блокировки (C-03/C-04)      */
/* ------------------------------------------------------------------ */

int tls_connect_start(tls_conn_t *conn, int fd,
                      const tls_config_t *config)
{
    memset(conn, 0, sizeof(*conn));
    conn->fd = fd;
    conn->config.fingerprint      = config->fingerprint;
    conn->config.verify_cert      = config->verify_cert;
    conn->config.reality_key_len  = config->reality_key_len;

    /* Deep copy reality_key и reality_short_id для защиты от reload (H-05) */
    if (config->reality_key && config->reality_key_len > 0) {
        uint8_t *key_copy = malloc(config->reality_key_len);
        /* M-10: проверка malloc failure */
        if (!key_copy) {
            log_msg(LOG_ERROR, "TLS: нет памяти для reality_key");
            tls_close(conn);
            return -1;
        }
        memcpy(key_copy, config->reality_key, config->reality_key_len);
        conn->config.reality_key = key_copy;
    } else {
        conn->config.reality_key = NULL;
    }
    if (config->reality_short_id) {
        conn->config.reality_short_id = strdup(config->reality_short_id);
    } else {
        conn->config.reality_short_id = NULL;
    }

    /* Копируем SNI — защита от dangling pointer при reload конфига */
    if (config->sni[0])
        snprintf(conn->config.sni, sizeof(conn->config.sni),
                 "%s", config->sni);
    else
        conn->config.sni[0] = '\0';

    /* CTX из кэша (H-04: один CTX на все соединения с одним fingerprint) */
    WOLFSSL_CTX *ctx = get_or_create_ctx(config->fingerprint,
                                         config->verify_cert);
    if (!ctx) {
        log_msg(LOG_ERROR, "TLS: не удалось получить CTX");
        return -1;
    }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) {
        log_msg(LOG_ERROR, "TLS: wolfSSL_new провалился");
        return -1;
    }

    wolfSSL_set_fd(ssl, fd);

    if (conn->config.sni[0]) {
        int ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME,
                                 conn->config.sni,
                                 (unsigned short)strlen(conn->config.sni));
        if (ret != WOLFSSL_SUCCESS)
            log_msg(LOG_WARN, "TLS: UseSNI провалился: %d", ret);
    }

    apply_ssl_fingerprint(ssl, config->fingerprint);

    conn->ssl = ssl;
    conn->ctx = ctx;
    /* connected остаётся false — handshake ещё не завершён */

    return 0;
}

/* ------------------------------------------------------------------ */
/*  tls_connect_step — один шаг handshake, без select()                */
/* ------------------------------------------------------------------ */

tls_step_result_t tls_connect_step(tls_conn_t *conn)
{
    if (!conn->ssl)
        return TLS_ERR;

    int ret = wolfSSL_connect((WOLFSSL *)conn->ssl);
    if (ret == WOLFSSL_SUCCESS) {
        conn->connected = true;
        log_msg(LOG_DEBUG, "TLS соединение установлено (%s, %s)",
                wolfSSL_get_version((WOLFSSL *)conn->ssl),
                wolfSSL_get_cipher_name((WOLFSSL *)conn->ssl));
        return TLS_OK;
    }

    int err = wolfSSL_get_error((WOLFSSL *)conn->ssl, ret);
    if (err == WOLFSSL_ERROR_WANT_READ ||
        err == WOLFSSL_ERROR_WANT_WRITE)
        return TLS_WANT_IO;

    wolfSSL_ERR_error_string(err, tls_err_buf);
    log_msg(LOG_WARN, "TLS handshake провалился: %s", tls_err_buf);
    return TLS_ERR;
}

/* ------------------------------------------------------------------ */
/*  tls_connect — блокирующая обёртка (для обратной совместимости)      */
/* ------------------------------------------------------------------ */

int tls_connect(tls_conn_t *conn, int fd, const tls_config_t *config)
{
    if (tls_connect_start(conn, fd, config) < 0)
        return -1;

    /* M-18: проверка fd < FD_SETSIZE перед select() */
    if (fd >= FD_SETSIZE) {
        log_msg(LOG_ERROR, "TLS: fd %d >= FD_SETSIZE", fd);
        tls_close(conn);
        return -1;
    }

    int max_attempts = 50;  /* 50 × 100мс = 5 сек */
    tls_step_result_t r;
    while ((r = tls_connect_step(conn)) == TLS_WANT_IO) {
        if (--max_attempts <= 0) {
            log_msg(LOG_WARN, "TLS: таймаут handshake");
            tls_close(conn);
            return -1;
        }
        fd_set rfds, wfds;
        FD_ZERO(&rfds); FD_ZERO(&wfds);
        FD_SET(fd, &rfds); FD_SET(fd, &wfds);
        struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
        select(fd + 1, &rfds, &wfds, NULL, &tv);
    }

    if (r == TLS_ERR) {
        tls_close(conn);
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  tls_send / tls_recv                                                */
/* ------------------------------------------------------------------ */

ssize_t tls_send(tls_conn_t *conn, const void *buf, size_t len)
{
    if (!conn->ssl || !conn->connected)
        return -1;

    int ret = wolfSSL_write((WOLFSSL *)conn->ssl, buf, (int)len);
    if (ret <= 0) {
        int err = wolfSSL_get_error((WOLFSSL *)conn->ssl, ret);
        if (err == WOLFSSL_ERROR_WANT_WRITE ||
            err == WOLFSSL_ERROR_WANT_READ) {
            errno = EAGAIN;
            return -1;
        }
        wolfSSL_ERR_error_string(err, tls_err_buf);
        log_msg(LOG_DEBUG, "TLS send ошибка: %s", tls_err_buf);
        return -1;
    }

    return ret;
}

ssize_t tls_recv(tls_conn_t *conn, void *buf, size_t len)
{
    if (!conn->ssl || !conn->connected)
        return -1;

    int ret = wolfSSL_read((WOLFSSL *)conn->ssl, buf, (int)len);
    if (ret <= 0) {
        int err = wolfSSL_get_error((WOLFSSL *)conn->ssl, ret);
        if (err == WOLFSSL_ERROR_WANT_READ ||
            err == WOLFSSL_ERROR_WANT_WRITE) {
            errno = EAGAIN;
            return -1;
        }
        if (err == WOLFSSL_ERROR_ZERO_RETURN)
            return 0;  /* peer закрыл TLS */
        wolfSSL_ERR_error_string(err, tls_err_buf);
        log_msg(LOG_DEBUG, "TLS recv ошибка: %s", tls_err_buf);
        return -1;
    }

    return ret;
}

/* ------------------------------------------------------------------ */
/*  tls_close                                                          */
/* ------------------------------------------------------------------ */

void tls_close(tls_conn_t *conn)
{
    if (conn->ssl) {
        wolfSSL_shutdown((WOLFSSL *)conn->ssl);
        wolfSSL_free((WOLFSSL *)conn->ssl);
        conn->ssl = NULL;
    }
    /* CTX не освобождаем — кэшированный (H-04) */
    conn->ctx = NULL;
    conn->connected = false;

    /* M-11: обнулить ключевой материал перед освобождением */
    if (conn->config.reality_key) {
        explicit_bzero((void *)conn->config.reality_key,
                       conn->config.reality_key_len);
        free((void *)conn->config.reality_key);
        conn->config.reality_key = NULL;
    }
    if (conn->config.reality_short_id) {
        size_t sid_len = strlen(conn->config.reality_short_id);
        if (sid_len > 0)
            explicit_bzero((void *)conn->config.reality_short_id, sid_len);
        free((void *)conn->config.reality_short_id);
        conn->config.reality_short_id = NULL;
    }
}

/* ------------------------------------------------------------------ */
/*  tls_last_error                                                     */
/* ------------------------------------------------------------------ */

const char *tls_last_error(void)
{
    /* tls_err_buf заполняется при ошибках в connect/send/recv */
    if (tls_err_buf[0] == '\0')
        return "нет ошибок";
    return tls_err_buf;
}

/* ------------------------------------------------------------------ */
/*  tls_get_client_random — извлечь clientRandom из TLS сессии        */
/* ------------------------------------------------------------------ */

int tls_get_client_random(const tls_conn_t *conn, uint8_t *buf, size_t buflen)
{
    if (!conn || !conn->ssl || !conn->connected || !buf || buflen == 0)
        return -1;

    /* wolfSSL_get_client_random доступен при OPENSSL_EXTRA (DEC-025) */
#ifdef OPENSSL_EXTRA
    size_t n = wolfSSL_get_client_random(
                    (const WOLFSSL *)conn->ssl,
                    buf,
                    buflen < 32 ? buflen : 32);
    return (n > 0) ? (int)n : -1;
#else
    /* OPENSSL_EXTRA не включён — clientRandom недоступен */
    (void)buf; (void)buflen;
    return -1;
#endif
}

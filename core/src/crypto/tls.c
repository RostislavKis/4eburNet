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
#include "phoenix.h"

#include <string.h>
#include <errno.h>

/* Буфер для строки ошибки */
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

void tls_global_cleanup(void)
{
    wolfSSL_Cleanup();
    log_msg(LOG_DEBUG, "wolfSSL очищен");
}

/* ------------------------------------------------------------------ */
/*  Применить fingerprint профиль к контексту и соединению              */
/* ------------------------------------------------------------------ */

static void apply_fingerprint(WOLFSSL_CTX *ctx, WOLFSSL *ssl,
                              tls_fingerprint_t fp)
{
    const char *ciphers = NULL;

    switch (fp) {
    case TLS_FP_CHROME120:
        ciphers = fp_chrome120_ciphers;
        break;
    case TLS_FP_FIREFOX121:
        ciphers = fp_firefox121_ciphers;
        break;
    case TLS_FP_IOS17:
        ciphers = fp_ios17_ciphers;
        break;
    case TLS_FP_NONE:
    default:
        return;
    }

    /* Cipher suites */
    if (ciphers)
        wolfSSL_CTX_set_cipher_list(ctx, ciphers);

    /* x25519 key share — все три клиента используют */
    wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_X25519);

    /* ALPN: h2 + http/1.1 */
    wolfSSL_UseALPN(ssl, (char *)alpn_protocols,
                    strlen(alpn_protocols),
                    WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);

    log_msg(LOG_DEBUG, "TLS fingerprint: %s",
            fp == TLS_FP_CHROME120  ? "Chrome120" :
            fp == TLS_FP_FIREFOX121 ? "Firefox121" :
            fp == TLS_FP_IOS17      ? "iOS17" : "unknown");
}

/* ------------------------------------------------------------------ */
/*  tls_connect                                                        */
/* ------------------------------------------------------------------ */

int tls_connect(tls_conn_t *conn, int fd, const tls_config_t *config)
{
    memset(conn, 0, sizeof(*conn));
    conn->fd = fd;
    conn->config = *config;

    /* Контекст: TLS 1.2 + 1.3 (Reality требует 1.3, fallback 1.2) */
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (!ctx) {
        log_msg(LOG_ERROR, "TLS: wolfSSL_CTX_new провалился");
        return -1;
    }

    /* Минимум TLS 1.2 */
    wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2);

    /* Верификация сертификата */
    if (!config->verify_cert) {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }

    /* SSL объект */
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) {
        log_msg(LOG_ERROR, "TLS: wolfSSL_new провалился");
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    /* Привязать TCP дескриптор */
    wolfSSL_set_fd(ssl, fd);

    /* SNI */
    if (config->sni && config->sni[0]) {
        int ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME,
                                 config->sni, (unsigned short)strlen(config->sni));
        if (ret != WOLFSSL_SUCCESS)
            log_msg(LOG_WARN, "TLS: UseSNI провалился: %d", ret);
    }

    /* Fingerprint профиль */
    apply_fingerprint(ctx, ssl, config->fingerprint);

    /* TLS handshake */
    int ret = wolfSSL_connect(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, ret);
        wolfSSL_ERR_error_string(err, tls_err_buf);
        log_msg(LOG_WARN, "TLS handshake провалился: %s", tls_err_buf);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    conn->ssl = ssl;
    conn->ctx = ctx;
    conn->connected = true;

    log_msg(LOG_DEBUG, "TLS соединение установлено (%s, %s)",
            wolfSSL_get_version(ssl),
            wolfSSL_get_cipher_name(ssl));

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
    if (conn->ctx) {
        wolfSSL_CTX_free((WOLFSSL_CTX *)conn->ctx);
        conn->ctx = NULL;
    }
    conn->connected = false;
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

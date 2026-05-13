#include "config.h"
#include "constants.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <regex.h>

/* Максимальная длина строки в конфиге */
#define MAX_LINE 8192

/* Порт сервера по умолчанию */
#define DEFAULT_SERVER_PORT 443

/* Максимальное количество серверов */
#define MAX_SERVERS 64

/* Тип текущей секции */
typedef enum {
    SECTION_NONE,
    SECTION_EBURNET,
    SECTION_SERVER,
    SECTION_DNS,
    SECTION_DNS_RULE,
    SECTION_DNS_POLICY,
    SECTION_DEVICE_POLICY,
    SECTION_PROXY_GROUP,
    SECTION_RULE_PROVIDER,
    SECTION_PROXY_PROVIDER,
    SECTION_TRAFFIC_RULE,
} section_type_t;

#define MAX_DNS_RULES      256
#define MAX_DNS_POLICIES   64
#define MAX_DEVICES        64
#define MAX_PROXY_GROUPS    32
#define MAX_PROXY_PROVIDERS 16
#define MAX_RULE_PROVIDERS  16
#define MAX_TRAFFIC_RULES   512
#define AWG_BLOB_MAX        8192
#define MAX_GROUP_SERVERS   256

/* Убрать \n/\r из строки перед передачей в лог — защита от log injection */
static void sanitize_log(char *s)
{
    for (char *p = s; *p; p++)
        if (*p == '\n' || *p == '\r') *p = ' ';
}

/* Удаление окружающих кавычек из строки */
static void strip_quotes(char *s)
{
    size_t len = strlen(s);
    if (len < 2)
        return;

    if ((s[0] == '\'' && s[len - 1] == '\'') ||
        (s[0] == '"'  && s[len - 1] == '"')) {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }
}

/* Пропуск пробелов в начале строки */
static char *skip_whitespace(char *s)
{
    while (*s && (*s == ' ' || *s == '\t'))
        s++;
    return s;
}

/* Извлечение следующего токена, разделённого пробелами/табами */
static char *next_token(char **cursor)
{
    char *s = skip_whitespace(*cursor);
    if (*s == '\0')
        return NULL;

    char *start = s;

    /* Если токен начинается с кавычки — ищем закрывающую, убираем кавычки */
    if (*s == '\'' || *s == '"') {
        char quote = *s;
        start = ++s;  /* пропустить открывающую кавычку */
        while (*s && *s != quote)
            s++;
        /* s указывает на закрывающую кавычку или \0 */
    } else {
        while (*s && *s != ' ' && *s != '\t' && *s != '\n' && *s != '\r')
            s++;
    }

    if (*s) {
        *s = '\0';
        *cursor = s + 1;
    } else {
        *cursor = s;
    }
    return start;
}

/* Безопасный парсинг числа из UCI строки.
 * При ошибке возвращает default_val и логирует WARNING. */
static int parse_int_uci(const char *value, const char *field_name,
                          int default_val, int min_val, int max_val)
{
    if (!value || !value[0]) return default_val;

    char *endptr;
    errno = 0;
    long v = strtol(value, &endptr, 10);

    if (errno != 0 || endptr == value || *endptr != '\0') {
        log_msg(LOG_WARN,
            "config: поле %s='%s' — не число, использую %d",
            field_name, value, default_val);
        return default_val;
    }

    if (v < (long)min_val || v > (long)max_val) {
        log_msg(LOG_WARN,
            "config: поле %s=%ld вне диапазона [%d..%d], использую %d",
            field_name, v, min_val, max_val, default_val);
        return default_val;
    }

    return (int)v;
}

/* WHY: reality_pbk — base64url X25519 public key (32 байта → 43 символа без padding).
 * Алфавит RFC 4648 §5: A-Za-z0-9-_
 * Ранняя валидация: ошибка при загрузке конфига, не при первом соединении. */
static bool reality_pbk_valid(const char *pbk)
{
    if (!pbk) return false;
    size_t len = strlen(pbk);
    if (len != 43) return false;
    for (size_t i = 0; i < 43; i++) {
        char c = pbk[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_'))
            return false;
    }
    return true;
}

/* WHY: поддерживаемые TLS fingerprint-профили для Reality.
 * Неизвестное значение — silent fallback на chrome120 без диагностики. */
static const char * const k_valid_fingerprints[] = {
    "chrome", "chrome120", NULL
};

/* Применение опции к секции 4eburnet */
static void apply_eburnet_option(EburNetConfig *cfg, const char *key, const char *value)
{
    if (strcmp(key, "enabled") == 0) {
        if (strcmp(value, "1") == 0)      cfg->enabled = true;
        else if (strcmp(value, "0") == 0) cfg->enabled = false;
        else log_msg(LOG_WARN, "enabled: невалидное '%s', ожидается '0'/'1'", value);
    } else if (strcmp(key, "log_level") == 0) {
        strncpy(cfg->log_level, value, sizeof(cfg->log_level) - 1);
        cfg->log_level[sizeof(cfg->log_level) - 1] = '\0';
    } else if (strcmp(key, "mode") == 0) {
        strncpy(cfg->mode, value, sizeof(cfg->mode) - 1);
        cfg->mode[sizeof(cfg->mode) - 1] = '\0';
    } else if (strcmp(key, "lan_interface") == 0) {
        int _n = snprintf(cfg->lan_interface, sizeof(cfg->lan_interface), "%s", value);
        if (_n < 0 || (size_t)_n >= sizeof(cfg->lan_interface))
            log_msg(LOG_WARN, "config: обрезано: lan_interface");
    } else if (strcmp(key, "tai_utc_offset") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 0 && v <= 200)
            cfg->tai_utc_offset = (int)v;
        else
            log_msg(LOG_WARN, "tai_utc_offset: невалидное '%s'", value);
    } else if (strcmp(key, "region") == 0) {
        int _n = snprintf(cfg->geo_region, sizeof(cfg->geo_region), "%s", value);
        if (_n < 0 || (size_t)_n >= sizeof(cfg->geo_region))
            log_msg(LOG_WARN, "config: обрезано: geo_region");
    } else if (strcmp(key, "geo_dir") == 0) {
        int _n = snprintf(cfg->geo_dir, sizeof(cfg->geo_dir), "%s", value);
        if (_n < 0 || (size_t)_n >= sizeof(cfg->geo_dir))
            log_msg(LOG_WARN, "config: обрезано: geo_dir");
    } else if (strcmp(key, "geo_profile") == 0) {
        int _n = snprintf(cfg->geo_profile, sizeof(cfg->geo_profile), "%s", value);
        if (_n < 0 || (size_t)_n >= sizeof(cfg->geo_profile))
            log_msg(LOG_WARN, "config: обрезано: geo_profile");
    } else if (strcmp(key, "dpi_dir") == 0) {
        int _n = snprintf(cfg->dpi_dir, sizeof(cfg->dpi_dir), "%s", value);
        if (_n < 0 || (size_t)_n >= sizeof(cfg->dpi_dir))
            log_msg(LOG_WARN, "config: обрезано: dpi_dir");
    } else if (strcmp(key, "dpi_enabled") == 0) {
        if (strcmp(value, "1") == 0)      cfg->dpi_enabled = true;
        else if (strcmp(value, "0") == 0) cfg->dpi_enabled = false;
        else log_msg(LOG_WARN, "dpi_enabled: невалидное '%s', ожидается '0'/'1'", value);
    } else if (strcmp(key, "dpi_split_pos") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 1 && v <= 1400)
            cfg->dpi_split_pos = (int)v;
        else
            log_msg(LOG_WARN,
                    "dpi_split_pos: невалидное '%s' (диапазон 1..1400), "
                    "используется %d", value, cfg->dpi_split_pos);
    } else if (strcmp(key, "dpi_fake_ttl") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 1 && v <= 64)
            cfg->dpi_fake_ttl = (int)v;
        else
            log_msg(LOG_WARN,
                    "dpi_fake_ttl: невалидное '%s' (диапазон 1..64), "
                    "используется %d", value, cfg->dpi_fake_ttl);
    } else if (strcmp(key, "dpi_fake_repeats") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 1 && v <= 20)
            cfg->dpi_fake_repeats = (int)v;
        else
            log_msg(LOG_WARN,
                    "dpi_fake_repeats: невалидное '%s' (диапазон 1..20), "
                    "используется %d", value, cfg->dpi_fake_repeats);
    } else if (strcmp(key, "dpi_fake_sni") == 0) {
        size_t vlen = strlen(value);
        /* Базовая проверка: не пустой, нет пробелов/управляющих символов, ≤ 253 */
        int valid = (vlen > 0 && vlen <= 253);
        for (size_t i = 0; i < vlen && valid; i++)
            if (value[i] == ' ' || value[i] == '\t' ||
                value[i] == '\n' || value[i] == '\r')
                valid = 0;
        if (valid) {
            int _n = snprintf(cfg->dpi_fake_sni, sizeof(cfg->dpi_fake_sni), "%s", value);
            if (_n < 0 || (size_t)_n >= sizeof(cfg->dpi_fake_sni))
                log_msg(LOG_WARN, "config: обрезано: dpi_fake_sni");
        } else
            log_msg(LOG_WARN,
                    "dpi_fake_sni: невалидный hostname '%s', "
                    "используется '%s'", value, cfg->dpi_fake_sni);
    } else if (strcmp(key, "cdn_update_interval_days") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 0 && v <= 365)
            cfg->cdn_update_interval_days = (int)v;
        else
            log_msg(LOG_WARN,
                    "cdn_update_interval_days: невалидное '%s' (диапазон 0..365), "
                    "используется %d", value, cfg->cdn_update_interval_days);
    } else if (strcmp(key, "cdn_cf_v4_url") == 0) {
        /* Пустая строка → default без предупреждения.
         * Минимальная валидация: "https://X" — хотя бы один символ после схемы */
        size_t vlen = strlen(value);
        if (vlen == 0) { /* пусто → default */ }
        else if (vlen <= 8 || strncmp(value, "https://", 8) != 0)
            log_msg(LOG_WARN,
                    "cdn_cf_v4_url: ожидается https://host/path, "
                    "получено '%s' — поле не изменено", value);
        else {
            int _n = snprintf(cfg->cdn_cf_v4_url, sizeof(cfg->cdn_cf_v4_url),
                              "%s", value);
            if (_n < 0 || (size_t)_n >= sizeof(cfg->cdn_cf_v4_url))
                log_msg(LOG_WARN, "config: обрезано: cdn_cf_v4_url");
        }
    } else if (strcmp(key, "cdn_cf_v6_url") == 0) {
        size_t vlen = strlen(value);
        if (vlen == 0) { /* пусто → default */ }
        else if (vlen <= 8 || strncmp(value, "https://", 8) != 0)
            log_msg(LOG_WARN,
                    "cdn_cf_v6_url: ожидается https://host/path, "
                    "получено '%s' — поле не изменено", value);
        else {
            int _n = snprintf(cfg->cdn_cf_v6_url, sizeof(cfg->cdn_cf_v6_url),
                              "%s", value);
            if (_n < 0 || (size_t)_n >= sizeof(cfg->cdn_cf_v6_url))
                log_msg(LOG_WARN, "config: обрезано: cdn_cf_v6_url");
        }
    } else if (strcmp(key, "cdn_fastly_url") == 0) {
        size_t vlen = strlen(value);
        if (vlen == 0) { /* пусто → default */ }
        else if (vlen <= 8 || strncmp(value, "https://", 8) != 0)
            log_msg(LOG_WARN,
                    "cdn_fastly_url: ожидается https://host/path, "
                    "получено '%s' — поле не изменено", value);
        else {
            int _n = snprintf(cfg->cdn_fastly_url, sizeof(cfg->cdn_fastly_url),
                              "%s", value);
            if (_n < 0 || (size_t)_n >= sizeof(cfg->cdn_fastly_url))
                log_msg(LOG_WARN, "config: обрезано: cdn_fastly_url");
        }
    } else if (strcmp(key, "opencck_url") == 0) {
        size_t vlen = strlen(value);
        if (vlen == 0) { /* пусто → выключено */ }
        else if (vlen <= 8 || strncmp(value, "https://", 8) != 0)
            log_msg(LOG_WARN,
                    "opencck_url: ожидается https://host/path, "
                    "получено '%s' — поле не изменено", value);
        else {
            int _n = snprintf(cfg->opencck_url, sizeof(cfg->opencck_url),
                              "%s", value);
            if (_n < 0 || (size_t)_n >= sizeof(cfg->opencck_url))
                log_msg(LOG_WARN, "config: обрезано: opencck_url");
        }
    } else if (strcmp(key, "opencck_update_interval_s") == 0) {
        char *ep;
        long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 0 && v <= 604800)
            cfg->opencck_update_interval_s = (uint32_t)v;
        else
            log_msg(LOG_WARN,
                    "opencck_update_interval_s: невалидное '%s' (0..604800), "
                    "используется %u", value, cfg->opencck_update_interval_s);
    } else if (strcmp(key, "flow_offload") == 0) {
        cfg->flow_offload = (strcmp(value, "1") == 0);
    } else if (strcmp(key, "tc_fast_enabled") == 0) {
        cfg->tc_fast_enabled = (strcmp(value, "1") == 0);
    } else if (strcmp(key, "mtu") == 0) {
        uint32_t v = (uint32_t)strtoul(value, NULL, 10);
        cfg->mtu = (v >= 576 && v <= 9000) ? (uint16_t)v : 0;
    } else if (strcmp(key, "lan_prefix") == 0) {
        struct in_addr a;
        if (inet_pton(AF_INET, value, &a) == 1) cfg->lan_prefix = ntohl(a.s_addr);
    } else if (strcmp(key, "lan_mask") == 0) {
        struct in_addr a;
        if (inet_pton(AF_INET, value, &a) == 1) cfg->lan_mask = ntohl(a.s_addr);
    } else if (strcmp(key, "mixed_port") == 0) {
        cfg->mixed_port = (uint16_t)strtoul(value, NULL, 10);
    } else if (strcmp(key, "inbound_auth") == 0) {
        cfg->inbound_auth = (strcmp(value, "1") == 0);
    } else if (strcmp(key, "inbound_username") == 0) {
        strncpy(cfg->inbound_username, value, sizeof(cfg->inbound_username) - 1);
    } else if (strcmp(key, "inbound_password") == 0) {
        strncpy(cfg->inbound_password, value, sizeof(cfg->inbound_password) - 1);
    } else if (strcmp(key, "sniffer_tls") == 0) {
        cfg->sniffer.tls_sni = (strcmp(value, "1") == 0);
    } else if (strcmp(key, "sniffer_http") == 0) {
        cfg->sniffer.http_host = (strcmp(value, "1") == 0);
    } else if (strcmp(key, "sniffer_quic") == 0) {
        cfg->sniffer.quic_sni = (strcmp(value, "1") == 0);
    } else if (strcmp(key, "sniffer_override_dest") == 0) {
        cfg->sniffer.override_dest = (strcmp(value, "1") == 0);
    } else if (strcmp(key, "sniffer_bypass") == 0) {
        if (cfg->sniffer.bypass_count < 32)
            strncpy(cfg->sniffer.bypass_domains[cfg->sniffer.bypass_count++],
                    value, 127);
    } else if (strcmp(key, "dpi_whitelist") == 0) {
        if (cfg->dpi_whitelist.count < MAX_DPI_DOMAIN_LIST)
            strncpy(cfg->dpi_whitelist.entries[cfg->dpi_whitelist.count++],
                    value, sizeof(cfg->dpi_whitelist.entries[0]) - 1);
    } else if (strcmp(key, "dpi_blacklist") == 0) {
        if (cfg->dpi_blacklist.count < MAX_DPI_DOMAIN_LIST)
            strncpy(cfg->dpi_blacklist.entries[cfg->dpi_blacklist.count++],
                    value, sizeof(cfg->dpi_blacklist.entries[0]) - 1);
    } else {
        log_msg(LOG_WARN, "Неизвестная опция 4eburnet: %s", key);
    }
}

/* MAC парсинг и нормализация.
 * %x без ширины безопасен: strlen==17 гарантирует макс 2 hex-цифры на октет,
 * а проверка m[i]>255 отсеивает невалидные значения (L-07). */
static int parse_mac(const char *str, uint8_t mac[6], char *out_str)
{
    if (!str || strlen(str) != 17) return -1;
    unsigned int m[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) {
        if (m[i] > 255) return -1;
        mac[i] = (uint8_t)m[i];
    }
{   int _n = snprintf(out_str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    if (_n < 0 || (size_t)_n >= 18)
        log_msg(LOG_DEBUG, "config: обрезано (некритично): %d", __LINE__);
}
    return 0;
}

/* Применение опции к текущему серверу */
/* Возвращает 0 при успехе, -1 при OOM */
static int apply_server_option(ServerConfig *srv, const char *key, const char *value)
{
    if (strcmp(key, "name") == 0) {
        int _n = snprintf(srv->name, sizeof(srv->name), "%s", value);
        if (_n < 0 || (size_t)_n >= sizeof(srv->name)) {
            log_msg(LOG_ERROR, "config: поле обрезано: srv->name");
            return -1;
        }
    } else if (strcmp(key, "enabled") == 0) {
        if (strcmp(value, "1") == 0)      srv->enabled = true;
        else if (strcmp(value, "0") == 0) srv->enabled = false;
        else log_msg(LOG_WARN, "server.enabled: невалидное '%s', ожидается '0'/'1'", value);
    } else if (strcmp(key, "protocol") == 0) {
        strncpy(srv->protocol, value, sizeof(srv->protocol) - 1);
        srv->protocol[sizeof(srv->protocol) - 1] = '\0';
    } else if (strcmp(key, "address") == 0) {
        /* P3-02: WARNING но не reject — address используется только через
         * TLS/WireGuard API, никогда не передаётся в shell из C (DEC-033) */
        if (strpbrk(value, ";|&`$(){}[]<>\\\"'"))
            log_msg(LOG_WARN, "config: address содержит спецсимволы");
        strncpy(srv->address, value, sizeof(srv->address) - 1);
        srv->address[sizeof(srv->address) - 1] = '\0';
    } else if (strcmp(key, "port") == 0) {
        char *endptr;
        long port_val = strtol(value, &endptr, 10);
        if (endptr == value || (*endptr != '\0' && *endptr != '\n' && *endptr != '\r')) {
            log_msg(LOG_WARN, "Невалидный порт: '%s'", value);
            port_val = DEFAULT_SERVER_PORT;
        }
        if (port_val < 1 || port_val > 65535) {
            log_msg(LOG_WARN, "Конфиг: невалидный порт %ld", port_val);
            port_val = DEFAULT_SERVER_PORT;
        }
        srv->port = (uint16_t)port_val;
    } else if (strcmp(key, "uuid") == 0) {
        /* P3-02: UUID формат: 36 символов, hex + дефисы */
        if (strlen(value) == 36 &&
            strspn(value, "0123456789abcdefABCDEF-") != 36)
            log_msg(LOG_WARN, "config: UUID содержит невалидные символы");
        strncpy(srv->uuid, value, sizeof(srv->uuid) - 1);
        srv->uuid[sizeof(srv->uuid) - 1] = '\0';
    } else if (strcmp(key, "password") == 0) {
        /* P3-02: WARNING но не reject — password передаётся только через
         * TLS/WireGuard API, не в shell-строку (DEC-033) */
        if (strpbrk(value, ";|&`$()\\"))
            log_msg(LOG_WARN, "config: password содержит shell-спецсимволы");
        strncpy(srv->password, value, sizeof(srv->password) - 1);
        srv->password[sizeof(srv->password) - 1] = '\0';
    } else if (strcmp(key, "ss_method") == 0) {
        strncpy(srv->ss_method, value, sizeof(srv->ss_method) - 1);
        srv->ss_method[sizeof(srv->ss_method) - 1] = '\0';
    } else if (strcmp(key, "vmess_security") == 0) {
        strncpy(srv->vmess_security, value, sizeof(srv->vmess_security) - 1);
        srv->vmess_security[sizeof(srv->vmess_security) - 1] = '\0';
    } else if (strcmp(key, "transport") == 0) {
        strncpy(srv->transport, value, sizeof(srv->transport) - 1);
        srv->transport[sizeof(srv->transport) - 1] = '\0';
    } else if (strcmp(key, "xhttp_path") == 0) {
        strncpy(srv->xhttp_path, value, sizeof(srv->xhttp_path) - 1);
        srv->xhttp_path[sizeof(srv->xhttp_path) - 1] = '\0';
    } else if (strcmp(key, "xhttp_host") == 0) {
        strncpy(srv->xhttp_host, value, sizeof(srv->xhttp_host) - 1);
        srv->xhttp_host[sizeof(srv->xhttp_host) - 1] = '\0';
    } else if (strcmp(key, "ws_path") == 0) {
        strncpy(srv->ws_path, value, sizeof(srv->ws_path) - 1);
        srv->ws_path[sizeof(srv->ws_path) - 1] = '\0';
    } else if (strcmp(key, "ws_host") == 0) {
        strncpy(srv->ws_host, value, sizeof(srv->ws_host) - 1);
        srv->ws_host[sizeof(srv->ws_host) - 1] = '\0';
    } else if (strcmp(key, "packet_encoding") == 0) {
        strncpy(srv->packet_encoding, value,
                sizeof(srv->packet_encoding) - 1);
        srv->packet_encoding[sizeof(srv->packet_encoding) - 1] = '\0';
    } else if (strcmp(key, "reality_short_id") == 0) {
        strncpy(srv->reality_short_id, value, sizeof(srv->reality_short_id) - 1);
        srv->reality_short_id[sizeof(srv->reality_short_id) - 1] = '\0';
    } else if (strcmp(key, "reality_pbk") == 0) {
        if (!reality_pbk_valid(value))
            log_msg(LOG_WARN,
                "config: сервер '%s': reality_pbk невалидный "
                "(ожидается 43 символа base64url, получено %zu: '%.8s...')",
                srv->name, strlen(value), value);
        strncpy(srv->reality_pbk, value, sizeof(srv->reality_pbk) - 1);
        srv->reality_pbk[sizeof(srv->reality_pbk) - 1] = '\0';
    } else if (strcmp(key, "reality_sni") == 0) {
        strncpy(srv->reality_sni, value, sizeof(srv->reality_sni) - 1);
        srv->reality_sni[sizeof(srv->reality_sni) - 1] = '\0';
    } else if (strcmp(key, "reality_flow") == 0) {
        strncpy(srv->reality_flow, value, sizeof(srv->reality_flow) - 1);
        srv->reality_flow[sizeof(srv->reality_flow) - 1] = '\0';
    } else if (strcmp(key, "reality_fingerprint") == 0) {
        bool fp_ok = false;
        for (int i = 0; k_valid_fingerprints[i]; i++)
            if (strcasecmp(value, k_valid_fingerprints[i]) == 0) { fp_ok = true; break; }
        if (!fp_ok)
            log_msg(LOG_WARN,
                "config: сервер '%s': reality_fingerprint '%s' неизвестен — "
                "используется chrome120",
                srv->name, value);
        strncpy(srv->reality_fingerprint, value, sizeof(srv->reality_fingerprint) - 1);
        srv->reality_fingerprint[sizeof(srv->reality_fingerprint) - 1] = '\0';
    /* AWG параметры */
    } else if (strcmp(key, "awg_private_key") == 0) {
        int _n = snprintf(srv->awg_private_key, sizeof(srv->awg_private_key), "%s", value);
        if (_n < 0 || (size_t)_n >= sizeof(srv->awg_private_key)) {
            log_msg(LOG_ERROR, "config: поле обрезано: awg_private_key");
            return -1;
        }
        {
            size_t key_len = strnlen(srv->awg_private_key, sizeof(srv->awg_private_key));
            if (key_len != 44) {
                log_msg(LOG_ERROR,
                        "config: awg_private_key: неверная длина %zu (ожидается 44)", key_len);
                srv->awg_private_key[0] = '\0';
            }
        }
    } else if (strcmp(key, "awg_public_key") == 0) {
        int _n = snprintf(srv->awg_public_key, sizeof(srv->awg_public_key), "%s", value);
        if (_n < 0 || (size_t)_n >= sizeof(srv->awg_public_key)) {
            log_msg(LOG_ERROR, "config: поле обрезано: awg_public_key");
            return -1;
        }
        {
            size_t key_len = strnlen(srv->awg_public_key, sizeof(srv->awg_public_key));
            if (key_len != 44) {
                log_msg(LOG_ERROR,
                        "config: awg_public_key: неверная длина %zu (ожидается 44)", key_len);
                srv->awg_public_key[0] = '\0';
            }
        }
    } else if (strcmp(key, "awg_psk") == 0) {
        int _n = snprintf(srv->awg_psk, sizeof(srv->awg_psk), "%s", value);
        if (_n < 0 || (size_t)_n >= sizeof(srv->awg_psk)) {
            log_msg(LOG_ERROR, "config: поле обрезано: awg_psk");
            return -1;
        }
    } else if (strcmp(key, "awg_h1") == 0) {
        /* P9-04: awg_h — формат "MIN-MAX" или "VAL" (десятичные uint32) */
        if (strspn(value, "0123456789-") != strlen(value))
            log_msg(LOG_WARN, "config: awg_h1 невалидный формат: %s", value);
        int _n = snprintf(srv->awg_h1, sizeof(srv->awg_h1), "%s", value);
        if (_n < 0 || (size_t)_n >= sizeof(srv->awg_h1))
            log_msg(LOG_WARN, "config: обрезано: awg_h1");
    } else if (strcmp(key, "awg_h2") == 0) {
        if (strspn(value, "0123456789-") != strlen(value))
            log_msg(LOG_WARN, "config: awg_h2 невалидный формат: %s", value);
        int _n = snprintf(srv->awg_h2, sizeof(srv->awg_h2), "%s", value);
        if (_n < 0 || (size_t)_n >= sizeof(srv->awg_h2))
            log_msg(LOG_WARN, "config: обрезано: awg_h2");
    } else if (strcmp(key, "awg_h3") == 0) {
        if (strspn(value, "0123456789-") != strlen(value))
            log_msg(LOG_WARN, "config: awg_h3 невалидный формат: %s", value);
        int _n = snprintf(srv->awg_h3, sizeof(srv->awg_h3), "%s", value);
        if (_n < 0 || (size_t)_n >= sizeof(srv->awg_h3))
            log_msg(LOG_WARN, "config: обрезано: awg_h3");
    } else if (strcmp(key, "awg_h4") == 0) {
        if (strspn(value, "0123456789-") != strlen(value))
            log_msg(LOG_WARN, "config: awg_h4 невалидный формат: %s", value);
        int _n = snprintf(srv->awg_h4, sizeof(srv->awg_h4), "%s", value);
        if (_n < 0 || (size_t)_n >= sizeof(srv->awg_h4))
            log_msg(LOG_WARN, "config: обрезано: awg_h4");
    } else if (strcmp(key, "awg_s1") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 0 && v <= 1500)
            srv->awg_s1 = (uint16_t)v;
    } else if (strcmp(key, "awg_s2") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 0 && v <= 1500)
            srv->awg_s2 = (uint16_t)v;
    } else if (strcmp(key, "awg_s3") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 0 && v <= 1500)
            srv->awg_s3 = (uint16_t)v;
    } else if (strcmp(key, "awg_s4") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 0 && v <= 1500)
            srv->awg_s4 = (uint16_t)v;
    } else if (strcmp(key, "awg_jc") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 0 && v <= 255)
            srv->awg_jc = (uint8_t)v;
    } else if (strcmp(key, "awg_jmin") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 0 && v <= 65535)
            srv->awg_jmin = (uint16_t)v;
    } else if (strcmp(key, "awg_jmax") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 0 && v <= 65535)
            srv->awg_jmax = (uint16_t)v;
    } else if (strncmp(key, "awg_i", 5) == 0 &&
               key[5] >= '1' && key[5] <= '5' && key[6] == '\0') {
        int idx = key[5] - '1';
        if (strnlen(value, AWG_BLOB_MAX + 1) > AWG_BLOB_MAX) {
            log_msg(LOG_ERROR, "config: awg_i[%d]: поле слишком длинное — пропущено", idx);
            return 0;
        }
        free(srv->awg_i[idx]);
        srv->awg_i[idx] = strndup(value, AWG_BLOB_MAX);
        if (!srv->awg_i[idx]) {
            log_msg(LOG_ERROR, "config: OOM awg_i[%d]", idx);
            return -1;
        }
    } else if (strcmp(key, "awg_keepalive") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 0 && v <= 65535)
            srv->awg_keepalive = (uint16_t)v;
        else
            log_msg(LOG_WARN, "awg_keepalive: невалидное '%s'", value);
    /* P9-03: AWG mtu/dns/reserved */
    } else if (strcmp(key, "awg_mtu") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 576 && v <= 65535)
            srv->awg_mtu = (uint16_t)v;
        else
            log_msg(LOG_WARN, "awg_mtu: невалидное '%s'", value);
    } else if (strcmp(key, "awg_dns") == 0) {
        snprintf(srv->awg_dns, sizeof(srv->awg_dns), "%s", value);
    } else if (strcmp(key, "awg_reserved") == 0) {
        snprintf(srv->awg_reserved, sizeof(srv->awg_reserved), "%s", value);
    } else if (strcmp(key, "awg_j1") == 0) {
        if (strnlen(value, AWG_BLOB_MAX + 1) > AWG_BLOB_MAX) {
            log_msg(LOG_ERROR, "config: awg_j1: поле слишком длинное — пропущено");
            return 0;
        }
        free(srv->awg_j1);
        srv->awg_j1 = strndup(value, AWG_BLOB_MAX);
        if (!srv->awg_j1) {
            log_msg(LOG_ERROR, "config: OOM awg_j1");
            return -1;
        }
    } else if (strcmp(key, "awg_itime") == 0) {
        srv->awg_itime = (uint16_t)strtoul(value, NULL, 10);
    /* Hysteria2-специфичные опции */
    } else if (strcmp(key, "hy2_obfs_password") == 0) {
        strncpy(srv->hy2_obfs_password, value,
                sizeof(srv->hy2_obfs_password) - 1);
        srv->hy2_obfs_password[sizeof(srv->hy2_obfs_password) - 1] = '\0';
        /* Наличие непустого obfs_password = obfs включён */
        srv->hy2_obfs_enabled = (value[0] != '\0');
    } else if (strcmp(key, "hy2_sni") == 0) {
        strncpy(srv->hy2_sni, value, sizeof(srv->hy2_sni) - 1);
        srv->hy2_sni[sizeof(srv->hy2_sni) - 1] = '\0';
    } else if (strcmp(key, "hy2_insecure") == 0) {
        if (strcmp(value, "1") == 0)      srv->hy2_insecure = true;
        else if (strcmp(value, "0") == 0) srv->hy2_insecure = false;
        else log_msg(LOG_WARN, "hy2_insecure: невалидное '%s', ожидается '0'/'1'", value);
    } else if (strcmp(key, "hy2_up_mbps") == 0) {
        char *endp; long v = strtol(value, &endp, 10);
        if (endp == value || *endp != '\0') v = 0;  /* нечисловой ввод */
        srv->hy2_up_mbps = (v > 0 && v <= 100000) ? (uint32_t)v : 0;
    } else if (strcmp(key, "hy2_down_mbps") == 0) {
        char *endp; long v = strtol(value, &endp, 10);
        if (endp == value || *endp != '\0') v = 0;  /* нечисловой ввод */
        srv->hy2_down_mbps = (v > 0 && v <= 100000) ? (uint32_t)v : 0;
    /* AnyTLS-специфичные опции */
    } else if (strcmp(key, "anytls_password") == 0) {
        strncpy(srv->anytls_password, value, sizeof(srv->anytls_password) - 1);
        srv->anytls_password[sizeof(srv->anytls_password) - 1] = '\0';
    } else if (strcmp(key, "anytls_sni") == 0) {
        strncpy(srv->anytls_sni, value, sizeof(srv->anytls_sni) - 1);
        srv->anytls_sni[sizeof(srv->anytls_sni) - 1] = '\0';
    /* TUIC v5-специфичные опции */
    } else if (strcmp(key, "tuic_uuid") == 0) {
        strncpy(srv->tuic_uuid, value, sizeof(srv->tuic_uuid) - 1);
        srv->tuic_uuid[sizeof(srv->tuic_uuid) - 1] = '\0';
    } else if (strcmp(key, "tuic_password") == 0) {
        strncpy(srv->tuic_password, value, sizeof(srv->tuic_password) - 1);
        srv->tuic_password[sizeof(srv->tuic_password) - 1] = '\0';
    } else if (strcmp(key, "tuic_udp_relay_mode") == 0) {
        srv->tuic_udp_relay_mode = (strcmp(value, "quic") == 0) ? 1 : 0;
    } else if (strcmp(key, "tuic_cc") == 0) {
        strncpy(srv->tuic_cc, value, sizeof(srv->tuic_cc) - 1);
        srv->tuic_cc[sizeof(srv->tuic_cc) - 1] = '\0';
    } else if (strcmp(key, "tuic_cc_profile") == 0) {
        strncpy(srv->tuic_cc_profile, value, sizeof(srv->tuic_cc_profile) - 1);
        srv->tuic_cc_profile[sizeof(srv->tuic_cc_profile) - 1] = '\0';
#if CONFIG_EBURNET_STLS
    } else if (strcmp(key, "stls_password") == 0) {
        int _n = snprintf(srv->stls_password, sizeof(srv->stls_password), "%s", value);
        if (_n < 0 || (size_t)_n >= sizeof(srv->stls_password)) {
            log_msg(LOG_ERROR, "config: поле обрезано: stls_password");
            return -1;
        }
    } else if (strcmp(key, "stls_sni") == 0) {
        if (!strchr(value, '.') || value[0] == '.' || value[0] == '\0') {
            log_msg(LOG_WARN, "config: stls_sni '%s' не FQDN", value);
        } else {
            int _n = snprintf(srv->stls_sni, sizeof(srv->stls_sni), "%s", value);
            if (_n < 0 || (size_t)_n >= sizeof(srv->stls_sni)) {
                log_msg(LOG_ERROR, "config: поле обрезано: stls_sni");
                return -1;
            }
        }
#endif
    } else {
        log_msg(LOG_WARN, "Неизвестная опция server: %s", key);
    }

    /* M-08: jmin <= jmax проверка */
    if (srv->awg_jmin > srv->awg_jmax && srv->awg_jmax > 0) {
        uint16_t tmp = srv->awg_jmin;
        srv->awg_jmin = srv->awg_jmax;
        srv->awg_jmax = tmp;
    }
    return 0;
}

/* Разобрать одно вложенное OR-условие формата "TYPE,VALUE" → sub TrafficRule.
 * Пример: "DOMAIN-SUFFIX,.google.com" → type=DOMAIN_SUFFIX value=".google.com" */
static void parse_sub_condition(const char *str, TrafficRule *sub)
{
    memset(sub, 0, sizeof(*sub));
    const char *comma = strchr(str, ',');
    if (!comma) return;

    char tbuf[32];
    size_t tlen = (size_t)(comma - str);
    if (tlen >= sizeof(tbuf)) tlen = sizeof(tbuf) - 1;
    memcpy(tbuf, str, tlen);
    tbuf[tlen] = '\0';

    const char *val = comma + 1;
    snprintf(sub->value, sizeof(sub->value), "%s", val);

    if      (strcasecmp(tbuf, "DOMAIN") == 0)         sub->type = RULE_TYPE_DOMAIN;
    else if (strcasecmp(tbuf, "DOMAIN-SUFFIX") == 0)  sub->type = RULE_TYPE_DOMAIN_SUFFIX;
    else if (strcasecmp(tbuf, "DOMAIN-KEYWORD") == 0) sub->type = RULE_TYPE_DOMAIN_KEYWORD;
    else if (strcasecmp(tbuf, "IP-CIDR") == 0)        sub->type = RULE_TYPE_IP_CIDR;
    else if (strcasecmp(tbuf, "IP-CIDR6") == 0)       sub->type = RULE_TYPE_IP_CIDR6;
    else if (strcasecmp(tbuf, "GEOIP") == 0)          sub->type = RULE_TYPE_GEOIP;
    else if (strcasecmp(tbuf, "GEOSITE") == 0)        sub->type = RULE_TYPE_GEOSITE;
    else                                               sub->type = RULE_TYPE_DOMAIN;
}

/*
 * Единая точка входа парсинга UCI конфига. Монолитная функция —
 * секции server/proxy_group/traffic_rule ссылаются друг на друга,
 * однопроходный парсинг резолвит ссылки без повторного чтения файла.
 */
int config_load(const char *path, EburNetConfig *cfg)
{
    /* L-11: O_CLOEXEC через open()+fdopen() */
    int cfg_fd = open(path, O_RDONLY | O_CLOEXEC);
    FILE *f = (cfg_fd >= 0) ? fdopen(cfg_fd, "r") : NULL;
    if (!f) {
        if (cfg_fd >= 0) close(cfg_fd);
        log_msg(LOG_ERROR, "Не удалось открыть конфиг: %s", path);
        return -1;
    }

    /* Инициализация структуры */
    memset(cfg, 0, sizeof(*cfg));
    cfg->enabled = false;
{   int _n = snprintf(cfg->log_level, sizeof(cfg->log_level), "%s", "info");
    if (_n < 0 || (size_t)_n >= sizeof(cfg->log_level))
        log_msg(LOG_DEBUG, "config: обрезано (некритично): %d", __LINE__);
}
{   int _n = snprintf(cfg->mode, sizeof(cfg->mode), "%s", "rules");
    if (_n < 0 || (size_t)_n >= sizeof(cfg->mode))
        log_msg(LOG_DEBUG, "config: обрезано (некритично): %d", __LINE__);
}
    cfg->tai_utc_offset   = 37;  /* с 2017-01-01, https://www.ietf.org/timezones/data/leap-seconds.list */
{   int _n = snprintf(cfg->geo_profile, sizeof(cfg->geo_profile), "%s", "full");
    if (_n < 0 || (size_t)_n >= sizeof(cfg->geo_profile))
        log_msg(LOG_DEBUG, "config: обрезано (некритично): %d", __LINE__);
}
    /* DPI bypass defaults */
    cfg->dpi_enabled      = true;
    cfg->dpi_split_pos    = 1;
    cfg->dpi_fake_ttl     = 5;
    cfg->dpi_fake_repeats = 8;
{   int _n = snprintf(cfg->dpi_fake_sni, sizeof(cfg->dpi_fake_sni), EBURNET_DPI_DEFAULT_FAKE_SNI);
    if (_n < 0 || (size_t)_n >= sizeof(cfg->dpi_fake_sni))
        log_msg(LOG_DEBUG, "config: обрезано (некритично): %d", __LINE__);
}

    /* CDN updater defaults */
    cfg->cdn_update_interval_days = 7;
    /* cdn_*_url: пустые строки → cdn_updater.c использует встроенные defaults */

    /* Inbound proxy defaults */
    cfg->mixed_port   = 1080;
    cfg->inbound_auth = false;
    cfg->mtu          = 0;  /* 0 = не менять системный MTU */

    /* WHY: adblock включён по умолчанию — пользователь должен явно выключить
     * через UCI (block_geosite_ads=0), не наоборот. Без этих defaults
     * dns_rules_add_geosite не вызывается и geosite-ads игнорируется. */
    cfg->dns.block_geosite_ads      = true;
    cfg->dns.block_geosite_trackers = true;
    cfg->dns.block_geosite_threats  = true;
    cfg->dns.stale_while_revalidate = true;
    cfg->dns.stale_grace_seconds    = 3600;

    /* Sniffer defaults: TLS SNI включён (was always on) → backward compat.
     * HTTP Host и QUIC SNI выключены — новые opt-in фичи. */
    cfg->sniffer.tls_sni       = true;
    cfg->sniffer.http_host     = false;
    cfg->sniffer.quic_sni      = false;
    cfg->sniffer.override_dest = true;
    strncpy(cfg->sniffer.bypass_domains[0], "*.local", 127);
    cfg->sniffer.bypass_count  = 1;

    /* Временные массивы на heap (H-11: ~191KB на стеке → calloc) */
    ServerConfig *servers = calloc(MAX_SERVERS, sizeof(ServerConfig));
    DnsRule *dns_rules = calloc(MAX_DNS_RULES, sizeof(DnsRule));
    DnsPolicy *dp_tmp = calloc(MAX_DNS_POLICIES, sizeof(DnsPolicy));
    device_config_t *devices_tmp = calloc(MAX_DEVICES, sizeof(device_config_t));
    ProxyGroupConfig *pg_tmp = calloc(MAX_PROXY_GROUPS, sizeof(ProxyGroupConfig));
    ProxyProviderConfig *pp_tmp = calloc(MAX_PROXY_PROVIDERS, sizeof(ProxyProviderConfig));
    RuleProviderConfig *rp_tmp = calloc(MAX_RULE_PROVIDERS, sizeof(RuleProviderConfig));
    TrafficRule *tr_tmp = calloc(MAX_TRAFFIC_RULES, sizeof(TrafficRule));
    int pg_count = 0, pp_count = 0, rp_count = 0, tr_count = 0, dp_count = 0;

    if (!servers || !dns_rules || !dp_tmp || !devices_tmp ||
        !pg_tmp || !pp_tmp || !rp_tmp || !tr_tmp) {
        log_msg(LOG_ERROR, "Конфиг: нет памяти для временных массивов");
        free(servers); free(dns_rules); free(dp_tmp); free(devices_tmp);
        free(pg_tmp); free(pp_tmp); free(rp_tmp); free(tr_tmp);
        fclose(f);
        return -1;
    }

    int srv_count = 0;
    int dns_rule_count = 0;
    cfg->dns_rule_count = 0;
    int dev_count = 0;
    cfg->device_count = 0;

    section_type_t section = SECTION_NONE;
    char *line = malloc(MAX_LINE);
    if (!line) {
        log_msg(LOG_ERROR, "Конфиг: нет памяти для line buffer");
        free(servers); free(dns_rules); free(dp_tmp); free(devices_tmp);
        free(pg_tmp); free(pp_tmp); free(rp_tmp); free(tr_tmp);
        fclose(f);
        return -1;
    }
    int line_num = 0;

    while (fgets(line, MAX_LINE, f)) {
        line_num++;

        /* Убираем перенос строки */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        char *cursor = skip_whitespace(line);

        /* Пустая строка или комментарий */
        if (*cursor == '\0' || *cursor == '#')
            continue;

        char *keyword = next_token(&cursor);
        if (!keyword)
            continue;

        if (strcmp(keyword, "config") == 0) {
            /* Начало секции: config TYPE 'NAME' */
            char *type = next_token(&cursor);
            char *name = next_token(&cursor);
            if (!type) {
                log_msg(LOG_ERROR, "Ошибка в строке %d: нет типа секции", line_num);
                goto cleanup_fail;
            }

            if (name)
                strip_quotes(name);

            if (strcmp(type, "4eburnet") == 0) {
                section = SECTION_EBURNET;
            } else if (strcmp(type, "server") == 0) {
                if (srv_count >= MAX_SERVERS) {
                    log_msg(LOG_ERROR, "Строка %d: превышен лимит серверов (%d)",
                            line_num, MAX_SERVERS);
                    goto cleanup_fail;
                }
                section = SECTION_SERVER;
                memset(&servers[srv_count], 0, sizeof(ServerConfig));
                /* WHY: server enabled по умолчанию как proxy_provider.
                 * UCI 'option enabled 0' явно отключает сервер. Без этого
                 * новые сервера без явного option enabled пропускались. */
                servers[srv_count].enabled = true;
                /* WHY: CUBIC default — лучше NewReno на высоком RTT без сложности BBR.
                 * RFC 8312. Переключается через UCI tuic_cc=newreno. */
                strncpy(servers[srv_count].tuic_cc, "cubic",
                        sizeof(servers[srv_count].tuic_cc));
                strncpy(servers[srv_count].tuic_cc_profile, "standard",
                        sizeof(servers[srv_count].tuic_cc_profile));
                if (name) {
                    strncpy(servers[srv_count].name, name,
                            sizeof(servers[srv_count].name) - 1);
                }
                srv_count++;
            } else if (strcmp(type, "proxy_group") == 0) {
                section = SECTION_PROXY_GROUP;
                if (pg_count < MAX_PROXY_GROUPS) {
                    if (name) {
                        int _n = snprintf(pg_tmp[pg_count].name,
                            sizeof(pg_tmp[pg_count].name), "%s", name);
                        if (_n < 0 || (size_t)_n >= sizeof(pg_tmp[pg_count].name))
                            log_msg(LOG_WARN, "config: обрезано: pg->name");
                    }
                    pg_count++;
                    /* WHY: proxy_group enabled по умолчанию как proxy_provider
                     * (L667). UCI 'option enabled 0' явно отключает.
                     * Без этого group пропускалась в proxy_group_init →
                     * rules engine fallback на DIRECT. */
                    pg_tmp[pg_count - 1].enabled = true;
                }
            } else if (strcmp(type, "proxy_provider") == 0) {
                section = SECTION_PROXY_PROVIDER;
                if (pp_count < MAX_PROXY_PROVIDERS) {
                    ProxyProviderConfig *pp = &pp_tmp[pp_count++];
                    memset(pp, 0, sizeof(*pp));
                    pp->enabled = true;
                    if (name && name[0]) {
                        int _n = snprintf(pp->name, sizeof(pp->name), "%s", name);
                        if (_n < 0 || (size_t)_n >= sizeof(pp->name))
                            log_msg(LOG_WARN, "config: обрезано: pp->name");
                    }
                }
            } else if (strcmp(type, "rule_provider") == 0) {
                section = SECTION_RULE_PROVIDER;
                if (rp_count < MAX_RULE_PROVIDERS) {
                    if (name) {
                        int _n = snprintf(rp_tmp[rp_count].name,
                            sizeof(rp_tmp[rp_count].name), "%s", name);
                        if (_n < 0 || (size_t)_n >= sizeof(rp_tmp[rp_count].name))
                            log_msg(LOG_WARN, "config: обрезано: rp->name");
                    }
                    rp_count++;
                }
            } else if (strcmp(type, "traffic_rule") == 0) {
                section = SECTION_TRAFFIC_RULE;
                if (tr_count < MAX_TRAFFIC_RULES)
                    tr_count++;
            } else if (strcmp(type, "dns") == 0) {
                section = SECTION_DNS;
            } else if (strcmp(type, "device_policy") == 0) {
                section = SECTION_DEVICE_POLICY;
                if (dev_count < MAX_DEVICES) {
                    memset(&devices_tmp[dev_count], 0, sizeof(device_config_t));
                    if (name) {
                        int _n = snprintf(devices_tmp[dev_count].name,
                                 sizeof(devices_tmp[dev_count].name), "%s", name);
                        if (_n < 0 || (size_t)_n >= sizeof(devices_tmp[dev_count].name))
                            log_msg(LOG_WARN, "config: обрезано: device name");
                    }
                    dev_count++;
                }
            } else if (strcmp(type, "dns_rule") == 0) {
                section = SECTION_DNS_RULE;
                if (dns_rule_count < MAX_DNS_RULES) {
                    memset(&dns_rules[dns_rule_count], 0, sizeof(DnsRule));
                    dns_rule_count++;
                }
            } else if (strcmp(type, "dns_policy") == 0) {
                section = SECTION_DNS_POLICY;
                if (dp_count < MAX_DNS_POLICIES) {
                    memset(&dp_tmp[dp_count], 0, sizeof(DnsPolicy));
                    dp_count++;
                }
            } else {
                log_msg(LOG_WARN, "Строка %d: неизвестный тип секции '%s'",
                        line_num, type);
                section = SECTION_NONE;
            }
        } else if (strcmp(keyword, "option") == 0) {
            /* Параметр: option KEY 'VALUE' */
            char *key   = next_token(&cursor);
            char *value = next_token(&cursor);

            if (!key || !value) {
                log_msg(LOG_ERROR, "Строка %d: неполная опция", line_num);
                goto cleanup_fail;
            }

            strip_quotes(key);
            strip_quotes(value);

            /* S-04: UCI spec — option names только [a-zA-Z0-9_] */
            {
                bool valid_key = true;
                for (const char *p = key; *p; p++) {
                    if (!isalnum((unsigned char)*p) && *p != '_') {
                        valid_key = false;
                        break;
                    }
                }
                if (!valid_key) {
                    log_msg(LOG_WARN, "Строка %d: невалидный UCI ключ '%s'",
                            line_num, key);
                    continue;
                }
            }

            switch (section) {
            case SECTION_EBURNET:
                apply_eburnet_option(cfg, key, value);
                break;
            case SECTION_SERVER:
                if (srv_count > 0 &&
                    apply_server_option(&servers[srv_count - 1], key, value) < 0)
                    goto cleanup_fail;
                break;
            case SECTION_DNS: {
                DnsConfig *d = &cfg->dns;
                if (strcmp(key, "enabled") == 0) {
                    if (strcmp(value, "1") == 0)      d->enabled = true;
                    else if (strcmp(value, "0") == 0) d->enabled = false;
                    else log_msg(LOG_WARN, "dns.enabled: невалидное '%s'", value);
                } else if (strcmp(key, "listen_port") == 0)
                    d->listen_port = (uint16_t)parse_int_uci(
                        value, "listen_port", 53, 1, 65535);
                else if (strcmp(key, "upstream_bypass") == 0) {
                    int _n = snprintf(d->upstream_bypass, sizeof(d->upstream_bypass), "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->upstream_bypass)) {
                        log_msg(LOG_ERROR, "config: поле обрезано: upstream_bypass");
                        goto cleanup_fail;
                    }
                } else if (strcmp(key, "upstream_proxy") == 0) {
                    int _n = snprintf(d->upstream_proxy, sizeof(d->upstream_proxy), "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->upstream_proxy)) {
                        log_msg(LOG_ERROR, "config: поле обрезано: upstream_proxy");
                        goto cleanup_fail;
                    }
                } else if (strcmp(key, "upstream_default") == 0) {
                    int _n = snprintf(d->upstream_default, sizeof(d->upstream_default), "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->upstream_default)) {
                        log_msg(LOG_ERROR, "config: поле обрезано: upstream_default");
                        goto cleanup_fail;
                    }
                }
                else if (strcmp(key, "upstream_port") == 0)
                    d->upstream_port = (uint16_t)parse_int_uci(
                        value, "upstream_port", 53, 1, 65535);
                else if (strcmp(key, "cache_size") == 0)
                    d->cache_size = parse_int_uci(
                        value, "cache_size", 256, 0, 65536);
                else if (strcmp(key, "cache_ttl_max") == 0)
                    d->cache_ttl_max = parse_int_uci(
                        value, "cache_ttl_max", 3600, 0, 86400);
                else if (strcmp(key, "doh_enabled") == 0) {
                    if (strcmp(value, "1") == 0)      d->doh_enabled = true;
                    else if (strcmp(value, "0") == 0) d->doh_enabled = false;
                    else log_msg(LOG_WARN, "doh_enabled: невалидное '%s'", value);
                } else if (strcmp(key, "doh_url") == 0) {
                    int _n = snprintf(d->doh_url, sizeof(d->doh_url), "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->doh_url)) {
                        log_msg(LOG_ERROR, "config: поле обрезано: doh_url");
                        goto cleanup_fail;
                    }
                } else if (strcmp(key, "doh_sni") == 0) {
                    int _n = snprintf(d->doh_sni, sizeof(d->doh_sni), "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->doh_sni)) {
                        log_msg(LOG_ERROR, "config: поле обрезано: doh_sni");
                        goto cleanup_fail;
                    }
                } else if (strcmp(key, "doh_ip") == 0) {
                    int _n = snprintf(d->doh_ip, sizeof(d->doh_ip), "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->doh_ip)) {
                        log_msg(LOG_ERROR, "config: поле обрезано: doh_ip");
                        goto cleanup_fail;
                    }
                }
                else if (strcmp(key, "doh_port") == 0)
                    d->doh_port = (uint16_t)parse_int_uci(
                        value, "doh_port", 443, 1, 65535);
                else if (strcmp(key, "dot_enabled") == 0) {
                    if (strcmp(value, "1") == 0)      d->dot_enabled = true;
                    else if (strcmp(value, "0") == 0) d->dot_enabled = false;
                    else log_msg(LOG_WARN, "dot_enabled: невалидное '%s'", value);
                } else if (strcmp(key, "dot_server_ip") == 0) {
                    int _n = snprintf(d->dot_server_ip, sizeof(d->dot_server_ip), "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->dot_server_ip)) {
                        log_msg(LOG_ERROR, "config: поле обрезано: dot_server_ip");
                        goto cleanup_fail;
                    }
                }
                else if (strcmp(key, "dot_port") == 0)
                    d->dot_port = (uint16_t)parse_int_uci(
                        value, "dot_port", 853, 1, 65535);
                else if (strcmp(key, "dot_sni") == 0) {
                    int _n = snprintf(d->dot_sni, sizeof(d->dot_sni), "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->dot_sni)) {
                        log_msg(LOG_ERROR, "config: поле обрезано: dot_sni");
                        goto cleanup_fail;
                    }
                } else if (strcmp(key, "upstream_fallback") == 0) {
                    int _n = snprintf(d->upstream_fallback,
                                      sizeof(d->upstream_fallback), "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->upstream_fallback))
                        log_msg(LOG_WARN, "config: обрезано: upstream_fallback");
                } else if (strcmp(key, "fallback_timeout_ms") == 0)
                    d->fallback_timeout_ms = parse_int_uci(
                        value, "fallback_timeout_ms", 1000, 100, 10000);
                else if (strcmp(key, "upstream_timeout_ms") == 0)
                    d->upstream_timeout_ms = parse_int_uci(
                        value, "upstream_timeout_ms", 3000, 500, 30000);
                else if (strcmp(key, "tolerance_ms") == 0)
                    d->tolerance_ms = parse_int_uci(
                        value, "tolerance_ms", 100, 0, 5000);
                else if (strcmp(key, "bogus_nxdomain") == 0) {
                    int _n = snprintf(d->bogus_nxdomain,
                                      sizeof(d->bogus_nxdomain), "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->bogus_nxdomain))
                        log_msg(LOG_WARN, "config: обрезано: bogus_nxdomain");
                }
                else if (strcmp(key, "cache_ttl_min") == 0)
                    d->cache_ttl_min = parse_int_uci(
                        value, "cache_ttl_min", 0, 0, 3600);
                else if (strcmp(key, "parallel_query") == 0) {
                    if (strcmp(value, "1") == 0)      d->parallel_query = true;
                    else if (strcmp(value, "0") == 0) d->parallel_query = false;
                    else log_msg(LOG_WARN, "parallel_query: невалидное '%s'", value);
                } else if (strcmp(key, "fake_ip_enabled") == 0) {
                    if (strcmp(value, "1") == 0)      d->fake_ip_enabled = true;
                    else if (strcmp(value, "0") == 0) d->fake_ip_enabled = false;
                    else log_msg(LOG_WARN, "fake_ip_enabled: невалидное '%s'", value);
                } else if (strcmp(key, "fake_ip_range") == 0) {
                    int _n = snprintf(d->fake_ip_range, sizeof(d->fake_ip_range), "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->fake_ip_range)) {
                        log_msg(LOG_ERROR, "config: поле обрезано: fake_ip_range");
                        goto cleanup_fail;
                    }
                }
                else if (strcmp(key, "fake_ip_pool_size") == 0)
                    d->fake_ip_pool_size = parse_int_uci(
                        value, "fake_ip_pool_size", 65536, 1, 262144);
                else if (strcmp(key, "fake_ip_ttl") == 0)
                    d->fake_ip_ttl = parse_int_uci(
                        value, "fake_ip_ttl", 10, 1, 60);
                else if (strcmp(key, "resolve_ttl") == 0)
                    /* DEC-031: upstream DNS resolve cache TTL
                     * (dispatcher_resolve_server). Min 30s, max 86400s. */
                    d->resolve_ttl = (uint32_t)parse_int_uci(
                        value, "resolve_ttl", 300, 30, 86400);
                else if (strcmp(key, "fake_ip6_enabled") == 0) {
                    if (strcmp(value, "1") == 0)      d->fake_ip6_enabled = true;
                    else if (strcmp(value, "0") == 0) d->fake_ip6_enabled = false;
                    else log_msg(LOG_WARN, "fake_ip6_enabled: невалидное '%s'", value);
                } else if (strcmp(key, "fake_ip6_range") == 0) {
                    int _n = snprintf(d->fake_ip6_range, sizeof(d->fake_ip6_range),
                                      "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->fake_ip6_range))
                        log_msg(LOG_WARN, "config: поле обрезано: fake_ip6_range");
                }
                else if (strcmp(key, "doq_enabled") == 0) {
                    if (strcmp(value, "1") == 0)      d->doq_enabled = true;
                    else if (strcmp(value, "0") == 0) d->doq_enabled = false;
                    else log_msg(LOG_WARN,
                                 "doq_enabled: невалидное '%s', ожидается '0'/'1'",
                                 value);
                } else if (strcmp(key, "doq_server_ip") == 0) {
                    int _n = snprintf(d->doq_server_ip, sizeof(d->doq_server_ip),
                                      "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->doq_server_ip)) {
                        log_msg(LOG_ERROR, "config: поле обрезано: doq_server_ip");
                        goto cleanup_fail;
                    }
                } else if (strcmp(key, "doq_server_port") == 0)
                    d->doq_server_port = (uint16_t)parse_int_uci(
                        value, "doq_server_port", 853, 1, 65535);
                else if (strcmp(key, "doq_sni") == 0) {
                    int _n = snprintf(d->doq_sni, sizeof(d->doq_sni), "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->doq_sni)) {
                        log_msg(LOG_ERROR, "config: поле обрезано: doq_sni");
                        goto cleanup_fail;
                    }
                } else if (strcmp(key, "dns_cookie_secret_path") == 0) {
                    int _n = snprintf(d->cookie_secret_path,
                                      sizeof(d->cookie_secret_path), "%s", value);
                    if (_n < 0 || (size_t)_n >= sizeof(d->cookie_secret_path))
                        log_msg(LOG_WARN, "config: поле обрезано: dns_cookie_secret_path");
                } else if (strcmp(key, "dns_stale_while_revalidate") == 0) {
                    d->stale_while_revalidate = (strcmp(value, "1") == 0);
                } else if (strcmp(key, "dns_stale_grace_seconds") == 0) {
                    char *ep; long v = strtol(value, &ep, 10);
                    if (ep != value && *ep == '\0' && v >= 0 && v <= 86400 * 7)
                        d->stale_grace_seconds = (uint32_t)v;
                    else
                        log_msg(LOG_WARN,
                            "dns_stale_grace_seconds: невалидное '%s', "
                            "используется %u", value, d->stale_grace_seconds);
                }
                break;
            }
            case SECTION_DNS_RULE:
                if (dns_rule_count > 0) {
                    DnsRule *dr = &dns_rules[dns_rule_count - 1];
                    if (strcmp(key, "type") == 0) {
                        int _n = snprintf(dr->type, sizeof(dr->type), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(dr->type))
                            log_msg(LOG_WARN, "config: обрезано: dr->type");
                    } else if (strcmp(key, "pattern") == 0) {
                        int _n = snprintf(dr->pattern, sizeof(dr->pattern), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(dr->pattern))
                            log_msg(LOG_WARN, "config: обрезано: dr->pattern");
                    } else if (strcmp(key, "domain") == 0 ||
                               strcmp(key, "upstream") == 0) {
                        log_msg(LOG_WARN,
                            "config: dns_rule устаревший формат "
                            "(поле '%s'). Используйте 'type' и 'pattern'.", key);
                    }
                }
                break;
            case SECTION_DNS_POLICY:
                if (dp_count > 0) {
                    DnsPolicy *dp = &dp_tmp[dp_count - 1];
                    if (strcmp(key, "pattern") == 0) {
                        int _n = snprintf(dp->pattern, sizeof(dp->pattern), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(dp->pattern))
                            log_msg(LOG_WARN, "config: обрезано: dp->pattern");
                    } else if (strcmp(key, "upstream") == 0) {
                        int _n = snprintf(dp->upstream, sizeof(dp->upstream), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(dp->upstream)) {
                            log_msg(LOG_ERROR, "config: поле обрезано: dp->upstream");
                            goto cleanup_fail;
                        }
                    }
                    else if (strcmp(key, "port") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0' && v > 0 && v <= 65535)
                            dp->port = (uint16_t)v;
                    } else if (strcmp(key, "type") == 0) {
                        if (strcmp(value, "dot") == 0)
                            dp->type = DNS_UPSTREAM_DOT;
                        else if (strcmp(value, "doh") == 0)
                            dp->type = DNS_UPSTREAM_DOH;
                        else
                            dp->type = DNS_UPSTREAM_UDP;
                    } else if (strcmp(key, "sni") == 0) {
                        int _n = snprintf(dp->sni, sizeof(dp->sni), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(dp->sni))
                            log_msg(LOG_WARN, "config: обрезано: dp->sni");
                    } else if (strcmp(key, "priority") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0')
                            dp->priority = (int)v;
                    }
                }
                break;
            case SECTION_PROXY_GROUP:
                if (pg_count > 0) {
                    ProxyGroupConfig *g = &pg_tmp[pg_count - 1];
                    if (strcmp(key, "name") == 0) {
                        int _n = snprintf(g->name, sizeof(g->name), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(g->name))
                            log_msg(LOG_WARN, "config: обрезано: g->name");
                    } else if (strcmp(key, "type") == 0) {
                        if (strcmp(value, "select") == 0) g->type = PROXY_GROUP_SELECT;
                        else if (strcmp(value, "url-test") == 0 ||
                                 strcmp(value, "url_test") == 0) g->type = PROXY_GROUP_URL_TEST;
                        else if (strcmp(value, "fallback") == 0) g->type = PROXY_GROUP_FALLBACK;
                        else if (strcmp(value, "load-balance") == 0 ||
                                 strcmp(value, "load_balance") == 0) g->type = PROXY_GROUP_LOAD_BALANCE;
                    }
                    else if (strcmp(key, "servers") == 0) {
                        /* option servers 'a b c' → split по пробелу (legacy) */
                        char *tmp = strdup(value);
                        if (!tmp) goto cleanup_fail;
                        char *tok = strtok(tmp, " ");
                        while (tok) {
                            if (g->server_count >= MAX_GROUP_SERVERS) {
                                log_msg(LOG_WARN,
                                        "config: proxy_group '%s': достигнут лимит %d серверов",
                                        g->name, MAX_GROUP_SERVERS);
                                break;
                            }
                            char **tmp_srv = realloc(g->servers,
                                (size_t)(g->server_count + 1) * sizeof(char *));
                            if (!tmp_srv) { free(tmp); goto cleanup_fail; }
                            g->servers = tmp_srv;
                            char *s = strdup(tok);
                            if (!s) { free(tmp); goto cleanup_fail; }
                            g->servers[g->server_count++] = s;
                            tok = strtok(NULL, " ");
                        }
                        free(tmp);
                    }
                    else if (strcmp(key, "url") == 0) {
                        int _n = snprintf(g->url, sizeof(g->url), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(g->url)) {
                            log_msg(LOG_ERROR, "config: поле обрезано: g->url");
                            goto cleanup_fail;
                        }
                    }
                    else if (strcmp(key, "interval") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0') g->interval = (int)v;
                    } else if (strcmp(key, "timeout_ms") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0') g->timeout_ms = (int)v;
                    } else if (strcmp(key, "tolerance_ms") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0') g->tolerance_ms = (int)v;
                    } else if (strcmp(key, "providers") == 0) {
                        free(g->providers);
                        g->providers = strdup(value);
                        if (!g->providers) {
                            log_msg(LOG_ERROR, "config: нет памяти для providers");
                            goto cleanup_fail;
                        }
                    } else if (strcmp(key, "filter") == 0) {
                        int _n = snprintf(g->filter, sizeof(g->filter), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(g->filter))
                            log_msg(LOG_WARN, "config: обрезано: g->filter");
                    } else if (strcmp(key, "enabled") == 0) {
                        if (strcmp(value, "1") == 0)      g->enabled = true;
                        else if (strcmp(value, "0") == 0) g->enabled = false;
                        else log_msg(LOG_WARN, "proxy_group.enabled: невалидное '%s'", value);
                    }
                }
                break;
            case SECTION_RULE_PROVIDER:
                if (rp_count > 0) {
                    RuleProviderConfig *rp = &rp_tmp[rp_count - 1];
                    if (strcmp(key, "name") == 0) {
                        int _n = snprintf(rp->name, sizeof(rp->name), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(rp->name))
                            log_msg(LOG_WARN, "config: обрезано: rp->name");
                    } else if (strcmp(key, "type") == 0) {
                        if (strcmp(value, "http") == 0) rp->type = RULE_PROVIDER_HTTP;
                        else rp->type = RULE_PROVIDER_FILE;
                    }
                    else if (strcmp(key, "url") == 0) {
                        int _n = snprintf(rp->url, sizeof(rp->url), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(rp->url)) {
                            log_msg(LOG_ERROR, "config: поле обрезано: rp->url");
                            goto cleanup_fail;
                        }
                    } else if (strcmp(key, "path") == 0) {
                        int _n = snprintf(rp->path, sizeof(rp->path), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(rp->path)) {
                            log_msg(LOG_ERROR, "config: поле обрезано: rp->path");
                            goto cleanup_fail;
                        }
                    }
                    else if (strcmp(key, "format") == 0) {
                        if (strcmp(value, "domain") == 0) rp->format = RULE_FORMAT_DOMAIN;
                        else if (strcmp(value, "ipcidr") == 0) rp->format = RULE_FORMAT_IPCIDR;
                        else rp->format = RULE_FORMAT_CLASSICAL;
                    }
                    else if (strcmp(key, "file_format") == 0) {
                        /* WHY: file_format = кодировка файла (text/yaml/mrs) из UCI (F0-2).
                         * Отличается от format (behavior): domain/ipcidr/classical. */
                        if (strcmp(value, "yaml") == 0)
                            rp->file_format = RP_FILE_FORMAT_YAML;
                        else if (strcmp(value, "text") == 0)
                            rp->file_format = RP_FILE_FORMAT_TEXT;
                        else
                            rp->file_format = RP_FILE_FORMAT_AUTO;
                    }
                    else if (strcmp(key, "interval") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0') rp->interval = (int)v;
                    } else if (strcmp(key, "enabled") == 0) {
                        if (strcmp(value, "1") == 0)      rp->enabled = true;
                        else if (strcmp(value, "0") == 0) rp->enabled = false;
                        else log_msg(LOG_WARN, "rule_provider.enabled: невалидное '%s'", value);
                    } else if (strcmp(key, "region") == 0) {
                        int _n = snprintf(rp->region, sizeof(rp->region), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(rp->region))
                            log_msg(LOG_WARN, "config: обрезано: rp->region");
                    }
                }
                break;
            case SECTION_PROXY_PROVIDER:
                if (pp_count > 0) {
                    ProxyProviderConfig *pp = &pp_tmp[pp_count - 1];
                    if (strcmp(key, "name") == 0) {
                        int _n = snprintf(pp->name, sizeof(pp->name), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(pp->name))
                            log_msg(LOG_WARN, "config: обрезано: pp->name");
                    } else if (strcmp(key, "type") == 0) {
                        if (strcmp(value, "url") == 0) pp->type = PROXY_PROVIDER_URL;
                        else pp->type = PROXY_PROVIDER_FILE;
                    }
                    else if (strcmp(key, "url") == 0) {
                        int _n = snprintf(pp->url, sizeof(pp->url), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(pp->url)) {
                            log_msg(LOG_ERROR, "config: поле обрезано: pp->url");
                            goto cleanup_fail;
                        }
                    } else if (strcmp(key, "path") == 0) {
                        int _n = snprintf(pp->path, sizeof(pp->path), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(pp->path)) {
                            log_msg(LOG_ERROR, "config: поле обрезано: pp->path");
                            goto cleanup_fail;
                        }
                    }
                    else if (strcmp(key, "interval") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0') pp->interval = (int)v;
                    } else if (strcmp(key, "enabled") == 0) {
                        if (strcmp(value, "1") == 0)      pp->enabled = true;
                        else if (strcmp(value, "0") == 0) pp->enabled = false;
                        else log_msg(LOG_WARN, "proxy_provider.enabled: невалидное '%s'", value);
                    } else if (strcmp(key, "max_servers") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0') pp->max_servers = (int)v;
                    } else if (strncmp(key, "header_", 7) == 0) {
                        /* UCI: option header_0 "User-Agent: SSClash" */
                        char *eptr;
                        long idx = strtol(key + 7, &eptr, 10);
                        if (eptr != key + 7 && *eptr == '\0' &&
                            idx >= 0 && idx < PROXY_PROVIDER_MAX_HEADERS) {
                            int _n = snprintf(pp->headers[idx], 256, "%s", value);
                            if (_n < 0 || _n >= 256)
                                log_msg(LOG_WARN, "config: обрезано: pp->header_%ld", idx);
                            /* header_count = max(header_count, idx+1) */
                            if ((int)idx + 1 > pp->header_count)
                                pp->header_count = (int)idx + 1;
                        }
                    }
                }
                break;
            case SECTION_TRAFFIC_RULE:
                if (tr_count > 0) {
                    TrafficRule *tr = &tr_tmp[tr_count - 1];
                    if (strcmp(key, "type") == 0) {
                        if (strcasecmp(value, "DOMAIN") == 0 || strcmp(value, "domain") == 0) tr->type = RULE_TYPE_DOMAIN;
                        else if (strcasecmp(value, "DOMAIN-SUFFIX") == 0 || strcmp(value, "domain_suffix") == 0) tr->type = RULE_TYPE_DOMAIN_SUFFIX;
                        else if (strcasecmp(value, "DOMAIN-KEYWORD") == 0 || strcmp(value, "domain_keyword") == 0) tr->type = RULE_TYPE_DOMAIN_KEYWORD;
                        else if (strcasecmp(value, "IP-CIDR") == 0 || strcmp(value, "ip_cidr") == 0) tr->type = RULE_TYPE_IP_CIDR;
                        else if (strcasecmp(value, "IP-CIDR6") == 0 || strcmp(value, "ip_cidr6") == 0) tr->type = RULE_TYPE_IP_CIDR6;
                        else if (strcasecmp(value, "RULE-SET") == 0 || strcmp(value, "rule_set") == 0) tr->type = RULE_TYPE_RULE_SET;
                        else if (strcasecmp(value, "MATCH") == 0 || strcmp(value, "match") == 0) tr->type = RULE_TYPE_MATCH;
                        else if (strcasecmp(value, "GEOIP") == 0 || strcmp(value, "geoip") == 0) tr->type = RULE_TYPE_GEOIP;
                        else if (strcasecmp(value, "GEOSITE") == 0 || strcmp(value, "geosite") == 0) tr->type = RULE_TYPE_GEOSITE;
                        else if (strcasecmp(value, "DST-PORT") == 0 || strcmp(value, "port") == 0) tr->type = RULE_TYPE_DST_PORT;
                        else if (strcasecmp(value, "SRC-PORT") == 0 || strcmp(value, "src_port") == 0) tr->type = RULE_TYPE_SRC_PORT;
                        else if (strcasecmp(value, "PROCESS-NAME") == 0 || strcmp(value, "process_name") == 0) tr->type = RULE_TYPE_PROCESS_NAME;
                        else if (strcasecmp(value, "AND") == 0 || strcmp(value, "and") == 0) tr->type = RULE_TYPE_AND;
                        else if (strcasecmp(value, "OR") == 0 || strcmp(value, "or") == 0) tr->type = RULE_TYPE_OR;
                        else if (strcasecmp(value, "REGEX") == 0 || strcasecmp(value, "DOMAIN-REGEX") == 0) tr->type = RULE_TYPE_REGEX;
                    }
                    else if (strcmp(key, "value") == 0) {
                        int _n = snprintf(tr->value, sizeof(tr->value), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(tr->value))
                            log_msg(LOG_WARN, "config: обрезано: tr->value");
                        /* DST-PORT / SRC-PORT с диапазоном: "50000-65535" */
                        if (tr->type == RULE_TYPE_DST_PORT ||
                            tr->type == RULE_TYPE_SRC_PORT) {
                            char *dash = strchr(tr->value, '-');
                            if (dash) {
                                tr->port_min = (uint16_t)strtoul(tr->value, NULL, 10);
                                tr->port_max = (uint16_t)strtoul(dash + 1, NULL, 10);
                            } else {
                                tr->port_min = tr->port_max =
                                    (uint16_t)strtoul(tr->value, NULL, 10);
                            }
                        }
                    } else if (strcmp(key, "target") == 0) {
                        int _n = snprintf(tr->target, sizeof(tr->target), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(tr->target))
                            log_msg(LOG_WARN, "config: обрезано: tr->target");
                    }
                    else if (strcmp(key, "port") == 0) {
                        /* AND-правило: port range "50000-65535" или одиночный "443" */
                        char *dash = strchr(value, '-');
                        if (dash) {
                            tr->port_min = (uint16_t)strtoul(value,      NULL, 10);
                            tr->port_max = (uint16_t)strtoul(dash + 1,   NULL, 10);
                        } else {
                            tr->port_min = tr->port_max =
                                (uint16_t)strtoul(value, NULL, 10);
                        }
                    }
                    else if (strcmp(key, "network") == 0) {
                        /* WHY: AND-правила хранят NETWORK как uint8_t=6(TCP)/17(UDP)/0(any) */
                        if (strcmp(value, "tcp") == 0)       tr->network = 6;
                        else if (strcmp(value, "udp") == 0)  tr->network = 17;
                        else                                  tr->network = 0;
                    }
                    else if (strcmp(key, "or_condition") == 0) {
                        /* UCI list or_condition накапливается в value через '\n'.
                         * Финализирующий pass после memcpy разбивает на sub_rules[].
                         * WHY '\n': безопасный разделитель (никогда не встречается
                         * в доменных паттернах и CIDR значениях). */
                        size_t cur = strlen(tr->value);
                        size_t add = strlen(value);
                        if (cur + add + 2 < sizeof(tr->value)) {
                            if (cur > 0) tr->value[cur++] = '\n';
                            memcpy(tr->value + cur, value, add + 1);
                        }
                    }
                    else if (strcmp(key, "priority") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0') tr->priority = (int)v;
                    }
                }
                break;
            case SECTION_DEVICE_POLICY:
                if (dev_count > 0) {
                    device_config_t *d = &devices_tmp[dev_count - 1];
                    if (strcmp(key, "alias") == 0 || strcmp(key, "name") == 0) {
                        int _n = snprintf(d->alias, sizeof(d->alias), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(d->alias))
                            log_msg(LOG_WARN, "config: обрезано: d->alias");
                    }
                    else if (strcmp(key, "mac") == 0)
                        parse_mac(value, d->mac, d->mac_str);
                    else if (strcmp(key, "policy") == 0) {
                        if (strcmp(value, "proxy") == 0) d->policy = DEVICE_POLICY_PROXY;
                        else if (strcmp(value, "bypass") == 0) d->policy = DEVICE_POLICY_BYPASS;
                        else if (strcmp(value, "block") == 0) d->policy = DEVICE_POLICY_BLOCK;
                        else d->policy = DEVICE_POLICY_DEFAULT;
                    }
                    else if (strcmp(key, "server_group") == 0) {
                        int _n = snprintf(d->server_group, sizeof(d->server_group), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(d->server_group))
                            log_msg(LOG_WARN, "config: обрезано: d->server_group");
                    }
                    else if (strcmp(key, "enabled") == 0) {
                        if (strcmp(value, "1") == 0)      d->enabled = true;
                        else if (strcmp(value, "0") == 0) d->enabled = false;
                        else log_msg(LOG_WARN, "device.enabled: невалидное '%s'", value);
                    } else if (strcmp(key, "priority") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0') d->priority = (int)v;
                    }
                    else if (strcmp(key, "comment") == 0) {
                        int _n = snprintf(d->comment, sizeof(d->comment), "%s", value);
                        if (_n < 0 || (size_t)_n >= sizeof(d->comment))
                            log_msg(LOG_DEBUG, "config: обрезано (некритично): %d", __LINE__);
                    }
                }
                break;
            case SECTION_NONE:
                log_msg(LOG_WARN, "Строка %d: опция вне секции", line_num);
                break;
            default:
                break;
            }
        } else if (strcmp(keyword, "list") == 0) {
            char *lkey = next_token(&cursor);
            char *lval = next_token(&cursor);
            if (!lkey || !lval) continue;
            if (section == SECTION_PROXY_GROUP && pg_count > 0 &&
                strcmp(lkey, "servers") == 0) {
                ProxyGroupConfig *g = &pg_tmp[pg_count - 1];
                if (g->server_count >= MAX_GROUP_SERVERS) {
                    log_msg(LOG_WARN,
                            "config: proxy_group '%s': достигнут лимит %d серверов",
                            g->name, MAX_GROUP_SERVERS);
                } else {
                char **tmp_srv = realloc(g->servers,
                    (size_t)(g->server_count + 1) * sizeof(char *));
                if (!tmp_srv) goto cleanup_fail;
                g->servers = tmp_srv;
                char *s = strdup(lval);
                if (!s) goto cleanup_fail;
                g->servers[g->server_count++] = s;
                }
            } else if (section == SECTION_DNS &&
                       strcmp(lkey, "block_geosite") == 0) {
                /* list block_geosite 'ads'|'trackers'|'threats' */
                if (strcmp(lval, "ads") == 0)
                    cfg->dns.block_geosite_ads      = true;
                else if (strcmp(lval, "trackers") == 0)
                    cfg->dns.block_geosite_trackers = true;
                else if (strcmp(lval, "threats") == 0)
                    cfg->dns.block_geosite_threats  = true;
                else
                    log_msg(LOG_WARN, "Строка %d: geosite категория неизвестна: '%s'",
                            line_num, lval);
            } else {
                log_msg(LOG_DEBUG, "Строка %d: list '%s' пропущена",
                        line_num, lkey);
            }
        } else {
            log_msg(LOG_WARN, "Строка %d: неизвестное ключевое слово '%s'",
                    line_num, keyword);
        }
    }

    fclose(f);
    f = NULL;
    free(line);
    line = NULL;

    /* Копируем серверы в динамический массив */
    if (srv_count > 0) {
        if ((size_t)srv_count > SIZE_MAX / sizeof(ServerConfig)) goto cleanup_fail;
        cfg->servers = malloc((size_t)srv_count * sizeof(ServerConfig));
        if (!cfg->servers) {
            log_msg(LOG_ERROR, "Не удалось выделить память для серверов");
            goto cleanup_fail;
        }
        memcpy(cfg->servers, servers, (size_t)srv_count * sizeof(ServerConfig));
    }
    cfg->server_count = srv_count;

    /* Копируем DNS правила */
    if (dns_rule_count > 0) {
        if ((size_t)dns_rule_count > SIZE_MAX / sizeof(DnsRule)) { config_free(cfg); goto cleanup_fail; }
        cfg->dns_rules = malloc((size_t)dns_rule_count * sizeof(DnsRule));
        if (!cfg->dns_rules) {
            log_msg(LOG_ERROR, "Конфиг: нет памяти для dns_rules");
            config_free(cfg);
            goto cleanup_fail;
        }
        memcpy(cfg->dns_rules, dns_rules,
               (size_t)dns_rule_count * sizeof(DnsRule));
        cfg->dns_rule_count = dns_rule_count;
    }

    /* Копируем dns_policies */
    if (dp_count > 0) {
        if ((size_t)dp_count > SIZE_MAX / sizeof(DnsPolicy)) { config_free(cfg); goto cleanup_fail; }
        cfg->dns_policies = malloc((size_t)dp_count * sizeof(DnsPolicy));
        if (!cfg->dns_policies) {
            log_msg(LOG_ERROR, "Конфиг: нет памяти для dns_policies");
            config_free(cfg);
            goto cleanup_fail;
        }
        memcpy(cfg->dns_policies, dp_tmp,
               (size_t)dp_count * sizeof(DnsPolicy));
        cfg->dns_policy_count = dp_count;
    }

    /* Копируем устройства */
    if (dev_count > 0) {
        if ((size_t)dev_count > SIZE_MAX / sizeof(device_config_t)) { config_free(cfg); goto cleanup_fail; }
        cfg->devices = malloc((size_t)dev_count * sizeof(device_config_t));
        if (!cfg->devices) {
            log_msg(LOG_ERROR, "Конфиг: нет памяти для devices");
            config_free(cfg);
            goto cleanup_fail;
        }
        memcpy(cfg->devices, devices_tmp,
               (size_t)dev_count * sizeof(device_config_t));
        cfg->device_count = dev_count;
    }

    /* proxy groups (H-03: NULL → count=0) */
    if (pg_count > 0) {
        if ((size_t)pg_count > SIZE_MAX / sizeof(ProxyGroupConfig)) { config_free(cfg); goto cleanup_fail; }
        cfg->proxy_groups = malloc((size_t)pg_count * sizeof(ProxyGroupConfig));
        if (!cfg->proxy_groups) {
            log_msg(LOG_ERROR, "Конфиг: нет памяти для proxy_groups");
            config_free(cfg);
            goto cleanup_fail;
        }
        memcpy(cfg->proxy_groups, pg_tmp,
               (size_t)pg_count * sizeof(ProxyGroupConfig));
        cfg->proxy_group_count = pg_count;
    }
    if (pp_count > 0) {
        if ((size_t)pp_count > SIZE_MAX / sizeof(ProxyProviderConfig)) { config_free(cfg); goto cleanup_fail; }
        cfg->proxy_providers = malloc((size_t)pp_count * sizeof(ProxyProviderConfig));
        if (!cfg->proxy_providers) {
            log_msg(LOG_ERROR, "Конфиг: нет памяти для proxy_providers");
            config_free(cfg);
            goto cleanup_fail;
        }
        memcpy(cfg->proxy_providers, pp_tmp,
               (size_t)pp_count * sizeof(ProxyProviderConfig));
        cfg->proxy_provider_count = pp_count;
    }
    if (rp_count > 0) {
        if ((size_t)rp_count > SIZE_MAX / sizeof(RuleProviderConfig)) { config_free(cfg); goto cleanup_fail; }
        cfg->rule_providers = malloc((size_t)rp_count * sizeof(RuleProviderConfig));
        if (!cfg->rule_providers) {
            log_msg(LOG_ERROR, "Конфиг: нет памяти для rule_providers");
            config_free(cfg);
            goto cleanup_fail;
        }
        memcpy(cfg->rule_providers, rp_tmp,
               (size_t)rp_count * sizeof(RuleProviderConfig));
        cfg->rule_provider_count = rp_count;
    }
    if (tr_count > 0) {
        if ((size_t)tr_count > SIZE_MAX / sizeof(TrafficRule)) { config_free(cfg); goto cleanup_fail; }
        cfg->traffic_rules = malloc((size_t)tr_count * sizeof(TrafficRule));
        if (!cfg->traffic_rules) {
            log_msg(LOG_ERROR, "Конфиг: нет памяти для traffic_rules");
            config_free(cfg);
            goto cleanup_fail;
        }
        memcpy(cfg->traffic_rules, tr_tmp,
               (size_t)tr_count * sizeof(TrafficRule));
        cfg->traffic_rule_count = tr_count;

        /* Финализирующий pass: собрать sub_rules для OR и скомпилировать REGEX.
         * Делается после memcpy чтобы не зависеть от порядка UCI ключей. */
        for (int ti = 0; ti < tr_count; ti++) {
            TrafficRule *tr = &cfg->traffic_rules[ti];

            if (tr->type == RULE_TYPE_OR && tr->value[0]) {
                /* Разбить tr->value по '\n' → sub_rules[] */
                uint8_t cnt = 0;
                const char *p = tr->value;
                while (*p) {
                    cnt++;
                    const char *nl = strchr(p, '\n');
                    if (!nl) break;
                    p = nl + 1;
                }
                if (cnt > 0) {
                    tr->sub_rules = calloc(cnt, sizeof(TrafficRule));
                    if (tr->sub_rules) {
                        tr->sub_count = cnt;
                        uint8_t idx = 0;
                        char *buf = strdup(tr->value);
                        if (buf) {
                            char *tok = buf;
                            char *nl;
                            do {
                                nl = strchr(tok, '\n');
                                if (nl) *nl = '\0';
                                parse_sub_condition(tok, &tr->sub_rules[idx++]);
                                tok = nl ? nl + 1 : NULL;
                            } while (tok && idx < cnt);
                            free(buf);
                        }
                    }
                }
                /* Очищаем value — для OR не нужен, sub_rules заменяют */
                memset(tr->value, 0, sizeof(tr->value));
            }

            if (tr->type == RULE_TYPE_REGEX && tr->value[0]) {
                tr->compiled_re = malloc(sizeof(regex_t));
                if (tr->compiled_re) {
                    int rc = regcomp((regex_t *)tr->compiled_re,
                                     tr->value,
                                     REG_EXTENDED | REG_ICASE | REG_NOSUB);
                    if (rc != 0) {
                        char errbuf[128];
                        regerror(rc, (regex_t *)tr->compiled_re,
                                 errbuf, sizeof(errbuf));
                        log_msg(LOG_ERROR, "config: REGEX '%s': %s",
                                tr->value, errbuf);
                        free(tr->compiled_re);
                        tr->compiled_re = NULL;
                    }
                }
            }
        }
    }

    free(servers); free(dns_rules); free(dp_tmp); free(devices_tmp);
    free(pg_tmp); free(pp_tmp); free(rp_tmp); free(tr_tmp);

    log_msg(LOG_INFO,
            "Конфиг загружен: %s (серверов: %d, групп: %d, правил: %d, policy: %d, devices: %d)",
            path, srv_count, pg_count, tr_count, dp_count, dev_count);
    return 0;

cleanup_fail:
    if (f) fclose(f);
    free(line);
    free(servers);
    free(dns_rules);
    free(dp_tmp);
    free(devices_tmp);
    free(pg_tmp);
    free(pp_tmp);
    free(rp_tmp);
    free(tr_tmp);
    return -1;
}

void config_free(EburNetConfig *cfg)
{
    /* Освободить динамические awg поля серверов */
    for (int s = 0; s < cfg->server_count; s++) {
        for (int i = 0; i < 5; i++) {
            free(cfg->servers[s].awg_i[i]);
            cfg->servers[s].awg_i[i] = NULL;
        }
        free(cfg->servers[s].awg_j1);
        cfg->servers[s].awg_j1 = NULL;
    }
    for (int gi = 0; gi < cfg->proxy_group_count; gi++) {
        ProxyGroupConfig *g = &cfg->proxy_groups[gi];
        free(g->providers); g->providers = NULL;
        for (int si = 0; si < g->server_count; si++)
            free(g->servers[si]);
        free(g->servers);
    }
    free(cfg->proxy_groups);        cfg->proxy_groups = NULL;
    free(cfg->proxy_providers);     cfg->proxy_providers = NULL;
    cfg->proxy_provider_count = 0;
    free(cfg->provider_servers);    cfg->provider_servers = NULL;
    cfg->provider_server_count = 0;
    free(cfg->rule_providers);      cfg->rule_providers = NULL;
    /* Освободить heap-поля каждого правила (OR sub_rules + REGEX compiled_re) */
    if (cfg->traffic_rules) {
        for (int ti = 0; ti < cfg->traffic_rule_count; ti++) {
            TrafficRule *tr = &cfg->traffic_rules[ti];
            if (tr->sub_rules) {
                free(tr->sub_rules);
                tr->sub_rules = NULL;
            }
            if (tr->compiled_re) {
                regfree((regex_t *)tr->compiled_re);
                free(tr->compiled_re);
                tr->compiled_re = NULL;
            }
        }
    }
    free(cfg->traffic_rules);       cfg->traffic_rules = NULL;
    if (cfg->devices) {
        free(cfg->devices);
        cfg->devices = NULL;
    }
    if (cfg->dns_rules) {
        free(cfg->dns_rules);
        cfg->dns_rules = NULL;
    }
    if (cfg->dns_policies) {
        free(cfg->dns_policies);
        cfg->dns_policies = NULL;
        cfg->dns_policy_count = 0;
    }
    if (cfg->servers) {
        free(cfg->servers);
        cfg->servers = NULL;
    }
    cfg->server_count = 0;
}

void config_dump(const EburNetConfig *cfg)
{
    log_msg(LOG_DEBUG, "=== Конфигурация ===");
    log_msg(LOG_DEBUG, "  enabled:   %s", cfg->enabled ? "да" : "нет");
    log_msg(LOG_DEBUG, "  log_level: %s", cfg->log_level);
    log_msg(LOG_DEBUG, "  mode:      %s", cfg->mode);
    log_msg(LOG_DEBUG, "  серверов:  %d", cfg->server_count);

    for (int i = 0; i < cfg->server_count; i++) {
        const ServerConfig *s = &cfg->servers[i];
        static char log_name[sizeof(s->name)];
        memcpy(log_name, s->name, sizeof(log_name));
        sanitize_log(log_name);
        log_msg(LOG_DEBUG, "  [%d] name=%s enabled=%d proto=%s addr=%s:%u",
                i, log_name, s->enabled, s->protocol, s->address, s->port);
    }
    log_msg(LOG_DEBUG, "====================");
}

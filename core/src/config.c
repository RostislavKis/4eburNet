#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

/* Максимальная длина строки в конфиге */
#define MAX_LINE 1024

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

    /* Если токен начинается с кавычки — ищем закрывающую */
    if (*s == '\'' || *s == '"') {
        char quote = *s;
        s++;
        while (*s && *s != quote)
            s++;
        if (*s == quote)
            s++;
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
        snprintf(cfg->lan_interface, sizeof(cfg->lan_interface), "%s", value);
    } else if (strcmp(key, "tai_utc_offset") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 0 && v <= 200)
            cfg->tai_utc_offset = (int)v;
        else
            log_msg(LOG_WARN, "tai_utc_offset: невалидное '%s'", value);
    } else if (strcmp(key, "region") == 0) {
        snprintf(cfg->geo_region, sizeof(cfg->geo_region), "%s", value);
    } else if (strcmp(key, "geo_dir") == 0) {
        snprintf(cfg->geo_dir, sizeof(cfg->geo_dir), "%s", value);
    } else if (strcmp(key, "dpi_dir") == 0) {
        snprintf(cfg->dpi_dir, sizeof(cfg->dpi_dir), "%s", value);
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
        if (valid)
            snprintf(cfg->dpi_fake_sni, sizeof(cfg->dpi_fake_sni), "%s", value);
        else
            log_msg(LOG_WARN,
                    "dpi_fake_sni: невалидный hostname '%s', "
                    "используется '%s'", value, cfg->dpi_fake_sni);
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
    snprintf(out_str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return 0;
}

/* Применение опции к текущему серверу */
static void apply_server_option(ServerConfig *srv, const char *key, const char *value)
{
    if (strcmp(key, "enabled") == 0) {
        if (strcmp(value, "1") == 0)      srv->enabled = true;
        else if (strcmp(value, "0") == 0) srv->enabled = false;
        else log_msg(LOG_WARN, "server.enabled: невалидное '%s', ожидается '0'/'1'", value);
    } else if (strcmp(key, "protocol") == 0) {
        strncpy(srv->protocol, value, sizeof(srv->protocol) - 1);
        srv->protocol[sizeof(srv->protocol) - 1] = '\0';
    } else if (strcmp(key, "address") == 0) {
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
        strncpy(srv->uuid, value, sizeof(srv->uuid) - 1);
        srv->uuid[sizeof(srv->uuid) - 1] = '\0';
    } else if (strcmp(key, "password") == 0) {
        strncpy(srv->password, value, sizeof(srv->password) - 1);
        srv->password[sizeof(srv->password) - 1] = '\0';
    } else if (strcmp(key, "transport") == 0) {
        strncpy(srv->transport, value, sizeof(srv->transport) - 1);
        srv->transport[sizeof(srv->transport) - 1] = '\0';
    } else if (strcmp(key, "xhttp_path") == 0) {
        strncpy(srv->xhttp_path, value, sizeof(srv->xhttp_path) - 1);
        srv->xhttp_path[sizeof(srv->xhttp_path) - 1] = '\0';
    } else if (strcmp(key, "xhttp_host") == 0) {
        strncpy(srv->xhttp_host, value, sizeof(srv->xhttp_host) - 1);
        srv->xhttp_host[sizeof(srv->xhttp_host) - 1] = '\0';
    } else if (strcmp(key, "reality_short_id") == 0) {
        strncpy(srv->reality_short_id, value, sizeof(srv->reality_short_id) - 1);
        srv->reality_short_id[sizeof(srv->reality_short_id) - 1] = '\0';
    /* AWG параметры */
    } else if (strcmp(key, "awg_private_key") == 0) {
        snprintf(srv->awg_private_key, sizeof(srv->awg_private_key), "%s", value);
    } else if (strcmp(key, "awg_public_key") == 0) {
        snprintf(srv->awg_public_key, sizeof(srv->awg_public_key), "%s", value);
    } else if (strcmp(key, "awg_psk") == 0) {
        snprintf(srv->awg_psk, sizeof(srv->awg_psk), "%s", value);
    } else if (strcmp(key, "awg_h1") == 0) {
        snprintf(srv->awg_h1, sizeof(srv->awg_h1), "%s", value);
    } else if (strcmp(key, "awg_h2") == 0) {
        snprintf(srv->awg_h2, sizeof(srv->awg_h2), "%s", value);
    } else if (strcmp(key, "awg_h3") == 0) {
        snprintf(srv->awg_h3, sizeof(srv->awg_h3), "%s", value);
    } else if (strcmp(key, "awg_h4") == 0) {
        snprintf(srv->awg_h4, sizeof(srv->awg_h4), "%s", value);
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
    } else if (strcmp(key, "awg_i1") == 0) {
        snprintf(srv->awg_i1, sizeof(srv->awg_i1), "%s", value);
    } else if (strcmp(key, "awg_i2") == 0) {
        snprintf(srv->awg_i2, sizeof(srv->awg_i2), "%s", value);
    } else if (strcmp(key, "awg_i3") == 0) {
        snprintf(srv->awg_i3, sizeof(srv->awg_i3), "%s", value);
    } else if (strcmp(key, "awg_i4") == 0) {
        snprintf(srv->awg_i4, sizeof(srv->awg_i4), "%s", value);
    } else if (strcmp(key, "awg_i5") == 0) {
        snprintf(srv->awg_i5, sizeof(srv->awg_i5), "%s", value);
    } else if (strcmp(key, "awg_keepalive") == 0) {
        char *ep; long v = strtol(value, &ep, 10);
        if (ep != value && *ep == '\0' && v >= 0 && v <= 65535)
            srv->awg_keepalive = (uint16_t)v;
        else
            log_msg(LOG_WARN, "awg_keepalive: невалидное '%s'", value);
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
    } else {
        log_msg(LOG_WARN, "Неизвестная опция server: %s", key);
    }

    /* M-08: jmin <= jmax проверка */
    if (srv->awg_jmin > srv->awg_jmax && srv->awg_jmax > 0) {
        uint16_t tmp = srv->awg_jmin;
        srv->awg_jmin = srv->awg_jmax;
        srv->awg_jmax = tmp;
    }
}

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
    snprintf(cfg->log_level, sizeof(cfg->log_level), "%s", "info");
    snprintf(cfg->mode, sizeof(cfg->mode), "%s", "rules");
    cfg->tai_utc_offset   = 37;  /* с 2017-01-01, https://www.ietf.org/timezones/data/leap-seconds.list */
    /* DPI bypass defaults */
    cfg->dpi_enabled      = true;
    cfg->dpi_split_pos    = 1;
    cfg->dpi_fake_ttl     = 5;
    cfg->dpi_fake_repeats = 8;
    snprintf(cfg->dpi_fake_sni, sizeof(cfg->dpi_fake_sni), "www.google.com");

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
    char line[MAX_LINE];
    int line_num = 0;

    while (fgets(line, sizeof(line), f)) {
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
                if (name) {
                    strncpy(servers[srv_count].name, name,
                            sizeof(servers[srv_count].name) - 1);
                }
                srv_count++;
            } else if (strcmp(type, "proxy_group") == 0) {
                section = SECTION_PROXY_GROUP;
                if (pg_count < MAX_PROXY_GROUPS) {
                    if (name) snprintf(pg_tmp[pg_count].name,
                        sizeof(pg_tmp[pg_count].name), "%s", name);
                    pg_count++;
                }
            } else if (strcmp(type, "proxy_provider") == 0) {
                section = SECTION_PROXY_PROVIDER;
                if (pp_count < MAX_PROXY_PROVIDERS) {
                    ProxyProviderConfig *pp = &pp_tmp[pp_count++];
                    memset(pp, 0, sizeof(*pp));
                    pp->enabled = true;
                    if (name && name[0])
                        snprintf(pp->name, sizeof(pp->name), "%s", name);
                }
            } else if (strcmp(type, "rule_provider") == 0) {
                section = SECTION_RULE_PROVIDER;
                if (rp_count < MAX_RULE_PROVIDERS) {
                    if (name) snprintf(rp_tmp[rp_count].name,
                        sizeof(rp_tmp[rp_count].name), "%s", name);
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
                    if (name)
                        snprintf(devices_tmp[dev_count].name,
                                 sizeof(devices_tmp[dev_count].name), "%s", name);
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

            switch (section) {
            case SECTION_EBURNET:
                apply_eburnet_option(cfg, key, value);
                break;
            case SECTION_SERVER:
                if (srv_count > 0)
                    apply_server_option(&servers[srv_count - 1], key, value);
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
                else if (strcmp(key, "upstream_bypass") == 0)
                    snprintf(d->upstream_bypass, sizeof(d->upstream_bypass), "%s", value);
                else if (strcmp(key, "upstream_proxy") == 0)
                    snprintf(d->upstream_proxy, sizeof(d->upstream_proxy), "%s", value);
                else if (strcmp(key, "upstream_default") == 0)
                    snprintf(d->upstream_default, sizeof(d->upstream_default), "%s", value);
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
                } else if (strcmp(key, "doh_url") == 0)
                    snprintf(d->doh_url, sizeof(d->doh_url), "%s", value);
                else if (strcmp(key, "doh_sni") == 0)
                    snprintf(d->doh_sni, sizeof(d->doh_sni), "%s", value);
                else if (strcmp(key, "doh_ip") == 0)
                    snprintf(d->doh_ip, sizeof(d->doh_ip), "%s", value);
                else if (strcmp(key, "doh_port") == 0)
                    d->doh_port = (uint16_t)parse_int_uci(
                        value, "doh_port", 443, 1, 65535);
                else if (strcmp(key, "dot_enabled") == 0) {
                    if (strcmp(value, "1") == 0)      d->dot_enabled = true;
                    else if (strcmp(value, "0") == 0) d->dot_enabled = false;
                    else log_msg(LOG_WARN, "dot_enabled: невалидное '%s'", value);
                } else if (strcmp(key, "dot_server_ip") == 0)
                    snprintf(d->dot_server_ip, sizeof(d->dot_server_ip), "%s", value);
                else if (strcmp(key, "dot_port") == 0)
                    d->dot_port = (uint16_t)parse_int_uci(
                        value, "dot_port", 853, 1, 65535);
                else if (strcmp(key, "dot_sni") == 0)
                    snprintf(d->dot_sni, sizeof(d->dot_sni), "%s", value);
                else if (strcmp(key, "upstream_fallback") == 0)
                    snprintf(d->upstream_fallback,
                             sizeof(d->upstream_fallback), "%s", value);
                else if (strcmp(key, "fallback_timeout_ms") == 0)
                    d->fallback_timeout_ms = parse_int_uci(
                        value, "fallback_timeout_ms", 1000, 100, 10000);
                else if (strcmp(key, "bogus_nxdomain") == 0)
                    snprintf(d->bogus_nxdomain,
                             sizeof(d->bogus_nxdomain), "%s", value);
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
                } else if (strcmp(key, "fake_ip_range") == 0)
                    snprintf(d->fake_ip_range, sizeof(d->fake_ip_range), "%s", value);
                else if (strcmp(key, "fake_ip_pool_size") == 0)
                    d->fake_ip_pool_size = parse_int_uci(
                        value, "fake_ip_pool_size", 65536, 1, 262144);
                else if (strcmp(key, "fake_ip_ttl") == 0)
                    d->fake_ip_ttl = parse_int_uci(
                        value, "fake_ip_ttl", 60, 1, 3600);
                else if (strcmp(key, "doq_enabled") == 0) {
                    if (strcmp(value, "1") == 0)      d->doq_enabled = true;
                    else if (strcmp(value, "0") == 0) d->doq_enabled = false;
                    else log_msg(LOG_WARN,
                                 "doq_enabled: невалидное '%s', ожидается '0'/'1'",
                                 value);
                } else if (strcmp(key, "doq_server_ip") == 0)
                    snprintf(d->doq_server_ip, sizeof(d->doq_server_ip),
                             "%s", value);
                else if (strcmp(key, "doq_server_port") == 0)
                    d->doq_server_port = (uint16_t)parse_int_uci(
                        value, "doq_server_port", 853, 1, 65535);
                else if (strcmp(key, "doq_sni") == 0)
                    snprintf(d->doq_sni, sizeof(d->doq_sni), "%s", value);
                break;
            }
            case SECTION_DNS_RULE:
                if (dns_rule_count > 0) {
                    DnsRule *dr = &dns_rules[dns_rule_count - 1];
                    if (strcmp(key, "type") == 0)
                        snprintf(dr->type, sizeof(dr->type), "%s", value);
                    else if (strcmp(key, "pattern") == 0)
                        snprintf(dr->pattern, sizeof(dr->pattern), "%s", value);
                }
                break;
            case SECTION_DNS_POLICY:
                if (dp_count > 0) {
                    DnsPolicy *dp = &dp_tmp[dp_count - 1];
                    if (strcmp(key, "pattern") == 0)
                        snprintf(dp->pattern, sizeof(dp->pattern), "%s", value);
                    else if (strcmp(key, "upstream") == 0)
                        snprintf(dp->upstream, sizeof(dp->upstream), "%s", value);
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
                    } else if (strcmp(key, "sni") == 0)
                        snprintf(dp->sni, sizeof(dp->sni), "%s", value);
                    else if (strcmp(key, "priority") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0')
                            dp->priority = (int)v;
                    }
                }
                break;
            case SECTION_PROXY_GROUP:
                if (pg_count > 0) {
                    ProxyGroupConfig *g = &pg_tmp[pg_count - 1];
                    if (strcmp(key, "type") == 0) {
                        if (strcmp(value, "select") == 0) g->type = PROXY_GROUP_SELECT;
                        else if (strcmp(value, "url-test") == 0) g->type = PROXY_GROUP_URL_TEST;
                        else if (strcmp(value, "fallback") == 0) g->type = PROXY_GROUP_FALLBACK;
                        else if (strcmp(value, "load-balance") == 0) g->type = PROXY_GROUP_LOAD_BALANCE;
                    }
                    else if (strcmp(key, "servers") == 0)
                        snprintf(g->servers, sizeof(g->servers), "%s", value);
                    else if (strcmp(key, "url") == 0)
                        snprintf(g->url, sizeof(g->url), "%s", value);
                    else if (strcmp(key, "interval") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0') g->interval = (int)v;
                    } else if (strcmp(key, "timeout_ms") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0') g->timeout_ms = (int)v;
                    } else if (strcmp(key, "tolerance_ms") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0') g->tolerance_ms = (int)v;
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
                    if (strcmp(key, "type") == 0) {
                        if (strcmp(value, "http") == 0) rp->type = RULE_PROVIDER_HTTP;
                        else rp->type = RULE_PROVIDER_FILE;
                    }
                    else if (strcmp(key, "url") == 0)
                        snprintf(rp->url, sizeof(rp->url), "%s", value);
                    else if (strcmp(key, "path") == 0)
                        snprintf(rp->path, sizeof(rp->path), "%s", value);
                    else if (strcmp(key, "format") == 0) {
                        if (strcmp(value, "domain") == 0) rp->format = RULE_FORMAT_DOMAIN;
                        else if (strcmp(value, "ipcidr") == 0) rp->format = RULE_FORMAT_IPCIDR;
                        else rp->format = RULE_FORMAT_CLASSICAL;
                    }
                    else if (strcmp(key, "interval") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0') rp->interval = (int)v;
                    } else if (strcmp(key, "enabled") == 0) {
                        if (strcmp(value, "1") == 0)      rp->enabled = true;
                        else if (strcmp(value, "0") == 0) rp->enabled = false;
                        else log_msg(LOG_WARN, "rule_provider.enabled: невалидное '%s'", value);
                    } else if (strcmp(key, "region") == 0)
                        snprintf(rp->region, sizeof(rp->region), "%s", value);
                }
                break;
            case SECTION_PROXY_PROVIDER:
                if (pp_count > 0) {
                    ProxyProviderConfig *pp = &pp_tmp[pp_count - 1];
                    if (strcmp(key, "name") == 0)
                        snprintf(pp->name, sizeof(pp->name), "%s", value);
                    else if (strcmp(key, "type") == 0) {
                        if (strcmp(value, "url") == 0) pp->type = PROXY_PROVIDER_URL;
                        else pp->type = PROXY_PROVIDER_FILE;
                    }
                    else if (strcmp(key, "url") == 0)
                        snprintf(pp->url, sizeof(pp->url), "%s", value);
                    else if (strcmp(key, "path") == 0)
                        snprintf(pp->path, sizeof(pp->path), "%s", value);
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
                    }
                }
                break;
            case SECTION_TRAFFIC_RULE:
                if (tr_count > 0) {
                    TrafficRule *tr = &tr_tmp[tr_count - 1];
                    if (strcmp(key, "type") == 0) {
                        if (strcmp(value, "DOMAIN") == 0) tr->type = RULE_TYPE_DOMAIN;
                        else if (strcmp(value, "DOMAIN-SUFFIX") == 0) tr->type = RULE_TYPE_DOMAIN_SUFFIX;
                        else if (strcmp(value, "DOMAIN-KEYWORD") == 0) tr->type = RULE_TYPE_DOMAIN_KEYWORD;
                        else if (strcmp(value, "IP-CIDR") == 0) tr->type = RULE_TYPE_IP_CIDR;
                        else if (strcmp(value, "RULE-SET") == 0) tr->type = RULE_TYPE_RULE_SET;
                        else if (strcmp(value, "MATCH") == 0)    tr->type = RULE_TYPE_MATCH;
                        else if (strcmp(value, "GEOIP") == 0)    tr->type = RULE_TYPE_GEOIP;
                        else if (strcmp(value, "GEOSITE") == 0)  tr->type = RULE_TYPE_GEOSITE;
                    }
                    else if (strcmp(key, "value") == 0)
                        snprintf(tr->value, sizeof(tr->value), "%s", value);
                    else if (strcmp(key, "target") == 0)
                        snprintf(tr->target, sizeof(tr->target), "%s", value);
                    else if (strcmp(key, "priority") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0') tr->priority = (int)v;
                    }
                }
                break;
            case SECTION_DEVICE_POLICY:
                if (dev_count > 0) {
                    device_config_t *d = &devices_tmp[dev_count - 1];
                    if (strcmp(key, "alias") == 0 || strcmp(key, "name") == 0)
                        snprintf(d->alias, sizeof(d->alias), "%s", value);
                    else if (strcmp(key, "mac") == 0)
                        parse_mac(value, d->mac, d->mac_str);
                    else if (strcmp(key, "policy") == 0) {
                        if (strcmp(value, "proxy") == 0) d->policy = DEVICE_POLICY_PROXY;
                        else if (strcmp(value, "bypass") == 0) d->policy = DEVICE_POLICY_BYPASS;
                        else if (strcmp(value, "block") == 0) d->policy = DEVICE_POLICY_BLOCK;
                        else d->policy = DEVICE_POLICY_DEFAULT;
                    }
                    else if (strcmp(key, "server_group") == 0)
                        snprintf(d->server_group, sizeof(d->server_group), "%s", value);
                    else if (strcmp(key, "enabled") == 0) {
                        if (strcmp(value, "1") == 0)      d->enabled = true;
                        else if (strcmp(value, "0") == 0) d->enabled = false;
                        else log_msg(LOG_WARN, "device.enabled: невалидное '%s'", value);
                    } else if (strcmp(key, "priority") == 0) {
                        char *ep; long v = strtol(value, &ep, 10);
                        if (ep != value && *ep == '\0') d->priority = (int)v;
                    }
                    else if (strcmp(key, "comment") == 0)
                        snprintf(d->comment, sizeof(d->comment), "%s", value);
                }
                break;
            case SECTION_NONE:
                log_msg(LOG_WARN, "Строка %d: опция вне секции", line_num);
                break;
            }
        } else if (strcmp(keyword, "list") == 0) {
            /* Списки пока не поддержаны */
            log_msg(LOG_WARN, "Строка %d: 'list' не поддерживается", line_num);
        } else {
            log_msg(LOG_WARN, "Строка %d: неизвестное ключевое слово '%s'",
                    line_num, keyword);
        }
    }

    fclose(f);
    f = NULL;

    /* Копируем серверы в динамический массив */
    if (srv_count > 0) {
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
        cfg->traffic_rules = malloc((size_t)tr_count * sizeof(TrafficRule));
        if (!cfg->traffic_rules) {
            log_msg(LOG_ERROR, "Конфиг: нет памяти для traffic_rules");
            config_free(cfg);
            goto cleanup_fail;
        }
        memcpy(cfg->traffic_rules, tr_tmp,
               (size_t)tr_count * sizeof(TrafficRule));
        cfg->traffic_rule_count = tr_count;
    }

    free(servers); free(dns_rules); free(dp_tmp); free(devices_tmp);
    free(pg_tmp); free(pp_tmp); free(rp_tmp); free(tr_tmp);

    log_msg(LOG_INFO,
            "Конфиг загружен: %s (серверов: %d, групп: %d, правил: %d, policy: %d)",
            path, srv_count, pg_count, tr_count, dp_count);
    return 0;

cleanup_fail:
    if (f) fclose(f);
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
    free(cfg->proxy_groups);        cfg->proxy_groups = NULL;
    free(cfg->proxy_providers);     cfg->proxy_providers = NULL;
    cfg->proxy_provider_count = 0;
    free(cfg->provider_servers);    cfg->provider_servers = NULL;
    cfg->provider_server_count = 0;
    free(cfg->rule_providers);      cfg->rule_providers = NULL;
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
        log_msg(LOG_DEBUG, "  [%d] name=%s enabled=%d proto=%s addr=%s:%u",
                i, s->name, s->enabled, s->protocol, s->address, s->port);
    }
    log_msg(LOG_DEBUG, "====================");
}

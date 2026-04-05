#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Максимальная длина строки в конфиге */
#define MAX_LINE 1024

/* Максимальное количество серверов */
#define MAX_SERVERS 64

/* Тип текущей секции */
typedef enum {
    SECTION_NONE,
    SECTION_PHOENIX,
    SECTION_SERVER,
    SECTION_DNS,
    SECTION_DNS_RULE,
    SECTION_DEVICE_POLICY,
} section_type_t;

#define MAX_DNS_RULES 256
#define MAX_DEVICES   64

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

/* Применение опции к секции phoenix */
static void apply_phoenix_option(PhoenixConfig *cfg, const char *key, const char *value)
{
    if (strcmp(key, "enabled") == 0) {
        cfg->enabled = (strcmp(value, "1") == 0);
    } else if (strcmp(key, "log_level") == 0) {
        strncpy(cfg->log_level, value, sizeof(cfg->log_level) - 1);
        cfg->log_level[sizeof(cfg->log_level) - 1] = '\0';
    } else if (strcmp(key, "mode") == 0) {
        strncpy(cfg->mode, value, sizeof(cfg->mode) - 1);
        cfg->mode[sizeof(cfg->mode) - 1] = '\0';
    } else if (strcmp(key, "lan_interface") == 0) {
        snprintf(cfg->lan_interface, sizeof(cfg->lan_interface), "%s", value);
    } else {
        log_msg(LOG_WARN, "Неизвестная опция phoenix: %s", key);
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
        srv->enabled = (strcmp(value, "1") == 0);
    } else if (strcmp(key, "protocol") == 0) {
        strncpy(srv->protocol, value, sizeof(srv->protocol) - 1);
        srv->protocol[sizeof(srv->protocol) - 1] = '\0';
    } else if (strcmp(key, "address") == 0) {
        strncpy(srv->address, value, sizeof(srv->address) - 1);
        srv->address[sizeof(srv->address) - 1] = '\0';
    } else if (strcmp(key, "port") == 0) {
        long port_val = strtol(value, NULL, 10);
        if (port_val < 1 || port_val > 65535) {
            log_msg(LOG_WARN, "Конфиг: невалидный порт %ld", port_val);
            port_val = 443;
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
        srv->awg_s1 = (uint16_t)strtol(value, NULL, 10);
    } else if (strcmp(key, "awg_s2") == 0) {
        srv->awg_s2 = (uint16_t)strtol(value, NULL, 10);
    } else if (strcmp(key, "awg_s3") == 0) {
        srv->awg_s3 = (uint16_t)strtol(value, NULL, 10);
    } else if (strcmp(key, "awg_s4") == 0) {
        srv->awg_s4 = (uint16_t)strtol(value, NULL, 10);
    } else if (strcmp(key, "awg_jc") == 0) {
        srv->awg_jc = (uint8_t)strtol(value, NULL, 10);
    } else if (strcmp(key, "awg_jmin") == 0) {
        srv->awg_jmin = (uint16_t)strtol(value, NULL, 10);
    } else if (strcmp(key, "awg_jmax") == 0) {
        srv->awg_jmax = (uint16_t)strtol(value, NULL, 10);
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
        srv->awg_keepalive = (uint16_t)strtol(value, NULL, 10);
    } else {
        log_msg(LOG_WARN, "Неизвестная опция server: %s", key);
    }
}

int config_load(const char *path, PhoenixConfig *cfg)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        log_msg(LOG_ERROR, "Не удалось открыть конфиг: %s", path);
        return -1;
    }

    /* Инициализация структуры */
    memset(cfg, 0, sizeof(*cfg));
    cfg->enabled = false;
    strcpy(cfg->log_level, "info");
    strcpy(cfg->mode, "rules");

    /* Временные массивы на heap (H-11: ~191KB на стеке → calloc) */
    ServerConfig *servers = calloc(MAX_SERVERS, sizeof(ServerConfig));
    DnsRule *dns_rules = calloc(MAX_DNS_RULES, sizeof(DnsRule));
    device_config_t *devices_tmp = calloc(MAX_DEVICES, sizeof(device_config_t));
    if (!servers || !dns_rules || !devices_tmp) {
        log_msg(LOG_ERROR, "Конфиг: нет памяти для временных массивов");
        free(servers);
        free(dns_rules);
        free(devices_tmp);
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

            if (strcmp(type, "phoenix") == 0) {
                section = SECTION_PHOENIX;
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
            case SECTION_PHOENIX:
                apply_phoenix_option(cfg, key, value);
                break;
            case SECTION_SERVER:
                if (srv_count > 0)
                    apply_server_option(&servers[srv_count - 1], key, value);
                break;
            case SECTION_DNS: {
                DnsConfig *d = &cfg->dns;
                if (strcmp(key, "enabled") == 0)
                    d->enabled = (strcmp(value, "1") == 0);
                else if (strcmp(key, "listen_port") == 0) {
                    long v = strtol(value, NULL, 10);
                    d->listen_port = (v > 0 && v <= 65535) ? (uint16_t)v : 0;
                } else if (strcmp(key, "upstream_bypass") == 0)
                    snprintf(d->upstream_bypass, sizeof(d->upstream_bypass), "%s", value);
                else if (strcmp(key, "upstream_proxy") == 0)
                    snprintf(d->upstream_proxy, sizeof(d->upstream_proxy), "%s", value);
                else if (strcmp(key, "upstream_default") == 0)
                    snprintf(d->upstream_default, sizeof(d->upstream_default), "%s", value);
                else if (strcmp(key, "upstream_port") == 0) {
                    long v = strtol(value, NULL, 10);
                    d->upstream_port = (v > 0 && v <= 65535) ? (uint16_t)v : 53;
                } else if (strcmp(key, "cache_size") == 0)
                    d->cache_size = (int)strtol(value, NULL, 10);
                else if (strcmp(key, "cache_ttl_max") == 0)
                    d->cache_ttl_max = (int)strtol(value, NULL, 10);
                else if (strcmp(key, "doh_enabled") == 0)
                    d->doh_enabled = (strcmp(value, "1") == 0);
                else if (strcmp(key, "doh_url") == 0)
                    snprintf(d->doh_url, sizeof(d->doh_url), "%s", value);
                else if (strcmp(key, "doh_sni") == 0)
                    snprintf(d->doh_sni, sizeof(d->doh_sni), "%s", value);
                else if (strcmp(key, "dot_enabled") == 0)
                    d->dot_enabled = (strcmp(value, "1") == 0);
                else if (strcmp(key, "dot_server_ip") == 0)
                    snprintf(d->dot_server_ip, sizeof(d->dot_server_ip), "%s", value);
                else if (strcmp(key, "dot_port") == 0) {
                    long v = strtol(value, NULL, 10);
                    d->dot_port = (v > 0 && v <= 65535) ? (uint16_t)v : 853;
                } else if (strcmp(key, "dot_sni") == 0)
                    snprintf(d->dot_sni, sizeof(d->dot_sni), "%s", value);
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
                    else if (strcmp(key, "enabled") == 0)
                        d->enabled = (strcmp(value, "1") == 0);
                    else if (strcmp(key, "priority") == 0)
                        d->priority = (int)strtol(value, NULL, 10);
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
            log_msg(LOG_DEBUG, "Строка %d: 'list' пропущен (не поддержан)", line_num);
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

    free(servers);
    free(dns_rules);
    free(devices_tmp);

    log_msg(LOG_INFO, "Конфиг загружен: %s (серверов: %d, DNS правил: %d, устройств: %d)",
            path, srv_count, dns_rule_count, dev_count);
    return 0;

cleanup_fail:
    if (f) fclose(f);
    free(servers);
    free(dns_rules);
    free(devices_tmp);
    return -1;
}

void config_free(PhoenixConfig *cfg)
{
    if (cfg->devices) {
        free(cfg->devices);
        cfg->devices = NULL;
    }
    if (cfg->dns_rules) {
        free(cfg->dns_rules);
        cfg->dns_rules = NULL;
    }
    if (cfg->servers) {
        free(cfg->servers);
        cfg->servers = NULL;
    }
    cfg->server_count = 0;
}

void config_dump(const PhoenixConfig *cfg)
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

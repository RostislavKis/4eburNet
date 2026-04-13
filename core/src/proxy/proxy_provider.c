/*
 * Proxy providers — загрузка серверов по URI подписке
 * Форматы: vless://, ss://, trojan://
 */

#include "proxy/proxy_provider.h"
#include "net_utils.h"
#include "resource_manager.h"
#include "4eburnet.h"
#include "constants.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#if CONFIG_EBURNET_QUIC
#include "proxy/hysteria2.h"
#endif

/* Проверка truncation для некритичных snprintf (LOG_DEBUG) */
#define SNPRINTF_NC(dst, sz, ...) do { \
    int _n = snprintf((dst), (sz), __VA_ARGS__); \
    if (_n < 0 || (size_t)_n >= (sz)) \
        log_msg(LOG_DEBUG, "snprintf truncated (non-critical): %s:%d", \
                __FILE__, __LINE__); \
} while(0)

/* ── RFC 4648 base64 decode (standard + URL-safe alphabet) ── */

/* Возвращает 6-битное значение символа, -2=whitespace, -3=padding, -1=invalid */
static int b64val(uint8_t c)
{
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a' + 26);
    if (c >= '0' && c <= '9') return (int)(c - '0' + 52);
    if (c == '+' || c == '-') return 62;  /* standard / URL-safe */
    if (c == '/' || c == '_') return 63;  /* standard / URL-safe */
    if (c == '=') return -3;
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') return -2;
    return -1;
}

/* Игнорирует пробелы и переносы строк.
 * Возвращает 0 при успехе, -1 при ошибке. */
static int base64_decode(const char *in, size_t in_len,
                          uint8_t *out, size_t *out_len)
{
    size_t olen   = 0;
    size_t max    = *out_len;
    uint32_t bits = 0;
    int nbits     = 0;

    for (size_t i = 0; i < in_len; i++) {
        int v = b64val((uint8_t)in[i]);
        if (v == -2) continue;  /* пробел / перевод строки */
        if (v == -3) break;     /* padding — конец данных */
        if (v <   0) return -1; /* невалидный символ */
        bits = (bits << 6) | (uint32_t)v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (olen >= max) return -1;  /* выход за буфер */
            out[olen++] = (uint8_t)((bits >> nbits) & 0xFF);
        }
    }
    *out_len = olen;
    return 0;
}

/* ── URL helpers ── */

static int url_decode_char(const char *p, char *out)
{
    if (p[0] == '%' && isxdigit((unsigned char)p[1]) &&
        isxdigit((unsigned char)p[2])) {
        char hex[3] = { p[1], p[2], '\0' };
        *out = (char)(int)strtol(hex, NULL, 16);
        return 3;
    }
    *out = *p;
    return 1;
}

static void url_decode(const char *in, char *out, size_t out_size)
{
    if (!in || !out || out_size == 0) return;
    size_t j = 0;
    while (*in && j < out_size - 1) {
        char c;
        int adv = url_decode_char(in, &c);
        out[j++] = c;
        in += adv;
    }
    out[j] = '\0';
}

/* ── URI парсеры ── */

/*
 * vless://uuid@host:port?params#name
 */
static int parse_vless_uri(const char *uri, ServerConfig *s)
{
    const char *p = uri + 8;  /* пропустить "vless://" */

    const char *hash = strchr(p, '#');
    if (hash)
        url_decode(hash + 1, s->name, sizeof(s->name));

    const char *at = strchr(p, '@');
    if (!at) return -1;
    size_t uuid_len = (size_t)(at - p);
    if (uuid_len >= sizeof(s->uuid)) return -1;
    memcpy(s->uuid, p, uuid_len);
    s->uuid[uuid_len] = '\0';
    p = at + 1;

    const char *qmark = strchr(p, '?');
    const char *end   = qmark ? qmark : (hash ? hash : p + strlen(p));

    /* Найти последнее двоеточие (IPv6 safe) */
    const char *colon = NULL;
    for (const char *c = end - 1; c > p; c--) {
        if (*c == ':') { colon = c; break; }
    }
    if (!colon) return -1;

    size_t hlen = (size_t)(colon - p);
    if (hlen >= sizeof(s->address)) return -1;
    memcpy(s->address, p, hlen);
    s->address[hlen] = '\0';

    char port_buf[8] = {0};
    size_t plen = (size_t)(end - colon - 1);
    if (plen >= sizeof(port_buf)) return -1;
    memcpy(port_buf, colon + 1, plen);
    long port = strtol(port_buf, NULL, 10);
    if (port <= 0 || port > 65535) return -1;
    s->port = (uint16_t)port;

    if (!qmark) goto done;
    p = qmark + 1;
    while (*p && *p != '#') {
        const char *eq  = strchr(p, '=');
        if (!eq) break;
        const char *amp = strchr(eq + 1, '&');
        const char *seg_end = amp ? amp
                             : (hash ? hash : p + strlen(p));

        char key[64]      = {0};
        char val[512]     = {0};
        char val_dec[512] = {0};
        size_t klen = (size_t)(eq - p);
        size_t vlen = (size_t)(seg_end - eq - 1);
        if (klen < sizeof(key))  memcpy(key, p, klen);
        if (vlen < sizeof(val))  { memcpy(val, eq + 1, vlen); val[vlen] = '\0'; }
        url_decode(val, val_dec, sizeof(val_dec));

        if (strcmp(key, "pbk") == 0) {
            SNPRINTF_NC(s->reality_pbk, sizeof(s->reality_pbk), "%s", val_dec);
        } else if (strcmp(key, "sid") == 0) {
            SNPRINTF_NC(s->reality_short_id, sizeof(s->reality_short_id),
                     "%s", val_dec);
        } else if (strcmp(key, "type") == 0) {
            if (strcmp(val_dec, "xhttp") == 0 ||
                strcmp(val_dec, "httpupgrade") == 0)
                SNPRINTF_NC(s->transport, sizeof(s->transport), "xhttp");
            else
                SNPRINTF_NC(s->transport, sizeof(s->transport), "raw");
        }
        /* sni, fp, flow, security — игнорируем или нет отдельного поля */

        p = amp ? amp + 1 : seg_end;
    }

done:
    SNPRINTF_NC(s->protocol, sizeof(s->protocol), "vless");
    s->enabled = true;
    return 0;
}

/*
 * ss://BASE64(method:password)@host:port#name  (SIP002)
 * ss://BASE64(method:pass@host:port)#name      (legacy)
 */
static int parse_ss_uri(const char *uri, ServerConfig *s)
{
    const char *p = uri + 5;  /* пропустить "ss://" */

    const char *hash = strchr(p, '#');
    if (hash) url_decode(hash + 1, s->name, sizeof(s->name));

    const char *at = strchr(p, '@');
    if (at) {
        /* SIP002 */
        size_t blen = (size_t)(at - p);
        if (blen > 0 && blen < 512) {
            char tmp[512];
            memcpy(tmp, p, blen); tmp[blen] = '\0';
            uint8_t decoded[256];
            size_t dlen = sizeof(decoded) - 1;
            if (base64_decode(tmp, blen, decoded, &dlen) == 0) {
                decoded[dlen] = '\0';
                char *colon2 = strchr((char *)decoded, ':');
                if (colon2)
                    SNPRINTF_NC(s->password, sizeof(s->password), "%s", colon2 + 1);
            }
        }
        p = at + 1;
        const char *end = hash ? hash : p + strlen(p);
        const char *colon = NULL;
        for (const char *c = end - 1; c > p; c--)
            if (*c == ':') { colon = c; break; }
        if (!colon) return -1;
        size_t hlen = (size_t)(colon - p);
        if (hlen >= sizeof(s->address)) return -1;
        memcpy(s->address, p, hlen);
        s->address[hlen] = '\0';
        char port_buf[8] = {0};
        size_t plen = (size_t)(end - colon - 1);
        if (plen >= sizeof(port_buf)) return -1;
        memcpy(port_buf, colon + 1, plen);
        long port = strtol(port_buf, NULL, 10);
        if (port <= 0 || port > 65535) return -1;
        s->port = (uint16_t)port;
    } else {
        /* Legacy: ss://BASE64 */
        const char *end = hash ? hash : p + strlen(p);
        size_t blen = (size_t)(end - p);
        if (blen >= 512) return -1;
        char tmp[512];
        memcpy(tmp, p, blen); tmp[blen] = '\0';
        uint8_t decoded[512];
        size_t dlen = sizeof(decoded) - 1;
        if (base64_decode(tmp, blen, decoded, &dlen) < 0) return -1;
        decoded[dlen] = '\0';
        char *at2 = strrchr((char *)decoded, '@');
        if (!at2) return -1;
        *at2 = '\0';
        char *colon2 = strchr((char *)decoded, ':');
        if (colon2)
            SNPRINTF_NC(s->password, sizeof(s->password), "%s", colon2 + 1);
        const char *hp = at2 + 1;
        char *colon3 = strrchr(hp, ':');
        if (!colon3) return -1;
        *colon3 = '\0';
        SNPRINTF_NC(s->address, sizeof(s->address), "%s", hp);
        long port = strtol(colon3 + 1, NULL, 10);
        if (port <= 0 || port > 65535) return -1;
        s->port = (uint16_t)port;
    }

    SNPRINTF_NC(s->protocol, sizeof(s->protocol), "shadowsocks");
    s->enabled = true;
    return 0;
}

/*
 * trojan://password@host:port?sni=X#name
 */
static int parse_trojan_uri(const char *uri, ServerConfig *s)
{
    const char *p = uri + 9;  /* "trojan://" */

    const char *hash = strchr(p, '#');
    if (hash) url_decode(hash + 1, s->name, sizeof(s->name));

    const char *at = strchr(p, '@');
    if (!at) return -1;
    size_t plen = (size_t)(at - p);
    if (plen >= sizeof(s->password)) return -1;
    memcpy(s->password, p, plen);
    s->password[plen] = '\0';

    p = at + 1;
    const char *qmark = strchr(p, '?');
    const char *end   = qmark ? qmark : (hash ? hash : p + strlen(p));

    const char *colon = NULL;
    for (const char *c = end - 1; c > p; c--)
        if (*c == ':') { colon = c; break; }
    if (!colon) return -1;

    size_t hlen = (size_t)(colon - p);
    if (hlen >= sizeof(s->address)) return -1;
    memcpy(s->address, p, hlen);
    s->address[hlen] = '\0';

    char port_buf[8] = {0};
    size_t portlen = (size_t)(end - colon - 1);
    if (portlen >= sizeof(port_buf)) return -1;
    memcpy(port_buf, colon + 1, portlen);
    long port = strtol(port_buf, NULL, 10);
    if (port <= 0 || port > 65535) return -1;
    s->port = (uint16_t)port;

    SNPRINTF_NC(s->protocol, sizeof(s->protocol), "trojan");
    s->enabled = true;
    return 0;
}

/*
 * Конвертировать hysteria2_config_t → ServerConfig.
 * Используется при разборе hysteria2:// из подписок.
 */
#if CONFIG_EBURNET_QUIC
static void hy2_config_to_server(const hysteria2_config_t *hy2,
                                  ServerConfig *s)
{
    SNPRINTF_NC(s->address,  sizeof(s->address),  "%s", hy2->server_addr);
    SNPRINTF_NC(s->password, sizeof(s->password), "%s", hy2->password);
    s->port    = hy2->server_port;
    SNPRINTF_NC(s->protocol, sizeof(s->protocol), "hysteria2");
    s->enabled = true;
    /* Hysteria2-специфичные поля */
    s->hy2_obfs_enabled = hy2->obfs_enabled;
    SNPRINTF_NC(s->hy2_obfs_password, sizeof(s->hy2_obfs_password),
             "%s", hy2->obfs_password);
    s->hy2_insecure  = hy2->insecure;
    SNPRINTF_NC(s->hy2_sni, sizeof(s->hy2_sni), "%s", hy2->sni);
    s->hy2_up_mbps   = hy2->up_mbps;
    s->hy2_down_mbps = hy2->down_mbps;
}
#endif

/*
 * Диспетчер: URI → ServerConfig.
 * CRLF injection check (M-22), max URI length 2048.
 * Возвращает 0 при успехе, -1 если URI неизвестен или битый.
 */
static int parse_server_uri(const char *uri, ServerConfig *s,
                             const char *provider_name)
{
    if (!uri || !s) return -1;

    for (const char *c = uri; *c; c++)
        if (*c == '\r' || *c == '\n') return -1;
    if (strlen(uri) > 2048) return -1;

    memset(s, 0, sizeof(*s));
    if (provider_name)
        SNPRINTF_NC(s->source_provider, sizeof(s->source_provider),
                 "%s", provider_name);

    if (strncmp(uri, "vless://", 8) == 0)
        return parse_vless_uri(uri, s);
    if (strncmp(uri, "ss://", 5) == 0)
        return parse_ss_uri(uri, s);
    if (strncmp(uri, "trojan://", 9) == 0)
        return parse_trojan_uri(uri, s);
#if CONFIG_EBURNET_QUIC
    if (strncmp(uri, "hysteria2://", 12) == 0 ||
        strncmp(uri, "hy2://",        6) == 0) {
        hysteria2_config_t hy2cfg;
        if (hy2_parse_uri(uri, &hy2cfg) != 0) return -1;
        hy2_config_to_server(&hy2cfg, s);
        explicit_bzero(&hy2cfg, sizeof(hy2cfg));
        return 0;
    }
#endif

    return -1;  /* неизвестный протокол */
}

/* ── Stub реализации (будут дополнены в Шаге 3) ── */

int proxy_provider_max_servers(DeviceProfile profile, int configured_max)
{
    if (configured_max > 0) return configured_max;
    switch (profile) {
    case DEVICE_MICRO:   return 256;
    case DEVICE_NORMAL:  return 1024;
    default:             return 4096;
    }
}

/* Разрешить хост из URL → IP кэш, затем скачать без getaddrinfo */
static int fetch_with_ip_cache(const char *url, const char *cache_path,
                                char *resolved_ip, size_t ip_size,
                                int *resolved_family)
{
    if (!resolved_ip[0]) {
        char h[256] = {0};
        uint16_t p = 443;
        net_parse_url_host(url, h, sizeof(h), &p);
        if (h[0])
            net_resolve_host(h, p, resolved_ip, ip_size, resolved_family);
    }
    if (!resolved_ip[0]) {
        log_msg(LOG_WARN, "fetch_with_ip_cache: не удалось резолвить хост из %s",
                url);
        return -1;
    }
    return net_http_fetch_ip(url, resolved_ip, *resolved_family, cache_path);
}

int proxy_provider_init(proxy_provider_manager_t *ppm, EburNetConfig *cfg)
{
    if (!ppm || !cfg) return -1;
    memset(ppm, 0, sizeof(*ppm));
    ppm->cfg = cfg;
    int n = cfg->proxy_provider_count;
    if (n == 0) return 0;
    ppm->providers = calloc((size_t)n, sizeof(proxy_provider_state_t));
    if (!ppm->providers) return -1;
    for (int i = 0; i < n; i++) {
        ppm->providers[i].resolved_family = AF_INET;
        ppm->providers[i].fetch_pipe_fd   = -1;
    }
    for (int i = 0; i < n; i++) {
        const ProxyProviderConfig *pc = &cfg->proxy_providers[i];
        proxy_provider_state_t *ps = &ppm->providers[i];
        SNPRINTF_NC(ps->name, sizeof(ps->name), "%s", pc->name);
        if (pc->path[0]) {
            SNPRINTF_NC(ps->cache_path, sizeof(ps->cache_path), "%s", pc->path);
        } else {
            SNPRINTF_NC(ps->cache_path, sizeof(ps->cache_path),
                     "/etc/4eburnet/providers/%s.txt", pc->name);
        }
    }
    ppm->count = n;
    return 0;
}

void proxy_provider_free(proxy_provider_manager_t *ppm)
{
    if (!ppm) return;
    for (int i = 0; i < ppm->count; i++) {
        if (ppm->providers[i].fetch_pipe_fd >= 0) {
            close(ppm->providers[i].fetch_pipe_fd);
            ppm->providers[i].fetch_pipe_fd = -1;
        }
    }
    free(ppm->providers);
    memset(ppm, 0, sizeof(*ppm));
}

/* Разобрать файл кэша провайдера и заполнить provider_servers.
 * Вызывается из load_all и tick после успешной загрузки. */
static int provider_parse_file(proxy_provider_manager_t *ppm, int idx)
{
    proxy_provider_state_t *ps = &ppm->providers[idx];
    const ProxyProviderConfig *pc = &ppm->cfg->proxy_providers[idx];
    DeviceProfile profile = rm_detect_profile();
    int max = proxy_provider_max_servers(profile, pc->max_servers);

    /* Читать файл целиком. Если первая непустая строка не URI —
       попробовать base64-decode всего содержимого (большинство
       реальных подписок отдают список URI в base64). */
    ServerConfig *tmp = calloc((size_t)max, sizeof(ServerConfig));
    if (!tmp) return -1;

    int count = 0;
    char *raw = NULL;

    FILE *f = fopen(ps->cache_path, "r");
    if (!f) { free(tmp); return -1; }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    if (fsize > 0 && fsize < 4 * 1024 * 1024) {  /* max 4MB */
        raw = malloc((size_t)fsize + 2);
        if (raw) {
            size_t nread = fread(raw, 1, (size_t)fsize, f);
            fclose(f); f = NULL;
            raw[nread] = '\0';

            /* Найти первую непустую строку */
            const char *first = raw;
            while (*first == ' ' || *first == '\t' ||
                   *first == '\n' || *first == '\r') first++;

            bool is_plain = (strncmp(first, "vless://",    8)  == 0 ||
                             strncmp(first, "ss://",        5)  == 0 ||
                             strncmp(first, "trojan://",    9)  == 0 ||
                             strncmp(first, "hysteria2://", 12) == 0 ||
                             strncmp(first, "hy2://",       6)  == 0 ||
                             first[0] == '#');

            if (!is_plain) {
                /* Попробовать base64-decode */
                size_t dec_len = (size_t)nread * 3 / 4 + 16;
                uint8_t *decoded = malloc(dec_len + 1);
                if (decoded) {
                    if (base64_decode(raw, nread, decoded, &dec_len) == 0) {
                        decoded[dec_len] = '\0';
                        free(raw);
                        raw = (char *)decoded;
                        nread = dec_len;
                    } else {
                        free(decoded);
                        /* Не base64 и не plain — парсить как есть */
                    }
                }
            }

            /* Разобрать построчно */
            char *saveptr = NULL;
            char *line = strtok_r(raw, "\n", &saveptr);
            while (line && count < max) {
                size_t llen = strlen(line);
                while (llen > 0 && (line[llen-1] == '\r' || line[llen-1] == '\n'))
                    line[--llen] = '\0';
                if (llen == 0 || line[0] == '#') {
                    line = strtok_r(NULL, "\n", &saveptr);
                    continue;
                }
                ServerConfig s;
                if (parse_server_uri(line, &s, ps->name) == 0)
                    tmp[count++] = s;
                else
                    log_msg(LOG_DEBUG,
                        "proxy_provider[%s]: пропущено: %.60s",
                        ps->name, line);
                line = strtok_r(NULL, "\n", &saveptr);
            }
            free(raw);
            raw = NULL;
        }
    }
    if (f) fclose(f);

    /* Обновить provider_servers: удалить старые записи этого провайдера,
       вставить новые в конец. Поскольку архитектура однопоточная (epoll),
       realloc безопасен — dispatcher читает g_config->provider_servers
       только из того же потока. */
    EburNetConfig *cfg = ppm->cfg;

    /* Удалить записи с source_provider == ps->name */
    int new_total = 0;
    for (int i = 0; i < cfg->provider_server_count; i++) {
        if (strcmp(cfg->provider_servers[i].source_provider, ps->name) != 0)
            cfg->provider_servers[new_total++] = cfg->provider_servers[i];
    }
    cfg->provider_server_count = new_total;

    /* Добавить новые */
    ServerConfig *grown = NULL;
    if (count > 0) {
        int needed = new_total + count;
        grown = realloc(cfg->provider_servers,
                        (size_t)needed * sizeof(ServerConfig));
        if (grown) {
            cfg->provider_servers = grown;
            memcpy(cfg->provider_servers + new_total, tmp,
                   (size_t)count * sizeof(ServerConfig));
            cfg->provider_server_count = needed;
        }
    }
    free(tmp);

    /* Если realloc провалился — серверы не добавлены */
    if (count > 0 && !grown) {
        log_msg(LOG_WARN,
                "proxy_provider[%s]: realloc провалился, серверы потеряны",
                ps->name);
        ps->server_count = 0;
        ps->loaded       = false;
    } else {
        ps->server_count = count;
        ps->loaded       = true;
    }
    log_msg(LOG_INFO, "proxy_provider[%s]: загружено %d серверов",
            ps->name, ps->server_count);
    return count;
}

int proxy_provider_load_all(proxy_provider_manager_t *ppm)
{
    if (!ppm) return -1;
    int total = 0;
    for (int i = 0; i < ppm->count; i++) {
        proxy_provider_state_t *ps = &ppm->providers[i];
        const ProxyProviderConfig *pc = &ppm->cfg->proxy_providers[i];
        if (!pc->enabled) continue;

        if (pc->type == PROXY_PROVIDER_URL && pc->url[0]) {
            if (fetch_with_ip_cache(pc->url, ps->cache_path,
                                    ps->resolved_ip, sizeof(ps->resolved_ip),
                                    &ps->resolved_family) < 0)
                log_msg(LOG_WARN, "proxy_provider[%s]: не удалось скачать",
                        ps->name);
        }
        int n = provider_parse_file(ppm, i);
        if (n >= 0) {
            total += n;
            time_t now = time(NULL);
            ps->last_update = now;
            ps->next_update = pc->interval > 0 ? now + pc->interval : 0;
        }
    }
    return total;
}

void proxy_provider_handle_fetch(proxy_provider_manager_t *ppm,
                                  int fd, uint32_t events)
{
    (void)events;
    for (int i = 0; i < ppm->count; i++) {
        proxy_provider_state_t *ps = &ppm->providers[i];
        if (ps->fetch_pipe_fd != fd) continue;

        char buf[8] = {0};
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(ps->fetch_pipe_fd);
        ps->fetch_pipe_fd   = -1;
        ps->fetch_registered = false;

        if (n > 0 && strncmp(buf, "OK", 2) == 0) {
            int cnt = provider_parse_file(ppm, i);
            time_t now = time(NULL);
            ps->last_update = now;
            const ProxyProviderConfig *pc = &ppm->cfg->proxy_providers[i];
            ps->next_update = pc->interval > 0 ? now + pc->interval : 0;
            log_msg(LOG_INFO, "proxy_provider[%s]: обновлён (%d серверов)",
                    ps->name, cnt);
        } else {
            log_msg(LOG_WARN, "proxy_provider[%s]: fetch провалился", ps->name);
            ps->next_update = time(NULL) + TIMEOUT_PROVIDER_RETRY_SEC;
        }
        return;
    }
}

bool proxy_provider_owns_fd(const proxy_provider_manager_t *ppm, int fd)
{
    for (int i = 0; i < ppm->count; i++)
        if (ppm->providers[i].fetch_pipe_fd == fd) return true;
    return false;
}

void proxy_provider_tick(proxy_provider_manager_t *ppm)
{
    if (!ppm || ppm->count == 0) return;
    time_t now = time(NULL);
    /* Обновлять по одному провайдеру за тик */
    for (int attempts = 0; attempts < ppm->count; attempts++) {
        uint32_t i = ppm->round_robin % (uint32_t)ppm->count;
        ppm->round_robin = (ppm->round_robin + 1) % (uint32_t)ppm->count;
        const ProxyProviderConfig *pc = &ppm->cfg->proxy_providers[i];
        proxy_provider_state_t    *ps = &ppm->providers[i];
        if (!pc->enabled) continue;
        if (pc->interval <= 0) continue;
        if (ps->next_update == 0 || now < ps->next_update) continue;

        if (pc->type == PROXY_PROVIDER_URL && pc->url[0]) {
            /* Если уже идёт fetch этого провайдера — пропустить */
            if (ps->fetch_pipe_fd >= 0) break;

            /* Запустить async fetch */
            int pfd = net_spawn_fetch(pc->url, ps->cache_path);
            if (pfd >= 0) {
                ps->fetch_pipe_fd   = pfd;
                ps->fetch_registered = false;
                ps->fetch_started   = now;
                /* pipe fd зарегистрируется в epoll из main loop */
            } else {
                log_msg(LOG_WARN, "proxy_provider[%s]: spawn fetch провалился",
                        ps->name);
                ps->next_update = now + TIMEOUT_PROVIDER_RETRY_SEC;
            }
        }
        break;  /* один провайдер за тик */
    }
}

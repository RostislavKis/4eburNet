# DEC-013 / DEC-025 / DEC-027 — три технических долга одним проходом

**Дата:** 2026-04-07  
**Коммит базы:** аудит v6 + волна v6 fixes

---

## DEC-013: device.h — централизованные профили устройств

### Проблема
DeviceProfile и лимиты ресурсов были разбросаны по `phoenix.h` и `resource_manager.h`.
Не было единого API для получения лимитов по профилю (relay_buf / max_conns / dns_pending).

### Изменения

**`core/include/device.h`** (новый файл):
```c
/* Буфер relay по профилю */
#define RELAY_BUF_MICRO    (8   * 1024)   /* 8KB  — WR840N и др.   */
#define RELAY_BUF_NORMAL   (32  * 1024)   /* 32KB — EC330, GL-AR750 */
#define RELAY_BUF_FULL     (64  * 1024)   /* 64KB — Flint 2, AX3000 */

/* Максимум relay соединений */
#define RELAY_CONNS_MICRO   64
#define RELAY_CONNS_NORMAL  256
#define RELAY_CONNS_FULL    1024

/* DNS pending queue */
#define DNS_PENDING_MICRO   16
#define DNS_PENDING_NORMAL  32
#define DNS_PENDING_FULL    64

static inline size_t device_relay_buf(DeviceProfile p) { ... }
static inline int    device_max_conns(DeviceProfile p) { ... }
static inline int    device_dns_pending(DeviceProfile p) { ... }
DeviceProfile device_detect_profile(void);
const char   *device_profile_name(DeviceProfile p);
```

**`core/src/resource_manager.c`** — добавлены обёртки:
```c
DeviceProfile device_detect_profile(void) { return rm_detect_profile(); }
const char *device_profile_name(DeviceProfile p) { return rm_profile_name(p); }
```

**`core/src/main.c`** — обновлён лог запуска:
```c
/* Было: */
state.profile = rm_detect_profile();
log_msg(LOG_INFO, "Профиль: %s (макс. соединений: %d, буфер: %zu)", ...);

/* Стало: */
state.profile = device_detect_profile();
log_msg(LOG_INFO, "Устройство: %s", device_profile_name(state.profile));
log_msg(LOG_INFO, "Лимиты: relay_buf=%zuKB, max_conns=%d, dns_pending=%d",
        device_relay_buf(state.profile) / 1024,
        device_max_conns(state.profile),
        device_dns_pending(state.profile));
```

### VM лог (FULL профиль, 225 МБ RAM):
```
[INFO] Обнаружено RAM: 225 МБ
[INFO] Устройство: FULL
[INFO] Лимиты: relay_buf=64KB, max_conns=1024, dns_pending=64
```

---

## DEC-025: Reality shortId — диагностическое логирование

### Проблема
После TLS handshake не было информации о том, какой Reality shortId использовался
и какой clientRandom был отправлен (нужно для отладки соединений с Reality серверами).

### Изменения

**`core/include/config.h`** — поле ServerConfig:
```c
/* Reality параметры (DEC-025) */
char reality_short_id[17]; /* hex-строка до 16 символов + '\0' */
```

**`core/src/config.c`** — парсинг:
```c
} else if (strcmp(key, "reality_short_id") == 0) {
    strncpy(srv->reality_short_id, value, sizeof(srv->reality_short_id) - 1);
    ...
```

**`core/include/crypto/tls.h`** — новый прототип:
```c
/* Получить clientRandom из завершённого TLS handshake (DEC-025) */
int tls_get_client_random(const tls_conn_t *conn, uint8_t *buf, size_t buflen);
```

**`core/src/crypto/tls.c`** — реализация:
```c
int tls_get_client_random(const tls_conn_t *conn, uint8_t *buf, size_t buflen)
{
#ifdef OPENSSL_EXTRA
    size_t n = wolfSSL_get_client_random((const WOLFSSL *)conn->ssl, buf,
                                         buflen < 32 ? buflen : 32);
    return (n > 0) ? (int)n : -1;
#else
    return -1;  /* OPENSSL_EXTRA не включён */
#endif
}
```

**`core/src/proxy/dispatcher.c`** — передача shortId + диагностика:
```c
/* В vless_protocol_start: */
if (server->reality_short_id[0])
    cfg.reality_short_id = server->reality_short_id;

/* После TLS_OK: */
if (server && server->reality_short_id[0]) {
    uint8_t rnd[32];
    int rn = tls_get_client_random(&r->tls, rnd, sizeof(rnd));
    if (rn >= 8) {
        char hex[17] = {0};
        for (int hi = 0; hi < 8; hi++)
            snprintf(hex + hi * 2, 3, "%02x", rnd[hi]);
        log_msg(LOG_DEBUG, "Reality shortId=%s clientRandom[0:8]=%s",
                server->reality_short_id, hex);
    }
}
```

### Примечание
Полная ECDH-верификация shortId невозможна без ephemeral private key.
Диагностика достаточна для отладки Reality соединений в реальных условиях.

---

## DEC-027: getaddrinfo в rule_provider — поддержка доменных имён

### Проблема
`http_fetch()` в rule_provider.c использовал `inet_pton(AF_INET, ...)` — только IP адреса.
URL вида `https://raw.githubusercontent.com/...` вызывал:
```
Rule provider: 'raw.githubusercontent.com' — domain не поддерживается, нужен IP адрес
```

### Изменения

**`core/src/proxy/rule_provider.c`**:
```c
/* Было: */
int fd = socket(AF_INET, SOCK_STREAM, 0);
struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
    log_msg(LOG_WARN, "domain не поддерживается, нужен IP адрес");
    close(fd); return -1;
}
connect(fd, (struct sockaddr *)&addr, sizeof(addr));

/* Стало (DEC-027): */
char port_str[8];
snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
struct addrinfo hints = {0};
hints.ai_family   = AF_UNSPEC;
hints.ai_socktype = SOCK_STREAM;
struct addrinfo *res = NULL;
int gai = getaddrinfo(host, port_str, &hints, &res);
if (gai != 0) {
    log_msg(LOG_WARN, "Rule provider: не удалось резолвить '%s': %s",
            host, gai_strerror(gai));
    return -1;
}
int fd = socket(res->ai_family, res->ai_socktype | SOCK_CLOEXEC, res->ai_protocol);
connect(fd, res->ai_addr, res->ai_addrlen);
freeaddrinfo(res);
```

### VM тест
rule_provider с `url https://raw.githubusercontent.com/...` успешно резолвит хост и устанавливает TLS соединение. Старое сообщение "domain не поддерживается" не появляется.

```
[DEBUG] TLS: CTX кэш создан (fingerprint 0)
[DEBUG] TLS соединение установлено (TLSv1.3, TLS13-AES128-GCM-SHA256)
[WARN] Provider dectestprov: загрузка провалилась   ← 404, не DNS/TLS
```

---

## Итог

| DEC | Статус | Файлы |
|---|---|---|
| DEC-013 | ✅ Закрыт | device.h (новый), resource_manager.c, main.c |
| DEC-025 | ✅ Закрыт (диагностика) | config.h, config.c, tls.h, tls.c, dispatcher.c |
| DEC-027 | ✅ Закрыт | rule_provider.c |

# Phoenix Router -- Audit v2

**Дата**: 2026-04-05
**Коммит**: 6df8a7ff37ae16f05d9c6592c3bdc540ad82b2be
**Ветка**: master
**Строк кода**: 10581
**Файлов**: 62 (.c/.h)

---

## Инвентаризация файлов

### core/src/ -- реализация

| Файл | Статус |
|------|--------|
| main.c | [.c] активный |
| log.c | [.c] активный |
| config.c | [.c] активный |
| ipc.c | [.c] активный |
| resource_manager.c | [.c] активный |
| net_utils.c | [.c] активный |
| ntp_bootstrap.c | [.c] активный |
| watchdog.c | [ORPHAN] stub, 15 строк, TODO |
| proxy/tproxy.c | [.c] активный |
| proxy/dispatcher.c | [.c] активный (1350 строк, самый большой) |
| proxy/protocols/vless.c | [.c] активный |
| proxy/protocols/vless_xhttp.c | [.c] активный |
| proxy/protocols/trojan.c | [.c] активный |
| proxy/protocols/shadowsocks.c | [.c] активный |
| proxy/protocols/awg.c | [.c] активный |
| crypto/tls.c (src/) | [.c] активный |
| crypto/blake2s.c | [.c] активный |
| crypto/blake3.c | [.c] активный |
| crypto/noise.c | [.c] активный |
| dns/dns_server.c | [.c] активный |
| dns/dns_packet.c | [.c] активный |
| dns/dns_cache.c | [.c] активный |
| dns/dns_rules.c | [.c] активный |
| dns/dns_upstream.c | [.c] активный |
| dns/adblock.c | [ORPHAN] stub, 15 строк, TODO |
| dns/cache.c | [ORPHAN] stub, 21 строк, TODO, конфликт имён с dns_cache.c |
| dns/classifier.c | [ORPHAN] stub, 17 строк, TODO |
| dns/resolver.c | [ORPHAN] stub, 17 строк, TODO |
| routing/nftables.c | [.c] активный |
| routing/policy.c | [.c] активный |
| routing/rules_loader.c | [.c] активный |
| routing/device_policy.c | [.c] активный |
| routing/ipset.c | [ORPHAN] stub, 15 строк, TODO |

### core/crypto/ -- старые stub-файлы

| Файл | Статус |
|------|--------|
| tls.c | [ORPHAN] stub (14 строк), замещён src/crypto/tls.c |
| reality.c | [ORPHAN] stub (14 строк), TODO |
| chacha20.c | [ORPHAN] stub (16 строк), TODO |

### core/include/ -- заголовки

Все 27 .h файлов активны. Сирот нет.

---

## Критические (CRITICAL)

### C-01 [config.c:414] Ошибка аллокации dns_rules не прерывает загрузку

✅ **ЗАКРЫТА**: malloc fail для dns_rules и devices возвращает -1 через config_free.

```c
cfg->dns_rules = malloc((size_t)dns_rule_count * sizeof(DnsRule));
if (cfg->dns_rules)
    memcpy(cfg->dns_rules, dns_rules, ...);
// Нет else: если malloc == NULL, dns_rule_count остаётся >0
// но cfg->dns_rules == NULL → segfault при обращении
```

При ошибке malloc для dns_rules устанавливается dns_rule_count, но указатель NULL.
Любой код, итерирующий cfg->dns_rules[0..dns_rule_count-1], получит segfault.
То же самое для devices (строка 424).

**Рекомендация**: При ошибке malloc обнулять соответствующий count, либо возвращать -1.

---

### C-02 [dns_upstream.c:72-131] DoT/DoH используют блокирующий tls_connect в main thread

✅ **ЗАКРЫТА** (частично): UDP потолок 500ms, DoT/DoH таймаут 1 сек через SO_RCVTIMEO/SO_SNDTIMEO. Полный async -- v2.

```c
ssize_t dns_dot_query(...) {
    ...
    if (tls_connect(&tls, fd, &cfg) < 0) { ... }  // блокирует до 5 секунд
```

DNS upstream запросы (DoT и DoH) вызывают блокирующий `tls_connect()` который
выполняет select() с таймаутом до 5 секунд. Это вызывается из `dns_server_handle_event()`,
который ра��отает в main event loop. Блокировка main loop на 5 секунд означает:
- Все TPROXY соединения заморожены
- IPC не отвечает
- Новые TCP accept не выполняются

**Рекомендация**: Перевести DNS upstream на неблокирующий ввод-вывод или
выделить в отдельный поток/резолвер с очередью.

---

### C-03 [noise.c:167-169] open("/dev/urandom") без O_CLOEXEC и без проверки read()

✅ **ЗАКРЫТА**: getrandom() + O_CLOEXEC fallback + цикл read + возврат int с проверкой.�� read()

```c
static void random_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", 0);
    if (fd >= 0) { read(fd, buf, len); close(fd); }
}
```

1. `open()` без O_RDONLY (0 == O_RDONLY на Linux, но не портабельно)
2. Нет O_CLOEXEC -- утечка fd при exec
3. Результат `read()` не проверяется -- partial read на загруженной системе
   приведёт к неинициализированным байтам в криптографическом ключе
4. Если /dev/urandom недоступен, буфер остаётся нулевым -- нулевой ephemeral key

**Рекомендация**: Использовать `getrandom()` (Linux 3.17+) или проверять
возврат read() в цикле. Добавить O_RDONLY|O_CLOEXEC. При ошибке -- аварийный выход.

---

### C-04 [shadowsocks.c:230] Стековый буфер 16KB+ для шифрования

✅ **ЗАКРЫТА**: data_cipher и packet заменены на malloc+free в ss_send.

```c
ssize_t ss_send(...) {
    ...
    uint8_t data_cipher[16384];     // 16KB на стеке
    ...
    uint8_t packet[16384 + 64];     // ещё 16KB на стеке
```

~32KB+ на стеке в одной функции. На MIPS с дефолтным стеком 8KB (ulimit -s в OpenWrt)
это гарантирова��ный stack overflow и segfault. Даже с типичным 128KB стеком
это опасно при глубокой вложенности вызовов.

**Рекомендация**: Использовать relay_buf из dispatcher_state_t или malloc+free.

---

### C-05 [noise.c:188] wc_curve25519_import_private_raw с одним ключом в двух параметрах

✅ **ЗАКРЫТА**: wc_curve25519_import_private + export_public вместо _raw.

```c
wc_curve25519_import_private_raw(local_priv, 32, local_priv, 32, &key);
```

Функция `wc_curve25519_import_private_raw(priv, priv_len, pub, pub_len, key)`
принимает и private, и public. Здесь local_priv передан как оба параметра.
Это сработает только если wolfSSL сам вычислит public из private, но
это зависит от версии wolfSSL и флагов компиляции. Если не вычислит --
public key будет содержать private key, что катастрофически небезопасно.

**Рекомендация**: Вычислить public key явно через wc_curve25519_make_pub()
или использовать wc_curve25519_make_key_ex() с предварительно импортированным private.

---

### C-06 [dispatcher.c:1176,1235] write() к client без проверки возврата

✅ **ЗАКРЫТА**: write() в XHTTP и AWG секциях проверяется, при ошибке relay_free.

```c
// строка 1176 (XHTTP_ACTIVE, download -> client)
write(r->client_fd, ds->relay_buf, n);
// строка 1235 (AWG_ACTIVE)
write(r->client_fd, buf, n);
```

Возврат write() не проверяется. Если клиент закрыл соединение, write() вернёт -1
с EPIPE (SIGPIPE уже подавлен). Но partial write потеряет данные без уведомления.

**Рекомендация**: Проверять возврат write() и обрабатывать partial write.

---

## Высокие (HIGH)

### H-01 [ipc.c:38] IPC сокет без O_CLOEXEC

```c
int fd = socket(AF_UNIX, SOCK_STREAM, 0);
```

Сокет создаётся без SOCK_CLOEXEC. При любом fork+exec (popen/exec_cmd/system)
fd утечёт в дочерний процесс. Многочисленные вызовы popen через exec_cmd
гарантируют эту утечку.

**Рекомендация**: `socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)`.

---

### H-02 [ipc.c:155] Клиентский IPC сокет без O_CLOEXEC

```c
int fd = socket(AF_UNIX, SOCK_STREAM, 0);
```

Аналогично H-01 для клиентской стороны IPC.

**Рекомендация**: Добавить SOCK_CLOEXEC.

---

### H-03 [dns_upstream.c:27,74] DNS upstream сокеты без O_CLOEXEC

```c
int fd = socket(AF_INET, SOCK_DGRAM, 0);  // строка 27
int fd = socket(AF_INET, SOCK_STREAM, 0); // строка 74
```

Каждый DNS запрос создаёт сокет бе�� SOCK_CLOEXEC. При высокой нагрузке
(сотни DNS запросов + popen для nft) утечка fd может исчерпать лимит.

**Рекомендация**: Добавить SOCK_DGRAM|SOCK_CLOEXEC и SOCK_STREAM|SOCK_CLOEXEC.

---

### H-04 [dns_upstream.c:186] DoH сокет без O_CLOEXEC

```c
int fd = socket(AF_INET, SOCK_STREAM, 0);
```

**Рекомендация**: `SOCK_STREAM | SOCK_CLOEXEC`.

---

### H-05 [ntp_bootstrap.c:75] NTP bootstrap сокет без O_CLOEXEC

```c
int fd = socket(AF_INET, SOCK_STREAM, 0);
```

**Рекомендация**: `SOCK_STREAM | SOCK_CLOEXEC`.

---

### H-06 [tls.c:159] CTX кэш: verify_cert передаётся, но игнорируется при cache hit

```c
static WOLFSSL_CTX *get_or_create_ctx(tls_fingerprint_t fp, bool verify_cert) {
    int idx = (int)fp;
    if (g_ctx_cache[idx])
        return g_ctx_cache[idx];  // verify_cert может быть другим!
    ...
    if (!verify_cert)
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
```

Первый вызов создаёт CTX с verify_cert=false (Reality). Если позже потребуется
CTX с тем же fingerprint но verify_cert=true, вернётся кэшированны�� CTX
без проверки сертификата. Индекс кэша не учитывает verify_cert.

**Рекомендация**: Ключ кэша должен включать verify_cert: `idx = fp*2 + verify_cert`.
Увеличить массив до 8 элементов.

---

### H-07 [dns_server.c:242] DNS TCP с MSG_WAITALL на NONBLOCK сокете

```c
int client = accept4(ds->tcp_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
...
if (recv(client, len_buf, 2, MSG_WAITALL) != 2) {
```

MSG_WAITALL на non-blocking сокете не гарантирует получение всех 2 байт.
Вернёт EAGAIN если данные ещё не пришли. Это приведёт к отбрасыванию
легитимных TCP DNS запросов.

**Рекомендация**: Убрать SOCK_NONBLOCK для TCP DNS клиентов, или реализовать
неблокирующее чтение с буферизацией.

---

### H-08 [awg.c:34,232] AWG random_fill() и udp_fd без O_CLOEXEC для urandom

```c
static void random_fill(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) { read(fd, buf, len); close(fd); }
}
```

read() без проверки возврата. Нет O_CLOEXEC. Результат random_fill используется
для криптографических junk пакетов и index generation.

**Рекомендация**: O_RDONLY|O_CLOEXEC, проверка read() в цикле.

---

### H-09 [awg.c:234] AWG UDP сокет только IPv4

```c
awg->udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
...
struct sockaddr_in addr = { .sin_family = AF_INET, ... };
if (inet_pton(AF_INET, server_ip, &addr.sin_addr) != 1) {
```

AWG handshake поддерживает только IPv4 серверы. inet_pton IPv6 не вызывается.
Если в конфиге адрес сервера -- IPv6, подключение молча провалится.

**Рекомендация**: Добавить поддержку AF_INET6 аналогично upstream_connect().

---

### H-10 [device_policy.c:226-238] JSON injection через device fields

```c
pos += snprintf(buf + pos, buflen - pos,
    "{\"name\":\"%s\",\"alias\":\"%s\","
    "\"mac\":\"%s\",\"policy\":\"%s\","
    "\"server_group\":\"%s\","
    "\"enabled\":%s,\"priority\":%d,"
    "\"comment\":\"%s\"}",
    d->name, d->alias, d->mac_str, pol, ...);
```

Поля name, alias, comment из конфига могут содержать кавычки, обратные слеши
или управляющие символы, что сломает JSON и потенциально позволит XSS через LuCI.

**Рекомендация**: Экранировать спецсимволы JSON перед вставкой в строку
или использовать JSON-библиотеку.

---

### H-11 [config.c:209] Стековый массив ServerConfig занимает ~84KB

```c
ServerConfig servers[MAX_SERVERS];  // MAX_SERVERS=64, sizeof(ServerConfig)~1320
```

64 * ~1320 байт = ~84KB на стеке. В сумме с DnsRule dns_rules[256] (~69KB)
и device_config_t devices_tmp[64] (~38KB) -- итого ~191KB на стеке одной функции.
При дефолтном стеке 128KB на OpenWrt это stack overflow.

**Рекомендация**: Выделять временные массивы через malloc.

---

### H-12 [main.c:240-241] PhoenixConfig cfg на стеке, указатель в state

```c
PhoenixConfig cfg;                   // ~800+ байт на стеке main()
config_load(config_path, &cfg);
state.config = &cfg;                 // указатель на стековую переменную
```

Это работает пока cfg живёт до конца main(). Но при reload (строка 423):

```c
PhoenixConfig new_cfg;
config_free(&cfg);
cfg = new_cfg;
state.config = &cfg;
```

Структурное копировани�� new_cfg -> cfg копирует указатели servers/dns_rules/devices.
Если бы cfg и new_cfg были в разных областях видимости, это было бы use-after-free.
Сейчас работает корректно, но хрупко.

**Рекомендация**: Выделить config через malloc для безопасности при рефакторинге.

---

### H-13 [dispatcher.c:617-636] splice() всё ещё в коде, хотя отключён

```c
if (!r->use_tls && ds->has_splice) {
    n = splice(r->client_fd, NULL, ds->splice_pipe[1], NULL, ...);
```

ds->has_splice установлен в false (строка 737), но код splice() остаётся.
При случайном изменении has_splice на true -- data corruption (аудит C-05).

**Рекомендация**: Удалить весь мёртвый код splice().

---

## Средние (MEDIUM)

### M-01 [core/crypto/] 3 файла-сироты: tls.c, reality.c, chacha20.c

Старые stub-файлы из начальной структуры проекта. Не включены в Makefile.dev,
но включены в Makefile (OpenWrt SDK) через `$(shell find ... -name '*.c')`.
При сборке через OpenWrt SDK попадут в линковку и вызовут конфликт символов
(два определения tls_connect).

**Рекомендация**: Удалить core/crypto/tls.c, core/crypto/reality.c, core/crypto/chacha20.c.

---

### M-02 [core/src/dns/] 4 файла-сироты: adblock.c, cache.c, classifier.c, resolver.c

Старые stub-файлы. Не включены в Makefile.dev. cache.c конфликтует с dns_cache.c
(оба определяют `dns_cache_init`, хотя с разными сигнатурами).
При сборке через OpenWrt Makefile -- конфликт символов.

**Рекомендация**: Удалить core/src/dns/adblock.c, cache.c, classifier.c, resolver.c.

---

### M-03 [core/src/routing/ipset.c] Файл-сирота

Stub, 15 строк. Не включён в Makefile.dev. Функциональность заменена
rules_loader.c + nftables.c verdict maps.

**Рекомендация**: Удалить.

---

### M-04 [core/src/watchdog.c] Файл-сирота

Stub, 15 строк, TODO. Не включён в Makefile.dev. Не вызывается ниоткуда.

**Рекомендация**: Удалить или оставить как заготовку (убрать из сборки SDK).

---

### M-05 [Makefile:41] OpenWrt Makefile собирает ВСЕ .c через shell find

```makefile
$(shell find $(PKG_BUILD_DIR) -name '*.c' -not -path '*/test/*')
```

Подхватит stub-файлы (M-01, M-02, M-03, M-04), вызовет конфликт символов
при линковке.

**Рекомендация**: Использовать явный список SOURCES как в Makefile.dev,
или удалить stub-файлы.

---

### M-06 [Makefile:17] Зависимость от libnftables неверна

```makefile
DEPENDS:=+libwolfssl +libnftables +libuci +libpthread
```

Проект не использует libnftables API (netlink). Используется subprocess
(`nft` CLI через popen). libuci тоже не используется (парсер UCI самописный).
libpthread не нужен (однопоточная архитектура).

**Рекомендация**: `DEPENDS:=+libwolfssl +nftables` (пакет nftables содержит
CLI утилиту). Убрать libuci и libpthread.

---

### M-07 [dns_cache.c:66-86] O(n) линейный поиск в кэше при промахе

```c
for (int i = 0; i < c->capacity; i++) {
    int idx = (h + i) % c->capacity;
    if (!e->used) return NULL;
    ...
}
```

Open addressing с линейным пробированием. Если слот `h` занят другим ключом,
поиск проходит до первого пустого слота. При высоком заполнении (>70%)
это деградирует до O(n). При capacity=32768 (FULL профиль) -- серьёзная
просадка.

**Рекомендация**: Ограничить длину пробирования (max 8-16 шагов) или
перейти на chained hashing.

---

### M-08 [dns_rules.c:111-131] O(n) линейный поиск правил DNS для каждого запроса

```c
for (int i = 0; i < g_rules.count; i++) {
    ...
    matched = suffix_match(qname, pat + 2);  // O(len) для каждого
}
```

При 256+ правилах кажды�� DNS запрос проходит линейный поиск со строковым
сравнением. DNS запрос�� происходят в hot path (каждый клиент).

**Рекомендация**: Использовать trie или хэш-таблицу для доменов.

---

### M-09 [dispatcher.c:50-51] Глобальные указатели для g_dispatcher и g_config

```c
static dispatcher_state_t *g_dispatcher = NULL;
static const PhoenixConfig *g_config    = NULL;
```

Используются для о��хода ограничения callback-функции dispatcher_handle_conn
(не принимает контекст). При множественных экземплярах (маловероятно, но
архитектурно нечисто) -- data race.

**Рекомендация**: Передавать контекст явно чере�� параметр или tproxy_conn_t.

---

### M-10 [vless_xhttp.c:27-35] /dev/urandom каждый раз при генерации session ID

```c
void xhttp_session_id_gen(xhttp_session_id_t *sid) {
    int fd = open("/dev/urandom", O_RDONLY);
    ...
    close(fd);
```

Каждое XHTTP соединение открывает/закрывает /dev/urandom. Два syscall
(open + close) на каждое соединение. Нет O_CLOEXEC.

**Рекомендация**: Кэшировать fd /dev/urandom глобально или использовать getrandom().

---

### M-11 [dispatcher.c:1014,1029] time(NULL) вызывается при каждом transferred >0

```c
r->last_active = time(NULL);  // в цикле for(;;)
```

time() -- syscall. При активном relay может вызываться сотни раз в секунду.

**Рекомендация**: Кэшировать time(NULL) один раз в начале tick.

---

### M-12 [log.c:68-84] Логирование в stderr + файл дублирует va_list

```c
va_start(ap, fmt);
vfprintf(stderr, fmt, ap);
va_end(ap);
if (log_file) {
    va_start(ap, fmt);
    vfprintf(log_file, fmt, ap);
    va_end(ap);
}
```

При демонизации stderr перенаправлен в /dev/null. Запись в /dev/null --
бесполезный syscall на каждый log_msg. При высокой нагрузке -- ощутимы�� overhead.

**Рекомендация**: Пропускать запись в stderr если daemon_mode.

---

### M-13 [ntp_bootstrap.c:104-105] send() без цикла partial write

```c
if (send(fd, req, req_len, 0) != req_len) {
```

Один вызов send(). Partial write возможен при высокой нагрузке.

**Рекомендация**: Ци��л до полной отправки.

---

### M-14 [dns_cache.h:18] bool в структуре без include stdbool.h

```c
bool     used;  // dns_cache_entry_t
```

dns_cache.h не включает `<stdbool.h>`. Работает только потому что phoenix.h
(включённый через цепочку) включает `<stdbool.h>`.

**Рекомендация**: Добавить `#include <stdbool.h>` в dns_cache.h.

---

### M-15 [ss_recv:291] Truncation при data_len > buflen

```c
size_t data_len = ss->recv_data_need - SS_TAG_LEN;
if (data_len > buflen) data_len = buflen;  // обрезка
if (ss_aead_decrypt(..., ss->recv_data_buf, data_len, ...)) {
```

Если data_len > buflen, дешифруется только buflen байт, но тег
вычислен для полного data_len. Дешифрование провалится с ошибкой тега.
Данные потеряны.

**Рекомендация**: Если data_len > buflen -- дешифровать полностью во
временный буфер, затем копировать buflen в out.

---

### M-16 [dns_server.c:154-230] DNS resolver блокирует main loop (UDP)

```c
static void handle_udp_query(dns_server_t *ds) {
    ...
    ssize_t resp_n = resolve_query(...);  // блокирующий вызов
```

Аналогично C-02, но для обычного UDP DNS upstream. dns_upstream_query
использует recvfrom с SO_RCVTIMEO (2 секунды). В это время main loop заморожен.

**Рекомендация**: Асинхронный DNS resolver.

---

## Низкие (LOW)

### L-01 [Kconfig] PHOENIX_ADBLOCK и PHOENIX_REALITY не используются в коде

Kconfig определяет `PHOENIX_ADBLOCK` и `PHOENIX_REALITY`, но в исходниках
нет `#ifdef CONFIG_PHOENIX_ADBLOCK` или аналогичных проверок. Kconfig-флаги
не влияют на компиляцию.

---

### L-02 [phoenix.h:39] PHOENIX_LOG_MAX_BYTES -- magic number без пояснения

```c
#define PHOENIX_LOG_MAX_BYTES   (512 * 1024)  /* 512KB -- защита tmpfs */
```

Комментарий есть, но нет связи с размером tmpfs. На устройствах с 64MB RAM
tmpfs обычно ~32MB. 512KB -- адекватно.

---

### L-03 [dispatcher.h:95] Хардкод максимума 8 серверов в health[]

```c
} health[8];  /* до 8 серверов */
```

Если конфиг содержит >8 серверов, лишние не получат health tracking.

**Рекомендация**: Динамический массив или увеличить до MAX_SERVERS(64).

---

### L-04 [tproxy.c:294-296] 64KB буфер на стеке для UDP

```c
uint8_t buf[TPROXY_UDP_BUF];  // 65536 байт на стеке
```

65KB на стеке. На MIPS с ограниченным стеком -- рискованно.

**Рекомендация**: Использовать heap-allocated буфер.

---

### L-05 [awg.c:287-288] 256-байтный буфер для Noise Init может быть мал

```c
uint8_t init_pkt[256];
size_t init_len = sizeof(init_pkt);
```

NOISE_INIT_SIZE = 148, но awg_add_padding добавляет до S1 байт padding.
Если S1 > 108, буфер переполнится. S1 = uint16_t (до 65535).

**Рекомендация**: Увеличить до 1500 (MTU) или проверять boundary.

---

### L-06 [awg.c:364] Буф��р 2048 для encrypted AWG пакета может быть мал

```c
uint8_t pkt[2048];
```

NOISE_TRANSPORT_OVERHEAD = 32. Если len > 2048 - 32 - S4_padding, переполнение.
len приходит из relay_buf_size (до 64KB для FULL профиля).

**Рекомендация**: Ограничить len размером MTU или увеличить буфер.

---

### L-07 [config.c:103] sscanf с %x для MAC не ограничен по длине

```c
sscanf(str, "%x:%x:%x:%x:%x:%x", &m[0], ...);
```

Безопасно, так как str предварите��ьно проверен на strlen == 17,
но unsigned int m[6] может содержать мусор если str содержит
нечисловые символы -- проверка m[i] > 255 ловит это.

---

### L-08 Несколько с��илистических замечаний

- dns_cache.h использует bool без stdbool.h (M-14 покрывает)
- Файлы-сироты не в .gitignore (но это .c файлы, .gitignore не должен
  игнорировать исходники)

---

## Информационные (INFO)

### I-01 Архитектура однопоточная -- корректна для OpenWrt

Статические буферы (tls_err_buf и др.) безопасны.
epoll + неблокирующий ввод-вывод -- правильный выбор для роутеров.

---

### I-02 SIGPIPE подавлен корректно

```c
signal(SIGPIPE, SIG_IGN);
```

В main.c, строка 357. Без этого write() в закрытый сокет убил бы процесс.

---

### I-03 Cleanup порядок в main.c корректен

Ресурсы освобождаются в обратном порядке инициализации. PID-файл удаляется.
nft таблица удаляется. Policy rules чистятся.

---

### I-04 OOM score 500 -- адекватно для демона на роутере

Ядро убьёт phoenixd раньше dnsmasq/sshd/ubusd.

---

### I-05 AWG/Noise модуль реализован

В отличие от audit_v1, AWG + Noise_IKpsk2 полностью реализован:
blake2s.c, noise.c, awg.c. Протокол работает в dispatcher.

---

### I-06 validate_cidr() и validate_nft_cmd() -- защита от инъекций

nftables.c проверяет входные данные перед передачей в popen/nft.
Запрещены shell метасимволы |&;`$()<>.

---

### I-07 UUID не попадает в логи

Аудит S-04/S-05 из v1 закрыт -- в log_msg нет вывода UUID/пароля.

---

## Специфика AWG/Noise

Модуль ��олностью реализован:
- crypto/blake2s.c -- BLAKE2s для Noise HKDF
- crypto/noise.c -- Noise_IKpsk2 handshake (X25519 + ChaCha20Poly1305)
- proxy/protocols/awg.c -- AWG 2.0 обфускация (H1-H4, S1-S4, Jc, CPS)

Нерешённые проблемы: C-03 (random_bytes), C-05 (noise_init ключ), L-05/L-06
(буферы для AWG пакетов).

---

## Статистика

| Категория | Найдено | Закрыто |
|-----------|---------|---------|
| CRITICAL  |    6    |    6    |
| HIGH      |   13    |    0    |
| MEDIUM    |   16    |    0    |
| LOW       |    8    |    0    |
| INFO      |    7    |   N/A  |
| **ИТОГО** | **43**  |  **6** |

### По модулям

| Модуль | CRIT | HIGH | MED | LOW |
|--------|------|------|-----|-----|
| dispatcher.c | 1 | 1 | 2 | 0 |
| config.c | 1 | 1 | 0 | 0 |
| noise.c | 2 | 0 | 0 | 0 |
| shadowsocks.c | 1 | 0 | 1 | 0 |
| dns_upstream.c | 1 | 2 | 0 | 0 |
| dns_server.c | 0 | 1 | 1 | 0 |
| tls.c | 0 | 1 | 0 | 0 |
| ipc.c | 0 | 2 | 0 | 0 |
| awg.c | 0 | 2 | 0 | 2 |
| device_policy.c | 0 | 1 | 0 | 0 |
| ntp_bootstrap.c | 0 | 1 | 1 | 0 |
| vless_xhttp.c | 0 | 0 | 1 | 0 |
| Makefile | 0 | 0 | 2 | 0 |
| dns_cache.c | 0 | 0 | 1 | 0 |
| dns_rules.c | 0 | 0 | 1 | 0 |
| dns_cache.h | 0 | 0 | 1 | 0 |
| log.c | 0 | 0 | 1 | 0 |
| tproxy.c | 0 | 0 | 0 | 1 |
| phoenix.h | 0 | 0 | 0 | 1 |
| dispatcher.h | 0 | 0 | 0 | 1 |
| Kconfig | 0 | 0 | 0 | 1 |
| Stub файлы | 0 | 0 | 4 | 1 |

# audit_v37 — Devil Audit v1.2 (коммиты 9daa00f..HEAD)

**Скоуп**: 3 коммита + dashboard rewrite
- `45e37b3` feat: JA3/JA4 TLS fingerprint валидатор (v1.2-3)
- `77bc0ea` feat: TC ingress fast path cls_u32 + act_skbedit (v1.2-2)
- `381d518` feat(dashboard-v2): полный контроль + tooltips

**Статистика диффа**: 23 файла, +3151 / -1443 строк

---

## ШАГ 0: Инвентаризация

### Новые файлы
| Файл | Строк | Описание |
|------|-------|---------|
| `core/src/routing/tc_fast.c` | 432 | TC ingress fast path через rtnetlink |
| `core/include/routing/tc_fast.h` | 17 | Публичный API tc_fast |
| `core/src/proxy/ja3.c` | 183 | JA3/JA4 вычисление |
| `core/include/proxy/ja3.h` | 52 | Интерфейс JA3/JA4 |
| `core/include/crypto/tiny_md5.h` | 144 | MD5 header-only реализация |
| `core/tests/test_ja3.c` | 232 | Unit тесты JA3/JA4 |
| `luci-app-4eburnet/files/kmods/*.ko` | — | 3 kmod для MIPS (sch_ingress, cls_u32, act_skbedit) |

### Изменённые файлы (ключевые)
- `core/src/http_server.c` +208: новые endpoint /api/geo, /api/logs, новые control actions
- `core/src/proxy/sniffer.c` +170: полный ClientHello парсер для JA3/JA4
- `core/src/proxy/dispatcher.c` +47: g_last_ja3 + ja3/ja4 вычисление + dispatcher_get_last_ja3
- `core/src/main.c` +14: tc_fast init/reload/cleanup
- `core/src/config.c` +9: tc_fast_enabled, lan_prefix, lan_mask из UCI
- `core/include/config.h` +3: поля tc_fast_enabled, lan_prefix, lan_mask
- `core/src/dashboard.html` полная переработка (зеркальный файл в luci-app-4eburnet)

---

## ШАГ 1: tc_fast.c — Safety Audit

### Z1-01 НЕЗНАЧИТЕЛЬНЫЙ: мёртвый код — AF_NETLINK_V
```c
#define AF_NETLINK_V  16   /* строка 28 */
```
`AF_NETLINK_V` нигде не используется — `nl_open()` использует `AF_NETLINK` из
`<sys/socket.h>`. Код работает корректно. Рекомендация: убрать лишнее определение.

### Z1-02 НИЗКИЙ: recv() без таймаута в nl_send_recv_ack
```c
ssize_t n = recv(fd, ack, sizeof(ack), 0);  /* строка 175 */
```
Нет `SO_RCVTIMEO`. На исправном ядре netlink ACK приходит синхронно (<1мкс),
но теоретически может заблокировать epoll-цикл при патологии ядра.
Риск в реальности минимален: netlink RTM_NEWQDISC всегда ACK-ует.

### Z1-03 OK: защита от NLA-переполнения
`nla_put()` проверяет `*pos + 4 + aligned > cap` перед записью. ✓
`nla_nest_begin()` проверяет `*pos + 4 > cap`. ✓
Оба возвращают -1, вызывающий проверяет и прерывает.

### Z1-04 OK: конфликт меток
`TC_FAST_MARK = 0x10` не пересекается с TPROXY `0x01` и TUN `0x02`. ✓

### Z1-05 OK: стек tc_fast.c
| Функция | Стек | Лимит 512 |
|---------|------|-----------|
| `kmod_load` | ~160 B (syspath[80]+modpath[128]) | ✓ |
| `tc_qdisc_ingress_op` | ~88 B (buf[96]+hdr+tc) | ✓ |
| `tc_filter_u32_add` | ~376 B (buf[256]+sel[32]+parms[20]+hdr+tc+vars) | ✓ |
| `nl_send_recv_ack` | ~152 B (ack[128]+nh+err) | ✓ |
| `tc_fast_enable` | ~64 B | ✓ |

### Z1-06 OK: идемпотентность
`tc_fast_enable()` начинает с `if (g_active) tc_fast_disable(ifname)` — повторный
вызов безопасен. NLM_F_EXCL при RTM_NEWQDISC не оставляет висячий qdisc. ✓

### Z1-07 OK: nft position 0
`nft insert rule ... position 0` вставляет правило accept в начало prerouting,
до TPROXY redirect. Семантика корректна для задачи bypass. ✓

---

## ШАГ 2: dpi_adapt.c — Накопленные проблемы

Файл `dpi_adapt.c` не изменялся в данных коммитах.
Открытые долги из прошлых аудитов в скоуп не входят — перенесены в backlog.

---

## ШАГ 3: ja3.c + sniffer.c

### Z3-01 СРЕДНИЙ: ja3_expected не реализован
Комментарий в `ja3.h` (строка 44):
> "Пользователь задаёт ожидаемый хэш через UCI option ja3_expected"

В `config.h`, `config.c`, `dispatcher.c` нет поля `ja3_expected` и нет его чтения.
Документировано как намерение, но не реализовано. Пользователь не может задать
ожидаемый хэш из UCI — функция недокументированно отсутствует.

**Исправление**: удалить или исправить комментарий в ja3.h до реализации.

### Z3-02 ВЫСОКИЙ: wc_Sha256 на стеке в ja4_compute — MIPS нарушение
```c
wc_Sha256 sha;  /* строка 144 */
byte digest[WC_SHA256_DIGEST_SIZE];
```
`wc_Sha256` на стандартной wolfSSL компиляции занимает ~108–220 байт.
Стек `ja4_compute` в сумме:
- `uint16_t sorted[64]`: 128 B
- `wc_Sha256 sha`: ~200 B (с полями wolfSSL)
- `byte digest[32]`: 32 B
- `char cipher12[13]+ext12[13]+buf[48]`: 74 B
- locals (~50 B)
- **Итого: ~484–580 B**

При wolfSSL без hardware accel близко к лимиту или нарушает его.

**Исправление**: объявить `sha` как `static wc_Sha256 sha` (однопоточный epoll — безопасно).

### Z3-03 OK: static буферы в ja3_compute/ja4_compute
`static char str[640]`, `static char cipher_str[320]`, `static char ext_str[160]`
— не на стеке. Для однопоточного epoll не-реентерабельность безопасна. ✓

### Z3-04 OK: GREASE фильтрация
`ja3_is_grease()` применяется в sniffer.c для ciphers, extensions, groups. ✓
Паттерн `(v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)` корректен по RFC 8701. ✓

### Z3-05 OK: sniffer boundary guards
`sniffer_parse_hello()` проверяет каждое чтение: `if ((size_t)n < pos + N) return -1`.
Всё ограничено `SNIFFER_PEEK_SIZE = 512`. ✓

### Z3-06 OK: JA4 формат
`t{ver}{sni}{cc}{ec}{alpn}_{cipher12}_{ext12}` соответствует спецификации FoxIO JA4. ✓
- Ciphers отсортированы перед SHA-256 ✓
- Extensions без SNI(0x0000) и ALPN(0x0010) ✓
- SHA-256 → первые 12 hex символов ✓

### Z3-07 НЕЗНАЧИТЕЛЬНЫЙ: ja4_compute `n` не проверяет < 0
```c
int n = snprintf(buf, sizeof(buf), ...);
if (n > 0) { memcpy(ja4_out, buf, ...); }
```
`snprintf` возвращает -1 только при ошибке форматирования, что здесь невозможно.
Практически безопасно.

---

## ШАГ 4: Dashboard API / http_server.c

### Z4-01 ВЫСОКИЙ: MIPS стек route_api_geo — НАРУШЕНИЕ
```c
char fullpath[256];      /* строка 857 */
struct stat st;          /* ~88 B на MIPS32 */
char name[64];           /* строка 863 */
char bloom_path[256];    /* строка 870 */
```
Стек функции:
- fullpath[256] + bloom_path[256] + name[64] + stat(88) + прочее(~50) = **~714 B**

**Нарушение лимита 512 B для MIPS.** Аварийный сбой стека возможен на роутерах.

**Исправление**: объявить `static char fullpath[256]`, `static char bloom_path[256]`,
`static char name[64]`, `static struct stat st` — всё статическое безопасно для
однопоточного epoll.

### Z4-02 СРЕДНИЙ: MIPS стек route_api_logs — НАРУШЕНИЕ
```c
char ln[160];    /* строка 903 */
char esc[320];   /* строка 920 */
```
Стек: ln(160) + esc(320) + locals(40) = **~520 B** > 512 B.

**Исправление**: `static char ln[160]`, `static char esc[320]`.

### Z4-03 СРЕДНИЙ: race condition dpi_on/dpi_off
```c
system("uci set 4eburnet.main.dpi_enabled=1;"
       "uci commit 4eburnet >/dev/null 2>&1 &");   /* строка 810 */
/* ... */
kill(_pid, SIGHUP);   /* строка 816 */
```
`&` в конце shell-строки делает `uci commit` фоновым. Шелл возвращается сразу,
`system()` возвращает управление, затем немедленно отправляется SIGHUP.
Если SIGHUP приходит до завершения `uci commit`, `config_load()` прочитает
устаревший конфиг — dpi_enabled останется в старом состоянии.

**Исправление**: убрать `&` из shell-строки (`uci commit` работает быстро,
блокирование system() на ~50мс допустимо), отправлять SIGHUP только после return.

### Z4-04 НЕЗНАЧИТЕЛЬНЫЙ: tc_fast_on без s_cfg возвращает ok
```c
if (s_cfg) {
    tc_fast_enable(...);
}
http_send(conn, ..., ok_resp, ...);   /* строка 801 */
```
Если `s_cfg == NULL` (http_server_set_config не вызван), action возвращает 200 OK
не выполнив ничего. Пользователь не получит ошибку.

**Исправление**: при `s_cfg == NULL` вернуть `err_resp` с текстом "config unavailable".

### Z4-05 OK: DIR* утечка не возможна
`closedir(d)` вызывается вне if(d) блока:
```c
if (d) { while (...) { ... } closedir(d); }
```
Утечки нет. ✓

### Z4-06 OK: popen/pclose симметрия
В `route_api_servers` и `route_api_dns` — `pclose(f)` вызывается всегда при успехе.
В `route_api_servers` нет ранних return после `popen`, только при `!f`. ✓

### Z4-07 OK: token comparison
Bearer token сравнивается через `strncmp(..., tlen)` + проверка терминатора `\r\n\0`.
Нет возможности переполнить `api_token[64]` через HTTP-запрос. ✓

---

## ШАГ 5: main.c — Порядок инициализации

### Z5-01 OK: http_server_set_config timing
```c
if (http_server_init(&g_http) == 0) {
    http_server_set_config(cfg_ptr);        /* строка 772 */
    http_server_register_epoll(&g_http, master_epoll);
```
`s_cfg` устанавливается сразу после init, до первого epoll_wait. ✓

### Z5-02 OK: tc_fast после nft_init
```c
if (nft_init() != NFT_OK) { ... }
/* ... nft_mode_set_* ... */
if (cfg_ptr->tc_fast_enabled) {             /* строка 530 */
    tc_fast_enable(...);
}
```
nftables таблица существует перед вызовом `nft_add_accept_rule()`. ✓

### Z5-03 OK: SIGHUP reload порядок
```c
tc_fast_disable(...);                        /* строка 1078 */
if (cfg_ptr->tc_fast_enabled)
    tc_fast_enable(...);                     /* строка 1079 */
```
Disable перед enable. Так же симметрично с flow_offload. ✓

### Z5-04 OK: cleanup порядок
```c
nft_flow_offload_disable();
tc_fast_disable(...);    /* строка 1148 */
nft_cleanup();           /* строка 1149 */
```
TC правила убраны до очистки nftables таблицы. ✓
`http_server_close` вызывается до `close(master_epoll)`. ✓

---

## ШАГ 6: MIPS стек — сводная таблица новых функций

| Функция | Файл | Стек | Лимит | Статус |
|---------|------|------|-------|--------|
| `tc_qdisc_ingress_op` | tc_fast.c | 88 B | 512 | ✓ |
| `tc_filter_u32_add` | tc_fast.c | 376 B | 512 | ✓ |
| `nl_send_recv_ack` | tc_fast.c | 152 B | 512 | ✓ |
| `kmod_load` | tc_fast.c | 160 B | 512 | ✓ |
| `tc_fast_enable` | tc_fast.c | ~64 B | 512 | ✓ |
| `ja3_compute` | ja3.c | ~64 B (static буф) | 512 | ✓ |
| `ja4_compute` | ja3.c | **~540 B** (wc_Sha256) | 512 | ⚠ FIX |
| `route_api_geo` | http_server.c | **~714 B** | 512 | ✗ БЛОКЕР |
| `route_api_logs` | http_server.c | **~520 B** | 512 | ✗ БЛОКЕР |
| `sniffer_parse_hello` | sniffer.c | ~520 B (buf[512]) | 512 | ⚠ |
| `sniffer_peek_sni` | sniffer.c | ~16 B (calloc) | 512 | ✓ |

**Примечание sniffer_parse_hello**: `buf[SNIFFER_PEEK_SIZE=512]` + locals ≈ 520 B.
Было в предыдущей версии, не изменялось. Долг.

---

## ШАГ 7: Итоговая компиляция

Тесты компиляции не выполнялись (аудит read-only). Ключевые риски компиляции:

1. `wc_Sha256` в ja4_compute требует wolfSSL заголовок `wolfssl/wolfcrypt/sha256.h` —
   включён в ja3.c строка 16. Зависит от наличия `-lwolfssl` в Makefile.
2. Новые includes в http_server.c (`dirent.h`, `sys/stat.h`) — стандартные musl. ✓
3. `g_dpi_adapt` используется в http_server.c под `#if CONFIG_EBURNET_DPI` — должен
   быть extern в dpi_adapt.h. Не проверялось в этом аудите.
4. `dispatcher_get_last_ja3()` — реализован в dispatcher.c под `#ifdef`/`#else`
   условно. ✓

---

## Итог по блокерам

### БЛОКЕРЫ (нельзя деплоить на MIPS до исправления)

| ID | Место | Проблема | Исправление |
|----|-------|---------|------------|
| **Z4-01** | http_server.c:route_api_geo | Стек ~714 B > 512 B | Объявить fullpath/bloom_path/name/stat как `static` |
| **Z4-02** | http_server.c:route_api_logs | Стек ~520 B > 512 B | Объявить ln/esc как `static` |
| **Z3-02** | ja3.c:ja4_compute | wc_Sha256 на стеке ~540 B | Объявить `sha` как `static wc_Sha256 sha` |

### СРЕДНИЕ (исправить в текущем спринте)

| ID | Место | Проблема |
|----|-------|---------|
| **Z4-03** | http_server.c:dpi_on/off | Race condition: SIGHUP до uci commit |
| **Z3-01** | ja3.h:44 | Комментарий про ja3_expected вводит в заблуждение |

### НЕЗНАЧИТЕЛЬНЫЕ (backlog)

| ID | Место | Проблема |
|----|-------|---------|
| Z1-01 | tc_fast.c:28 | AF_NETLINK_V unused |
| Z1-02 | tc_fast.c:nl_send_recv_ack | recv() без таймаута |
| Z4-04 | http_server.c:tc_fast_on | Тихий no-op при s_cfg == NULL |
| Z3-07 | ja3.c:ja4_compute | snprintf result unchecked |

---

## Рекомендация

Перед деплоем на mipsel_24kc применить три исправления БЛОКЕРОВ (static локальные буферы).
Исправление минимальное и не меняет логику — для однопоточного epoll static-буферы
идентичны по семантике стековым.

Отдельным коммитом: исправить race condition dpi_on/off (убрать `&` из system()).

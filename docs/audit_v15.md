# Devil Audit v15 — dpi_strategy + config DPI + config.c fixes

**Дата:** 2026-04-11  
**Файлы:** `core/include/dpi/dpi_strategy.h`, `core/src/dpi/dpi_strategy.c`, `core/src/config.c` (DPI-секция + strtol/bool аудит)  
**Предыдущий аудит:** audit_v14 (dpi_filter — 1🔴 открыта)

---

## A. dpi_strategy.c

### A.1 — 🟡 getsockopt(IP_TTL) возвращает -1, saved_ttl = 64

**Строки:** 86–88

```c
int saved_ttl = 64;
socklen_t slen = sizeof(saved_ttl);
getsockopt(fd, IPPROTO_IP, IP_TTL, &saved_ttl, &slen);
```

**Анализ:** Возвращаемое значение `getsockopt` игнорируется. Если вызов завершится с ошибкой
(например, `fd` — UDP-сокет на платформе, где `IP_TTL` не поддерживается для UDP,
или `slen` вернулся изменённым из-за ошибки), переменная `saved_ttl` останется равной 64.

Сценарий реального сбоя: на musl/Linux `getsockopt(IP_TTL)` для подключённого TCP-сокета
почти всегда успешен и возвращает реальный TTL (обычно 64 или 128). Таким образом,
**в большинстве случаев на Linux проблемы нет**.

Однако если реальный TTL сокета отличается от 64 (например, пользователь выставил
`/proc/sys/net/ipv4/ip_default_ttl = 128`), а `getsockopt` провалится — восстановим
неверное значение. Утечки нет, но трафик после фейка пойдёт с TTL=64 вместо 128,
что потенциально обнаруживает стратегию или нарушает маршрутизацию.

**Вердикт:** 🟡 предупреждение — стоит добавить `if (getsockopt(...) < 0) { saved_ttl = 64; /* fallback */ }` с логированием, и документировать, что 64 — безопасный fallback.

---

### A.2 — 🟢 send() на SOCK_STREAM — частичная отправка

**Строки:** 99–107 (`dpi_send_fake`), 129–143 (`dpi_send_fragment`)

`send()` на блокирующем TCP-сокете с флагом `MSG_NOSIGNAL` может вернуть значение меньше
`payload_len` (partial write), если буфер отправки заполнен. Код проверяет только `n < 0`,
не проверяет `n < payload_len`.

В контексте DPI-стратегии fake+TTL: частично отправленный фейковый пакет всё равно достигает
DPI-узла (хотя и усечённым). Для задачи «ввести DPI в заблуждение» это менее критично,
чем для реальных данных. Тем не менее — **молчаливая потеря части фейка** без предупреждения.

Аналогично в `dpi_send_fragment`: если `n1 < p1`, второй фрагмент начинается от `data + p1`,
а не от `data + n1`, что означает пропуск байт `[n1 .. p1-1]`. Это **баг данных** при
частичной отправке первого фрагмента.

**Но:** на неблокирующих сокетах send() возвращает EAGAIN, а не частичные данные — и функция
не рассчитана на неблокирующие. На блокирующих сокетах частичный write редок, но возможен при
больших payload (QUIC Initial = 1200 байт, что близко к MTU).

**Вердикт:** 🟡 — слабый баг для fragment-стратегии: при partial write первого фрагмента
второй фрагмент отправляет неверные байты. Для fake-стратегии — менее критично.

---

### A.3 — 🟢 setsockopt(fake_ttl) провалился — TTL не тронут, возврат -1

**Строки:** 91–95

```c
if (setsockopt(fd, IPPROTO_IP, IP_TTL, &fake_ttl, sizeof(fake_ttl)) < 0) {
    log_msg(LOG_WARN, ...);
    return -1;
}
```

Если `setsockopt(fake_ttl)` не удался — функция возвращает `-1` немедленно, до отправки
и до вызова restore-блока. Исходный TTL не изменён. Поведение корректно: нет ни fake-отправки
с неверным TTL, ни порчи исходного TTL.

**Вердикт:** 🟢 логика корректна.

---

### A.4 — 🟡 TCP_NODELAY не восстанавливается после dpi_send_fragment

**Строки:** 126

```c
dpi_set_nodelay(fd, 1);
```

`TCP_NODELAY` устанавливается, но никогда не снимается (нет `dpi_set_nodelay(fd, 0)` после
отправки). Для повторного использования сокета (например, keepalive-соединение с VLESS-сервером)
алгоритм Nagle навсегда отключён. Это означает, что каждый небольшой пакет (ACK-пигибэк,
небольшой запрос) будет отправляться немедленно, увеличивая количество TCP-сегментов и нагрузку
на сеть.

На слабых роутерах (MICRO-профиль, 256 соединений) это может влиять на throughput при
одновременно активных соединениях.

**Вердикт:** 🟡 — для однократного хэндшейка (TLS ClientHello) некритично, но при reuse
сокета это постоянная побочка. Следует добавить `dpi_set_nodelay(fd, 0)` после отправки
второго фрагмента.

---

### A.5 — 🟡 TCP_NODELAY выставляется даже когда p2 == 0 (нет split)

**Строки:** 123–126

```c
dpi_fragment_sizes(data_len, split_pos, &p1, &p2);
dpi_set_nodelay(fd, 1);
```

Когда `split_pos >= data_len`, функция `dpi_fragment_sizes` устанавливает `p2 = 0` —
фрагментация не нужна, данные отправляются одним куском. Тем не менее `TCP_NODELAY`
всё равно выставляется, что бессмысленно и оставляет сокет с отключённым Nagle (см. A.4).

Лишний `setsockopt()` — системный вызов с задержкой (syscall overhead).

**Вердикт:** 🟡 — незначительная неэффективность + усугубляет A.4.

---

### A.6 — 🟢 dpi_raw_socket_close защищена от fd < 0

**Строка:** 72

```c
void dpi_raw_socket_close(int fd)
{
    if (fd >= 0) close(fd);
}
```

Защита присутствует. `close(-1)` не вызывается.

**Вердикт:** 🟢 корректно.

---

### A.7 — 🟡 Отсутствующий include: `<sys/types.h>` для `ssize_t`

**Строки:** 1–17

```c
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
```

`ssize_t` используется в строках 100, 129, 136. На glibc/musl `ssize_t` обычно попадает через
`<sys/socket.h>` или `<unistd.h>`, поэтому на практике компилируется. Однако стандарт C
определяет `ssize_t` в `<sys/types.h>` (POSIX), и его отсутствие — техническая неаккуратность,
которая может дать предупреждение на нестандартной libc или в режиме `-pedantic`.

Дополнительно: `dpi_strategy.h` включает `<stdint.h>`, `<stdbool.h>`, `<sys/socket.h>`,
но **не включает `<sys/types.h>`**. Заголовок объявляет `dpi_send_fake(...)` и
`dpi_send_fragment(...)` без упоминания `ssize_t`, что нормально (функции возвращают `int`).
Замечание только к `.c`-файлу.

**Вердикт:** 🟡 — техническая неаккуратность, рекомендуется добавить `<sys/types.h>`.

---

## B. config.c — DPI секция

### B.1 — 🟢 DPI defaults выставлены корректно

**Строки:** 347–352

```c
cfg->dpi_enabled      = true;
cfg->dpi_split_pos    = 1;
cfg->dpi_fake_ttl     = 5;
cfg->dpi_fake_repeats = 8;
snprintf(cfg->dpi_fake_sni, sizeof(cfg->dpi_fake_sni), "www.google.com");
```

Все пять полей инициализированы после `memset(cfg, 0, ...)`. Значения соответствуют
`dpi_strategy_config_init()` из `dpi_strategy.c`. NUL-завершение `dpi_fake_sni` гарантировано
через `snprintf` с размером буфера.

**Вердикт:** 🟢 корректно.

---

### B.2 — 🔴 dpi_split_pos: нет LOG_WARN при невалидном значении

**Строки:** 155–158

```c
} else if (strcmp(key, "dpi_split_pos") == 0) {
    char *ep; long v = strtol(value, &ep, 10);
    if (ep != value && *ep == '\0' && v >= 1 && v <= 1400)
        cfg->dpi_split_pos = (int)v;
```

Если UCI содержит `option dpi_split_pos '0'` (значение вне диапазона) или мусор вроде `'abc'` —
парсинг молча провалится, `cfg->dpi_split_pos` останется равным дефолту (1). Никакого
предупреждения в лог. Администратор не узнает, что его конфиг проигнорирован.

Та же проблема для `dpi_fake_ttl` (строки 159–162) и `dpi_fake_repeats` (строки 163–166) —
все три поля парсятся без `LOG_WARN` при невалидных значениях.

Для сравнения: `awg_keepalive` (строка 295) имеет `else log_msg(LOG_WARN, ...)`.
DPI-поля непоследовательно обработаны.

Отдельный сценарий для `dpi_split_pos = 0`: значение `0` не проходит проверку `v >= 1`,
применяется дефолт 1 — молча. Пользователь, намеренно попытавшийся отключить split через `0`,
получит молчаливое игнорирование вместо явной ошибки.

**Вердикт:** 🔴 — три поля без LOG_WARN при невалидном UCI-значении. Нужно добавить `else log_msg(LOG_WARN, ...)` по аналогии с `awg_keepalive`.

---

### B.3 — 🟢 dpi_fake_ttl диапазон [1, 64]

**Строки:** 159–162

```c
} else if (strcmp(key, "dpi_fake_ttl") == 0) {
    char *ep; long v = strtol(value, &ep, 10);
    if (ep != value && *ep == '\0' && v >= 1 && v <= 64)
        cfg->dpi_fake_ttl = (int)v;
```

Диапазон совпадает с проверкой в `dpi_send_fake()` (строка 82: `fake_ttl <= 0 || fake_ttl > 64`).
Граничное значение 64 логично: TTL=64 — стандартный default, значение выше не имеет смысла
для "fake, который не доходит до сервера".

**Вердикт:** 🟢 — диапазон правильный (но нет LOG_WARN — см. B.2).

---

### B.4 — 🟢 dpi_fake_repeats диапазон [1, 20]

**Строки:** 163–166

```c
} else if (strcmp(key, "dpi_fake_repeats") == 0) {
    char *ep; long v = strtol(value, &ep, 10);
    if (ep != value && *ep == '\0' && v >= 1 && v <= 20)
        cfg->dpi_fake_repeats = (int)v;
```

Диапазон совпадает с `dpi_send_fake()` (строка 83: `repeats <= 0 || repeats > 20`).

**Вердикт:** 🟢 — диапазон правильный (но нет LOG_WARN — см. B.2).

---

### B.5 — 🟢 dpi_enabled bool с LOG_WARN

**Строки:** 151–154

```c
} else if (strcmp(key, "dpi_enabled") == 0) {
    if (strcmp(value, "1") == 0)      cfg->dpi_enabled = true;
    else if (strcmp(value, "0") == 0) cfg->dpi_enabled = false;
    else log_msg(LOG_WARN, "dpi_enabled: невалидное '%s', ожидается '0'/'1'", value);
```

Паттерн соответствует остальным bool-полям в файле.

**Вердикт:** 🟢 корректно.

---

### B.6 — 🟡 dpi_fake_sni: пустая строка молча игнорируется, нет валидации формата

**Строки:** 167–169

```c
} else if (strcmp(key, "dpi_fake_sni") == 0) {
    if (value[0] != '\0')
        snprintf(cfg->dpi_fake_sni, sizeof(cfg->dpi_fake_sni), "%s", value);
```

Пустая строка (`option dpi_fake_sni ''`) молча игнорируется — поле остаётся с дефолтом
`"www.google.com"`. Это разумное поведение, но отсутствует LOG_WARN.

Важнее: нет никакой валидации, что строка является корректным hostname (без пробелов,
без `://`, длина разумная). Если UCI содержит `option dpi_fake_sni 'foo bar'` — строка
с пробелом попадёт в `fake_sni`, что может сломать `dpi_make_tls_clienthello()`.

NUL-завершение гарантировано через `snprintf` с `sizeof(cfg->dpi_fake_sni)` — это ок.

**Вердикт:** 🟡 — нет LOG_WARN для пустой строки; нет базовой валидации hostname (пробелы).

---

## C. config.c — strtol/bool аудит

### C.1 — 🟢 strtol(value, NULL, ...) — количество: 0

Поиск по файлу `grep "strtol(value, NULL"` — **совпадений нет**. Все вызовы `strtol`
используют `endptr` (`&ep` или `&endptr` или `&endp`). Задача C.1 выполнена полностью.

**Вердикт:** 🟢 все `strtol` с `NULL`-эндптером устранены.

---

### C.2 — 🟢 = (strcmp — количество: 0

Поиск по файлу `grep "= (strcmp"` — **совпадений нет**. Паттерн
`field = (strcmp(value, "1") == 0)` (присваивание через приведение bool) не встречается.
Все bool-поля парсятся через явный `if/else if`.

**Вердикт:** 🟢 old-style bool assignment устранён.

---

### C.3 — 🟢 LOG_WARN для bool-полей: подсчёт

Найдено **14 вхождений** `log_msg(LOG_WARN, "...: невалидное"`:
- `enabled` (основной) — строка 130
- `tai_utc_offset` — строка 144
- `dpi_enabled` — строка 154
- `server.enabled` — строка 200
- `awg_keepalive` — строка 295
- `hy2_insecure` — строка 309
- `dns.enabled` — строка 510
- `doh_enabled` — строка 532
- `dot_enabled` — строка 545
- `parallel_query` — строка 568
- `fake_ip_enabled` — строка 572
- `proxy_group.enabled` — строка 644
- `rule_provider.enabled` — строка 670
- `proxy_provider.enabled` — строка 694
- `device.enabled` — строка 742

Покрытие хорошее. **Исключение:** `dpi_split_pos`, `dpi_fake_ttl`, `dpi_fake_repeats` —
LOG_WARN отсутствует (см. B.2).

**Вердикт:** 🟢 в целом — большинство bool-полей защищено. Минус: три DPI int-поля без лога.

---

### C.4 — 🟢 awg_keepalive — исправлен с LOG_WARN, диапазон [0, 65535]

**Строки:** 290–295

```c
} else if (strcmp(key, "awg_keepalive") == 0) {
    char *ep; long v = strtol(value, &ep, 10);
    if (ep != value && *ep == '\0' && v >= 0 && v <= 65535)
        srv->awg_keepalive = (uint16_t)v;
    else
        log_msg(LOG_WARN, "awg_keepalive: невалидное '%s'", value);
```

Исправлен: использует `endptr`, диапазон [0, 65535] (0 = keepalive отключён),
присутствует `else LOG_WARN`. Значение хранится как `uint16_t` — корректно.

Нет отдельного default в `config_load()` — при старте `memset(cfg, 0, ...)` + calloc серверов
→ `awg_keepalive = 0` (keepalive выключен по умолчанию). Разумно.

**Вердикт:** 🟢 корректно.

---

### C.5 — 🔴 doq_enabled и доп. DoQ-поля не парсятся из UCI

В `config.h` определены четыре поля в `DnsConfig`:
```c
bool     doq_enabled;
char     doq_server_ip[64];
uint16_t doq_server_port;
char     doq_sni[256];
```

Поиск в `config.c` по `doq_enabled`, `doq_server_ip`, `doq_server_port`, `doq_sni` —
**ноль совпадений**. Ни одно из этих полей не читается из UCI.

Последствие: DoQ (DNS over QUIC) фактически не может быть включён через UCI-конфиг,
несмотря на то что `dns_upstream_doq.h` объявляет `doq_pool_init(pool, epoll_fd, cfg)`.
Поля `doq_*` всегда остаются нулевыми (после `memset`). `doq_enabled = false` → DoQ
никогда не запускается независимо от желания пользователя.

**Вердикт:** 🔴 — функциональность DoQ мертва на уровне конфига. Нужно добавить парсинг
`doq_enabled`, `doq_server_ip`, `doq_server_port`, `doq_sni` в `SECTION_DNS` по аналогии
с `doh_*` / `dot_*` полями.

---

## Сводка

| # | Файл | Находка | Серьёзность |
|---|------|---------|-------------|
| A.1 | dpi_strategy.c | `getsockopt(IP_TTL)` без проверки возврата — при ошибке восстанавливаем TTL=64 вместо реального | 🟡 |
| A.2 | dpi_strategy.c | `send()` не проверяет partial write: в `dpi_send_fragment` — при p1<n1 второй фрагмент шлёт неверные байты | 🟡 |
| A.3 | dpi_strategy.c | `setsockopt(fake_ttl)` fail → return -1, TTL не тронут | 🟢 |
| A.4 | dpi_strategy.c | `TCP_NODELAY` не восстанавливается после fragmentation — Nagle навсегда отключён | 🟡 |
| A.5 | dpi_strategy.c | `TCP_NODELAY` выставляется даже когда `p2==0` (нет split) — лишний syscall | 🟡 |
| A.6 | dpi_strategy.c | `dpi_raw_socket_close` защищена `fd >= 0` | 🟢 |
| A.7 | dpi_strategy.c | Отсутствует `#include <sys/types.h>` для `ssize_t` | 🟡 |
| B.1 | config.c | DPI defaults: все 5 полей верны | 🟢 |
| B.2 | config.c | `dpi_split_pos` / `dpi_fake_ttl` / `dpi_fake_repeats` — нет `LOG_WARN` при невалидном UCI | 🔴 |
| B.3 | config.c | `dpi_fake_ttl` диапазон [1,64] — совпадает с `dpi_send_fake()` | 🟢 |
| B.4 | config.c | `dpi_fake_repeats` диапазон [1,20] — совпадает с `dpi_send_fake()` | 🟢 |
| B.5 | config.c | `dpi_enabled` bool с LOG_WARN | 🟢 |
| B.6 | config.c | `dpi_fake_sni` — нет LOG_WARN для пустой строки, нет валидации hostname | 🟡 |
| C.1 | config.c | `strtol(value, NULL, ...)` — 0 вхождений | 🟢 |
| C.2 | config.c | `= (strcmp(...)` — 0 вхождений | 🟢 |
| C.3 | config.c | `LOG_WARN` для bool — 14 мест, покрытие хорошее | 🟢 |
| C.4 | config.c | `awg_keepalive` — исправлен, диапазон [0,65535], LOG_WARN присутствует | 🟢 |
| C.5 | config.c | `doq_enabled` и все DoQ-поля не парсятся из UCI — DoQ мертва в конфиге | 🔴 |

**Итог:** 2 🔴  5 🟡  8 🟢

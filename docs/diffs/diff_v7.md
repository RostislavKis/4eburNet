# Волна v7 — исправления аудита v7

**Дата:** 2026-04-07  
**Базовый коммит:** e2fa26a (Аудит v7)

---

## V7-01 + V7-02: sniffer.c — порядок проверок

**Файл:** `core/src/proxy/sniffer.c:41–48`

```c
/* Было: */
uint16_t rec_len = ((uint16_t)buf[3] << 8) | buf[4];
if (rec_len < 4 || (size_t)(5 + rec_len) > (size_t)n) return 0;
if (buf[5] != 0x01) return 0;   /* UB: n может быть == 5 */
if (n < 9) return 0;            /* слишком поздно */

/* Стало: */
uint16_t rec_len = ((uint16_t)buf[3] << 8) | buf[4];
if (rec_len < 4) return 0;           /* V7-01: partial record допустим */
if ((size_t)n < 9) return 0;         /* V7-02: n>=9 ДО buf[5..8] */
if (buf[5] != 0x01) return 0;        /* теперь безопасно */
```

**V7-01**: убрано `(size_t)(5 + rec_len) > (size_t)n`. Chrome 130+ с ML-KEM
отправляет ClientHello 700–1200 байт — раньше sniffer всегда возвращал 0.
Теперь парсинг продолжается, ext_end clamping (строка 81) обеспечивает
безопасность при частичном peek-буфере.

**V7-02**: `if ((size_t)n < 9)` перенесён ПЕРЕД `buf[5]`. Устранён UB —
при `n == 5` обращение к неинициализированному `buf[5]` теперь невозможно.

---

## V7-03: sniffer.c — null-байт в SNI

**Файл:** `core/src/proxy/sniffer.c:100–113`

```c
/* Было: */
memcpy(sni_buf, buf + pos + 5, copy_len);
sni_buf[copy_len] = '\0';
return (int)copy_len;

/* Стало: */
memcpy(sni_buf, buf + pos + 5, copy_len);
sni_buf[copy_len] = '\0';
/* V7-03: null-байт в SNI невалиден (RFC 6066) */
if (strlen(sni_buf) != copy_len) {
    log_msg(LOG_DEBUG, "SNI sniffer: null-байт в SNI — отклонено");
    sni_buf[0] = '\0';
    return 0;
}
return (int)copy_len;
```

Атака: SNI `"evil\x00.com"` → rules_engine видит `"evil"` → DOMAIN-SUFFIX
правило `evil.com` не срабатывает → обход фильтрации. Теперь такие SNI
отклоняются, соединение идёт без домена (domain=NULL → MATCH fallback).

---

## V7-05: sniffer.c — удалён неиспользуемый include

```c
/* Удалено: */
#include <errno.h>

/* Добавлен вместо (для log_msg): */
#include "phoenix.h"
```

`errno` не использовался в sniffer.c после финального кода. `phoenix.h`
нужен для `log_msg()` в V7-03 fix.

---

## V7-04: rule_provider.c — DEC-031 задокументирован

**Файл:** `core/src/proxy/rule_provider.c:123`

```c
/* DEC-031: getaddrinfo() блокирует event loop при DNS timeout.
   При недоступном DNS сервере (ТСПУ block) — freeze до 30 сек.
   Решение: async DNS через dns_resolver.c в 4.x. */
int gai = getaddrinfo(host, port_str, &hints, &res);
```

DEC-031 добавлен в CLAUDE.md decisions.

---

## Итог

| # | Файл | Исправление |
|---|---|---|
| V7-01 | sniffer.c | Убрана `> n` проверка — partial ClientHello теперь парсится |
| V7-02 | sniffer.c | `n<9` check перед `buf[5]` — UB устранён |
| V7-03 | sniffer.c | null-байт в SNI отклоняется (RFC 6066) |
| V7-04 | rule_provider.c | DEC-031 задокументирован |
| V7-05 | sniffer.c | `errno.h` удалён, `phoenix.h` добавлен для log_msg |

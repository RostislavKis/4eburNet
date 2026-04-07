# Аудит v7 — phoenix-router

**Дата:** 2026-04-07  
**Фокус:** новый код этапов 3.6 + DEC-013/025/027  
**Предыдущий аудит:** v6 (10/10, 100%)

---

## Файлы под аудитом

| Файл | Этап |
|---|---|
| `core/src/proxy/sniffer.c` | 3.6 |
| `core/include/proxy/sniffer.h` | 3.6 |
| `core/src/proxy/dispatcher.c` (SNI интеграция) | 3.6 |
| `core/include/device.h` | DEC-013 |
| `core/src/resource_manager.c` | DEC-013 |
| `core/src/crypto/tls.c` (tls_get_client_random) | DEC-025 |
| `core/src/proxy/rule_provider.c` (getaddrinfo) | DEC-027 |
| `core/include/config.h` (reality_short_id) | DEC-025 |

---

## Итоговая таблица

| # | Файл | Серьёзность | Описание | Статус |
|---|---|---|---|---|
| V7-01 | sniffer.c:42 | **MEDIUM** | Строгая проверка rec_len обрезает ClientHello >507 байт | Принято к 3.6 |
| V7-02 | sniffer.c:45 | **MEDIUM** | buf[5] читается без гарантии n≥6 (UB при n==5) | Принято к 3.6 |
| V7-03 | sniffer.c:104 | LOW | Нет валидации null-байтов в SNI — обход DOMAIN-SUFFIX правил | Принято к 3.6 |
| V7-04 | rule_provider.c:124 | LOW | getaddrinfo() блокирует event loop на DNS (acceptable) | Долг (DEC-031) |
| V7-05 | sniffer.c:14 | INFO | `#include <errno.h>` — не используется | ✅ Закрыт |
| V7-06 | dispatcher.c:755 | INFO | SNI интеграция корректна, lifetimes sni/domain правильные | OK |
| V7-07 | tls.c:419 | INFO | tls_get_client_random: OPENSSL_EXTRA guard правильный | OK |
| V7-08 | device.h | INFO | Пороги MICRO/NORMAL/FULL соответствуют CLAUDE.md | OK |
| V7-09 | dispatcher.c:109 | INFO | reality_short_id pointer lifetime корректен (strdup в tls.c) | OK |

**Итого: MEDIUM 2 (к 3.6) | LOW 1+1 | INFO 5**

---

## V7-01 — MEDIUM: sniffer.c строгая проверка rec_len

**Файл:** `proxy/sniffer.c:42`

```c
if (rec_len < 4 || (size_t)(5 + rec_len) > (size_t)n) return 0;
```

`n` ≤ 512 (SNIFFER_PEEK_SIZE). `5 + rec_len > n` означает, что весь TLS Record не вошёл в peek-буфер. Функция возвращает 0, хотя SNI extension обычно стоит в первых 200–400 байтах ClientHello.

**Проблема:** Chrome 120+ ClientHello ≈ 500–520 байт (без PQ). Chrome 130+ с ML-KEM/Kyber ≈ 700–1200 байт. Для них `rec_len ≥ 508` → `5 + rec_len > 512` → return 0 → domain=NULL → DOMAIN/GEOSITE правила не работают.

**Противоречие с дизайном:** строка 81 `if (ext_end > (size_t)n) ext_end = (size_t)n;` явно предусматривает частичный парсинг. Но мы возвращаем 0 раньше.

**Решение:**
```c
/* Было: */
if (rec_len < 4 || (size_t)(5 + rec_len) > (size_t)n) return 0;

/* Стало: только базовая санитизация, partial parse разрешён */
if (rec_len < 4) return 0;
```

Все последующие `(size_t)n < pos + N` checks + ext_end clamping обеспечивают безопасность при частичном буфере.

---

## V7-02 — MEDIUM: sniffer.c buf[5] без гарантии n≥6

**Файл:** `proxy/sniffer.c:45`

```c
if (n < 5) return 0;          /* гарантирует n ≥ 5 (buf[0..4]) */
...
if (buf[5] != 0x01) return 0; /* требует n ≥ 6 — не гарантировано! */
if (n < 9) return 0;           /* слишком поздно */
```

`buf` — стек-массив 512 байт. Если `recv()` вернул ровно 5 байт (например, только TLS Record заголовок без тела), то `buf[5]` — **неинициализированная память**. Чтение UB по стандарту C. На практике: не крашится (стек), но читает мусор. Мусор скорее всего ≠ 0x01 → return 0 (правильное поведение случайно).

**Решение:** переместить `if (n < 9) return 0;` раньше:

```c
if (n < 5) return 0;
if (buf[0] != 0x16) return 0;
if (buf[1] != 0x03 || buf[2] < 0x01 || buf[2] > 0x04) return 0;
uint16_t rec_len = ((uint16_t)buf[3] << 8) | buf[4];
if (rec_len < 4) return 0;               /* V7-01 fix */
if (n < 9) return 0;                     /* V7-02 fix — ЗДЕСЬ */
if (buf[5] != 0x01) return 0;            /* теперь n≥9 гарантировано */
```

---

## V7-03 — LOW: sniffer.c нет валидации null-байтов в SNI

**Файл:** `proxy/sniffer.c:104`

```c
memcpy(sni_buf, buf + pos + 5, copy_len);
sni_buf[copy_len] = '\0';
```

Если клиент отправляет SNI `"evil\x00.com"` (9 байт, `name_len=9`):
- `memcpy` скопирует все 9 байт включая `\x00`
- `sni_buf = "evil\x00.com\x00"`
- В rules_engine: `strcmp(sni_buf, "evil.com")` → сравнивает `"evil"` с `"evil.com"` → нет совпадения
- DOMAIN-SUFFIX правило `evil.com` **не сработает**

Атака: обход REJECT/GROUP правил через встроенный null-байт в SNI. Цель: на сервере SNI виден как `"evil.com"`, в rules_engine — как `"evil"` → правило не срабатывает → MATCH fallback.

**Решение:** валидация после memcpy:
```c
memcpy(sni_buf, buf + pos + 5, copy_len);
sni_buf[copy_len] = '\0';
/* Null-байт в SNI невалиден — отклонить */
if (strlen(sni_buf) != copy_len) {
    sni_buf[0] = '\0';
    return 0;
}
return (int)copy_len;
```

---

## V7-04 — LOW (долг DEC-031): getaddrinfo блокирует event loop

**Файл:** `proxy/rule_provider.c:124`

```c
int gai = getaddrinfo(host, port_str, &hints, &res);
```

`getaddrinfo()` — блокирующий системный вызов. При DNS timeout (обычно 5–30 сек) блокирует главный event loop на всё время ожидания.

**Контекст:** допустимо при текущих условиях:
- Вызывается через `rule_provider_tick()` не чаще 1 раза за tick
- Не более 1 провайдера за вызов (H-04)
- Обычный RTT для DNS ≈ 1–50 мс (не критично)

**Риск:** при недоступном DNS сервере (ТСПУ block) — 5–30 секундный freeze event loop. Для продакшена на EC330 это означает полную остановку relay соединений.

**Решение (DEC-031):** вынести http_fetch в отдельный non-blocking контекст или использовать DNS через dns_resolver (async). Зарегистрировать как DEC-031, реализовать в 4.x.

---

## V7-05 — INFO: errno.h не используется в sniffer.c

```c
#include <errno.h>   /* используется → нет */
```

`errno` нигде в sniffer.c не используется после рефакторинга. Удалить.

---

## Проверка новых компонентов (покрытие)

### sniffer.c — парсер ClientHello

Протестированные пути:
- `n <= 0` → return 0 ✅
- `buf[0] != 0x16` (не-TLS) → return 0 ✅  
- `buf[1] != 0x03` (не-TLS версия) → return 0 ✅
- Handshake Type != 0x01 → return 0 ✅
- ClientHello без SNI extension (ECH/ESNI) → return 0 ✅
- `sni_buflen < 2` → return 0, sni_buf[0]='\0' ✅
- Корректный SNI → memcpy + return len ✅
- Усечение при `name_len >= sni_buflen` ✅
- Частичный peek (ext_end clamping) → парсит что есть ⚠️ (только если V7-01 закрыт)

### dispatcher.c — SNI интеграция

```c
char sni[256] = {0};
const char *domain = NULL;
if (conn->fd >= 0) {
    if (sniffer_peek_sni(conn->fd, sni, sizeof(sni)) > 0) {
        domain = sni;
```

- `sni` инициализирован нулями → fallback на `domain=NULL` при ошибке ✅
- `domain` указывает на стек-массив `sni`, передаётся в `rules_engine_get_server()` в рамках той же функции ✅
- `conn->fd >= 0` — лишняя проверка (fd всегда валиден при handle_conn), но безвредна ✅

### device.h — профили устройств

- Пороги `<64MB → MICRO`, `≤128MB → NORMAL`, `else → FULL` — соответствуют CLAUDE.md ✅
- `device_relay_buf(DEVICE_FULL) = 64KB` — соответствует CLAUDE.md ✅
- VM (225 МБ RAM) → DEVICE_FULL → `Лимиты: relay_buf=64KB, max_conns=1024, dns_pending=64` ✅

### tls_get_client_random

```c
#ifdef OPENSSL_EXTRA
size_t n = wolfSSL_get_client_random((const WOLFSSL *)conn->ssl, buf, ...);
```

- `OPENSSL_EXTRA` определён в нашей сборке wolfSSL 5.9.0 ✅
- NULL-проверки параметров ✅
- Функция `connected` гарантирует завершённый handshake ✅

### rule_provider.c — getaddrinfo (DEC-027)

- `AF_UNSPEC` → IPv4 + IPv6 + domain ✅
- Первый результат `res` используется для connect ✅
- `freeaddrinfo(res)` вызывается во всех путях ✅
- Порт парсится из URL (`strtol` + endptr проверка) ✅
- `SOCK_CLOEXEC` у нового fd ✅

---

## Регрессии от предыдущих изменений

### Нет новых регрессий

- DEC-013 (device.h): только логирование в main.c, нет side effects ✅
- DEC-025 (reality_short_id): добавлено поле `char[17]` в ServerConfig, нулевая инициализация через `memset 0` ✅
- DEC-027 (getaddrinfo): заменяет `inet_pton` блок, функциональность расширена, backward compatible ✅
- 3.6 Sniffer: добавляет peek до rules_engine, не изменяет relay create/destroy ✅

---

## Приоритеты для волны v7

1. **V7-02 (MEDIUM)** — однострочное исправление, тривиально
2. **V7-01 (MEDIUM)** — однострочное исправление (убрать `>= n` часть проверки)
3. **V7-05 (INFO)** — удалить `#include <errno.h>`
4. **V7-03 (LOW)** — добавить `strlen` проверку после memcpy

---

*Аудит v7: 4 замечания к исправлению + 1 долг. Аудиты v1-v7: ~305 пунктов.*

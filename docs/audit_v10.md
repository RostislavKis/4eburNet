# 4eburNet — Devil Audit v10
**Дата:** 2026-04-10
**Охват:** B.4 — `hysteria2_udp.h`, `hysteria2_udp.c`, `test_hysteria2_udp.c`
**Предыдущий аудит:** audit_v9 (все находки закрыты)

---

## 🔴 Критично — 0 находок

Нет находок уровня 🔴. Нет переполнений буфера, утечек памяти, неинициализированных данных.
NEED() macro надёжно ограничивает запись, все NULL-пути проверены до разыменования.

---

## 🟡 Важно — 5 находок

### #1 — HY2_UDP_FRAG_SIZE слишком мал для длинных хостов
**Файл:** `hysteria2_udp.h:37`, `hysteria2_udp.c:169`

```
Max первого фрагмента = 8 (header)
                      + 2 (HostLen field) + 253 (max_host_len) + 2 (Port)
                      + 1200 (HY2_UDP_FRAG_PAYLOAD)
                      = 1465 байт
HY2_UDP_FRAG_SIZE     = 1300 байт
Дефицит              = 165 байт
```

При хосте >= 89 символов `NEED(data_len)` в `hy2_udp_msg_encode` возвращает -1 → `hy2_udp_fragment` возвращает -1 → весь UDP-датаграмм теряется, без лога. Нет переполнения (NEED защищает), но корректность нарушена.

Примеры, когда проблема проявится:
- Целевой хост за прокси с длинным именем (CDN поддомены > 88 символов)
- DNS-over-UDP к хостам вида `long-subdomain.another.example.org`

**Исправление:**
```c
/* hysteria2_udp.h */
#define HY2_UDP_FRAG_SIZE     1470   /* 8 + (2+253+2) + 1200 + запас */
```

---

### #2 — Нет TTL/eviction для сессий → истощение таблицы
**Файл:** `hysteria2_udp.c:197-230`

`hy2_udp_session_mgr_t` хранит 256 слотов без времени жизни. Сессии не вытесняются по LRU и не истекают по таймауту. Сценарий:

1. Клиент отправляет 256 UDP-пакетов с уникальными session_id.
2. Все 256 слотов заняты.
3. Новые легитимные сессии отклоняются с LOG_WARN, UDP теряются.

Одиночный клиент с интенсивным UDP (DNS-резолвинг) за часы исчерпает таблицу.
DoS-поверхность ограничена (только клиенты на роутере), но риск реален.

**Исправление:** добавить поле `uint32_t last_seen` (timestamp), при заполнении таблицы вытеснять самую старую сессию.

---

### #3 — Lifetime zero-copy `msg->data` не задокументирован
**Файл:** `hysteria2_udp.h:55-58`

```c
/* Данные — zero-copy указатель в исходный буфер */
const uint8_t  *data;
size_t          data_len;
```

Поле `msg_out->data` указывает непосредственно в `buf` (параметр вызова `hy2_udp_msg_decode`). Если caller освободит или переиспользует `buf` до окончания работы с `msg_out->data` — UB. В .h-файле нет предупреждения.

Будущий dispatcher, читающий `msg->data` после recv-буфер-ротации, получит мусор без явного предупреждения о зависимости.

**Исправление:** добавить комментарий в `hysteria2_udp.h`:
```c
/*
 * ВНИМАНИЕ: msg_out->data — zero-copy, указывает в buf.
 * buf должен жить не меньше, чем используется msg_out->data.
 */
```

---

### #4 — test_udp_msg_roundtrip не проверяет host и port
**Файл:** `test_hysteria2_udp.c:44-50`

```c
CHECK(msg.data_len   == sizeof(data), "data_len верный");
/* ← нет проверки msg.host и msg.port */
```

Decode может вернуть неверный хост или порт (например, при инверсии байт в read_u16_be) — тест этого не поймает. Уже поймали похожую проблему в тесте varint (audit_v9 #3, bytes test).

**Исправление:**
```c
CHECK(strcmp(msg.host, "8.8.8.8") == 0, "host верный");
CHECK(msg.port == 53,                   "port верный");
```

---

### #5 — hy2_udp_session_mgr_t (~66 KB) без предупреждения об аллокации
**Файл:** `hysteria2_udp.h:78-80`

```
sizeof(hy2_udp_session_t)     = 4 + 256 + 2 + 1 + padding = ~264 байт
sizeof(hy2_udp_session_mgr_t) = 256 * 264 = ~67 584 байт = ~66 KB
```

Тест (`test_hysteria2_udp.c:129`) объявляет `hy2_udp_session_mgr_t mgr` на стеке — это 66 KB на stack frame. На стандартном Linux (8 MB stack) некритично, но на OpenWrt с ограниченным стеком потока может вызвать переполнение стека без видимой ошибки.

**Исправление:** добавить в .h комментарий:
```c
/* ~66 KB — размещать только в heap (malloc) или как глобальный объект */
typedef struct { ... } hy2_udp_session_mgr_t;
```

---

## 🟢 Улучшения — 4 находки

### #6 — encode не проверяет frag_id < frag_count
**Файл:** `hysteria2_udp.c:43-85`

`hy2_udp_msg_encode` не проверяет, что `frag_id < frag_count`. Decode отклоняет такой пакет (строка 107), но encode молча создаёт некорректный датаграмм, который сервер отклонит. Единственный caller — `hy2_udp_fragment`, который гарантирует корректность. Но прямой вызов encode с неверными значениями не будет диагностирован на encode-стороне.

```c
/* Добавить после frag_count == 0 check: */
if (frag_count > 0 && frag_id >= frag_count) return -1;
```

---

### #7 — return (int)buf_size теоретически переполняется
**Файл:** `hysteria2_udp.c:137`

```c
return (int)buf_size;  /* потреблена вся датаграмма */
```

Если `buf_size > INT_MAX` — UB при каст к int. Реальный QUIC datagram ограничен MTU (< 65535), поэтому на практике недостижимо. Но `assert(buf_size <= INT_MAX)` или смена сигнатуры на `ssize_t` устранили бы вопрос при ревью.

---

### #8 — hy2_udp_fragment: data=NULL при data_len=0 → -1 не задокументировано
**Файл:** `hysteria2_udp.c:150`

```c
if (!host || !data) return -1;
```

Нулевой UDP датаграмм (пустое тело) с `data=NULL, data_len=0` вернёт -1, хотя `hy2_udp_msg_encode` принимает `data=NULL, data_len=0` (guard `!data && data_len > 0`). Вызвать `hy2_udp_fragment` с пустым датаграммом невозможно.

Если нужна поддержка пустых UDP-датаграмм: изменить guard на `if (!data && data_len > 0) return -1;`

---

### #9 — test_udp_fragment_split не проверяет восстановимость данных
**Файл:** `test_hysteria2_udp.c:73-103`

Тест проверяет число фрагментов и порядковые номера, но не декодирует фрагменты обратно и не проверяет, что данные совпадают. Если фрагментатор испортит данные в chunk-смещении — тест не поймает.

Reassembly не реализован (B.4 — только encode-сторона), поэтому тест декодирует только первый фрагмент — достаточно добавить:
```c
/* Декодировать первый фрагмент и проверить первые 1200 байт = 0xCC */
hy2_udp_msg_t first_msg;
hy2_udp_msg_decode(frags[0].buf, frags[0].buf_len, &first_msg, NULL, 0);
CHECK(first_msg.data_len == 1200, "первый фрагмент содержит 1200 байт");
CHECK(((const uint8_t*)first_msg.data)[0] == 0xCC, "данные первого фрагмента корректны");
```

---

## Сводная таблица

| # | Файл | Строки | Класс | Серьёзность |
|---|------|--------|-------|-------------|
| 1 | hysteria2_udp.h:37 + hysteria2_udp.c:169 | const + NEED() | HY2_UDP_FRAG_SIZE занижен → потеря датаграмм при host >= 89 символов | 🟡 |
| 2 | hysteria2_udp.c:197-230 | session_add | Нет TTL/eviction → таблица исчерпывается | 🟡 |
| 3 | hysteria2_udp.h:55-58 | hy2_udp_msg_t | Lifetime zero-copy data не задокументирован | 🟡 |
| 4 | test_hysteria2_udp.c:44-50 | roundtrip test | host и port не проверяются после decode | 🟡 |
| 5 | hysteria2_udp.h:78-80 | session_mgr_t | ~66 KB без предупреждения о heap-размещении | 🟡 |
| 6 | hysteria2_udp.c:43-85 | hy2_udp_msg_encode | frag_id < frag_count не проверяется в encode | 🟢 |
| 7 | hysteria2_udp.c:137 | hy2_udp_msg_decode | return (int)buf_size теоретически UB | 🟢 |
| 8 | hysteria2_udp.c:150 | hy2_udp_fragment | data=NULL при data_len=0 → -1, не задокументировано | 🟢 |
| 9 | test_hysteria2_udp.c:73-103 | fragment_split test | Нет проверки содержимого фрагментированных данных | 🟢 |

**Итого:** 🔴 0 / 🟡 5 / 🟢 4

---

## Рекомендуемый порядок исправления

```
Обязательно перед B.5:
  #1  HY2_UDP_FRAG_SIZE → 1470 (одна строка в .h)
  #4  test roundtrip: добавить CHECK(host) и CHECK(port)

До dispatcher integration:
  #2  Добавить last_seen + LRU eviction в session_mgr
  #3  Комментарий lifetime в .h

Опционально:
  #5  Комментарий ~66 KB в .h
  #6  frag_id < frag_count guard в encode
  #9  Проверка данных в fragment_split тесте
  #7  #8  Документация/assert (low priority)
```

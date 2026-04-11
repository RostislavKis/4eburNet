# Devil Audit v21 — D.1+D.2 ShadowTLS v3 (HMAC-SHA256 + protocol)

**Дата:** 2026-04-11
**Статус:** аудит после коммитов `0ad4acf` (D.1), `9223e8b` (D.2), `4b9c09d` (D.2 fix)
**Файлы:** `hmac_sha256.h` (41), `hmac_sha256.c` (83), `shadowtls.h` (86), `shadowtls.c` (267), `test_hmac_sha256.c` (132), `test_shadowtls.c` (161), `dpi_payload.h` (+18), `dpi_payload.c` (+35)

---

## Scope

- `hmac_sha256` / `hmac_sha256_2` / `hmac_sha256_verify` — crypto primitives
- `stls_ctx_init` / `stls_send_client_hello` / `stls_recv_handshake` — handshake
- `stls_wrap` / `stls_unwrap` — data framing
- `dpi_make_tls_clienthello_ex` — расширенный ClientHello builder
- Тесты: 13 + 21 = 34 тестов

---

## Находки

### 1. 🟡 TLS 1.3 серверы могут не отправлять CCS

**Файл:** `shadowtls.c:154-160`

TLS 1.3 spec (RFC 8446 §5) определяет CCS как необязательный compatibility message. Некоторые серверы (особенно с конфигом `disable_middlebox_compat`) не отправляют CCS вообще. В этом случае `STLS_SKIP_HS` никогда не перейдёт в `STLS_WAIT_FINISHED` → соединение зависнет.

ShadowTLS серверы (ihcr/shadow-tls) **всегда** отправляют CCS (проксируют реальный TLS handshake), поэтому на практике проблема не возникнет с правильно настроенными серверами. Но для совместимости стоит добавить fallback: если после 5 записей без CCS → ACTIVE.

**Влияние:** минимальное при работе с ShadowTLS серверами. Потенциальная проблема с нестандартными конфигурациями.
**Действие:** добавить счётчик records в STLS_SKIP_HS, fallback на ACTIVE после 5+ records без CCS. Можно отложить до реального столкновения.

---

### 2. 🟡 `stls_recv_handshake` STLS_WAIT_FINISHED: Finished record остаётся в recv_buf

**Файл:** `shadowtls.c:161-169`

```c
} else if (ctx->state == STLS_WAIT_FINISHED) {
    ctx->state = STLS_ACTIVE;
    int remaining = ctx->recv_len - pos;
    ...
    ctx->recv_len = remaining;
    return 1;
}
```

При переходе в ACTIVE: `recv_buf` содержит Finished record (pos указывает на него). `remaining = recv_len - pos` включает Finished record. memmove перемещает его в начало buf. Этот record не является AppData — но dispatcher не знает о нём. При первом вызове `stls_unwrap` на данных из `recv_buf` — Finished record (type != 0x17) будет отклонён (`return -1`).

На практике: dispatcher вызывает `stls_recv_handshake` пока не вернёт 1, затем переключается на relay через `stls_wrap/unwrap` с новыми данными из `read()`. `recv_buf` не используется напрямую в relay — dispatcher читает из socket. **Не баг**, но `recv_buf` содержит мусор — стоит обнулить `recv_len = 0` после ACTIVE.

**Влияние:** минимальное. recv_buf не используется после handshake в текущей архитектуре.
**Действие:** `ctx->recv_len = 0;` вместо `ctx->recv_len = remaining;` в STLS_WAIT_FINISHED ветке.

---

### 3. 🟡 `stls_unwrap`: data_len=0 обрабатывается

**Файл:** `shadowtls.c:237-238`

```c
int data_len = payload_len - STLS_TAG_LEN;
if (out_size < data_len) return -1;
```

Если `payload_len == STLS_TAG_LEN` (4) → `data_len = 0`. `memcmp(tag, hmac_out, 4)` пройдёт (HMAC от пустых данных), `memcpy(out, data, 0)` — noop. Возвращает 0. Caller получит 0 байт — может интерпретировать как EOF.

ShadowTLS спецификация не запрещает пустые AppData. Возврат 0 для 0 байт корректен, но caller должен отличать "0 байт данных" от "нет данных".

**Влияние:** минимальное. Пустые AppData не генерируются ни одной стороной.
**Действие:** нет. Документировать что 0 = пустой payload, не EOF.

---

### 4. 🟢 `hmac_sha256_2`: wc_HmacFree на всех exit путях

Все 5 error ветвей содержат `wc_HmacFree(&h); return -1;`. Успешный путь: `wc_HmacFinal` → `wc_HmacFree` → `return 0`. Нет утечки.

Обработка NULL: `data1=NULL && len1=0` → `if (len1 > 0 && data1)` пропускает Update. Корректно — HMAC от пустых данных.

**Вердикт:** корректно.

---

### 5. 🟢 `stls_wrap/unwrap` counter_be: big-endian сериализация

```c
uint64_t cnt = ctx->send_counter;
for (int i = 7; i >= 0; i--) {
    counter_be[i] = (uint8_t)(cnt & 0xFF);
    cnt >>= 8;
}
```

Локальная переменная `cnt` — копия. `ctx->send_counter` не повреждается. Big-endian 8 байт. Инкремент после HMAC. Корректно.

**Вердикт:** корректно.

---

### 6. 🟢 `stls_wrap`: out_size проверяется

```c
int total = TLS_RECORD_HDR + STLS_TAG_LEN + len;
if (out_size < total) return -1;
```

`total = 5 + 4 + len`. При `len = 16384` (TLS max record) → `total = 16393`. Если `out_size < 16393` → -1.

**Вердикт:** корректно.

---

### 7. 🟢 `stls_send_client_hello`: /dev/urandom + error handling

Все error paths возвращают -1. `close(rfd)` перед каждым early return. hmac_sha256 fail → -1. `dpi_make_tls_clienthello_ex` fail → -1. `send()` partial → state = ERROR + return -1.

**Вердикт:** корректно.

---

### 8. 🟢 `parse_server_hello`: позиция server_random

```c
memcpy(server_random, msg + 6, 32);
```

ServerHello layout: `[0] type=0x02`, `[1-3] length`, `[4-5] version(0x0303)`, `[6-37] server_random(32)`. Offset 6 — корректно для server_random.

Handshake message находится внутри TLS record payload. `payload` в `stls_recv_handshake` указывает на начало handshake message (после TLS record header). Корректно.

**Вердикт:** корректно.

---

### 9. 🟢 `dpi_make_tls_clienthello_ex`: out_random = p-32

```c
if (client_random)
    WN(p, client_random, 32);
else
    { fill_random(p, 32); p += 32; }
if (out_random)
    memcpy(out_random, p - 32, 32);
```

При `client_random != NULL`: `WN` копирует 32 байта и сдвигает `p += 32`. `p - 32` указывает на записанные байты. При `client_random == NULL`: `fill_random(p, 32); p += 32;` → `p - 32` указывает на random. В обоих случаях `p - 32` корректен.

**Вердикт:** корректно.

---

### 10. 🟢 Тест session_id: offset 44

```c
ASSERT(memcmp(buf + 44, expected, 32) == 0, ...);
```

TLS record: `hdr(5) + handshake_type(1) + handshake_len(3) + version(2) + random(32) + sid_len(1) = 44`. Первый байт SessionID на offset 44. Проверено структурой `dpi_make_tls_clienthello_ex`.

**Вердикт:** корректно. Offset стабильный — формат ClientHello фиксирован.

---

## Компиляция и тесты

```
$ make -f Makefile.dev test
ALL PASS × 9 (34 тестов суммарно: 13 hmac + 21 shadowtls)

$ ls -lh build/4eburnetd
-rwxr-xr-x 1.6M 4eburnetd
```

---

## Итог

| Уровень | Количество | Детали |
|---------|-----------|--------|
| 🔴 RED | 0 | — |
| 🟡 YELLOW | 3 | CCS необязательный в TLS 1.3, Finished в recv_buf, data_len=0 |
| 🟢 GREEN | 7 | HmacFree paths, counter_be, out_size, urandom, parse_server_hello, out_random, offset 44 |

**Вердикт: D.1+D.2 чистые.** Ноль критических проблем. Три 🟡 — один architectural (CCS fallback, отложить), два cosmetic (recv_buf cleanup, data_len=0 документация). Готово для D.3.

# Devil Audit v22 — блок D ShadowTLS v3 (полный)

**Дата:** 2026-04-11
**Статус:** аудит после коммитов D.1-D.4 + fixes (последний: `f9bb8b8`)
**Scope:** `dispatcher.h` (+9), `dispatcher.c` (+122), `shadowtls.c` (267), `hmac_sha256.c` (83), `dpi_payload.c` (+35), `config.h/c`, `servers.js`, `4eburnet.uc`

---

## Находки

### 1. 🔴 ShadowTLS + TLS inner protocols (VLESS, Trojan) — архитектурный конфликт

**Файлы:** `dispatcher.c:785,821,1640-1647`

При `transport="shadowtls"` + `protocol="vless"` или `protocol="trojan"`:

1. RELAY_STLS_SHAKE → `stls_recv_handshake()` → ACTIVE
2. `proto->start()` → `vless_protocol_start()` → `tls_connect_start(relay->tls, upstream_fd)`
3. wolfSSL начинает TLS handshake на `upstream_fd`
4. **Конфликт:** wolfSSL читает/пишет raw TCP на upstream_fd, но ShadowTLS сервер ожидает AppData records с HMAC тегами

В `relay_transfer` guard `!r->use_tls` предотвращает вызов `stls_wrap/unwrap` когда `use_tls=true`. wolfSSL работает напрямую с upstream_fd → ShadowTLS сервер получает raw TLS bytes вместо wrapped records → connection reset.

**Корневая причина:** wolfSSL привязан к file descriptor (`wolfSSL_set_fd`). Для работы ShadowTLS + TLS нужна прослойка: wolfSSL → stls_wrap → send(upstream_fd). Это требует custom BIO (wolfSSL I/O callbacks: `wolfSSL_SetIORecv/wolfSSL_SetIOSend`).

**Что работает сейчас:**
- `transport="shadowtls"` + `protocol="shadowsocks"` — SS не использует TLS → `use_tls=false` → wrap/unwrap активны → **OK**
- `transport="shadowtls"` + `protocol="direct"` — без TLS → **OK**

**Что НЕ работает:**
- `transport="shadowtls"` + `protocol="vless"` — wolfSSL конфликт
- `transport="shadowtls"` + `protocol="trojan"` — wolfSSL конфликт

**Влияние:** критическое для VLESS/Trojan. SS/direct — работает.
**Действие (варианты):**
- A) Валидация в config.c: запретить `transport=shadowtls` с TLS-протоколами. Лог предупреждение.
- B) wolfSSL I/O callbacks: `wolfSSL_SetIOSend` → `stls_wrap` → `send()`. ~100 строк, корректное решение.
- C) Документировать ограничение, реализовать B в следующей версии.

**Рекомендация:** A (валидация) сейчас + B (I/O callbacks) как отдельный блок.

---

### 2. 🟡 malloc на каждый пакет в relay_transfer

**Файлы:** `dispatcher.c:787,824`

```c
uint8_t *wrap_buf = malloc((size_t)wrap_size);   /* n + 9 байт */
uint8_t *unwrap_buf = malloc((size_t)n);          /* n байт */
```

При relay_buf_size = 64KB (FULL): malloc(65545) + free() на каждом пакете. На MIPS с musl: musl malloc использует mmap для > 128KB, для 64KB — heap. Heap фрагментация при интенсивном трафике.

**Альтернатива:** добавить `stls_buf` в `dispatcher_state_t` (один буфер, выделяется при init). Размер = `relay_buf_size + 9`.

**Влияние:** производительность. На EC330 при 100 соединениях × 1000 пакетов/сек → 100K malloc/free в секунду. musl справится, но suboptimal.
**Действие:** отложить оптимизацию до профилирования на реальном трафике.

---

### 3. 🟡 `protocol_find_for_server` при transport="shadowtls" + protocol="vless"

**Файл:** `dispatcher.c:377-381`

```c
if (strcmp(server->protocol, "vless") == 0) {
    if (server->transport[0] &&
        strcmp(server->transport, "xhttp") == 0)
        return &proto_xhttp;
    return &proto_vless;
}
```

При `protocol="vless"` + `transport="shadowtls"`: `transport[0]` != 0, но != "xhttp" → вернёт `proto_vless` (не proto_xhttp). Это корректно — xhttp проверяется явно. Но `transport="shadowtls"` не влияет на выбор inner protocol — тоже корректно (transport обрабатывается в RELAY_CONNECTING, не в protocol_find).

**Влияние:** нет проблемы, но стоит документировать что `transport` влияет на два разных пути: xhttp → protocol_find, shadowtls → RELAY_CONNECTING.

---

### 4. 🟢 relay_free корректно очищает stls

```c
#if CONFIG_EBURNET_STLS
    if (r->stls) {
        free(r->stls);
        r->stls = NULL;
    }
#endif
```

`shadowtls_ctx_t` не содержит fd или malloc'ed полей — только stack-like данные (password, counters, recv_buf[4096]). `free()` достаточен.

**Вердикт:** корректно.

---

### 5. 🟢 epoll cleanup при stls_send_client_hello failure

В RELAY_CONNECTING: если `stls_send_client_hello()` < 0 → `relay_free(ds, r)`. К этому моменту `upstream_fd` уже в epoll (добавлен в RELAY_CONNECTING handler перед ShadowTLS check). `relay_free` делает `epoll_ctl(DEL, upstream_fd)` → корректно.

**Вердикт:** корректно.

---

### 6. 🟢 RELAY_STLS_SHAKE: EPOLLIN guard

```c
if (ep->is_client) break;
if (!(ev & EPOLLIN)) break;
```

ShadowTLS handshake — серверные данные приходят на upstream_fd. Client events игнорируются. Только EPOLLIN (данные от сервера). Корректно.

**Вердикт:** корректно.

---

### 7. 🟢 stls_wrap partial send check

```c
ssize_t sent = send(fd, wrap_buf, wlen, MSG_NOSIGNAL);
return (sent == wlen) ? n : (ssize_t)-1;
```

Если send() вернул partial → return -1 → relay_free. Данные потеряны, но соединение корректно закрывается. Для ShadowTLS partial send невозможен на первом пакете (буфер пуст), но при нагрузке — возможен. Поведение аналогично DPI path.

**Вердикт:** допустимо.

---

### 8. 🟢 default case в switch

```c
default:
    log_msg(LOG_WARN, "relay: неизвестное состояние %d", r->state);
    relay_free(ds, r);
    continue;
```

Покрывает enum gaps. Корректно.

**Вердикт:** корректно.

---

## Компиляция и тесты

```
$ make -f Makefile.dev 2>&1 | grep -E 'error:|warning:'
(только dns_upstream_doq.c empty translation unit — не наш)

$ make -f Makefile.dev test
ALL PASS × 9

$ ls -lh build/4eburnetd
-rwxr-xr-x 1.6M 4eburnetd
```

---

## Итог

| Уровень | Кол-во | Детали |
|---------|--------|--------|
| 🔴 RED | 1 | ShadowTLS + TLS inner protocols (VLESS/Trojan) — wolfSSL конфликт |
| 🟡 YELLOW | 2 | malloc per-packet, transport path documentation |
| 🟢 GREEN | 5 | relay_free, epoll cleanup, EPOLLIN guard, partial send, default case |

**Вердикт: 1 критическая проблема.** ShadowTLS работает только с SS/direct. Для VLESS/Trojan нужны wolfSSL I/O callbacks или валидация запрета. Рекомендация: config.c валидация сейчас (запретить transport=shadowtls с TLS-протоколами), wolfSSL I/O callbacks — отдельный блок.

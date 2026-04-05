# Audit v3 Wave 9 — Diff

**Дата**: 2026-04-05
**Закрыто**: C-01, C-06, H-18 (3 находки)
**Результат**: 127/127 = 100% (93 закрыто + 34 принято, 0 открыто)

---

## C-01 — ложное срабатывание (keyed BLAKE2s = HMAC для WireGuard)

WireGuard whitepaper sec 5.4 определяет:
`HMAC(key, input) := BLAKE2s(data=input, key=key, outlen=32)`

Наша `blake2s_hmac()` делает именно это — keyed BLAKE2s.
Это **не** RFC 2104 HMAC (ipad/opad), а WG-специфичная конструкция.
Статус обновлён в audit_v3.md.

---

## C-06 + H-18 — Неблокирующий DNS resolver

### Проблема

`resolve_query()` в dns_server.c вызывал `dns_upstream_query()` синхронно.
Каждый DNS запрос к upstream блокировал main event loop на 2 сек (UDP timeout).
Флуд некэшированными запросами = полный DoS прокси.

### Решение

Async UDP DNS resolver через pending queue + master epoll.

### Новые файлы

- `core/include/dns/dns_resolver.h` — структуры pending queue (64 слота)
- `core/src/dns/dns_resolver.c` — управление очередью, таймауты

### Изменённые файлы

- `core/include/dns/dns_server.h`:
  - Добавлен `#include "dns/dns_resolver.h"`
  - Поле `dns_pending_queue_t pending` в dns_server_t
  - Поле `int master_epoll_fd` для доступа к epoll из handle_udp_query
  - Новая сигнатура: `dns_server_handle_event(ds, fd, master_epoll_fd)`
  - Новая функция: `dns_server_is_pending_fd(ds, fd)`

- `core/src/dns/dns_server.c`:
  - `dns_pending_init()` в init
  - `handle_udp_query()`: async путь для UDP upstream (BYPASS/DEFAULT/PROXY без DoH)
  - `handle_upstream_response()`: обработка ответа upstream, восстановление client_id, кэш
  - BLOCK и DoH/DoT остались синхронными (мгновенные / пока без async TLS)
  - Удалён `resolve_query()`, заменён на `resolve_query_sync()` (только DoH/DoT)
  - `dns_server_cleanup()`: закрытие всех pending fd

- `core/src/main.c`:
  - Проверка `dns_server_is_pending_fd()` перед tproxy в epoll loop
  - Periodic `dns_pending_check_timeouts()` каждые 100 итераций (~1с)

- `core/Makefile.dev`:
  - Добавлен `dns_resolver.c` в SOURCES

### Архитектура async DNS

```
Client -> recvfrom(udp_fd)
       -> dns_parse_query
       -> cache hit? -> sendto клиенту (мгновенно)
       -> BLOCK? -> NXDOMAIN (мгновенно)
       -> DoH/DoT? -> синхронно (пока)
       -> UDP upstream:
          -> dns_pending_add() -> socket(NONBLOCK) -> sendto upstream
          -> epoll_ctl(ADD upstream_fd)
          -> return (не блокирует!)

[epoll_wait]
Upstream fd ready -> handle_upstream_response()
                  -> recv() ответ
                  -> проверить upstream_id
                  -> восстановить client_id
                  -> кэшировать
                  -> sendto клиенту
                  -> epoll_ctl(DEL) + close fd

Таймаут 2с -> dns_pending_check_timeouts()
           -> epoll_ctl(DEL) + close fd
```

### Параметры

- `DNS_PENDING_MAX = 64` — максимум параллельных запросов
- Таймаут: 2 секунды
- Проверка таймаутов: каждые ~1с (100 epoll iterations * 10ms)

### Сборка

0 ошибок, 0 warnings. Бинарник: 988 KB (было 971 KB, +17 KB).

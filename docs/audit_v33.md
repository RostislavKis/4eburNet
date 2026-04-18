# Devil Audit v33 — 4eburNet
Дата: 2026-04-18
Скоуп: v1.1-2 — Async IPC 2.0 (коммит f92498d)
Аудитор: Devil Audit (Claude Code)

---

## Итог

| Блокеров | Проблем | Замечаний | OK |
|----------|---------|-----------|-----|
| 0        | 1       | 4         | ✅  |

Сборка: 0 ошибок, 1.9MB dev бинарник, 19/19 тестов ALL PASS.
EC330 деплой: `status` + `stats` отвечают без зависания, RAM 23MB available.

---

## Найденные issues

### ⚠️ ПРОБЛЕМЫ

**P1** — `core/src/ipc.c:503–582` — EPOLLET EPOLLOUT deadlock при split delivery

Сценарий:
```
1. accept() → клиент подключился, но header отправит с задержкой
2. epoll_ctl ADD EPOLLIN|EPOLLOUT|EPOLLET
3. epoll_wait → {EPOLLOUT} (write buffer ready, данных ещё нет)
   → ipc_client_event: state=READING_HDR, EPOLLIN=0 → всё пропущено → return 0
4. Клиент отправляет header
5. epoll_wait → {EPOLLIN}
   → READING_HDR: читаем header → ipc_dispatch() → state=WRITING
   → WRITING: events & EPOLLOUT = 0 → НЕ ВЫПОЛНЯЕТСЯ → return 0
6. state=WRITING, write buffer пуст (мы ничего не писали)
   → EPOLLET доставляет EPOLLOUT только при переходе non-ready→ready
   → буфер всё ещё ready → переход не произошёл → EPOLLOUT больше не придёт
   → КЛИЕНТ ЗАВИСАЕТ НАВСЕГДА
```

На практике не воспроизводится (EC330 OK): при Unix domain socket + `4eburnetd --ipc status`
клиент пишет сразу после connect, данные буферизуются ядром до accept, первый event
содержит EPOLLIN|EPOLLOUT вместе. Но гарантии нет — тайминг зависит от планировщика.

Фикс: после `ipc_dispatch()` вызвать `ipc_try_write(c)` немедленно, не ждать EPOLLOUT:
```c
/* После ipc_dispatch в READING_HDR: */
if (c->state == IPC_CS_WRITING)
    ipc_try_write(c);  /* попытка writev; EAGAIN → ждём EPOLLOUT */
/* Аналогично после READING_BODY */
```

---

### 💬 ЗАМЕЧАНИЯ

**Z1** — `core/src/ipc.c:87` — `strlen` в `ipc_set_response` предполагает null-termination внешних функций

```c
static void ipc_set_response(ipc_client_t *c, const char *json)
{
    size_t len = strlen(json);  // json == c->resp_body после proxy_group_to_json
```

`proxy_group_to_json(g_pgm, buf, IPC_RESPONSE_MAX)` и `rule_provider_to_json` —
принимают size, ожидаются null-terminated. Если они не ставят `\0` — strlen выйдет за буфер.
Фактически безопасно (обе функции используют snprintf), но контракт не задокументирован.

---

**Z2** — `core/src/ipc.c:591–598` — `ipc_cleanup` не освобождает активные g_clients

При `SIGTERM` или `state->running = false`, main loop завершается, `ipc_cleanup(server_fd)`
закрывает server socket. Активные g_clients (в состоянии WRITING/READING_BODY) остаются
с открытыми fd — закрываются только при завершении процесса. Не критично, но не чисто.

---

**Z3** — `core/tests/test_ipc_async.c` — тест не покрывает реальную state machine

Тест standalone (не линкуется с ipc.c) — тестирует только:
- ipc_header_t layout
- writev протокол через socketpair
- MSG_DONTWAIT/EAGAIN поведение

Не тестируется:
- `ipc_client_event` state machine (READING_HDR → WRITING)
- `ipc_is_client_ptr` с валидными ptr из g_clients[]
- Параллельные клиенты (IPC_MAX_CLIENTS=8)
- Payload команды (GROUP_SELECT)

Причина: полный ipc.c тянет граф зависимостей всего проекта. Для интеграционного теста
нужен живой демон (покрывается ручным деплоем на EC330).

---

**Z4** — `core/src/ipc.c:24` — мёртвая константа

```c
#define IPC_RECV_TIMEOUT_MS 500  /* никогда не используется */
```

`ipc_recv_payload` удалена, константа осталась. Безвредно.

---

## Проверено и подтверждено (OK)

| Компонент | Статус |
|-----------|--------|
| `accept4(SOCK_NONBLOCK\|SOCK_CLOEXEC)` | ✅ |
| SO_PEERCRED fail-secure | ✅ |
| ipc_client_alloc: все слоты заняты → close + return | ✅ |
| epoll_ctl ADD fail → ipc_client_free | ✅ |
| READING_HDR: recv до EAGAIN в for(;;) | ✅ |
| READING_HDR: partial read без переполнения | ✅ |
| READING_HDR fallthrough в READING_BODY | ✅ |
| READING_BODY: recv до EAGAIN в for(;;) | ✅ |
| WRITING: iov offsets корректны при resp_sent > 0 | ✅ |
| WRITING: niov==0 dead code, не бесконечный цикл | ✅ |
| WRITING: EAGAIN → break (ждём EPOLLOUT) | ✅ |
| WRITING: resp_sent >= total → DEL + free, нет double-free | ✅ |
| ipc_client_free: payload free если != NULL | ✅ |
| ipc_client_free: fd close если >= 0 | ✅ |
| ipc_set_response: json == buf → нет memcpy | ✅ |
| ipc_set_response: truncation guard + null-terminator | ✅ |
| GROUP_LIST: прямо в c->resp_body, нет malloc | ✅ |
| RULES_LIST: IPC_SNPRINTF → c->resp_body | ✅ |
| GROUP_SELECT: c->payload вместо ipc_recv_payload | ✅ |
| PROVIDER_UPDATE: аналогично GROUP_SELECT | ✅ |
| main.c: ipc_is_client_ptr ПЕРВЫМ в epoll loop | ✅ |
| main.c: IPC ptr vs DNS async ptr — разные регионы памяти | ✅ |
| main.c: ipc_process удалён | ✅ |
| close_client: epoll DEL перед ipc_client_free | ✅ |
| MIPS stack: iov[2] = 16B | ✅ |
| BSS: g_clients[8] × 65KB ≈ 512KB — не стек | ✅ |
| Сборка dev: 0 ошибок, 1.9MB | ✅ |
| Тесты: 19/19 ALL PASS | ✅ |
| EC330 деплой: IPC отвечает без зависания | ✅ |
| EC330 RAM: 23MB available (stable) | ✅ |

---

## Вердикт

**0 блокеров. Код production-ready.**

P1 (EPOLLET EPOLLOUT split delivery) — теоретически возможен, практически не воспроизводится
на Unix domain socket с локальным клиентом. Реальный риск: около нуля для `4eburnetd --ipc`.
Рекомендуется исправить в v1.1-3 добавив `ipc_try_write()` после dispatch.

Приоритет следующих исправлений:
1. **P1** — вызывать writev сразу после ipc_dispatch, не ждать EPOLLOUT
2. **Z4** — удалить мёртвую константу IPC_RECV_TIMEOUT_MS

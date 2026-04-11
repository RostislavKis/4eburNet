# Devil Audit v20 — async CDN update + dpi.js polish

**Дата:** 2026-04-11
**Статус:** аудит после коммита `2c7b084` (fix: audit_v19 — 1🔴 3🟡)
**Файлы:** `cdn_updater.c` (+47), `main.c` (+44), `4eburnet.h` (+1), `cdn_updater.h` (+11), `dpi.js` (+39/-5), `4eburnet.uc` (+11/-2)

---

## Scope

- `cdn_updater_update_async()` — fork+pipe async CDN update
- `cdn_do_update()` — рефакторинг с `reload_filter` флагом
- `main.c` — `cdn_pipe_fd` в epoll event loop
- `dpi.js` — `numVal()`, `setTimeout` + `callDpiGet`, `mkStatRow` с id
- `4eburnet.uc` — `dpi_dir` валидация

---

## Находки

### 1. 🟡 `waitpid(-1, NULL, WNOHANG)` бесполезен — SA_NOCLDWAIT активен

**Файл:** `main.c:606`

```c
while (waitpid(-1, NULL, WNOHANG) > 0) {}
```

`main.c:500-505` устанавливает `SIGCHLD` с `SA_NOCLDWAIT`:

```c
sa_chld.sa_handler = SIG_DFL;
sa_chld.sa_flags   = SA_NOCLDWAIT;
sigaction(SIGCHLD, &sa_chld, NULL);
```

С `SA_NOCLDWAIT` ядро автоматически reap'ит zombie. `waitpid(-1, WNOHANG)` вернёт -1/`ECHILD` всегда. Вызов безвреден (цикл сразу завершится), но мёртвый код.

**Влияние:** нулевое. Один лишний syscall.
**Действие:** убрать `while (waitpid...)` строку — `SA_NOCLDWAIT` обрабатывает zombie.

---

### 2. 🟡 `cdn_pipe_fd` не закрывается при shutdown

**Файл:** `main.c:792-821` (cleanup секция)

При `state.running = false` → выход из while loop → cleanup. Если `cdn_pipe_fd >= 0` — fd утечёт. Child уже завершился (SA_NOCLDWAIT), но pipe read-end не закрыт.

На практике: `close(master_epoll)` (строка 793) не закрывает зарегистрированные fd. Процесс завершается → ядро закроет все fd. Утечка только в период между exit из while и _exit процесса — несколько миллисекунд.

**Влияние:** минимальное. fd leak при shutdown, ядро всё равно подберёт.
**Действие:** добавить `if (state.cdn_pipe_fd >= 0) close(state.cdn_pipe_fd);` перед cleanup.

---

### 3. 🟡 `EPOLLHUP` без `EPOLLIN` — не обработан

**Файл:** `main.c:780-781, 597`

epoll регистрация: `EPOLLIN | EPOLLHUP`. Обработка (строка 597): `if (state.cdn_pipe_fd >= 0 && fd == state.cdn_pipe_fd)`.

Если child упадёт (_exit без write в pipe или SIGKILL) → `EPOLLHUP` придёт. Обработчик вызовется, `read()` вернёт 0 → `rn` = 0 → `rbuf[0]` != 'O' → ветка "ошибка". fd закрывается, state обнуляется. **Корректно обработан.**

Но: если `EPOLLHUP` придёт одновременно с `EPOLLIN` (child написал "OK\n" + закрыл pipe) → `events[i].events` содержит `EPOLLIN | EPOLLHUP`. `read()` прочитает данные. **Тоже корректно.**

**Влияние:** нулевое. Оба случая обработаны.
**Действие:** нет. Переквалификация: 🟢.

---

### 4. 🟢 cfg copy-on-write в child после fork

`cdn_updater_update_async`: child вызывает `cdn_do_update(cfg, false)`. `cfg` — const pointer из родителя. После `fork()` child имеет COW копию адресного пространства. `cfg` только читается → страницы не копируются, memory overhead минимален (~4KB для page tables).

**Вердикт:** корректно.

---

### 5. 🟢 pipe write "OK\n" — атомарен для < PIPE_BUF

`write(fds[1], msg, strlen(msg))` — msg = "OK\n" (3 байта) или "ERR\n" (4 байта). POSIX гарантирует атомарную запись для `n <= PIPE_BUF` (минимум 512 байт). 4 < 512 → partial write невозможен.

**Вердикт:** корректно.

---

### 6. 🟢 Двойной клик "Обновить CDN" — защищён

`main.c:774`: `if (state.cdn_update_requested && state.cdn_pipe_fd < 0)`. Если предыдущее обновление не завершилось (`cdn_pipe_fd >= 0`) — новый запрос откладывается. `cdn_update_requested` остаётся `true`, сработает на следующем тике после завершения child.

Но: `state.cdn_update_requested = false` выполняется ДО проверки `cdn_pipe_fd`. Перечитаю код... Нет, проверка: `if (cdn_update_requested && cdn_pipe_fd < 0)` — оба условия в одном if. Если `cdn_pipe_fd >= 0`, весь if пропускается, `cdn_update_requested` остаётся `true`.

**Вердикт:** корректно.

---

### 7. 🟢 epoll_ctl ADD сразу после fork — нет race

`main.c:780-784`: `epoll_ctl(ADD, cfd, pev)` вызывается сразу после `cdn_updater_update_async()` вернул `cfd`. Child может уже завершиться к этому моменту и записать "OK\n" в pipe. Но pipe имеет буфер (минимум 4KB) → данные ждут. `EPOLLIN` событие будет сгенерировано на следующем `epoll_wait`. Нет потери данных.

**Вердикт:** корректно.

---

### 8. 🟢 `numVal()` — корректная обработка NaN

```javascript
function numVal(id, def) {
    var v = parseInt(sel(id).value, 10);
    return isNaN(v) ? def : '' + v;
}
```

`parseInt("", 10)` → `NaN` → возвращает default. `parseInt("abc", 10)` → `NaN` → default. `parseInt("5", 10)` → `5` → `"5"`. Покрывает все edge cases.

**Вердикт:** корректно.

---

### 9. 🟢 `setTimeout` + `callDpiGet` — null guards

```javascript
if (ipset) ipset.textContent = ...;
if (wl)    wl.textContent    = ...;
```

Если пользователь ушёл со страницы до 5 секунд: `sel('stat-ipset')` вернёт null → guard пропустит. `callDpiGet` — RPC вызов, ошибка при закрытой странице просто проглатывается промисом.

**Вердикт:** корректно.

---

### 10. 🟢 `dpi_dir` валидация — покрывает все случаи

```javascript
if (length(val) < 2 || val[0] !== '/' || index(val, '..') >= 0)
    continue;
```

- `""` → length 0 < 2 → отклонён
- `"/"` → length 1 < 2 → отклонён
- `"relative/path"` → val[0] != '/' → отклонён
- `"/etc/../passwd"` → index(..) >= 0 → отклонён
- `"/etc/4eburnet/dpi"` → пройдёт ✓

**Вердикт:** корректно.

---

## Компиляция и тесты

```
$ make -f Makefile.dev 2>&1 | grep -E 'error:|warning:'
(пусто — 0 ошибок, 0 предупреждений)

$ make -f Makefile.dev test
ALL PASS: 0 тест(ов) провалено

$ ls -lh build/4eburnetd
-rwxr-xr-x 1.6M 4eburnetd
```

---

## Итог

| Уровень | Количество | Детали |
|---------|-----------|--------|
| 🔴 RED | 0 | — |
| 🟡 YELLOW | 2 | waitpid мёртвый код (SA_NOCLDWAIT), cdn_pipe_fd не закрыт при shutdown |
| 🟢 GREEN | 8 | COW fork, pipe атомарность, двойной клик, epoll race, numVal, setTimeout, dpi_dir, EPOLLHUP |

**Вердикт: async CDN update чистый.** Два 🟡 — мёртвый код и fd leak при shutdown (ядро подберёт). Ноль критических проблем.

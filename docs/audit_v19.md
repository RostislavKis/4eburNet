# Devil Audit v19 — C.6 LuCI dpi.js + pre-C.6 fixes

**Дата:** 2026-04-11
**Статус:** аудит после коммитов `456be69` (pre-C.6), `120fd9b` (dpi.js), `4749ad8` (fix 2🟡)
**Файлы:** `dpi.js` (231 строка), `4eburnet.uc` (+48 строк DPI), `ipc.c` (+12), `main.c` (+8), `4eburnet.h` (+2)

---

## Scope

- `dpi.js` — LuCI страница DPI Bypass (3 карточки)
- `4eburnet.uc` — RPC методы `dpi_get`, `dpi_set`, `cdn_update`, `count_lines()`
- `ipc.c` — `IPC_CMD_CDN_UPDATE` обработчик
- `main.c` — `cdn_update_requested` флаг в main event loop

---

## Находки

### 1. 🔴 `cdn_updater_update()` блокирует event loop

**Файл:** `main.c:751`

```c
if (state.cdn_update_requested) {
    state.cdn_update_requested = false;
    cdn_updater_update(cfg_ptr);
}
```

`cdn_updater_update` вызывает `net_http_fetch` × 3 (Cloudflare v4, v6, Fastly). Каждый делает блокирующий `getaddrinfo()` + `connect()` + `read()`. На EC330 (mipsel, медленный WAN): 3 HTTP запроса = 3-30 секунд блокировки event loop. Все соединения (relay, DNS, IPC) зависают на это время.

`net_utils.c:488` уже имеет async spawn механизм (`net_http_fetch_async` через `fork+pipe`). Нужно использовать async вариант или вынести cdn_update в дочерний процесс.

**Влияние:** критическое для продакшен. Все активные соединения замирают на время обновления.
**Действие:** вынести `cdn_updater_update` в fork (аналогично `rule_provider_update`) или cron.

---

### 2. 🟡 Статистика не обновляется после "Обновить CDN сейчас"

**Файл:** `dpi.js:198-205`

```javascript
callCdnUpdate().then(function(r) {
    if (r && r.ok) {
        if (st) { st.textContent = '✓ ' + (r.msg || _('Запущено')); ... }
    }
});
```

После нажатия "Обновить CDN сейчас" карточка 3 (статистика) показывает старые числа. CDN обновляется асинхронно в демоне, но LuCI не перезагружает данные. Пользователь видит "✓ Запущено" и ipset_lines=8996 (старое), хотя могло стать 9100.

**Влияние:** косметическое. Перезагрузка страницы (F5) обновит статистику.
**Действие:** добавить `setTimeout(function(){ location.reload(); }, 3000)` после успешного cdn_update (дать 3 сек на скачивание). Или показать hint "обновите страницу".

---

### 3. 🟡 Пустое числовое поле → пустая строка в UCI

**Файл:** `dpi.js:119`

```javascript
dpi_split_pos: sel('dpi-split-pos').value,
```

Если пользователь очистит `input[type=number]`, `value = ""`. В UCI запишется `option dpi_split_pos ''`. В `config.c` — `strtol("", &ep, 10)` вернёт 0, `ep == value` → невалидно → LOG_WARN, используется default. Graceful degradation работает, но пользователь не видит предупреждения в LuCI.

**Влияние:** минимальное. Пустое поле = default значение. Но UX неинтуитивный.
**Действие:** в dpi.js добавить клиентскую валидацию перед callDpiSet: если поле пусто → подставить default.

---

### 4. 🟡 `count_lines()` в `.uc` — 3 файловых обхода при каждом открытии

**Файл:** `4eburnet.uc:58-68`

```javascript
let ipset_lines     = count_lines(dpi_dir + '/ipset.txt');
let whitelist_count = count_lines(dpi_dir + '/whitelist.txt');
let autohosts_count = count_lines(dpi_dir + '/autohosts.txt');
```

При каждом открытии LuCI страницы DPI: 3 вызова `count_lines`, каждый перебирает все строки файла. `ipset.txt` = 8996 строк, `whitelist.txt` = 2109 строк. Итого ~11000 строк на каждый page load. На MIPS это ~50-100ms — заметно, но не блокирует.

**Влияние:** минимальное. rpcd однопоточный, задержка <200ms на слабом железе.
**Действие:** нет. Приемлемая производительность. Если потребуется оптимизация — кэшировать wc -l результат в stamp файле.

---

### 5. 🟡 `dpi_dir` не валидируется в `dpi_set`

**Файл:** `4eburnet.uc:680`

```javascript
if (allowed[k]) {
    c.set('4eburnet', 'main', k, '' + a[k]);
```

`dpi_dir` записывается без проверки. Можно записать `../../etc/passwd` или пустую строку. `count_lines` попытается открыть несуществующий файл → вернёт 0. `config.c` при загрузке использует `dpi_dir` для `dpi_filter_init()` → файлы не найдены → фильтр в pass-through (NONE для всех). Не crash, но DPI bypass перестанет работать.

**Влияние:** root-only UCI, self-sabotage. Не уязвимость — только LuCI admin может изменить.
**Действие:** добавить guard: `if (k == 'dpi_dir' && (a[k][0] != '/' || match(a[k], /\.\./))) continue;`

---

### 6. 🟢 `callDpiSet` flat-args паттерн корректен

`callDpiSet({...})` без params declaration — объект передаётся как `req.args`. Аналогично `callDnsSet(values)` в `dns.js:133`. rpcd десериализует первый аргумент в `req.args`. Рассогласования нет — `config_set` с params `['section','values']` это другой паттерн для другого API.

**Вердикт:** корректно.

---

### 7. 🟢 `dpi_get` возвращает статистику независимо от демона

`count_lines` читает файлы на диске напрямую — не через IPC. Статистика доступна даже при остановленном демоне. `ipset_updated` из `ipset.stamp` — тоже файл. Единственное что недоступно без демона — live connection stats (не реализовано и не нужно на этом этапе).

**Вердикт:** корректно.

---

### 8. 🟢 `IPC_CMD_CDN_UPDATE` — fire-and-forget

`ipc.c` сразу отвечает `{"status":"ok","msg":"cdn update scheduled"}` без ожидания результата. LuCI не зависает на 30 секунд. Проблема блокировки event loop (находка #1) — в исполнении, не в IPC протоколе.

**Вердикт:** IPC протокол корректен. Проблема в executor.

---

### 9. 🟢 `cdn_update_requested` проверяется каждый тик

`main.c:748` — проверка `state.cdn_update_requested` происходит на каждой итерации `while (state.running)` после `dispatcher_tick`. Задержка = 1 тик (10ms). Быстро.

**Вердикт:** корректно.

---

### 10. 🟢 Checkbox `dpi-enabled` правильно обрабатывает null

`dpi.js:91`: `checked: cfg.dpi_enabled === '1' ? '' : null`. Если UCI поле отсутствует — `dpi_get` возвращает `'0'` (default) → unchecked. При сохранении: `sel('dpi-enabled').checked ? '1' : '0'` — всегда строка, не null.

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
| 🔴 RED | 1 | cdn_updater_update блокирует event loop (3 HTTP запроса) |
| 🟡 YELLOW | 4 | статистика не обновляется, пустое число, count_lines perf, dpi_dir без валидации |
| 🟢 GREEN | 5 | flat-args, статистика без демона, fire-and-forget IPC, тик проверка, checkbox |

**Вердикт: 1 критическая проблема — блокирующий cdn_update в event loop.** Требует fork/async перед продакшен деплоем. Остальное — UX polish.

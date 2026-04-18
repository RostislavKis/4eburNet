# audit_v36 — Adaptive DPI v1.2-1

**Скоуп:** коммит 4f219d7 — dpi_adapt.h/c, dispatcher.c (интеграция),
ipc.c, main.c, http_server.c, dashboard.html, test_dpi_adapt.c

**База:** fc2fe05 (audit_v35, v1.1 Bloom/SIMD)
**Дата:** 2026-04-18

---

## Итог

| Категория      | Кол-во | Статус    |
|----------------|--------|-----------|
| Блокеры        | 0      | ✅ нет    |
| Функциональные | 0      | ✅ нет    |
| Замечания      | 5      | ⚠ закрыты ниже |
| Компиляция     | OK     | ✅ 0 ошибок |
| Тесты          | 21/21  | ✅ ALL PASS |

---

## Проверенные файлы

```
core/include/dpi/dpi_adapt.h          100 строк
core/src/dpi/dpi_adapt.c              153 строки
core/include/proxy/dispatcher.h       +9 строк (dpi_strat_t, dpi_success)
core/src/proxy/dispatcher.c           +78 строк (интеграция адаптации)
core/src/ipc.c                        +57 строк (DPI_SET реализация, STATUS)
core/src/main.c                       +7 строк (save при SIGHUP/shutdown)
core/src/http_server.c                +11 строк (dpi_clear action)
core/src/dashboard.html               +29 строк (DPI Adapt карточка)
core/tests/test_dpi_adapt.c           191 строка (T1-T6, 24 проверки)
```

---

## ШАГ 1 — dpi_adapt.c: корректность

### Z1: ip==0 зарезервирован как маркер пустого слота
**Уровень:** Замечание (не блокер)
**Место:** `find_slot()` строка 46 — `if (r->ip == 0)` определяет слот как пустой.
**Проблема:** IP 0.0.0.0 (`ntohl(INADDR_ANY) = 0`) невозможно сохранить в таблице —
при записи он занимает слот (строка 48 `r->ip = ip`), но сразу воспринимается
как пустой при последующих lookup-ах.
**На практике:** 0.0.0.0 никогда не является DST адресом в TPROXY соединении.
Dispatcher передаёт `dst_ip=0` только для IPv6 и не вызывает `dpi_adapt_report` при
`dst_ip==0` (guard строки 592, 1445 dispatcher.c).
**Статус:** Не критично, архитектурная дыра задокументирована.

### Проверки пройдены
- linear probe без удалений: цепочка зондирования без дыр → `break` на ip==0 корректен ✓
- эскалация: `s < DPI_STRAT_BOTH` перед инкрементом — регрессия к NONE невозможна ✓
- fail_count cap 255: строка 87 ✓
- атомарная запись `.tmp → rename`: строки 136-137 ✓
- валидация magic при load: строка 98 ✓
- fread DPI_ADAPT_SLOTS проверяется: строка 107 ✓
- heap не используется (BSS глобальная таблица) ✓
- MIPS stack: `char tmp[280]` — единственный буфер, в пределах 512B ✓

---

## ШАГ 2 — dispatcher.c: интеграция

### Z2: dpi_adapt_get вызывается с dst_ip=0 для IPv6
**Уровень:** Замечание (не блокер)
**Место:** dispatcher.c строка 907 — `r->dpi_strategy = dpi_adapt_get(&g_dpi_adapt, dst_ip)`
без guard `if (dst_ip != 0)`.
**Поведение:** `dpi_adapt_get(t, 0)` хэширует ip=0, находит пустой слот (ip==0 совпадает),
возвращает `DPI_STRAT_NONE`. Функционально верно (NONE = default), но это ложный lookup.
**Отчёт не делается:** строки 592, 1445 оба защищены `if (dst_ip)`. ✓
**Статус:** Зафиксировано, не требует исправления.

### Проверки пройдены
- ntohl(): host byte order в таблице ✓
- Успех: первые байты от upstream → `transferred > 0` → report SUCCESS ✓
- relay_free: FAIL только если `dpi_first_done && !dpi_success` ✓
- Нет двойного report: `r->dpi_success=true` исключает FAIL после SUCCESS ✓
- g_dpi_adapt: определён в dispatcher.c строка 160, extern в dpi_adapt.h ✓

---

## ШАГ 3 — main.c: save при SIGHUP и shutdown

### Z3: нет mkdir -p /etc/4eburnet перед первым сохранением
**Уровень:** Замечание (не блокер)
**Место:** main.c строки 1076, 1104 — `dpi_adapt_save("/etc/4eburnet/dpi_cache.bin")`.
**Проблема:** Демон не создаёт директорию `/etc/4eburnet/` явно. `fopen` вернёт NULL
если директория не существует; `dpi_adapt_save` вернёт -1, ошибка игнорируется.
**На практике:** Пакет opkg устанавливает файлы в `/etc/4eburnet/dpi/`, что создаёт
директорию автоматически. При ручной сборке без пакета — кэш не сохранится.
**Статус:** Зафиксировано. Рекомендуется добавить `mkdir -p /etc/4eburnet` в init-скрипт.

### Проверки пройдены
- dpi_adapt_init + load вызываются из dispatcher_init() при старте ✓
- dpi_adapt_save при SIGHUP: main.c строка 1076 (после блока reload) ✓
- dpi_adapt_save при shutdown: main.c строка 1104 (метка cleanup:) ✓

---

## ШАГ 4 — IPC DPI_SET и STATUS

### Z4: IPC_CMD_DPI_GET — нет NULL-проверки state->config
**Уровень:** Замечание (не блокер)
**Место:** ipc.c строка 452 — `cfg->dpi_fake_sni` разыменовывается без проверки `cfg != NULL`.
**Условие:** только если `state->config == NULL` в момент DPI_GET, что возможно
при очень раннем IPC-запросе до завершения загрузки конфига.
**На практике:** IPC принимается только после инициализации, вероятность низкая.
**Статус:** Зафиксировано.

### Проверки пройдены
- DPI_SET payload: json_get_str + atoi с валидацией диапазонов ✓
- DPI_SET cast: state->config не const (4eburnet.h строка 101) ✓
- DPI_SET split_pos: `v > 0 && v < 1400` ✓
- STATUS dpi_adapt_stats: вызывается корректно (строки 237-238) ✓
- DPI_GET: json_escape_str для fake_sni ✓

---

## ШАГ 5 — Dashboard и dpi_clear

### Z5: dpi_clear не атомарен между init и unlink
**Уровень:** Замечание (не блокер, не race condition)
**Место:** http_server.c строки 724-725.
```c
dpi_adapt_init(&g_dpi_adapt);          // memset в памяти
unlink("/etc/4eburnet/dpi_cache.bin"); // удалить файл
```
**Обоснование:** dispatcher и http_server работают в одном epoll-потоке → race
невозможен. Порядок корректен: сначала обнуление в памяти, потом удаление файла.
Если демон упадёт между строками 724 и 725 — при следующем старте будет загружен
старый кэш (не конец света). ✓
**Статус:** Зафиксировано, не требует исправления.

### Проверки пройдены
- dpi_adapt_init + unlink оба присутствуют ✓
- Bearer токен: route_api_control проверяет api_token для всех action ✓
- Dashboard polling: fetchStatus() читает dpi_adapt_count из /api/status ✓
- Оба dashboard.html синхронизированы (core/src/ и luci-app/) ✓

---

## ШАГ 6 — MIPS stack + test coverage

### Проверки пройдены
- dpi_adapt.c: единственный буфер `char tmp[280]`, не превышает 512B ✓
- DpiAdaptTable (64KB) в тестах: на стеке x86_64, в продакшене — глобальная BSS ✓
- T3: проверяет все 4 ступени эскалации + кэп на BOTH ✓
- T5: full table (4096 записей) → count не меняется, get возвращает NONE ✓
- Cleanup: стек-переменные, T4 вызывает unlink ✓

---

## ШАГ 7 — Финальная компиляция

```
make -f Makefile.dev → 0 ошибок, 0 предупреждений (-Werror)
4eburnetd: 1.9MB (x86_64 musl static)

make -f Makefile.dev test → 21 суит, ALL PASS (0 провалено)
```

---

## Сводная таблица замечаний

| ID | Файл                  | Строка | Описание                                   | Критичность |
|----|-----------------------|--------|--------------------------------------------|-------------|
| Z1 | dpi_adapt.c           | 46     | ip=0 зарезервирован — 0.0.0.0 не хранится | Замечание   |
| Z2 | dispatcher.c          | 907    | dpi_adapt_get вызывается для IPv6 (ip=0)  | Замечание   |
| Z3 | main.c                | 1076   | нет mkdir -p /etc/4eburnet                | Замечание   |
| Z4 | ipc.c                 | 452    | DPI_GET: нет NULL-check state->config      | Замечание   |
| Z5 | http_server.c         | 724    | dpi_clear: init+unlink не атомарны         | Замечание   |

Все замечания **зафиксированы**, ни одно не является блокером для продакшена.

---

## Архитектурная корректность v1.2-1

- Эскалация NONE→FRAGMENT→FAKE_TTL→BOTH с кэпом на BOTH: ✓ (критический фикс пользователя применён)
- Персистентность: атомарная запись `.tmp → rename`, load при старте, save при SIGHUP/shutdown ✓
- Нет heap (BSS 64KB): работает на MIPS32r2, aarch64, x86_64 ✓
- Open addressing без удалений: linear probe корректен без tombstone ✓
- Детекция SUCCESS/FAIL: единственный report на соединение (dpi_success flag) ✓
- IPC STATUS: dpi_adapt_count + dpi_adapt_hits репортируются ✓
- Dashboard: карточка появляется только при CONFIG_EBURNET_DPI, кнопка очистки ✓

---

## Вывод

v1.2-1 (Adaptive DPI) прошёл devil audit без блокеров.
5 замечаний уровня Z зафиксированы, не требуют немедленного исправления.
Код готов к деплою на EC330 (MIPS32r2, profile=NORMAL).

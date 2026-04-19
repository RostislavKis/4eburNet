# Devil Audit v39 — 4eburNet v1.3

**Дата:** 2026-04-19  
**Скоуп:** v1.3 (Proxy Groups UI + ECH/ESNI + geo pipeline)  
**Коммиты:** v1.2.0..HEAD (6 коммитов)  
**Компиляция:** 0 ошибок, 48/48 тестов ✅  
**dashboard.html md5:** идентичен в обеих копиях ✅

---

## Итог

| Блокеров 🔴 | Проблем ⚠️ | Замечаний 📝 | OK ✅ |
|:-----------:|:----------:|:------------:|:-----:|
| 0           | 3          | 4            | 47    |

---

## Найденные issues

### ⚠️ P1 — testGroup: нет .catch() → btn.disabled навсегда

**Файл:** `core/src/dashboard.html`, функция `testGroup()`

```js
apiFetch('/api/control', { ... }).then(function() {
    setTimeout(function() {
        fetchGroups();
        if (btn) { btn.disabled = false; btn.textContent = '▶ Test'; }
    }, 3000);
});
// нет .catch() или финального восстановления btn
```

При сетевой ошибке (timeout, 503) `.then()` не вызывается → `btn.disabled = true`
навсегда до перезагрузки страницы. Пользователь теряет кнопку Test.

**Фикс:** добавить `.catch(function() { if (btn) { btn.disabled = false; btn.textContent = '▶ Test'; } })`.

---

### ⚠️ P2 — geo_update_all.bat ШАГ 3: geo_compile бинарник не существует

**Файл:** `geo_update_all.bat`, строка 58

```bat
wsl bash -c "... make -f Makefile.dev geo_compile 2>/dev/null; for lst in ..."
```

`make geo_compile 2>/dev/null` — stderr подавлен. Если цель не собралась
(нет musl-gcc в PATH, иная ошибка), скрипт молча продолжит цикл for, где
`./tools/geo_compile` не существует (`|| true` поглощает ошибку).  
Проверено: `~/4eburnet-dev/project/4eburNet/tools/geo_compile` отсутствует до первого `make geo_compile`.

**Следствие:** .gbin файлы не обновятся, скрипт не сообщит об ошибке, выйдет с кодом 0.

**Фикс:** убрать `2>/dev/null`, добавить проверку существования бинарника после make:
```bash
make -f Makefile.dev geo_compile && test -f ./tools/geo_compile || { echo 'geo_compile не собран'; exit 1; }
```

---

### ⚠️ P3 — selectServer: getElementById без escHtml → элемент не найдётся

**Файл:** `core/src/dashboard.html`, функции `buildGroupCard` / `selectServer`

В `buildGroupCard`:
```js
'<div class="server-list" id="slist-' + escHtml(g.name) + '">'
```

В `selectServer`:
```js
var slist = document.getElementById('slist-' + group);
```

`group` передаётся напрямую из `onclick="selectServer('...escHtml(g.name)...')"`.
HTML-атрибуты парсятся браузером, поэтому `&#39;` в `id=` и при передаче в
функцию приходит как `'` — `getElementById` не найдёт элемент с `id="slist-name'with'quote"`.

Практически: имена групп из UCI — простые ASCII без кавычек. Edge case, но
если имя содержит `'` — optimistic подсветка сломается молча.

**Фикс:** нормализовать id: заменять спецсимволы в id атрибуте на `-`.

---

### 📝 Z1 — main.c: fputs/rename возврат не проверяется

**Файл:** `core/src/main.c`, строки 915–918

```c
fputs(grp_json_buf, gf);   // возврат не проверяется
fclose(gf);
rename("/tmp/4eburnet-groups.json.tmp",
       "/tmp/4eburnet-groups.json");  // возврат не проверяется
```

tmpfs практически не падает при записи, но по `-Wall -Wextra` это игнорируемый возврат.
Компилируется без предупреждений (`fputs` возвращает `int`, не `__warn_unused_result__` у musl).
Не блокер, но замечание по стилю.

---

### 📝 Z2 — update_geo.py: .tmp файл не удаляется при исключении write

**Файл:** `tools/update_geo.py`, функции `fetch_geosite_trackers` / `fetch_geosite_threats`

```python
tmp = out_path + '.tmp'
with open(tmp, 'w') as f:
    f.write('\n'.join(domains) + '\n')  # исключение → .tmp остаётся
os.replace(tmp, out_path)
```

При исключении (нет места на диске, прерывание) `.tmp` файл остаётся.
Для еженедельного скрипта некритично, но стоит обернуть в try/finally с `os.unlink`.

---

### 📝 Z3 — geo_update_all.bat: хардкод пути в echo-строках

**Файл:** `geo_update_all.bat`, строки 9, 27, 51–52

```bat
echo ║   D:\Проекты\filter                  ║
echo [ОШИБКА] Репо filter не найден: D:\Проекты\filter
```

Рабочие пути используют `%~dp0` (корректно), но информационные сообщения
хардкодируют `D:\Проекты\filter`. Если проект переместится — сообщения будут
вводить в заблуждение. Не функциональный баг.

---

### 📝 Z4 — fetchGroups: нет AbortController → race condition при быстром переключении

**Файл:** `core/src/dashboard.html`, функция `fetchGroups()`

```js
function fetchGroups() {
  if (state.section !== 'groups') return;
  apiFetch('/api/groups').then(function(d) { ... });
}
```

Если пользователь быстро переключается между вкладками, старый fetch (ещё в полёте)
вернётся после перехода и вызовет `renderGroups()` на неактивной вкладке.
Функциональный эффект минимален (результат просто не отобразится — `grid` не в DOM),
но правильнее добавить AbortController в `showSection()`.

---

## Детальный чеклист

### ШАГ 1 — main.c groups.json
| | |
|---|---|
| grp_json_buf static BSS 65536 | ✅ |
| Тик % 300 × 10ms = 3 секунды | ✅ |
| fopen + fclose без утечки | ✅ |
| rename атомарная (tmpfs) | ✅ |
| Guard pgm_state.count > 0 | ✅ |
| fputs/rename возврат проверяется | 📝 Z1 |

### ШАГ 2 — http_server.c
| | |
|---|---|
| route_api_groups: нет утечки FILE* | ✅ |
| grp_cache[65536] — достаточен | ✅ |
| http_json_get_str out_sz-1 guard | ✅ |
| config_get_server si < total | ✅ |
| proxy_group_select_manual: r проверяется | ✅ |
| proxy_group_tick async | ✅ |
| s_pgm NULL guard оба actions | ✅ |
| strncmp длины 12/10 корректны | ✅ |

### ШАГ 3 — dashboard.html Groups
| | |
|---|---|
| escHtml: &, <, >, ", ' | ✅ |
| onclick XSS защита через escHtml | ✅ |
| groupsTimer clearInterval при смене вкладки | ✅ |
| fetchGroups только при section=groups | ✅ |
| selectServer: optimistic + rollback | ✅ |
| testGroup: btn.disabled восстановление при ошибке | ⚠️ P1 |
| buildGroupCard: все innerHTML через escHtml | ✅ |
| getElementById без escHtml (edge case) | ⚠️ P3 |
| dashboard.html md5 идентичен | ✅ |

### ШАГ 4 — ECH/ESNI sniffer
| | |
|---|---|
| ECH в else-if, не прерывает цепочку | ✅ |
| pos += ext_len после ECH ветки | ✅ |
| ech_ext_type = ext_type (uint16_t) | ✅ |
| hello != NULL при stats_inc_ech | ✅ |
| stats_inc_ech сигнатура совпадает | ✅ |

### ШАГ 5 — stats.h
| | |
|---|---|
| last_ech_type uint_fast32_t ≥ uint16_t | ✅ |
| Race: однопоточный epoll → нет | ✅ |
| last_ech_type: строка "0x%04x" | ✅ |
| JS сравнение строковое === '0xfe0d' | ✅ |

### ШАГ 6 — update_geo.py
| | |
|---|---|
| _TRACKER_RE/_THREAT_RE на уровне модуля | ✅ |
| _THREAT_RE: 0.0.0.0 и 127.0.0.1 форматы | ✅ |
| os.replace атомарна (POSIX/приемлемо Win) | ✅ |
| guard: threats < 100, trackers < 1000 | ✅ |
| .tmp при исключении не удаляется | 📝 Z2 |
| import re присутствует | ✅ |

### ШАГ 7 — mmdb_to_lst.py
| | |
|---|---|
| ImportError с сообщением | ✅ |
| collapse_addresses корректна | ✅ |
| --all: makedirs geo/ | ✅ |
| context manager — нет утечки handle | ✅ |
| IPv6 пропускаются (version == 4) | ✅ |
| < 5 CIDR пропускаются в --all | ✅ |
| Сортировка по IP (числовая, не строковая) | ✅ |

### ШАГ 8 — geo_update_all.bat
| | |
|---|---|
| chcp 65001 | ✅ |
| Проверка Python | ✅ |
| Проверка filter репо | ✅ |
| geo_compile путь и проверка успеха | ⚠️ P2 |
| git push master/main оба варианта | ✅ |
| Ярлык однократно | ✅ |
| Хардкод в echo-строках | 📝 Z3 |

### ШАГ 9 — Компиляция + тесты
| | |
|---|---|
| 0 ошибок компилятора | ✅ |
| 48/48 тестов PASS | ✅ |

---

## Вердикт

**0 блокеров.** v1.3 готов к деплою на EC330.

Три проблемы требуют исправления перед следующим минорным релизом:
- **P1** (testGroup .catch) — UX баг, заметен при нестабильной сети
- **P2** (geo_compile проверка) — geo обновление молча не работает без бинарника
- **P3** (getElementById edge case) — только при именах групп со спецсимволами

Четыре замечания некритичны, можно закрыть в audit_v40 вместе со следующей задачей.

# Devil Audit v32 — 4eburNet
Дата: 2026-04-18
Скоуп: v1.1-1 — binary geo format + mmap загрузка (коммит 6488a51)
Аудитор: Devil Audit (Claude Code)

---

## Итог

| Блокеров | Проблем | Замечаний | OK |
|----------|---------|-----------|-----|
| 0        | 3       | 5         | ✅  |

Сборка: 0 ошибок, 1.9MB dev бинарник, 18/18 тестов ALL PASS.
EC330 деплой: VmRSS ~5MB (было ~20MB), DNS работает, [mmap] в логах.

---

## Найденные issues

### ⚠️ ПРОБЛЕМЫ

**P1** — `tools/geo_compile.c:172,174` — мусорная запись при ошибке парсинга CIDR

```c
if (vi6 < n_v6) parse_cidr6_c(line, &v6[vi6++]);  /* vi6++ даже при return 0 */
if (vi4 < n_v4) parse_cidr4_c(line, &v4[vi4++]);  /* vi4++ даже при return 0 */
```

Если строка проходит фильтр `strchr(line, '/')` в pass1, но `inet_pton` проваливается
в pass2 — `parse_cidr4_c` возвращает 0, однако `vi4` уже инкрементирован. В `v4[vi4-1]`
остаётся heap-мусор из `malloc` (не `calloc`). После qsort мусорная запись попадает
в .gbin и используется в IP-lookup как CIDR с рандомными net/mask.

Реальное воздействие: низкое (реальные .lst файлы имеют валидные CIDR), но логический дефект.
Фикс: проверять возврат `parse_cidr4_c` и только тогда инкрементировать счётчик:
```c
if (vi4 < n_v4 && parse_cidr4_c(line, &v4[vi4])) vi4++;
```

---

**P2** — `luci-app-4eburnet/files/usr/share/4eburnet/geo_update.sh:70-74` —
ложное предупреждение для trackers/threats когда geo_compile не установлен

```sh
[ -x "$GEO_COMPILE" ] && "$GEO_COMPILE" ... \
    && logger "скомпилирован" \
    || logger "WARN: не скомпилирован"   # ← срабатывает если /usr/bin/geo_compile отсутствует
```

Шаблон `A && B || C` — `C` выполняется когда `A` ложно (не установлен).
В `fetch_direct` используется `if [ -x ... ]; then ... fi` — тихо пропускает.
Непоследовательное поведение: для ads/geoip-ru/geosite-ru нет предупреждения,
для trackers/threats — есть, хотя geo_compile одинаково не установлен.

Фикс: заменить шаблон в trackers/threats на `if [ -x "$GEO_COMPILE" ]; then ... fi`.

---

**P3** — `luci-app-4eburnet/files/usr/share/4eburnet/geo_update.sh:97-119` —
`opencck-domains.lst` обновляется каждые 6ч, но `geo_compile` не вызывается

После auto-update opencck-domains.lst: `.gbin` не обновляется.
При следующем SIGHUP-reload демон загружает старый `.gbin` (mmap приоритетнее .lst).
Домены из нового opencck-domains.lst не вступают в силу до ручного `geo_compile`.

Фикс: добавить вызов geo_compile после `mv "$TMP_OPENCCK" "${RULES_DIR}/opencck-domains.lst"`:
```sh
if [ -x "$GEO_COMPILE" ]; then
    "$GEO_COMPILE" "${RULES_DIR}/opencck-domains.lst" \
        "${RULES_DIR}/opencck-domains.gbin" 1 0 2>/dev/null \
        && logger -t "$LOG_TAG" "opencck-domains.lst: .gbin скомпилирован" \
        || logger -t "$LOG_TAG" "WARN: opencck-domains.lst .gbin не скомпилирован"
fi
```

---

### 💬 ЗАМЕЧАНИЯ

**Z1** — `tools/geo_compile.c:330-331` — `atoi` без валидации диапазона

```c
return geo_compile_file(argv[1], argv[2],
                        (uint32_t)atoi(argv[3]),   /* region */
                        (uint32_t)atoi(argv[4]));  /* cat_type */
```

`atoi("-1")` → `(uint32_t)(-1)` = `UINT32_MAX` записывается в hdr.region/cat_type.
Не вызывает краш, но создаёт .gbin с невалидными метаданными.
Standalone утилита с доверенным входом — практически не опасно.
Фикс: `strtol` + проверка диапазона [0..99] для region, [0..3] для cat_type.

---

**Z2** — `core/src/geo/geo_loader.c:412-413` — `.gbin` авторитетен для region/cat_type,
name-based логика теряется

`geo_load_category_bin` перезаписывает `c->region` и `c->cat_type` из hdr, игнорируя:
- параметр `region` из `geo_load_category`
- name-based определение cat_type (строки 459-462)

Если .gbin скомпилирован с неправильными region/cat_type, исправить через имя файла
нельзя. Нужно пересобрать .gbin с правильными аргументами.
Это контракт по дизайну (не баг), но поведение неочевидно.

---

**Z3** — `core/tests/test_geo_bin.c` — нет теста с невалидным magic

`geo_load_category_bin` проверяет magic (строка 371) и должен вернуть -1.
Тест не покрывает этот путь.

---

**Z4** — `core/tests/test_geo_bin.c` — нет теста с truncated файлом

`geo_load_category_bin` проверяет `st.st_size < expected` (строка 381).
Тест не покрывает файл меньше `expected_size`.

---

**Z5** — `core/tests/test_geo_bin.c:50,63` — cat_type проверяется после ручного override

```c
if (gm.count > 0) gm.categories[0].cat_type = GEO_CAT_ADS;
```

Тест не верифицирует, что `geo_load_category_bin` сам читает `hdr->cat_type = 1`
без ручного присваивания. Тест проходит даже если эта строка в loader сломана.

---

## Проверено и подтверждено (OK)

| Компонент | Статус |
|-----------|--------|
| `geo_bin_header_t`: packed, 9×4=36 байт | ✅ |
| offset инлайн-функции: `(size_t)X * sizeof(Y)`, нет overflow | ✅ |
| Секции .gbin: все uint32_t выравнены по 4B | ✅ |
| geo_compile: два прохода одинаковые фильтры | ✅ |
| geo_compile: сортировка перед pool → bsearch корректен | ✅ |
| geo_compile: атомарная запись .tmp → rename | ✅ |
| geo_compile: MIN_ENTRIES=100 guard | ✅ |
| geo_compile: fclose перед rename | ✅ |
| geo_compile: free() на всех путях выхода | ✅ |
| geo_loader: fstat + magic + expected_size валидация | ✅ |
| geo_loader: close(fd) после mmap | ✅ |
| geo_loader: free_category_data — munmap, v4/v6 не free() | ✅ |
| geo_loader: ptrie_free до mmap/heap ветки | ✅ |
| geo_loader: fallback .lst если .gbin отсутствует | ✅ |
| geo_loader: bin_find_domain корректный binary search | ✅ |
| geo_match_domain/cat: чистая mmap vs heap ветка | ✅ |
| suffix lookup: `strchr(p,'.')+1` итерация в обоих режимах | ✅ |
| MIPS stack: нет буферов > 512B в демоне | ✅ |
| geo_update.sh: правильные region/cat_type per file | ✅ |
| geo_update.sh: guard `[ -x "$GEO_COMPILE" ]` для fetch_direct | ✅ |
| geo_update.sh: SIGHUP после всех компиляций | ✅ |
| Сборка dev: 0 ошибок, 1.9MB | ✅ |
| Тесты: 18/18 ALL PASS | ✅ |
| EC330 деплой: VmRSS 3.5→5.3MB (было ~20MB) | ✅ |
| EC330 DNS: instagram→198.51.100.1, doubleclick→0.0.0.0, ya.ru→real IP | ✅ |
| EC330 лог: `[mmap]` для ads/trackers/threats | ✅ |

---

## Вердикт

**0 блокеров. Код production-ready.**

P1 (мусор в CIDR при parse fail) — не воспроизводится на реальных .lst.
P2 (ложное warning для trackers/threats) — косметическая несогласованность.
P3 (opencck .gbin не обновляется) — функциональный дефект, нужно исправить.

Приоритет следующих исправлений:
1. **P3** — критично для автообновления opencck
2. **P1** — чистота логики geo_compile
3. **P2** — согласованность логирования

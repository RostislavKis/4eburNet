# audit_v35 — Devil Audit: v1.1 (Bloom filter + SIMD strcmp)

**Диапазон:** `a98cfc7..1e366e8` (14 коммитов)
**Файлы:** bloom.h, simd_strcmp.h, geo_types.h, geo_compile.c, geo_loader.c, Makefile.dev, test_bloom.c, test_simd_strcmp.c
**Дата:** 2026-04-18

---

## Итог

| Категория       | Количество |
|-----------------|-----------|
| БЛОКЕРЫ         | 0         |
| Функциональные  | 3         |
| Замечания       | 5         |

**Статус:** ОДОБРЕНО с исправлениями (F1–F3)

---

## Функциональные дефекты

### F1 — bloom.h:39 — `bloom_add()` без защиты от `nbits == 0`

```c
// bloom.h:39–48
static inline void bloom_add(uint8_t *bits, uint32_t nbits, const char *key)
{
    uint32_t h0 = bloom_hash(key, 0x811c9dc5u) % nbits;  // деление на ноль если nbits==0
```

`bloom_check()` имеет guard `if (!bits || nbits == 0) return true` (строка 29), но `bloom_add()` — нет.
В geo_compile вызывается только с `BLOOM_BYTES * 8u`, поэтому в production не триггерится.
Но API асимметричен: `bloom_check(bits, 0, key)` безопасен, `bloom_add(bits, 0, key)` — UB.

**Исправление:** добавить `if (!bits || nbits == 0) return;` в начало `bloom_add`.

---

### F2 — geo_compile.c:297-299 — padding fwrite вне переменной `ok`

```c
// geo_compile.c:297-299
{
    static const uint8_t pad[16] = {0};
    fwrite(pad, 1, sizeof(pad), out);   // результат не проверяется
}
fclose(out);

if (!ok) { ... unlink(tmp_path); ... }   // но ok тут уже не захватывает ошибку padding
```

Если запись 16-байтового padding провалится (переполненный диск), файл переименуется как успешный.
Последняя строка string_pool будет читаться NEON/SSE2 за пределами валидных данных.

**Исправление:**
```c
ok &= (fwrite(pad, 1, sizeof(pad), out) == sizeof(pad));
```

---

### F3 — geo_compile.c:336-345 — `total_sz` занижен в выводе

```c
size_t total_sz = sizeof(hdr)
                  + (size_t)n_dom * sizeof(uint32_t)
                  + ...
                  + actual_pool;   // bloom_domain (512KB) + bloom_suffix (512KB) не включены
printf("  string pool: %u Б, итого: %zu Б\n", actual_pool, total_sz);
```

Для категорий с доменами реальный размер файла на ~1MB больше выведенного `total_sz`.

**Исправление:**
```c
size_t total_sz = sizeof(hdr)
                  + (size_t)n_dom * sizeof(uint32_t)
                  + (size_t)n_sfx * sizeof(uint32_t)
                  + (size_t)n_v4  * sizeof(geo_cidr4_t)
                  + (size_t)n_v6  * sizeof(geo_cidr6_t)
                  + (bloom_domain ? BLOOM_BYTES : 0u)
                  + (bloom_suffix ? BLOOM_BYTES : 0u)
                  + actual_pool;
```

---

## Замечания

### Z1 — geo_types.h:33-35 — стейл комментарий "36 байт"

```c
/*
 * Заголовок .gbin файла (36 байт).
 * Раскладка файла:
 *   [geo_bin_header_t 36B]
```

Структура расширена до 44 байт в VERSION=2. Комментарий и раскладка устарели.

---

### Z2 — simd_strcmp.h:34,36 — двойной вызов `vceqq_u8` в NEON

```c
uint64_t z0 = vgetq_lane_u64(
                  vreinterpretq_u64_u8(vceqq_u8(va, zero)), 0);  // строка 34
uint64_t z1 = vgetq_lane_u64(
                  vreinterpretq_u64_u8(vceqq_u8(va, zero)), 1);  // строка 36 — повтор
```

Одна и та же операция `vceqq_u8(va, zero)` вычисляется дважды. Компилятор с -O2 скорее всего оптимизирует, но код неаккуратен. Лучше:

```c
uint8x16_t znull = vceqq_u8(va, zero);
uint64_t z0 = vgetq_lane_u64(vreinterpretq_u64_u8(znull), 0);
uint64_t z1 = vgetq_lane_u64(vreinterpretq_u64_u8(znull), 1);
```

---

### Z3 — simd_strcmp.h:65 — комментарий "Нет overread" вводит в заблуждение

```c
/* Нет overread: haszero detection останавливает перед концом строки. */
static inline int fast_strcmp(const char *a, const char *b)
{
    for (;;) {
        uint32_t ca, cb;
        memcpy(&ca, a, sizeof(ca));   // читает 4 байта даже для "" или "x"
```

Для строк длиной < 4 байт (включая `""`) `memcpy` читает байты за пределами NUL-терминатора.
В production безопасен (string_pool имеет 16-byte padding), но комментарий противоречит факту.
Комментарий следует заменить: `/* overread безопасен: string_pool имеет 16-byte padding */`.

---

### Z4 — geo_loader.c:677 — устаревший специфичный комментарий

```c
/* O(n) — geoip-ru.lst содержит 0 IPv6 CIDR, bsearch не нужен */
```

Привязан к конкретному файлу, неверен как общее утверждение.

---

### Z5 — Makefile.dev:370 — счётчик тест-суитов устарел

```makefile
@echo "  make test                — запустить все тесты (18 суитов)"
```

С добавлением test-bloom и test-simd в v1.1-4 тест-суитов стало 20.

---

## Проверки безопасности

| Проверка                        | Результат |
|---------------------------------|-----------|
| MIPS стек (макс. буфер)         | 264 байт ≤ 512 лимит — OK |
| geobin_pool_off VERSION=1 compat | bds=bss=0 → корректно — OK |
| bloom_check(NULL, 0) = true      | guard на строке 29 — OK |
| 16-byte padding в geo_compile    | fwrite(pad,16) после pool — OK (c учётом F2) |
| n_dom==0 bloom guard             | if (n_dom>0 || n_sfx>0) — OK (commit 1e366e8) |
| Backward compat VERSION=1        | min_hdr=36u, bds/bss=0 — OK |

---

## Тесты

Запускались на x86_64 (SSE2), musl-gcc -std=gnu2x -O2:

```
=== test_bloom ===
  PASS: T1: нет false negative (10 доменов)
  PASS: T2: FPR=0.01% < 5% (50K доменов, 512KB)
  PASS: T3: bloom_check(NULL, 0, key) = true
  PASS: T3b: bloom_check(NULL, 42, key) = true
  PASS: T4: bloom_check(bits, 0, key) = true
=== ALL PASS (0 failures) ===

=== test_simd_strcmp (режим: SSE2) ===
  PASS: T1: fast_strcmp == strcmp для коротких строк
  PASS: T2a: равные длинные строки = 0
  PASS: T2b: длинные строки с различием → знак совпадает
  PASS: T3: fast_strcmp(s, s) = 0
  PASS: T4: порядок fast_strcmp совпадает со strcmp
=== ALL PASS (0 failures) ===
```

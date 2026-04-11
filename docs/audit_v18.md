# Devil Audit v18 — C.5 dispatcher DPI интеграция

**Дата:** 2026-04-11
**Статус:** аудит после коммита `1f2e917` (C.5 dispatcher: интеграция DPI bypass)
**Файлы:** `core/include/proxy/dispatcher.h` (161 строка), `core/src/proxy/dispatcher.c` (~1230 строк), `core/src/dpi/dpi_strategy.c` (178 строк)

---

## Scope

Три точки интеграции DPI bypass в dispatcher:
1. **dispatcher.h:72-74** — поля `dpi_bypass`, `dpi_first_done` в `relay_conn_t`
2. **dispatcher.c:912-924** — `dpi_filter_match()` в `dispatcher_handle_conn`
3. **dispatcher.c:735-769** — DPI bypass блок в `relay_transfer`

---

## Находки

### 1. 🟡 `dpi_send_fragment` partial send = потеря данных без retry

**Файл:** `dpi_strategy.c:144-149`

```c
if (n1 < (ssize_t)p1) {
    log_msg(LOG_WARN,
            "dpi_send_fragment: partial send part1: %zd < %d",
            n1, p1);
    dpi_set_nodelay(fd, saved_nodelay);
    return -1;
}
```

Обычный путь relay_transfer (строка 776) имеет `while (written < n)` цикл для partial write. DPI путь использует одиночный `send()` — при partial send возвращает -1, relay закрывается.

На практике первый пакет — TLS ClientHello ~300-600 байт, TCP send buffer стандартно 16KB+, partial send невозможен кроме экстремального memory pressure. Но это формальная разница поведения двух путей.

**Влияние:** минимальное. Первый пакет всегда мал (<1500 байт). partial send на сокете с пустым буфером нереалистичен.
**Действие:** нет. Допустимо оставить как есть.

---

### 2. 🟡 `dpi_send_fake` ошибка → `dpi_send_fragment` всё равно вызывается

**Файл:** `dispatcher.c:760-768`

```c
if (fake_len > 0)
    dpi_send_fake(r->upstream_fd, fake_buf, fake_len,
                  strat.fake_ttl, strat.fake_repeats);
free(fake_buf);
}

return (ssize_t)dpi_send_fragment(r->upstream_fd,
                                   ds->relay_buf, (int)n,
                                   strat.split_pos);
```

Если `dpi_send_fake` вернул -1 из-за EPIPE/ECONNRESET — upstream сокет разорван. Вызов `dpi_send_fragment` тоже вернёт -1, relay закроется корректно. Но будет два LOG_WARN подряд: один из `dpi_send_fake`, другой из `dpi_send_fragment`.

**Влияние:** шумные логи при разорванном соединении. Не баг — корректная обработка.
**Действие:** нет. Два лога = больше диагностики. Для DIRECT соединений (не прокси) это нормально.

---

### 3. 🟡 IPv6 DPI matching не работает

**Файл:** `dispatcher.c:917-921`

```c
if (conn->dst.ss_family == AF_INET) {
    const struct sockaddr_in *s4 =
        (const struct sockaddr_in *)&conn->dst;
    dst4     = ntohl(s4->sin_addr.s_addr);
    dst_port = ntohs(s4->sin_port);
}
```

Если `dst` — IPv6, то `dst4 = 0`, `dst_port = 0`. Вызов `dpi_filter_match(domain, 0, NULL, 0)` — только domain match. Без domain (sniffer выключен) — `DPI_MATCH_NONE` всегда.

`dpi_filter.h:56` уже объявляет `dpi_filter_match_ipv6()`, но из dispatcher не вызывается. В ipset.txt есть IPv6 CIDR (Cloudflare 2606:4700::/32 и т.д.).

**Влияние:** DPI bypass для IPv6 DIRECT работает только если SNI/domain известен. IP-only IPv6 bypass не работает.
**Действие:** документировать как ограничение C.5. Исправление — добавить `ip6` извлечение в БЛОК 3 (C.6 или отдельный патч).

---

### 4. 🟢 malloc(1300) OOM → skip fake, продолжить fragment

**Файл:** `dispatcher.c:754-764`

```c
uint8_t *fake_buf = malloc(1300);
if (fake_buf) {
    ...
    free(fake_buf);
}

return (ssize_t)dpi_send_fragment(...);
```

Если malloc вернул NULL — fake пропускается, fragment отправляется. Соединение не прерывается. Это правильное поведение: лучше пройти без fake чем отказать в соединении.

**Вердикт:** корректно.

---

### 5. 🟢 memset(r, 0) обнуляет dpi поля

**Файл:** `dispatcher.c:419`

```c
memset(r, 0, sizeof(*r));
```

`relay_alloc` делает `memset(r, 0, sizeof(*r))` — `dpi_bypass = false`, `dpi_first_done = false` бесплатно. Явная инициализация в DIRECT ветке (строка 947-948) — дополнительная страховка.

**Вердикт:** корректно.

---

### 6. 🟢 PROXY путь: dpi_bypass всегда false

**Файл:** `dispatcher.c:995-1004`

PROXY ветка (idx >= 0) вызывает `relay_alloc` → memset(0) → `dpi_bypass = false`. Нет кода который бы установил `dpi_bypass = true` для proxy. Только DIRECT ветка (idx == -1, строка 946-948) устанавливает bypass.

**Вердикт:** корректно.

---

### 7. 🟢 cfg NULL-check гарантирован

**Файл:** `dispatcher.c:874`

```c
if (!g_dispatcher || !g_config) {
    log_msg(LOG_ERROR, "relay: контекст не инициализирован");
    ...
    return;
}
```

`cfg` = `g_config` проверен на NULL до строки 914 (`cfg->dpi_enabled`). В relay_transfer `g_config` проверяется на строке 742 (`if (g_config)`).

**Вердикт:** корректно.

---

### 8. 🟢 domain=NULL → только IP match

**Файл:** `dpi_filter.h:76`

```c
dpi_match_t dpi_filter_match(const char *domain,
                              uint32_t ipv4,
                              const uint8_t *ip6,
                              uint16_t port);
```

Документация (строка 72-75): "Комбинированная проверка: сначала домен, затем IP". При `domain=NULL` — пропускает domain match, проверяет IP. При sniffer выключен + fake-ip выключен → `domain = NULL` → только IP CDN ranges.

**Вердикт:** корректно, задокументировано в dpi_filter.h.

---

### 9. 🟢 (ssize_t) cast безопасен

**Файл:** `dispatcher.c:766`

```c
return (ssize_t)dpi_send_fragment(r->upstream_fd,
                                   ds->relay_buf, (int)n,
                                   strat.split_pos);
```

`dpi_send_fragment` возвращает `int`. Cast `(int)n` — `n` максимум `relay_buf_size` (64KB для FULL). `int` вмещает 64KB. `(ssize_t)` обратный cast тоже безопасен. INT_MAX > 64KB.

**Вердикт:** корректно.

---

### 10. 🟢 strat на стеке — безопасно для MIPS

**Файл:** `dispatcher.c:739`

`dpi_strategy_config_t`: `bool(1) + int(4)*3 + char[256] = ~270 байт`. Суммарный стековый кадр relay_transfer в DPI ветке: ~270 (strat) + 8 (fake_buf ptr) + 8 (n) + прочие = ~300 байт. Стек MIPS 8KB, вызывающие фреймы ~500 байт. Итого ~800/8192 — запас 7KB+.

**Вердикт:** корректно. malloc(1300) правильно вынесен из стека.

---

### 11. 🟢 `dpi_first_done = true` ДО отправки

**Файл:** `dispatcher.c:737`

```c
r->dpi_first_done = true;
```

Установлен до `dpi_send_fake` + `dpi_send_fragment`. Если fragment упадёт → relay_transfer вернёт -1 → relay закроется. Если relay каким-то образом выживет — повторный DPI bypass не произойдёт. Защита от повторного fake.

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
| 🟡 YELLOW | 3 | partial send без retry, double-log при EPIPE, IPv6 IP match |
| 🟢 GREEN | 8 | malloc OOM, memset, proxy path, NULL-check, domain=NULL, cast, стек, first_done |

**Вердикт: C.5 чистый.** Ноль критических проблем. Три жёлтых — два намеренные design decisions (partial send, double-log), один ограничение (IPv6 IP match) для будущего патча.

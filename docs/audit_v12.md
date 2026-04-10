# 4eburNet — Devil Audit v12
**Дата:** 2026-04-11
**Охват:** B.6 — `hy2_parse_uri`, `percent_decode`, `hy2_config_to_server`,
           proxy_provider интеграция, `test_hysteria2_uri.c`
**Предыдущий аудит:** audit_v11 (все закрыты)

## 🟡 Важно — 2 находки

### #1 — query parser: `eq` пересекает границу текущего сегмента

| Файл | `hysteria2.c:609` |
|------|-------------------|
| Класс | LOGIC |

```c
const char *eq  = strchr(p, '=');
if (!eq) break;
const char *amp = strchr(eq + 1, '&');
```

`strchr(p, '=')` ищет `'='` по всей оставшейся строке, а не только
в текущем `&`-сегменте. При URI вида `?badkey&sni=foo`:

1. p = `"badkey&sni=foo"`, `eq` = position 10 (`'='` внутри `"sni=foo"`),
   `amp` = NULL, `seg_end` = конец строки.
2. `klen = eq - p = 10` → `key = "badkey&sni"` (не совпадает ни с чем).
3. Параметр `sni=foo` **молча проглочен** — `sni` не будет установлен.

Любой ключ без значения перед реальным параметром делает реальный
параметр невидимым. Значит URI из реальных подписок с лишними полями
(например `#comment`-фрагменты превратившиеся в `&`-сегменты после
base64-decode) потеряют следующий после них параметр.

**Исправление:** искать `amp` (или конец сегмента) ДО поиска `eq`,
проверять что `eq < seg_end` перед использованием:
```c
const char *amp = strchr(p, '&');
if (hash && (!amp || amp > hash)) amp = hash;
const char *seg_end = amp ? amp : (hash ? hash : p + strlen(p));
const char *eq = memchr(p, '=', (size_t)(seg_end - p));
if (!eq) { p = amp ? amp + 1 : seg_end; continue; }
```

---

### #2 — hy2_config_to_server теряет все hysteria2-специфичные поля

| Файл | `proxy_provider.c:301-309` |
|------|---------------------------|
| Класс | ARCH |

`hy2_config_to_server` копирует в `ServerConfig` только:
`address`, `password`, `port`, `protocol`, `enabled`.

Поля `ServerConfig` **отсутствуют** для:

| Поле `hysteria2_config_t` | Потеря |
|--------------------------|--------|
| `obfs_enabled` / `obfs_password` | Salamander-серверы из подписок **не работают** |
| `insecure` | TLS-верификация всегда включена |
| `sni` | SNI = server_addr вместо заданного |
| `up_mbps` / `down_mbps` | Brutal CC работает без ограничения |

Salamander-obfuscated сервер из подписки будет добавлен в список
серверов, но при подключении Salamander не активируется → соединение
отвалится на уровне QUIC handshake без осмысленной ошибки.

**Исправление (два варианта):**

A. Добавить в `ServerConfig` hysteria2-специфичные поля
   (`hy2_obfs_enabled`, `hy2_obfs_password[512]`, `hy2_insecure`,
   `hy2_sni[256]`, `hy2_up_mbps`, `hy2_down_mbps`) и заполнять
   их в `hy2_config_to_server`.

B. Хранить оригинальный URI в `ServerConfig.source_uri[2048]`
   и перепарсировать при подключении. Меньше полей, но дороже.

Вариант A предпочтителен — один разбор, явные поля, удобно
для debug/dump.

---

## 🟢 Улучшения — 4 находки

### #3 — IPv6 адрес с квадратными скобками сохраняется verbatim

Для `hysteria2://pw@[::1]:443`:
`server_addr = "[::1]"` (со скобками). Большинство реализаций
`getaddrinfo` не принимают адрес в скобках — нужно стрипить `[` и `]`.
Код: `hysteria2.c:588-595`.

**Исправление:** при `server_addr[0] == '['` удалить скобки перед записью:
```c
if (p[0] == '[') { p++; hlen -= 2; /* убрать [ и ] */ }
```

---

### #4 — возвращаемое значение percent_decode в query loop игнорируется

```c
percent_decode(raw_val, vlen, val, sizeof(val));
```
Если декодированное значение не помещается в `val[512]`, функция
возвращает `-1` и `val` остаётся пустой строкой `""`. Параметр
молча игнорируется. Пароль obfs длиной >510 байт до percent-decode
будет молча потерян.
Код: `hysteria2.c:627`.

**Исправление:** проверять возвращаемое значение и возвращать `-1`
из `hy2_parse_uri` если критичное поле не поместилось.

---

### #5 — тестовая компиляция: `explicit_bzero` без `-D_GNU_SOURCE`

При компиляции теста командой `gcc -std=c11` без `-D_GNU_SOURCE`:
```
hysteria2.c:304: warning: implicit declaration of function 'explicit_bzero'
```

Тест работает корректно (линкуется с glibc 2.35 где `explicit_bzero`
есть), но warning загромождает вывод. Основная сборка через
`musl-gcc -D_GNU_SOURCE` предупреждения не даёт.

**Исправление:** добавить `-D_GNU_SOURCE` в команду компиляции теста
в `Makefile.dev`, либо обернуть в `#if defined(__GLIBC__) || defined(__musl__)`.

---

### #6 — лимит 10000 Мбит/с для up/down не задокументирован

```c
if (v > 0 && v <= 10000) cfg->up_mbps = (uint32_t)v;
```
Значения `up > 10000` молча игнорируются — `up_mbps` остаётся 0.
Не документировано в `hysteria2.h`. 10 Гбит — реальный порог для
серверов 2026 года.

**Исправление:** увеличить лимит до 100000 и добавить комментарий
в `.h`. Либо логировать предупреждение при превышении.

---

## Сводка

| Уровень | Кол-во | Статус |
|---------|--------|--------|
| 🔴 | 0 | — |
| 🟡 | 2 | ожидают исправления |
| 🟢 | 4 | ожидают исправления |

## Рекомендуемый порядок исправления

1. **#1** (query parser eq/seg_end) — функциональный баг, минимальный diff
2. **#2** (hy2_config_to_server) — требует расширения `ServerConfig`,
   затрагивает config.h + proxy_provider.c + возможно config.c
3. **#3** (IPv6 скобки) — небольшой патч в hy2_parse_uri
4. **#4** (percent_decode return value) — добавить проверку
5. **#5** (test compile warning) — одна строка в Makefile.dev
6. **#6** (лимит bw) — одна строка в .h + одна в .c

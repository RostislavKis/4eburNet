# 4eburNet IPC Protocol Schema

> Протокол: Unix socket (`/var/run/4eburnet.sock`)
> Формат: бинарный header (8 байт) + JSON payload
> Аутентификация: SO_PEERCRED uid=0

## Header

| Поле | Тип | Описание |
|------|-----|----------|
| version | uint8 | Версия протокола (1) |
| command | uint8 | Код команды (см. ниже) |
| length | uint16 BE | Длина payload в байтах |
| request_id | uint32 BE | ID запроса (для корреляции) |

## Команды

### status (1)

Статус демона.

**Payload:** нет

**Ответ:**
```json
{
  "status": "running",
  "version": "1.4.1",
  "profile": "MICRO|NORMAL|FULL",
  "uptime": 3600
}
```

| Поле | Тип | Описание |
|------|-----|----------|
| status | string | Всегда "running" |
| version | string | EBURNET_VERSION из 4eburnet.h |
| profile | string | Профиль устройства (MICRO/NORMAL/FULL) |
| uptime | int | Секунды с момента старта |

---

### reload (2)

Перечитать конфиг без перезапуска.

**Payload:** нет

**Ответ:** `{"status":"ok"}`

---

### stop (3)

Остановить демон.

**Payload:** нет

**Ответ:** `{"status":"stopping"}`

---

### stats (4)

Статистика соединений и DNS.

**Payload:** нет

**Ответ:**
```json
{
  "connections_total": 1234,
  "connections_active": 5,
  "dns_queries": 5678,
  "dns_cached": 3456
}
```

| Поле | Тип | Описание |
|------|-----|----------|
| connections_total | uint64 | Всего соединений за uptime |
| connections_active | uint64 | Активных relay соединений |
| dns_queries | uint64 | Всего DNS запросов |
| dns_cached | uint64 | DNS ответов из кэша |

---

### groups (20)

Список proxy групп с серверами.

**Payload:** нет

**Ответ:**
```json
{
  "groups": [{
    "name": "auto",
    "type": 1,
    "selected": 0,
    "servers": [{
      "idx": 0,
      "available": true,
      "latency": 45,
      "fails": 0
    }]
  }]
}
```

| Поле | Тип | Описание |
|------|-----|----------|
| groups[].name | string | Имя группы |
| groups[].type | int | 0=select, 1=url_test, 2=fallback, 3=load_balance |
| groups[].selected | int | Индекс выбранного сервера |
| groups[].servers[].idx | int | Unified server index |
| groups[].servers[].available | bool | Доступен по health-check |
| groups[].servers[].latency | uint32 | Задержка в мс (0 = не измерено) |
| groups[].servers[].fails | uint32 | Счётчик последовательных неудач |

---

### group-select (21)

Ручной выбор сервера в группе.

**Payload:**
```json
{"group": "auto", "server": "vless-1"}
```

**Ответ:** `{"status":"ok"}` или `{"status":"error","msg":"..."}`

---

### group-test (22)

Запустить health-check (один tick).

**Payload:** нет

**Ответ:** `{"status":"ok"}` или `{"error":"no groups"}`

---

### providers (23)

Список rule providers.

**Payload:** нет

**Ответ:**
```json
{
  "providers": [{
    "name": "anti-filter",
    "url": "https://...",
    "count": 1500,
    "loaded": true,
    "last_update": 1712956800
  }]
}
```

---

### provider-update (24)

Принудительное обновление провайдера.

**Payload:**
```json
{"name": "anti-filter"}
```

**Ответ:** `{"status":"ok"}` или `{"status":"error","msg":"..."}`

---

### rules (25)

Список traffic rules.

**Payload:** нет

**Ответ:**
```json
{
  "rules": [{
    "type": 1,
    "value": "youtube.com",
    "target": "PROXY",
    "priority": 200
  }]
}
```

| Поле | Тип | Описание |
|------|-----|----------|
| rules[].type | int | 0=domain, 1=domain_suffix, 2=domain_keyword, 3=ip_cidr, 4=rule_set, 5=match, 6=geoip, 7=geosite |
| rules[].value | string | Значение правила |
| rules[].target | string | DIRECT / PROXY / REJECT / имя группы |
| rules[].priority | int | При��ритет (меньше = важнее) |

---

### geo-status (26)

Статус GeoIP менеджера.

**Payload:** нет

**Ответ:**
```json
{
  "region": "RU",
  "categories": [{
    "name": "geoip-ru",
    "region": "RU",
    "loaded": true,
    "v4": 15000,
    "v6": 3000,
    "domains": 500,
    "suffixes": 200
  }]
}
```

---

### cdn-update (30)

Принудительное обновление CDN IP (DPI).

**Payload:** нет

**Ответ:** `{"status":"ok","msg":"cdn update scheduled"}`

Доступна только при `CONFIG_EBURNET_DPI=1`.

---

### dpi-get (40)

Получить текущие настройки DPI.

**Payload:** нет

**Ответ:**
```json
{
  "enabled": true,
  "split_pos": 2,
  "fake_ttl": 5,
  "fake_count": 3,
  "fake_sni": "www.microsoft.com",
  "whitelist": ["youtube.com"],
  "blacklist": []
}
```

| Поле | Тип | Описание |
|------|-----|----------|
| enabled | bool | DPI обход включён |
| split_pos | int | Позиция разбивки TCP пакета (байт) |
| fake_ttl | int | TTL поддельных пакетов |
| fake_count | int | Количество поддельных пакетов |
| fake_sni | string | SNI в поддельном ClientHello |
| whitelist | string[] | Домены принудительно через DPI |
| blacklist | string[] | Домены исключённые из DPI |

Доступна только при `CONFIG_EBURNET_DPI=1`.

---

### dpi-set (41)

Изменить настройки DPI в памяти и сохранить кэш адаптации.

**Payload:**
```json
{
  "enabled": "true",
  "split_pos": "2",
  "fake_ttl": "5",
  "fake_count": "3",
  "fake_sni": "www.microsoft.com"
}
```

Все поля опциональны; отсутствующие поля не меняются. Значения передаются как строки.

| Поле      | Допустимые значения          |
|-----------|------------------------------|
| enabled   | "true" / "false" / "1" / "0" |
| split_pos | "1" – "1399"                 |
| fake_ttl  | "1" – "64"                   |
| fake_count| "1" – "20"                   |
| fake_sni  | произвольная строка          |

**Ответ:** `{"status":"ok"}`

**Side effects:** вызывает `dpi_adapt_save()` — кэш адаптации записывается в `/etc/4eburnet/dpi_cache.bin`.

Доступна только при `CONFIG_EBURNET_DPI=1`.

---

## HTTP-only эндпоинты без IPC-backing

Следующие HTTP-эндпоинты реализованы напрямую в HTTP-сервере без отдельных IPC команд:

| Endpoint                | Method | Description                                              |
|-------------------------|--------|----------------------------------------------------------|
| `/api/dns/cache/flush`  | POST   | unlink dns-cache.json + SIGHUP                           |
| `/api/dns/stats`        | GET    | реальные атомарные счётчики из `g_stats` (audit_v53 §3)  |
| `/api/subscribe/parse`  | POST   | preview серверов подписки БЕЗ сохранения                 |
| `/api/subscribe/import` | POST   | импорт подписки в UCI + `uci commit` + reload демона     |

`IPC_CMD_DNS_CACHE_FLUSH` и `IPC_CMD_DNS_STATS` не реализованы как IPC команды.

### `GET /api/dns/stats`

Реальные счётчики DNS — НЕ заглушка (audit_v53 §3 закрыл нарушение «0 stub»).
Источник: атомарные поля `g_stats`, инкремент в `dns_server.c`.

**Ответ:**
```json
{"queries":12345,"cached":9876,"blocked":42,"upstream_errors":3,"hit_rate":80.0}
```

| Поле              | Источник `g_stats`                                  |
|-------------------|-----------------------------------------------------|
| `queries`         | `dns_queries_total`                                 |
| `cached`          | `dns_cached_total`                                  |
| `blocked`         | `blocked_ads + blocked_trackers + blocked_threats`  |
| `upstream_errors` | `dns_upstream_errors` (timeout → SERVFAIL)          |
| `hit_rate`        | `cached / queries * 100` (%, `0.0` при `queries=0`) |

### `POST /api/subscribe/parse`

Превью серверов подписки без записи в UCI.

**Запрос:** `{"data":"<подписка>"}` либо `{"url":"<URL подписки>"}` (при пустом
`data` подписка скачивается по `url` встроенным HTTP-клиентом с bypass fake-IP).

**Автодетект форматов:** base64 (v2rayN/Hiddify/Shadowrocket), URI-list
(`vless|vmess|trojan|ss|hy2|hysteria2|tuic://`), Clash YAML (`proxies:`),
sing-box JSON (`outbounds[]`), SIP008 JSON (`servers[]` + `server_port`).

**Ответ 200:** массив превью серверов:
```json
[{"name":"...","protocol":"vless","address":"...","port":443}]
```

**Ошибки:** 400 `no body` / `missing data or url`; 502 `download failed` /
`empty response`; 500 `oom`.

### `POST /api/subscribe/import`

Импорт подписки в UCI (анонимные секции `server`) + `uci commit` + reload демона
(только если добавлен ≥1 сервер).

**Запрос:** `{"data":"<подписка>","target_group":"<имя>"}` либо `{"url":"..."}`.

**Форматы:** Clash YAML (`proxies:` — полный парсинг через `clash_yaml.c`) и
URI-list (`vless|trojan|ss://` вида `user@host:port#name`).

**Ответ 200:** `{"added":N,"errors":N}`.

**Ошибки:** 400 `no data or url`; 502 `download failed`; 500 `oom`.

---

## Ошибки

Все ошибки возвращаются в формате:
```json
{"error": "описание"}
```
или
```json
{"status": "error", "msg": "описание"}
```

Неизвестная команда: `{"error":"unknown command"}`
Неверная версия протокола: `{"error":"version mismatch"}`

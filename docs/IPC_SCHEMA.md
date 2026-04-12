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
  "version": "1.0.0",
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

# 4eburNet — Devil Audit v13
**Дата:** 2026-04-11
**Охват:** B.7 финальный код — `config.c` (hy2_* ветви), `4eburnet.uc` (server_add),
           `servers.js` (UI форма Hysteria2)
**Предыдущий аудит:** audit_v12 (все 6 находок закрыты)

---

## 🟡 Важно

### v13-1 — servers.js: protoSel не сбрасывается; updateFields не вызывается после добавления

**Место:** `servers.js`, блок очистки формы (строки 347–356)

**Проблема:**
```js
/* Текущий код очистки */
['add-name','add-address','add-port',
 'add-uuid','add-password','add-pbk','add-sid',
 'add-hy2-password','add-hy2-obfs-password',
 'add-hy2-sni','add-hy2-up','add-hy2-down'
].forEach(...)
var hy2InEl2 = document.getElementById('add-hy2-insecure');
if (hy2InEl2) hy2InEl2.checked = false;
rebuildList();
/* updateFields() отсутствует, protoSel не сброшен */
```

`protoSel` (id=`add-proto`) и `transportSel` (id=`add-transport`) отсутствуют в списке
сброса. После успешного добавления Hysteria2 сервера:

1. `protoSel.value` остаётся `'hysteria2'`
2. `updateFields()` не вызывается
3. Форма остаётся с видимыми hy2 полями и скрытым row-transport

**Практический сценарий сбоя:**
Пользователь добавляет Hysteria2 сервер → форма не переключается обратно на VLESS →
пользователь вводит адрес/порт нового VLESS → нажимает "+ Добавить" →
фронтенд читает `proto='hysteria2'`, `hy2Pass=''` → срабатывает валидация
`"Для Hysteria2 обязателен пароль"` — **новый VLESS-сервер добавить невозможно**
без ручного переключения протокола.

**Исправление:**
```js
/* Добавить после блока очистки, перед rebuildList() */
protoSel.value = 'vless';
transportSel.value = 'tcp';
updateFields();
rebuildList();
```

---

## 🟢 Улучшения

### v13-2 — servers.js: поле hy2-password — type='text', пароль видим в UI

**Место:** `servers.js:162`

```js
var rowHy2Auth = E('div', {id: 'row-hy2-auth', ...}, [
    mkInp('add-hy2-password', 'Пароль авторизации', true)
    /* mkInp создаёт <input type='text'> */
]);
```

Пароль авторизации Hysteria2 отображается в открытом тексте.
В OpenWrt LuCI это системно допустимо (uuid/password других протоколов тоже `type='text'`),
но `type='password'` улучшил бы безопасность при работе с роутером по HTTP.

**Исправление:** добавить опциональный параметр `password_type` в `mkInp` или
использовать отдельный helper для hy2-password:
```js
E('input', {type: 'password', id: 'add-hy2-password', placeholder: 'пароль', ...})
```

---

### v13-3 — 4eburnet.uc: hy2_insecure='0' записывается безусловно

**Место:** `4eburnet.uc`, блок Hysteria2 в `server_add`

```js
c.set('4eburnet', sec, 'hy2_insecure',
      a.hy2_insecure ? '1' : '0');  /* всегда, даже при значении '0' */
```

Каждый Hysteria2 сервер получает `option hy2_insecure '0'` в UCI, даже если TLS
верификация включена (дефолт). Функционально корректно: `config.c` читает `'0' → false`.
Добавляет один лишний ключ в UCI на каждый сервер.

**Исправление (опционально):**
```js
if (a.hy2_insecure)
    c.set('4eburnet', sec, 'hy2_insecure', '1');
/* Отсутствие опции = false; config.c уже обнуляет структуру при инициализации */
```

---

### v13-4 — config.c: strtol без endptr — "10abc" принимается как 10

**Место:** `config.c`, ветви `hy2_up_mbps` / `hy2_down_mbps`

```c
long v = strtol(value, NULL, 10);
srv->hy2_up_mbps = (v > 0 && v <= 100000) ? (uint32_t)v : 0;
```

`strtol` с `endptr=NULL` не позволяет обнаружить частично числовую строку типа `"10abc"` —
она принимается как `10`. В контексте UCI (данные приходят из нашего собственного UI или
UCI-файла, а не от пользователя напрямую), риск минимален. Тем не менее, явная
валидация через `endptr` была бы точнее:

```c
char *endp;
long v = strtol(value, &endp, 10);
if (endp == value || *endp != '\0') v = 0;  /* нечисловой ввод → 0 */
```

---

## Без замечаний (проверено, всё корректно)

- **Позиционный вызов callServerAdd**: params[5]=`uuid` ← `authUuid=''`, params[6]=`password` ← `authPwd=hy2Pass` ✓
- **server_add safe-whitelist + hy2 блок**: hy2_* поля сохраняются через отдельный
  `if (a.protocol === 'hysteria2')` блок, не через generic `safe` loop ✓
- **c.commit() порядок**: после всех `c.set()` включая hy2 блок ✓
- **server_list полнота**: `uci_get_sections_of_type` → `c.foreach` → возвращает все ключи
  секции, в т.ч. `hy2_*` без явного фильтра ✓
- **config.c NUL терминаторы**: explicit `[sizeof-1] = '\0'` после strncpy для
  `hy2_obfs_password` и `hy2_sni` ✓
- **hy2_obfs_enabled логика**: вычисляется из `value[0] != '\0'` при загрузке `hy2_obfs_password`;
  ручное редактирование UCI (добавить `hy2_obfs_password` без `hy2_obfs_enabled`) — работает ✓
- **updateFields при первом рендере**: начальное состояние элементов (`display:none` для hy2,
  `display:''` для row-uuid) соответствует дефолтному протоколу VLESS (первый option) ✓
- **hy2_up/down_mbps string→int pipeline**: `gv()` → string → `int()` ucode → `strtol` c.c →
  `v > 0 && v <= 100000` — граничные случаи (пусто→0, отрицательное→0) обработаны ✓
- **buildRows transport column**: `s.hy2_obfs_password ? 'salamander' : 'quic'` —
  `undefined` → falsy → `'quic'`; удалённый obfs_password → UCI опции нет → undefined ✓

---

## Сводка

| Уровень | Кол-во | Находки |
|---------|--------|---------|
| 🔴 | 0 | — |
| 🟡 | 1 | v13-1: protoSel не сбрасывается → UX lock-in на Hysteria2 |
| 🟢 | 3 | v13-2: hy2-password type='text'; v13-3: hy2_insecure UCI шум; v13-4: strtol endptr |

# Devil Audit v34 — 4eburNet
Дата: 2026-04-18
Скоуп: v1.1-3 — nftables flow offload для DIRECT трафика (коммит 6153341)
Аудитор: Devil Audit (Claude Code)

---

## Итог

| Блокеров | Проблем | Замечаний | OK |
|----------|---------|-----------|-----|
| 0        | 0       | 4         | ✅  |

Сборка: 0 ошибок, 1.9MB dev бинарник, 19/19 тестов ALL PASS.
EC330 деплой: `status` отвечает с полем `"flow_offload":false` (отключён по умолчанию).

---

## Найденные issues

### 💬 ЗАМЕЧАНИЯ

**Z1** — `core/src/routing/nftables.c` — wan_iface не валидируется

```c
snprintf(config, NFT_ATOMIC_MAX,
    "... devices = { %s, br-lan } ; }\n ...",
    wan_iface, ...);
```

`wan_iface` попадает в nft конфиг через `snprintf` без проверки символов.
Linux гарантирует IFNAMSIZ ≤ 16 и только `[a-zA-Z0-9._-@]`, поэтому
shell-injection через имя интерфейса невозможна.
Но проверки нет в коде — если `ip route` вернёт неожиданный вывод (например,
пустую строку или строку с пробелом), `nft -f` завершится с ошибкой.

Фикс (опционально): добавить валидацию символов перед snprintf:
```c
for (size_t i = 0; i < l; i++)
    if (!isalnum((unsigned char)wan_iface[i]) && wan_iface[i] != '-'
        && wan_iface[i] != '_' && wan_iface[i] != '.')
        { log_msg(LOG_WARN, "flow offload: невалидный WAN iface"); return -1; }
```

---

**Z2** — `core/src/routing/nftables.c:1285` — `disable()` логирует "деактивирован" при отсутствующих объектах

`nft_flow_offload_disable()` вызывается:
1. В начале `nft_flow_offload_enable()` (idempotency)
2. При cleanup (всегда, `nft_cleanup()` всё равно удалит таблицу)
3. При reload (всегда, даже если `flow_offload = 0`)

В случаях 2 и 3 когда offload не был активирован — три `exec_cmd_safe`
(flush/delete chain/delete flowtable) запускают `nft` процессы, которые
возвращают ошибку "не найдено" (молча игнорируется). Затем пишется:
`flow offload: деактивирован` — в лог при каждом reload, вводит в заблуждение.

---

**Z3** — `core/src/main.c:1065` — `disable()` при reload вызывается до проверки `flow_offload`

```c
/* reload */
nft_flow_offload_disable();      /* вызывается всегда */
if (cfg_ptr->flow_offload)
    nft_flow_offload_enable();
```

Если `flow_offload = 0`: disable() запускает три nft процесса вхолостую
и пишет лог-сообщение при каждом SIGHUP. Незначительно на x86, заметно
на MIPS (posix_spawn дорог).

Фикс — добавить флаг состояния или проверку:
```c
/* при reload */
if (offload_was_active)
    nft_flow_offload_disable();
if (cfg_ptr->flow_offload)
    nft_flow_offload_enable();
```
Альтернатива: в `disable()` проверять `nft list flowtables | grep eburnet_ft`
перед удалением — но это ещё один fork. Проще трекать глобальный bool.

---

**Z4** — `core/src/ipc.c:232` — `exec_cmd_contains` в hot path IPC status

```c
bool flow_ok = exec_cmd_contains(
    "nft list flowtables 2>/dev/null", NFT_FLOWTABLE_NAME);
```

Каждый вызов `--ipc status` порождает дочерний процесс `nft`.
IPC status не горячий путь (CLI-запрос), но на MIPS fork/exec дорог.

Фикс: кэшировать значение в статической переменной, обновляемой
только в `nft_flow_offload_enable/disable`:
```c
/* в nftables.c */
static bool g_flow_offload_active = false;
/* в ipc.c заменить exec_cmd_contains на: */
bool flow_ok = nft_flow_offload_active();
```

---

## Проверено и подтверждено (OK)

| Компонент | Статус |
|-----------|--------|
| get_wan_iface: pclose на всех путях (fgets fail → pclose; success → pclose) | ✅ |
| get_wan_iface: buf[32] > IFNAMSIZ(16), overflow невозможен | ✅ |
| snprintf: проверка `n < 0 \|\| n >= NFT_ATOMIC_MAX` перед nft_exec_atomic | ✅ |
| free(config) на всех путях включая rc != NFT_OK | ✅ |
| modprobe argv: NULL-terminated `{"modprobe","nft_flow_offload",NULL}` | ✅ |
| NFT_ATOMIC_MAX=16384 достаточен для конфига (~350 байт с длинным wan) | ✅ |
| NFT_PRIO_FLOW=-1: после наших цепочек (-200), до fw4 (0) — корректно | ✅ |
| NFT_MARK_PROXY=0x01 совпадает с FWMARK_PROXY — proxy трафик не offload-ится | ✅ |
| TPROXY трафик не попадает в forward chain — flow_forward его не видит | ✅ |
| disable(): flush chain → delete chain → delete flowtable — верный порядок | ✅ |
| disable(): ошибки exec_cmd_safe игнорируются (chain/ft могут отсутствовать) | ✅ |
| enable() вызывается только если cfg->flow_offload == true | ✅ |
| disable() вызывается при cleanup перед nft_cleanup() | ✅ |
| reload: disable() + enable() — WAN интерфейс обновляется | ✅ |
| enable() -1 → LOG_WARN, демон продолжает работу (software path) | ✅ |
| flow_offload в EburNetConfig: bool, default 0 (memset) | ✅ |
| Парсинг: strcmp(value,"1") — любое другое значение → false | ✅ |
| IPC status: flow_offload из nft list flowtables, не захардкожено | ✅ |
| UCI: option flow_offload '0' добавлен | ✅ |
| Сборка dev: 0 ошибок, 1.9MB | ✅ |
| Тесты: 19/19 ALL PASS | ✅ |
| EC330 деплой: `"flow_offload":false` (disabled by default) | ✅ |
| EC330 RAM: 21MB available (stable) | ✅ |

---

## Вердикт

**0 блокеров. Код production-ready.**

Z1 (no wan_iface validation) — теоретически безопасно (Linux IFNAMSIZ + символы),
но добавить проверку в v1.1-4 несложно.

Z2/Z3 (шумные логи + лишние fork при reload) — рекомендуется трекать
`g_flow_offload_active` bool в v1.1-4.

Z4 (fork в IPC status) — незначительно на CLI, рекомендуется кэшировать.

Приоритет следующих исправлений:
1. **Z2/Z3** — добавить `g_flow_offload_active` флаг, убрать лишние log/fork
2. **Z1** — валидация символов wan_iface
3. **Z4** — `nft_flow_offload_active()` без fork

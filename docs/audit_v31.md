# Devil Audit v31 — 4eburNet

> Дата: 2026-04-18
> Аудитор: Claude Code (Sonnet 4.6)
> Предыдущий: audit_v30 (0 блокеров, 0 проблем)
> Скоуп: блоки 3.5 (GeoIP/GeoSite) + 3.6 (Sniffer SNI) + весь новый код с commit acfc52b..HEAD

## Итог

| Блокеров | Проблем | Замечаний | OK |
|---------|---------|-----------|-----|
| **0** | **3** | **3** | **58** |

## Компиляция и тесты

```
make -f Makefile.dev    → 1.9MB, 0 ошибок, 0 предупреждений (-Werror)
make -f Makefile.dev test → 16 тест-таргетов, ALL PASS
```

---

## Найденные Issues

### ⚠️ П1 — main.c:987 — dns_rules_init() при reload без проверки return value

**Файл:** `core/src/main.c:987`

```c
// На старте (корректно):
if (dns_rules_init(cfg_ptr) < 0) {
    log_msg(LOG_ERROR, "dns_rules: инициализация провалилась");
    goto cleanup;
}

// При reload (SIGHUP) — return value игнорируется:
dns_rules_init(cfg_ptr);   // ← без проверки
```

При OOM во время SIGHUP reload `dns_rules_init` вернёт -1, DNS продолжит работу
с пустыми правилами. Весь трафик пойдёт через geosite fallback без explicit правил.
Не crash, но молчаливая деградация без LOG_WARN.

**Приоритет:** Medium

---

### ⚠️ П2 — main.c:1016 — geo atomic swap теряет данные при пустой загрузке файлов

**Файл:** `core/src/main.c:1011–1025`

```c
if (geo_manager_init(&new_geo, cfg_ptr) == 0) {
    geo_load_region_categories(&new_geo, cfg_ptr);  // может загрузить 0 файлов
    geo_manager_free(&geo_state);   // ← старые данные удалены
    geo_state = new_geo;            // ← пустой менеджер
}
```

`geo_manager_init` всегда возвращает 0 (если нет OOM). Если `geo_load_region_categories`
не загрузила ни одного файла (все отсутствуют), `geo_state` заменяется пустым
менеджером — 877K доменов теряются. Защита только против OOM init, не против
отсутствующих файлов.

**Исправление:** проверить `new_geo.count > 0` перед swap:
```c
if (geo_manager_init(&new_geo, cfg_ptr) == 0) {
    geo_load_region_categories(&new_geo, cfg_ptr);
    if (new_geo.count > 0) {
        geo_manager_free(&geo_state);
        geo_state = new_geo;
    } else {
        log_msg(LOG_WARN, "geo: ни одна категория не загружена — сохраняем старые");
        geo_manager_free(&new_geo);
    }
}
```

**Приоритет:** Medium

---

### ⚠️ П3 — net_utils.c:647 — uclient-fetch пишет напрямую в dest_path без атомарной замены

**Файл:** `core/src/net_utils.c:640–663` (`child_do_fetch`)

```c
const char *argv[] = {
    "uclient-fetch", "-q", "-T", "15", "-O", dest_path, url, NULL
};
```

`uclient-fetch -O dest_path` пишет прямо в целевой файл. При сетевой ошибке
(таймаут, обрыв) на диске остаётся частично загруженный файл. После рестарта
демона `rule_provider_load_all` видит файл через `stat()` и загружает битый контент
в memory cache.

**Исправление:** использовать `.tmp` файл + rename:
```c
// tmp_path = dest_path + ".tmp"
"uclient-fetch", "-q", "-T", "15", "-O", tmp_path, url, NULL
// после waitpid: rename(tmp_path, dest_path)
```

**Приоритет:** Medium

---

### 💬 З1 — nftables.h:53 — NFT_FAKE_IP_CIDR жёстко прошит, игнорирует fake_ip_range из UCI

**Файл:** `core/include/routing/nftables.h:53`, `core/src/routing/nftables.c:569`

```c
#define NFT_FAKE_IP_CIDR "198.51.100.0/24"  // hardcoded

// В nft_mode_set_rules():
"ip daddr " NFT_FAKE_IP_CIDR " meta l4proto { tcp, udp } meta mark set 0x%02x accept\n"
```

`cfg->dns.fake_ip_range` парсится из UCI, передаётся в `fake_ip_init()`, но
в nftables-правило не попадает. Если пользователь изменит `option fake_ip_range '203.0.113.0/24'`,
nftables продолжит матчить `198.51.100.0/24`.

В текущей конфигурации это не проблема (UCI и константа совпадают). Но архитектурно
некорректно — два источника правды.

**Приоритет:** Low (косметика при текущем дефолтном диапазоне)

---

### 💬 З2 — dns_rules_load_file определена но не вызывается нигде

**Файл:** `core/src/dns/dns_rules.c:210`

```c
int dns_rules_load_file(const char *path, dns_action_t action)
```

Функция объявлена и реализована, но не вызывается ни из одного .c файла.
Opencck-domains.lst загружается через `rules_engine` / `ruleset_match_domain`,
а не через DNS правила напрямую. Это намеренно (разные pipeline), но мёртвый код.

**Приоритет:** Low (убрать или оставить для будущего использования — документировать)

---

### 💬 З3 — geo_convert.sh: при 0 совпадениях grep → set -e срабатывает до rm -f "$TMP"

**Файл:** `luci-app-4eburnet/files/usr/share/4eburnet/geo_convert.sh`

```sh
set -e
...
grep '^||' "$TMP" | ... > "${OUTPUT}.new"  # если 0 строк — grep exit 1
rm -f "$TMP"  # не достигается при set -e
```

При пустом trackers-файле `grep` возвращает exit code 1 → `set -e` выходит →
`"${OUTPUT}.tmp"` ($TMP) не удаляется. На следующем запуске перезапишется.
Безвредно, но лишний файл.

**Приоритет:** Low

---

## Проверенные OK пункты (58)

| # | Что проверено | Результат |
|---|--------------|-----------|
| 1 | DNS_TYPE_GEOSITE через geo_cat_type_t — нет конфликта enum | ✅ |
| 2 | dns_rules_add_geosite(): bounds check (unsigned)cat >= 4 | ✅ |
| 3 | geosite_check(): вызывается только когда best==DEFAULT | ✅ |
| 4 | geosite_check(): g_gm == NULL guard | ✅ |
| 5 | При отсутствии geo файла: LOG_WARN, не crash | ✅ |
| 6 | block_geosite в config.c: парсится list секция | ✅ |
| 7 | fake_ip_enabled в config.c: парсит "1"/"0" с валидацией | ✅ |
| 8 | dns_rules_free(): сбрасывает g_gm и g_engine_cb | ✅ |
| 9 | geo_manager + engine переустанавливаются после reload | ✅ |
| 10 | Priority table prio[4]: BLOCK первым в sorted index | ✅ |
| 11 | cmp_rule_idx: безопасное индексирование [0..3] | ✅ |
| 12 | OOM rollback в dns_rules_load_file: realloc patterns к старому size | ✅ |
| 13 | dns_rules_rebuild_index(): idx_free + пересборка | ✅ |
| 14 | free_category_data(): domains[], suffixes[], v4[], v6[], ptrie | ✅ |
| 15 | geo_manager_free(): полный memset | ✅ |
| 16 | geo_load_category(): 2-проход подсчёт→аллокация | ✅ |
| 17 | geo_load_category(): free_category_data перед загрузкой | ✅ |
| 18 | ptrie_insert(): OOM → ptrie_free + fallback O(n) | ✅ |
| 19 | ptrie_lookup(): наиболее специфичный match | ✅ |
| 20 | geo_match_domain_cat(): только не-GENERIC категории | ✅ |
| 21 | atomic swap если geo_manager_init() возвращает -1 | ✅ |
| 22 | SIGHUP single-threaded epoll — нет race при reload | ✅ |
| 23 | opencck-domains.lst через rule_provider (отдельный pipeline) | ✅ |
| 24 | sniffer.c:buf[512] — стек ровно на лимите MIPS | ✅ |
| 25 | dispatcher.c:sni[256] на стеке — в пределах лимита | ✅ |
| 26 | conn->fd >= 0 guard перед sniffer_peek_sni | ✅ |
| 27 | Fallback chain: fake-ip → SNI → rules_engine(NULL) | ✅ |
| 28 | rules_engine_match(): NULL domain handled для всех DOMAIN-type rules | ✅ |
| 29 | fake_ip_lookup_by_ip(): pointer safe (single-threaded, heap) | ✅ |
| 30 | MSG_PEEK: данные не потребляются, повторное чтение OK | ✅ |
| 31 | Нет double-peek после sniffer | ✅ |
| 32 | rules_engine_get_server(): DIRECT=-1, REJECT=-2, GROUP=idx | ✅ |
| 33 | rule_provider_tick(): вызов из main epoll loop | ✅ |
| 34 | net_spawn_fetch(): fork/pipe, O_NONBLOCK read end | ✅ |
| 35 | child_do_fetch(): uclient-fetch -T 15 таймаут | ✅ |
| 36 | handle_fetch(): обновление метадаты только при "OK" | ✅ |
| 37 | rule_provider_tick(): только 1 провайдер за вызов | ✅ |
| 38 | fake_ip_enabled в UCI: option fake_ip_enabled '1' | ✅ |
| 39 | fake_ip_range в UCI: '198.51.100.0/24' | ✅ |
| 40 | fake_ip_ttl в UCI: '60' | ✅ |
| 41 | dns_server: fake-ip только для QTYPE=A + PROXY доменов | ✅ |
| 42 | dns_server: AAAA → NODATA для fake-ip доменов | ✅ |
| 43 | NFT_FAKE_IP_CIDR в nft_mode_set_rules: 198.51.100.0/24 перехватывается | ✅ |
| 44 | fake_ip_ready проверяется перед любым обращением к fake_ip_table | ✅ |
| 45 | fake_ip_free() вызывается в dns_server_cleanup() | ✅ |
| 46 | 198.51.100.0/24: RFC 5737 TEST-NET-2, не в bypass списке nftables | ✅ |
| 47 | geo_update.sh: 7 источников, атомарная замена .tmp → mv | ✅ |
| 48 | geo_update.sh: пороги (geosite≥100, opencck≥1000, cidr≥100) | ✅ |
| 49 | geo_update.sh: SIGHUP (kill -HUP), не SIGUSR1 или restart | ✅ |
| 50 | geo_update.sh: mkdir -p при отсутствии директории | ✅ |
| 51 | geo_convert.sh: busybox ash совместимость, нет bashisms | ✅ |
| 52 | geo_convert.sh: атомарная замена .new → mv | ✅ |
| 53 | geo_convert.sh: порог 100 строк, выход 1 если мало | ✅ |
| 54 | sub_convert.py: AWG поля jc/jmin/jmax/s1/s2/h1-h4/i1-i5/mtu/reserved | ✅ |
| 55 | _awg_i_field(): list → hex строка | ✅ |
| 56 | _awg_reserved(): list/string → "0,0,0" формат | ✅ |
| 57 | DST-PORT → 'DST_PORT' (не None) | ✅ |
| 58 | sub_convert.py import OK без ошибок | ✅ |

---

## Вердикт

**0 блокеров. 3 проблемы Medium, 3 замечания Low.**

Блоки 3.5 и 3.6 функционально корректны. Все 16 тест-таргетов проходят.
Проблемы П1–П3 не вызывают crash и не блокируют production deploy,
но требуют исправления перед следующим major audit.

**Приоритет исправлений:**
1. П3 (`uclient-fetch` без atomic) — может привести к partial file на следующем рестарте
2. П2 (geo swap при пустой загрузке) — потеря 877K доменов при пустом geo_dir
3. П1 (`dns_rules_init` без проверки) — тихая деградация при OOM reload

---

## Post-audit fixes (коммит 7c49a89)

| ID | Действие | Статус |
| -- | -------- | ------ |
| П1 | dns_rules_init() return проверяется при reload | ✓ |
| П2 | geo swap только если new_geo.count > 0 | ✓ |
| П3 | uclient-fetch → .tmp + rename | ✓ |
| З1 | NFT_FAKE_IP_CIDR → cfg->dns.fake_ip_range | ✓ |
| З2 | dns_rules_load_file мёртвый код удалён | ✓ |
| З3 | geo_convert.sh: grep + fallback на true при 0 совпадениях | ✓ |

**Итог: 0 блокеров, 0 открытых проблем.**
**4eburNet v1.0 — production ready.**

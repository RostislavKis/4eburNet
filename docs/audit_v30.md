# Devil Audit v30 — 4eburNet

> Дата: 2026-04-18
> Аудитор: Claude Code (Sonnet 4.6)
> Предыдущий: audit_v29 (0 блокеров, 228 OK)
> Скоуп: блок D (HTTP dashboard) + блок 3.5 (GeoIP/GeoSite) + накопленный код

## Итог

| Метрика | v29 | v30 |
|---------|-----|-----|
| Блокеров | 0 | 15 → **0** ✅ |
| Проблем | 8 | 33 |
| OK пунктов | 228 | 228+ |

## Закрытые блокеры (15/15)

| ID | Коммит | Описание |
|----|--------|---------|
| Б1-1 | 43de662 | dns_upstream_doq.c frames[2048] → heap |
| Б1-2 | 43de662 | dns_upstream_doq.c frames[1500] → heap |
| Б1-3 | 43de662 | http_server.c chunk[2048] → static |
| Б1-4 | 43de662 | dns_upstream_async.c b64[1024] → heap |
| Б1-5 | 43de662 | proxy_provider.c line[1024] → heap |
| Б1-6 | 43de662 | net_utils.c tls_conn_t → heap |
| Б1-7 | 43de662 | dns_upstream.c tls_conn_t × 2 → heap |
| Б3-1 | bd4f2d8 | http_server bind 127.0.0.1 вместо INADDR_ANY |
| Б3-2 | bd4f2d8 | /api/control Bearer токен из UCI |
| Б6-1 | 22ff9e9 | IPC race: EAGAIN → close → EOF клиента |
| Б6-2 | 22ff9e9 | IPC partial write → ipc_write_all() |
| Б8-1 | bd4f2d8 | rules_create_test_file() убрана из production |
| Б9-1 | 23c3804 | sub_convert.py AWG поля jc/jmin/jmax/s1-h4/i1-i5/mtu |
| Б10-1 | bd4f2d8 | Makefile cross-mipsel PROFILE=full → normal |
| Б12-1 | bd4f2d8 | 4eburnet.uci секреты заменены плейсхолдерами |

## Открытые проблемы (33, не блокеры)

Приоритет Medium (решить до v1.1):
- П1-1: relay_conn_t tls_conn_t inline 704KB NORMAL профиль
- П1-2: dns_cache_entry_t response[4096] × 256 = 1.1MB
- П4-4: geosite_check() безусловно на каждый DNS запрос
- П7-2: IPv6 CIDR O(n) вместо Patricia trie

Приоритет Low:
- П2-1..П2-4: wolfSSL мелкие нарушения
- П3-1..П3-2: HTTP bare-LF, popen в hot path
- П5-1..П5-5: dashboard детали
- П6-1..П6-3: IPC мелкие проблемы
- П7-1..П7-4: DNS/GeoIP оптимизации
- П8-2..П8-3: технический долг
- П9-2: DST-PORT в sub_convert
- П10-1: тесты -std=c11 vs gnu2x
- П11-1..П11-2: LuCI/JS детали
- П12-1: нет CI/CD
- П13-1..П13-2: деплой детали

## Вердикт

**0 блокеров. 4eburNet v1.0 готов к production деплою.**

Следующий этап: 3.6 Sniffer SNI → audit_v31 → release.

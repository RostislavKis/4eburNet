# 4eburNet — Devil Audit v11
**Дата:** 2026-04-11
**Охват:** B.5 — `hysteria2_cc.h`, `hysteria2_cc.c`, `Makefile.dev`
**Предыдущий аудит:** audit_v10 (все закрыты)

## 🔴 Критично — 1 находка

### #1 — Makefile: `full` профиль — все флаги кроме QUIC отключены
| Файл | Makefile.dev:29-31 |
|------|--------------------|
| Класс | CONFIG |

`else` блок (full профиль) содержал только `-DCONFIG_EBURNET_QUIC=1`.
VLESS/Trojan/SS/AWG/FakeIP/DoH/Sniffer/ProxyProviders не определены →
все `#if CONFIG_EBURNET_*` блоки отключены → production бинарник
работал, но не проксировал трафик.

**Закрыто:** восстановлены все 9 флагов для full профиля.

## 🟡 Важно — 4 находки

### #2 — brutal_cc_on_sent: BRUTAL_WINDOW_SIZE не применялся
`window_sent` рос без ограничений. CC не адаптировался без явного
вызова `brutal_cc_update()`. **Закрыто:** авто-update при
`window_sent >= BRUTAL_WINDOW_SIZE`.

### #3 — window_lost не ограничен window_sent
При двойном подсчёте потерь `loss_rate` мог превышать 1.0.
**Закрыто:** guard `if (window_lost < window_sent)`.

### #4 — brutal_cc_tick: sub-millisecond тики → bucket не пополнялся
`elapsed_us / 1000 = 0` при elapsed < 1 мс. Effective rate ниже цели.
**Закрыто:** `tick_remainder_us` накапливает sub-ms остатки.

### #5 — brutal_cc_get_rate: комментарий байт/с vs бит/с
Hysteria-CC-RX ожидает бит/с, функция возвращает байт/с без указания.
**Закрыто:** комментарий `get_rate(cc) * 8 → бит/с`.

## 🟢 Улучшения — 2 находки

### #6 — double вместо float в rate calculation
15 vs 7 значимых цифр. **Закрыто:** `double denom/scaled`.

### #7 — window_acked не используется в расчётах
Хранится и обновляется, но `brutal_cc_update` использует только
`window_sent` и `window_lost`. Оставлено для будущей sanity-check
интеграции (acked + lost <= sent).

## Сводка

| Уровень | Кол-во | Статус |
|---------|--------|--------|
| 🔴 | 1 | ✅ закрыто |
| 🟡 | 4 | ✅ закрыто |
| 🟢 | 2 | ✅ закрыто (6/7), #7 отложено |

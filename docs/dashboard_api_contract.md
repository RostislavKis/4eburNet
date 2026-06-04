
<!-- Статус: v1.4.0 реализован. Актуален на 2026-04-20.
     /api/devices реализован. Google Fonts CDN удалён (Z20). -->

# dashboard.html v2.0 — API контракт и архитектурные решения
# Зафиксировано: 2026-04-20

## ТЕМЫ
- Источник: docs/themes_extracted.css (43KB, 38 тем, 1271 строка)
- Вставить ПОЛНОСТЬЮ в <style> dashboard.html
- document.body.setAttribute('data-theme', value)  ← на BODY, не на html
- Дефолт: 'dark'
- Monet-темы: работают через fallback-значения в браузере (Material You если есть)

## ШРИФТЫ
- Основной: System UI (нет внешних зависимостей, нет CDN)
- Флаги-эмодзи: /usr/share/4eburnet/fonts/NotoColorEmoji-flagsonly-CWWDk9km.ttf
               /usr/share/4eburnet/fonts/TwemojiMozilla-flags-B12sb_Bp.woff2
- @font-face только для флагов — всё остальное системное

## CSS АРХИТЕКТУРА
- Темы: вставить themes_extracted.css (готово)
- Утилиты: писать вручную, использовать var(--color-*) из тем
- DaisyUI классы — БРАТЬ ТОЧНЫЕ ИМЕНА: btn btn-primary btn-sm,
  badge badge-sm, toggle toggle-sm, modal modal-box,
  collapse collapse-title collapse-content
- НЕ импортировать index-CbZ4wfHq.css — это Vue SPA бандл (1.5MB JS + 650KB CSS)

## LATENCY ПОРОГИ
- Зелёный: delay < 400ms  → text-green-500
- Жёлтый: 400 ≤ delay < 800ms → text-yellow-500
- Красный: delay ≥ 800ms  → text-red-500
- Нет данных (0 или null) → text-base-content/60 (серый)
- Пороги настраиваемые, дефолт 400/800

## TOOLTIP ДВИЖОК
- position: fixed, z-index: 99999
- Добавляется в document.body (не inline)
- JS: getBoundingClientRect() + viewport проверка
- Сверху если есть место (rect.top > 100), иначе снизу
- Делегирование через document.addEventListener('mouseover')
  на элементы с data-tip атрибутом

## API ENDPOINTS (актуально v1.3.x на EC330)

### Реализованы (используем сейчас):
GET  /api/status   → {version, uptime, profile, mode, running,
                       conn_active, dns_queries,
                       dpi_adapt_count, dpi_adapt_hits,
                       ech_connections, last_ech_type,
                       flow_offload, tc_fast,
                       last_ja3, ja3_expected, geo_loaded}

GET  /api/groups   → {groups: [{name, type, current,
                                servers: [{name, latency, history}]}]}

GET  /api/geo      → {files: [{name, size, count, bloom, loaded}]}

GET  /api/logs     → {lines: [...]}

POST /api/control  → {action: ..., ...params}
  Действия v1.3:
    start | stop | reload
    flow_offload_on | flow_offload_off    (async fork)
    tc_fast_on | tc_fast_off              (async fork)
    dpi_on | dpi_off | dpi_clear
    ja3_expected {hash: "32hex"}
    group_select {group, server}
    group_test {group}                    (async fork)
    cdn_update [{file}]

### Подписки + DNS-статистика (реализованы, v2.x):
GET  /api/dns/stats → {queries, cached, blocked, upstream_errors, hit_rate}
                      реальные атомарные счётчики g_stats (НЕ заглушка, audit_v53 §3)

POST /api/subscribe/parse  → превью серверов БЕЗ сохранения
                             тело: {data:"<подписка>"} или {url:"<URL>"}
                             форматы: base64, uri (vless/vmess/trojan/ss/hy2/tuic),
                                      clash YAML, sing-box (outbounds), SIP008 (servers)
                             ответ: [{name, protocol, address, port}, ...]

POST /api/subscribe/import → импорт в UCI (anon server) + commit + reload
                             тело: {data|url, target_group}
                             форматы: clash YAML, uri (vless/trojan/ss)
                             ответ: {added, errors}

### Нужны для v1.4 (показывать UI, graceful fallback если 404):
GET  /api/servers  → {servers: [{name, type, host, port, latency}]}
GET  /api/rules    → {rules: [{type, value, target, index}]}
GET  /api/providers → {providers: [{name, url, type, count, updated}]}
GET  /api/dns      → {upstream, fallback, proto, fake_ip, fake_ip_range, fake_ip_ttl}

POST /api/control v1.4:
    server_add {proto, name, ...fields}
    server_delete {name}
    provider_add {name, url, type, interval}
    provider_delete {name}
    provider_update {name}
    rule_add {type, value, target}
    rule_delete {index}
    rule_reorder {from, to}
    group_add {name, type, interval, url, tolerance}
    group_delete {group}
    dns_set {upstream, fallback, proto, fake_ip, fake_ip_range, fake_ip_ttl}
    dns_block_set {type: ads|trackers|threats, enabled: bool}

## POLLING ИНТЕРВАЛЫ
- /api/status:  5000ms  (configurable, localStorage '4eb_si')
- /api/groups:  5000ms  (configurable, localStorage '4eb_gi')
- /api/logs:    3000ms  (только активная вкладка, только !paused)
- /api/geo:    60000ms  (только активная вкладка)

## AUTH
- Bearer: headers: {Authorization: 'Bearer TOKEN'}
- Fallback: ?token=TOKEN в URL
- Токен: localStorage '4eb_token'

## СЕКЦИИ (14 разделов, data-p атрибут)
overview | groups | servers | providers | rules | devices |
connections | dns | dpi | geo | network | access | logs | settings

## РАЗМЕР ЦЕЛИ
- themes_extracted.css: 43KB
- logo base64: ~107KB
- HTML+CSS+JS: ~50KB
- Итого: ~200KB — допустимо

## AWG ВЕРСИИ (поля из user_context.md)
AWG 1.0: Jc Jmin Jmax H1 H2 H3 H4 S1 S2
AWG 1.5: + S3 S4 i1 i2 i3 i4 i5
AWG 2.0: + reserved(hex 3B) + key_derivation(v2|v1.5-compat)
Общие: name host port private_key public_key preshared_key
       allowed_ips mtu dns keepalive

## БЕЗОПАСНОСТЬ
- escHtml() на ВСЕХ строках из API перед innerHTML
- normId() для DOM id из имён групп/серверов
- ja3_expected: /^[0-9a-fA-F]{32}$/ валидация на клиенте
- fake_ip_ttl: default=10, max=60 (НЕ 60 по умолчанию)
- private_key: НЕ отображать в таблице серверов (только имя/хост/порт)

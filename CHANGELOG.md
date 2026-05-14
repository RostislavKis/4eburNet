# 4eburNet — Changelog

## v2.3.19 (2026-05-14) — audit_v49 §20

- fix(api): PATCH /api/devices — валидация policy против enum {proxy|bypass|block|default}
  произвольная строка записывалась в UCI без проверки; возвращает HTTP 400 при невалидном значении
- fix(devices): device_traffic_get() — передаётся raw arp[i].mac вместо esc_mac
  lookup функция ожидает оригинальный ключ, не escaped строку

## v2.3.18 (2026-05-14) — audit_v49 §17-19

- docs: дополнен CHANGELOG.md записями v2.3.7–v2.3.17
- chore: .gitignore — репо содержит только README + лого + CHANGELOG

## v2.3.17 (2026-05-14) — audit_v49 §16

- feat(test): smoke-тесты для hc_vmess_spawn — 6 PASS (T1-T4: NULL guards + ECONNREFUSED)
- feat(test): smoke-тесты для hc_anytls_spawn — 4 PASS (T1: NULL + T2: ECONNREFUSED)
- feat(test): smoke-тесты для hc_tuic_spawn — 4 PASS (T1: NULL + T2: QUIC недоступный UDP)
  Все три теста добавлены в test: и .PHONY: цели Makefile.dev
  tuic_uuid strncpy n=sizeof (не n-1) — поле ровно 37 байт

## v2.3.16 (2026-05-14) — audit_v49 §15

- fix(config): fallback DNS 1.1.1.1/8.8.8.8 UCI-configurable, dashboard controls

## v2.3.15 (2026-05-14) — audit_v49 §13

- fix(config): mixed_port, awg_itime — заменены strtoul без проверки на parse_int_uci
  WHY: strtoul(..., NULL, 10) принимал 0 и >65535 без предупреждения
- fix(config): port_min/port_max в traffic_rule — parse_int_uci с временным нуль-терминатором
  WHY: диапазон "50000-65535" мог дать port_min=65535 при беззнаковом переполнении
- fix(config): OOB write при переполнении MAX_DNS_RULES/MAX_DNS_POLICIES + LOG_WARN
  WHY: при dns_rule_count>=MAX_DNS_RULES секция оставалась SECTION_DNS_RULE,
  последующие option строки писали за пределами буфера (dns_rules[MAX_DNS_RULES])
  теперь section=SECTION_NONE при превышении — OOB устранён
- note: MAX_SERVERS=64 hard error намеренно; для >64 серверов использовать proxy_provider

## v2.3.14 (2026-05-14) — audit_v49 §12

- feat(dpi): DPI disorder strategy (DPI_STRAT_DISORDER=4), sniffer docs fix

## v2.3.13 (2026-05-14) — audit_v49 §11

- feat(dns): dns_static_hosts impl, IPC full-read loop, fake_ip6 default, dns_rule warn

## v2.3.12 (2026-05-13) — audit_v49 §10

- feat(api): DELETE /connections close-all, HTTP keep-alive, 204 No Content

## v2.3.11 (2026-05-13) — audit_v49 §9

- fix(geo): geo_match_domain_cat bloom OOB — bloom_nbits→suffix_bloom_nbits (L956)

## v2.3.10 (2026-05-13) — audit_v49 §8

- fix(pkg): remove kmod-nft-tproxy from DEPENDS, mark-based TPROXY only

## v2.3.9 (2026-05-13) — audit_v49 §7

- fix(epoll): DIRECT relay upstream — убран EPOLLOUT из начального EPOLL_CTL_ADD
  WHY: upstream уже подключён при RELAY_ACTIVE → EPOLLOUT в ADD вызывал spurious event
  добавлен EPOLL_CTL_MOD с EPOLLOUT только при EAGAIN от write() (dispatcher.c:2513-2528)
- fix(epoll): DIRECT relay — добавлен EPOLLRDHUP на client_fd и upstream_fd
  WHY: без EPOLLRDHUP half-close детектируется только через recv()=0, задержка закрытия
- fix(vision): удалён raw_fd splice dead code из vision.c/vision.h
  WHY: dispatcher всегда передавал raw_fd=-1, путь никогда не активировался
  убран параметр raw_fd из vision_raw_send(), обновлены 4 call-site

## v2.3.8 (2026-05-13) — audit_v49 §4

- fix(core): atomics→relaxed, hit_count saturation, monotonic timeout, selected_idx sentinel=-1

## v2.3.7 (2026-05-13) — audit_v49 §3

- fix(core): MIPS entry[1760]→static, snprintf truncation, global rate limit, Bearer ptr fix; docs IPC+ctx

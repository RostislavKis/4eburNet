### v2.3.17 (2026-05-14) — audit_v49 §16

- feat(test): smoke-тесты для hc_vmess_spawn — 6 PASS (T1-T4: NULL guards + ECONNREFUSED)
- feat(test): smoke-тесты для hc_anytls_spawn — 4 PASS (T1: NULL + T2: ECONNREFUSED)
- feat(test): smoke-тесты для hc_tuic_spawn — 4 PASS (T1: NULL + T2: QUIC недоступный UDP)
  Все три теста добавлены в test: и .PHONY: цели Makefile.dev
  tuic_uuid strncpy n=sizeof (не n-1) — поле ровно 37 байт

### v2.3.15 (2026-05-14) — audit_v49 §13

- fix(config): mixed_port, awg_itime — заменены strtoul без проверки на parse_int_uci
  WHY: strtoul(..., NULL, 10) принимал 0 и >65535 без предупреждения
- fix(config): port_min/port_max в traffic_rule — parse_int_uci с временным нуль-терминатором
  WHY: диапазон "50000-65535" мог дать port_min=65535 при беззнаковом переполнении
- fix(config): OOB write при переполнении MAX_DNS_RULES/MAX_DNS_POLICIES + LOG_WARN
  WHY: при dns_rule_count>=MAX_DNS_RULES секция оставалась SECTION_DNS_RULE,
  последующие option строки писали за пределами буфера (dns_rules[MAX_DNS_RULES])
  теперь section=SECTION_NONE при превышении — OOB устранён
- note: MAX_SERVERS=64 hard error намеренно; для >64 серверов использовать proxy_provider

### v2.3.9 (2026-05-13) — audit_v49 §7

- fix(epoll): DIRECT relay upstream — убран EPOLLOUT из начального EPOLL_CTL_ADD
  WHY: upstream уже подключён при RELAY_ACTIVE → EPOLLOUT в ADD вызывал spurious event
  добавлен EPOLL_CTL_MOD с EPOLLOUT только при EAGAIN от write() (dispatcher.c:2513-2528)
- fix(epoll): DIRECT relay — добавлен EPOLLRDHUP на client_fd и upstream_fd
  WHY: без EPOLLRDHUP half-close детектируется только через recv()=0, задержка закрытия
- fix(vision): удалён raw_fd splice dead code из vision.c/vision.h
  WHY: dispatcher всегда передавал raw_fd=-1, путь никогда не активировался
  убран параметр raw_fd из vision_raw_send(), обновлены 4 call-site

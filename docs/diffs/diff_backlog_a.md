# backlog_A — улучшения proxy_group и geo

**Дата:** 2026-04-07
**Коммиты:** backlog_A закрыт

## V6-07: measure_latency IPv4 + IPv6

proxy_group.c: заменён AF_INET хардкод на sockaddr_storage.
inet_pton(AF_INET) → inet_pton(AF_INET6) → WARN невалидный IP.
SOCK_CLOEXEC добавлен.

## V6-02: Patricia trie для geo_match_ip

geo_loader.h: ptrie_node_t структура + trie_v4 в geo_category_t.
geo_loader.c:
  - ptrie_alloc/free/insert/lookup
  - построение trie после загрузки категории
  - geo_match_ip: ptrie_lookup O(32) вместо O(n)
  - OOM fallback: ptrie_free → линейный скан
  - free_category_data: ptrie_free(c->trie_v4)

## V6-01: статус

connect() в measure_latency остаётся синхронным — это допустимо:
  - 1 сервер за tick (H-1 из аудита v5)
  - timeout из конфига (default 5000ms)
  - При доступном сервере RTT = 10-100ms, не блокирует ощутимо
  - При недоступном: до timeout_ms мс — приемлемо для 1 сервера

Полная async реализация (nonblock connect + EPOLLOUT) — в 4.x
вместе с DEC-031 async getaddrinfo.

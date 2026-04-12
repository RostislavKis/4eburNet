# 4eburNet — Ограничения проекта

## Жёсткие ограничения (нарушение = блокер релиза)

| Ограничение | Причина | Где проверяется |
|---|---|---|
| Стек MIPS: локальный буфер ≤ 512 байт | Стек 8KB на mipsel_24kc | audit_v25 §1 |
| Бинарник ≤ 4MB stripped | Flash 32MB на слабых роутерах | Makefile.dev: strip --strip-all |
| Без внешних зависимостей в runtime | musl static link, wolfSSL встроен | Makefile.dev: -static |
| Только nftables (fw4) | OpenWrt 22.03+, iptables legacy отключён | DEC-006 |
| Логи только в tmpfs (/tmp) | Flash wear protection | DEC-007, EBURNET_LOG_FILE |
| DNS BYPASS: никогда через DoH/DoT | Утечка паттерна трафика на DNS upstream | dns_server.c: action==BYPASS → udp_upstream |
| splice отключён | Data corruption на некоторых ядрах OpenWrt | DEC-016: shutdown(SHUT_WR) вместо splice |
| Flint 2 (192.168.1.1): запрет деплоя | Боевой роутер, живой интернет | deploy.sh:44-50: exit 99 |
| IPC tmp-файлы: 0600 + уникальное имя | Защита от TOCTOU и information disclosure | 4eburnet.uc: time()+random+chmod |
| wolfSSL 5.9.0 зафиксирована | Стабильность, воспроизводимость | dev-setup.sh:18 |

## Архитектурные решения (менять только с обоснованием)

| Решение | Код | Обоснование |
|---|---|---|
| C23 + musl static | DEC-001 | Минимум ресурсов, один бинарник |
| wolfSSL + uTLS fingerprint | DEC-002 | Reality маскировка под Chrome/Firefox |
| epoll + io_uring fallback | DEC-003 | Единый event loop, O(1) dispatch |
| Kconfig compile-time протоколы | DEC-004 | MICRO профиль без QUIC/Reality |
| Свой DNS :53, dnsmasq → :5353 | DEC-005 | Раздельный резолвинг RU/proxy |
| nft -f атомарное применение | DEC-011 | Нет окна пустых правил |
| Verdict Maps для 300K+ списков | DEC-017 | O(1) lookup вместо линейного |
| NTP Bootstrap перед wolfSSL | DEC-019 | TLS cert validation fails at 1970 |
| MAC per-device routing | DEC-020 | ether_addr sets в nftables |

## Профили устройств

| Профиль | RAM | Connections | QUIC/Reality | Буфер relay |
|---|---|---|---|---|
| MICRO | < 64MB | 256 | нет | 4KB |
| NORMAL | 64-128MB | 2048 | да | 16KB |
| FULL | 128MB+ | 16384 | да | 64KB |

# 4eburNet — Контекст проекта для Claude Code

## Что это
Собственный прокси-пакет для OpenWrt.
Полная замена mihomo + podkop + xray одним бинарником на C.
Цель: поддержка всех протоколов обхода, минимум ресурсов, работа на любом OpenWrt железе.

## Стек
- Язык: C23
- Libc: musl (статическая линковка)
- Крипто: wolfSSL (x25519, ChaCha20-Poly1305, AES-GCM, uTLS fingerprint)
- Сеть: nftables (только), epoll + io_uring fallback
- Интерфейс: LuCI (Lua)
- Сборка: OpenWrt SDK (Makefile)

## Правила кода (ОБЯЗАТЕЛЬНО)
- Все комментарии на русском языке
- Имена переменных и функций: английские, snake_case
- Коммиты: на русском, от первого лица, без упоминания AI
- Никаких следов AI в коде, комментариях, коммитах
- Запрещённые слова: utilize, leverage, implement, seamlessly,
  robust, ensure, "это решение позволяет", "данный подход"

## Ограничения (КРИТИЧНО)
- Бинарник ≤4MB
- Без внешних зависимостей в runtime
- Никаких iptables — только nftables API
- Логи только в tmpfs (/tmp)
- Поддержка OpenWrt 22.03+ (fw4), отказ от fw3/iptables legacy

## Целевые архитектуры
- x86_64      — QEMU VM (разработка)
- mipsel_24kc — слабые роутеры (128MB RAM, 32MB Flash)
- aarch64     — мощные роутеры (Flint 2)
- armv7       — средние роутеры

## Профили устройств
- MICRO  (<64MB RAM):  256 conn, без QUIC/Reality, буфер 4KB
- NORMAL (64-128MB):   2048 conn, все протоколы, буфер 16KB
- FULL   (128MB+):     16384 conn, статистика, буфер 64KB

## Приоритет протоколов (РФ/ТСПУ)
1. VLESS + XTLS-Reality  — топ-1, TCP, Vision flow = нулевой оверхед
2. VLESS + XHTTP         — топ-2, HTTP-чанки + padding
3. AmneziaWG (kmod)      — топ-3, UDP kernel-space
4. Trojan                — четвёртый
5. Shadowsocks 2022      — пятый (блокируется ТСПУ статистически)
6. VMess                 — legacy, только для совместимости

## Архитектурные правила nftables
- Verdict Maps для списков 300K+ (не обычные sets)
- Hardware Offload bypass: bypass-трафик в forward chain исключён из offload
- Атомарные обновления через nft -f /tmp/4eburnet_rules.nft
- MAC-based per-device routing через ether_addr sets

## DNS стек
- Свой демон на :53 (заменяет dnsmasq)
- dnsmasq переезжает на :5353 как fallback
- DoH через прокси для заблокированных доменов
- Раздельный резолвинг: RU-домены → провайдер, остальное → DoH
- Защита от DNS leak (IPv4 + IPv6)

## NTP Bootstrap
- При старте: HTTP Date Bootstrapper перед инициализацией wolfSSL
- Алгоритм: GET / к незаблокированному HTTP-хосту, парсинг Date: заголовка
- Без этого Reality не стартует (TLS cert validation fails at 1970)

## Failover (без перезапуска демона)
- Встроенный health-check каждые 30 сек через контрольный URL
- Авто-переключение между серверами без обрыва текущих соединений
- Приоритет серверов: Reality → XHTTP → прямой upstream

## Инфраструктура разработки
- SDK aarch64: ~/phoenix-router-dev/sdk/aarch64/sdk-aarch64/
- SDK mipsel:  ~/phoenix-router-dev/sdk/mipsel/sdk-mipsel/
- VM:   ssh -p 2222 root@localhost
- LuCI: http://localhost:8080

## НЕЛЬЗЯ ТРОГАТЬ
- 192.168.1.1 — боевой Flint 2, живой интернет

## Принятые решения
- DEC-001: C23 + musl static (не Rust, не Go, не Xray)
- DEC-002: wolfSSL с uTLS fingerprint для Reality
- DEC-003: io_uring + epoll fallback
- DEC-004: Kconfig compile-time флаги протоколов
- DEC-005: Свой DNS :53, dnsmasq → :5353
- DEC-006: nftables ONLY, fw4
- DEC-007: Логи только tmpfs
- DEC-008: QEMU VM для тестов
- DEC-009: Deploy SSH :2222
- DEC-010: nft subprocess v1
- DEC-011: nft -f файл атомарно
- DEC-012: ip subprocess v1
- DEC-013: DeviceProfile → device.h (долг)
- DEC-014: dispatcher отдельный epoll
- DEC-015: epoll data.ptr O(1)
- DEC-016: half-close shutdown(SHUT_WR)
- DEC-017: Verdict Maps для 300K+ списков
- DEC-018: HW Offload bypass в forward chain
- DEC-019: NTP Bootstrap перед wolfSSL init
- DEC-020: MAC per-device routing через ether_addr sets
- DEC-021: VLESS+Reality — первый реализуемый протокол (не SS2022)
- DEC-031: rule_provider getaddrinfo() async — вынести в dns_resolver (4.x)
# phoenix-router — Контекст проекта для Claude Code

## Что это
Собственный прокси-пакет для OpenWrt.
Полная замена mihomo + podkop + xray одним бинарником на C.
Цель: поддержка всех протоколов обхода, минимум ресурсов, работа на любом OpenWrt железе.

## Стек
- Язык: C23
- Libc: musl (статическая линковка)
- Крипто: wolfSSL
- Сеть: nftables (только), io_uring + epoll fallback
- Интерфейс: LuCI (Lua)
- Сборка: OpenWrt SDK (Makefile)

## Правила кода (ОБЯЗАТЕЛЬНО)
- Все комментарии на русском языке
- Имена переменных и функций: английские, snake_case
- Коммиты: на русском, от первого лица, без упоминания AI
- Никаких следов AI в коде, комментариях, коммитах
- Запрещённые слова в коде/комментариях: utilize, leverage, implement,
  seamlessly, robust, ensure, "это решение позволяет", "данный подход"

## Ограничения (КРИТИЧНО)
- Бинарник ≤4MB (Flash ограничение слабых роутеров)
- Без внешних зависимостей в runtime
- Никаких iptables — только nftables API
- Логи только в tmpfs (/tmp), не на Flash

## Целевые архитектуры
- x86_64     — QEMU VM (разработка и тесты)
- mipsel_24kc — слабые роутеры (EC330 и аналоги)
- aarch64    — мощные роутеры (Flint 2 и аналоги)

## Профили устройств
- MICRO  (<64MB RAM):  max 256 соединений, без QUIC, буфер 4KB
- NORMAL (64-128MB):   max 2048 соединений, все протоколы, буфер 16KB
- FULL   (128MB+):     max 16384 соединений, статистика, буфер 64KB

## Инфраструктура разработки
- SDK aarch64: ~/phoenix-router-dev/sdk/aarch64/sdk-aarch64/
- SDK mipsel:  ~/phoenix-router-dev/sdk/mipsel/sdk-mipsel/
- VM запуск:   ~/phoenix-router-dev/qemu/start-vm.sh
- VM сброс:    ~/phoenix-router-dev/qemu/reset-vm.sh
- VM снапшот:  ~/phoenix-router-dev/qemu/snapshot.sh save [имя]
- Деплой:      ./scripts/deploy.sh full
- Сборка:      ./scripts/build.sh x86_64

## SSH и доступ к VM
ssh -p 2222 root@localhost      <- VM
http://localhost:8080            <- LuCI VM (в браузере Windows)

## НЕЛЬЗЯ ТРОГАТЬ
- 192.168.1.1 — боевой роутер Flint 2, на нём живой интернет
- Любые команды на 192.168.1.1 — ЗАПРЕЩЕНО до финала проекта

## Текущая фаза
Этап 1 — реализация phoenixd (управляющий демон)
Следующий шаг: main.c, resource_manager.c, config.c, ipc.c

## Принятые решения (не обсуждать повторно)
- DEC-001: C23 + musl static (не Rust, не Go)
- DEC-002: wolfSSL (не OpenSSL, не mbedTLS)
- DEC-003: io_uring + epoll fallback (автодетект в runtime)
- DEC-004: Kconfig флаги для протоколов (compile-time)
- DEC-005: Свой DNS демон, dnsmasq переезжает на :5353
- DEC-006: nftables ONLY
- DEC-007: Логи только в tmpfs
- DEC-008: Тесты в QEMU VM, физический деплой позже

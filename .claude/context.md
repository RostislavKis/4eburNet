# Журнал разработки phoenix-router

## Сессия 001 — 2026-04-02
Статус: завершена
Сделано:
- Полный анализ требований и архитектурные решения
- Выбор стека: C23 + musl + wolfSSL + nftables
- Принято решений: DEC-001..007

## Сессия 002 — 2026-04-03 (утро)
Статус: завершена
Сделано:
- Настройка Ubuntu WSL2, все инструменты
- SDK aarch64 (OpenWrt 25.12.0) + mipsel (23.05.5)
- Структура проекта, первый коммит (46 файлов, 927 строк)
- QEMU VM OpenWrt 23.05.5 x86_64 (SSH :2222, LuCI :8080)
- EC330 убит (нет UART) → заменён VM
- DEC-008, DEC-009
Коммиты: 2893acd → 0b879b5 (4 коммита)

## Сессия 003 — 2026-04-03 (вечер)
Статус: завершена
Сделано:
- GUI режим VM (start-vm.sh обновлён)
- Создан CLAUDE.md и .claude/context.md
- Реализован phoenixd: resource_manager, config, ipc, main
- Бинарник: 109 KB (x86_64, не stripped) ✅
- Демон работает в VM, отвечает на IPC команды
- Тест: phoenixd status → {"status":"running","profile":"FULL","uptime":2}
Коммиты: 91585cd → 33133f0 (2 коммита, итого 6)
Строк кода: ~1090

## Сессия 004 — 2026-04-03
Статус: завершена
Сделано:
- Реализован routing/nftables.c (subprocess через nft)
- DEC-010: nft subprocess v1, netlink v2 позже
- DEC-011: nft -f файл для атомарных операций
- Таблица inet phoenix: 6 наборов, 3 цепочки, priority -200/-200/-150
- Режимы: rules/global/direct/tun — все работают
- TPROXY IPv4+IPv6 работает (kmod-nft-tproxy установлен в VM)
- Исправлен SIGHUP: без -d завершает, с -d reload
- Добавлен log_flush() перед cleanup
- QMP снапшоты: snapshot.sh и start-vm.sh обновлены
- Полный цикл: init → режим rules → stop → cleanup работает
Коммиты этой сессии: 3dc7b9b, da4ce46
Размер бинарника: 123 KB (x86_64, не stripped)

## Сессия 005 — 2026-04-04
Статус: завершена
Сделано:
- Реализован routing/policy.c (ip subprocess, DEC-012)
- IPv4+IPv6 симметричны: rule_exists/route_exists с параметром ipv6
- TPROXY цепочка полная: nftables fwmark → ip rule → ip route → loopback
- TUN заготовка готова (policy_init_tun)
- policy_check_conflicts: проверка таблиц 100/200 на чужие маршруты
- policy_dump: вывод ip rule + ip route table 100/200 в лог DEBUG
- Полный цикл init+cleanup подтверждён в VM
- QMP снапшоты работают (socat установлен, wsl -u root)
- passwordless sudo настроен для WSL
- Бинарник: 131 KB (x86_64, не stripped)
Коммиты: 3f946fb

## Сессия 006 — 2026-04-04
Статус: завершена
Сделано:
- Реализован proxy/tproxy.c (370 строк)
- Неблокирующий TCP+UDP сервер, epoll edge-triggered, timeout=0
- SO_ORIGINAL_DST для TCP, IP_ORIGDSTADDR cmsg для UDP
- IPv4 + IPv6, 4 сокета, rcvbuf по профилю (64K/256K/1MB)
- format_addr DEBUG лог в tproxy_accept_tcp
- dispatcher.c: логирует src→dst, закрывает fd (временно до 1.5)
- DEC-013: DeviceProfile вынести в device.h (технический долг)
- tproxy_state отдельная static в main.c (circular dep fix)
- Тест: 4 сокета на :7893, перехват подтверждён, cleanup чистый
Бинарник: 136 KB
Коммиты: 4ff083b

## Сессия 007 — 2026-04-04
Статус: завершена
Сделано:
- Полная перезапись proxy/dispatcher.c (637 строк)
- Неблокирующий relay через epoll, timeout=0
- DEC-014: отдельный epoll для relay
- DEC-015: epoll data.ptr → O(1) поиск relay
- splice() zero-copy с fallback read/write
- upstream_connect() через inet_pton (без getaddrinfo)
- proxy_protocol_t интерфейс: direct реализован, vless/ss/trojan в 1.6
- Исправлен баг: relay_alloc устанавливает RELAY_CONNECTING сразу
- Таймаут зависших соединений 60 сек
- Тест: relay 127.0.0.1:7893 → 127.0.0.1:9999 (echo), 12 байт прошли
- half-close (out:0) — ограничение v1, DEC-016 для 1.6
- Бинарник: 145 KB
Коммиты: c77c03a

## Сессия 008 — 2026-04-04
Статус: завершена
Сделано:
- nftables.c расширен: Verdict Maps для block/bypass (DEC-017)
- Фикс: auto-merge не поддерживается в verdict maps nft 1.0.8, убран
- nft_offload_bypass_init(): HW Offload bypass chain priority -300 (DEC-018)
- rules_loader.c: менеджер файлов правил, batch загрузка, mtime обновление
- rules_create_test_file(): 40 реальных RU CIDR для bypass
- ntp_bootstrap.c: raw TCP HTTP Date: парсинг, settimeofday (DEC-019)
- Интеграция в main.c: NTP → vmap → offload → rules → policy → tproxy
- Бинарник: 162 KB (+17KB)
- Тест: 40 RU CIDR в bypass_map, lookup 5.3.0.0/16 : accept работает
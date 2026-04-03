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
Коммиты этой сессии: (будут после коммита)
Размер бинарника: 123 KB (x86_64, не stripped)
# Аудит v3 волна 8: все LOW закрыты

Бинарник: 984 KB (0 errors, 0 warnings)

## Изменения по файлам

### core/Kconfig
- L-01: обновлён комментарий (INFO: Kconfig интеграция при портировании на SDK)

### core/Makefile
- L-08: удалена строка PKGARCH:=all (SDK определит архитектуру автоматически)

### core/Makefile.dev
- L-06: добавлен комментарий к StrictHostKeyChecking=no (dev QEMU VM only)
- L-07: параметризован WOLFSSL_PREFIX ?= /usr/local/musl-wolfssl

### core/src/config.c
- L-02: лог "list" keyword повышен с LOG_DEBUG до LOG_INFO
- L-04: strtol для порта теперь с endptr проверкой
- L-12: magic number 443 заменён на DEFAULT_SERVER_PORT

### core/src/resource_manager.c
- L-03: fopen заменён на open(O_RDONLY|O_CLOEXEC)+fdopen для /proc/meminfo и /proc/self/oom_score_adj

### core/src/main.c
- L-05: fscanf %d читает в int, затем каст в pid_t
- L-09: magic numbers 32/10 заменены на EPOLL_MAX_EVENTS/EPOLL_TIMEOUT_MS

### core/src/ipc.c
- L-10: magic number 5 заменён на IPC_LISTEN_BACKLOG (8)

### core/src/ntp_bootstrap.c
- L-11: hardcoded htons(80) заменён на NTP_HTTP_PORT

### core/include/dns/dns_cache.h
- L-13: добавлен комментарий к DNS_MAX_PACKET (EDNS0 совместимо)

### core/include/dns/dns_packet.h
- L-14: добавлен #include <stdbool.h>

### core/src/dns/dns_upstream.c
- L-15: http_req и http_buf перенесены на heap (malloc/free)

### core/src/dns/dns_server.c
- L-16: response и reply в handle_udp_query перенесены на heap; nxdomain использует reply буфер

### core/src/dns/dns_rules.c
- L-17: добавлена проверка integer overflow перед capacity + 256

### core/src/crypto/blake3.c
- L-18: добавлен комментарий о single-chunk ограничении (<= 1024 байт)

### core/src/crypto/tls.c
- L-19: комментарий о static tls_err_buf уже корректен (M-06), без изменений

### core/src/crypto/noise.c
- L-20: добавлен NOISE_REKEY_AFTER_MESSAGES (2^60), soft warning в noise_encrypt

### core/src/proxy/protocols/awg.c
- L-21: добавлен комментарий о modulo bias (пренебрежимо для обфускации)

### core/include/proxy/protocols/awg.h
- L-22: добавлен комментарий о 5 CPS строк по 256 байт (~10KB на 8 серверов)

### core/src/routing/nftables.c
- L-23: atoi() заменён на strtol() с endptr проверкой
- L-26: validate_cidr ужесточён: макс 1 слеш, после '/' только цифры, длина <= 43, без пробелов

### core/src/routing/rules_loader.c
- L-24: добавлена проверка path traversal (strstr "..")

### core/src/routing/device_policy.c
- L-25: realloc linear growth (+16) заменён на exponential (capacity * 2)

### docs/audit_v3.md
- Все L-01..L-26 отмечены как закрытые или принятые (INFO)
- Обновлена таблица статистики

# Аудит v4 волна 10 — все CRITICAL закрыты

**Дата**: 2026-04-05

## Изменения по файлам

### core/include/net_utils.h
- Добавлен `#include <stdint.h>`
- Добавлена декларация `net_random_bytes(uint8_t *buf, size_t len)` (C-01)

### core/src/net_utils.c
- Добавлены `#include <fcntl.h>`, `<errno.h>`, `<sys/syscall.h>`, `<stdint.h>`
- Добавлена функция `net_random_bytes()` — getrandom() с fallback на /dev/urandom (C-01)

### core/src/dns/dns_resolver.c
- Добавлен `#include "net_utils.h"`, `#include <errno.h>`
- upstream_id: `time(NULL) * LCG` заменён на `net_random_bytes()` с fallback (C-01)
- sendto(): добавлена проверка возврата, при ошибке — close(fd), active=false, return -1 (C-02)

### core/src/crypto/noise.c
- noise_decrypt(): удалён мёртвый код "sliding window" (Check 2), оставлен strict ordering (C-03)
- Комментарий: out-of-order через bitmap sliding window — в v2

### core/src/routing/nftables.c
- validate_nft_cmd(): `{}` убраны из forbidden (C-04, регрессия от v3 H-27)
- Добавлен комментарий про защиту через validate_cidr()/valid_nft_name()
- nft_set_add_addr(): добавлена проверка validate_cidr(cidr) (C-04)
- nft_set_del_addr(): добавлена проверка validate_cidr(cidr) (C-04)

### core/src/routing/device_policy.c
- Добавлены `#include <fcntl.h>`, `<sys/stat.h>`
- Удалён `#define DEVICE_NFT_TMP` с фиксированным путём
- device_policy_apply(): mkstemp("/tmp/phoenix_dev_XXXXXX") вместо фиксированного tmpfile (H-13)

### docs/audit_v4.md
- C-01, C-02, C-03, C-04 отмечены как ЗАКРЫТА (волна 10)
- H-13 отмечена как ЗАКРЫТА (волна 10)
- Статистика: CRITICAL 4/4, HIGH 1/14, итого 13/56

## Сборка
- 0 ошибок, 0 warnings
- Бинарник: 988 KB (было 971 KB, +17 KB от net_random_bytes + syscall)

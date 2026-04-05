# Audit v4 Wave 13 — L-03, L-07

## L-03: TAI64N offset из конфига

### config.h

```c
/* В PhoenixConfig добавлено: */
int tai_utc_offset;      /* TAI-UTC в секундах, default 37 */
```

### config.c

```c
/* Default при инициализации: */
cfg->tai_utc_offset = 37;  /* с 2017-01-01 */

/* Парсинг в SECTION_PHOENIX: */
} else if (strcmp(key, "tai_utc_offset") == 0) {
    long v = strtol(value, NULL, 10);
    cfg->tai_utc_offset = (v >= 0 && v <= 200) ? (int)v : 37;
```

### noise.h

```c
/* В noise_state_t добавлено: */
int tai_utc_offset;   /* TAI-UTC смещение в секундах (L-03) */

/* Обновлён прототип: */
int noise_init(noise_state_t *ns,
               const uint8_t local_priv[32],
               const uint8_t remote_pub[32],
               const uint8_t psk[32], bool has_psk,
               int tai_utc_offset);
```

### noise.c

```c
/* noise_init(): сохранение offset */
ns->tai_utc_offset = tai_utc_offset;

/* noise_handshake_init_create(): было TAI64N_BASE хардкод */
/* стало: */
uint64_t tai = (uint64_t)time(NULL) + 4611686018427387904ULL
             + (uint64_t)ns->tai_utc_offset;
```

### awg.h

```c
/* В awg_config_t добавлено: */
int tai_utc_offset;

/* Обновлён прототип: */
int awg_init(awg_state_t *awg, const void *server_config,
             int tai_utc_offset);
```

### awg.c

```c
/* awg_init(): передача offset в noise_init */
awg->cfg.tai_utc_offset = tai_utc_offset;
noise_init(&awg->noise, ..., tai_utc_offset);

/* awg_tick() retry: передача offset */
noise_init(&awg->noise, ..., awg->cfg.tai_utc_offset);
```

### dispatcher.c

```c
/* Передача offset из глобального конфига: */
awg_init(relay->awg, server,
         g_config ? g_config->tai_utc_offset : 37);
```

---

## L-07: DNS timeout через CLOCK_MONOTONIC

### dns_resolver.h

```c
/* Было: */
time_t    sent_at;              /* для таймаута */

/* Стало: */
struct timespec sent_at;        /* CLOCK_MONOTONIC (L-07) */
```

### dns_resolver.c

```c
/* dns_pending_add() — было: */
p->sent_at = time(NULL);
/* стало: */
clock_gettime(CLOCK_MONOTONIC, &p->sent_at);

/* dns_pending_check_timeouts() — полная замена: */
struct timespec now_mono;
clock_gettime(CLOCK_MONOTONIC, &now_mono);
#define DNS_TIMEOUT_SEC 2
for (int i = 0; i < DNS_PENDING_MAX; i++) {
    dns_pending_t *p = &q->slots[i];
    if (!p->active) continue;
    long elapsed_sec = now_mono.tv_sec - p->sent_at.tv_sec;
    if (elapsed_sec > DNS_TIMEOUT_SEC ||
        (elapsed_sec == DNS_TIMEOUT_SEC &&
         now_mono.tv_nsec >= p->sent_at.tv_nsec)) {
        /* таймаут */
    }
}
```

### main.c

```c
/* Было: каждые 100 итераций (~1с) с counter */
/* Стало: каждый тик (10ms), CLOCK_MONOTONIC дёшев */
if (cfg.dns.enabled && dns_state.initialized)
    dns_pending_check_timeouts(&dns_state.pending, master_epoll);
```

---

## Сборка

0 ошибок, 0 warnings. Бинарник: 988 KB.

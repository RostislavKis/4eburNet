# Phoenix Router — Audit v3

**Дата**: 2026-04-05
**Коммит**: 38ec342
**Строк кода**: 10622
**Файлов**: 56

---

## Критические (CRITICAL) — 14

### C-01 [crypto/blake2s.c:139-147] blake2s_hmac — не настоящий HMAC, ломает Noise/WireGuard — Ложное срабатывание — keyed BLAKE2s корректно для WireGuard spec
`blake2s_hmac` реализован как keyed BLAKE2s, а не как HMAC(ipad/opad) по RFC 2104.
Noise spec и WireGuard whitepaper требуют HMAC-BLAKE2s. Keyed BLAKE2s даёт другой
результат → HKDF2/HKDF3 выдают неверные ключи → handshake не совместим ни с одним
WireGuard пиром.
```c
void blake2s_hmac(...) {
    blake2s_keyed(out, outlen, key, keylen, in, inlen);
}
```
**Рекомендация:** Реализовать HMAC: `BLAKE2s((key ^ opad) || BLAKE2s((key ^ ipad) || data))`, block size 64.

### C-02 [crypto/noise.c:436-456] Нет replay protection в noise_decrypt — ✅ ЗАКРЫТА (волна 5)
`noise_decrypt` принимает любой counter с провода и просто устанавливает `recv_counter = ctr + 1`.
Нет проверки монотонности. Атакующий может переигрывать любой пакет.
```c
uint64_t ctr;
memcpy(&ctr, cipher + 8, 8);
// нет проверки ctr > recv_counter
ns->recv_counter = ctr + 1;
```
**Рекомендация:** Sliding window bitmap (минимум 64-bit) как в WireGuard.

### C-03 [crypto/noise.c:279-299, 367-374] Ключевой материал не обнуляется на стеке — ✅ ЗАКРЫТА (волна 5)
Множество функций оставляют DH shared secrets, PRK, temp ключи на стеке без zeroing:
- `noise_handshake_init_create`: `shared[32]`, `tag[16]`, `mac1_key[32]`
- `noise_handshake_response_process`: `shared[32]`, `temp[32]`
- `noise_hkdf2/3`: `prk[32]`
```c
uint8_t shared[32];
x25519_shared(..., shared);
// ... return без explicit_bzero(shared, 32)
```
**Рекомендация:** `explicit_bzero()` для всех буферов с ключевым материалом.

### C-04 [dns/dns_upstream.c:99-100] DoT — verify_cert=false, сертификат не проверяется — Принято — verify_cert=false намеренно для РФ use case
Все DoT подключения принимают любой сертификат. Атакующий на пути (ISP/ТСПУ) может
MITM DNS-over-TLS и подменить ответы.
```c
cfg.fingerprint = TLS_FP_NONE;
cfg.verify_cert = false;
```
**Рекомендация:** `verify_cert = true` по умолчанию.

### C-05 [dns/dns_upstream.c:225-226] DoH — verify_cert=false, та же проблема — Принято — verify_cert=false намеренно для РФ use case
```c
tls_cfg.fingerprint = TLS_FP_NONE;
tls_cfg.verify_cert = false;
```
**Рекомендация:** Аналогично C-04.

### C-06 [dns/dns_server.c:113-114] Блокирующий upstream DNS в event loop
Каждый upstream запрос блокирует main loop до 2 сек (UDP) / 5 сек (DoT/DoH).
Флуд DNS-запросами к некэшированным доменам = полный DoS прокси.
```c
/* TODO: перевести на асинхронный резолвинг — сейчас блокирует main loop */
```
**Рекомендация:** Неблокирующий резолвинг через epoll или thread pool.

### C-07 [proxy/tproxy.c:304] UDP iov_len = sizeof(pointer) вместо размера буфера — ✅ ЗАКРЫТА (волна 5)
`sizeof(buf)` = 8 на 64-bit, а не 65536. Все UDP дейтаграммы обрезаются до 8 байт.
```c
uint8_t *buf = malloc(TPROXY_UDP_BUF);
struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) }; // 8!
```
**Рекомендация:** Заменить `sizeof(buf)` на `TPROXY_UDP_BUF`.

### C-08 [proxy/protocols/shadowsocks.c:296-317] SS recv: данные больше buflen теряются — ✅ ЗАКРЫТА (волна 6)
Когда расшифрованный чанк > buflen, лишние байты безвозвратно уничтожаются.
```c
memcpy(buf, tmp, buflen);  // копируем только buflen
free(tmp);                  // ОСТАТОК ПОТЕРЯН
```
**Рекомендация:** Буферизовать остаток в `ss_state_t` для следующего вызова `ss_recv`.

### C-09 [proxy/protocols/shadowsocks.c:69-78, 87-92] Nonce increment при неудачной AEAD операции — ✅ ЗАКРЫТА (волна 5)
`nonce_increment()` вызывается после encrypt/decrypt независимо от результата.
При ошибке nonce десинхронизируется — все последующие пакеты нерасшифровываемы.
```c
int rc = wc_ChaCha20Poly1305_Encrypt(...);
nonce_increment(nonce);  // даже если rc != 0
return rc;
```
**Рекомендация:** Инкрементировать nonce только при `rc == 0`.

### C-10 [routing/policy.c:214-215] Command injection через `dev` в policy_init_tun() — ✅ ЗАКРЫТА (волна 5)
Параметр `dev` подставляется в shell команду без валидации.
```c
snprintf(cmd, sizeof(cmd), "route add default dev %s table 200", dev);
```
**Рекомендация:** Валидировать `dev` против `^[a-zA-Z0-9._-]+$`, max IFNAMSIZ.

### C-11 [routing/device_policy.c:155-156] Command injection через lan_iface — ✅ ЗАКРЫТА (волна 5)
`lan_iface` вставляется в nft конфиг в двойных кавычках без валидации.
```c
fprintf(f, "... device \"%s\" priority -300;\n", lan_iface);
```
**Рекомендация:** Валидировать против `^[a-zA-Z0-9._-]+$`.

### C-12 [routing/device_policy.c:146] NFT injection через mac_str — ✅ ЗАКРЫТА (волна 5)
MAC адрес из конфига пишется в verdict map без валидации формата.
```c
fprintf(f, " %s : goto %s", d->mac_str, chain);
```
**Рекомендация:** Валидировать MAC: `^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$`.

### C-13 [routing/nftables.c:290-296] NFT injection через set_name — ✅ ЗАКРЫТА (волна 5)
`set_name` и `map_name` подставляются в nft команды без валидации.
`validate_nft_cmd()` не ловит `}` и `#` которые являются nft метасимволами.
```c
snprintf(cmd, sizeof(cmd),
         "add element inet " NFT_TABLE_NAME " %s { %s }", set_name, cidr);
```
**Рекомендация:** Валидировать: `^[a-zA-Z_][a-zA-Z0-9_]*$`.

### C-14 [crypto/blake2s.c:69-83] blake2s_init: buffer overflow при keylen > 64 — ✅ ЗАКРЫТА (волна 5)
Нет валидации keylen ≤ 32 / outlen ≤ 32. При keylen > 64 — переполнение стекового буфера.
```c
uint8_t block[BLAKE2S_BLOCK] = {0};  // 64 байта
memcpy(block, key, keylen);           // overflow если keylen > 64
```
**Рекомендация:** `if (keylen > 32 || outlen == 0 || outlen > 32) abort();`

---

## Высокие (HIGH) — 28

### H-01 [crypto/noise.c:304] TAI64N смещение неверное — ✅ ЗАКРЫТА (волна 5)
Используется `+4611686018427387914` (2^62 + 10), но TAI-UTC = 37 сек (с 2017-01-01).
Правильно: `4611686018427387941ULL` (2^62 + 37).
```c
uint64_t tai = (uint64_t)time(NULL) + 4611686018427387914ULL;
```
**Рекомендация:** Исправить на `4611686018427387904ULL + 37`.

### H-02 [crypto/noise.c:422] Нет REJECT_AFTER_MESSAGES — nonce может переполниться — ✅ ЗАКРЫТА (волна 6)
`send_counter++` без проверки на 2^64. WireGuard: REJECT_AFTER_MESSAGES = 2^64 - 2^16 - 1.
```c
uint64_t ctr = ns->send_counter++;
```

### H-03 [crypto/noise.c:178-179] getrandom() partial read не обрабатывается — ✅ ЗАКРЫТА (волна 6)
Short read или EINTR от getrandom() молча переходит к /dev/urandom fallback.

### H-04 [crypto/noise.c:401-406] Нет REJECT_AFTER_TIME (180 сек) — ✅ ЗАКРЫТА (волна 6)
Ключи handshake не имеют TTL. WireGuard требует rekeying после 180 секунд.

### H-05 [crypto/tls.c:187-189] reality_key/reality_short_id — сырые указатели, не deep copy — ✅ ЗАКРЫТА (волна 6)
При перезагрузке конфига — dangling pointer.
```c
conn->config.reality_key = config->reality_key;
```

### H-06 [crypto/noise.c:165-166] x25519_generate: return values не проверяются — ✅ ЗАКРЫТА (волна 5)
```c
wc_curve25519_export_private_raw(&key, priv, &plen);
wc_curve25519_export_public(&key, pub, &plen);
```

### H-07 [src/net_utils.c:37-65] Shell injection через popen() — системный риск — ✅ ЗАКРЫТА (волна 6)
Все `exec_cmd*` передают строку напрямую в `popen()` = `/bin/sh -c`.
**Рекомендация:** `exec_argv()` через `posix_spawn` / `fork+execvp`.

### H-08 [src/main.c:123] open("/dev/null") без O_CLOEXEC в daemonize() — ✅ ЗАКРЫТА (волна 6)
```c
int devnull = open("/dev/null", O_RDWR);
```

### H-09 [src/main.c:391] epoll_ctl return value не проверяется — ✅ ЗАКРЫТА (волна 6)
```c
epoll_ctl(master_epoll, EPOLL_CTL_ADD, listen_fds[i], &mev);
```

### H-10 [src/ipc.c:83-84] IPC recv без retry при EAGAIN/short read — ✅ ЗАКРЫТА (волна 6)
```c
ssize_t n = recv(client_fd, &hdr, sizeof(hdr), MSG_DONTWAIT);
if (n != sizeof(hdr)) { ... }
```

### H-11 [src/ipc.c:193-194] IPC response read без loop для short reads — ✅ ЗАКРЫТА (волна 6)

### H-12 [src/ntp_bootstrap.c:152-153] Время из неаутентифицированного HTTP ответа — ✅ ЗАКРЫТА (волна 6+7)
Атакующий через MITM может установить произвольное время → TLS replay.
Sanity check добавлен (волна 6), warning о ненадёжности (волна 7). Принято как ограничение v1.

### H-13 [dns/dns_server.c:157-232] DNS amplification — нет rate limiting — ✅ ЗАКРЫТА (волна 7)
DNS сервер на INADDR_ANY без ограничения по rate и без проверки source IP.
**Рекомендация:** Биндить только на LAN, добавить per-source-IP rate limiting.

### H-14 [dns/dns_packet.c:122-129] DNS compression pointer loop → OOB read — ✅ ЗАКРЫТА (волна 5)
`pos += 1 + reply[pos]` без проверки `pos + 1 + reply[pos] <= len`.
```c
while (pos < len && reply[pos] != 0) {
    pos += 1 + reply[pos];  // может выйти за пределы
}
```

### H-15 [dns/dns_packet.c:134-147] Answer section parsing — та же OOB проблема — ✅ ЗАКРЫТА (волна 5)

### H-16 [dns/dns_rules.c:72-80] Partial realloc leak — ✅ ЗАКРЫТА (волна 5)
Если `np` успешен но `na` неуспешен — `np` утекает, `g_rules.patterns` = старый указатель.

### H-17 [dns/dns_rules.c:32, 82] strdup без проверки NULL — ✅ ЗАКРЫТА (волна 5)
NULL от strdup записывается в массив → segfault при strcmp().

### H-18 [dns/dns_server.c:235-292] TCP DNS handler блокирует event loop до 3+ сек — Принято (async TCP DNS → v2, SO_RCVTIMEO=2s)

### H-19 [proxy/dispatcher.c:608] SS relay: partial write → возврат n вместо w — ✅ ЗАКРЫТА (волна 6)
```c
ssize_t w = write(r->client_fd, ds->relay_buf, n);
return (w > 0) ? n : w;  // должно быть w, не n
```

### H-20 [proxy/dispatcher.c:624] TLS relay: partial write не обрабатывается — ✅ ЗАКРЫТА (волна 6)

### H-21 [proxy/protocols/shadowsocks.c:183-188] SS handshake: partial write = fatal error — ✅ ЗАКРЫТА (волна 6)
На nonblocking сокете write() может вернуть short write. Данные уже отправлены частично.

### H-22 [proxy/protocols/shadowsocks.c:243-248] SS send: та же проблема — ✅ ЗАКРЫТА (волна 6)

### H-23 [proxy/protocols/vless.c:130-159] Блокирующий select() loop 5 сек в event loop — ✅ ЗАКРЫТА (волна 6)
**Рекомендация:** Удалить блокирующий `vless_read_response`, оставить только step API.

### H-24 [proxy/protocols/awg.c:231-237] Stack buffer overflow через user-controlled padding — ✅ ЗАКРЫТА (волна 5)
`awg_add_padding` пишет `pad` байт за `pkt_len` без проверки размера буфера.
При `s1=65535` из конфига → переполнение 1536-байтного стекового буфера.
```c
random_fill(pkt + pkt_len, pad);  // нет проверки границ
```

### H-25 [proxy/protocols/awg.c:53-54] random_u32 возвращает 0 при ошибке — ✅ ЗАКРЫТА (волна 6)
Все обфускация AWG становится детерминированной (нулевой).

### H-26 [proxy/protocols/shadowsocks.c:44-51] /dev/urandom без O_CLOEXEC — ✅ ЗАКРЫТА (волна 6)
```c
int fd = open("/dev/urandom", O_RDONLY);
```

### H-27 [routing/nftables.c:57] validate_nft_cmd: неполный blocklist — ✅ ЗАКРЫТА (волна 5)
Пропущены: `\n`, `{`, `}`, `#`, `'`, `"`. Blacklist подход ненадёжен.
**Рекомендация:** Whitelist подход.

### H-28 [routing/nftables.c:102-109] TOCTOU: предсказуемый tmpfile /tmp/phoenix_nft.conf — ✅ ЗАКРЫТА (волна 5)
```c
FILE *f = fopen(NFT_TMP_CONF, "w");
fclose(f);
// окно для атаки
exec_cmd_capture("nft -f " NFT_TMP_CONF);
```
**Рекомендация:** `mkstemp()` + 0600.

---

## Средние (MEDIUM) — 38

### M-01 [config.c:207-208] strcpy на fixed-size буферах — ✅ ЗАКРЫТА (волна 7)

### M-02 [main.c:92-97] PID file write без error handling — ✅ ЗАКРЫТА (волна 7)

### M-03 [main.c:70, 92] fopen без CLOEXEC (PID file) — ✅ ЗАКРЫТА (волна 7)

### M-04 [main.c:304-308] Стековые буферы path 512 байт + large cfg struct — ✅ ЗАКРЫТА (волна 7)

### M-05 [main.c:450-451] master_epoll close перед goto cleanup label — ✅ ЗАКРЫТА (волна 7)

### M-06 [log.c:47] Log file fopen без CLOEXEC — ✅ ЗАКРЫТА (волна 7)

### M-07 [log.c:72-73] Отрицательный level → OOB access на level_names[] — ✅ ЗАКРЫТА (волна 7)

### M-08 [config.c:166-178] AWG поля без range validation (uint16_t/uint8_t cast) — ✅ ЗАКРЫТА (волна 7)

### M-09 [config.c:338] cache_size без проверки >= 0 — ✅ ЗАКРЫТА (волна 7)

### M-10 [main.c:356] sigaction sa_flags не задан явно (нет SA_RESTART) — ✅ ЗАКРЫТА (волна 7)

### M-11 [ipc.c:56] chmod TOCTOU на IPC socket — ✅ ЗАКРЫТА (волна 7)

### M-12 [main.c:362] signal() вместо sigaction() для SIGPIPE — ✅ ЗАКРЫТА (волна 7)

### M-13 [ipc.c:24] IPC длина ответа truncated к uint16_t — ✅ ЗАКРЫТА (волна 7)

### M-14 [crypto/noise.c:134, 217] wc_curve25519_import_private может не делать clamping — ✅ ЗАКРЫТА (волна 7)

### M-15 [crypto/noise.c:287-291] aead_encrypt return value не проверяется в handshake — ✅ ЗАКРЫТА (волна 7)

### M-16 [crypto/noise.c:280-281] x25519_shared return value игнорируется в handshake — ✅ ЗАКРЫТА (волна 7)

### M-17 [crypto/noise.c:205-248] noise_state_t не обнуляется при ошибке noise_init — ✅ ЗАКРЫТА (волна 7)

### M-18 [crypto/tls.c:276-280] select() с fd >= FD_SETSIZE → UB — ✅ ЗАКРЫТА (волна 7)

### M-19 [dns/dns_cache.c:9] DNS_MAX_PACKET=512 — нет EDNS0 — ✅ ЗАКРЫТА (волна 7)

### M-20 [dns/dns_cache.c:12-19] Слабый хеш djb2 — уязвим к collision атакам — ✅ ЗАКРЫТА (волна 7)

### M-21 [dns/dns_upstream.c:173] Base64 буфер может быть мал при увеличении пакета — ✅ ЗАКРЫТА (волна 7)

### M-22 [dns/dns_upstream.c:234-242] HTTP header injection через CRLF в DoH URL — ✅ ЗАКРЫТА (волна 7)

### M-23 [dns/dns_server.c:97-110] epoll_ctl return values не проверяются — ✅ ЗАКРЫТА (волна 7)

### M-24 [dns/dns_server.c:288] write() return value не проверяется (TCP DNS) — ✅ ЗАКРЫТА (волна 7)

### M-25 [dns/dns_server.c:181-182] sendto() return value не проверяется (UDP DNS) — ✅ ЗАКРЫТА (волна 7)

### M-26 [dns/dns_cache.c:70-76] Expired entry corruption в LRU — ✅ ЗАКРЫТА (волна 7)

### M-27 [dns/dns_upstream.c:248-256] DoH ответ не обрабатывает chunked encoding — ✅ ЗАКРЫТА (волна 7)

### M-28 [dns/dns_upstream.c:236] HTTP/1.1 но поведение HTTP/1.0 — ✅ ЗАКРЫТА (волна 7)

### M-29 [dns/dns_rules.c:111-132] O(n) linear scan на каждый DNS запрос (300K+ правил) — Принято (TODO v2, допустимо при < 10K)

### M-30 [proxy/vless_xhttp.c:312] Chunk size без upper bound — ✅ ЗАКРЫТА (волна 7)

### M-31 [proxy/vless_xhttp.c:46-51] Слабый fallback session ID (pid+time) — ✅ ЗАКРЫТА (волна 7)

### M-32 [proxy/protocols/awg.c:102-109] CPS hex parser без bounds check на p[1] — ✅ ЗАКРЫТА (волна 7)

### M-33 [proxy/protocols/vless.c:313-318] vless_read_response_step не читает addons bytes — ✅ ЗАКРЫТА (волна 7)

### M-34 [proxy/protocols/shadowsocks.c:206-207] ss_send: len > 0x3FFF возвращает -1, данные потеряны — ✅ ЗАКРЫТА (волна 7)

### M-35 [routing/nftables.c:179] 16KB стековый буфер config[NFT_ATOMIC_MAX] — ✅ ЗАКРЫТА (волна 7)

### M-36 [routing/device_policy.c:253-264] snprintf unsigned underflow в to_json — ✅ ЗАКРЫТА (волна 7)

### M-37 [routing/nftables.c:604-605] fclose(NULL) при ошибке batch reopen → UB — ✅ ЗАКРЫТА (волна 7)

### M-38 [routing/device_policy.c:166-189] delete+apply без rollback — Принято (TODO, операция редкая)

---

## Низкие (LOW) — 26

### L-01 [Kconfig:2] TODO: Kconfig не используется в коде — ✅ Принято INFO (волна 8)
### L-02 [config.c:395-396] "list" keyword молча игнорируется — ✅ ЗАКРЫТА (волна 8)
### L-03 [resource_manager.c:9, 83] fopen без CLOEXEC (/proc/*) — ✅ ЗАКРЫТА (волна 8)
### L-04 [config.c:129] strtol без endptr check (port) — ✅ ЗАКРЫТА (волна 8)
### L-05 [main.c:75] fscanf %d для pid_t — ✅ ЗАКРЫТА (волна 8)
### L-06 [Makefile.dev:26] SSH StrictHostKeyChecking=no — ✅ ЗАКРЫТА (волна 8)
### L-07 [Makefile.dev:2] Hardcoded path /usr/local/musl-wolfssl — ✅ ЗАКРЫТА (волна 8)
### L-08 [Makefile:17] PKGARCH:=all для C бинарника — ✅ ЗАКРЫТА (волна 8)
### L-09 [main.c:409] Magic numbers 32/10 для epoll events/timeout — ✅ ЗАКРЫТА (волна 8)
### L-10 [ipc.c:58] Magic number 5 для listen backlog — ✅ ЗАКРЫТА (волна 8)
### L-11 [ntp_bootstrap.c:88] Hardcoded port 80 — ✅ ЗАКРЫТА (волна 8)
### L-12 [config.c:132] Magic number 443 default port — ✅ ЗАКРЫТА (волна 8)
### L-13 [dns/dns_cache.h:9] DNS_MAX_PACKET определён в cache header — ✅ Принято INFO (волна 8)
### L-14 [dns/dns_packet.h:12] Нет #include <stdbool.h> — ✅ ЗАКРЫТА (волна 8)
### L-15 [dns/dns_upstream.c:235] Stack 6KB (http_req[2048]+http_buf[4096]) — ✅ ЗАКРЫТА (волна 8)
### L-16 [dns/dns_server.c:158] Stack ~16KB в handle_udp_query — ✅ ЗАКРЫТА (волна 8)
### L-17 [dns/dns_rules.c:25-28] Integer overflow в capacity + 256 — ✅ ЗАКРЫТА (волна 8)
### L-18 [crypto/blake3.c] Поддержка только < 1024 байт (single chunk) — ✅ Принято INFO (волна 8)
### L-19 [crypto/tls.c:24] tls_err_buf static — не thread-safe — ✅ Принято INFO (волна 8)
### L-20 [crypto/noise.c] Нет REKEY_AFTER_MESSAGES (2^60) — ✅ ЗАКРЫТА (волна 8)
### L-21 [proxy/protocols/awg.c:60] rand_in_range modulo bias — ✅ Принято INFO (волна 8)
### L-22 [proxy/protocols/awg.h:28] CPS строки 5×256 = 1280 байт в структуре — ✅ Принято INFO (волна 8)
### L-23 [routing/nftables.c:971] atoi() без error check — ✅ ЗАКРЫТА (волна 8)
### L-24 [routing/rules_loader.c:96] Нет проверки path traversal — ✅ ЗАКРЫТА (волна 8)
### L-25 [routing/device_policy.c:59-60] realloc linear growth (+16) — ✅ ЗАКРЫТА (волна 8)
### L-26 [routing/nftables.c:39-52] validate_cidr слишком permissive — ✅ ЗАКРЫТА (волна 8)

---

## Информационные (INFO) — 21

### I-01 [main.c:133] chdir("/") ошибка игнорируется — корректно
### I-02 [ipc.c:129-131] Stats bytes_in/bytes_out = 0 — незавершённая фича
### I-03 [config.h:25] ServerConfig ~2KB из-за AWG полей (5×256)
### I-04 [phoenix.h:39] LOG_MAX_BYTES — compile-time, нет runtime override
### I-05 [main.c:415-416] dns_state fd=0 может совпасть с реальным fd
### I-06 [ntp_bootstrap.c:81] setsockopt return values не проверяются
### I-07 [config.c:9] MAX_LINE 1024 — длинные строки обрезаются
### I-08 [crypto] blake2s sigma table, IV, BLAKE3 MSG_SCHEDULE — корректны
### I-09 [crypto] AEAD nonce format корректен (LE 64-bit в bytes 4-11)
### I-10 [crypto] /dev/urandom с O_CLOEXEC в noise.c — корректно
### I-11 [crypto] Нет TODO/FIXME/HACK/XXX в crypto файлах
### I-12 [crypto] MAC comparison через wolfSSL constant-time внутри
### I-13 [crypto] Стековые буферы в crypto < 1KB
### I-14 [dns/dns_server.c:113] TODO marker — async DNS
### I-15 [dns/dns_cache.h:28] reply_buf shared — fragile API
### I-16 [dns/dns_rules.c:106-132] Приоритет правил зависит от enum values
### I-17 [dns/dns_upstream.c:179] doh_sni содержит IP, не SNI — confusing naming
### I-18 [proxy/dispatcher.c:98-99] verify_cert=false для всех протоколов — намеренно
### I-19 [proxy/vless.c:97] SNI = server address — может быть IP (fingerprintable)
### I-20 [routing/nftables.c:8] DEC-010: subprocess v1, netlink v2 "потом"
### I-21 [routing/policy.c:8] DEC-012: ip subprocess v1, RTNETLINK v2 "потом"

---

## Статистика

| Категория | Найдено | Закрыто | Принято/Ложное | Открыто |
|-----------|---------|---------|----------------|---------|
| CRITICAL  |   14    |   10    |       3        |    1    |
| HIGH      |   28    |   25    |       1        |    2    |
| MEDIUM    |   38    |   36    |       2        |    0    |
| LOW       |   26    |   20    |       6        |    0    |
| INFO      |   21    |   21    |       0        |    0    |
| **ИТОГО** | **127** | **112** |    **12**      |  **3**  |

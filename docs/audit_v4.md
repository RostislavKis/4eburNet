# Phoenix Router — Audit v4

**Дата**: 2026-04-05
**Коммит**: 598cb56
**Строк кода**: 11678
**Файлов**: 58

---

## Критические (CRITICAL) — 4

### C-01 [dns/dns_resolver.c:42] ~~Предсказуемый upstream_id → DNS cache poisoning
`upstream_id` генерируется из `time(NULL) * LCG + idx` — предсказуем.
Атакующий в LAN может подобрать ID за ~128 попыток (Kaminsky-style атака).
```c
uid = (uint16_t)((time(NULL) * 1103515245 + idx) & 0xFFFF);
```
**Рекомендация:** getrandom() для генерации upstream_id.

> **СТАТУС: ЗАКРЫТА (волна 10).** net_random_bytes() через getrandom/urandom.

### C-02 [dns/dns_resolver.c:76-77] ~~sendto() ошибка → утечка fd в epoll
Return value sendto() игнорируется. При ENETUNREACH все 64 слота
заполняются zombie-записями, DNS полностью недоступен до таймаута 2с.
```c
sendto(p->upstream_fd, p->query, p->query_len, 0, ...);
q->count++;
return idx;  // всегда "успех"
```
**Рекомендация:** Проверять sendto(), при ошибке закрывать fd, возвращать -1.

> **СТАТУС: ЗАКРЫТА (волна 10).** sendto() с проверкой, zombie slot cleanup.

### C-03 [crypto/noise.c:537-545] ~~Replay protection — sliding window мёртвый код
Check 1 (строка 537) отклоняет ВСЕ пакеты с `ctr <= recv_counter - 1`.
Check 2 (строка 545, "sliding window") никогда не достигается — dead code.
Результат: строгий порядок, нет out-of-order tolerance.
```c
if (ns->recv_counter > 0 && ctr <= ns->recv_counter - 1) return -1; // ← ловит ВСЁ
if (ns->recv_counter > 64 && ctr < ns->recv_counter - 64) return -1; // ← dead code
```
**Рекомендация:** Либо удалить Check 2 (принять strict ordering), либо реализовать bitmap sliding window.

> **СТАТУС: ЗАКРЫТА (волна 10).** Dead code удалён, strict ordering.

### C-04 [routing/nftables.c:81-88,335-346] ~~validate_nft_cmd блокирует {} → nft_set_add/del_addr мёртвый код
РЕГРЕССИЯ от v3 H-27: `{}` добавлены в forbidden, но nft_set_add_addr использует `{ %s }`.
Все вызовы nft_exec с set element add/delete молча отклоняются validate_nft_cmd.
```c
const char *forbidden = "|&;`$()<>'\"{}#\n\r\\";  // {} запрещены
// ...
snprintf(cmd, ..., "add element inet phoenix %s { %s }", set_name, cidr);
nft_exec(cmd);  // validate_nft_cmd → false → NFT_ERR_EXEC
```
**Рекомендация:** Убрать `{}` из forbidden, добавить validate_cidr() на cidr параметр.

> **СТАТУС: ЗАКРЫТА (волна 10).** {} убраны из forbidden, validate_cidr() добавлен.

---

## Высокие (HIGH) — 14

### H-01 [proxy/shadowsocks.c:207-221] ~~SS handshake: header_sent=true даже при partial write~~
EAGAIN выходит из write loop, но `header_sent = true` ставится безусловно.
Сервер получает обрезанный header → протокол сломан.

> **СТАТУС: ЗАКРЫТА (волна 11).** EAGAIN = fatal return -1 для framed SS 2022.

### H-02 [proxy/shadowsocks.c:276-292] ~~SS send_chunk: возвращает len при partial write~~
write loop прерывается на EAGAIN, но функция возвращает `(ssize_t)len`.
Framed SS 2022 пакет обрезан на проводе — поток десинхронизирован.

> **СТАТУС: ЗАКРЫТА (волна 11).** EAGAIN = fatal return -1 для framed SS 2022.

### H-03 [proxy/vless.c:315-320] ~~VLESS addons_len > 0 → stream corruption (TODO не закрыт)~~
addons байты не вычитываются, следующий tls_recv читает мусор как данные.
Reality серверы могут отправлять addons → гарантированная порча потока.

> **СТАТУС: ЗАКРЫТА (волна 11).** Addons вычитываются через step API, resp_buf[3].

### H-04 [crypto/noise.c:184-185] ~~Clamping после export → pub/priv несовместимость~~
clamp_curve25519_key(priv) после export_private, но pub экспортирован из оригинального key.
Если wolfSSL export_private отдаёт unclamped ключ — pub не соответствует priv.

> **СТАТУС: ЗАКРЫТА (волна 11).** Redundant clamp убран, make_key уже делает clamping.

### H-05 [crypto/noise.c:480] ~~REJECT_AFTER_MESSAGES: 2^64-2^16-1 ≠ спецификация 2^64-2^4-1~~
Спецификация WireGuard: REJECT_AFTER_MESSAGES = 2^64 - 2^4 - 1, код использует 2^64 - 2^16 - 1.
```c
#define NOISE_REJECT_AFTER_MESSAGES (UINT64_MAX - (1ULL << 16) - 1)
```
**Рекомендация:** `(UINT64_MAX - 15)`.

> **СТАТУС: ЗАКРЫТА (волна 11).** Значение исправлено на UINT64_MAX - 15ULL.

### H-06 [crypto/noise.c] ~~Нет noise_destroy() — ключи остаются в памяти~~
noise_state_t содержит send_key, recv_key, preshared_key, ephemeral_private.
При teardown соединения структура не обнуляется — ключи в heap/stack до перезаписи.

> **СТАТУС: ЗАКРЫТА (волна 11).** noise_state_cleanup() с explicit_bzero, вызов в awg_close().

### H-07 [crypto/blake2s.c:84-89] ~~Ключ в blake2s_init не обнуляется на стеке~~
block[64] с ключевым материалом не zeroed после blake2s_compress.
```c
uint8_t block[BLAKE2S_BLOCK] = {0};
memcpy(block, key, keylen);
blake2s_compress(s, block);
// block не обнулён — ключ на стеке
```

> **СТАТУС: ЗАКРЫТА (волна 11).** explicit_bzero(block) после blake2s_compress.

### H-08 [src/main.c:451] ~~DNS fd без guard cfg.dns.enabled~~
dns_state.udp_fd/tcp_fd = 0 (static init) может совпасть с реальным fd после daemonize.
```c
} else if (fd == dns_state.udp_fd || fd == dns_state.tcp_fd) {
    dns_server_handle_event(&dns_state, fd, master_epoll);
```

> **СТАТУС: ЗАКРЫТА (волна 11).** Guard dns_state.initialized, bool в dns_server_t.

### H-09 [src/main.c:474-493] ~~Config reload не реинициализирует DNS сервер~~
SIGHUP вызывает dns_rules_init но не dns_server_init/register_epoll.
Если DNS enabled/disabled или порт изменился — stale fd в epoll.

> **СТАТУС: ЗАКРЫТА (волна 11).** Полная реинициализация DNS при reload: cleanup + init + register_epoll.

### H-10 [dns/dns_server.c:191-211] ~~Rate limiting обходится через IPv6~~
IPv6 клиенты получают src_ip=0 → все IPv6 в одном bucket.

> **СТАТУС: ЗАКРЫТА (волна 11).** Полный адрес IPv4/IPv6 (16 байт), djb2 хеш, 512 слотов.

### H-11 [dns/dns_server.c:197-210] ~~Rate table: 256 слотов → collision bypass~~
2 IP с одинаковым hash сбрасывают счётчик друг друга.

> **СТАТУС: ЗАКРЫТА (волна 11).** Conservative collision: не сбрасываем чужой слот.

### H-12 [dns/dns_resolver.c:91-100] ~~dns_pending_complete без проверки idx bounds~~
Отрицательный или > DNS_PENDING_MAX idx → OOB доступ к массиву.

> **СТАТУС: ЗАКРЫТА (волна 11).** Bounds check idx < 0 || idx >= DNS_PENDING_MAX.

### H-13 [routing/device_policy.c:117-205] ~~TOCTOU: предсказуемый /tmp/phoenix_dev.nft~~
device_policy_apply использует фиксированный путь вместо mkstemp.
Несовместимо с остальной кодовой базой (nft_exec_atomic использует mkstemp).

> **СТАТУС: ЗАКРЫТА (волна 10).** mkstemp() для device_policy tmpfile.

### H-14 [dns/dns_upstream.c:273] ~~strstr на не-NUL-terminated буфере~~
http_buf читается через tls_recv без NUL-терминации, strstr читает за пределы.
```c
if (strstr((char *)http_buf, "Transfer-Encoding: chunked"))
```

> **СТАТУС: ЗАКРЫТА (волна 11).** http_buf[total] = '\0' перед strstr.

---

## Средние (MEDIUM) — 18

### M-01 [dns/dns_server.c:402-414] TCP DNS handler: 12KB+ на стеке
pkt[4096] + response[4096] + tcp_reply[4098] = 12290 байт. На MICRO опасно.

### M-02 [dns/dns_server.c:332-333] Upstream ответ без валидации DNS формата
Нет проверки QR=1, resp_n >= 12, question section match.

### M-03 [dns/dns_cache.c:119-128] LRU eviction нарушает open-addressing
Evicted entry может быть вне probe sequence хеша нового entry → invisible slot.

### M-04 [proxy/trojan.c:39-51] SHA224 hash и context не zeroed после use

### M-05 [proxy/dispatcher.c:838-839] Use-after-free риск при двух events на одном relay

### M-06 [proxy/dispatcher.c:610-611] SS relay upstream→client: partial write теряет данные

### M-07 [proxy/dispatcher.c:1149-1155] XHTTP download→client: partial write теряет данные

### M-08 [proxy/dispatcher.c:1216-1224] AWG downstream→client: partial write теряет данные

### M-09 [crypto/noise.c:502-503] time_t вычитание может wrap на 32-bit mipsel

### M-10 [crypto/tls.c:191-193] malloc failure для reality_key → silent NULL

### M-11 [crypto/tls.c:377] reality_key free без zeroing key material

### M-12 [routing/nftables.c:41-78] validate_cidr не проверяет prefix length range
`1.2.3.4/99` проходит валидацию. IPv4 max /32, IPv6 max /128.

### M-13 [routing/nftables.c:41-78] validate_cidr принимает `1/` (trailing slash)

### M-14 [routing/device_policy.c:197,201] exec_cmd (shell) вместо exec_cmd_safe для nft

### M-15 [routing/rules_loader.c:96] Path traversal: strstr("..") недостаточно
Symlinks, абсолютные пути (/etc/shadow) обходят проверку.

### M-16 [src/ntp_bootstrap.c:155] Sanity check upper bound 2033 → устареет через 7 лет

### M-17 [src/config.c:204-205] awg_keepalive без range validation

### M-18 [src/ipc.c:77-78] fcntl F_GETFL return value не проверяется

---

## Низкие (LOW) — 12

### L-01 [crypto/noise.c:60-63,79-83] HKDF buf[33] с ключевым материалом не zeroed
### L-02 [crypto/blake2s.c:38-67] blake2s_compress: m[16]/v[16] на стеке не zeroed
### L-03 [crypto/noise.c:351] TAI64N +37 устареет при новых leap seconds
### L-04 [proxy/awg.c:56-60] random_u32 fallback предсказуем
### L-05 [proxy/dispatcher.c:761-769] AWG client_fd не добавлен в epoll
### L-06 [dns/dns_resolver.c:63-64] Upstream сокет только IPv4
### L-07 [dns/dns_resolver.c:108] Timeout granularity: time(NULL) ±1 сек
### L-08 [dns/dns_rules.c:80-88] Unbounded realloc growth (нет upper cap)
### L-09 [src/main.c:319] PATH_MAX (2×4096) на стеке main()
### L-10 [routing/device_policy.c:257] mac_str не json_escape'd
### L-11 [src/config.c:220] config fopen без O_CLOEXEC
### L-12 [Makefile] dns_resolver.c не в production Makefile

---

## Информационные (INFO) — 8

### I-01 Однопоточная архитектура — static буферы безопасны
### I-02 HMAC-BLAKE2s = keyed BLAKE2s — корректно для WG spec (повтор v3 C-01, false positive)
### I-03 AEAD nonce format корректен
### I-04 /dev/urandom с O_CLOEXEC в noise.c
### I-05 valid_ifname/valid_mac_str/valid_nft_name — корректны
### I-06 mkstemp + unlink на всех путях в nftables.c
### I-07 exec_cmd_safe posix_spawn — корректно
### I-08 SS overflow_buf cleanup — корректен

---

## Статистика

| Категория | Найдено | Закрыто |
|-----------|---------|---------|
| CRITICAL  |    4    |    4    |
| HIGH      |   14    |   14    |
| MEDIUM    |   18    |    0    |
| LOW       |   12    |    0    |
| INFO      |    8    |    8    |
| **ИТОГО** | **56**  | **26**  |

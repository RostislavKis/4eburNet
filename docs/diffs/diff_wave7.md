# Волна 7 — Оставшиеся HIGH + все MEDIUM

## Изменённые файлы (20 файлов, +339/-106)

### core/src/config.c
- M-01: strcpy → snprintf для log_level, mode
- M-08: AWG поля с range validation (s1-s4: 0-1500, jc: 0-255, jmin/jmax: 0-65535)
- M-08: jmin/jmax swap если jmin > jmax
- M-09: cache_size проверка > 0, default 256

### core/src/main.c
- M-02: PID file write с error handling (fprintf + fflush)
- M-03: PID file open/read через O_CLOEXEC (open+fdopen)
- M-04: path буферы PATH_MAX + snprintf truncation check
- M-05: master_epoll = -1 init, close после cleanup label
- M-10: SA_RESTART для всех sigaction
- M-12: signal(SIGPIPE) → sigaction

### core/src/log.c
- M-06: log file через open(O_CLOEXEC) + fdopen
- M-07: bounds check для level < 0 / level > LOG_ERROR

### core/src/ipc.c
- M-11: umask(0177) перед bind вместо chmod TOCTOU
- M-13: IPC resp_len > UINT16_MAX проверка с логом

### core/src/crypto/noise.c
- M-14: clamp_curve25519_key() перед import + после generate
- M-15: aead_encrypt return value проверяется во всех handshake вызовах
- M-16: x25519_shared return value проверяется
- M-17: explicit_bzero(ns) на всех error paths в noise_init

### core/src/crypto/tls.c
- M-18: fd >= FD_SETSIZE проверка перед select()

### core/include/dns/dns_cache.h
- M-19: DNS_MAX_PACKET = 4096 (было 512)

### core/src/dns/dns_cache.c
- M-20: FNV-1a хеш вместо djb2
- M-26: LRU unlink при expired entry перед пометкой unused

### core/src/dns/dns_rules.c
- M-29: TODO комментарий для qsort+bsearch (ограничение v1)

### core/include/dns/dns_server.h
- H-13: rate_table[256] в dns_server_t

### core/src/dns/dns_server.c
- H-13: per-source IP rate limiting (100 req/sec/IP)
- M-19: pkt/nxdomain/response/reply буферы → DNS_MAX_PACKET
- M-23: epoll_ctl return value проверка
- M-24: write() return value (TCP DNS)
- M-25: sendto() return value (UDP DNS)

### core/src/dns/dns_upstream.c
- M-21: b64 буфер 1024 → 8192
- M-22: CRLF injection check для DoH URL
- M-27: chunked encoding detection + reject
- M-28: HTTP/1.1 → HTTP/1.0

### core/src/ntp_bootstrap.c
- H-12: warning о неаутентифицированном HTTP

### core/src/proxy/protocols/awg.c
- M-32: CPS hex parser bounds check + isxdigit validation

### core/src/proxy/protocols/shadowsocks.c
- M-34: ss_send разбивает данные на chunks ≤ 0x3FFF

### core/src/proxy/protocols/vless.c
- M-33: warning при addons_len > 0 + TODO

### core/src/proxy/protocols/vless_xhttp.c
- M-30: chunk size upper bound 65536
- M-31: fallback session ID с counter

### core/src/routing/device_policy.c
- M-36: snprintf unsigned underflow защита (pos >= buflen check)
- M-38: TODO комментарий для rollback

### core/src/routing/nftables.c
- M-35: 16KB стековый буфер → heap (malloc/free) в 5 функциях
- M-37: if (f) перед fclose для batch NULL safety

# Audit v4 Wave 12 — All MEDIUM + LOW (30 items)

## M-01 dns_server.c: TCP DNS heap buffers
- `pkt`, `response`, `tcp_reply` moved from stack to heap (malloc)
- `goto cleanup` pattern for all exit paths with free()

## M-02 dns_server.c: DNS response validation
- Added `resp_n < 12` length check after recv
- Added QR bit check `resp[2] & 0x80` (must be response)

## M-03 dns_cache.c: LRU tombstone eviction
- Evict LRU tail: detach from LRU, mark `used=false`
- Re-probe from original hash to find correct slot
- Fallback to freed slot if no free slot in probe sequence

## M-04 trojan.c: SHA224 zeroing
- `wc_Sha224Free(&sha)` after Final
- `explicit_bzero(hash, sizeof(hash))` on stack

## M-05 dispatcher.c: use-after-free guard
- `if (r->state == RELAY_DONE) continue` at top of event loop
- Prevents processing relay freed by earlier event in same batch

## M-06 dispatcher.c: SS partial write
- `write()` return < n: log + return -1 (fatal for framed SS 2022)

## M-07 dispatcher.c: XHTTP partial write
- `write()` return < n: log + relay_free (fatal for chunked stream)

## M-08 dispatcher.c: AWG partial write
- `write()` return < n: log + relay_free (fatal for UDP framing)

## M-09 noise.c: time_t wrap protection
- `elapsed = (now >= handshake_time) ? (now - handshake_time) : 0`
- Prevents negative diff on 32-bit mipsel

## M-10 tls.c: reality_key malloc check
- If malloc fails: log error, tls_close, return -1

## M-11 tls.c: reality_key zeroing
- `explicit_bzero` before free for reality_key
- `explicit_bzero` before free for reality_short_id

## M-12/M-13 nftables.c: validate_cidr prefix range
- Trailing slash check: `*(slash+1) == '\0'`
- IPv4: prefix 0-32, IPv6: prefix 0-128

## M-14 device_policy.c: exec_cmd_safe
- `exec_cmd("nft delete...")` -> `exec_cmd_safe(argv, ...)`
- `exec_cmd_capture("nft -f...")` -> `exec_cmd_safe(argv, err, sizeof(err))`

## M-15 rules_loader.c: safe_rules_path whitelist
- Reject absolute paths (starts with `/`)
- Reject `..` traversal
- Whitelist: alnum + `_` `-` `.` `/`

## M-16 ntp_bootstrap.c: NTP sanity constants
- `NTP_SANITY_MIN = 1700000000L` (~2023-11-14)
- `NTP_SANITY_MAX = 2145916800L` (2038-01-01)

## M-17 config.c: awg_keepalive range
- strtol + range check 0-65535, default 25

## M-18 ipc.c: fcntl check
- `if (flags >= 0)` before F_SETFL

## L-01 noise.c: HKDF buf zeroed
- `explicit_bzero(buf, sizeof(buf))` in noise_hkdf2 and noise_hkdf3

## L-02 blake2s.c: compress m/v zeroed
- `explicit_bzero(m, sizeof(m))` + `explicit_bzero(v, sizeof(v))`

## L-03 noise.c: TAI64N comment
- Added leap second source URL and update instructions

## L-04 awg.c: xorshift64 fallback
- Replaced LCG with xorshift64 for better distribution

## L-05 dispatcher.c: AWG client_fd in epoll
- Added `epoll_ctl(EPOLL_CTL_ADD, r->client_fd)` in AWG branch

## L-06 dns_resolver.c: IPv6 upstream
- Detect AF by `strchr(upstream_ip, ':')`
- Use `sockaddr_in6` for IPv6 upstream DNS

## L-07 dns_resolver.c: timeout comment
- Documented ~2-3s granularity as acceptable for DNS

## L-08 dns_rules.c: unbounded realloc cap
- `DNS_RULES_MAX = 500000` with log warning

## L-09 main.c: PATH_MAX on heap
- `malloc(PATH_MAX)` instead of stack arrays
- `free()` after use

## L-10 device_policy.c: mac_str json_escape
- Applied `json_escape()` to `d->mac_str` in JSON output

## L-11 config.c: O_CLOEXEC
- `open(path, O_RDONLY | O_CLOEXEC)` + `fdopen()`

## L-12 Makefile: dns_resolver.c
- Added `dns/dns_resolver.c` to production PHOENIX_SOURCES

## Build result
- 0 errors, 0 warnings
- Binary: 988K

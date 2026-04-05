# Аудит v4 волна 11 — все HIGH закрыты

## Изменённые файлы

### core/src/proxy/protocols/shadowsocks.c
- **H-01**: ss_handshake_start — EAGAIN при write = fatal return -1 (framed SS 2022 не допускает partial frame)
- **H-02**: ss_send_chunk — аналогично, EAGAIN = fatal return -1

### core/src/proxy/protocols/vless.c
- **H-03**: vless_read_response_step — addons_len > 0 вычитываются побайтово через tls_recv, resp_buf[2] = счётчик

### core/include/proxy/dispatcher.h
- **H-03**: vless_resp_buf расширен до [3] (добавлен addons_read counter)

### core/src/crypto/noise.c
- **H-04**: Убран redundant clamp_curve25519_key() в x25519_generate (make_key уже делает clamping)
- **H-05**: NOISE_REJECT_AFTER_MESSAGES исправлен с (UINT64_MAX - (1ULL << 16) - 1) на (UINT64_MAX - 15ULL) по WG spec
- **H-06**: Добавлен noise_state_cleanup() — explicit_bzero всей структуры

### core/include/crypto/noise.h
- **H-06**: Объявление noise_state_cleanup()

### core/src/proxy/protocols/awg.c
- **H-06**: Вызов noise_state_cleanup(&awg->noise) в awg_close() перед закрытием fd

### core/src/crypto/blake2s.c
- **H-07**: explicit_bzero(block) после blake2s_compress в blake2s_init (ключевой материал на стеке)

### core/src/main.c
- **H-08**: Guard dns_state.initialized для DNS fd в epoll dispatch
- **H-09**: Полная реинициализация DNS при config reload (cleanup old + init new + register_epoll)
- Cleanup секция использует dns_state.initialized вместо cfg.dns.enabled

### core/include/dns/dns_server.h
- **H-08**: Добавлен bool initialized в dns_server_t
- **H-10/H-11**: rate_table расширен: addr[16] + addr_len, DNS_RATE_TABLE_SIZE = 512

### core/src/dns/dns_server.c
- **H-08**: initialized = true при успешном init, false при cleanup
- **H-10/H-11**: Rate limiting по полному IPv4/IPv6 адресу, djb2 хеш, conservative collision

### core/src/dns/dns_resolver.c
- **H-12**: Bounds check idx в dns_pending_complete()

### core/src/dns/dns_upstream.c
- **H-14**: NUL-терминация http_buf[total] = '\0' перед strstr

## Сборка

- 0 ошибок, 0 warnings
- Бинарник: 988 KB

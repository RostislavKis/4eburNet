# Аудит v3 волна 6 — diff

## core/include/proxy/protocols/shadowsocks.h
- Добавлены поля overflow_buf/overflow_len/overflow_off в ss_state_t (C-08)
- Добавлена функция ss_cleanup()

## core/src/proxy/protocols/shadowsocks.c
- C-08: overflow буфер для данных chunk > buflen в ss_recv()
- C-08: проверка overflow в начале ss_recv(), сохранение остатка при data_len > buflen
- C-08: ss_cleanup() для освобождения overflow буфера
- H-21: write loop в ss_handshake_start() для partial write
- H-22: write loop в ss_send() для partial write
- H-26: getrandom() с loop + fallback /dev/urandom с O_CLOEXEC

## core/include/crypto/noise.h
- H-04: добавлено поле handshake_time в noise_state_t

## core/src/crypto/noise.c
- H-02: NOISE_REJECT_AFTER_MESSAGES проверка в noise_encrypt()
- H-03: getrandom() loop с обработкой EINTR и partial read
- H-04: NOISE_REJECT_AFTER_TIME 180s проверка в noise_encrypt()
- H-04: запись handshake_time в noise_handshake_response_process()

## core/src/crypto/tls.c
- H-05: deep copy reality_key (malloc+memcpy) и reality_short_id (strdup)
- H-05: free deep copy в tls_close()

## core/include/net_utils.h
- H-07: объявление exec_cmd_safe()

## core/src/net_utils.c
- H-07: реализация exec_cmd_safe() через posix_spawn без shell

## core/src/routing/nftables.c
- H-07: nft_exec_atomic() и nft_exec_file() переведены на exec_cmd_safe()

## core/src/main.c
- H-08: open("/dev/null", O_RDWR | O_CLOEXEC)
- H-09: epoll_ctl с проверкой возврата и логированием ошибки

## core/src/ipc.c
- H-10: EAGAIN обработка при recv (не ошибка)
- H-10: проверка hdr.length > IPC_RESPONSE_MAX

## core/src/ntp_bootstrap.c
- H-11: sanity check времени (1700000000..2000000000)

## core/src/proxy/dispatcher.c
- H-19: SS relay возвращает w вместо n
- C-08: ss_cleanup() при relay_free()

## core/src/proxy/protocols/vless.c
- H-23: vless_read_response помечена DEPRECATED

## core/src/proxy/protocols/awg.c
- H-25: random_u32() fallback при ошибке random_fill()

## docs/audit_v3.md
- Отмечены закрытыми: C-08, H-02..H-05, H-07..H-12, H-19..H-23, H-25, H-26
- Обновлена таблица статистики (55 закрыто)

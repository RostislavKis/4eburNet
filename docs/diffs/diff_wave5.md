# Аудит v3 — Волна 5: diff

## Закрыто: 9 CRITICAL + 9 HIGH = 18 находок

---

### crypto/blake2s.c
- C-14: добавлена проверка outlen (0, >32) и keylen (>32) в blake2s_init, защита от buffer overflow

### crypto/noise.c
- C-02: replay protection в noise_decrypt — проверка монотонности counter + sliding window 64 пакета
- C-03: explicit_bzero для shared/tag/mac1_key в noise_handshake_init_create, shared/temp в noise_handshake_response_process, prk в noise_hkdf2/hkdf3
- H-01: TAI64N смещение исправлено с 4611686018427387914 на 2^62 + 37 (TAI64N_BASE)
- H-06: x25519_generate — проверка return values от export_private_raw и export_public

### proxy/tproxy.c
- C-07: sizeof(buf) заменён на TPROXY_UDP_BUF в iov_len (был sizeof(pointer)=8 вместо 65536)

### proxy/protocols/shadowsocks.c
- C-09: nonce_increment вызывается только при rc == 0 в ss_aead_encrypt и ss_aead_decrypt

### proxy/protocols/awg.c
- H-24: awg_add_padding получает параметр buf_size, проверяет границы буфера перед записью padding. Все вызовы обновлены с sizeof(буфера)

### routing/policy.c
- C-10: валидация dev через valid_ifname() перед использованием в shell-команде

### routing/device_policy.c
- C-11: валидация lan_iface через valid_ifname() в device_policy_apply
- C-12: добавлена valid_mac_str() для проверки формата MAC перед записью в nft verdict map

### routing/nftables.c
- C-13: добавлена valid_nft_name() для whitelist валидации имён set/map. Проверки в nft_set_add_addr, nft_set_del_addr, nft_set_flush, nft_set_load_file, nft_vmap_load_batch, nft_vmap_load_file
- H-27: validate_nft_cmd расширен — добавлены '"\{}#\n\r\ в forbidden set
- H-28: все fopen(NFT_TMP_CONF) заменены на mkstemp + fchmod(0600) в nft_exec_atomic, nft_set_load_file, nft_vmap_load_batch, nft_vmap_load_file

### net_utils.c / net_utils.h
- C-10/C-11: вынесена valid_ifname() — общая функция для валидации имён сетевых интерфейсов

### dns/dns_packet.c
- H-14: OOB read fix в question section — проверка pos + 1 + label_len > len
- H-15: OOB read fix в answer section — та же проверка для name parsing

### dns/dns_rules.c
- H-16: partial realloc leak fix — realloc делается последовательно, np сохраняется сразу
- H-17: strdup с проверкой NULL в dns_rules_init и dns_rules_load_file

### docs/audit_v3.md
- Отмечены закрытые: C-02, C-03, C-07, C-09, C-10, C-11, C-12, C-13, C-14
- Отмечены закрытые: H-01, H-06, H-14, H-15, H-16, H-17, H-24, H-27, H-28
- C-01: ложное срабатывание
- C-04, C-05: принято (verify_cert=false намеренно)
- Обновлена таблица статистики

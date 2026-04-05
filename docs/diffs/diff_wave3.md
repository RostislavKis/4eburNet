# Волна 3: MEDIUM + LOW

**Дата**: 2026-04-05

**Файлы**:
- core/src/crypto/blake2s.c (M-02)
- core/src/crypto/noise.c (M-03)
- core/include/crypto/noise.h (M-03)
- core/src/proxy/dispatcher.c (M-04, M-12)
- core/include/proxy/dispatcher.h (M-12)
- core/src/log.c (M-05)
- core/include/phoenix.h (M-05)
- core/src/main.c (M-05)
- core/src/dns/dns_cache.c (M-06)
- core/include/dns/dns_cache.h (M-08)
- core/src/proxy/protocols/shadowsocks.c (M-09)
- core/src/ntp_bootstrap.c (M-10)
- core/src/proxy/protocols/vless_xhttp.c (M-11)
- core/src/proxy/tproxy.c (L-04)
- core/src/proxy/protocols/awg.c (L-05, L-06)
- Удалены: core/crypto/{chacha20,reality,tls}.c, core/src/dns/{adblock,cache,classifier,resolver}.c, core/src/routing/ipset.c, core/src/watchdog.c (M-01)

```diff
diff --git a/core/crypto/chacha20.c b/core/crypto/chacha20.c
deleted file mode 100644
index f45ffb3..0000000
--- a/core/crypto/chacha20.c
+++ /dev/null
@@ -1,15 +0,0 @@
-/*
- * ChaCha20-Poly1305
- *
- * Шифрование для Shadowsocks AEAD.
- * На ARM-процессорах быстрее AES без аппаратного ускорения.
- */
-
-#include <stdio.h>
-
-int chacha20_encrypt(const void *key, const void *nonce,
-                     const void *plaintext, int len, void *ciphertext)
-{
-    /* TODO: wolfSSL ChaCha20-Poly1305 */
-    return -1;
-}
diff --git a/core/crypto/reality.c b/core/crypto/reality.c
deleted file mode 100644
index 68a816c..0000000
--- a/core/crypto/reality.c
+++ /dev/null
@@ -1,14 +0,0 @@
-/*
- * REALITY — маскировка TLS-трафика
- *
- * Альтернатива обычному TLS: сервер выглядит как
- * легитимный сайт для внешнего наблюдателя.
- */
-
-#include <stdio.h>
-
-int reality_handshake(int fd, const char *pubkey, const char *sid)
-{
-    /* TODO: REALITY клиентское рукопожатие */
-    return -1;
-}
diff --git a/core/crypto/tls.c b/core/crypto/tls.c
deleted file mode 100644
index 52c9d41..0000000
--- a/core/crypto/tls.c
+++ /dev/null
@@ -1,14 +0,0 @@
-/*
- * TLS-обёртка над wolfSSL
- *
- * Инициализация контекста, подключение к серверу,
- * проверка сертификатов.
- */
-
-#include <stdio.h>
-
-int tls_connect(int fd, const char *sni)
-{
-    /* TODO: wolfSSL_new, wolfSSL_set_fd, wolfSSL_connect */
-    return -1;
-}
diff --git a/core/include/crypto/noise.h b/core/include/crypto/noise.h
index ca9d0ee..458ad73 100644
--- a/core/include/crypto/noise.h
+++ b/core/include/crypto/noise.h
@@ -20,8 +20,8 @@ typedef struct {
     /* Результат handshake */
     uint8_t  send_key[32];
     uint8_t  recv_key[32];
-    uint32_t send_counter;
-    uint32_t recv_counter;
+    uint64_t send_counter;
+    uint64_t recv_counter;
     uint32_t local_index;
     uint32_t remote_index;
     bool     handshake_complete;
diff --git a/core/include/dns/dns_cache.h b/core/include/dns/dns_cache.h
index 5a11e38..fb47ab7 100644
--- a/core/include/dns/dns_cache.h
+++ b/core/include/dns/dns_cache.h
@@ -4,6 +4,7 @@
 #include <stdint.h>
 #include <stddef.h>
 #include <time.h>
+#include <stdbool.h>
 
 #define DNS_MAX_PACKET 512
 
diff --git a/core/include/phoenix.h b/core/include/phoenix.h
index 95eb62f..ceda6cd 100644
--- a/core/include/phoenix.h
+++ b/core/include/phoenix.h
@@ -95,5 +95,6 @@ void log_msg(log_level_t level, const char *fmt, ...)
     __attribute__((format(printf, 2, 3)));
 void log_flush(void);
 void log_close(void);
+void log_set_daemon_mode(bool daemon);
 
 #endif /* PHOENIX_H */
diff --git a/core/include/proxy/dispatcher.h b/core/include/proxy/dispatcher.h
index 4efacc2..65285be 100644
--- a/core/include/proxy/dispatcher.h
+++ b/core/include/proxy/dispatcher.h
@@ -9,6 +9,7 @@
 #include <stddef.h>
 #include <sys/socket.h>
 #include <time.h>
+#define DISPATCHER_MAX_HEALTH  64
 
 /* Состояние relay соединения */
 typedef enum {
@@ -91,7 +92,7 @@ typedef struct {
         time_t    last_success;
         uint32_t  fail_count;
         bool      available;
-    } health[8];                        /* до 8 серверов */
+    } health[DISPATCHER_MAX_HEALTH];    /* до DISPATCHER_MAX_HEALTH серверов */
     int             health_count;       /* 0 = не инициализирован */
     time_t          health_reset_at;    /* следующий health reset (M-07) */
 } dispatcher_state_t;
diff --git a/core/src/crypto/blake2s.c b/core/src/crypto/blake2s.c
index 73422d3..a890780 100644
--- a/core/src/crypto/blake2s.c
+++ b/core/src/crypto/blake2s.c
@@ -135,27 +135,13 @@ void blake2s_keyed(uint8_t *out, size_t outlen,
     blake2s_final(&s, out);
 }
 
+/*
+ * HMAC для Noise/WireGuard: keyed BLAKE2s, НЕ классический HMAC(ipad/opad).
+ * Noise spec: HMAC(key, input) = BLAKE2s(key=key, input=input).
+ */
 void blake2s_hmac(uint8_t *out, size_t outlen,
                   const uint8_t *key, size_t keylen,
                   const uint8_t *in, size_t inlen)
 {
-    uint8_t ikey[64], okey[64];
-    memset(ikey, 0x36, 64);
-    memset(okey, 0x5c, 64);
-    for (size_t i = 0; i < keylen && i < 64; i++) {
-        ikey[i] ^= key[i];
-        okey[i] ^= key[i];
-    }
-
-    uint8_t inner[32];
-    blake2s_state_t s;
-    blake2s_init(&s, 32, NULL, 0);
-    blake2s_update(&s, ikey, 64);
-    blake2s_update(&s, in, inlen);
-    blake2s_final(&s, inner);
-
-    blake2s_init(&s, outlen, NULL, 0);
-    blake2s_update(&s, okey, 64);
-    blake2s_update(&s, inner, 32);
-    blake2s_final(&s, out);
+    blake2s_keyed(out, outlen, key, keylen, in, inlen);
 }
diff --git a/core/src/crypto/noise.c b/core/src/crypto/noise.c
index 93acc28..e1b15cb 100644
--- a/core/src/crypto/noise.c
+++ b/core/src/crypto/noise.c
@@ -88,10 +88,14 @@ static int aead_encrypt(const uint8_t key[32], uint64_t counter,
                         uint8_t *out, uint8_t tag[16])
 {
     uint8_t nonce[12] = {0};
-    nonce[4] = (uint8_t)(counter);
-    nonce[5] = (uint8_t)(counter >> 8);
-    nonce[6] = (uint8_t)(counter >> 16);
-    nonce[7] = (uint8_t)(counter >> 24);
+    nonce[4]  = (uint8_t)(counter);
+    nonce[5]  = (uint8_t)(counter >> 8);
+    nonce[6]  = (uint8_t)(counter >> 16);
+    nonce[7]  = (uint8_t)(counter >> 24);
+    nonce[8]  = (uint8_t)(counter >> 32);
+    nonce[9]  = (uint8_t)(counter >> 40);
+    nonce[10] = (uint8_t)(counter >> 48);
+    nonce[11] = (uint8_t)(counter >> 56);
 
     return wc_ChaCha20Poly1305_Encrypt(key, nonce,
         aad, (word32)aad_len, plain, (word32)plen, out, tag);
@@ -104,10 +108,14 @@ static int aead_decrypt(const uint8_t key[32], uint64_t counter,
                         const uint8_t tag[16], uint8_t *out)
 {
     uint8_t nonce[12] = {0};
-    nonce[4] = (uint8_t)(counter);
-    nonce[5] = (uint8_t)(counter >> 8);
-    nonce[6] = (uint8_t)(counter >> 16);
-    nonce[7] = (uint8_t)(counter >> 24);
+    nonce[4]  = (uint8_t)(counter);
+    nonce[5]  = (uint8_t)(counter >> 8);
+    nonce[6]  = (uint8_t)(counter >> 16);
+    nonce[7]  = (uint8_t)(counter >> 24);
+    nonce[8]  = (uint8_t)(counter >> 32);
+    nonce[9]  = (uint8_t)(counter >> 40);
+    nonce[10] = (uint8_t)(counter >> 48);
+    nonce[11] = (uint8_t)(counter >> 56);
 
     return wc_ChaCha20Poly1305_Decrypt(key, nonce,
         aad, (word32)aad_len, cipher, (word32)clen, tag, out);
@@ -443,6 +451,6 @@ int noise_decrypt(noise_state_t *ns,
         return -1;
 
     *out_len = payload_len;
-    ns->recv_counter = (uint32_t)(ctr + 1);
+    ns->recv_counter = ctr + 1;
     return 0;
 }
diff --git a/core/src/dns/adblock.c b/core/src/dns/adblock.c
deleted file mode 100644
index 668c52b..0000000
--- a/core/src/dns/adblock.c
+++ /dev/null
@@ -1,14 +0,0 @@
-/*
- * Блокировка рекламных доменов
- *
- * Проверяет домен по спискам adblock и возвращает
- * 0.0.0.0 для заблокированных.
- */
-
-#include <stdio.h>
-
-int adblock_check(const char *domain)
-{
-    /* TODO: поиск по загруженным спискам блокировки */
-    return 0;
-}
diff --git a/core/src/dns/cache.c b/core/src/dns/cache.c
deleted file mode 100644
index 1c85757..0000000
--- a/core/src/dns/cache.c
+++ /dev/null
@@ -1,20 +0,0 @@
-/*
- * DNS-кеш
- *
- * Хранит результаты DNS-запросов в памяти.
- * Размер кеша зависит от профиля устройства.
- */
-
-#include <stdio.h>
-
-int dns_cache_init(int max_entries)
-{
-    /* TODO: аллокация хеш-таблицы для кеша */
-    return 0;
-}
-
-int dns_cache_lookup(const char *domain, void *result)
-{
-    /* TODO */
-    return -1;
-}
diff --git a/core/src/dns/classifier.c b/core/src/dns/classifier.c
deleted file mode 100644
index b72acbb..0000000
--- a/core/src/dns/classifier.c
+++ /dev/null
@@ -1,16 +0,0 @@
-/*
- * Классификатор доменов
- *
- * Определяет категорию домена по загруженным спискам:
- * - прямой доступ (bypass)
- * - через прокси (proxy)
- * - заблокировать (block)
- */
-
-#include <stdio.h>
-
-int dns_classify(const char *domain)
-{
-    /* TODO: поиск домена по спискам geosite */
-    return 0;
-}
diff --git a/core/src/dns/dns_cache.c b/core/src/dns/dns_cache.c
index a051d2b..c8ef29f 100644
--- a/core/src/dns/dns_cache.c
+++ b/core/src/dns/dns_cache.c
@@ -7,6 +7,7 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
+#define DNS_CACHE_PROBE_MAX  16
 
 static uint32_t djb2_hash(const char *qname, uint16_t qtype)
 {
@@ -63,7 +64,7 @@ const uint8_t *dns_cache_get(dns_cache_t *c,
                              uint16_t *resp_len, uint16_t orig_id)
 {
     uint32_t h = djb2_hash(qname, qtype);
-    for (int i = 0; i < c->capacity; i++) {
+    for (int i = 0; i < DNS_CACHE_PROBE_MAX && i < c->capacity; i++) {
         int idx = (h + i) % c->capacity;
         dns_cache_entry_t *e = &c->entries[idx];
         if (!e->used) return NULL;
@@ -96,7 +97,7 @@ void dns_cache_put(dns_cache_t *c,
     int target = -1;
 
     /* Ищем существующий или пустой слот */
-    for (int i = 0; i < c->capacity; i++) {
+    for (int i = 0; i < DNS_CACHE_PROBE_MAX && i < c->capacity; i++) {
         int idx = (h + i) % c->capacity;
         if (!c->entries[idx].used) { target = idx; break; }
         if (c->entries[idx].qtype == qtype &&
diff --git a/core/src/dns/resolver.c b/core/src/dns/resolver.c
deleted file mode 100644
index a6c2504..0000000
--- a/core/src/dns/resolver.c
+++ /dev/null
@@ -1,16 +0,0 @@
-/*
- * DNS-резолвер
- *
- * Перехватывает DNS-запросы и направляет их:
- * - внутренние домены → локальный DNS
- * - заблокированные домены → DNS через прокси (DoH/DoT)
- * - остальные → системный DNS
- */
-
-#include <stdio.h>
-
-int dns_resolver_start(int cache_size)
-{
-    /* TODO: запуск UDP/TCP слушателя на порту 5353 */
-    return 0;
-}
diff --git a/core/src/log.c b/core/src/log.c
index c574ece..dade58d 100644
--- a/core/src/log.c
+++ b/core/src/log.c
@@ -10,6 +10,7 @@
 /* Файловый дескриптор лога и минимальный уровень */
 static FILE       *log_file     = NULL;
 static log_level_t log_min_level = LOG_INFO;
+static bool        g_daemon_mode  = false;
 
 /* Строковые представления уровней */
 static const char *level_names[] = {
@@ -37,6 +38,7 @@ static void log_check_size(void)
     }
 }
 
+
 void log_init(const char *path, log_level_t min_level)
 {
     log_min_level = min_level;
@@ -49,6 +51,11 @@ void log_init(const char *path, log_level_t min_level)
     }
 }
 
+void log_set_daemon_mode(bool daemon)
+{
+    g_daemon_mode = daemon;
+}
+
 void log_msg(log_level_t level, const char *fmt, ...)
 {
     if (level < log_min_level)
@@ -66,11 +73,15 @@ void log_msg(log_level_t level, const char *fmt, ...)
 
     /* Вывод в stderr */
     va_list ap;
-    va_start(ap, fmt);
-    fprintf(stderr, "[%s] [%s] ", ts, lvl);
-    vfprintf(stderr, fmt, ap);
-    fprintf(stderr, "\n");
-    va_end(ap);
+
+    /* В daemon mode stderr = /dev/null, пропускаем бесполезный syscall */
+    if (!g_daemon_mode) {
+        va_start(ap, fmt);
+        fprintf(stderr, "[%s] [%s] ", ts, lvl);
+        vfprintf(stderr, fmt, ap);
+        fprintf(stderr, "\n");
+        va_end(ap);
+    }
 
     /* Вывод в файл, если открыт */
     if (log_file) {
diff --git a/core/src/main.c b/core/src/main.c
index 0674ff2..bafa1ca 100644
--- a/core/src/main.c
+++ b/core/src/main.c
@@ -208,8 +208,10 @@ int main(int argc, char *argv[])
     }
 
     /* Демонизация, если запрошена */
-    if (daemon_mode)
+    if (daemon_mode) {
         daemonize();
+        log_set_daemon_mode(true);
+    }
 
     /* Инициализация логирования (пока с уровнем по умолчанию) */
     log_init(PHOENIX_LOG_FILE, LOG_INFO);
diff --git a/core/src/ntp_bootstrap.c b/core/src/ntp_bootstrap.c
index 2516d65..72be401 100644
--- a/core/src/ntp_bootstrap.c
+++ b/core/src/ntp_bootstrap.c
@@ -102,9 +102,12 @@ static int try_host(const char *ip, const char *host)
     /* Отправляем HTTP HEAD */
     char req[256];
     int req_len = snprintf(req, sizeof(req), HTTP_REQ_FMT, host);
-    if (send(fd, req, req_len, 0) != req_len) {
-        close(fd);
-        return -1;
+    /* Цикл partial write */
+    size_t sent = 0;
+    while (sent < (size_t)req_len) {
+        ssize_t n = send(fd, req + sent, (size_t)req_len - sent, 0);
+        if (n <= 0) { close(fd); return -1; }
+        sent += (size_t)n;
     }
 
     /* Читаем ответ (HEAD не содержит тела, но читаем буфер
diff --git a/core/src/proxy/dispatcher.c b/core/src/proxy/dispatcher.c
index d5f1c69..eb6cc41 100644
--- a/core/src/proxy/dispatcher.c
+++ b/core/src/proxy/dispatcher.c
@@ -448,7 +448,7 @@ int dispatcher_select_server(dispatcher_state_t *ds,
     /* Lazy init — заполнить health[] при первом вызове */
     if (ds->health_count == 0 && cfg->server_count > 0) {
         int count = cfg->server_count;
-        if (count > 8) count = 8;
+        if (count > DISPATCHER_MAX_HEALTH) count = DISPATCHER_MAX_HEALTH;
         for (int i = 0; i < count; i++) {
             ds->health[i].server_idx = i;
             ds->health[i].available  = true;
@@ -819,6 +819,8 @@ void dispatcher_tick(dispatcher_state_t *ds)
     struct epoll_event events[DISPATCHER_MAX_EVENTS];
     int n = epoll_wait(ds->epoll_fd, events, DISPATCHER_MAX_EVENTS, 0);
 
+    time_t now = time(NULL);
+
     for (int i = 0; i < n; i++) {
         relay_ep_t *ep = events[i].data.ptr;
         if (!ep || !ep->relay)
@@ -978,7 +980,7 @@ void dispatcher_tick(dispatcher_state_t *ds)
                         ds, r, true);
                     if (transferred > 0) {
                         r->bytes_in += transferred;
-                        r->last_active = time(NULL);
+                        r->last_active = now;
                         continue;
                     }
                     if (transferred == 0) {
@@ -997,7 +999,7 @@ void dispatcher_tick(dispatcher_state_t *ds)
                         ds, r, false);
                     if (transferred > 0) {
                         r->bytes_out += transferred;
-                        r->last_active = time(NULL);
+                        r->last_active = now;
                         continue;
                     }
                     if (transferred == 0) {
@@ -1122,7 +1124,7 @@ void dispatcher_tick(dispatcher_state_t *ds)
                             r->xhttp, ds->relay_buf, n);
                         if (sent > 0) {
                             r->bytes_in += sent;
-                            r->last_active = time(NULL);
+                            r->last_active = now;
                             continue;
                         }
                     }
@@ -1149,7 +1151,7 @@ void dispatcher_tick(dispatcher_state_t *ds)
                             goto next_event_xhttp;
                         }
                         r->bytes_out += (uint64_t)wr;
-                        r->last_active = time(NULL);
+                        r->last_active = now;
                         continue;
                     }
                     if (n == 0) {
@@ -1192,7 +1194,7 @@ void dispatcher_tick(dispatcher_state_t *ds)
                     if (n > 0) {
                         awg_send(r->awg, ds->relay_buf, n);
                         r->bytes_in += n;
-                        r->last_active = time(NULL);
+                        r->last_active = now;
                         continue;
                     }
                     if (n == 0) relay_do_half_close(r, true);
@@ -1216,7 +1218,7 @@ void dispatcher_tick(dispatcher_state_t *ds)
                             break;
                         }
                         r->bytes_out += (uint64_t)wr;
-                        r->last_active = time(NULL);
+                        r->last_active = now;
                     }
                 } else if (arc < 0) {
                     r->state = RELAY_CLOSING;
@@ -1241,7 +1243,7 @@ void dispatcher_tick(dispatcher_state_t *ds)
     /* Периодическая проверка таймаутов (M-03: ранний выход, M-09: idle) */
     if (ds->tick_count % RELAY_TIMEOUT_CHECK == 0
         && ds->conns_count > 0) {
-        time_t now = time(NULL);
+        /* now уже кэширован в начале tick */
         int checked = 0;
         for (int i = 0; i < ds->conns_max
                         && checked < ds->conns_count; i++) {
@@ -1267,7 +1269,7 @@ void dispatcher_tick(dispatcher_state_t *ds)
 
     /* Health reset по абсолютному времени (M-07) */
     {
-        time_t now_t = time(NULL);
+        time_t now_t = now;
         if (now_t >= ds->health_reset_at && ds->health_count > 0) {
             ds->health_reset_at = now_t + 30;
             for (int i = 0; i < ds->health_count; i++) {
diff --git a/core/src/proxy/protocols/awg.c b/core/src/proxy/protocols/awg.c
index 209491f..19b00df 100644
--- a/core/src/proxy/protocols/awg.c
+++ b/core/src/proxy/protocols/awg.c
@@ -310,7 +310,7 @@ int awg_handshake_start(awg_state_t *awg,
         log_msg(LOG_DEBUG, "AWG: отправлены junk пакеты (%u)", awg->cfg.jc);
 
     /* Noise Init handshake */
-    uint8_t init_pkt[256];
+    uint8_t init_pkt[1536];  /* 148 + max S1 padding */
     size_t init_len = sizeof(init_pkt);
     if (noise_handshake_init_create(&awg->noise, init_pkt, &init_len) < 0) {
         log_msg(LOG_ERROR, "AWG: не удалось создать Init handshake");
@@ -387,7 +387,10 @@ ssize_t awg_send(awg_state_t *awg, const uint8_t *data, size_t len)
 {
     if (!awg->handshake_done) return -1;
 
-    uint8_t pkt[2048];
+    /* Ограничение по MTU: header(16) + data + tag(16) + S4 padding */
+    if (len > 1420) len = 1420;
+
+    uint8_t pkt[1536];
     size_t pkt_len;
 
     if (noise_encrypt(&awg->noise, data, len, pkt, &pkt_len) != 0)
@@ -427,7 +430,7 @@ void awg_tick(awg_state_t *awg)
                        awg->cfg.remote_public_key,
                        awg->cfg.preshared_key, awg->cfg.has_psk);
 
-            uint8_t init[256];
+            uint8_t init[1536];
             size_t init_len = sizeof(init);
             if (noise_handshake_init_create(&awg->noise, init, &init_len) == 0) {
                 awg_obfuscate_header(init, awg->cfg.h1_min, awg->cfg.h1_max);
diff --git a/core/src/proxy/protocols/shadowsocks.c b/core/src/proxy/protocols/shadowsocks.c
index 4ac39b4..fc67fb5 100644
--- a/core/src/proxy/protocols/shadowsocks.c
+++ b/core/src/proxy/protocols/shadowsocks.c
@@ -16,6 +16,7 @@
 #include "phoenix.h"
 
 #include <stdio.h>
+#include <stdlib.h>
 #include <string.h>
 #include <errno.h>
 #include <unistd.h>
@@ -295,7 +296,25 @@ ssize_t ss_recv(ss_state_t *ss, int fd,
     }
 
     size_t data_len = ss->recv_data_need - SS_TAG_LEN;
-    if (data_len > buflen) data_len = buflen;
+
+    if (data_len > buflen) {
+        /* Дешифруем полный блок во временный буфер, копируем buflen */
+        uint8_t *tmp = malloc(data_len);
+        if (!tmp) return -1;
+
+        if (ss_aead_decrypt(ss->session_key, ss->recv_nonce,
+                            ss->recv_data_buf, data_len,
+                            ss->recv_data_buf + data_len,
+                            tmp) != 0) {
+            free(tmp);
+            log_msg(LOG_WARN, "SS: ошибка дешифрования данных");
+            return -1;
+        }
+        memcpy(buf, tmp, buflen);
+        free(tmp);
+        ss->recv_len_done = false;
+        return (ssize_t)buflen;
+    }
 
     if (ss_aead_decrypt(ss->session_key, ss->recv_nonce,
                         ss->recv_data_buf, data_len,
diff --git a/core/src/proxy/protocols/vless_xhttp.c b/core/src/proxy/protocols/vless_xhttp.c
index 68b8a9a..b8cd2a3 100644
--- a/core/src/proxy/protocols/vless_xhttp.c
+++ b/core/src/proxy/protocols/vless_xhttp.c
@@ -16,6 +16,7 @@
 #include <unistd.h>
 #include <fcntl.h>
 #include <stdlib.h>
+#include <sys/syscall.h>
 
 /* ------------------------------------------------------------------ */
 /*  xhttp_session_id_gen                                               */
@@ -24,22 +25,35 @@
 void xhttp_session_id_gen(xhttp_session_id_t *sid)
 {
     uint8_t bytes[16];
-    int fd = open("/dev/urandom", O_RDONLY);
-    if (fd >= 0) {
-        ssize_t n = read(fd, bytes, sizeof(bytes));
-        close(fd);
-        if (n == sizeof(bytes)) {
-            for (int i = 0; i < 16; i++)
-                snprintf(sid->hex + i * 2, 3, "%02x", bytes[i]);
-            return;
+
+    /* getrandom() — без открытия fd (Linux 3.17+) */
+#ifdef __NR_getrandom
+    if (syscall(__NR_getrandom, bytes, sizeof(bytes), 0) == (ssize_t)sizeof(bytes))
+        goto encode;
+#endif
+
+    /* Fallback: /dev/urandom с O_CLOEXEC */
+    {
+        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
+        if (fd >= 0) {
+            ssize_t n = read(fd, bytes, sizeof(bytes));
+            close(fd);
+            if (n == (ssize_t)sizeof(bytes))
+                goto encode;
         }
     }
-    /* Fallback: pid + time */
+
+    /* Аварийный fallback: pid + time */
     snprintf(sid->hex, sizeof(sid->hex),
              "%08x%08x%08x%08x",
              (unsigned)getpid(), (unsigned)time(NULL),
              (unsigned)getpid() ^ 0xDEADBEEF,
              (unsigned)time(NULL) ^ 0xCAFEBABE);
+    return;
+
+encode:
+    for (int i = 0; i < 16; i++)
+        snprintf(sid->hex + i * 2, 3, "%02x", bytes[i]);
 }
 
 /* ------------------------------------------------------------------ */
diff --git a/core/src/proxy/tproxy.c b/core/src/proxy/tproxy.c
index 9336b55..8e7b21c 100644
--- a/core/src/proxy/tproxy.c
+++ b/core/src/proxy/tproxy.c
@@ -13,6 +13,7 @@
 #include "phoenix.h"
 
 #include <stdio.h>
+#include <stdlib.h>
 #include <string.h>
 #include <errno.h>
 #include <unistd.h>
@@ -292,7 +293,11 @@ static void tproxy_accept_tcp(tproxy_state_t *ts, int listen_fd,
 
 static void tproxy_recv_udp(tproxy_state_t *ts, int udp_fd, int family)
 {
-    uint8_t buf[TPROXY_UDP_BUF];
+    uint8_t *buf = malloc(TPROXY_UDP_BUF);
+    if (!buf) {
+        log_msg(LOG_ERROR, "TPROXY: malloc UDP буфера провалился");
+        return;
+    }
 
     for (;;) {
         struct sockaddr_storage src;
@@ -347,6 +352,8 @@ static void tproxy_recv_udp(tproxy_state_t *ts, int udp_fd, int family)
         ts->accepted++;
         dispatcher_handle_udp(&conn, buf, (size_t)n);
     }
+
+    free(buf);
 }
 
 /* ------------------------------------------------------------------ */
diff --git a/core/src/routing/ipset.c b/core/src/routing/ipset.c
deleted file mode 100644
index 6dd65ea..0000000
--- a/core/src/routing/ipset.c
+++ /dev/null
@@ -1,14 +0,0 @@
-/*
- * Управление IP-списками (nftables sets)
- *
- * Загружает списки IP-адресов и доменов для выборочной
- * маршрутизации: какой трафик идёт через прокси, какой — напрямую.
- */
-
-#include <stdio.h>
-
-int ipset_load(const char *path)
-{
-    /* TODO: загрузить IP-список из файла в nftables set */
-    return 0;
-}
diff --git a/core/src/watchdog.c b/core/src/watchdog.c
deleted file mode 100644
index 7c1919c..0000000
--- a/core/src/watchdog.c
+++ /dev/null
@@ -1,14 +0,0 @@
-/*
- * Watchdog — мониторинг работоспособности
- *
- * Периодически проверяет доступность прокси-серверов,
- * перезапускает упавшие подсистемы, пишет статистику.
- */
-
-#include <stdio.h>
-
-int watchdog_start(void)
-{
-    /* TODO: запуск таймера проверки здоровья */
-    return 0;
-}
```

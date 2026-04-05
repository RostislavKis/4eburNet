diff --git a/core/Kconfig b/core/Kconfig
index 3c2a752..10ba11b 100644
--- a/core/Kconfig
+++ b/core/Kconfig
@@ -1,4 +1,5 @@
 # Флаги компиляции phoenix-core
+# TODO: добавить #ifdef CONFIG_PHOENIX_* в код или убрать неиспользуемые (L-01)
 
 config PHOENIX_SHADOWSOCKS
     bool "Поддержка Shadowsocks"
diff --git a/core/Makefile b/core/Makefile
index 8e569f7..c69b0d4 100644
--- a/core/Makefile
+++ b/core/Makefile
@@ -13,7 +13,7 @@ define Package/phoenix-core
   CATEGORY:=Network
   TITLE:=Phoenix Router — ядро прокси-маршрутизации
   URL:=https://github.com/RostislavKis/phoenix-router
-  DEPENDS:=+libwolfssl +libnftables +libuci +libpthread
+  DEPENDS:=+libwolfssl +nftables
   PKGARCH:=all
 endef
 
@@ -33,12 +33,41 @@ define Build/Prepare
 	$(CP) ./include $(PKG_BUILD_DIR)/
 endef
 
+PHOENIX_SOURCES = \
+	$(PKG_BUILD_DIR)/src/main.c \
+	$(PKG_BUILD_DIR)/src/log.c \
+	$(PKG_BUILD_DIR)/src/resource_manager.c \
+	$(PKG_BUILD_DIR)/src/config.c \
+	$(PKG_BUILD_DIR)/src/ipc.c \
+	$(PKG_BUILD_DIR)/src/net_utils.c \
+	$(PKG_BUILD_DIR)/src/ntp_bootstrap.c \
+	$(PKG_BUILD_DIR)/src/routing/nftables.c \
+	$(PKG_BUILD_DIR)/src/routing/policy.c \
+	$(PKG_BUILD_DIR)/src/routing/rules_loader.c \
+	$(PKG_BUILD_DIR)/src/routing/device_policy.c \
+	$(PKG_BUILD_DIR)/src/proxy/tproxy.c \
+	$(PKG_BUILD_DIR)/src/proxy/dispatcher.c \
+	$(PKG_BUILD_DIR)/src/proxy/protocols/vless.c \
+	$(PKG_BUILD_DIR)/src/proxy/protocols/vless_xhttp.c \
+	$(PKG_BUILD_DIR)/src/proxy/protocols/trojan.c \
+	$(PKG_BUILD_DIR)/src/proxy/protocols/shadowsocks.c \
+	$(PKG_BUILD_DIR)/src/proxy/protocols/awg.c \
+	$(PKG_BUILD_DIR)/src/crypto/tls.c \
+	$(PKG_BUILD_DIR)/src/crypto/blake2s.c \
+	$(PKG_BUILD_DIR)/src/crypto/blake3.c \
+	$(PKG_BUILD_DIR)/src/crypto/noise.c \
+	$(PKG_BUILD_DIR)/src/dns/dns_packet.c \
+	$(PKG_BUILD_DIR)/src/dns/dns_cache.c \
+	$(PKG_BUILD_DIR)/src/dns/dns_rules.c \
+	$(PKG_BUILD_DIR)/src/dns/dns_upstream.c \
+	$(PKG_BUILD_DIR)/src/dns/dns_server.c
+
 define Build/Compile
 	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
 		-I$(PKG_BUILD_DIR)/include \
 		-o $(PKG_BUILD_DIR)/phoenix \
-		$(shell find $(PKG_BUILD_DIR) -name '*.c' -not -path '*/test/*') \
-		-lwolfssl -luci -lm
+		$(PHOENIX_SOURCES) \
+		-lwolfssl -lm
 endef
 
 define Package/phoenix-core/install
diff --git a/core/include/phoenix.h b/core/include/phoenix.h
index ceda6cd..0781ecd 100644
--- a/core/include/phoenix.h
+++ b/core/include/phoenix.h
@@ -36,7 +36,7 @@ typedef enum {
 #define PHOENIX_CONFIG_PATH     "/etc/config/phoenix"
 #define PHOENIX_PID_FILE        "/var/run/phoenix.pid"
 #define PHOENIX_LOG_FILE        "/tmp/phoenix.log"
-#define PHOENIX_LOG_MAX_BYTES   (512 * 1024)  /* 512KB — защита tmpfs */
+#define PHOENIX_LOG_MAX_BYTES   (512 * 1024)  /* 512KB — защита tmpfs (1.5% от 32MB tmpfs на 64MB RAM) */
 #define PHOENIX_RULES_DIR       "/etc/phoenix/rules/"
 
 /* Версия протокола IPC между phoenixd и LuCI */
diff --git a/core/src/config.c b/core/src/config.c
index 61935ba..7638954 100644
--- a/core/src/config.c
+++ b/core/src/config.c
@@ -95,7 +95,9 @@ static void apply_phoenix_option(PhoenixConfig *cfg, const char *key, const char
     }
 }
 
-/* MAC парсинг и нормализация */
+/* MAC парсинг и нормализация.
+ * %x без ширины безопасен: strlen==17 гарантирует макс 2 hex-цифры на октет,
+ * а проверка m[i]>255 отсеивает невалидные значения (L-07). */
 static int parse_mac(const char *str, uint8_t mac[6], char *out_str)
 {
     if (!str || strlen(str) != 17) return -1;
diff --git a/core/src/dns/dns_server.c b/core/src/dns/dns_server.c
index fcd00eb..3a68629 100644
--- a/core/src/dns/dns_server.c
+++ b/core/src/dns/dns_server.c
@@ -109,7 +109,9 @@ int dns_server_register_epoll(dns_server_t *ds, int master_epoll_fd)
     return 0;
 }
 
-/* Выбрать upstream и отправить запрос */
+/* Выбрать upstream и отправить запрос
+ * TODO: перевести на асинхронный резолвинг — сейчас блокирует main loop
+ * на время upstream таймаута (до 2 сек UDP, до 5 сек DoT/DoH) (M-16, C-02). */
 static ssize_t resolve_query(dns_server_t *ds, dns_action_t action,
                              const uint8_t *query, size_t query_len,
                              uint8_t *response, size_t resp_buflen)
diff --git a/core/src/main.c b/core/src/main.c
index bafa1ca..bb3fa76 100644
--- a/core/src/main.c
+++ b/core/src/main.c
@@ -238,7 +238,10 @@ int main(int argc, char *argv[])
     /* Настройка OOM */
     rm_apply_oom_settings();
 
-    /* Загрузка конфигурации */
+    /* Загрузка конфигурации
+     * TODO: перенести cfg на heap (malloc) для безопасности при рефакторинге.
+     * Сейчас cfg живёт на стеке main() до конца — работает корректно,
+     * но при будущем выносе в отдельную функцию станет use-after-free (H-12). */
     PhoenixConfig cfg;
     if (config_load(config_path, &cfg) < 0) {
         log_msg(LOG_ERROR, "Не удалось загрузить конфиг, завершение");
diff --git a/core/src/proxy/dispatcher.c b/core/src/proxy/dispatcher.c
index eb6cc41..3e5e330 100644
--- a/core/src/proxy/dispatcher.c
+++ b/core/src/proxy/dispatcher.c
@@ -46,6 +46,8 @@
 /*  Глобальный контекст (handle_conn вызывается без аргумента ds)      */
 /* ------------------------------------------------------------------ */
 
+/* TODO: передавать контекст явно через параметр вместо глобальных указателей.
+ * Сейчас безопасно — однопоточная архитектура, один экземпляр (M-09). */
 static dispatcher_state_t *g_dispatcher = NULL;
 static const PhoenixConfig *g_config    = NULL;
 

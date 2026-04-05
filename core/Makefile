include $(TOPDIR)/rules.mk

PKG_NAME:=phoenix-core
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/phoenix-core
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Phoenix Router — ядро прокси-маршрутизации
  URL:=https://github.com/RostislavKis/phoenix-router
  DEPENDS:=+libwolfssl +nftables
endef

define Package/phoenix-core/description
  Прокси-маршрутизатор для OpenWrt с поддержкой Shadowsocks,
  VLESS, Trojan. Автоматическая маршрутизация по спискам
  доменов и IP-адресов.
endef

define Package/phoenix-core/config
  source "$(SOURCE)/Kconfig"
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(CP) ./include $(PKG_BUILD_DIR)/
endef

PHOENIX_SOURCES = \
	$(PKG_BUILD_DIR)/src/main.c \
	$(PKG_BUILD_DIR)/src/log.c \
	$(PKG_BUILD_DIR)/src/resource_manager.c \
	$(PKG_BUILD_DIR)/src/config.c \
	$(PKG_BUILD_DIR)/src/ipc.c \
	$(PKG_BUILD_DIR)/src/net_utils.c \
	$(PKG_BUILD_DIR)/src/ntp_bootstrap.c \
	$(PKG_BUILD_DIR)/src/routing/nftables.c \
	$(PKG_BUILD_DIR)/src/routing/policy.c \
	$(PKG_BUILD_DIR)/src/routing/rules_loader.c \
	$(PKG_BUILD_DIR)/src/routing/device_policy.c \
	$(PKG_BUILD_DIR)/src/proxy/tproxy.c \
	$(PKG_BUILD_DIR)/src/proxy/dispatcher.c \
	$(PKG_BUILD_DIR)/src/proxy/protocols/vless.c \
	$(PKG_BUILD_DIR)/src/proxy/protocols/vless_xhttp.c \
	$(PKG_BUILD_DIR)/src/proxy/protocols/trojan.c \
	$(PKG_BUILD_DIR)/src/proxy/protocols/shadowsocks.c \
	$(PKG_BUILD_DIR)/src/proxy/protocols/awg.c \
	$(PKG_BUILD_DIR)/src/crypto/tls.c \
	$(PKG_BUILD_DIR)/src/crypto/blake2s.c \
	$(PKG_BUILD_DIR)/src/crypto/blake3.c \
	$(PKG_BUILD_DIR)/src/crypto/noise.c \
	$(PKG_BUILD_DIR)/src/dns/dns_packet.c \
	$(PKG_BUILD_DIR)/src/dns/dns_cache.c \
	$(PKG_BUILD_DIR)/src/dns/dns_rules.c \
	$(PKG_BUILD_DIR)/src/dns/dns_upstream.c \
	$(PKG_BUILD_DIR)/src/dns/dns_server.c \
	$(PKG_BUILD_DIR)/src/dns/dns_resolver.c

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-I$(PKG_BUILD_DIR)/include \
		-o $(PKG_BUILD_DIR)/phoenix \
		$(PHOENIX_SOURCES) \
		-lwolfssl -lm
endef

define Package/phoenix-core/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/phoenix $(1)/usr/bin/phoenix
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/phoenix/rules
endef

$(eval $(call BuildPackage,phoenix-core))

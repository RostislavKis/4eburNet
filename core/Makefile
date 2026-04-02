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
  DEPENDS:=+libwolfssl +libnftables +libuci +libpthread
  PKGARCH:=all
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
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/phoenix \
		$(PKG_BUILD_DIR)/main.c \
		$(PKG_BUILD_DIR)/config.c \
		-luci -lwolfssl -lpthread
endef

define Package/phoenix-core/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/phoenix $(1)/usr/bin/phoenix
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/phoenix/rules
endef

$(eval $(call BuildPackage,phoenix-core))

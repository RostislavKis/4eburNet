include $(TOPDIR)/rules.mk

PKG_NAME:=4eburnet-core
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/4eburnet-core
  SECTION:=net
  CATEGORY:=Network
  TITLE:=4eburNet — прокси-маршрутизатор для OpenWrt
  URL:=https://github.com/RostislavKis/4eburnet
  DEPENDS:=
endef

define Package/4eburnet-core/description
  Прокси-маршрутизатор для OpenWrt: VLESS+Reality, Trojan, Shadowsocks 2022,
  AmneziaWG, Hysteria2, ShadowTLS v3. DPI bypass, DNS over HTTPS/TLS/QUIC.
  Один бинарник ≤4MB на C23, musl static.
endef

define Package/4eburnet-core/config
  source "$(SOURCE)/Kconfig"
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

# Pre-built static binary (wolfSSL linked at compile time).
# Собирается отдельно: cd core && make -f Makefile.dev cross-$(ARCH)
# Результат: prebuilt/$(ARCH)/4eburnetd
define Build/Compile
	@if [ ! -f "$(SOURCE)/../prebuilt/$(ARCH)/4eburnetd" ]; then \
		echo "ERROR: prebuilt/$(ARCH)/4eburnetd не найден."; \
		echo "Запустите: cd core && make -f Makefile.dev cross-$(ARCH)"; \
		exit 1; \
	fi
	$(CP) $(SOURCE)/../prebuilt/$(ARCH)/4eburnetd $(PKG_BUILD_DIR)/
endef

define Package/4eburnet-core/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/4eburnetd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/4eburnet/rules
	$(INSTALL_DIR) $(1)/etc/4eburnet/dpi
endef

$(eval $(call BuildPackage,4eburnet-core))

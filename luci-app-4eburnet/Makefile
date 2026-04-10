include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-4eburnet
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-4eburnet
  SECTION:=luci
  CATEGORY:=LuCI
  TITLE:=4eburNet — прокси-маршрутизатор
  DEPENDS:=+luci-base +luci-lib-jsonc +nixio
  PKGARCH:=all
endef

define Package/luci-app-4eburnet/description
  Веб-интерфейс LuCI для управления 4eburnetd.
  VLESS+Reality, AmneziaWG, Shadowsocks 2022, DNS over HTTPS/TLS/QUIC.
endef

define Build/Compile
endef

define Package/luci-app-4eburnet/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./luasrc/controller/4eburnet.lua \
	  $(1)/usr/lib/lua/luci/controller/

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/lib/4eburnet
	$(INSTALL_DATA) ./luasrc/lib/4eburnet/*.lua \
	  $(1)/usr/lib/lua/luci/lib/4eburnet/

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/4eburnet
	$(INSTALL_DATA) ./luasrc/view/4eburnet/*.htm \
	  $(1)/usr/lib/lua/luci/view/4eburnet/

	$(INSTALL_DIR) $(1)/www/luci-static/4eburnet
	$(INSTALL_DATA) ./htdocs/luci-static/4eburnet/style.css \
	  $(1)/www/luci-static/4eburnet/
	$(INSTALL_DATA) ./htdocs/luci-static/4eburnet/app.js \
	  $(1)/www/luci-static/4eburnet/
	$(INSTALL_DATA) ./htdocs/luci-static/4eburnet/logo.png \
	  $(1)/www/luci-static/4eburnet/

	$(INSTALL_DIR) $(1)/www/luci-static/4eburnet/fonts
	$(INSTALL_DATA) ./htdocs/luci-static/4eburnet/fonts/*.woff2 \
	  $(1)/www/luci-static/4eburnet/fonts/

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/4eburnet.uci \
	  $(1)/etc/config/4eburnet

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/4eburnet.init \
	  $(1)/etc/init.d/4eburnet
endef

$(eval $(call BuildPackage,luci-app-4eburnet))

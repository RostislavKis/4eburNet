include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-4eburnet
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-4eburnet
  SECTION:=luci
  CATEGORY:=LuCI
  TITLE:=4eburNet — прокси-маршрутизатор (LuCI)
  DEPENDS:=+luci-base +ucode-mod-socket +rpcd-mod-ucode
  PKGARCH:=all
endef

define Package/luci-app-4eburnet/description
  Веб-интерфейс LuCI для управления 4eburnetd.
  VLESS+Reality, Trojan, Shadowsocks, AmneziaWG, Hysteria2, ShadowTLS v3.
  DPI bypass, DNS over HTTPS/TLS, подписки, устройства.
endef

define Build/Compile
endef

define Package/luci-app-4eburnet/install
	# ── Legacy Lua controller (OpenWrt 22.03 + luci-compat) ────────
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./luasrc/controller/4eburnet.lua \
	  $(1)/usr/lib/lua/luci/controller/

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/lib/4eburnet
	$(INSTALL_DATA) ./luasrc/lib/4eburnet/*.lua \
	  $(1)/usr/lib/lua/luci/lib/4eburnet/

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/4eburnet
	$(INSTALL_DATA) ./luasrc/view/4eburnet/*.htm \
	  $(1)/usr/lib/lua/luci/view/4eburnet/

	# ── Статические ресурсы (CSS, JS, logo) ────────────────────────
	$(INSTALL_DIR) $(1)/www/luci-static/4eburnet
	$(INSTALL_DATA) ./htdocs/luci-static/4eburnet/style.css \
	  $(1)/www/luci-static/4eburnet/
	$(INSTALL_DATA) ./htdocs/luci-static/4eburnet/app.js \
	  $(1)/www/luci-static/4eburnet/
	if [ -f ./htdocs/luci-static/4eburnet/logo.png ]; then \
	  $(INSTALL_DATA) ./htdocs/luci-static/4eburnet/logo.png \
	    $(1)/www/luci-static/4eburnet/; \
	fi

	if [ -d ./htdocs/luci-static/4eburnet/fonts ]; then \
	  $(INSTALL_DIR) $(1)/www/luci-static/4eburnet/fonts; \
	  $(INSTALL_DATA) ./htdocs/luci-static/4eburnet/fonts/*.woff2 \
	    $(1)/www/luci-static/4eburnet/fonts/; \
	fi

	# ── LuCI JS views (ucode backend) ─────────────────────────────
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/4eburnet
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/4eburnet/*.js \
	  $(1)/www/luci-static/resources/view/4eburnet/

	if [ -d ./htdocs/luci-static/resources/4eburnet ]; then \
	  $(INSTALL_DIR) $(1)/www/luci-static/resources/4eburnet; \
	  $(INSTALL_DATA) ./htdocs/luci-static/resources/4eburnet/* \
	    $(1)/www/luci-static/resources/4eburnet/; \
	fi

	# ── rpcd ucode backend + ACL + menu ────────────────────────────
	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode
	$(INSTALL_BIN) ./root/usr/share/rpcd/ucode/4eburnet.uc \
	  $(1)/usr/share/rpcd/ucode/

	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-4eburnet.json \
	  $(1)/usr/share/rpcd/acl.d/

	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/4eburnet.json \
	  $(1)/usr/share/luci/menu.d/

	# ── Конфиг, init.d, hotplug ────────────────────────────────────
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/4eburnet.uci \
	  $(1)/etc/config/4eburnet

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/4eburnet.init \
	  $(1)/etc/init.d/4eburnet

	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/etc/hotplug.d/iface/40-4eburnet \
	  $(1)/etc/hotplug.d/iface/

	# ── sub_convert.py ─────────────────────────────────────────────
	$(INSTALL_DIR) $(1)/usr/share/4eburnet
	$(INSTALL_BIN) ./files/usr/share/4eburnet/sub_convert.py \
	  $(1)/usr/share/4eburnet/

	# ── DPI файлы (ipset, whitelist, autohosts) ────────────────────
	$(INSTALL_DIR) $(1)/etc/4eburnet/dpi
	$(INSTALL_DATA) ./files/etc/4eburnet/dpi/ipset.txt \
	  $(1)/etc/4eburnet/dpi/
	$(INSTALL_DATA) ./files/etc/4eburnet/dpi/whitelist.txt \
	  $(1)/etc/4eburnet/dpi/
	$(INSTALL_DATA) ./files/etc/4eburnet/dpi/autohosts.txt \
	  $(1)/etc/4eburnet/dpi/
endef

$(eval $(call BuildPackage,luci-app-4eburnet))

include $(TOPDIR)/rules.mk

LUCI_TITLE:=4eburNet — панель управления
LUCI_DEPENDS:=+4eburnet-core
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

define Package/luci-app-4eburnet/install
	$(call Package/luci/install/template,$(1),.)

	# Lua lib: IPC клиент + UCI хелпер
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/lib/4eburnet/
	$(INSTALL_DATA) ./luasrc/lib/4eburnet/*.lua \
		$(1)/usr/lib/lua/luci/lib/4eburnet/

	# Шаблоны страниц
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/4eburnet/
	$(INSTALL_DATA) ./luasrc/view/4eburnet/*.htm \
		$(1)/usr/lib/lua/luci/view/4eburnet/

	# Static: CSS, JS, PNG
	$(INSTALL_DIR) $(1)/www/luci-static/4eburnet/
	$(INSTALL_DATA) ./htdocs/luci-static/4eburnet/*.css \
		$(1)/www/luci-static/4eburnet/
	$(INSTALL_DATA) ./htdocs/luci-static/4eburnet/*.js \
		$(1)/www/luci-static/4eburnet/
	$(INSTALL_DATA) ./htdocs/luci-static/4eburnet/*.png \
		$(1)/www/luci-static/4eburnet/

	# Web-шрифты (woff2)
	$(INSTALL_DIR) $(1)/www/luci-static/4eburnet/fonts/
	$(INSTALL_DATA) ./htdocs/luci-static/4eburnet/fonts/*.woff2 \
		$(1)/www/luci-static/4eburnet/fonts/
endef

$(eval $(call BuildPackage,luci-app-4eburnet))

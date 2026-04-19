include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-4eburnet
PKG_VERSION:=1.2.0  # должно совпадать с EBURNET_VERSION в core/Makefile.dev
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-4eburnet
  SECTION:=luci
  CATEGORY:=LuCI
  TITLE:=4eburNet — прокси-маршрутизатор (LuCI)
  DEPENDS:=+luci-base
  PKGARCH:=all
endef

define Package/luci-app-4eburnet/description
  Минимальная LuCI-вкладка для 4eburnetd.
  Показывает статус демона и ссылку на embedded dashboard (:8080).
endef

define Build/Compile
endef

define Package/luci-app-4eburnet/install
	# ── LuCI JS view (mini tab) ────────────────────────────────────
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/4eburnet
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/4eburnet/overview.js \
	  $(1)/www/luci-static/resources/view/4eburnet/

	# ── Logo (для mini tab) ────────────────────────────────────────
	$(INSTALL_DIR) $(1)/www/luci-static/resources/4eburnet
	$(INSTALL_DATA) ./htdocs/luci-static/resources/4eburnet/logo.png \
	  $(1)/www/luci-static/resources/4eburnet/

	# ── rpcd ucode backend (только status) ────────────────────────
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

	# ── sub_convert.py + embedded dashboard + geo скрипты ────────
	$(INSTALL_DIR) $(1)/usr/share/4eburnet
	$(INSTALL_BIN) ./files/usr/share/4eburnet/sub_convert.py \
	  $(1)/usr/share/4eburnet/
	$(INSTALL_DATA) ./files/usr/share/4eburnet/dashboard.html \
	  $(1)/usr/share/4eburnet/
	$(INSTALL_DATA) ./files/usr/share/4eburnet/4eburNet.png \
	  $(1)/usr/share/4eburnet/
	$(INSTALL_BIN) ./files/usr/share/4eburnet/geo_convert.sh \
	  $(1)/usr/share/4eburnet/
	$(INSTALL_BIN) ./files/usr/share/4eburnet/geo_update.sh \
	  $(1)/usr/share/4eburnet/

	# ── TC fast path kmods (cls_u32, sch_ingress, act_skbedit) ───
	$(INSTALL_DIR) $(1)/lib/modules/4eburnet
	$(INSTALL_DATA) ./files/kmods/sch_ingress.ko $(1)/lib/modules/4eburnet/
	$(INSTALL_DATA) ./files/kmods/cls_u32.ko     $(1)/lib/modules/4eburnet/
	$(INSTALL_DATA) ./files/kmods/act_skbedit.ko $(1)/lib/modules/4eburnet/

	# ── DPI файлы ──────────────────────────────────────────────────
	$(INSTALL_DIR) $(1)/etc/4eburnet/dpi
	$(INSTALL_DATA) ./files/etc/4eburnet/dpi/ipset.txt \
	  $(1)/etc/4eburnet/dpi/
	$(INSTALL_DATA) ./files/etc/4eburnet/dpi/whitelist.txt \
	  $(1)/etc/4eburnet/dpi/
	$(INSTALL_DATA) ./files/etc/4eburnet/dpi/autohosts.txt \
	  $(1)/etc/4eburnet/dpi/
endef

$(eval $(call BuildPackage,luci-app-4eburnet))

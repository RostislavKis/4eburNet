#
# 4eburNet — unified OpenWrt package (binary + LuCI + dashboard + geo data)
# Copyright (C) 2025-2026 Rostislav
# License: Proprietary
#

include $(TOPDIR)/rules.mk

PKG_NAME:=4eburnet
PKG_VERSION:=1.5.115
PKG_RELEASE:=1

PKG_MAINTAINER:=Rostislav
PKG_LICENSE:=Proprietary

# Mapping OpenWrt ARCH → prebuilt/ subdirectory
#   mipsel_24kc                          → mipsel
#   aarch64_cortex-a53 / aarch64_generic → aarch64
#   x86_64                               → x86_64
PREBUILT_ARCH:=$(ARCH)
ifeq ($(ARCH),mipsel_24kc)
  PREBUILT_ARCH:=mipsel
endif
ifneq ($(filter aarch64_%,$(ARCH)),)
  PREBUILT_ARCH:=aarch64
endif

PREBUILT_BIN:=$(CURDIR)/prebuilt/$(PREBUILT_ARCH)/4eburnetd

include $(INCLUDE_DIR)/package.mk

define Package/4eburnet
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=4eburNet — unified proxy daemon (VLESS/Shadowsocks/Trojan/Hysteria2 + TPROXY + DNS)
  URL:=https://github.com/RostislavKis/4eburNet
  MAINTAINER:=Rostislav
  DEPENDS:=+libc +libpthread +nftables +kmod-nft-tproxy +kmod-nft-fib \
           +luci-base +luci-compat +rpcd +rpcd-mod-ucode
  CONFLICTS:=4eburnet-core luci-app-4eburnet
endef

define Package/4eburnet/description
  4eburNet is a unified proxy daemon for OpenWrt providing transparent
  TPROXY forwarding through VLESS/Shadowsocks/Trojan/Hysteria2 protocols
  with integrated LuCI management interface, custom DNS server with
  fake-IP support, adblock and geo routing.

  This single package includes:
    - 4eburnetd daemon (C23, statically linked with wolfSSL 5.9)
    - LuCI web interface + dashboard HTML on :8080
    - Geo data (adblock rules, CDN lists, DPI fragment lists)
    - Subscription parser (sub_convert.py)
    - Kernel modules for TC Fast Path (sch_ingress, cls_u32, act_skbedit)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	@if [ ! -f "$(PREBUILT_BIN)" ]; then \
		echo ""; \
		echo "ERROR: $(PREBUILT_BIN) not found."; \
		echo "Build binary first:"; \
		echo "  cd core && make -f Makefile.dev cross-$(PREBUILT_ARCH)"; \
		echo ""; \
		exit 1; \
	fi
	$(CP) $(PREBUILT_BIN) $(PKG_BUILD_DIR)/4eburnetd
endef

define Build/Compile
	@echo "4eburnet: using prebuilt binary from $(PREBUILT_BIN)"
endef

define Build/Configure
endef

define Package/4eburnet/conffiles
/etc/config/4eburnet
endef

define Package/4eburnet/install
	# ── Daemon binary ──
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/4eburnetd $(1)/usr/sbin/4eburnetd

	# ── UCI defaults ──
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./luci-app-4eburnet/files/4eburnet.uci $(1)/etc/config/4eburnet

	# ── Init script (с автоматизацией DHCP option 6) ──
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./luci-app-4eburnet/files/4eburnet.init $(1)/etc/init.d/4eburnet

	# ── Hotplug ──
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./luci-app-4eburnet/files/etc/hotplug.d/iface/40-4eburnet \
		$(1)/etc/hotplug.d/iface/40-4eburnet

	# ── LuCI view ──
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/4eburnet
	$(INSTALL_DATA) ./luci-app-4eburnet/htdocs/luci-static/resources/view/4eburnet/overview.js \
		$(1)/www/luci-static/resources/view/4eburnet/overview.js

	# ── LuCI logo ──
	$(INSTALL_DIR) $(1)/www/luci-static/resources/4eburnet
	$(INSTALL_DATA) ./luci-app-4eburnet/htdocs/luci-static/resources/4eburnet/logo.png \
		$(1)/www/luci-static/resources/4eburnet/logo.png

	# ── rpcd ucode ──
	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode
	$(INSTALL_BIN) ./luci-app-4eburnet/root/usr/share/rpcd/ucode/4eburnet.uc \
		$(1)/usr/share/rpcd/ucode/4eburnet.uc

	# ── rpcd ACL ──
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./luci-app-4eburnet/root/usr/share/rpcd/acl.d/luci-app-4eburnet.json \
		$(1)/usr/share/rpcd/acl.d/luci-app-4eburnet.json

	# ── LuCI menu ──
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./luci-app-4eburnet/root/usr/share/luci/menu.d/4eburnet.json \
		$(1)/usr/share/luci/menu.d/4eburnet.json

	# ── 4eburnet shared assets ──
	$(INSTALL_DIR) $(1)/usr/share/4eburnet
	$(INSTALL_BIN) ./luci-app-4eburnet/files/usr/share/4eburnet/sub_convert.py \
		$(1)/usr/share/4eburnet/sub_convert.py
	$(INSTALL_DATA) ./luci-app-4eburnet/files/usr/share/4eburnet/4eburNet.png \
		$(1)/usr/share/4eburnet/4eburNet.png
	$(INSTALL_BIN) ./luci-app-4eburnet/files/usr/share/4eburnet/geo_convert.sh \
		$(1)/usr/share/4eburnet/geo_convert.sh
	$(INSTALL_BIN) ./luci-app-4eburnet/files/usr/share/4eburnet/geo_update.sh \
		$(1)/usr/share/4eburnet/geo_update.sh

	# ── Dashboard v2 (Vue SPA из dashboard-src/dist/) ──
	# Собирается отдельно: cd dashboard-src && npm run build
	@if [ ! -f ./dashboard-src/dist/index.html ]; then \
		echo ""; \
		echo "ERROR: dashboard-src/dist/index.html not found."; \
		echo "Build dashboard first:"; \
		echo "  cd dashboard-src && npm run build"; \
		echo ""; \
		exit 1; \
	fi
	$(INSTALL_DIR) $(1)/usr/share/4eburnet/dashboard
	$(INSTALL_DIR) $(1)/usr/share/4eburnet/dashboard/assets
	$(CP) ./dashboard-src/dist/. $(1)/usr/share/4eburnet/dashboard/

	# ── Kernel modules для TC Fast Path (только MT7621/mipsel_24kc) ──
	# TC Fast Path kmods скомпилированы под kernel 6.6 MT7621.
	# Для aarch64/x86_64 они невалидны — fast path будет недоступен,
	# но основная функциональность (TPROXY, DNS, proxy) работает.
	# Shell-level условие: $(ARCH) внутри define-блока может не
	# разворачиваться в нужное значение, поэтому проверяем в recipe time.
	@if [ "$(ARCH)" = "mipsel" ]; then \
		install -d -m0755 $(1)/lib/modules/4eburnet ; \
		install -m0644 ./luci-app-4eburnet/files/kmods/sch_ingress.ko \
			$(1)/lib/modules/4eburnet/sch_ingress.ko ; \
		install -m0644 ./luci-app-4eburnet/files/kmods/cls_u32.ko \
			$(1)/lib/modules/4eburnet/cls_u32.ko ; \
		install -m0644 ./luci-app-4eburnet/files/kmods/act_skbedit.ko \
			$(1)/lib/modules/4eburnet/act_skbedit.ko ; \
		echo "4eburnet: installed TC Fast Path kmods (3 files)" ; \
	else \
		echo "4eburnet: skipping TC Fast Path kmods (arch=$(ARCH))" ; \
	fi

	# ── DPI fragment assets ──
	$(INSTALL_DIR) $(1)/etc/4eburnet/dpi
	$(INSTALL_DATA) ./luci-app-4eburnet/files/etc/4eburnet/dpi/ipset.txt \
		$(1)/etc/4eburnet/dpi/ipset.txt
	$(INSTALL_DATA) ./luci-app-4eburnet/files/etc/4eburnet/dpi/whitelist.txt \
		$(1)/etc/4eburnet/dpi/whitelist.txt
	$(INSTALL_DATA) ./luci-app-4eburnet/files/etc/4eburnet/dpi/autohosts.txt \
		$(1)/etc/4eburnet/dpi/autohosts.txt

	# ── Rules directory (пустая, для runtime правил) ──
	$(INSTALL_DIR) $(1)/etc/4eburnet/rules
endef

define Package/4eburnet/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0

# Enable service
/etc/init.d/4eburnet enable 2>/dev/null

# Reload rpcd для применения ACL
/etc/init.d/rpcd reload 2>/dev/null

# Очистить LuCI cache
rm -rf /tmp/luci-*cache 2>/dev/null

echo ""
echo "4eburnet v$(PKG_VERSION) установлен."
echo "Запуск:     /etc/init.d/4eburnet start"
echo "Дашборд:    http://<router-ip>:8080"
echo ""
exit 0
endef

define Package/4eburnet/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/4eburnet stop 2>/dev/null
/etc/init.d/4eburnet disable 2>/dev/null
exit 0
endef

$(eval $(call BuildPackage,4eburnet))

# ── 4eburnet-geo: предкомпилированные .gbin базы (G15-3) ─────────────
# WHY Architecture:=all: .gbin — бинарные данные (структура + строковый пул),
# не машинный код. Один пакет ставится на mipsel/aarch64/x86_64 одинаково.
# Обновляется независимо от 4eburnet — позволяет менять geo-базы без передеплоя
# демона (cdn_updater также может скачивать новые версии в /usr/share/4eburnet/).
define Package/4eburnet-geo
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=4eburNet GeoSite/GeoIP databases
  DEPENDS:=4eburnet
  PKGARCH:=all
  URL:=https://github.com/RostislavKis/4eburNet
  MAINTAINER:=Rostislav
endef

define Package/4eburnet-geo/description
  Pre-compiled GeoSite/GeoIP .gbin databases for 4eburnet.
  Includes: geoip-ru, geosite-ru/ads/trackers/threats, opencck-domains.
  Updated independently from the daemon binary via cdn_updater
  or by reinstalling this package.
endef

define Package/4eburnet-geo/install
	$(INSTALL_DIR) $(1)/usr/share/4eburnet
	@if ls $(CURDIR)/prebuilt/geo/*.gbin >/dev/null 2>&1; then \
		echo "4eburnet-geo: устанавливаю $$(ls $(CURDIR)/prebuilt/geo/*.gbin | wc -l) .gbin файлов" ; \
		$(INSTALL_DATA) $(CURDIR)/prebuilt/geo/*.gbin $(1)/usr/share/4eburnet/ ; \
	else \
		echo "4eburnet-geo: WARN: prebuilt/geo/ пуст — пакет будет без данных" ; \
	fi
endef

$(eval $(call BuildPackage,4eburnet-geo))

# Синхронизировать tools/sub_convert.py → luci-app bundle
# Вызывать вручную после изменений в tools/sub_convert.py
install-tools:
	install -m 755 tools/sub_convert.py \
		luci-app-4eburnet/files/usr/share/4eburnet/sub_convert.py
	@echo "sub_convert.py синхронизирован"

.PHONY: install-tools

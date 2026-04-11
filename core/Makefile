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
	mkdir -p $(PKG_BUILD_DIR)/src
	$(CP) ./src/* $(PKG_BUILD_DIR)/src/
	$(CP) ./include $(PKG_BUILD_DIR)/
endef

# ── Kconfig → CFLAGS ──────────────────────────────────────────────────
EBURNET_CFLAGS := -std=c2x -D_GNU_SOURCE
EBURNET_CFLAGS += $(if $(CONFIG_EBURNET_VLESS),-DCONFIG_EBURNET_VLESS=1,-DCONFIG_EBURNET_VLESS=0)
EBURNET_CFLAGS += $(if $(CONFIG_EBURNET_TROJAN),-DCONFIG_EBURNET_TROJAN=1,-DCONFIG_EBURNET_TROJAN=0)
EBURNET_CFLAGS += $(if $(CONFIG_EBURNET_SS),-DCONFIG_EBURNET_SS=1,-DCONFIG_EBURNET_SS=0)
EBURNET_CFLAGS += $(if $(CONFIG_EBURNET_AWG),-DCONFIG_EBURNET_AWG=1,-DCONFIG_EBURNET_AWG=0)
EBURNET_CFLAGS += $(if $(CONFIG_EBURNET_FAKE_IP),-DCONFIG_EBURNET_FAKE_IP=1,-DCONFIG_EBURNET_FAKE_IP=0)
EBURNET_CFLAGS += $(if $(CONFIG_EBURNET_DOH),-DCONFIG_EBURNET_DOH=1,-DCONFIG_EBURNET_DOH=0)
EBURNET_CFLAGS += $(if $(CONFIG_EBURNET_QUIC),-DCONFIG_EBURNET_QUIC=1,-DCONFIG_EBURNET_QUIC=0)
EBURNET_CFLAGS += $(if $(CONFIG_EBURNET_DOQ),-DCONFIG_EBURNET_DOQ=1,-DCONFIG_EBURNET_DOQ=0)
EBURNET_CFLAGS += $(if $(CONFIG_EBURNET_PROXY_PROVIDERS),-DCONFIG_EBURNET_PROXY_PROVIDERS=1,-DCONFIG_EBURNET_PROXY_PROVIDERS=0)
EBURNET_CFLAGS += $(if $(CONFIG_EBURNET_SNIFFER),-DCONFIG_EBURNET_SNIFFER=1,-DCONFIG_EBURNET_SNIFFER=0)
EBURNET_CFLAGS += $(if $(CONFIG_EBURNET_DPI),-DCONFIG_EBURNET_DPI=1,-DCONFIG_EBURNET_DPI=0)
EBURNET_CFLAGS += $(if $(CONFIG_EBURNET_STLS),-DCONFIG_EBURNET_STLS=1,-DCONFIG_EBURNET_STLS=0)

# ── Исходники (синхронизировано с Makefile.dev) ───────────────────────
B:=$(PKG_BUILD_DIR)/src

EBURNET_SOURCES = \
	$(B)/main.c $(B)/log.c $(B)/resource_manager.c $(B)/config.c $(B)/ipc.c \
	$(B)/routing/nftables.c $(B)/routing/policy.c \
	$(B)/proxy/tproxy.c $(B)/proxy/dispatcher.c \
	$(B)/routing/rules_loader.c $(B)/ntp_bootstrap.c \
	$(B)/crypto/tls.c \
	$(B)/proxy/protocols/vless.c \
	$(B)/proxy/protocols/vless_xhttp.c \
	$(B)/proxy/protocols/trojan.c \
	$(B)/proxy/protocols/shadowsocks.c \
	$(B)/crypto/blake3.c \
	$(B)/crypto/blake2s.c $(B)/crypto/blake2b.c \
	$(B)/crypto/quic_salamander.c \
	$(B)/proxy/protocols/hysteria2.c \
	$(B)/proxy/protocols/hysteria2_udp.c \
	$(B)/proxy/protocols/hysteria2_cc.c \
	$(B)/crypto/noise.c \
	$(B)/proxy/protocols/awg.c \
	$(B)/routing/device_policy.c \
	$(B)/proxy/proxy_group.c \
	$(B)/proxy/rule_provider.c \
	$(B)/proxy/proxy_provider.c \
	$(B)/proxy/rules_engine.c \
	$(B)/proxy/sniffer.c \
	$(B)/net_utils.c \
	$(B)/dns/dns_packet.c $(B)/dns/dns_cache.c \
	$(B)/dns/dns_rules.c $(B)/dns/dns_upstream.c \
	$(B)/dns/dns_upstream_async.c \
	$(B)/dns/dns_server.c \
	$(B)/dns/dns_resolver.c \
	$(B)/dns/fake_ip.c \
	$(B)/dns/dns_upstream_doq.c \
	$(B)/crypto/quic.c \
	$(B)/geo/geo_loader.c \
	$(B)/dpi/dpi_filter.c \
	$(B)/dpi/dpi_payload.c \
	$(B)/dpi/dpi_strategy.c \
	$(B)/dpi/cdn_updater.c \
	$(B)/crypto/hmac_sha256.c \
	$(B)/proxy/protocols/shadowtls.c

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(EBURNET_CFLAGS) $(TARGET_LDFLAGS) \
		-I$(PKG_BUILD_DIR)/include \
		-o $(PKG_BUILD_DIR)/4eburnetd \
		$(EBURNET_SOURCES) \
		-lwolfssl -lm
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

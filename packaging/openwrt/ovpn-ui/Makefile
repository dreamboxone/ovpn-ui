#
# OpenWrt package for the ovpn-ui panel.
#
# The binary is NOT compiled by the SDK: packaging/openwrt/build-binary.sh produces a
# static musl build, and this package only installs it together with the procd service,
# the UCI config and the first-boot defaults. That keeps the package a pure packaging
# step, so one SDK can emit the .apk for every CPU architecture:
#
#   package/ovpn-ui/build.mk:
#       OVPNUI_BINARY:=/abs/path/ovpn-ui-arm
#       OVPNUI_PKGARCH:=arm_cortex-a7_neon-vfpv4
#       OVPNUI_VERSION:=1.9.4
#   make package/ovpn-ui/compile
#
# packaging/openwrt/make-apk.sh drives exactly that for every architecture. The values
# come from a file rather than the make command line so they reach only this package,
# not every sub-make the SDK runs for its dependencies.
#

include $(TOPDIR)/rules.mk
-include $(TOPDIR)/package/ovpn-ui/build.mk

PKG_NAME:=ovpn-ui
PKG_VERSION:=$(if $(OVPNUI_VERSION),$(OVPNUI_VERSION),0.0.0)
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=dreamboxone

include $(INCLUDE_DIR)/package.mk

# A Go binary is already stripped (-s -w); the SDK's sstrip can corrupt one.
STRIP:=:
RSTRIP:=:

define Package/ovpn-ui
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=ovpn-ui multi-protocol VPN/Xray web panel
  URL:=https://github.com/dreamboxone/ovpn-ui
  # Everything IKEv2 needs from the official feeds, so an IKEv2 inbound works right
  # after install, plus TUN and the SSL manager's tools. Keep in step with
  # openwrtIkev2Packages and openwrtPanelPackages in web/service/openwrt.go.
  DEPENDS:=+ca-bundle +kmod-tun +curl +openssl-util +socat +ip-full +kmod-nft-tproxy +kmod-ipsec4 +kmod-crypto-gcm \
	+kmod-crypto-sha256 +strongswan-charon +strongswan-swanctl \
	+strongswan-mod-vici +strongswan-mod-kernel-netlink +strongswan-mod-socket-default \
	+strongswan-mod-openssl +strongswan-mod-random +strongswan-mod-x509 \
	+strongswan-mod-pem +strongswan-mod-pkcs1 +strongswan-mod-attr \
	+strongswan-mod-eap-identity +strongswan-mod-eap-mschapv2 \
	+strongswan-mod-eap-radius +strongswan-mod-eap-tls
  PKGARCH:=$(if $(OVPNUI_PKGARCH),$(OVPNUI_PKGARCH),$(ARCH_PACKAGES))
endef

define Package/ovpn-ui/description
  Web panel (3x-ui based) with the patched Xray core embedded, plus IKEv2/IPsec
  inbounds through OpenWrt's strongSwan packages.
  Runs as a procd service; the database lives in /etc/ovpn-ui and survives sysupgrade.
endef

define Package/ovpn-ui/conffiles
/etc/config/ovpn-ui
/etc/ovpn-ui/
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	[ -n "$(OVPNUI_BINARY)" ] && [ -f "$(OVPNUI_BINARY)" ] || { \
		echo "OVPNUI_BINARY must point at a binary from packaging/openwrt/build-binary.sh" >&2; exit 1; }
	$(CP) "$(OVPNUI_BINARY)" $(PKG_BUILD_DIR)/ovpn-ui
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/ovpn-ui/install
	$(INSTALL_DIR) $(1)/usr/lib/ovpn-ui $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ovpn-ui $(1)/usr/lib/ovpn-ui/ovpn-ui
	$(INSTALL_DATA) ./files/ovpn-ui.env $(1)/usr/lib/ovpn-ui/env.sh
	$(INSTALL_BIN) ./files/ovpn-ui.credentials $(1)/usr/lib/ovpn-ui/credentials.sh
	$(INSTALL_BIN) ./files/ovpn-ui.wrapper $(1)/usr/bin/ovpn-ui

	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/config $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/ovpn-ui.init $(1)/etc/init.d/ovpn-ui
	$(INSTALL_CONF) ./files/ovpn-ui.config $(1)/etc/config/ovpn-ui
	$(INSTALL_BIN) ./files/ovpn-ui.uci-defaults $(1)/etc/uci-defaults/90-ovpn-ui

	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) ./files/ovpn-ui.keep $(1)/lib/upgrade/keep.d/ovpn-ui
endef

define Package/ovpn-ui/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
cat /etc/ovpn-ui/initial-credentials 2>/dev/null | sed 's/^/  /'
echo "  (credentials file: /etc/ovpn-ui/initial-credentials, run 'ovpn-ui info' any time)"
exit 0
endef

define Package/ovpn-ui/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
# The panel drops its bash management menu at /usr/bin/vpn-ui on start. It is not a
# package file, so remove it here; the database in /etc/ovpn-ui is deliberately kept.
grep -qs 'vpn-ui' /usr/bin/vpn-ui && rm -f /usr/bin/vpn-ui
rm -rf /usr/lib/ovpn-ui/bin
# IKEv2: close UDP 500/4500 and ESP again, and stop the charon the panel ran (procd
# stopped the panel, not its children). OpenWrt's own swanctl service stays disabled.
if [ -f /usr/share/nftables.d/chain-pre/input/90-ovpn-ui.nft ]; then
	rm -f /usr/share/nftables.d/chain-pre/input/90-ovpn-ui.nft
	fw4 -q reload 2>/dev/null
fi
/etc/init.d/swanctl running >/dev/null 2>&1 || pkill -f /usr/lib/ipsec/charon 2>/dev/null
echo "ovpn-ui removed. The database is kept in /etc/ovpn-ui; delete it by hand if unwanted."
exit 0
endef

$(eval $(call BuildPackage,ovpn-ui))

# Copyright (C) 2022 xwcoco
#
# This is free software, licensed under the GNU General Public License v3.

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-myproxy
PKG_VERSION:=1.4
PKG_RELEASE:=2


LUCI_TITLE:=LuCI support for Sing-box 
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+coreutils +coreutils-base64 +coreutils-nohup +curl \
	+ip-full +libuci-lua +lua +luci-compat +luci-lib-jsonc +resolveip +tcping 


PKG_CONFIG_DEPENDS:= \
	CONFIG_PACKAGE_$(PKG_NAME)_Nftables_Transparent_Proxy 

config PACKAGE_$(PKG_NAME)_Nftables_Transparent_Proxy
	bool "Nftables Transparent Proxy"
	select PACKAGE_dnsmasq-full
	select PACKAGE_nftables
	select PACKAGE_kmod-nft-socket
	select PACKAGE_kmod-nft-tproxy
	select PACKAGE_kmod-nft-nat
	depends on PACKAGE_$(PKG_NAME)
	default y if PACKAGE_firewall4

define Package/$(PKG_NAME)/conffiles
/etc/config/myproxy
/etc/config/myproxy_server
/usr/share/myproxy/domains_excluded
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature

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
	+ip-full +libuci-lua +lua +luci-compat +luci-lib-jsonc +resolveip +tcping +unzip



define Package/$(PKG_NAME)/conffiles
/etc/config/myproxy
/etc/config/myproxy_server
/usr/share/myproxy/domains_excluded
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature

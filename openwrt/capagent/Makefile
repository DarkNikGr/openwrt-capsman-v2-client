# SPDX-License-Identifier: GPL-2.0
#
# capagent: the native CAPsMAN v2 CAP for OpenWrt (prebuilt static binary).
#
# The binary is built outside OpenWrt by native/Makefile, which needs mbedTLS
# and the mipsel toolchain that this repository already pins (see docs/BUILD.md).
# Keeping it prebuilt makes the package reproducible without shipping a second
# copy of the source tree inside an OpenWrt feed, and lets the image script
# rebuild it from a known commit.
#
# Usage:  make package/capagent/compile  (with CAPAGENT_BIN pointing at the
#         already built native/capagent-mipsel)

include $(TOPDIR)/rules.mk

PKG_NAME:=capagent
PKG_VERSION:=$(shell cat $(CURDIR)/../../VERSION 2>/dev/null || echo 0.0.0)
PKG_RELEASE:=1
PKG_MAINTAINER:=DarkNik <darknik@users.noreply.github.com>
PKG_LICENSE:=GPL-2.0

# Optional manual launcher for the multi-identity topology.  In this repo it
# lives in scripts/; an OpenWrt feed checkout can override it.
MULTI_CAP?=$(CURDIR)/../../scripts/multi-cap.sh

include $(INCLUDE_DIR)/package.mk

define Package/capagent
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Native MikroTik CAPsMAN v2 CAP
  DEPENDS:=+libc
  URL:=https://github.com/DarkNikGr/openwrt-capsman-v2-client
endef

define Package/capagent/description
 A CAP for the official RouterOS CAPsMAN v2 manager.  It takes SSID, RSN,
 channel and VLAN from the manager and runs a PSK-free hostapd: the manager is
 the RSN authenticator and the EAPOL exchange is relayed.
endef

define Build/Compile
	# The static binary is produced by native/Makefile; nothing to build here.
endef

define Package/capagent/conffiles
/etc/cap/capagent.conf
endef

define Package/capagent/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(CAPAGENT_BIN) $(1)/usr/sbin/capagent
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/capagent.init $(1)/etc/init.d/capagent
	$(INSTALL_DIR) $(1)/etc/cap
	$(INSTALL_CONF) ./files/capagent.conf $(1)/etc/cap/capagent.conf
	# Multi-identity: opt-in launcher and the example identity map.  The init
	# script uses /etc/cap/identities.conf automatically when it exists.
	$(INSTALL_DIR) $(1)/usr/sbin
	if [ -f "$(MULTI_CAP)" ]; then \
		$(INSTALL_BIN) "$(MULTI_CAP)" $(1)/usr/sbin/multi-cap.sh; \
	fi
	$(INSTALL_CONF) ./files/identities.conf.example $(1)/etc/cap/identities.conf.example
	# first-boot zone for the on-cap VLAN bridges (br-vlan*), and the DHCP
	# option 138 request that makes MANAGER=auto work on a clean image
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/99-cap-firewall $(1)/etc/uci-defaults/99-cap-firewall
	$(INSTALL_BIN) ./files/98-cap-dhcp138 $(1)/etc/uci-defaults/98-cap-dhcp138
	# lease hook: decode option 138 into /tmp/cap-manager
	$(INSTALL_DIR) $(1)/etc/udhcpc.user.d
	$(INSTALL_BIN) ./files/99-cap-dhcp138 $(1)/etc/udhcpc.user.d/99-cap-dhcp138
endef

$(eval $(call BuildPackage,capagent))

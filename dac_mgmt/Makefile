#
# Copyright (C) 2010-2013 hua.shao@mediatek.com
#
# Ralink Property Software.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=dac_mgmt
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/dac_mgmt
	CATEGORY:=IoT
	TITLE:=Iot door access control managment package
	DEPENDS:=
endef

define Package/dac_mgmt/description
  Iot door access control managment package
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

TARGET_CFLAGS+=

define Build/Configure
endef

define Package/dac_mgmt/install
	$(INSTALL_DIR) $(1)/usr/sbin	
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dac_mgmt $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,dac_mgmt))

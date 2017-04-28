include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

# Name and release number of this package
PKG_NAME:=dac_forward
PKG_RELEASE:=1
PKG_VERSION:=1.0

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)
MAKE_ARGS:= \
	CROSS_COMPILE="$(KERNEL_CROSS)" \
	ARCH="$(LINUX_KARCH)" \
	KLIB_BUILD="$(LINUX_DIR)"

include $(INCLUDE_DIR)/package.mk

define KernelPackage/dac_forward
  SUBMENU:=dac_forward modules
  SECTION:=ko util
  TITLE:=dac_forward
  VERSION:=$(LINUX_VERSION)+$(PKG_VERSION)
  FILES:= $(PKG_BUILD_DIR)/dac_forward.ko
  MENU:=1
endef

# Uncomment portion below for Kamikaze and delete DESCRIPTION variable above
define KernelPackage/dac_forward/description
	Door access control module
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile/dac_forward
	$(MAKE) -C "$(PKG_BUILD_DIR)" $(MAKE_ARGS) CFLAGS="$(TARGET_CFLAGS)" modules
endef

define Build/Compile
	$(call Build/Compile/dac_forward)
endef

$(eval $(call KernelPackage,dac_forward))

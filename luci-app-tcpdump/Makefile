include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-tcpdump
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-tcpdump
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=TCPDump Web Interface
  DEPENDS:=+tcpdump
  PKGARCH:=all
endef

define Package/luci-app-tcpdump/description
  A simple web interface for tcpdump packet capture.
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luci-app-tcpdump/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./root/usr/lib/lua/luci/controller/tcpdump.lua $(1)/usr/lib/lua/luci/controller/tcpdump.lua
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/tcpdump
	$(INSTALL_DATA) ./root/usr/lib/lua/luci/view/tcpdump/status.htm $(1)/usr/lib/lua/luci/view/tcpdump/status.htm
endef

$(eval $(call BuildPackage,luci-app-tcpdump))

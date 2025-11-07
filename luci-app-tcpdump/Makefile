include $(TOPDIR)/rules.mk

LUCI_TITLE:=TCPDump
LUCI_DEPENDS:=+tcpdump
LUCI_PKGARCH:=all
LUCI_DESCRIPTION:=TCPDump capture frontend for OpenWrt
LUCI_MENU:=1
LUCI_MENU_PATH:=Network

include $(TOPDIR)/feeds/luci/luci.mk

define Package/$(PKG_NAME)
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=Applications
  TITLE:=$(LUCI_TITLE)
  DEPENDS:=$(LUCI_DEPENDS)
  PKGARCH:=all
endef

define Package/$(PKG_NAME)/description
  This package provides a LuCI web interface for tcpdump network packet capture.
  It allows users to capture and analyze TCP traffic without using the command line.
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./controller/tcpdump.lua $(1)/usr/lib/lua/luci/controller/
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/tcpdump
	$(INSTALL_DATA) ./view/tcpdump/index.htm $(1)/usr/lib/lua/luci/view/tcpdump/

	# 使用 $(CP) 来复制 root 目录下的所有文件（包括 ACL）
	# 这会将 ./root/usr/share/luci/acl/luci-app-tcpdump.json
	# 正确安装到 $(1)/usr/share/luci/acl/luci-app-tcpdump.json
	$(CP) ./root/* $(1)/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

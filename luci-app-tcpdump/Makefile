include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-tcpdump
PKG_VERSION:=1.0
PKG_RELEASE:=1

LUCI_TITLE:=TCPDump Web Interface
LUCI_DEPENDS:=+tcpdump +rpcd
LUCI_PKGARCH:=all
LUCI_DESCRIPTION:=Web interface for tcpdump packet capture
LUCI_MENU:=1
LUCI_MENU_PATH:=Network

include $(TOPDIR)/feeds/luci/luci.mk

# ✅ 移除重复的 Package 定义，只使用 LUCI_* 变量
# ✅ 或者使用标准的 Package 定义，但不能两者都用

define Package/luci-app-tcpdump/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./files/luci/controller/tcpdump.lua $(1)/usr/lib/lua/luci/controller/
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/tcpdump
	$(INSTALL_DATA) ./files/luci/view/tcpdump/index.htm $(1)/usr/lib/lua/luci/view/tcpdump/
	
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/acl.d/tcpdump.json $(1)/usr/share/rpcd/acl.d/
	
	# ✅ 安装 RPC 后端
	$(INSTALL_DIR) $(1)/usr/libexec/rpcd
	$(INSTALL_BIN) ./files/rpcd/luci_tcpdump.lua $(1)/usr/libexec/rpcd/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

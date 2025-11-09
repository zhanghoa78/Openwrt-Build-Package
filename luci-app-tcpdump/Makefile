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
  DEPENDS:=+luci-base +tcpdump
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
	# 安装 LuCI 控制器 - 直接从当前目录安装
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./root/usr/lib/lua/luci/controller/tcpdump.lua $(1)/usr/lib/lua/luci/controller/
	
	# 安装 LuCI 视图模板 - 直接从当前目录安装
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/tcpdump
	$(INSTALL_DATA) ./root/usr/lib/lua/luci/view/tcpdump/overview.htm $(1)/usr/lib/lua/luci/view/tcpdump/
	
	# 安装静态资源 (CSS) - 直接从当前目录安装
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/tcpdump/assets
	$(INSTALL_DATA) ./www/luci-static/resources/view/tcpdump/assets/tcpdump.css $(1)/www/luci-static/resources/view/tcpdump/assets/
endef

$(eval $(call BuildPackage,luci-app-tcpdump))

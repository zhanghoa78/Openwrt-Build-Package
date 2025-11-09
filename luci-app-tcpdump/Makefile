include $(TOPDIR)/rules.mk

PKG_NAME:=tcpdump-web
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Your Name <your@email.com>
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/tcpdump-web
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=TCPDump Web Interface
  DEPENDS:=+luci-base +tcpdump
  PKGARCH:=all
endef

define Package/tcpdump-web/description
  A web interface for tcpdump packet capture on OpenWrt.
  Provides real-time packet capture with filter support.
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/tcpdump-web/install
	# 安装 LuCI 控制器
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/controller/tcpdump.lua $(1)/usr/lib/lua/luci/controller/
	
	# 安装 LuCI 视图模板
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/tcpdump
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/view/tcpdump/overview.htm $(1)/usr/lib/lua/luci/view/tcpdump/
	
	# 安装静态资源 (CSS)
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/tcpdump/assets
	$(INSTALL_DATA) ./files/www/luci-static/resources/view/tcpdump/assets/tcpdump.css $(1)/www/luci-static/resources/view/tcpdump/assets/
endef

$(eval $(call BuildPackage,tcpdump-web))

#
# 版权 (C) 2025 你的名字 <your-email@example.com>
# 本程序为自由软件，遵循 GNU 通用公共许可证 v2 或更高版本。
#

# 引入 OpenWrt 标准构建规则
include $(TOPDIR)/rules.mk

# 插件基本信息
PKG_NAME:=luci-app-tcpdump-js
PKG_VERSION:=1.0
PKG_RELEASE:=1

# 引入基础包构建规则
include $(INCLUDE_DIR)/package.mk

# 引入 LuCI 构建规则
include $(TOPDIR)/feeds/luci/luci.mk

# 定义软件包元信息
define Package/luci-app-tcpdump-js
	$(call Package/luci/Template)
	TITLE:=TCPDump 的 LuCI 界面（JavaScript 版）
	DEPENDS:=+luci-base +luci-lib-nixio +luci-mod-rpc +tcpdump
	PKGARCH:=all
	CATEGORY:=LuCI
	SUBMENU:=Utilities
endef

# 插件描述
define Package/luci-app-tcpdump-js/description
	一个基于 JavaScript 的现代化 TCPDump Web 界面，
	通过 LuCI RPC 实现抓包控制与结果显示。
endef

# 安装阶段：将文件部署到目标系统对应路径
define Package/luci-app-tcpdump-js/install
	# 1. 创建目标目录
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/rpc
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view
	
	# ⭐️ 关键修正 #1：ImmortalWrt 菜单路径
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	
	# ⭐️ 关键修正 #2：ImmortalWrt ACL 路径
	$(INSTALL_DIR) $(1)/usr/share/acl.d

	# 2. 显式复制文件到正确位置
	$(INSTALL_DATA) ./luasrc/model/rpc/tcpdump.lua $(1)/usr/lib/lua/luci/model/rpc/
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/tcpdump.js $(1)/www/luci-static/resources/view/
	
	# ⭐️ 关键修正 #3：安装菜单到新路径
	$(INSTALL_DATA) ./luasrc/menu.d/luci-app-tcpdump-js.json $(1)/usr/share/luci/menu.d/
	
	# ⭐️ 关键修正 #4：安装 ACL 文件
	$(INSTALL_DATA) ./acl.d/luci-app-tcpdump-js.json $(1)/usr/share/acl.d/
endef

# 注册该软件包
$(eval $(call BuildPackage,luci-app-tcpdump-js))

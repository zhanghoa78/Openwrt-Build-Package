# 版权 (C) 2025 您的名字 <your-email@example.com>
# 本程序为自由软件，遵循 GNU 通用公共许可证 v2 或更高版本。

# 引入 ImmortalWrt 标准构建规则
include $(TOPDIR)/feeds/luci/luci.mk

# 插件基本信息
PKG_NAME:=luci-app-tcpdump-js
PKG_VERSION:=1.0
PKG_RELEASE:=1

# 定义软件包元信息
define Package/luci-app-tcpdump-js
  $(call Package/luci/Default)
  TITLE:=TCPDump 的 LuCI 界面（JavaScript 版）
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=Utilities
  DEPENDS:=+luci-base +luci-lib-nixio +luci-mod-rpc +tcpdump
  TITLE:=TCPDump 的 LuCI 界面（JavaScript 版）
  # ⭐️ 关键修正：使用 ImmortalWrt 标准架构声明
  PKGARCH:=all
endef

# 插件描述
define Package/luci-app-tcpdump-js/description
	一个基于 JavaScript 的现代化 TCPDump Web 界面，
	通过 LuCI RPC 实现抓包控制与结果显示。
endef

# 安装阶段：部署到 ImmortalWrt 正确路径
define Package/luci-app-tcpdump-js/install
	# 1. 创建目标目录
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/rpc
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d  # ⭐️ 关键修正：ImmortalWrt 正确路径

	# 2. 复制核心文件
	$(INSTALL_DATA) ./luasrc/model/rpc/tcpdump.lua $(1)/usr/lib/lua/luci/model/rpc/
	$(INSTALL_DATA) ./luasrc/menu.d/luci-app-tcpdump-js.json $(1)/usr/share/luci/menu.d/
	$(INSTALL_DATA) ./acl.d/luci-app-tcpdump-js.json $(1)/usr/share/rpcd/acl.d/  # ⭐️ 关键修正

	# 3. 前端资源（JavaScript）
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/tcpdump.js $(1)/www/luci-static/resources/view/
endef

# 注册该软件包
$(eval $(call BuildPackage,luci-app-tcpdump-js))

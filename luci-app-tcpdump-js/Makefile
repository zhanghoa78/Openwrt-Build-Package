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

# 引入基础包构建规则 和 LuCI 专用规则
include $(INCLUDE_DIR)/package.mk
# ⭐️ 关键修正 #1：使用现代 LuCI 的正确路径
include $(TOPDIR)/feeds/luci/luci.mk

# 定义软件包元信息
define Package/luci-app-tcpdump-js
	# 使用 LuCI 标准模板（自动设置 SECTION、CATEGORY 等）
	$(call Package/luci/Template)
	TITLE:=TCPDump 的 LuCI 界面（JavaScript 版）
	
	# ⭐️ 关键修正 #2：使用正确的现代 RPC 依赖
	DEPENDS:=+luci-base +luci-lib-nixio +luci-mod-rpc +tcpdump
	
	# ⭐️ 关键修正 #3：确保包被标记为平台无关
	PKGARCH:=all
	
	# 分类（在 LuCI 软件包列表中显示位置）
	CATEGORY:=LuCI
	SUBMENU:=Utilities
endef

# 插件描述（opkg info 时可见）
define Package/luci-app-tcpdump-js/description
	一个基于 JavaScript 的现代化 TCPDump Web 界面，
	通过 LuCI RPC 实现抓包控制与结果显示。
endef

# ⭐️ 关键修正 #4：
# 对于纯脚本包，不定义 Build/Prepare 和 Build/Compile
# 而是直接定义 install 阶段

# 安装阶段：将文件部署到目标系统对应路径
define Package/luci-app-tcpdump-js/install
	# 1. 创建目标目录
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/rpc
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view

	# 2. 显式复制文件
	$(INSTALL_DATA) ./luasrc/model/rpc/tcpdump.lua $(1)/usr/lib/lua/luci/model/rpc/
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/tcpdump.js $(1)/www/luci-static/resources/view/
endef

# 注册该软件包，使其能被 OpenWrt 构建系统识别
$(eval $(call BuildPackage,luci-app-tcpdump-js))

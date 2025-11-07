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

# 构建时的工作目录
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

# 引入基础包构建规则 和 LuCI 专用规则
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/luci.mk

# 定义软件包元信息
define Package/luci-app-tcpdump-js
	# 使用 LuCI 标准模板（自动设置 SECTION、CATEGORY 等）
	$(call Package/luci/Template)
	TITLE:=TCPDump 的 LuCI 界面（JavaScript 版）
	# 声明依赖：必须安装这些包才能运行本插件
	DEPENDS:=+luci-base +luci-lib-nixio +luci-lib-rpc +tcpdump
	# 分类（在 LuCI 软件包列表中显示位置）
	CATEGORY:=LuCI
	SUBMENU:=Utilities
endef

# 插件描述（opkg info 时可见）
define Package/luci-app-tcpdump-js/description
	一个基于 JavaScript 的现代化 TCPDump Web 界面，
	通过 LuCI RPC 实现抓包控制与结果显示。
endef

# 准备阶段：将源码复制到构建目录
define Build/Prepare
	$(CP) ./luasrc $(PKG_BUILD_DIR)/
	$(CP) ./htdocs $(PKG_BUILD_DIR)/
endef

# 编译阶段：本插件无 C 代码，无需编译
define Build/Compile
	# 留空即可
endef

# 安装阶段：将文件部署到目标系统对应路径
define Package/luci-app-tcpdump-js/install
	# 自动将 luasrc/ 映射到 /usr/lib/lua/luci/
	$(call Luci/Install/template,$(PKG_BUILD_DIR)/luasrc)
	# 自动将 htdocs/ 映射到 /www/
	$(call Luci/Install/template,$(PKG_BUILD_DIR)/htdocs)
endef

# 注册该软件包，使其能被 OpenWrt 构建系统识别
$(eval $(call BuildPackage,luci-app-tcpdump-js))

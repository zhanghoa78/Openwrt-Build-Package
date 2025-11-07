#
# 版权 (C) 2025 你 (Your Name) <your-email@example.com>
#
# 这是一个自由软件；你可以根据自由软件基金会发布的 GNU 通用公共许可证
# 的条款重新分发和/或修改它；无论是许可证的第 2 版，还是
# （根据你的选择）任何更高版本。
#

include $(TOPDIR)/rules.mk

# 插件名称和版本
PKG_NAME:=luci-app-tcpdump-js
PKG_VERSION:=1.0
PKG_RELEASE:=1

# 依赖：需要 LuCI JS 核心、RPC 和 tcpdump 本体
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)
PKG_DEPS:=+luci-base +luci-lib-nixio +luci-lib-rpc +tcpdump

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/luci.mk

define Package/luci-app-tcpdump-js
	$(call Package/luci/Module)
	TITLE:=LuCI support for TCPDump (JS Version)
	DEPENDS:=$(PKG_DEPS)
endef

define Package/luci-app-tcpdump-js/description
	A modern, JS-based LuCI interface for tcpdump.
endef

define Build/Prepare
	$(CP) ./luasrc $(PKG_BUILD_DIR)/
	$(CP) ./htdocs $(PKG_BUILD_DIR)/
endef

define Build/Compile
endef

define Package/luci-app-tcpdump-js/install
	$(call Luci/Install,$(PKG_BUILD_DIR)/luasrc,luasrc)
	$(call Luci/Install,$(PKG_BUILD_DIR)/htdocs,htdocs)
end_install

$(eval $(call BuildPackage,luci-app-tcpdump-js))

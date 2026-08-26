export ARCHS = arm64 arm64e
GO_EASY_ON_ME = 1

TARGET = iphone:clang:14.5
THEOS_LAYOUT_DIR_NAME = layout-rootless
THEOS_PACKAGE_SCHEME = rootless

export SYSROOT = $(THEOS)/sdks/iPhoneOS14.5.sdk

include $(THEOS)/makefiles/common.mk

# v2.5.0 按「注入目标」分类(真相源: ARCHITECTURE.md,架构变动必须同步更新它)
TWEAK_NAME = FolderX AppHooks IAPtools

# FolderX(SpringBoard: 文件夹变色 + 系统增强[充电限制/Wi-Fi永连])
FolderX_FILES = $(filter-out MFPanel.m MFNetworkCapture.m MFJSRules.m MFAppStoreSpoof.m MFTestFlightHooks.m MFKeychainManager.m MFClassDump.m MFDiagnostics.m MFNetAnalyzer.m MFCryptoToolbox.m MFCryptoHooks.m MFMethodTrace.m MFHostLogCapture.m MFBatteryInfo.m, $(wildcard *.xm *.m *.mm))
FolderX_FRAMEWORKS = UIKit Foundation SpringBoardServices
FolderX_CFLAGS = -fno-objc-arc -fmodules
MFSystemEnhance.m_CFLAGS = -fobjc-arc
FolderX_ARCHS = arm64 arm64e
FolderX_INSTALL_PATH = /usr/lib/TweakInject

# IAPtools v2.4.0(原 MinisFix.dylib 改名——职责纯化: 仅 IAP工具箱面板,全局 UIKit 注入)
IAPtools_FILES = MFPanel.m MFNetworkCapture.m MFJSRules.m MFDiagnosticCleaner.m MFKeychainManager.m MFClassDump.m MFDiagnostics.m MFNetAnalyzer.m MFCryptoToolbox.m MFCryptoHooks.m MFMethodTrace.m MFHostLogCapture.m MFBatteryInfo.m
IAPtools_FRAMEWORKS = UIKit Foundation Security
IAPtools_LDFLAGS = -weak_framework UIKit -weak_framework StoreKit -weak_framework JavaScriptCore -lz
IAPtools_CFLAGS = -fobjc-arc -Wno-everything
IAPtools_ARCHS = arm64 arm64e
IAPtools_INSTALL_PATH = /usr/lib/TweakInject

# AppHooks v2.4.0(原 AppStoreSpoof 扩编——指定进程注入: appstored/installd/TestFlight)
AppHooks_FILES = MFAppStoreSpoof.m MFTestFlightHooks.m
AppHooks_FRAMEWORKS = Foundation
AppHooks_CFLAGS = -fobjc-arc
AppHooks_ARCHS = arm64 arm64e
AppHooks_INSTALL_PATH = /usr/lib/TweakInject


include $(THEOS_MAKE_PATH)/tweak.mk
SUBPROJECTS += folderx
include $(THEOS_MAKE_PATH)/aggregate.mk

# ============================================================
# minisfixd(v2.6.31): 特权充电控制 LaunchDaemon
# IOKit power source 直写需要 powersource-write entitlement,
# 注入 dylib 给不了宿主进程 → 独立 daemon 持证上岗(对标 ChargeLimiter)
# ============================================================
MINISFIXD_BIN = layout-rootless/usr/bin/minisfixd

before-package::
	@mkdir -p layout-rootless/usr/bin
	$(CC) -arch arm64 -arch arm64e -isysroot $(SYSROOT) -miphoneos-version-min=14.5 \
		-framework CoreFoundation -O2 -Wall \
		-o $(MINISFIXD_BIN) minisfixd.c
	$(THEOS)/bin/ldid -Sminisfixd.entitlements $(MINISFIXD_BIN)
	@echo "[minisfixd] built and entitled: $(MINISFIXD_BIN)"


# ============================================================
# 外部依赖: Dobby(github.com/jmpews/Dobby)需预编译静态库
# 方案:CI 中 git submodule 添加 Dobby,编译 libdobby.a 到 $(THEOS)/lib/
# 临时占位:若无 libdobby.a,UnseenHooks 会链接失败(CI 日志会报错)
# ============================================================

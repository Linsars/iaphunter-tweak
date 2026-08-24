export ARCHS = arm64 arm64e
GO_EASY_ON_ME = 1

TARGET = iphone:clang:14.5
THEOS_LAYOUT_DIR_NAME = layout-rootless
THEOS_PACKAGE_SCHEME = rootless

export SYSROOT = $(THEOS)/sdks/iPhoneOS14.5.sdk

include $(THEOS)/makefiles/common.mk

# v2.5.0 按「注入目标」分类(真相源: ARCHITECTURE.md,架构变动必须同步更新它)
TWEAK_NAME = FolderX AppHooks IAPtools UnseenHooks

# FolderX(SpringBoard: 文件夹变色 + 系统增强[充电限制/Wi-Fi永连])
FolderX_FILES = $(filter-out MFPanel.m MFNetworkCapture.m MFJSRules.m MFAppStoreSpoof.m MFTestFlightHooks.m MFKeychainManager.m MFClassDump.m MFDiagnostics.m MFNetAnalyzer.m MFCryptoToolbox.m MFCryptoHooks.m MFMethodTrace.m UnseenHooks.mm, $(wildcard *.xm *.m))
FolderX_FRAMEWORKS = UIKit Foundation SpringBoardServices
FolderX_CFLAGS = -fno-objc-arc -fmodules
MFSystemEnhance.m_CFLAGS = -fobjc-arc
FolderX_ARCHS = arm64 arm64e

# IAPtools v2.4.0(原 MinisFix.dylib 改名——职责纯化: 仅 IAP工具箱面板,全局 UIKit 注入)
IAPtools_FILES = MFPanel.m MFNetworkCapture.m MFJSRules.m MFDiagnosticCleaner.m MFKeychainManager.m MFClassDump.m MFDiagnostics.m MFNetAnalyzer.m MFCryptoToolbox.m MFCryptoHooks.m MFMethodTrace.m
IAPtools_FRAMEWORKS = UIKit Foundation Security
IAPtools_LDFLAGS = -weak_framework UIKit -weak_framework StoreKit -weak_framework JavaScriptCore -lz
IAPtools_CFLAGS = -fobjc-arc -Wno-everything
IAPtools_ARCHS = arm64 arm64e

# AppHooks v2.4.0(原 AppStoreSpoof 扩编——指定进程注入: appstored/installd/TestFlight)
AppHooks_FILES = MFAppStoreSpoof.m MFTestFlightHooks.m
AppHooks_FRAMEWORKS = Foundation
AppHooks_CFLAGS = -fobjc-arc
AppHooks_ARCHS = arm64 arm64e
AppHooks_INSTALL_PATH = /usr/lib/TweakInject

# UnseenHooks v2.5.0(反检测/隐私——双进程注入: backboardd + SpringBoard)
# 依赖 Dobby(内联 hook 引擎,静态链接 libdobby.a,见外部依赖说明)
UnseenHooks_FILES = UnseenHooks.mm
UnseenHooks_FRAMEWORKS = UIKit Foundation QuartzCore BackBoardServices
UnseenHooks_PRIVATE_FRAMEWORKS = BackBoardServices
UnseenHooks_CFLAGS = -fobjc-arc -DTARGET_BACKBOARDD=0 -DTARGET_SPRINGBOARD=0
UnseenHooks_LDFLAGS = -ldobby
UnseenHooks_ARCHS = arm64 arm64e
UnseenHooks_INSTALL_PATH = /usr/lib/TweakInject

# 两进程分编译:同源文件,不同宏
UnseenHooks_BACKBOARDD_FILES = UnseenHooks.mm
UnseenHooks_BACKBOARDD_CFLAGS = -fobjc-arc -DTARGET_BACKBOARDD=1 -DTARGET_SPRINGBOARD=0
UnseenHooks_SPRINGBOARD_FILES = UnseenHooks.mm
UnseenHooks_SPRINGBOARD_CFLAGS = -fobjc-arc -DTARGET_BACKBOARDD=0 -DTARGET_SPRINGBOARD=1

include $(THEOS_MAKE_PATH)/tweak.mk
SUBPROJECTS += folderx
include $(THEOS_MAKE_PATH)/aggregate.mk

# ============================================================
# 外部依赖: Dobby(github.com/jmpews/Dobby)需预编译静态库
# 方案:CI 中 git submodule 添加 Dobby,编译 libdobby.a 到 $(THEOS)/lib/
# 临时占位:若无 libdobby.a,UnseenHooks 会链接失败(CI 日志会报错)
# ============================================================

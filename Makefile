export ARCHS = arm64 arm64e
GO_EASY_ON_ME = 1
PACKAGE_VERSION = 1.2.1

TARGET = iphone:clang:14.5
THEOS_LAYOUT_DIR_NAME = layout-rootless
THEOS_PACKAGE_SCHEME = rootless

export SYSROOT = $(THEOS)/sdks/iPhoneOS14.5.sdk

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FolderX MinisFix AppStoreSpoof

# FolderX（文件夹变色——原有功能不变）
FolderX_FILES = $(filter-out MFPanel.m MFNetworkCapture.m MFJSRules.m MFAppStoreSpoof.m, $(wildcard *.xm *.m))
FolderX_FRAMEWORKS = UIKit Foundation SpringBoardServices
FolderX_CFLAGS = -fno-objc-arc -fmodules
FolderX_ARCHS = arm64 arm64e

# IAPHunter 已合并进 MinisFix（SK hooks + IAP 收集 + 交易观察器）

# MinisFix v5.0（新面板：数据分析/网络修改/Product）
MinisFix_FILES = MFPanel.m MFNetworkCapture.m MFJSRules.m
MinisFix_FRAMEWORKS = UIKit Foundation StoreKit JavaScriptCore
MinisFix_LDFLAGS = -weak_framework UIKit -weak_framework StoreKit -weak_framework JavaScriptCore
MinisFix_CFLAGS = -fobjc-arc -Wno-everything
MinisFix_ARCHS = arm64 arm64e

# AppStoreSpoof（版本伪装——使用 method_setImplementation 替代 MSHookMessageEx）
AppStoreSpoof_FILES = MFAppStoreSpoof.m
AppStoreSpoof_FRAMEWORKS = Foundation
AppStoreSpoof_CFLAGS = -fobjc-arc
AppStoreSpoof_ARCHS = arm64 arm64e
AppStoreSpoof_INSTALL_PATH = /usr/lib/TweakInject

include $(THEOS_MAKE_PATH)/tweak.mk
SUBPROJECTS += folderx
include $(THEOS_MAKE_PATH)/aggregate.mk

export ARCHS = arm64 arm64e
GO_EASY_ON_ME = 1
PACKAGE_VERSION = 5.0

TARGET = iphone:clang:14.5
THEOS_LAYOUT_DIR_NAME = layout-rootless
THEOS_PACKAGE_SCHEME = rootless

export SYSROOT = $(THEOS)/sdks/iPhoneOS14.5.sdk

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FolderX IAPHunter MinisFix

# FolderX（文件夹变色——原有功能不变）
FolderX_FILES = $(filter-out MFPanel.m MFNetworkCapture.m, $(wildcard *.xm *.m))
FolderX_FRAMEWORKS = UIKit Foundation SpringBoardServices
FolderX_CFLAGS = -fno-objc-arc -fmodules
FolderX_ARCHS = arm64 arm64e

# IAPHunter（旧 IAP 收集——保留向后兼容）
IAPHunter_FILES = IAP/IAPHunter.m
IAPHunter_FRAMEWORKS = UIKit Foundation StoreKit
IAPHunter_CFLAGS = -fno-objc-arc
IAPHunter_ARCHS = arm64

# MinisFix v5.0（新面板：数据分析/网络修改/FLEX/Product）
# FLEX 源码在构建时由 GH Actions clone 到 FLEX/ 目录
FLEX_FILES := $(shell find FLEX/Classes -name '*.m' -o -name '*.mm' 2>/dev/null)
MinisFix_FILES = MFPanel.m MFNetworkCapture.m $(FLEX_FILES)
MinisFix_FRAMEWORKS = UIKit Foundation StoreKit Security CoreLocation
MinisFix_CFLAGS = -fobjc-arc -Wno-everything $(shell find FLEX/Classes -type d -exec echo -I{} \; 2>/dev/null)
MinisFix_ARCHS = arm64 arm64e

include $(THEOS_MAKE_PATH)/tweak.mk
SUBPROJECTS += folderx
include $(THEOS_MAKE_PATH)/aggregate.mk

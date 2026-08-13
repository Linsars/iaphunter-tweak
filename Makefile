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
MinisFix_CFLAGS = -fno-objc-arc -Wno-everything -IFLEX/Classes/Headers -IFLEX/Classes -IFLEX/Classes/Core -IFLEX/Classes/Network -IFLEX/Classes/Manager -IFLEX/Classes/Utility -IFLEX/Classes/Utility/Categories -IFLEX/Classes/Utility/Runtime -IFLEX/Classes/Editing -IFLEX/Classes/Editing/ArgumentInputViews -IFLEX/Classes/ExplorerInterface -IFLEX/Classes/ExplorerInterface/Bookmarks -IFLEX/Classes/ExplorerInterface/Tabs -IFLEX/Classes/GlobalStateExplorers -IFLEX/Classes/GlobalStateExplorers/DatabaseBrowser -IFLEX/Classes/GlobalStateExplorers/FileBrowser -IFLEX/Classes/GlobalStateExplorers/Globals -IFLEX/Classes/GlobalStateExplorers/Keychain -IFLEX/Classes/GlobalStateExplorers/RuntimeBrowser -IFLEX/Classes/GlobalStateExplorers/SystemLog -IFLEX/Classes/ObjectExplorers -IFLEX/Classes/ObjectExplorers/Sections -IFLEX/Classes/ObjectExplorers/Sections/Shortcuts -IFLEX/Classes/Toolbar -IFLEX/Classes/ViewHierarchy -IFLEX/Classes/ViewHierarchy/SnapshotExplorer -IFLEX/Classes/ViewHierarchy/TreeExplorer -IFLEX/Classes/Network/OSCache -IFLEX/Classes/Network/PonyDebugger
MinisFix_ARCHS = arm64 arm64e

include $(THEOS_MAKE_PATH)/tweak.mk
SUBPROJECTS += folderx
include $(THEOS_MAKE_PATH)/aggregate.mk

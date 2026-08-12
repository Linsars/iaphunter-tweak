export ARCHS = arm64 arm64e
GO_EASY_ON_ME = 1
PACKAGE_VERSION = 4.0

TARGET = iphone:clang:14.5
THEOS_LAYOUT_DIR_NAME = layout-rootless
THEOS_PACKAGE_SCHEME = rootless

export SYSROOT = $(THEOS)/sdks/iPhoneOS14.5.sdk

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FolderX IAPHunter

FolderX_FILES = $(wildcard *.xm *.m)
FolderX_FRAMEWORKS = UIKit Foundation SpringBoardServices
FolderX_CFLAGS = -fno-objc-arc
FolderX_ARCHS = arm64 arm64e

IAPHunter_FILES = IAP/IAPHunter.m
IAPHunter_FRAMEWORKS = UIKit Foundation StoreKit
IAPHunter_CFLAGS = -fno-objc-arc
IAPHunter_ARCHS = arm64

include $(THEOS_MAKE_PATH)/tweak.mk
SUBPROJECTS += folderx
include $(THEOS_MAKE_PATH)/aggregate.mk

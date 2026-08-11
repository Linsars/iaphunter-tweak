export ARCHS = arm64
GO_EASY_ON_ME = 1
PACKAGE_VERSION = 1.3.5

TARGET = iphone:clang:14.5
THEOS_LAYOUT_DIR_NAME = layout-rootless
THEOS_PACKAGE_SCHEME = rootless

export SYSROOT = $(THEOS)/sdks/iPhoneOS14.5.sdk

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = IAPHunter

$(TWEAK_NAME)_FILES = IAPHunter.m
$(TWEAK_NAME)_FRAMEWORKS = UIKit Foundation StoreKit
$(TWEAK_NAME)_CFLAGS = -fno-objc-arc

include $(THEOS_MAKE_PATH)/tweak.mk

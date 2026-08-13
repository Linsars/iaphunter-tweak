// MFPanel.h — MinisFix v5.0 面板系统头文件
// 四板块：数据分析 / 网络修改 / FLEX / Product
// 呼出：双指长按

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

// ====== 全局状态 ======
extern UIView *g_mfPanelOverlay;
extern UIViewController *g_mfPanelRootVC;
extern id g_mfCtrl;
extern NSMutableArray *g_mfPages;
extern CGFloat g_mfCardW, g_mfCardH;

// ====== 日志 ======
void mfLog(NSString *fmt, ...);
#define MFLOG(fmt, ...) mfLog(fmt, ##__VA_ARGS__)

// ====== Prefs ======
NSDictionary *mfPrefsDict(void);
BOOL mfPrefBool(NSString *key, BOOL def);
void mfSetBoolPref(NSString *key, BOOL val);
void mfSetPrefDouble(NSString *key, double val);
double mfPrefDouble(NSString *key, double def);

// ====== 面板导航（定义在 MFPanel.m） ======
UIView *mfMakePage(NSString *title, BOOL showBack);
void mfPushPage(UIView *page);
void mfPopPage(void);
void mfClosePanel(void);
CGFloat mfGridButton(UIView *card, CGFloat x, CGFloat y, CGFloat w, NSString *title, NSString *emoji, SEL action, BOOL switchMode, NSString *pfx);

// ====== 功能页面入口（各模块 .m 定义） ======
// 数据分析（MFNetworkCapture.m）
void mfShowDataAnalysisPage(void);    // 实时捕获网络请求 + 数据解密
void mfShowNetworkCapturePage(void);   // 网络捕获列表
void mfShowCryptoToolboxPage(void);    // 解密工具箱

// 网络修改（MFNetworkCapture.m）
void mfShowNetworkModifyPage(void);    // 拦截规则列表 + 开关
void mfInstallNetworkCapture(void);     // 安装 NSURLProtocol（ctor 调用）

// FLEX（MFPanel.m）
void mfShowFlexPage(void);             // FLEX 调试器

// Product（IAPHunter）（MFPanel.m）
void mfShowProductPage(void);          // 扫描购买 / 手动购买 / 图标解锁
void mfShowScanPage(void);
void mfShowManualBuyPage(void);
void mfShowIconPage(void);

// FakeGPS（MFPanel.m）
void mfShowGpsPage(void);

// ====== FLEX 呼出 ======
// FLEX 源码直接编译进 dylib，调用 [FLEXManager.sharedManager showExplorer]
// 定义在 MFPanel.m
void mfShowFLEX(void);

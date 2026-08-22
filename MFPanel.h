// MFPanel.h — MinisFix v5.0 面板系统头文件
// 三板块：数据分析 / 网络修改 / Product
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
extern UIView *g_mfCardContentView;
extern UIView *g_mfHomePage;
extern UIVisualEffectView *g_mfCardView;
extern CGFloat g_mfHomeCardH;
void mfSetCardHeight(CGFloat h);

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

// Product（IAPHunter）（MFPanel.m）
void mfShowProductPage(void);          // 扫描购买 / 手动购买 / 图标解锁
void mfShowScanPage(void);
void mfShowManualBuyPage(void);
void mfShowIconPage(void);

// Keychain（MFKeychainManager.m）
void mfShowKeychainManagerPage(void);       // Keychain 主页
void mfShowKeychainListPageAction(void);    // 查看列表
void mfCopyKeychainAction(void);            // 导出到剪贴板

// ClassDump（MFClassDump.m）— v1.5.0 数据分析板块
void mfShowClassDumpPage(void);             // ClassDump 页
void mfClassDumpStartAction(UIProgressView *pv, UILabel *lb, UIButton *btn, UIView *actionRow);
void mfShowRestorePromptAction(void);       // 从剪贴板恢复
void mfShowKeychainDetail(NSDictionary *item); // 详情 (由 MFPanelCtrl 转发)

// ====== JS 规则引擎（MFJSRules.m） ======
BOOL mfJSLoadScript(NSString *script);
NSDictionary *mfJSRunRequestHeaders(NSString *method, NSString *url, NSDictionary *headers);
NSDictionary *mfJSRunResponseHeaders(int status, NSString *url, NSDictionary *headers);

// ====== 捕获数据模型 ======
@interface MFNetRecord : NSObject
@property (copy) NSString *url;
@property (copy) NSString *method;
@property (copy) NSDictionary *reqHeaders;
@property (copy) NSData *reqBody;
@property (copy) NSDictionary *respHeaders;
@property (copy) NSData *respBody;
@property NSInteger status;
@property (copy) NSString *mimeType;
@property (strong) NSDate *timestamp;
@property (copy) NSString *summary;
@end
void mfShowCaptureDetailPage(MFNetRecord *rec);

// ====== 拦截规则模型（实现 MFNetworkCapture.m） ======
// 规则隔离：appBundle 非空时只对创建它的 app 生效
@interface MFRewriteRule : NSObject
@property (copy) NSString *pattern;
@property (copy) NSString *matchType;    // url / regex / contain
@property (copy) NSString *action;       // block / replaceReq / replaceResp
@property (copy) NSString *urlReplace;
@property (copy) NSString *bodyReplace;
@property (copy) NSDictionary *headerReplaces;
@property BOOL enabled;
@property (copy) NSString *appBundle;
- (NSDictionary *)toDict;
+ (instancetype)fromDict:(NSDictionary *)d;
@end
void mfSaveRule(MFRewriteRule *rule, NSInteger index);   // index<0 追加
void mfRemoveRule(NSInteger index);
NSString *mfCurrentBundleId(void);
void mfShowRuleEditPage(NSString *pattern, NSString *action, NSInteger index, BOOL fromList);

// ====== 诊断日志清理（MFDiagnosticCleaner.m） ======
void mfDiagnosticCleanupFromSettings(void);

// ====== Keychain 管理（MFKeychainManager.m） ======
void mfShowKeychainManagerPage(void);
void mfCopyICloudRecordIDFromCell(UIViewController *vc, UIView *cell);

// ====== ClassDump 浏览器（MFClassDump.m） ======
typedef struct { uint32_t localOff; uint32_t csize; uint32_t usize; uint16_t method; } MFZipEnt;
NSDictionary *mfZipBuildIndex(NSString *path);                 // @{name: NSValue(MFZipEnt)}
NSData *mfZipReadEntry(NSString *path, const MFZipEnt *e);     // 按需解压单条目
void mfShowCDBrowserPage(NSString *zipPath);                   // 文件列表 + 搜索
void mfShowCDFilePage(NSString *zipPath, NSString *entry);     // 单文件查看 + 文内搜索

// ====== 诊断（MFDiagnostics.m） ======
void mfShowSecurityScanPage(void);        // 安全扫描八连扫
void mfShowMachODeepPage(void);           // MachO 深检
void mfShowTextReportPage(NSString *title, NSString *text, NSString *exportName); // 通用文本报告页
void mfSecurityScanRun(int idx, UIButton *btn); // idx=-1 全扫
NSString *mfMachOSections(void);
NSString *mfMachODylibs(void);
NSString *mfMachOStrings(void);
NSString *mfMachOSymbols(void);
NSString *mfMachORuntime(void);


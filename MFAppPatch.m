// MFAppPatch.m — 进程层 patch 引擎 (v2.20.0, 2026-09-04)
// 灵感来源: ReflixPatch-3.0.5 逆向 (vm_protect 写 __text 模式) — 见 reven-recon/REFLIXPATCH-REPORT.md
// 【归属】IAPtools.dylib (IAP 域); 实验模拟页入口; 不碰系统进程
// 【铁律】ctor 有系统进程守卫(IAPtools 既有); 本文件不新增 ctor, 由 MFPanel ctor 按开关拉起
//
// 三层能力:
//   1. 规则引擎: prefs 读 JSON 规则表, bundleID+version 匹配当前进程
//   2. 执行器:   kind=method → objc swizzle;  kind=text → vm_protect(0x13)+写字节+恢复
//   3. 采集器:   hook vm_protect/mach_msg, 抓外部补丁器(ReflixPatch 之类)的点位落盘
//
// 规则表格式 (prefs key = mfAppPatchRules, 值 = JSON 字符串):
// [{
//   "bid": "com.magicgroot.gooby", "ver": "3.0.5", "note": "Reflix Pro gate",
//   "patches": [
//     {"kind":"method","cls":"ProGateChecker","sel":"isPro","ret":true},
//     {"kind":"text","off":"0x12345678","old":"1f2003d5","new":"20008052c0035fd6"}
//   ]
// }]

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <libkern/OSCacheControl.h>
#include <sys/sysctl.h>

#import "MFPanel.h"
#import "fishhook.h"

// ====== 偏好 ======
BOOL mfAppPatchIsOn(void) {
    return mfPrefBool(@"mfAppPatchEnabled", NO);
}
long mfAppPatchHits(void); // fwd
void apInstallCollectors(void); // fwd
void mfAppPatchSectionInLabPage(UIView *page, CGFloat *yio); // fwd
NSString *mfAppPatchRulesJSON(void);
void mfAppPatchSetRulesJSON(NSString *json);

static NSString *MFPrefsPath(void) {
    return @"/var/mobile/Library/Preferences/com.linsars.minisfix.plist";
}
static id mfReadPrefObj(NSString *key) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:MFPrefsPath()];
    return d[key];
}
static void mfWritePrefObj(NSString *key, id val) {
    NSMutableDictionary *d = [[NSDictionary dictionaryWithContentsOfFile:MFPrefsPath()] mutableCopy] ?: [NSMutableDictionary dictionary];
    if (val) d[key] = val; else [d removeObjectForKey:key];
    [d writeToFile:MFPrefsPath() atomically:YES];
}

// ====== 状态 ======
static long g_apHits = 0;          // 成功 patch 数
static long g_apCollHits = 0;      // 采集到的外部 patch 数
static BOOL g_apCollInstalled = NO;
static NSMutableArray *g_apLog = nil;   // 最近 50 条日志
static NSObject *g_apLock = nil;

static void apLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void apLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!g_apLock) g_apLock = [NSObject new];
    @synchronized (g_apLog) {
        if (!g_apLog) g_apLog = [NSMutableArray new];
        [g_apLog insertObject:[NSString stringWithFormat:@"%@ %@", [NSDate date], s] atIndex:0];
        if (g_apLog.count > 50) [g_apLog removeLastObject];
    }
    mfLog(@"[AppPatch] %@", s);
}
long mfAppPatchHits(void) { return g_apHits; }

// ====== 工具: hex string <-> bytes (纯 C 解析, 避开 SDK selector 可见性怪问题) ======
static NSMutableData *apHexToBytes(NSString *hex) {
    NSMutableData *d = [NSMutableData data];
    if (![hex isKindOfClass:[NSString class]]) return d;
    const unsigned char *s = (const unsigned char*)hex.UTF8String;
    if (!s) return d;
    int hi = -1; // -1 = 待高半字节
    for (const unsigned char *p = s; *p; p++) {
        unsigned char c = *p; int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else if (c == ' ' || c == '\t' || c == '\n') continue;
        else return [NSMutableData data]; // 非法字符
        if (hi < 0) { hi = v; }
        else { unsigned char b = (unsigned char)((hi << 4) | v); [d appendBytes:&b length:1]; hi = -1; }
    }
    if (hi >= 0) return [NSMutableData data]; // 奇数长度
    return d;
}
static NSString *apBytesToHex(const void *bytes, NSUInteger len) {
    if (!bytes || !len) return @"";
    NSMutableString *s = [NSMutableString stringWithCapacity:len * 3];
    const unsigned char *b = bytes;
    for (NSUInteger i = 0; i < len; i++) [s appendFormat:@"%02x", b[i]];
    return s;
}

// ====== 当前 app 信息 ======
static NSString *apCurBundleID(void) {
    return [[NSBundle mainBundle] bundleIdentifier] ?: @"";
}
static NSString *apCurVersion(void) {
    return [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
}

// ====== Mach-O 自我定位: 找主程序 __TEXT 的 vmaddr/slide ======
// ReflixPatch 同款思路: _dyld_get_image_header(0) = 主程序
static uintptr_t apMainImageBase(void) {
    if (_dyld_image_count() == 0) return 0;
    const struct mach_header *mh = _dyld_get_image_header(0);
    return (uintptr_t)mh;
}

// ====== text patch: vm_protect 三步 (ReflixPatch 同款) ======
static BOOL apTextPatch(uintptr_t fileOffAddr, NSData *expectOld, NSData *newBytes, NSString **err) {
    // off 是相对主程序加载基址的 vm offset (即主程序文件里的 vmaddr 偏移)
    uintptr_t base = apMainImageBase();
    if (!base) { *err = @"no main image"; return NO; }
    volatile uintptr_t target = base + fileOffAddr;
    // old 校验
    if (expectOld.length) {
        NSData *cur = [NSData dataWithBytes:(void*)target length:expectOld.length];
        if (![cur isEqualToData:expectOld]) {
            *err = [NSString stringWithFormat:@"old mismatch @0x%lx: cur=%@ want=%@", (unsigned long)fileOffAddr, apBytesToHex(cur.bytes, cur.length), apBytesToHex(expectOld.bytes, expectOld.length)];
            return NO;
        }
    }
    kern_return_t kr = vm_protect(mach_task_self(), target & ~0xFFFUL, 0x1000, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        *err = [NSString stringWithFormat:@"vm_protect RW failed kr=%d", kr];
        return NO;
    }
    memcpy((void*)target, newBytes.bytes, newBytes.length);
    // 清 instruction cache — 否则 CPU 可能跑旧指令
    sys_icache_invalidate((void*)target, newBytes.length);
    kr = vm_protect(mach_task_self(), target & ~0xFFFUL, 0x1000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        *err = [NSString stringWithFormat:@"vm_protect RX restore failed kr=%d", kr];
        return NO; // 字节已写, 权限没恢复 — 仍算半成功
    }
    return YES;
}

// ====== objc hook: 把方法 IMP 换成常量返回 ======
static long g_apStubTrue = 0, g_apStubFalse = 0;
static void apStubTrue(id self, SEL _cmd) { g_apStubTrue++; }
static BOOL apStubTrueB(id self, SEL _cmd) { g_apStubTrue++; return YES; }
static void apStubFalse(id self, SEL _cmd) { g_apStubFalse++; }
static BOOL apStubFalseB(id self, SEL _cmd) { g_apStubFalse++; return NO; }

static BOOL apMethodPatch(NSString *clsName, NSString *selName, BOOL ret, NSString **err) {
    Class cls = NSClassFromString(clsName);
    if (!cls) { *err = [NSString stringWithFormat:@"class %@ not found", clsName]; return NO; }
    SEL sel = NSSelectorFromString(selName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) m = class_getClassMethod(cls, sel);
    if (!m) { *err = [NSString stringWithFormat:@"method %@/%@ not found", clsName, selName]; return NO; }
    // 判断原方法是否有返回值 (粗判: 类型编码首字符)
    char retType = method_copyReturnType(m)[0];
    IMP newImp;
    if (retType == 'B' || retType == 'c') newImp = ret ? (IMP)apStubTrueB : (IMP)apStubFalseB;
    else newImp = ret ? (IMP)apStubTrue : (IMP)apStubFalse;
    method_setImplementation(m, newImp);
    return YES;
}

// ====== 规则执行 ======
static void apApplyRules(void) {
    if (!mfAppPatchIsOn()) return;
    @try {
        NSString *rulesJSON = mfReadPrefObj(@"mfAppPatchRules");
        if (![rulesJSON isKindOfClass:[NSString class]] || rulesJSON.length < 5) return;
        NSData *rd = [rulesJSON dataUsingEncoding:NSUTF8StringEncoding];
        NSArray *rules = [NSJSONSerialization JSONObjectWithData:rd options:0 error:nil];
        if (![rules isKindOfClass:[NSArray class]]) return;
        NSString *curBid = apCurBundleID();
        NSString *curVer = apCurVersion();
        for (NSDictionary *rule in rules) {
            if (![rule isKindOfClass:[NSDictionary class]]) continue;
            NSString *bid = rule[@"bid"];
            if (![bid isEqualToString:curBid]) continue;
            // 版本门: 留空 = 不限; 不匹配跳过
            NSString *rv = rule[@"ver"];
            if (rv.length && ![rv isEqualToString:curVer]) {
                apLog(@"ver gate: rule=%@ cur=%@ skip", rv, curVer);
                continue;
            }
            BOOL globalOn = mfPrefBool(@"mfAppPatchEnabled", NO);
            if (!globalOn) return;
            // 每条规则独立开关: rule key = mfAppPatch_<bid> (默认开)
            BOOL ruleOn = mfPrefBool([NSString stringWithFormat:@"mfAppPatch_%@", bid], YES);
            if (!ruleOn) { apLog(@"rule disabled: %@", bid); continue; }
            NSArray *patches = rule[@"patches"];
            for (NSDictionary *p in patches) {
                if (![p isKindOfClass:[NSDictionary class]]) continue;
                NSString *kind = p[@"kind"] ?: @"";
                NSString *err = nil;
                BOOL ok = NO;
                if ([kind isEqualToString:@"method"]) {
                    ok = apMethodPatch(p[@"cls"] ?: @"", p[@"sel"] ?: @"", [p[@"ret"] boolValue], &err);
                } else if ([kind isEqualToString:@"text"]) {
                    NSString *offS = [p[@"off"] stringByReplacingOccurrencesOfString:@"0x" withString:@""];
                    unsigned long long off = strtoull(offS.UTF8String, NULL, 16);
                    NSData *old = apHexToBytes(p[@"old"] ?: @"");
                    NSData *new = apHexToBytes(p[@"new"] ?: @"");
                    if (!new.length) err = @"empty new bytes";
                    else ok = apTextPatch((uintptr_t)off, old, new, &err);
                }
                if (ok) { g_apHits++; apLog(@"✓ %@ patch applied", kind); }
                else apLog(@"✗ %@ failed: %@", kind, err);
            }
        }
    } @catch (NSException *e) {
        apLog(@"apply exc: %@", e.reason);
    }
}

// 引擎拉起: 主线程延迟执行 (dyld 阶段 ObjC 类未注册完, 太早 hook 会 miss)
void mfAppPatchBoot(void) {
    if (!mfAppPatchIsOn()) return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        apApplyRules();
    });
    apInstallCollectors(); // 采集器顺带装上 (内部自判开关)
}

// ====== 采集器: hook vm_protect, 抓外部补丁器的写入 ======
// 原理: ReflixPatch 等外部补丁器写 __text 前必调 vm_protect(task, addr, len, 0, 0x13)
// 我们截下 (addr,size), 在写入前后 diff 主程序内存 → 点位落盘
static kern_return_t (*g_orig_vm_protect)(vm_map_t, vm_address_t, vm_size_t, BOOL, vm_prot_t);
static NSMutableData *g_collSnap = nil;   // 抓到的区域前快照
static vm_address_t g_collAddr = 0;
static vm_size_t g_collSize = 0;

static kern_return_t my_vm_protect(vm_map_t task, vm_address_t addr, vm_size_t size, BOOL set_max, vm_prot_t prot) {
    kern_return_t r = g_orig_vm_protect(task, addr, size, set_max, prot);
    if (task == mach_task_self() && (prot & VM_PROT_WRITE) && !g_collSnap) {
        uintptr_t base = apMainImageBase();
        // 只关心主程序 __text 范围内的解保护 (外部补丁器 patch 目标)
        if (base && addr >= base && addr < base + 0x8000000) {
            @try {
                g_collSnap = [NSMutableData dataWithBytes:(void*)addr length:size];
                g_collAddr = addr; g_collSize = size;
                apLog(@"[采集] vm_protect RW @main+0x%lx size=0x%lx — 5s 后 diff", (unsigned long)(addr - base), (unsigned long)size);
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    if (!g_collSnap) return;
                    const unsigned char *b = g_collSnap.bytes;
                    unsigned char *n = (unsigned char*)g_collAddr;
                    NSMutableArray *diffs = [NSMutableArray new];
                    BOOL inRun = NO; NSUInteger runStart = 0;
                    for (vm_size_t i = 0; i <= g_collSize; i++) {
                        BOOL ch = (i < g_collSize) && (b[i] != n[i]);
                        if (ch && !inRun) { inRun = YES; runStart = i; }
                        else if (!ch && inRun) {
                            inRun = NO;
                            [diffs addObject:@{@"off": [NSString stringWithFormat:@"0x%lx", (unsigned long)(g_collAddr - apMainImageBase() + runStart)],
                                               @"old": apBytesToHex(b + runStart, i - runStart),
                                               @"new": apBytesToHex(n + runStart, i - runStart)}];
                        }
                    }
                    if (diffs.count) {
                        g_apCollHits += diffs.count;
                        NSMutableDictionary *rec = [NSMutableDictionary new];
                        rec[@"bid"] = apCurBundleID(); rec[@"ver"] = apCurVersion();
                        rec[@"captured"] = [NSDate date]; rec[@"patches"] = diffs;
                        // 追加到采集文件
                        NSString *path = @"/var/mobile/Documents/mf_patch_capture.json";
                        NSArray *old = [NSJSONSerialization JSONObjectWithData:[[NSFileManager defaultManager] contentsAtPath:path] options:0 error:nil] ?: @[];
                        NSMutableArray *all = [old mutableCopy] ?: [NSMutableArray new];
                        [all addObject:rec];
                        NSData *out = [NSJSONSerialization dataWithJSONObject:all options:NSJSONWritingPrettyPrinted error:nil];
                        [out writeToFile:path atomically:YES];
                        apLog(@"[采集] ✓ %lu 处点位 → mf_patch_capture.json", (unsigned long)diffs.count);
                    } else {
                        apLog(@"[采集] 5s 内无写入变化");
                    }
                    g_collSnap = nil;
                });
            } @catch (NSException *e) { g_collSnap = nil; }
        }
    }
    return r;
}

BOOL mfAppPatchCollIsOn(void) { return mfPrefBool(@"mfAppPatchCollector", NO); }

void apInstallCollectors(void) {
    if (g_apCollInstalled) return;
    if (!mfAppPatchCollIsOn()) return;
    // fishhook 全局 rebind (项目自带 fishhook.h/fishhook.c)
    g_orig_vm_protect = (kern_return_t (*)(vm_map_t, vm_address_t, vm_size_t, BOOL, vm_prot_t))dlsym(RTLD_DEFAULT, "vm_protect");
    if (!g_orig_vm_protect) return;
    struct rebinding rb = { "vm_protect", (void*)my_vm_protect, (void**)&g_orig_vm_protect };
    rebind_symbols(&rb, 1);
    g_apCollInstalled = YES;
    apLog(@"[采集] vm_protect rebind installed");
}

// ====== 面板交互 API (给 MFPanel.m 实验模拟页用) ======
NSString *mfAppPatchRulesJSON(void) {
    id v = mfReadPrefObj(@"mfAppPatchRules");
    if ([v isKindOfClass:[NSString class]]) return v;
    return @"[\n  {\n    \"bid\": \"com.magicgroot.gooby\",\n    \"ver\": \"3.0.5\",\n    \"patches\": [\n      {\"kind\":\"method\",\"cls\":\"ClassHere\",\"sel\":\"isPro\",\"ret\":true},\n      {\"kind\":\"text\",\"off\":\"0x12345678\",\"old\":\"1f2003d5\",\"new\":\"20008052c0035fd6\"}\n    ]\n  }\n]";
}
void mfAppPatchSetRulesJSON(NSString *json) {
    // 写前校验
    NSData *d = [json dataUsingEncoding:NSUTF8StringEncoding];
    id obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (![obj isKindOfClass:[NSArray class]]) return;
    mfWritePrefObj(@"mfAppPatchRules", json);
}
void mfAppPatchApplyNow(void) {   // 面板手动触发
    dispatch_async(dispatch_get_main_queue(), ^{ apApplyRules(); });
}
NSArray *mfAppPatchLogLines(void) {
    @synchronized (g_apLog) { return [g_apLog copy] ?: @[]; }
}
long mfAppPatchCollHits(void) { return g_apCollHits; }

// ====== 页面 UI: 实验模拟 → AppPatch 子页 ======
// MFPanelCtrl 定义在 MFPanel.m — 此处最小前向声明让 category 可编译, 运行时指向真类
@interface MFPanelCtrl : NSObject @end
@interface MFPanelCtrl (AppPatch)
- (void)mfAPSwitchChanged:(UISwitch *)sw;
- (void)mfAPCollSwitchChanged:(UISwitch *)sw;
- (void)mfAPShowRulesEditor;
- (void)mfAPRulesEditorSave;
- (void)mfAPApplyNow;
- (void)mfAPShowLog;
@end

@implementation MFPanelCtrl (AppPatch)
- (void)mfAPSwitchChanged:(UISwitch *)sw {
    mfSetBoolPref(@"mfAppPatchEnabled", sw.on);
    if (sw.on) mfAppPatchBoot();
    mfToast(sw.on ? @"引擎已开, 冷启动 app 生效" : @"引擎已关");
}
- (void)mfAPCollSwitchChanged:(UISwitch *)sw {
    mfSetBoolPref(@"mfAppPatchCollector", sw.on);
    if (sw.on) { apInstallCollectors(); mfToast(@"采集器已挂 vm_protect"); }
    else mfToast(@"开关已存, 重启 app 卸载 rebind");
}
- (void)mfAPApplyNow {
    mfAppPatchApplyNow();
    mfToast(@"已触发");
}
static UITextView *g_apEditor = nil;
- (void)mfAPShowRulesEditor {
    UIView *page = mfMakePage(@"📜 规则表编辑", YES);
    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(12, 54, g_mfCardW - 24, g_mfCardH - 200)];
    tv.text = mfAppPatchRulesJSON();
    tv.font = [UIFont fontWithName:@"Menlo" size:11];
    tv.autocorrectionType = UITextAutocorrectionTypeNo;
    tv.autocapitalizationType = UITextAutocapitalizationTypeNone;
    tv.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
    tv.layer.cornerRadius = 10;
    [page addSubview:tv];
    g_apEditor = tv;
    mfAttachKbBar(tv);
    UIButton *save = [UIButton buttonWithType:UIButtonTypeSystem];
    save.frame = CGRectMake(12, g_mfCardH - 136, (g_mfCardW - 32) / 2, 42);
    [save setTitle:@"💾 保存" forState:UIControlStateNormal];
    [save addTarget:g_mfCtrl action:@selector(mfAPRulesEditorSave) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:save];
    UIButton *apply = [UIButton buttonWithType:UIButtonTypeSystem];
    apply.frame = CGRectMake(12 + (g_mfCardW - 32) / 2 + 8, g_mfCardH - 136, (g_mfCardW - 32) / 2, 42);
    [apply setTitle:@"⚡ 立即应用" forState:UIControlStateNormal];
    [apply addTarget:g_mfCtrl action:@selector(mfAPApplyNow) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:apply];
    mfPushPage(page);
}
- (void)mfAPRulesEditorSave {
    if (!g_apEditor) return;
    mfAppPatchSetRulesJSON(g_apEditor.text);
    mfToast(@"已保存");
}
- (void)mfAPShowLog {
    UIView *page = mfMakePage(@"📋 AppPatch 日志", YES);
    NSArray *lines = mfAppPatchLogLines();
    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(12, 54, g_mfCardW - 24, g_mfCardH - 120)];
    tv.text = lines.count ? [lines componentsJoinedByString:@"\n"] : @"(空)";
    tv.font = [UIFont fontWithName:@"Menlo" size:10];
    tv.editable = NO;
    [page addSubview:tv];
    mfPushPage(page);
}
@end

// ====== 实验模拟页嵌入块 (由 MFPanel.m 的 mfShowLabPage 调用) ======
void mfAppPatchSectionInLabPage(UIView *page, CGFloat *yio) {
    CGFloat y = *yio;
    UILabel *grp = [[UILabel alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 20)];
    grp.text = @"AppPatch 进程层引擎";
    grp.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    grp.textColor = [UIColor secondaryLabelColor];
    [page addSubview:grp];
    y += 24;

    // 开关行 1: 引擎总开关
    {
        UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 52)];
        bar.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
        bar.layer.cornerRadius = 10;
        UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(10, 10, 51, 31)];
        sw.on = mfAppPatchIsOn();
        [sw addTarget:g_mfCtrl action:@selector(mfAPSwitchChanged:) forControlEvents:UIControlEventValueChanged];
        [bar addSubview:sw];
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(72, 6, g_mfCardW - 96 - 10, 22)];
        l.text = @"⚙️ patch 引擎";
        l.font = [UIFont systemFontOfSize:14 weight:UIFontWeightMedium];
        [bar addSubview:l];
        UILabel *st = [[UILabel alloc] initWithFrame:CGRectMake(72, 28, g_mfCardW - 96 - 10, 18)];
        st.text = [NSString stringWithFormat:@"objc swizzle + vm_protect · 命中 %ld", g_apHits];
        st.font = [UIFont systemFontOfSize:11];
        st.textColor = [UIColor secondaryLabelColor];
        [bar addSubview:st];
        [page addSubview:bar];
        y += 56;
    }
    // 开关行 2: 采集器
    {
        UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 52)];
        bar.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
        bar.layer.cornerRadius = 10;
        UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(10, 10, 51, 31)];
        sw.on = mfAppPatchCollIsOn();
        [sw addTarget:g_mfCtrl action:@selector(mfAPCollSwitchChanged:) forControlEvents:UIControlEventValueChanged];
        [bar addSubview:sw];
        UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(72, 6, g_mfCardW - 96 - 10, 22)];
        l.text = @"📡 补丁点位采集器";
        l.font = [UIFont systemFontOfSize:14 weight:UIFontWeightMedium];
        [bar addSubview:l];
        UILabel *st = [[UILabel alloc] initWithFrame:CGRectMake(72, 28, g_mfCardW - 96 - 10, 18)];
        st.text = [NSString stringWithFormat:@"hook vm_protect 抓外部补丁 · 采集 %ld", g_apCollHits];
        st.font = [UIFont systemFontOfSize:11];
        st.textColor = [UIColor secondaryLabelColor];
        [bar addSubview:st];
        [page addSubview:bar];
        y += 56;
    }
    // 按钮行
    UIButton *btnRules = [UIButton buttonWithType:UIButtonTypeSystem];
    btnRules.frame = CGRectMake(16, y, (g_mfCardW - 40) / 2, 38);
    [btnRules setTitle:@"📜 规则表" forState:UIControlStateNormal];
    [btnRules addTarget:g_mfCtrl action:@selector(mfAPShowRulesEditor) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:btnRules];
    UIButton *btnLog = [UIButton buttonWithType:UIButtonTypeSystem];
    btnLog.frame = CGRectMake(16 + (g_mfCardW - 40) / 2 + 8, y, (g_mfCardW - 40) / 2, 38);
    [btnLog setTitle:@"📋 日志" forState:UIControlStateNormal];
    [btnLog addTarget:g_mfCtrl action:@selector(mfAPShowLog) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:btnLog];
    y += 44;

    UILabel *note = [[UILabel alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 60)];
    note.text = @"规则: bid+ver 匹配 → method(swizzle) / text(vm_protect 写 __text)。\n采集器抓 ReflixPatch 类外部补丁的写入点位, 落盘 Documents/mf_patch_capture.json。\n冷启动生效; 「立即应用」热触发。";
    note.numberOfLines = 0;
    note.font = [UIFont systemFontOfSize:11];
    note.textColor = [UIColor secondaryLabelColor];
    [page addSubview:note];
    y += 66;

    *yio = y;
}

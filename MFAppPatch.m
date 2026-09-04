// MFAppPatch.m — 进程层 patch 引擎 (v2.21.0, 2026-09-04)
// 灵感来源: ReflixPatch-3.0.5 逆向 (vm_protect 写 __text 模式) — 见 reven-recon/REFLIXPATCH-REPORT.md
// 【归属】IAPtools.dylib (IAP 域); 实验模拟页入口; 不碰系统进程
// 【铁律】ctor 有系统进程守卫(IAPtools 既有); 本文件不新增 ctor, 由 MFPanel ctor 按开关拉起
//
// 三层能力:
//   1. 规则引擎: prefs 读 JSON 规则表, bundleID+version 匹配当前进程
//   2. 执行器:   kind=method → objc swizzle;  kind=text → vm_protect(RW)+写字节+icache+恢复RX
//   3. 采集器:   纯被动周期快照 diff (v2.21: 不 hook vm_protect — fishhook 会污染
//                ReflixPatch 的 backtrace 反 hook 检测导致其 abort, 见 2026-09-04 实测)
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
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <libkern/OSCacheControl.h>
#include <sys/sysctl.h>

#import "MFPanel.h"

BOOL mfAppPatchIsOn(void) {
    return mfPrefBool(@"mfAppPatchEnabled", NO);
}
long mfAppPatchHits(void); // fwd
void apInstallCollectors(void); // fwd
void mfAppPatchSectionInLabPage(UIView *page, CGFloat *yio); // fwd
NSString *mfAppPatchRulesJSON(void);
void mfAppPatchSetRulesJSON(NSString *json);

// ====== 偏好 ======
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

// ====== Mach-O 主程序定位 (MH_EXECUTE, ReflixPatch 同款思路) ======
static uintptr_t apMainImageBase(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h && h->magic == MH_MAGIC_64 && h->filetype == MH_EXECUTE) return (uintptr_t)h;
    }
    return _dyld_image_count() ? (uintptr_t)_dyld_get_image_header(0) : 0;
}

// ====== text patch: vm_protect 三步 (ReflixPatch 同款) ======
static BOOL apTextPatch(uintptr_t fileOffAddr, NSData *expectOld, NSData *newBytes, NSString **err) {
    // off 是相对主程序加载基址的 vm offset
    uintptr_t base = apMainImageBase();
    if (!base) { *err = @"no main image"; return NO; }
    volatile uintptr_t target = base + fileOffAddr;
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
    char retType = method_copyReturnType(m)[0];
    IMP newImp;
    if (retType == 'B' || retType == 'c') newImp = ret ? (IMP)apStubTrueB : (IMP)apStubFalseB;
    else newImp = ret ? (IMP)apStubTrue : (IMP)apStubFalse;
    method_setImplementation(m, newImp);
    return YES;
}

// ====== 规则执行 ======
static void apApplyRules(void) {
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
            NSString *rv = rule[@"ver"];
            if (rv.length && ![rv isEqualToString:curVer]) {
                apLog(@"ver gate: rule=%@ cur=%@ skip", rv, curVer);
                continue;
            }
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
                    NSString *offS = p[@"off"] ?: @"";
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

// ==================================================================
// 采集器 v2.21: 纯被动周期快照 diff
// v2.20 教训: fishhook rebind vm_protect 会把自己的帧塞进外部补丁器的
// backtrace → ReflixPatch 反 hook 检测命中 → abort (2026-09-04 实测崩溃)
// 改法: 不碰任何函数, 只周期性快照主程序可写段 + 与首拍比对, 有变化即记录
// ==================================================================
BOOL mfAppPatchCollIsOn(void) { return mfPrefBool(@"mfAppPatchCollector", NO); }

static dispatch_source_t g_collTimer = nil;
static NSData *g_collBase = nil;      // 首拍 (__TEXT 全量)
static uintptr_t g_collBaseAddr = 0;
static NSUInteger g_collBaseLen = 0;

void apInstallCollectors(void) {
    if (g_apCollInstalled) return;
    if (!mfAppPatchCollIsOn()) return;
    g_collBaseAddr = apMainImageBase();
    if (!g_collBaseAddr) return;
    // 快照 __TEXT 整段 (主程序第一个 LC_SEGMENT_64, filesize 内)
    const struct mach_header_64 *mh = (const struct mach_header_64*)g_collBaseAddr;
    uint64_t textFileSize = 0;
    uint8_t *p = (uint8_t*)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command*)p;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64*)p;
            if (strncmp(seg->segname, "__TEXT", 16) == 0) { textFileSize = seg->filesize; break; }
        }
        p += lc->cmdsize;
    }
    if (!textFileSize || textFileSize > 96ull*1024*1024) return;
    g_collBaseLen = (NSUInteger)textFileSize;
    @try {
        g_collBase = [NSData dataWithBytes:(void*)g_collBaseAddr length:g_collBaseLen];
    } @catch (NSException *e) { return; }
    apLog(@"[采集] 首拍 __TEXT 0x%lx (%lu B) — 周期 2s diff", (unsigned long)g_collBaseAddr, (unsigned long)g_collBaseLen);

    g_collTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_timer(g_collTimer, dispatch_walltime(NULL, 0), 2.0 * NSEC_PER_SEC, 0.5 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(g_collTimer, ^{
        if (!g_collBase) return;
        @autoreleasepool {
            NSData *now = nil;
            @try { now = [NSData dataWithBytes:(void*)g_collBaseAddr length:g_collBaseLen]; }
            @catch (NSException *e) { return; }
            if ([now isEqualToData:g_collBase]) return;
            const unsigned char *b = g_collBase.bytes;
            const unsigned char *n = now.bytes;
            NSMutableArray *diffs = [NSMutableArray new];
            NSUInteger i = 0;
            while (i < g_collBaseLen) {
                if (b[i] != n[i]) {
                    NSUInteger s = i;
                    while (i < g_collBaseLen && b[i] != n[i]) i++;
                    if (diffs.count < 64) {
                        [diffs addObject:@{@"off": [NSString stringWithFormat:@"0x%lx", (unsigned long)s],
                                           @"old": apBytesToHex(b + s, i - s),
                                           @"new": apBytesToHex(n + s, i - s)}];
                    }
                } else i++;
            }
            if (diffs.count) {
                g_apCollHits += diffs.count;
                NSMutableDictionary *rec = [NSMutableDictionary new];
                rec[@"bid"] = apCurBundleID(); rec[@"ver"] = apCurVersion();
                rec[@"captured"] = [NSDate date]; rec[@"patches"] = diffs;
                NSString *path = @"/var/mobile/Documents/mf_patch_capture.json";
                NSArray *old = [NSJSONSerialization JSONObjectWithData:[[NSFileManager defaultManager] contentsAtPath:path] options:0 error:nil] ?: @[];
                NSMutableArray *all = [old mutableCopy] ?: [NSMutableArray new];
                [all addObject:rec];
                NSData *out = [NSJSONSerialization dataWithJSONObject:all options:NSJSONWritingPrettyPrinted error:nil];
                [out writeToFile:path atomically:YES];
                apLog(@"[采集] ✓ %lu 处变化 → mf_patch_capture.json (首址 0x%lx)", (unsigned long)diffs.count, (unsigned long)[[diffs[0] objectForKey:@"off"] longLongValue]);
                g_collBase = now; // 更新基线, 后续 diff 相对当前
            }
        }
    });
    dispatch_resume(g_collTimer);
    g_apCollInstalled = YES;
}

// ====== 面板交互 API ======
NSString *mfAppPatchRulesJSON(void) {
    id v = mfReadPrefObj(@"mfAppPatchRules");
    if ([v isKindOfClass:[NSString class]]) return v;
    return @"[\n  {\n    \"bid\": \"com.magicgroot.gooby\",\n    \"ver\": \"3.0.5\",\n    \"patches\": [\n      {\"kind\":\"method\",\"cls\":\"ClassHere\",\"sel\":\"isPro\",\"ret\":true},\n      {\"kind\":\"text\",\"off\":\"0x12345678\",\"old\":\"1f2003d5\",\"new\":\"20008052c0035fd6\"}\n    ]\n  }\n]";
}
void mfAppPatchSetRulesJSON(NSString *json) {
    NSData *d = [json dataUsingEncoding:NSUTF8StringEncoding];
    id obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (![obj isKindOfClass:[NSArray class]]) return;
    mfWritePrefObj(@"mfAppPatchRules", json);
}
void mfAppPatchApplyNow(void) {
    dispatch_async(dispatch_get_main_queue(), ^{ apApplyRules(); });
}
NSArray *mfAppPatchLogLines(void) {
    @synchronized (g_apLog) { return [g_apLog copy] ?: @[]; }
}
long mfAppPatchCollHits(void) { return g_apCollHits; }

// ====== 面板 UI ======
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

static UITextView *g_apEditor = nil;
@implementation MFPanelCtrl (AppPatch)
- (void)mfAPSwitchChanged:(UISwitch *)sw {
    mfSetBoolPref(@"mfAppPatchEnabled", sw.on);
    if (sw.on) mfAppPatchBoot();
    mfToast(sw.on ? @"引擎已开, 冷启动 app 生效" : @"引擎已关");
}
- (void)mfAPCollSwitchChanged:(UISwitch *)sw {
    mfSetBoolPref(@"mfAppPatchCollector", sw.on);
    if (sw.on) { apInstallCollectors(); mfToast(@"采集器已装 (被动快照模式)"); }
    else mfToast(@"开关已存, 重启 app 卸载");
}
- (void)mfAPApplyNow {
    mfAppPatchApplyNow();
    mfToast(@"已触发");
}
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
        st.text = [NSString stringWithFormat:@"被动快照 diff · 采集 %ld", g_apCollHits];
        st.font = [UIFont systemFontOfSize:11];
        st.textColor = [UIColor secondaryLabelColor];
        [bar addSubview:st];
        [page addSubview:bar];
        y += 56;
    }
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
    note.text = @"规则: bid+ver 匹配 → method(swizzle) / text(vm_protect 写 __TEXT)。\n采集器: 周期快照 __TEXT 全段, 有外部写入即落盘 mf_patch_capture.json。\n引擎冷启动生效; 「立即应用」热触发。";
    note.numberOfLines = 0;
    note.font = [UIFont systemFontOfSize:11];
    note.textColor = [UIColor secondaryLabelColor];
    [page addSubview:note];
    y += 66;
    *yio = y;
}

// ====== MFObjCHook.m - 精确 ObjC 方法 hook(返回值改写) ======
// 取代只读的 MFMethodTrace(方法监控)。引擎提炼自原 MFMethodTrace 的 block-IMP 包装,
//   改为「返回值改写」模式: 对当前 app(class+selector)短路/替换返回值。
//   作用域: 仅当前面板所在 app(规则管理同款范式, 避免全局干扰其他进程)。
// 配置持久化: /var/jb/Library/MinisFix/objchooks.plist
//   规则: [{class, selector, mode, value, enabled}]  mode: 0=orig 1=nil 2=str(value)
#import "MFPanel.h"
#import <objc/runtime.h>

// v2.6.50: /var/jb/Library/MinisFix/ 在 rootless 下不可写(实测 save fail)
//   改用用户空间路径(与网络规则/电池日志同层)
static NSString *MF_OBJC_HOOK_PATH = @"/var/jb/var/mobile/Library/MinisFix/objchooks.plist";
static NSString *g_objcPrefill = nil;
static void mfObjCHookLoad(void);  // 前向声明
// v2.6.44: 全程诊断日志(NSLog 双写进 hostlog 管道)
#define OH_LOG(fmt, ...) NSLog(@"[ObCHook] " fmt, ##__VA_ARGS__)
// v2.6.41: 实现 mfTraceSetPrefill(MFPanel.h 声明 + MFClassDump.m 调用, 之前漏实现 = undefined symbol)
void mfTraceSetPrefill(NSString *cls) {
    g_objcPrefill = cls ? [cls copy] : nil;
}
static NSMutableArray *g_objcHooks = nil;      // 规则(dict)
static NSMutableArray *g_hookRestore = nil;    // 已应用 {cls,sel,origIMP,enc}
static BOOL g_hookOn = NO;
static UITextField *g_clsF = nil, *g_selF = nil, *g_valF = nil;   // v2.6.47 表单字段
static UISegmentedControl *g_modeSeg = nil;

#pragma mark - 安全签名解析(NSMethodSignature)
// 只接受 ret=@/v + 参数全 @(≤4)。返回对象/void 方法可接管, 其余跳过。
static int mfSafeArgs(const char *t, char *retOut) {
    if (!t) return -1;
    @try {
        NSMethodSignature *sig = [NSMethodSignature signatureWithObjCTypes:t];
        if (!sig) return -1;
        char ret = [sig getArgumentTypeAtIndex:0][0];
        if (ret != '@' && ret != 'v') return -1;
        // v2.6.46: 无参方法 sig.numberOfArguments=2(self+_cmd), 2-3 下溢→全被拒
        NSUInteger n = sig.numberOfArguments > 2 ? sig.numberOfArguments - 3 : 0;
        if (n > 4) return -1;
        for (NSUInteger i = 3; i < sig.numberOfArguments; i++) {
            const char *ty = [sig getArgumentTypeAtIndex:i];
            if (ty[0] != '@') return -1;
        }
        *retOut = ret;
        return (int)n;
    } @catch (NSException *e) { return -1; }
}

#pragma mark - 返回值改写 wrapper
static IMP mfWrapRet(char ret, int nargs, IMP orig, int mode, id val) {
    IMP o = orig; int rm = mode; id rv = val;
    id blk = nil;
    if (ret == 'v') {
        if (nargs == 0) { blk = ^void(id s, SEL c){ ((void(*)(id,SEL))o)(s,c); }; }
        else if (nargs == 1) { blk = ^void(id s, SEL c, id a1){ ((void(*)(id,SEL,id))o)(s,c,a1); }; }
        else if (nargs == 2) { blk = ^void(id s, SEL c, id a1, id a2){ ((void(*)(id,SEL,id,id))o)(s,c,a1,a2); }; }
        else if (nargs == 3) { blk = ^void(id s, SEL c, id a1, id a2, id a3){ ((void(*)(id,SEL,id,id,id))o)(s,c,a1,a2,a3); }; }
        else { blk = ^void(id s, SEL c, id a1, id a2, id a3, id a4){ ((void(*)(id,SEL,id,id,id,id))o)(s,c,a1,a2,a3,a4); }; }
    } else { // '@'
        if (nargs == 0) { blk = ^id(id s, SEL c){ if(rm==0)return ((id(*)(id,SEL))o)(s,c); if(rm==1)return nil; return rv; }; }
        else if (nargs == 1) { blk = ^id(id s, SEL c, id a1){ if(rm==0)return ((id(*)(id,SEL,id))o)(s,c,a1); if(rm==1)return nil; return rv; }; }
        else if (nargs == 2) { blk = ^id(id s, SEL c, id a1, id a2){ if(rm==0)return ((id(*)(id,SEL,id,id))o)(s,c,a1,a2); if(rm==1)return nil; return rv; }; }
        else if (nargs == 3) { blk = ^id(id s, SEL c, id a1, id a2, id a3){ if(rm==0)return ((id(*)(id,SEL,id,id,id))o)(s,c,a1,a2,a3); if(rm==1)return nil; return rv; }; }
        else { blk = ^id(id s, SEL c, id a1, id a2, id a3, id a4){ if(rm==0)return ((id(*)(id,SEL,id,id,id,id))o)(s,c,a1,a2,a3,a4); if(rm==1)return nil; return rv; }; }
    }
    return blk ? imp_implementationWithBlock(blk) : nil;
}

#pragma mark - 应用/还原
void mfObjCHookApply(void) {
    if (!g_objcHooks) mfObjCHookLoad();
    if (!g_hookRestore) g_hookRestore = [NSMutableArray new];
    OH_LOG(@"apply: %lu rules, restore=%@", (unsigned long)g_objcHooks.count, g_hookOn ? @"exists" : @"fresh");
    for (NSDictionary *rule in g_objcHooks) {
        if (![rule[@"enabled"] boolValue]) continue;
        Class cls = NSClassFromString(rule[@"class"]);
        if (!cls) { OH_LOG(@"skip: class %@ not found", rule[@"class"]); continue; }
        SEL sel = NSSelectorFromString(rule[@"selector"]);
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) { OH_LOG(@"skip: selector %@ not found on %@", rule[@"selector"], rule[@"class"]); continue; }
        const char *enc = method_getTypeEncoding(m);
        char ret; int args = mfSafeArgs(enc, &ret);
        if (args < 0) { OH_LOG(@"skip: unsafe signature %@#%@", rule[@"class"], rule[@"selector"]); continue; }
        IMP orig = method_getImplementation(m);
        IMP wrap = mfWrapRet(ret, args, orig, [rule[@"mode"] intValue], rule[@"value"]);
        if (!wrap) { OH_LOG(@"skip: wrap fail %@#%@", rule[@"class"], rule[@"selector"]); continue; }
        if (class_getMethodImplementation(cls, sel) != orig) {
            class_addMethod(cls, sel, wrap, enc);
        } else {
            method_setImplementation(m, wrap);
        }
        [g_hookRestore addObject:@{@"cls": cls, @"sel": NSStringFromSelector(sel), @"imp": [NSValue valueWithPointer:orig], @"enc": [NSString stringWithUTF8String:enc]}];
        OH_LOG(@"hook OK: %@#%@ mode=%d", rule[@"class"], rule[@"selector"], [rule[@"mode"] intValue]);
    }
    g_hookOn = YES;
    mfToast(@"🔧 ObjC 规则已应用");
}

void mfObjCHookStop(void) {
    if (!g_hookRestore) return;
    for (NSDictionary *e in g_hookRestore) {
        Class c = e[@"cls"]; SEL sel = NSSelectorFromString(e[@"sel"]);
        IMP orig = (IMP)[e[@"imp"] pointerValue];
        const char *enc = [e[@"enc"] UTF8String];
        Method old = class_getInstanceMethod(c, sel);
        if (old && method_getImplementation(old) == orig) continue;
        class_replaceMethod(c, sel, orig, enc);
    }
    [g_hookRestore removeAllObjects];
    g_hookOn = NO;
    mfToast(@"⏹️ ObjC 规则已停止");
}

#pragma mark - 持久化
void mfObjCHookLoad(void) {
    NSArray *a = [NSArray arrayWithContentsOfFile:MF_OBJC_HOOK_PATH];
    g_objcHooks = a ? [a mutableCopy] : [NSMutableArray new];
    OH_LOG(@"load: %lu rules from %@", (unsigned long)g_objcHooks.count, MF_OBJC_HOOK_PATH);
}
void mfObjCHookSave(void) {
    // v2.6.49: 先建目录——writeToFile 遇不存在目录静默失败(14:05 rules=0 实锤)
    NSString *dir = [MF_OBJC_HOOK_PATH stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
    BOOL ok = [g_objcHooks writeToFile:MF_OBJC_HOOK_PATH atomically:YES];
    OH_LOG(@"save: %lu rules -> %d", (unsigned long)g_objcHooks.count, ok);
}

#pragma mark - UI
void mfShowObjCHookPage(void) {
    if (!g_objcHooks) mfObjCHookLoad();
    // v2.6.45: 防重入——重复点击不叠加页面(v2.6.44 日志暴露 page open 循环)
    if ([[(UIView *)g_mfPages.lastObject accessibilityIdentifier] isEqualToString:@"mf_objcrules"]) return;
    OH_LOG(@"page open: rules=%lu prefill=%@", (unsigned long)g_objcHooks.count, g_objcPrefill);
    UIView *page = mfMakePage(@"🔧 ObjC 规则", YES);
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 48, g_mfCardW, g_mfCardH - 48)];
    [page addSubview:sv];
    CGFloat cw = g_mfCardW;
    CGFloat y = 8;

    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(16, y, cw-32, 20)];
    hint.text = @"精确 hook 方法返回值(作用于当前 app)";
    hint.font = [UIFont systemFontOfSize:11]; hint.textColor = [UIColor tertiaryLabelColor];
    hint.numberOfLines = 0; [sv addSubview:hint]; y += 24;
    // 🧪 强制 sandbox(官方私有 API)——优先试试,不行再回退 hook 路线
    UIButton *sbBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    sbBtn.frame = CGRectMake(16, y, cw-32, 36);
    sbBtn.backgroundColor = [UIColor systemOrangeColor]; sbBtn.layer.cornerRadius = 9;
    sbBtn.tintColor = UIColor.whiteColor; [sbBtn setTitle:@"🧪 强制 sandbox(当前 App)" forState:UIControlStateNormal];
    sbBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [sbBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfObjCForceSandboxTapped") forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:sbBtn]; y += 44;
    UIButton *probeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    probeBtn.frame = CGRectMake(16, y, cw-32, 36);
    probeBtn.backgroundColor = [UIColor systemBrownColor]; probeBtn.layer.cornerRadius = 9;
    probeBtn.tintColor = UIColor.whiteColor; [probeBtn setTitle:@"🧪 伪造交易实验" forState:UIControlStateNormal];
    probeBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [probeBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfObjCTxProbeTapped") forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:probeBtn]; y += 44;

    // v2.6.47: 页面内表单(替代系统弹窗)——对齐面板原生交互
    g_clsF = [[UITextField alloc] initWithFrame:CGRectMake(16, y, (cw-40)/2, 34)];
    g_clsF.placeholder = @"类名 (NSBundle)";
    [sv addSubview:g_clsF];
    g_selF = [[UITextField alloc] initWithFrame:CGRectMake(24+(cw-40)/2, y, (cw-40)/2, 34)];
    g_selF.placeholder = @"方法 (appStoreReceiptURL)";
    [sv addSubview:g_selF]; y += 40;
    g_modeSeg = [[UISegmentedControl alloc] initWithItems:@[@"透传", @"返回 nil", @"str 值"]];
    g_modeSeg.frame = CGRectMake(16, y, (cw-40)/2, 30);
    g_modeSeg.selectedSegmentIndex = 1;
    [sv addSubview:g_modeSeg];
    g_valF = [[UITextField alloc] initWithFrame:CGRectMake(24+(cw-40)/2, y, (cw-40)/2, 34)];
    g_valF.placeholder = @"str 值(str 模式用)";
    [sv addSubview:g_valF]; y += 42;
    for (UITextField *f in @[g_clsF, g_selF, g_valF]) {
        f.font = [UIFont systemFontOfSize:12];
        f.borderStyle = UITextBorderStyleRoundedRect;
        f.autocapitalizationType = UITextAutocapitalizationTypeNone;
        f.autocorrectionType = UITextAutocorrectionTypeNo;
    }
    if (g_objcPrefill) { g_clsF.text = g_objcPrefill; g_objcPrefill = nil; }
    UIButton *addBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    addBtn.frame = CGRectMake(16, y, cw-32, 38);
    addBtn.backgroundColor = [UIColor systemIndigoColor]; addBtn.layer.cornerRadius = 9;
    addBtn.tintColor = UIColor.whiteColor; [addBtn setTitle:@"➕ 添加" forState:UIControlStateNormal];
    [addBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfObjCHookFormAddTapped") forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:addBtn]; y += 46;

    for (NSDictionary *r in g_objcHooks) {
        UIView *row = [[UIView alloc] initWithFrame:CGRectMake(12, y, cw-24, 64)];
        row.backgroundColor = [UIColor secondarySystemBackgroundColor];
        row.layer.cornerRadius = 10;
        UILabel *t = [[UILabel alloc] initWithFrame:CGRectMake(10, 4, cw-90, 36)];
        NSString *modeS = [@[@"orig",@"nil",@"str:"] objectAtIndex:MIN([r[@"mode"] intValue],2)];
        t.text = [NSString stringWithFormat:@"%@\n%@ → %@%@", r[@"class"], r[@"selector"], modeS, [r[@"mode"] intValue]==2 ? r[@"value"] : @""];
        t.font = [UIFont systemFontOfSize:11]; t.numberOfLines = 2; [row addSubview:t];
        UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(cw-24-60, 16, 51, 31)];
        sw.on = [r[@"enabled"] boolValue]; sw.tag = [g_objcHooks indexOfObject:r];
        [sw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfObjCHookToggle:") forControlEvents:UIControlEventValueChanged];
        [row addSubview:sw];
        UIButton *del = [UIButton buttonWithType:UIButtonTypeSystem];
        del.frame = CGRectMake(cw-24-18, 44, 22, 18); del.tag = [g_objcHooks indexOfObject:r];
        [del setTitle:@"✕" forState:UIControlStateNormal]; del.titleLabel.font = [UIFont systemFontOfSize:12];
        [del addTarget:g_mfCtrl action:NSSelectorFromString(@"mfObjCHookDelTapped:") forControlEvents:UIControlEventTouchUpInside];
        [row addSubview:del];
        [sv addSubview:row]; y += 72;
    }
    sv.contentSize = CGSizeMake(cw, y + 20);
    // v2.6.45: 缺失的 push——页面从未显示(「点不动」真凶)
    [page setAccessibilityIdentifier:@"mf_objcrules"];
    mfPushPage(page);
}

// v2.6.42: MFClassDump 左滑「方法监控」入口的 C 函数别名 → 指向 ObjC 规则页
void mfShowMethodTracePage(void) {
    mfShowObjCHookPage();
}

#pragma mark - 🧪 强制 sandbox(v2.6.51: dump 挖到官方私有 API)
// [[SKPaymentQueue defaultQueue] forceSandboxForBundleIdentifier:untilDate:]
// storekitd 配合强制 bundle 走 sandbox——比进程内任何伪装都正
void mfObjCForceSandboxTapped(void) {
    id q = nil;
    Class qcls = objc_getClass("SKPaymentQueue");
    if (qcls) q = ((id(*)(id,SEL))objc_msgSend)((id)qcls, NSSelectorFromString(@"defaultQueue"));
    SEL sel = NSSelectorFromString(@"forceSandboxForBundleIdentifier:untilDate:");
    if (q && [q respondsToSelector:sel]) {
        ((void(*)(id,SEL,NSString*,NSDate*))objc_msgSend)(q, sel,
            mfCurrentBundleId(), [NSDate dateWithTimeIntervalSinceNow:365*24*3600]);
        OH_LOG(@"forceSandbox requested for %@", mfCurrentBundleId());
        mfToast(@"🧪 已强制 sandbox——重启 App 点购买验证");
    } else {
        OH_LOG(@"forceSandbox selector missing");
        mfToast(@"SDK 不支持此接口");
    }
}

#pragma mark - 🧪 伪造交易实验(v2.6.52)
// 目标: hook SKPaymentQueue#transactions 返回伪造已购数组(通用 SK1 解锁)
// 本按钮: 运行时构造 SKPaymentTransaction 并读写验证——ivar 布局 dump 有, 壳层转发未证实
#include <string.h>
void mfObjCTxProbeTapped(void) {
    // 1. 枚举 SKPaymentTransaction 类 ivar(转发路径真相)
    Class TT = objc_getClass("SKPaymentTransaction");
    unsigned int n = 0;
    Ivar *ivs = class_copyIvarList(TT, &n);
    OH_LOG(@"TX ivars: %u", n);
    for (unsigned int i = 0; i < n; i++) {
        OH_LOG(@"  ivar %s off=%ld", ivar_getName(ivs[i]), (long)ivar_getOffset(ivs[i]));
    }
    free(ivs);
    // 2. 构造 internal + 直接写 scalar/对象 ivar
    // v2.6.53: class_createInstance 绕过 alloc/init——SK 内部类 init 可能连 XPC/断言(闪退点)
    Class TI = objc_getClass("SKPaymentTransactionInternal");
    if (!TI) { OH_LOG(@"Internal class missing"); return; }
    OH_LOG(@"probe: creating internal via class_createInstance");
    id ti = CFBridgingRelease(class_createInstance(TI, 0));
    OH_LOG(@"probe: internal=%@", ti);
    Ivar stI = class_getInstanceVariable(TI, "__transactionState");
    if (stI) { long long st = 1; memcpy((char *)(__bridge void *)ti + ivar_getOffset(stI), &st, 8); }
    Ivar payI = class_getInstanceVariable(TI, "__payment");
    // 3. 构造 SKPayment(Internal) 填 productIdentifier(同样绕过 init)
    Class PI = objc_getClass("SKPaymentInternal");
    id pi = nil;
    if (PI) pi = CFBridgingRelease(class_createInstance(PI, 0));
    if (pi) {
        Ivar pidI = class_getInstanceVariable(PI, "__productIdentifier");
        if (pidI) object_setIvar(pi, pidI, @"com.sugarmo.ScrollClip.pro");
    }
    OH_LOG(@"probe: payment built=%@", pi);
    if (payI && pi) object_setIvar(ti, payI, pi);
    // 4. 包壳: SKPaymentTransaction class_createInstance 后塞 internal
    OH_LOG(@"probe: creating SKPaymentTransaction shell");
    id tx = CFBridgingRelease(class_createInstance(TT, 0));
    Ivar intI = class_getInstanceVariable(TT, "_internal");
    if (intI) object_setIvar(tx, intI, ti);
    Ivar intI2 = class_getInstanceVariable(TT, "__internal");
    if (intI2) object_setIvar(tx, intI2, ti);
    OH_LOG(@"probe: shell=%@", tx);
    // 5. 读写验证(修正: transaction 无 productIdentifier — pid 在 payment 上)
    long long st2 = ((long long(*)(id,SEL))objc_msgSend)(tx, NSSelectorFromString(@"transactionState"));
    id pay2 = ((id(*)(id,SEL))objc_msgSend)(tx, NSSelectorFromString(@"payment"));
    NSString *pid2 = nil;
    if (pay2) pid2 = ((id(*)(id,SEL))objc_msgSend)(pay2, NSSelectorFromString(@"productIdentifier"));
    OH_LOG(@"probe: state=%lld pid=%@", st2, pid2);
}

#pragma mark - 编辑
// v2.6.47: 页面内表单添加(替代弹窗)——直接读表单字段
void mfObjCHookFormAddTapped(void) {
    if (!g_clsF) { OH_LOG(@"form not ready"); return; }
    int mode = (int)g_modeSeg.selectedSegmentIndex; // 0=透传 1=nil 2=str
    id val = mode == 2 ? (g_valF.text ?: @"") : nil;
    mfObjCHookPersist(g_clsF.text, g_selF.text, mode, val);
}

void mfObjCHookPersist(NSString *cls, NSString *sel, int mode, id val) {
    OH_LOG(@"persist: cls=%@ sel=%@ mode=%d val=%@", cls, sel, mode, val);
    if (cls.length == 0 || sel.length == 0) { mfToast(@"类名和方法必填"); return; }
    [g_objcHooks addObject:@{@"class": cls, @"selector": sel, @"mode": @(mode), @"value": (val ?: @""), @"enabled": @YES}];
    mfObjCHookSave();
    mfObjCHookApply();
    // v2.6.45: 弹旧页重建刷新列表(配合防重入)
    if ([[(UIView *)g_mfPages.lastObject accessibilityIdentifier] isEqualToString:@"mf_objcrules"]) {
        UIView *top = g_mfPages.lastObject;
        [top removeFromSuperview];
        [g_mfPages removeLastObject];
    }
    mfShowObjCHookPage();
}

void mfObjCHookToggle(UISwitch *sw) {
    NSInteger idx = sw.tag;
    if (idx < 0 || idx >= g_objcHooks.count) return;
    NSMutableDictionary *r = [g_objcHooks[idx] mutableCopy];
    r[@"enabled"] = @(sw.on);
    g_objcHooks[idx] = r;
    mfObjCHookSave();
    [g_hookRestore removeAllObjects]; g_hookOn = NO;
    mfObjCHookApply();
}

void mfObjCHookDelTapped(UIButton *b) {
    NSInteger idx = b.tag;
    if (idx < 0 || idx >= g_objcHooks.count) return;
    [g_objcHooks removeObjectAtIndex:idx];
    mfObjCHookSave();
    [g_hookRestore removeAllObjects]; g_hookOn = NO;
    // v2.6.45: 弹旧页重建
    if ([[(UIView *)g_mfPages.lastObject accessibilityIdentifier] isEqualToString:@"mf_objcrules"]) {
        UIView *top = g_mfPages.lastObject;
        [top removeFromSuperview];
        [g_mfPages removeLastObject];
    }
    mfShowObjCHookPage();
}

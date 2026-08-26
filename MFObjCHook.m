// ====== MFObjCHook.m - 精确 ObjC 方法 hook(返回值改写) ======
// 取代只读的 MFMethodTrace(方法监控)。引擎提炼自原 MFMethodTrace 的 block-IMP 包装,
//   改为「返回值改写」模式: 对当前 app(class+selector)短路/替换返回值。
//   作用域: 仅当前面板所在 app(规则管理同款范式, 避免全局干扰其他进程)。
// 配置持久化: /var/jb/Library/MinisFix/objchooks.plist
//   规则: [{class, selector, mode, value, enabled}]  mode: 0=orig 1=nil 2=str(value)
#import "MFPanel.h"
#import <objc/runtime.h>

static NSString *MF_OBJC_HOOK_PATH = @"/var/jb/Library/MinisFix/objchooks.plist";
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
}
void mfObjCHookSave(void) {
    [g_objcHooks writeToFile:MF_OBJC_HOOK_PATH atomically:YES];
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

    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(16, y, cw-32, 40)];
    hint.text = @"精确 hook 方法返回值(作用于当前 app)。定音实验: NSBundle.appStoreReceiptURL → nil";
    hint.font = [UIFont systemFontOfSize:11]; hint.textColor = [UIColor tertiaryLabelColor];
    hint.numberOfLines = 0; [sv addSubview:hint]; y += 48;

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

#pragma mark - 编辑
// v2.6.47: 页面内表单添加(替代弹窗)——直接读表单字段
static UITextField *g_clsF = nil, *g_selF = nil, *g_valF = nil;
static UISegmentedControl *g_modeSeg = nil;

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

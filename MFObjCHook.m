// ====== MFObjCHook.m - 精确 ObjC 方法 hook(返回值改写) ======
// 取代只读的 MFMethodTrace(方法监控)。引擎提炼自原 MFMethodTrace 的 block-IMP 包装,
//   改为「返回值改写」模式: 对当前 app(class+selector)短路/替换返回值。
//   作用域: 仅当前面板所在 app(规则管理同款范式, 避免全局干扰其他进程)。
// 配置持久化: /var/jb/Library/MinisFix/objchooks.plist
//   规则: [{class, selector, mode, value, enabled}]  mode: 0=orig 1=nil 2=str(value)
#import "MFPanel.h"
#import <objc/runtime.h>

static NSString *MF_OBJC_HOOK_PATH = @"/var/jb/Library/MinisFix/objchooks.plist";
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
        NSUInteger n = sig.numberOfArguments - 3;
        if (n < 0 || n > 4) return -1;
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
    for (NSDictionary *rule in g_objcHooks) {
        if (![rule[@"enabled"] boolValue]) continue;
        Class cls = NSClassFromString(rule[@"class"]);
        if (!cls) continue;
        SEL sel = NSSelectorFromString(rule[@"selector"]);
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) continue;
        const char *enc = method_getTypeEncoding(m);
        char ret; int args = mfSafeArgs(enc, &ret);
        if (args < 0) continue;
        IMP orig = method_getImplementation(m);
        IMP wrap = mfWrapRet(ret, args, orig, [rule[@"mode"] intValue], rule[@"value"]);
        if (!wrap) continue;
        if (class_getMethodImplementation(cls, sel) != orig) {
            class_addMethod(cls, sel, wrap, enc);
        } else {
            method_setImplementation(m, wrap);
        }
        [g_hookRestore addObject:@{@"cls": cls, @"sel": NSStringFromSelector(sel), @"imp": [NSValue valueWithPointer:orig], @"enc": [NSString stringWithUTF8String:enc]}];
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
    UIView *page = mfMakePage(@"🔧 ObjC 规则", YES);
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 48, g_mfCardW, g_mfCardH - 48)];
    [page addSubview:sv];
    CGFloat cw = g_mfCardW;
    CGFloat y = 8;

    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(16, y, cw-32, 40)];
    hint.text = @"精确 hook 方法返回值(作用于当前 app)。定音实验: NSBundle.appStoreReceiptURL → nil";
    hint.font = [UIFont systemFontOfSize:11]; hint.textColor = [UIColor tertiaryLabelColor];
    hint.numberOfLines = 0; [sv addSubview:hint]; y += 48;

    UIButton *addBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    addBtn.frame = CGRectMake(16, y, cw-32, 38);
    addBtn.backgroundColor = [UIColor systemIndigoColor]; addBtn.layer.cornerRadius = 9;
    addBtn.tintColor = UIColor.whiteColor; [addBtn setTitle:@"➕ 添加规则" forState:UIControlStateNormal];
    [addBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfObjCHookAddTapped") forControlEvents:UIControlEventTouchUpInside];
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
}

#pragma mark - 编辑
void mfObjCHookAddTapped(void) {
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"添加 ObjC 规则"
        message:@"类 + 方法 + 返回值模式" preferredStyle:UIAlertControllerStyleAlert];
    [ac addTextFieldWithConfigurationHandler:^(UITextField *t){ t.placeholder = @"类名 (如 NSBundle)"; }];
    [ac addTextFieldWithConfigurationHandler:^(UITextField *t){ t.placeholder = @"方法 (如 appStoreReceiptURL)"; }];
    [ac addTextFieldWithConfigurationHandler:^(UITextField *t){ t.placeholder = @"str 值(可选)"; }];
    UIAlertAction *nilA = [UIAlertAction actionWithTitle:@"短路 nil" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a){
        mfObjCHookPersist(ac.textFields[0].text, ac.textFields[1].text, 1, nil);
    }];
    UIAlertAction *strA = [UIAlertAction actionWithTitle:@"返回 str 值" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a){
        mfObjCHookPersist(ac.textFields[0].text, ac.textFields[1].text, 2, ac.textFields[2].text);
    }];
    UIAlertAction *cancel = [UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil];
    [ac addAction:nilA]; [ac addAction:strA]; [ac addAction:cancel];
    [g_mfPanel.rootViewController presentViewController:ac animated:YES completion:nil];
}

void mfObjCHookPersist(NSString *cls, NSString *sel, int mode, id val) {
    if (cls.length == 0 || sel.length == 0) { mfToast(@"类名和方法必填"); return; }
    [g_objcHooks addObject:@{@"class": cls, @"selector": sel, @"mode": @(mode), @"value": (val ?: @""), @"enabled": @YES}];
    mfObjCHookSave();
    mfObjCHookApply();
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
    mfShowObjCHookPage();
}

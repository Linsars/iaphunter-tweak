// MFMethodTrace.m — T1: 方法调用监控（对标 ToolsEric UCPTObjCMsgSendMonitorVC 32 方法）
// 安全子集方案：只包装「返回 @/v + 参数全 @（≤4个）」的方法——block IMP 类型可枚举，签名不匹配不碰
// 全量 objc_msgSend fishhook 风险高（struct return/varargs 必崩），不做

#import "MFPanel.h"
#import <objc/runtime.h>

#pragma mark - 状态

static Class g_traceCls = nil;
static BOOL g_traceOn = NO;
static NSMutableArray *g_traceLog = nil;   // NSString 行
static NSMutableArray *g_traceRestore = nil; // @[ @{m:Method, imp:IMP} ]

NSArray *mfTraceLines(void) {
    if (!g_traceLog) return @[];
    @synchronized (g_traceLog) { return [g_traceLog copy]; }
}
BOOL mfTraceRunning(void) { return g_traceOn; }

#pragma mark - 日志

static void mfTraceLine(NSString *s) {
    if (!g_traceLog) g_traceLog = [NSMutableArray new];
    @synchronized (g_traceLog) {
        [g_traceLog addObject:s];
        if (g_traceLog.count > 800) [g_traceLog removeObjectsInRange:NSMakeRange(0, g_traceLog.count - 800)];
    }
}

static NSDateFormatter *_g_traceDF(void) {
    static NSDateFormatter *df;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        df = [NSDateFormatter new];
        df.dateFormat = @"HH:mm:ss.SSS";
    });
    return df;
}
static NSString *mfNow(void) { return [_g_traceDF() stringFromDate:[NSDate date]]; }

static NSString *mfArgDesc(id a) {
    if (!a) return @"nil";
    if ([a isKindOfClass:NSString.class]) {
        NSString *s = (NSString *)a;
        return s.length > 40 ? [[s substringToIndex:40] stringByAppendingString:@"…"] : s;
    }
    if ([a isKindOfClass:NSNumber.class]) return [(NSNumber *)a stringValue];
    return [NSString stringWithFormat:@"<%@ %p>", NSStringFromClass([a class]), a];
}

#define LOG_HEAD(self_, cmd_) \
    NSMutableString *ln = [NSMutableString stringWithFormat:@"%@ %@[%@ ", mfNow(), \
        class_isMetaClass(object_getClass(self_)) ? @"+" : @"-", NSStringFromClass(object_getClass(self_))]; \
    [ln appendString:NSStringFromSelector(cmd_)];

#define LOG_ARGS1(a1) [ln appendFormat:@" arg0:%@", mfArgDesc(a1)];
#define LOG_ARGS2(a1,a2) LOG_ARGS1(a1) [ln appendFormat:@" arg1:%@", mfArgDesc(a2)];
#define LOG_ARGS3(a1,a2,a3) LOG_ARGS2(a1,a2) [ln appendFormat:@" arg2:%@", mfArgDesc(a3)];
#define LOG_ARGS4(a1,a2,a3,a4) LOG_ARGS3(a1,a2,a3) [ln appendFormat:@" arg3:%@", mfArgDesc(a4)];

// ---- v ret ----
#define WRAP_V0 ^void(id s, SEL c) { LOG_HEAD(s,c) [ln appendString:@"]"]; mfTraceLine(ln); ((void(*)(id,SEL))o)(s,c); }
#define WRAP_V1 ^void(id s, SEL c, id a1) { LOG_HEAD(s,c) LOG_ARGS1(a1) [ln appendString:@"]"]; mfTraceLine(ln); ((void(*)(id,SEL,id))o)(s,c,a1); }
#define WRAP_V2 ^void(id s, SEL c, id a1, id a2) { LOG_HEAD(s,c) LOG_ARGS2(a1,a2) [ln appendString:@"]"]; mfTraceLine(ln); ((void(*)(id,SEL,id,id))o)(s,c,a1,a2); }
#define WRAP_V3 ^void(id s, SEL c, id a1, id a2, id a3) { LOG_HEAD(s,c) LOG_ARGS3(a1,a2,a3) [ln appendString:@"]"]; mfTraceLine(ln); ((void(*)(id,SEL,id,id,id))o)(s,c,a1,a2,a3); }
#define WRAP_V4 ^void(id s, SEL c, id a1, id a2, id a3, id a4) { LOG_HEAD(s,c) LOG_ARGS4(a1,a2,a3,a4) [ln appendString:@"]"]; mfTraceLine(ln); ((void(*)(id,SEL,id,id,id,id))o)(s,c,a1,a2,a3,a4); }

// ---- @ ret ----
#define WRAP_A0 ^id(id s, SEL c) { LOG_HEAD(s,c) [ln appendString:@"]"]; mfTraceLine(ln); return ((id(*)(id,SEL))o)(s,c); }
#define WRAP_A1 ^id(id s, SEL c, id a1) { LOG_HEAD(s,c) LOG_ARGS1(a1) [ln appendString:@"]"]; mfTraceLine(ln); return ((id(*)(id,SEL,id))o)(s,c,a1); }
#define WRAP_A2 ^id(id s, SEL c, id a1, id a2) { LOG_HEAD(s,c) LOG_ARGS2(a1,a2) [ln appendString:@"]"]; mfTraceLine(ln); return ((id(*)(id,SEL,id,id))o)(s,c,a1,a2); }
#define WRAP_A3 ^id(id s, SEL c, id a1, id a2, id a3) { LOG_HEAD(s,c) LOG_ARGS3(a1,a2,a3) [ln appendString:@"]"]; mfTraceLine(ln); return ((id(*)(id,SEL,id,id,id))o)(s,c,a1,a2,a3); }
#define WRAP_A4 ^id(id s, SEL c, id a1, id a2, id a3, id a4) { LOG_HEAD(s,c) LOG_ARGS4(a1,a2,a3,a4) [ln appendString:@"]"]; mfTraceLine(ln); return ((id(*)(id,SEL,id,id,id,id))o)(s,c,a1,a2,a3,a4); }

// block 字面量是栈对象——必须经 imp_implementationWithBlock 堆拷贝后才是合法 IMP
static IMP mfWrapFor(char ret, int nargs, IMP orig) {
    IMP o = orig;  // 各 wrapper 宏引用此局部变量，block 创建时按值捕获
    id blk = nil;
    #define P(R,N) (ret=='v' ? (id)WRAP_V##N : (id)WRAP_A##N)
    switch (nargs) {
        case 0: blk = P(ret,0); break;
        case 1: blk = P(ret,1); break;
        case 2: blk = P(ret,2); break;
        case 3: blk = P(ret,3); break;
        case 4: blk = P(ret,4); break;
        default: return NULL;
    }
    #undef P
    if (!blk) return NULL;
    return imp_implementationWithBlock(blk);
}

// 编码检查(v2.6.35 重写): 旧版手搓字符比对被 arm64 偏移量数字坑死(@16@0:8 的 t[1]=='1')
//   → 全部方法误判非安全签名,"已包装 0 个"。用 NSMethodSignature 正规解析。
static int mfSafeArgs(const char *t, char *retOut) {
    if (!t) return -1;
    @try {
        NSMethodSignature *sig = [NSMethodSignature signatureWithObjCTypes:t];
        if (!sig) return -1;
        // arg0=ret, arg1=self(@), arg2=_cmd(:), arg3..=真实参数
        char ret = [sig getArgumentTypeAtIndex:0][0];
        if (ret != '@' && ret != 'v') return -1;
        NSUInteger n = sig.numberOfArguments - 3; // 实参个数
        if (n < 0 || n > 4) return -1;
        for (NSUInteger i = 3; i < sig.numberOfArguments; i++) {
            const char *ty = [sig getArgumentTypeAtIndex:i];
            if (ty[0] != '@') return -1;   // 只接受对象/block 参数(nilable 安全)
        }
        *retOut = ret;
        return (int)n;
    } @catch (NSException *e) {
        return -1;
    }
}

#pragma mark - 启停

// v2.6.36: selector 白名单制——NSBundle 等基础设施类全量包装 = 崩溃(Picsew 实测)
//   只 hook 明确列出的 selector; sels=nil 保持旧的全量模式(仅限小型业务类)
static BOOL mfTraceStartInternal(NSString *className, NSArray<NSString *> *sels, NSString **errOut);

BOOL mfTraceStart(NSString *className, NSString **errOut) {
    return mfTraceStartInternal(className, nil, errOut);
}

// 🧪 SK 收银台侦察包: 环境判定点定位专用(AS vs TF 双端对照)
NSDictionary<NSString *, NSArray<NSString *> *> *mfSKPresetMap(void) {
    return @{
        @"NSBundle": @[@"appStoreReceiptURL"],
        @"SKPaymentQueue": @[@"addPayment:", @"addTransactions:", @"restoreCompletedTransactions",
                             @"finishTransaction:", @"paymentQueue:updatedTransactions:"],
        @"SKReceiptRefreshRequest": @[@"start"],
    };
}

BOOL mfTraceStartPreset(NSString **errOut) {
    if (g_traceOn) { if (errOut) *errOut = @"已在监控中，请先停止"; return NO; }
    if (!g_traceLog) g_traceLog = [NSMutableArray new];
    if (!g_traceRestore) g_traceRestore = [NSMutableArray new];

    __block int totalCount = 0, totalSkip = 0;
    NSMutableString *report = [NSMutableString string];
    for (NSString *clsName in mfSKPresetMap()) {
        Class cls = NSClassFromString(clsName);
        if (!cls) { [report appendFormat:@"✗ %@ 不存在\n", clsName]; continue; }
        int before = (int)g_traceRestore.count;
        NSString *subErr = nil;
        BOOL ok = mfTraceStartInternal(clsName, mfSKPresetMap()[clsName], &subErr);
        if (ok) {
            int added = (int)g_traceRestore.count - before;
            [report appendFormat:@"✓ %@ ×%d\n", clsName, added];
            totalCount += added;
        } else {
            [report appendFormat:@"✗ %@ 失败 %@\n", clsName, subErr ?: @""];
        }
        totalSkip++;
    }
    if (totalCount == 0) {
        if (errOut) *errOut = [@"侦察包无可用方法:\n" stringByAppendingString:report];
        g_traceOn = NO;
        return NO;
    }
    g_traceOn = YES;
    mfTraceLine([NSString stringWithFormat:@"▶ 🧪SK侦察包 启动 (%d methods)\n%@", totalCount, report]);
    return YES;
}

static BOOL mfTraceStartInternal(NSString *className, NSArray<NSString *> *sels, NSString **errOut) {
    if (g_traceOn && !sels) { if (errOut) *errOut = @"已在监控中，请先停止"; return NO; }
    Class cls = NSClassFromString(className) ?: objc_getClass(className.UTF8String);
    if (!cls) { if (errOut) *errOut = [NSString stringWithFormat:@"类不存在: %@", className]; return NO; }

    if (!g_traceLog) g_traceLog = [NSMutableArray new];
    if (!g_traceRestore) g_traceRestore = [NSMutableArray new];
    g_traceCls = cls;

    __block int count = 0, skipped = 0;
    void (^traceList)(Class, BOOL) = ^(Class c, BOOL isMeta) {
        unsigned int n = 0;
        Method *ms = class_copyMethodList(c, &n);
        for (unsigned int i = 0; i < n; i++) {
            Method m = ms[i];
            SEL sel = method_getName(m);
            NSString *selName = NSStringFromSelector(sel);
            if (sels && ![sels containsObject:selName]) { skipped++; continue; }
            const char *enc = method_getTypeEncoding(m);
            char ret;
            int args = mfSafeArgs(enc, &ret);
            if (args < 0) { skipped++; continue; }
            IMP orig = method_getImplementation(m);
            IMP wrap = mfWrapFor(ret, args, orig);
            if (!wrap) { skipped++; continue; }
            method_setImplementation(m, wrap);
            [g_traceRestore addObject:@{@"m": [NSValue valueWithPointer:m], @"imp": [NSValue valueWithPointer:orig], @"cls": c, @"sel": selName}];
            count++;
        }
        free(ms);
    };
    traceList(cls, NO);
    traceList(object_getClass(cls), YES);

    if (count == 0) {
        if (errOut) *errOut = sels.count
            ? [NSString stringWithFormat:@"%@ 无白名单方法可包装(目标 %@)", className, sels]
            : @"该类没有符合安全签名的可监控方法";
        if (!g_traceOn) g_traceCls = nil;
        return NO;
    }
    if (!g_traceOn) {
        g_traceOn = YES;
        mfTraceLine([NSString stringWithFormat:@"▶ 监控 %@ 开始（已包装 %d 个方法，跳过 %d 个）", className, count, skipped]);
    } else {
        mfTraceLine([NSString stringWithFormat:@"▶ + %@（+%d 个方法）", className, count]);
    }
    return YES;
}

void mfTraceStop(void) {
    if (!g_traceOn) return;
    for (NSDictionary *e in g_traceRestore) {
        Method m = (Method)[e[@"m"] pointerValue];
        IMP orig = (IMP)[e[@"imp"] pointerValue];
        method_setImplementation(m, orig);
    }
    [g_traceRestore removeAllObjects];
    g_traceOn = NO;
    mfTraceLine(@"■ 监控停止");
}

#pragma mark - 页面（Ctrl wrapper 经由 MFPanel.m 调）

static UITextView *g_traceTV = nil;
static UIButton *g_traceToggleBtn = nil;
static NSTimer *g_traceTimer = nil;
static UITextField *g_traceClsField = nil;
static UITextField *g_traceFilterField = nil;
static NSString *g_tracePrefillCls = nil;

void mfTraceSetPrefill(NSString *cls) { g_tracePrefillCls = [cls copy]; }

void mfTraceRefreshUI(void) {
    if (!g_traceTV) return;
    NSString *filter = g_traceFilterField.text ?: @"";
    NSArray *lines = mfTraceLines();
    NSMutableString *s = [NSMutableString string];
    for (NSString *l in lines) {
        if (filter.length && ![l containsString:filter]) continue;
        [s appendFormat:@"%@\n", l];
    }
    if (s.length == 0) [s appendString:@"（暂无调用记录）"];
    NSRange sel = g_traceTV.selectedRange;
    BOOL atBottom = sel.location == NSNotFound || sel.location >= g_traceTV.text.length - 1;
    g_traceTV.text = s;
    if (atBottom) {
        NSRange end = NSMakeRange(g_traceTV.text.length, 0);
        [g_traceTV scrollRangeToVisible:end];
    }
}

void mfTraceToggleTapped(void) {
    if (g_traceOn) {
        mfTraceStop();
        mfToast(@"⏹️ 已停止");
    } else {
        NSString *err = nil;
        NSString *name = g_traceClsField.text ?: @"";
        if (name.length == 0) { mfToast(@"⚠️ 请输入类名"); return; }
        if (!mfTraceStart(name, &err) && err) { mfToast([@"⚠️ " stringByAppendingString:err]); }
        else mfToast(@"▶️ 监控开始");
    }
    [g_traceToggleBtn setTitle:g_traceOn ? @"⏹ 停止监控" : @"▶ 开始监控" forState:UIControlStateNormal];
    [g_traceToggleBtn setBackgroundColor:g_traceOn ? [UIColor systemRedColor] : [UIColor systemGreenColor]];
    mfTraceRefreshUI();
}

void mfTraceTogglePresetTapped(void) {
    if (g_traceOn) {
        mfTraceStop();
        mfToast(@"⏹️ 已停止");
    } else {
        NSString *err = nil;
        if (!mfTraceStartPreset(&err) && err) { mfToast([@"⚠️ " stringByAppendingString:err]); }
        else mfToast(@"▶️ SK 侦察包启动");
    }
    [g_traceToggleBtn setTitle:g_traceOn ? @"⏹ 停止监控" : @"▶ 开始监控" forState:UIControlStateNormal];
    [g_traceToggleBtn setBackgroundColor:g_traceOn ? [UIColor systemRedColor] : [UIColor systemGreenColor]];
    mfTraceRefreshUI();
}

void mfTraceClearTapped(void) {
    @synchronized (g_traceLog) { [g_traceLog removeAllObjects]; }
    mfTraceRefreshUI();
    mfToast(@"🗑️ 日志已清空");
}

void mfShowMethodTracePage(void) {
    UIView *page = mfMakePage(@"🔍 方法监控", YES);
    CGFloat cw = g_mfCardW - 32;

    UILabel *lb1 = [[UILabel alloc] initWithFrame:CGRectMake(16, 46, cw, 20)];
    lb1.text = @"目标类名";
    lb1.font = [UIFont systemFontOfSize:11];
    lb1.textColor = [UIColor secondaryLabelColor];
    [page addSubview:lb1];

    g_traceClsField = [[UITextField alloc] initWithFrame:CGRectMake(16, 68, cw, 36)];
    g_traceClsField.placeholder = @"如 NSURLSessionDataManager";
    g_traceClsField.font = [UIFont systemFontOfSize:12];
    g_traceClsField.borderStyle = UITextBorderStyleRoundedRect;
    g_traceClsField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    g_traceClsField.autocorrectionType = UITextAutocorrectionTypeNo;
    if (g_tracePrefillCls) { g_traceClsField.text = g_tracePrefillCls; g_tracePrefillCls = nil; }
    [page addSubview:g_traceClsField];

    UILabel *lb2 = [[UILabel alloc] initWithFrame:CGRectMake(16, 110, cw, 20)];
    lb2.text = @"过滤（选填，含即记录）";
    lb2.font = [UIFont systemFontOfSize:11];
    lb2.textColor = [UIColor secondaryLabelColor];
    [page addSubview:lb2];

    g_traceFilterField = [[UITextField alloc] initWithFrame:CGRectMake(16, 132, cw, 36)];
    g_traceFilterField.placeholder = @"如 login / refresh";
    g_traceFilterField.font = [UIFont systemFontOfSize:12];
    g_traceFilterField.borderStyle = UITextBorderStyleRoundedRect;
    g_traceFilterField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    [page addSubview:g_traceFilterField];

    // 操作行：启停 / 清空 / 分享
    g_traceToggleBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    g_traceToggleBtn.frame = CGRectMake(16, 178, (cw - 24) / 3, 38);
    g_traceToggleBtn.backgroundColor = [UIColor systemGreenColor];
    g_traceToggleBtn.layer.cornerRadius = 9;
    g_traceToggleBtn.tintColor = UIColor.whiteColor;
    [g_traceToggleBtn setTitle:g_traceOn ? @"⏹ 停止" : @"▶ 开始" forState:UIControlStateNormal];
    g_traceToggleBtn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [page addSubview:g_traceToggleBtn];

    UIButton *presetBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    presetBtn.frame = CGRectMake(20 + (cw - 24) / 3, 178, (cw - 24) / 3, 38);
    presetBtn.backgroundColor = [UIColor systemIndigoColor];
    presetBtn.layer.cornerRadius = 9;
    presetBtn.tintColor = UIColor.whiteColor;
    [presetBtn setTitle:@"🧪 SK侦察包" forState:UIControlStateNormal];
    presetBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [presetBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfTracePresetTapped") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:presetBtn];

    UIButton *clrBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    clrBtn.frame = CGRectMake(24 + (cw - 24) * 2 / 3, 178, (cw - 24) / 3, 38);
    clrBtn.backgroundColor = [UIColor secondarySystemBackgroundColor];
    clrBtn.layer.cornerRadius = 9;
    clrBtn.tintColor = [UIColor labelColor];
    [clrBtn setTitle:@"🗑 清空" forState:UIControlStateNormal];
    clrBtn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [page addSubview:clrBtn];

    g_traceTV = [[UITextView alloc] initWithFrame:CGRectMake(16, 226, cw, g_mfCardH - 240)];
    g_traceTV.editable = NO;
    g_traceTV.font = [UIFont fontWithName:@"Menlo" size:10];
    g_traceTV.layer.cornerRadius = 8;
    g_traceTV.layer.borderWidth = 0.5;
    g_traceTV.layer.borderColor = [UIColor systemGray3Color].CGColor;
    g_traceTV.backgroundColor = [UIColor secondarySystemBackgroundColor];
    [page addSubview:g_traceTV];

    // 事件绑定 → Ctrl wrapper（静态方法）
    [g_traceToggleBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfTraceToggleTapped") forControlEvents:UIControlEventTouchUpInside];
    [clrBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfTraceClearTapped") forControlEvents:UIControlEventTouchUpInside];

    // 定时刷新
    g_traceTimer = [NSTimer scheduledTimerWithTimeInterval:0.8 repeats:YES block:^(NSTimer *t) {
        if (!g_mfPanelOverlay) { [t invalidate]; g_traceTimer = nil; return; }
        mfTraceRefreshUI();
    }];
    objc_setAssociatedObject(page, "traceTimer", g_traceTimer, OBJC_ASSOCIATION_RETAIN);

    mfTraceRefreshUI();
    mfPushPage(page);
}

// MFCryptoHooks.m — T1: 解密捕获（对标 ToolsEric UCDecryptTool 8 方法）
// MSHookFunction 运行时 dlsym 解析（ellekit 注入进程后存在；编译期不依赖 substrate 头）
// Hook: CCCrypt / CCCryptorCreate(CreateWithMode) / Update / Final / CCHmac / CC_MD5/SHA*
// 开关: pref "mfCryptoCapture"；关=纯透传零开销路径

#import "MFPanel.h"
#import <CommonCrypto/CommonCrypto.h>
#import <dlfcn.h>
#import <objc/runtime.h>

typedef uint32_t CCPaddingOptionsT;  // 老 SDK SPI 常量手动补（v1.8.0 已验证）

#pragma mark - 捕获记录模型

@interface MFCryptoRecord : NSObject
@property (copy) NSString *kind;    // AES-CBC / HMAC-SHA256 / MD5 ...
@property (copy) NSString *dir;     // 加密/解密/流式/HMAC/摘要
@property (copy) NSString *keyHex;
@property (copy) NSString *ivHex;
@property (strong) NSData *input;
@property (strong) NSData *output;
@property (strong) NSDate *ts;
@end
@implementation MFCryptoRecord @end

static NSMutableArray *g_cryptoRecs = nil;
static BOOL g_cryptoHookInstalled = NO;

BOOL mfCryptoEnabledState(void) {
    return mfPrefBool(@"mfCryptoCapture", NO);
}

static void mfCryptoRecord(MFCryptoRecord *r) {
    if (!g_cryptoRecs) g_cryptoRecs = [NSMutableArray new];
    @synchronized (g_cryptoRecs) {
        [g_cryptoRecs addObject:r];
        if (g_cryptoRecs.count > 100) [g_cryptoRecs removeObjectAtIndex:0];
    }
}

NSArray *mfCryptoRecordsSnapshot(void) {
    if (!g_cryptoRecs) return @[];
    @synchronized (g_cryptoRecs) { return [g_cryptoRecs copy]; }
}

static NSString *mfHex(NSData *d, NSUInteger cap) {
    if (!d || d.length == 0) return @"(空)";
    NSUInteger n = MIN(d.length, cap);
    NSMutableString *s = [NSMutableString stringWithCapacity:n * 2];
    const unsigned char *b = d.bytes;
    for (NSUInteger i = 0; i < n; i++) [s appendFormat:@"%02x", b[i]];
    if (d.length > cap) [s appendFormat:@"…(+%luB)", (unsigned long)(d.length - cap)];
    return s;
}
static NSString *mfTryUtf8(NSData *d) {
    if (!d || d.length == 0) return nil;
    NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if (!s) return nil;
    unichar printable = 0;
    for (NSUInteger i = 0; i < s.length && i < 64; i++)
        if ([s characterAtIndex:i] >= 32 && [s characterAtIndex:i] != 127) printable++;
    if (printable * 100 / MIN((NSUInteger)64, s.length) < 70) return nil;
    return s.length > 200 ? [[s substringToIndex:200] stringByAppendingString:@"…"] : s;
}

#pragma mark - 流式上下文映射（CCCryptorRef -> key/iv/out）

static NSMutableDictionary *g_streamMap = nil;
static NSString *mfCtxKey(void *ctx) { return [NSString stringWithFormat:@"%p", ctx]; }

#pragma mark - 原函数指针

static CCCryptorStatus (*o_CCCrypt)(CCOperation, CCAlgorithm, CCOptions, const void *, size_t, const void *, const void *, size_t, void *, size_t, size_t *);
static CCCryptorStatus (*o_CCCryptorCreate)(CCOperation, CCAlgorithm, CCPaddingOptionsT, const void *, size_t, const void *, CCCryptorRef *);
static CCCryptorStatus (*o_CCCryptorCreateWithMode)(CCOperation, CCMode, CCAlgorithm, CCPaddingOptionsT, const void *, const void *, size_t, const void *, size_t, int, CCModeOptions, CCCryptorRef *);
static CCCryptorStatus (*o_CCCryptorUpdate)(CCCryptorRef, const void *, size_t, void *, size_t, size_t *);
static CCCryptorStatus (*o_CCCryptorFinal)(CCCryptorRef, void *, size_t, size_t *);
static void (*o_CCHmac)(CCHmacAlgorithm, const void *, size_t, const void *, size_t, void *);

static NSString *mfAlgName(CCAlgorithm alg, CCMode mode) {
    NSString *a = alg == kCCAlgorithmAES ? @"AES" : alg == kCCAlgorithm3DES ? @"3DES" : alg == kCCAlgorithmDES ? @"DES" : alg == kCCAlgorithmRC4 ? @"RC4" : alg == kCCAlgorithmCAST ? @"CAST" : alg == kCCAlgorithmBlowfish ? @"Blowfish" : [NSString stringWithFormat:@"alg%d", alg];
    NSString *m = mode == kCCModeECB ? @"ECB" : mode == kCCModeCBC ? @"CBC" : mode == kCCModeCFB ? @"CFB" : mode == kCCModeCTR ? @"CTR" : @"";
    return m.length ? [NSString stringWithFormat:@"%@-%@", a, m] : a;
}

#pragma mark - Hook 实现

static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opts,
                                  const void *key, size_t keyLen, const void *iv,
                                  const void *dataIn, size_t dataInLen,
                                  void *dataOut, size_t dataOutAvail, size_t *dataOutMoved) {
    CCCryptorStatus st = o_CCCrypt(op, alg, opts, key, keyLen, iv, dataIn, dataInLen, dataOut, dataOutAvail, dataOutMoved);
    if (!mfCryptoEnabledState() || !key) return st;
    @autoreleasepool {
        MFCryptoRecord *r = [MFCryptoRecord new];
        r.kind = mfAlgName(alg, opts & kCCOptionECBMode ? kCCModeECB : kCCModeCBC);
        r.dir = op == kCCEncrypt ? @"加密" : @"解密";
        r.keyHex = mfHex([[NSData alloc] initWithBytes:key length:keyLen], 32);
        r.ivHex = iv ? mfHex([[NSData alloc] initWithBytes:iv length:MIN(keyLen == 24 ? 8 : 16, (NSUInteger)16)], 16) : @"(无)";
        r.input = [[NSData alloc] initWithBytes:dataIn length:dataInLen];
        if (dataOutMoved && *dataOutMoved > 0) r.output = [[NSData alloc] initWithBytes:dataOut length:*dataOutMoved];
        r.ts = [NSDate date];
        mfCryptoRecord(r);
        mfLog(@"[crypto] %@ %@ in=%luB out=%luB", r.dir, r.kind, (unsigned long)dataInLen, dataOutMoved ? (unsigned long)*dataOutMoved : 0);
    }
    return st;
}

static CCCryptorStatus my_CCCryptorCreate(CCOperation op, CCAlgorithm alg, CCPaddingOptionsT pad,
                                          const void *key, size_t keyLen, const void *iv, CCCryptorRef *ref) {
    CCCryptorStatus st = o_CCCryptorCreate(op, alg, pad, key, keyLen, iv, ref);
    if (st == 0 && ref && *ref && key && mfCryptoEnabledState()) {
        @synchronized (g_streamMap) {
            NSMutableDictionary *info = [NSMutableDictionary new];
            info[@"alg"] = mfAlgName(alg, kCCModeCBC);
            info[@"op"] = op == kCCEncrypt ? @"加密" : @"解密";
            info[@"key"] = mfHex([[NSData alloc] initWithBytes:key length:keyLen], 32);
            if (iv) info[@"iv"] = mfHex([[NSData alloc] initWithBytes:iv length:16], 16);
            info[@"out"] = [NSMutableData new];
            g_streamMap[mfCtxKey((void *)*ref)] = info;
        }
    }
    return st;
}

static CCCryptorStatus my_CCCryptorUpdate(CCCryptorRef ref, const void *dataIn, size_t dataInLen,
                                          void *dataOut, size_t dataOutAvail, size_t *dataOutMoved) {
    CCCryptorStatus st = o_CCCryptorUpdate(ref, dataIn, dataInLen, dataOut, dataOutAvail, dataOutMoved);
    if (st == 0 && dataOutMoved && *dataOutMoved > 0 && mfCryptoEnabledState()) {
        @synchronized (g_streamMap) {
            NSMutableDictionary *info = g_streamMap[mfCtxKey((void *)ref)];
            if (info) [info[@"out"] appendBytes:dataOut length:MIN(*dataOutMoved, (size_t)65536)];
        }
    }
    return st;
}

static CCCryptorStatus my_CCCryptorFinal(CCCryptorRef ref, void *dataOut, size_t dataOutAvail, size_t *dataOutMoved) {
    CCCryptorStatus st = o_CCCryptorFinal(ref, dataOut, dataOutAvail, dataOutMoved);
    NSString *k = mfCtxKey((void *)ref);
    @synchronized (g_streamMap) {
        NSMutableDictionary *info = g_streamMap[k];
        if (info && mfCryptoEnabledState()) {
            if (dataOutMoved && *dataOutMoved > 0) [info[@"out"] appendBytes:dataOut length:MIN(*dataOutMoved, (size_t)65536)];
            MFCryptoRecord *r = [MFCryptoRecord new];
            r.kind = info[@"alg"];
            r.dir = [@"流式·" stringByAppendingString:info[@"op"]];
            r.keyHex = info[@"key"];
            r.ivHex = info[@"iv"] ?: @"(无)";
            r.output = info[@"out"];
            r.ts = [NSDate date];
            mfCryptoRecord(r);
            [g_streamMap removeObjectForKey:k];
        } else if (info) {
            [g_streamMap removeObjectForKey:k];
        }
    }
    return st;
}

static void my_CCHmac(CCHmacAlgorithm alg, const void *key, size_t keyLen,
                      const void *data, size_t dataLen, void *macOut) {
    o_CCHmac(alg, key, keyLen, data, dataLen, macOut);
    if (!mfCryptoEnabledState() || !key) return;
    @autoreleasepool {
        MFCryptoRecord *r = [MFCryptoRecord new];
        NSString *a = alg == kCCHmacAlgSHA256 ? @"HMAC-SHA256" : alg == kCCHmacAlgSHA1 ? @"HMAC-SHA1" : alg == kCCHmacAlgMD5 ? @"HMAC-MD5" : alg == kCCHmacAlgSHA384 ? @"HMAC-SHA384" : alg == kCCHmacAlgSHA512 ? @"HMAC-SHA512" : @"HMAC";
        r.kind = a;
        r.dir = @"HMAC";
        r.keyHex = mfHex([[NSData alloc] initWithBytes:key length:keyLen], 32);
        r.input = [[NSData alloc] initWithBytes:data length:dataLen];
        size_t macLen = alg == kCCHmacAlgSHA1 ? 20 : alg == kCCHmacAlgMD5 ? 16 : alg == kCCHmacAlgSHA256 ? 32 : alg == kCCHmacAlgSHA384 ? 48 : 64;
        r.output = [[NSData alloc] initWithBytes:macOut length:macLen];
        r.ts = [NSDate date];
        mfCryptoRecord(r);
    }
}

static CCCryptorStatus my_CCCryptorCreateWithMode(CCOperation op, CCMode mode, CCAlgorithm alg, CCPaddingOptionsT pad,
                                                  const void *iv, const void *key, size_t keyLen,
                                                  const void *tweak, size_t tweakLen, int numRounds,
                                                  CCModeOptions options, CCCryptorRef *ref) {
    CCCryptorStatus st = o_CCCryptorCreateWithMode(op, mode, alg, pad, iv, key, keyLen, tweak, tweakLen, numRounds, options, ref);
    if (st == 0 && ref && *ref && key && mfCryptoEnabledState()) {
        @synchronized (g_streamMap) {
            NSMutableDictionary *info = [NSMutableDictionary new];
            info[@"alg"] = mfAlgName(alg, mode);
            info[@"op"] = op == kCCEncrypt ? @"加密" : @"解密";
            info[@"key"] = mfHex([[NSData alloc] initWithBytes:key length:keyLen], 32);
            if (iv) info[@"iv"] = mfHex([[NSData alloc] initWithBytes:iv length:MIN(keyLen, (size_t)16)], 16);
            info[@"out"] = [NSMutableData new];
            g_streamMap[mfCtxKey((void *)*ref)] = info;
        }
    }
    return st;
}

#pragma mark - 安装

void mfInstallCryptoHooks(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_streamMap = [NSMutableDictionary new];
        void (*hook)(void *, void *, void **) = (void (*)(void *, void *, void **))dlsym(RTLD_DEFAULT, "MSHookFunction");
        if (!hook) { mfLog(@"[crypto] MSHookFunction 不可用（ellekit 未注入？），解密捕获禁用"); return; }

        void *f;
        f = dlsym(RTLD_DEFAULT, "CCCrypt");
        if (f) { hook(f, (void *)my_CCCrypt, (void **)&o_CCCrypt); }
        f = dlsym(RTLD_DEFAULT, "CCCryptorCreateWithMode");
        if (f) { hook(f, (void *)my_CCCryptorCreateWithMode, (void **)&o_CCCryptorCreateWithMode); }
        f = dlsym(RTLD_DEFAULT, "CCCryptorCreate");
        if (f) { hook(f, (void *)my_CCCryptorCreate, (void **)&o_CCCryptorCreate); }
        f = dlsym(RTLD_DEFAULT, "CCCryptorUpdate");
        if (f) { hook(f, (void *)my_CCCryptorUpdate, (void **)&o_CCCryptorUpdate); }
        f = dlsym(RTLD_DEFAULT, "CCCryptorFinal");
        if (f) { hook(f, (void *)my_CCCryptorFinal, (void **)&o_CCCryptorFinal); }
        f = dlsym(RTLD_DEFAULT, "CCHmac");
        if (f) { hook(f, (void *)my_CCHmac, (void **)&o_CCHmac); }
        g_cryptoHookInstalled = YES;
        mfLog(@"[crypto] hooks installed (MSHookFunction via ellekit)");
    });
}

#pragma mark - 页面

@interface MFCryptoCapList : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray *recs;
@end
@implementation MFCryptoCapList
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return (NSInteger)self.recs.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *id_ = @"mfcaprow";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:id_];
    if (!c) c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:id_];
    MFCryptoRecord *r = self.recs[ip.row];
    c.textLabel.text = [NSString stringWithFormat:@"%@ · %@", r.dir, r.kind];
    c.textLabel.font = [UIFont systemFontOfSize:12];
    c.textLabel.textColor = [UIColor labelColor];
    NSDateFormatter *df = [NSDateFormatter new];
    df.dateFormat = @"HH:mm:ss";
    c.detailTextLabel.text = [NSString stringWithFormat:@"%@ | key %@ | %luB", [df stringFromDate:r.ts], r.keyHex ?: @"-", (unsigned long)(r.output.length ?: r.input.length)];
    c.detailTextLabel.font = [UIFont systemFontOfSize:10];
    c.detailTextLabel.textColor = [UIColor tertiaryLabelColor];
    c.backgroundColor = UIColor.clearColor;
    return c;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    MFCryptoRecord *r = self.recs[ip.row];
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"类型: %@\n方向: %@\n时间: %@\n\n【Key】\n%@\n\n【IV】\n%@\n",
        r.kind, r.dir, r.ts, r.keyHex ?: @"-", r.ivHex ?: @"-"];
    [s appendFormat:@"\n【输入 hex】(%luB)\n%@\n", (unsigned long)r.input.length, mfHex(r.input, 512)];
    NSString *inU = mfTryUtf8(r.input);
    if (inU) [s appendFormat:@"\n【输入 UTF8?】\n%@\n", inU];
    [s appendFormat:@"\n【输出 hex】(%luB)\n%@\n", (unsigned long)r.output.length, mfHex(r.output, 512)];
    NSString *outU = mfTryUtf8(r.output);
    if (outU) [s appendFormat:@"\n【输出 UTF8?】\n%@\n", outU];
    mfShowTextReportPage(r.kind, s, @"CryptoCapture");
}
@end

// Ctrl wrapper 调用
void mfCryptoCapSwitchChanged(UISwitch *sw) {
    mfSetBoolPref(@"mfCryptoCapture", sw.on);
    if (sw.on) mfInstallCryptoHooks();
    mfToast(sw.on ? @"🔓 解密捕获已开启" : @"🔒 解密捕获已关闭");
}

void mfCryptoClearTapped(void) {
    @synchronized (g_cryptoRecs) { [g_cryptoRecs removeAllObjects]; }
    mfToast(@"🗑️ 记录已清空");
}

void mfShowCryptoCapturePage(void) {
    mfExpandCardForPage();
    UIView *page = mfMakePage(@"🔓 解密捕获", YES);

    UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(16, 46, g_mfCardW - 90, 24)];
    lb.text = @"⏺ 实时捕获 CCCrypt/HMAC";
    lb.font = [UIFont boldSystemFontOfSize:13];
    lb.textColor = [UIColor labelColor];
    [page addSubview:lb];
    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(g_mfCardW - 68, 44, 51, 31)];
    sw.on = mfCryptoEnabledState();
    objc_setAssociatedObject(sw, "on", @(1), OBJC_ASSOCIATION_RETAIN);
    [page addSubview:sw];

    UIButton *clrBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    clrBtn.frame = CGRectMake(16, 82, g_mfCardW - 32, 34);
    clrBtn.backgroundColor = [UIColor secondarySystemBackgroundColor];
    clrBtn.layer.cornerRadius = 8;
    [clrBtn setTitle:@"清空记录" forState:UIControlStateNormal];
    clrBtn.tintColor = [UIColor labelColor];
    objc_setAssociatedObject(clrBtn, "sw", sw, OBJC_ASSOCIATION_RETAIN);
    [page addSubview:clrBtn];

    UITableView *tv = [[UITableView alloc] initWithFrame:CGRectMake(0, 122, g_mfCardW, g_mfCardH - 122) style:UITableViewStylePlain];
    tv.backgroundColor = UIColor.clearColor;
    tv.separatorStyle = UITableViewCellSeparatorStyleNone;
    tv.rowHeight = 52;
    MFCryptoCapList *ds = [MFCryptoCapList new];
    ds.recs = mfCryptoRecordsSnapshot();
    tv.dataSource = ds;
    tv.delegate = ds;
    objc_setAssociatedObject(page, "capDS", ds, OBJC_ASSOCIATION_RETAIN);

    // 定时刷新列表 + 开关状态同步
    __block NSTimer *timer = [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *t) {
        if (!g_mfPanelOverlay) { [t invalidate]; return; }
        sw.on = mfCryptoEnabledState();
        NSArray *snap = mfCryptoRecordsSnapshot();
        if (![snap isEqualToArray:ds.recs]) {
            ds.recs = snap;
            [tv reloadData];
        }
    }];
    objc_setAssociatedObject(page, "capTimer", timer, OBJC_ASSOCIATION_RETAIN);

    // 控件事件 → Ctrl wrapper（静态方法，MFPanel.m @implementation MFPanelCtrl）
    [sw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCryptoSwitchChanged:") forControlEvents:UIControlEventValueChanged];
    [clrBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCryptoClearTapped") forControlEvents:UIControlEventTouchUpInside];

    // 首次打开即预装 hook（开关开着才生效）
    if (mfCryptoEnabledState()) mfInstallCryptoHooks();

    [page addSubview:tv];
    mfPushPage(page);
}

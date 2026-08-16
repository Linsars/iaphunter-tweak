// MFPanel.m — MinisFix v5.0 面板控制器 + 导航系统 + 主面板
// 主页双列网格：数据分析 📡 / 网络修改 🔧 / Product 🛍️

#import "MFPanel.h"
#import <CommonCrypto/CommonCrypto.h>
#import <StoreKit/StoreKit.h>

// ====== 全局状态（定义在此，extern 在 MFPanel.h） ======
UIView *g_mfPanelOverlay = nil;
UIViewController *g_mfPanelRootVC = nil;
id g_mfCtrl = nil;
NSMutableArray *g_mfPages = nil;
CGFloat g_mfCardW = 0, g_mfCardH = 0;
UIView *g_mfCardContentView = nil;  // card.contentView——子页挂这里
UIView *g_mfHomePage = nil;         // 主页内容容器——push 子页时隐藏
UIVisualEffectView *g_mfCardView = nil;  // 卡片引用——动态伸缩用
CGFloat g_mfHomeCardH = 300;        // 主页卡片高度

// ====== 日志 ======
void mfLog(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSLog(@"[MF] %@", msg);
    // 写沙盒日志
    static NSString *logPath = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        logPath = [docs stringByAppendingPathComponent:@"mf_debug.log"];
    });
    @try {
        NSString *line = [NSString stringWithFormat:@"[%.0f] %@\n", [NSDate date].timeIntervalSince1970, msg];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
        if (!fh) {
            [[NSFileManager defaultManager] createFileAtPath:logPath contents:nil attributes:nil];
            fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
        }
        if (fh) { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
    } @catch (NSException *e) {}
}

// ====== Prefs ======
NSDictionary *mfPrefsDict(void) {
    static NSString *path = nil;
    if (!path) path = @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist";
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:path];
    return d ?: @{};
}

// 设置页启用检查：启用 IAP工具箱（mfIAPEnabled，默认开）× 应用程序白名单（mfIAPAppList，
// AltList 多选存启用数组；空=不启用任何 app）。所有更改需 respring 生效（ctor 只跑一次）。
BOOL mfIsEnabledForCurrentApp(void) {
    NSDictionary *prefs = mfPrefsDict();
    NSNumber *en = prefs[@"mfIAPEnabled"];
    if (en && ![en boolValue]) return NO;
    NSArray *wl = prefs[@"mfIAPAppList"];
    if (![wl isKindOfClass:[NSArray class]]) return NO;
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    if (wl.count == 0) return NO;
    return [wl containsObject:bid];
}
void mfSetPrefs(NSDictionary *d) {
    [d writeToFile:@"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist" atomically:YES];
}
BOOL mfPrefBool(NSString *key, BOOL def) {
    id v = mfPrefsDict()[key];
    return v ? [v boolValue] : def;
}
void mfSetBoolPref(NSString *key, BOOL val) {
    NSMutableDictionary *d = [mfPrefsDict() mutableCopy];
    d[key] = @(val);
    mfSetPrefs(d);
}
void mfSetPrefDouble(NSString *key, double val) {
    NSMutableDictionary *d = [mfPrefsDict() mutableCopy];
    d[key] = @(val);
    mfSetPrefs(d);
}
double mfPrefDouble(NSString *key, double def) {
    id v = mfPrefsDict()[key];
    return v ? [v doubleValue] : def;
}

// ====== 网络捕获状态（MFNetworkCapture.m 里的全局变量，用 extern 或直接声明） ======
extern BOOL g_captureEnabled;
extern BOOL g_rewriteEnabled;
extern NSMutableArray *g_rewriteRules;
extern void mfLoadRules(void);
extern void mfSaveRules(void);
extern void mfAddRule(NSString *pattern, NSString *matchType, NSString *action);

// ====== 页面导航 ======
UIView *mfMakePage(NSString *title, BOOL showBack) {
    // 子页统一拉长卡片（主页不经过这里）
    if (g_mfPanelOverlay) {
        CGFloat maxH = MIN(560, g_mfPanelOverlay.bounds.size.height - 100);
        if (g_mfCardH < maxH) mfSetCardHeight(maxH);
    }
    UIView *page = [[UIView alloc] initWithFrame:CGRectMake(0, 0, g_mfCardW, g_mfCardH)];
    page.backgroundColor = [UIColor clearColor];
    UIView *nav = [[UIView alloc] initWithFrame:CGRectMake(0, 0, g_mfCardW, 40)];
    [page addSubview:nav];
    if (showBack) {
        UIButton *back = [UIButton buttonWithType:UIButtonTypeSystem];
        back.frame = CGRectMake(6, 4, 64, 32);
        [back setTitle:@"‹ 返回" forState:UIControlStateNormal];
        back.titleLabel.font = [UIFont systemFontOfSize:15];
        [back addTarget:g_mfCtrl action:NSSelectorFromString(@"mfPopPage") forControlEvents:UIControlEventTouchUpInside];
        [nav addSubview:back];
    }
    UILabel *t = [[UILabel alloc] initWithFrame:CGRectMake(60, 6, g_mfCardW - 120, 28)];
    t.text = title;
    t.font = [UIFont boldSystemFontOfSize:16];
    t.textAlignment = NSTextAlignmentCenter;
    t.textColor = [UIColor labelColor];
    [nav addSubview:t];
    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    close.frame = CGRectMake(g_mfCardW - 40, 4, 32, 32);
    [close setTitle:@"✕" forState:UIControlStateNormal];
    [close addTarget:g_mfCtrl action:NSSelectorFromString(@"mfClosePanel") forControlEvents:UIControlEventTouchUpInside];
    [nav addSubview:close];
    return page;
}

// 动态调整卡片高度（子页拉长 / 主页恢复紧凑）
void mfSetCardHeight(CGFloat h) {
    if (!g_mfCardView || !g_mfPanelOverlay) return;
    CGRect sb = g_mfPanelOverlay.bounds;
    CGRect f = g_mfCardView.frame;
    f.size.height = h;
    f.origin.y = (sb.size.height - h) / 2;
    g_mfCardView.frame = f;
    g_mfCardH = h;
    g_mfCardContentView.frame = CGRectMake(0, 0, f.size.width, h);
    mfLog(@"card height -> %.0f", h);
}

void mfPushPage(UIView *page) {
    if (!g_mfPages) g_mfPages = [[NSMutableArray alloc] init];
    // 隐藏主页和所有已存在子页
    if (g_mfHomePage) g_mfHomePage.hidden = YES;
    for (UIView *p in g_mfPages) p.hidden = YES;
    // 子页自动拉长卡片（最高 560 或屏高-100）
    if (g_mfPanelOverlay) {
        CGFloat maxH = MIN(560, g_mfPanelOverlay.bounds.size.height - 100);
        if (g_mfCardH < maxH) mfSetCardHeight(maxH);
    }
    page.frame = CGRectMake(0, 0, g_mfCardW, g_mfCardH);
    UIView *container = g_mfCardContentView ?: g_mfPanelOverlay;
    [container addSubview:page];
    [g_mfPages addObject:page];
}

void mfPopPage(void) {
    if (g_mfPages.count == 0) return;
    UIView *top = [g_mfPages lastObject];
    [top removeFromSuperview];
    [g_mfPages removeLastObject];
    if (g_mfPages.count > 0) {
        [[g_mfPages lastObject] setHidden:NO];
        // 子页还在——保持拉长
    } else if (g_mfHomePage) {
        g_mfHomePage.hidden = NO;
        // 回主页——恢复紧凑高度
        if (g_mfHomeCardH > 0) mfSetCardHeight(g_mfHomeCardH);
        if (g_mfHomePage) g_mfHomePage.frame = g_mfCardContentView.bounds;
    }
}

void mfClosePanel(void) {
    if (g_mfPanelOverlay) {
        UIView *ov = g_mfPanelOverlay;
        [UIView animateWithDuration:0.2 animations:^{ ov.alpha = 0; } completion:^(BOOL f) {
            [ov removeFromSuperview];
            g_mfPanelOverlay = nil;
            g_mfPanelRootVC = nil;
            g_mfCardContentView = nil;
            g_mfHomePage = nil;
            g_mfCardView = nil;
            [g_mfPages removeAllObjects];
            mfLog(@"panel: closed");
        }];
    }
}

// ====== 网格按钮工具 ======
CGFloat mfGridButton(UIView *card, CGFloat x, CGFloat y, CGFloat w, NSString *title, NSString *emoji, SEL action, BOOL switchMode, NSString *pfx) {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = CGRectMake(x, y, w, 84);
    b.backgroundColor = [UIColor secondarySystemBackgroundColor];
    b.layer.cornerRadius = 16;
    [b addTarget:g_mfCtrl action:action forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:b];
    UILabel *ic = [[UILabel alloc] initWithFrame:CGRectMake(0, 10, w, 44)];
    ic.text = emoji;
    ic.font = [UIFont systemFontOfSize:24];
    ic.textAlignment = NSTextAlignmentCenter;
    ic.userInteractionEnabled = NO;
    [b addSubview:ic];
    UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(0, 58, w, 18)];
    lb.text = title;
    lb.font = [UIFont systemFontOfSize:12];
    lb.textAlignment = NSTextAlignmentCenter;
    lb.textColor = [UIColor labelColor];
    lb.adjustsFontSizeToFitWidth = YES;
    lb.minimumScaleFactor = 0.7;
    lb.userInteractionEnabled = NO;
    [b addSubview:lb];
    if (switchMode && pfx) {
        BOOL on = mfPrefBool(pfx, NO);
        b.backgroundColor = on ? [UIColor systemGreenColor] : [UIColor secondarySystemBackgroundColor];
        objc_setAssociatedObject(b, "pfx", pfx, OBJC_ASSOCIATION_RETAIN);
    }
    return y + 92;
}

// ====== 功能页面入口（转发到各模块） ======
// 页面函数（各模块 .m 定义——extern 到 MFPanel.h）
void mfShowDataAnalysisPage(void);  // MFNetworkCapture.m
void mfShowNetworkCapturePage(void); // MFNetworkCapture.m
void mfShowCryptoToolboxPage(void);  // MFNetworkCapture.m
void mfShowNetworkModifyPage(void);  // MFNetworkCapture.m

// ====== IAPHunter 功能（从 v4.1 迁移） ======
// 远程查 IAP 列表
static void mfFetchIAPList(void (^cb)(NSArray *items, NSString *err)) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (!bid) { cb(nil, @"无 bundle id"); return; }
    NSString *url = [NSString stringWithFormat:@"https://xn--ug8h.eu.org/api/iap?bundleId=%@&country=us", bid];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url] cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:12];
    [req setValue:@"IAPHunter/1.1" forHTTPHeaderField:@"User-Agent"];
    [req setValue:@"https://xn--ug8h.eu.org" forHTTPHeaderField:@"Origin"];
    [req setValue:@"https://xn--ug8h.eu.org" forHTTPHeaderField:@"Referer"];
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (err) { cb(nil, err.localizedDescription); return; }
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if (![json isKindOfClass:[NSDictionary class]]) { cb(nil, @"响应格式错误"); return; }
        NSArray *iaps = json[@"iaps"];
        if (![iaps isKindOfClass:[NSArray class]]) { cb(nil, @"无 IAP 数据"); return; }
        NSMutableArray *items = [NSMutableArray array];
        for (NSDictionary *iap in iaps) {
            if (![iap isKindOfClass:[NSDictionary class]]) continue;
            NSString *pid = iap[@"productId"];
            if (pid.length == 0) continue;
            NSString *price = iap[@"priceFormatted"];
            [items addObject:[NSDictionary dictionaryWithObjectsAndKeys:
                pid, @"pid", (price.length ? price : @"?"), @"price", nil]];
        }
        cb(items, nil);
    }];
    [task resume];
}

// ====== 本地二进制扫描 ======
// 前向声明
static NSSet *mfScanFileForPIDs(NSString *path);
static void mfQueryLocalPrices(NSArray *pids, void (^cb)(NSDictionary *pidToPrice));

// 从 Mach-O 的 __cstring 段提取 product ID（只匹配 bundleId. 前缀）
static NSArray *mfScanLocalProductIDs(void) {
    NSMutableSet *found = [NSMutableSet set];
    NSString *exePath = [[NSBundle mainBundle] executablePath];
    if (exePath) [found unionSet:mfScanFileForPIDs(exePath)];
    NSString *fwDir = [[NSBundle mainBundle] privateFrameworksPath];
    if (fwDir) {
        for (NSString *fw in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:fwDir error:nil]) {
            if ([fw hasSuffix:@".framework"]) {
                NSString *name = [fw stringByDeletingPathExtension];
                NSString *fwBin = [fwDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/%@", fw, name]];
                [found unionSet:mfScanFileForPIDs(fwBin)];
            }
        }
    }
    NSString *pluginDir = [[NSBundle mainBundle] builtInPlugInsPath];
    if (pluginDir) {
        for (NSString *ext in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:pluginDir error:nil]) {
            if ([ext hasSuffix:@".appex"]) {
                NSString *extExe = [pluginDir stringByAppendingPathComponent:
                    [NSString stringWithFormat:@"%@/%@", ext, [ext stringByDeletingPathExtension]]];
                [found unionSet:mfScanFileForPIDs(extExe)];
            }
        }
    }
    return [[found allObjects] sortedArrayUsingSelector:@selector(compare:)];
}

// 扫描单个文件：提取所有 com.xxx.xxx.xxx 格式的字符串（3段以上点分）
// 后续由 SKProductsRequest 验证哪些是真正的 product ID
static NSSet *mfScanFileForPIDs(NSString *path) {
    NSMutableSet *pids = [NSMutableSet set];
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
    if (!data.length) return pids;
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSUInteger len = data.length;
    NSMutableString *current = [NSMutableString string];
    for (NSUInteger i = 0; i < len; i++) {
        uint8_t c = bytes[i];
        if (c >= 0x20 && c < 0x7F) {
            [current appendFormat:@"%c", c];
        } else {
            if (current.length >= 10 && [current hasPrefix:@"com."]) {
                // 至少3段（com.xxx.xxx），排除系统框架标识符
                NSInteger dots = 0;
                for (NSUInteger j = 0; j < current.length; j++) {
                    if ([current characterAtIndex:j] == '.') dots++;
                }
                if (dots >= 2) {
                    NSString *s = [current copy];
                    // 排除已知系统前缀
                    if ([s hasPrefix:@"com.apple."] ||
                        [s hasPrefix:@"com.facebook.sdk."] ||
                        [s hasPrefix:@"com.google."] ||
                        [s hasPrefix:@"com.adjust."] ||
                        [s hasPrefix:@"com.appsflyer."] ||
                        [s hasPrefix:@"com.branch."]) {
                        // skip
                    } else {
                        [pids addObject:s];
                    }
                }
            }
            [current setString:@""];
        }
    }
    if (current.length >= 10 && [current hasPrefix:@"com."]) {
        NSInteger dots = 0;
        for (NSUInteger j = 0; j < current.length; j++) {
            if ([current characterAtIndex:j] == '.') dots++;
        }
        if (dots >= 2) {
            NSString *s = [current copy];
            if (![s hasPrefix:@"com.apple."] && ![s hasPrefix:@"com.facebook.sdk."] &&
                ![s hasPrefix:@"com.google."] && ![s hasPrefix:@"com.adjust."] &&
                ![s hasPrefix:@"com.appsflyer."] && ![s hasPrefix:@"com.branch."]) {
                [pids addObject:s];
            }
        }
    }
    return pids;
}

// SKProductsRequest 查询本地 PID 的价格
@interface MFProductReqDelegate : NSObject <SKProductsRequestDelegate>
@property (nonatomic, copy) void (^cb)(NSDictionary *);
@end
@implementation MFProductReqDelegate
- (void)productsRequest:(SKProductsRequest *)request didReceiveResponse:(SKProductsResponse *)response {
    NSMutableDictionary *map = [NSMutableDictionary dictionary];
    for (SKProduct *p in response.products) {
        NSNumberFormatter *fmt = [[NSNumberFormatter alloc] init];
        fmt.numberStyle = NSNumberFormatterCurrencyStyle;
        fmt.locale = p.priceLocale;
        NSString *priceStr = [fmt stringFromNumber:p.price];
        if (priceStr.length) map[p.productIdentifier] = priceStr;
    }
    if (self.cb) self.cb([map copy]);
}
- (void)request:(SKRequest *)request didFailWithError:(NSError *)error {
    if (self.cb) self.cb(@{});
}
@end
static void mfQueryLocalPrices(NSArray *pids, void (^cb)(NSDictionary *pidToPrice)) {
    if (pids.count == 0) { cb(@{}); return; }
    SKProductsRequest *req = [[SKProductsRequest alloc] initWithProductIdentifiers:[NSSet setWithArray:pids]];
    MFProductReqDelegate *delegate = [[MFProductReqDelegate alloc] init];
    __block BOOL done = NO;
    delegate.cb = ^(NSDictionary *map) {
        if (!done) { done = YES; cb(map); }
    };
    req.delegate = delegate;
    // 防 ARC 释放 delegate
    objc_setAssociatedObject(req, "delegate", delegate, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [req start];
    // 超时保护（8秒）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        if (!done) { done = YES; cb(@{}); }
    });
}

// IAP 记录
static void IAPRecord(NSString *pid) {
    if (pid.length == 0) return;
    @autoreleasepool {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSMutableArray *list = [NSMutableArray arrayWithArray:([d objectForKey:@"SavedIAPIDs"] ?: @[])];
        if (![list containsObject:pid]) { [list addObject:pid]; [d setObject:list forKey:@"SavedIAPIDs"]; [d synchronize]; }
    }
}

// 解析价格字符串为数字（支持 ¥6.00, $0.99, €1,99, 0, 免费 等格式）
static double mfParsePrice(NSString *priceStr) {
    if (!priceStr.length || [priceStr isEqualToString:@"?"] || [priceStr isEqualToString:@"未上架"]) return 99999;
    if ([priceStr containsString:@"免费"] || [priceStr containsString:@"Free"]) return 0;
    // 提取数字部分（保留小数点，处理逗号作为小数点）
    NSMutableString *num = [NSMutableString string];
    BOOL hasDot = NO;
    for (NSUInteger i = 0; i < priceStr.length; i++) {
        unichar c = [priceStr characterAtIndex:i];
        if (c >= '0' && c <= '9') {
            [num appendFormat:@"%C", c];
        } else if ((c == '.' || c == ',') && !hasDot) {
            // 取最后一个数字分隔符作为小数点
            if (num.length > 0) {
                // 检查后面是否有数字
                BOOL digitAfter = NO;
                for (NSUInteger j = i + 1; j < priceStr.length; j++) {
                    unichar nc = [priceStr characterAtIndex:j];
                    if (nc >= '0' && nc <= '9') { digitAfter = YES; break; }
                    if (nc != ' ') break;
                }
                if (digitAfter) {
                    hasDot = YES;
                    [num appendString:@"."];
                }
            }
        }
    }
    return num.length > 0 ? [num doubleValue] : 99999;
}

// 扫描购买页（本地扫描 + SKProductsRequest 验证 + 在线查询，去重合并，按价格排序）
void mfShowScanPage(void) {
    UIView *page = mfMakePage(@"扫描购买", YES);
    UILabel *st = [[UILabel alloc] initWithFrame:CGRectMake(16, g_mfCardH/2 - 20, g_mfCardW - 32, 40)];
    st.text = @"正在扫描…";
    st.textAlignment = NSTextAlignmentCenter;
    st.font = [UIFont systemFontOfSize:14];
    st.textColor = [UIColor secondaryLabelColor];
    [page addSubview:st];
    mfPushPage(page);

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // 1. 本地扫描：提取所有 com.xxx.xxx 格式字符串
        NSArray *localCandidates = mfScanLocalProductIDs();
        mfLog(@"scan local candidates: %d", (int)localCandidates.count);

        // 2. 在线查询
        mfFetchIAPList(^(NSArray *onlineItems, NSString *err) {
            NSMutableDictionary *onlineMap = [NSMutableDictionary dictionary]; // pid -> price
            for (NSDictionary *item in onlineItems) {
                if (item[@"pid"]) onlineMap[item[@"pid"]] = item[@"price"] ?: @"?";
            }

            // 3. 本地候选中排除在线已有的，剩下的用 SKProductsRequest 验证
            NSMutableArray *toVerify = [NSMutableArray array];
            for (NSString *pid in localCandidates) {
                if (!onlineMap[pid]) [toVerify addObject:pid];
            }

            mfQueryLocalPrices(toVerify, ^(NSDictionary *verifiedPrices) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [st removeFromSuperview];

                    // 4. 合并：在线结果 + SKProductsRequest 验证通过的本地结果
                    NSMutableArray *merged = [NSMutableArray array];
                    for (NSDictionary *item in onlineItems) {
                        [merged addObject:@{@"pid": item[@"pid"], @"price": item[@"price"] ?: @"?", @"src": @"在线"}];
                    }
                    // verifiedPrices 里的是 Apple 确认可购买的 PID
                    for (NSString *pid in verifiedPrices) {
                        [merged addObject:@{@"pid": pid, @"price": verifiedPrices[pid], @"src": @"本地"}];
                    }

                    // 按价格从低到高排序
                    [merged sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
                        double pa = mfParsePrice(a[@"price"]);
                        double pb = mfParsePrice(b[@"price"]);
                        if (pa < pb) return NSOrderedAscending;
                        if (pa > pb) return NSOrderedDescending;
                        return NSOrderedSame;
                    }];

                    if (merged.count == 0) {
                        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 100, g_mfCardW - 32, 40)];
                        e.text = @"未找到 IAP 产品"; e.textAlignment = NSTextAlignmentCenter;
                        e.textColor = [UIColor secondaryLabelColor]; [page addSubview:e]; return;
                    }

                    UILabel *countLb = [[UILabel alloc] initWithFrame:CGRectMake(16, 46, g_mfCardW - 32, 20)];
                    countLb.text = [NSString stringWithFormat:@"在线 %lu  本地验证 %lu（共 %d）",
                        (unsigned long)onlineItems.count, (unsigned long)verifiedPrices.count, (int)merged.count];
                    countLb.font = [UIFont systemFontOfSize:11];
                    countLb.textColor = [UIColor tertiaryLabelColor];
                    [page addSubview:countLb];

                    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 70, g_mfCardW, g_mfCardH - 70)];
                    CGFloat y = 8;
                    for (NSDictionary *item in merged) {
                        UIButton *row = [UIButton buttonWithType:UIButtonTypeSystem];
                        row.frame = CGRectMake(12, y, g_mfCardW - 24, 46);
                        BOOL isLocal = [item[@"src"] isEqualToString:@"本地"];
                        row.backgroundColor = isLocal ?
                            [UIColor tertiarySystemBackgroundColor] :
                            [UIColor secondarySystemBackgroundColor];
                        row.layer.cornerRadius = 12;
                        [row setTitle:[NSString stringWithFormat:@"%@    %@", item[@"pid"], item[@"price"]] forState:UIControlStateNormal];
                        row.titleLabel.font = [UIFont systemFontOfSize:13];
                        row.titleLabel.lineBreakMode = NSLineBreakByTruncatingMiddle;
                        [row setContentHorizontalAlignment:UIControlContentHorizontalAlignmentLeft];
                        [row setTitleEdgeInsets:UIEdgeInsetsMake(0, 14, 0, 14)];
                        objc_setAssociatedObject(row, "pid", item[@"pid"], OBJC_ASSOCIATION_RETAIN);
                        [row addTarget:g_mfCtrl action:NSSelectorFromString(@"mfBuyProduct:") forControlEvents:UIControlEventTouchUpInside];
                        [sv addSubview:row];
                        y += 52;
                    }
                    sv.contentSize = CGSizeMake(g_mfCardW, y + 16);
                    [page addSubview:sv];
                    mfLog(@"scan merged: online=%lu localVerified=%lu total=%d",
                        (unsigned long)onlineItems.count, (unsigned long)verifiedPrices.count, (int)merged.count);
                });
            });
        });
    });
}

// 手动购买页
void mfShowManualBuyPage(void) {
    UIView *page = mfMakePage(@"手动购买", YES);
    UITextField *tf = [[UITextField alloc] initWithFrame:CGRectMake(16, 56, g_mfCardW - 32, 42)];
    tf.borderStyle = UITextBorderStyleRoundedRect;
    tf.placeholder = @"输入产品 ID";
    tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
    tf.font = [UIFont systemFontOfSize:13];
    [page addSubview:tf];
    objc_setAssociatedObject(page, "tf", tf, OBJC_ASSOCIATION_RETAIN);
    UIButton *buy = [UIButton buttonWithType:UIButtonTypeSystem];
    buy.frame = CGRectMake(16, 110, g_mfCardW - 32, 44);
    buy.backgroundColor = [UIColor systemBlueColor];
    buy.layer.cornerRadius = 12;
    [buy setTitle:@"购买" forState:UIControlStateNormal];
    [buy setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [buy addTarget:g_mfCtrl action:NSSelectorFromString(@"mfDoManualBuy") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:buy];
    UILabel *res = [[UILabel alloc] initWithFrame:CGRectMake(16, 164, g_mfCardW - 32, 60)];
    res.numberOfLines = 0; res.font = [UIFont systemFontOfSize:13];
    res.textColor = [UIColor labelColor]; res.textAlignment = NSTextAlignmentCenter;
    [page addSubview:res];
    objc_setAssociatedObject(page, "res", res, OBJC_ASSOCIATION_RETAIN);
    mfPushPage(page);
}

// 图标解锁页
void mfShowIconPage(void) {
    UIView *page = mfMakePage(@"图标解锁", YES);
    NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
    NSDictionary *alt = info[@"CFBundleIcons"][@"CFBundleAlternateIcons"];
    NSArray *names = [alt allKeys];
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, g_mfCardH - 42)];
    if (names.count == 0) {
        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 60, g_mfCardW - 32, 40)];
        e.text = @"此 app 没有备用图标"; e.textAlignment = NSTextAlignmentCenter;
        e.textColor = [UIColor secondaryLabelColor]; [page addSubview:e];
    } else {
        CGFloat gw = (g_mfCardW - 32 - 12) / 2;
        CGFloat y = 8;
        for (NSUInteger i = 0; i < names.count; i++) {
            CGFloat x = (i % 2 == 0) ? 16 : 16 + gw + 12;
            if (i > 0 && i % 2 == 0) y += 62;
            UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
            b.frame = CGRectMake(x, y, gw, 56);
            b.backgroundColor = [UIColor secondarySystemBackgroundColor];
            b.layer.cornerRadius = 12;
            [b setTitle:names[i] forState:UIControlStateNormal];
            b.titleLabel.font = [UIFont systemFontOfSize:13];
            objc_setAssociatedObject(b, "icon", names[i], OBJC_ASSOCIATION_RETAIN);
            [b addTarget:g_mfCtrl action:NSSelectorFromString(@"mfIconTap:") forControlEvents:UIControlEventTouchUpInside];
            [sv addSubview:b];
        }
        sv.contentSize = CGSizeMake(g_mfCardW, y + 70);
        [page addSubview:sv];
    }
    mfPushPage(page);
}

// Product 子页
void mfShowProductPage(void) {
    UIView *page = mfMakePage(@"Product", YES);
    CGFloat gw = (g_mfCardW - 32 - 12) / 2;
    CGFloat gy = 48;
    gy = mfGridButton(page, 16, gy, gw, @"扫描购买", @"🔍", @selector(mfShowScanPage), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"手动购买", @"⌨️", @selector(mfShowManualBuyPage), NO, nil);
    gy = mfGridButton(page, 16, gy, gw, @"图标解锁", @"🎨", @selector(mfShowIconPage), NO, nil);
    mfPushPage(page);
}

// ====== FakeGPS（v4.1 迁移） ======
static double iaphFakeLat(void) { id v = mfPrefsDict()[@"iaphFakeLat"]; return v ? [v doubleValue] : 39.9042; }
static double iaphFakeLon(void) { id v = mfPrefsDict()[@"iaphFakeLon"]; return v ? [v doubleValue] : 116.4074; }
static double g_mfSelLat = 0, g_mfSelLon = 0;

void mfShowGpsPage(void) {
    dlopen("/System/Library/Frameworks/MapKit.framework/MapKit", RTLD_LAZY | RTLD_GLOBAL);
    dlopen("/System/Library/Frameworks/CoreLocation.framework/CoreLocation", RTLD_LAZY | RTLD_GLOBAL);
    UIView *page = mfMakePage(@"Fake GPS", YES);
    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(16, 48, 60, 31)];
    sw.on = mfPrefBool(@"iaphFakeGPS", NO);
    [sw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfGpsSwitch:") forControlEvents:UIControlEventValueChanged];
    [page addSubview:sw];
    UILabel *swLb = [[UILabel alloc] initWithFrame:CGRectMake(84, 52, 160, 24)];
    swLb.text = @"启用模拟定位"; swLb.font = [UIFont systemFontOfSize:14];
    [page addSubview:swLb];
    Class MKCls = objc_getClass("MKMapView");
    if (!MKCls) {
        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 100, g_mfCardW - 32, 40)];
        e.text = @"MapKit 不可用"; e.textColor = [UIColor secondaryLabelColor];
        [page addSubview:e]; mfPushPage(page); return;
    }
    id map = [[MKCls alloc] initWithFrame:CGRectMake(12, 86, g_mfCardW - 24, 200)];
    ((UIView *)map).layer.cornerRadius = 14;
    ((UIView *)map).clipsToBounds = YES;
    typedef struct { double lat, lon; } CLLoc;
    typedef struct { CLLoc center; struct { double latD, lonD; } span; } MKReg;
    MKReg reg; reg.center.lat = iaphFakeLat(); reg.center.lon = iaphFakeLon();
    reg.span.latD = 0.05; reg.span.lonD = 0.05;
    ((void(*)(id, SEL, MKReg, BOOL))objc_msgSend)(map, NSSelectorFromString(@"setRegion:animated:"), reg, NO);
    UILongPressGestureRecognizer *lp = [[UILongPressGestureRecognizer alloc] initWithTarget:g_mfCtrl action:NSSelectorFromString(@"mfMapLongPress:")];
    lp.minimumPressDuration = 0.5;
    [map addGestureRecognizer:lp];
    [page addSubview:map];
    UILabel *coord = [[UILabel alloc] initWithFrame:CGRectMake(16, 296, g_mfCardW - 32, 36)];
    coord.text = [NSString stringWithFormat:@"当前: %.4f, %.4f（长按地图选点）", iaphFakeLat(), iaphFakeLon()];
    coord.font = [UIFont systemFontOfSize:12]; coord.textColor = [UIColor secondaryLabelColor];
    coord.numberOfLines = 0; coord.textAlignment = NSTextAlignmentCenter;
    [page addSubview:coord];
    objc_setAssociatedObject(page, "coord", coord, OBJC_ASSOCIATION_RETAIN);
    UIButton *ok = [UIButton buttonWithType:UIButtonTypeSystem];
    ok.frame = CGRectMake(16, 338, g_mfCardW - 32, 44);
    ok.backgroundColor = [UIColor systemBlueColor];
    ok.layer.cornerRadius = 12;
    [ok setTitle:@"确认模拟此坐标" forState:UIControlStateNormal];
    [ok setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [ok addTarget:g_mfCtrl action:NSSelectorFromString(@"mfConfirmCoord") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:ok];
    mfPushPage(page);
}

// ====== FakeGPS hook（ctor 注册） ======
static IMP orig_clLocation, orig_startUpdating;
static id makeFakeLocation(void) {
    Class locCls = objc_getClass("CLLocation");
    if (!locCls) return nil;
    id loc = [locCls alloc];
    SEL initSel = NSSelectorFromString(@"initWithLatitude:longitude:");
    return ((id(*)(id, SEL, double, double))objc_msgSend)(loc, initSel, iaphFakeLat(), iaphFakeLon());
}
static id new_clLocation(id self, SEL _cmd) {
    if (mfPrefBool(@"iaphFakeGPS", NO)) return makeFakeLocation();
    return orig_clLocation ? ((id(*)(id, SEL))orig_clLocation)(self, _cmd) : nil;
}
static void new_startUpdating(id self, SEL _cmd) {
    if (mfPrefBool(@"iaphFakeGPS", NO)) {
        id delegate = [self performSelector:NSSelectorFromString(@"delegate")];
        SEL upd = NSSelectorFromString(@"locationManager:didUpdateLocations:");
        if (delegate && [delegate respondsToSelector:upd]) {
            id fake = makeFakeLocation();
            ((void(*)(id, SEL, id, id))objc_msgSend)(delegate, upd, self, @[fake]);
            return;
        }
    }
    if (orig_startUpdating) ((void(*)(id, SEL))orig_startUpdating)(self, _cmd);
}
static void hookFakeGPS(void) {
    Class cls = objc_getClass("CLLocationManager");
    if (!cls) return;
    Method m;
    if ((m = class_getInstanceMethod(cls, @selector(location)))) { orig_clLocation = method_getImplementation(m); method_setImplementation(m, (IMP)new_clLocation); }
    if ((m = class_getInstanceMethod(cls, @selector(startUpdatingLocation)))) { orig_startUpdating = method_getImplementation(m); method_setImplementation(m, (IMP)new_startUpdating); }
    mfLog(@"hookFakeGPS: installed");
}

// 屏蔽摇一摇
static IMP orig_motionEnded;
static void new_motionEnded(id self, SEL _cmd, int motion, id event) {
    if (mfPrefBool(@"iaphShakeBlock", NO)) return;
    if (orig_motionEnded) ((void(*)(id, SEL, int, id))orig_motionEnded)(self, _cmd, motion, event);
}
static void hookShakeBlock(void) {
    Class cls = objc_getClass("UIResponder");
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, NSSelectorFromString(@"motionEnded:withEvent:"));
    if (m) { orig_motionEnded = method_getImplementation(m); method_setImplementation(m, (IMP)new_motionEnded); mfLog(@"hookShakeBlock: installed"); }
}

// ====== MFPanelCtrl（所有 action 方法） ======
@interface MFPanelCtrl : NSObject @end
@implementation MFPanelCtrl
- (void)mfPopPage { mfPopPage(); }
- (void)mfClosePanel { mfClosePanel(); }

// 页面入口
- (void)mfShowDataAnalysisPage { mfShowDataAnalysisPage(); }
- (void)mfShowNetworkCapturePage { mfShowNetworkCapturePage(); }
- (void)mfShowCryptoPage { mfShowCryptoToolboxPage(); }
- (void)mfShowNetworkModifyPage { mfShowNetworkModifyPage(); }
- (void)mfShowFlexPage { }  // FLEX 已砍——保留空方法防止 KVO/archive 崩
- (void)mfShowProductPage { mfShowProductPage(); }
- (void)mfShowScanPage { mfShowScanPage(); }
- (void)mfShowManualBuyPage { mfShowManualBuyPage(); }
- (void)mfShowIconPage { mfShowIconPage(); }
- (void)mfShowGpsPage { mfShowGpsPage(); }

// 捕获详情
- (void)mfShowCaptureDetail:(UITapGestureRecognizer *)g {
    MFNetRecord *rec = objc_getAssociatedObject(g, "rec");
    mfShowCaptureDetailPage(rec);
}
- (void)mfCopyRecord:(UIButton *)btn {
    MFNetRecord *rec = objc_getAssociatedObject(btn, "rec");
    if (!rec) return;
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"%@ %ld %@\n", rec.method ?: @"?", (long)rec.status, rec.url ?: @"?"];
    [s appendString:@"\n--- 请求 Headers ---\n"];
    for (NSString *k in rec.reqHeaders) [s appendFormat:@"%@: %@\n", k, rec.reqHeaders[k]];
    if (rec.reqBody.length) {
        [s appendString:@"\n--- 请求 Body ---\n"];
        [s appendString:[[NSString alloc] initWithData:rec.reqBody encoding:NSUTF8StringEncoding] ?: @""];
    }
    [s appendString:@"\n--- 响应 Headers ---\n"];
    for (NSString *k in rec.respHeaders) [s appendFormat:@"%@: %@\n", k, rec.respHeaders[k]];
    if (rec.respBody.length) {
        [s appendString:@"\n--- 响应 Body ---\n"];
        [s appendString:[[NSString alloc] initWithData:rec.respBody encoding:NSUTF8StringEncoding] ?: @""];
    }
    [UIPasteboard generalPasteboard].string = s;
    mfLog(@"copied %lu chars to pasteboard", (unsigned long)s.length);
    // 视觉反馈
    [UIView animateWithDuration:0.15 animations:^{ btn.alpha = 0.3; } completion:^(BOOL f){ btn.alpha = 1; }];
}

// 详情页"改响应"→ 用当前记录 URL 预填规则编辑页
- (void)mfModifyResponse:(UIButton *)btn {
    MFNetRecord *rec = objc_getAssociatedObject(btn, "rec");
    if (!rec) return;
    // 预填：scheme://host（包含匹配该域名所有请求）
    NSString *pattern = rec.url ?: @"";
    NSURL *u = [NSURL URLWithString:pattern];
    if (u.host.length > 0) {
        pattern = [NSString stringWithFormat:@"%@://%@", u.scheme ?: @"https", u.host];
    }
    mfShowRuleEditPage(pattern, @"replaceResp", -1, NO);
}

// 网格开关
- (void)mfGridSwitchChanged:(UIButton *)b {
    NSString *key = objc_getAssociatedObject(b, "pfx");
    if (!key) return;
    BOOL on = !mfPrefBool(key, NO);
    mfSetBoolPref(key, on);
    b.backgroundColor = on ? [UIColor systemGreenColor] : [UIColor secondarySystemBackgroundColor];
    mfLog(@"switch %@ -> %d", key, on);
}

// 网络捕获开关
- (void)mfCaptureSwitchChanged:(UISwitch *)sw {
    g_captureEnabled = sw.on;
    if (sw.on) {
        // 开启时注册 NSURLProtocol（延迟注册——不影响未开启的 app）
        extern void mfInstallNetworkCapture(void);
        mfInstallNetworkCapture();
        mfLog(@"capture ON — NSURLProtocol registered");
    }
    mfLog(@"capture -> %d", sw.on);
}

// 拦截修改开关
- (void)mfRewriteSwitchChanged:(UISwitch *)sw {
    g_rewriteEnabled = sw.on;
    mfLog(@"rewrite -> %d", sw.on);
}

// 规则行开关
- (void)mfRuleSwitchChanged:(UISwitch *)sw {
    NSInteger idx = [objc_getAssociatedObject(sw, "idx") integerValue];
    if (idx >= 0 && idx < (NSInteger)g_rewriteRules.count) {
        ((MFRewriteRule *)g_rewriteRules[idx]).enabled = sw.on;
        mfSaveRule(g_rewriteRules[idx], idx);
        mfLog(@"rule %ld enabled -> %d", (long)idx, sw.on);
    }
}

// 编辑规则
- (void)mfEditRuleTapped:(UIButton *)btn {
    NSInteger idx = [objc_getAssociatedObject(btn, "idx") integerValue];
    if (idx >= 0 && idx < (NSInteger)g_rewriteRules.count) {
        mfShowRuleEditPage(nil, nil, idx, YES);
    }
}

// 删除规则（带确认）
- (void)mfDeleteRuleTapped:(UIButton *)btn {
    NSInteger idx = [objc_getAssociatedObject(btn, "idx") integerValue];
    if (idx < 0 || idx >= (NSInteger)g_rewriteRules.count) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"删除规则"
        message:[NSString stringWithFormat:@"确定删除这条规则？\n%@", ((MFRewriteRule *)g_rewriteRules[idx]).pattern]
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"删除" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
        mfRemoveRule(idx);
        mfPopPage(); mfShowNetworkModifyPage();
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    UIViewController *vc = g_mfPanelRootVC;
    if (vc) [vc presentViewController:alert animated:YES completion:nil];
}

// 保存规则（编辑页）
- (void)mfSaveRuleTapped:(UIButton *)btn {
    UISegmentedControl *matchSeg = objc_getAssociatedObject(btn, "seg");
    UISegmentedControl *actSeg = objc_getAssociatedObject(btn, "seg2");
    UITextField *patField = objc_getAssociatedObject(btn, "f1");
    UITextField *urlField = objc_getAssociatedObject(btn, "f2");
    UITextView *bodyView = objc_getAssociatedObject(btn, "tv");
    NSInteger index = [objc_getAssociatedObject(btn, "idx") integerValue];
    BOOL fromList = [objc_getAssociatedObject(btn, "fromList") boolValue];

    NSString *pattern = [patField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (pattern.length == 0) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"提示" message:@"请填写匹配的 URL" preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
        [g_mfPanelRootVC presentViewController:alert animated:YES completion:nil];
        return;
    }
    NSString *matchType = matchSeg.selectedSegmentIndex == 1 ? @"url" : (matchSeg.selectedSegmentIndex == 2 ? @"regex" : @"contain");
    NSString *action = actSeg.selectedSegmentIndex == 1 ? @"replaceReq" : (actSeg.selectedSegmentIndex == 2 ? @"block" : @"replaceResp");

    MFRewriteRule *r = [MFRewriteRule new];
    r.pattern = pattern;
    r.matchType = matchType;
    r.action = action;
    r.urlReplace = urlField.text ?: @"";
    r.bodyReplace = bodyView.text ?: @"";
    r.headerReplaces = @{};
    r.enabled = YES;
    if (index >= 0 && index < (NSInteger)g_rewriteRules.count) {
        r.appBundle = ((MFRewriteRule *)g_rewriteRules[index]).appBundle;
    } else {
        r.appBundle = mfCurrentBundleId();
    }
    mfSaveRule(r, index);
    // 保存后返回并刷新列表
    mfPopPage();               // 弹掉编辑页
    if (fromList) {
        mfPopPage();           // 弹掉列表页
        mfShowNetworkModifyPage();
    }
}

// 添加规则（列表页）——走完整编辑页
- (void)mfAddRuleTapped {
    mfShowRuleEditPage(nil, @"replaceResp", -1, YES);
}



// IAP 购买
- (void)mfBuyProduct:(UIButton *)b {
    NSString *pid = objc_getAssociatedObject(b, "pid");
    if (!pid) return;
    IAPRecord(pid);
    SKPayment *pay = [SKPayment paymentWithProductIdentifier:pid];
    [[SKPaymentQueue defaultQueue] addPayment:pay];
    b.backgroundColor = [UIColor systemGreenColor];
    mfLog(@"buy: %@", pid);
}
- (void)mfDoManualBuy {
    UIView *top = [g_mfPages lastObject];
    UITextField *tf = objc_getAssociatedObject(top, "tf");
    UILabel *res = objc_getAssociatedObject(top, "res");
    NSString *pid = [[tf text] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if (pid.length == 0) { res.text = @"请输入产品 ID"; return; }
    IAPRecord(pid);
    SKPayment *pay = [SKPayment paymentWithProductIdentifier:pid];
    [[SKPaymentQueue defaultQueue] addPayment:pay];
    res.text = [NSString stringWithFormat:@"已发起购买:\n%@", pid];
    res.textColor = [UIColor systemGreenColor];
    mfLog(@"manual buy: %@", pid);
}
- (void)mfIconTap:(UIButton *)b {
    NSString *nm = objc_getAssociatedObject(b, "icon");
    if (!nm) return;
    UIApplication *app = [UIApplication sharedApplication];
    if ([app respondsToSelector:@selector(setAlternateIconName:completionHandler:)]) {
        [app setAlternateIconName:nm completionHandler:^(NSError *e) {
            mfLog(@"icon %@ -> %@", nm, e ? e.localizedDescription : @"ok");
        }];
        b.backgroundColor = [UIColor systemGreenColor];
    }
}

// FakeGPS
- (void)mfGpsSwitch:(UISwitch *)sw { mfSetBoolPref(@"iaphFakeGPS", sw.on); mfLog(@"FakeGPS -> %d", sw.on); }
- (void)mfMapLongPress:(UILongPressGestureRecognizer *)g {
    if (g.state != UIGestureRecognizerStateBegan) return;
    UIView *map = g.view;
    typedef struct { double lat, lon; } CLLoc;
    CLLoc c = ((CLLoc(*)(id, SEL, CGPoint, id))objc_msgSend)(map, NSSelectorFromString(@"convertPoint:toCoordinateFromView:"), [g locationInView:map], map);
    g_mfSelLat = c.lat; g_mfSelLon = c.lon;
    Class annCls = objc_getClass("MKPointAnnotation");
    if (annCls) {
        id ann = [[annCls alloc] init];
        ((void(*)(id, SEL, CLLoc))objc_msgSend)(ann, NSSelectorFromString(@"setCoordinate:"), c);
        [map performSelector:NSSelectorFromString(@"removeAnnotations:") withObject:[map performSelector:NSSelectorFromString(@"annotations")]];
        [map performSelector:NSSelectorFromString(@"addAnnotation:") withObject:ann];
    }
    UIView *top = [g_mfPages lastObject];
    UILabel *cl = objc_getAssociatedObject(top, "coord");
    if (cl) cl.text = [NSString stringWithFormat:@"选中: %.4f, %.4f", c.lat, c.lon];
}
- (void)mfConfirmCoord {
    UIView *top = [g_mfPages lastObject];
    UILabel *cl = objc_getAssociatedObject(top, "coord");
    if (g_mfSelLat == 0 && g_mfSelLon == 0) {
        if (cl) { cl.text = @"请先长按地图选择坐标"; cl.textColor = [UIColor systemOrangeColor]; }
        return;
    }
    mfSetPrefDouble(@"iaphFakeLat", g_mfSelLat);
    mfSetPrefDouble(@"iaphFakeLon", g_mfSelLon);
    mfSetBoolPref(@"iaphFakeGPS", YES);
    if (cl) { cl.text = [NSString stringWithFormat:@"✅ 已启用: %.4f, %.4f", g_mfSelLat, g_mfSelLon]; cl.textColor = [UIColor systemGreenColor]; }
    mfLog(@"FakeGPS set: %.4f, %.4f", g_mfSelLat, g_mfSelLon);
}

// Crypto 工具箱
- (void)mfCryptoRun:(UIButton *)b {
    UIView *top = [g_mfPages lastObject];
    UITextView *input = objc_getAssociatedObject(top, "input");
    UITextField *key = objc_getAssociatedObject(top, "key");
    UITextField *iv = objc_getAssociatedObject(top, "iv");
    UISegmentedControl *algo = objc_getAssociatedObject(top, "algo");
    UITextView *output = objc_getAssociatedObject(top, "output");
    BOOL encrypt = [objc_getAssociatedObject(b, "mode") intValue] == 1;
    NSInteger sel = algo.selectedSegmentIndex;
    NSString *inputText = input.text;
    
    if (sel == 2) {  // Base64
        if (encrypt) {
            output.text = [[inputText dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
        } else {
            NSData *d = [[NSData alloc] initWithBase64EncodedString:inputText options:0];
            output.text = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] ?: d.description;
        }
        return;
    }
    if (sel == 3) {  // Hex
        if (encrypt) {
            NSData *d = [inputText dataUsingEncoding:NSUTF8StringEncoding];
            NSMutableString *hex = [NSMutableString string];
            const Byte *bytes = d.bytes;
            for (NSUInteger i = 0; i < d.length; i++) [hex appendFormat:@"%02x", bytes[i]];
            output.text = hex;
        } else {
            NSMutableData *d = [NSMutableData data];
            for (NSInteger i = 0; i < inputText.length; i += 2) {
                unsigned int b = 0;
                NSScanner *sc = [NSScanner scannerWithString:[inputText substringWithRange:NSMakeRange(i, MIN(2, inputText.length - i))]];
                [sc scanHexInt:&b];
                [d appendBytes:&b length:1];
            }
            output.text = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] ?: d.description;
        }
        return;
    }
    
    // AES-CBC / AES-ECB
    NSData *keyData = [key.text dataUsingEncoding:NSUTF8StringEncoding];
    if (keyData.length == 0) { output.text = @"请输入密钥"; return; }
    // 填充密钥到 32 字节（AES-256）
    NSMutableData *paddedKey = [NSMutableData dataWithLength:32];
    [paddedKey replaceBytesInRange:NSMakeRange(0, MIN(keyData.length, 32)) withBytes:keyData.bytes];
    
    NSData *ivData = nil;
    if (sel == 0 && iv.text.length > 0) {  // CBC 需要 IV
        NSData *rawIV = [iv.text dataUsingEncoding:NSUTF8StringEncoding];
        ivData = [NSMutableData dataWithLength:16];
        [(NSMutableData *)ivData replaceBytesInRange:NSMakeRange(0, MIN(rawIV.length, 16)) withBytes:rawIV.bytes];
    }
    
    NSData *inputData = [inputText dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *outData = [NSMutableData dataWithLength:inputData.length + kCCBlockSizeAES128];
    size_t outLen = 0;
    CCCryptorStatus status = CCCrypt(
        encrypt ? kCCEncrypt : kCCDecrypt,
        kCCAlgorithmAES,
        sel == 0 ? kCCOptionPKCS7Padding : (kCCOptionPKCS7Padding | kCCOptionECBMode),
        paddedKey.bytes, 32,
        sel == 0 ? ivData.bytes : NULL,
        inputData.bytes, inputData.length,
        outData.mutableBytes, outData.length, &outLen);
    
    if (status == kCCSuccess) {
        outData.length = outLen;
        if (encrypt) {
            NSMutableString *hex = [NSMutableString string];
            const Byte *bytes = outData.bytes;
            for (NSUInteger i = 0; i < outLen; i++) [hex appendFormat:@"%02x", bytes[i]];
            output.text = [NSString stringWithFormat:@"加密结果(Hex):\n%@", hex];
        } else {
            NSString *dec = [[NSString alloc] initWithData:outData encoding:NSUTF8StringEncoding];
            output.text = [NSString stringWithFormat:@"解密结果:\n%@", dec ?: outData.description];
        }
    } else {
        output.text = [NSString stringWithFormat:@"错误: %d", status];
    }
}
@end

// ====== 主面板（四板块双列网格） ======
static void iaphShowPanel(UIViewController *vc) {
    if (g_mfPanelOverlay) return;
    if (!g_mfCtrl) g_mfCtrl = [[MFPanelCtrl alloc] init];
    @try {
        mfLog(@"PANEL STEP 1: vc=%@", NSStringFromClass([vc class]));
        UIWindow *keyWin = nil;
        if (@available(iOS 13.0, *)) {
            for (id sc in [UIApplication sharedApplication].connectedScenes) {
                if ([sc isKindOfClass:[UIWindowScene class]] && ((UIWindowScene *)sc).activationState == UISceneActivationStateForegroundActive) {
                    keyWin = [(UIWindowScene *)sc keyWindow]; break;
                }
            }
        }
        if (!keyWin) keyWin = [UIApplication sharedApplication].keyWindow;
        if (!keyWin) { mfLog(@"PANEL: NO keyWindow"); return; }
        mfLog(@"PANEL STEP 2: keyWin=%@", keyWin);

        CGRect sb = keyWin.bounds;
        UIView *overlay = [[UIView alloc] initWithFrame:sb];
        overlay.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        mfLog(@"PANEL STEP 3: overlay created");

        UIButton *mask = [UIButton buttonWithType:UIButtonTypeCustom];
        mask.frame = overlay.bounds;
        mask.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        mask.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.35];
        [mask addTarget:g_mfCtrl action:NSSelectorFromString(@"mfClosePanel") forControlEvents:UIControlEventTouchUpInside];
        [overlay addSubview:mask];
        mfLog(@"PANEL STEP 4: mask added");

        CGFloat cardW = sb.size.width - 32;
        CGFloat cardH = 300;  // 主页紧凑——子页 push 时自动拉长
        g_mfCardW = cardW; g_mfCardH = cardH;
        g_mfHomeCardH = cardH;
        UIVisualEffectView *card = [[UIVisualEffectView alloc] initWithFrame:CGRectMake(16, (sb.size.height - cardH)/2, cardW, cardH)];
        card.effect = [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemMaterial];
        card.layer.cornerRadius = 22;
        card.clipsToBounds = YES;
        g_mfCardView = card;
        UIView *content = card.contentView;
        g_mfCardContentView = content;
        mfLog(@"PANEL STEP 5: card created");

        // 主页内容容器——push 子页时隐藏它
        UIView *home = [[UIView alloc] initWithFrame:content.bounds];
        home.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        [content addSubview:home];
        g_mfHomePage = home;

        UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 12, 200, 26)];
        title.text = @"MinisFix";
        title.font = [UIFont boldSystemFontOfSize:18];
        title.textColor = [UIColor labelColor];
        [home addSubview:title];
        UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        closeBtn.frame = CGRectMake(cardW - 44, 10, 32, 32);
        [closeBtn setTitle:@"✕" forState:UIControlStateNormal];
        closeBtn.titleLabel.font = [UIFont systemFontOfSize:17];
        [closeBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfClosePanel") forControlEvents:UIControlEventTouchUpInside];
        [home addSubview:closeBtn];
        mfLog(@"PANEL STEP 6: title+close added");

        CGFloat gw = (cardW - 32 - 12) / 2;
        CGFloat gy = 48;
        gy = mfGridButton(home, 16, gy, gw, @"数据分析", @"📡", @selector(mfShowDataAnalysisPage), NO, nil);
        mfLog(@"PANEL STEP 7a: dataAnalysis btn");
        gy = mfGridButton(home, 16 + gw + 12, gy - 92, gw, @"网络修改", @"🔧", @selector(mfShowNetworkModifyPage), NO, nil);
        mfLog(@"PANEL STEP 7b: networkModify btn");
        gy = mfGridButton(home, 16, gy, gw, @"Product", @"🛍️", @selector(mfShowProductPage), NO, nil);
        mfLog(@"PANEL STEP 7c: product btn");

        [overlay addSubview:card];
        g_mfPanelOverlay = overlay;
        g_mfPanelRootVC = vc;
        mfLog(@"PANEL STEP 8: overlay stored, g_mfCtrl=%p g_mfPanelOverlay=%p", g_mfCtrl, g_mfPanelOverlay);

        [keyWin addSubview:overlay];
        mfLog(@"PANEL STEP 9: added to keyWin");

        overlay.alpha = 0;
        [UIView animateWithDuration:0.25 animations:^{ overlay.alpha = 1; }];
        mfLog(@"PANEL STEP 10: animation started — DONE");
    } @catch (NSException *e) {
        mfLog(@"PANEL EXCEPTION: %@ %@\n%@", e.name, e.reason, e.callStackSymbols);
    }
}

// ====== ctor：注入入口 ======
static IMP orig_viewDidAppear;

// ====== IAP 收集（从 IAPHunter.m 合并） ======
static void ensureStoreKit(void) {
    if (NSClassFromString(@"SKProduct") != nil) return;
    dlopen("/System/Library/Frameworks/StoreKit.framework/StoreKit", RTLD_LAZY | RTLD_GLOBAL);
}

@interface MFIAPObserver : NSObject <SKPaymentTransactionObserver>
@end
@implementation MFIAPObserver
- (void)paymentQueue:(SKPaymentQueue *)queue updatedTransactions:(NSArray *)transactions {
    for (SKPaymentTransaction *t in transactions) {
        if (t.transactionState == SKPaymentTransactionStatePurchased ||
            t.transactionState == SKPaymentTransactionStateFailed) {
            [queue finishTransaction:t];
        }
    }
}
@end

// SK hooks——自动收集 productIdentifier
static IMP orig_SKProduct_pid;
static NSString *new_SKProduct_pid(id self, SEL _cmd) {
    NSString *r = ((NSString *(*)(id, SEL))orig_SKProduct_pid)(self, _cmd);
    IAPRecord(r);
    return r;
}
static IMP orig_SKPayment_pid;
static NSString *new_SKPayment_pid(id self, SEL _cmd) {
    NSString *r = ((NSString *(*)(id, SEL))orig_SKPayment_pid)(self, _cmd);
    IAPRecord(r);
    return r;
}
static IMP orig_SKPaymentTxn_pid;
static NSString *new_SKPaymentTxn_pid(id self, SEL _cmd) {
    NSString *r = ((NSString *(*)(id, SEL))orig_SKPaymentTxn_pid)(self, _cmd);
    IAPRecord(r);
    return r;
}
static IMP orig_SKProductsReq_init;
static id new_SKProductsReq_init(id self, SEL _cmd, NSSet *identifiers) {
    for (NSString *pid in identifiers) IAPRecord(pid);
    return ((id(*)(id, SEL, NSSet *))orig_SKProductsReq_init)(self, _cmd, identifiers);
}

static void swizzle(Class cls, SEL sel, IMP newImp, IMP *origOut) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (origOut) *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

// ====== TestFlight 增强 ======
// 兼容性增强（mfTFCompatible）：compatible/platformCompatible/hardwareCompatible/minOSCompatible
// 禁止跑路（mfTFExpiration）：expirationDate/setExpirationDate

static BOOL (*orig_tfCompatible)(id self, SEL _cmd);
static BOOL (*orig_tfPlatformCompatible)(id self, SEL _cmd);
static BOOL (*orig_tfHardwareCompatible)(id self, SEL _cmd);
static BOOL (*orig_tfMinOSCompatible)(id self, SEL _cmd);
static NSDate *(*orig_tfExpirationDate)(id self, SEL _cmd);
static void (*orig_tfSetExpirationDate)(id self, SEL _cmd, NSDate *date);

static BOOL hook_tfCompatible(id self, SEL _cmd) {
    return mfPrefBool(@"mfTFCompatible", YES) ? YES : orig_tfCompatible ? orig_tfCompatible(self, _cmd) : YES;
}
static BOOL hook_tfPlatformCompatible(id self, SEL _cmd) {
    return mfPrefBool(@"mfTFCompatible", YES) ? YES : orig_tfPlatformCompatible ? orig_tfPlatformCompatible(self, _cmd) : YES;
}
static BOOL hook_tfHardwareCompatible(id self, SEL _cmd) {
    return mfPrefBool(@"mfTFCompatible", YES) ? YES : orig_tfHardwareCompatible ? orig_tfHardwareCompatible(self, _cmd) : YES;
}
static BOOL hook_tfMinOSCompatible(id self, SEL _cmd) {
    return mfPrefBool(@"mfTFCompatible", YES) ? YES : orig_tfMinOSCompatible ? orig_tfMinOSCompatible(self, _cmd) : YES;
}
static NSDate *hook_tfExpirationDate(id self, SEL _cmd) {
    return mfPrefBool(@"mfTFExpiration", YES) ? [NSDate distantFuture] : orig_tfExpirationDate ? orig_tfExpirationDate(self, _cmd) : [NSDate distantFuture];
}
static void hook_tfSetExpirationDate(id self, SEL _cmd, NSDate *date) {
    if (mfPrefBool(@"mfTFExpiration", YES)) return;
    if (orig_tfSetExpirationDate) orig_tfSetExpirationDate(self, _cmd, date);
}

static void mfInstallTestFlightBypass(void) {
    Class TFAppBuild = objc_getClass("TFAppBuild");
    if (!TFAppBuild) return;

    swizzle(TFAppBuild, @selector(compatible), (IMP)hook_tfCompatible, (IMP *)&orig_tfCompatible);
    swizzle(TFAppBuild, @selector(platformCompatible), (IMP)hook_tfPlatformCompatible, (IMP *)&orig_tfPlatformCompatible);
    swizzle(TFAppBuild, @selector(hardwareCompatible), (IMP)hook_tfHardwareCompatible, (IMP *)&orig_tfHardwareCompatible);
    swizzle(TFAppBuild, @selector(minOSCompatible), (IMP)hook_tfMinOSCompatible, (IMP *)&orig_tfMinOSCompatible);

    swizzle(TFAppBuild, @selector(expirationDate), (IMP)hook_tfExpirationDate, (IMP *)&orig_tfExpirationDate);
    swizzle(TFAppBuild, @selector(setExpirationDate:), (IMP)hook_tfSetExpirationDate, (IMP *)&orig_tfSetExpirationDate);
}

// ====== TestFlight 排序优化（非侵入式） ======
// 不干扰 TF 内部排序流程，只在 UICollectionView reloadData 之后
// 通过递归查找 cell 中的按钮标题判断状态

static IMP orig_tfReloadCVData;

static NSString *mfFindButtonTitle(UIView *view) {
    for (UIView *sub in view.subviews) {
        if ([sub isKindOfClass:[UIButton class]]) {
            NSString *title = [((UIButton *)sub) titleForState:UIControlStateNormal];
            if (title.length > 0) return title;
        }
        NSString *found = mfFindButtonTitle(sub);
        if (found) return found;
    }
    return nil;
}

static void mfSortVisibleCells(UICollectionView *cv) {
    if (!cv) return;
    NSInteger sections = [cv numberOfSections];
    for (NSInteger s = 0; s < sections; s++) {
        NSInteger items = [cv numberOfItemsInSection:s];
        if (items <= 1) continue;
        NSMutableArray *entries = [NSMutableArray array];
        for (NSInteger i = 0; i < items; i++) {
            NSIndexPath *ip = [NSIndexPath indexPathForItem:i inSection:s];
            UICollectionViewCell *cell = [cv cellForItemAtIndexPath:ip];
            if (!cell) continue;
            NSString *btnTitle = mfFindButtonTitle(cell.contentView);
            NSInteger priority = 3;
            if (btnTitle) {
                mfLog(@"TF sort: cell[%ld] button='%@'", (long)i, btnTitle);
                if ([btnTitle containsString:@"更新"] || [btnTitle caseInsensitiveCompare:@"Update"] == NSOrderedSame) priority = 0;
                else if ([btnTitle containsString:@"打开"] || [btnTitle caseInsensitiveCompare:@"Open"] == NSOrderedSame) priority = 1;
                else if ([btnTitle containsString:@"安装"] || [btnTitle caseInsensitiveCompare:@"Install"] == NSOrderedSame) priority = 2;
            }
            [entries addObject:@{@"p": @(priority), @"ip": ip}];
        }
        BOOL needSort = NO;
        for (NSInteger i = 1; i < entries.count; i++) {
            if ([entries[i][@"p"] integerValue] < [entries[i-1][@"p"] integerValue]) {
                needSort = YES; break;
            }
        }
        if (!needSort) continue;
        [entries sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            return [a[@"p"] compare:b[@"p"]];
        }];
        [cv reloadSections:[NSIndexSet indexSetWithIndex:s]];
        mfLog(@"TF sort: section %ld sorted", (long)s);
    }
}

static void hook_tfReloadCVData(id self, SEL _cmd) {
    if (orig_tfReloadCVData) ((void(*)(id, SEL))orig_tfReloadCVData)(self, _cmd);
    if (!mfPrefBool(@"mfTFSortOptimize", NO)) return;
    if (!objc_getClass("OASAppList")) return;
    UICollectionView *cv = (UICollectionView *)self;
    if (![cv isKindOfClass:[UICollectionView class]]) return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        mfSortVisibleCells(cv);
    });
}

static void mfInstallTestFlightSorting(void) {
    mfLog(@"TF sort: installing hooks");
    // hook UICollectionView layoutSubviews —— SwiftUI 渲染后触发
    Class cvClass = NSClassFromString(@"UICollectionView");
    if (!cvClass) { mfLog(@"TF sort: UICollectionView not found"); return; }
    Method layoutM = class_getInstanceMethod(cvClass, @selector(layoutSubviews));
    if (layoutM) {
        orig_tfReloadCVData = method_getImplementation(layoutM);
        method_setImplementation(layoutM, (IMP)hook_tfReloadCVData);
        mfLog(@"TF sort: layoutSubviews hooked");
    }
}

// ====== 自动添加新安装 App 到白名单 ======
// 监听 SpringBoard 的应用安装/注册通知

static void mfAutoApplyAdd(NSString *bid) {
    if (!mfPrefBool(@"mfIAPAutoApply", NO)) return;
    if (bid.length == 0) return;
    mfLog(@"autoApply: adding %@ to whitelist", bid);
    @autoreleasepool {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSMutableArray *list = [NSMutableArray arrayWithArray:([d objectForKey:@"mfIAPAppList"] ?: @[])];
        if (![list containsObject:bid]) {
            [list addObject:bid];
            [d setObject:list forKey:@"mfIAPAppList"];
            [d synchronize];
            mfLog(@"autoApply: %@ added successfully", bid);
        } else {
            mfLog(@"autoApply: %@ already in list", bid);
        }
    }
}

// 监听应用安装相关通知
static void mfObserveAppInstallNotifications(void) {
    mfLog(@"autoApply: observing notifications");
    // 通知名列表（SpringBoard/installd 会发送这些通知）
    NSArray *notifNames = @[
        @"com.apple.LaunchServices.applicationRegistered",
        @"com.apple.LaunchServices.applicationStateChanged",
        @"SBInstalledApplicationsDidChangeNotification",
        @"com.apple.mobile.application_installed",
        @"com.apple.mobile.installation.changed",
    ];
    for (NSString *name in notifNames) {
        [[NSNotificationCenter defaultCenter] addObserverForName:name
            object:nil queue:nil usingBlock:^(NSNotification *note) {
                mfLog(@"autoApply: notification %@ received", name);
                if (!mfPrefBool(@"mfIAPAutoApply", NO)) return;
                // 尝试从通知获取 bundleId
                NSString *bid = nil;
                // 方式1: userInfo 中的 bundleId
                bid = note.userInfo[@"bundleIdentifier"] ?: note.userInfo[@"bundleId"] ?: note.userInfo[@"SBApplicationBundleIdentifier"];
                // 方式2: 从 LSApplicationProxy 获取
                if (!bid && note.object) {
                    if ([note.object respondsToSelector:@selector(bundleIdentifier)]) {
                        bid = [note.object performSelector:@selector(bundleIdentifier)];
                    } else if ([note.object isKindOfClass:[NSDictionary class]]) {
                        bid = ((NSDictionary *)note.object)[@"MCMMetadataIdentifier"] ?: ((NSDictionary *)note.object)[@"CFBundleIdentifier"];
                    }
                }
                mfLog(@"autoApply: notification bid=%@", bid ?: @"nil");
                if (bid) mfAutoApplyAdd(bid);
            }];
        mfLog(@"autoApply: observing %@", name);
    }
    // 额外: hook LSApplicationWorkspace 的 registerApplicationDictionary:
    Class ws = objc_getClass("LSApplicationWorkspace");
    if (ws) {
        SEL sel = NSSelectorFromString(@"registerApplicationDictionary:");
        Method m = class_getInstanceMethod(ws, sel);
        if (m) {
            IMP orig = method_getImplementation(m);
            method_setImplementation(m, imp_implementationWithBlock(^(id self, NSDictionary *dict) {
                mfLog(@"autoApply: registerApplicationDictionary called");
                if (mfPrefBool(@"mfIAPAutoApply", NO)) {
                    NSString *bid = dict[@"MCMMetadataIdentifier"] ?: dict[@"CFBundleIdentifier"];
                    mfLog(@"autoApply: registerApp bid=%@", bid ?: @"nil");
                    if (bid) mfAutoApplyAdd(bid);
                }
                ((void(*)(id, SEL, NSDictionary *))orig)(self, sel, dict);
            }));
            mfLog(@"autoApply: registerApplicationDictionary hooked");
        }
    }
}

static void mfInstallAutoApply(void) {
    mfLog(@"autoApply: installing, pid=%d app=%@", getpid(), [[NSBundle mainBundle] bundleIdentifier]);
    mfObserveAppInstallNotifications();
}

// 双指长按手势处理
static void mfLongPressAction(id self, SEL _cmd, UILongPressGestureRecognizer *g) {
    if (g.state != UIGestureRecognizerStateBegan) return;
    mfLog(@"LONGPRESS BEGAN touches=%lu", (unsigned long)g.numberOfTouches);
    if (g_mfPanelOverlay) { mfLog(@"panel already open, skip"); return; }
    iaphShowPanel((UIViewController *)self);
    mfLog(@"LONGPRESS iaphShowPanel called");
}

static void new_viewDidAppear(id self, SEL _cmd, BOOL animated) {
    ((void(*)(id, SEL, BOOL))orig_viewDidAppear)(self, _cmd, animated);
    static const char kLPKey = 0;
    if (objc_getAssociatedObject(self, &kLPKey) == nil) {
        UILongPressGestureRecognizer *lp = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(mfHandleLongPress:)];
        lp.minimumPressDuration = 0.5;
        lp.numberOfTouchesRequired = 2;
        UIViewController *vc = (UIViewController *)self;
        [vc.view addGestureRecognizer:lp];
        objc_setAssociatedObject(self, &kLPKey, @"1", OBJC_ASSOCIATION_RETAIN);
        mfLog(@"gesture added to %@", NSStringFromClass([self class]));
    }
}

__attribute__((constructor)) static void MinisFixCtor(void) {
    @autoreleasepool {
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        mfLog(@"=== MinisFix ctor ENTER pid=%d app=%@ ===", getpid(), bid);

        // TestFlight 增强（独立于 IAP工具箱，始终检查）
        // 兼容性增强
        if (mfPrefBool(@"mfTFCompatible", YES)) {
            mfInstallTestFlightBypass();
        }
        // 禁止跑路
        if (mfPrefBool(@"mfTFExpiration", YES)) {
            // expirationDate 和 setExpirationDate 的 hook 在 mfInstallTestFlightBypass 里
            // 如果兼容性增强已关，需要单独装
            if (!mfPrefBool(@"mfTFCompatible", YES)) {
                Class TFAppBuild = objc_getClass("TFAppBuild");
                if (TFAppBuild) {
                    swizzle(TFAppBuild, @selector(expirationDate), (IMP)hook_tfExpirationDate, (IMP *)&orig_tfExpirationDate);
                    swizzle(TFAppBuild, @selector(setExpirationDate:), (IMP)hook_tfSetExpirationDate, (IMP *)&orig_tfSetExpirationDate);
                }
            }
        }
        // 排序优化
        if (mfPrefBool(@"mfTFSortOptimize", YES)) {
            mfInstallTestFlightSorting();
        }

        // 自动添加新 App 到白名单（始终注册通知，运行时检查开关）
        mfLog(@"autoApply: installing observers");
        mfInstallAutoApply();

        // 启用检查：设置页「启用 IAP工具箱」×「应用程序」白名单（不通过则不加载任何功能）
        if (!mfIsEnabledForCurrentApp()) {
            mfLog(@"app not in IAP工具箱 whitelist — MinisFix disabled in this app");
            return;
        }

        // IAP 收集
        ensureStoreKit();
        Class SKProductCls = NSClassFromString(@"SKProduct");
        if (SKProductCls) {
            swizzle(SKProductCls, @selector(productIdentifier), (IMP)new_SKProduct_pid, &orig_SKProduct_pid);
            swizzle(NSClassFromString(@"SKPayment"), @selector(productIdentifier), (IMP)new_SKPayment_pid, &orig_SKPayment_pid);
            swizzle(NSClassFromString(@"SKPaymentTransaction"), @selector(productIdentifier), (IMP)new_SKPaymentTxn_pid, &orig_SKPaymentTxn_pid);
            swizzle(NSClassFromString(@"SKProductsRequest"), @selector(initWithProductIdentifiers:), (IMP)new_SKProductsReq_init, &orig_SKProductsReq_init);
            mfLog(@"ctor SK hooks installed");
        }
        // 交易观察器（finishTransaction）
        static MFIAPObserver *g_observer = nil;
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            g_observer = [[MFIAPObserver alloc] init];
            [[SKPaymentQueue defaultQueue] addTransactionObserver:g_observer];
        });

        // 手势注册
        Class vcCls = NSClassFromString(@"UIViewController");
        if (vcCls) {
            Method m = class_getInstanceMethod(vcCls, @selector(viewDidAppear:));
            if (m) {
                orig_viewDidAppear = method_getImplementation(m);
                method_setImplementation(m, (IMP)new_viewDidAppear);
                mfLog(@"ctor viewDidAppear swizzled");
            }
            class_addMethod(vcCls, @selector(mfHandleLongPress:), (IMP)mfLongPressAction, "v@:@");
            mfLog(@"ctor longPress method added");
        }

        mfLog(@"=== MinisFix ctor DONE ===");
    }
}

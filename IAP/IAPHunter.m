// IAPHunter.m — IAP 产品 ID 全链路自动收集 + 可视化面板（合体版）
// 纯 ObjC，无 substrate 依赖。摇一摇/长按呼出面板。
// 编译: xcrun --sdk iphoneos clang -arch arm64 -fno-objc-arc -dynamiclib -O2 \
//       IAPHunter.m -o IAPHunter.dylib -framework Foundation -framework UIKit -framework StoreKit

#import <Foundation/Foundation.h>
#import <StoreKit/StoreKit.h>
#import <UIKit/UIKit.h>
// v3.5: 不再链接 CoreLocation/AVFoundation（v3.0 加的链接导致 ElleKit 注入失败——回归 v2.1.1 链接方式，伪装/权限改动态调用）
#import <objc/message.h>
#import <objc/runtime.h>
#import <dlfcn.h>

// 在线查询（App Store 网页 API 转发）— 兜底用
// v4.1: 不再用 queryOnlineIAP（远程查询由面板「扫描购买」页 mfFetchIAPList 负责）
// 购买指令接收轮询（SB 版发起，app 内执行）
static void startBuyPoller(void);
// 购买指令接收轮询（SB 版发起，app 内执行）

// ================= 收集核心 =================
static void IAPRecord(NSString *pid) {
    if (pid == nil || pid.length == 0) return;
    @autoreleasepool {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSMutableArray *list = [NSMutableArray arrayWithArray:([d objectForKey:@"SavedIAPIDs"] ?: [NSArray array])];
        if (![list containsObject:pid]) {
            [list addObject:pid];
            [d setObject:list forKey:@"SavedIAPIDs"];
            [d synchronize];
        }
        // 文件兜底：写 app 自己的沙盒 Documents（rootless 下 /var/mobile 写不进）
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *log = [docs stringByAppendingPathComponent:@"iaphunter.log"];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:log];
        if (fh == nil) {
            [[NSFileManager defaultManager] createFileAtPath:log contents:nil attributes:nil];
            fh = [NSFileHandle fileHandleForWritingAtPath:log];
        }
        if (fh != nil) {
            [fh seekToEndOfFile];
            [fh writeData:[[pid stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
    }
}

// ================= 全链路调试日志（v3.6） =================
// 双通道：NSLog（系统日志——远程 log show 可查）+ app 沙盒 Documents/iaph_debug.log（一定能写）
static void iaphLog(NSString *fmt, ...);
// ================= swizzle 工具 =================
static void swizzle(Class cls, SEL sel, IMP newImp, IMP *origOut) {
    if (cls == Nil || sel == NULL || newImp == NULL) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (m == NULL) return;
    if (origOut) *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

static void addMethod(Class cls, SEL sel, IMP imp, const char *types) {
    if (cls == Nil || sel == NULL || imp == NULL) return;
    class_addMethod(cls, sel, imp, types);
}

static void ensureStoreKit(void) {
    if (NSClassFromString(@"SKProduct") != nil) { iaphLog(@"ensureStoreKit: already loaded"); return; }
    void *h = dlopen("/System/Library/Frameworks/StoreKit.framework/StoreKit", RTLD_LAZY | RTLD_GLOBAL);
    iaphLog(@"ensureStoreKit: dlopen=%p SKProduct=%@", h, NSClassFromString(@"SKProduct") ? @"loaded" : @"nil");
}

// ================= IAPManager =================
@interface IAPManager : NSObject <SKProductsRequestDelegate, SKPaymentTransactionObserver>
+ (IAPManager *)sharedManager;
- (void)fetchProductsWithIDs:(NSSet *)ids;
- (void)fetchProductsWithIDs:(NSSet *)ids completion:(void (^)(NSArray *products, NSArray *invalid))completion;
@end

static UIViewController *topVC(void);

@implementation IAPManager {
    void (^_fetchCompletion)(NSArray *products, NSArray *invalid);
    UIAlertController *_loadingAlert;  // v1.3.3: 查询 loading（消除"点了没反应"）
    BOOL _isFetching;                  // v1.3.3: 防重复点击
}

static IAPManager *g_shared = nil;

+ (IAPManager *)sharedManager {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ g_shared = [[IAPManager alloc] init]; });
    return g_shared;
}

- (void)dealloc {
    if (_fetchCompletion != nil) Block_release(_fetchCompletion);
    [super dealloc];
}

- (instancetype)init {
    self = [super init];
    if (self) {
        [[SKPaymentQueue defaultQueue] addTransactionObserver:self];
    }
    return self;
}

- (UIViewController *)topViewController {
    return topVC();
}

- (void)fetchProductsWithIDs:(NSSet *)ids {
    if (_isFetching) return; // v1.3.3: 正在查询——忽略重复点击
    _isFetching = YES;
    // v1.3.3: 立即弹 loading——第一次 SKProductsRequest 慢（StoreKit 初始化/网络），
    // 无反馈导致用户以为没反应重复点击（"第一次不弹第二次弹"根因）
    UIViewController *vc0 = topVC();
    if (vc0 != nil) {
        _loadingAlert = [[UIAlertController alertControllerWithTitle:@"[IAPHunter] 正在查询"
                                                             message:[NSString stringWithFormat:@"%lu 个产品...", (unsigned long)ids.count]
                                                      preferredStyle:UIAlertControllerStyleAlert] retain];
        [vc0 presentViewController:_loadingAlert animated:YES completion:nil];
    }
    __block IAPManager *weakSelf = self;
    [self fetchProductsWithIDs:ids completion:^(NSArray *products, NSArray *invalid) {
        // v1.3.3: 先关 loading（无动画——避免 present 冲突）
        if (_loadingAlert != nil) {
            if (_loadingAlert.presentingViewController != nil)
                [_loadingAlert dismissViewControllerAnimated:NO completion:nil];
            [_loadingAlert release];
            _loadingAlert = nil;
        }
        _isFetching = NO;
        UIViewController *vc = [weakSelf topViewController];
        if (vc == nil) return;
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"[IAPHunter] 扫描结果"
                                                                      message:@"点击产品直接购买"
                                                               preferredStyle:UIAlertControllerStyleAlert];
        for (SKProduct *p in products) {
            NSNumberFormatter *fmt = [[NSNumberFormatter alloc] init];
            fmt.numberStyle = NSNumberFormatterCurrencyStyle;
            fmt.locale = p.priceLocale;
            NSString *priceStr = [fmt stringFromNumber:p.price];
            [fmt release];
            NSString *title = [NSString stringWithFormat:@"%@ (%@)", p.localizedTitle ?: @"?", priceStr ?: @"?"];
            SKProduct *product = [p retain];
            [alert addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                SKPayment *pay = [SKPayment paymentWithProduct:product];
                [[SKPaymentQueue defaultQueue] addPayment:pay];
                [product release];
            }]];
        }
        if (products.count == 0) {
            [alert addAction:[UIAlertAction actionWithTitle:@"本地 ID 全部无效（用面板「扫描购买」远程查询）" style:UIAlertActionStyleDefault handler:nil]];
        }
        [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:alert animated:YES completion:nil];
    }];
}

- (void)fetchProductsWithIDs:(NSSet *)ids completion:(void (^)(NSArray *products, NSArray *invalid))completion {
    if (ids.count == 0) {
        if (completion) completion(@[], @[]);
        return;
    }
    if (_fetchCompletion != nil) Block_release(_fetchCompletion);
    _fetchCompletion = (completion ? Block_copy(completion) : NULL);
    SKProductsRequest *req = [[SKProductsRequest alloc] initWithProductIdentifiers:ids];
    req.delegate = self;
    [req start];
    [req release];
}

- (void)productsRequest:(SKProductsRequest *)request didReceiveResponse:(SKProductsResponse *)response {
    NSArray *products = [response.products retain];
    NSArray *invalid = [response.invalidProductIdentifiers retain];
    void (^cb)(NSArray *, NSArray *) = _fetchCompletion;
    _fetchCompletion = nil;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (cb != nil) cb(products, invalid);
        if (cb != nil) Block_release(cb);
        [products release];
        [invalid release];
    });
}

- (void)request:(SKRequest *)request didFailWithError:(NSError *)error {
    // v1.3.3: 查询失败也关 loading + 重置状态
    if (_loadingAlert != nil) {
        if (_loadingAlert.presentingViewController != nil)
            [_loadingAlert dismissViewControllerAnimated:NO completion:nil];
        [_loadingAlert release];
        _loadingAlert = nil;
    }
    _isFetching = NO;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *vc = [self topViewController];
        if (vc == nil) return;
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"[IAPHunter] 查询失败"
                                                                      message:[error localizedDescription]
                                                               preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:alert animated:YES completion:nil];
    });
}

- (void)paymentQueue:(SKPaymentQueue *)queue updatedTransactions:(NSArray *)transactions {
    for (SKPaymentTransaction *t in transactions) {
        if (t.transactionState == SKPaymentTransactionStatePurchased ||
            t.transactionState == SKPaymentTransactionStateFailed) {
            [queue finishTransaction:t];
        }
    }
}

@end

// ================= UI 动作 =================
static UIViewController *topVC(void) {
    UIWindow *win = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if ([scene isKindOfClass:NSClassFromString(@"UIWindowScene")] &&
                scene.activationState == UISceneActivationStateForegroundActive) {
                id ws = (id)scene;
                UIWindow *w = [ws valueForKey:@"keyWindow"];
                if (w == nil) w = [[ws valueForKey:@"windows"] firstObject];
                if (w != nil) { win = w; break; }
            }
        }
    }
    if (win == nil) win = [UIApplication sharedApplication].keyWindow;
    UIViewController *vc = win.rootViewController;
    while (vc.presentedViewController != nil) vc = vc.presentedViewController;
    return vc;
}

// ================= v4.1 面板系统声明 =================
static void showMainMenu(UIViewController *vc);
static void iaphShowPanel(UIViewController *vc);
static void hookShakeBlock(void);
static void hookFakeGPS(void);
// 面板全局（v4.1——定义在此，供各页面/控制器使用）
static UIView *g_mfPanelOverlay = nil;
static UIViewController *g_mfPanelRootVC = nil;
static id g_mfCtrl = nil;
static NSMutableArray *g_mfPages = nil;
static CGFloat g_mfCardW = 0, g_mfCardH = 0;
static double g_mfSelLat = 0, g_mfSelLon = 0;
// 导航/页面工具（段 B 定义）
static UIView *mfMakePage(NSString *title, BOOL showBack);
static void mfPushPage(UIView *page);
static void mfPopPage(void);
static void mfClosePanel(void);
// 页面函数（段 A/B 定义，控制器方法调用）
static void mfShowProductPage(void);
static void mfShowScanPage(void);
static void mfShowManualBuyPage(void);
static void mfShowIconPage(void);
static void mfShowGpsPage(void);
static CGFloat mfGridButton(UIView *card, CGFloat x, CGFloat y, CGFloat w, NSString *title, NSString *emoji, SEL action, BOOL switchMode, NSString *pfx);
// FakeGPS 坐标（段 B 定义——hook 用）
static double iaphFakeLat(void);
static double iaphFakeLon(void);
// 地图结构体（v4.1——动态 MapKit 需要，避免依赖 CoreLocation 头）
typedef struct { double latitude; double longitude; } CLLocationCoordinate2D;
typedef struct { CLLocationCoordinate2D center; struct { double latitudeDelta, longitudeDelta; } span; } MKCoordinateRegion;


// ================= v4.1 IAP 页面函数（子页形式——不用弹窗） =================

// 远程查 IAP 列表（回调 items: [{pid,price}] 或 err）
static void mfFetchIAPList(void (^cb)(NSArray *items, NSString *err)) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (!bid) { cb(nil, @"无 bundle id"); return; }
    NSString *url = [NSString stringWithFormat:@"https://xn--ug8h.eu.org/api/iap?bundleId=%@&country=us", bid];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url] cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:12];
    [req setValue:@"IAPHunter/1.1" forHTTPHeaderField:@"User-Agent"];
    [req setValue:@"https://xn--ug8h.eu.org" forHTTPHeaderField:@"Origin"];
    [req setValue:@"https://xn--ug8h.eu.org" forHTTPHeaderField:@"Referer"];
    NSURLSession *ses = [NSURLSession sharedSession];
    NSURLSessionDataTask *task = [ses dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
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
            IAPRecord(pid);  // 收集记录
            [items addObject:[NSDictionary dictionaryWithObjectsAndKeys:
                pid, @"pid",
                (price.length ? price : @"?"), @"price",
                nil]];
        }
        cb(items, nil);
    }];
    [task resume];
}

// 扫描购买页：查询 → 列表渲染（子页内）
static void mfShowScanPage(void) {
    UIView *page = mfMakePage(@"扫描购买", YES);
    UILabel *st = [[UILabel alloc] initWithFrame:CGRectMake(16, g_mfCardH/2 - 20, g_mfCardW - 32, 40)];
    st.text = @"正在查询 IAP 列表…";
    st.textAlignment = NSTextAlignmentCenter;
    st.font = [UIFont systemFontOfSize:14];
    st.textColor = [UIColor secondaryLabelColor];
    [page addSubview:st];
    mfPushPage(page);
    mfFetchIAPList(^(NSArray *items, NSString *err) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [st removeFromSuperview];
            if (err) {
                UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 100, g_mfCardW - 32, 60)];
                e.text = [NSString stringWithFormat:@"查询失败:\n%@", err];
                e.numberOfLines = 0;
                e.textAlignment = NSTextAlignmentCenter;
                e.font = [UIFont systemFontOfSize:13];
                e.textColor = [UIColor systemRedColor];
                [page addSubview:e];
                return;
            }
            if (items.count == 0) {
                UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 100, g_mfCardW - 32, 40)];
                e.text = @"未找到 IAP 产品";
                e.textAlignment = NSTextAlignmentCenter;
                e.textColor = [UIColor secondaryLabelColor];
                [page addSubview:e];
                return;
            }
            UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, g_mfCardH - 42)];
            CGFloat y = 8;
            for (NSDictionary *item in items) {
                UIButton *row = [UIButton buttonWithType:UIButtonTypeSystem];
                row.frame = CGRectMake(12, y, g_mfCardW - 24, 46);
                row.backgroundColor = [UIColor secondarySystemBackgroundColor];
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
            iaphLog(@"scan: %d items rendered", (int)items.count);
        });
    });
}

// 手动购买页：输入 PID 直购
static void mfShowManualBuyPage(void) {
    UIView *page = mfMakePage(@"手动购买", YES);
    UITextField *tf = [[UITextField alloc] initWithFrame:CGRectMake(16, 56, g_mfCardW - 32, 42)];
    tf.borderStyle = UITextBorderStyleRoundedRect;
    tf.placeholder = @"输入产品 ID（如 app.lebaby.unlimited_entries）";
    tf.autocorrectionType = UITextAutocorrectionTypeNo;
    tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
    tf.font = [UIFont systemFontOfSize:13];
    tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    [page addSubview:tf];
    objc_setAssociatedObject(page, "tf", tf, OBJC_ASSOCIATION_RETAIN);
    UIButton *buy = [UIButton buttonWithType:UIButtonTypeSystem];
    buy.frame = CGRectMake(16, 110, g_mfCardW - 32, 44);
    buy.backgroundColor = [UIColor systemBlueColor];
    buy.layer.cornerRadius = 12;
    [buy setTitle:@"购买" forState:UIControlStateNormal];
    [buy setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [buy.titleLabel setFont:[UIFont boldSystemFontOfSize:15]];
    [buy addTarget:g_mfCtrl action:NSSelectorFromString(@"mfDoManualBuy") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:buy];
    UILabel *res = [[UILabel alloc] initWithFrame:CGRectMake(16, 164, g_mfCardW - 32, 60)];
    res.numberOfLines = 0;
    res.font = [UIFont systemFontOfSize:13];
    res.textColor = [UIColor labelColor];
    res.textAlignment = NSTextAlignmentCenter;
    [page addSubview:res];
    objc_setAssociatedObject(page, "res", res, OBJC_ASSOCIATION_RETAIN);
    mfPushPage(page);
}

// 图标解锁页：读 CFBundleAlternateIcons → 网格 → 点击切换
static void mfShowIconPage(void) {
    UIView *page = mfMakePage(@"图标解锁", YES);
    NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
    NSDictionary *alt = info[@"CFBundleIcons"][@"CFBundleAlternateIcons"];
    NSArray *names = [alt allKeys];
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, g_mfCardH - 42)];
    if (names.count == 0) {
        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 60, g_mfCardW - 32, 40)];
        e.text = @"此 app 没有备用图标";
        e.textAlignment = NSTextAlignmentCenter;
        e.textColor = [UIColor secondaryLabelColor];
        [page addSubview:e];
    } else {
        CGFloat gw = (g_mfCardW - 32 - 12) / 2;
        CGFloat y = 8;
        for (NSString *nm in names) {
            UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
            b.frame = CGRectMake(16, y, gw, 56);
            b.backgroundColor = [UIColor secondarySystemBackgroundColor];
            b.layer.cornerRadius = 12;
            [b setTitle:nm forState:UIControlStateNormal];
            [b.titleLabel setFont:[UIFont systemFontOfSize:13]];
            objc_setAssociatedObject(b, "icon", nm, OBJC_ASSOCIATION_RETAIN);
            [b addTarget:g_mfCtrl action:NSSelectorFromString(@"mfIconTap:") forControlEvents:UIControlEventTouchUpInside];
            [sv addSubview:b];
            y += 62;
        }
        sv.contentSize = CGSizeMake(g_mfCardW, y + 16);
        [page addSubview:sv];
    }
    mfPushPage(page);
}

static void showMainMenu(UIViewController *vc) {
    if (vc == nil) { iaphLog(@"showMainMenu: vc == nil"); return; }
    iaphLog(@"showMainMenu vc=%@", NSStringFromClass([vc class]));
    iaphShowPanel(vc);  // v3.0: 毛玻璃悬浮面板（双指长按呼出）
    iaphLog(@"showMainMenu iaphShowPanel returned");
}


// 长按手势 action（v3.0: 双指长按呼出——全屏区域，双指误触率极低）
static void longPressAction(id self, SEL _cmd, UILongPressGestureRecognizer *g) {
    if (g.state != UIGestureRecognizerStateBegan) return;
    iaphLog(@"LONGPRESS BEGAN touches=%lu", (unsigned long)g.numberOfTouches);
    showMainMenu((UIViewController *)self);
    iaphLog(@"LONGPRESS showMainMenu returned");
}

// ================= Hook 实现 =================
static IMP orig_viewDidAppear;
static void new_viewDidAppear(id self, SEL _cmd, BOOL animated) {
    ((void(*)(id, SEL, BOOL))orig_viewDidAppear)(self, _cmd, animated);
    iaphLog(@"viewDidAppear %@", NSStringFromClass([self class]));
    // 给 view 加长按手势（防重复）
    static const char kLPKey = 0;
    if (objc_getAssociatedObject(self, &kLPKey) == nil) {
        UILongPressGestureRecognizer *lp = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(handleLongPress:)];
        lp.minimumPressDuration = 0.5;
        lp.numberOfTouchesRequired = 2;  // v3.0: 双指长按呼出（无误触）
        UIViewController *vc = (UIViewController *)self;
        [vc.view addGestureRecognizer:lp];
        [lp release];
        objc_setAssociatedObject(self, &kLPKey, @"1", OBJC_ASSOCIATION_RETAIN);
        iaphLog(@"gesture added to %@", NSStringFromClass([self class]));
    }
}

static IMP orig_SKProduct_productIdentifier;
static NSString *new_SKProduct_productIdentifier(id self, SEL _cmd) {
    NSString *r = ((NSString *(*)(id, SEL))orig_SKProduct_productIdentifier)(self, _cmd);
    IAPRecord(r);
    return r;
}

static IMP orig_SKPayment_productIdentifier;
static NSString *new_SKPayment_productIdentifier(id self, SEL _cmd) {
    NSString *r = ((NSString *(*)(id, SEL))orig_SKPayment_productIdentifier)(self, _cmd);
    IAPRecord(r);
    return r;
}

static IMP orig_SKPaymentTransaction_productIdentifier;
static NSString *new_SKPaymentTransaction_productIdentifier(id self, SEL _cmd) {
    NSString *r = ((NSString *(*)(id, SEL))orig_SKPaymentTransaction_productIdentifier)(self, _cmd);
    IAPRecord(r);
    return r;
}

static IMP orig_SKProductsRequest_init;
static id new_SKProductsRequest_init(id self, SEL _cmd, NSSet *identifiers) {
    for (NSString *pid in identifiers) IAPRecord(pid);
    return ((id(*)(id, SEL, NSSet *))orig_SKProductsRequest_init)(self, _cmd, identifiers);
}

static IMP orig_SKPaymentQueue_addPayment;
static void new_SKPaymentQueue_addPayment(id self, SEL _cmd, SKPayment *payment) {
    NSString *pid = [payment productIdentifier];
    IAPRecord(pid);
    ((void(*)(id, SEL, SKPayment *))orig_SKPaymentQueue_addPayment)(self, _cmd, payment);
}

static IMP orig_SKProductsResponse_products;
static NSArray *new_SKProductsResponse_products(id self, SEL _cmd) {
    NSArray *r = ((NSArray *(*)(id, SEL))orig_SKProductsResponse_products)(self, _cmd);
    for (SKProduct *p in r) IAPRecord([p productIdentifier]);
    return r;
}

static IMP orig_SKProductsResponse_invalid;
static NSArray *new_SKProductsResponse_invalid(id self, SEL _cmd) {
    NSArray *r = ((NSArray *(*)(id, SEL))orig_SKProductsResponse_invalid)(self, _cmd);
    for (NSString *pid in r) IAPRecord(pid);
    return r;
}

// ================= 设置开关 =================
// v2.0: Settings → IAPHunter → 启用（preferenceloader 开关——写 /var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist）
// 直接读 rootless 文件（initWithSuiteName 在无 group entitlement 的注入进程里读 app 沙盒——读不到设置）
// 默认开；关则 ctor 直接 return（完全禁用——hook/手势都不装）
static BOOL iaphIsEnabled(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"];
    id v = [d objectForKey:@"IAPHunterEnabled"];
    BOOL on = (v == nil) ? YES : [v boolValue];
    return on;
}

// ================= per-app 注入开关（MinisFix 设置 → 应用程序） =================
// 默认全开；IAPDisabledApps 数组里的 app 不注入
static BOOL iaphIsAppAllowed(void) {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    if (bundleID == nil) return YES;
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"];
    NSArray *disabled = d[@"IAPDisabledApps"];
    if ([disabled containsObject:bundleID]) return NO;
    return YES;
}

// ================= 全链路调试日志（v3.6） =================
// 双通道：NSLog（系统日志——远程 log show 可查）+ app 沙盒 Documents/iaph_debug.log（一定能写）
// 目标：注入没注入 / 跑没跑 / 卡在哪一步，一次日志全说清
static void iaphLog(NSString *fmt, ...) {
    va_list args; va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSLog(@"[IAPHunter] %@", msg);
    @try {
        static NSString *logPath = nil;
        if (logPath == nil) {
            NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
            if (dirs.count > 0) logPath = [[dirs.firstObject stringByAppendingPathComponent:@"iaph_debug.log"] retain];
        }
        if (logPath) {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
            if (fh == nil) {
                [[NSFileManager defaultManager] createFileAtPath:logPath contents:nil attributes:nil];
                fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
            }
            if (fh) {
                [fh seekToEndOfFile];
                NSString *line = [NSString stringWithFormat:@"[%ld] %@\n", (long)getpid(), msg];
                [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
                [fh closeFile];
            }
        }
    } @catch (NSException *e) {}
    [msg release];
}

// ================= 入口 =================
__attribute__((constructor)) static void IAPHunterCtor(void) {
    @autoreleasepool {
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        iaphLog(@"=== ctor ENTER pid=%d app=%@ ===", getpid(), bid);
        if (!iaphIsAppAllowed()) { iaphLog(@"ctor EXIT: app not allowed"); return; }
        // v3.0: 屏蔽摇一摇 + FakeGPS hook
        hookShakeBlock(); iaphLog(@"ctor hookShakeBlock done");
        hookFakeGPS(); iaphLog(@"ctor hookFakeGPS done");

        ensureStoreKit(); iaphLog(@"ctor ensureStoreKit done");

        Class UIViewControllerCls = NSClassFromString(@"UIViewController");
        swizzle(UIViewControllerCls, @selector(viewDidAppear:), (IMP)new_viewDidAppear, &orig_viewDidAppear);
        addMethod(UIViewControllerCls, @selector(handleLongPress:), (IMP)longPressAction, "v@:@");
        iaphLog(@"ctor UIViewController swizzle+addMethod done (cls=%@)", UIViewControllerCls ? NSStringFromClass(UIViewControllerCls) : @"nil");

        Class SKProductCls = NSClassFromString(@"SKProduct");
        swizzle(SKProductCls, @selector(productIdentifier), (IMP)new_SKProduct_productIdentifier, &orig_SKProduct_productIdentifier);
        swizzle(NSClassFromString(@"SKPayment"), @selector(productIdentifier), (IMP)new_SKPayment_productIdentifier, &orig_SKPayment_productIdentifier);
        swizzle(NSClassFromString(@"SKPaymentTransaction"), @selector(productIdentifier), (IMP)new_SKPaymentTransaction_productIdentifier, &orig_SKPaymentTransaction_productIdentifier);
        swizzle(NSClassFromString(@"SKProductsRequest"), @selector(initWithProductIdentifiers:), (IMP)new_SKProductsRequest_init, &orig_SKProductsRequest_init);
        swizzle(NSClassFromString(@"SKPaymentQueue"), @selector(addPayment:), (IMP)new_SKPaymentQueue_addPayment, &orig_SKPaymentQueue_addPayment);
        swizzle(NSClassFromString(@"SKProductsResponse"), @selector(products), (IMP)new_SKProductsResponse_products, &orig_SKProductsResponse_products);
        swizzle(NSClassFromString(@"SKProductsResponse"), @selector(invalidProductIdentifiers), (IMP)new_SKProductsResponse_invalid, &orig_SKProductsResponse_invalid);
        iaphLog(@"ctor SK hooks done (SKProduct=%@)", SKProductCls ? NSStringFromClass(SKProductCls) : @"nil");

        // 预热单例，注册交易 observer
        [IAPManager sharedManager];
        // 购买指令接收（SB 版发起：写指令文件 + Darwin 通知，app 内执行购买）
        startBuyPoller();
        iaphLog(@"=== ctor DONE ===");
    }
}


// ============ 购买指令接收（SB 版发起，app 内执行正规购买） ============
static void checkBuyCommand(void) {
    NSString *path = @"/var/mobile/Library/Preferences/com.linsars.minisfix.cmd.plist";
    NSDictionary *cmd = [NSDictionary dictionaryWithContentsOfFile:path];
    if (cmd == nil) return;
    NSString *targetBundle = cmd[@"bundleId"];
    NSString *myBundle = [[NSBundle mainBundle] bundleIdentifier];
    if (targetBundle.length == 0 || ![targetBundle isEqualToString:myBundle]) return;
    NSString *productId = cmd[@"productId"];
    if (productId.length > 0) {
        // app 进程内 SKPaymentQueue 是正规购买流程（弹密码、有记录）
        dispatch_async(dispatch_get_main_queue(), ^{
            UIViewController *vc = topVC();
            if (vc != nil) {
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"[IAPHunter]"
                                    message:[NSString stringWithFormat:@"收到购买指令：\n%@\n确认购买？", productId]
                             preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"购买" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                    SKPayment *pay = [SKPayment paymentWithProductIdentifier:productId];
                    [[SKPaymentQueue defaultQueue] addPayment:pay];
                }]];
                [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
                [vc presentViewController:alert animated:YES completion:nil];
            } else {
                SKPayment *pay = [SKPayment paymentWithProductIdentifier:productId];
                [[SKPaymentQueue defaultQueue] addPayment:pay];
            }
        });
    }
    [[NSFileManager defaultManager] removeItemAtPath:path error:NULL];
}

static void iaphBuyNotify(CFNotificationCenterRef c, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool { checkBuyCommand(); }
    });
}

static void startBuyPoller(void) {
    // Darwin 通知即时响应（app 已运行时）
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL,
        iaphBuyNotify, CFSTR("com.linsars.minisfix.buy"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    // 轮询兜底（app 刚启动 / 通知丢失时）
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        while (1) {
            @autoreleasepool { checkBuyCommand(); }
            [NSThread sleepForTimeInterval:3.0];
        }
    });
}

// ============================================================================
// v3.0 新面板（毛玻璃悬浮卡片——仿 FakeTools CustomMenuView 风格）
// 呼出：双指长按任意位置 → iaphShowPanel
// 分组：IAP | 屏蔽（摇一摇）| 相机（权限查看）| 伪装（FakeGPS/设备）
// ============================================================================
#pragma mark - v3.0 设置读写
static NSMutableDictionary *mfPrefsDict(void) {
    NSMutableDictionary *d = [NSMutableDictionary dictionaryWithContentsOfFile:@"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"];
    if (!d) d = [NSMutableDictionary new];
    return d;
}
static BOOL mfPrefBool(NSString *key, BOOL def) {
    id v = mfPrefsDict()[key];
    return v ? [v boolValue] : def;
}
static void mfSetBoolPref(NSString *key, BOOL val) {
    NSMutableDictionary *d = mfPrefsDict();
    d[key] = @(val);
    [d writeToFile:@"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist" atomically:YES];
}


// ================= v4.1 MFPanelCtrl + 面板系统（导航容器 + 子页 + FakeGPS 地图） =================

// ---- FakeGPS 坐标（prefs——默认北京） ----
static double iaphFakeLat(void) { id v = mfPrefsDict()[@"iaphFakeLat"]; return v ? [v doubleValue] : 39.9042; }
static double iaphFakeLon(void) { id v = mfPrefsDict()[@"iaphFakeLon"]; return v ? [v doubleValue] : 116.4074; }
static void mfSetPrefDouble(NSString *key, double val) {
    NSMutableDictionary *d = mfPrefsDict();
    d[key] = @(val);
    [d writeToFile:@"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist" atomically:YES];
}

#pragma mark - 屏蔽摇一摇（motionEnded hook）
static IMP orig_motionEnded;
static void new_motionEnded(id self, SEL _cmd, int motion, id event) {
    if (mfPrefBool(@"iaphShakeBlock", NO)) {
        return;  // 屏蔽摇一摇（摇一摇广告/弹窗）
    }
    if (orig_motionEnded) ((void(*)(id, SEL, int, id))orig_motionEnded)(self, _cmd, motion, event);
}
static void hookShakeBlock(void) {
    Class cls = objc_getClass("UIResponder");
    if (!cls) { iaphLog(@"hookShakeBlock: UIResponder nil"); return; }
    Method m = class_getInstanceMethod(cls, NSSelectorFromString(@"motionEnded:withEvent:"));
    if (m) { orig_motionEnded = method_getImplementation(m); method_setImplementation(m, (IMP)new_motionEnded); iaphLog(@"hookShakeBlock: motionEnded hooked"); }
    else { iaphLog(@"hookShakeBlock: motionEnded method not found"); }
}

#pragma mark - Fake GPS 伪装（CLLocationManager hook，v3.5 动态调用——不链接 CoreLocation）
// v4.1: 动态创建 CLLocation——坐标用面板地图选点（iaphFakeLat/iaphFakeLon，默认北京）
static id makeFakeLocation(void) {
    Class locCls = objc_getClass("CLLocation");
    if (!locCls) return nil;
    id loc = [locCls alloc];
    SEL initSel = NSSelectorFromString(@"initWithLatitude:longitude:");
    if (!initSel) return nil;
    return ((id(*)(id, SEL, double, double))objc_msgSend)(loc, initSel, iaphFakeLat(), iaphFakeLon());
}
static IMP orig_clLocation, orig_startUpdating;
static id new_clLocation(id self, SEL _cmd) {
    if (mfPrefBool(@"iaphFakeGPS", NO)) {
        return makeFakeLocation();
    }
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
    if (!cls) { iaphLog(@"hookFakeGPS: CLLocationManager class nil"); return; }
    Method m;
    if ((m = class_getInstanceMethod(cls, @selector(location)))) { orig_clLocation = method_getImplementation(m); method_setImplementation(m, (IMP)new_clLocation); }
    if ((m = class_getInstanceMethod(cls, @selector(startUpdatingLocation)))) { orig_startUpdating = method_getImplementation(m); method_setImplementation(m, (IMP)new_startUpdating); }
    iaphLog(@"hookFakeGPS: hooks installed");
}

// ---- 面板导航（全局在声明区定义） ----

// 页面工具：带导航条的页面容器（返回 + 标题 + ✕）
static UIView *mfMakePage(NSString *title, BOOL showBack) {
    UIView *page = [[UIView alloc] initWithFrame:CGRectMake(0, 0, g_mfCardW, g_mfCardH)];
    page.backgroundColor = [UIColor clearColor];
    UIView *nav = [[UIView alloc] initWithFrame:CGRectMake(0, 0, g_mfCardW, 40)];
    nav.backgroundColor = [UIColor clearColor];
    [page addSubview:nav];
    if (showBack) {
        UIButton *back = [UIButton buttonWithType:UIButtonTypeSystem];
        back.frame = CGRectMake(6, 4, 64, 32);
        [back setTitle:@"‹ 返回" forState:UIControlStateNormal];
        [back.titleLabel setFont:[UIFont systemFontOfSize:15]];
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
static void mfPushPage(UIView *page) {
    if (!g_mfPages) g_mfPages = [[NSMutableArray alloc] init];
    for (UIView *p in g_mfPages) p.hidden = YES;
    [g_mfPanelOverlay addSubview:page];
    [g_mfPages addObject:page];
}
static void mfPopPage(void) {
    if (g_mfPages.count == 0) return;
    UIView *top = [g_mfPages lastObject];
    [top removeFromSuperview];
    [g_mfPages removeLastObject];
    if (g_mfPages.count > 0) [[g_mfPages lastObject] setHidden:NO];
}
static void mfClosePanel(void) {
    if (g_mfPanelOverlay) {
        UIView *ov = g_mfPanelOverlay;
        [UIView animateWithDuration:0.2 animations:^{ ov.alpha = 0; } completion:^(BOOL f) {
            [ov removeFromSuperview];
            g_mfPanelOverlay = nil;
            g_mfPanelRootVC = nil;
            [g_mfPages removeAllObjects];
            iaphLog(@"panel: closed");
        }];
    }
}

// ---- FakeTools 风格网格按钮（圆形图标 + 文字；switchMode 点击切换 + 状态色） ----
static CGFloat mfGridButton(UIView *card, CGFloat x, CGFloat y, CGFloat w, NSString *title, NSString *emoji, SEL action, BOOL switchMode, NSString *pfx) {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = CGRectMake(x, y, w, 84);
    b.backgroundColor = [UIColor secondarySystemBackgroundColor];
    b.layer.cornerRadius = 16;
    [b addTarget:g_mfCtrl action:action forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:b];
    UIView *badge = [[UIView alloc] initWithFrame:CGRectMake(w/2 - 22, 10, 44, 44)];
    badge.backgroundColor = [UIColor tertiarySystemBackgroundColor];
    badge.layer.cornerRadius = 22;
    badge.userInteractionEnabled = NO;
    [b addSubview:badge];
    UILabel *ic = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, 44, 44)];
    ic.text = emoji;
    ic.font = [UIFont systemFontOfSize:24];
    ic.textAlignment = NSTextAlignmentCenter;
    [badge addSubview:ic];
    UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(0, 58, w, 18)];
    lb.text = title;
    lb.font = [UIFont systemFontOfSize:12];
    lb.textAlignment = NSTextAlignmentCenter;
    lb.textColor = [UIColor labelColor];
    lb.adjustsFontSizeToFitWidth = YES;
    lb.minimumScaleFactor = 0.7;
    [b addSubview:lb];
    if (switchMode && pfx) {
        BOOL on = mfPrefBool(pfx, NO);
        b.backgroundColor = on ? [UIColor systemGreenColor] : [UIColor secondarySystemBackgroundColor];
        objc_setAssociatedObject(b, "pfx", pfx, OBJC_ASSOCIATION_RETAIN);
    }
    return y + 92;
}

@interface MFPanelCtrl : NSObject
@end
@implementation MFPanelCtrl
- (void)mfPopPage { mfPopPage(); }
- (void)mfClosePanel { mfClosePanel(); }
// 网格开关（屏蔽摇一摇）
- (void)mfGridSwitchChanged:(UIButton *)b {
    NSString *key = objc_getAssociatedObject(b, "pfx");
    if (!key) return;
    BOOL on = !mfPrefBool(key, NO);
    mfSetBoolPref(key, on);
    b.backgroundColor = on ? [UIColor systemGreenColor] : [UIColor secondarySystemBackgroundColor];
    iaphLog(@"grid switch %@ -> %d", key, on);
}
// 扫描结果行点击购买
- (void)mfBuyProduct:(UIButton *)b {
    NSString *pid = objc_getAssociatedObject(b, "pid");
    if (!pid) return;
    IAPRecord(pid);
    SKPayment *pay = [SKPayment paymentWithProductIdentifier:pid];
    [[SKPaymentQueue defaultQueue] addPayment:pay];
    b.backgroundColor = [UIColor systemGreenColor];
    iaphLog(@"buy: %@", pid);
}
// 手动购买
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
    iaphLog(@"manual buy: %@", pid);
}
// 图标点击切换
- (void)mfIconTap:(UIButton *)b {
    NSString *nm = objc_getAssociatedObject(b, "icon");
    if (!nm) return;
    UIApplication *app = [UIApplication sharedApplication];
    NSError *err = nil;
    if ([app respondsToSelector:@selector(setAlternateIconName:completionHandler:)]) {
        [app setAlternateIconName:nm completionHandler:^(NSError *e) {
            iaphLog(@"icon switch %@ -> %@", nm, e ? [e localizedDescription] : @"ok");
        }];
        b.backgroundColor = [UIColor systemGreenColor];
    }
}
// FakeGPS 地图长按选点
- (void)mfMapLongPress:(UILongPressGestureRecognizer *)g {
    if (g.state != UIGestureRecognizerStateBegan) return;
    UIView *map = g.view;
    CGPoint p = [g locationInView:map];
    CLLocationCoordinate2D c = ((CLLocationCoordinate2D(*)(id, SEL, CGPoint, id))objc_msgSend)(map, NSSelectorFromString(@"convertPoint:toCoordinateFromView:"), p, map);
    g_mfSelLat = c.latitude; g_mfSelLon = c.longitude;
    Class annCls = objc_getClass("MKPointAnnotation");
    if (annCls) {
        id ann = [[annCls alloc] init];
        ((void(*)(id, SEL, CLLocationCoordinate2D))objc_msgSend)(ann, NSSelectorFromString(@"setCoordinate:"), c);
        [map performSelector:NSSelectorFromString(@"removeAnnotations:") withObject:[map performSelector:NSSelectorFromString(@"annotations")]];
        [map performSelector:NSSelectorFromString(@"addAnnotation:") withObject:ann];
    }
    UIView *top = [g_mfPages lastObject];
    UILabel *cl = objc_getAssociatedObject(top, "coord");
    if (cl) cl.text = [NSString stringWithFormat:@"选中: %.4f, %.4f", c.latitude, c.longitude];
    iaphLog(@"map select: %.4f, %.4f", c.latitude, c.longitude);
}
// FakeGPS 确认坐标
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
    if (cl) { cl.text = [NSString stringWithFormat:@"✅ 已启用 Fake GPS:\n%.4f, %.4f", g_mfSelLat, g_mfSelLon]; cl.textColor = [UIColor systemGreenColor]; }
    iaphLog(@"FakeGPS set: %.4f, %.4f", g_mfSelLat, g_mfSelLon);
}
// FakeGPS 开关
- (void)mfGpsSwitch:(UISwitch *)sw {
    mfSetBoolPref(@"iaphFakeGPS", sw.on);
    iaphLog(@"FakeGPS switch -> %d", sw.on);
}
// 页面入口
- (void)mfShowProductPage { mfShowProductPage(); }
- (void)mfShowScanPage { mfShowScanPage(); }
- (void)mfShowManualBuyPage { mfShowManualBuyPage(); }
- (void)mfShowIconPage { mfShowIconPage(); }
- (void)mfShowGpsPage { mfShowGpsPage(); }
@end

// ---- Product 子页 ----
static void mfShowProductPage(void) {
    UIView *page = mfMakePage(@"Product", YES);
    CGFloat gw = (g_mfCardW - 32 - 12) / 2;
    CGFloat gy = 48;
    gy = mfGridButton(page, 16, gy, gw, @"扫描购买", @"🔍", @selector(mfShowScanPage), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"手动购买", @"⌨️", @selector(mfShowManualBuyPage), NO, nil);
    gy = mfGridButton(page, 16, gy, gw, @"图标解锁", @"🎨", @selector(mfShowIconPage), NO, nil);
    mfPushPage(page);
}

// ---- FakeGPS 地图页（动态 MapKit——不链接防注入失败） ----
static void mfShowGpsPage(void) {
    dlopen("/System/Library/Frameworks/MapKit.framework/MapKit", RTLD_LAZY | RTLD_GLOBAL);
    dlopen("/System/Library/Frameworks/CoreLocation.framework/CoreLocation", RTLD_LAZY | RTLD_GLOBAL);
    UIView *page = mfMakePage(@"Fake GPS", YES);
    // 启用开关
    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(16, 48, 60, 31)];
    sw.on = mfPrefBool(@"iaphFakeGPS", NO);
    [sw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfGpsSwitch:") forControlEvents:UIControlEventValueChanged];
    [page addSubview:sw];
    UILabel *swLb = [[UILabel alloc] initWithFrame:CGRectMake(84, 52, 160, 24)];
    swLb.text = @"启用模拟定位";
    swLb.font = [UIFont systemFontOfSize:14];
    swLb.textColor = [UIColor labelColor];
    [page addSubview:swLb];
    // 地图
    Class MKCls = objc_getClass("MKMapView");
    if (!MKCls) {
        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 100, g_mfCardW - 32, 40)];
        e.text = @"MapKit 不可用";
        e.textColor = [UIColor secondaryLabelColor];
        [page addSubview:e];
        mfPushPage(page);
        return;
    }
    id map = [[MKCls alloc] initWithFrame:CGRectMake(12, 86, g_mfCardW - 24, 200)];
    map.layer.cornerRadius = 14;
    map.clipsToBounds = YES;
    MKCoordinateRegion reg;
    reg.center.latitude = iaphFakeLat();
    reg.center.longitude = iaphFakeLon();
    reg.span.latitudeDelta = 0.05;
    reg.span.longitudeDelta = 0.05;
    ((void(*)(id, SEL, MKCoordinateRegion, BOOL))objc_msgSend)(map, NSSelectorFromString(@"setRegion:animated:"), reg, NO);
    UILongPressGestureRecognizer *lp = [[UILongPressGestureRecognizer alloc] initWithTarget:g_mfCtrl action:NSSelectorFromString(@"mfMapLongPress:")];
    lp.minimumPressDuration = 0.5;
    [map addGestureRecognizer:lp];
    [page addSubview:map];
    objc_setAssociatedObject(page, "map", map, OBJC_ASSOCIATION_RETAIN);
    // 坐标 label
    UILabel *coord = [[UILabel alloc] initWithFrame:CGRectMake(16, 296, g_mfCardW - 32, 36)];
    coord.text = [NSString stringWithFormat:@"当前: %.4f, %.4f（长按地图选点）", iaphFakeLat(), iaphFakeLon()];
    coord.font = [UIFont systemFontOfSize:12];
    coord.textColor = [UIColor secondaryLabelColor];
    coord.numberOfLines = 0;
    coord.textAlignment = NSTextAlignmentCenter;
    [page addSubview:coord];
    objc_setAssociatedObject(page, "coord", coord, OBJC_ASSOCIATION_RETAIN);
    // 确认按钮
    UIButton *ok = [UIButton buttonWithType:UIButtonTypeSystem];
    ok.frame = CGRectMake(16, 338, g_mfCardW - 32, 44);
    ok.backgroundColor = [UIColor systemBlueColor];
    ok.layer.cornerRadius = 12;
    [ok setTitle:@"确认模拟此坐标" forState:UIControlStateNormal];
    [ok setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [ok.titleLabel setFont:[UIFont boldSystemFontOfSize:15]];
    [ok addTarget:g_mfCtrl action:NSSelectorFromString(@"mfConfirmCoord") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:ok];
    mfPushPage(page);
    iaphLog(@"GPS page shown (MKMapView=%@)", MKCls ? @"loaded" : @"nil");
}

// ---- 主页面板（v4.1：Product / 屏蔽摇一摇 / Fake GPS） ----
static void iaphShowPanel(UIViewController *vc) {
    if (g_mfPanelOverlay) return;
    if (!g_mfCtrl) g_mfCtrl = [[MFPanelCtrl alloc] init];
    @try {
        iaphLog(@"panel: show called vc=%@", NSStringFromClass([vc class]));
        UIWindow *keyWin = nil;
        if (@available(iOS 13.0, *)) {
            for (id sc in [UIApplication sharedApplication].connectedScenes) {
                if ([sc isKindOfClass:[UIWindowScene class]] && ((UIWindowScene *)sc).activationState == UISceneActivationStateForegroundActive) {
                    keyWin = [(UIWindowScene *)sc keyWindow]; break;
                }
            }
        }
        if (!keyWin) keyWin = [UIApplication sharedApplication].keyWindow;
        if (!keyWin) { iaphLog(@"panel: NO keyWindow"); return; }

        CGRect sb = keyWin.bounds;
        UIView *overlay = [[UIView alloc] initWithFrame:sb];
        overlay.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        overlay.backgroundColor = [UIColor clearColor];
        UIButton *mask = [UIButton buttonWithType:UIButtonTypeCustom];
        mask.frame = overlay.bounds;
        mask.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        mask.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.35];
        [mask addTarget:g_mfCtrl action:NSSelectorFromString(@"mfClosePanel") forControlEvents:UIControlEventTouchUpInside];
        [overlay addSubview:mask];

        CGFloat cardW = sb.size.width - 32;
        CGFloat cardH = 240;
        g_mfCardW = cardW; g_mfCardH = cardH;
        UIVisualEffectView *card = [[UIVisualEffectView alloc] initWithFrame:CGRectMake(16, (sb.size.height - cardH)/2, cardW, cardH)];
        card.effect = [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemMaterial];
        card.layer.cornerRadius = 22;
        card.clipsToBounds = YES;
        card.layer.borderWidth = 0.5;
        card.layer.borderColor = [[UIColor systemGray3Color] colorWithAlphaComponent:0.5].CGColor;
        UIView *content = card.contentView;

        UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 12, 200, 26)];
        title.text = @"MinisFix";
        title.font = [UIFont boldSystemFontOfSize:18];
        title.textColor = [UIColor labelColor];
        [content addSubview:title];
        UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        closeBtn.frame = CGRectMake(cardW - 44, 10, 32, 32);
        [closeBtn setTitle:@"✕" forState:UIControlStateNormal];
        [closeBtn.titleLabel setFont:[UIFont systemFontOfSize:17]];
        [closeBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfClosePanel") forControlEvents:UIControlEventTouchUpInside];
        [content addSubview:closeBtn];

        // 主页网格：Product / 屏蔽摇一摇 / Fake GPS
        CGFloat gw = (cardW - 32 - 12) / 2;
        CGFloat gy = 48;
        gy = mfGridButton(content, 16, gy, gw, @"Product", @"🛍️", @selector(mfShowProductPage), NO, nil);
        gy = mfGridButton(content, 16 + gw + 12, gy - 92, gw, @"屏蔽摇一摇", @"📳", @selector(mfGridSwitchChanged:), YES, @"iaphShakeBlock");
        gy = mfGridButton(content, 16, gy, gw, @"Fake GPS", @"📍", @selector(mfShowGpsPage), NO, nil);

        [overlay addSubview:card];
        [keyWin addSubview:overlay];
        g_mfPanelOverlay = overlay;
        g_mfPanelRootVC = vc;
        overlay.alpha = 0;
        [UIView animateWithDuration:0.25 animations:^{ overlay.alpha = 1; }];
        iaphLog(@"panel: SHOWN (home)");
    } @catch (NSException *e) {
        iaphLog(@"panel EXCEPTION: %@ %@", e.name, e.reason);
    }
}


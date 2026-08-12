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
static void queryOnlineIAP(UIViewController *vc);
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
    int r = dlopen("/System/Library/Frameworks/StoreKit.framework/StoreKit", RTLD_LAZY | RTLD_GLOBAL);
    iaphLog(@"ensureStoreKit: dlopen=%d SKProduct=%@", r, NSClassFromString(@"SKProduct") ? @"loaded" : @"nil");
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
            [alert addAction:[UIAlertAction actionWithTitle:@"本地 ID 全部无效" style:UIAlertActionStyleDefault handler:nil]];
            [alert addAction:[UIAlertAction actionWithTitle:@"在线查询（App Store 兜底）" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                queryOnlineIAP(vc);
            }]];
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

static void showMainMenu(UIViewController *vc);
static void iaphShowPanel(UIViewController *vc);
static void hookShakeBlock(void);
static void hookFakeGPS(void);
static CGFloat mfSectionHeader(UIView *card, CGFloat y, NSString *title);
static CGFloat mfActionRow(UIView *card, CGFloat y, NSString *title, NSString *icon, SEL action);
static CGFloat mfSwitchRow(UIView *card, CGFloat y, NSString *title, NSString *pfx, BOOL def, SEL action, BOOL useSwitch);
static CGFloat mfLabelRow(UIView *card, CGFloat y, NSString *text);
static NSString *mfPermText(id mediaType);

#pragma mark - IAP 列表页（Product ID 列表风格）
@interface IAPHunterVC : UIViewController <UITableViewDataSource, UITableViewDelegate>
@property (nonatomic, retain) NSMutableArray *items;   // {pid, price, title}
@property (nonatomic, copy) void (^onBuy)(NSString *pid);
@property (nonatomic, copy) void (^onRefresh)(void);
- (void)updateWithProducts:(NSArray *)products;
- (void)setCountLabel;
@end

@implementation IAPHunterVC {
    UITableView *_tv;
    UILabel *_countLabel;
    int _detailFetched;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Product ID 列表";
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    // 顶栏：数量状态 + 刷新
    UIView *topBar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, self.view.bounds.size.width, 36)];
    topBar.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    _countLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 8, self.view.bounds.size.width - 120, 20)];
    _countLabel.font = [UIFont systemFontOfSize:13];
    _countLabel.textColor = [UIColor secondaryLabelColor];
    [topBar addSubview:_countLabel];
    [_countLabel release];
    UIButton *refreshBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    refreshBtn.frame = CGRectMake(self.view.bounds.size.width - 84, 4, 68, 28);
    refreshBtn.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin;
    [refreshBtn setTitle:@"刷新" forState:UIControlStateNormal];
    [refreshBtn addTarget:self action:@selector(refreshTapped) forControlEvents:UIControlEventTouchUpInside];
    [topBar addSubview:refreshBtn];
    [self.view addSubview:topBar];
    [topBar release];

    _tv = [[UITableView alloc] initWithFrame:CGRectMake(0, 36, self.view.bounds.size.width, self.view.bounds.size.height - 36)
                                      style:UITableViewStylePlain];
    _tv.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    _tv.dataSource = self;
    _tv.delegate = self;
    [self.view addSubview:_tv];
    [_tv release];

    [self setCountLabel];
}

- (void)setCountLabel {
    if (_countLabel == nil) return;
    int n = (int)self.items.count;
    if (_detailFetched > 0)
        _countLabel.text = [NSString stringWithFormat:@"查询 %d 个 · 已获取详情", n];
    else
        _countLabel.text = [NSString stringWithFormat:@"查询 %d 个⋯", n];
}

- (void)updateWithProducts:(NSArray *)products {
    if (products.count == 0) return;
    for (SKProduct *p in products) {
        NSString *pid = p.productIdentifier;
        for (NSMutableDictionary *item in self.items) {
            if ([[item objectForKey:@"pid"] isEqualToString:pid]) {
                if (p.localizedTitle.length > 0)
                    [item setObject:p.localizedTitle forKey:@"title"];
                NSNumberFormatter *fmt = [[NSNumberFormatter alloc] init];
                fmt.numberStyle = NSNumberFormatterCurrencyStyle;
                fmt.locale = p.priceLocale;
                NSString *ps = [fmt stringFromNumber:p.price];
                [fmt release];
                if (ps.length > 0) [item setObject:ps forKey:@"price"];
                break;
            }
        }
    }
    _detailFetched = (int)products.count;
    [_tv reloadData];
    [self setCountLabel];
}

- (void)refreshTapped {
    if (self.onRefresh) self.onRefresh();
}

#pragma mark - UITableView
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)section {
    return self.items.count;
}

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *cid = @"iap";
    UITableViewCell *cell = [tv dequeueReusableCellWithIdentifier:cid];
    if (cell == nil) {
        cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:cid] autorelease];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
    NSDictionary *item = [self.items objectAtIndex:ip.row];
    cell.textLabel.text = [item objectForKey:@"pid"];
    cell.textLabel.font = [UIFont systemFontOfSize:14];
    cell.textLabel.adjustsFontSizeToFitWidth = YES;
    cell.textLabel.minimumScaleFactor = 0.7;
    NSString *title = [item objectForKey:@"title"];
    cell.detailTextLabel.text = (title.length > 0 ? title : @"点击购买");
    cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    NSString *price = [item objectForKey:@"price"];
    UILabel *pl = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, 100, 22)];
    pl.text = (price.length > 0 ? price : @"?");
    pl.textAlignment = NSTextAlignmentRight;
    pl.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
    pl.textColor = [UIColor labelColor];
    cell.accessoryView = pl;
    [pl release];
    return cell;
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    NSDictionary *item = [self.items objectAtIndex:ip.row];
    NSString *pid = [item objectForKey:@"pid"];
    if (self.onBuy != nil && pid.length > 0) self.onBuy(pid);
}

- (void)dealloc {
    [_tv release];
    [_countLabel release];
    self.items = nil;
    self.onBuy = nil;
    self.onRefresh = nil;
    [super dealloc];
}
@end

// ===== 在线查 IAP（App Store 网页数据 API 转发） =====
static void queryOnlineIAP(UIViewController *vc) {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    if (bundleID.length == 0) bundleID = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleIdentifier"];
    if (bundleID.length == 0) {
        // 兜底：从 bundlePath 反推（xxx.app → xxx）
        NSString *bp = [[NSBundle mainBundle] bundlePath];
        bundleID = [[bp lastPathComponent] stringByDeletingPathExtension];
    }
    if (bundleID.length == 0) {
        UIAlertController *err = [UIAlertController alertControllerWithTitle:@"[IAPHunter]"
                                                                    message:@"无法获取 Bundle ID"
                                                             preferredStyle:UIAlertControllerStyleAlert];
        [err addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:err animated:YES completion:nil];
        return;
    }
    UIAlertController *waiting = [UIAlertController alertControllerWithTitle:@"[IAPHunter] 在线查询"
                                                                    message:[NSString stringWithFormat:@"正在查询 %@ ...", bundleID]
                                                             preferredStyle:UIAlertControllerStyleAlert];
    [vc presentViewController:waiting animated:YES completion:nil];

    NSString *enc = [bundleID stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    NSString *urlStr = [NSString stringWithFormat:@"https://xn--ug8h.eu.org/api/iap?bundleId=%@&country=us", enc];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]
                                                       cachePolicy:NSURLRequestReloadIgnoringCacheData
                                                   timeoutInterval:25];
    [req setValue:@"https://xn--ug8h.eu.org" forHTTPHeaderField:@"Origin"];
    [req setValue:@"https://xn--ug8h.eu.org/iap" forHTTPHeaderField:@"Referer"];
    [req setValue:@"IAPHunter/1.1" forHTTPHeaderField:@"User-Agent"];

    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:
        ^(NSData *data, NSURLResponse *response, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                void (^finish)(UIAlertController *) = ^(UIAlertController *alert) {
                    [waiting dismissViewControllerAnimated:NO completion:^{
                        [vc presentViewController:alert animated:YES completion:nil];
                    }];
                };
                if (error != nil) {
                    UIAlertController *err = [UIAlertController alertControllerWithTitle:@"[IAPHunter] 查询失败"
                                                                                message:error.localizedDescription
                                                                         preferredStyle:UIAlertControllerStyleAlert];
                    [err addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleCancel handler:nil]];
                    finish(err);
                    return;
                }
                NSDictionary *json = nil;
                if (data.length > 0) json = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
                NSArray *iaps = json[@"iaps"];
                if (![iaps isKindOfClass:[NSArray class]] || iaps.count == 0) {
                    NSString *msg = json[@"error"] ?: @"该 app 没有内购";
                    UIAlertController *err = [UIAlertController alertControllerWithTitle:@"[IAPHunter] 无结果"
                                                                                message:[NSString stringWithFormat:@"%@", msg]
                                                                         preferredStyle:UIAlertControllerStyleAlert];
                    [err addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleCancel handler:nil]];
                    finish(err);
                    return;
                }
                NSMutableArray *ids = [NSMutableArray array];
                for (NSDictionary *iap in iaps) {
                    if (![iap isKindOfClass:[NSDictionary class]]) continue;
                    NSString *pid = iap[@"productId"];
                    if (pid.length == 0) continue;
                    [ids addObject:pid];
                }
                if (ids.count > 0) {
                    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
                    NSMutableArray *saved = [[d objectForKey:@"SavedIAPIDs"] mutableCopy];
                    if (saved == nil) saved = [NSMutableArray array];
                    for (NSString *pid in ids) if (![saved containsObject:pid]) [saved addObject:pid];
                    [d setObject:saved forKey:@"SavedIAPIDs"];
                }
                // Product ID 列表：在线拿 ID → 列表展示 → 点击即购
                NSString *appName = json[@"app"][@"name"];
                NSMutableArray *items = [NSMutableArray array];
                for (NSDictionary *iap in iaps) {
                    if (![iap isKindOfClass:[NSDictionary class]]) continue;
                    NSString *pid = iap[@"productId"];
                    if (pid.length == 0) continue;
                    NSString *price = iap[@"priceFormatted"];
                    NSMutableDictionary *item = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                        pid, @"pid",
                        (price.length ? price : @"?"), @"price",
                        @"", @"title",
                        nil];
                    [items addObject:item];
                }
                IAPHunterVC *listVC = [[IAPHunterVC alloc] init];
                listVC.items = items;
                __block IAPHunterVC *blkList = listVC; // MRC: __block 不 retain，防循环引用
                listVC.onBuy = ^(NSString *pid) {
                    IAPRecord(pid);
                    SKPayment *pay = [SKPayment paymentWithProductIdentifier:pid];
                    [[SKPaymentQueue defaultQueue] addPayment:pay];
                };
                listVC.onRefresh = ^{
                    [blkList dismissViewControllerAnimated:YES completion:^{
                        queryOnlineIAP(topVC());
                    }];
                };
                UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:listVC];
                nav.modalPresentationStyle = UIModalPresentationPageSheet;
                // 异步查详情（本地化名称 + 精确价格）
                NSArray *idsCopy = [[ids copy] autorelease];
                [vc presentViewController:nav animated:YES completion:^{
                    [[IAPManager sharedManager] fetchProductsWithIDs:[NSSet setWithArray:idsCopy]
                                                          completion:^(NSArray *products, NSArray *invalid) {
                        [listVC updateWithProducts:products];
                    }];
                }];
                [nav release];
                [listVC release];
                [waiting dismissViewControllerAnimated:NO completion:nil];
            });
        }];
    [task resume];
}

// ================= 图标解锁（移植自 IconSwitcher） =================
// 读 Info.plist CFBundleAlternateIcons 备用图标列表 → 弹窗选择 → setAlternateIconName 切换
static void iaphShowIconSwitcher(UIViewController *vc) {
    if (vc == nil) return;
    UIApplication *app = [UIApplication sharedApplication];
    if (![app respondsToSelector:@selector(supportsAlternateIcons)] || !app.supportsAlternateIcons) {
        UIAlertController *err = [UIAlertController alertControllerWithTitle:@"[MinisFix]"
                                                                     message:@"当前 app 不支持切换图标"
                                                              preferredStyle:UIAlertControllerStyleAlert];
        [err addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:err animated:YES completion:nil];
        return;
    }
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"[MinisFix] 图标解锁"
                                                                  message:@"选择要切换的图标"
                                                           preferredStyle:UIAlertControllerStyleActionSheet];
    [sheet addAction:[UIAlertAction actionWithTitle:@"默认图标" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        [app setAlternateIconName:nil completionHandler:nil];
    }]];
    NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
    NSDictionary *iconsDict = info[@"CFBundleIcons"];
    NSDictionary *alt = iconsDict[@"CFBundleAlternateIcons"];
    for (NSString *name in alt) {
        [sheet addAction:[UIAlertAction actionWithTitle:name style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            [app setAlternateIconName:name completionHandler:nil];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    if (sheet.popoverPresentationController != nil) {
        sheet.popoverPresentationController.sourceView = vc.view;
        sheet.popoverPresentationController.sourceRect = vc.view.bounds;
        sheet.popoverPresentationController.permittedArrowDirections = 0;
    }
    [vc presentViewController:sheet animated:YES completion:nil];
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

static UIWindow *g_mfPanelWindow = nil;
static id g_mfCtrl = nil;

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
// 动态创建 CLLocation（避免链接 CoreLocation.framework——v2.1.1 注入成功版无此链接）
static id makeFakeLocation(void) {
    Class locCls = objc_getClass("CLLocation");
    if (!locCls) return nil;
    id loc = [locCls alloc];
    SEL initSel = NSSelectorFromString(@"initWithLatitude:longitude:");
    if (!initSel) return nil;
    return ((id(*)(id, SEL, double, double))objc_msgSend)(loc, initSel, 39.9042, 116.4074);  // 北京
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

#pragma mark - 面板控制器（按钮/开关回调）
@interface MFPanelCtrl : NSObject
@end
@implementation MFPanelCtrl
- (void)mfSwitchChanged:(UISwitch *)sw {
    NSString *key = objc_getAssociatedObject(sw, "pfx");
    if (!key) return;
    mfSetBoolPref(key, sw.on);
}
- (void)mfDismissPanel { 
    if (g_mfPanelWindow) {
        UIWindow *w = g_mfPanelWindow;
        [UIView animateWithDuration:0.2 animations:^{ w.alpha = 0; } completion:^(BOOL f) {
            w.hidden = YES; g_mfPanelWindow = nil;
        }];
    }
}
- (void)mfScanProducts { queryOnlineIAP(g_mfPanelWindow.rootViewController); [self mfDismissPanel]; }
- (void)mfManualBuy { queryOnlineIAP(g_mfPanelWindow.rootViewController); [self mfDismissPanel]; }
- (void)mfIconSwitch { iaphShowIconSwitcher(g_mfPanelWindow.rootViewController); [self mfDismissPanel]; }
- (void)mfToggleEnabled { 
    mfSetBoolPref(@"iaphIsEnabled", !mfPrefBool(@"iaphIsEnabled", NO));
}
@end

#pragma mark - 面板构建
static void iaphShowPanel(UIViewController *vc) {
    if (g_mfPanelWindow) return;
    if (!g_mfCtrl) g_mfCtrl = [[MFPanelCtrl alloc] init];

    FILE *plog = fopen("/var/jb/var/mobile/Documents/iaph_panel.log", "a");
    #define PLOG(...) do { if (plog) { flockfile(plog); fprintf(plog, __VA_ARGS__); fprintf(plog, "\n"); fflush(plog); funlockfile(plog); } } while(0)
    @try {
    PLOG("[panel] show called pid=%d", getpid());
    iaphLog(@"panel: show called vc=%@", NSStringFromClass([vc class]));
    CGRect sb = [UIScreen mainScreen].bounds;
    UIWindow *win = [[UIWindow alloc] initWithFrame:sb];
    win.windowLevel = UIWindowLevelAlert + 100;
    win.backgroundColor = [UIColor clearColor];
    if (@available(iOS 13.0, *)) {
        UIWindowScene *target = nil;
        for (id sc in [UIApplication sharedApplication].connectedScenes) {
            if ([sc isKindOfClass:[UIWindowScene class]] && ((UIWindowScene *)sc).activationState == UISceneActivationStateForegroundActive) {
                target = (UIWindowScene *)sc; break;
            }
        }
        if (!target) target = [UIApplication sharedApplication].keyWindow.windowScene;
        if (target) { win.windowScene = target; PLOG("[panel] scene set"); }
        else PLOG("[panel] NO scene found");
    }
    win.rootViewController = [[UIViewController alloc] init];

    // 遮罩（点击关闭）
    UIButton *mask = [UIButton buttonWithType:UIButtonTypeCustom];
    mask.frame = win.bounds;
    mask.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.35];
    [mask addTarget:g_mfCtrl action:NSSelectorFromString(@"mfDismissPanel") forControlEvents:UIControlEventTouchUpInside];
    [win addSubview:mask];

    CGFloat cardW = sb.size.width - 32;
    CGFloat cardH = 470;
    UIView *card = [[UIView alloc] initWithFrame:CGRectMake(16, (sb.size.height - cardH)/2, cardW, cardH)];
    card.layer.cornerRadius = 22;
    card.clipsToBounds = YES;
    card.layer.borderWidth = 0.5;
    card.layer.borderColor = [[UIColor systemGray3Color] colorWithAlphaComponent:0.5].CGColor;
    // v3.2: 纯色背景（去毛玻璃——注入窗口下毛玻璃可能触发问题）
    card.backgroundColor = [UIColor systemBackgroundColor];

    // 标题栏
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 14, 200, 26)];
    title.text = @"MinisFix";
    title.font = [UIFont boldSystemFontOfSize:18];
    title.textColor = [UIColor labelColor];
    [card addSubview:title];
    UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    closeBtn.frame = CGRectMake(cardW - 44, 12, 32, 32);
    [closeBtn setTitle:@"✕" forState:UIControlStateNormal];
    [closeBtn.titleLabel setFont:[UIFont systemFontOfSize:17]];
    [closeBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfDismissPanel") forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:closeBtn];

    CGFloat y = 52;
    // ── IAP 组 ──
    y = mfSectionHeader(card, y, @"IAP");
    y = mfActionRow(card, y, @"扫描产品", @"magnifyingglass", @selector(mfScanProducts));
    y = mfActionRow(card, y, @"手动购买", @"cart", @selector(mfManualBuy));
    y = mfActionRow(card, y, @"图标解锁", @"app.badge", @selector(mfIconSwitch));
    y = mfSwitchRow(card, y, @"启用 IAPHunter", @"iaphIsEnabled", YES, @selector(mfToggleEnabled), NO);
    // ── 屏蔽 ──
    y = mfSectionHeader(card, y, @"屏蔽");
    y = mfSwitchRow(card, y, @"屏蔽摇一摇", @"iaphShakeBlock", NO, nil, YES);
    // ── 相机 ──
    y = mfSectionHeader(card, y, @"相机");
    y = mfLabelRow(card, y, [NSString stringWithFormat:@"相机权限: %@  麦克风: %@", mfPermText(@"AVMediaTypeVideo"), mfPermText(@"AVMediaTypeAudio")]);
    // ── 伪装 ──
    y = mfSectionHeader(card, y, @"伪装");
    y = mfSwitchRow(card, y, @"Fake GPS（北京）", @"iaphFakeGPS", NO, nil, YES);

    [win addSubview:card];
    win.alpha = 0;
    win.hidden = NO;
    [win makeKeyAndVisible];
    [UIView animateWithDuration:0.25 animations:^{ win.alpha = 1; }];
    g_mfPanelWindow = win;
    PLOG("[panel] shown ok, windowScene=%@", win.windowScene ? @"set" : @"nil");
    iaphLog(@"panel: SHOWN ok (window=%@ root=%@)", win, win.rootViewController);
    } @catch (NSException *e) {
        PLOG("[panel] EXCEPTION: %@ %@", e.name, e.reason);
        iaphLog(@"panel EXCEPTION: %@ %@", e.name, e.reason);
        NSLog(@"[MinisFix] panel exception: %@ %@", e.name, e.reason);
    }
    if (plog) fclose(plog);
}

// 分组标题
static CGFloat mfSectionHeader(UIView *card, CGFloat y, NSString *title) {
    UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(20, y, 200, 22)];
    lb.text = title;
    lb.font = [UIFont boldSystemFontOfSize:13];
    lb.textColor = [UIColor secondaryLabelColor];
    [card addSubview:lb];
    return y + 26;
}
// 动作行（图标 + 文字）
static CGFloat mfActionRow(UIView *card, CGFloat y, NSString *title, NSString *icon, SEL action) {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = CGRectMake(12, y, 300, 40);
    [b setTitle:title forState:UIControlStateNormal];
    [b setTitleColor:[UIColor labelColor] forState:UIControlStateNormal];
    b.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
    b.titleLabel.font = [UIFont systemFontOfSize:15];
    b.titleEdgeInsets = UIEdgeInsetsMake(0, 30, 0, 0);
    b.backgroundColor = [UIColor secondarySystemBackgroundColor];
    b.layer.cornerRadius = 10;
    if (action) [b addTarget:g_mfCtrl action:action forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:b];
    return y + 46;
}
// 开关行
static CGFloat mfSwitchRow(UIView *card, CGFloat y, NSString *title, NSString *pfx, BOOL def, SEL action, BOOL useSwitch) {
    UIView *row = [[UIView alloc] initWithFrame:CGRectMake(12, y, 300, 40)];
    row.backgroundColor = [UIColor secondarySystemBackgroundColor];
    row.layer.cornerRadius = 10;
    UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(14, 0, 210, 40)];
    lb.text = title;
    lb.font = [UIFont systemFontOfSize:15];
    lb.textColor = [UIColor labelColor];
    [row addSubview:lb];
    if (useSwitch) {
        UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(240, 4, 51, 31)];
        sw.on = mfPrefBool(pfx, def);
        objc_setAssociatedObject(sw, "pfx", pfx, OBJC_ASSOCIATION_RETAIN);
        [sw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfSwitchChanged:") forControlEvents:UIControlEventValueChanged];
        [row addSubview:sw];
    } else if (action) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        b.frame = CGRectMake(240, 4, 60, 32);
        [b setTitle:@"切换" forState:UIControlStateNormal];
        [b addTarget:g_mfCtrl action:action forControlEvents:UIControlEventTouchUpInside];
        [row addSubview:b];
    }
    [card addSubview:row];
    return y + 46;
}
// 信息行
static CGFloat mfLabelRow(UIView *card, CGFloat y, NSString *text) {
    UIView *row = [[UIView alloc] initWithFrame:CGRectMake(12, y, 300, 40)];
    row.backgroundColor = [UIColor secondarySystemBackgroundColor];
    row.layer.cornerRadius = 10;
    UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(14, 0, 272, 40)];
    lb.text = text;
    lb.font = [UIFont systemFontOfSize:13];
    lb.textColor = [UIColor secondaryLabelColor];
    lb.numberOfLines = 0;
    [row addSubview:lb];
    [card addSubview:row];
    return y + 46;
}
// 权限文本
static NSString *mfPermText(id mediaType) {
    Class ac = objc_getClass("AVCaptureDevice");
    if (!ac) return @"n/a";
    SEL ssel = NSSelectorFromString(@"authorizationStatusForMediaType:");
    if (![ac respondsToSelector:ssel]) return @"n/a";
    int s = (int)[ac performSelector:ssel withObject:mediaType];
    switch (s) {
        case 0: return @"未决定";
        case 1: return @"受限";
        case 2: return @"拒绝";
        case 3: return @"已授权";
        default: return @"?";
    }
}

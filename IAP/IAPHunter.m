// IAPHunter.m — IAP 产品 ID 全链路自动收集 + 可视化面板（合体版）
// 纯 ObjC，无 substrate 依赖。摇一摇/长按呼出面板。
// 编译: xcrun --sdk iphoneos clang -arch arm64 -fno-objc-arc -dynamiclib -O2 \
//       IAPHunter.m -o IAPHunter.dylib -framework Foundation -framework UIKit -framework StoreKit

#import <Foundation/Foundation.h>
#import <StoreKit/StoreKit.h>
#import <UIKit/UIKit.h>
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
    if (NSClassFromString(@"SKProduct") != nil) return;
    dlopen("/System/Library/Frameworks/StoreKit.framework/StoreKit", RTLD_LAZY | RTLD_GLOBAL);
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

static void showMainMenu(UIViewController *vc) {
    if (vc == nil) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"[IAPHunter]"
                                                                  message:@"IAP 可视化器"
                                                           preferredStyle:UIAlertControllerStyleActionSheet];
    [sheet addAction:[UIAlertAction actionWithTitle:@"扫描并列出 IAP 产品" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSArray *saved = [d objectForKey:@"SavedIAPIDs"];
        if (saved.count == 0) {
            // 本地无收集到 ID → 在线兜底（App Store 网页 API）
            queryOnlineIAP(vc);
            return;
        }
        [[IAPManager sharedManager] fetchProductsWithIDs:[NSSet setWithArray:saved]];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"手动输入 ProductID 购买" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        UIAlertController *input = [UIAlertController alertControllerWithTitle:@"[IAPHunter] 手动购买"
                                                                       message:@"输入 IAP 产品 ID"
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [input addTextFieldWithConfigurationHandler:^(UITextField *tf) {
            tf.placeholder = @"com.xxx.productid";
            tf.keyboardType = UIKeyboardTypeASCIICapable;
        }];
        [input addAction:[UIAlertAction actionWithTitle:@"购买" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            NSString *pid = [input.textFields.firstObject.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (pid.length == 0) return;
            IAPRecord(pid);
            SKPayment *pay = [SKPayment paymentWithProductIdentifier:pid];
            [[SKPaymentQueue defaultQueue] addPayment:pay];
        }]];
        [input addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:input animated:YES completion:nil];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"查看已收集 ID" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSArray *saved = [d objectForKey:@"SavedIAPIDs"];
        NSString *body = saved.count ? [saved componentsJoinedByString:@"\n"] : @"（空）";
        UIAlertController *list = [UIAlertController alertControllerWithTitle:@"[IAPHunter] 已收集 ID"
                                                                     message:body
                                                              preferredStyle:UIAlertControllerStyleAlert];
        [list addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleCancel handler:nil]];
        [vc presentViewController:list animated:YES completion:nil];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    // iPad popover 需要 sourceView
    if (sheet.popoverPresentationController != nil) {
        sheet.popoverPresentationController.sourceView = vc.view;
        sheet.popoverPresentationController.sourceRect = vc.view.bounds;
        sheet.popoverPresentationController.permittedArrowDirections = 0;
    }
    [vc presentViewController:sheet animated:YES completion:nil];
}

// 长按手势 action
static void longPressAction(id self, SEL _cmd, UILongPressGestureRecognizer *g) {
    if (g.state != UIGestureRecognizerStateBegan) return;
    showMainMenu((UIViewController *)self);
}

// ================= Hook 实现 =================
static IMP orig_viewDidAppear;
static void new_viewDidAppear(id self, SEL _cmd, BOOL animated) {
    ((void(*)(id, SEL, BOOL))orig_viewDidAppear)(self, _cmd, animated);
    // 给 view 加长按手势（防重复）
    static const char kLPKey = 0;
    if (objc_getAssociatedObject(self, &kLPKey) == nil) {
        UILongPressGestureRecognizer *lp = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(handleLongPress:)];
        lp.minimumPressDuration = 0.5;
        UIViewController *vc = (UIViewController *)self;
        [vc.view addGestureRecognizer:lp];
        [lp release];
        objc_setAssociatedObject(self, &kLPKey, @"1", OBJC_ASSOCIATION_RETAIN);
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
// v2.0: Settings → IAPHunter → 启用（preferenceloader 开关——写 /var/jb/var/mobile/Library/Preferences/com.linsars.iaphunter.plist）
// 直接读 rootless 文件（initWithSuiteName 在无 group entitlement 的注入进程里读 app 沙盒——读不到设置）
// 默认开；关则 ctor 直接 return（完全禁用——hook/手势都不装）
static BOOL iaphIsEnabled(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@"/var/jb/var/mobile/Library/Preferences/com.linsars.iaphunter.plist"];
    id v = [d objectForKey:@"IAPHunterEnabled"];
    BOOL on = (v == nil) ? YES : [v boolValue];
    return on;
}

// ================= 入口 =================
__attribute__((constructor)) static void IAPHunterCtor(void) {
    @autoreleasepool {
        // v1.3.4: 设置开关——关则完全禁用（不 hook 不加手势，重启 app 生效）
        if (!iaphIsEnabled()) return;

        ensureStoreKit();

        Class UIViewControllerCls = NSClassFromString(@"UIViewController");
        swizzle(UIViewControllerCls, @selector(viewDidAppear:), (IMP)new_viewDidAppear, &orig_viewDidAppear);
        addMethod(UIViewControllerCls, @selector(handleLongPress:), (IMP)longPressAction, "v@:@");

        Class SKProductCls = NSClassFromString(@"SKProduct");
        swizzle(SKProductCls, @selector(productIdentifier), (IMP)new_SKProduct_productIdentifier, &orig_SKProduct_productIdentifier);
        swizzle(NSClassFromString(@"SKPayment"), @selector(productIdentifier), (IMP)new_SKPayment_productIdentifier, &orig_SKPayment_productIdentifier);
        swizzle(NSClassFromString(@"SKPaymentTransaction"), @selector(productIdentifier), (IMP)new_SKPaymentTransaction_productIdentifier, &orig_SKPaymentTransaction_productIdentifier);
        swizzle(NSClassFromString(@"SKProductsRequest"), @selector(initWithProductIdentifiers:), (IMP)new_SKProductsRequest_init, &orig_SKProductsRequest_init);
        swizzle(NSClassFromString(@"SKPaymentQueue"), @selector(addPayment:), (IMP)new_SKPaymentQueue_addPayment, &orig_SKPaymentQueue_addPayment);
        swizzle(NSClassFromString(@"SKProductsResponse"), @selector(products), (IMP)new_SKProductsResponse_products, &orig_SKProductsResponse_products);
        swizzle(NSClassFromString(@"SKProductsResponse"), @selector(invalidProductIdentifiers), (IMP)new_SKProductsResponse_invalid, &orig_SKProductsResponse_invalid);

        // 预热单例，注册交易 observer
        [IAPManager sharedManager];
        // 购买指令接收（SB 版发起：写指令文件 + Darwin 通知，app 内执行购买）
        startBuyPoller();
    }
}


// ============ 购买指令接收（SB 版发起，app 内执行正规购买） ============
static void checkBuyCommand(void) {
    NSString *path = @"/var/mobile/Library/Preferences/com.linsars.iaphunter.cmd.plist";
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
        iaphBuyNotify, CFSTR("com.linsars.iaphunter.buy"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    // 轮询兜底（app 刚启动 / 通知丢失时）
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        while (1) {
            @autoreleasepool { checkBuyCommand(); }
            [NSThread sleepForTimeInterval:3.0];
        }
    });
}

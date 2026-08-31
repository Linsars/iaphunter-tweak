// MFSubInject.m — 订阅 SDK 响应注入 (通杀实验 v2.10.0)
// 层次定位: RevenueCat / Superwall / Adapty 云端订阅判定 → 进程内伪造 200 响应
// 与 SK1 通杀(本地交易伪造)互补——app 把订阅状态存云端时, SK1 假交易救不了, 这里救
// 商品 ID 来自 SK1 扫描列表(SavedIAPIDs), 无 per-app 硬编码
// schema 来源: Reven 网关实测(2026-08-31) + SatellaJailed ServerVerificationHooks

#import "MFPanel.h"
#import <Foundation/Foundation.h>

static BOOL g_subOn = NO;
static IMP orig_dtReq = NULL, orig_dtURL = NULL;
static long g_subHits = 0;

#pragma mark - 商品 ID 源(SK1 扫描列表)

NSArray *mfSubPids(void) { // 非 static: MFReceiptForge.m 共用
    NSArray *p = [[NSUserDefaults standardUserDefaults] objectForKey:@"SavedIAPIDs"];
    NSMutableArray *clean = [NSMutableArray array];
    for (NSString *pid in p) {
        if (![pid isKindOfClass:[NSString class]]) continue;
        // JSON 安全: 剥引号/反斜杠/控制符
        NSString *s = [pid stringByReplacingOccurrencesOfString:@"\"" withString:@""];
        s = [s stringByReplacingOccurrencesOfString:@"\\" withString:@""];
        NSCharacterSet *bad = [[NSCharacterSet controlCharacterSet] invertedSet];
        s = [[s componentsSeparatedByCharactersInSet:bad] componentsJoinedByString:@""];
        if (s.length && s.length <= 200) [clean addObject:s];
    }
    if (clean.count) return clean;
    return @[@"com.mf.premium.lifetime"];
}

static NSString *mfSubNowISO(void) {
    static NSISO8601DateFormatter *f = nil;
    if (!f) { f = [NSISO8601DateFormatter new]; f.formatOptions = NSISO8601DateFormatWithInternetDateTime; }
    return [f stringFromDate:[NSDate date]];
}

#pragma mark - 目标匹配(host 白名单制, 不做关键词 shotgun)

static BOOL mfSubIsTarget(NSURL *u) {
    if (!u.host) return NO;
    NSString *h = u.host.lowercaseString, *p = u.path ?: @"";
    if ([h isEqualToString:@"api.revenuecat.com"] || [h isEqualToString:@"api.rc-backup.com"])
        return [p containsString:@"/subscribers"] || [p hasSuffix:@"/receipts"];
    if ([h isEqualToString:@"subscriptions-api.superwall.com"])
        return YES; // SW SDK 的 session/events 响应均携带 entitlement 数据
    if ([h isEqualToString:@"api.adapty.io"] || [h isEqualToString:@"api-backup.adapty.io"])
        return [p containsString:@"/in-apps"] || [p containsString:@"/profiles"] || [p containsString:@"/purchase"];
    // v2.11.0: 客户端直调 verifyReceipt 的老 app
    if ([h isEqualToString:@"buy.itunes.apple.com"] || [h isEqualToString:@"sandbox.itunes.apple.com"])
        return [p hasSuffix:@"/verifyReceipt"];
    return NO;
}

#pragma mark - 响应构造

static NSString *mfSubJSON(NSURL *u) {
    NSString *h = u.host.lowercaseString;
    NSArray *pids = mfSubPids();
    NSString *pid0 = pids.firstObject;
    NSString *now = mfSubNowISO();
    NSString *far = @"2099-09-09T09:09:09Z";

    if ([h isEqualToString:@"api.revenuecat.com"] || [h isEqualToString:@"api.rc-backup.com"]) {
        NSMutableString *subs = [NSMutableString string];
        for (NSString *pid in pids)
            [subs appendFormat:@"%@{\"%@\":{\"is_sandbox\":false,\"ownership_type\":\"PURCHASED\",\"store\":\"app_store\",\"original_purchase_date\":\"%@\",\"purchase_date\":\"%@\",\"expires_date\":\"%@\"}}",
             subs.length ? @"," : @"", pid, now, now, far];
        NSString *ent = [NSString stringWithFormat:@"\"pro\":{\"is_sandbox\":false,\"ownership_type\":\"PURCHASED\",\"store\":\"app_store\",\"original_purchase_date\":\"%@\",\"purchase_date\":\"%@\",\"expires_date\":\"%@\",\"product_identifier\":\"%@\"}", now, now, far, pid0];
        return [NSString stringWithFormat:
            @"{\"request_date\":\"%@\",\"request_date_ms\":%lld,\"subscriber\":{"
            @"\"entitlements\":{%@},"
            @"\"subscriptions\":{%@},"
            @"\"non_subscriptions\":{},\"other_purchases\":{},"
            @"\"first_seen\":\"%@\",\"last_seen\":\"%@\","
            @"\"original_app_user_id\":\"mf-user\",\"management_url\":\"https://apps.apple.com\"}}",
            now, (long long)([[NSDate date] timeIntervalSince1970] * 1000), ent, subs, now, now];
    }

    if ([h isEqualToString:@"subscriptions-api.superwall.com"]) {
        NSMutableString *parr = [NSMutableString string];
        for (NSString *pid in pids)
            [parr appendFormat:@"%@\"%@\"", parr.length ? @"," : @"", pid];
        return [NSString stringWithFormat:
            @"{\"entitlements\":[\"pro\"],\"customerInfo\":{\"subscriptions\":[],\"nonSubscriptions\":[],"
            @"\"entitlements\":[{\"identifier\":\"pro\",\"type\":\"SERVICE_LEVEL\",\"isActive\":true,"
            @"\"productIds\":[%@],\"isLifetime\":true,\"willRenew\":true,\"startsAt\":\"%@\",\"expiresAt\":\"%@\"}]}}",
            parr, now, far];
    }

    // v2.11.0: Apple verifyReceipt JSON(in_app 来自扫描列表)
    if ([h isEqualToString:@"buy.itunes.apple.com"] || [h isEqualToString:@"sandbox.itunes.apple.com"]) {
        NSMutableString *inApp = [NSMutableString string];
        long long i = 0;
        for (NSString *pid in pids) {
            [inApp appendFormat:@"%@{\"quantity\":\"1\",\"product_id\":\"%@\",\"transaction_id\":\"mfsk1.vr.%lld\","
             @"\"original_transaction_id\":\"mfsk1.vr.%lld\",\"purchase_date\":\"%@\",\"original_purchase_date\":\"%@\","
             @"\"expires_date\":\"2099-09-09T09:09:09Z\",\"is_trial_period\":\"false\"}",
             inApp.length ? @"," : @"", pid, i, i, now, now];
            i++;
        }
        return [NSString stringWithFormat:
            @"{\"status\":0,\"environment\":\"Production\","
            @"\"receipt\":{\"receipt_type\":\"Production\",\"adam_id\":100000,\"app_item_id\":100000,"
            @"\"bundle_id\":\"%@\",\"application_version\":\"%@\",\"download_id\":100000,"
            @"\"version_external_identifier\":0,\"original_application_version\":\"1.0\","
            @"\"request_date\":\"%@\",\"receipt_creation_date\":\"%@\",\"original_purchase_date\":\"%@\","
            @"\"in_app\":[%@]},"
            @"\"latest_receipt_info\":[%@],"
            @"\"pending_renewal_info\":[{\"auto_renew_product_id\":\"%@\",\"product_id\":\"%@\","
            @"\"original_transaction_id\":\"mfsk1.vr.0\",\"auto_renew_status\":\"1\"}],"
            @"\"latest_receipt\":\"mfsk1-blob\"}",
            [NSBundle mainBundle].bundleIdentifier ?: @"com.mf.unknown",
            [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"1.0",
            now, now, now, inApp, inApp, pids.firstObject ?: @"com.mf.product", pids.firstObject ?: @"com.mf.product"];
    }

    // Adapty
    return [NSString stringWithFormat:
        @"{\"profile_id\":\"mf-user\",\"access_levels\":{\"premium\":{\"id\":\"premium\",\"isActive\":true,"
        @"\"will_renew\":true,\"is_lifetime\":true,\"vendor_product_id\":\"%@\",\"store\":\"app_store\","
        @"\"starts_at\":\"%@\",\"expires_at\":\"%@\",\"renewed_at\":\"%@\"}},"
        @"\"subscriptions\":{\"%@\":{\"vendor_product_id\":\"%@\",\"store\":\"app_store\",\"is_active\":true,"
        @"\"is_lifetime\":true,\"expires_at\":\"%@\"}},\"non_subscriptions\":{},\"is_active\":true}",
        pid0, now, far, far, pid0, pid0, far];
}

#pragma mark - Hook(包装 completionHandler, 网络照发, 响应替换)

typedef id (*DTReqIMP)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
typedef id (*DTURLIMP)(id, SEL, NSURL *, void (^)(NSData *, NSURLResponse *, NSError *));

static void mfSubDeliver(NSURL *u, void (^h)(NSData *, NSURLResponse *, NSError *)) {
    g_subHits++;
    NSString *json = mfSubJSON(u);
    NSData *d = [json dataUsingEncoding:NSUTF8StringEncoding];
    NSHTTPURLResponse *r = [[NSHTTPURLResponse alloc] initWithURL:u statusCode:200
                                                     HTTPVersion:@"HTTP/1.1"
                                                 headerFields:@{@"Content-Type": @"application/json"}];
    mfLog(@"[subinject] #%ld mock %@%@", g_subHits, u.host, u.path);
    h(d, r, nil);
}

static id mf_dtReq(id self, SEL _cmd, NSURLRequest *req, void (^handler)(NSData *, NSURLResponse *, NSError *)) {
    if (!g_subOn || !handler || !req.URL || !mfSubIsTarget(req.URL))
        return ((DTReqIMP)orig_dtReq)(self, _cmd, req, handler);
    NSURL *u = req.URL;
    return ((DTReqIMP)orig_dtReq)(self, _cmd, req, ^(NSData *d, NSURLResponse *r, NSError *e) {
        mfSubDeliver(u, handler); // 吞掉真实响应
    });
}

static id mf_dtURL(id self, SEL _cmd, NSURL *u, void (^handler)(NSData *, NSURLResponse *, NSError *)) {
    if (!g_subOn || !handler || !u || !mfSubIsTarget(u))
        return ((DTURLIMP)orig_dtURL)(self, _cmd, u, handler);
    return ((DTURLIMP)orig_dtURL)(self, _cmd, u, ^(NSData *d, NSURLResponse *r, NSError *e) {
        mfSubDeliver(u, handler);
    });
}

#pragma mark - 开关/持久化

void mfSubInjectEnable(void) {
    if (g_subOn) return;
    Class c = [NSURLSession class];
    Method m1 = class_getInstanceMethod(c, @selector(dataTaskWithRequest:completionHandler:));
    Method m2 = class_getInstanceMethod(c, @selector(dataTaskWithURL:completionHandler:));
    if (!m1 || !m2) { mfLog(@"[subinject] hook fail: selector missing"); return; }
    orig_dtReq = method_setImplementation(m1, (IMP)mf_dtReq);
    orig_dtURL = method_setImplementation(m2, (IMP)mf_dtURL);
    g_subOn = YES;
    mfLog(@"[subinject] hooks ON");
}

void mfSubInjectDisable(void) {
    if (!g_subOn) return;
    Class c = [NSURLSession class];
    Method m1 = class_getInstanceMethod(c, @selector(dataTaskWithRequest:completionHandler:));
    Method m2 = class_getInstanceMethod(c, @selector(dataTaskWithURL:completionHandler:));
    if (m1 && orig_dtReq) method_setImplementation(m1, orig_dtReq);
    if (m2 && orig_dtURL) method_setImplementation(m2, orig_dtURL);
    orig_dtReq = orig_dtURL = NULL;
    g_subOn = NO;
    mfLog(@"[subinject] hooks OFF");
}

void mfSubInjectSwitchChanged(UISwitch *sw) {
    if (sw.on) { mfSubInjectEnable(); mfToast(@"📡 订阅 SDK 注入已开启"); }
    else { mfSubInjectDisable(); mfToast(@"⏹️ 订阅 SDK 注入已关闭"); }
    [[NSUserDefaults standardUserDefaults] setBool:sw.on forKey:@"mfSubInjectEnabled"];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

void mfSubInjectAutoStart(void) {
    if (![[NSUserDefaults standardUserDefaults] boolForKey:@"mfSubInjectEnabled"]) return;
    mfSubInjectEnable();
}

long mfSubInjectHits(void) { return g_subHits; }
BOOL mfSubInjectIsOn(void) { return g_subOn; }

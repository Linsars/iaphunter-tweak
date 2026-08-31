// MFKillAllLab.m — 通杀实验页 (v2.10.0)
// Product 板块下的实验性通杀聚合: SK1 本地交易伪造 + 订阅 SDK 云端响应注入
// 开关迁移: SK1 开关从 ObjC 规则页移入此处(ObjC 页保留方法, 双入口同状态)

#import "MFPanel.h"
#import <UIKit/UIKit.h>

void mfSK1SwitchChanged(UISwitch *sw);      // MFObjCHook.m
void mfSubInjectSwitchChanged(UISwitch *sw); // MFSubInject.m
void mfReceiptForgeSwitchChanged(UISwitch *sw); // MFReceiptForge.m
void mfJudgeTakeoverSwitchChanged(UISwitch *sw); // MFObjCHook.m
long mfSubInjectHits(void);
BOOL mfSubInjectIsOn(void);
long mfReceiptForgeHits(void);
BOOL mfReceiptForgeIsOn(void);

// 宿主 app 是否接入了订阅 SDK(面板内提示用, 不阻断)
static NSString *mfLabDetectSDKs(void) {
    NSMutableArray *found = [NSMutableArray array];
    if (NSClassFromString(@"RevenueCatServices") || objc_getClass("RCPurchases"))
        [found addObject:@"RevenueCat"];
    if (NSClassFromString(@"SuperwallKitManager") || objc_getClass("SWManager"))
        [found addObject:@"Superwall"];
    if (objc_getClass("Adapty"))
        [found addObject:@"Adapty"];
    if (NSClassFromString(@"Qonversion"))
        [found addObject:@"Qonversion"];
    if (objc_getClass("ApphudSDK"))
        [found addObject:@"Apphud"];
    return found.count ? [found componentsJoinedByString:@", "] : @"未检测到";
}

void mfShowKillAllLabPage(void) {
    UIView *page = mfMakePage(@"🧪 通杀实验", YES);
    CGFloat cw = g_mfCardW;
    CGFloat y = 54;

    // 状态行
    UILabel *st = [[UILabel alloc] initWithFrame:CGRectMake(16, y, cw - 32, 16)];
    st.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    st.textColor = [UIColor secondaryLabelColor];
    [page addSubview:st];
    y += 24;

    // 层 1: SK1 本地交易伪造
    UIView *r1 = [[UIView alloc] initWithFrame:CGRectMake(12, y, cw - 24, 56)];
    r1.backgroundColor = [UIColor secondarySystemBackgroundColor];
    r1.layer.cornerRadius = 10;
    UILabel *l1 = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, cw - 110, 40)];
    l1.numberOfLines = 2;
    l1.text = @"⚡ SK1 通杀\n伪造已购交易 — 本地判定类 app";
    l1.font = [UIFont systemFontOfSize:12];
    [r1 addSubview:l1];
    UISwitch *sw1 = [[UISwitch alloc] initWithFrame:CGRectMake(cw - 24 - 66, 12, 51, 31)];
    sw1.on = [[NSUserDefaults standardUserDefaults] boolForKey:@"mfSK1Enabled"];
    [sw1 addTarget:g_mfCtrl action:NSSelectorFromString(@"mfSK1SwitchChanged:") forControlEvents:UIControlEventValueChanged];
    [r1 addSubview:sw1];
    [page addSubview:r1];
    y += 64;

    // 层 2: 订阅 SDK 云端响应注入
    UIView *r2 = [[UIView alloc] initWithFrame:CGRectMake(12, y, cw - 24, 56)];
    r2.backgroundColor = [UIColor secondarySystemBackgroundColor];
    r2.layer.cornerRadius = 10;
    UILabel *l2 = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, cw - 110, 40)];
    l2.numberOfLines = 2;
    l2.text = @"📡 订阅 SDK 注入\nRevenueCat/Superwall/Adapty 云端判定类";
    l2.font = [UIFont systemFontOfSize:12];
    [r2 addSubview:l2];
    UISwitch *sw2 = [[UISwitch alloc] initWithFrame:CGRectMake(cw - 24 - 66, 12, 51, 31)];
    sw2.on = [[NSUserDefaults standardUserDefaults] boolForKey:@"mfSubInjectEnabled"];
    [sw2 addTarget:g_mfCtrl action:NSSelectorFromString(@"mfSubInjectSwitchChanged:") forControlEvents:UIControlEventValueChanged];
    [r2 addSubview:sw2];
    [page addSubview:r2];
    y += 64;

    // 层 3: 收据伪造
    UIView *r3 = [[UIView alloc] initWithFrame:CGRectMake(12, y, cw - 24, 56)];
    r3.backgroundColor = [UIColor secondarySystemBackgroundColor];
    r3.layer.cornerRadius = 10;
    UILabel *l3 = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, cw - 110, 40)];
    l3.numberOfLines = 2;
    l3.text = @"🧾 收据伪造\n本地解析收据判定类(Picsew 等)";
    l3.font = [UIFont systemFontOfSize:12];
    [r3 addSubview:l3];
    UISwitch *sw3 = [[UISwitch alloc] initWithFrame:CGRectMake(cw - 24 - 66, 12, 51, 31)];
    sw3.on = [[NSUserDefaults standardUserDefaults] boolForKey:@"mfReceiptForgeEnabled"];
    [sw3 addTarget:g_mfCtrl action:NSSelectorFromString(@"mfReceiptForgeSwitchChanged:") forControlEvents:UIControlEventValueChanged];
    [r3 addSubview:sw3];
    [page addSubview:r3];
    y += 66;

    // 层 4: 判定接管
    UIView *r4 = [[UIView alloc] initWithFrame:CGRectMake(12, y, cw - 24, 56)];
    r4.backgroundColor = [UIColor secondarySystemBackgroundColor];
    r4.layer.cornerRadius = 10;
    UILabel *l4 = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, cw - 110, 40)];
    l4.numberOfLines = 2;
    l4.text = @"🎯 判定接管\n订阅中心注入 isSubscribed=YES 实例";
    l4.font = [UIFont systemFontOfSize:12];
    [r4 addSubview:l4];
    UISwitch *sw4 = [[UISwitch alloc] initWithFrame:CGRectMake(cw - 24 - 66, 12, 51, 31)];
    sw4.on = [[NSUserDefaults standardUserDefaults] boolForKey:@"mfJudgeTakeoverEnabled"];
    [sw4 addTarget:g_mfCtrl action:NSSelectorFromString(@"mfJudgeTakeoverSwitchChanged:") forControlEvents:UIControlEventValueChanged];
    [r4 addSubview:sw4];
    [page addSubview:r4];
    y += 64;

    // SDK 检测提示
    UILabel *det = [[UILabel alloc] initWithFrame:CGRectMake(16, y, cw - 32, 30)];
    det.font = [UIFont systemFontOfSize:10];
    det.textColor = [UIColor tertiaryLabelColor];
    det.numberOfLines = 2;
    det.text = [NSString stringWithFormat:@"当前 app 订阅 SDK: %@", mfLabDetectSDKs()];
    [page addSubview:det];
    y += 38;

    // 判定侦察按钮
    UIButton *probeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    probeBtn.frame = CGRectMake(12, y, cw - 24, 34);
    probeBtn.backgroundColor = [UIColor systemTealColor];
    probeBtn.layer.cornerRadius = 9;
    probeBtn.tintColor = UIColor.whiteColor;
    [probeBtn setTitle:@"🔍 判定侦察(扫判定方法)" forState:UIControlStateNormal];
    probeBtn.titleLabel.font = [UIFont systemFontOfSize:12];
    [probeBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfJudgeProbeTapped") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:probeBtn];
    y += 42;

    // 说明
    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(16, y, cw - 32, 96)];
    hint.font = [UIFont systemFontOfSize:10];
    hint.textColor = [UIColor tertiaryLabelColor];
    hint.numberOfLines = 0;
    hint.text = @"产品 ID 来自「扫描购买」列表, 三层共用:\n· 本地判定类 → 只开 SK1\n· 云端订阅类 → SK1 + 订阅注入\n· 收据解析类 → SK1 + 收据伪造\n· 严格验签(hash/证书链)的 app 收据层过不了\n· 判定层数据流: 扫描购买→启用→重开 app→恢复购买\n· 实验层, 不保证所有 app 生效";
    [page addSubview:hint];

    objc_setAssociatedObject(page, "labStatus", st, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    // 状态刷新(页面可见期间每 2s)
    __weak UILabel *wst = st;
    dispatch_source_t t = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(t, DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC, 1 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(t, ^{
        if (!wst || !wst.window) { dispatch_source_cancel(t); return; }
        wst.text = [NSString stringWithFormat:@"SK1:%@ 注入:%@(%ld) 收据:%@(%ld)",
            [[NSUserDefaults standardUserDefaults] boolForKey:@"mfSK1Enabled"] ? @"ON" : @"off",
            mfSubInjectIsOn() ? @"ON" : @"off", mfSubInjectHits(),
            mfReceiptForgeIsOn() ? @"ON" : @"off", mfReceiptForgeHits()];
    });
    dispatch_resume(t);

    mfPushPage(page);
}

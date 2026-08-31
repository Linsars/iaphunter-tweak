// MFJudgeProbe.m — v2.13.0 判定函数侦察 (通杀实验 → 🔍 判定侦察)
// 目标: 找出 app 判定 "pro/vip/premium/是否已购" 的方法, 供 ObjC 规则一键 hook
// 思路: 扫描 Paywall 相关类 + 购买管理类的全部方法, 标注:
//   - 返回 BOOL 且 selector 含 pro|premium|vip|purchased|entitle|unlock|subscri 关键词
//   - 存名单到 Documents/MinisFix/judge_hits.plist, 面板列表展示
#import "MFPanel.h"
#import <objc/runtime.h>

static NSArray *g_judgeHits = nil;

void mfJudgeProbeRun(void) {
    Class paywallCls = objc_getClass("Picsew.PaywallViewController");
    NSMutableArray *out = [NSMutableArray array];

    // 关键词(通用, 不针对特定 app)
    NSArray *kws = @[@"pro", @"premium", @"vip", @"purchased", @"purchase", @"entitle",
                     @"unlock", @"subscri", @"isMember", @"isActive", @"receipt", @"upgrad"];
    NSString *selfBundle = [NSBundle mainBundle].bundleIdentifier ?: @"";

    // 候选类: Paywall 相关 + 全进程名字里带 purchase/paywall/premium 的类
    NSMutableArray *classes = [NSMutableArray array];
    if (paywallCls) [classes addObject:paywallCls];
    int n = objc_getClassList(NULL, 0);
    Class *buf = (Class *)malloc(sizeof(Class) * n);
    objc_getClassList(buf, n);
    for (int i = 0; i < n; i++) {
        NSString *nm = NSStringFromClass(buf[i]);
        NSString *low = nm.lowercaseString;
        if ([low containsString:@"paywall"] || [low containsString:@"purchase"] ||
            [low containsString:@"premium"] || [low containsString:@"iapstore"] ||
            [low containsString:@"subscription"] || [low containsString:@"entitlement"]) {
            if (![classes containsObject:buf[i]]) [classes addObject:buf[i]];
        }
    }
    free(buf);

    for (Class cls in classes) {
        NSString *clsName = NSStringFromClass(cls);
        unsigned int cnt = 0;
        Method *ml = class_copyMethodList(cls, &cnt);
        for (unsigned int i = 0; i < cnt; i++) {
            SEL sel = method_getName(ml[i]);
            NSString *selName = NSStringFromSelector(sel);
            NSString *low = selName.lowercaseString;
            BOOL kwHit = NO;
            for (NSString *kw in kws) if ([low containsString:kw]) { kwHit = YES; break; }
            if (!kwHit) continue;
            char ret = 0;
            { char *rt = method_copyReturnType(ml[i]); if (rt) { ret = rt[0]; free(rt); } }
            // 只挑返回 BOOL(char B/BOOL 'c')或对象的判定方法
            NSString *kind = nil;
            if (ret == 'B' || ret == 'c') kind = @"BOOL";
            else if (ret == '@') kind = @"id";
            if (!kind) continue;
            // 方法类型编码 + 前几行实现地址(供 ObjC 规则页定位宿主)
            NSString *typeEnc = [NSString stringWithUTF8String:method_getTypeEncoding(ml[i])] ?: @"";
            [out addObject:@{@"class": clsName, @"sel": selName, @"kind": kind, @"enc": typeEnc}];
        }
        if (ml) free(ml);
    }
    g_judgeHits = out;
    // 落盘: Documents/MinisFix/judge_hits.plist
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *sub = [dir stringByAppendingPathComponent:@"MinisFix"];
    [[NSFileManager defaultManager] createDirectoryAtPath:sub withIntermediateDirectories:YES attributes:nil error:NULL];
    [out writeToFile:[sub stringByAppendingPathComponent:@"judge_hits.plist"] atomically:YES];
    mfLog(@"[judge] classes=%lu hits=%lu saved", (unsigned long)classes.count, (unsigned long)out.count);
    mfToast([NSString stringWithFormat:@"判定侦察完成: %lu 命中", (unsigned long)out.count]);
}

NSArray *mfJudgeHitsSnapshot(void) { return g_judgeHits ?: @[]; }
void mfJudgeProbeAuto(void) {
    // ctor 后 15s 自动跑(等 app 类全部加载) + 监听 paywall 出现后补跑
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ mfJudgeProbeRun(); });
}

// MFRecon.m — 内购模式一次性侦查(扫描时点指纹, 零 hook 零常驻, 纯读)
// 判据沉淀自 Reflix 3.0.5 战役终案(2026-09-05):
//   云验证类   — RC/SW/Adapty 等订阅 SDK 品牌串/域名串/RC 缓存在场 → MFSubInject mock 直达
//   mach 协议类 — 二进制含大立即数 brk 探针(imm 0x800-0xFFF; Reflix=0x965/0x966/0x967/0x9c9/0x9ca/0x9cb,
//               v2.29.1 实测六个 brk 立即数=查询请求码) + 进程异常端口 BREAKPOINT 注册(伴侣 dylib 指纹)
//   双面       — 云+mach 并存(Reflix 正是 RC 云验证 + 本地 license 双因子)
// 全部证据同步落 [recon] 日志, 供远端判读; 判定错漏由证据行兜底

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <string.h>
#import "MFPanel.h"

extern CGFloat g_mfCardW;
extern UIViewController *g_mfPanelRootVC;

// ===== F1 二进制品牌串/域名串(mapped 读, memmem 早退) =====
static const uint8_t *mfRecFind(const uint8_t *hay, size_t hn, const char *ndl) {
    size_t nl = strlen(ndl);
    if (!hay || !nl || hn < nl) return NULL;
    return (const uint8_t *)memmem(hay, hn, ndl, nl);
}

// F3 brk 探针: (w & 0xFFE0001F) == 0xD4200000, imm=(w>>5)&0xFFFF
// 编译器陷阱 brk 用小立即数(#0/#1/#0xb), 大立即数=手写查询码(异常端口客户端特征)
static NSDictionary *mfRecBrkProbe(const uint8_t *p, NSUInteger n) {
    NSUInteger words = n / 4;
    NSMutableDictionary *imms = [NSMutableDictionary dictionary]; // imm -> count
    uint32_t total = 0;
    const uint32_t *w = (const uint32_t *)p;
    for (NSUInteger i = 0; i < words; i++) {
        uint32_t insn = w[i];
        if ((insn & 0xFFE0001F) != 0xD4200000) continue;
        total++;
        uint32_t imm = (insn >> 5) & 0xFFFF;
        if (imm >= 0x800 && imm <= 0xFFF) {
            NSString *k = [NSString stringWithFormat:@"0x%03x", imm];
            imms[k] = @([imms[k] unsignedIntegerValue] + 1);
        }
    }
    return @{@"total": @(total), @"probes": imms};
}

NSDictionary *mfReconFingerprint(void) {
    NSMutableArray *lines = [NSMutableArray array];
    BOOL cloud = NO, mach = NO;
    NSString *exe = [[NSBundle mainBundle] executablePath];
    NSData *d = exe ? [NSData dataWithContentsOfFile:exe options:NSDataReadingMappedIfSafe error:NULL] : nil;
    const uint8_t *p = d.bytes;
    NSUInteger n = d.length;
    if (n > 320u * 1024 * 1024) { n = 320u * 1024 * 1024; [lines addObject:@"(二进制超 320MB, 指纹只扫前段)"]; }

    // ---- F1 品牌串/域名串 ----
    NSArray *cloudPats = @[@"api.revenuecat.com", @"rc-backup", @"revenuecat", @"RevenueCat",
        @"superwall", @"Superwall", @"adapty", @"Adapty", @"qonversion", @"Qonversion",
        @"apphud", @"Apphud", @"purchasely", @"Purchasely", @"Glassfy"];
    NSMutableArray *binHits = [NSMutableArray array];
    for (NSString *pat in cloudPats) {
        if (mfRecFind(p, n, pat.UTF8String)) {
            cloud = YES;
            [binHits addObject:pat];
            if (binHits.count <= 6) [lines addObject:[NSString stringWithFormat:@"二进制含订阅 SDK 串: %@", pat]];
        }
    }
    if (binHits.count > 6) [lines addObject:[NSString stringWithFormat:@"…共 %lu 个 SDK 串命中", (unsigned long)binHits.count]];

    // ---- F2 RC 缓存(云响应已到过本机) ----
    if ([[NSUserDefaults standardUserDefaults] objectForKey:@"com.revenuecat.userdefaults.productEntitlementMapping"]) {
        cloud = YES;
        [lines addObject:@"RC 缓存 productEntitlementMapping 在场(云响应已过手)"];
    }

    // ---- F3 brk 探针 ----
    NSDictionary *brk = p ? mfRecBrkProbe(p, n) : nil;
    NSDictionary *probes = brk[@"probes"];
    if (probes.count >= 2) {
        mach = YES;
        NSArray *ks = probes.allKeys;
        NSString *joined = [ks componentsJoinedByString:@","];
        NSString *sample = [ks count] > 5 ?
            [NSString stringWithFormat:@"%@ 等 %lu 种", [joined substringToIndex:MIN(40, joined.length)], (unsigned long)ks.count] :
            [NSString stringWithFormat:@"imm=%@ (%lu 种)", joined, (unsigned long)ks.count];
        [lines addObject:[NSString stringWithFormat:@"brk 探针 %lu 处大立即数(%@) — 异常端口客户端特征", (unsigned long)ks.count, sample]];
    } else {
        [lines addObject:[NSString stringWithFormat:@"brk 探针: 无大立即数站(总 brk %lu 处均为编译器常规)", (unsigned long)[brk[@"total"] unsignedIntegerValue]]];
    }

    // ---- F4 EXCPORTS 实况(伴侣 dylib ctor 注册过就一直在) ----
    {
        exception_mask_t masks[32]; mach_msg_type_number_t cnt = 32;
        mach_port_t ports[32]; exception_behavior_t behs[32]; thread_state_flavor_t flvs[32];
        kern_return_t kr = task_get_exception_ports(mach_task_self(), EXC_MASK_ALL, masks, &cnt, ports, behs, flvs);
        if (kr != KERN_SUCCESS) {
            [lines addObject:[NSString stringWithFormat:@"EXCPORTS 读取失败 kr=%d", kr]];
        } else {
            BOOL found = NO;
            for (mach_msg_type_number_t i = 0; i < cnt; i++) {
                if (ports[i] == MACH_PORT_NULL) continue;
                found = YES;
                BOOL bk = (masks[i] & EXC_MASK_BREAKPOINT) != 0;
                if (bk && (behs[i] & MACH_EXCEPTION_CODES)) {
                    mach = YES;
                    [lines addObject:[NSString stringWithFormat:@"EXCPORTS[%u] mask=0x%x beh=%#x flv=%d ← BREAKPOINT 已注册(Reflix 型指纹)", (unsigned)i, masks[i], behs[i], flvs[i]]];
                } else {
                    [lines addObject:[NSString stringWithFormat:@"EXCPORTS[%u] mask=0x%x beh=%#x flv=%d", (unsigned)i, masks[i], behs[i], flvs[i]]];
                }
            }
            if (!found) [lines addObject:@"EXCPORTS: 全空(无异常端口注册者)"];
        }
    }

    // ---- F5 网络捕获域命中 ----
    {
        NSArray *recs = mfCapturedRecordsSnapshot();
        unsigned hits = 0;
        for (MFNetRecord *r in recs) {
            NSString *u = r.url.lowercaseString;
            if (!u) continue;
            if ([u containsString:@"revenuecat"] || [u containsString:@"rc-backup"] ||
                [u containsString:@"superwall"] || [u containsString:@"adapty"] ||
                [u containsString:@"qonversion"] || [u containsString:@"apphud"] ||
                [u containsString:@"revenue."]) {
                hits++;
                if (hits <= 3) [lines addObject:[NSString stringWithFormat:@"网络捕获命中: %@", r.url]];
            }
        }
        if (hits > 3) [lines addObject:[NSString stringWithFormat:@"…网络捕获共 %u 条云验证域请求", hits]];
        if (!hits) [lines addObject:[NSString stringWithFormat:@"网络捕获 %lu 条记录, 无云验证域(未开捕获或纯本地)", (unsigned long)recs.count]];
        if (hits) cloud = YES;
    }

    // ---- 判定(可叠加: Reflix = 云+mach 双面) ----
    NSString *verdict;
    UIColor *color;
    if (cloud && mach)      verdict = @"云验证 + Mach 探针 双面 — 先 mock 直试, 不亮走录制战役";
    else if (cloud)         verdict = @"云验证 — MFSubInject mock 直达, 扫描购买→点按即可";
    else if (mach)          verdict = @"Mach 探针(Reflix 同款) — 需录制破译战役, 拉日志给管理员";
    else                    verdict = @"未检出云验证/mach 指纹 — 逛购买页+开捕获后重扫";

    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    out[@"verdict"] = verdict;
    out[@"lines"] = lines;
    out[@"cloud"] = @(cloud);
    out[@"mach"] = @(mach);
    return out;
}

// ===== 置顶侦查卡 =====
@interface MFReconCard : UIButton
@end
@implementation MFReconCard
+ (void)showDetail:(UIButton *)btn {
    NSArray *lines = objc_getAssociatedObject(btn, "lines");
    NSDictionary *recon = objc_getAssociatedObject(btn, "recon");
    NSMutableString *msg = [NSMutableString string];
    for (NSString *l in lines) [msg appendFormat:@"%@\n", l];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:[NSString stringWithFormat:@"侦查: %@", recon[@"verdict"]]
        message:msg preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"复制证据" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        UIPasteboard.generalPasteboard.string = msg;
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
    UIViewController *vc = g_mfPanelRootVC;
    if (vc) [vc presentViewController:alert animated:YES completion:nil];
}
@end

// 返回高度 52 的置顶卡(y 由调用方定)
UIView *mfReconMakeCard(NSDictionary *recon) {
    MFReconCard *card = [MFReconCard buttonWithType:UIButtonTypeSystem];
    card.frame = CGRectMake(16, 46, g_mfCardW - 32, 52);
    card.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
    card.layer.cornerRadius = 10;
    BOOL c = [recon[@"cloud"] boolValue], m = [recon[@"mach"] boolValue];
    UILabel *v = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, (g_mfCardW - 32) - 24, 18)];
    v.text = [NSString stringWithFormat:@"侦查: %@", recon[@"verdict"]];
    v.font = [UIFont systemFontOfSize:12.5 weight:UIFontWeightSemibold];
    v.textColor = (c && m) ? [UIColor systemIndigoColor] : c ? [UIColor systemGreenColor] :
                  m ? [UIColor systemPurpleColor] : [UIColor secondaryLabelColor];
    UILabel *sub = [[UILabel alloc] initWithFrame:CGRectMake(12, 28, (g_mfCardW - 32) - 24, 16)];
    sub.text = [NSString stringWithFormat:@"%lu 条证据 · 点看详情", (unsigned long)[recon[@"lines"] count]];
    sub.font = [UIFont systemFontOfSize:10.5];
    sub.textColor = [UIColor tertiaryLabelColor];
    [card addSubview:v]; [card addSubview:sub];
    objc_setAssociatedObject(card, "lines", recon[@"lines"], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(card, "recon", recon, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [card addTarget:[MFReconCard class] action:@selector(showDetail:) forControlEvents:UIControlEventTouchUpInside];
    return card;
}

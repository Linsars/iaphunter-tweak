// ====== MFBatteryInfo.m — 电池详情页 (v2.6.21) ======
// 对标 ChargeLimiter (lich4) 的电池/电源信息面板:
//   IORegistryEntryCreateCFProperties 直读 AppleSmartBattery( iPhone8+ ) /
//   IOPMPowerSource 兜底, 全量属性展示。
// 只读不写, app 进程可安全调用; 5s 自动刷新, 页面 pop 自动停表。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "MFPanel.h"
#import <IOKit/IOMessage.h>
#include <dlfcn.h>

// dlsym 零链接依赖 IOKit
typedef mach_port_t bi_io_t;
static mach_port_t (*bi_IOMasterPort)(mach_port_t, mach_port_t *);
static CFMutableDictionaryRef (*bi_IOServiceMatching)(const char *);
static bi_io_t (*bi_IOServiceGetMatchingService)(mach_port_t, CFMutableDictionaryRef);
static kern_return_t (*bi_IORegistryEntryCreateCFProperties)(bi_io_t, CFMutableDictionaryRef *, CFAllocatorRef, UInt32);
static kern_return_t (*bi_IOObjectRelease)(bi_io_t);

static BOOL biLoadIOKit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *h = dlsym(RTLD_DEFAULT, "IOMasterPort");
        if (!h) h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        if (!h) return;
        bi_IOMasterPort = dlsym(RTLD_DEFAULT, "IOMasterPort");
        bi_IOServiceMatching = dlsym(RTLD_DEFAULT, "IOServiceMatching");
        bi_IOServiceGetMatchingService = dlsym(RTLD_DEFAULT, "IOServiceGetMatchingService");
        bi_IORegistryEntryCreateCFProperties = dlsym(RTLD_DEFAULT, "IORegistryEntryCreateCFProperties");
        bi_IOObjectRelease = dlsym(RTLD_DEFAULT, "IOObjectRelease");
    });
    return bi_IOMasterPort != NULL;
}

NSDictionary *mfBatteryRead(void) {
    if (!biLoadIOKit()) return nil;
    mach_port_t master = 0;
    bi_IOMasterPort(0, &master);
    bi_io_t svc = bi_IOServiceGetMatchingService(master, bi_IOServiceMatching("AppleSmartBattery"));
    if (!svc) svc = bi_IOServiceGetMatchingService(master, bi_IOServiceMatching("IOPMPowerSource"));
    if (!svc) return nil;
    CFMutableDictionaryRef props = NULL;
    if (bi_IORegistryEntryCreateCFProperties(svc, &props, kCFAllocatorDefault, 0) != 0 || !props) {
        bi_IOObjectRelease(svc);
        return nil;
    }
    bi_IOObjectRelease(svc);
    return [(__bridge NSDictionary *)props copy];
}

#pragma mark - 键名中文化与单位换算

static NSString *biFmtVal(NSString *key, id v) {
    if ([v isKindOfClass:[NSDictionary class]]) return nil; // 子字典单独展开
    // 温度: 0.01K → °C
    if ([key isEqualToString:@"Temperature"] || [key isEqualToString:@"VirtualTemperature"]) {
        NSNumber *n = [v isKindOfClass:[NSNumber class]] ? v : nil;
        return n ? [NSString stringWithFormat:@"%.1f °C", n.doubleValue / 100.0] : [v description];
    }
    if ([v isKindOfClass:[NSNumber class]]) return [v stringValue];
    if ([v isKindOfClass:[NSDate class]]) return [v description];
    return [v description] ?: @"—";
}

static NSString *biCName(NSString *key) {
    static NSDictionary *map;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        map = @{
            @"IsCharging":                @"充电中",
            @"ExternalConnected":         @"外部电源连接",
            @"ExternalChargeCapable":     @"允许外部充电",
            @"CurrentCapacity":           @"当前电量 (%)",
            @"AppleRawCurrentCapacity":   @"原始电量 (mAh)",
            @"NominalChargeCapacity":     @"标称满容量 (mAh)",
            @"DesignCapacity":            @"设计容量 (mAh)",
            @"CycleCount":                @"循环次数",
            @"Amperage":                  @"电流 (mA)",
            @"InstantAmperage":           @"瞬时电流 (mA)",
            @"Voltage":                   @"电压 (mV)",
            @"BootVoltage":               @"启动电压 (mV)",
            @"Temperature":               @"电池温度",
            @"VirtualTemperature":        @"虚拟温度",
            @"BatteryInstalled":          @"电池在位",
            @"Serial":                    @"序列号",
            @"UpdateTime":                @"数据更新时间",
            @"PostChargeWaitSeconds":     @"充满后等待 (s)",
            @"PostDischargeWaitSeconds":  @"放电后等待 (s)",
            @"AdapterDetails":            @"⚡️ 电源适配器",
            @"Manufacturer":              @"制造商",
            @"Name":                      @"名称",
            @"Description":               @"描述",
            @"Watts":                     @"功率 (W)",
            @"IsWireless":                @"无线充电",
            @"AdapterVoltage":            @"适配器电压",
            @"Current":                   @"电流",
        };
    });
    return map[key];
}

#pragma mark - 详情页

void mfShowBatteryPage(void);

// 列表模型: 平铺的 (标题, 值) 行
@interface MFBatteryList : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray *rows; // @{t:, v:}
@end
@implementation MFBatteryList
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return self.rows.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *idt = @"mfBatRow";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:idt];
    if (!c) {
        c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:idt];
        c.backgroundColor = UIColor.clearColor;
        c.textLabel.font = [UIFont systemFontOfSize:12];
        c.textLabel.textColor = [UIColor secondaryLabelColor];
        c.detailTextLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
        c.detailTextLabel.textColor = [UIColor labelColor];
        c.selectionStyle = UITableViewCellSelectionStyleNone;
    }
    NSDictionary *r = self.rows[ip.row];
    c.textLabel.text = r[@"t"];
    c.detailTextLabel.text = r[@"v"];
    return c;
}
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSDictionary *r = self.rows[ip.row];
    UIContextualAction *copy = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"复制" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            [UIPasteboard generalPasteboard].string =
                [NSString stringWithFormat:@"%@ = %@", r[@"t"], r[@"v"]];
            done(YES);
        }];
    copy.backgroundColor = [UIColor systemBlueColor];
    return [UISwipeActionsConfiguration configurationWithActions:@[copy]];
}
@end

static NSArray *biBuildRows(void) {
    NSDictionary *d = mfBatteryRead();
    if (!d.count) return @[ @{@"t": @"读取失败", @"v": @"IOKit 不可用"} ];
    NSMutableArray *rows = [NSMutableArray array];
    // 关键项优先
    for (NSString *k in @[@"CurrentCapacity", @"IsCharging", @"ExternalConnected", @"ExternalChargeCapable"]) {
        if (d[k] != nil) [rows addObject:@{@"t": biCName(k) ?: k, @"v": biFmtVal(k, d[k]) ?: @""}];
    }
    for (NSString *k in d) {
        if ([@[@"CurrentCapacity", @"IsCharging", @"ExternalConnected", @"ExternalChargeCapable"] containsObject:k]) continue;
        NSString *cn = biCName(k) ?: k;
        if ([d[k] isKindOfClass:[NSDictionary class]]) {
            [rows addObject:@{@"t": cn, @"v": @""}];
            for (NSString *sk in d[k]) {
                [rows addObject:@{@"t": [NSString stringWithFormat:@"   %@", biCName(sk) ?: sk],
                                  @"v": biFmtVal(sk, d[k][sk]) ?: @""}];
            }
        } else {
            [rows addObject:@{@"t": cn, @"v": biFmtVal(k, d[k]) ?: @""}];
        }
    }
    return rows;
}

void mfShowBatteryPage(void) {
    UIView *page = mfMakePage(@"电池详情", YES);

    UILabel *status = [[UILabel alloc] initWithFrame:CGRectMake(16, 44, g_mfCardW - 32, 18)];
    status.tag = 301;
    status.font = [UIFont systemFontOfSize:11];
    status.textColor = [UIColor tertiaryLabelColor];
    status.text = @"5 秒自动刷新 · 左划复制";
    [page addSubview:status];

    UITableView *tv = [[UITableView alloc] initWithFrame:CGRectMake(0, 64, g_mfCardW, g_mfCardH - 64) style:UITableViewStylePlain];
    tv.tag = 310;
    tv.backgroundColor = [UIColor tertiarySystemBackgroundColor];
    tv.separatorColor = [UIColor separatorColor];
    MFBatteryList *list = [MFBatteryList new];
    list.rows = biBuildRows();
    tv.dataSource = list;
    tv.delegate = list;
    objc_setAssociatedObject(page, "batList", list, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [page addSubview:tv];

    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 5.0 * NSEC_PER_SEC, 0.5 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
        if (!page.superview) { dispatch_source_cancel(timer); return; }
        UITableView *ltv = [page viewWithTag:310];
        MFBatteryList *ll = objc_getAssociatedObject(page, "batList");
        if (!ltv || !ll) return;
        ll.rows = biBuildRows();
        [ltv reloadData];
    });
    dispatch_resume(timer);
    objc_setAssociatedObject(page, "batTimer", timer, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    mfPushPage(page);
}

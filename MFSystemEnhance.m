// MFSystemEnhance.m — 系统增强(仅 SpringBoard 进程,由 MFPanel ctor 定向激活)
// ⚡ 充电限制: IOKit IOPMPowerSource 注册表直写(SB 本身 root,无需子进程)
//    机制来源: LimitCharging(com.zqbb.limitcharging) 逆向确认——IsCharging/PredictiveChargingInhibit
// 📶 Wi-Fi 永连: SBBacklightController allowIdleSleep → NO(阻止空闲睡眠=待机不断网)
// 设计: 开关实时读偏好,改设置即时生效,免 respring

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach/mach.h>

#define SE_PREFS @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"

static NSDictionary *sePrefs(void) {
    return [NSDictionary dictionaryWithContentsOfFile:SE_PREFS] ?: @{};
}

#pragma mark - IOKit 直写(dlsym 零头文件依赖)

typedef mach_port_t se_io_t;
static kern_return_t (*p_IOMasterPort)(mach_port_t, mach_port_t *);
static CFMutableDictionaryRef (*p_IOServiceMatching)(const char *);
static se_io_t (*p_IOServiceGetMatchingService)(mach_port_t, CFMutableDictionaryRef);
static kern_return_t (*p_IORegistryEntrySetCFProperties)(se_io_t, CFTypeRef);
static kern_return_t (*p_IOObjectRelease)(se_io_t);

static BOOL seLoadIOKit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *h = dlsym(RTLD_DEFAULT, "IOMasterPort");
        if (!h) h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        if (!h) return;
        p_IOMasterPort = dlsym(RTLD_DEFAULT, "IOMasterPort");
        p_IOServiceMatching = dlsym(RTLD_DEFAULT, "IOServiceMatching");
        p_IOServiceGetMatchingService = dlsym(RTLD_DEFAULT, "IOServiceGetMatchingService");
        p_IORegistryEntrySetCFProperties = dlsym(RTLD_DEFAULT, "IORegistryEntrySetCFProperties");
        p_IOObjectRelease = dlsym(RTLD_DEFAULT, "IOObjectRelease");
        if (!p_IOMasterPort || !p_IOServiceMatching || !p_IOServiceGetMatchingService ||
            !p_IORegistryEntrySetCFProperties || !p_IOObjectRelease) {
            NSLog(@"[SysEnhance] IOKit symbols missing");
        }
    });
    return p_IOMasterPort != NULL;
}

// v2.6.19: SB 进程无 IAPtools 面板,决策日志双写固定文件(Filza/SSH 直接看)
// 上限 32KB,超过砍半防无限增长
static void seFileLog(NSString *line) {
    static NSString *path = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        path = @"/var/mobile/Documents/minisfix_sysenhance.log";
    });
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSDictionary *attr = [fm attributesOfItemAtPath:path error:nil];
        if ([attr fileSize] > 32768) { // 砍半续命
            NSString *old = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
            if (old.length > 4096)
                [[old substringFromIndex:old.length - 16384] writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) { [@"" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil]; fh = [NSFileHandle fileHandleForWritingAtPath:path]; }
        if (fh) { [fh seekToEndOfFile]; [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
    } @catch (NSException *e) {}
}

// on=YES 恢复充电 / NO=停充
static void seSetCharging(BOOL on) {
    if (!seLoadIOKit()) return;
    mach_port_t master = 0;
    p_IOMasterPort(0, &master);
    se_io_t svc = p_IOServiceGetMatchingService(master, p_IOServiceMatching("IOPMPowerSource"));
    if (!svc) { NSLog(@"[SysEnhance] IOPMPowerSource not found"); return; }
    CFMutableDictionaryRef props = CFDictionaryCreateMutable(kCFAllocatorDefault, 2,
        &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(props, CFSTR("IsCharging"),
                         on ? kCFBooleanTrue : kCFBooleanFalse);
    CFDictionarySetValue(props, CFSTR("PredictiveChargingInhibit"),
                         on ? kCFBooleanFalse : kCFBooleanTrue);
    kern_return_t kr = p_IORegistryEntrySetCFProperties(svc, props);
    CFRelease(props);
    p_IOObjectRelease(svc);
    NSLog(@"[SysEnhance] setCharging(%d) kr=%d", on ? 1 : 0, kr);
}

#pragma mark - 充电上限逻辑(5% 回差防抖)

static int seLastCmd = -1; // -1 未定 / 0 已停 / 1 已恢复

static void seApplyCharge(void) {
    @autoreleasepool {
        NSDictionary *p = sePrefs();
        if (![p[@"mfSysChargeEnabled"] boolValue]) return;
        int limit = [p[@"mfSysChargeLimit"] intValue];
        if (limit <= 0) limit = 90;
        if (limit < 50) limit = 50;
        if (limit > 100) limit = 100;

        UIDevice *dev = [UIDevice currentDevice];
        int lvl = (int)(dev.batteryLevel * 100 + 0.5);
        if (lvl <= 0 || lvl > 100) return;
        BOOL charging = dev.batteryState == UIDeviceBatteryStateCharging;
        int cmd = -1;
        if (charging && lvl >= limit)           cmd = 0; // 到上限停充
        else if (!charging && lvl <= limit - 5) cmd = 1; // 回差恢复
        // v2.6.18 诊断: 决策变化时打出完整依据(rawLimit 原始值排查滑条落盘)
        static int seLastLoggedCmd = -2;
        if (cmd >= 0 && cmd != seLastLoggedCmd) {
            id raw = p[@"mfSysChargeLimit"];
            NSString *msg = [NSString stringWithFormat:
                @"[%@] charge decision: lvl=%d limit=%d rawLimit=%@ (%s) charging=%d",
                [NSDateFormatter localizedStringFromDate:[NSDate date] dateStyle:NSDateFormatterShortStyle timeStyle:NSDateFormatterMediumStyle],
                lvl, limit, raw ?: @"nil", [raw isKindOfClass:[NSNumber class]] ? "num" : "other",
                charging];
            NSLog(@"[SysEnhance] %@", msg);
            seFileLog(msg);
            seLastLoggedCmd = cmd;
        }
        if (cmd >= 0 && cmd != seLastCmd) {
            seSetCharging(cmd == 1);
            seLastCmd = cmd;
        }
    }
}

#pragma mark - Wi-Fi 永连 hook

static BOOL (*orig_allowIdleSleep)(id, SEL);
static BOOL hook_allowIdleSleep(id self, SEL _cmd) {
    if ([[sePrefs() objectForKey:@"mfSysWifiAlwaysOn"] boolValue]) return NO;
    return orig_allowIdleSleep(self, _cmd);
}

#pragma mark - 自启动(v2.4.0 编入 FolderX.dylib,仅 SpringBoard 注入,无需进程守卫)

void mfSystemEnhanceInit(void);

__attribute__((constructor))
static void SystemEnhanceAutoStart(void) {
    // 按开关自启:全关则零 hook 零监听,改开关后 respring 生效
    NSDictionary *p = sePrefs();
    if ([p[@"mfSysChargeEnabled"] boolValue] || [p[@"mfSysWifiAlwaysOn"] boolValue]) {
        mfSystemEnhanceInit();
    }
}

void mfSystemEnhanceInit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // 充电监控:通知常驻,回调内实时判开关
        [UIDevice currentDevice].batteryMonitoringEnabled = YES;
        seApplyCharge();
        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
        void (^blk)(NSNotification *) = ^(NSNotification *n){ seApplyCharge(); };
        [nc addObserverForName:UIDeviceBatteryLevelDidChangeNotification object:nil
                         queue:[NSOperationQueue mainQueue] usingBlock:blk];
        [nc addObserverForName:UIDeviceBatteryStateDidChangeNotification object:nil
                         queue:[NSOperationQueue mainQueue] usingBlock:blk];

        // Wi-Fi 永连:方法替换一次,hook 内实时判开关
        Class sbbc = objc_getClass("SBBacklightController");
        Method m = sbbc ? class_getInstanceMethod(sbbc, @selector(allowIdleSleep)) : NULL;
        if (m && !orig_allowIdleSleep) {
            orig_allowIdleSleep = (BOOL (*)(id, SEL))method_getImplementation(m);
            method_setImplementation(m, (IMP)hook_allowIdleSleep);
        }
        NSLog(@"[SysEnhance] init done (charge monitor + idle-sleep hook)");
    });
}

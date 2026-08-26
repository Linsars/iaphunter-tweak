// ====== MFBatteryServer.m — 电池数据服务端 (v2.6.23, 仅 SpringBoard) ======
// 背景: 普通 app 沙盒 deny IOKit AppleSmartBattery 属性读取(iOS15+),
//   ChargeLimiter 同样场景用 root daemon + 私有 entitlements 解决;
//   我们的有权限进程 = SpringBoard(FolderX 注入), 用 CFMessagePort 提供查询。
// 协议: port 名 "minisfix.battery", msgid=0, 无请求体, 回复 = plist 二进制全量属性。
// 极轻: 一个 mach port 监听, 查询时才读 registry。

#import <Foundation/Foundation.h>
#import <IOKit/IOMessage.h>
#import <mach/mach.h>
#include <dlfcn.h>

typedef mach_port_t bs_io_t;
static mach_port_t (*bs_IOMasterPort)(mach_port_t, mach_port_t *);
static CFMutableDictionaryRef (*bs_IOServiceMatching)(const char *);
static bs_io_t (*bs_IOServiceGetMatchingService)(mach_port_t, CFMutableDictionaryRef);
static kern_return_t (*bs_IORegistryEntryCreateCFProperties)(bs_io_t, CFMutableDictionaryRef *, CFAllocatorRef, UInt32);
static kern_return_t (*bs_IOObjectRelease)(bs_io_t);

static BOOL bsLoadIOKit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *h = dlsym(RTLD_DEFAULT, "IOMasterPort");
        if (!h) h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        if (!h) return;
        bs_IOMasterPort = dlsym(RTLD_DEFAULT, "IOMasterPort");
        bs_IOServiceMatching = dlsym(RTLD_DEFAULT, "IOServiceMatching");
        bs_IOServiceGetMatchingService = dlsym(RTLD_DEFAULT, "IOServiceGetMatchingService");
        bs_IORegistryEntryCreateCFProperties = dlsym(RTLD_DEFAULT, "IORegistryEntryCreateCFProperties");
        bs_IOObjectRelease = dlsym(RTLD_DEFAULT, "IOObjectRelease");
    });
    return bs_IOMasterPort != NULL;
}

static NSDictionary *bsReadBattery(void) {
    if (!bsLoadIOKit()) return nil;
    mach_port_t master = 0;
    bs_IOMasterPort(0, &master);
    bs_io_t svc = bs_IOServiceGetMatchingService(master, bs_IOServiceMatching("AppleSmartBattery"));
    if (!svc) svc = bs_IOServiceGetMatchingService(master, bs_IOServiceMatching("IOPMPowerSource"));
    if (!svc) return nil;
    CFMutableDictionaryRef props = NULL;
    if (bs_IORegistryEntryCreateCFProperties(svc, &props, kCFAllocatorDefault, 0) != 0 || !props) {
        bs_IOObjectRelease(svc);
        return nil;
    }
    bs_IOObjectRelease(svc);
    return [(__bridge NSDictionary *)props copy];
}

static CFDataRef bsCallback(CFMessagePortRef port, SInt32 msgid, CFDataRef data, void *info) {
    @autoreleasepool {
        NSDictionary *props = bsReadBattery();
        NSData *out = [NSPropertyListSerialization dataWithPropertyList:(props ?: @{})
                                                                format:NSPropertyListBinaryFormat_v1_0
                                                               options:0 error:NULL];
        return out ? CFDataCreate(NULL, out.bytes, out.length) : CFDataCreate(NULL, NULL, 0);
    }
}

__attribute__((constructor))
static void BatteryServerAutoStart(void) {
    // 双保险: filter=springboard 已定向, 这里再验身份防误注入
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (![bid isEqualToString:@"com.apple.springboard"]) return;

    static dispatch_once_t once;
    dispatch_once(&once, ^{
        CFMessagePortRef local = CFMessagePortCreateLocal(
            kCFAllocatorDefault, CFSTR("minisfix.battery"), bsCallback, NULL, NULL, FALSE);
        if (!local) {
            NSLog(@"[SysEnhance] battery server create failed");
            return;
        }
        CFMessagePortSetDispatchQueue(local, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
        NSLog(@"[SysEnhance] battery server listening (minisfix.battery)");
    });
}

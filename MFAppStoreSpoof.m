// MFAppStoreSpoof.m — AppStore 版本伪装（独立轻量 dylib）
// 完全参考 AppStoreTroller 逆向反汇编逻辑，用 MSHookMessageEx
// 不依赖 UIKit——只用 Foundation + CydiaSubstrate，daemon 里可加载

#import <Foundation/Foundation.h>
#import <substrate.h>

static NSUserDefaults *prefs;

// ====== NSMutableURLRequest setValue:forHTTPHeaderField: hook ======
// 拦截 App Store 购买请求，修改 User-Agent 里的 iOS 版本号
// AppStoreTroller 逻辑：enabled 检查 + iOSVersion 全局变量（为空跳过修改）
static NSString *g_spoofVersion;  // ctor 里从 prefs 读取，为空则跳过修改
static void (*orig_setValue_forField)(id self, SEL _cmd, NSString *value, NSString *field);

static void hook_setValue_forField(id self, SEL _cmd, NSString *value, NSString *field) {
    // AppStoreTroller: 先检查全局 iOSVersion，为空直接跳过
    if (!g_spoofVersion) {
        orig_setValue_forField(self, _cmd, value, field);
        return;
    }
    if ([field isEqualToString:@"User-Agent"]) {
        NSString *url = [[self URL] absoluteString] ?: @"";
        if ([url containsString:@"WebObjects/MZBuy.woa/wa/buyProduct"]) {
            value = [value stringByReplacingOccurrencesOfString:@"iOS/.*? "
                                                     withString:[NSString stringWithFormat:@"iOS/%@ ", g_spoofVersion]
                                                       options:NSRegularExpressionSearch
                                                         range:NSMakeRange(0, value.length)];
        }
    }
    orig_setValue_forField(self, _cmd, value, field);
}

// ====== MIBundle isMinimumOSVersion hook ======
// 绕过安装版本检查——直接返回 YES
static BOOL (*orig_isMinimumOSVersion)(id self, SEL _cmd, id arg1, id arg2, id arg3, id *arg4);

static BOOL hook_isMinimumOSVersion(id self, SEL _cmd, id arg1, id arg2, id arg3, id *arg4) {
    return YES;
}

// ====== ctor ======
// AppStoreTroller 逻辑：
// 1. 读 prefs enabled 开关——NO 则不 hook appstored
// 2. 读 iOSVersion 存全局变量——hook 函数里用全局变量，为空则跳过修改
// 3. installd 分支不受 enabled 影响——直接 hook
__attribute__((constructor)) static void init(void) {
    @autoreleasepool {
        NSString *processName = [[NSProcessInfo processInfo] processName];
        
        prefs = [[NSUserDefaults alloc] initWithSuiteName:@"dev.mineek.appstoretroller"];
        
        if ([processName isEqualToString:@"appstored"]) {
            // 和 AppStoreTroller 一致：检查 enabled 开关
            if (![prefs boolForKey:@"enabled"]) {
                return;  // disabled → 不注册任何 hook
            }
            // 读 iOSVersion 存全局变量（AppStoreTroller 在 ctor 里一次性读好）
            g_spoofVersion = [[prefs stringForKey:@"iOSVersion"] copy];
            
            Class cls = NSClassFromString(@"NSMutableURLRequest");
            if (cls) {
                SEL sel = @selector(setValue:forHTTPHeaderField:);
                MSHookMessageEx(cls, sel, (IMP)hook_setValue_forField, (IMP *)&orig_setValue_forField);
            }
        } else if ([processName isEqualToString:@"installd"]) {
            // installd 不受 enabled 影响——直接 hook（和 AppStoreTroller 一致）
            Class cls = NSClassFromString(@"MIBundle");
            if (cls) {
                SEL sel = NSSelectorFromString(@"isMinimumOSVersion:applicableToOSVersion:requiredOS:error:");
                MSHookMessageEx(cls, sel, (IMP)hook_isMinimumOSVersion, (IMP *)&orig_isMinimumOSVersion);
            }
        }
    }
}

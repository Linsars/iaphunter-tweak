// MFAppStoreSpoof.m — AppStore 版本伪装（独立轻量 dylib）
// 完全参考 AppStoreTroller 逆向反汇编逻辑，用 MSHookMessageEx
// 不依赖 UIKit——只用 Foundation + CydiaSubstrate，daemon 里可加载

#import <Foundation/Foundation.h>
#import <substrate.h>

static NSUserDefaults *prefs;

// ====== NSMutableURLRequest setValue:forHTTPHeaderField: hook ======
// 拦截 App Store 购买请求，修改 User-Agent 里的 iOS 版本号
static void (*orig_setValue_forField)(id self, SEL _cmd, NSString *value, NSString *field);

static void hook_setValue_forField(id self, SEL _cmd, NSString *value, NSString *field) {
    if ([field isEqualToString:@"User-Agent"]) {
        NSString *url = [[self URL] absoluteString] ?: @"";
        if ([url containsString:@"WebObjects/MZBuy.woa/wa/buyProduct"]) {
            NSString *version = [prefs stringForKey:@"iOSVersion"] ?: @"99.0.0";
            if (version.length > 0) {
                value = [value stringByReplacingOccurrencesOfString:@"iOS/.*? "
                                                         withString:[NSString stringWithFormat:@"iOS/%@ ", version]
                                                           options:NSRegularExpressionSearch
                                                             range:NSMakeRange(0, value.length)];
            }
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
__attribute__((constructor)) static void init(void) {
    @autoreleasepool {
        NSString *processName = [[NSProcessInfo processInfo] processName];
        
        prefs = [[NSUserDefaults alloc] initWithSuiteName:@"dev.mineek.appstoretroller"];
        
        if ([processName isEqualToString:@"appstored"]) {
            // hook NSMutableURLRequest setValue:forHTTPHeaderField:
            Class cls = NSClassFromString(@"NSMutableURLRequest");
            if (cls) {
                SEL sel = @selector(setValue:forHTTPHeaderField:);
                MSHookMessageEx(cls, sel, (IMP)hook_setValue_forField, (IMP *)&orig_setValue_forField);
            }
        } else if ([processName isEqualToString:@"installd"]) {
            // hook MIBundle isMinimumOSVersion:applicableToOSVersion:requiredOS:error:
            Class cls = NSClassFromString(@"MIBundle");
            if (cls) {
                SEL sel = NSSelectorFromString(@"isMinimumOSVersion:applicableToOSVersion:requiredOS:error:");
                MSHookMessageEx(cls, sel, (IMP)hook_isMinimumOSVersion, (IMP *)&orig_isMinimumOSVersion);
            }
        }
    }
}

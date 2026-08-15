// MFAppStoreSpoof.m — AppStore 版本伪装（独立轻量 dylib）
// 完全参考 AppStoreTroller 逆向反汇编逻辑

#import <Foundation/Foundation.h>
#import <substrate.h>

static NSUserDefaults *prefs;
static NSString *g_spoofVersion;

static void (*orig_setValue_forField)(id self, SEL _cmd, NSString *value, NSString *field);
static BOOL (*orig_isMinimumOSVersion)(id self, SEL _cmd, id arg1, id arg2, id arg3, id *arg4);

static void hook_setValue_forField(id self, SEL _cmd, NSString *value, NSString *field) {
    if (g_spoofVersion && [field isEqualToString:@"User-Agent"]) {
        NSString *url = [[self URL] absoluteString];
        if (url && [url containsString:@"WebObjects/MZBuy.woa/wa/buyProduct"]) {
            value = [value stringByReplacingOccurrencesOfString:@"iOS/.*? "
                                                     withString:[NSString stringWithFormat:@"iOS/%@ ", g_spoofVersion]
                                                       options:NSRegularExpressionSearch
                                                         range:NSMakeRange(0, value.length)];
        }
    }
    orig_setValue_forField(self, _cmd, value, field);
}

static BOOL hook_isMinimumOSVersion(id self, SEL _cmd, id arg1, id arg2, id arg3, id *arg4) {
    return YES;
}

__attribute__((constructor)) static void init(void) {
    NSString *processName = [[NSProcessInfo processInfo] processName];
    prefs = [[NSUserDefaults alloc] initWithSuiteName:@"dev.mineek.appstoretroller"];
    
    if ([processName isEqualToString:@"appstored"]) {
        if (![prefs boolForKey:@"enabled"]) return;
        g_spoofVersion = [prefs stringForKey:@"iOSVersion"];
        Class cls = NSClassFromString(@"NSMutableURLRequest");
        if (cls) {
            MSHookMessageEx(cls, @selector(setValue:forHTTPHeaderField:), (IMP)hook_setValue_forField, (IMP *)&orig_setValue_forField);
        }
    } else if ([processName isEqualToString:@"installd"]) {
        Class cls = NSClassFromString(@"MIBundle");
        if (cls) {
            SEL sel = NSSelectorFromString(@"isMinimumOSVersion:applicableToOSVersion:requiredOS:error:");
            MSHookMessageEx(cls, sel, (IMP)hook_isMinimumOSVersion, (IMP *)&orig_isMinimumOSVersion);
        }
    }
}

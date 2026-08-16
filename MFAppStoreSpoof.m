// MFAppStoreSpoof.m — AppStore 版本伪装
// hook appstored: 修改 User-Agent 里的 iOS 版本号
// hook installd: 绕过最低版本检查

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>

static NSString *g_spoofVersion = nil;

static void loadConfig(void) {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:
        @"/var/mobile/Library/Preferences/dev.mineek.appstoretroller.plist"];
    if (prefs) {
        NSNumber *enabled = prefs[@"enabled"];
        if (enabled && ![enabled boolValue]) return;
        NSString *ver = prefs[@"iOSVersion"];
        if (ver.length > 0) g_spoofVersion = ver;
    }
    if (!g_spoofVersion) g_spoofVersion = @"99.0.0";
}

static BOOL isProcess(const char *name) {
    char path[1024];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
    NSString *execPath = [NSString stringWithUTF8String:path];
    return [execPath hasSuffix:[NSString stringWithFormat:@"/%s", name]];
}

// hook 1: NSMutableURLRequest setValue:forHTTPHeaderField:
static void (*orig_setValue)(id self, SEL _cmd, NSString *value, NSString *field);
static void hook_setValue(id self, SEL _cmd, NSString *value, NSString *field) {
    if ([field isEqualToString:@"User-Agent"] && [value containsString:@"iOS/"]) {
        NSRange range = [value rangeOfString:@"iOS/"];
        if (range.location != NSNotFound) {
            NSString *afterIOS = [value substringFromIndex:range.location + range.length];
            NSString *oldVersion = [[afterIOS componentsSeparatedByString:@" "] firstObject];
            NSString *oldFull = [NSString stringWithFormat:@"iOS/%@", oldVersion];
            NSString *newFull = [NSString stringWithFormat:@"iOS/%@", g_spoofVersion];
            NSString *modified = [value stringByReplacingOccurrencesOfString:oldFull withString:newFull];
            orig_setValue(self, _cmd, modified, field);
            return;
        }
    }
    orig_setValue(self, _cmd, value, field);
}

// hook 2: MIBundle 版本检查
static BOOL (*orig_isMinOS)(id self, SEL _cmd, NSString *min, NSString *current, NSString *required, NSError **err);
static BOOL hook_isMinOS(id self, SEL _cmd, NSString *min, NSString *current, NSString *required, NSError **err) {
    return YES;
}

static BOOL (*orig_isApplicable)(id self, SEL _cmd, NSError **err);
static BOOL hook_isApplicable(id self, SEL _cmd, NSError **err) {
    return YES;
}

__attribute__((constructor))
static void AppStoreSpoof_init(void) {
    loadConfig();
    if (!g_spoofVersion) return;
    
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:
        @"/var/mobile/Library/Preferences/dev.mineek.appstoretroller.plist"];
    if (prefs && prefs[@"enabled"] && ![prefs[@"enabled"] boolValue]) return;
    
    if (isProcess("appstored")) {
        Class cls = objc_getClass("NSMutableURLRequest");
        if (cls) {
            Method m = class_getInstanceMethod(cls, @selector(setValue:forHTTPHeaderField:));
            if (m) {
                orig_setValue = (void *)method_getImplementation(m);
                method_setImplementation(m, (IMP)hook_setValue);
            }
        }
    } else if (isProcess("installd")) {
        Class cls = objc_getClass("MIBundle");
        if (cls) {
            // hook 多个版本检查方法
            Method m1 = class_getInstanceMethod(cls, @selector(_isMinimumOSVersion:applicableToOSVersion:requiredOS:error:));
            if (m1) {
                orig_isMinOS = (void *)method_getImplementation(m1);
                method_setImplementation(m1, (IMP)hook_isMinOS);
            }
            Method m2 = class_getInstanceMethod(cls, @selector(isMinimumOSVersion:applicableToOSVersion:error:));
            if (m2) {
                method_setImplementation(m2, (IMP)hook_isMinOS);
            }
            Method m3 = class_getInstanceMethod(cls, @selector(isApplicableToCurrentOSVersionWithError:));
            if (m3) {
                orig_isApplicable = (void *)method_getImplementation(m3);
                method_setImplementation(m3, (IMP)hook_isApplicable);
            }
        }
    }
}

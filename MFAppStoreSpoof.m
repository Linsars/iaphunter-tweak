// MFAppStoreSpoof.m — AppStore 版本伪装（使用 method_setImplementation）
// hook 1: appstored 进程 — 修改 User-Agent 里的 iOS 版本号
// hook 2: installd 进程 — 绕过最低版本检查

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>

// 配置
static NSString *g_spoofVersion = nil;

// 读取配置
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

// 判断当前进程
static BOOL isProcess(const char *name) {
    char path[1024];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
    NSString *execPath = [NSString stringWithUTF8String:path];
    return [execPath hasSuffix:[NSString stringWithFormat:@"/%s", name]];
}

// hook 1: NSMutableURLRequest setValue:forHTTPHeaderField:
// 拦截购买请求，修改 User-Agent 里的 iOS 版本号
static void (*orig_setValue)(id self, SEL _cmd, NSString *value, NSString *field);
static void hook_setValue(id self, SEL _cmd, NSString *value, NSString *field) {
    if ([field isEqualToString:@"User-Agent"] && [value containsString:@"iOS/"]) {
        // 提取 "iOS/x.x.x" 部分并替换版本号
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

// hook 2: MIBundle isMinimumOSVersion:applicableToOSVersion:requiredOS:error:
// 绕过 installd 的最低版本检查
static BOOL (*orig_isMinOS)(id self, SEL _cmd, NSString *min, NSString *current, NSString *required, NSError **err);
static BOOL hook_isMinOS(id self, SEL _cmd, NSString *min, NSString *current, NSString *required, NSError **err) {
    return YES;
}

__attribute__((constructor))
static void AppStoreSpoof_init(void) {
    loadConfig();
    if (!g_spoofVersion) return;
    
    // 检查是否启用
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:
        @"/var/mobile/Library/Preferences/dev.mineek.appstoretroller.plist"];
    if (prefs && prefs[@"enabled"] && ![prefs[@"enabled"] boolValue]) return;
    
    if (isProcess("appstored")) {
        // hook NSMutableURLRequest
        Class cls = objc_getClass("NSMutableURLRequest");
        if (cls) {
            Method m = class_getInstanceMethod(cls, @selector(setValue:forHTTPHeaderField:));
            if (m) {
                orig_setValue = (void *)method_getImplementation(m);
                method_setImplementation(m, (IMP)hook_setValue);
            }
        }
    } else if (isProcess("installd")) {
        // hook MIBundle
        Class cls = objc_getClass("MIBundle");
        if (cls) {
            Method m = class_getInstanceMethod(cls, 
                @selector(isMinimumOSVersion:applicableToOSVersion:requiredOS:error:));
            if (m) {
                orig_isMinOS = (void *)method_getImplementation(m);
                method_setImplementation(m, (IMP)hook_isMinOS);
            }
        }
    }
}

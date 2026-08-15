// MFAppStoreSpoof.m — AppStore 版本伪装（使用 method_setImplementation）
// hook 1: appstored 进程 — 修改 User-Agent 里的 iOS 版本号
// hook 2: installd 进程 — 绕过最低版本检查

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>

// 配置
static NSString *g_spoofVersion = nil;

// 日志
static void spoofLog(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSLog(@"[AppStoreSpoof] %@", msg);
}

// 读取配置
static void loadConfig(void) {
    NSString *path = @"/var/mobile/Library/Preferences/dev.mineek.appstoretroller.plist";
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:path];
    spoofLog(@"loadConfig: prefs=%@ path=%@", prefs, path);
    
    if (prefs) {
        NSNumber *enabled = prefs[@"enabled"];
        spoofLog(@"enabled=%@", enabled);
        if (enabled && ![enabled boolValue]) {
            spoofLog(@"disabled in prefs");
            return;
        }
        NSString *ver = prefs[@"iOSVersion"];
        if (ver.length > 0) g_spoofVersion = ver;
    }
    if (!g_spoofVersion) g_spoofVersion = @"99.0.0";
    spoofLog(@"g_spoofVersion=%@", g_spoofVersion);
}

// 判断当前进程
static BOOL isProcess(const char *name) {
    char path[1024];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
    NSString *execPath = [NSString stringWithUTF8String:path];
    NSString *target = [NSString stringWithFormat:@"/%s", name];
    BOOL result = [execPath hasSuffix:target];
    spoofLog(@"isProcess(%s): execPath=%@ result=%d", name, execPath, result);
    return result;
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
            spoofLog(@"hook_setValue: %@ -> %@", oldFull, newFull);
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
    spoofLog(@"hook_isMinOS: min=%@ current=%@ required=%@ -> YES", min, current, required);
    return YES;
}

__attribute__((constructor))
static void AppStoreSpoof_init(void) {
    spoofLog(@"=== AppStoreSpoof init ENTER ===");
    
    loadConfig();
    if (!g_spoofVersion) {
        spoofLog(@"g_spoofVersion is nil, exiting");
        return;
    }
    
    // 检查是否启用
    NSString *path = @"/var/mobile/Library/Preferences/dev.mineek.appstoretroller.plist";
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:path];
    if (prefs && prefs[@"enabled"] && ![prefs[@"enabled"] boolValue]) {
        spoofLog(@"disabled in prefs (double check), exiting");
        return;
    }
    
    if (isProcess("appstored")) {
        spoofLog(@"in appstored, installing hook_setValue");
        // hook NSMutableURLRequest
        Class cls = objc_getClass("NSMutableURLRequest");
        if (cls) {
            Method m = class_getInstanceMethod(cls, @selector(setValue:forHTTPHeaderField:));
            if (m) {
                orig_setValue = (void *)method_getImplementation(m);
                method_setImplementation(m, (IMP)hook_setValue);
                spoofLog(@"hook_setValue installed");
            } else {
                spoofLog(@"setValue:forHTTPHeaderField: method not found");
            }
        } else {
            spoofLog(@"NSMutableURLRequest class not found");
        }
    } else if (isProcess("installd")) {
        spoofLog(@"in installd, installing hook_isMinOS");
        // hook MIBundle
        Class cls = objc_getClass("MIBundle");
        if (cls) {
            Method m = class_getInstanceMethod(cls, 
                @selector(isMinimumOSVersion:applicableToOSVersion:requiredOS:error:));
            if (m) {
                orig_isMinOS = (void *)method_getImplementation(m);
                method_setImplementation(m, (IMP)hook_isMinOS);
                spoofLog(@"hook_isMinOS installed");
            } else {
                spoofLog(@"isMinimumOSVersion:applicableToOSVersion:requiredOS:error: method not found");
            }
        } else {
            spoofLog(@"MIBundle class not found");
        }
    } else {
        spoofLog(@"not in appstored or installd");
    }
    
    spoofLog(@"=== AppStoreSpoof init DONE ===");
}

// MFAppStoreSpoof.m — AppStore 版本伪装（使用 method_setImplementation）
// hook 1: appstored 进程 — 修改 User-Agent 里的 iOS 版本号
// hook 2: installd 进程 — 绕过最低版本检查

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>

// 配置
static NSString *g_spoofVersion = nil;

// 日志 - 写入文件以便调试
static void spoofLog(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    
    // 写入文件
    NSString *logPath = @"/tmp/appstorespoof_debug.log";
    NSString *line = [NSString stringWithFormat:@"[%.0f] %@\n", [[NSDate date] timeIntervalSince1970], msg];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:logPath contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
    }
    if (fh) {
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    }
}

// 读取配置
static void loadConfig(void) {
    NSString *path = @"/var/mobile/Library/Preferences/dev.mineek.appstoretroller.plist";
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:path];
    spoofLog(@"loadConfig: prefs=%@", prefs);
    
    if (prefs) {
        NSNumber *enabled = prefs[@"enabled"];
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

// 列出所有包含特定关键字的类
static void listClassesWithKeyword(NSString *keyword) {
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    
    spoofLog(@"=== Classes containing '%@' ===", keyword);
    for (unsigned int i = 0; i < count; i++) {
        NSString *className = NSStringFromClass(classes[i]);
        if ([className containsString:keyword]) {
            // 列出这个类的方法
            unsigned int methodCount = 0;
            Method *methods = class_copyMethodList(classes[i], &methodCount);
            spoofLog(@"  %@ (%u methods)", className, methodCount);
            
            // 列出前10个方法
            for (unsigned int j = 0; j < MIN(methodCount, 10); j++) {
                SEL sel = method_getName(methods[j]);
                NSString *selName = NSStringFromSelector(sel);
                spoofLog(@"    - %@", selName);
            }
            free(methods);
        }
    }
    free(classes);
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

// hook 2: MIBundle 版本检查方法
// 绕过 installd 的最低版本检查
static BOOL (*orig_isMinOS)(id self, SEL _cmd, NSString *min, NSString *current, NSString *required, NSError **err);
static BOOL hook_isMinOS(id self, SEL _cmd, NSString *min, NSString *current, NSString *required, NSError **err) {
    spoofLog(@"hook_isMinOS called -> YES");
    return YES;
}

static BOOL (*orig_isApplicable)(id self, SEL _cmd, NSError **err);
static BOOL hook_isApplicable(id self, SEL _cmd, NSError **err) {
    spoofLog(@"hook_isApplicable called -> YES");
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
        spoofLog(@"in installd, listing classes...");
        
        // 列出包含 "MI" 的类
        listClassesWithKeyword(@"MI");
        
        // 列出包含 "Bundle" 的类
        listClassesWithKeyword(@"Bundle");
        
        // 列出包含 "Install" 的类
        listClassesWithKeyword(@"Install");
        
        // 尝试 hook MIBundle
        Class cls = objc_getClass("MIBundle");
        if (cls) {
            spoofLog(@"Found MIBundle class");
            
            // 尝试多个可能的方法名
            SEL selectors[] = {
                @selector(_isMinimumOSVersion:applicableToOSVersion:requiredOS:error:),
                @selector(isMinimumOSVersion:applicableToOSVersion:error:),
                @selector(isApplicableToCurrentOSVersionWithError:),
            };
            const char *selNames[] = {
                "_isMinimumOSVersion:applicableToOSVersion:requiredOS:error:",
                "isMinimumOSVersion:applicableToOSVersion:error:",
                "isApplicableToCurrentOSVersionWithError:",
            };
            
            BOOL hooked = NO;
            for (int i = 0; i < 3; i++) {
                Method m = class_getInstanceMethod(cls, selectors[i]);
                if (m) {
                    if (i < 2) {
                        orig_isMinOS = (void *)method_getImplementation(m);
                        method_setImplementation(m, (IMP)hook_isMinOS);
                    } else {
                        orig_isApplicable = (void *)method_getImplementation(m);
                        method_setImplementation(m, (IMP)hook_isApplicable);
                    }
                    spoofLog(@"hook installed: %s", selNames[i]);
                    hooked = YES;
                    // 继续 hook 其他方法
                } else {
                    spoofLog(@"method not found: %s", selNames[i]);
                }
            }
            
            if (!hooked) {
                spoofLog(@"No version check method found on MIBundle");
            }
        } else {
            spoofLog(@"MIBundle class not found");
        }
    } else {
        spoofLog(@"not in appstored or installd");
    }
    
    spoofLog(@"=== AppStoreSpoof init DONE ===");
}

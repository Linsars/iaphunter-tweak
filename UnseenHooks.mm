// UnseenHooks.mm — v2.5.2 调试版:日志写文件(不依赖 syslog),逐步追踪加载链
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <string.h>

#define UNSEEN_PREFS @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"
#define DBG_LOG      @"/var/jb/var/mobile/Library/Preferences/unseen_debug.log"

// 文件日志(追加模式,任何进程都能写)
static void dbg(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void dbg(NSString *fmt, ...) {
    @autoreleasepool {
        va_list args;
        va_start(args, fmt);
        NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
        va_end(args);
        NSString *line = [NSString stringWithFormat:@"[%@][pid:%d] %@\n",
            [NSDate dateWithTimeIntervalSinceNow:0], getpid(), msg];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:DBG_LOG];
        if (!fh) {
            [line writeToFile:DBG_LOG atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } else {
            [fh seekToEndOfFile];
            [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
    }
}

// 偏好缓存(hook 内不再读文件+写日志——v2.5.10 日志爆炸 9268 行教训)
static NSTimeInterval g_lastPrefRead = 0;
static BOOL g_cachedHideScreenshot = YES;
static BOOL g_cachedHideRecording = YES;
static BOOL g_cachedRevealHidden = YES;

static void unseenRefreshPrefs(void) {
    NSTimeInterval now = [NSDate date].timeIntervalSince1970;
    if (now - g_lastPrefRead < 2.0) return;
    g_lastPrefRead = now;
    @autoreleasepool {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:UNSEEN_PREFS];
        id v;
        v = d[@"mfUnseenHideScreenshot"]; g_cachedHideScreenshot = v ? [v boolValue] : YES;
        v = d[@"mfUnseenHideRecording"];  g_cachedHideRecording  = v ? [v boolValue] : YES;
        v = d[@"mfUnseenRevealHidden"];   g_cachedRevealHidden   = v ? [v boolValue] : YES;
    }
}

static inline BOOL unseenPref(NSString *key, BOOL def) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:UNSEEN_PREFS];
    id v = d[key];
    return v ? [v boolValue] : def;
}

static BOOL g_unseenEnabled = NO;

extern "C" {
    int DobbyHook(void *address, void *replace, void **origin);
    void *DobbySymbolResolver(const char *image, const char *symbol);
}

static BOOL isBackboardd(void) {
    char path[1024]; uint32_t sz = sizeof(path); _NSGetExecutablePath(path, &sz);
    return strstr(path, "backboardd") != NULL;
}
static BOOL isSpringBoard(void) {
    char path[1024]; uint32_t sz = sizeof(path); _NSGetExecutablePath(path, &sz);
    return strstr(path, "SpringBoard") != NULL;
}

// ============================================================
// backboardd 侧
// ============================================================
static BOOL (*orig_allowed_in_update)(void *self, void *ctx, void *layer);
static int hook_call_count = 0;

static BOOL hook_allowed_in_update(void *self, void *ctx, void *layer) {
    hook_call_count++;
    if (hook_call_count <= 5) {
        dbg(@"🔥 allowed_in_update #%d self=%p ctx=%p layer=%p", hook_call_count, self, ctx, layer);
    }
    if (!g_unseenEnabled || !unseenPref(@"mfUnseenRevealHidden", YES)) {
        if (orig_allowed_in_update) return orig_allowed_in_update(self, ctx, layer);
        return YES;
    }
    return YES;
}

static void install_backboardd_hooks(void) {
    dbg(@"=== BB install START ===");

    // 探测 QuartzCore 是否加载
    void *handle = dlopen("QuartzCore", RTLD_NOW);
    dbg(@"dlopen(QuartzCore) = %p", handle);
    if (!handle) {
        dbg(@"dlopen error: %s", dlerror());
    }

    // v2.5.9: 多种方式尝试符号解析(包括 NULL 镜像名搜索全部已加载镜像)
    const char *syms[] = {
        "_ZN2CA6Render6Update17allowed_in_updateEPNS0_7ContextEPKNS0_5LayerE",
        "__ZN2CA6Render6Update17allowed_in_updateEPNS0_7ContextEPKNS0_5LayerE",
    };
    void *sym = NULL;
    for (int i = 0; i < 2; i++) {
        // 尝试 DobbySymbolResolver(NULL) — 搜索全部镜像
        sym = DobbySymbolResolver(NULL, syms[i]);
        dbg(@"DobbySymbolResolver(NULL,\"%s\") → %p", syms[i], sym);
        if (sym) break;
        // 尝试 dlsym
        sym = dlsym(RTLD_DEFAULT, syms[i]);
        dbg(@"dlsym(RTLD_DEFAULT,\"%s\") → %p", syms[i], sym);
        if (sym) break;
        // 尝试通过 handle 查找(如果 QuartzCore 已加载)
        if (handle) {
            sym = dlsym(handle, syms[i]);
            dbg(@"dlsym(handle,\"%s\") → %p", syms[i], sym);
            if (sym) break;
        }
    }

    if (!sym) {
        dbg(@"❌ symbol NOT FOUND — no hook");
        return;
    }

    dbg(@"calling DobbyHook(%p)...", sym);
    int ret = DobbyHook(sym, (void*)hook_allowed_in_update, (void**)&orig_allowed_in_update);
    dbg(@"DobbyHook ret=%d orig=%p %s", ret, orig_allowed_in_update, ret==0 ? "✅" : "❌");
    dbg(@"=== BB install END ===");
}

// ============================================================
// SpringBoard 侧
// ============================================================
static BOOL (*orig_sendAction)(id, SEL, id, id, id, id);
static int sb_action_count = 0;

static BOOL hook_sendAction(id self, SEL _cmd, id action, id target, id sender, id event) {
    sb_action_count++;
    Class actionCls = object_getClass(action);
    const char *clsName = actionCls ? class_getName(actionCls) : "(nil)";

    // 前 20 次全量打日志,之后只打截图
    if (sb_action_count <= 20) {
        dbg(@"SB sendAction #%d class=%s self=%p action=%p", sb_action_count, clsName, self, action);
    }

    if (actionCls && strstr(clsName, "TakeScreenshot") != NULL) {
        dbg(@"🚫 filtered screenshot: %s", clsName);
        return YES; // 吞掉截图 action
    }

    if (orig_sendAction) {
        BOOL r = orig_sendAction(self, _cmd, action, target, sender, event);
        if (sb_action_count <= 20) {
            dbg(@"  → orig returned %d", r);
        }
        return r;
    }
    return YES;
}

// 截图/录屏通知过滤(v2.5.9 安全方案: hook NSNotificationCenter 而非 UIApplication)
static void (*orig_postNotificationName)(id, SEL, NSString*, id, NSDictionary*);
static void (*orig_postNotificationObj)(id, SEL, NSNotification*);
static int sb_notif_count = 0;

static BOOL shouldFilterNotification(NSString *name) {
    if (!name) return NO;
    // 过滤所有截图/录屏相关通知
    if ([name containsString:@"Screenshot"] || [name containsString:@"screenshot"]) return YES;
    if ([name containsString:@"Captured"] || [name containsString:@"captured"]) return YES;
    if ([name containsString:@"CaptureState"]) return YES;
    return NO;
}

static void hook_postNotificationName(id self, SEL _cmd, NSString *name, id obj, NSDictionary *userInfo) {
    sb_notif_count++;
    unseenRefreshPrefs();
    if (g_unseenEnabled && g_cachedHideScreenshot && shouldFilterNotification(name)) {
        if (sb_notif_count <= 50) dbg(@"🚫 filtered: %@", name);
        return;
    }
    if (orig_postNotificationName) orig_postNotificationName(self, _cmd, name, obj, userInfo);
}

static void hook_postNotificationObj(id self, SEL _cmd, NSNotification *notification) {
    unseenRefreshPrefs();
    if (g_unseenEnabled && g_cachedHideScreenshot && shouldFilterNotification(notification.name)) {
        dbg(@"🚫 filtered (obj): %@", notification.name);
        return;
    }
    if (orig_postNotificationObj) orig_postNotificationObj(self, _cmd, notification);
}

static void install_springboard_hooks(void) {
    dbg(@"=== SB install START ===");

    // v2.5.9: 安全截图过滤——hook NSNotificationCenter 而非 UIApplication.sendAction
    Class ncCls = objc_getClass("NSNotificationCenter");
    if (!ncCls) { dbg(@"❌ no NSNotificationCenter"); return; }

    SEL postSel = @selector(postNotificationName:object:userInfo:);
    Method m = class_getInstanceMethod(ncCls, postSel);
    if (m) {
        orig_postNotificationName = (void (*)(id, SEL, NSString*, id, NSDictionary*))method_getImplementation(m);
        method_setImplementation(m, (IMP)hook_postNotificationName);
        dbg(@"✅ postNotificationName:object:userInfo: hooked");
    }

    SEL postSel2 = @selector(postNotification:);
    Method m2 = class_getInstanceMethod(ncCls, postSel2);
    if (m2) {
        orig_postNotificationObj = (void (*)(id, SEL, NSNotification*))method_getImplementation(m2);
        method_setImplementation(m2, (IMP)hook_postNotificationObj);
        dbg(@"✅ postNotification: hooked");
    }

    dbg(@"=== SB install END ===");
}

// ============================================================
// 入口
// ============================================================
__attribute__((constructor))
static void UnseenHooks_init(void) {
    @autoreleasepool {
        dbg(@"━━━ ctor ENTER pid=%d ━━━", getpid());

        char path[1024]; uint32_t sz = sizeof(path); _NSGetExecutablePath(path, &sz);
        dbg(@"exec path: %s", path);
        dbg(@"bundle ID: %@", [[NSBundle mainBundle] bundleIdentifier] ?: @"(nil)");

        g_unseenEnabled = unseenPref(@"mfUnseenEnabled", NO);
        if (!g_unseenEnabled) {
            dbg(@"disabled — zero hooks, exit");
            return;
        }

        if (isBackboardd()) {
            dbg(@"→ backboardd mode");
            install_backboardd_hooks();
        } else if (isSpringBoard()) {
            dbg(@"→ SpringBoard mode");
            install_springboard_hooks();
        } else {
            dbg(@"neither process — skip");
        }
        dbg(@"━━━ ctor EXIT ━━━");
    }
}
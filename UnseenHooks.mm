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

static inline BOOL unseenPref(NSString *key, BOOL def) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:UNSEEN_PREFS];
    id v = d[key];
    BOOL r = v ? [v boolValue] : def;
    dbg(@"pref %@ = %d", key, r);
    return r;
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

    // 符号解析(多种格式尝试)
    const char *syms[] = {
        "_ZN2CA6Render6Update17allowed_in_updateEPNS0_7ContextEPKNS0_5LayerE",
        "__ZN2CA6Render6Update17allowed_in_updateEPNS0_7ContextEPKNS0_5LayerE",
    };
    void *sym = NULL;
    for (int i = 0; i < 2; i++) {
        sym = DobbySymbolResolver("QuartzCore", syms[i]);
        dbg(@"DobbySymbolResolver(\"QuartzCore\",\"%s\") → %p", syms[i], sym);
        if (sym) break;
        sym = dlsym(RTLD_DEFAULT, syms[i]);
        dbg(@"dlsym(RTLD_DEFAULT,\"%s\") → %p", syms[i], sym);
        if (sym) break;
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
static void (*orig_sendAction)(id, SEL, id, id, id, id);

static void hook_sendAction(id self, SEL _cmd, id action, id target, id sender, id event) {
    Class actionCls = object_getClass(action);
    if (actionCls && strstr(class_getName(actionCls), "TakeScreenshot") != NULL) {
        dbg(@"🚫 filtered screenshot: %s", class_getName(actionCls));
        return;
    }
    if (orig_sendAction) orig_sendAction(self, _cmd, action, target, sender, event);
}

static void install_springboard_hooks(void) {
    dbg(@"=== SB install START ===");
    Class uiApp = objc_getClass("UIApplication");
    dbg(@"UIApplication = %p", uiApp);
    if (!uiApp) { dbg(@"❌ no UIApplication"); return; }

    Method m = class_getInstanceMethod(uiApp, @selector(sendAction:to:from:forEvent:));
    dbg(@"Method = %p", m);
    if (!m) { dbg(@"❌ method not found"); return; }

    orig_sendAction = (void (*)(id, SEL, id, id, id, id))method_getImplementation(m);
    method_setImplementation(m, (IMP)hook_sendAction);
    dbg(@"✅ sendAction hooked (orig=%p)", orig_sendAction);
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
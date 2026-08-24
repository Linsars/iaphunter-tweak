// UnseenHooks.mm — v2.5.2 调试版:全链路日志追踪,定位安全模式根因
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <notify.h>
#import <mach-o/dyld.h>
#import <string.h>

#define UNSEEN_PREFS @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"
#define LOG(fmt, ...) do { \
    NSLog(@"[UnseenHooks][%s:%d] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
} while(0)

static inline BOOL unseenPref(NSString *key, BOOL def) {
    @autoreleasepool {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:UNSEEN_PREFS];
        id v = d[key];
        BOOL r = v ? [v boolValue] : def;
        LOG(@"pref %@ = %d (default %d)", key, r, def);
        return r;
    }
}

static BOOL g_unseenEnabled = NO;

extern "C" {
    int DobbyHook(void *address, void *replace, void **origin);
    void *DobbySymbolResolver(const char *image, const char *symbol);
}

static BOOL isBackboardd(void) {
    char path[1024]; uint32_t sz = sizeof(path); _NSGetExecutablePath(path, &sz);
    BOOL r = strstr(path, "backboardd") != NULL;
    LOG(@"process path=%s → isBackboardd=%d", path, r);
    return r;
}
static BOOL isSpringBoard(void) {
    char path[1024]; uint32_t sz = sizeof(path); _NSGetExecutablePath(path, &sz);
    BOOL r = strstr(path, "SpringBoard") != NULL;
    LOG(@"process path=%s → isSpringBoard=%d", path, r);
    return r;
}

// ============================================================
// backboardd 侧
// ============================================================

// v2.5.1 修复: C++ 成员函数带隐式 this
static BOOL (*orig_allowed_in_update)(void *self, void *ctx, void *layer);
static int  hook_call_count = 0;

static BOOL hook_allowed_in_update(void *self, void *ctx, void *layer) {
    hook_call_count++;
    if (hook_call_count <= 10) {
        LOG(@"🔥 allowed_in_update call #%d self=%p ctx=%p layer=%p", hook_call_count, self, ctx, layer);
    }
    if (!g_unseenEnabled || !unseenPref(@"mfUnseenRevealHidden", YES)) {
        if (orig_allowed_in_update) {
            BOOL r = orig_allowed_in_update(self, ctx, layer);
            if (hook_call_count <= 10) LOG(@"  → orig returned %d", r);
            return r;
        }
        LOG(@"  ⚠️ orig is NULL! returning YES");
        return YES;
    }
    LOG(@"  → reveal mode, returning YES");
    return YES;
}

static void install_backboardd_hooks(void) {
    LOG(@"=== backboardd hook install START ===");

    // Step 1: 检查 QuartzCore 是否加载
    void *qc = dlopen(NULL, RTLD_NOW); // 自己进程
    LOG(@"dlopen(NULL) = %p", qc);

    // Step 2: 逐个尝试符号解析
    const char *sym_names[] = {
        "_ZN2CA6Render6Update17allowed_in_updateEPNS0_7ContextEPKNS0_5LayerE",
        "__ZN2CA6Render6Update17allowed_in_updateEPNS0_7ContextEPKNS0_5LayerE",
        "CA::Render::Update::allowed_in_update(CA::Render::Context*, CA::Render::Layer const*)",
    };
    void *sym = NULL;
    for (int i = 0; i < 3; i++) {
        LOG(@"trying DobbySymbolResolver(\"QuartzCore\", \"%s\")...", sym_names[i]);
        sym = DobbySymbolResolver("QuartzCore", sym_names[i]);
        LOG(@"  → %p", sym);
        if (sym) break;
    }

    // 也试 dlsym 直接查
    if (!sym) {
        LOG(@"DobbySymbolResolver failed, trying dlsym(RTLD_DEFAULT)...");
        for (int i = 0; i < 2; i++) {
            sym = dlsym(RTLD_DEFAULT, sym_names[i]);
            LOG(@"  dlsym(\"%s\") → %p", sym_names[i], sym);
            if (sym) break;
        }
    }

    if (!sym) {
        LOG(@"❌ allowed_in_update symbol NOT FOUND in any form — no hook installed");
        LOG(@"=== backboardd hook install END (no hooks) ===");
        return;
    }

    // Step 3: DobbyHook
    LOG(@"calling DobbyHook(%p, %p, %p)...", sym, hook_allowed_in_update, &orig_allowed_in_update);
    int ret = DobbyHook(sym, (void*)hook_allowed_in_update, (void**)&orig_allowed_in_update);
    LOG(@"DobbyHook returned %d, orig_allowed_in_update = %p", ret, orig_allowed_in_update);

    if (ret != 0) {
        LOG(@"❌ DobbyHook FAILED ret=%d — hook NOT installed", ret);
    } else {
        LOG(@"✅ allowed_in_update hook installed successfully");
    }

    LOG(@"=== backboardd hook install END ===");
}

// ============================================================
// SpringBoard 侧
// ============================================================

static void (*orig_sendAction)(id, SEL, id, id, id, id);
static int sb_action_count = 0;

static void hook_sendAction(id self, SEL _cmd, id action, id target, id sender, id event) {
    sb_action_count++;
    Class actionCls = object_getClass(action);
    const char *clsName = actionCls ? class_getName(actionCls) : "(nil)";

    // 只在截图 action 或前几次打日志
    BOOL isScreenshot = actionCls && strstr(clsName, "TakeScreenshot") != NULL;
    if (isScreenshot || sb_action_count <= 3) {
        LOG(@"SB sendAction #%d class=%s isScreenshot=%d", sb_action_count, clsName, isScreenshot);
    }

    if (g_unseenEnabled && unseenPref(@"mfUnseenHideScreenshot", YES) && isScreenshot) {
        LOG(@"🚫 filtered screenshot action (class=%s)", clsName);
        return;
    }
    if (orig_sendAction) orig_sendAction(self, _cmd, action, target, sender, event);
}

static void install_springboard_hooks(void) {
    LOG(@"=== SpringBoard hook install START ===");

    Class uiApp = objc_getClass("UIApplication");
    LOG(@"UIApplication class: %p", uiApp);
    if (!uiApp) {
        LOG(@"❌ UIApplication not found — no hooks");
        return;
    }

    SEL sel = @selector(sendAction:to:from:forEvent:);
    LOG(@"selector sendAction:to:from:forEvent: = %@", NSStringFromSelector(sel));

    Method m = class_getInstanceMethod(uiApp, sel);
    LOG(@"class_getInstanceMethod → Method=%p", m);
    if (!m) {
        LOG(@"❌ method not found on UIApplication");
        return;
    }

    IMP imp = method_getImplementation(m);
    LOG(@"current IMP = %p", imp);
    orig_sendAction = (void (*)(id, SEL, id, id, id, id))imp;

    method_setImplementation(m, (IMP)hook_sendAction);
    LOG(@"✅ sendAction hook installed (new IMP=%p, orig=%p)", (void*)hook_sendAction, (void*)orig_sendAction);

    LOG(@"=== SpringBoard hook install END ===");
}

// ============================================================
// 入口
// ============================================================
__attribute__((constructor))
static void UnseenHooks_init(void) {
    @autoreleasepool {
        LOG(@"━━━ constructor ENTER pid=%d ━━━", getpid());

        // 环境探测
        LOG(@"NSProcessInfo: %@", [[NSProcessInfo processInfo] processName]);
        LOG(@"bundle ID: %@", [[NSBundle mainBundle] bundleIdentifier] ?: @"(nil)");

        // 偏好读取(逐键)
        g_unseenEnabled = unseenPref(@"mfUnseenEnabled", NO);
        LOG(@"mfUnseenEnabled = %d", g_unseenEnabled);

        if (!g_unseenEnabled) {
            LOG(@"globally disabled — zero hooks, exiting");
            return;
        }

        // 进程判断
        if (isBackboardd()) {
            LOG(@"→ installing backboardd hooks");
            install_backboardd_hooks();
        } else if (isSpringBoard()) {
            LOG(@"→ installing SpringBoard hooks");
            install_springboard_hooks();
        } else {
            LOG(@"neither backboardd nor SpringBoard — skipping");
        }

        LOG(@"━━━ constructor EXIT ━━━");
    }
}
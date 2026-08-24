// UnseenHooks.mm — 反检测/隐私 dylib(v2.5.1 修复 C++ this 指针签名)
// 注入: backboardd(渲染服务器 inline hook) + SpringBoard(截图/录屏过滤)
// 偏好域: com.linsars.minisfix
//
// v2.5.0 → v2.5.1 修复:
//   ① C++ 成员函数隐式 this 指针缺失 → 栈错位 → backboardd 崩 → 安全模式
//   ② DobbySymbolResolver 失败时不再尝试 hook(空指针防护)
//   ③ hook 内所有 orig 调用前必须非空检查
//   ④ notify_register_dispatch token 使用独立变量

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <notify.h>
#import <mach-o/dyld.h>
#import <string.h>

#define UNSEEN_PREFS @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"

static inline BOOL unseenPref(NSString *key, BOOL def) {
    @autoreleasepool {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:UNSEEN_PREFS];
        id v = d[key];
        return v ? [v boolValue] : def;
    }
}

static BOOL g_unseenEnabled = NO;

// Dobby 声明
extern "C" {
    int DobbyHook(void *address, void *replace, void **origin);
    void *DobbySymbolResolver(const char *image, const char *symbol);
}

// 运行时进程判断
static BOOL isBackboardd(void) {
    char path[1024]; uint32_t sz = sizeof(path); _NSGetExecutablePath(path, &sz);
    return strstr(path, "backboardd") != NULL;
}
static BOOL isSpringBoard(void) {
    char path[1024]; uint32_t sz = sizeof(path); _NSGetExecutablePath(path, &sz);
    return strstr(path, "SpringBoard") != NULL;
}

// ============================================================
// backboardd 侧: CA::Render 内部 inline hook
// ⚠️ 所有 C++ 成员函数 hook 必须包含隐式 this 指针!
// ============================================================

// CA::Render::Update::allowed_in_update(Context*, Layer const*)
// 实际签名: BOOL allowed_in_update(Update* this, Context* ctx, Layer* layer)
static BOOL (*orig_allowed_in_update)(void *self, void *ctx, void *layer);

static BOOL hook_allowed_in_update(void *self, void *ctx, void *layer) {
    if (!g_unseenEnabled || !unseenPref(@"mfUnseenRevealHidden", YES))
        return orig_allowed_in_update ? orig_allowed_in_update(self, ctx, layer) : YES;
    // 放行:返回 YES = 该 layer 允许渲染(揭示被隐藏的内容)
    return YES;
}

// CA::Render::Context::process_id()
// 实际签名: uint64_t process_id(Context* this)  — 只有一个隐式 this
static uint64_t (*orig_process_id)(void *self);

static uint64_t hook_process_id(void *self) {
    return orig_process_id ? orig_process_id(self) : 0;
}

// 安全 hook 包装:仅当符号解析成功且 Dobby 返回 0 时才认为安装成功
static BOOL safeHook(void *sym, void *hook, void **orig, const char *name) {
    if (!sym) { NSLog(@"[UnseenHooks] symbol not found: %s — skip", name); return NO; }
    int ret = DobbyHook(sym, hook, orig);
    if (ret != 0) { NSLog(@"[UnseenHooks] DobbyHook %s failed ret=%d — skip", name, ret); return NO; }
    NSLog(@"[UnseenHooks] hooked %s at %p", name, sym);
    return YES;
}

static void install_backboardd_hooks(void) {
    g_unseenEnabled = unseenPref(@"mfUnseenEnabled", NO);
    if (!g_unseenEnabled) { NSLog(@"[UnseenHooks] BB disabled by pref"); return; }

    // 只 hook allowed_in_update(最安全、最关键的一个)
    // prepare_layer0 和 process_id 的调用约定更复杂,先不碰(保守策略)
    void *sym = DobbySymbolResolver("QuartzCore",
        "_ZN2CA6Render6Update17allowed_in_updateEPNS0_7ContextEPKNS0_5LayerE");
    safeHook(sym, (void*)hook_allowed_in_update, (void**)&orig_allowed_in_update,
             "allowed_in_update");

    NSLog(@"[UnseenHooks] backboardd hooks done");
}

// ============================================================
// SpringBoard 侧: 截图/录屏过滤(ObjC hook,安全)
// ============================================================

static void (*orig_sendAction)(id, SEL, id, id, id, id);
static void hook_sendAction(id self, SEL _cmd, id action, id target, id sender, id event) {
    if (!g_unseenEnabled || !unseenPref(@"mfUnseenHideScreenshot", YES)) {
        if (orig_sendAction) orig_sendAction(self, _cmd, action, target, sender, event);
        return;
    }
    // 识别 UIDidTakeScreenshotAction
    Class actionCls = object_getClass(action);
    if (actionCls && strstr(class_getName(actionCls), "TakeScreenshot") != NULL) {
        NSLog(@"[UnseenHooks] filtered screenshot action");
        return; // 吞掉
    }
    if (orig_sendAction) orig_sendAction(self, _cmd, action, target, sender, event);
}

static void install_springboard_hooks(void) {
    g_unseenEnabled = unseenPref(@"mfUnseenEnabled", NO);
    if (!g_unseenEnabled) { NSLog(@"[UnseenHooks] SB disabled by pref"); return; }

    // UIApplication sendAction:to:from:forEvent: — 过滤截图 action
    Class uiApp = objc_getClass("UIApplication");
    if (uiApp) {
        Method m = class_getInstanceMethod(uiApp, @selector(sendAction:to:from:forEvent:));
        if (m) {
            orig_sendAction = (void (*)(id, SEL, id, id, id, id))method_getImplementation(m);
            method_setImplementation(m, (IMP)hook_sendAction);
            NSLog(@"[UnseenHooks] SB sendAction hooked");
        }
    }

    NSLog(@"[UnseenHooks] SpringBoard hooks done");
}

// ============================================================
// 统一入口
// ============================================================
__attribute__((constructor))
static void UnseenHooks_init(void) {
    @autoreleasepool {
        // 总开关关 = 零操作
        if (!unseenPref(@"mfUnseenEnabled", NO)) {
            NSLog(@"[UnseenHooks] globally disabled");
            return;
        }
        if (isBackboardd()) {
            install_backboardd_hooks();
        } else if (isSpringBoard()) {
            install_springboard_hooks();
        }
    }
}
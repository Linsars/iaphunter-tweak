// MFProcCapture.m — 第二拳·点位采集器 (被动, 零 hook)
// 层1 内存差分: ctor 快照主二进制 __TEXT/__DATA_CONST/__DATA, 2s diff — 抓直接写内存的 patch
// 层2 ObjC imp 巡检: 枚举全部类方法表, imp 落在 ReflixPatch dylib 镜像内 = 它 swizzle 的点
//     (实测教训: dylib 不写主二进制段 — 它是 NSInvocation+method_getImplementation 型 swizzle,
//      目标 selector 运行时解密, 但 objc 运行时表是明文, 类名/selector 直出)
// 产出: mfcap_*.json + hostlog 每事件一行

#import "MFPanel.h"
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <string.h>
#import <os/object.h>
#import <os/lock.h>
#import <mach/mach.h>
#import "fishhook.h"

// ===== 层5: 主二进制 mach_msg 观察 — app=license 客户端(六个子系统 id 全在主二进制, 2.29.1 实测) =====
// 只重绑 main image 的 mach_msg 导入(vendor dylib 自身调用不受影响, 绕开 backtrace 反 hook)
// MIG send+rcv 一体: 同次调用 rcv 缓冲区 = 服务端应答 → 一次 hook 抓全双向握手
static mach_msg_return_t (*g_origMachMsg)(mach_msg_header_t *, mach_msg_option_t, mach_msg_size_t,
                                          mach_msg_header_t *, mach_msg_size_t, mach_port_t, mach_msg_timeout_t);
static os_unfair_lock g_machLock = OS_UNFAIR_LOCK_INIT;
static int g_machCapCount = 0;

static inline BOOL mf_licReqId(uint32_t id) { return id == 0x965 || id == 0x966 || id == 0x967; }
static inline BOOL mf_licRepId(uint32_t id) { return id == 0x9c9 || id == 0x9ca || id == 0x9cb; }

static void mf_machDump(const char *kind, int seq, mach_msg_header_t *h) {
    if (!h) return;
    uint32_t size = h->msgh_size;
    if (size > 5276 || size < 24) return;
    @try {
        NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/MinisFix"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        NSMutableString *body = [NSMutableString string];
        const uint8_t *b = (const uint8_t *)h;
        for (uint32_t i = 0; i < MIN(size, 512u); i++)
            [body appendFormat:@"%02x", b[i]];
        NSDictionary *r = @{@"kind": [NSString stringWithUTF8String:kind],
                            @"id": [NSString stringWithFormat:@"0x%x", h->msgh_id],
                            @"bits": [NSString stringWithFormat:@"0x%x", h->msgh_bits],
                            @"size": @(size),
                            @"retcode_0x20": size > 0x24 ? [NSString stringWithFormat:@"0x%08x",
                                *(const uint32_t *)(b + 0x20)] : @"n/a",
                            @"hex": body};
        NSString *path = [NSString stringWithFormat:@"%@/mfcap_mach_%s_%d_0x%x.json", dir, kind, seq, h->msgh_id];
        NSData *d = [NSJSONSerialization dataWithJSONObject:r options:NSJSONWritingPrettyPrinted error:nil];
        if (d) [d writeToFile:path atomically:YES];
        // hostlog 摘要: 前 48 字节
        NSString *head = [body substringToIndex:MIN(96, body.length)];
        mfLog(@"[capture] MACH%s #%d id=0x%x size=%u rc@0x20=%s hex=%@",
              kind, seq, h->msgh_id, size,
              (size > 0x24 ? [[NSString stringWithFormat:@"0x%08x", *(const uint32_t *)(b + 0x20)] UTF8String] : "n/a"),
              head);
    } @catch (NSException *e) {}
}

static void mf_machMaybeCap(mach_msg_header_t *send, mach_msg_header_t *rcv, mach_msg_return_t kr) {
    if (g_machCapCount >= 32) return;
    if (!send || !(send->msgh_bits & MACH_SEND_MSG)) return;
    if (!mf_licReqId(send->msgh_id)) return;
    os_unfair_lock_lock(&g_machLock);
    int seq = ++g_machCapCount;
    os_unfair_lock_unlock(&g_machLock);
    mf_machDump("REQ", seq, send);
    // rcv 缓冲区 = 同次调用收到的应答(MIG 风格 send+rcv)
    if ((kr == MACH_MSG_SUCCESS || kr == 0) && rcv && mf_licRepId(rcv->msgh_id))
        mf_machDump("REP", seq, rcv);
    else if (rcv && rcv->msgh_id)
        mfLog(@"[capture] MACHREQ #%d kr=0x%x rcv_id=0x%x (non-lic)", seq, kr, rcv->msgh_id);
    else
        mfLog(@"[capture] MACHREQ #%d id=0x%x kr=0x%x (no reply captured)", seq, send->msgh_id, kr);
}

static mach_msg_return_t mf_machMsgHook(mach_msg_header_t *msg, mach_msg_option_t option,
        mach_msg_size_t send_size, mach_msg_header_t *rcv_msg, mach_msg_size_t rcv_limit,
        mach_port_t notify, mach_msg_timeout_t timeout) {
    mach_msg_return_t kr = g_origMachMsg(msg, option, send_size, rcv_msg, rcv_limit, notify, timeout);
    mf_machMaybeCap(msg, rcv_msg, kr);
    return kr;
}

static void mfCapInstallMachTap(const struct mach_header_64 *mh, intptr_t slide) {
    if (g_origMachMsg) return;
    struct rebinding rb = {"mach_msg", (void *)mf_machMsgHook, (void **)&g_origMachMsg};
    int r = rebind_symbols_image((void *)mh, slide, &rb, 1);
    mfLog(@"[capture] main-image mach_msg rebind: %d (hook=%p)", r, g_origMachMsg);
}

static NSString *const kCapBID = @"com.magicgroot.gooby";
static NSString *const kCapVersion = @"3.0.5";
static NSString *const kCapDylib = @"/var/jb/usr/lib/MinisFix/ReflixPatch-3.0.5.dylib";
static const NSTimeInterval kCapPollSec = 0.5;   // v2.27.1: 2s→0.5s 逮瞬时 swizzle
static const uint32_t kCapMaxEvents = 256;

static NSString *mfCapHex(const uint8_t *p, size_t n) {
    static const char h[] = "0123456789abcdef";
    if (!p || !n) return @"";
    if (n > 256) n = 256;
    char *s = malloc(n * 2 + 1);
    if (!s) return @"";
    for (size_t i = 0; i < n; i++) {
        s[i * 2] = h[p[i] >> 4];
        s[i * 2 + 1] = h[p[i] & 15];
    }
    s[n * 2] = 0;
    NSString *r = [NSString stringWithUTF8String:s];
    free(s);
    return r;
}

typedef struct {
    uint8_t *base;           // 运行期内存基址(mh 相对寻址算好, 主二进制进程内永不卸载)
    uint8_t *baseline;       // ctor 时刻快照(预触发)
    uint8_t *absBase;        // 绝对地址(sweep 用)
    uint64_t size;
    uint64_t vmaddr;         // 报告坐标: 主程序=unslid vmaddr, dylib 段=镜像相对偏移
    uint64_t fileoff;        // 段文件偏移(报告坐标用)
    BOOL noisy;              // __DATA = 噪声层, 只计数
    char name[20];
} mfCapSeg;

static mfCapSeg g_capSegs[8];
static int g_capNSeg = 0;
static uint32_t g_capEvents = 0;
static uint64_t g_capNoiseBytes = 0;
static uint64_t g_capNoiseTotal = 0;
static uint32_t g_capSweeps = 0;
static BOOL g_capOn = NO;
static dispatch_source_t g_capTimer;
static double g_capT0 = 0;

// imp 基线快照: "cls|sel" -> imp(主二进制类, ctor 时拍) — diff 出任意 imp 变化
static NSMutableDictionary *g_impSnap;

// ===== 层3: NSInvocation 窃听 — dylib 唯一明文手法面(13 个 selector 全是 invocation 链) =====
// v2.29.1 安全化: 2.29.0 在 XPC reply 路径崩(SIGSEGV@NSStringFromSelector strlen 野 selector)
//   铁律: 目标类非主二进制 → 直接放行不碰 selector; 字典操作上锁; selector 先过指针门
static IMP g_origInvoke = NULL, g_origInvokeWTH = NULL;
static NSMutableDictionary *g_invSeen;
static os_unfair_lock g_invLock = OS_UNFAIR_LOCK_INIT;
static uint32_t g_invCount = 0;


static void mfCapLogInv(NSInvocation *inv, const char *via) {
    @try {
        static NSString *g_mainExecStr = nil;
        static dispatch_once_t onceT;
        dispatch_once(&onceT, ^{ g_mainExecStr = [[[NSBundle mainBundle] executablePath] copy]; });
        if (!g_mainExecStr) return;
        id t = [inv target];
        if (!t) return;
        Class c = object_getClass(t);           // 目标有效则类指针安全
        if (!c) return;
        const char *img = class_getImageName(c);
        // v2.31.0: 主二进制 + 内嵌 Frameworks 目标 = 全量(类+selector — dylib 构造的 invocation 目标是合法 selector);
        //          系统框架目标 = 只记类名(永不解析 selector — 2.29.0 SIGSEGV 根源), 类名去重天然有界
        BOOL isMain = img && strstr(img, g_mainExecStr.fileSystemRepresentation) != NULL;
        BOOL embedded = img && strstr(img, "/Frameworks/") != NULL;
        if (isMain || embedded) {
            SEL s = [inv selector];
            if (!s || (uintptr_t)s < 0x1000) return; // 野 selector 指针门
            NSString *selName = NSStringFromSelector(s);
            if (!selName.length) return;
            NSString *key = [NSString stringWithFormat:@"F|%@|%@|%s", NSStringFromClass(c), selName, via];
            os_unfair_lock_lock(&g_invLock);
            BOOL dup = (g_invSeen[key] || g_invCount >= 200);
            if (!dup) { g_invSeen[key] = @YES; g_invCount++; }
            os_unfair_lock_unlock(&g_invLock);
            if (!dup) {
                const char *b = img ? strrchr(img, '/') : NULL;
                mfLog(@"[capture] INVOKE[%s] %@ -> %@ (img=%s)", via, NSStringFromClass(c), selName, b ? b + 1 : "?");
            }
        } else {
            NSString *key = [NSString stringWithFormat:@"S|%@", NSStringFromClass(c)];
            os_unfair_lock_lock(&g_invLock);
            BOOL dup = (g_invSeen[key] || g_invCount >= 200);
            if (!dup) { g_invSeen[key] = @YES; g_invCount++; }
            os_unfair_lock_unlock(&g_invLock);
            if (!dup) mfLog(@"[capture] INV-SYS %@", NSStringFromClass(c));   // 系统目标被 invocation 触碰 = 信号
        }
    } @catch (NSException *e) {}
}
static void mf_invHook(id self, SEL _cmd) {
    mfCapLogInv((NSInvocation *)self, "invoke");
    ((void (*)(id, SEL))g_origInvoke)(self, _cmd);
}
static void mf_invWTHook(id self, SEL _cmd, id target) {
    mfCapLogInv((NSInvocation *)self, "withTarget");
    ((void (*)(id, SEL, id))g_origInvokeWTH)(self, _cmd, target);
}
static void mfCapInstallInvocationTap(void) {
    if (g_origInvoke) return;
    Method m1 = class_getInstanceMethod([NSInvocation class], @selector(invoke));
    Method m2 = class_getInstanceMethod([NSInvocation class], @selector(invokeWithTarget:));
    if (m1) g_origInvoke = method_setImplementation(m1, (IMP)mf_invHook);
    if (m2) g_origInvokeWTH = method_setImplementation(m2, (IMP)mf_invWTHook);
    if (g_origInvoke) mfLog(@"[capture] NSInvocation tap installed");
}

// ===== 层6: NSUserDefaults 写监听 — 验证 "dylib 经 NSUserDefaults 伪造 RC 缓存" 假说 =====
static IMP g_origSetObj = NULL;
static uint32_t g_capCount6 = 0;
static void mf_setObjHook(id self, SEL _cmd, id value, NSString *key) {
    if (key && g_capCount6 < 40) {
        NSString *k = key.lowercaseString;
        if ([k containsString:@"revenuecat"] || [k containsString:@"entitlement"]
            || [k containsString:@"customer"] || [k containsString:@"reflix"]
            || [k containsString:@"purchases"] || [k containsString:@"subscri"]) {
            @try {
                NSString *vs = [value description];
                if (vs.length > 200) vs = [[vs substringToIndex:200] stringByAppendingString:@"…"];
                g_capCount6++;
                mfLog(@"[capture] UD-SET %@ = %@", key, vs);
            } @catch (NSException *e) {}
        }
    }
    ((void (*)(id, SEL, id, NSString *))g_origSetObj)(self, _cmd, value, key);
}

static void mfCapInstallUDTap(void) {
    if (g_origSetObj) return;
    Method m = class_getInstanceMethod([NSUserDefaults class], @selector(setObject:forKey:));
    if (!m) return;
    g_origSetObj = method_setImplementation(m, (IMP)mf_setObjHook);
    mfLog(@"[capture] NSUserDefaults write tap installed");
}

// ===== 层4: 主二进制引用扫描 — "app 是查询方"模型判决(名字引用 + mach 子系统常量) =====
static void mfCapScanMainBinary(void) {
    @try {
        NSString *path = [[NSBundle mainBundle] executablePath];
        NSData *d = [NSData dataWithContentsOfFile:path];
        if (!d) return;
        const uint8_t *p = d.bytes;
        NSUInteger n = d.length;
        const char *pats[] = {"ReflixPatch", "MinisFix", "/var/jb", "proAccessOverride"};
        for (int i = 0; i < 4; i++) {
            size_t pl = strlen(pats[i]);
            const uint8_t *hit = NULL;
            for (NSUInteger off = 0; off + pl <= n; off++)
                if (p[off] == pats[i][0] && memcmp(p + off, pats[i], pl) == 0) { hit = p + off; break; }
            if (hit) {
                char ctx[96] = {0};
                NSUInteger cs = (NSUInteger)(hit - p);
                memcpy(ctx, p + (cs > 24 ? cs - 24 : 0), MIN((NSUInteger)95, n - (cs > 24 ? cs - 24 : 0)));
                mfLog(@"[capture] MAINBIN '%s' @0x%lx ctx=%.95s", pats[i], cs, ctx);
            } else {
                mfLog(@"[capture] MAINBIN '%s' absent", pats[i]);
            }
        }
        // mach 子系统客户端特征: 0x965..0x967(请求) / 0x9c9..0x9cb(应答) u32 出现计数
        const uint32_t *u = (const uint32_t *)p;
        NSUInteger nu = n / 4;
        uint32_t want[6] = {0x965, 0x966, 0x967, 0x9c9, 0x9ca, 0x9cb};
        for (int i = 0; i < 6; i++) {
            uint32_t c = 0;
            for (NSUInteger j = 0; j < nu; j++) if (u[j] == want[i]) c++;
            mfLog(@"[capture] MAINBIN u32 0x%x count=%u", want[i], c);
        }
    } @catch (NSException *e) {}
}

static void mfCapWriteEvent(const mfCapSeg *sg, uint64_t off, uint64_t len,
                            const uint8_t *cur) {
    @try {
        NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/MinisFix"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        NSDictionary *r = @{
            @"seg": [NSString stringWithUTF8String:sg->name],
            @"vmaddr": [NSString stringWithFormat:@"0x%llx", sg->vmaddr + off],
            @"seg_offset": [NSString stringWithFormat:@"0x%llx", off],
            @"file_offset": [NSString stringWithFormat:@"0x%llx", sg->fileoff + off],
            @"length": @(len),
            @"baseline": mfCapHex(sg->baseline + off, (size_t)len),
            @"patched": mfCapHex(cur + off, (size_t)len),
            @"elapsed_s": @([[NSDate date] timeIntervalSinceReferenceDate] - g_capT0),
            @"event": @(g_capEvents),
        };
        NSString *path = [NSString stringWithFormat:@"%@/mfcap_%u_%s_0x%llx.json",
                          dir, g_capEvents, sg->name, off];
        NSData *d = [NSJSONSerialization dataWithJSONObject:r options:NSJSONWritingPrettyPrinted error:nil];
        if (d) [d writeToFile:path atomically:YES];
    } @catch (NSException *e) {}
}

// ===== 层2: ObjC imp 巡检 — dylib swizzle 点白送(imp 指进 dylib 镜像 = 被hook) =====
static uint8_t *g_capDylibBase = NULL;
static uint64_t g_capDylibSize = 0;
static NSMutableDictionary *g_capSeen;   // "类|sel" -> 每点只报一次

static void mfCapRecordSwizzle(NSString *cls, NSString *sel, uintptr_t imp) {
    NSString *key = [NSString stringWithFormat:@"%@|%@", cls, sel];
    if (g_capSeen[key]) return;
    g_capSeen[key] = @YES;
    uintptr_t off = imp - (uintptr_t)g_capDylibBase;
    @try {
        NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/MinisFix"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        NSDictionary *r = @{@"class": cls, @"selector": sel,
                            @"dylib_offset": [NSString stringWithFormat:@"0x%lx", (unsigned long)off]};
        NSString *path = [NSString stringWithFormat:@"%@/mfcap_swizzle_%@.json", dir,
                          [key stringByReplacingOccurrencesOfString:@"|" withString:@"_"]];
        NSData *d = [NSJSONSerialization dataWithJSONObject:r options:NSJSONWritingPrettyPrinted error:nil];
        if (d) [d writeToFile:path atomically:YES];
    } @catch (NSException *e) {}
    mfLog(@"[capture] SWIZZLE %@ -> %@ dylib_off=0x%lx", cls, sel, (unsigned long)off);
    g_capEvents++;
}

static void mfCapObjcSweep(void) {
    if (!g_capDylibBase) return;
    NSString *mainPath = [[NSBundle mainBundle] executablePath] ?: @"";
    unsigned int ncls = 0;
    Class *classes = objc_copyClassList(&ncls);
    if (!classes) return;
    for (unsigned int i = 0; i < ncls; i++) {
        NSString *cn = NSStringFromClass(classes[i]);
        const char *img = class_getImageName(classes[i]);
        BOOL isMain = img && mainPath.length && strstr(img, mainPath.fileSystemRepresentation) != NULL;
        for (int pass = 0; pass < 2; pass++) {
            Class target = pass == 0 ? classes[i] : object_getClass(classes[i]); // 实例方法/类方法
            unsigned int nm = 0;
            Method *ms = class_copyMethodList(target, &nm);
            for (unsigned int j = 0; j < nm; j++) {
                uintptr_t v = (uintptr_t)method_getImplementation(ms[j]);
                if (v >= (uintptr_t)g_capDylibBase && v < (uintptr_t)g_capDylibBase + g_capDylibSize) {
                    mfCapRecordSwizzle(cn, NSStringFromSelector(method_getName(ms[j])), v);
                }
                // v2.27.1 imp diff: 主二进制类的 imp 任意变化都报(瞬时 swizzle 的 0.5s 窗口捕获)
                if (isMain && g_impSnap) {
                    NSString *key = [NSString stringWithFormat:@"%@|%@|%@", cn,
                                     NSStringFromSelector(method_getName(ms[j])), pass ? @"+" : @"-"];
                    NSNumber *old = g_impSnap[key];
                    if (old && old.unsignedLongLongValue != v) {
                        Dl_info info; const char *zone = "unknown";
                        if (dladdr((void *)v, &info) && info.dli_fname) {
                            const char *b = strrchr(info.dli_fname, '/');
                            zone = b ? b + 1 : info.dli_fname;
                        }
                        mfLog(@"[capture] IMPCHG %s[%@%@] 0x%llx→0x%llx zone=%s",
                              pass ? "+" : "-", cn, NSStringFromSelector(method_getName(ms[j])),
                              (unsigned long long)old.unsignedLongLongValue, (unsigned long long)v, zone);
                        if (g_impSnap) g_impSnap[key] = @(v);
                        g_capEvents++;
                    } else if (!old) {
                        g_impSnap[key] = @(v);
                    }
                }
            }
            free(ms);
        }
    }
    free(classes);
}

// imp 基线: 主二进制类全方法表(ctor, 激活前) — 只建一次
static void mfCapBuildImpBaseline(void) {
    if (g_impSnap) return;
    g_impSnap = [NSMutableDictionary dictionary];
    NSString *mainPath = [[NSBundle mainBundle] executablePath] ?: @"";
    unsigned int ncls = 0;
    Class *classes = objc_copyClassList(&ncls);
    if (!classes) return;
    unsigned long cnt = 0;
    for (unsigned int i = 0; i < ncls; i++) {
        const char *img = class_getImageName(classes[i]);
        if (!img || !mainPath.length || !strstr(img, mainPath.fileSystemRepresentation)) continue;
        NSString *cn = NSStringFromClass(classes[i]);
        for (int pass = 0; pass < 2; pass++) {
            Class target = pass == 0 ? classes[i] : object_getClass(classes[i]);
            unsigned int nm = 0;
            Method *ms = class_copyMethodList(target, &nm);
            for (unsigned int j = 0; j < nm; j++) {
                NSString *key = [NSString stringWithFormat:@"%@|%@|%@", cn,
                                 NSStringFromSelector(method_getName(ms[j])), pass ? @"+" : @"-"];
                g_impSnap[key] = @((unsigned long long)method_getImplementation(ms[j]));
                cnt++;
            }
            free(ms);
        }
    }
    free(classes);
    mfLog(@"[capture] imp baseline: %lu methods of main-binary classes", cnt);
}

static void mfCapLocateDylib(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, "ReflixPatch")) {
            const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
            if (h && h->magic == MH_MAGIC_64) {
                // load commands 求 __LINKEDIT 段末 = 镜像 vm 范围
                const uint8_t *p = (const uint8_t *)(h + 1);
                uint64_t end = 0;
                for (uint32_t k = 0; k < h->ncmds; k++) {
                    const struct load_command *lc = (const struct load_command *)p;
                    if (lc->cmdsize < sizeof(*lc)) break;
                    if (lc->cmd == LC_SEGMENT_64) {
                        const struct segment_command_64 *sg = (const struct segment_command_64 *)p;
                        if (sg->vmaddr + sg->vmsize > end) end = sg->vmaddr + sg->vmsize;
                    }
                    p += lc->cmdsize;
                }
                g_capDylibBase = (uint8_t *)h;
                g_capDylibSize = end ?: 0x1e4000;   // dylib 段 vmaddr 从 0 起, 镜像内偏移即范围
                mfLog(@"[capture] dylib in-proc @%p size=0x%llx (imp sweep armed)", g_capDylibBase, (unsigned long long)g_capDylibSize);
            }
            return;
        }
    }
}

void mfProcCaptureStart(void) {
    if (g_capOn) return;
    NSString *bid = [NSBundle mainBundle].bundleIdentifier;
    NSString *ver = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    if (![bid isEqualToString:kCapBID] || ![ver isEqualToString:kCapVersion]) return;

    // v2.28.1: debug 通道已证伪(2.28.0 实测写入正确域仍不亮) — 默认关, 别污染采集对照
    if ([[NSUserDefaults standardUserDefaults] boolForKey:@"mfDebugOverride"]) {
        NSString *dbg = @"com.reflix.debug.proAccessOverride";
        id cur = [[NSUserDefaults standardUserDefaults] objectForKey:dbg];
        if (![cur isKindOfClass:[NSString class]] || ![cur isEqualToString:@"active"]) {
            [[NSUserDefaults standardUserDefaults] setObject:@"active" forKey:dbg];
            [[NSUserDefaults standardUserDefaults] synchronize];
            mfLog(@"[mfdbg] proAccessOverride -> active (was %@)", cur ?: @"nil");
        } else {
            mfLog(@"[mfdbg] proAccessOverride already active");
        }
    }

    const struct mach_header_64 *mh = NULL;
    intptr_t mainSlide = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h && h->magic == MH_MAGIC_64 && h->filetype == MH_EXECUTE) {
            mh = (const struct mach_header_64 *)h;
            mainSlide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    if (!mh) return;

    // 段表解析 + 快照。主二进制 __PIE__: 运行期地址 = mh + (vmaddr - __TEXT.vmaddr)
    uint64_t textVM = 0;
    {
        const uint8_t *q = (const uint8_t *)(mh + 1);
        for (uint32_t i = 0; i < mh->ncmds; i++) {
            const struct load_command *lc = (const struct load_command *)q;
            if (lc->cmdsize < sizeof(*lc)) break;
            if (lc->cmd == LC_SEGMENT_64 &&
                !strncmp(((const struct segment_command_64 *)q)->segname, "__TEXT", 16)) {
                textVM = ((const struct segment_command_64 *)q)->vmaddr;
                break;
            }
            q += lc->cmdsize;
        }
    }
    if (!textVM) { mfLog(@"[capture] __TEXT vmaddr not found"); return; }

    const uint8_t *p = (const uint8_t *)(mh + 1);
    uint64_t totalSnap = 0;
    for (uint32_t i = 0; i < mh->ncmds && g_capNSeg < 8; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof(*lc)) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sgp = (const struct segment_command_64 *)p;
            BOOL isText = !strncmp(sgp->segname, "__TEXT", 16);
            BOOL isDC   = !strncmp(sgp->segname, "__DATA_CONST", 16);
            BOOL isData = !strncmp(sgp->segname, "__DATA", 16) && !isDC;
            if ((isText || isDC || isData) && sgp->vmsize > 0 &&
                totalSnap + sgp->vmsize <= 96ULL * 1024 * 1024) {
                uint8_t *abs = (uint8_t *)((uintptr_t)mh + (sgp->vmaddr - textVM));
                uint8_t *snap = malloc((size_t)sgp->vmsize);
                if (snap) {
                    mfCapSeg *sg = &g_capSegs[g_capNSeg];
                    memset(sg, 0, sizeof(*sg));
                    strncpy(sg->name, sgp->segname, 19);
                    sg->base = sg->absBase = abs;
                    sg->baseline = snap;
                    sg->size = sgp->vmsize;
                    sg->vmaddr = sgp->vmaddr;
                    sg->fileoff = sgp->fileoff;
                    sg->noisy = isData;
                    memcpy(snap, abs, (size_t)sgp->vmsize);   // 预触发快照
                    totalSnap += sgp->vmsize;
                    g_capNSeg++;
                    mfLog(@"[capture] baseline@ctor %s vm=0x%llx size=0x%llx @%p",
                          sg->name, sg->vmaddr, sg->size, abs);
                }
            }
        }
        p += lc->cmdsize;
    }
    if (!g_capNSeg) { mfLog(@"[capture] no segments snapshotted"); return; }

    g_capT0 = [[NSDate date] timeIntervalSinceReferenceDate];
    g_capOn = YES;
    g_capSeen = [NSMutableDictionary dictionary];
    // 层2 就位: 先拍 imp 基线(必须在 dlopen 之前! 否则 dylib ctor 期 swizzle 被基线吃掉, IMPCHG 失明)
    mfCapBuildImpBaseline();
    mfCapLocateDylib();
    if (!g_capDylibBase) {
        // v2.28.1: dlopen 兜底默认 ON(采集工作模式 — 增强采集需要 dylib 在场被逮)
        if ([[NSUserDefaults standardUserDefaults] objectForKey:@"mfCaptureDlopen"] == nil
            || [[NSUserDefaults standardUserDefaults] boolForKey:@"mfCaptureDlopen"]) {
            void *h = dlopen(kCapDylib.UTF8String, RTLD_NOW | RTLD_LOCAL);
            if (h) { mfLog(@"[capture] dlopened vendor dylib (fallback)"); mfCapLocateDylib();
                     if (g_capDylibBase) mfCapObjcSweep();  // dlopen 后立即扫一轮: 逮 ctor 期 swizzle
            }
            else mfLog(@"[capture] vendor dylib absent (fallback ON but load failed)");
        } else {
            mfLog(@"[capture] vendor dylib absent (dlopen fallback OFF) — clean-run mode");
        }
    }
    // v2.27.1: dylib 自身 __DATA/__bss 状态区快照(激活证据层)
    if (g_capDylibBase) {
        const uint8_t *dp = (const uint8_t *)g_capDylibBase;
        const struct mach_header_64 *dh = (const struct mach_header_64 *)g_capDylibBase;
        dp = (const uint8_t *)(dh + 1);
        for (uint32_t k = 0; k < dh->ncmds && g_capNSeg < 8; k++) {
            const struct load_command *lc = (const struct load_command *)dp;
            if (lc->cmdsize < sizeof(*lc)) break;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sgp = (const struct segment_command_64 *)dp;
                BOOL isD = !strncmp(sgp->segname, "__DATA", 16);
                BOOL isDC = !strncmp(sgp->segname, "__DATA_CONST", 16);
                if ((isD && !isDC) || isDC) {   // v2.28.0: __DATA_CONST 也盯(__got 自体 fishhook 隐身点)
                    mfCapSeg *sg = &g_capSegs[g_capNSeg];
                    memset(sg, 0, sizeof(*sg));
                    snprintf(sg->name, 19, "dylib.%s", sgp->segname);
                    sg->base = sg->absBase = (uint8_t *)g_capDylibBase + sgp->vmaddr;
                    sg->vmaddr = sgp->vmaddr;       // dylib 段从 0 起 = 相对偏移
                    sg->fileoff = sgp->fileoff;
                    sg->size = MIN(sgp->vmsize, 2ULL * 1024 * 1024); // dylib.__DATA 0x48000 实际
                    sg->noisy = NO;
                    sg->baseline = malloc((size_t)sg->size);
                    if (sg->baseline) {
                        memcpy(sg->baseline, sg->absBase, (size_t)sg->size);
                        g_capNSeg++;
                        mfLog(@"[capture] dylib state watch %s off=0x%llx size=0x%llx", sg->name, sg->vmaddr, sg->size);
                    }
                }
            }
            dp += lc->cmdsize;
        }
        // imp 基线已在 dlopen 之前拍完(见上) — 这里不再重复
    }
    // v2.29.0: 审讯层 — NSInvocation 窃听 + 主二进制引用扫描
    g_invSeen = [NSMutableDictionary dictionary];
    mfCapInstallInvocationTap();
    mfCapInstallUDTap();
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ mfCapScanMainBinary(); });
    // v2.30.0: 层5 — 主二进制 mach_msg 重绑(license 客户端握手双向捕获)
    if (mh) mfCapInstallMachTap(mh, mainSlide);
    g_capTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_timer(g_capTimer,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kCapPollSec * NSEC_PER_SEC)),
                              (uint64_t)(kCapPollSec * NSEC_PER_SEC), (uint64_t)(0.5 * NSEC_PER_SEC));

    dispatch_source_set_event_handler(g_capTimer, ^{
        if (g_capEvents >= kCapMaxEvents) { dispatch_suspend(g_capTimer); return; }
        g_capSweeps++;
        // 层2 优先: dylib 在进程内才巡检(被 TrollFools 移除 = 永不触发)
        if (g_capDylibBase) mfCapObjcSweep();
        uint64_t noiseNow = 0;
        for (int s = 0; s < g_capNSeg; s++) {
            mfCapSeg *sg = &g_capSegs[s];
            if (!sg->baseline) continue;
            uint8_t *cur = sg->absBase;
            uint64_t hit = 0;
            for (uint64_t i = 0; i < sg->size;) {
                if (sg->baseline[i] == cur[i]) { i++; continue; }
                uint64_t start = i;
                while (i < sg->size && sg->baseline[i] != cur[i]) i++;
                uint64_t len = i - start;
                hit += len;
                if (!sg->noisy && g_capEvents < kCapMaxEvents) {
                    mfCapWriteEvent(sg, start, len, cur);
                    mfLog(@"[capture] #%u %s vm=0x%llx segoff=0x%llx len=%llu %s→%s",
                          g_capEvents, sg->name, sg->vmaddr + start, start,
                          (unsigned long long)len,
                          mfCapHex(sg->baseline + start, 16), mfCapHex(cur + start, 16));
                    g_capEvents++;
                }
            }
            if (sg->noisy) noiseNow += hit;
            // 基线推进: 已见变化不重报(每个 patch 点只报一次)
            memcpy(sg->baseline, cur, (size_t)sg->size);
        }
        // v2.27.1: __DATA 噪声可见化 — 有增量就累计, 每 40 sweep(20s)汇总一次防刷屏
        if (noiseNow > 0) {
            g_capNoiseTotal += noiseNow;
            if (g_capSweeps % 40 == 0)
                mfLog(@"[capture] __DATA noise +0x%llx this window, total 0x%llu bytes",
                      (unsigned long long)noiseNow, (unsigned long long)g_capNoiseTotal);
        }
        if (g_capEvents >= kCapMaxEvents) {
            mfLog(@"[capture] event cap reached (%u), sweep stops", g_capEvents);
            dispatch_suspend(g_capTimer);
        }
    });
    mfLog(@"[capture] ON segs=%d snap=%.1fMB poll=%.1fs (passive, no hooks)",
          g_capNSeg, totalSnap / 1048576.0, kCapPollSec);
}

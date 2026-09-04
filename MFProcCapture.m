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

static NSString *const kCapBID = @"com.magicgroot.gooby";
static NSString *const kCapVersion = @"3.0.5";
static NSString *const kCapDylib = @"/var/jb/usr/lib/MinisFix/ReflixPatch-3.0.5.dylib";
static const NSTimeInterval kCapPollSec = 2.0;
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
    uint64_t size;
    uint64_t vmaddr;         // unslid vmaddr(报告坐标用)
    uint64_t fileoff;        // 段文件偏移(报告坐标用)
    BOOL noisy;              // __DATA = 噪声层, 只计数
    char name[20];
} mfCapSeg;

static mfCapSeg g_capSegs[8];
static int g_capNSeg = 0;
static uint32_t g_capEvents = 0;
static uint64_t g_capNoiseBytes = 0;
static BOOL g_capOn = NO;
static dispatch_source_t g_capTimer;
static double g_capT0 = 0;

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
    unsigned int ncls = 0;
    Class *classes = objc_copyClassList(&ncls);
    if (!classes) return;
    for (unsigned int i = 0; i < ncls; i++) {
        NSString *cn = NSStringFromClass(classes[i]);
        for (int pass = 0; pass < 2; pass++) {
            Class target = pass == 0 ? classes[i] : object_getClass(classes[i]); // 实例方法/类方法
            unsigned int nm = 0;
            Method *ms = class_copyMethodList(target, &nm);
            for (unsigned int j = 0; j < nm; j++) {
                uintptr_t v = (uintptr_t)method_getImplementation(ms[j]);
                if (v >= (uintptr_t)g_capDylibBase && v < (uintptr_t)g_capDylibBase + g_capDylibSize) {
                    mfCapRecordSwizzle(cn, NSStringFromSelector(method_getName(ms[j])), v);
                }
            }
            free(ms);
        }
    }
    free(classes);
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
                g_capDylibSize = end ? end - h->vmaddr : 0x1e4000;
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

    const struct mach_header_64 *mh = NULL;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h && h->magic == MH_MAGIC_64 && h->filetype == MH_EXECUTE) {
            mh = (const struct mach_header_64 *)h;
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
                    sg->base = abs;
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
    // 层2 就位: dylib 已被注入(TrollFools)则定位之; 未注入则按开关 dlopen 兜底
    mfCapLocateDylib();
    if (!g_capDylibBase) {
        void *h = dlopen(kCapDylib.UTF8String, RTLD_NOW | RTLD_LOCAL);
        if (h) { mfLog(@"[capture] dlopened vendor dylib (fallback)"); mfCapLocateDylib(); }
        else mfLog(@"[capture] vendor dylib absent — imp sweep idle, mem-diff layer only");
    }
    g_capTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_timer(g_capTimer,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kCapPollSec * NSEC_PER_SEC)),
                              (uint64_t)(kCapPollSec * NSEC_PER_SEC), (uint64_t)(0.5 * NSEC_PER_SEC));
    __block uint8_t *bbase = (uint8_t *)mh;
    __block uint64_t btext = textVM;

    dispatch_source_set_event_handler(g_capTimer, ^{
        if (g_capEvents >= kCapMaxEvents) { dispatch_suspend(g_capTimer); return; }
        // 层2 优先: dylib 在进程内才巡检(被 TrollFools 移除 = 永不触发)
        if (g_capDylibBase) mfCapObjcSweep();
        for (int s = 0; s < g_capNSeg; s++) {
            mfCapSeg *sg = &g_capSegs[s];
            uint8_t *cur = bbase + (sg->vmaddr - btext);
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
            if (sg->noisy) g_capNoiseBytes += hit;
            // 基线推进: 已见变化不重报(每个 patch 点只报一次)
            memcpy(sg->baseline, cur, (size_t)sg->size);
        }
        if (g_capEvents >= kCapMaxEvents) {
            mfLog(@"[capture] event cap reached (%u), sweep stops", g_capEvents);
            dispatch_suspend(g_capTimer);
        }
    });
    mfLog(@"[capture] ON segs=%d snap=%.1fMB poll=%.0fs (passive, no hooks)",
          g_capNSeg, totalSnap / 1048576.0, kCapPollSec);
}

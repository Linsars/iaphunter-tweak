// MFProcCapture.m — 第二拳·点位采集器 (被动内存差分, 零 hook)
// 原理: ReflixPatch 由 RC 响应延迟自激活(实测 ctor 后 ~7s), 我方 ctor 先全量快照
//       主二进制 __TEXT/__DATA_CONST/__DATA(预触发保证), 之后 2s 周期 diff。
//       持久 patch 必留痕 → 每个变化区 = 一个 patch 点位 + 前后字节。
// 纪律: 不 hook vm_protect(backtrace 反 hook, v2.20 崩溃根因), 不引用目标 dylib
//       任何符号, 纯内存读。
// 分层: __TEXT/__DATA_CONST 变化 = patch 事件(落盘+hostlog);
//       __DATA 变化 = 运行期全局写噪声, 只累计不落盘(防挤爆事件额度)。
//       基线每轮推进 → 每个 patch 点只报一次, 后续轮询零成本。
// 产出: Documents/MinisFix/mfcap_<seq>_<seg>_<off>.json + hostlog 每事件一行

#import "MFPanel.h"
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

static NSString *const kCapBID = @"com.magicgroot.gooby";
static NSString *const kCapVersion = @"3.0.5";
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
    g_capTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_timer(g_capTimer,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kCapPollSec * NSEC_PER_SEC)),
                              (uint64_t)(kCapPollSec * NSEC_PER_SEC), (uint64_t)(0.5 * NSEC_PER_SEC));
    __block uint8_t *bbase = (uint8_t *)mh;
    __block uint64_t btext = textVM;

    dispatch_source_set_event_handler(g_capTimer, ^{
        if (g_capEvents >= kCapMaxEvents) { dispatch_suspend(g_capTimer); return; }
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

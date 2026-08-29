// MFCompatPatcher.m — iOS 18+ SDK 向下兼容补丁（CompatPatcher.dylib）
//
// 场景: 用户装了个 Xcode 26(Swift 6.2) 编译的 app, iOS 17 启动即 SIGSEGV pc=0。
// 根因(AllPic 实战实锤): app 生成代码引用 4 个 iOS 18+ 才有的 Swift runtime 弱符号,
// iOS 17 libswiftCore 缺失 → dyld 绑 GOT=0 → 无判空的调用点 bl 0 崩。
//
// 本 dylib 在每个 UIKit 进程 ctor 里做「运行时 GOT 修复」,不改 app 文件:
//   解析主镜像 dyld_chained_fixups(blob 仍在内存) → 找到 4 符号的 GOT 槽 →
//   mprotect → 写等价实现地址(getExtended→6参版转发/malloc/ret1/noop)。
//
// 与「1 刀文件手术」行为等价但零重签、随偏好开关、跨 app 通用。
// 数据源: /var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist 的 mfCompatAppList。

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <sys/mman.h>
#import <dlfcn.h>
#import <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>

// 调试日志——双通道:
// 1) 偏好诊断 mfCompatDiag(跨进程可读,SSH 直接 cat,崩溃不失)——主通道
// 2) 沙盒 Documents 日志(NSHomeDirectory 直拼,不依赖 NSSearchPath 早期行为)
#define MF_PREF_PATH "/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"

static void mfCompatDiag(NSString *step, NSString *detail) {
    @autoreleasepool {
        NSMutableDictionary *prefs = [[NSDictionary dictionaryWithContentsOfFile:@MF_PREF_PATH] mutableCopy] ?: [NSMutableDictionary dictionary];
        NSMutableDictionary *diag = [prefs[@"mfCompatDiag"] mutableCopy] ?: [NSMutableDictionary dictionary];
        diag[step] = detail ?: @"";
        diag[@"last_pid"] = @(getpid());
        diag[@"last_bid"] = [[NSBundle mainBundle] bundleIdentifier] ?: @"?";
        prefs[@"mfCompatDiag"] = diag;
        [prefs writeToFile:@MF_PREF_PATH atomically:YES];
    }
}

static void mfCompatLog(const char *fmt, ...) {
    @autoreleasepool {
        va_list ap;
        va_start(ap, fmt);
        char buf[512];
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        // 通道 2: NSHomeDirectory 直拼(ctor 早期最稳)
        NSString *home = NSHomeDirectory();
        if (home) {
            FILE *f = fopen([[home stringByAppendingPathComponent:@"Documents/mfcompat.log"] UTF8String], "a");
            if (f) { fprintf(f, "%s\n", buf); fclose(f); }
        }
    }
}

// ---- dyld_chained_fixups 结构(apple-oss-distributions/dyld include/mach-o/fixup-chains.h) ----
#define LC_DYLD_CHAINED_FIXUPS 0x80000034
#define DYLD_CHAINED_PTR_64_OFFSET 6

struct dyld_chained_fixups_header {
    uint32_t fixups_version;
    uint32_t starts_offset;
    uint32_t imports_offset;
    uint32_t symbols_offset;
    uint32_t imports_count;
    uint32_t imports_format;   // 1 = DYLD_CHAINED_IMPORT(4B: lib_ordinal:8 weak:1 name_offset:23)
    uint32_t symbols_format;
};

struct dyld_chained_starts_in_image {
    uint32_t seg_count;
    uint32_t seg_info_offset[1];
};

struct dyld_chained_starts_in_segment {
    uint32_t size;
    uint16_t page_size;
    uint16_t pointer_format;
    uint64_t segment_offset;
    uint32_t max_valid_pointer;
    uint8_t  page_count;        // uint8, 后面紧跟 uint16 page_start[]
};

// ---- 4 符号对照表 ----
static const char *kTgt[4] = {
    "_swift_getExtendedFunctionTypeMetadata",
    "_swift_coroFrameAlloc",
    "_swift_stdlib_isStackAllocationSafe",
    "_swift_task_deinitOnExecutor",
};

// 等价实现
static void *g_impl[4];

// 调用点签名: isStackSafe(p, align) 返回 bool; deinitOnExecutor 4 参数。
static int compat_isStackSafe(void *p, size_t align) { return 1; }
static void compat_deinitNoop(void *obj, void *work, void *exec, void *flags) {}

// ---- 主镜像 mach_header / slide / 段表 ----
static const struct mach_header_64 *g_mh;
static intptr_t g_slide;
typedef struct { uint64_t vmaddr, vmsize, fileoff, filesize; } MFseg;
static MFseg g_segs[16];
static int g_segCount;

// LC_DYLD_CHAINED_FIXUPS 的数据(file offset)
static uint32_t g_fixDataoff;

// 主二进制磁盘文件句柄——chained fixup entry 内联在槽里,dyld 已消费(槽=绑定结果),
// 原始 entry 只能从磁盘读(文件偏移与 starts 链语义一致)
static FILE *g_binFp;

static uint64_t mfReadFileU64(uint64_t fileoff) {
    uint64_t v = 0;
    if (!g_binFp) return 0;
    fseek(g_binFp, (long)fileoff, SEEK_SET);   // iOS long=64 位, <4GB 安全
    if (fread(&v, 8, 1, g_binFp) != 1) return 0;
    return v;
}

static void mfParseLcs(void) {
    g_segCount = 0;
    g_fixDataoff = 0;
    const uint8_t *base = (const uint8_t *)g_mh;
    uint32_t ncmds = g_mh->ncmds;
    uint32_t off = sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd = *(uint32_t *)(base + off);
        uint32_t cs  = *(uint32_t *)(base + off + 4);
        if (cmd == LC_SEGMENT_64 && g_segCount < 16) {
            MFseg s;
            memcpy(&s.vmaddr, base + off + 24, 8);
            memcpy(&s.vmsize, base + off + 32, 8);
            memcpy(&s.fileoff, base + off + 40, 8);
            memcpy(&s.filesize, base + off + 48, 8);
            g_segs[g_segCount++] = s;
        } else if (cmd == LC_DYLD_CHAINED_FIXUPS) {
            memcpy(&g_fixDataoff, base + off + 8, 4);
        }
        off += cs;
    }
}

// 文件偏移 → 运行时 vm 指针
static uint8_t *mfFileOffToPtr(uint64_t fileoff) {
    for (int i = 0; i < g_segCount; i++) {
        if (fileoff >= g_segs[i].fileoff && fileoff < g_segs[i].fileoff + g_segs[i].filesize) {
            return (uint8_t *)(g_slide + g_segs[i].vmaddr + (fileoff - g_segs[i].fileoff));
        }
    }
    return NULL;
}

// 遍历 fixup 链, 把 4 个目标 ordinals 的槽地址填进 outSlots(下标按 kTgt 序号)
static int mfFindTargetSlots(uint8_t *blob, const int *tgtOrd, void **outSlots) {
    struct dyld_chained_fixups_header *hdr = (struct dyld_chained_fixups_header *)blob;
    uint8_t *starts = blob + hdr->starts_offset;
    struct dyld_chained_starts_in_image *img = (struct dyld_chained_starts_in_image *)starts;
    uint32_t segCount = img->seg_count;
    if (segCount > 16) segCount = 16;
    int found = 0;
    for (uint32_t si = 0; si < segCount; si++) {
        uint32_t segOff = img->seg_info_offset[si];
        if (!segOff) continue;
        struct dyld_chained_starts_in_segment *ss =
            (struct dyld_chained_starts_in_segment *)(starts + segOff);
        if (ss->pointer_format != DYLD_CHAINED_PTR_64_OFFSET) continue; // 只处理本 app 实际格式
        uint32_t pageSize = ss->page_size;
        uint8_t *pageStart = (uint8_t *)ss + 21; // size(4)+page_size(2)+fmt(2)+seg_off(8)+max(4)+count(1)
        for (uint32_t pi = 0; pi < ss->page_count; pi++) {
            uint16_t ps = *(uint16_t *)(pageStart + pi * 2);
            if (ps == 0xFFFF) continue; // orphaned
            uint64_t ptrFile = ss->segment_offset + (uint64_t)pi * pageSize + ps;
            for (int guard = 0; guard < 500000; guard++) {
                uint64_t raw = mfReadFileU64(ptrFile);   // 原始 entry 必须从磁盘读(dyld 已改写运行时槽)
                uint32_t nxt = (uint32_t)((raw >> 51) & 0xFFF);
                if ((raw >> 63) & 1) { // bind
                    uint32_t ord = (uint32_t)(raw & 0xFFFFFF);
                    for (int t = 0; t < 4; t++) {
                        if (ord == tgtOrd[t] && outSlots[t] == NULL) {
                            outSlots[t] = (void *)mfFileOffToPtr(ptrFile); // 运行时槽地址(写槽用)
                            if (++found == 4) return found;
                        }
                    }
                }
                if (!nxt) break;
                ptrFile += (uint64_t)nxt * 4; // 64_OFFSET stride=4
            }
        }
    }
    return found;
}

// 主流程: 解析 imports → 名字匹配 → 找槽 → mprotect 写
static void mfCompatPatchMainBinary(void) {
    g_mh = _dyld_get_image_header(0);
    g_slide = _dyld_get_image_vmaddr_slide(0);
    mfCompatDiag(@"step_enter", [NSString stringWithFormat:@"slide=%p", (void *)g_slide]);
    if (!g_mh) { mfCompatDiag(@"fail", @"no mh"); return; }
    mfParseLcs();
    if (!g_fixDataoff) { mfCompatDiag(@"fail", @"no chained fixups LC"); return; }
    mfCompatDiag(@"step_fixdata", [NSString stringWithFormat:@"fix=%#x segs=%d", g_fixDataoff, g_segCount]);

    // 打开磁盘二进制(读原始 fixup entry 用)
    NSString *exePath = [[NSBundle mainBundle] executablePath];
    if (exePath.length) g_binFp = fopen([exePath fileSystemRepresentation], "rb");
    if (!g_binFp) { mfCompatDiag(@"fail", @"fopen exe FAIL"); return; }

    uint8_t *blob = mfFileOffToPtr(g_fixDataoff);
    if (!blob) { mfCompatDiag(@"fail", @"blob ptr NULL"); fclose(g_binFp); g_binFp = NULL; return; }
    struct dyld_chained_fixups_header *hdr = (struct dyld_chained_fixups_header *)blob;
    mfCompatDiag(@"step_blob", [NSString stringWithFormat:@"fmt=%u count=%u", hdr->imports_format, hdr->imports_count]);
    if (hdr->imports_format != 1) { mfCompatDiag(@"fail", @"imports fmt != 1"); fclose(g_binFp); g_binFp = NULL; return; }
    uint8_t *imports = blob + hdr->imports_offset;
    uint8_t *symbols = blob + hdr->symbols_offset;

    // dlsym 等价实现
    g_impl[0] = dlsym(RTLD_DEFAULT, "swift_getFunctionTypeMetadata");
    if (!g_impl[0]) g_impl[0] = dlsym(RTLD_DEFAULT, "_swift_getFunctionTypeMetadata");
    g_impl[1] = dlsym(RTLD_DEFAULT, "malloc");
    if (!g_impl[1]) g_impl[1] = dlsym(RTLD_DEFAULT, "_malloc");
    g_impl[2] = (void *)compat_isStackSafe;
    g_impl[3] = (void *)compat_deinitNoop;
    if (!g_impl[0] || !g_impl[1]) {
        mfCompatDiag(@"fail", [NSString stringWithFormat:@"dlsym null g0=%p g1=%p", g_impl[0], g_impl[1]]);
        fclose(g_binFp); g_binFp = NULL; return;
    }

    // imports 名字 → ordinal
    int tgtOrd[4] = {-1, -1, -1, -1};
    int tgtCnt = 0;
    for (uint32_t i = 0; i < hdr->imports_count; i++) {
        uint32_t v = *(uint32_t *)(imports + i * 4);
        uint32_t nameOff = (v >> 9) & 0x7FFFFF;
        const char *name = (const char *)(symbols + nameOff);
        for (int t = 0; t < 4; t++) {
            if (tgtOrd[t] < 0 && strcmp(name, kTgt[t]) == 0) {
                tgtOrd[t] = (int)i;
                tgtCnt++;
            }
        }
        if (tgtCnt == 4) break;
    }
    mfCompatDiag(@"step_imports", [NSString stringWithFormat:@"tgtCnt=%d o=%d,%d,%d,%d", tgtCnt, tgtOrd[0], tgtOrd[1], tgtOrd[2], tgtOrd[3]]);
    if (tgtCnt == 0) { mfCompatDiag(@"fail", @"no target imports"); fclose(g_binFp); g_binFp = NULL; return; }

    void *slots[4] = {NULL, NULL, NULL, NULL};
    int found = mfFindTargetSlots(blob, tgtOrd, slots);
    mfCompatDiag(@"step_slots", [NSString stringWithFormat:@"found=%d s=%p,%p,%p,%p", found, slots[0], slots[1], slots[2], slots[3]]);
    if (!found) { mfCompatDiag(@"fail", @"no slots"); fclose(g_binFp); g_binFp = NULL; return; }

    int patched = 0;
    for (int t = 0; t < 4; t++) {
        if (!slots[t] || !g_impl[t]) continue;
        uint64_t page = (uint64_t)slots[t] & ~(uint64_t)(sysconf(_SC_PAGESIZE) - 1);
        if (mprotect((void *)page, (size_t)sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE) != 0) {
            mfCompatDiag(@"fail", [NSString stringWithFormat:@"mprotect t=%d errno=%d", t, errno]);
            continue;
        }
        *(void **)slots[t] = g_impl[t];
        mprotect((void *)page, (size_t)sysconf(_SC_PAGESIZE), PROT_READ);
        patched++;
    }
    mfCompatDiag(@"done", [NSString stringWithFormat:@"patched=%d", patched]);
    fclose(g_binFp);
    g_binFp = NULL;
}

// ---- 偏好读取(与 MFPanel.m 同源) ----
static BOOL mfCompatNeeded(void) {
    static NSString *path = nil;
    if (!path) path = @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist";
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:path] ?: @{};
    NSArray *list = d[@"mfCompatAppList"];
    if (![list isKindOfClass:[NSArray class]] || list.count == 0) return NO;
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (bid.length == 0) return NO;
    return [list containsObject:bid];
}

__attribute__((constructor)) static void CompatPatcherCtor(void) {
    @autoreleasepool {
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        mfCompatDiag(@"ctor", [NSString stringWithFormat:@"pid=%d bid=%@", getpid(), bid ?: @"NIL"]);
        // 系统进程守卫(与 IAPtools 同律): 只服务用户 app
        if (bid.length == 0 || [bid.lowercaseString hasPrefix:@"com.apple."]) return;
        BOOL needed = mfCompatNeeded();
        mfCompatDiag(@"needed", needed ? @"YES" : @"NO");
        if (!needed) return;
        mfCompatPatchMainBinary();
    }
}

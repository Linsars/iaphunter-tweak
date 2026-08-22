// MFDiagnostics.m — T0 金矿开采 (v1.6.0 新增)
// 思路来源：ToolsEric UCPTSecurityScannerVC(八连扫) + UCPTMachODeepVC(MachO深检) 方法表逆向，
// 实现全部自研。零第三方依赖。

#import "MFPanel.h"
#import <Security/Security.h>
#import <mach-o/dyld.h>
// SecTask 私有 API（同 MFKeychainManager.m，SDK 未公开头文件）
typedef struct CF_BRIDGED_TYPE(id) OpaqueSecTaskRef *SecTaskRef;
extern SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task, CFStringRef entitlement, CFErrorRef *error);
// 本地 nlist_64（绕开 modules 与 loader.h 的定义冲突）
struct mf_nlist_64 { uint32_t n_strx; uint8_t n_type; uint8_t n_sect; uint16_t n_desc; uint64_t n_value; };
#include <sys/sysctl.h>
#include <sys/types.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#include <mach/mach.h>
#include <dlfcn.h>

// csops 系统调用（不引私有头）
#ifndef CS_OPS_STATUS
#define CS_OPS_STATUS 0
#endif
#define MF_CS_VALID        0x00000001
#define MF_CS_ADHOC        0x00000002
#define MF_CS_GET_TASK_ALLOW 0x00000004
#define MF_CS_DEBUGGED     0x00000010
#define MF_CS_KILL         0x00000200
#define MF_CS_RESTRICT     0x00000800
#define MF_CS_PLATFORM_BINARY 0x04000000

extern char **environ;

#pragma mark - ====== 八连扫实现 ======

static NSString *mfScanJailbreak(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【越狱检测】\n"];
    NSArray<NSString *> *paths = @[
        @"/Applications/Cydia.app", @"/Applications/Sileo.app", @"/Applications/Zebra.app",
        @"/Applications/Filza.app", @"/Applications/TrollStore.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
        @"/usr/lib/libsubstrate.dylib", @"/usr/lib/substitute-inserter.dylib",
        @"/usr/lib/ellekit.dylib", @"/usr/lib/TweakInject.dylib",
        @"/private/var/jb", @"/private/jailbreak_test", @"/var/jb/usr/libexec/substrate",
        @"/bin/bash", @"/bin/sh", @"/usr/sbin/sshd", @"/etc/apt", @"/etc/ssh/sshd_config",
        @"/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
    ];
    int found = 0;
    for (NSString *p in paths) {
        BOOL exists = access(p.fileSystemRepresentation, F_OK) == 0;
        if (exists) { [r appendFormat:@"  🔴 %@\n", p]; found++; }
    }
    // URL scheme 检测
    for (NSString *scheme in @[@"cydia://", @"sileo://"]) {
        NSURL *u = [NSURL URLWithString:scheme];
        BOOL ok = [[UIApplication sharedApplication] canOpenURL:u];
        if (ok) { [r appendFormat:@"  🔴 scheme 可打开: %@\n", scheme]; found++; }
    }
    if (!found) [r appendString:@"  ✅ 未发现越狱痕迹\n"];
    [r appendFormat:@"  命中：%d 项\n", found];
    return r;
}

static NSString *mfScanAntiDebug(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【反调试状态】\n"];
    struct kinfo_proc kp;
    size_t len = sizeof(kp);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    if (sysctl(mib, 4, &kp, &len, NULL, 0) == 0) {
        BOOL traced = (kp.kp_proc.p_flag & P_TRACED) != 0;
        [r appendFormat:@"  %@ P_TRACED 标志 = %d\n", traced ? @"🔴" : @"✅", traced ? 1 : 0];
    } else {
        [r appendString:@"  ⚠️ sysctl 查询失败\n"];
    }
    pid_t pp = getppid();
    [r appendFormat:@"  %@ PPID = %d%@ (launchd=1)\n", pp == 1 ? @"✅" : @"🟡", pp, pp == 1 ? @"" : @" ← 非 launchd 直启"];
    // ptrace PT_DENY_ATTACH 自我保护检测：看主二进制是否导入 ptrace
    NSString *exPath = [[NSBundle mainBundle] executablePath];
    NSData *bin = [NSData dataWithContentsOfFile:exPath options:NSDataReadingMappedIfSafe error:nil];
    if (bin.length) {
        NSRange pr = [bin rangeOfData:[@"_ptrace\x00" dataUsingEncoding:NSUTF8StringEncoding]
                              options:NSDataSearchBackwards range:NSMakeRange(bin.length - MIN(bin.length, 2u << 20), MIN(bin.length, 2u << 20))];
        [r appendFormat:@"  %@ 目标 App 导入 ptrace 符号：%@（PT_DENY_ATTACH 反调试能力）\n",
            pr.location != NSNotFound ? @"🟡" : @"✅", pr.location != NSNotFound ? @"是" : @"否"];
    }
    return r;
}

static NSString *mfScanEntitlements(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【Entitlements】\n"];
    void (^dump)(NSString *, id) = ^(NSString *k, id v) {
        [r appendFormat:@"  %@ %@ = %@\n", v ? @"🔵" : @"⚪️", k, v ?: @"(未声明)"];
    };
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) { [r appendString:@"  ⚠️ SecTask 创建失败\n"]; return r; }
    NSArray<NSString *> *keys = @[
        @"application-identifier", @"com.apple.developer.team-identifier",
        @"com.apple.developer.icloud-container-identifiers",
        @"com.apple.developer.ubiquity-kvstore-identifier",
        @"com.apple.developer.associated-domains", @"aps-environment",
        @"keychain-access-groups", @"get-task-allow", @"beta-reports-active",
        @"com.apple.developer.personal-vpn", @"com.apple.developer.networking.networkextension",
        @"com.apple.security.application-groups",
        @"com.apple.developer.healthkit", @"com.apple.developer.homekit",
        @"com.apple.developer.default-data-protection",
        @"com.apple.developer.siri", @"com.apple.developer.usernotifications.time-sensitive",
    ];
    for (NSString *k in keys) {
        CFTypeRef v = SecTaskCopyValueForEntitlement(task, (__bridge CFStringRef)k, NULL);
        // CFBridgingRelease 移交 ARC，绝不能再手动 CFRelease（双重释放=闪退）
        id val = v ? CFBridgingRelease(v) : nil;
        // 值类型兜底：非容器类型转 description
        if (val && ![val isKindOfClass:[NSString class]] && ![val isKindOfClass:[NSArray class]] &&
            ![val isKindOfClass:[NSNumber class]] && ![val isKindOfClass:[NSData class]])
            val = [val description];
        dump(k, val);
    }
    CFRelease(task);
    return r;
}

static NSString *mfScanCodeSignature(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【代码签名】\n"];
    uint32_t flags = 0;
    if (csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags)) == 0) {
        [r appendFormat:@"  csops flags = 0x%08x\n", flags];
        [r appendFormat:@"  %@ 签名有效 (CS_VALID=%d)\n", flags & MF_CS_VALID ? @"✅" : @"🔴", !!(flags & MF_CS_VALID)];
        [r appendFormat:@"  %@ 平台二进制 (%d)\n", flags & MF_CS_PLATFORM_BINARY ? @"🟡" : @"⚪️", !!(flags & MF_CS_PLATFORM_BINARY)];
        [r appendFormat:@"  %@ 允许附加调试器 (GET_TASK_ALLOW=%d)\n", flags & MF_CS_GET_TASK_ALLOW ? @"🔴" : @"✅", !!(flags & MF_CS_GET_TASK_ALLOW)];
        [r appendFormat:@"  %@ 由调试器启动 (CS_DEBUGGED=%d)\n", flags & MF_CS_DEBUGGED ? @"🔴" : @"✅", !!(flags & MF_CS_DEBUGGED)];
        [r appendFormat:@"  %@ Ad-hoc 签名 (%d)\n", flags & MF_CS_ADHOC ? @"🟡" : @"⚪️", !!(flags & MF_CS_ADHOC)];
    } else {
        [r appendString:@"  ⚠️ csops 失败\n"];
    }
    // embedded.mobileprovision 存在性
    NSString *pp = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"];
    [r appendFormat:@"  %@ 描述文件: %@\n", pp ? @"🔵" : @"⚪️", pp ?: @"无（非开发签名/AppStore）"];
    return r;
}

static NSString *mfScanSandbox(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【沙盒状态】\n"];
    NSString *home = NSHomeDirectory();
    [r appendFormat:@"  容器: %@\n", home];
    NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:
        [home stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"]];
    [r appendFormat:@"  容器 ID: %@\n", meta[@"MCMMetadataIdentifier"] ?: @"?"];
    // 写测试：容器内（应成功）/ 容器外（应失败=沙盒生效）
    NSString *t1 = [home stringByAppendingPathComponent:@".mf_sb_test"];
    BOOL inOK = [@"" writeToFile:t1 atomically:YES encoding:NSUTF8StringEncoding error:nil];
    if (inOK) unlink(t1.fileSystemRepresentation);
    [r appendFormat:@"  %@ 容器内写入: %@\n", inOK ? @"✅" : @"🔴", inOK ? @"成功" : @"失败"];
    NSString *outP = @"/var/mobile/Media/.mf_sb_test";
    BOOL outOK = [@"" writeToFile:outP atomically:YES encoding:NSUTF8StringEncoding error:nil];
    if (outOK) unlink(outP.fileSystemRepresentation);
    [r appendFormat:@"  %@ 容器外写入: %@（失败=沙盒正常隔离）\n", outOK ? @"🔴" : @"✅", outOK ? @"成功⚠️" : @"失败"];
    return r;
}

static NSString *mfScanPrivacy(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【隐私清单】\n"];
    // PrivacyInfo.xcprivacy（iOS17+ manifest）
    NSString *mpath = [[NSBundle mainBundle] pathForResource:@"PrivacyInfo" ofType:@"xcprivacy"];
    NSDictionary *m = mpath ? [NSDictionary dictionaryWithContentsOfFile:mpath] : nil;
    if (m) {
        [r appendFormat:@"  PrivacyInfo.xcprivacy 存在\n"];
        for (NSDictionary *a in m[@"NSPrivacyAccessedAPITypes"] ?: @[])
            [r appendFormat:@"    • %@ (reasons: %@)\n", a[@"NSPrivacyAccessedAPIType"], a[@"NSPrivacyAccessedAPITypeReasons"]];
        [r appendFormat:@"  收集数据类型：%lu 项\n", (unsigned long)[(NSArray *)m[@"NSPrivacyCollectedDataTypes"] count]];
        [r appendFormat:@"  追踪声明: %@\n", m[@"NSPrivacyTracking"] ? @"是" : @"否"];
    } else {
        [r appendString:@"  ⚪️ 无 PrivacyInfo.xcprivacy（iOS17 前构建或未提供）\n"];
    }
    // 敏感框架导入检测（遍历已加载镜像名）
    [r appendString:@"【敏感框架加载】\n"];
    NSArray *sens = @[@".CoreLocation", @"Contacts", @"AVFoundation", @"AddressBook",
                      @"HealthKit", @"CoreBluetooth", @"EventKit", @"AssetsLibrary"];
    uint32_t n = _dyld_image_count();
    int hits = 0;
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        NSString *path = [NSString stringWithUTF8String:nm];
        for (NSString *s in sens) {
            if ([path.lastPathComponent containsString:s]) {
                [r appendFormat:@"  🔵 %@\n", path.lastPathComponent];
                hits++;
            }
        }
    }
    if (!hits) [r appendString:@"  ✅ 未加载敏感框架\n"];
    return r;
}

static NSString *mfScanScreenCapture(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【截屏/录屏】\n"];
    BOOL captured = UIScreen.mainScreen.isCaptured;
    [r appendFormat:@"  %@ 当前屏幕被捕获: %@\n", captured ? @"🔴" : @"✅", captured ? @"是（录屏/投屏中）" : @"否"];
    [r appendFormat:@"  提示：监听 UIScreenCapturedDidChangeNotification 可实时感知录屏\n"];
    return r;
}

static NSString *mfScanAPIStats(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【运行时统计】\n"];
    unsigned total = objc_getClassList(NULL, 0);
    __unsafe_unretained Class *classes = (__unsafe_unretained Class *)malloc(total * sizeof(Class));
    unsigned got = 0;
    if (classes) { got = objc_getClassList(classes, total); }
    NSString *myEx = [[NSBundle mainBundle] executablePath].lastPathComponent;
    unsigned mine = 0;
    for (unsigned i = 0; i < got; i++) {
        const char *img = class_getImageName(classes[i]);
        if (img && strstr(img, myEx.UTF8String)) mine++;
    }
    free(classes);
    unsigned protoCount = 0;
    Protocol *__unsafe_unretained *protos = objc_copyProtocolList(&protoCount);
    if (protos) free(protos);
    uint32_t imgs = _dyld_image_count();
    size_t envN = 0; while (environ[envN]) envN++;
    [r appendFormat:@"  ObjC 类：%u（本 App：%u）\n", total, mine];
    [r appendFormat:@"  协议：%u · 已加载镜像：%u · 环境变量：%zu\n", protoCount, imgs, envN];
    task_vm_info_data_t vm;
    mach_msg_type_number_t cnt = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vm, &cnt) == KERN_SUCCESS)
        [r appendFormat:@"  物理内存占用: %.1f MB\n", vm.phys_footprint / 1048576.0];
    return r;
}

static NSArray<NSString *> * const mfScanNames = @[
    @"① 越狱检测", @"② 反调试状态", @"③ Entitlements", @"④ 代码签名",
    @"⑤ 沙盒状态", @"⑥ 隐私清单+敏感框架", @"⑦ 截屏/录屏", @"⑧ 运行时统计",
];

typedef NSString *(*mfScanFn)(void);
static const mfScanFn mfScanFns[] = {
    mfScanJailbreak, mfScanAntiDebug, mfScanEntitlements, mfScanCodeSignature,
    mfScanSandbox, mfScanPrivacy, mfScanScreenCapture, mfScanAPIStats,
};

#pragma mark - ====== MachO 深检 ======

// 主二进制解析：读文件头 + load commands（进程内自读，无需注入）
static NSData *mfMainBinaryData(void) {
    NSString *p = [[NSBundle mainBundle] executablePath];
    return p ? [NSData dataWithContentsOfFile:p options:NSDataReadingMappedAlways error:nil] : nil;
}

// 定长 char[N] 字段安全转 NSString（segname/sectname 不保证 \0 结尾，直接 %@ 会越界读）
static NSString *mfFixedStr(const char *src, size_t n) {
    char buf[17];
    memcpy(buf, src, MIN(n, 16));
    buf[MIN(n, 16)] = 0;
    return [NSString stringWithUTF8String:buf] ?: @"?";
}

NSString *mfMachOSections(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【Sections】\n"];
    NSData *d = mfMainBinaryData();
    if (!d) return @"⚠️ 无法读取主二进制";
    const uint8_t *b = d.bytes;
    const uint8_t *end = b + d.length;
    if (d.length < sizeof(struct mach_header_64) || *(const uint32_t *)b != MH_MAGIC_64)
        return @"⚠️ 非 64 位 Mach-O";
    struct mach_header_64 mh;
    memcpy(&mh, b, sizeof(mh));
    [r appendFormat:@"  cputype=%x ncmds=%u filetype=%u\n", (unsigned)mh.cputype, mh.ncmds, (unsigned)mh.filetype];
    const uint8_t *p = b + sizeof(mh);
    for (uint32_t i = 0; i < mh.ncmds; i++) {
        if (p + sizeof(struct load_command) > end) { [r appendString:@"  ⚠️ 越界截断\n"]; break; }
        struct load_command lc; memcpy(&lc, p, sizeof(lc));
        if (lc.cmdsize < sizeof(lc) || p + lc.cmdsize > end) { [r appendString:@"  ⚠️ cmdsize 异常截断\n"]; break; }
        if (lc.cmd == LC_SEGMENT_64 && p + sizeof(struct segment_command_64) <= end) {
            struct segment_command_64 sg; memcpy(&sg, p, sizeof(sg));
            [r appendFormat:@"▸ %@ (vmaddr=%llx)\n", mfFixedStr(sg.segname, 16), sg.vmaddr];
            const uint8_t *sp = p + sizeof(sg);
            for (uint32_t j = 0; j < sg.nsects; j++) {
                if (sp + (j + 1) * sizeof(struct section_64) > end) break;
                struct section_64 sec; memcpy(&sec, sp + j * sizeof(sec), sizeof(sec));
                [r appendFormat:@"  · %@,%@ off=%-6u size=%-7u flags=%x\n",
                    mfFixedStr(sec.segname, 16), mfFixedStr(sec.sectname, 16),
                    (unsigned)sec.offset, (unsigned)sec.size, (unsigned)sec.flags];
            }
        }
        p += lc.cmdsize;
    }
    return r;
}

NSString *mfMachODylibs(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【Dylib 依赖】\n"];
    NSData *d = mfMainBinaryData();
    const uint8_t *b = d.bytes;
    const uint8_t *end = b + (d ? d.length : 0);
    if (!d || d.length < sizeof(struct mach_header_64) || *(const uint32_t *)b != MH_MAGIC_64) return @"⚠️ 解析失败";
    struct mach_header_64 mh; memcpy(&mh, b, sizeof(mh));
    const uint8_t *p = b + sizeof(mh);
    int n = 0;
    for (uint32_t i = 0; i < mh.ncmds; i++) {
        if (p + sizeof(struct load_command) > end) break;
        struct load_command lc; memcpy(&lc, p, sizeof(lc));
        if (lc.cmdsize < sizeof(lc) || p + lc.cmdsize > end) break;
        if ((lc.cmd == LC_LOAD_WEAK_DYLIB || LC_LOAD_DYLIB == lc.cmd) && p + sizeof(struct dylib_command) <= end) {
            struct dylib_command dc; memcpy(&dc, p, sizeof(dc));
            // name offset 指向 LC 内字符串区，校验后按 %s 打印（null-terminated 保证）
            uint32_t noff = dc.dylib.name.offset;
            if (noff > 0 && noff < lc.cmdsize) {
                const char *nm = (const char *)p + noff;
                [r appendFormat:@"  %@ %.200s\n", lc.cmd == LC_LOAD_WEAK_DYLIB ? @"🟡(weak)" : @"·", nm];
                n++;
            }
        }
        p += lc.cmdsize;
    }
    [r appendFormat:@"  共 %d 个依赖\n", n];
    return r;
}

NSString *mfMachOStrings(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【__cstring 抽样】\n"];
    unsigned long sz = 0;
    // 必须传主镜像 header——getsectiondata(NULL) 是未定义行为（闪退点）
    const struct mach_header_64 *hdr = _dyld_get_image_header(0);
    const uint8_t *cs = hdr ? getsectiondata(hdr, "__TEXT", "__cstring", &sz) : NULL;
    if (!cs || !sz) return @"⚠️ __cstring 未找到";
    [r appendFormat:@"  段大小: %lu bytes\n", sz];
    // 抽样前 60 条可读字符串
    int shown = 0, i = 0;
    while (i < (int)sz && shown < 60) {
        const char *s = (const char *)cs + i;
        size_t len = strnlen(s, sz - i);
        if (len >= 6 && len <= 120 && isprint((unsigned char)s[0])) {
            int alpha = 0;
            for (size_t k = 0; k < len && k < 40; k++) if (isalpha((unsigned char)s[k])) alpha++;
            if (alpha > len / 2) {
                [r appendFormat:@"  %.*s\n", (int)MIN(len, 100), s];
                shown++;
            }
        }
        i += (int)(len + 1);
    }
    return r;
}

NSString *mfMachOSymbols(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【符号表概览】\n"];
    NSData *d = mfMainBinaryData();
    const uint8_t *b = d.bytes;
    const uint8_t *end = b + (d ? d.length : 0);
    if (!d || d.length < sizeof(struct mach_header_64) || *(const uint32_t *)b != MH_MAGIC_64) return @"⚠️ 解析失败";
    struct mach_header_64 mh; memcpy(&mh, b, sizeof(mh));
    const uint8_t *p = b + sizeof(mh);
    struct symtab_command st = {0};
    for (uint32_t i = 0; i < mh.ncmds; i++) {
        if (p + sizeof(struct load_command) > end) break;
        struct load_command lc; memcpy(&lc, p, sizeof(lc));
        if (lc.cmdsize < sizeof(lc) || p + lc.cmdsize > end) break;
        if (lc.cmd == LC_SYMTAB && p + sizeof(st) <= end) memcpy(&st, p, sizeof(st));
        p += lc.cmdsize;
    }
    if (!st.cmd) return @"⚠️ 无 LC_SYMTAB（stripped）";
    // symoff/stroff 边界校验后再解引用
    if (st.symoff >= d.length || st.stroff >= d.length ||
        (unsigned long long)st.symoff + (unsigned long long)st.nsyms * sizeof(struct mf_nlist_64) > d.length)
        return @"⚠️ 符号表偏移越界（可能被 strip 工具破坏）";
    [r appendFormat:@"  符号总数: %u\n", st.nsyms];
    struct mf_nlist_64 nl;
    int shown = 0;
    for (uint32_t i = 0; i < st.nsyms && shown < 50; i++) {
        memcpy(&nl, b + st.symoff + i * sizeof(nl), sizeof(nl));
        if (!nl.n_strx) continue;
        uint32_t off = st.stroff + nl.n_strx;
        if (off >= d.length) continue;
        const char *s = (const char *)b + off;
        if (!isprint((unsigned char)s[0])) continue;
        size_t slen = strnlen(s, d.length - off);
        [r appendFormat:@"  %.*s\n", (int)MIN(slen, 120), s];
        shown++;
    }
    if (st.nsyms > 50) [r appendFormat:@"  …（共 %u 条）\n", st.nsyms];
    return r;
}

NSString *mfMachORuntime(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【ObjC 运行时】\n"];
    unsigned total = objc_getClassList(NULL, 0);
    __unsafe_unretained Class *classes = (__unsafe_unretained Class *)malloc(total * sizeof(Class));
    unsigned got = classes ? objc_getClassList(classes, total) : 0;
    NSString *myEx = [[NSBundle mainBundle] executablePath].lastPathComponent;
    NSMutableSet *myClasses = [NSMutableSet set];
    for (unsigned i = 0; i < got; i++) {
        const char *img = class_getImageName(classes[i]);
        if (!img) continue;
        NSString *ip = [NSString stringWithUTF8String:img];
        if (![ip.lastPathComponent containsString:myEx]) continue;
        [myClasses addObject:NSStringFromClass(classes[i])];
    }
    free(classes);
    unsigned protoCount = 0;
    Protocol *__unsafe_unretained *protos = objc_copyProtocolList(&protoCount);
    if (protos) free(protos);
    [r appendFormat:@"  本 App 类数: %lu（全进程 %u）\n", (unsigned long)myClasses.count, total];
    [r appendFormat:@"  全进程协议: %u\n", protoCount];
    // 类名抽样前 30
    NSArray *sorted = [myClasses.allObjects sortedArrayUsingSelector:@selector(compare:)];
    for (NSUInteger i = 0; i < sorted.count && i < 30; i++) [r appendFormat:@"    @interface %@\n", sorted[i]];
    if (myClasses.count > 30) [r appendFormat:@"    …（共 %lu）\n", (unsigned long)myClasses.count];
    return r;
}

#pragma mark - ====== 通用文本报告页（对标 UCPTTextViewController） ======

void mfShowTextReportPage(NSString *title, NSString *text, NSString *exportName) {
    UIView *page = mfMakePage(title, YES);
    CGFloat w = g_mfCardW;

    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(0, 42, w, g_mfCardH - 92)];
    tv.editable = NO;
    tv.font = [UIFont fontWithName:@"Menlo-Regular" size:11] ?: [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    tv.backgroundColor = UIColor.clearColor;
    tv.text = text;
    tv.autocorrectionType = UITextAutocorrectionTypeNo;
    [page addSubview:tv];

    CGFloat by = g_mfCardH - 46;
    UIButton *copyB = [UIButton buttonWithType:UIButtonTypeSystem];
    copyB.frame = CGRectMake(w - 170, by, 78, 36);
    copyB.backgroundColor = [UIColor secondarySystemBackgroundColor];
    copyB.layer.cornerRadius = 10;
    [copyB setTitle:@"📋 复制" forState:UIControlStateNormal];
    [page addSubview:copyB];

    UIButton *shareB = [UIButton buttonWithType:UIButtonTypeSystem];
    shareB.frame = CGRectMake(w - 84, by, 78, 36);
    shareB.backgroundColor = [UIColor systemBlueColor];
    shareB.layer.cornerRadius = 10;
    shareB.tintColor = UIColor.whiteColor;
    [shareB setTitle:@"⤴ 分享" forState:UIControlStateNormal];
    [page addSubview:shareB];

    objc_setAssociatedObject(page, "text", text, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "name", exportName, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(copyB, "page", page, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(shareB, "page", page, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [copyB addTarget:g_mfCtrl action:NSSelectorFromString(@"mfDiagCopy:") forControlEvents:UIControlEventTouchUpInside];
    [shareB addTarget:g_mfCtrl action:NSSelectorFromString(@"mfDiagShare:") forControlEvents:UIControlEventTouchUpInside];

    mfPushPage(page);
}

#pragma mark - ====== 扫描页面 ======

void mfSecurityScanRun(int idx, UIButton *btn) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *title, *report;
        if (idx < 0) { // 全扫
            title = @"安全扫描报告";
            NSMutableString *all = [NSMutableString string];
            for (int i = 0; i < 8; i++) {
                [all appendString:mfScanFns[i]()];
                [all appendString:@"\n"];
            }
            report = all;
        } else {
            title = mfScanNames[idx];
            report = mfScanFns[idx]();
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            btn.enabled = YES;
            mfShowTextReportPage(title, report, @"SecurityScan");
        });
    });
}

void mfShowSecurityScanPage(void) {
    UIView *page = mfMakePage(@"🛡️ 安全扫描", YES);
    CGFloat gw = g_mfCardW - 32;
    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(16, 44, gw, 30)];
    hint.font = [UIFont systemFontOfSize:11];
    hint.textColor = [UIColor secondaryLabelColor];
    hint.numberOfLines = 2;
    hint.text = @"八项运行时安全体检（对标 ToolsEric 八连扫）";
    [page addSubview:hint];

    CGFloat y = 80;
    UIButton *all = [UIButton buttonWithType:UIButtonTypeSystem];
    all.frame = CGRectMake(16, y, gw, 42);
    all.backgroundColor = [UIColor systemRedColor];
    all.layer.cornerRadius = 10;
    all.tintColor = UIColor.whiteColor;
    [all setTitle:@"⚡️ 一键全扫" forState:UIControlStateNormal];
    all.tag = -1;
    [page addSubview:all];
    y += 52;
    for (int i = 0; i < 8; i += 2) {
        for (int j = 0; j < 2; j++) {
            int k = i + j;
            UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
            b.frame = CGRectMake(16 + j * ((gw + 12) / 2 + 6), y, (gw - 12) / 2, 38);
            b.backgroundColor = [UIColor secondarySystemBackgroundColor];
            b.layer.cornerRadius = 9;
            b.tintColor = [UIColor labelColor];
            b.titleLabel.font = [UIFont systemFontOfSize:12];
            [b setTitle:mfScanNames[k] forState:UIControlStateNormal];
            b.tag = k;
            [page addSubview:b];
            [b addTarget:g_mfCtrl action:NSSelectorFromString(@"mfSecScanRun:") forControlEvents:UIControlEventTouchUpInside];
        }
        y += 46;
    }
    [all addTarget:g_mfCtrl action:NSSelectorFromString(@"mfSecScanRun:") forControlEvents:UIControlEventTouchUpInside];
    mfPushPage(page);
}

void mfShowMachODeepPage(void) {
    UIView *page = mfMakePage(@"🔬 MachO 深检", YES);
    CGFloat gw = g_mfCardW - 32;
    NSString *exPath = [[NSBundle mainBundle] executablePath];
    NSDictionary *at = [[NSFileManager defaultManager] attributesOfItemAtPath:exPath error:nil];
    UILabel *info = [[UILabel alloc] initWithFrame:CGRectMake(16, 44, gw, 44)];
    info.font = [UIFont systemFontOfSize:11];
    info.textColor = [UIColor secondaryLabelColor];
    info.numberOfLines = 2;
    info.text = [NSString stringWithFormat:@"%@\n%.1f MB", exPath.lastPathComponent,
                 [at[NSFileSize] doubleValue] / 1048576.0];
    [page addSubview:info];

    NSArray *items = @[
        @[@"Sections 全览", @"sec"], @[@"Dylib 依赖", @"dylib"],
        @[@"__cstring 抽样", @"str"], @[@"符号表概览", @"sym"],
        @[@"ObjC 运行时归属", @"rt"],
    ];
    CGFloat y = 96;
    for (NSArray *it in items) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        b.frame = CGRectMake(16, y, gw, 42);
        b.backgroundColor = [UIColor secondarySystemBackgroundColor];
        b.layer.cornerRadius = 10;
        b.tintColor = [UIColor labelColor];
        b.titleLabel.font = [UIFont systemFontOfSize:13];
        [b setTitle:[@"▸ " stringByAppendingString:it[0]] forState:UIControlStateNormal];
        objc_setAssociatedObject(b, "kind", it[1], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [page addSubview:b];
        [b addTarget:g_mfCtrl action:NSSelectorFromString(@"mfMachORun:") forControlEvents:UIControlEventTouchUpInside];
        y += 50;
    }
    mfPushPage(page);
}

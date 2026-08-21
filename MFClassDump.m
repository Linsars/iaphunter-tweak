// MFClassDump.m — 运行时 class dump（v1.4.0 新增，数据分析板块）
// 思路来源：RuntimeClassDump.dylib 逆向（CD* 模型层），实现全部自研：
// objc runtime API 枚举 → 内存生成 .h → 内置 zip writer（zlib deflate）→ 分享
// 零第三方依赖，不落盘中间文件

#import "MFPanel.h"
#include <zlib.h>
#include <time.h>
#include <ctype.h>

// ====== 类型编码 → C 类型（精简版 CDTypeParser） ======
static NSString *mfDecOne(const char *e, NSUInteger *ip) {
    NSUInteger i = *ip;
    if (i >= strlen(e)) return @"void";
    char c = e[i];
    switch (c) {
        case 'v': *ip=i+1; return @"void";
        case 'B': *ip=i+1; return @"_Bool";
        case 'c': *ip=i+1; return @"char";
        case 'C': *ip=i+1; return @"unsigned char";
        case 's': *ip=i+1; return @"short";
        case 'S': *ip=i+1; return @"unsigned short";
        case 'i': *ip=i+1; return @"int";
        case 'I': *ip=i+1; return @"unsigned int";
        case 'l': *ip=i+1; return @"long";
        case 'L': *ip=i+1; return @"unsigned long";
        case 'q': *ip=i+1; return @"long long";
        case 'Q': *ip=i+1; return @"unsigned long long";
        case 'f': *ip=i+1; return @"float";
        case 'd': *ip=i+1; return @"double";
        case '@': {
            if (e[i+1] == '"') {
                const char *q = strchr(e+i+2, '"');
                NSString *cls = q ? [NSString stringWithFormat:@"%.*s *", (int)(q-(e+i+2)), e+i+2]
                                  : @"id";
                *ip = q ? (q - e + 1) : i+2;
                return cls;
            }
            if (e[i+1] == '?') { *ip=i+2; return @"void (^)(void)"; } // block 简化
            *ip=i+1; return @"id";
        }
        case '#': *ip=i+1; return @"Class";
        case ':': *ip=i+1; return @"SEL";
        case '^': {
            *ip=i+1;
            NSString *inner = mfDecOne(e, ip);
            return [NSString stringWithFormat:@"%@ *", inner];
        }
        case '[': { // [nT]
            NSUInteger j=i+1;
            while (isdigit((unsigned char)e[j])) j++;
            NSString *t = mfDecOne(e, &j); j++; // 跳 ]
            *ip=j;
            return [NSString stringWithFormat:@"%@[%@]", t, @""];
        }
        case '{': { // {name=...}
            NSUInteger j = i+1;
            const char *eq = strchr(e+j, '=');
            const char *rb = strchr(e+j, '}');
            if (!rb) { *ip=strlen(e); return @"struct"; }
            NSUInteger nlen = eq && eq < rb ? (NSUInteger)(eq-(e+j)) : (NSUInteger)(rb-(e+j));
            NSString *t = [NSString stringWithFormat:@"struct %.*s", (int)nlen, e+j];
            j = rb - e + 1;
            *ip=j; return t;
        }
        case '(': { // (name=...)
            const char *rb = strchr(e+i+1, ')');
            NSUInteger nlen = rb ? (NSUInteger)(rb-(e+i+1)) : 0;
            *ip = rb ? rb-e+1 : strlen(e);
            return [NSString stringWithFormat:@"union %.*s", (int)nlen, e+i+1];
        }
        case 'j': *ip=i+1; return @"_Complex";
        case 'b': *ip=i+1; return @"bitfield";
        default:  *ip=i+1; return nil; // 数字(对齐)/?/未知 → 跳过
    }
}

static NSString *mfDecodeType(const char *enc) {
    if (!enc || !*enc) return @"void";
    NSUInteger i = 0;
    NSString *t = mfDecOne(enc, &i);
    return t ?: @"void";
}

// ====== 方法渲染：- (ret)sela:(arg)a1 b:(arg)a2; ======
static NSString *mfRenderMethod(Method m, BOOL isCls) {
    // 老版 SDK 把 method_getReturnType 声明为 (m,dst,len) 遗留变体，统一用 copy 系
    char *retp = method_copyReturnType(m);
    NSMutableString *sig = [NSMutableString string];
    [sig appendFormat:@"%c (%@)", isCls ? '+' : '-', mfDecodeType(retp)];
    if (retp) free(retp);
    SEL sel = method_getName(m);
    NSArray *parts = [NSStringFromSelector(sel) componentsSeparatedByString:@":"];
    int ai = 0;
    for (NSUInteger p = 0; p < parts.count; p++) {
        if (p == 0) [sig appendFormat:@"%@", parts[0]];
        else {
            const char *ae = method_copyArgumentType(m, 2 + ai);
            NSString *at = mfDecodeType(ae); free(ae); ai++;
            [sig appendFormat:@":(%@)a%d %@", at, ai, parts[p]];
        }
    }
    [sig appendString:@";"];
    return sig;
}

// ====== 单类头文件生成 ======
static NSString *mfHeaderForClass(Class cls) {
    const char *nm = class_getName(cls);
    Class sup = class_getSuperclass(cls);
    NSMutableString *h = [NSMutableString string];

    // 协议
    NSMutableArray *protos = [NSMutableArray array];
    unsigned pc = 0;
    Protocol * __unsafe_unretained *pl = class_copyProtocolList(cls, &pc);
    for (unsigned i = 0; i < pc; i++) [protos addObject:@(protocol_getName(pl[i]))];
    free(pl);

    [h appendFormat:@"@interface %s", nm];
    if (sup) [h appendFormat:@" : %s", class_getName(sup)];
    if (protos.count) [h appendFormat:@" <%@>", [protos componentsJoinedByString:@", "]];
    [h appendString:@"\n{\n"];

    unsigned ic = 0;
    Ivar *iv = class_copyIvarList(cls, &ic);
    for (unsigned i = 0; i < ic; i++) {
        const char *tn = ivar_getTypeEncoding(iv[i]);
        ptrdiff_t off = ivar_getOffset(iv[i]);
        [h appendFormat:@"    %@ _%s; // +%td\n",
            mfDecodeType(tn), ivar_getName(iv[i]) ?: "?", off];
    }
    free(iv);
    [h appendString:@"}\n"];

    // 实例方法
    unsigned mc = 0;
    Method *ml = class_copyMethodList(cls, &mc);
    for (unsigned i = 0; i < mc; i++) [h appendFormat:@"%@\n", mfRenderMethod(ml[i], NO)];
    // 类方法（元类）
    unsigned cmc = 0;
    Method *cml = class_copyMethodList(object_getClass(cls), &cmc);
    for (unsigned i = 0; i < cmc; i++) [h appendFormat:@"%@\n", mfRenderMethod(cml[i], YES)];
    free(ml); free(cml);

    // 属性
    unsigned prc = 0;
    objc_property_t *pr = class_copyPropertyList(cls, &prc);
    for (unsigned i = 0; i < prc; i++) {
        const char *attrs = property_getAttributes(pr[i]);
        NSString *type = @"id", *mods = @"";
        if (attrs && attrs[0]=='T') {
            const char *comma = strchr(attrs+1, ',');
            type = comma ? [NSString stringWithFormat:@"%.*s", (int)(comma-attrs-1), attrs+1] : @(attrs+1);
            type = type.length ? mfDecodeType(type.UTF8String) : @"id";
            NSMutableArray *kw = [NSMutableArray array];
            for (const char *p = comma ? comma+1 : attrs+strlen(attrs); *p; ) {
                switch (*p) {
                    case 'R': [kw addObject:@"readonly"]; break;
                    case 'C': [kw addObject:@"copy"]; break;
                    case '&': [kw addObject:@"strong"]; break;
                    case 'N': [kw addObject:@"nonatomic"]; break;
                    case 'W': [kw addObject:@"weak"]; break;
                }
                const char *nx = strchr(p, ',');
                if (!nx) break; p = nx+1;
            }
            mods = kw.count ? [kw componentsJoinedByString:@", "] : @"nonatomic";
        }
        [h appendFormat:@"@property(%@) %@ %s;\n", mods, type, property_getName(pr[i])];
    }
    free(pr);

    [h appendString:@"@end\n"];
    return h;
}

// ====== 最小 ZIP writer（deflate via zlib）======
static void mfPut16(NSMutableData *d, uint16_t v) { [d appendBytes:&v length:2]; }
static void mfPut32(NSMutableData *d, uint32_t v) { [d appendBytes:&v length:4]; }

// 中央目录记录：必须用 ObjC 对象持有 name（NSValue+裸结构体会 UAF，v2 闪退根因）
@interface MFCDRec : NSObject
@property (copy) NSString *name;
@property (assign) uint32_t crc, csize, usize, offset;
@property (assign) uint16_t method;
@end
@implementation MFCDRec @end

static void mfZipTime(uint16_t *t, uint16_t *dt) {
    time_t now = time(NULL);
    struct tm tmv; localtime_r(&now, &tmv);
    *t  = (uint16_t)((tmv.tm_hour << 11) | (tmv.tm_min << 5) | (tmv.tm_sec >> 1));
    *dt = (uint16_t)(((tmv.tm_year + 1900 - 1980) << 9) | ((tmv.tm_mon + 1) << 5) | tmv.tm_mday);
}

// 流式写单条目到文件句柄，CD 记录进数组（最后统一追加）
static BOOL mfZipAddStream(NSFileHandle *fh, NSMutableArray *cds, NSString *name, NSData *data,
                           NSMutableData *scratch) {
    @try {
        uint16_t mtime, mdate; mfZipTime(&mtime, &mdate);
        uint32_t crc = (uint32_t)crc32(0, data.bytes, (uInt)data.length);

        // deflate 到复用 scratch 缓冲，避免每类 malloc/free 大块
        uLongf bound = compressBound(data.length);
        if (scratch.length < bound) [scratch setLength:bound];
        uLongf csz = scratch.length;
        int rc = compress2(scratch.mutableBytes, &csz, data.bytes, data.length, Z_BEST_SPEED);
        BOOL stored = (rc != Z_OK || csz >= data.length);
        uint16_t method = stored ? 0 : 8;
        uint32_t finalSize = stored ? (uint32_t)data.length : (uint32_t)csz;

        uint32_t off = (uint32_t)fh.offsetInFile;
        NSMutableData *lh = [NSMutableData dataWithCapacity:30 + name.length];
        mfPut32(lh, 0x04034b50); mfPut16(lh, 20); mfPut16(lh, 0x0800);
        mfPut16(lh, method); mfPut16(lh, mtime); mfPut16(lh, mdate);
        mfPut32(lh, crc);
        mfPut32(lh, finalSize);
        mfPut32(lh, (uint32_t)data.length);
        NSData *nb = [name dataUsingEncoding:NSUTF8StringEncoding];
        mfPut16(lh, (uint16_t)nb.length); mfPut16(lh, 0);
        [lh appendData:nb];
        [fh writeData:lh];
        [fh writeData:(stored ? data : [NSData dataWithBytesNoCopy:scratch.mutableBytes length:csz freeWhenDone:NO])];

        MFCDRec *rec = [MFCDRec new];
        rec.name = name; rec.crc = crc; rec.csize = finalSize;
        rec.usize = (uint32_t)data.length; rec.offset = off; rec.method = method;
        [cds addObject:rec];
        return YES;
    } @catch (NSException *ex) {
        mfLog(@"CLASSDUMP zip entry failed: %@", ex.reason);
        return NO;
    }
}

static BOOL mfZipFinishStream(NSFileHandle *fh, NSMutableArray *cds) {
    @try {
        uint32_t cdOff = (uint32_t)fh.offsetInFile;
        NSMutableData *cd = [NSMutableData data];
        for (MFCDRec *e in cds) {
            uint16_t mtime, mdate; mfZipTime(&mtime, &mdate);
            mfPut32(cd, 0x02014b50); mfPut16(cd, 20); mfPut16(cd, 20);
            mfPut16(cd, 0x0800); mfPut16(cd, e.method);
            mfPut16(cd, mtime); mfPut16(cd, mdate);
            mfPut32(cd, e.crc); mfPut32(cd, e.csize); mfPut32(cd, e.usize);
            NSData *nb = [e.name dataUsingEncoding:NSUTF8StringEncoding];
            mfPut16(cd, (uint16_t)nb.length);
            mfPut16(cd, 0); mfPut16(cd, 0); mfPut16(cd, 0); mfPut16(cd, 0);
            mfPut32(cd, 0); mfPut32(cd, e.offset);
            [cd appendData:nb];
        }
        [fh writeData:cd];
        uint32_t cdSize = (uint32_t)cd.length;
        NSMutableData *eo = [NSMutableData dataWithCapacity:22];
        mfPut32(eo, 0x06054b50); mfPut16(eo, 0); mfPut16(eo, 0);
        mfPut16(eo, (uint16_t)cds.count); mfPut16(eo, (uint16_t)cds.count);
        mfPut32(eo, cdSize); mfPut32(eo, cdOff); mfPut16(eo, 0);
        [fh writeData:eo];
        return YES;
    } @catch (NSException *ex) {
        mfLog(@"CLASSDUMP zip finish failed: %@", ex.reason);
        return NO;
    }
}

// ====== Swift 类型扫描（__swift5_types → 伪接口）======
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>

// 相对指针解析（swift metadata 全是 i32 自相对），带镜像范围校验
static uintptr_t mfRelPtr(uintptr_t slotAddr, int32_t off, uintptr_t lo, uintptr_t hi) {
    if (off == 0) return 0;
    uintptr_t t = slotAddr + (uintptr_t)(int64_t)off;
    return (t >= lo && t < hi) ? t : 0;
}
static const char *mfSafeStr(uintptr_t addr, uintptr_t lo, uintptr_t hi) {
    if (!addr || addr >= hi - 1) return NULL;
    const char *s = (const char *)addr;
    // 粗略可读性校验
    if (*s && !(*s >= 32 && *s < 127) && (unsigned char)*s < 0xC0) return NULL;
    return s;
}

static NSString *mfSwiftKindName(uint8_t kind) {
    switch (kind) {
        case 16: return @"class";
        case 17: return @"struct";
        case 18: return @"enum";
        default: return nil;
    }
}

// 遍历单镜像 __swift5_types，输出伪接口文本
static NSString *mfSwiftDumpImage(const struct mach_header *mh, intptr_t slide, NSString **outModuleCount) {
    unsigned long sz = 0;
    // getsectiondata 内部处理 slide，返回的是已重定位地址
    const uint8_t *types = getsectiondata(mh, "__TEXT", "__swift5_types", &sz);
    if (!types || sz < 4) return nil;
    uintptr_t lo = (uintptr_t)mh, hi = lo; // 范围用所有段聚合
    {
        uintptr_t minA = ~0ull, maxA = 0;
        const struct mach_header_64 *h64 = (const struct mach_header_64 *)mh;
        const uint8_t *p = (const uint8_t *)(h64 + 1);
        for (uint32_t i = 0; i < h64->ncmds; i++) {
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sg = (const struct segment_command_64 *)p;
                uintptr_t a = (uintptr_t)sg->vmaddr + slide, b = a + sg->vmsize;
                if (a < minA) minA = a;
                if (b > maxA) maxA = b;
            }
            p += lc->cmdsize;
        }
        if (!maxA) return nil;
        lo = minA; hi = maxA;
    }

    NSMutableString *out = [NSMutableString string];
    __block NSUInteger count = 0;
    const int32_t *rels = (const int32_t *)types;
    size_t n = sz / 4;
    for (size_t i = 0; i < n; i++) {
        uintptr_t descAddr = mfRelPtr((uintptr_t)&rels[i], rels[i], lo, hi);
        if (!descAddr) continue;
        const int32_t *desc = (const int32_t *)descAddr;
        uint32_t flags = (uint32_t)desc[0];
        uint8_t kind = flags & 0x1F;
        NSString *kindName = mfSwiftKindName(kind);
        if (!kindName) continue;
        const char *tname = mfSafeStr(mfRelPtr(descAddr + 8, desc[2], lo, hi), lo, hi);
        if (!tname || !*tname) continue;

        // 模块名：parent 链上溯
        NSString *module = @"Unknown";
        {
            uintptr_t pa = mfRelPtr(descAddr + 4, desc[1], lo, hi);
            int depth = 0;
            while (pa && depth++ < 8) {
                const int32_t *pd = (const int32_t *)pa;
                uint8_t pk = (uint32_t)pd[0] & 0x1F;
                if (pk != 0 && pk != 1) break; // 只沿 Module/Extension 上溯
                if (pk == 0) { // Module
                    const char *mn = mfSafeStr(mfRelPtr(pa + 8, pd[2], lo, hi), lo, hi);
                    if (mn) module = @(mn);
                    break;
                }
                pa = mfRelPtr(pa + 4, pd[1], lo, hi);
            }
        }
        (void)module; // v1: 按镜像归档即可，模块名留作后续分组

        [out appendFormat:@"%@ %s {\n", kindName, tname];
        // 字段描述符 @+16
        uintptr_t fd = mfRelPtr(descAddr + 16, desc[4], lo, hi);
        if (fd) {
            uint16_t frecSize = *(const uint16_t *)(fd + 10);
            uint32_t nf = *(const uint32_t *)(fd + 12);
            if (nf > 4096) nf = 4096; // 防御
            for (uint32_t f = 0; f < nf; f++) {
                uintptr_t fr = fd + 16 + (uintptr_t)f * frecSize;
                if (fr + 12 > hi) break;
                const int32_t *fri = (const int32_t *)fr;
                const char *fname = mfSafeStr(mfRelPtr(fr + 8, fri[2], lo, hi), lo, hi);
                if (!fname) fname = "?";
                const char *mty = mfSafeStr(mfRelPtr(fr + 4, fri[1], lo, hi), lo, hi);
                NSString *ty = mty ? @(mty) : @"?";
                [out appendFormat:@"    %@ %s: %@\n",
                    (kind == 18 ? @"case" : @"var"), fname, ty];
            }
        }
        [out appendString:@"}\n\n"];
        count++;
    }
    if (outModuleCount) *outModuleCount = @(count);
    return count ? out : nil;
}

// 扫全部镜像，产出 swift/<Image>.swift 条目
static void mfDumpAllSwift(NSFileHandle *fh, NSMutableArray *cds, NSMutableData *scratch,
                           NSMutableArray<NSString *> *modules) {
    uint32_t ic = _dyld_image_count();
    for (uint32_t i = 0; i < ic; i++) {
        @autoreleasepool {
            const struct mach_header *mh = _dyld_get_image_header(i);
            if (!mh) continue;
            const char *path = _dyld_get_image_name(i);
            NSString *imgName = path ? [@(path) lastPathComponent] : [NSString stringWithFormat:@"img%u", i];
            NSString *cnt = nil;
            NSString *body = mfSwiftDumpImage(mh, (intptr_t)_dyld_get_image_vmaddr_slide(i), &cnt);
            if (!body) continue;
            NSString *header = [NSString stringWithFormat:@"// Swift types in %@ (%@ types)\n// 由 __swift5_types 元数据还原，字段类型为 mangled 原始串\n\n", imgName, cnt ?: @"0"];
            NSString *full = [header stringByAppendingString:body];
            [modules addObject:[NSString stringWithFormat:@"%@ (%@)", imgName, cnt]];
            NSString *safeImg = [[imgName stringByReplacingOccurrencesOfString:@"/" withString:@"_"]
                                  stringByReplacingOccurrencesOfString:@":" withString:@"_"];
            mfZipAddStream(fh, cds, [NSString stringWithFormat:@"swift/%@.swift", safeImg],
                           [full dataUsingEncoding:NSUTF8StringEncoding], scratch);
        }
    }
}

// ====== 主流程（流式落盘：内存峰值 = 单类头文件，防 jetsam） ======
void mfClassDumpStartAction(UIProgressView *pv, UILabel *lb, UIButton *btn, UIViewController *hostVC) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        unsigned total = 0;
        Class *classes = objc_copyClassList(&total);
        mfLog(@"CLASSDUMP start: %u classes", total);
        if (!total || !classes) {
            dispatch_async(dispatch_get_main_queue(), ^{ lb.text = @"⚠️ 无类可枚举"; btn.enabled = YES; });
            return;
        }
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0]
                            stringByAppendingPathComponent:@"classdump"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *app = [[[NSBundle mainBundle] bundleIdentifier] lastPathComponent] ?: @"App";
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        df.dateFormat = @"yyyyMMdd_HHmm";
        NSString *finalPath = [dir stringByAppendingFormat:@"/%@_Dump_%@.zip", app, [df stringFromDate:[NSDate date]]];
        NSString *tmpPath = [finalPath stringByAppendingString:@".building"];

        [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
        if (![[NSFileManager defaultManager] createFileAtPath:tmpPath contents:nil attributes:nil]) {
            mfLog(@"CLASSDUMP create file FAILED");
            dispatch_async(dispatch_get_main_queue(), ^{ lb.text = @"⚠️ 无法创建输出文件"; btn.enabled = YES; });
            free(classes); return;
        }
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:tmpPath];
        NSMutableData *scratch = [NSMutableData dataWithCapacity:1 << 16];
        NSMutableArray *cds = [NSMutableArray array];
        NSMutableSet *seen = [NSMutableSet set];
        unsigned done = 0;

        for (unsigned i = 0; i < total; i++) {
            @autoreleasepool {
                @try {
                    const char *nm = class_getName(classes[i]);
                    if (!nm || !*nm) continue;
                    NSString *name = @(nm);
                    if ([seen containsObject:name]) continue;
                    [seen addObject:name];
                    NSString *fname = [[name stringByReplacingOccurrencesOfString:@"/" withString:@"_"]
                                        stringByAppendingString:@".h"];
                    NSString *body = mfHeaderForClass(classes[i]);
                    if (body) mfZipAddStream(fh, cds, fname, [body dataUsingEncoding:NSUTF8StringEncoding], scratch);
                } @catch (NSException *ex) {
                    mfLog(@"CLASSDUMP class %u failed: %@", i, ex.name);
                }
            }
            done++;
            if (done % 500 == 0 || done == total) {
                float frac = (float)done / total;
                unsigned d = done;
                dispatch_async(dispatch_get_main_queue(), ^{
                    pv.progress = frac;
                    lb.text = [NSString stringWithFormat:@"正在生成头文件... %.0f%% (%u/%u)", frac * 100, d, total];
                });
            }
        }
        free(classes);
        mfLog(@"CLASSDUMP generated %u headers, scanning Swift metadata", (unsigned)cds.count);

        dispatch_async(dispatch_get_main_queue(), ^{
            lb.text = @"正在扫描 Swift 类型...";
        });

        // Swift 元数据阶段
        NSMutableArray<NSString *> *swiftModules = [NSMutableArray array];
        @try {
            mfDumpAllSwift(fh, cds, scratch, swiftModules);
            mfLog(@"CLASSDUMP swift modules with types: %lu", (unsigned long)swiftModules.count);
        } @catch (NSException *ex) {
            mfLog(@"CLASSDUMP swift phase failed: %@", ex.reason);
        }

        mfLog(@"CLASSDUMP writing central dir (%u entries)", (unsigned)cds.count);
        // finish 标记 + 中央目录
        mfZipAddStream(fh, cds, @"finish.txt", [@"finish" dataUsingEncoding:NSUTF8StringEncoding], scratch);
        BOOL ok = mfZipFinishStream(fh, cds);
        [fh closeFile];

        if (!ok || cds.count < 2) {
            [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
            dispatch_async(dispatch_get_main_queue(), ^{ lb.text = @"⚠️ 压缩失败，详见日志"; btn.enabled = YES; });
            return;
        }
        // 原子落位：.building → 正式名
        [[NSFileManager defaultManager] removeItemAtPath:finalPath error:nil];
        NSError *mvErr = nil;
        [[NSFileManager defaultManager] moveItemAtPath:tmpPath toPath:finalPath error:&mvErr];
        if (mvErr) mfLog(@"CLASSDUMP move failed: %@", mvErr.localizedDescription);

        unsigned cnt = (unsigned)cds.count;
        NSDictionary *szAt = [[NSFileManager defaultManager] attributesOfItemAtPath:finalPath error:nil];
        mfLog(@"CLASSDUMP done: %@ size=%@", finalPath, szAt[NSFileSize]);

        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *sw = swiftModules.count ? [NSString stringWithFormat:@"\nSwift 模块：%lu 个", (unsigned long)swiftModules.count] : @"";
            lb.text = [NSString stringWithFormat:@"✅ 完成：%u 条目 → %@%@", cnt, [finalPath lastPathComponent], sw];
            btn.enabled = YES;
            UIViewController *presenter = hostVC ?: g_mfPanelRootVC;
            while (presenter.presentedViewController && presenter.presentedViewController != presenter)
                presenter = presenter.presentedViewController;
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"ClassDump"
                    message:[NSString stringWithFormat:@"已导出 %u 个条目%@\n\n选择「保存到文件」可存到 下载/任意位置", cnt, sw]
                    preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"保存到文件" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                UIDocumentPickerViewController *dp =
                    [[UIDocumentPickerViewController alloc] initWithURL:[NSURL fileURLWithPath:finalPath]
                                                                 inMode:UIDocumentPickerModeExportToService];
                [presenter presentViewController:dp animated:YES completion:nil];
            }]];
            [alert addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
            [presenter presentViewController:alert animated:YES completion:nil];
        });
    });
}

// ====== 页面入口 ======
void mfShowClassDumpPage(void) {
    UIView *page = mfMakePage(@"ClassDump", YES);
    CGFloat gw = g_mfCardW - 32;

    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"未知";
    UILabel *info = [[UILabel alloc] initWithFrame:CGRectMake(16, 48, gw, 40)];
    info.numberOfLines = 2;
    info.font = [UIFont systemFontOfSize:12];
    info.textColor = [UIColor secondaryLabelColor];
    info.text = [NSString stringWithFormat:@"%@\n%u 个 ObjC 类待导出", bid, objc_getClassList(NULL, 0)];
    [page addSubview:info];

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(16, 96, gw, 44);
    btn.backgroundColor = [UIColor systemBlueColor];
    btn.layer.cornerRadius = 10;
    btn.tintColor = UIColor.whiteColor;
    btn.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    [btn setTitle:@"开始 Dump 并压缩" forState:UIControlStateNormal];
    [page addSubview:btn];

    UIProgressView *pv = [[UIProgressView alloc] initWithProgressViewStyle:UIProgressViewStyleDefault];
    pv.frame = CGRectMake(16, 156, gw, 8);
    [page addSubview:pv];

    UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(16, 172, gw, 60)];
    lb.font = [UIFont systemFontOfSize:12];
    lb.textColor = [UIColor secondaryLabelColor];
    lb.numberOfLines = 3;
    lb.text = @"ObjC 全类 + Swift 类型 → zip\n输出 Documents/classdump，可保存到文件App";
    [page addSubview:lb];

    UIViewController *hostVC = g_mfPanelRootVC;
    objc_setAssociatedObject(btn, "trio", @[pv, lb], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [btn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfClassDumpStart:") forControlEvents:UIControlEventTouchUpInside];

    mfPushPage(page);
}

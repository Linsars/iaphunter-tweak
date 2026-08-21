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

typedef struct { NSString *name; uint32_t crc, csize, usize, offset; uint16_t method; } MFCDEntry;

static void mfZipTime(uint16_t *t, uint16_t *dt) {
    time_t now = time(NULL);
    struct tm tmv; localtime_r(&now, &tmv);
    *t  = (uint16_t)((tmv.tm_hour << 11) | (tmv.tm_min << 5) | (tmv.tm_sec >> 1));
    *dt = (uint16_t)(((tmv.tm_year + 1900 - 1980) << 9) | ((tmv.tm_mon + 1) << 5) | tmv.tm_mday);
}

static void mfZipAdd(NSMutableData *zip, NSMutableArray *cds, NSString *name, NSData *data) {
    uint16_t mtime, mdate; mfZipTime(&mtime, &mdate);
    uint32_t crc = (uint32_t)crc32(0, data.bytes, (uInt)data.length);
    NSMutableData *comp = [NSMutableData dataWithCapacity:data.length / 2 + 64];
    uLongf csz = compressBound(data.length);
    [comp setLength:csz];
    int rc = compress2(comp.mutableBytes, &csz, data.bytes, data.length, Z_DEFAULT_COMPRESSION);
    BOOL stored = (rc != Z_OK || csz >= data.length);
    uint16_t method = stored ? 0 : 8;
    uint32_t finalSize = stored ? (uint32_t)data.length : (uint32_t)csz;

    uint32_t off = (uint32_t)zip.length;
    mfPut32(zip, 0x04034b50); mfPut16(zip, 20); mfPut16(zip, 0x0800);
    mfPut16(zip, method); mfPut16(zip, mtime); mfPut16(zip, mdate);
    mfPut32(zip, crc);
    mfPut32(zip, stored ? (uint32_t)data.length : (uint32_t)csz);
    mfPut32(zip, (uint32_t)data.length);
    NSData *nb = [name dataUsingEncoding:NSUTF8StringEncoding];
    mfPut16(zip, (uint16_t)nb.length); mfPut16(zip, 0);
    [zip appendData:nb];
    [zip appendData:(stored ? data : comp)];

    MFCDEntry e = { name, crc, finalSize, (uint32_t)data.length, off, method };
    [cds addObject:[NSValue valueWithBytes:&e objCType:@encode(MFCDEntry)]];
}

static NSData *mfZipFinish(NSMutableData *zip, NSMutableArray *cds) {
    uint32_t cdOff = (uint32_t)zip.length;
    for (NSValue *v in cds) {
        MFCDEntry e; [v getValue:&e];
        uint16_t mtime, mdate; mfZipTime(&mtime, &mdate);
        mfPut32(zip, 0x02014b50); mfPut16(zip, 20); mfPut16(zip, 20);
        mfPut16(zip, 0x0800); mfPut16(zip, e.method);
        mfPut16(zip, mtime); mfPut16(zip, mdate);
        mfPut32(zip, e.crc); mfPut32(zip, e.csize); mfPut32(zip, e.usize);
        NSData *nb = [e.name dataUsingEncoding:NSUTF8StringEncoding];
        mfPut16(zip, (uint16_t)nb.length);
        mfPut16(zip, 0); mfPut16(zip, 0); mfPut16(zip, 0); mfPut16(zip, 0);
        mfPut32(zip, 0); mfPut32(zip, e.offset);
        [zip appendData:nb];
    }
    uint32_t cdSize = (uint32_t)(zip.length - cdOff);
    mfPut32(zip, 0x06054b50); mfPut16(zip, 0); mfPut16(zip, 0);
    mfPut16(zip, (uint16_t)cds.count); mfPut16(zip, (uint16_t)cds.count);
    mfPut32(zip, cdSize); mfPut32(zip, cdOff); mfPut16(zip, 0);
    return zip;
}

// ====== 主流程 ======
void mfClassDumpStartAction(UIProgressView *pv, UILabel *lb, UIButton *btn, UIViewController *hostVC) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        Class *classes = NULL;
        unsigned total = 0;
        classes = objc_copyClassList(&total);
        if (!total || !classes) {
            dispatch_async(dispatch_get_main_queue(), ^{ lb.text = @"⚠️ 无类可枚举"; });
            free(classes); return;
        }
        NSMutableData *zip = [NSMutableData dataWithCapacity:1 << 20];
        NSMutableArray *cds = [NSMutableArray array];
        NSMutableSet *seen = [NSMutableSet set];
        unsigned done = 0;

        for (unsigned i = 0; i < total; i++) {
            @autoreleasepool {
                const char *nm = class_getName(classes[i]);
                if (!nm || !*nm) continue;
                NSString *name = @(nm);
                if ([seen containsObject:name]) continue;
                [seen addObject:name];
                NSString *fname = [[name stringByReplacingOccurrencesOfString:@"/" withString:@"_"]
                                    stringByAppendingString:@".h"];
                NSString *body = mfHeaderForClass(classes[i]);
                if (body) mfZipAdd(zip, cds, fname, [body dataUsingEncoding:NSUTF8StringEncoding]);
            }
            done++;
            if (done % 200 == 0 || done == total) {
                float frac = (float)done / total;
                dispatch_async(dispatch_get_main_queue(), ^{
                    pv.progress = frac;
                    lb.text = [NSString stringWithFormat:@"正在生成头文件... %.0f%%", frac * 100];
                });
            }
        }
        free(classes);
        mfZipAdd(zip, cds, @"finish.txt", [@"finish" dataUsingEncoding:NSUTF8StringEncoding]);
        mfZipFinish(zip, cds);

        NSString *app = [[[NSBundle mainBundle] bundleIdentifier] lastPathComponent] ?: @"App";
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        df.dateFormat = @"yyyyMMdd_HHmm";
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0]
                            stringByAppendingPathComponent:@"classdump"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *path = [dir stringByAppendingFormat:@"/%@_Dump_%@.zip", app, [df stringFromDate:[NSDate date]]];
        [zip writeToFile:path atomically:YES];

        dispatch_async(dispatch_get_main_queue(), ^{
            lb.text = [NSString stringWithFormat:@"✅ 完成：%u 类 → %@", seen.count,
                       [path lastPathComponent]];
            btn.enabled = YES;
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"ClassDump"
                    message:[NSString stringWithFormat:@"已压缩为 zip\n%@", path]
                    preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"分享/保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                UIActivityViewController *av = [[UIActivityViewController alloc]
                        initWithActivityItems:@[[NSURL fileURLWithPath:path]] applicationActivities:nil];
                [hostVC presentViewController:av animated:YES completion:nil];
            }]];
            [alert addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
            [hostVC presentViewController:alert animated:YES completion:nil];
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
    lb.text = @"输出到 Documents/classdump/*.zip";
    [page addSubview:lb];

    UIViewController *hostVC = g_mfPanelRootVC;
    objc_setAssociatedObject(btn, "trio", @[pv, lb], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [btn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfClassDumpStart:") forControlEvents:UIControlEventTouchUpInside];

    mfPushPage(page);
}

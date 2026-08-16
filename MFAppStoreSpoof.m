// MFAppStoreSpoof.m — AppStore 版本伪装 + 兼容性下载
// hook appstored: UA伪装始终生效 + 兼容性下载额外注入 appExtVrsId
// hook installd: 绕过最低版本检查

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>

#define SPOOF_LOG_FILE "/var/mobile/Library/Caches/appstore_spoof.log"
#define SPOOF_LOG(fmt, ...) do { \
    NSString *_msg = [NSString stringWithFormat:fmt, ##__VA_ARGS__]; \
    NSString *_line = [NSString stringWithFormat:@"[%@] %@\n", \
        [NSDateFormatter localizedStringFromDate:[NSDate date] \
            dateStyle:NSDateFormatterNoStyle timeStyle:NSDateFormatterMediumStyle], _msg]; \
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:@SPOOF_LOG_FILE]; \
    if (fh) { [fh seekToEndOfFile]; [fh writeData:[_line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; } \
    else { [_line writeToFile:@SPOOF_LOG_FILE atomically:YES encoding:NSUTF8StringEncoding error:nil]; } \
} while(0)

static NSString *g_spoofVersion = nil;
static BOOL g_spoofEnabled = NO;
static BOOL g_compatibleDownload = NO;
static NSString *g_currentIOSVersion = nil;

static NSString *mfGetCurrentIOSVersion(void) {
    NSDictionary *sysVer = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    return sysVer[@"ProductVersion"] ?: @"17.0";
}

static void loadConfig(void) {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:
        @"/var/mobile/Library/Preferences/dev.mineek.appstoretroller.plist"];
    if (prefs) {
        NSNumber *enabled = prefs[@"enabled"];
        g_spoofEnabled = enabled ? [enabled boolValue] : NO;
        if (!g_spoofEnabled) {
            SPOOF_LOG(@"version spoof disabled");
            return;
        }
        NSString *ver = prefs[@"iOSVersion"];
        if (ver.length > 0) g_spoofVersion = ver;
        NSNumber *compat = prefs[@"compatibleDownload"];
        g_compatibleDownload = compat ? [compat boolValue] : NO;
    }
    if (!g_spoofVersion) g_spoofVersion = @"99.0.0";
    g_currentIOSVersion = mfGetCurrentIOSVersion();
    SPOOF_LOG(@"config: enabled=%d version=%@ compatible=%d currentOS=%@",
        g_spoofEnabled, g_spoofVersion, g_compatibleDownload, g_currentIOSVersion);
}

static BOOL isProcess(const char *name) {
    char path[1024];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
    NSString *execPath = [NSString stringWithUTF8String:path];
    return [execPath hasSuffix:[NSString stringWithFormat:@"/%s", name]];
}

// ====== bilin API ======
static NSArray *mfFetchVersionHistory(NSString *trackId) {
    if (trackId.length == 0) { SPOOF_LOG(@"bilin: trackId empty"); return nil; }
    NSString *urlStr = [NSString stringWithFormat:@"https://apis.bilin.eu.org/history/%@", trackId];
    SPOOF_LOG(@"bilin: GET %@", urlStr);
    NSURL *url = [NSURL URLWithString:urlStr];
    if (!url) { SPOOF_LOG(@"bilin: invalid URL"); return nil; }

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:10];
    [req setValue:@"MinisFix/1.2.1" forHTTPHeaderField:@"User-Agent"];
    __block NSArray *result = nil;
    __block BOOL done = NO;

    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (err) { SPOOF_LOG(@"bilin: error=%@", err.localizedDescription); done = YES; return; }
        NSHTTPURLResponse *hr = (NSHTTPURLResponse *)resp;
        SPOOF_LOG(@"bilin: status=%ld bytes=%lu", (long)hr.statusCode, (unsigned long)data.length);
        if (hr.statusCode != 200 || !data) { done = YES; return; }
        NSError *je = nil;
        id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&je];
        if (je) { SPOOF_LOG(@"bilin: json err=%@", je.localizedDescription); done = YES; return; }
        if ([json isKindOfClass:[NSArray class]]) {
            result = (NSArray *)json;
        } else if ([json isKindOfClass:[NSDictionary class]]) {
            result = json[@"versions"] ?: json[@"data"] ?: json[@"results"];
            if (![result isKindOfClass:[NSArray class]]) {
                SPOOF_LOG(@"bilin: unexpected dict keys=%@", [json allKeys]);
                result = nil;
            }
        }
        SPOOF_LOG(@"bilin: got %lu versions", (unsigned long)result.count);
        done = YES;
    }];
    [task resume];

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:8.0];
    while (!done && [[NSDate date] compare:deadline] == NSOrderedAscending)
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    if (!done) { SPOOF_LOG(@"bilin: timeout"); [task cancel]; }
    return result;
}

// 降序遍历，找第一个 minOS <= currentOS 的版本
static NSDictionary *mfFindCompatibleVersion(NSArray *versions, NSString *currentOS) {
    if (versions.count == 0 || currentOS.length == 0) { SPOOF_LOG(@"findCompat: empty"); return nil; }
    SPOOF_LOG(@"findCompat: %lu versions, currentOS=%@", (unsigned long)versions.count, currentOS);

    NSArray *sorted = [versions sortedArrayUsingComparator:^NSComparisonResult(id a, id b) {
        NSString *va = a[@"externalVersionId"] ?: a[@"versionId"] ?: @"0";
        NSString *vb = b[@"externalVersionId"] ?: b[@"versionId"] ?: @"0";
        return [vb compare:va options:NSNumericSearch];
    }];

    for (NSDictionary *ver in sorted) {
        NSString *verId = ver[@"externalVersionId"] ?: ver[@"versionId"];
        NSString *verStr = ver[@"versionDisplay"] ?: ver[@"versionString"] ?: @"";
        NSString *minOS = ver[@"minimumOsVersion"] ?: ver[@"minimumOSVersion"] ?: ver[@"minOS"];
        if (!verId) { SPOOF_LOG(@"findCompat: skip no-id ver=%@", ver); continue; }
        if (!minOS.length) {
            SPOOF_LOG(@"findCompat: ver %@ (%@) no minOS → compatible", verId, verStr);
            return @{@"versionId": verId, @"versionString": verStr};
        }
        NSComparisonResult cmp = [minOS compare:currentOS options:NSNumericSearch];
        if (cmp != NSOrderedDescending) {
            SPOOF_LOG(@"findCompat: ✓ ver %@ (%@) minOS=%@", verId, verStr, minOS);
            return @{@"versionId": verId, @"versionString": verStr};
        }
        SPOOF_LOG(@"findCompat: ✗ ver %@ (%@) minOS=%@ > %@", verId, verStr, minOS, currentOS);
    }
    SPOOF_LOG(@"findCompat: no compatible version");
    return nil;
}

// ====== body 解析 ======
static NSString *mfExtractParam(NSData *body, NSString *key) {
    if (!body.length || !key.length) return nil;
    NSString *s = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (!s) return nil;
    NSString *needle = [key stringByAppendingString:@"="];
    NSRange r = [s rangeOfString:needle];
    if (r.location == NSNotFound) return nil;
    NSUInteger start = r.location + r.length;
    NSUInteger end = [s rangeOfString:@"&" options:0 range:NSMakeRange(start, s.length - start)].location;
    if (end == NSNotFound) end = s.length;
    return [[s substringWithRange:NSMakeRange(start, end - start)] stringByRemovingPercentEncoding];
}

static NSData *mfSetParam(NSData *body, NSString *key, NSString *value) {
    if (!body.length || !key.length || !value.length) return body;
    NSString *s = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (!s) return body;
    NSString *needle = [key stringByAppendingString:@"="];
    NSRange r = [s rangeOfString:needle];
    NSString *kv = [NSString stringWithFormat:@"%@=%@", key, value];
    if (r.location != NSNotFound) {
        NSUInteger end = [s rangeOfString:@"&" options:0 range:NSMakeRange(r.location, s.length - r.location)].location;
        if (end == NSNotFound) end = s.length;
        return [[s stringByReplacingCharactersInRange:NSMakeRange(r.location, end - r.location) withString:kv] dataUsingEncoding:NSUTF8StringEncoding];
    }
    return [[NSString stringWithFormat:@"%@&%@", s, kv] dataUsingEncoding:NSUTF8StringEncoding];
}

// ====== hook 1: UA 伪装（始终生效） ======
static void (*orig_setValue)(id self, SEL _cmd, NSString *value, NSString *field);
static void hook_setValue(id self, SEL _cmd, NSString *value, NSString *field) {
    if (g_spoofEnabled && [field isEqualToString:@"User-Agent"] && [value containsString:@"iOS/"]) {
        NSRange range = [value rangeOfString:@"iOS/"];
        if (range.location != NSNotFound) {
            NSString *afterIOS = [value substringFromIndex:range.location + 4];
            NSString *oldVer = [[afterIOS componentsSeparatedByString:@" "] firstObject];
            NSString *oldFull = [NSString stringWithFormat:@"iOS/%@", oldVer];
            NSString *newFull = [NSString stringWithFormat:@"iOS/%@", g_spoofVersion];
            NSString *modified = [value stringByReplacingOccurrencesOfString:oldFull withString:newFull];
            SPOOF_LOG(@"UA: %@ → %@", oldFull, newFull);
            orig_setValue(self, _cmd, modified, field);
            return;
        }
    }
    orig_setValue(self, _cmd, value, field);
}

// ====== hook 2: 购买请求注入 appExtVrsId（仅兼容下载开启时） ======
static NSURLSessionDataTask *(*orig_dataTask)(id self, SEL _cmd, NSURLRequest *request, void (^completionHandler)(NSData *, NSURLResponse *, NSError *));
static NSURLSessionDataTask *hook_dataTask(id self, SEL _cmd, NSURLRequest *request, void (^completionHandler)(NSData *, NSURLResponse *, NSError *)) {
    NSURL *url = request.URL;
    BOOL isBuy = [url.absoluteString containsString:@"MZBuy.woa/wa/buyProduct"];

    if (!isBuy || !g_compatibleDownload || !g_spoofEnabled) {
        return orig_dataTask(self, _cmd, request, completionHandler);
    }

    SPOOF_LOG(@"buy request intercepted: %@", url.absoluteString);

    // 读 body
    NSData *body = [request HTTPBody];
    if (!body.length) {
        NSInputStream *stream = [request HTTPBodyStream];
        if (stream) {
            [stream open];
            NSMutableData *d = [NSMutableData data];
            uint8_t buf[4096];
            NSInteger n;
            while ((n = [stream read:buf maxLength:sizeof(buf)]) > 0) [d appendBytes:buf length:n];
            [stream close];
            body = d;
            SPOOF_LOG(@"body from stream: %lu bytes", (unsigned long)body.length);
        }
    }
    if (!body.length) {
        SPOOF_LOG(@"no body, skip compat injection");
        return orig_dataTask(self, _cmd, request, completionHandler);
    }

    // 提取 track ID
    NSString *trackId = mfExtractParam(body, @"salableAdamId");
    SPOOF_LOG(@"salableAdamId=%@", trackId ?: @"nil");
    if (!trackId.length) {
        SPOOF_LOG(@"no salableAdamId, skip");
        return orig_dataTask(self, _cmd, request, completionHandler);
    }

    // 查版本
    NSArray *versions = mfFetchVersionHistory(trackId);
    if (!versions.count) {
        SPOOF_LOG(@"no versions, use UA spoof (latest)");
        return orig_dataTask(self, _cmd, request, completionHandler);
    }

    NSDictionary *compat = mfFindCompatibleVersion(versions, g_currentIOSVersion);
    if (!compat) {
        SPOOF_LOG(@"no compatible version, use UA spoof (latest)");
        return orig_dataTask(self, _cmd, request, completionHandler);
    }

    NSString *verId = compat[@"versionId"];
    NSString *verStr = compat[@"versionString"];
    SPOOF_LOG(@"injecting appExtVrsId=%@ (%@)", verId, verStr);

    // 注入 appExtVrsId 到 body（UA 已经在 hook1 伪装好了）
    NSData *newBody = mfSetParam(body, @"appExtVrsId", verId);
    NSMutableURLRequest *newReq = [request mutableCopy];
    [newReq setHTTPBody:newBody];
    SPOOF_LOG(@"body %lu → %lu bytes", (unsigned long)body.length, (unsigned long)newBody.length);

    return orig_dataTask(self, _cmd, newReq, completionHandler);
}

// ====== hook 3: MIBundle 版本检查（installd） ======
static BOOL (*orig_isMinOS)(id self, SEL _cmd, NSString *min, NSString *current, NSString *required, NSError **err);
static BOOL hook_isMinOS(id self, SEL _cmd, NSString *min, NSString *current, NSString *required, NSError **err) {
    SPOOF_LOG(@"isMinOS bypass: min=%@ cur=%@", min, current);
    return YES;
}
static BOOL (*orig_isApplicable)(id self, SEL _cmd, NSError **err);
static BOOL hook_isApplicable(id self, SEL _cmd, NSError **err) {
    SPOOF_LOG(@"isApplicable bypass");
    return YES;
}

__attribute__((constructor))
static void AppStoreSpoof_init(void) {
    @autoreleasepool {
        loadConfig();
        if (!g_spoofEnabled) return;

        if (isProcess("appstored")) {
            SPOOF_LOG(@"init in appstored");
            Class reqCls = objc_getClass("NSMutableURLRequest");
            if (reqCls) {
                Method m = class_getInstanceMethod(reqCls, @selector(setValue:forHTTPHeaderField:));
                if (m) {
                    orig_setValue = (void *)method_getImplementation(m);
                    method_setImplementation(m, (IMP)hook_setValue);
                    SPOOF_LOG(@"hooked setValue:forHTTPHeaderField:");
                } else SPOOF_LOG(@"ERROR: setValue: not found");
            } else SPOOF_LOG(@"ERROR: NSMutableURLRequest not found");

            if (g_compatibleDownload) {
                Class sessCls = objc_getClass("NSURLSession");
                if (sessCls) {
                    Method m = class_getInstanceMethod(sessCls, @selector(dataTaskWithRequest:completionHandler:));
                    if (m) {
                        orig_dataTask = (void *)method_getImplementation(m);
                        method_setImplementation(m, (IMP)hook_dataTask);
                        SPOOF_LOG(@"hooked dataTaskWithRequest:");
                    } else SPOOF_LOG(@"ERROR: dataTaskWithRequest: not found");
                } else SPOOF_LOG(@"ERROR: NSURLSession not found");
            }
        } else if (isProcess("installd")) {
            SPOOF_LOG(@"init in installd");
            Class cls = objc_getClass("MIBundle");
            if (cls) {
                Method m1 = class_getInstanceMethod(cls, @selector(_isMinimumOSVersion:applicableToOSVersion:requiredOS:error:));
                if (m1) {
                    orig_isMinOS = (void *)method_getImplementation(m1);
                    method_setImplementation(m1, (IMP)hook_isMinOS);
                    SPOOF_LOG(@"hooked _isMinimumOSVersion:");
                } else SPOOF_LOG(@"WARN: _isMinimumOSVersion: not found");

                Method m2 = class_getInstanceMethod(cls, @selector(isMinimumOSVersion:applicableToOSVersion:error:));
                if (m2) {
                    method_setImplementation(m2, (IMP)hook_isMinOS);
                    SPOOF_LOG(@"hooked isMinimumOSVersion:");
                } else SPOOF_LOG(@"WARN: isMinimumOSVersion: not found");

                Method m3 = class_getInstanceMethod(cls, @selector(isApplicableToCurrentOSVersionWithError:));
                if (m3) {
                    orig_isApplicable = (void *)method_getImplementation(m3);
                    method_setImplementation(m3, (IMP)hook_isApplicable);
                    SPOOF_LOG(@"hooked isApplicable:");
                } else SPOOF_LOG(@"WARN: isApplicable: not found");
            } else SPOOF_LOG(@"ERROR: MIBundle not found");
        }
        SPOOF_LOG(@"init complete");
    }
}

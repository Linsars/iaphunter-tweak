// MFAppStoreSpoof.m — AppStore 版本伪装 + 兼容性下载
// hook appstored: UA伪装始终生效 + 兼容性下载额外注入 appExtVrsId
// hook installd: 绕过最低版本检查

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>

// 文件日志 —— appstored/installd 是 daemon，NSLog 不好读
static void mfSpoofLog(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSString *line = [NSString stringWithFormat:@"%@\n", msg];
    NSString *path = @"/var/mobile/Library/Caches/appstore_spoof.log";
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (fh) {
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    } else {
        [line writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

static NSString *g_spoofVersion = nil;
static BOOL g_spoofEnabled = NO;
static BOOL g_compatibleDownload = NO;
static NSString *g_currentIOSVersion = nil;

static void loadConfig(void) {
    mfSpoofLog(@"[spoof] loadConfig ENTER");
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:
        @"/var/mobile/Library/Preferences/dev.mineek.appstoretroller.plist"];
    mfSpoofLog(@"[spoof] prefs=%@", prefs);
    if (prefs) {
        NSNumber *enabled = prefs[@"enabled"];
        g_spoofEnabled = enabled ? [enabled boolValue] : NO;
        mfSpoofLog(@"[spoof] enabled=%d", g_spoofEnabled);
        if (!g_spoofEnabled) {
            mfSpoofLog(@"[spoof] DISABLED, return");
            return;
        }
        NSString *ver = prefs[@"iOSVersion"];
        if (ver.length > 0) g_spoofVersion = ver;
        NSNumber *compat = prefs[@"compatibleDownload"];
        g_compatibleDownload = compat ? [compat boolValue] : NO;
        mfSpoofLog(@"[spoof] version=%@ compatible=%d", g_spoofVersion, g_compatibleDownload);
    }
    if (!g_spoofVersion) g_spoofVersion = @"99.0.0";
    NSDictionary *sysVer = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    g_currentIOSVersion = sysVer[@"ProductVersion"] ?: @"17.0";
    mfSpoofLog(@"[spoof] config DONE: enabled=%d version=%@ compatible=%d os=%@",
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
    mfSpoofLog(@"[bilin] ENTER trackId=%@", trackId);
    if (trackId.length == 0) { mfSpoofLog(@"[bilin] trackId empty, return nil"); return nil; }
    NSString *urlStr = [NSString stringWithFormat:@"https://apis.bilin.eu.org/history/%@", trackId];
    mfSpoofLog(@"[bilin] GET %@", urlStr);
    NSURL *url = [NSURL URLWithString:urlStr];
    if (!url) { mfSpoofLog(@"[bilin] invalid URL"); return nil; }

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:10];
    [req setValue:@"MinisFix/1.2.1" forHTTPHeaderField:@"User-Agent"];
    __block NSArray *result = nil;
    __block BOOL done = NO;

    mfSpoofLog(@"[bilin] starting dataTask...");
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        mfSpoofLog(@"[bilin] callback entered, data=%lu bytes err=%@", (unsigned long)data.length, err);
        if (err) { mfSpoofLog(@"[bilin] error=%@", err.localizedDescription); done = YES; return; }
        NSHTTPURLResponse *hr = (NSHTTPURLResponse *)resp;
        mfSpoofLog(@"[bilin] status=%ld", (long)hr.statusCode);
        if (hr.statusCode != 200 || !data) { mfSpoofLog(@"[bilin] bad response"); done = YES; return; }
        NSError *je = nil;
        id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&je];
        mfSpoofLog(@"[bilin] json class=%@ err=%@", NSStringFromClass([json class]), je);
        if (je) { done = YES; return; }
        if ([json isKindOfClass:[NSArray class]]) {
            result = (NSArray *)json;
        } else if ([json isKindOfClass:[NSDictionary class]]) {
            result = json[@"versions"] ?: json[@"data"] ?: json[@"results"];
            if (![result isKindOfClass:[NSArray class]]) {
                mfSpoofLog(@"[bilin] dict keys=%@, no array found", [json allKeys]);
                result = nil;
            }
        }
        mfSpoofLog(@"[bilin] got %lu versions", (unsigned long)result.count);
        done = YES;
    }];
    [task resume];
    mfSpoofLog(@"[bilin] task resumed, waiting...");

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:8.0];
    while (!done && [[NSDate date] compare:deadline] == NSOrderedAscending)
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    if (!done) { mfSpoofLog(@"[bilin] TIMEOUT after 8s"); [task cancel]; }
    mfSpoofLog(@"[bilin] returning %lu versions", (unsigned long)result.count);
    return result;
}

static NSDictionary *mfFindCompatibleVersion(NSArray *versions, NSString *currentOS) {
    mfSpoofLog(@"[findCompat] ENTER %lu versions, os=%@", (unsigned long)versions.count, currentOS);
    if (versions.count == 0 || currentOS.length == 0) return nil;

    NSArray *sorted = [versions sortedArrayUsingComparator:^NSComparisonResult(id a, id b) {
        NSString *va = a[@"externalVersionId"] ?: a[@"versionId"] ?: @"0";
        NSString *vb = b[@"externalVersionId"] ?: b[@"versionId"] ?: @"0";
        return [vb compare:va options:NSNumericSearch];
    }];

    for (NSDictionary *ver in sorted) {
        NSString *verId = ver[@"externalVersionId"] ?: ver[@"versionId"];
        NSString *verStr = ver[@"versionDisplay"] ?: ver[@"versionString"] ?: @"";
        NSString *minOS = ver[@"minimumOsVersion"] ?: ver[@"minimumOSVersion"] ?: ver[@"minOS"];
        if (!verId) { mfSpoofLog(@"[findCompat] skip no-id, keys=%@", [ver allKeys]); continue; }
        if (!minOS.length) {
            mfSpoofLog(@"[findCompat] ver %@ (%@) no minOS → compatible", verId, verStr);
            return @{@"versionId": verId, @"versionString": verStr};
        }
        NSComparisonResult cmp = [minOS compare:currentOS options:NSNumericSearch];
        mfSpoofLog(@"[findCompat] ver %@ (%@) minOS=%@ vs os=%@ → %@",
            verId, verStr, minOS, currentOS, cmp != NSOrderedDescending ? @"✓COMPAT" : @"✗SKIP");
        if (cmp != NSOrderedDescending) {
            return @{@"versionId": verId, @"versionString": verStr};
        }
    }
    mfSpoofLog(@"[findCompat] NO compatible version found");
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
            mfSpoofLog(@"[UA] %@ → %@", oldFull, newFull);
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

    if (!isBuy) {
        return orig_dataTask(self, _cmd, request, completionHandler);
    }

    mfSpoofLog(@"[buy] intercepted: %@", url.absoluteString);

    if (!g_compatibleDownload) {
        mfSpoofLog(@"[buy] compatible download OFF, pass through");
        return orig_dataTask(self, _cmd, request, completionHandler);
    }

    // 读 body
    NSData *body = [request HTTPBody];
    mfSpoofLog(@"[buy] HTTPBody=%lu bytes", (unsigned long)body.length);
    if (!body.length) {
        NSInputStream *stream = [request HTTPBodyStream];
        mfSpoofLog(@"[buy] HTTPBodyStream=%@", stream);
        if (stream) {
            [stream open];
            NSMutableData *d = [NSMutableData data];
            uint8_t buf[4096];
            NSInteger n;
            while ((n = [stream read:buf maxLength:sizeof(buf)]) > 0) [d appendBytes:buf length:n];
            [stream close];
            body = d;
            mfSpoofLog(@"[buy] stream read %lu bytes", (unsigned long)body.length);
        }
    }
    if (!body.length) {
        mfSpoofLog(@"[buy] no body, pass through");
        return orig_dataTask(self, _cmd, request, completionHandler);
    }

    NSString *trackId = mfExtractParam(body, @"salableAdamId");
    mfSpoofLog(@"[buy] salableAdamId=%@", trackId ?: @"nil");
    if (!trackId.length) {
        mfSpoofLog(@"[buy] no salableAdamId, pass through");
        return orig_dataTask(self, _cmd, request, completionHandler);
    }

    NSArray *versions = mfFetchVersionHistory(trackId);
    if (!versions.count) {
        mfSpoofLog(@"[buy] no versions, pass through (UA spoof still active)");
        return orig_dataTask(self, _cmd, request, completionHandler);
    }

    NSDictionary *compat = mfFindCompatibleVersion(versions, g_currentIOSVersion);
    if (!compat) {
        mfSpoofLog(@"[buy] no compatible version, pass through (UA spoof still active)");
        return orig_dataTask(self, _cmd, request, completionHandler);
    }

    NSString *verId = compat[@"versionId"];
    mfSpoofLog(@"[buy] INJECTING appExtVrsId=%@", verId);

    NSData *newBody = mfSetParam(body, @"appExtVrsId", verId);
    NSMutableURLRequest *newReq = [request mutableCopy];
    [newReq setHTTPBody:newBody];
    mfSpoofLog(@"[buy] body %lu → %lu bytes", (unsigned long)body.length, (unsigned long)newBody.length);

    return orig_dataTask(self, _cmd, newReq, completionHandler);
}

// ====== hook 3: MIBundle 版本检查（installd） ======
static BOOL (*orig_isMinOS)(id self, SEL _cmd, NSString *min, NSString *current, NSString *required, NSError **err);
static BOOL hook_isMinOS(id self, SEL _cmd, NSString *min, NSString *current, NSString *required, NSError **err) {
    return YES;
}
static BOOL (*orig_isApplicable)(id self, SEL _cmd, NSError **err);
static BOOL hook_isApplicable(id self, SEL _cmd, NSError **err) {
    return YES;
}

__attribute__((constructor))
static void AppStoreSpoof_init(void) {
    @autoreleasepool {
        mfSpoofLog(@"========== AppStoreSpoof INIT pid=%d ==========", getpid());
        loadConfig();
        if (!g_spoofEnabled) {
            mfSpoofLog(@"[init] spoof disabled, return");
            return;
        }

        if (isProcess("appstored")) {
            mfSpoofLog(@"[init] running in appstored");
            Class reqCls = objc_getClass("NSMutableURLRequest");
            mfSpoofLog(@"[init] NSMutableURLRequest=%@", reqCls);
            if (reqCls) {
                Method m = class_getInstanceMethod(reqCls, @selector(setValue:forHTTPHeaderField:));
                mfSpoofLog(@"[init] setValue: method=%p", m);
                if (m) {
                    orig_setValue = (void *)method_getImplementation(m);
                    method_setImplementation(m, (IMP)hook_setValue);
                    mfSpoofLog(@"[init] HOOKED setValue:forHTTPHeaderField:");
                }
            }

            if (g_compatibleDownload) {
                mfSpoofLog(@"[init] compatible download ON, hooking NSURLSession...");
                Class sessCls = objc_getClass("NSURLSession");
                mfSpoofLog(@"[init] NSURLSession=%@", sessCls);
                if (sessCls) {
                    Method m = class_getInstanceMethod(sessCls, @selector(dataTaskWithRequest:completionHandler:));
                    mfSpoofLog(@"[init] dataTaskWithRequest: method=%p", m);
                    if (m) {
                        orig_dataTask = (void *)method_getImplementation(m);
                        method_setImplementation(m, (IMP)hook_dataTask);
                        mfSpoofLog(@"[init] HOOKED dataTaskWithRequest:");
                    }
                }
            } else {
                mfSpoofLog(@"[init] compatible download OFF, skip NSURLSession hook");
            }
        } else if (isProcess("installd")) {
            mfSpoofLog(@"[init] running in installd");
            Class cls = objc_getClass("MIBundle");
            if (cls) {
                Method m1 = class_getInstanceMethod(cls, @selector(_isMinimumOSVersion:applicableToOSVersion:requiredOS:error:));
                if (m1) { orig_isMinOS = (void *)method_getImplementation(m1); method_setImplementation(m1, (IMP)hook_isMinOS); }
                Method m2 = class_getInstanceMethod(cls, @selector(isMinimumOSVersion:applicableToOSVersion:error:));
                if (m2) { method_setImplementation(m2, (IMP)hook_isMinOS); }
                Method m3 = class_getInstanceMethod(cls, @selector(isApplicableToCurrentOSVersionWithError:));
                if (m3) { orig_isApplicable = (void *)method_getImplementation(m3); method_setImplementation(m3, (IMP)hook_isApplicable); }
            }
        }
        mfSpoofLog(@"========== AppStoreSpoof INIT DONE ==========");
    }
}

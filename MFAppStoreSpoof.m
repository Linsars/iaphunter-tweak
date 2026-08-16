// MFAppStoreSpoof.m — AppStore 版本伪装 + 兼容性下载
// hook appstored: 修改 User-Agent + 兼容性下载（bilin API 查版本 → appExtVrsId）
// hook installd: 绕过最低版本检查

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>

#define SPOOF_LOG(fmt, ...) NSLog(@"[AppStoreSpoof] " fmt, ##__VA_ARGS__)

static NSString *g_spoofVersion = nil;
static BOOL g_spoofEnabled = NO;
static BOOL g_compatibleDownload = NO;
static NSString *g_currentIOSVersion = nil;

// 获取当前系统版本
static NSString *mfGetCurrentIOSVersion(void) {
    return [[UIDevice currentDevice] systemVersion] ?: @"17.0";
}

// 读取配置
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
    SPOOF_LOG(@"config loaded: enabled=%d version=%@ compatible=%d currentOS=%@",
        g_spoofEnabled, g_spoofVersion, g_compatibleDownload, g_currentIOSVersion);
}

static BOOL isProcess(const char *name) {
    char path[1024];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
    NSString *execPath = [NSString stringWithUTF8String:path];
    return [execPath hasSuffix:[NSString stringWithFormat:@"/%s", name]];
}

// ====== bilin API 查询版本历史 ======
// 返回 @[@{@"versionId": @"xxx", @"versionString": @"1.2.3", @"minimumOSVersion": @"14.0"}, ...]
static NSArray *mfFetchVersionHistory(NSString *trackId) {
    if (trackId.length == 0) {
        SPOOF_LOG(@"fetchVersionHistory: trackId is empty");
        return nil;
    }
    
    NSString *urlStr = [NSString stringWithFormat:@"https://apis.bilin.eu.org/history/%@", trackId];
    SPOOF_LOG(@"fetchVersionHistory: requesting %@", urlStr);
    
    NSURL *url = [NSURL URLWithString:urlStr];
    if (!url) {
        SPOOF_LOG(@"fetchVersionHistory: invalid URL");
        return nil;
    }
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:10];
    [request setValue:@"MinisFix/1.2.1" forHTTPHeaderField:@"User-Agent"];
    
    __block NSArray *result = nil;
    __block BOOL finished = NO;
    
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            SPOOF_LOG(@"fetchVersionHistory: error=%@", error.localizedDescription);
            finished = YES;
            return;
        }
        
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
        SPOOF_LOG(@"fetchVersionHistory: status=%ld", (long)httpResp.statusCode);
        
        if (httpResp.statusCode != 200 || !data) {
            SPOOF_LOG(@"fetchVersionHistory: invalid response");
            finished = YES;
            return;
        }
        
        NSError *jsonError = nil;
        id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        if (jsonError) {
            SPOOF_LOG(@"fetchVersionHistory: JSON parse error=%@", jsonError.localizedDescription);
            finished = YES;
            return;
        }
        
        // bilin API 返回格式可能是数组或字典，需要适配
        if ([json isKindOfClass:[NSArray class]]) {
            result = (NSArray *)json;
        } else if ([json isKindOfClass:[NSDictionary class]]) {
            // 可能是 {"versions": [...]} 或 {"data": [...]}
            result = json[@"versions"] ?: json[@"data"] ?: json[@"results"];
            if (![result isKindOfClass:[NSArray class]]) {
                SPOOF_LOG(@"fetchVersionHistory: unexpected dict structure, keys=%@", [json allKeys]);
                result = nil;
            }
        } else {
            SPOOF_LOG(@"fetchVersionHistory: unexpected JSON type=%@", NSStringFromClass([json class]));
        }
        
        SPOOF_LOG(@"fetchVersionHistory: got %lu versions", (unsigned long)result.count);
        finished = YES;
    }];
    [task resume];
    
    // 同步等待（最多 8 秒）
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:8.0];
    while (!finished && [[NSDate date] compare:deadline] == NSOrderedAscending) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }
    
    if (!finished) {
        SPOOF_LOG(@"fetchVersionHistory: timeout after 8s");
        [task cancel];
    }
    
    return result;
}

// 从版本列表中找最后一个兼容当前系统的版本
// 返回 @{@"versionId": xxx, @"versionString": xxx} 或 nil
static NSDictionary *mfFindCompatibleVersion(NSArray *versions, NSString *currentOS) {
    if (versions.count == 0 || currentOS.length == 0) {
        SPOOF_LOG(@"findCompatible: empty versions or currentOS");
        return nil;
    }
    
    SPOOF_LOG(@"findCompatible: searching %lu versions for iOS %@", (unsigned long)versions.count, currentOS);
    
    // 按版本号降序排列（最新版本在前），找第一个 minimumOSVersion <= currentOS 的
    // bilin API 返回的格式可能是：
    // @{@"externalVersionId": xxx, @"versionDisplay": xxx, @"minimumOsVersion": xxx}
    // 或 @{@"versionId": xxx, @"versionString": xxx, @"minimumOSVersion": xxx}
    
    // 先尝试排序
    NSArray *sorted = [versions sortedArrayUsingComparator:^NSComparisonResult(id a, id b) {
        NSString *va = a[@"externalVersionId"] ?: a[@"versionId"] ?: @"0";
        NSString *vb = b[@"externalVersionId"] ?: b[@"versionId"] ?: @"0";
        // 降序
        return [vb compare:va options:NSNumericSearch];
    }];
    
    for (NSDictionary *ver in sorted) {
        NSString *verId = ver[@"externalVersionId"] ?: ver[@"versionId"];
        NSString *verStr = ver[@"versionDisplay"] ?: ver[@"versionString"] ?: ver[@"bundleVersion"];
        NSString *minOS = ver[@"minimumOsVersion"] ?: ver[@"minimumOSVersion"] ?: ver[@"minOS"];
        
        if (!verId) {
            SPOOF_LOG(@"findCompatible: skip version with no ID, dict=%@", ver);
            continue;
        }
        
        if (!minOS || minOS.length == 0) {
            // 没有 minimumOSVersion 信息，假设兼容（保守策略：直接返回这个版本）
            SPOOF_LOG(@"findCompatible: version %@ (%@) has no minOS, assuming compatible", verId, verStr);
            return @{@"versionId": verId, @"versionString": verStr ?: @"?"};
        }
        
        // 比较版本号
        NSComparisonResult cmp = [minOS compare:currentOS options:NSNumericSearch];
        if (cmp != NSOrderedDescending) {
            // minOS <= currentOS，兼容
            SPOOF_LOG(@"findCompatible: found compatible version %@ (%@) minOS=%@", verId, verStr, minOS);
            return @{@"versionId": verId, @"versionString": verStr ?: @"?"};
        } else {
            SPOOF_LOG(@"findCompatible: version %@ (%@) minOS=%@ > currentOS=%@, skip", verId, verStr, minOS, currentOS);
        }
    }
    
    SPOOF_LOG(@"findCompatible: no compatible version found");
    return nil;
}

// 从 form-encoded body 中提取参数值
static NSString *mfExtractParam(NSData *body, NSString *key) {
    if (!body || key.length == 0) return nil;
    NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (!bodyStr) return nil;
    
    NSString *searchKey = [key stringByAppendingString:@"="];
    NSRange range = [bodyStr rangeOfString:searchKey];
    if (range.location == NSNotFound) return nil;
    
    NSUInteger start = range.location + range.length;
    NSUInteger end = [bodyStr rangeOfString:@"&" options:0 range:NSMakeRange(start, bodyStr.length - start)].location;
    if (end == NSNotFound) end = bodyStr.length;
    
    NSString *value = [bodyStr substringWithRange:NSMakeRange(start, end - start)];
    // URL decode
    value = [value stringByRemovingPercentEncoding] ?: value;
    return value;
}

// 在 form-encoded body 中追加或替换参数
static NSData *mfSetParam(NSData *body, NSString *key, NSString *value) {
    if (!body || key.length == 0 || value.length == 0) return body;
    
    NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (!bodyStr) return body;
    
    NSString *searchKey = [key stringByAppendingString:@"="];
    NSRange range = [bodyStr rangeOfString:searchKey];
    
    NSString *newParam = [NSString stringWithFormat:@"%@=%@", key, value];
    
    if (range.location != NSNotFound) {
        // 替换现有参数
        NSUInteger start = range.location;
        NSUInteger end = [bodyStr rangeOfString:@"&" options:0 range:NSMakeRange(start, bodyStr.length - start)].location;
        if (end == NSNotFound) end = bodyStr.length;
        
        NSString *newBody = [bodyStr stringByReplacingCharactersInRange:NSMakeRange(start, end - start) withString:newParam];
        return [newBody dataUsingEncoding:NSUTF8StringEncoding];
    } else {
        // 追加新参数
        NSString *newBody = [NSString stringWithFormat:@"%@&%@", bodyStr, newParam];
        return [newBody dataUsingEncoding:NSUTF8StringEncoding];
    }
}

// hook 1: NSMutableURLRequest setValue:forHTTPHeaderField: — User-Agent 伪装
static void (*orig_setValue)(id self, SEL _cmd, NSString *value, NSString *field);
static void hook_setValue(id self, SEL _cmd, NSString *value, NSString *field) {
    if ([field isEqualToString:@"User-Agent"] && [value containsString:@"iOS/"]) {
        // 检查是否是购买请求（MZBuy.woa/wa/buyProduct）
        NSURL *url = [self URL];
        BOOL isBuyRequest = [url.absoluteString containsString:@"MZBuy.woa/wa/buyProduct"];
        
        if (isBuyRequest && g_compatibleDownload) {
            SPOOF_LOG(@"setValue: compatible download enabled, skip UA spoof (will handle in body hook)");
            // 兼容性下载模式：不改 UA，等 body hook 处理
            orig_setValue(self, _cmd, value, field);
            return;
        }
        
        // 非兼容下载模式或非购买请求：走原来的 UA 伪装
        if (g_spoofEnabled) {
            NSRange range = [value rangeOfString:@"iOS/"];
            if (range.location != NSNotFound) {
                NSString *afterIOS = [value substringFromIndex:range.location + range.length];
                NSString *oldVersion = [[afterIOS componentsSeparatedByString:@" "] firstObject];
                NSString *oldFull = [NSString stringWithFormat:@"iOS/%@", oldVersion];
                NSString *newFull = [NSString stringWithFormat:@"iOS/%@", g_spoofVersion];
                NSString *modified = [value stringByReplacingOccurrencesOfString:oldFull withString:newFull];
                SPOOF_LOG(@"setValue: UA spoofed %@ -> %@ in %@", oldFull, newFull, url.absoluteString);
                orig_setValue(self, _cmd, modified, field);
                return;
            }
        }
    }
    orig_setValue(self, _cmd, value, field);
}

// hook 2: NSURLSession dataTaskWithRequest: — 拦截购买请求，注入 appExtVrsId
static NSURLSessionDataTask *(*orig_dataTask)(id self, SEL _cmd, NSURLRequest *request, void (^completionHandler)(NSData *, NSURLResponse *, NSError *));
static NSURLSessionDataTask *hook_dataTask(id self, SEL _cmd, NSURLRequest *request, void (^completionHandler)(NSData *, NSURLResponse *, NSError *)) {
    NSURL *url = request.URL;
    BOOL isBuyRequest = [url.absoluteString containsString:@"MZBuy.woa/wa/buyProduct"];
    
    if (!isBuyRequest || !g_compatibleDownload || !g_spoofEnabled) {
        return orig_dataTask(self, _cmd, request, completionHandler);
    }
    
    SPOOF_LOG(@"dataTask: intercepted buy request %@", url.absoluteString);
    
    NSData *body = [request HTTPBody];
    if (!body) {
        SPOOF_LOG(@"dataTask: no HTTP body, trying HTTPBodyStream");
        // 尝试从 HTTPBodyStream 读取
        NSInputStream *stream = [request HTTPBodyStream];
        if (stream) {
            [stream open];
            NSMutableData *data = [NSMutableData data];
            uint8_t buf[4096];
            NSInteger len;
            while ((len = [stream read:buf maxLength:sizeof(buf)]) > 0) {
                [data appendBytes:buf length:len];
            }
            [stream close];
            body = data;
            SPOOF_LOG(@"dataTask: read %lu bytes from body stream", (unsigned long)body.length);
        }
    }
    
    if (!body || body.length == 0) {
        SPOOF_LOG(@"dataTask: no body found, falling back to UA spoof");
        // 没有 body，回退到 UA 伪装
        return orig_dataTask(self, _cmd, request, completionHandler);
    }
    
    // 提取 salableAdamId（track ID）
    NSString *trackId = mfExtractParam(body, @"salableAdamId");
    SPOOF_LOG(@"dataTask: extracted salableAdamId=%@", trackId ?: @"nil");
    
    if (trackId.length == 0) {
        SPOOF_LOG(@"dataTask: no salableAdamId in body, falling back to UA spoof");
        return orig_dataTask(self, _cmd, request, completionHandler);
    }
    
    // 查询版本历史
    NSArray *versions = mfFetchVersionHistory(trackId);
    if (!versions || versions.count == 0) {
        SPOOF_LOG(@"dataTask: no versions returned, falling back to UA spoof");
        // 没有版本历史，回退到 UA 伪装（下最新版）
        return orig_dataTask(self, _cmd, request, completionHandler);
    }
    
    // 查找兼容版本
    NSDictionary *compatVer = mfFindCompatibleVersion(versions, g_currentIOSVersion);
    if (!compatVer) {
        SPOOF_LOG(@"dataTask: no compatible version found, falling back to UA spoof");
        // 没有兼容版本，回退到 UA 伪装（下最新版）
        return orig_dataTask(self, _cmd, request, completionHandler);
    }
    
    NSString *versionId = compatVer[@"versionId"];
    NSString *versionStr = compatVer[@"versionString"];
    SPOOF_LOG(@"dataTask: using compatible version %@ (%@)", versionId, versionStr);
    
    // 在 body 中注入 appExtVrsId
    NSData *newBody = mfSetParam(body, @"appExtVrsId", versionId);
    SPOOF_LOG(@"dataTask: injected appExtVrsId=%@, body size %lu -> %lu", versionId, (unsigned long)body.length, (unsigned long)newBody.length);
    
    // 创建新请求
    NSMutableURLRequest *newRequest = [request mutableCopy];
    [newRequest setHTTPBody:newBody];
    
    // 也要修改 User-Agent（确保 Apple 不会拒绝）
    NSString *ua = [request valueForHTTPHeaderField:@"User-Agent"];
    if (ua && [ua containsString:@"iOS/"]) {
        NSRange range = [ua rangeOfString:@"iOS/"];
        if (range.location != NSNotFound) {
            NSString *afterIOS = [ua substringFromIndex:range.location + 4];
            NSString *oldVersion = [[afterIOS componentsSeparatedByString:@" "] firstObject];
            NSString *oldFull = [NSString stringWithFormat:@"iOS/%@", oldVersion];
            NSString *newFull = [NSString stringWithFormat:@"iOS/%@", g_spoofVersion];
            NSString *modified = [ua stringByReplacingOccurrencesOfString:oldFull withString:newFull];
            [newRequest setValue:modified forHTTPHeaderField:@"User-Agent"];
            SPOOF_LOG(@"dataTask: also spoofed UA %@ -> %@", oldFull, newFull);
        }
    }
    
    SPOOF_LOG(@"dataTask: sending modified request with appExtVrsId=%@", versionId);
    return orig_dataTask(self, _cmd, newRequest, completionHandler);
}

// hook 3: MIBundle 版本检查（installd 进程）
static BOOL (*orig_isMinOS)(id self, SEL _cmd, NSString *min, NSString *current, NSString *required, NSError **err);
static BOOL hook_isMinOS(id self, SEL _cmd, NSString *min, NSString *current, NSString *required, NSError **err) {
    SPOOF_LOG(@"isMinOS: bypassed (min=%@ current=%@)", min, current);
    return YES;
}

static BOOL (*orig_isApplicable)(id self, SEL _cmd, NSError **err);
static BOOL hook_isApplicable(id self, SEL _cmd, NSError **err) {
    SPOOF_LOG(@"isApplicable: bypassed");
    return YES;
}

__attribute__((constructor))
static void AppStoreSpoof_init(void) {
    @autoreleasepool {
        loadConfig();
        if (!g_spoofEnabled) return;
        
        if (isProcess("appstored")) {
            SPOOF_LOG(@"init: running in appstored");
            
            // hook User-Agent 修改
            Class reqCls = objc_getClass("NSMutableURLRequest");
            if (reqCls) {
                Method m = class_getInstanceMethod(reqCls, @selector(setValue:forHTTPHeaderField:));
                if (m) {
                    orig_setValue = (void *)method_getImplementation(m);
                    method_setImplementation(m, (IMP)hook_setValue);
                    SPOOF_LOG(@"init: hooked setValue:forHTTPHeaderField:");
                } else {
                    SPOOF_LOG(@"init: ERROR setValue:forHTTPHeaderField: not found");
                }
            } else {
                SPOOF_LOG(@"init: ERROR NSMutableURLRequest class not found");
            }
            
            // hook NSURLSession dataTaskWithRequest: — 兼容性下载
            if (g_compatibleDownload) {
                Class sessionCls = objc_getClass("NSURLSession");
                if (sessionCls) {
                    // dataTaskWithRequest:completionHandler: 的签名
                    SEL sel = @selector(dataTaskWithRequest:completionHandler:);
                    Method m = class_getInstanceMethod(sessionCls, sel);
                    if (m) {
                        orig_dataTask = (void *)method_getImplementation(m);
                        method_setImplementation(m, (IMP)hook_dataTask);
                        SPOOF_LOG(@"init: hooked dataTaskWithRequest:completionHandler:");
                    } else {
                        SPOOF_LOG(@"init: ERROR dataTaskWithRequest:completionHandler: not found");
                    }
                } else {
                    SPOOF_LOG(@"init: ERROR NSURLSession class not found");
                }
            }
            
        } else if (isProcess("installd")) {
            SPOOF_LOG(@"init: running in installd");
            
            Class cls = objc_getClass("MIBundle");
            if (cls) {
                // hook 多个版本检查方法
                Method m1 = class_getInstanceMethod(cls, @selector(_isMinimumOSVersion:applicableToOSVersion:requiredOS:error:));
                if (m1) {
                    orig_isMinOS = (void *)method_getImplementation(m1);
                    method_setImplementation(m1, (IMP)hook_isMinOS);
                    SPOOF_LOG(@"init: hooked _isMinimumOSVersion:applicableToOSVersion:requiredOS:error:");
                } else {
                    SPOOF_LOG(@"init: WARN _isMinimumOSVersion: not found");
                }
                
                Method m2 = class_getInstanceMethod(cls, @selector(isMinimumOSVersion:applicableToOSVersion:error:));
                if (m2) {
                    method_setImplementation(m2, (IMP)hook_isMinOS);
                    SPOOF_LOG(@"init: hooked isMinimumOSVersion:applicableToOSVersion:error:");
                } else {
                    SPOOF_LOG(@"init: WARN isMinimumOSVersion: not found");
                }
                
                Method m3 = class_getInstanceMethod(cls, @selector(isApplicableToCurrentOSVersionWithError:));
                if (m3) {
                    orig_isApplicable = (void *)method_getImplementation(m3);
                    method_setImplementation(m3, (IMP)hook_isApplicable);
                    SPOOF_LOG(@"init: hooked isApplicableToCurrentOSVersionWithError:");
                } else {
                    SPOOF_LOG(@"init: WARN isApplicableToCurrentOSVersionWithError: not found");
                }
            } else {
                SPOOF_LOG(@"init: ERROR MIBundle class not found");
            }
        }
        
        SPOOF_LOG(@"init complete");
    }
}

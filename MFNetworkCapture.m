// MFNetworkCapture.m — MinisFix v5.0 网络捕获 + 拦截修改
// 自研轻量版：NSURLProtocol + NSURLSession delegate hook
// 能力：捕获请求/响应（URL/method/headers/body/status/响应body）+ 规则替换（body/header/URL/block）

#import "MFPanel.h"
#import <objc/runtime.h>

// ====== 捕获记录模型（@interface 在 MFPanel.h 共享） ======
@implementation MFNetRecord
@end

// ====== 全局捕获存储 ======
static NSMutableArray *g_capturedRecords = nil;
BOOL g_captureEnabled = NO;
BOOL g_rewriteEnabled = NO;
NSMutableArray *g_rewriteRules = nil;
#define MF_MAX_RECORDS 200

// ====== 拦截规则模型（@interface 在 MFPanel.h 共享） ======
@implementation MFRewriteRule
- (NSDictionary *)toDict {
    return @{
        @"pattern": self.pattern ?: @"",
        @"matchType": self.matchType ?: @"contain",
        @"action": self.action ?: @"replaceResp",
        @"urlReplace": self.urlReplace ?: @"",
        @"bodyReplace": self.bodyReplace ?: @"",
        @"headerReplaces": self.headerReplaces ?: @{},
        @"enabled": @(self.enabled),
        @"appBundle": self.appBundle ?: @"",
    };
}
+ (instancetype)fromDict:(NSDictionary *)d {
    MFRewriteRule *r = [MFRewriteRule new];
    r.pattern = d[@"pattern"];
    r.matchType = d[@"matchType"];
    r.action = d[@"action"];
    r.urlReplace = d[@"urlReplace"];
    r.bodyReplace = d[@"bodyReplace"];
    r.headerReplaces = d[@"headerReplaces"];
    r.enabled = [d[@"enabled"] boolValue];
    r.appBundle = d[@"appBundle"];
    return r;
}
@end

// 当前 app bundle id（规则隔离用）
NSString *mfCurrentBundleId(void) {
    return [[NSBundle mainBundle] bundleIdentifier] ?: @"";
}

// ====== 规则匹配 ======
static BOOL mfRuleMatchesURL(MFRewriteRule *rule, NSString *url) {
    if (!rule.enabled || rule.pattern.length == 0) return NO;
    // 规则隔离：带 appBundle 的规则只对创建它的 app 生效
    if (rule.appBundle.length > 0 && ![rule.appBundle isEqualToString:mfCurrentBundleId()]) return NO;
    NSString *pat = rule.pattern;
    if ([rule.matchType isEqualToString:@"url"]) {
        return [url isEqualToString:pat];
    } else if ([rule.matchType isEqualToString:@"regex"]) {
        NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pat options:0 error:nil];
        return [re firstMatchInString:url options:0 range:NSMakeRange(0, url.length)] != nil;
    } else {  // contain
        return [url containsString:pat];
    }
}

static void mfLoadRules(void) {
    if (g_rewriteRules) return;
    g_rewriteRules = [NSMutableArray new];
    NSArray *arr = mfPrefsDict()[@"mfRewriteRules"];
    for (NSDictionary *d in arr) {
        [g_rewriteRules addObject:[MFRewriteRule fromDict:d]];
    }
}

static void mfSaveRules(void) {
    NSMutableDictionary *d = [mfPrefsDict() mutableCopy];
    NSMutableArray *arr = [NSMutableArray new];
    for (MFRewriteRule *r in g_rewriteRules) [arr addObject:[r toDict]];
    d[@"mfRewriteRules"] = arr;
    [d writeToFile:@"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist" atomically:YES];
}

// 保存规则：index<0 追加，否则替换 index 处
void mfSaveRule(MFRewriteRule *rule, NSInteger index) {
    mfLoadRules();
    if (index >= 0 && index < (NSInteger)g_rewriteRules.count) {
        [g_rewriteRules replaceObjectAtIndex:index withObject:rule];
        mfLog(@"rule updated: %@ %@ %@", rule.pattern, rule.matchType, rule.action);
    } else {
        [g_rewriteRules addObject:rule];
        mfLog(@"rule added: %@ %@ %@", rule.pattern, rule.matchType, rule.action);
    }
    mfSaveRules();
}

// 删除规则
void mfRemoveRule(NSInteger index) {
    mfLoadRules();
    if (index >= 0 && index < (NSInteger)g_rewriteRules.count) {
        [g_rewriteRules removeObjectAtIndex:index];
        mfSaveRules();
        mfLog(@"rule removed at %ld", (long)index);
    }
}

// MFPanel.m 调用的接口——添加规则（带当前 app 隔离）
void mfAddRule(NSString *pattern, NSString *matchType, NSString *action) {
    MFRewriteRule *r = [MFRewriteRule new];
    r.pattern = pattern; r.matchType = matchType; r.action = action; r.enabled = YES;
    r.appBundle = mfCurrentBundleId();
    mfSaveRule(r, -1);
}

// 网络分析模块（MFNetAnalyzer.m）读捕获缓冲的只读快照
NSArray *mfCapturedRecordsSnapshot(void) {
    @synchronized (g_capturedRecords) {
        return g_capturedRecords ? [g_capturedRecords copy] : @[];
    }
}

// ====== 记录捕获 ======
static void mfRecordCapture(MFNetRecord *rec) {
    if (!g_captureEnabled) return;
    @synchronized (g_capturedRecords) {
        if (!g_capturedRecords) g_capturedRecords = [NSMutableArray new];
        if (g_capturedRecords.count >= MF_MAX_RECORDS) {
            [g_capturedRecords removeObjectAtIndex:0];
        }
        // 生成简要摘要
        NSString *bodyStr = nil;
        if (rec.respBody.length > 0) {
            bodyStr = [[NSString alloc] initWithData:rec.respBody encoding:NSUTF8StringEncoding];
            if (!bodyStr) bodyStr = [rec.respBody description];
            if (bodyStr.length > 200) bodyStr = [bodyStr substringToIndex:200];
        }
        rec.summary = [NSString stringWithFormat:@"%@ %ld %@",
            rec.method, (long)rec.status, bodyStr ?: @""];
        [g_capturedRecords addObject:rec];
    }
}

// ====== NSURLProtocol 拦截 ======
@interface MFURLProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (strong) NSURLSession *session;
@property (strong) NSMutableData *data;
@property (strong) MFNetRecord *record;
@property (strong) NSURLResponse *response;
@property (strong) NSData *replaceBody;   // replaceResp 预构建的替换 body
@property BOOL replacingBody;             // 是否正在替换 body（原始数据不转发）
@end

@implementation MFURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"MFHandled" inRequest:request]) return NO;
    NSString *scheme = request.URL.scheme.lowercaseString;
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"]) return NO;
    // WebSocket upgrade 请求不拦截——NSURLProtocol 无法正确转发 101 Switching Protocols，
    // 会导致上层 NSURLSessionWebSocketTask 状态错乱甚至崩溃（openminis 闪退根因之一）
    NSString *upgrade = request.allHTTPHeaderFields[@"Upgrade"];
    if ([upgrade.lowercaseString containsString:@"websocket"]) return NO;
    return YES;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

+ (BOOL)requestIsCacheEquivalent:(NSURLRequest *)a toRequest:(NSURLRequest *)b {
    return [[super class] requestIsCacheEquivalent:a toRequest:b];
}

- (void)startLoading {
    NSMutableURLRequest *req = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"MFHandled" inRequest:req];
    
    self.record = [MFNetRecord new];
    self.record.url = req.URL.absoluteString;
    self.record.method = req.HTTPMethod;
    self.record.reqHeaders = req.allHTTPHeaderFields;
    self.record.reqBody = req.HTTPBody;
    self.record.timestamp = [NSDate date];
    
    // 应用请求拦截规则
    mfLoadRules();
    if (g_rewriteEnabled) {
        for (MFRewriteRule *rule in g_rewriteRules) {
            if (!mfRuleMatchesURL(rule, self.record.url)) continue;
            if ([rule.action isEqualToString:@"block"]) {
                // block: 返回空响应
                NSURLResponse *resp = [[NSURLResponse alloc] initWithURL:req.URL MIMEType:nil expectedContentLength:0 textEncodingName:nil];
                [self.client URLProtocol:self didReceiveResponse:resp cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                self.record.status = 0;
                self.record.summary = @"BLOCKED";
                mfRecordCapture(self.record);
                return;
            }
            if ([rule.action isEqualToString:@"replaceReq"]) {
                // 替换 URL
                if (rule.urlReplace.length > 0) {
                    NSURL *newURL = [NSURL URLWithString:rule.urlReplace];
                    if (newURL) [req setURL:newURL];
                }
                // 替换 body
                if (rule.bodyReplace.length > 0) {
                    [req setHTTPBody:[rule.bodyReplace dataUsingEncoding:NSUTF8StringEncoding]];
                }
                // 替换 headers
                for (NSString *key in rule.headerReplaces) {
                    [req setValue:rule.headerReplaces[key] forHTTPHeaderField:key];
                }
            }
        }
    }
    
    // JS onRequestHeaders 钩子（规则脚本改请求 headers）
    NSDictionary *jsHeaders = mfJSRunRequestHeaders(req.HTTPMethod, req.URL.absoluteString, req.allHTTPHeaderFields);
    if (jsHeaders) {
        [req setAllHTTPHeaderFields:jsHeaders];
        self.record.reqHeaders = jsHeaders;
        mfLog(@"JS: request headers rewritten (%lu headers)", (unsigned long)jsHeaders.count);
    }

    // 转发请求
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    self.session = [NSURLSession sessionWithConfiguration:cfg delegate:self delegateQueue:nil];
    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:req];
    [task resume];
}

- (void)stopLoading {
    [self.session invalidateAndCancel];
}

#pragma mark NSURLSessionDataDelegate

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveResponse:(NSURLResponse *)response
    completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    self.response = response;
    if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
        self.record.status = httpResp.statusCode;
        self.record.respHeaders = httpResp.allHeaderFields;
        self.record.mimeType = httpResp.MIMEType;

        // JS onResponseHeaders 钩子（规则脚本改响应 headers）
        NSDictionary *jsRespHeaders = mfJSRunResponseHeaders(httpResp.statusCode, httpResp.URL.absoluteString, httpResp.allHeaderFields);
        NSHTTPURLResponse *outResp = httpResp;
        NSDictionary *outHeaders = httpResp.allHeaderFields;
        if (jsRespHeaders) {
            outHeaders = jsRespHeaders;
            outResp = [[NSHTTPURLResponse alloc] initWithURL:httpResp.URL
                                                   statusCode:httpResp.statusCode
                                                  HTTPVersion:@"HTTP/1.1"
                                                 headerFields:jsRespHeaders];
            mfLog(@"JS: response headers rewritten");
        }

        // replaceResp 规则——在响应阶段预构建替换 body
        // （不能在 didCompleteWithError 里再次 didReceiveResponse——NSURLProtocolClient
        //   每 task 只允许一次 response，重复调用触发 NSInternalInconsistencyException 崩溃）
        NSData *replBody = nil;
        if (g_rewriteEnabled) {
            mfLoadRules();
            for (MFRewriteRule *rule in g_rewriteRules) {
                if (!mfRuleMatchesURL(rule, self.record.url)) continue;
                if ([rule.action isEqualToString:@"replaceResp"] && rule.bodyReplace.length > 0) {
                    replBody = [rule.bodyReplace dataUsingEncoding:NSUTF8StringEncoding];
                    break;
                }
            }
        }
        if (replBody) {
            NSMutableDictionary *hdrs = [outHeaders mutableCopy];
            hdrs[@"Content-Length"] = [NSString stringWithFormat:@"%lu", (unsigned long)replBody.length];
            outResp = [[NSHTTPURLResponse alloc] initWithURL:httpResp.URL
                                                   statusCode:httpResp.statusCode
                                                  HTTPVersion:@"HTTP/1.1"
                                                 headerFields:hdrs];
            self.replaceBody = replBody;
            self.replacingBody = YES;
            self.record.respHeaders = hdrs;
            mfLog(@"replaceResp: body replaced (%lu bytes)", (unsigned long)replBody.length);
        }

        [self.client URLProtocol:self didReceiveResponse:outResp cacheStoragePolicy:NSURLCacheStorageNotAllowed];
        self.data = [NSMutableData new];
        completionHandler(NSURLSessionResponseAllow);
        return;
    }
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    self.data = [NSMutableData new];
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    if (self.replacingBody) return;  // 原始 body 不转发（已被规则替换）
    [self.data appendData:data];
    [self.client URLProtocol:self didLoadData:data];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) {
        [self.client URLProtocol:self didFailWithError:error];
        self.record.status = -1;
        self.record.summary = [NSString stringWithFormat:@"ERROR: %@", error.localizedDescription];
    } else {
        if (self.replacingBody && self.replaceBody) {
            // 发送替换后的 body（正常路径数据已在 didReceiveData 转发，此处只发替换 body）
            self.record.respBody = self.replaceBody;
            [self.client URLProtocol:self didLoadData:self.replaceBody];
        } else {
            self.record.respBody = self.data;
        }
        [self.client URLProtocolDidFinishLoading:self];
    }
    mfRecordCapture(self.record);
}

@end

// ====== WebSocket 捕获（参考 FLEX injectWebsocketSendMessage/ReceiveMessage） ======
@interface MFWebSocketRecord : NSObject
@property (copy) NSString *url;
@property (copy) NSString *direction;  // send / receive
@property (copy) NSString *type;       // text / data
@property (copy) NSString *content;
@property (strong) NSDate *timestamp;
@end
@implementation MFWebSocketRecord
@end

static NSMutableArray *g_wsRecords = nil;

static void mfRecordWebSocket(NSString *url, NSString *direction, NSObject *message) {
    if (!g_captureEnabled) return;
    if (!g_wsRecords) g_wsRecords = [NSMutableArray new];
    MFWebSocketRecord *rec = [MFWebSocketRecord new];
    rec.url = url;
    rec.direction = direction;
    rec.timestamp = [NSDate date];
    if ([message isKindOfClass:[NSString class]]) {
        rec.type = @"text";
        rec.content = (NSString *)message;
    } else if ([message isKindOfClass:[NSData class]]) {
        rec.type = @"data";
        rec.content = [[NSString alloc] initWithData:(NSData *)message encoding:NSUTF8StringEncoding] ?: @"<binary>";
    } else {
        // NSURLSessionWebSocketMessage——动态取
        @try {
            SEL sel = NSSelectorFromString(@"string");
            if ([message respondsToSelector:sel]) {
                NSString *s = [message performSelector:sel];
                if ([s isKindOfClass:[NSString class]]) { rec.type = @"text"; rec.content = s; }
            }
            sel = NSSelectorFromString(@"data");
            if (!rec.content && [message respondsToSelector:sel]) {
                NSData *d = [message performSelector:sel];
                if ([d isKindOfClass:[NSData class]]) {
                    rec.type = @"data";
                    rec.content = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] ?: @"<binary>";
                }
            }
        } @catch (NSException *e) {
            rec.content = [message description];
        }
    }
    if (rec.content.length > 2000) rec.content = [rec.content substringToIndex:2000];
    @synchronized (g_wsRecords) {
        [g_wsRecords addObject:rec];
        if (g_wsRecords.count > 200) [g_wsRecords removeObjectAtIndex:0];
    }
    mfLog(@"WS %@ %@ (%@): %@", direction, url, rec.type, rec.content.length > 100 ? [rec.content substringToIndex:100] : rec.content);
}

// hook NSURLSessionWebSocketTask——sendMessage/receiveMessage
static IMP orig_ws_sendMessage;
static void new_ws_sendMessage(id self, SEL _cmd, id message, id completion) {
    NSString *url = [[[self performSelector:NSSelectorFromString(@"originalRequest")] URL] absoluteString] ?: @"?";
    mfRecordWebSocket(url, @"send", message);
    ((void(*)(id, SEL, id, id))orig_ws_sendMessage)(self, _cmd, message, completion);
}
static IMP orig_ws_receiveMessage;
static void new_ws_receiveMessage(id self, SEL _cmd, id completion) {
    NSString *url = [[[self performSelector:NSSelectorFromString(@"originalRequest")] URL] absoluteString] ?: @"?";
    id wrappedCompletion = ^(id message, id error) {
        if (message) mfRecordWebSocket(url, @"recv", message);
        if (completion) {
            void (^origBlock)(id, id) = completion;
            origBlock(message, error);
        }
    };
    ((void(*)(id, SEL, id))orig_ws_receiveMessage)(self, _cmd, wrappedCompletion);
}

static void mfInstallWebSocketHooks(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Class wsTask = NSClassFromString(@"NSURLSessionWebSocketTask");
        if (!wsTask) { mfLog(@"WS hooks: NSURLSessionWebSocketTask not found (iOS < 15)"); return; }
        Method m = class_getInstanceMethod(wsTask, NSSelectorFromString(@"sendMessage:completionHandler:"));
        if (m) { orig_ws_sendMessage = method_getImplementation(m); method_setImplementation(m, (IMP)new_ws_sendMessage); }
        m = class_getInstanceMethod(wsTask, NSSelectorFromString(@"receiveMessageWithCompletionHandler:"));
        if (m) { orig_ws_receiveMessage = method_getImplementation(m); method_setImplementation(m, (IMP)new_ws_receiveMessage); }
        mfLog(@"WS hooks installed (NSURLSessionWebSocketTask)");
    });
}

// ====== 注册/注销 NSURLProtocol ======
// swizzle NSURLSessionConfiguration.protocolClasses——所有新建 session 都带上 MFURLProtocol
static IMP orig_protocolClasses;
static NSArray *new_protocolClasses(id self, SEL _cmd) {
    NSArray *orig = ((NSArray *(*)(id, SEL))orig_protocolClasses)(self, _cmd);
    NSMutableArray *arr = [orig mutableCopy] ?: [NSMutableArray array];
    if (![arr containsObject:[MFURLProtocol class]]) {
        [arr insertObject:[MFURLProtocol class] atIndex:0];
    }
    return arr;
}

static void mfInstallNetworkCaptureOnce(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        [NSURLProtocol registerClass:[MFURLProtocol class]];
        // swizzle protocolClasses——拦截所有 NSURLSession
        Class cfgCls = NSClassFromString(@"NSURLSessionConfiguration");
        if (cfgCls) {
            Method m = class_getInstanceMethod(cfgCls, @selector(protocolClasses));
            if (m) {
                orig_protocolClasses = method_getImplementation(m);
                method_setImplementation(m, (IMP)new_protocolClasses);
                mfLog(@"NetworkCapture: protocolClasses swizzled");
            }
        }
        mfLog(@"NetworkCapture: NSURLProtocol registered");
    });
}

void mfInstallNetworkCapture(void) {
    mfInstallNetworkCaptureOnce();
    mfInstallWebSocketHooks();
}

// ====== 捕获列表页面（子页展示） ======
static void mfExpandCardForPage(void) {
    // 子页创建前先拉长卡片——让滚动视图等基于 g_mfCardH 的布局用大高度
    if (g_mfPanelOverlay) {
        CGFloat maxH = MIN(560, g_mfPanelOverlay.bounds.size.height - 100);
        if (g_mfCardH < maxH) mfSetCardHeight(maxH);
    }
}
static NSString *mfDisplayDict(NSDictionary *d) {
    if (!d || d.count == 0) return @"(空)";
    NSMutableString *s = [NSMutableString string];
    for (NSString *k in d) [s appendFormat:@"%@: %@\n", k, d[k]];
    return s;
}
static NSString *mfDisplayData(NSData *data) {
    if (!data || data.length == 0) return @"(空)";
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!s) return [NSString stringWithFormat:@"<二进制 %lu 字节>", (unsigned long)data.length];
    return s;
}

// 详情页——完整展示请求/响应 headers/body，可复制
void mfShowCaptureDetailPage(MFNetRecord *rec) {
    if (!rec) return;
    mfExpandCardForPage();
    UIView *page = mfMakePage(@"请求详情", YES);

    // 复制按钮（左上——远离右上角关闭 X，防误触）
    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    copyBtn.frame = CGRectMake(g_mfCardW - 136, 8, 56, 28);
    [copyBtn setTitle:@"复制" forState:UIControlStateNormal];
    copyBtn.titleLabel.font = [UIFont systemFontOfSize:13];
    objc_setAssociatedObject(copyBtn, "rec", rec, OBJC_ASSOCIATION_RETAIN);
    [copyBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCopyRecord:") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:copyBtn];

    // 改响应按钮——用当前记录 URL 预填规则（跳规则编辑页）
    UIButton *modBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    modBtn.frame = CGRectMake(g_mfCardW - 200, 8, 56, 28);
    [modBtn setTitle:@"改响应" forState:UIControlStateNormal];
    modBtn.titleLabel.font = [UIFont systemFontOfSize:13];
    modBtn.tintColor = [UIColor systemOrangeColor];
    objc_setAssociatedObject(modBtn, "rec", rec, OBJC_ASSOCIATION_RETAIN);
    [modBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfModifyResponse:") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:modBtn];

    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, g_mfCardH - 42)];
    CGFloat y = 8;

    // 概览
    NSString *summary = [NSString stringWithFormat:@"%@ %ld  %@",
        rec.method ?: @"?", (long)rec.status, rec.url ?: @"?"];
    UILabel *sumLb = [UILabel new];
    sumLb.font = [UIFont systemFontOfSize:12];
    sumLb.textColor = [UIColor labelColor];
    sumLb.numberOfLines = 0;
    sumLb.frame = CGRectMake(12, y, g_mfCardW - 24, 46);
    sumLb.text = summary;
    [sv addSubview:sumLb];
    y += 52;

    // Section
    NSArray *sectionTitles = @[@"请求 Headers", @"请求 Body", @"响应 Headers", @"响应 Body"];
    NSArray *sectionValues = @[
        mfDisplayDict(rec.reqHeaders),
        mfDisplayData(rec.reqBody),
        mfDisplayDict(rec.respHeaders),
        mfDisplayData(rec.respBody),
    ];
    for (NSUInteger i = 0; i < sectionTitles.count; i++) {
        UILabel *t = [UILabel new];
        t.font = [UIFont boldSystemFontOfSize:12];
        t.textColor = [UIColor systemBlueColor];
        t.frame = CGRectMake(12, y, g_mfCardW - 24, 22);
        t.text = sectionTitles[i];
        [sv addSubview:t];
        y += 24;

        UILabel *v = [UILabel new];
        v.font = [UIFont systemFontOfSize:11];
        v.textColor = [UIColor secondaryLabelColor];
        v.numberOfLines = 0;
        NSString *val = sectionValues[i];
        CGSize size = [val boundingRectWithSize:CGSizeMake(g_mfCardW - 24, CGFLOAT_MAX)
            options:NSStringDrawingUsesLineFragmentOrigin
            attributes:@{NSFontAttributeName: v.font} context:nil].size;
        v.frame = CGRectMake(12, y, g_mfCardW - 24, size.height + 4);
        v.text = val;
        [sv addSubview:v];
        y += size.height + 12;
    }

    sv.contentSize = CGSizeMake(g_mfCardW, y + 16);
    [page addSubview:sv];
    mfPushPage(page);
}

void mfShowNetworkCapturePage(void) {
    mfExpandCardForPage();
    UIView *page = mfMakePage(@"网络捕获", YES);
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, g_mfCardH - 42)];
    
    if (!g_capturedRecords || g_capturedRecords.count == 0) {
        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 60, g_mfCardW - 32, 40)];
        e.text = @"暂无捕获记录\n请先在数据分析页打开捕获开关";
        e.numberOfLines = 0;
        e.textAlignment = NSTextAlignmentCenter;
        e.font = [UIFont systemFontOfSize:13];
        e.textColor = [UIColor secondaryLabelColor];
        [sv addSubview:e];
    } else {
        CGFloat y = 8;
        @synchronized (g_capturedRecords) {
            for (MFNetRecord *rec in g_capturedRecords) {
                UIView *row = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 56)];
                row.backgroundColor = [UIColor secondarySystemBackgroundColor];
                row.layer.cornerRadius = 10;
                
                UILabel *url = [[UILabel alloc] initWithFrame:CGRectMake(10, 4, row.bounds.size.width - 20, 18)];
                url.font = [UIFont systemFontOfSize:11];
                url.textColor = [UIColor systemBlueColor];
                NSString *fullUrl = rec.url;
                if (fullUrl.length > 60) fullUrl = [fullUrl substringToIndex:60];
                url.text = fullUrl;
                [row addSubview:url];
                
                UILabel *info = [[UILabel alloc] initWithFrame:CGRectMake(10, 24, row.bounds.size.width - 20, 28)];
                info.font = [UIFont systemFontOfSize:10];
                info.textColor = [UIColor secondaryLabelColor];
                info.numberOfLines = 2;
                info.text = [NSString stringWithFormat:@"%@ %ld | %@", rec.method, (long)rec.status, rec.summary ?: @""];
                [row addSubview:info];
                
                [sv addSubview:row];
                // 点击行 → 详情页
                UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:g_mfCtrl action:NSSelectorFromString(@"mfShowCaptureDetail:")];
                objc_setAssociatedObject(tap, "rec", rec, OBJC_ASSOCIATION_RETAIN);
                [row addGestureRecognizer:tap];
                y += 62;
            }
        }
        sv.contentSize = CGSizeMake(g_mfCardW, y + 16);
    }
    [page addSubview:sv];
    mfPushPage(page);
}

// ====== 数据分析页（捕获开关 + 解密工具箱入口） ======
void mfShowDataAnalysisPage(void) {
    UIView *page = mfMakePage(@"数据分析", YES);
    CGFloat gw = (g_mfCardW - 32 - 12) / 2;
    CGFloat gy = 48;
    gy = mfGridButton(page, 16, gy, gw, @"网络捕获", @"📡", @selector(mfShowNetworkCapturePage), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"解密工具", @"🔐", @selector(mfShowCryptoPage), NO, nil);
    gy = mfGridButton(page, 16, gy, gw, @"ClassDump", @"📦", @selector(mfShowClassDumpPage), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"Keychain 管理", @"🔑", @selector(mfShowKeychainManagerPage), NO, nil);
    gy = mfGridButton(page, 16, gy, gw, @"安全扫描", @"🛡️", @selector(mfShowSecurityScanPage), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"MachO 深检", @"🔬", @selector(mfShowMachODeepPage), NO, nil);
    gy = mfGridButton(page, 16, gy, gw, @"网络分析", @"🌐", @selector(mfShowNetAnalyzerPage), NO, nil);
    // 捕获开关
    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(16, gy, 60, 31)];
    sw.on = g_captureEnabled;
    objc_setAssociatedObject(sw, "key", @"mfCaptureEnabled", OBJC_ASSOCIATION_RETAIN);
    [sw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCaptureSwitchChanged:") forControlEvents:UIControlEventValueChanged];
    [page addSubview:sw];
    UILabel *swLb = [[UILabel alloc] initWithFrame:CGRectMake(84, gy + 4, 160, 24)];
    swLb.text = @"实时捕获网络请求";
    swLb.font = [UIFont systemFontOfSize:14];
    swLb.textColor = [UIColor labelColor];
    [page addSubview:swLb];
    mfPushPage(page);
}

// ====== CryptoToolbox 页面 ======
void mfShowCryptoToolboxPage(void) {
    UIView *page = mfMakePage(@"解密工具", YES);
    // 输入框
    UITextView *input = [[UITextView alloc] initWithFrame:CGRectMake(12, 48, g_mfCardW - 24, 80)];
    input.font = [UIFont systemFontOfSize:13];
    input.backgroundColor = [UIColor secondarySystemBackgroundColor];
    input.layer.cornerRadius = 10;
    input.text = @"在此输入要解密的内容…";
    [page addSubview:input];
    objc_setAssociatedObject(page, "input", input, OBJC_ASSOCIATION_RETAIN);
    // 密钥
    UITextField *key = [[UITextField alloc] initWithFrame:CGRectMake(12, 136, g_mfCardW - 24, 36)];
    key.borderStyle = UITextBorderStyleRoundedRect;
    key.placeholder = @"密钥 (Key, Hex 或 Base64)";
    key.font = [UIFont systemFontOfSize:13];
    [page addSubview:key];
    objc_setAssociatedObject(page, "key", key, OBJC_ASSOCIATION_RETAIN);
    // IV
    UITextField *iv = [[UITextField alloc] initWithFrame:CGRectMake(12, 178, g_mfCardW - 24, 36)];
    iv.borderStyle = UITextBorderStyleRoundedRect;
    iv.placeholder = @"IV (可选, Hex 或 Base64)";
    iv.font = [UIFont systemFontOfSize:13];
    [page addSubview:iv];
    objc_setAssociatedObject(page, "iv", iv, OBJC_ASSOCIATION_RETAIN);
    // 算法选择
    UISegmentedControl *algo = [[UISegmentedControl alloc] initWithItems:@[@"AES-CBC", @"AES-ECB", @"Base64", @"Hex"]];
    algo.frame = CGRectMake(12, 222, g_mfCardW - 24, 32);
    algo.selectedSegmentIndex = 0;
    [page addSubview:algo];
    objc_setAssociatedObject(page, "algo", algo, OBJC_ASSOCIATION_RETAIN);
    // 加密/解密按钮
    UIButton *decBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    decBtn.frame = CGRectMake(12, 262, (g_mfCardW - 24 - 8) / 2, 38);
    decBtn.backgroundColor = [UIColor systemBlueColor];
    decBtn.layer.cornerRadius = 10;
    [decBtn setTitle:@"解密" forState:UIControlStateNormal];
    [decBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    objc_setAssociatedObject(decBtn, "mode", @(0), OBJC_ASSOCIATION_RETAIN);
    [decBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCryptoRun:") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:decBtn];
    
    UIButton *encBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    encBtn.frame = CGRectMake(12 + (g_mfCardW - 24 - 8) / 2 + 8, 262, (g_mfCardW - 24 - 8) / 2, 38);
    encBtn.backgroundColor = [UIColor systemGreenColor];
    encBtn.layer.cornerRadius = 10;
    [encBtn setTitle:@"加密" forState:UIControlStateNormal];
    [encBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    objc_setAssociatedObject(encBtn, "mode", @(1), OBJC_ASSOCIATION_RETAIN);
    [encBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCryptoRun:") forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:encBtn];
    // 输出
    UITextView *output = [[UITextView alloc] initWithFrame:CGRectMake(12, 308, g_mfCardW - 24, 80)];
    output.font = [UIFont systemFontOfSize:13];
    output.backgroundColor = [UIColor secondarySystemBackgroundColor];
    output.layer.cornerRadius = 10;
    output.editable = NO;
    [page addSubview:output];
    objc_setAssociatedObject(page, "output", output, OBJC_ASSOCIATION_RETAIN);
    mfPushPage(page);
}

// ====== 规则编辑页（新建/编辑共用） ======
// index<0 新建；>=0 编辑 g_rewriteRules[index]
static void mfShowRuleEditPageImpl(NSString *pattern, NSString *action, NSInteger index, BOOL fromList) {
    UIView *page = mfMakePage(index < 0 ? @"新建规则" : @"编辑规则", YES);
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, g_mfCardH - 42)];
    CGFloat y = 12;

    // 编辑模式预填
    MFRewriteRule *editRule = nil;
    if (index >= 0 && index < (NSInteger)g_rewriteRules.count) editRule = g_rewriteRules[index];
    NSString *initPattern = editRule.pattern ?: pattern ?: @"";
    NSString *initMatch = editRule.matchType ?: @"contain";
    NSString *initAction = editRule.action ?: (action ?: @"replaceResp");
    NSString *initUrlRepl = editRule.urlReplace ?: @"";
    NSString *initBody = editRule.bodyReplace ?: @"";

    // 匹配方式分段
    UILabel *mLabel = [UILabel new];
    mLabel.frame = CGRectMake(16, y, 100, 22);
    mLabel.text = @"匹配方式";
    mLabel.font = [UIFont systemFontOfSize:13];
    mLabel.textColor = [UIColor secondaryLabelColor];
    [sv addSubview:mLabel];
    UISegmentedControl *matchSeg = [[UISegmentedControl alloc] initWithItems:@[@"包含", @"精确", @"正则"]];
    matchSeg.frame = CGRectMake(16, y + 24, g_mfCardW - 32, 32);
    matchSeg.selectedSegmentIndex = [initMatch isEqualToString:@"url"] ? 1 : ([initMatch isEqualToString:@"regex"] ? 2 : 0);
    [sv addSubview:matchSeg];
    y += 64;

    // 匹配内容输入框
    UITextField *patField = [[UITextField alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 40)];
    patField.placeholder = @"匹配的 URL（含域名即可）";
    patField.text = initPattern;
    patField.font = [UIFont systemFontOfSize:13];
    patField.borderStyle = UITextBorderStyleRoundedRect;
    patField.clearButtonMode = UITextFieldViewModeWhileEditing;
    patField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    patField.autocorrectionType = UITextAutocorrectionTypeNo;
    patField.keyboardType = UIKeyboardTypeURL;
    [sv addSubview:patField];
    y += 48;

    // 动作分段
    UILabel *aLabel = [UILabel new];
    aLabel.frame = CGRectMake(16, y, 100, 22);
    aLabel.text = @"动作";
    aLabel.font = [UIFont systemFontOfSize:13];
    aLabel.textColor = [UIColor secondaryLabelColor];
    [sv addSubview:aLabel];
    UISegmentedControl *actSeg = [[UISegmentedControl alloc] initWithItems:@[@"替换响应", @"替换请求", @"屏蔽"]];
    actSeg.frame = CGRectMake(16, y + 24, g_mfCardW - 32, 32);
    actSeg.selectedSegmentIndex = [initAction isEqualToString:@"replaceReq"] ? 1 : ([initAction isEqualToString:@"block"] ? 2 : 0);
    [sv addSubview:actSeg];
    y += 64;

    // 替换 URL（replaceReq 用）
    UITextField *urlField = [[UITextField alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 40)];
    urlField.placeholder = @"替换为的 URL（替换请求时用）";
    urlField.text = initUrlRepl;
    urlField.font = [UIFont systemFontOfSize:13];
    urlField.borderStyle = UITextBorderStyleRoundedRect;
    urlField.clearButtonMode = UITextFieldViewModeWhileEditing;
    urlField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    urlField.keyboardType = UIKeyboardTypeURL;
    [sv addSubview:urlField];
    y += 48;

    // 替换 Body（replaceResp 用，多行）
    UILabel *bLabel = [UILabel new];
    bLabel.frame = CGRectMake(16, y, 200, 22);
    bLabel.text = @"替换响应 Body";
    bLabel.font = [UIFont systemFontOfSize:13];
    bLabel.textColor = [UIColor secondaryLabelColor];
    [sv addSubview:bLabel];
    y += 26;
    UITextView *bodyView = [[UITextView alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 120)];
    bodyView.text = initBody;
    bodyView.font = [UIFont systemFontOfSize:12];
    bodyView.layer.cornerRadius = 8;
    bodyView.layer.borderWidth = 0.5;
    bodyView.layer.borderColor = [UIColor systemGray3Color].CGColor;
    bodyView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    [sv addSubview:bodyView];
    y += 128;

    // 保存按钮
    UIButton *saveBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    saveBtn.frame = CGRectMake(16, y + 4, g_mfCardW - 32, 40);
    saveBtn.backgroundColor = [UIColor systemBlueColor];
    saveBtn.layer.cornerRadius = 10;
    [saveBtn setTitle:@"保存规则" forState:UIControlStateNormal];
    [saveBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [saveBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfSaveRuleTapped:") forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:saveBtn];
    y += 56;

    sv.contentSize = CGSizeMake(g_mfCardW, y + 20);
    [page addSubview:sv];

    // 保存按钮回调所需上下文（segments 引用 + index + 来源标记）
    objc_setAssociatedObject(saveBtn, "seg", matchSeg, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "seg2", actSeg, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "f1", patField, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "f2", urlField, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "tv", bodyView, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "idx", @(index), OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(saveBtn, "fromList", @(fromList), OBJC_ASSOCIATION_RETAIN);

    mfPushPage(page);
}

// 对外入口：详情页"改响应"→ 预填当前记录 URL（fromList=NO，保存后回详情）；
// 列表页添加/编辑（fromList=YES，保存后刷新列表）
void mfShowRuleEditPage(NSString *pattern, NSString *action, NSInteger index, BOOL fromList) {
    mfLoadRules();
    mfShowRuleEditPageImpl(pattern, action, index, fromList);
}

// ====== 网络修改页（当前 app 的规则列表 + 开关） ======
void mfShowNetworkModifyPage(void) {
    UIView *page = mfMakePage(@"网络修改", YES);
    mfLoadRules();
    // 开关
    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(16, 48, 60, 31)];
    sw.on = g_rewriteEnabled;
    [sw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfRewriteSwitchChanged:") forControlEvents:UIControlEventValueChanged];
    [page addSubview:sw];
    UILabel *swLb = [[UILabel alloc] initWithFrame:CGRectMake(84, 52, 220, 24)];
    swLb.text = @"启用拦截修改";
    swLb.font = [UIFont systemFontOfSize:14];
    [page addSubview:swLb];
    UILabel *scopeLb = [[UILabel alloc] initWithFrame:CGRectMake(84, 74, g_mfCardW - 100, 16)];
    scopeLb.text = [NSString stringWithFormat:@"仅作用于：%@", mfCurrentBundleId()];
    scopeLb.font = [UIFont systemFontOfSize:10];
    scopeLb.textColor = [UIColor tertiaryLabelColor];
    [page addSubview:scopeLb];

    // 规则列表（只显示当前 app 的规则）
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 96, g_mfCardW, g_mfCardH - 96)];
    CGFloat y = 8;
    NSMutableArray *myRules = [NSMutableArray new];
    for (MFRewriteRule *r in g_rewriteRules) {
        if (r.appBundle.length == 0 || [r.appBundle isEqualToString:mfCurrentBundleId()]) [myRules addObject:r];
    }
    if (myRules.count == 0) {
        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 20, g_mfCardW - 32, 40)];
        e.text = @"暂无规则\n可在捕获详情页点「改响应」快速添加";
        e.numberOfLines = 0;
        e.textAlignment = NSTextAlignmentCenter;
        e.textColor = [UIColor secondaryLabelColor];
        e.font = [UIFont systemFontOfSize:13];
        [sv addSubview:e];
    } else {
        for (MFRewriteRule *rule in myRules) {
            NSInteger idx = [g_rewriteRules indexOfObject:rule];
            UIView *row = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 62)];
            row.backgroundColor = [UIColor secondarySystemBackgroundColor];
            row.layer.cornerRadius = 10;
            CGFloat rightX = row.bounds.size.width - 8;
            // 左侧：pattern + 信息
            UILabel *pat = [[UILabel alloc] initWithFrame:CGRectMake(10, 6, rightX - 110, 20)];
            pat.font = [UIFont systemFontOfSize:11];
            pat.textColor = rule.enabled ? [UIColor systemBlueColor] : [UIColor secondaryLabelColor];
            pat.text = rule.pattern;
            [row addSubview:pat];
            UILabel *act = [[UILabel alloc] initWithFrame:CGRectMake(10, 28, rightX - 110, 30)];
            act.font = [UIFont systemFontOfSize:10];
            act.textColor = [UIColor secondaryLabelColor];
            act.numberOfLines = 2;
            NSString *actName = [rule.action isEqualToString:@"block"] ? @"屏蔽" :
                ([rule.action isEqualToString:@"replaceReq"] ? @"替换请求" : @"替换响应");
            act.text = [NSString stringWithFormat:@"%@ | %@", rule.matchType, actName];
            [row addSubview:act];
            // 右侧：开关（上）+ 编辑/删除（下）
            UISwitch *rsw = [[UISwitch alloc] initWithFrame:CGRectMake(rightX - 51, 4, 51, 31)];
            rsw.on = rule.enabled;
            objc_setAssociatedObject(rsw, "idx", @(idx), OBJC_ASSOCIATION_RETAIN);
            [rsw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfRuleSwitchChanged:") forControlEvents:UIControlEventValueChanged];
            [row addSubview:rsw];
            UIButton *editBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            editBtn.frame = CGRectMake(rightX - 80, 38, 36, 20);
            [editBtn setTitle:@"编辑" forState:UIControlStateNormal];
            editBtn.titleLabel.font = [UIFont systemFontOfSize:11];
            objc_setAssociatedObject(editBtn, "idx", @(idx), OBJC_ASSOCIATION_RETAIN);
            [editBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfEditRuleTapped:") forControlEvents:UIControlEventTouchUpInside];
            [row addSubview:editBtn];
            UIButton *delBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            delBtn.frame = CGRectMake(rightX - 40, 38, 32, 20);
            [delBtn setTitle:@"删除" forState:UIControlStateNormal];
            delBtn.titleLabel.font = [UIFont systemFontOfSize:11];
            [delBtn setTitleColor:[UIColor systemRedColor] forState:UIControlStateNormal];
            objc_setAssociatedObject(delBtn, "idx", @(idx), OBJC_ASSOCIATION_RETAIN);
            [delBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfDeleteRuleTapped:") forControlEvents:UIControlEventTouchUpInside];
            [row addSubview:delBtn];
            [sv addSubview:row];
            y += 68;
        }
    }
    // 添加规则按钮
    UIButton *addBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    addBtn.frame = CGRectMake(12, y + 4, g_mfCardW - 24, 38);
    addBtn.backgroundColor = [UIColor systemBlueColor];
    addBtn.layer.cornerRadius = 10;
    [addBtn setTitle:@"+ 添加规则" forState:UIControlStateNormal];
    [addBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [addBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfAddRuleTapped") forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:addBtn];
    y += 46;
    sv.contentSize = CGSizeMake(g_mfCardW, y + 16);
    [page addSubview:sv];
    mfPushPage(page);
}

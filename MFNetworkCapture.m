// MFNetworkCapture.m — MinisFix v5.0 网络捕获 + 拦截修改
// 自研轻量版：NSURLProtocol + NSURLSession delegate hook
// 能力：捕获请求/响应（URL/method/headers/body/status/响应body）+ 规则替换（body/header/URL/block）

#import "MFPanel.h"

// ====== 捕获记录模型 ======
@interface MFNetRecord : NSObject
@property (copy) NSString *url;
@property (copy) NSString *method;
@property (copy) NSDictionary *reqHeaders;
@property (copy) NSData *reqBody;
@property (copy) NSDictionary *respHeaders;
@property (copy) NSData *respBody;
@property NSInteger status;
@property (copy) NSString *mimeType;
@property (strong) NSDate *timestamp;
@property (copy) NSString *summary;  // 简要描述
@end
@implementation MFNetRecord
@end

// ====== 全局捕获存储 ======
static NSMutableArray *g_capturedRecords = nil;
BOOL g_captureEnabled = NO;
BOOL g_rewriteEnabled = NO;
NSMutableArray *g_rewriteRules = nil;
#define MF_MAX_RECORDS 200

// ====== 拦截规则模型 ======
// 规则 JSON: {pattern, matchType(url/regex/contain), action(capture/block/replaceReq/replaceResp), urlReplace, bodyReplace, headerReplaces, enabled}
@interface MFRewriteRule : NSObject
@property (copy) NSString *pattern;
@property (copy) NSString *matchType;    // url / regex / contain
@property (copy) NSString *action;       // block / replaceReq / replaceResp
@property (copy) NSString *urlReplace;
@property (copy) NSString *bodyReplace;
@property (copy) NSDictionary *headerReplaces;
@property BOOL enabled;
- (NSDictionary *)toDict;
+ (instancetype)fromDict:(NSDictionary *)d;
@end
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
    return r;
}
@end

// ====== 规则匹配 ======
static BOOL mfRuleMatchesURL(MFRewriteRule *rule, NSString *url) {
    if (!rule.enabled || rule.pattern.length == 0) return NO;
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

// MFPanel.m 调用的接口——添加规则
void mfAddRule(NSString *pattern, NSString *matchType, NSString *action) {
    mfLoadRules();
    MFRewriteRule *r = [MFRewriteRule new];
    r.pattern = pattern; r.matchType = matchType; r.action = action; r.enabled = YES;
    [g_rewriteRules addObject:r];
    mfSaveRules();
    mfLog(@"rule added: %@ %@ %@", pattern, matchType, action);
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
@end

@implementation MFURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"MFHandled" inRequest:request]) return NO;
    NSString *scheme = request.URL.scheme.lowercaseString;
    return [scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"];
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
    }
    self.data = [NSMutableData new];
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.data appendData:data];
    [self.client URLProtocol:self didLoadData:data];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) {
        [self.client URLProtocol:self didFailWithError:error];
        self.record.status = -1;
        self.record.summary = [NSString stringWithFormat:@"ERROR: %@", error.localizedDescription];
    } else {
        // 应用响应拦截规则
        self.record.respBody = self.data;
        if (g_rewriteEnabled) {
            for (MFRewriteRule *rule in g_rewriteRules) {
                if (!mfRuleMatchesURL(rule, self.record.url)) continue;
                if ([rule.action isEqualToString:@"replaceResp"]) {
                    // 替换响应 body
                    if (rule.bodyReplace.length > 0) {
                        NSData *newBody = [rule.bodyReplace dataUsingEncoding:NSUTF8StringEncoding];
                        self.record.respBody = newBody;
                        // 重新构建响应
                        NSHTTPURLResponse *orig = (NSHTTPURLResponse *)self.response;
                        NSMutableDictionary *hdrs = [orig.allHeaderFields mutableCopy];
                        hdrs[@"Content-Length"] = [NSString stringWithFormat:@"%lu", (unsigned long)newBody.length];
                        NSHTTPURLResponse *newResp = [[NSHTTPURLResponse alloc] initWithURL:orig.URL statusCode:orig.statusCode HTTPVersion:nil headerFields:hdrs];
                        [self.client URLProtocol:self didReceiveResponse:newResp cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                        [self.client URLProtocol:self didLoadData:newBody];
                    }
                }
            }
        }
        [self.client URLProtocolDidFinishLoading:self];
    }
    mfRecordCapture(self.record);
}

@end

// ====== 注册/注销 NSURLProtocol ======
static void mfInstallNetworkCapture(void) {
    [NSURLProtocol registerClass:[MFURLProtocol class]];
    // 也注册到 NSURLSession defaultSessionConfiguration（需要 swizzle）
    mfLog(@"NetworkCapture: NSURLProtocol registered");
}

// ====== 捕获列表页面（子页展示） ======
void mfShowNetworkCapturePage(void) {
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
    gy = mfGridButton(page, 16, gy, gw, @"网络捕获", @"📡", @selector(mfShowNetCapturePage), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"解密工具", @"🔐", @selector(mfShowCryptoPage), NO, nil);
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

// ====== 网络修改页（规则列表 + 开关） ======
void mfShowNetworkModifyPage(void) {
    UIView *page = mfMakePage(@"网络修改", YES);
    mfLoadRules();
    // 开关
    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(16, 48, 60, 31)];
    sw.on = g_rewriteEnabled;
    [sw addTarget:g_mfCtrl action:NSSelectorFromString(@"mfRewriteSwitchChanged:") forControlEvents:UIControlEventValueChanged];
    [page addSubview:sw];
    UILabel *swLb = [[UILabel alloc] initWithFrame:CGRectMake(84, 52, 200, 24)];
    swLb.text = @"启用拦截修改";
    swLb.font = [UIFont systemFontOfSize:14];
    [page addSubview:swLb];
    // 规则列表
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 90, g_mfCardW, g_mfCardH - 90)];
    CGFloat y = 8;
    if (g_rewriteRules.count == 0) {
        UILabel *e = [[UILabel alloc] initWithFrame:CGRectMake(16, 20, g_mfCardW - 32, 40)];
        e.text = @"暂无规则，点击下方添加";
        e.textAlignment = NSTextAlignmentCenter;
        e.textColor = [UIColor secondaryLabelColor];
        [sv addSubview:e];
    } else {
        for (NSUInteger i = 0; i < g_rewriteRules.count; i++) {
            MFRewriteRule *rule = g_rewriteRules[i];
            UIView *row = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 50)];
            row.backgroundColor = [UIColor secondarySystemBackgroundColor];
            row.layer.cornerRadius = 10;
            UILabel *pat = [[UILabel alloc] initWithFrame:CGRectMake(10, 4, row.bounds.size.width - 20, 20)];
            pat.font = [UIFont systemFontOfSize:11];
            pat.textColor = rule.enabled ? [UIColor systemBlueColor] : [UIColor secondaryLabelColor];
            pat.text = rule.pattern;
            [row addSubview:pat];
            UILabel *act = [[UILabel alloc] initWithFrame:CGRectMake(10, 26, row.bounds.size.width - 20, 18)];
            act.font = [UIFont systemFontOfSize:10];
            act.textColor = [UIColor secondaryLabelColor];
            act.text = [NSString stringWithFormat:@"%@ | %@", rule.matchType, rule.action];
            [row addSubview:act];
            [sv addSubview:row];
            y += 56;
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

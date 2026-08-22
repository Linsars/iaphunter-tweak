// MFNetAnalyzer.m — T0 金矿开采第二波 (v1.7.0)
// 对标 ToolsEric UCPTNetworkAnalyzerVC (60 方法)，实现全部自研
// 独立七扫：接口/TCP/DNS/Cookie/证书/VPN/SSID
// 捕获关联：HTTP 记录摘要 + cURL 导出（复用 MFNetworkCapture 的 g_capturedRecords）
// WebSocket/gRPC 不做：NSURLProtocol 无法拦截 WS upgrade（101），HTTP/2 gRPC 同理——报告页说明

#import "MFPanel.h"
#import <SystemConfiguration/SystemConfiguration.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <Security/Security.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/sysctl.h>
#include <resolv.h>

NSString *mfNetScanHTTP(void);
NSString *mfNetScanCurl(void);

#pragma mark - 接口列表（对标 scanInterfaces）

NSString *mfNetScanInterfaces(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【网络接口】\n"];
    struct ifaddrs *ifs = NULL, *ifa;
    if (getifaddrs(&ifs) != 0) return @"⚠️ getifaddrs 失败";
    NSString *last = nil;
    for (ifa = ifs; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        NSString *name = [NSString stringWithUTF8String:ifa->ifa_name];
        if ([name isEqualToString:last]) continue; // 每个 interface 多族重复，只报首个地址
        last = name;
        char ip[64] = "?";
        if (ifa->ifa_addr->sa_family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ip, sizeof(ip));
        else if (ifa->ifa_addr->sa_family == AF_INET6)
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, ip, sizeof(ip));
        else continue;
        BOOL up = (ifa->ifa_flags & IFF_UP) != 0;
        BOOL vpnLike = [name hasPrefix:@"utun"] || [name hasPrefix:@"ipsec"] || [name hasPrefix:@"tap"] || [name hasPrefix:@"ppp"];
        [r appendFormat:@"  %@ %@  %@%@%@\n",
            up ? @"🟢" : @"⚪️", name, ip,
            vpnLike ? @"  ← VPN/隧道" : @"", [name hasPrefix:@"en"] ? @"" : @""];
    }
    freeifaddrs(ifs);
    return r;
}

#pragma mark - TCP 连接（对标 scanTCPConnections）

NSString *mfNetScanTCP(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【TCP 连接表】\n"];
    int mib[6] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_FLAGS, 0};
    size_t len = 0;
    if (sysctl(mib, 6, NULL, &len, NULL, 0) != 0 || len == 0) {
        return @"⚠️ 路由表不可读（沙盒限制，sysctl EPERM）\n提示：这是 iOS 沙盒的常规表现，非故障";
    }
    char *buf = malloc(len);
    if (!buf || sysctl(mib, 6, buf, &len, NULL, 0) != 0) { free(buf); return @"⚠️ sysctl 读取失败"; }
    // 遍历 rt_msghdr 流
    size_t off = 0;
    int n = 0;
    while (off + sizeof(struct rt_msghdr) <= len) {
        struct rt_msghdr *rtm = (struct rt_msghdr *)(buf + off);
        if (rtm->rtm_msglen < sizeof(struct rt_msghdr) || off + rtm->rtm_msglen > len) break;
        // sockaddr 数组跟在 header 后（简化：只数条目，详细解析依赖 rtm_addrs 位图）
        n++;
        off += rtm->rtm_msglen;
    }
    free(buf);
    [r appendFormat:@"  路由/socket 表目: %d 条\n  ⚠️ iOS 上完整 TCP 状态表需 root+特殊 entitlement，此处仅探测可达性\n", n];
    return r;
}

#pragma mark - DNS（对标 queryDNS + scanDNSRecords）

NSString *mfNetScanDNS(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【DNS 解析器】\n"];
    res_state st = calloc(1, sizeof(struct __res_state));
    if (res_ninit(st) == 0) {
        [r appendString:@"  nameserver:\n"];
        for (int i = 0; i < MAXNS && st->nsaddr_list[i].sin_addr.s_addr; i++) {
            char ip[INET_ADDRSTRLEN] = "?";
            inet_ntop(AF_INET, &st->nsaddr_list[i].sin_addr, ip, sizeof(ip));
            [r appendFormat:@"    · %s\n", ip];
        }
        res_nclose(st);
    } else {
        [r appendString:@"  ⚠️ res_ninit 失败\n"];
    }
    free(st);
    // 连通性测试
    [r appendString:@"【解析测试】\n"];
    for (NSString *host in @[@"apple.com", @"google.com"]) {
        CFHostRef h = CFHostCreateWithName(kCFAllocatorDefault, (__bridge CFStringRef)host);
        Boolean ok = CFHostStartInfoResolution(h, kCFHostAddresses, NULL);
        NSError *err = nil;
        NSArray *addrs = CFBridgingRelease(CFHostGetAddressing(h, &ok)) ?: @[];
        CFRelease(h);
        [r appendFormat:@"  %@ %-12s → %lu 个地址\n", ok && addrs.count ? @"✅" : @"🔴", host.UTF8String, (unsigned long)addrs.count];
    }
    return r;
}

#pragma mark - Cookie（对标 scanCookies）

NSString *mfNetScanCookies(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【HTTP Cookies】\n"];
    NSArray<NSHTTPCookie *> *cs = NSHTTPCookieStorage.sharedHTTPCookieStorage.cookies;
    [r appendFormat:@"  共 %lu 个\n", (unsigned long)cs.count];
    for (NSHTTPCookie *c in cs) {
        NSString *val = c.value.length > 40 ? [[c.value substringToIndex:40] stringByAppendingString:@"…"] : c.value;
        [r appendFormat:@"  · %@ | %@ = %@\n", c.domain, c.name, val ?: @"(空)"];
    }
    return r;
}

#pragma mark - 证书（对标 scanCertificates）

NSString *mfNetScanCertificates(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【Keychain 证书】\n"];
    NSMutableDictionary *q = [@{
        (__bridge NSString *)kSecClass: (__bridge NSString *)kSecClassCertificate,
        (__bridge NSString *)kSecMatchLimit: (__bridge NSString *)kSecMatchLimitAll,
        (__bridge NSString *)kSecReturnRef: @YES,
        (__bridge NSString *)kSecReturnAttributes: @YES,
    } mutableCopy];
    CFTypeRef result = NULL;
    OSStatus st2 = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
    if (st2 != errSecSuccess || !result) {
        [r appendFormat:@"  %@ 无证书或不可见（status=%d）\n", st2 == errSecItemNotFound ? @"✅" : @"⚠️", (int)st2];
        return r;
    }
    NSArray *items = CFBridgingRelease(result);
    [r appendFormat:@"  共 %lu 个\n", (unsigned long)items.count];
    unsigned shown = 0;
    for (NSDictionary *it in items) {
        if (shown++ >= 30) { [r appendFormat:@"  …（其余 %lu 条略）\n", (unsigned long)(items.count - 30)]; break; }
        [r appendFormat:@"  · %@\n", it[(__bridge NSString *)kSecAttrLabel] ?: @"(无标签)"];
    }
    return r;
}

#pragma mark - VPN 配置（对标 scanVPNConfigurations）

static BOOL mfIsTunInterface(const char *name) {
    return strncmp(name, "utun", 4) == 0 || strncmp(name, "ipsec", 5) == 0 ||
           strncmp(name, "tap", 3) == 0 || strncmp(name, "ppp", 3) == 0;
}

NSString *mfNetScanVPN(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【VPN 配置探测】\n"];
    // utun 接口存在性 = 最可靠的运行时信号
    struct ifaddrs *ifs = NULL, *ifa;
    int tunCount = 0;
    NSMutableString *tuns = [NSMutableString string];
    if (getifaddrs(&ifs) == 0) {
        for (ifa = ifs; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && mfIsTunInterface(ifa->ifa_name)) {
                tunCount++;
                [tuns appendFormat:@"    · %s\n", ifa->ifa_name];
            }
        }
        freeifaddrs(ifs);
    }
    [r appendFormat:@"  %@ 隧道接口: %d 个\n", tunCount ? @"🔵" : @"⚪️", tunCount];
    [r appendString:tuns];
    // NEVPN 状态（App 进程只能看到自身配置，系统级 VPN 读不全属正常）
    [r appendString:@"  提示：系统级 VPN profile 在沙盒内不可枚举，utun 计数为最可靠信号\n"];
    return r;
}

#pragma mark - SSID（对标 currentSSID）

NSString *mfNetScanSSID(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【Wi-Fi 信息】\n"];
    @try {
        CFArrayRef ifs = CNCopySupportedInterfaces();
        if (!ifs) { [r appendString:@"  ⚠️ CNCopySupportedInterfaces 返回空\n"]; return r; }
        NSArray *ifsAry = CFBridgingRelease(ifs);
        for (NSString *ifn in ifsAry) {
            CFDictionaryRef info = CNCopyCurrentNetworkInfo((__bridge CFStringRef)ifn);
            if (info) {
                NSDictionary *d = CFBridgingRelease(info);
                [r appendFormat:@"  %@: SSID=%@ BSSID=%@\n", ifn, d[@"SSID"] ?: @"?", d[@"BSSID"] ?: @"?"];
            } else {
                [r appendFormat:@"  %@: 无权限或未连接（iOS14+ 需定位授权）\n", ifn];
            }
        }
    } @catch (NSException *ex) {
        [r appendFormat:@"  ⚠️ 异常: %@\n", ex.reason];
    }
    return r;
}

#pragma mark - 页面 + 扫描分发

static NSArray * const mfNetItems = @[
    @[@"接口列表", @"if"], @[@"TCP 连接表", @"tcp"],
    @[@"DNS 解析器+测试", @"dns"], @[@"HTTP Cookies", @"cookie"],
    @[@"Keychain 证书", @"cert"], @[@"VPN 配置探测", @"vpn"],
    @[@"Wi-Fi SSID", @"ssid"],
    @[@"已捕获 HTTP 请求", @"http"], @[@"cURL 导出", @"curl"],
];

void mfNetAnalyzerRun(NSString *kind, UIButton *btn) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *report = nil, *title = nil;
        if ([kind isEqualToString:@"if"]) { report = mfNetScanInterfaces(); title = @"网络接口"; }
        else if ([kind isEqualToString:@"tcp"]) { report = mfNetScanTCP(); title = @"TCP 连接表"; }
        else if ([kind isEqualToString:@"dns"]) { report = mfNetScanDNS(); title = @"DNS"; }
        else if ([kind isEqualToString:@"cookie"]) { report = mfNetScanCookies(); title = @"Cookies"; }
        else if ([kind isEqualToString:@"cert"]) { report = mfNetScanCertificates(); title = @"证书"; }
        else if ([kind isEqualToString:@"vpn"]) { report = mfNetScanVPN(); title = @"VPN 探测"; }
        else if ([kind isEqualToString:@"ssid"]) { report = mfNetScanSSID(); title = @"Wi-Fi"; }
        else if ([kind isEqualToString:@"http"]) { report = mfNetScanHTTP(); title = @"已捕获 HTTP"; }
        else if ([kind isEqualToString:@"curl"]) { report = mfNetScanCurl(); title = @"cURL 导出"; }
        dispatch_async(dispatch_get_main_queue(), ^{
            btn.enabled = YES;
            if (!report) return;
            mfShowTextReportPage(title, report, @"NetAnalyzer");
        });
    });
}

void mfShowNetAnalyzerPage(void) {
    UIView *page = mfMakePage(@"🌐 网络分析", YES);
    CGFloat gw = g_mfCardW - 32;

    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(16, 44, gw, 30)];
    hint.font = [UIFont systemFontOfSize:11];
    hint.textColor = [UIColor secondaryLabelColor];
    hint.numberOfLines = 2;
    hint.text = @"九项网络体检（对标 ToolsEric NetworkAnalyzer）";
    [page addSubview:hint];

    CGFloat y = 80;
    for (NSArray *it in mfNetItems) {
        BOOL captureDep = [it[1] isEqualToString:@"http"] || [it[1] isEqualToString:@"curl"];
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        b.frame = CGRectMake(16, y, gw, 40);
        b.backgroundColor = [UIColor secondarySystemBackgroundColor];
        b.layer.cornerRadius = 10;
        b.tintColor = captureDep ? [UIColor systemOrangeColor] : [UIColor labelColor];
        b.titleLabel.font = [UIFont systemFontOfSize:13];
        [b setTitle:[NSString stringWithFormat:@"%@%@", captureDep ? @"⏺ " : @"▸ ", it[0]] forState:UIControlStateNormal];
        objc_setAssociatedObject(b, "kind", it[1], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [page addSubview:b];
        [b addTarget:g_mfCtrl action:NSSelectorFromString(@"mfNetRun:") forControlEvents:UIControlEventTouchUpInside];
        y += 48;
    }
    UILabel *note = [[UILabel alloc] initWithFrame:CGRectMake(16, y + 4, gw, 30)];
    note.font = [UIFont systemFontOfSize:10];
    note.textColor = [UIColor tertiaryLabelColor];
    note.numberOfLines = 2;
    note.text = @"⏺ 橙色项依赖实时捕获记录（先开捕获开关）\nWebSocket/gRPC 不经 NSURLProtocol，无法捕获";
    [page addSubview:note];
    mfPushPage(page);
}

// 由 MFNetworkCapture.m 提供
NSArray *mfCapturedRecordsSnapshot(void);

NSString *mfNetScanHTTP(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【已捕获 HTTP 请求】\n"];
    NSArray *recs = mfCapturedRecordsSnapshot();
    if (!recs.count) return @"⚠️ 无捕获记录——请先到数据分析页开启「实时捕获」开关再浏览目标 App";
    [r appendFormat:@"  缓冲区 %lu 条（上限内最近优先）\n\n", (unsigned long)recs.count];
    NSUInteger start = recs.count > 50 ? recs.count - 50 : 0;
    for (NSUInteger i = recs.count; i > start; i--) {
        MFNetRecord *rec = recs[i - 1];
        static NSDateFormatter *df = nil;
        static dispatch_once_t once;
        dispatch_once(&once, ^{ df = [NSDateFormatter new]; df.dateFormat = @"HH:mm:ss"; });
        [r appendFormat:@"[%@] %@ %ld %@\n",
            [df stringFromDate:rec.timestamp] ?: @"?",
            rec.method ?: @"?", (long)rec.status, rec.url ?: @"?"];
    }
    return r;
}

NSString *mfNetScanCurl(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【cURL 导出（最近 10 条）】\n"];
    NSArray *recs = mfCapturedRecordsSnapshot();
    if (!recs.count) return @"⚠️ 无捕获记录——先开启实时捕获";
    NSUInteger start = recs.count > 10 ? recs.count - 10 : 0;
    for (NSUInteger i = recs.count; i > start; i--) {
        MFNetRecord *rec = recs[i - 1];
        [r appendFormat:@"# %ld %@\n", (long)rec.status, rec.url ?: @""];
        NSMutableString *cmd = [NSMutableString stringWithFormat:@"curl '%@'", rec.url ?: @""];
        if (![rec.method isEqualToString:@"GET"])
            [cmd appendFormat:@" -X %@", rec.method ?: @"GET"];
        for (NSString *hk in rec.reqHeaders)
            [cmd appendFormat:@" \\\n  -H '%@: %@'", hk,
                [rec.reqHeaders[hk] length] > 120 ? [[[rec.reqHeaders[hk] substringToIndex:120] stringByAppendingString:@"…"] stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"] : [rec.reqHeaders[hk] stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"]];
        if (rec.reqBody.length) {
            NSString *bs = [[NSString alloc] initWithData:rec.reqBody encoding:NSUTF8StringEncoding] ?: [rec.reqBody base64EncodedStringWithOptions:0];
            bs = [bs stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"];
            if (bs.length > 400) bs = [[bs substringToIndex:400] stringByAppendingString:@"…"];
            [cmd appendFormat:@" \\\n  --data-raw '%@'", bs];
        }
        [r appendFormat:@"%@\n\n", cmd];
    }
    return r;
}

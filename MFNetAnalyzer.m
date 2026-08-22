// MFNetAnalyzer.m — 网络分析 (v1.7.1 瘦身版)
// v1.7.0 九项被砍一半：已捕获HTTP/cURL 与网络捕获页重复，TCP表/SSID 沙盒权限墙，VPN 并入接口列表
// 保留四项真金：接口列表(含VPN隧道) / DNS连通性 / Cookies / Keychain证书

#import "MFPanel.h"
#import <SystemConfiguration/SystemConfiguration.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <Security/Security.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>

#pragma mark - 接口列表 + VPN 隧道探测

NSString *mfNetScanInterfaces(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【网络接口】\n"];
    struct ifaddrs *ifs = NULL, *ifa;
    if (getifaddrs(&ifs) != 0) return @"⚠️ getifaddrs 失败";
    NSString *last = nil;
    int tun = 0, en = 0;
    for (ifa = ifs; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_addr->sa_family != AF_INET6) continue;
        NSString *name = [NSString stringWithUTF8String:ifa->ifa_name];
        if ([name isEqualToString:last]) continue;
        last = name;
        char ip[64] = "?";
        if (ifa->ifa_addr->sa_family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ip, sizeof(ip));
        else
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, ip, sizeof(ip));
        BOOL up = (ifa->ifa_flags & IFF_UP) != 0;
        BOOL vpnLike = [name hasPrefix:@"utun"] || [name hasPrefix:@"ipsec"] || [name hasPrefix:@"tap"] || [name hasPrefix:@"ppp"];
        if (vpnLike) tun++;
        if ([name hasPrefix:@"en"]) en++;
        [r appendFormat:@"  %@ %@  %@%@\n", up ? @"🟢" : @"⚪️", name, ip,
            vpnLike ? @"  ← VPN/隧道" : @""];
    }
    freeifaddrs(ifs);
    [r appendFormat:@"\n  物理网卡 %d · 隧道接口 %d %@\n", en, tun,
        tun ? @"（检测到 VPN 活动）" : @"（无 VPN）"];
    return r;
}

#pragma mark - DNS 连通性（getaddrinfo，无 runloop 依赖）

NSString *mfNetScanDNS(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【DNS 解析器】\n"];
    NSString *rc = [NSString stringWithContentsOfFile:@"/etc/resolv.conf" encoding:NSUTF8StringEncoding error:nil];
    if (rc.length) {
        for (NSString *line in [rc componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet])
            if ([line hasPrefix:@"nameserver"] || [line hasPrefix:@"search"])
                [r appendFormat:@"  %@\n", line];
    } else {
        [r appendString:@"  ⚪️ resolv.conf 由 mDNSResponder 托管，不可直读\n"];
    }
    // getaddrinfo 同步解析测试——POSIX 标准，GCD 线程安全（CFHost 无 runloop 会崩，已弃）
    [r appendString:@"【解析测试】\n"];
    for (NSString *host in @[@"apple.com", @"google.com"]) {
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_UNSPEC;
        int rc2 = getaddrinfo(host.UTF8String, NULL, &hints, &res);
        int count = 0;
        for (struct addrinfo *ai = res; ai; ai = ai->ai_next) count++;
        if (res) freeaddrinfo(res);
        [r appendFormat:@"  %@ %-12s → %@ (%d 地址)\n",
            rc2 == 0 ? @"✅" : @"🔴", host.UTF8String,
            rc2 == 0 ? @"解析成功" : [NSString stringWithUTF8String:gai_strerror(rc2)], count];
    }
    return r;
}

#pragma mark - HTTP Cookies

NSString *mfNetScanCookies(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【HTTP Cookies】\n"];
    NSArray<NSHTTPCookie *> *cs = NSHTTPCookieStorage.sharedHTTPCookieStorage.cookies;
    [r appendFormat:@"  共 %lu 个\n\n", (unsigned long)cs.count];
    for (NSHTTPCookie *c in cs) {
        NSString *val = c.value.length > 40 ? [[c.value substringToIndex:40] stringByAppendingString:@"…"] : c.value;
        [r appendFormat:@"  · %@ | %@ = %@\n", c.domain, c.name, val ?: @"(空)"];
    }
    return r;
}

#pragma mark - Keychain 证书

NSString *mfNetScanCertificates(void) {
    NSMutableString *r = [NSMutableString stringWithString:@"【Keychain 证书】\n"];
    NSDictionary *q = @{
        (__bridge NSString *)kSecClass: (__bridge NSString *)kSecClassCertificate,
        (__bridge NSString *)kSecMatchLimit: (__bridge NSString *)kSecMatchLimitAll,
        (__bridge NSString *)kSecReturnAttributes: @YES,
    };
    CFTypeRef result = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
    if (st != errSecSuccess || !result) {
        [r appendFormat:@"  %@ 无证书或不可见（status=%d）\n", st == errSecItemNotFound ? @"✅" : @"⚠️", (int)st];
        return r;
    }
    NSArray *items = CFBridgingRelease(result);
    [r appendFormat:@"  共 %lu 个\n", (unsigned long)items.count];
    unsigned shown = 0;
    for (NSDictionary *it in items) {
        if (shown++ >= 30) { [r appendFormat:@"  …（其余略）\n"]; break; }
        [r appendFormat:@"  · %@\n", it[(__bridge NSString *)kSecAttrLabel] ?: @"(无标签)"];
    }
    return r;
}

#pragma mark - 页面

static NSArray * const mfNetItems = @[
    @[@"接口列表 + VPN 探测", @"if"],
    @[@"DNS 连通性测试", @"dns"],
    @[@"HTTP Cookies", @"cookie"],
    @[@"Keychain 证书", @"cert"],
];

void mfNetAnalyzerRun(NSString *kind, UIButton *btn) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *report = nil, *title = nil;
        if ([kind isEqualToString:@"if"]) { report = mfNetScanInterfaces(); title = @"接口/VPN"; }
        else if ([kind isEqualToString:@"dns"]) { report = mfNetScanDNS(); title = @"DNS"; }
        else if ([kind isEqualToString:@"cookie"]) { report = mfNetScanCookies(); title = @"Cookies"; }
        else if ([kind isEqualToString:@"cert"]) { report = mfNetScanCertificates(); title = @"证书"; }
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

    CGFloat y = 52;
    for (NSArray *it in mfNetItems) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        b.frame = CGRectMake(16, y, gw, 44);
        b.backgroundColor = [UIColor secondarySystemBackgroundColor];
        b.layer.cornerRadius = 10;
        b.tintColor = [UIColor labelColor];
        b.titleLabel.font = [UIFont systemFontOfSize:13];
        [b setTitle:[@"▸ " stringByAppendingString:it[0]] forState:UIControlStateNormal];
        objc_setAssociatedObject(b, "kind", it[1], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [page addSubview:b];
        [b addTarget:g_mfCtrl action:NSSelectorFromString(@"mfNetRun:") forControlEvents:UIControlEventTouchUpInside];
        y += 52;
    }
    UILabel *note = [[UILabel alloc] initWithFrame:CGRectMake(16, y + 6, gw, 30)];
    note.font = [UIFont systemFontOfSize:10];
    note.textColor = [UIColor tertiaryLabelColor];
    note.numberOfLines = 2;
    note.text = @"HTTP 抓包/改包请用「网络捕获」；系统 TCP 表与 SSID 受沙盒限制不提供";
    [page addSubview:note];
    mfPushPage(page);
}

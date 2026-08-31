// MFKeychainProbe.m — v2.16.0 Keychain 深挖: 定位 Picsew PurchaseManager.CustomerInfo 的 Keychain 条目
// 依据: dump 显示 YJStorage.CryptoLocation<CustomerInfo> — pro 状态 = 加密 CustomerInfo 存 Keychain
// 目标: 枚举当前 app 可访问的全部 Keychain 条目(service/account/长度), 找到 CustomerInfo 条目后覆写
#import "MFPanel.h"
#import <Security/Security.h>

static NSArray *g_kcItems = nil;

void mfKeychainProbeRun(void) {
    NSMutableDictionary *query = [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecReturnData: @YES
    } mutableCopy];
    CFTypeRef result = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    mfLog(@"[kcprobe] status=%d", (int)st);
    if (st != errSecSuccess) { g_kcItems = @[]; return; }
    NSArray *items = (__bridge_transfer NSArray *)result;
    NSMutableArray *out = [NSMutableArray array];
    for (NSDictionary *it in items) {
        NSString *svc = it[(__bridge id)kSecAttrService] ?: @"";
        NSString *acc = it[(__bridge id)kSecAttrAccount] ?: @"";
        NSData *dat = it[(__bridge id)kSecValueData] ?: [NSData data];
        [out addObject:@{@"service": svc, @"account": acc,
                         @"len": @(dat.length),
                         @"b64": [dat base64EncodedStringWithOptions:0]}];
    }
    g_kcItems = out;
    [out writeToFile:[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0]
                      stringByAppendingPathComponent:@"MinisFix/kc_items.plist"] atomically:YES];
    mfLog(@"[kcprobe] %lu items saved", (unsigned long)out.count);
    for (NSDictionary *e in out) {
        mfLog(@"[kcprobe] svc=%@ acc=%@ len=%@", e[@"service"], e[@"account"], e[@"len"]);
    }
    mfToast([NSString stringWithFormat:@"Keychain %lu 条", (unsigned long)out.count]);
}

NSArray *mfKeychainProbeSnapshot(void) { return g_kcItems ?: @[]; }

// 覆写指定 service/account 的数据(写探测出的 CustomerInfo 条目用)
BOOL mfKeychainOverwrite(NSString *service, NSString *account, NSData *data) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service ?: @"",
        (__bridge id)kSecAttrAccount: account ?: @""
    };
    NSDictionary *update = @{(__bridge id)kSecValueData: data ?: [NSData data]};
    OSStatus st = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)update);
    mfLog(@"[kcprobe] overwrite svc=%@ st=%d", service, (int)st);
    return st == errSecSuccess;
}

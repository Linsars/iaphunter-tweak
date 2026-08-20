// MFKeychainManager.m — Keychain 可视化/备份/恢复模块
// 基于 KeychainManager.dylib 逆向重写 (Theos/Logos -> 纯 Objective-C)

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import "MFPanel.h"

// ====== 前向声明 ======
static NSArray *mfGetKeychainItems(void);
static NSString *mfFormatKeychainItem(NSDictionary *item);
static NSString *mfFormatKeychainSummary(NSDictionary *item);
static void mfShowKeychainDetail(NSDictionary *item);
static void mfShowRestorePrompt(void);

// ====== 工具函数 ======
static void mfKLog(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSLog(@"[MFKeychain] %@", msg);
}

static NSArray *mfGetKeychainItems(void) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecReturnData: @YES
    };
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    
    if (status == errSecItemNotFound) {
        return @[];
    }
    if (status != errSecSuccess) {
        mfKLog(@"SecItemCopyMatching failed: %d", (int)status);
        return @[];
    }
    
    NSArray *items = (__bridge_transfer NSArray *)result;
    return items ?: @[];
}

static NSString *mfFormatKeychainItem(NSDictionary *item) {
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(无账号)";
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(无服务)";
    NSData *data = item[(__bridge id)kSecValueData];
    NSString *dataStr = data ? [data base64EncodedStringWithOptions:0] : @"(无数据)";
    return [NSString stringWithFormat:@"账号: %@\n服务: %@\n数据(Base64): %@", account, service, dataStr];
}

static NSString *mfFormatKeychainSummary(NSDictionary *item) {
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(无账号)";
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(无服务)";
    return [NSString stringWithFormat:@"%@ / %@", account, service];
}

// ====== 核心功能 ======

// 导出 Keychain -> Base64 JSON -> 粘贴板
void mfCopyKeychain(void) {
    NSArray *items = mfGetKeychainItems();
    if (items.count == 0) {
        mfKLog(@"no items to copy");
        return;
    }
    
    NSMutableArray *exportArray = [NSMutableArray array];
    for (NSDictionary *item in items) {
        NSMutableDictionary *exp = [NSMutableDictionary dictionary];
        NSData *data = item[(__bridge id)kSecValueData];
        if (data) {
            exp[@"data"] = [data base64EncodedStringWithOptions:0];
        }
        // 保留所有属性
        for (id key in item) {
            if (![key isEqual:(__bridge id)kSecValueData]) {
                exp[key] = item[key];
            }
        }
        [exportArray addObject:exp];
    }
    
    NSError *err = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:exportArray options:NSJSONWritingPrettyPrinted error:&err];
    if (err) {
        mfKLog(@"JSON encode failed: %@", err);
        return;
    }
    
    NSString *base64 = [jsonData base64EncodedStringWithOptions:0];
    [[UIPasteboard generalPasteboard] setString:base64];
    
    mfKLog(@"copied %lu items to pasteboard (%lu chars)", (unsigned long)items.count, (unsigned long)base64.length);
}

// 从粘贴板导入恢复 Keychain
void mfRestoreKeychain(void) {
    NSString *base64 = [UIPasteboard generalPasteboard].string;
    if (!base64 || base64.length == 0) {
        mfKLog(@"pasteboard empty or no string");
        return;
    }
    
    NSData *jsonData = [[NSData alloc] initWithBase64EncodedString:base64 options:0];
    if (!jsonData) {
        mfKLog(@"base64 decode failed");
        return;
    }
    
    NSError *err = nil;
    NSArray *importArray = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&err];
    if (err || !importArray) {
        mfKLog(@"JSON decode failed: %@", err);
        return;
    }
    
    NSUInteger successCount = 0, failCount = 0;
    NSMutableArray *errors = [NSMutableArray array];
    
    for (NSDictionary *item in importArray) {
        NSData *data = nil;
        if (item[@"data"]) {
            data = [[NSData alloc] initWithBase64EncodedString:item[@"data"] options:0];
        }
        
        NSMutableDictionary *addQuery = [NSMutableDictionary dictionary];
        addQuery[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
        if (data) addQuery[(__bridge id)kSecValueData] = data;
        
        for (id key in item) {
            if (![key isEqualToString:@"data"]) {
                addQuery[key] = item[key];
            }
        }
        
        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
        if (status == errSecSuccess) {
            successCount++;
        } else if (status == errSecDuplicateItem) {
            // 尝试更新
            NSDictionary *updateQuery = @{
                (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                (__bridge id)kSecAttrAccount: item[(__bridge id)kSecAttrAccount] ?: @"",
                (__bridge id)kSecAttrService: item[(__bridge id)kSecAttrService] ?: @""
            };
            NSDictionary *updateAttrs = @{ (__bridge id)kSecValueData: data ?: [NSData data] };
            OSStatus updStatus = SecItemUpdate((__bridge CFDictionaryRef)updateQuery, (__bridge CFDictionaryRef)updateAttrs);
            if (updStatus == errSecSuccess) {
                successCount++;
            } else {
                failCount++;
                [errors addObject:[NSString stringWithFormat:@"update failed: %d", (int)updStatus]];
            }
        } else {
            failCount++;
            [errors addObject:[NSString stringWithFormat:@"add failed: %d", (int)status]];
        }
    }
    
    mfKLog(@"restore done: success=%lu, fail=%lu", (unsigned long)successCount, (unsigned long)failCount);
    
    // 结果弹窗
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"恢复完成"
                                                                       message:[NSString stringWithFormat:@"成功: %lu\n失败: %lu", (unsigned long)successCount, (unsigned long)failCount]
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
        UIWindow *win = [[UIApplication sharedApplication] keyWindow];
        if (win && win.rootViewController) {
            [win.rootViewController presentViewController:alert animated:YES completion:nil];
        }
    });
}

// 显示主菜单
void mfShowKeychainMainMenu(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *menu = [UIAlertController alertControllerWithTitle:@"Keychain 管理"
                                                                      message:nil
                                                               preferredStyle:UIAlertControllerStyleActionSheet];
        
        [menu addAction:[UIAlertAction actionWithTitle:@"查看 Keychain 列表" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            mfShowKeychainList();
        }]];
        
        [menu addAction:[UIAlertAction actionWithTitle:@"导出 Keychain (Base64→剪贴板)" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            mfCopyKeychain();
            // Toast 反馈
            UIAlertController *toast = [UIAlertController alertControllerWithTitle:nil message:@"✅ 已复制到剪贴板" preferredStyle:UIAlertControllerStyleAlert];
            UIWindow *win = [[UIApplication sharedApplication] keyWindow];
            if (win && win.rootViewController) {
                [win.rootViewController presentViewController:toast animated:YES completion:^{
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1.5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                        [toast dismissViewControllerAnimated:YES completion:nil];
                    });
                }];
            }
        }]];
        
        [menu addAction:[UIAlertAction actionWithTitle:@"导入/恢复 Keychain (从剪贴板)" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            mfShowRestorePrompt();
        }]];
        
        [menu addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
        
        UIWindow *win = [[UIApplication sharedApplication] keyWindow];
        if (win && win.rootViewController) {
            UIViewController *vc = win.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;
            [vc presentViewController:menu animated:YES completion:nil];
        }
    });
}

// 显示 Keychain 列表
void mfShowKeychainList(void) {
    NSArray *items = mfGetKeychainItems();
    
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *list;
        if (items.count == 0) {
            list = [UIAlertController alertControllerWithTitle:@"Keychain 列表"
                                                       message:@"(无 Generic Password 项)"
                                                preferredStyle:UIAlertControllerStyleAlert];
            [list addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
        } else {
            list = [UIAlertController alertControllerWithTitle:[NSString stringWithFormat:@"Keychain 列表 (%lu 项)", (unsigned long)items.count]
                                                       message:nil
                                                preferredStyle:UIAlertControllerStyleAlert];
            
            for (NSDictionary *item in items) {
                NSString *summary = mfFormatKeychainSummary(item);
                [list addAction:[UIAlertAction actionWithTitle:summary style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                    mfShowKeychainDetail(item);
                }]];
            }
            [list addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        }
        
        UIWindow *win = [[UIApplication sharedApplication] keyWindow];
        if (win && win.rootViewController) {
            UIViewController *vc = win.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;
            [vc presentViewController:list animated:YES completion:nil];
        }
    });
}

// 显示单项详情
static void mfShowKeychainDetail(NSDictionary *item) {
    NSString *detail = mfFormatKeychainItem(item);
    
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *detailAlert = [UIAlertController alertControllerWithTitle:@"Keychain 详情"
                                                                             message:detail
                                                                      preferredStyle:UIAlertControllerStyleAlert];
        [detailAlert addAction:[UIAlertAction actionWithTitle:@"复制数据" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            NSData *data = item[(__bridge id)kSecValueData];
            if (data) {
                [[UIPasteboard generalPasteboard] setString:[data base64EncodedStringWithOptions:0]];
            }
        }]];
        [detailAlert addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        
        UIWindow *win = [[UIApplication sharedApplication] keyWindow];
        if (win && win.rootViewController) {
            UIViewController *vc = win.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;
            [vc presentViewController:detailAlert animated:YES completion:nil];
        }
    });
}

// 显示恢复输入框
static void mfShowRestorePrompt(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"恢复 Keychain"
                                                                       message:@"粘贴 Base64 编码的 Keychain JSON 数据"
                                                                preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
            tf.placeholder = @"Base64 JSON";
            tf.font = [UIFont systemFontOfSize:13];
        }];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
        [alert addAction:[UIAlertAction actionWithTitle:@"恢复" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            UITextField *tf = alert.textFields.firstObject;
            if (tf && tf.text.length > 0) {
                NSData *jsonData = [[NSData alloc] initWithBase64EncodedString:tf.text options:0];
                if (jsonData) {
                    NSError *err = nil;
                    NSArray *importArray = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&err];
                    if (importArray) {
                        // 在后台执行恢复
                        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                            NSUInteger successCount = 0, failCount = 0;
                            for (NSDictionary *item in importArray) {
                                NSData *data = nil;
                                if (item[@"data"]) {
                                    data = [[NSData alloc] initWithBase64EncodedString:item[@"data"] options:0];
                                }
                                NSMutableDictionary *addQuery = [NSMutableDictionary dictionary];
                                addQuery[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
                                if (data) addQuery[(__bridge id)kSecValueData] = data;
                                for (id key in item) {
                                    if (![key isEqualToString:@"data"]) {
                                        addQuery[key] = item[key];
                                    }
                                }
                                OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
                                if (status == errSecSuccess) successCount++;
                                else if (status == errSecDuplicateItem) {
                                    NSDictionary *updQuery = @{
                                        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                        (__bridge id)kSecAttrAccount: item[(__bridge id)kSecAttrAccount] ?: @"",
                                        (__bridge id)kSecAttrService: item[(__bridge id)kSecAttrService] ?: @""
                                    };
                                    NSDictionary *updAttrs = @{ (__bridge id)kSecValueData: data ?: [NSData data] };
                                    if (SecItemUpdate((__bridge CFDictionaryRef)updQuery, (__bridge CFDictionaryRef)updAttrs) == errSecSuccess) {
                                        successCount++;
                                    } else failCount++;
                                } else failCount++;
                            }
                            dispatch_async(dispatch_get_main_queue(), ^{
                                UIAlertController *result = [UIAlertController alertControllerWithTitle:@"恢复完成"
                                                                                                  message:[NSString stringWithFormat:@"成功: %lu\n失败: %lu", (unsigned long)successCount, (unsigned long)failCount]
                                                                                           preferredStyle:UIAlertControllerStyleAlert];
                                [result addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
                                UIWindow *win = [[UIApplication sharedApplication] keyWindow];
                                if (win && win.rootViewController) {
                                    [win.rootViewController presentViewController:result animated:YES completion:nil];
                                }
                            });
                        });
                    }
                }
            }
        }]];
        
        UIWindow *win = [[UIApplication sharedApplication] keyWindow];
        if (win && win.rootViewController) {
            UIViewController *vc = win.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;
            [vc presentViewController:alert animated:YES completion:nil];
        }
    });
}

// 面板入口：从主页网格按钮调用
void mfShowKeychainManagerPage(void) {
    mfShowKeychainMainMenu();
}
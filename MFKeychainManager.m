// MFKeychainManager.m — Keychain 可视化/备份/恢复模块
// 面板页实现 (类似 Product 页)

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import "MFPanel.h"

extern UIViewController *g_mfPanelRootVC;

// ====== 工具函数 ======
static void mfKLog(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSLog(@"[MFKeychain] %@", msg);
}

static NSArray *mfGetKeychainItems(void) {
    mfKLog(@"mfGetKeychainItems called");
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecReturnData: @YES
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    mfKLog(@"SecItemCopyMatching status=%d", (int)status);
    if (status == errSecItemNotFound) {
        mfKLog(@"no items found");
        return @[];
    }
    if (status != errSecSuccess) {
        mfKLog(@"SecItemCopyMatching failed: %d", (int)status);
        return @[];
    }
    NSArray *items = (__bridge_transfer NSArray *)result;
    mfKLog(@"found %lu items", (unsigned long)(items ? items.count : 0));
    return items ?: @[];
}

static void mfPresentOnPanelVC(UIAlertController *alert) {
    mfKLog(@"mfPresentOnPanelVC called, g_mfPanelRootVC=%p", g_mfPanelRootVC);
    if (g_mfPanelRootVC) {
        [g_mfPanelRootVC presentViewController:alert animated:YES completion:nil];
    } else {
        mfKLog(@"ERROR: g_mfPanelRootVC is nil, cannot present");
    }
}

// 删除单个 Keychain 项 (静态内部函数)
static BOOL mfDeleteKeychainItemInternal(NSDictionary *item) {
    mfKLog(@"mfDeleteKeychainItemInternal called for account=%@", item[(__bridge id)kSecAttrAccount] ?: @"(nil)");
    NSDictionary *deleteQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: item[(__bridge id)kSecAttrAccount] ?: @"",
        (__bridge id)kSecAttrService: item[(__bridge id)kSecAttrService] ?: @""
    };
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
    mfKLog(@"SecItemDelete status=%d", (int)status);
    return status == errSecSuccess || status == errSecItemNotFound;
}

// ====== 核心操作 (在后台线程执行) ======

// 导出 Keychain -> Base64 JSON -> 粘贴板
static void mfCopyKeychainInBackground(void) {
    mfKLog(@"mfCopyKeychainInBackground START");
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        mfKLog(@"background queue: fetching items");
        NSArray *items = mfGetKeychainItems();
        if (items.count == 0) {
            mfKLog(@"no items to copy");
            dispatch_async(dispatch_get_main_queue(), ^{
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"提示" message:@"无 Keychain 项可导出" preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
                mfPresentOnPanelVC(alert);
            });
            return;
        }
        
        mfKLog(@"building export array for %lu items", (unsigned long)items.count);
        NSMutableArray *exportArray = [NSMutableArray array];
        for (NSDictionary *item in items) {
            NSMutableDictionary *exp = [NSMutableDictionary dictionary];
            NSData *data = item[(__bridge id)kSecValueData];
            if (data) exp[@"data"] = [data base64EncodedStringWithOptions:0];
            for (id key in item) {
                if (![key isEqual:(__bridge id)kSecValueData]) exp[key] = item[key];
            }
            [exportArray addObject:exp];
        }
        
        mfKLog(@"serializing JSON");
        NSError *err = nil;
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:exportArray options:NSJSONWritingPrettyPrinted error:&err];
        if (err || !jsonData) {
            mfKLog(@"JSON encode failed: %@", err);
            dispatch_async(dispatch_get_main_queue(), ^{
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"导出失败" message:[NSString stringWithFormat:@"JSON 编码失败: %@", err ?: @"" ] preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
                mfPresentOnPanelVC(alert);
            });
            return;
        }
        
        mfKLog(@"JSON size: %lu bytes", (unsigned long)jsonData.length);
        NSString *base64 = [jsonData base64EncodedStringWithOptions:0];
        mfKLog(@"Base64 length: %lu", (unsigned long)base64.length);
        
        [[UIPasteboard generalPasteboard] setString:base64];
        mfKLog(@"copied to pasteboard");
        
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                mfKLog(@"presenting toast alert");
                UIAlertController *toast = [UIAlertController alertControllerWithTitle:nil message:[NSString stringWithFormat:@"✅ 已复制到剪贴板 (%lu 项, %lu 字符)", (unsigned long)items.count, (unsigned long)base64.length] preferredStyle:UIAlertControllerStyleAlert];
                mfPresentOnPanelVC(toast);
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1.5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                    [toast dismissViewControllerAnimated:YES completion:nil];
                });
            } @catch (NSException *e) {
                mfKLog(@"toast crash: %@", e);
            }
        });
    });
    mfKLog(@"mfCopyKeychainInBackground END (async)");
}

// 从粘贴板导入恢复 Keychain
static void mfRestoreKeychainInBackground(NSString *base64) {
    mfKLog(@"mfRestoreKeychainInBackground START, input length=%lu", (unsigned long)(base64 ? base64.length : 0));
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        mfKLog(@"background queue: processing restore");
        if (!base64 || base64.length == 0) {
            mfKLog(@"ERROR: empty base64 input");
            dispatch_async(dispatch_get_main_queue(), ^{
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"失败" message:@"输入为空" preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
                mfPresentOnPanelVC(alert);
            });
            return;
        }
        
        NSData *jsonData = [[NSData alloc] initWithBase64EncodedString:base64 options:0];
        if (!jsonData) {
            mfKLog(@"Base64 decode failed, first 50 chars: %@", [base64 substringToIndex:MIN(50, base64.length)]);
            dispatch_async(dispatch_get_main_queue(), ^{
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"失败" message:@"Base64 解码失败，请确认粘贴的是导出时的完整字符串" preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
                mfPresentOnPanelVC(alert);
            });
            return;
        }
        
        mfKLog(@"Base64 decoded, jsonData length: %lu", (unsigned long)jsonData.length);
        NSString *rawJson = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
        mfKLog(@"Raw JSON (first 200): %@", rawJson ? [rawJson substringToIndex:MIN(200, rawJson.length)] : @"(non-utf8)");
        
        NSError *jsonErr = nil;
        NSArray *importArray = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&jsonErr];
        if (jsonErr || !importArray) {
            mfKLog(@"JSON parse failed: %@, raw: %@", jsonErr, rawJson ?: @"(nil)");
            dispatch_async(dispatch_get_main_queue(), ^{
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"失败" message:[NSString stringWithFormat:@"JSON 解析失败: %@\n请确认粘贴的是导出时的完整 Base64 字符串", jsonErr ?: @"" ] preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
                mfPresentOnPanelVC(alert);
            });
            return;
        }
        
        mfKLog(@"Parsed %lu items from JSON", (unsigned long)importArray.count);
        
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
                if (![key isEqualToString:@"data"]) addQuery[key] = item[key];
            }
            OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
            if (status == errSecSuccess) {
                successCount++;
            } else if (status == errSecDuplicateItem) {
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
        
        mfKLog(@"Restore done: success=%lu, fail=%lu", (unsigned long)successCount, (unsigned long)failCount);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            UIAlertController *result = [UIAlertController alertControllerWithTitle:@"恢复完成"
                                                                              message:[NSString stringWithFormat:@"成功: %lu\n失败: %lu", (unsigned long)successCount, (unsigned long)failCount]
                                                                       preferredStyle:UIAlertControllerStyleAlert];
            [result addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
            mfPresentOnPanelVC(result);
        });
    });
    mfKLog(@"mfRestoreKeychainInBackground END (async)");
}

// ====== 面板页面 ======

// 显示 Keychain 列表
static void mfShowKeychainListPage(void) {
    mfKLog(@"mfShowKeychainListPage called");
    UIView *page = mfMakePage(@"Keychain 列表", YES);
    NSArray *items = mfGetKeychainItems();
    mfKLog(@"list page: %lu items", (unsigned long)items.count);
    
    if (items.count == 0) {
        UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(20, 50, g_mfCardW - 40, 40)];
        label.text = @"无 Generic Password 项";
        label.textAlignment = NSTextAlignmentCenter;
        label.textColor = [UIColor secondaryLabelColor];
        label.font = [UIFont systemFontOfSize:15];
        [page addSubview:label];
    } else {
        // ScrollView 从 nav bar 下方开始 (y=40)，避免遮挡返回键
        UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 40, g_mfCardW, g_mfCardH - 40)];
        sv.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        [page addSubview:sv];
        
        CGFloat y = 12;
        for (NSDictionary *item in items) {
            NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(无账号)";
            NSString *service = item[(__bridge id)kSecAttrService] ?: @"(无服务)";
            NSString *summary = [NSString stringWithFormat:@"%@ / %@", account, service];
            
            UIView *cell = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 44)];
            cell.backgroundColor = [UIColor secondarySystemBackgroundColor];
            cell.layer.cornerRadius = 8;
            
            UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
            btn.frame = cell.bounds;
            btn.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
            [btn setTitle:[NSString stringWithFormat:@"  %@", summary] forState:UIControlStateNormal];
            [btn setTitleColor:[UIColor labelColor] forState:UIControlStateNormal];
            btn.titleLabel.font = [UIFont systemFontOfSize:14];
            objc_setAssociatedObject(btn, "item", item, OBJC_ASSOCIATION_RETAIN);
            [btn addTarget:g_mfCtrl action:@selector(mfShowKeychainDetail:) forControlEvents:UIControlEventTouchUpInside];
            [cell addSubview:btn];
            
            // 删除按钮 (右侧红色)
            UIButton *delBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            delBtn.frame = CGRectMake(g_mfCardW - 24 - 60, 4, 60, 36);
            delBtn.backgroundColor = [UIColor systemRedColor];
            delBtn.layer.cornerRadius = 6;
            [delBtn setTitle:@"删除" forState:UIControlStateNormal];
            [delBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
            delBtn.titleLabel.font = [UIFont systemFontOfSize:12];
            objc_setAssociatedObject(delBtn, "item", item, OBJC_ASSOCIATION_RETAIN);
            [delBtn addTarget:g_mfCtrl action:@selector(mfDeleteKeychainItem:) forControlEvents:UIControlEventTouchUpInside];
            [cell addSubview:delBtn];
            
            [sv addSubview:cell];
            y += 48;
        }
        sv.contentSize = CGSizeMake(g_mfCardW, y + 20);
    }
    mfKLog(@"pushing list page");
    mfPushPage(page);
}

// 显示详情
void mfShowKeychainDetail(NSDictionary *item) {
    mfKLog(@"mfShowKeychainDetail called for account=%@", item[(__bridge id)kSecAttrAccount] ?: @"(nil)");
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(无账号)";
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(无服务)";
    NSData *data = item[(__bridge id)kSecValueData];
    NSString *dataStr = data ? [data base64EncodedStringWithOptions:0] : @"(无数据)";
    NSString *detail = [NSString stringWithFormat:@"账号: %@\n服务: %@\n数据(Base64): %@", account, service, dataStr];
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Keychain 详情"
                                                                     message:detail
                                                              preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"复制数据" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        if (data) {
            [[UIPasteboard generalPasteboard] setString:[data base64EncodedStringWithOptions:0]];
            mfKLog(@"copied detail data to pasteboard");
        }
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
    mfPresentOnPanelVC(alert);
}

// 删除 Keychain 项 (从列表页按钮调用) - 外部可见
void mfDeleteKeychainItem(UIButton *btn) {
    mfKLog(@"mfDeleteKeychainItem handler called");
    NSDictionary *item = objc_getAssociatedObject(btn, "item");
    if (!item) {
        mfKLog(@"ERROR: no item associated with button");
        return;
    }
    
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(无账号)";
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(无服务)";
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"删除 Keychain 项"
                                                                   message:[NSString stringWithFormat:@"确定删除？\n%@ / %@", account, service]
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"删除" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        mfKLog(@"user confirmed delete");
        BOOL ok = mfDeleteKeychainItemInternal(item);
        mfKLog(@"delete result: %@", ok ? @"YES" : @"NO");
        dispatch_async(dispatch_get_main_queue(), ^{
            UIAlertController *result = [UIAlertController alertControllerWithTitle:ok ? @"已删除" : @"删除失败"
                                                                               message:nil
                                                                        preferredStyle:UIAlertControllerStyleAlert];
            [result addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                if (ok) {
                    mfKLog(@"refreshing list page");
                    mfPopPage();
                    mfShowKeychainListPage();
                }
            }]];
            mfPresentOnPanelVC(result);
        });
    }]];
    mfPresentOnPanelVC(alert);
}

// 显示恢复输入
static void mfShowRestorePrompt(void) {
    mfKLog(@"mfShowRestorePrompt called");
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
            mfKLog(@"user submitted restore, text length=%lu", (unsigned long)tf.text.length);
            mfRestoreKeychainInBackground(tf.text);
        } else {
            mfKLog(@"empty restore input");
        }
    }]];
    
    mfPresentOnPanelVC(alert);
}

// ====== 面板入口 ======

// Keychain 主页
void mfShowKeychainManagerPage(void) {
    mfKLog(@"mfShowKeychainManagerPage called");
    
    UIView *page = mfMakePage(@"Keychain 管理", YES);
    CGFloat gw = (g_mfCardW - 32 - 12) / 2;
    CGFloat gy = 48;
    
    gy = mfGridButton(page, 16, gy, gw, @"查看列表", @"📋", @selector(mfShowKeychainListPage), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"导出到剪贴板", @"📤", @selector(mfCopyKeychainAction), NO, nil);
    gy = mfGridButton(page, 16, gy, gw, @"从剪贴板恢复", @"📥", @selector(mfShowRestorePromptAction), NO, nil);
    
    mfPushPage(page);
}

// 转发方法
void mfShowKeychainListPageAction(void) { 
    mfKLog(@"mfShowKeychainListPageAction called");
    mfShowKeychainListPage(); 
}
void mfCopyKeychainAction(void) { 
    mfKLog(@"mfCopyKeychainAction called");
    mfCopyKeychainInBackground(); 
}
void mfShowRestorePromptAction(void) { 
    mfKLog(@"mfShowRestorePromptAction called");
    mfShowRestorePrompt(); 
}
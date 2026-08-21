// MFKeychainManager.m — Keychain 可视化/备份/恢复模块
// 面板页实现 (类似 Product 页)

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CloudKit/CloudKit.h>
#import "MFPanel.h"
#import "LSApplicationProxy.h"

extern UIViewController *g_mfPanelRootVC;
extern void mfLog(NSString *fmt, ...);  // 使用面板统一日志

// ====== 工具函数 ======
#define MFKEYCHAIN_VERSION @"1.3.0"

static void mfKLog(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    mfLog(@"[MFKeychain v%@] %@", MFKEYCHAIN_VERSION, msg);
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
                if (![key isEqual:(__bridge id)kSecValueData]) {
                    id val = item[key];
                    // 只保留 JSON 可序列化类型：NSString, NSNumber, NSArray, NSDictionary, NSNull
                    // 其他类型 (NSDate, NSData 等) 转字符串
                    if ([val isKindOfClass:[NSString class]] ||
                        [val isKindOfClass:[NSNumber class]] ||
                        [val isKindOfClass:[NSArray class]] ||
                        [val isKindOfClass:[NSDictionary class]] ||
                        [val isKindOfClass:[NSNull class]]) {
                        exp[key] = val;
                    } else {
                        exp[key] = [val description];
                    }
                }
            }
            [exportArray addObject:exp];
        }
        
        mfKLog(@"serializing JSON");
        @try {
            NSError *err = nil;
            NSData *jsonData = [NSJSONSerialization dataWithJSONObject:exportArray options:NSJSONWritingPrettyPrinted error:&err];
            if (err || !jsonData) {
                mfKLog(@"JSON encode failed: %@", err);
                @throw [NSException exceptionWithName:@"JSONEncodeError" reason:[err ?: @"" description] userInfo:nil];
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
        } @catch (NSException *e) {
            mfKLog(@"JSON serialization exception: %@", e);
            dispatch_async(dispatch_get_main_queue(), ^{
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"导出失败" message:[NSString stringWithFormat:@"JSON 编码异常: %@", e.reason] preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
                mfPresentOnPanelVC(alert);
            });
        }
    });
    mfKLog(@"mfCopyKeychainInBackground END (async)");
}

// 单个项目恢复处理（前向声明）
static void mfProcessSingleRestoreItem(NSDictionary *item);

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
        
        // 如果不是有效 JSON 数组，尝试当作单个 base64 data 字符串处理
        NSMutableArray *itemsToRestore = [NSMutableArray array];
        BOOL isSingleItem = NO;
        
        if (jsonErr || !importArray) {
            mfKLog(@"Not a JSON array, trying single base64 item");
            // 当作单个 base64 data 字符串
            NSString *singleBase64 = rawJson ?: @"";
            NSData *itemData = [[NSData alloc] initWithBase64EncodedString:singleBase64 options:0];
            if (itemData) {
                isSingleItem = YES;
                // 需要用户提供 account/service，这里先用默认值
                NSMutableDictionary *item = [NSMutableDictionary dictionary];
                item[@"data"] = singleBase64;
                item[(__bridge id)kSecAttrAccount] = @"restored_item";
                item[(__bridge id)kSecAttrService] = @"MinisFix_Restore";
                item[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
                [itemsToRestore addObject:item];
                mfKLog(@"Parsed single item, data length=%lu", (unsigned long)itemData.length);
            } else {
                mfKLog(@"JSON parse failed and not valid base64: %@", jsonErr);
                dispatch_async(dispatch_get_main_queue(), ^{
                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"失败" message:[NSString stringWithFormat:@"无法解析输入：既不是有效的导出 JSON，也不是有效的 Base64 数据\n%@", jsonErr ?: @"" ] preferredStyle:UIAlertControllerStyleAlert];
                    [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
                    mfPresentOnPanelVC(alert);
                });
                return;
            }
        } else {
            mfKLog(@"Parsed %lu items from JSON", (unsigned long)importArray.count);
            [itemsToRestore addObjectsFromArray:importArray];
        }
        
        NSUInteger successCount = 0, failCount = 0, duplicateCount = 0;
        NSMutableArray *details = [NSMutableArray array];
        
        for (NSDictionary *item in itemsToRestore) {
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
            
            // 单个 item 模式且无 account/service 时，弹窗让用户输入
            if (isSingleItem && (!item[(__bridge id)kSecAttrAccount] || !item[(__bridge id)kSecAttrService])) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"恢复单个项目"
                                                                                   message:@"请输入账号和服务名"
                                                                        preferredStyle:UIAlertControllerStyleAlert];
                    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
                        tf.placeholder = @"账号";
                        tf.text = @"restored_item";
                    }];
                    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
                        tf.placeholder = @"服务";
                        tf.text = @"MinisFix_Restore";
                    }];
                    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
                    [alert addAction:[UIAlertAction actionWithTitle:@"恢复" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                        NSString *account = alert.textFields[0].text ?: @"restored_item";
                        NSString *service = alert.textFields[1].text ?: @"MinisFix_Restore";
                        // 创建 mutable copy 并设置 account/service
                        NSMutableDictionary *mutableItem = [item mutableCopy];
                        mutableItem[(__bridge id)kSecAttrAccount] = account;
                        mutableItem[(__bridge id)kSecAttrService] = service;
                        // 在后台处理这个 item
                        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                            mfProcessSingleRestoreItem(mutableItem);
                        });
                    }]];
                    mfPresentOnPanelVC(alert);
                });
                return; // 等待用户输入
            }
            
            OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
            NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(未知)";
            NSString *service = item[(__bridge id)kSecAttrService] ?: @"(未知)";
            
            if (status == errSecSuccess) {
                successCount++;
                [details addObject:[NSString stringWithFormat:@"✅ %@ / %@", account, service]];
            } else if (status == errSecDuplicateItem) {
                // 尝试更新
                NSDictionary *updQuery = @{
                    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                    (__bridge id)kSecAttrAccount: account,
                    (__bridge id)kSecAttrService: service
                };
                NSDictionary *updAttrs = @{ (__bridge id)kSecValueData: data ?: [NSData data] };
                OSStatus updStatus = SecItemUpdate((__bridge CFDictionaryRef)updQuery, (__bridge CFDictionaryRef)updAttrs);
                if (updStatus == errSecSuccess) {
                    duplicateCount++;
                    [details addObject:[NSString stringWithFormat:@"♻️ 已更新 %@ / %@", account, service]];
                } else {
                    failCount++;
                    [details addObject:[NSString stringWithFormat:@"❌ 更新失败 %@ / %@ (err=%d)", account, service, (int)updStatus]];
                }
            } else {
                failCount++;
                [details addObject:[NSString stringWithFormat:@"❌ 添加失败 %@ / %@ (err=%d)", account, service, (int)status]];
            }
        }
        
        mfKLog(@"Restore done: success=%lu, duplicate=%lu, fail=%lu", (unsigned long)successCount, (unsigned long)duplicateCount, (unsigned long)failCount);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *msg;
            if (isSingleItem) {
                msg = [details componentsJoinedByString:@"\n"];
            } else {
                msg = [NSString stringWithFormat:@"成功: %lu\n已更新(重复): %lu\n失败: %lu\n\n%@", 
                       (unsigned long)successCount, (unsigned long)duplicateCount, (unsigned long)failCount,
                       [details componentsJoinedByString:@"\n"]];
            }
            UIAlertController *result = [UIAlertController alertControllerWithTitle:@"恢复完成"
                                                                              message:msg
                                                                       preferredStyle:UIAlertControllerStyleAlert];
            [result addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
            mfPresentOnPanelVC(result);
        });
    });
    mfKLog(@"mfRestoreKeychainInBackground END (async)");
}

// 处理单个恢复项目（用户输入 account/service 后调用）
void mfProcessSingleRestoreItem(NSDictionary *item) {
    mfKLog(@"mfProcessSingleRestoreItem called");
    
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
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(未知)";
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(未知)";
    NSString *resultMsg;
    
    if (status == errSecSuccess) {
        resultMsg = [NSString stringWithFormat:@"✅ %@ / %@", account, service];
    } else if (status == errSecDuplicateItem) {
        NSDictionary *updQuery = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrAccount: account,
            (__bridge id)kSecAttrService: service
        };
        NSDictionary *updAttrs = @{ (__bridge id)kSecValueData: data ?: [NSData data] };
        OSStatus updStatus = SecItemUpdate((__bridge CFDictionaryRef)updQuery, (__bridge CFDictionaryRef)updAttrs);
        if (updStatus == errSecSuccess) {
            resultMsg = [NSString stringWithFormat:@"♻️ 已更新 %@ / %@", account, service];
        } else {
            resultMsg = [NSString stringWithFormat:@"❌ 更新失败 %@ / %@ (err=%d)", account, service, (int)updStatus];
        }
    } else {
        resultMsg = [NSString stringWithFormat:@"❌ 添加失败 %@ / %@ (err=%d)", account, service, (int)status];
    }
    
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *result = [UIAlertController alertControllerWithTitle:@"恢复完成"
                                                                          message:resultMsg
                                                                   preferredStyle:UIAlertControllerStyleAlert];
        [result addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
        mfPresentOnPanelVC(result);
    });
}

// ====== iCloud ID 查询 (通过当前前台 App 的 Entitlements 自动获取 Container Identifier) ======

// 获取当前前台 App 的 Container Identifiers
static NSArray *mfGetFrontmostAppContainerIdentifiers(NSString **outBundleID, NSString **outAppName) {
    mfKLog(@"mfGetFrontmostAppContainerIdentifiers called");
    
    LSApplicationWorkspace *ws = [LSApplicationWorkspace defaultWorkspace];
    if (!ws) {
        mfKLog(@"LSApplicationWorkspace defaultWorkspace returned nil");
        return nil;
    }
    
    NSArray *allApps = [ws allApplications];
    mfKLog(@"Found %lu total apps", (unsigned long)allApps.count);
    
    for (LSApplicationProxy *proxy in allApps) {
        // 检查是否为前台激活 App
        // activationState: 0=None, 1=Background, 2=ForegroundInactive, 3=ForegroundActive
        NSNumber *stateNum = proxy.embeddedEntitlements[@"activationState"] ?: proxy.embeddedEntitlements[@"UISceneActivationState"];
        // 更可靠：用 LSApplicationProxy 的私有方法或属性
        // 这里用启发式：检查是否有 window scene 连接
        // 简单做法：取第一个非系统、有 bundleID 的
        
        NSString *bundleID = proxy.applicationIdentifier;
        if (!bundleID || [bundleID hasPrefix:@"com.apple."]) continue;
        
        // 获取 entitlements
        NSDictionary *entitlements = proxy.embeddedEntitlements;
        if (!entitlements) continue;
        
        // 提取 iCloud Container Identifiers
        NSArray *containerIDs = entitlements[@"com.apple.developer.icloud-container-identifiers"];
        if (!containerIDs || containerIDs.count == 0) continue;
        
        mfKLog(@"Frontmost app candidate: %@, containers: %@", bundleID, containerIDs);
        
        if (outBundleID) *outBundleID = bundleID;
        if (outAppName) *outAppName = proxy.localizedName ?: bundleID;
        return containerIDs;
    }
    
    mfKLog(@"No frontmost app with iCloud containers found");
    return nil;
}

// 核心查询函数
static void mfFetchCloudKitRecordIDForContainer(NSString *containerIdentifier, NSString *appName) {
    mfKLog(@"mfFetchCloudKitRecordIDForContainer called, container=%@", containerIdentifier ?: @"default");
    
    NSString *title = appName ? [NSString stringWithFormat:@"%@ 的 iCloud ID", appName] : @"查询 iCloud ID";
    
    UIAlertController *loading = [UIAlertController alertControllerWithTitle:title
                                                                     message:@"正在获取 CloudKit Record ID...\n请稍候"
                                                              preferredStyle:UIAlertControllerStyleAlert];
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
    spinner.center = CGPointMake(130.5, 65.5);
    spinner.hidesWhenStopped = NO;
    [spinner startAnimating];
    [loading.view addSubview:spinner];
    mfPresentOnPanelVC(loading);
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        CKContainer *container = containerIdentifier ? [CKContainer containerWithIdentifier:containerIdentifier] : [CKContainer defaultContainer];
        [container fetchUserRecordIDWithCompletionHandler:^(CKRecordID *recordID, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [loading dismissViewControllerAnimated:YES completion:nil];
                
                if (error) {
                    mfKLog(@"CloudKit fetch error: %@", error);
                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"获取失败"
                                                                                   message:[NSString stringWithFormat:@"%@", error.localizedDescription]
                                                                            preferredStyle:UIAlertControllerStyleAlert];
                    [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
                    mfPresentOnPanelVC(alert);
                    return;
                }
                
                if (!recordID) {
                    mfKLog(@"No recordID returned");
                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"获取失败"
                                                                                   message:@"未返回 Record ID (可能未登录 iCloud)"
                                                                            preferredStyle:UIAlertControllerStyleAlert];
                    [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
                    mfPresentOnPanelVC(alert);
                    return;
                }
                
                NSString *recordName = recordID.recordName;
                mfKLog(@"Got iCloud Record ID: %@", recordName);
                
                [[UIPasteboard generalPasteboard] setString:recordName];
                
                UIAlertController *result = [UIAlertController alertControllerWithTitle:@"iCloud Record ID"
                                                                                message:[NSString stringWithFormat:@"App: %@\nContainer: %@\n\n%@", appName ?: @"未知", containerIdentifier ?: @"默认", recordName]
                                                                         preferredStyle:UIAlertControllerStyleAlert];
                [result addAction:[UIAlertAction actionWithTitle:@"再次复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                    [[UIPasteboard generalPasteboard] setString:recordName];
                }]];
                [result addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
                mfPresentOnPanelVC(result);
            });
        }];
    });
}

// 入口：自动检测当前 App 的容器并查询
void mfFetchCloudKitRecordIDAuto(void) {
    mfKLog(@"mfFetchCloudKitRecordIDAuto called");
    
    NSString *bundleID = nil;
    NSString *appName = nil;
    NSArray *containers = mfGetFrontmostAppContainerIdentifiers(&bundleID, &appName);
    
    if (!containers || containers.count == 0) {
        mfKLog(@"No iCloud containers found for frontmost app, fallback to default");
        // 回退到默认容器
        mfFetchCloudKitRecordIDForContainer(nil, @"(默认容器)");
        return;
    }
    
    if (containers.count == 1) {
        // 只有一个容器，直接查
        mfKLog(@"Single container found: %@", containers[0]);
        mfFetchCloudKitRecordIDForContainer(containers[0], appName);
        return;
    }
    
    // 多个容器，让用户选
    mfKLog(@"Multiple containers found: %@", containers);
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"选择 iCloud 容器"
                                                                   message:[NSString stringWithFormat:@"App: %@ (%@)\n发现 %lu 个 iCloud 容器", appName ?: @"未知", bundleID ?: @"", (unsigned long)containers.count]
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    for (NSString *containerID in containers) {
        [alert addAction:[UIAlertAction actionWithTitle:containerID style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            mfFetchCloudKitRecordIDForContainer(action.title, appName);
        }]];
    }
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    mfPresentOnPanelVC(alert);
}

// ====== 面板页面 ======

// 显示 Keychain 列表
static void mfShowKeychainListPage(void) {
    mfKLog(@"mfShowKeychainListPage called");
    UIView *page = mfMakePage(@"Keychain 列表", YES);
    
    // 先显示加载中
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
    spinner.center = CGPointMake(g_mfCardW / 2, g_mfCardH / 2);
    spinner.hidesWhenStopped = YES;
    [page addSubview:spinner];
    [spinner startAnimating];
    
    UILabel *loadingLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, spinner.center.y + 30, g_mfCardW - 40, 20)];
    loadingLabel.text = @"查询 Keychain 中...";
    loadingLabel.textAlignment = NSTextAlignmentCenter;
    loadingLabel.textColor = [UIColor secondaryLabelColor];
    loadingLabel.font = [UIFont systemFontOfSize:14];
    [page addSubview:loadingLabel];
    
    mfPushPage(page);
    
    // 后台查询
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray *items = mfGetKeychainItems();
        mfKLog(@"list page query done: %lu items", (unsigned long)items.count);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            // 移除加载指示器
            [spinner stopAnimating];
            [spinner removeFromSuperview];
            [loadingLabel removeFromSuperview];
            
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
        });
    });
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
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"获取 iCloud ID", @"☁️", @selector(mfFetchCloudKitRecordIDAuto), NO, nil);
    gy = mfGridButton(page, 16, gy, gw, @"导出到剪贴板", @"📤", @selector(mfShowCopyAction), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"从剪贴板恢复", @"📥", @selector(mfShowRestorePrompt), NO, nil);
    
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
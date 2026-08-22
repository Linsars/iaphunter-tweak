// MFKeychainManager.m — Keychain 可视化/备份/恢复模块
// 面板页实现 (类似 Product 页)

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CloudKit/CloudKit.h>
#import "MFPanel.h"
#import "LSApplicationProxy.h"

// SecTask 私有 API 声明 (Security framework 内，iOS 未公开头文件)
typedef struct CF_BRIDGED_TYPE(id) OpaqueSecTaskRef *SecTaskRef;
extern SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task, CFStringRef entitlement, CFErrorRef *error);

extern UIViewController *g_mfPanelRootVC;
extern void mfLog(NSString *fmt, ...);  // 使用面板统一日志

// ====== 工具函数 ======
#define MFKEYCHAIN_VERSION @"1.5.0"

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
// 关键：tweak 注入到每个 App 进程，直接用 SecTask 读自己的 Entitlements (内核级)
// outHasKVS: 返回是否声明了 ubiquity-kvstore (iCloud 键值存储)
static NSArray *mfGetFrontmostAppContainerIdentifiers(NSString **outBundleID, NSString **outAppName, BOOL *outHasKVS) {
    mfKLog(@"mfGetFrontmostAppContainerIdentifiers called (SecTask method)");
    
    // 我们就在目标 App 进程里
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    mfKLog(@"Current app bundleID: %@", bundleID);
    
    if (!bundleID || [bundleID hasPrefix:@"com.apple."]) {
        mfKLog(@"Invalid or system bundleID");
        return nil;
    }
    
    if (outBundleID) *outBundleID = bundleID;
    
    // 用 SecTask 直接从内核读当前进程的 Entitlements
    @try {
        SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
        if (!task) {
            mfKLog(@"SecTaskCreateFromSelf failed");
            return nil;
        }
        
        // 检测 ubiquity-kvstore (iCloud 键值存储)
        if (outHasKVS) {
            CFTypeRef kvsRef = SecTaskCopyValueForEntitlement(
                task,
                (__bridge CFStringRef)@"com.apple.developer.ubiquity-kvstore-identifier",
                NULL
            );
            *outHasKVS = (kvsRef != NULL);
            mfKLog(@"Has KVS entitlement: %@", kvsRef ? @"YES" : @"NO");
            if (kvsRef) CFRelease(kvsRef);
        }
        
        CFTypeRef containersRef = SecTaskCopyValueForEntitlement(
            task,
            (__bridge CFStringRef)@"com.apple.developer.icloud-container-identifiers",
            NULL
        );
        CFRelease(task);
        
        if (!containersRef) {
            mfKLog(@"No icloud-container-identifiers entitlement found");
            return nil;
        }
        
        NSArray *containerIDs = (__bridge_transfer NSArray *)containersRef;
        mfKLog(@"App %@ containers: %@", bundleID, containerIDs);
        
        // 尝试拿 App 名称
        NSDictionary *infoDict = [[NSBundle mainBundle] infoDictionary];
        NSString *appName = infoDict[@"CFBundleDisplayName"] ?: infoDict[@"CFBundleName"] ?: bundleID;
        if (outAppName) *outAppName = appName;
        
        return containerIDs;
    } @catch (NSException *e) {
        mfKLog(@"Exception: %@", e);
        return nil;
    }
}

// 核心查询函数：查单个容器的 Record ID 并回调
// 关键：App 无 iCloud entitlement 时 CKContainer API 会抛异常，必须 @try 包裹
static void mfQueryRecordIDForContainer(NSString *containerIdentifier,
                                         void (^completion)(NSString *recordName, NSError *error)) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        CKContainer *container = nil;
        NSString *fetchError = nil;
        
        @try {
            if (containerIdentifier && ![containerIdentifier isEqualToString:@"(默认容器)"]) {
                container = [CKContainer containerWithIdentifier:containerIdentifier];
            } else {
                container = [CKContainer defaultContainer];
            }
            if (!container) fetchError = @"CKContainer 为空";
        } @catch (NSException *e) {
            mfKLog(@"CKContainer exception: %@", e);
            fetchError = e.reason ?: @"无 iCloud 权限";
            container = nil;
        }
        
        if (!container) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(nil, [NSError errorWithDomain:@"MFCloudKit" code:-1 userInfo:@{NSLocalizedDescriptionKey: fetchError ?: @"无 iCloud 权限"}]);
            });
            return;
        }
        
        @try {
            [container fetchUserRecordIDWithCompletionHandler:^(CKRecordID *recordID, NSError *error) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    completion(recordID.recordName, error);
                });
            }];
        } @catch (NSException *e) {
            mfKLog(@"fetchUserRecordID exception: %@", e);
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(nil, [NSError errorWithDomain:@"MFCloudKit" code:-2 userInfo:@{NSLocalizedDescriptionKey: e.reason ?: @"查询异常"}]);
            });
        }
    });
}

// iCloud ID 列表页（类似 Keychain 查看列表）
static void mfShowICloudIDListPage(NSString *bundleID, NSString *appName, NSArray *containers, BOOL hasKVS) {
    mfKLog(@"mfShowICloudIDListPage called, %lu containers, kvs=%@", (unsigned long)containers.count, hasKVS ? @"YES" : @"NO");
    
    UIView *page = mfMakePage(@"iCloud ID 列表", YES);
    
    // 加载指示
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
    spinner.center = CGPointMake(g_mfCardW / 2, g_mfCardH / 2);
    spinner.hidesWhenStopped = YES;
    [page addSubview:spinner];
    [spinner startAnimating];
    
    UILabel *loadingLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, spinner.center.y + 30, g_mfCardW - 40, 20)];
    loadingLabel.text = @"查询 iCloud Record ID 中...";
    loadingLabel.textAlignment = NSTextAlignmentCenter;
    loadingLabel.textColor = [UIColor secondaryLabelColor];
    loadingLabel.font = [UIFont systemFontOfSize:14];
    [page addSubview:loadingLabel];
    
    mfPushPage(page);
    
    // ScrollView 预创建
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 40, g_mfCardW, g_mfCardH - 40)];
    sv.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [page addSubview:sv];
    
    __block CGFloat y = 12;
    __block NSInteger pendingCount = containers.count;
    
    // App 信息卡片（静态）
    UIView *infoCard = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 60)];
    infoCard.backgroundColor = [UIColor tertiarySystemBackgroundColor];
    infoCard.layer.cornerRadius = 8;
    UILabel *infoLabel = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, g_mfCardW - 48, 44)];
    infoLabel.text = [NSString stringWithFormat:@"📱 %@\n🆔 %@", appName ?: @"未知", bundleID ?: @""];
    infoLabel.font = [UIFont systemFontOfSize:13];
    infoLabel.textColor = [UIColor labelColor];
    infoLabel.numberOfLines = 0;
    [infoCard addSubview:infoLabel];
    [sv addSubview:infoCard];
    y += 68;
    
    // 分隔标题
    UILabel *sectionTitle = [[UILabel alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 24)];
    sectionTitle.text = [NSString stringWithFormat:@"iCloud 容器 (%lu)", (unsigned long)containers.count];
    sectionTitle.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    sectionTitle.textColor = [UIColor secondaryLabelColor];
    [sv addSubview:sectionTitle];
    y += 28;
    
    // KVS 状态行（如果声明了 ubiquity-kvstore）
    if (hasKVS) {
        UIView *kvsCell = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 56)];
        kvsCell.backgroundColor = [UIColor secondarySystemBackgroundColor];
        kvsCell.layer.cornerRadius = 8;
        
        UILabel *kvsTitle = [[UILabel alloc] initWithFrame:CGRectMake(12, 6, g_mfCardW - 48, 18)];
        kvsTitle.text = @"iCloud 键值存储 (KVS)";
        kvsTitle.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
        kvsTitle.textColor = [UIColor labelColor];
        [kvsCell addSubview:kvsTitle];
        
        UILabel *kvsStatus = [[UILabel alloc] initWithFrame:CGRectMake(12, 26, g_mfCardW - 48, 24)];
        kvsStatus.text = @"ℹ️ 已启用 NSUbiquitousKeyValueStore 小数据同步";
        kvsStatus.font = [UIFont systemFontOfSize:12];
        kvsStatus.textColor = [UIColor systemBlueColor];
        kvsStatus.numberOfLines = 2;
        [kvsCell addSubview:kvsStatus];
        
        [sv addSubview:kvsCell];
        y += 64;
    }
    
    // 为每个容器查询 Record ID
    for (NSString *containerID in containers) {
        // 占位 cell
        UIView *cell = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 72)];
        cell.backgroundColor = [UIColor secondarySystemBackgroundColor];
        cell.layer.cornerRadius = 8;
        
        UILabel *containerLabel = [[UILabel alloc] initWithFrame:CGRectMake(12, 6, g_mfCardW - 48, 18)];
        containerLabel.text = containerID;
        containerLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
        containerLabel.textColor = [UIColor labelColor];
        [cell addSubview:containerLabel];
        
        UILabel *statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(12, 26, g_mfCardW - 48, 40)];
        statusLabel.text = @"⏳ 查询中...";
        statusLabel.font = [UIFont systemFontOfSize:12];
        statusLabel.textColor = [UIColor secondaryLabelColor];
        statusLabel.numberOfLines = 2;
        [cell addSubview:statusLabel];
        
        objc_setAssociatedObject(cell, "containerID", containerID, OBJC_ASSOCIATION_RETAIN);
        objc_setAssociatedObject(cell, "statusLabel", statusLabel, OBJC_ASSOCIATION_RETAIN);
        
        // 点击复制 Record ID
        UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:g_mfCtrl action:@selector(mfCopyICloudRecordID:)];
        [cell addGestureRecognizer:tap];
        
        [sv addSubview:cell];
        y += 80;
        
        // 无 iCloud 容器的 App：直接显示最终状态，绝不碰 CloudKit
        // （无 entitlement 的进程调用 CKContainer API 会底层 abort，@try 拦不住）
        if ([containerID isEqualToString:@"(默认容器)"]) {
            statusLabel.text = @"🚫 该 App 未声明 iCloud 容器\n（未启用 iCloud capability，无法查询）";
            statusLabel.textColor = [UIColor systemGrayColor];
            pendingCount--;
            if (pendingCount <= 0) {
                [spinner stopAnimating];
                [spinner removeFromSuperview];
                [loadingLabel removeFromSuperview];
            }
            continue;
        }
        
        // 异步查询
        NSString *cid = containerID;
        mfQueryRecordIDForContainer(cid, ^(NSString *recordName, NSError *error) {
            UILabel *lbl = objc_getAssociatedObject(cell, "statusLabel");
            if (!lbl) return;
            
            if (error) {
                lbl.text = [NSString stringWithFormat:@"❌ %@", error.localizedDescription ?: @"查询失败"];
                lbl.textColor = [UIColor systemRedColor];
                mfKLog(@"Container %@ error: %@", cid, error);
            } else if (recordName) {
                lbl.text = [NSString stringWithFormat:@"🔑 %@", recordName];
                lbl.textColor = [UIColor systemGreenColor];
                objc_setAssociatedObject(cell, "recordID", recordName, OBJC_ASSOCIATION_RETAIN);
                mfKLog(@"Container %@ recordID: %@", cid, recordName);
            } else {
                lbl.text = @"⚠️ 未返回 Record ID";
                lbl.textColor = [UIColor systemOrangeColor];
            }
            
            pendingCount--;
            if (pendingCount <= 0) {
                [spinner stopAnimating];
                [spinner removeFromSuperview];
                [loadingLabel removeFromSuperview];
            }
            sv.contentSize = CGSizeMake(g_mfCardW, y + 20);
        });
    }
    
    sv.contentSize = CGSizeMake(g_mfCardW, y + 20);
}

// iCloud Record ID 复制 (从列表页点击 cell) - 导出函数
void mfCopyICloudRecordIDFromCell(UIViewController *vc, UIView *cell) {
    if (!cell) return;
    NSString *recordID = objc_getAssociatedObject(cell, "recordID");
    NSString *containerID = objc_getAssociatedObject(cell, "containerID");
    if (!recordID) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"提示"
                                                                       message:@"Record ID 尚未查询完成"
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
        mfPresentOnPanelVC(alert);
        return;
    }
    [[UIPasteboard generalPasteboard] setString:recordID];
    mfKLog(@"Copied iCloud Record ID: %@ (container: %@)", recordID, containerID);
    
    UIAlertController *toast = [UIAlertController alertControllerWithTitle:nil
                                                                   message:@"✅ 已复制 Record ID"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    mfPresentOnPanelVC(toast);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1.0 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [toast dismissViewControllerAnimated:YES completion:nil];
    });
}
void mfFetchCloudKitRecordIDAuto(void) {
    mfKLog(@"mfFetchCloudKitRecordIDAuto called");
    
    NSString *bundleID = nil;
    NSString *appName = nil;
    BOOL hasKVS = NO;
    NSArray *containers = mfGetFrontmostAppContainerIdentifiers(&bundleID, &appName, &hasKVS);
    
    if (!containers || containers.count == 0) {
        mfKLog(@"No iCloud containers found (kvs=%@), opening list page", hasKVS ? @"YES" : @"NO");
        // 无容器：不碰 CloudKit，列表页显示降级说明（v17 查询前拦截）
        NSMutableArray *arr = [NSMutableArray arrayWithObject:@"(默认容器)"];
        mfShowICloudIDListPage(bundleID ?: @"未知", appName ?: @"未知", arr, hasKVS);
        return;
    }
    
    mfKLog(@"Found %lu containers (kvs=%@), opening list page", (unsigned long)containers.count, hasKVS ? @"YES" : @"NO");
    mfShowICloudIDListPage(bundleID, appName, containers, hasKVS);
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
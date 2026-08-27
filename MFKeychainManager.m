// MFKeychainManager.m — Keychain 可视化/备份/恢复模块
// 面板页实现 (类似 Product 页)

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CloudKit/CloudKit.h>
#import <dlfcn.h>
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
static BOOL mfDeleteKeychainItemInternal(NSDictionary *item);
static void mfRefreshKeychainListIfVisible(void);

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

// 导出 Keychain -> Base64 JSON -> 粘贴板（提示全部用浮层 toast，不用弹窗）
static void mfCopyKeychainInBackground(void) {
    mfKLog(@"mfCopyKeychainInBackground START");
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        mfKLog(@"background queue: fetching items");
        NSArray *items = mfGetKeychainItems();
        if (items.count == 0) {
            mfKLog(@"no items to copy");
            dispatch_async(dispatch_get_main_queue(), ^{ mfToast(@"⚠️ 无 Keychain 项可导出"); });
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
                mfKLog(@"copy done -> toast");
                mfToast([NSString stringWithFormat:@"✅ 已复制到剪贴板 (%lu 项, %lu 字符)", (unsigned long)items.count, (unsigned long)base64.length]);
            });
        } @catch (NSException *e) {
            mfKLog(@"JSON serialization exception: %@", e);
            dispatch_async(dispatch_get_main_queue(), ^{ mfToast([NSString stringWithFormat:@"❌ 导出失败: %@", e.reason ?: @""]); });
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
            dispatch_async(dispatch_get_main_queue(), ^{ mfToast(@"❌ 输入为空"); });
            return;
        }
        
        NSData *jsonData = [[NSData alloc] initWithBase64EncodedString:base64 options:0];
        if (!jsonData) {
            mfKLog(@"Base64 decode failed, first 50 chars: %@", [base64 substringToIndex:MIN(50, base64.length)]);
            dispatch_async(dispatch_get_main_queue(), ^{ mfToast(@"❌ Base64 解码失败，请粘贴完整导出字符串"); });
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
                dispatch_async(dispatch_get_main_queue(), ^{ mfToast(@"❌ 无法解析输入：不是导出 JSON 也不是 Base64"); });
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
            
            // 单个 item 模式且无 account/service 时：拒绝（提示走面板内说明，不再弹输入窗）
            if (isSingleItem && (!item[(__bridge id)kSecAttrAccount] || !item[(__bridge id)kSecAttrService])) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    mfToast(@"❌ 单条 Base64 需要含 service/account（请粘贴导出 JSON 数组格式）");
                });
                return;
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
            mfToast([NSString stringWithFormat:@"✅ 恢复完成: 成功 %lu · 更新 %lu · 失败 %lu",
                     (unsigned long)successCount, (unsigned long)duplicateCount, (unsigned long)failCount]);
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
    
    dispatch_async(dispatch_get_main_queue(), ^{ mfToast(resultMsg); });
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
                dlopen("/System/Library/Frameworks/CloudKit.framework/CloudKit", RTLD_LAZY); // v2.3.2 惰性加载
                container = [(id)objc_getClass("CKContainer") containerWithIdentifier:containerIdentifier];
            } else {
                dlopen("/System/Library/Frameworks/CloudKit.framework/CloudKit", RTLD_LAZY);
                container = [(id)objc_getClass("CKContainer") defaultContainer];
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
        mfToast(@"⏳ Record ID 尚未查询完成");
        return;
    }
    [[UIPasteboard generalPasteboard] setString:recordID];
    mfKLog(@"Copied iCloud Record ID: %@ (container: %@)", recordID, containerID);
    mfToast(@"✅ 已复制 Record ID");
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

// Keychain 条目摘要（列表 cell 用）
static NSString *mfItemSummary(NSDictionary *item) {
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(无账号)";
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(无服务)";
    return [NSString stringWithFormat:@"%@ / %@", service, account];
}

// Keychain 列表控制器（UITableView + 系统左滑：复制/编辑/删除）—— 对齐捕获列表风格
@interface MFKeychainList : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (copy) NSArray *records;
// 指向宿主 page（swipe 删除后控制 reload；nil=纯 dump 只读模式）
@property (nonatomic, weak) UITableView *table;
@end
@implementation MFKeychainList
- (UITableView *)mfMakeTableInPage:(UIView *)page {
    UITableView *tb = [[UITableView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, g_mfCardH - 42) style:UITableViewStylePlain];
    tb.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    tb.dataSource = self;
    tb.delegate = self;
    tb.backgroundColor = UIColor.clearColor;
    tb.separatorColor = [UIColor separatorColor];
    [page addSubview:tb];
    self.table = tb;
    return tb;
}
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return (NSInteger)self.records.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *id_ = @"mfkeyrow";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:id_];
    if (!c) c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:id_];
    NSDictionary *item = self.records[ip.row];
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(无服务)";
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(无账号)";
    NSString *ag = item[(__bridge id)kSecAttrAccessGroup] ?: @"";
    NSData *data = item[(__bridge id)kSecValueData];
    c.textLabel.text = service;
    c.textLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    c.detailTextLabel.text = [NSString stringWithFormat:@"%@ · %lu B%s%@",
                              account, (unsigned long)data.length,
                              ag.length ? " · " : "", ag];
    c.detailTextLabel.font = [UIFont systemFontOfSize:10];
    c.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    c.backgroundColor = UIColor.clearColor;
    if (data.length > 512) c.detailTextLabel.textColor = [UIColor systemOrangeColor]; // 大数据视觉提示
    return c;
}
- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    mfShowKeychainDetail(self.records[ip.row]);
}
// 左滑：复制 / 编辑 / 删除
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tv trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSDictionary *item = self.records[ip.row];
    UIContextualAction *copyA = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"复制" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            NSData *data = item[(__bridge id)kSecValueData];
            if (data) {
                [[UIPasteboard generalPasteboard] setString:[data base64EncodedStringWithOptions:0]];
                mfKLog(@"copied item data (service=%@)", item[(__bridge id)kSecAttrService]);
            }
            done(YES);
        }];
    copyA.backgroundColor = [UIColor systemBlueColor];
    UIContextualAction *editA = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"编辑" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            mfShowKeychainDetailMode(item, YES);  // 直接进编辑模式
            done(YES);
        }];
    editA.backgroundColor = [UIColor systemOrangeColor];
    UIContextualAction *delA = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleDestructive
        title:@"删除" handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            BOOL ok = mfDeleteKeychainItemInternal(item);
            mfKLog(@"swipe delete: %@", ok ? @"OK" : @"FAIL");
            NSMutableArray *mut = [self.records mutableCopy];
            [mut removeObjectAtIndex:ip.row];
            self.records = mut;
            [tv deleteRowsAtIndexPaths:@[ip] withRowAnimation:UITableViewRowAnimationAutomatic];
            done(YES);
        }];
    delA.backgroundColor = [UIColor systemRedColor];
    return [UISwipeActionsConfiguration configurationWithActions:@[delA, editA, copyA]];
}
@end

// 显示 Keychain 列表（表格版，左滑复制/编辑/删除）
static void mfShowKeychainListPage(void) {
    mfKLog(@"mfShowKeychainListPage called");
    UIView *page = mfMakePage(@"Keychain 列表", YES);
    
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
    
    MFKeychainList *ctrl = [[MFKeychainList alloc] init];
    objc_setAssociatedObject(page, "mfkeylist", ctrl, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray *items = mfGetKeychainItems();
        mfKLog(@"list page query done: %lu items", (unsigned long)items.count);
        dispatch_async(dispatch_get_main_queue(), ^{
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
                return;
            }
            ctrl.records = items;
            [ctrl mfMakeTableInPage:page];
        });
    });
}

// ====== Keychain Dump（当前 App 取证：装破解版跑一次→dump 看假记录格式） ======

// 判断条目是否属于当前 app（accessGroup 通常为 TEAMID.bundleid，service 常用 bundleid 前缀）
static BOOL mfItemBelongsToApp(NSDictionary *item, NSString *bundleId) {
    if (bundleId.length == 0) return NO;
    NSString *ag = item[(__bridge id)kSecAttrAccessGroup] ?: @"";
    NSString *sv = item[(__bridge id)kSecAttrService] ?: @"";
    if ([ag rangeOfString:bundleId].location != NSNotFound) return YES;
    if ([sv rangeOfString:bundleId].location != NSNotFound) return YES;
    if ([ag hasSuffix:bundleId]) return YES;
    return NO;
}

// 条目 → JSON 可序列化（完整属性）
static NSDictionary *mfItemToDumpDict(NSDictionary *item) {
    NSData *data = item[(__bridge id)kSecValueData];
    return @{
        @"service": item[(__bridge id)kSecAttrService] ?: @"",
        @"account": item[(__bridge id)kSecAttrAccount] ?: @"",
        @"accessGroup": item[(__bridge id)kSecAttrAccessGroup] ?: @"",
        @"type": item[(__bridge id)kSecAttrType] ?: @"",
        @"dataBase64": data ? [data base64EncodedStringWithOptions:0] : @"",
        @"dataLength": @(data.length),
    };
}

// Dump 当前 App Keychain（消息提示 + 落盘 + 面板列表）
void mfDumpCurrentAppKeychain(void) {
    mfKLog(@"mfDumpCurrentAppKeychain called");
    NSString *bundleId = mfCurrentBundleId();
    if (bundleId.length == 0) {
        mfToast(@"⚠️ 无法确定当前前台 App");
        return;
    }
    mfKLog(@"dumping keychain for app: %@", bundleId);
    
    UIView *page = mfMakePage([NSString stringWithFormat:@"Dump %@", bundleId], YES);
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
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray *items = mfGetKeychainItems();
        NSMutableArray *matched = [NSMutableArray array];
        for (NSDictionary *it in items)
            if (mfItemBelongsToApp(it, bundleId)) [matched addObject:it];
        mfKLog(@"dump: total=%lu matched=%lu", (unsigned long)items.count, (unsigned long)matched.count);
        
        // 落盘 JSON（完整 dump，含全部条目 + 匹配标记）
        NSMutableArray *all = [NSMutableArray array];
        for (NSDictionary *it in items) {
            NSMutableDictionary *d = [mfItemToDumpDict(it) mutableCopy];
            d[@"belongsToApp"] = @(mfItemBelongsToApp(it, bundleId));
            [all addObject:d];
        }
        NSDictionary *dump = @{@"app": bundleId, @"dumpedAt": [NSDate date].description ?: @"", @"total": @(items.count), @"matched": @(matched.count), @"items": all};
        NSString *path = @"/var/mobile/Documents";
        [[NSFileManager defaultManager] createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *file = [NSString stringWithFormat:@"%@/minisfix_keychain_dump_%@.json", path, bundleId];
        NSData *json = [NSJSONSerialization dataWithJSONObject:dump options:NSJSONWritingPrettyPrinted error:nil];
        BOOL wrote = json && [json writeToFile:file atomically:YES];
        mfKLog(@"dump saved: %@ wrote=%d", file, wrote);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [spinner stopAnimating];
            [spinner removeFromSuperview];
            [loadingLabel removeFromSuperview];
            
            UILabel *hdr = [[UILabel alloc] initWithFrame:CGRectMake(12, 46, g_mfCardW - 24, 34)];
            hdr.text = [NSString stringWithFormat:@"总 %lu · 匹配 %lu%s%@",
                        (unsigned long)items.count, (unsigned long)matched.count,
                        wrote ? " · ✅ 已存 " : " · ⚠️ 存文件失败 ",
                        wrote ? file : @""];
            hdr.font = [UIFont systemFontOfSize:10];
            hdr.textColor = [UIColor secondaryLabelColor];
            hdr.numberOfLines = 3;
            [page addSubview:hdr];
            
            UIButton *copyAll = [UIButton buttonWithType:UIButtonTypeSystem];
            copyAll.frame = CGRectMake(12, 84, (g_mfCardW - 36) / 2, 34);
            [copyAll setTitle:@"📋 复制全部 JSON" forState:UIControlStateNormal];
            copyAll.titleLabel.font = [UIFont systemFontOfSize:12];
            copyAll.backgroundColor = [UIColor secondarySystemBackgroundColor];
            copyAll.layer.cornerRadius = 8;
            objc_setAssociatedObject(copyAll, "dumpJson", json ? json : [NSData data], OBJC_ASSOCIATION_RETAIN);
            [copyAll addTarget:g_mfCtrl action:@selector(mfCopyDumpJson:) forControlEvents:UIControlEventTouchUpInside];
            [page addSubview:copyAll];
            
            UIButton *copyMatched = [UIButton buttonWithType:UIButtonTypeSystem];
            copyMatched.frame = CGRectMake(24 + (g_mfCardW - 36) / 2, 84, (g_mfCardW - 36) / 2, 34);
            [copyMatched setTitle:@"📋 复制匹配 JSON" forState:UIControlStateNormal];
            copyMatched.titleLabel.font = [UIFont systemFontOfSize:12];
            copyMatched.backgroundColor = [UIColor secondarySystemBackgroundColor];
            copyMatched.layer.cornerRadius = 8;
            NSMutableArray *mp = [NSMutableArray array];
            for (NSDictionary *it in matched) [mp addObject:mfItemToDumpDict(it)];
            NSData *mjson = [NSJSONSerialization dataWithJSONObject:@{@"app": bundleId, @"items": mp} options:NSJSONWritingPrettyPrinted error:nil];
            objc_setAssociatedObject(copyMatched, "dumpJson", mjson ?: [NSData data], OBJC_ASSOCIATION_RETAIN);
            [copyMatched addTarget:g_mfCtrl action:@selector(mfCopyDumpJson:) forControlEvents:UIControlEventTouchUpInside];
            [page addSubview:copyMatched];
            
            if (matched.count == 0) {
                UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(20, 130, g_mfCardW - 40, 40)];
                label.text = @"无匹配条目（可切「全部」查看所有）";
                label.textAlignment = NSTextAlignmentCenter;
                label.textColor = [UIColor secondaryLabelColor];
                label.font = [UIFont systemFontOfSize:13];
                [page addSubview:label];
            }
            
            // 复用列表控制器（只读+复制模式：swipe 删除也保留，可顺手清理）
            MFKeychainList *ctrl = [[MFKeychainList alloc] init];
            ctrl.records = matched.count ? matched : items;
            ctrl.table = nil;
            UITableView *tb = [[UITableView alloc] initWithFrame:CGRectMake(0, 126, g_mfCardW, g_mfCardH - 126) style:UITableViewStylePlain];
            tb.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
            tb.dataSource = ctrl;
            tb.delegate = ctrl;
            tb.backgroundColor = UIColor.clearColor;
            objc_setAssociatedObject(page, "mfkeylist", ctrl, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            [page addSubview:tb];
        });
    });
}

// 复制 dump JSON（由按钮调用）
void mfCopyDumpJsonFromButton(UIButton *btn) {
    NSData *json = objc_getAssociatedObject(btn, "dumpJson");
    if (json.length) {
        [[UIPasteboard generalPasteboard] setString:[[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding]];
        mfKLog(@"copied dump JSON (%lu bytes)", (unsigned long)json.length);
    }
}

// ====== 详情页（面板式，替代弹窗） ======

static void mfShowKeychainDetailMode(NSDictionary *item, BOOL autoEdit);
static void mfKeychainEnterEdit(UIButton *btn);
static void mfKeychainSaveEdit(UIButton *btn);

static void mfDoSaveKeychainData(NSDictionary *item, NSData *newData, void (^done)(BOOL)) {
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    NSString *account = item[(__bridge id)kSecAttrAccount];
    NSString *service = item[(__bridge id)kSecAttrService];
    if (account) query[(__bridge id)kSecAttrAccount] = account;
    if (service) query[(__bridge id)kSecAttrService] = service;
    NSDictionary *attrs = @{(__bridge id)kSecValueData: newData};
    OSStatus st = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attrs);
    mfKLog(@"SecItemUpdate(%@) status=%d", service, (int)st);
    done(st == errSecSuccess);
}

// 详情面板：信息 + Base64/Hex/UTF8 查看 + 复制/编辑/删除
void mfShowKeychainDetail(NSDictionary *item) { mfShowKeychainDetailMode(item, NO); }

static void mfShowKeychainDetailMode(NSDictionary *item, BOOL autoEdit) {
    mfKLog(@"mfShowKeychainDetailMode called (autoEdit=%d) for account=%@", autoEdit, item[(__bridge id)kSecAttrAccount] ?: @"(nil)");
    UIView *page = mfMakePage(@"Keychain 详情", YES);
    NSString *service = item[(__bridge id)kSecAttrService] ?: @"(无服务)";
    NSString *account = item[(__bridge id)kSecAttrAccount] ?: @"(无账号)";
    NSString *ag = item[(__bridge id)kSecAttrAccessGroup] ?: @"(无)";
    NSDate *cd = item[(__bridge id)kSecAttrCreationDate];
    NSDate *md = item[(__bridge id)kSecAttrModificationDate];
    NSData *data = item[(__bridge id)kSecValueData];
    
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 42, g_mfCardW, g_mfCardH - 42)];
    sv.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [page addSubview:sv];
    
    CGFloat y = 12;
    // 信息卡
    UIView *infoCard = [[UIView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, 92)];
    infoCard.backgroundColor = [UIColor secondarySystemBackgroundColor];
    infoCard.layer.cornerRadius = 8;
    UILabel *sLabel = [[UILabel alloc] initWithFrame:CGRectMake(10, 6, g_mfCardW - 44, 16)];
    sLabel.text = [NSString stringWithFormat:@"服务: %@", service];
    sLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightMedium];
    UILabel *aLbl = [[UILabel alloc] initWithFrame:CGRectMake(10, 24, g_mfCardW - 44, 16)];
    aLbl.text = [NSString stringWithFormat:@"账号: %@", account];
    aLbl.font = [UIFont systemFontOfSize:11];
    UILabel *gLbl = [[UILabel alloc] initWithFrame:CGRectMake(10, 42, g_mfCardW - 44, 16)];
    gLbl.text = [NSString stringWithFormat:@"Group: %@", ag];
    gLbl.font = [UIFont systemFontOfSize:11];
    UILabel *tLbl = [[UILabel alloc] initWithFrame:CGRectMake(10, 60, g_mfCardW - 44, 26)];
    tLbl.text = [NSString stringWithFormat:@"数据 %lu B%@%@%@%@%@",
                 (unsigned long)data.length,
                 cd ? @"\n创建 " : @"", cd ? [cd descriptionWithLocale:nil] : @"",
                 md ? @"\n修改 " : @"", md ? [md descriptionWithLocale:nil] : @""];
    tLbl.font = [UIFont systemFontOfSize:9];
    tLbl.textColor = [UIColor secondaryLabelColor];
    tLbl.numberOfLines = 2;
    [infoCard addSubview:sLabel];
    [infoCard addSubview:aLbl];
    [infoCard addSubview:gLbl];
    [infoCard addSubview:tLbl];
    [sv addSubview:infoCard];
    y += 100;
    
    UITextView *dataView = [[UITextView alloc] initWithFrame:CGRectMake(12, y, g_mfCardW - 24, g_mfCardH - y - 110)];
    dataView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    dataView.layer.cornerRadius = 8;
    dataView.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    dataView.editable = NO;
    dataView.dataDetectorTypes = UIDataDetectorTypeNone;
    dataView.textColor = [UIColor labelColor];
    dataView.autoresizingMask = UIViewAutoresizingFlexibleHeight;
    [sv addSubview:dataView];
    
    NSData *displayData = data ?: [NSData data];
    // 默认显示 Base64
    NSString *b64 = [displayData base64EncodedStringWithOptions:0];
    dataView.text = b64.length > 4096 ? [[b64 substringToIndex:4096] stringByAppendingFormat:@"\n… (共 %lu 字符, 完整用复制)", (unsigned long)b64.length] : b64;
    
    // 数据视图模式切换：Base64 / Hex / UTF8 三按钮（走 g_mfCtrl 转发）
    NSArray *modes = @[@"Base64", @"Hex", @"UTF8"];
    CGFloat segW = (g_mfCardW - 24 - 12) / 3;
    for (NSUInteger mi = 0; mi < modes.count; mi++) {
        UIButton *mb = [UIButton buttonWithType:UIButtonTypeSystem];
        mb.frame = CGRectMake(12 + mi * (segW + 6), y, segW, 30);
        [mb setTitle:modes[mi] forState:UIControlStateNormal];
        mb.titleLabel.font = [UIFont systemFontOfSize:12];
        mb.backgroundColor = [UIColor secondarySystemBackgroundColor];
        mb.layer.cornerRadius = 6;
        objc_setAssociatedObject(mb, "mode", @(mi), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(mb, "data", displayData, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(mb, "dataView", dataView, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [mb addTarget:g_mfCtrl action:@selector(mfKeychainDataDisplay:) forControlEvents:UIControlEventTouchUpInside];
        [sv addSubview:mb];
    }
    y += 38;
    
    y += g_mfCardH - y - 110 + 4;
    
    // 底部按钮行（复制/编辑/删除 → g_mfCtrl 转发，与列表 swipe 动作一致）
    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    copyBtn.frame = CGRectMake(12, y, (g_mfCardW - 36 - 24) / 2, 36);
    [copyBtn setTitle:@"📋 复制数据" forState:UIControlStateNormal];
    copyBtn.titleLabel.font = [UIFont systemFontOfSize:13];
    copyBtn.backgroundColor = [UIColor secondarySystemBackgroundColor];
    copyBtn.layer.cornerRadius = 8;
    objc_setAssociatedObject(copyBtn, "data", displayData, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [copyBtn addTarget:g_mfCtrl action:@selector(mfCopyKeychainData:) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:copyBtn];
    
    UIButton *editBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    editBtn.frame = CGRectMake(28 + (g_mfCardW - 36 - 24) / 2, y, (g_mfCardW - 36 - 24) / 2, 36);
    [editBtn setTitle:@"✏️ 编辑数据" forState:UIControlStateNormal];
    editBtn.titleLabel.font = [UIFont systemFontOfSize:13];
    editBtn.backgroundColor = [UIColor secondarySystemBackgroundColor];
    editBtn.layer.cornerRadius = 8;
    objc_setAssociatedObject(editBtn, "item", item, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(editBtn, "dataView", dataView, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [editBtn addTarget:g_mfCtrl action:@selector(mfEditKeychainData:) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:editBtn];
    y += 44;
    
    UIButton *delBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    delBtn.frame = CGRectMake(12, y, g_mfCardW - 24, 36);
    [delBtn setTitle:@"🗑 删除条目" forState:UIControlStateNormal];
    [delBtn setTitleColor:[UIColor systemRedColor] forState:UIControlStateNormal];
    delBtn.titleLabel.font = [UIFont systemFontOfSize:13];
    delBtn.backgroundColor = [UIColor secondarySystemBackgroundColor];
    delBtn.layer.cornerRadius = 8;
    objc_setAssociatedObject(delBtn, "item", item, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [delBtn addTarget:g_mfCtrl action:@selector(mfDeleteKeychainItem:) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:delBtn];
    y += 44;
    
    sv.contentSize = CGSizeMake(g_mfCardW, y + 20);
    mfPushPage(page);
    if (autoEdit) mfKeychainEnterEdit(editBtn);  // 左滑「编辑」直接进入编辑模式
}

// 详情页 C 实现：模式切换（Base64/Hex/UTF8）
void mfKeychainDataDisplayFromButton(UIButton *btn) {
    NSInteger mode = [objc_getAssociatedObject(btn, "mode") integerValue];
    NSData *d = objc_getAssociatedObject(btn, "data");
    UITextView *dv = objc_getAssociatedObject(btn, "dataView");
    if (!dv || !d) return;
    if (mode == 0) {
        NSString *b = [d base64EncodedStringWithOptions:0];
        dv.text = b.length > 4096 ? [[b substringToIndex:4096] stringByAppendingFormat:@"\n… (共 %lu 字符, 完整用复制)", (unsigned long)b.length] : b;
    } else if (mode == 1) {
        const unsigned char *p = d.bytes;
        NSMutableString *h = [NSMutableString string];
        NSUInteger n = MIN(d.length, 2048);
        for (NSUInteger i = 0; i < n; i++) [h appendFormat:@"%02X ", p[i]];
        dv.text = d.length > 2048 ? [h stringByAppendingFormat:@"\n… (共 %lu 字节, 完整用复制)", (unsigned long)d.length] : h;
    } else {
        NSString *u = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        dv.text = u ?: @"(非 UTF8 可解析数据)";
    }
}

// 详情页 C 实现：复制数据（base64 全量）
void mfCopyKeychainDataFromDetailButton(UIButton *btn) {
    NSData *d = objc_getAssociatedObject(btn, "data");
    if (!d) return;
    [[UIPasteboard generalPasteboard] setString:[d base64EncodedStringWithOptions:0]];
    mfKLog(@"detail: copied %lu bytes", (unsigned long)d.length);
    mfToast(@"✅ 已复制数据 (Base64)");
}

// 详情页 C 实现：进入编辑模式（设置文本框可写）
static void mfKeychainEnterEdit(UIButton *btn) {
    NSDictionary *item = objc_getAssociatedObject(btn, "item");
    UITextView *dv = objc_getAssociatedObject(btn, "dataView");
    if (!item || !dv) { mfKLog(@"edit: missing assoc (item=%p dv=%p)", item, dv); return; }
    mfKLog(@"enter edit mode: service=%@", item[(__bridge id)kSecAttrService]);
    NSString *cur = objc_getAssociatedObject(btn, "origB64");
    if (!cur) {
        NSData *od = item[(__bridge id)kSecValueData];
        cur = od ? [od base64EncodedStringWithOptions:0] : @"";
        objc_setAssociatedObject(btn, "origB64", cur, OBJC_ASSOCIATION_COPY_NONATOMIC);
    }
    dv.editable = YES;
    dv.backgroundColor = [UIColor systemBackgroundColor];
    dv.text = cur;
    [dv becomeFirstResponder];
    [btn setTitle:@"💾 保存修改" forState:UIControlStateNormal];
    objc_setAssociatedObject(btn, "editing", @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    mfToast(@"粘贴新的 Base64 数据后点保存");
}

// 详情页 C 实现：保存编辑（base64 decode → SecItemUpdate）
static void mfKeychainSaveEdit(UIButton *btn) {
    NSDictionary *item = objc_getAssociatedObject(btn, "item");
    UITextView *dv = objc_getAssociatedObject(btn, "dataView");
    if (!item || !dv) { mfKLog(@"save: missing assoc"); return; }
    NSString *text = dv.text;
    text = [text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSData *newData = [[NSData alloc] initWithBase64EncodedString:text options:0];
    if (!newData) { mfKLog(@"save: base64 decode failed"); mfToast(@"⚠️ Base64 解码失败"); return; }
    BOOL ok = NO;
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    NSString *account = item[(__bridge id)kSecAttrAccount];
    NSString *service = item[(__bridge id)kSecAttrService];
    if (account) query[(__bridge id)kSecAttrAccount] = account;
    if (service) query[(__bridge id)kSecAttrService] = service;
    NSDictionary *attrs = @{(__bridge id)kSecValueData: newData};
    OSStatus st = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attrs);
    ok = (st == errSecSuccess);
    mfKLog(@"save: SecItemUpdate(service=%@) status=%d", service, (int)st);
    dv.editable = NO;
    dv.backgroundColor = [UIColor secondarySystemBackgroundColor];
    [dv resignFirstResponder];
    dv.text = [newData base64EncodedStringWithOptions:0];
    [btn setTitle:@"✏️ 编辑数据" forState:UIControlStateNormal];
    objc_setAssociatedObject(btn, "editing", @NO, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    mfToast(ok ? @"✅ 已保存" : @"❌ 保存失败");
}

// 详情页 C 实现：编辑/保存数据（第一次点=进入编辑，第二次点=保存）
void mfEditKeychainDataFromDetailButton(UIButton *btn) {
    BOOL editing = [objc_getAssociatedObject(btn, "editing") boolValue];
    if (!editing) mfKeychainEnterEdit(btn);
    else mfKeychainSaveEdit(btn);
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
            if (ok) {
                mfKLog(@"refreshing keychain pages");
                mfPopPage();                       // 离开详情/列表
                mfRefreshKeychainListIfVisible();  // 刷新可见列表（若有）
                mfToast(@"✅ 已删除");
            } else {
                mfToast(@"❌ 删除失败");
            }
        });
    }]];
    mfPresentOnPanelVC(alert);
}

// 刷新当前可见的 Keychain 列表（删除后同步）
static void mfRefreshKeychainListIfVisible(void) {
    for (UIView *v in g_mfPanelRootVC.view.subviews) {
        MFKeychainList *ctrl = objc_getAssociatedObject(v, "mfkeylist");
        if (ctrl && ctrl.table) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                NSArray *items = mfGetKeychainItems();
                dispatch_async(dispatch_get_main_queue(), ^{
                    ctrl.records = items;
                    [ctrl.table reloadData];
                    mfKLog(@"keychain list refreshed: %lu items", (unsigned long)items.count);
                });
            });
            return;
        }
    }
}

// 从粘贴板恢复（面板页：多行粘贴区 + 恢复按钮 + 状态行，无弹窗）
static void mfShowRestorePrompt(void) {
    mfKLog(@"mfShowRestorePrompt called (panel version)");
    UIView *page = mfMakePage(@"从剪贴板恢复", YES);
    
    UILabel *hint = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, g_mfCardW - 24, 32)];
    hint.text = @"粘贴「导出到剪贴板」生成的内容（Base64 JSON 数组）\n完成后浮层提示结果";
    hint.font = [UIFont systemFontOfSize:11];
    hint.textColor = [UIColor secondaryLabelColor];
    hint.numberOfLines = 2;
    [page addSubview:hint];
    
    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(12, 44, g_mfCardW - 24, g_mfCardH - 44 - 130)];
    tv.backgroundColor = [UIColor secondarySystemBackgroundColor];
    tv.layer.cornerRadius = 8;
    tv.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    tv.textColor = [UIColor labelColor];
    tv.autoresizingMask = UIViewAutoresizingFlexibleHeight;
    [page addSubview:tv];
    
    UILabel *stateLb = [[UILabel alloc] initWithFrame:CGRectMake(12, g_mfCardH - 60, g_mfCardW - 24, 20)];
    stateLb.text = @"";
    stateLb.font = [UIFont systemFontOfSize:11];
    stateLb.textColor = [UIColor secondaryLabelColor];
    [page addSubview:stateLb];
    
    UIButton *restoreBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    restoreBtn.frame = CGRectMake(12, g_mfCardH - 92, g_mfCardW - 24, 36);
    [restoreBtn setTitle:@"🚀 恢复" forState:UIControlStateNormal];
    restoreBtn.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightSemibold];
    restoreBtn.backgroundColor = [UIColor systemGreenColor];
    [restoreBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    restoreBtn.layer.cornerRadius = 8;
    objc_setAssociatedObject(restoreBtn, "textView", tv, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(restoreBtn, "resultLabel", stateLb, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [restoreBtn addTarget:g_mfCtrl action:@selector(mfDoRestoreFromPage:) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:restoreBtn];
    
    mfPushPage(page);
}

// 恢复按钮处理（页面版）
void mfDoRestoreFromPageButton(UIButton *btn) {
    UITextView *tv = objc_getAssociatedObject(btn, "textView");
    UILabel *rl = objc_getAssociatedObject(btn, "resultLabel");
    NSString *text = tv.text ? [tv.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] : @"";
    if (text.length == 0) {
        mfToast(@"❌ 输入为空");
        if (rl) rl.text = @"❌ 输入为空";
        return;
    }
    mfKLog(@"restore from page: input length=%lu", (unsigned long)text.length);
    if (rl) { rl.text = @"⏳ 后台恢复中…（完成见浮层提示）"; rl.textColor = [UIColor systemOrangeColor]; }
    mfRestoreKeychainInBackground(text);
}

// ====== 面板入口 ======

// Keychain 主页
void mfShowKeychainManagerPage(void) {
    mfKLog(@"mfShowKeychainManagerPage called");
    
    UIView *page = mfMakePage(@"Keychain 管理", YES);
    CGFloat gw = (g_mfCardW - 32 - 12) / 2;
    CGFloat gy = 48;
    
    gy = mfGridButton(page, 16, gy, gw, @"查看列表", @"📋", @selector(mfShowKeychainListPage), NO, nil);
    gy = mfGridButton(page, 16 + gw + 12, gy - 92, gw, @"Dump 当前 App", @"🔎", @selector(mfDumpCurrentApp), NO, nil);
    gy = mfGridButton(page, 16, gy, gw, @"获取 iCloud ID", @"☁️", @selector(mfFetchCloudKitRecordIDAuto), NO, nil);
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
// MFAppStoreSpoof.xm — AppStore 版本伪装（独立轻量 dylib）
// 用 Logos 语法，让 Theos 处理 hook 注入

#import <Foundation/Foundation.h>

static NSUserDefaults *prefs;

// ====== appstored: NSMutableURLRequest setValue:forHTTPHeaderField: hook ======
%group AppStoredHook

%hook NSMutableURLRequest

- (void)setValue:(NSString *)value forHTTPHeaderField:(NSString *)field {
    static NSString *g_spoofVersion = nil;
    static BOOL loaded = NO;
    if (!loaded) {
        loaded = YES;
        prefs = [[NSUserDefaults alloc] initWithSuiteName:@"dev.mineek.appstoretroller"];
        if ([prefs boolForKey:@"enabled"]) {
            g_spoofVersion = [[prefs stringForKey:@"iOSVersion"] copy];
        }
    }
    
    if (g_spoofVersion && [field isEqualToString:@"User-Agent"]) {
        NSString *url = [[self URL] absoluteString] ?: @"";
        if ([url containsString:@"WebObjects/MZBuy.woa/wa/buyProduct"]) {
            value = [value stringByReplacingOccurrencesOfString:@"iOS/.*? "
                                                     withString:[NSString stringWithFormat:@"iOS/%@ ", g_spoofVersion]
                                                       options:NSRegularExpressionSearch
                                                         range:NSMakeRange(0, value.length)];
        }
    }
    %orig;
}

%end

%end

// ====== installd: MIBundle isMinimumOSVersion hook ======
%group InstalldHook

%hook MIBundle

- (BOOL)isMinimumOSVersion:(id)arg1 applicableToOSVersion:(id)arg2 requiredOS:(id)arg3 error:(id *)arg4 {
    return YES;
}

%end

%end

// ====== ctor ======
%ctor {
    NSString *processName = [[NSProcessInfo processInfo] processName];
    
    if ([processName isEqualToString:@"appstored"]) {
        prefs = [[NSUserDefaults alloc] initWithSuiteName:@"dev.mineek.appstoretroller"];
        if (![prefs boolForKey:@"enabled"]) {
            return;
        }
        %init(AppStoredHook);
    } else if ([processName isEqualToString:@"installd"]) {
        %init(InstalldHook);
    }
}

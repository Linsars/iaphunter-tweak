// MFAppStoreSpoof.xm — AppStore 版本伪装（独立轻量 dylib，注入 appstored + installd）
// 参考 appstoretroller（github.com/mineek/appstoretroller）
// 不依赖 UIKit——只用 Foundation + CydiaSubstrate，daemon 里可加载

#import <Foundation/Foundation.h>

@interface MIBundle : NSObject
- (BOOL)isMinimumOSVersion:(id)arg1 applicableToOSVersion:(id)arg2 requiredOS:(id)arg3 error:(id *)arg4;
@end

static NSUserDefaults *prefs;

%hook NSMutableURLRequest

- (void)setValue:(NSString *)value forHTTPHeaderField:(NSString *)field {
    if ([field isEqualToString:@"User-Agent"]) {
        NSString *url = [self.URL absoluteString] ?: @"";
        if ([url containsString:@"WebObjects/MZBuy.woa/wa/buyProduct"]) {
            if ([prefs boolForKey:@"enabled"]) {
                NSString *version = [prefs stringForKey:@"iOSVersion"] ?: @"99.0.0";
                value = [value stringByReplacingOccurrencesOfString:@"iOS/.*? "
                                                         withString:[NSString stringWithFormat:@"iOS/%@ ", version]
                                                           options:NSRegularExpressionSearch
                                                             range:NSMakeRange(0, value.length)];
            }
        }
    }
    %orig(value, field);
}

%end

// 绕过安装版本检查——installd 安装 App 时检查 isMinimumOSVersion，返回 YES 跳过检查
%hook MIBundle

- (BOOL)isMinimumOSVersion:(id)arg1 applicableToOSVersion:(id)arg2 requiredOS:(id)arg3 error:(id *)arg4 {
    if ([prefs boolForKey:@"enabled"]) {
        return YES;
    }
    return %orig(arg1, arg2, arg3, arg4);
}

%end

%ctor {
    prefs = [[NSUserDefaults alloc] initWithSuiteName:@"dev.mineek.appstoretroller"];
    if (![prefs boolForKey:@"enabled"]) {
        return;
    }
    %init;
}

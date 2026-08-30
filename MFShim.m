// MFShim.m — 早注入导出 shim：满足 Zora 类 app 的 strong 缺符号
// 机制: DYLD_INSERT_LIBRARIES 先于主二进制链接; 导出缺符号名 → dyld 正常绑定
// 每个导出 = trampoline, ctor 时 dlsym iOS 17.0 等价实现并填槽
#include <dlfcn.h>
#include <stdint.h>
#import <Foundation/Foundation.h>

// ---- 槽表(ctor 填充) ----
static void *g_s0, *g_s1, *g_s2, *g_s3, *g_s4, *g_s5, *g_s6, *g_s7, *g_s8;
static void g_retNil(void) { __asm__ volatile("mov x0, #0\n mov x1, #0\n ret"); }

// ---- 裸导出: adrp+ldr 槽 → br x16, 保持全部参数/返回寄存器 ----
__attribute__((naked)) void shim0(void) __asm("_$s8StoreKit11TransactionV5OfferV11PaymentModeV9freeTrialAGvgZ");
__attribute__((naked)) void shim0(void) {
    __asm__ volatile("adrp x16, _g_s0@PAGE\n ldr x16, [x16, _g_s0@PAGEOFF]\n br x16");
}
__attribute__((naked)) void shim1(void) __asm("_$s8StoreKit11TransactionV5OfferV11PaymentModeVMa");
__attribute__((naked)) void shim1(void) {
    __asm__ volatile("adrp x16, _g_s1@PAGE\n ldr x16, [x16, _g_s1@PAGEOFF]\n br x16");
}
__attribute__((naked)) void shim2(void) __asm("_$s8StoreKit11TransactionV5OfferV11PaymentModeVMn");
__attribute__((naked)) void shim2(void) {
    __asm__ volatile("adrp x16, _g_s2@PAGE\n ldr x16, [x16, _g_s2@PAGEOFF]\n br x16");
}
__attribute__((naked)) void shim3(void) __asm("_$s8StoreKit11TransactionV5OfferV11PaymentModeVSQAAMc");
__attribute__((naked)) void shim3(void) {
    __asm__ volatile("adrp x16, _g_s3@PAGE\n ldr x16, [x16, _g_s3@PAGEOFF]\n br x16");
}
__attribute__((naked)) void shim4(void) __asm("_$s8StoreKit11TransactionV5OfferV11paymentModeAE07PaymentF0VSgvg");
__attribute__((naked)) void shim4(void) {
    __asm__ volatile("adrp x16, _g_s4@PAGE\n ldr x16, [x16, _g_s4@PAGEOFF]\n br x16");
}
__attribute__((naked)) void shim5(void) __asm("_$s8StoreKit11TransactionV5OfferVMa");
__attribute__((naked)) void shim5(void) {
    __asm__ volatile("adrp x16, _g_s5@PAGE\n ldr x16, [x16, _g_s5@PAGEOFF]\n br x16");
}
__attribute__((naked)) void shim6(void) __asm("_$s8StoreKit11TransactionV5OfferVMn");
__attribute__((naked)) void shim6(void) {
    __asm__ volatile("adrp x16, _g_s6@PAGE\n ldr x16, [x16, _g_s6@PAGEOFF]\n br x16");
}
// offer getter: 17.0 可能无等价 → 回退返 nil
__attribute__((naked)) void shim7(void) __asm("_$s8StoreKit11TransactionV5offerAC5OfferVSgvg");
__attribute__((naked)) void shim7(void) {
    __asm__ volatile("adrp x16, _g_s7@PAGE\n ldr x16, [x16, _g_s7@PAGEOFF]\n br x16");
}
// WindowGroup(id:title:lazyContent:) → 17.0 WindowGroup(id:content:), x2 闭包搬到 x1(丢 title)
__attribute__((naked)) void shim8(void) __asm("_$s7SwiftUI11WindowGroupV2id5title11lazyContentACyxGSSSg_AA4TextVSgxyctcfC");
__attribute__((naked)) void shim8(void) {
    __asm__ volatile("mov x1, x2\n adrp x16, _g_s8@PAGE\n ldr x16, [x16, _g_s8@PAGEOFF]\n br x16");
}

__attribute__((constructor)) static void mfshimCtor(void) {
    // 宽进严出: 提交路径注入, ctor 只在白名单 app 里真正干活
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (!bid || [bid.lowercaseString hasPrefix:@"com.apple."]) return;
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:
        @"/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist"] ?: @{};
    NSArray *list = d[@"mfCompatAppList"];
    if (![list isKindOfClass:[NSArray class]] || ![list containsObject:bid]) return;
    // 8 个 StoreKit: 17.0 等价名
    g_s0 = dlsym(RTLD_DEFAULT, "_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeV9freeTrialAGvgZ");
    g_s1 = dlsym(RTLD_DEFAULT, "_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeVMa");
    g_s2 = dlsym(RTLD_DEFAULT, "_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeVMn");
    g_s3 = dlsym(RTLD_DEFAULT, "_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeVSQAAMc");
    g_s4 = dlsym(RTLD_DEFAULT, "_$s8StoreKit7ProductV17SubscriptionOfferV11paymentModeAE07PaymentG0Vvg");
    g_s5 = dlsym(RTLD_DEFAULT, "_$s8StoreKit7ProductV17SubscriptionOfferVMa");
    g_s6 = dlsym(RTLD_DEFAULT, "_$s8StoreKit7ProductV17SubscriptionOfferVMn");
    g_s7 = dlsym(RTLD_DEFAULT, "_$s8StoreKit7ProductV18subscriptionOfferAC17SubscriptionOfferVSgvg");
    if (!g_s7) g_s7 = (void *)g_retNil;   // 无等价 → nil
    g_s8 = dlsym(RTLD_DEFAULT, "_$s7SwiftUI11WindowGroupV2id7contentACyxGSS_xyXEtcfC");
    if (!g_s8) g_s8 = (void *)g_retNil;
}

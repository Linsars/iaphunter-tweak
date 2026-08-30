// mfpatcher — iOS 26 SDK app 向下兼容 (通用)
// 兼容列表闸门: CodeDirectory identifier(bundle ID) → prefs 搜索 → 命中才 patch
// CS blob 全部 BIG-ENDIAN (Apple CodeSigning 规范), Mach-O load commands 原生 LE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach-o/loader.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/sysctl.h>

static inline uint32_t be32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

// ---- 重签: 只重算 __LINKEDIT 范围内的 page hash ----
// __TEXT 加密页 hash 保留原值(内核解密后自验), __DATA 未修改保留原值
// 只有 __LINKEDIT 被我们修改, 只需重签这些页
static int resign_pages(uint8_t *buf, long sz) {
    struct mach_header_64 *mh = (struct mach_header_64 *)buf;
    uint8_t *p = buf + sizeof(struct mach_header_64);
    uint32_t sig_off = 0;
    uint64_t le_start = 0, le_end = 0; // __LINKEDIT 文件范围
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        uint32_t cmd = *(uint32_t *)p;
        uint32_t cs  = *(uint32_t *)(p + 4);
        if (cmd == 0x1D) { memcpy(&sig_off, p + 8, 4); }
        if (cmd == 0x19) { // LC_SEGMENT_64
            char sn[17]; memcpy(sn, p + 8, 16); sn[16] = 0;
            if (strcmp(sn, "__LINKEDIT") == 0) {
                memcpy(&le_start, p + 40, 8); // fileoff
                memcpy(&le_end, p + 48, 8);   // filesize
                le_end += le_start;
            }
        }
        p += cs;
    }
    if (!sig_off || sig_off >= (uint32_t)sz || !le_start) return -1;
    uint32_t *sb = (uint32_t *)(buf + sig_off);
    if (be32(sb) != 0xFADE0CC0) return -1;
    uint32_t sb_count = be32(sb + 2);
    for (uint32_t i = 0; i < sb_count; i++) {
        uint32_t type = be32(sb + 3 + i*2);
        uint32_t off  = be32(sb + 3 + i*2 + 1);
        if (type != 0) continue;
        uint8_t *cd = (uint8_t *)sb + off;
        uint32_t hashOff  = be32(cd + 16);
        uint32_t nSlots   = be32(cd + 28);
        uint32_t codeLim  = be32(cd + 32);
        uint32_t hashSize = be32(cd + 36);
        uint8_t  psLog2   = *(cd + 42);
        if (hashSize != 32 || !nSlots || !codeLim || codeLim > (uint32_t)sz) return -1;
        uint32_t ps = 1 << psLog2;
        uint8_t *hashes = cd + hashOff;
        int recalc = 0;
        for (uint32_t s = 0; s < nSlots; s++) {
            uint32_t o = s * ps;
            if (o >= codeLim) break;
            // 只重签 __LINKEDIT 范围内的页
            if (o >= le_start && o < le_end) {
                uint32_t l = (o + ps > codeLim) ? (codeLim - o) : ps;
                CC_SHA256(buf + o, l, hashes + s * hashSize);
                recalc++;
            }
            // __TEXT/__DATA 页 hash 保留原值(内核解密后自验)
        }
        return recalc > 0 ? 0 : -1;
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <binary>\n", argv[0]); return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 8192) { fclose(f); return 0; }
    uint8_t *buf = malloc(sz);
    if (!buf || fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return 1; }
    fclose(f);

    struct mach_header_64 *mh = (struct mach_header_64 *)buf;
    if (mh->magic != MH_MAGIC_64 || mh->filetype != MH_EXECUTE) { free(buf); return 0; }

    // ---- minos 启发式: binary minos > 当前 OS → 可能有缺符号 → weakify ----
    // 不依赖兼容列表, 不依赖 prefs, 不依赖任何 UI 状态
    uint32_t cur_os = 17;
    char osbuf[16] = {0};
    {
        size_t oslen = sizeof(osbuf);
        if (sysctlbyname("kern.osproductversion", osbuf, &oslen, NULL, 0) == 0)
            cur_os = (uint32_t)atoi(osbuf);
    }
    uint32_t bin_minos = 0;
    uint8_t *bp = buf + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        uint32_t cmd = *(uint32_t *)bp;
        uint32_t cs  = *(uint32_t *)(bp + 4);
        if (cmd == 0x32) { bin_minos = *(uint32_t *)(bp + 12); break; }
        bp += cs;
    }
    { int mj=0,mn=0; sscanf(osbuf, "%d.%d", &mj, &mn); cur_os = ((uint32_t)mj<<16)|((uint32_t)mn<<8); }
    fprintf(stderr, "mfpatcher: bin_minos=0x%08X cur_os=0x%08X\n", bin_minos, cur_os);
    if (bin_minos == 0 || bin_minos <= cur_os) {
        fprintf(stderr, "mfpatcher: minos<=cur, skip\n");
        free(buf);
        return 0;
    }
    fprintf(stderr, "mfpatcher: minos>cur, patching\n");

    // ---- LC_DYLD_CHAINED_FIXUPS (native LE) ----
    uint32_t cf_off = 0;
    uint8_t *q = buf + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        uint32_t cmd = *(uint32_t *)q;
        uint32_t cs  = *(uint32_t *)(q + 4);
        if (cmd == 0x80000034) { memcpy(&cf_off, q + 8, 4); break; }
        q += cs;
    }
    if (!cf_off) { free(buf); return 0; }

    uint32_t *fh = (uint32_t *)(buf + cf_off);
    uint32_t imports_off = fh[2], imports_count = fh[4], imports_fmt = fh[5];
    if (imports_fmt != 1 || !imports_count || imports_count > 100000) { free(buf); return 0; }

    uint32_t *imports = (uint32_t *)(buf + cf_off + imports_off);

    // 1. weakify ALL imports (通用安全网)  2. 已知 iOS 26 SDK 符号改名到 17.0 (dyld 直接解析)
    static const char *kRename[][2] = {
        {"_$s8StoreKit11TransactionV5OfferV11PaymentModeV9freeTrialAGvgZ","_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeV9freeTrialAGvgZ"},
        {"_$s8StoreKit11TransactionV5OfferV11PaymentModeVMa","_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeVMa"},
        {"_$s8StoreKit11TransactionV5OfferV11PaymentModeVMn","_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeVMn"},
        {"_$s8StoreKit11TransactionV5OfferV11PaymentModeVSQAAMc","_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeVSQAAMc"},
        {"_$s8StoreKit11TransactionV5OfferV11paymentModeAE07PaymentF0VSgvg","_$s8StoreKit7ProductV17SubscriptionOfferV11paymentModeAE07PaymentG0Vvg"},
        {"_$s8StoreKit11TransactionV5OfferVMa","_$s8StoreKit7ProductV17SubscriptionOfferVMa"},
        {"_$s8StoreKit11TransactionV5OfferVMn","_$s8StoreKit7ProductV17SubscriptionOfferVMn"},
        {"_$s8StoreKit11TransactionV5offerAC5OfferVSgvg","_$s8StoreKit7ProductV18subscriptionOfferAC17SubscriptionOfferVSgvg"},
        {"_$s7SwiftUI11WindowGroupV2id5title11lazyContentACyxGSSSg_AA4TextVSgxyctcfC","_$s7SwiftUI11WindowGroupV2id7contentACyxGSS_xyXEtcfC"},
    };
    int nrename = sizeof(kRename)/sizeof(kRename[0]);
    char *symPool = (char *)(buf + cf_off + fh[3]);
    uint32_t pool_end = 0;
    for (uint32_t i = 0; i < imports_count; i++) {
        uint32_t no = imports[i] >> 9;
        if (cf_off + fh[3] + no >= (uint32_t)sz) continue;
        uint32_t e = no + strlen(symPool + no) + 1;
        if (e > pool_end) pool_end = e;
    }
    pool_end = (pool_end + 7) & ~7;
    int weakified = 0, renamed = 0;
    for (uint32_t i = 0; i < imports_count; i++) {
        uint32_t v = imports[i];
        uint32_t no = v >> 9;
        const char *name = symPool + no;
        int matched = -1;
        for (int t = 0; t < nrename; t++) { if (strcmp(name, kRename[t][0]) == 0) { matched = t; break; } }
        if (matched >= 0) {
            uint32_t nlen = strlen(kRename[matched][1]) + 1;
            if (cf_off + fh[3] + pool_end + nlen < indirect_off) {
                strcpy(symPool + pool_end, kRename[matched][1]);
                imports[i] = (v & 0x1FF) | (1 << 8) | (pool_end << 9);
                pool_end += nlen;
                renamed++; weakified++;
                continue;
            }
        }
        if (!((v >> 8) & 1)) { imports[i] = v | (1 << 8); weakified++; }
    }
    fprintf(stderr, "mfpatcher: weakified=%d renamed=%d/%d\n", weakified, renamed, nrename);

    if (weakified > 0) {
        resign_pages(buf, sz);
        f = fopen(argv[1], "wb");
        if (!f) { free(buf); return 1; }
        fwrite(buf, 1, sz, f); fclose(f);
        fprintf(stderr, "mfpatcher: patched %s\n", argv[1]);
    }
    free(buf);
    return 0;
}

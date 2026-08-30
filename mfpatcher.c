// mfpatcher — iOS 26 SDK app 向下兼容二进制补丁
// 1. imports pool 里 17.5+ only 符号 → 追加 17.0 等价名到 symbols pool + 改 name_offset
// 2. 重算 CodeDirectory page hashes (re-sign)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach-o/loader.h>
#include <CommonCrypto/CommonDigest.h>

static const char *kRename[][2] = {
    {"_$s8StoreKit11TransactionV5OfferV11PaymentModeV9freeTrialAGvgZ",
     "_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeV9freeTrialAGvgZ"},
    {"_$s8StoreKit11TransactionV5OfferV11PaymentModeVMa",
     "_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeVMa"},
    {"_$s8StoreKit11TransactionV5OfferV11PaymentModeVMn",
     "_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeVMn"},
    {"_$s8StoreKit11TransactionV5OfferV11PaymentModeVSQAAMc",
     "_$s8StoreKit7ProductV17SubscriptionOfferV11PaymentModeVSQAAMc"},
    {"_$s8StoreKit11TransactionV5OfferV11paymentModeAE07PaymentF0VSgvg",
     "_$s8StoreKit7ProductV17SubscriptionOfferV11paymentModeAE07PaymentG0Vvg"},
    {"_$s8StoreKit11TransactionV5OfferVMa",
     "_$s8StoreKit7ProductV17SubscriptionOfferVMa"},
    {"_$s8StoreKit11TransactionV5OfferVMn",
     "_$s8StoreKit7ProductV17SubscriptionOfferVMn"},
    {"_$s8StoreKit11TransactionV5offerAC5OfferVSgvg",
     "_$s8StoreKit7ProductV18subscriptionOfferAC17SubscriptionOfferVSgvg"},
    {"_$s7SwiftUI11WindowGroupV2id5title11lazyContentACyxGSSSg_AA4TextVSgxyctcfC",
     "_$s7SwiftUI11WindowGroupV2id7contentACyxGSS_xyXEtcfC"},
};
#define NRENAME (sizeof(kRename)/sizeof(kRename[0]))

static int resign_pages(uint8_t *buf, long sz) {
    struct mach_header_64 *mh = (struct mach_header_64 *)buf;
    uint8_t *p = buf + sizeof(struct mach_header_64);
    uint32_t sig_off = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        uint32_t cmd = *(uint32_t *)p;
        uint32_t cs  = *(uint32_t *)(p + 4);
        if (cmd == 0x1D) { memcpy(&sig_off, p + 8, 4); break; }
        p += cs;
    }
    if (!sig_off || sig_off >= (uint32_t)sz) return -1;
    uint32_t *sb = (uint32_t *)(buf + sig_off);
    if (sb[0] != 0xFADE0CC0) return -1;
    uint32_t sb_count = sb[2];
    for (uint32_t i = 0; i < sb_count; i++) {
        uint32_t type = sb[3 + i*2], off = sb[3 + i*2 + 1];
        if (type != 0) continue;
        uint8_t *cd = (uint8_t *)sb + off;
        uint32_t hashOff  = *(uint32_t *)(cd + 16);
        uint32_t nSlots   = *(uint32_t *)(cd + 28);
        uint32_t codeLim  = *(uint32_t *)(cd + 32);
        uint32_t hashSize = *(uint32_t *)(cd + 36);
        uint8_t  psLog2   = *(cd + 42);
        if (hashSize != 32 || !nSlots || !codeLim || codeLim > (uint32_t)sz) return -1;
        uint32_t ps = 1 << psLog2;
        uint8_t *hashes = cd + hashOff;
        for (uint32_t s = 0; s < nSlots; s++) {
            uint32_t o = s * ps;
            if (o >= codeLim) break;
            uint32_t l = (o + ps > codeLim) ? (codeLim - o) : ps;
            CC_SHA256(buf + o, l, hashes + s * hashSize);
        }
        return 0;
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

    uint32_t cf_off = 0, indirect_off = 0;
    uint8_t *p = buf + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        uint32_t cmd = *(uint32_t *)p;
        uint32_t cs  = *(uint32_t *)(p + 4);
        if (cmd == 0x80000034 && !cf_off) memcpy(&cf_off, p + 8, 4);
        if (cmd == 0xB) memcpy(&indirect_off, p + 8 + 48, 4);
        p += cs;
    }
    if (!cf_off) { free(buf); return 0; }

    uint32_t *fh = (uint32_t *)(buf + cf_off);
    uint32_t imports_off = fh[2], symbols_off = fh[3], imports_count = fh[4], imports_fmt = fh[5];
    if (imports_fmt != 1 || !imports_count || imports_count > 100000) { free(buf); return 0; }

    uint32_t *imports = (uint32_t *)(buf + cf_off + imports_off);
    char *symPool = (char *)(buf + cf_off + symbols_off);

    uint32_t pool_end = 0;
    for (uint32_t i = 0; i < imports_count; i++) {
        uint32_t name_off = imports[i] >> 9;
        if (cf_off + symbols_off + name_off >= (uint32_t)sz) continue;
        uint32_t e = name_off + strlen(symPool + name_off) + 1;
        if (e > pool_end) pool_end = e;
    }
    pool_end = (pool_end + 7) & ~7;
    uint32_t pool_limit = indirect_off ? (indirect_off - cf_off - symbols_off) : (uint32_t)(sz - cf_off - symbols_off);

    int renamed = 0;
    for (uint32_t i = 0; i < imports_count; i++) {
        uint32_t v = imports[i];
        uint32_t name_off = v >> 9;
        if (cf_off + symbols_off + name_off >= (uint32_t)sz) continue;
        const char *name = symPool + name_off;
        for (unsigned t = 0; t < NRENAME; t++) {
            if (strcmp(name, kRename[t][0]) != 0) continue;
            uint32_t new_len = strlen(kRename[t][1]) + 1;
            if (pool_end + new_len > pool_limit) { fprintf(stderr, "mfpatcher: no space for %s\n", kRename[t][0]); continue; }
            strcpy(symPool + pool_end, kRename[t][1]);
            imports[i] = (v & 0x1FF) | (pool_end << 9);
            pool_end += new_len;
            renamed++;
            break;
        }
    }
    fprintf(stderr, "mfpatcher: renamed %d/%zu\n", renamed, NRENAME);

    // 只在真正改了 imports 才写回 + 重签 (修复: 不再碰无关 app 二进制)
    if (renamed > 0) {
        int resigned = resign_pages(buf, sz);
        fprintf(stderr, "mfpatcher: resign=%d\n", resigned);
        f = fopen(argv[1], "wb");
        if (!f) { free(buf); return 1; }
        fwrite(buf, 1, sz, f); fclose(f);
    }
    free(buf);
    return 0;
}

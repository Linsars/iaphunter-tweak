// mfpatcher — 扫描 app 二进制, 翻转 iOS 26 SDK strong 缺符号的 weak 位
// 用法: mfpatcher <binary_path>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach-o/loader.h>
#include <CommonCrypto/CommonDigest.h>

// ---- 重签: 重算 CodeDirectory page hashes ----
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
        if (type != 0) continue; // 只要 CodeDirectory
        uint8_t *cd = (uint8_t *)sb + off;
        uint32_t hashOff  = *(uint32_t *)(cd + 16);
        uint32_t nSlots   = *(uint32_t *)(cd + 28);
        uint32_t codeLim  = *(uint32_t *)(cd + 32);
        uint32_t hashSize = *(uint32_t *)(cd + 36);
        uint8_t  psLog2   = *(cd + 42);
        if (hashSize != 32 || !nSlots || !codeLim) return -1;
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

static const char *kTargets[] = {
    "_$s8StoreKit11TransactionV5OfferV11PaymentModeV9freeTrialAGvgZ",
    "_$s8StoreKit11TransactionV5OfferV11PaymentModeVMa",
    "_$s8StoreKit11TransactionV5OfferV11PaymentModeVMn",
    "_$s8StoreKit11TransactionV5OfferV11PaymentModeVSQAAMc",
    "_$s8StoreKit11TransactionV5OfferV11paymentModeAE07PaymentF0VSgvg",
    "_$s8StoreKit11TransactionV5OfferVMa",
    "_$s8StoreKit11TransactionV5OfferVMn",
    "_$s8StoreKit11TransactionV5offerAC5OfferVSgvg",
    "_$s7SwiftUI11WindowGroupV2id5title11lazyContentACyxGSSSg_AA4TextVSgxyctcfC",
};
#define NTGT (sizeof(kTargets)/sizeof(kTargets[0]))

static int patch_binary(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < (long)sizeof(struct mach_header_64)) { fclose(f); return -1; }
    uint8_t *buf = malloc(sz);
    if (!buf || fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return -1; }
    fclose(f);

    struct mach_header_64 *mh = (struct mach_header_64 *)buf;
    if (mh->magic != MH_MAGIC_64 || mh->filetype != MH_EXECUTE) { free(buf); return 0; }

    // 找 LC_DYLD_CHAINED_FIXUPS
    uint32_t cf_off = 0;
    uint8_t *p = buf + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        uint32_t cmd = *(uint32_t *)p;
        uint32_t cs  = *(uint32_t *)(p + 4);
        if (cmd == 0x80000034) { memcpy(&cf_off, p + 8, 4); break; }
        p += cs;
    }
    if (!cf_off || cf_off >= (uint32_t)sz) { free(buf); return 0; }

    // chained fixups header: fixups_version(4) starts_off(4) imports_off(4) symbols_off(4) imports_count(4) imports_format(4) symbols_format(4)
    uint32_t *fh = (uint32_t *)(buf + cf_off);
    uint32_t imports_off = fh[2], symbols_off = fh[3], imports_count = fh[4], imports_format = fh[5];
    if (imports_format != 1 || imports_count == 0 || imports_count > 100000) { free(buf); return 0; }

    uint32_t *imports = (uint32_t *)(buf + cf_off + imports_off);
    char *symPool = (char *)(buf + cf_off + symbols_off);

    int patched = 0;
    int dirty = 0;
    for (uint32_t i = 0; i < imports_count; i++) {
        uint32_t v = imports[i];
        if ((v >> 8) & 1) continue;
        uint32_t name_off = v >> 9;
        if (cf_off + symbols_off + name_off >= (uint32_t)sz) continue;
        const char *name = symPool + name_off;
        for (unsigned t = 0; t < NTGT; t++) {
            if (strcmp(name, kTargets[t]) == 0) {
                imports[i] = v | (1 << 8);
                patched++; dirty = 1;
                break;
            }
        }
    }

    if (dirty) {
        resign_pages(buf, sz);
        f = fopen(path, "wb");
        if (!f) { free(buf); return -1; }
        fwrite(buf, 1, sz, f); fclose(f);
        fprintf(stderr, "mfpatcher: weakified %d + resigned %s\n", patched, path);
    }
    free(buf);
    return dirty ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <binary>\n", argv[0]); return 1; }
    int r = patch_binary(argv[1]);
    return (r < 0) ? 1 : 0;
}

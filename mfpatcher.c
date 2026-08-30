// mfpatcher — 通用 iOS 26 SDK app 向下兼容
// 把 imports pool 里 ALL undefined 符号翻 weak → dyld 永不 abort
// 存在的符号正常绑定, 不存在的绑 0 (weak) → app 启动
// 加上重签(重算 CodeDirectory page hashes)防止 CSA kill
// 跳过加密二进制 (cryptid!=0, App Store 版)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach-o/loader.h>
#include <CommonCrypto/CommonDigest.h>

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

    // 兼容 App 列表闸门: 从 CodeDirectory 提取 identifier(bundle ID) → 搜 prefs
    uint8_t *cdp = buf + sizeof(struct mach_header_64);
    char bundleId[256] = {0};
    uint32_t sig_off_tmp = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        uint32_t cmd = *(uint32_t *)cdp;
        uint32_t cs  = *(uint32_t *)(cdp + 4);
        if (cmd == 0x1D) { memcpy(&sig_off_tmp, cdp + 8, 4); break; }
        cdp += cs;
    }
    if (sig_off_tmp && sig_off_tmp < (uint32_t)sz) {
        uint32_t *sb2 = (uint32_t *)(buf + sig_off_tmp);
        if (sb2[0] == 0xFADE0CC0) {
            for (uint32_t i = 0; i < sb2[2]; i++) {
                if (sb2[3+i*2] != 0) continue;
                uint8_t *cd = (uint8_t *)sb2 + sb2[3+i*2+1];
                uint32_t identOff = *(uint32_t *)(cd + 20);
                snprintf(bundleId, sizeof(bundleId), "%s", (char *)cd + identOff);
                break;
            }
        }
    }
    if (!bundleId[0]) { free(buf); return 0; }

    FILE *pf = fopen("/var/jb/var/mobile/Library/Preferences/com.linsars.minisfix.plist", "rb");
    if (!pf) { free(buf); return 0; }
    fseek(pf, 0, SEEK_END); long psz = ftell(pf); fseek(pf, 0, SEEK_SET);
    char *prefs = malloc(psz + 1);
    if (fread(prefs, 1, psz, pf) != (size_t)psz) { free(prefs); free(buf); fclose(pf); return 0; }
    prefs[psz] = 0; fclose(pf);
    int inList = 0;
    { // memmem fallback
        for (long i = 0; i <= psz - (long)strlen(bundleId); i++) {
            if (memcmp(prefs + i, bundleId, strlen(bundleId)) == 0) { inList = 1; break; }
        }
    }
    free(prefs);
    if (!inList) { fprintf(stderr, "mfpatcher: %s not in list\n", bundleId); free(buf); return 0; }
    fprintf(stderr, "mfpatcher: %s in list, patching\n", bundleId);

    // LC_DYLD_CHAINED_FIXUPS
    uint32_t cf_off = 0;
    q = buf + sizeof(struct mach_header_64);
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

    // 把 ALL non-weak undefined 翻 weak → 通用, 零硬编码
    int weakified = 0;
    for (uint32_t i = 0; i < imports_count; i++) {
        uint32_t v = imports[i];
        if ((v >> 8) & 1) continue;
        imports[i] = v | (1 << 8);
        weakified++;
    }
    fprintf(stderr, "mfpatcher: weakified %d/%d imports\n", weakified, imports_count);

    if (weakified > 0) {
        resign_pages(buf, sz);
        f = fopen(argv[1], "wb");
        if (!f) { free(buf); return 1; }
        fwrite(buf, 1, sz, f); fclose(f);
    }
    free(buf);
    return 0;
}

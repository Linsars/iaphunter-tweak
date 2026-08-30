// mfpatcher — 手动工具: weakify app imports pool + resign __LINKEDIT pages
// 用法: mfpatcher <binary_path> (root)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach-o/loader.h>
#include <CommonCrypto/CommonDigest.h>

static inline uint32_t be32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
}

static int resign_linkedit(uint8_t *buf, long sz) {
    struct mach_header_64 *mh = (struct mach_header_64 *)buf;
    uint8_t *p = buf + sizeof(struct mach_header_64);
    uint32_t sig_off = 0;
    uint64_t le_start = 0, le_end = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        uint32_t cmd = *(uint32_t *)p;
        uint32_t cs  = *(uint32_t *)(p + 4);
        if (cmd == 0x1D) memcpy(&sig_off, p + 8, 4);
        if (cmd == 0x19) {
            char sn[17]; memcpy(sn, p + 8, 16); sn[16] = 0;
            if (!strcmp(sn, "__LINKEDIT")) {
                memcpy(&le_start, p + 40, 8);
                memcpy(&le_end, p + 48, 8); le_end += le_start;
            }
        }
        p += cs;
    }
    if (!sig_off || sig_off >= (uint32_t)sz || !le_start) return -1;
    uint32_t *sb = (uint32_t *)(buf + sig_off);
    if (be32(sb) != 0xFADE0CC0) return -1;
    uint32_t cnt = be32(sb + 2);
    for (uint32_t i = 0; i < cnt; i++) {
        if (be32(sb + 3 + i*2) != 0) continue;
        uint8_t *cd = (uint8_t *)sb + be32(sb + 3 + i*2 + 1);
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
            if (o >= le_start && o < le_end) {
                uint32_t l = (o + ps > codeLim) ? (codeLim - o) : ps;
                CC_SHA256(buf + o, l, hashes + s * hashSize);
                recalc++;
            }
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

    // minos > 当前 OS → 可能缺符号 → weakify
    uint32_t cur_maj = 17, cur_min = 0;
    {
        char osbuf[16] = {0}; size_t oslen = sizeof(osbuf);
        if (sysctlbyname("kern.osproductversion", osbuf, &oslen, NULL, 0) == 0)
            sscanf(osbuf, "%u.%u", &cur_maj, &cur_min);
    }
    uint32_t bin_minos = 0;
    uint8_t *q = buf + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        uint32_t cmd = *(uint32_t *)q;
        uint32_t cs  = *(uint32_t *)(q + 4);
        if (cmd == 0x32) { bin_minos = *(uint32_t *)(q + 12); break; }
        q += cs;
    }
    uint32_t cur_ver = (cur_maj << 16) | (cur_min << 8);
    fprintf(stderr, "mfpatcher: minos=0x%08X cur=0x%08X\n", bin_minos, cur_ver);
    if (bin_minos == 0 || bin_minos <= cur_ver) { fprintf(stderr, "mfpatcher: skip\n"); free(buf); return 0; }

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
    int weakified = 0;
    for (uint32_t i = 0; i < imports_count; i++) {
        uint32_t v = imports[i];
        if ((v >> 8) & 1) continue;
        imports[i] = v | (1 << 8);
        weakified++;
    }
    fprintf(stderr, "mfpatcher: weakified %d/%d\n", weakified, imports_count);

    if (weakified > 0) {
        resign_linkedit(buf, sz);
        f = fopen(argv[1], "wb");
        if (!f) { free(buf); return 1; }
        fwrite(buf, 1, sz, f); fclose(f);
        fprintf(stderr, "mfpatcher: done %s\n", argv[1]);
    }
    free(buf);
    return 0;
}

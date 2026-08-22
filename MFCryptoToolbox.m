// MFCryptoToolbox.m — 解密工具 v2 (v1.8.0)
// 对标 ToolsEric UCPTCryptoToolboxVC (96 方法)，实现自研、零第三方依赖
// 能力：AES-CBC/ECB/CTR + MD5/SHA 家族 + HMAC + Base64/Hex/URL 编解码 + JWT 解码
// 输入格式解析(文本/hex/base64) + key/IV 自动归一化(hex→base64→utf8 逐级尝试)
// GCM/RSA/SM4 不做：GCM 需 CryptoKit(Swift-only)，RSA 无私钥场景无意义

#import "MFPanel.h"
#import <CommonCrypto/CommonCrypto.h>

#pragma mark - 算法表

typedef struct { int id; const char *name; int group; } MFCryptoAlgo;
// group: 0=对称(key+iv) 1=哈希 2=HMAC(key) 3=编解码
static const MFCryptoAlgo mfAlgos[] = {
    {0,  "AES-CBC",     0},
    {1,  "AES-ECB",     0},
    {2,  "AES-CTR",     0},
    {10, "MD5",         1},
    {11, "SHA1",        1},
    {12, "SHA256",      1},
    {13, "SHA512",      1},
    {20, "HMAC-SHA256", 2},
    {21, "HMAC-SHA1",   2},
    {22, "HMAC-MD5",    2},
    {30, "Base64 编码",  3},
    {31, "Base64 解码",  3},
    {32, "Hex 编码",     3},
    {33, "Hex 解码",     3},
    {34, "URL 编码",     3},
    {35, "URL 解码",     3},
    {40, "JWT 解码",     3},
};
static const int mfAlgoCount = sizeof(mfAlgos) / sizeof(mfAlgos[0]);

#pragma mark - 编解码基础

static NSData *mfCryptoUnhex(NSString *s) {
    NSMutableString *h = [s mutableCopy];
    [h replaceOccurrencesOfString:@" " withString:@"" options:0 range:NSMakeRange(0, h.length)];
    [h replaceOccurrencesOfString:@"\n" withString:@"" options:0 range:NSMakeRange(0, h.length)];
    if (!h.length || h.length % 2) return nil;
    NSMutableData *d = [NSMutableData dataWithCapacity:h.length / 2];
    char hex[3] = {0};
    for (NSUInteger i = 0; i + 1 < h.length; i += 2) {
        hex[0] = [h characterAtIndex:i]; hex[1] = [h characterAtIndex:i + 1];
        unsigned int byte;
        if (sscanf(hex, "%02x", &byte) != 1) return nil;
        unsigned char b = (unsigned char)byte;
        [d appendBytes:&b length:1];
    }
    return d;
}

static NSString *mfCryptoToHex(NSData *d) {
    if (!d.length) return @"";
    char *buf = malloc(d.length * 2 + 1);
    if (!buf) return @"";
    for (NSUInteger i = 0; i < d.length; i++) sprintf(buf + i * 2, "%02x", ((const unsigned char *)d.bytes)[i]);
    buf[d.length * 2] = 0;
    NSString *s = [NSString stringWithUTF8String:buf];
    free(buf);
    return s;
}

// key 归一化：hex(≥16字节且合法) → base64(≥16字节) → utf8 原文
static NSData *mfCryptoParseSecret(NSString *s) {
    s = [s stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!s.length) return nil;
    NSCharacterSet *nonHex = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"] invertedSet];
    if ([s rangeOfCharacterFromSet:nonHex].location == NSNotFound && s.length >= 32 && s.length % 2 == 0) {
        NSData *hd = mfCryptoUnhex(s);
        if (hd.length >= 16) return hd;
    }
    if (s.length % 4 == 0 && s.length >= 24) {
        NSData *b64 = [[NSData alloc] initWithBase64EncodedString:s options:NSDataBase64DecodingIgnoreUnknownCharacters];
        if (b64.length >= 16) return b64;
    }
    return [s dataUsingEncoding:NSUTF8StringEncoding];
}

// IV 归一化：不足补零、超长截断到 blockSize（对标 normalizedIV:blockSize:）
static NSData *mfCryptoNormalizeIV(NSString *s, NSUInteger blockLen) {
    NSMutableData *out = [NSMutableData dataWithLength:blockLen];
    memset(out.mutableBytes, 0, blockLen);
    NSData *iv = mfCryptoParseSecret(s ?: @"");
    if (iv.length) memcpy(out.mutableBytes, iv.bytes, MIN(iv.length, blockLen));
    return out;
}

// 输入解析：0=文本 1=hex 2=base64
static NSData *mfCryptoParseInput(NSString *text, NSInteger fmt) {
    if (!text.length) return nil;
    switch (fmt) {
        case 1: return mfCryptoUnhex(text);
        case 2: return [[NSData alloc] initWithBase64EncodedString:text options:NSDataBase64DecodingIgnoreUnknownCharacters];
        default: return [text dataUsingEncoding:NSUTF8StringEncoding];
    }
}

// 输出三视图：hex + base64 + UTF8 尝试（可打印比例 >70% 才显示文本视图）
static NSString *mfCryptoOutputViews(NSData *d) {
    if (!d.length) return @"(空)";
    NSMutableString *r = [NSMutableString stringWithFormat:@"HEX:\n%@\n\nBASE64:\n%@", mfCryptoToHex(d), [d base64EncodedStringWithOptions:0]];
    NSString *utf = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if (utf.length) {
        NSUInteger printable = 0;
        for (NSUInteger i = 0; i < utf.length && i < 200; i++)
            if ([[NSCharacterSet alphanumericCharacterSet] characterIsMember:[utf characterAtIndex:i]] ||
                [@"{}[]():;,.-_+/=?@#$%^&*!~'\"<>" containsString:[utf substringWithRange:NSMakeRange(i, 1)]]) printable++;
        if (printable * 10 >= MIN(utf.length, 200) * 7)
            [r appendFormat:@"\n\nUTF8:\n%@", utf.length > 800 ? [[utf substringToIndex:800] stringByAppendingString:@"…"] : utf];
    }
    return r;
}

#pragma mark - 运算核心

static NSData *mfCryptoHashData(NSData *in, int algo) {
    unsigned char buf[CC_SHA512_DIGEST_LENGTH];
    NSUInteger len = 0;
    switch (algo) {
        case 10: len = CC_MD5(in.bytes, (CC_LONG)in.length, buf); break;
        case 11: len = CC_SHA1(in.bytes, (CC_LONG)in.length, buf); break;
        case 12: len = CC_SHA256(in.bytes, (CC_LONG)in.length, buf); break;
        case 13: len = CC_SHA512(in.bytes, (CC_LONG)in.length, buf); break;
    }
    return len ? [NSData dataWithBytes:buf length:len] : nil;
}

static NSData *mfCryptoHmac(NSData *in, NSData *key, int algo) {
    CCHmacAlgorithm alg;
    NSUInteger dlen;
    switch (algo) {
        case 20: alg = kCCHmacAlgSHA256; dlen = CC_SHA256_DIGEST_LENGTH; break;
        case 21: alg = kCCHmacAlgSHA1;   dlen = CC_SHA1_DIGEST_LENGTH;   break;
        default: alg = kCCHmacAlgMD5;    dlen = CC_MD5_DIGEST_LENGTH;    break;
    }
    unsigned char buf[64];
    CCHmac(alg, key.bytes, key.length, in.bytes, in.length, buf);
    return [NSData dataWithBytes:buf length:dlen];
}

// 对称：CBC/ECB 用 PKCS7，CTR 无填充流式
static NSData *mfCryptoSymmetric(NSData *in, NSData *key, NSData *iv, int algo, BOOL encrypt, NSString **errOut) {
    if (key.length != 16 && key.length != 24 && key.length != 32) {
        *errOut = @"Key 须为 16/24/32 字节（输入框支持 hex/base64/utf8 自动识别）";
        return nil;
    }
    CCMode mode = algo == 0 ? kCCModeCBC : (algo == 1 ? kCCModeECB : kCCModeCTR);
    CCPaddingOptions pad = (algo == 2) ? ccNoPadding : ccPKCS7Padding;
    CCCryptorRef ref = NULL;
    CCCryptorStatus st = CCCryptorCreateWithMode(encrypt ? kCCEncrypt : kCCDecrypt, mode, kCCAlgorithmAES,
        pad, iv.length ? iv.bytes : NULL, key.bytes, key.length, NULL, 0, 0, &ref);
    if (st != kCCSuccess || !ref) { *errOut = [NSString stringWithFormat:@"初始化失败 status=%d", st]; return nil; }
    NSMutableData *out = [NSMutableData dataWithLength:in.length + kCCBlockSizeAES128 + 16];
    size_t moved = 0, total = 0;
    st = CCCryptorUpdate(ref, in.bytes, in.length, out.mutableBytes, out.length, &moved);
    total += moved;
    if (st == kCCSuccess) {
        st = CCCryptorFinal(ref, (char *)out.mutableBytes + total, out.length - total, &moved);
        total += moved;
    }
    CCCryptorRelease(ref);
    if (st != kCCSuccess) { *errOut = [NSString stringWithFormat:@"运算失败 status=%d（key 错误或数据非块对齐）", st]; return nil; }
    out.length = total;
    return out;
}

static NSString *mfCryptoJwtDecode(NSString *token) {
    token = [token stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSArray *parts = [token componentsSeparatedByString:@"."];
    if (parts.count < 2) return @"⚠️ JWT 格式错误（header.payload[.signature]）";
    NSMutableString *r = [NSMutableString string];
    NSArray *names = @[@"HEADER", @"PAYLOAD"];
    for (NSUInteger i = 0; i < 2 && i < parts.count; i++) {
        NSString *seg = parts[i];
        seg = [seg stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
        seg = [seg stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
        while (seg.length % 4) seg = [seg stringByAppendingString:@"="];
        NSData *d = [[NSData alloc] initWithBase64EncodedString:seg options:NSDataBase64DecodingIgnoreUnknownCharacters];
        NSString *json = d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
        [r appendFormat:@"【%@】\n%@\n\n", names[i], json ?: @"⚠️ 解码失败"];
    }
    if (parts.count > 2) [r appendFormat:@"【SIGNATURE】\n%@\n(签名校验需密钥)", parts[2]];
    return r;
}

#pragma mark - 执行分发

static NSString *mfCryptoExecute(int algo, NSInteger inFmt, BOOL encrypt,
                                 NSString *inputText, NSString *keyText, NSString *ivText) {
    NSData *in = mfCryptoParseInput(inputText, inFmt);
    if (!in.length && algo != 40) return @"⚠️ 输入为空或格式解析失败";

    // 编解码组
    switch (algo) {
        case 30: return mfCryptoOutputViews([[in base64EncodedStringWithOptions:0] dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data]);
        case 31: return mfCryptoOutputViews([[NSData alloc] initWithBase64EncodedString:[[NSString alloc] initWithData:in encoding:NSUTF8StringEncoding] ?: @"" options:NSDataBase64DecodingIgnoreUnknownCharacters] ?: [NSData data]);
        case 32: return mfCryptoToHex(in);
        case 33: return mfCryptoOutputViews(mfCryptoUnhex([[NSString alloc] initWithData:in encoding:NSUTF8StringEncoding] ?: @"") ?: [NSData data]);
        case 34: {
            NSString *s = [[NSString alloc] initWithData:in encoding:NSUTF8StringEncoding] ?: @"";
            return [s stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]] ?: @"⚠️ 编码失败";
        }
        case 35: {
            NSString *s = [[NSString alloc] initWithData:in encoding:NSUTF8StringEncoding] ?: @"";
            return [s stringByRemovingPercentEncoding] ?: @"⚠️ 解码失败";
        }
        case 40: return mfCryptoJwtDecode([[NSString alloc] initWithData:in encoding:NSUTF8StringEncoding] ?: @"");
    }

    // 哈希组
    if (algo >= 10 && algo <= 13) return mfCryptoOutputViews(mfCryptoHashData(in, algo));

    // HMAC 组
    if (algo >= 20 && algo <= 22) {
        NSData *key = mfCryptoParseSecret(keyText ?: @"");
        if (!key.length) return @"⚠️ 请填 Key";
        return mfCryptoOutputViews(mfCryptoHmac(in, key, algo));
    }

    // 对称组
    NSData *key = mfCryptoParseSecret(keyText ?: @"");
    if (!key.length) return @"⚠️ 请填 Key";
    NSData *iv = mfCryptoNormalizeIV(ivText, kCCBlockSizeAES128);
    NSString *err = nil;
    NSData *out = mfCryptoSymmetric(in, key, iv, algo, encrypt, &err);
    if (!out) return [NSString stringWithFormat:@"⚠️ %@", err ?: @"失败"];
    return mfCryptoOutputViews(out);
}

#pragma mark - 页面

void mfShowCryptoToolboxPage(void) {
    UIView *page = mfMakePage(@"🔐 解密工具箱", YES);
    CGFloat w = g_mfCardW;

    UITextView *input = [[UITextView alloc] initWithFrame:CGRectMake(12, 44, w - 24, 54)];
    input.font = [UIFont systemFontOfSize:12];
    input.backgroundColor = [UIColor secondarySystemBackgroundColor];
    input.layer.cornerRadius = 10;
    input.autocorrectionType = UITextAutocorrectionTypeNo;
    input.text = @"在此粘贴要处理的内容…";
    input.textColor = [UIColor placeholderTextColor];
    [page addSubview:input];

    UISegmentedControl *fmtSeg = [[UISegmentedControl alloc] initWithItems:@[@"文本", @"Hex", @"Base64"]];
    fmtSeg.frame = CGRectMake(12, 102, w - 24, 30);
    fmtSeg.selectedSegmentIndex = 0;
    fmtSeg.apportionsSegmentWidthsByContent = YES;
    [page addSubview:fmtSeg];

    UIButton *algoBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    algoBtn.frame = CGRectMake(12, 138, w - 24, 36);
    algoBtn.backgroundColor = [UIColor systemIndigoColor];
    algoBtn.layer.cornerRadius = 10;
    algoBtn.tintColor = UIColor.whiteColor;
    algoBtn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [algoBtn setTitle:@"算法: AES-CBC ▾" forState:UIControlStateNormal];
    objc_setAssociatedObject(algoBtn, "algo", @(0), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [page addSubview:algoBtn];

    UITextField *keyF = [[UITextField alloc] initWithFrame:CGRectMake(12, 180, w - 24, 34)];
    keyF.placeholder = @"Key（hex / base64 / 文本自动识别）";
    keyF.font = [UIFont systemFontOfSize:12];
    keyF.borderStyle = UITextBorderStyleRoundedRect;
    keyF.autocorrectionType = UITextAutocorrectionTypeNo;
    [page addSubview:keyF];

    UITextField *ivF = [[UITextField alloc] initWithFrame:CGRectMake(12, 218, w - 24, 34)];
    ivF.placeholder = @"IV / Nonce（不足补零，可空）";
    ivF.font = [UIFont systemFontOfSize:12];
    ivF.borderStyle = UITextBorderStyleRoundedRect;
    ivF.autocorrectionType = UITextAutocorrectionTypeNo;
    [page addSubview:ivF];

    UIButton *runBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    runBtn.frame = CGRectMake(12, 258, w - 24, 38);
    runBtn.backgroundColor = [UIColor systemGreenColor];
    runBtn.layer.cornerRadius = 10;
    runBtn.tintColor = UIColor.whiteColor;
    runBtn.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    [runBtn setTitle:@"▶ 执行" forState:UIControlStateNormal];
    [page addSubview:runBtn];

    UITextView *output = [[UITextView alloc] initWithFrame:CGRectMake(12, 302, w - 24, g_mfCardH - 352)];
    output.font = [UIFont fontWithName:@"Menlo-Regular" size:10] ?: [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    output.backgroundColor = [UIColor secondarySystemBackgroundColor];
    output.layer.cornerRadius = 10;
    output.editable = NO;
    [page addSubview:output];

    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    copyBtn.frame = CGRectMake(w - 92, g_mfCardH - 46, 80, 34);
    copyBtn.backgroundColor = [UIColor secondarySystemFillColor];
    copyBtn.layer.cornerRadius = 9;
    [copyBtn setTitle:@"📋 复制" forState:UIControlStateNormal];
    [page addSubview:copyBtn];

    objc_setAssociatedObject(page, "input", input, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "fmtSeg", fmtSeg, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "algoBtn", algoBtn, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "keyF", keyF, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "ivF", ivF, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(page, "output", output, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    [algoBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCryptoPickAlgo:") forControlEvents:UIControlEventTouchUpInside];
    [runBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCryptoRun:") forControlEvents:UIControlEventTouchUpInside];
    [copyBtn addTarget:g_mfCtrl action:NSSelectorFromString(@"mfCryptoCopy:") forControlEvents:UIControlEventTouchUpInside];

    mfPushPage(page);
}

// Ctrl 实现（MFPanel.m 转发到这些 C 函数）
void mfCryptoPickAlgoAction(UIButton *btn) {
    UIView *page = (UIView *)btn.superview;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"选择算法" message:nil preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray *groups = @[@[@"AES-CBC", @"AES-ECB", @"AES-CTR"],
                        @[@"MD5", @"SHA1", @"SHA256", @"SHA512"],
                        @[@"HMAC-SHA256", @"HMAC-SHA1", @"HMAC-MD5"],
                        @[@"Base64 编码", @"Base64 解码", @"Hex 编码", @"Hex 解码", @"URL 编码", @"URL 解码", @"JWT 解码"]];
    __block int idCursor = 0;
    for (NSArray *g in groups) {
        for (NSString *nm in g) {
            int aid = -1;
            for (int i = 0; i < mfAlgoCount; i++) if (!strcmp(mfAlgos[i].name, nm.UTF8String)) { aid = mfAlgos[i].id; break; }
            idCursor++;
            [sheet addAction:[UIAlertAction actionWithTitle:nm style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                UIButton *ab = objc_getAssociatedObject(page, "algoBtn");
                objc_setAssociatedObject(ab, "algo", @(aid), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                [ab setTitle:[NSString stringWithFormat:@"算法: %@ ▾", nm] forState:UIControlStateNormal];
            }]];
        }
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    UIViewController *presenter = g_mfPanelRootVC;
    while (presenter.presentedViewController && presenter.presentedViewController != presenter)
        presenter = presenter.presentedViewController;
    if (!presenter || !presenter.view.window)
        for (UIWindow *w2 in [UIApplication sharedApplication].windows)
            if (w2.isKeyWindow) { presenter = w2.rootViewController; break; }
    UIView *overlay = g_mfPanelOverlay;
    overlay.hidden = YES;
    sheet.popoverPresentationController.sourceView = btn;
    [presenter presentViewController:sheet animated:YES completion:^{
        overlay.hidden = NO; // action sheet 是浮层不占 presentation 层级，立即恢复
    }];
}

void mfCryptoRunAction(UIButton *btn) {
    UIView *page = (UIView *)btn.superview;
    UITextView *input = objc_getAssociatedObject(page, "input");
    UISegmentedControl *fmtSeg = objc_getAssociatedObject(page, "fmtSeg");
    UIButton *algoBtn = objc_getAssociatedObject(page, "algoBtn");
    UITextField *keyF = objc_getAssociatedObject(page, "keyF");
    UITextField *ivF = objc_getAssociatedObject(page, "ivF");
    UITextView *output = objc_getAssociatedObject(page, "output");
    if (!input || !output) return;

    int algo = [objc_getAssociatedObject(algoBtn, "algo") intValue];
    // 占位符文本当空处理
    NSString *txt = input.textColor == [UIColor placeholderTextColor] ? @"" : input.text;
    NSString *result = mfCryptoExecute(algo, fmtSeg.selectedSegmentIndex, YES, txt, keyF.text, ivF.text);
    output.text = result;
}

void mfCryptoCopyAction(UIButton *btn) {
    UIView *page = (UIView *)btn.superview;
    UITextView *output = objc_getAssociatedObject(page, "output");
    if (output.text.length) [UIPasteboard generalPasteboard].string = output.text;
}

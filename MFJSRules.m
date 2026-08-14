// MFJSRules.m — JS 规则引擎（借鉴 Inspecto CaptureScriptEngine 钩子模型）
// 用户写 .js 规则脚本，定义 onRequestHeaders/onResponseHeaders/onResponse 钩子
// 通过 JavaScriptCore 执行——链接 JavaScriptCore.framework
//
// 规则脚本格式（对齐 Inspecto 的 Capture.defineScript）：
//   Capture.defineScript({
//     match: { urls: ["*.example.com/*"], methods: ["POST"] },
//     onRequestHeaders(req) {
//       req.headers.set("X-Custom", "1");
//       return req;
//     },
//     onResponseHeaders(res) {
//       res.headers.set("X-Rewritten", "true");
//       return res;
//     }
//   });
//
// 提供的工具：Capture.base64.encode/decode, Capture.crypto.md5/sha256, Capture.log/info/error

#import "MFPanel.h"
#import <JavaScriptCore/JavaScriptCore.h>
#import <CommonCrypto/CommonCrypto.h>

static JSContext *g_jsCtx = nil;
static NSString *g_jsScript = nil;

#pragma mark - 工具函数（暴露给 JS）

static NSString *mfJSBase64Encode(NSString *s) {
    return [[s dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
}
static NSString *mfJSBase64Decode(NSString *s) {
    NSData *d = [[NSData alloc] initWithBase64EncodedString:s options:0];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : @"";
}
static NSString *mfJSMD5(NSString *s) {
    NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char buf[CC_MD5_DIGEST_LENGTH];
    CC_MD5(d.bytes, (CC_LONG)d.length, buf);
    NSMutableString *h = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) [h appendFormat:@"%02x", buf[i]];
    return h;
}
static NSString *mfJSSHA256(NSString *s) {
    NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char buf[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(d.bytes, (CC_LONG)d.length, buf);
    NSMutableString *h = [NSMutableString string];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [h appendFormat:@"%02x", buf[i]];
    return h;
}

#pragma mark - JS 引擎初始化

// 从 prefs 读规则脚本（面板"网络修改 → JS 规则"编辑保存）
static NSString *mfJSGetScript(void) {
    NSDictionary *prefs = mfPrefsDict();
    NSString *s = prefs[@"mfJSScript"];
    return s.length > 0 ? s : nil;
}

static void mfJSInitIfNeeded(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_jsCtx = [[JSContext alloc] init];
        g_jsCtx.exceptionHandler = ^(JSContext *ctx, JSValue *e) {
            mfLog(@"JS exception: %@", e);
        };

        // Capture 工具对象
        g_jsCtx[@"Capture"] = @{
            @"base64": @{
                @"encode": ^NSString *(NSString *s) { return mfJSBase64Encode(s); },
                @"decode": ^NSString *(NSString *s) { return mfJSBase64Decode(s); },
            },
            @"crypto": @{
                @"md5": ^NSString *(NSString *s) { return mfJSMD5(s); },
                @"sha256": ^NSString *(NSString *s) { return mfJSSHA256(s); },
            },
            @"log": ^(JSValue *v) { mfLog(@"JS log: %@", [v toString]); },
            @"info": ^(JSValue *v) { mfLog(@"JS info: %@", [v toString]); },
            @"error": ^(JSValue *v) { mfLog(@"JS error: %@", [v toString]); },
        };

        // 注入 defineScript 收集器——钩子从脚本里取
        [g_jsCtx evaluateScript:
         @"var __mfHooks = { requestHeaders: null, responseHeaders: null, response: null };"
         @"var Capture = {"
         @"  defineScript: function(def) {"
         @"    __mfHooks.requestHeaders = def.onRequestHeaders || null;"
         @"    __mfHooks.responseHeaders = def.onResponseHeaders || null;"
         @"    __mfHooks.response = def.onResponse || null;"
         @"  }"
         @"};"];
    });
}

// 加载/重载脚本
BOOL mfJSLoadScript(NSString *script) {
    @autoreleasepool {
        mfJSInitIfNeeded();
        if (script.length == 0) { g_jsScript = nil; mfLog(@"JS: script cleared"); return YES; }
        [g_jsCtx evaluateScript:script];
        JSValue *hasHooks = [g_jsCtx evaluateScript:@"__mfHooks.requestHeaders || __mfHooks.responseHeaders || __mfHooks.response"];
        if (hasHooks.isUndefined || !hasHooks.toBool) {
            mfLog(@"JS: script loaded but no hooks defined (need Capture.defineScript)");
            return NO;
        }
        g_jsScript = [script copy];
        mfLog(@"JS: script loaded with hooks");
        return YES;
    }
}

#pragma mark - 钩子执行

// 执行 onRequestHeaders——返回修改后的 headers（NSDictionary）或 nil
NSDictionary *mfJSRunRequestHeaders(NSString *method, NSString *url, NSDictionary *headers) {
    if (!g_jsScript) return nil;
    @autoreleasepool {
        @try {
            JSValue *fn = [g_jsCtx evaluateScript:@"__mfHooks.requestHeaders"];
            if (fn.isUndefined || fn.isNull) return nil;
            // 构造 JS 的 request 对象
            [g_jsCtx setObject:url forKeyedSubscript:@"__mfReqURL"];
            [g_jsCtx setObject:method forKeyedSubscript:@"__mfReqMethod"];
            [g_jsCtx setObject:headers ?: @{} forKeyedSubscript:@"__mfReqHeaders"];
            JSValue *result = [g_jsCtx evaluateScript:
                @"(function(){"
                @"  var req = { method: __mfReqMethod, url: __mfReqURL,"
                @"    headers: { set: function(k,v){ this[k]=v; }, get: function(k){ return this[k]; }, toJSON: function(){ var o={}; for (var k in this) if (typeof this[k] !== 'function') o[k]=this[k]; return o; } } };"
                @"  for (var k in __mfReqHeaders) req.headers[k] = __mfReqHeaders[k];"
                @"  var r = __mfHooks.requestHeaders(req);"
                @"  return r ? r.headers.toJSON() : null;"
                @"})()"];
            if (result.isUndefined || result.isNull) return nil;
            NSDictionary *d = [result toDictionary];
            mfLog(@"JS requestHeaders hook returned %lu headers", (unsigned long)d.count);
            return d;
        } @catch (NSException *e) {
            mfLog(@"JS requestHeaders EXCEPTION: %@", e.reason);
            return nil;
        }
    }
}

// 执行 onResponseHeaders——返回修改后的 headers
NSDictionary *mfJSRunResponseHeaders(int status, NSString *url, NSDictionary *headers) {
    if (!g_jsScript) return nil;
    @autoreleasepool {
        @try {
            JSValue *fn = [g_jsCtx evaluateScript:@"__mfHooks.responseHeaders"];
            if (fn.isUndefined || fn.isNull) return nil;
            [g_jsCtx setObject:url forKeyedSubscript:@"__mfRespURL"];
            [g_jsCtx setObject:@(status) forKeyedSubscript:@"__mfRespStatus"];
            [g_jsCtx setObject:headers ?: @{} forKeyedSubscript:@"__mfRespHeaders"];
            JSValue *result = [g_jsCtx evaluateScript:
                @"(function(){"
                @"  var res = { statusCode: Number(__mfRespStatus), url: __mfRespURL,"
                @"    headers: { set: function(k,v){ this[k]=v; }, get: function(k){ return this[k]; }, toJSON: function(){ var o={}; for (var k in this) if (typeof this[k] !== 'function') o[k]=this[k]; return o; } } };"
                @"  for (var k in __mfRespHeaders) res.headers[k] = __mfRespHeaders[k];"
                @"  var r = __mfHooks.responseHeaders(res);"
                @"  return r ? r.headers.toJSON() : null;"
                @"})()"];
            if (result.isUndefined || result.isNull) return nil;
            NSDictionary *d = [result toDictionary];
            mfLog(@"JS responseHeaders hook returned %lu headers", (unsigned long)d.count);
            return d;
        } @catch (NSException *e) {
            mfLog(@"JS responseHeaders EXCEPTION: %@", e.reason);
            return nil;
        }
    }
}

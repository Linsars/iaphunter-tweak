// MFReflixTrigger.m — ReflixPatch mach 触发器 v2 (v2.23.1)
// v1 教训: __DATA 扫描找不到端口名(全 MBA 密文); local_port=NULL 收不到应答。
// v2 方案: ReflixPatch 的 server port 是它 mach_port_allocate 的 receive right,
//   挂在本任务端口名字空间 → mach_port_names 全枚举 RECEIVE 权 → 逐个标准 MIG ping。
// 协议 (Unicorn 模拟验证, reven-recon/emu_*.py):
//   子系统表 @ __DATA_CONST+0x18c088: id 0x965..0x96a, max_msg=0x146c
//   0x965 ping 36B → reply id 0x9c9, RetCode@+0x20, 0=OK
//   0x966 cmd 5228B (arg u32 @+0x24) → 0x9ca
//   0x967 cmd 5228B (仅头) → 0x9cb
//   bits 0x1513 (COPY_SEND|MAKE_SEND_ONCE<<8) / 0x1514 / 0x11 均过 demux 模拟
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach-o/dyld.h>
#import "MFPanel.h"

static long g_rtPings = 0, g_rtPongs = 0, g_rtCmds = 0;
static NSMutableArray *g_rtLog = nil;
static NSObject *g_rtLock = nil;

static void rtLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void rtLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (!g_rtLock) g_rtLock = [NSObject new];
    @synchronized (g_rtLog) {
        if (!g_rtLog) g_rtLog = [NSMutableArray new];
        [g_rtLog insertObject:[NSString stringWithFormat:@"%@ %@", [NSDate date], s] atIndex:0];
        if (g_rtLog.count > 60) [g_rtLog removeLastObject];
    }
    mfLog(@"[RPTrig] %@", s);
}
long mfRPTrigPings(void) { return g_rtPings; }
long mfRPTrigPongs(void) { return g_rtPongs; }
long mfRPTrigCmds(void) { return g_rtCmds; }

#pragma mark - MIG 请求/应答

typedef struct { mach_msg_header_t hdr; NDR_record_t ndr; uint32_t arg; } rt_req_t;
typedef struct { mach_msg_header_t hdr; NDR_record_t ndr; kern_return_t ret; } rt_rep_t;

// 发一条 MIG 请求并等应答 (SEND+RCV 原子)。bits=0x1513 标准 MIG 客户端。
static kern_return_t rtMigCall(mach_port_t dest, int msgId, mach_msg_size_t size,
                               uint32_t arg, uint8_t *blob, uint32_t blobLen,
                               uint32_t *retcodeOut, uint32_t *replyIdOut) {
    mach_port_t reply = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &reply);
    if (kr != KERN_SUCCESS) return kr;

    uint8_t rbuf[0x1600]; memset(rbuf, 0, sizeof(rbuf));
    uint8_t sbuf[0x1600]; memset(sbuf, 0, sizeof(sbuf));
    rt_req_t *req = (rt_req_t *)sbuf;
    rt_rep_t *rep = (rt_rep_t *)rbuf;

    req->hdr.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    req->hdr.msgh_size        = size;
    req->hdr.msgh_remote_port = dest;
    req->hdr.msgh_local_port  = reply;
    req->hdr.msgh_voucher_port= 0;
    req->hdr.msgh_id          = msgId;
    req->ndr                  = NDR_record;
    if (size >= 0x28) req->arg = arg;
    if (blob && blobLen && size >= 0x28 + blobLen) memcpy(sbuf + 0x28, blob, blobLen);

    // remote 需要 send right: COPY_SEND 要求已持; 用 MAKE_SEND 从 receive 权现派
    // (MAKE_SEND descriptor 直接写在 bits 更稳, 但 demux 全放行, 内核端 COPY_SEND+预派最标准)
    kr = mach_port_insert_right(mach_task_self_, dest, dest, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS && kr != KERN_INVALID_RIGHT && kr != KERN_NAME_EXISTS) {
        // 没拿到 send right 依然尝试 (端口可能已双权)
    }
    mach_msg_option_t opt = MACH_SEND_MSG | MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_SEND_TIMEOUT;
    kr = mach_msg(&req->hdr, opt, size, sizeof(rbuf), reply, 600, MACH_PORT_NULL);

    mach_port_deallocate(mach_task_self_, dest);   // 递减 insert_right 的 send 引用
    mach_port_deallocate(mach_task_self_, reply);

    g_rtPings++;
    if (kr == MACH_RCV_TIMED_OUT || kr == MACH_RCV_INVALID_NAME) return kr;
    if (kr != KERN_SUCCESS) return kr;
    if (replyIdOut) *replyIdOut = rep->hdr.msgh_id;
    if (retcodeOut) *retcodeOut = rep->ret;
    return KERN_SUCCESS;
}

static BOOL rtPingPort(mach_port_t dest, uint32_t *retOut) {
    uint32_t rid = 0, rc = 0;
    kern_return_t kr = rtMigCall(dest, 0x965, 0x24, 0, NULL, 0, &rc, &rid);
    if (kr != KERN_SUCCESS) {
        rtLog(@"ping 0x%x -> kr=0x%x", dest, kr);
        return NO;
    }
    if (rid != 0x9c9) {
        rtLog(@"ping 0x%x -> reply_id=0x%x (expect 0x9c9) ret=%d", dest, rid, rc);
        return NO;
    }
    rtLog(@"PONG 0x%x ret=%d ✓", dest, rc);
    if (retOut) *retOut = rc;
    return YES;
}

#pragma mark - 端口发现 (全枚举)

static mach_port_t rtSweepPorts(void) {
    mach_port_name_array_t names = NULL;
    mach_msg_type_number_t nCnt = 0;
    mach_port_type_array_t types = NULL;
    mach_msg_type_number_t tCnt = 0;
    kern_return_t kr = mach_port_names(mach_task_self_, &names, &nCnt, &types, &tCnt);
    if (kr != KERN_SUCCESS) { rtLog(@"port_names fail 0x%x", kr); return MACH_PORT_NULL; }

    NSMutableArray *recv = [NSMutableArray array];
    for (mach_msg_type_number_t i = 0; i < nCnt && i < tCnt; i++) {
        if (types[i] & MACH_PORT_TYPE_RECEIVE) [recv addObject:@(names[i])];
    }
    if (names) vm_deallocate(mach_task_self_, (vm_address_t)names, nCnt * sizeof(mach_port_name_t));
    if (types) vm_deallocate(mach_task_self_, (vm_address_t)types, tCnt * sizeof(mach_port_type_t));

    rtLog(@"task ports: %u total, %lu RECEIVE", nCnt, (unsigned long)recv.count);

    for (NSNumber *n in recv) {
        mach_port_t p = (mach_port_t)n.unsignedIntValue;
        uint32_t rc = 0;
        if (rtPingPort(p, &rc)) {
            if (rc == KERN_SUCCESS) { g_rtPongs++; return p; }
            rtLog(@"port 0x%x answered ret=%d (not ok, keep sweeping)", p, rc);
        }
    }
    rtLog(@"sweep done, no server");
    return MACH_PORT_NULL;
}

// ReflixPatch 是否已加载 (决定要不要扫)
static BOOL rtDylibLoaded(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *n = _dyld_get_image_name(i);
        if (n && strstr(n, "ReflixPatch")) return YES;
    }
    return NO;
}

#pragma mark - 触发流程

static mach_port_t g_rpPort = MACH_PORT_NULL;

void mfRPTrigFire(NSString *mode) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        if (!rtDylibLoaded()) { rtLog(@"ReflixPatch dylib not loaded"); return; }

        if (g_rpPort == MACH_PORT_NULL) {
            g_rpPort = rtSweepPorts();
            if (g_rpPort == MACH_PORT_NULL) {
                rtLog(@"no server found — ReflixPatch server thread likely dead (time lock?) or port not created");
                return;
            }
        }
        rtLog(@"=== server port 0x%x locked ===", g_rpPort);

        // 命令序列: 0x966 word=0 → 0x966 word=1 → 0x967
        uint32_t rc = 0, rid = 0;
        kern_return_t kr;
        for (uint32_t w = 0; w <= 1; w++) {
            kr = rtMigCall(g_rpPort, 0x966, 0x146c, w, NULL, 0, &rc, &rid);
            g_rtCmds++;
            rtLog(@"cmd 0x966 word=%u -> kr=0x%x reply=0x%x ret=%d", w, kr, rid, rc);
        }
        kr = rtMigCall(g_rpPort, 0x967, 0x146c, 0, NULL, 0, &rc, &rid);
        g_rtCmds++;
        rtLog(@"cmd 0x967 -> kr=0x%x reply=0x%x ret=%d", kr, rid, rc);
        rtLog(@"done — 若 Pro 未亮, 检查 RetCode 语义");
    });
}

void mfRPTrigShowLog(void) {
    NSArray *lines = rtLogCopy();
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"RPTrig pings=%ld pongs=%ld cmds=%ld\n", g_rtPings, g_rtPongs, g_rtCmds];
    for (NSString *l in lines) [s appendFormat:@"%@\n", l];
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *p = [dir stringByAppendingPathComponent:@"MinisFix/rptrig_log.txt"];
    [s writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    mfLog(@"[RPTrig] log -> %@", p);
}

#pragma mark - 面板

void mfRPTrigSectionInLabPage(UIView *page, CGFloat *yio) {
    CGFloat y = *yio;
    UILabel *grp = [[UILabel alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 20)];
    grp.text = @"ReflixPatch mach 触发器 v2";
    grp.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    grp.textColor = [UIColor secondaryLabelColor];
    [page addSubview:grp];
    y += 24;
    UIButton *btnFire = [UIButton buttonWithType:UIButtonTypeSystem];
    btnFire.frame = CGRectMake(16, y, (g_mfCardW - 40), 38);
    [btnFire setTitle:@"🔥 触发 (枚举+ping+cmd)" forState:UIControlStateNormal];
    [btnFire addTarget:g_mfCtrl action:@selector(mfRPTrigFireTapped) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:btnFire];
    y += 42;
    UIButton *btnLog = [UIButton buttonWithType:UIButtonTypeSystem];
    btnLog.frame = CGRectMake(16, y, (g_mfCardW - 40), 38);
    [btnLog setTitle:@"📋 触发日志" forState:UIControlStateNormal];
    [btnLog addTarget:g_mfCtrl action:@selector(mfRPTrigShowLogTapped) forControlEvents:UIControlEventTouchUpInside];
    [page addSubview:btnLog];
    y += 44;
    UILabel *st = [[UILabel alloc] initWithFrame:CGRectMake(16, y, g_mfCardW - 32, 36)];
    st.text = [NSString stringWithFormat:@"ping %ld · pong %ld · cmd %ld", g_rtPings, g_rtPongs, g_rtCmds];
    st.font = [UIFont systemFontOfSize:11];
    st.textColor = [UIColor secondaryLabelColor];
    [page addSubview:st];
    y += 40;
    *yio = y;
}

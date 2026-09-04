// MFReflixTrigger.m — ReflixPatch mach 触发器 (v2.23.0)
// 替代已废弃的 MFAppPatch 进程层 patch 引擎。
// 原理: ReflixPatch-3.0.5.dylib 是 mach_msg_server (demux @dylib+0x121010)。
//   协议已用 Unicorn 全路径模拟破译 (reven-recon/emu_*.py, 2026-09-04):
//   - 子系统描述符 @ __DATA_CONST+0x18c088: start=0x965 end=0x96a max_msg=0x146c
//   - id 0x965: ping, 36B (头24+NDR8+4), reply id=0x9c9, RetCode@reply+0x20, 0=OK
//   - id 0x966: 命令, 5228B, 消费 request+0x24 的 u32 命令字, reply id=0x9ca
//   - id 0x967: 命令, 5228B, 仅头, reply id=0x9cb
//   - 发送 bits=0x11(MAKE_SEND) 或 0x1513(标准 MIG 客户端位) 均过 demux (模拟验证 HIT_SUCCESS)
// 端口发现: ReflixPatch __DATA 段里有它 mach_port_allocate 后存的全局 port 名
//   (u32 值, 任务 port 名字空间), 逐个试探 0x965 ping, RetCode=0 即 server port。
// 本文件全部纯 C + mach, 不依赖 ObjC runtime, 在 ReflixPatch 注册完成后再发。
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach-o/dyld.h>
#import "MFPanel.h"

// 段基址: dylib 静态基址 0, __DATA @0x190000-0x1d8000 (iOS dylib 共享缓存外, 直接文件布局)
#define RP_DATA_OFF     0x190000
#define RP_DATA_SIZE    0x48000

static long g_rtPings = 0;      // ping 发送数
static long g_rtPongs = 0;      // 有效 pong (RetCode==0)
static long g_rtCmds = 0;       // 命令发送数
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
        if (g_rtLog.count > 50) [g_rtLog removeLastObject];
    }
    mfLog(@"[RPTrig] %@", s);
}

long mfRPTrigPings(void) { return g_rtPings; }
long mfRPTrigPongs(void) { return g_rtPongs; }
long mfRPTrigCmds(void) { return g_rtCmds; }

static NSArray *rtLogCopy(void) {
    if (!g_rtLock) return @[];
    @synchronized (g_rtLog) { return [g_rtLog copy] ?: @[]; }
}
void mfRPTrigShowLog(void);

#pragma mark - mach 消息构造

// 0x965 ping: header(24) + NDR(8) + mach_msg_type_descriptor_t(8, u32*2) = 40? 实测 36B:
// header 24 + NDR 8 + 4B 参数。max probe size 0x24=36。
typedef struct {
    mach_msg_header_t       hdr;
    NDR_record_t            ndr;
    uint32_t                arg;        // proc 里被读的 4B 参数
} rp_ping_req_t;

typedef struct {
    mach_msg_header_t       hdr;
    NDR_record_t            ndr;
    kern_return_t           retcode;
    uint32_t                pad;
} rp_reply_t;

// 0x966 命令: header + NDR + body 5228-32=5196B, cmd word @ body+0
typedef struct {
    mach_msg_header_t       hdr;
    NDR_record_t            ndr;
    uint32_t                cmd;        // request+0x24 = 消息体首 u32 (模拟器实测被消费)
    uint8_t                 blob[5192]; // 填充到 0x146c
} rp_cmd_req_t;

static kern_return_t rtSendRecv(mach_port_t port, void *req, mach_msg_size_t reqsz,
                                void *reply, mach_msg_size_t replysz, mach_msg_timeout_t to) {
    mach_msg_option_t opt = MACH_SEND_MSG | MACH_RCV_MSG |
                            MACH_RCV_TIMEOUT | MACH_SEND_TIMEOUT;
    kern_return_t kr = mach_msg(req, opt,
                                reqsz, replysz, port, to, MACH_PORT_NULL);
    return kr;
}

// 发 ping 到指定 port, 返回 reply RetCode (KERN_INVALID_CAPABILITY 等失败码透传)
static kern_return_t rtPing(mach_port_t sendRight, uint32_t *replyIdOut) {
    rp_ping_req_t req; memset(&req, 0, sizeof(req));
    rp_reply_t rep;   memset(&rep, 0, sizeof(rep));

    mach_port_t selfTask = mach_task_self_;
    req.hdr.msgh_bits        = MACH_MSG_TYPE_MAKE_SEND; // 0x11 模拟验证过
    req.hdr.msgh_size        = 0x24;
    req.hdr.msgh_remote_port = sendRight;
    req.hdr.msgh_local_port  = MACH_PORT_NULL;
    req.hdr.msgh_voucher_port= 0;
    req.hdr.msgh_id          = 0x965;
    req.ndr                  = NDR_record;
    req.arg                  = 0;

    kern_return_t kr = rtSendRecv(selfTask, &req, sizeof(req), &rep, sizeof(rep), 800);
    g_rtPings++;
    if (kr != KERN_SUCCESS) return kr;
    if (replyIdOut) *replyIdOut = rep.hdr.msgh_id;
    return rep.retcode;
}

// 发命令 (0x966 带 cmd 字, 0x967 纯头)
static kern_return_t rtCmd(mach_port_t sendRight, int cmdId, uint32_t cmdWord) {
    rp_cmd_req_t req; memset(&req, 0, sizeof(req));
    rp_reply_t rep;   memset(&rep, 0, sizeof(rep));
    req.hdr.msgh_bits        = MACH_MSG_TYPE_MAKE_SEND;
    req.hdr.msgh_size        = 0x146c;
    req.hdr.msgh_remote_port = sendRight;
    req.hdr.msgh_id          = cmdId;
    req.ndr                  = NDR_record;
    req.cmd                  = cmdWord;
    // blob 特征字节, 便于设备日志比对
    for (int i = 0; i < (int)sizeof(req.blob); i++) req.blob[i] = (uint8_t)(i + 1);

    kern_return_t kr = rtSendRecv(mach_task_self_, &req, sizeof(req), &rep, sizeof(rep), 1500);
    g_rtCmds++;
    if (kr != KERN_SUCCESS) return kr;
    return rep.retcode;
}

#pragma mark - 端口发现

// 从 dylib 的 __DATA 段提取候选 port 名并 ping 验证。
// ReflixPatch ctor: mach_port_allocate(RECEIVE) → 存全局 → mach_port_insert_right(MAKE_SEND)。
// port 名是任务级 u32 句柄, 全局变量里能捞到。已加载判定: _dyld_image_count 遍历。
static mach_port_t rtFindServerPort(void) {
    // 1) 找 ReflixPatch 已加载 + 取加载基址 (slide)
    const struct mach_header *mh = NULL;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "ReflixPatch")) {
            mh = _dyld_get_image_header(i);
            break;
        }
    }
    if (!mh) {
        rtLog(@"ReflixPatch dylib not loaded");
        return MACH_PORT_NULL;
    }
    intptr_t slide = _dyld_get_image_vmaddr_slide(0); // 占位, 下面精确算
    // 重新精确遍历拿 slide
    for (uint32_t i = 0; i < count; i++) {
        if (_dyld_get_image_header(i) == mh) { slide = _dyld_get_image_vmaddr_slide(i); break; }
    }
    rtLog(@"dylib @ %p slide=0x%lx", mh, (long)slide);

    // 2) 解析 __DATA: 用段头 (vmaddr 相对) → 运行时地址
    const segment_command_64 *seg = NULL;
    const mach_header_64 *h64 = (const mach_header_64 *)mh;
    uint8_t *cmd = (uint8_t *)mh + sizeof(mach_header_64);
    for (uint32_t i = 0; i < h64->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cmd;
        if (lc->cmd == LC_SEGMENT_64) {
            segment_command_64 *sc = (segment_command_64 *)cmd;
            if (strcmp(sc->segname, "__DATA") == 0) { seg = sc; break; }
        }
        cmd += lc->cmdsize;
    }
    if (!seg) { rtLog(@"__DATA not found"); return MACH_PORT_NULL; }

    uint8_t *dataBase = (uint8_t *)seg->vmaddr + slide;
    uint64_t dataSize = seg->filesize;
    rtLog(@"__DATA runtime @ %p size=0x%llx", dataBase, dataSize);

    // 3) 逐 4B 对齐扫候选 port 名, ping 验证
    mach_port_t found = MACH_PORT_NULL;
    int tried = 0, alive = 0;
    for (uint64_t off = 0; off + 4 <= dataSize && tried < 4096; off += 4) {
        uint32_t cand = *(volatile uint32_t *)(dataBase + off);
        if (cand < 0x1000 || cand > 0x0fffffff) continue;   // port 名合理范围
        // 任务名空间快速校验: mach_port_kernel_object 确认是 PORT
        mach_port_kobject_type_t kotype = 0;
        mach_vm_address_t kaddr = 0;
        if (mach_port_kobject(mach_task_self_, cand, &kotype, &kaddr) != KERN_SUCCESS) continue;
        tried++;
        kern_return_t rc = rtPing((mach_port_t)cand, NULL);
        if (rc == KERN_SUCCESS) {
            alive++;
            rtLog(@"PONG @ __DATA+0x%llx port=0x%x", off, cand);
            found = (mach_port_t)cand;
            break;
        }
        if (tried % 256 == 0) rtLog(@"probe %d done", tried);
    }
    rtLog(@"port scan: tried=%d alive=%d", tried, alive);
    return found;
}

#pragma mark - 触发流程

static mach_port_t g_rpPort = MACH_PORT_NULL;

void mfRPTrigFire(NSString *mode) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        if (g_rpPort == MACH_PORT_NULL) {
            g_rpPort = rtFindServerPort();
            if (g_rpPort == MACH_PORT_NULL) {
                rtLog(@"no server port — dylib not loaded or port not registered");
                return;
            }
        }
        // 1) ping 握手
        uint32_t rid = 0;
        kern_return_t rc = rtPing(g_rpPort, &rid);
        rtLog(@"ping id=0x965 -> ret=0x%x reply_id=0x%x", rc, rid);
        if (rc != KERN_SUCCESS) {
            rtLog(@"ping failed, rescan");
            g_rpPort = MACH_PORT_NULL;
            return;
        }
        g_rtPongs++;
        // 2) 命令序列: 0x966(cmd word) + 0x967
        //    cmd word 待设备日志收敛: 先发 0, 再发 1, 观察哪种让 vm_protect 点火
        kern_return_t r1 = rtCmd(g_rpPort, 0x966, 0);
        rtLog(@"cmd 0x966(word=0) -> ret=0x%x", r1);
        kern_return_t r2 = rtCmd(g_rpPort, 0x967, 0);
        rtLog(@"cmd 0x967 -> ret=0x%x", r2);
        if (r1 == KERN_SUCCESS || r2 == KERN_SUCCESS) {
            rtLog(@"commands accepted — watch vm_protect / Pro state");
        }
    });
}

// 设备上探测完直接落盘全日志, 人工核对
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
    grp.text = @"ReflixPatch mach 触发器";
    grp.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    grp.textColor = [UIColor secondaryLabelColor];
    [page addSubview:grp];
    y += 24;
    UIButton *btnFire = [UIButton buttonWithType:UIButtonTypeSystem];
    btnFire.frame = CGRectMake(16, y, (g_mfCardW - 40), 38);
    [btnFire setTitle:@"🔥 触发 (ping+cmd)" forState:UIControlStateNormal];
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

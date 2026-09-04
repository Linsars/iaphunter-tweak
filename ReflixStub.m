// ReflixStub.m — v2.34.0 假说 B 判决件
// 假说: app 对伴侣 dylib 只做「存在性」检查(路径运行时拼接, 故主二进制字符串扫描全 absent),
//       dylib 本体加载后零行为(2.33.0 终局窃听: msgSend/mach/vm_protect/写内存/invocation 全零)。
// 若本空壳顶替真品后 app 依旧亮 Pro → 存在性检查实锤 → 永久替代(1KB 假货上岗, 真品进博物馆)。
#import <Foundation/Foundation.h>

__attribute__((visibility("default")))
void ReflixStubSentinel(void) {}   // 唯一导出占位, 无 ctor 无行为

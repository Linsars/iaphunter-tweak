# MinisFix 架构真相源(任何会话开工必读,防概念混淆)

> 状态: **v2.4.0 四 dylib 重组已完成** ✅ (FolderX / AppHooks / IAPtools + FolderX.bundle)
> 历史教训: 模型反复把「IAP工具箱面板」当成 MinisFix 全部、把功能塞错 dylib。
> 误导源: ①Makefile 旧注释 `# MinisFix v5.0(新面板:数据分析/...)` ②旧 memory 叙事。
> 本文件是唯一真相源,架构变动必须同步更新本文件(纪律)。

## 概念词典(先背下来)

| 词 | 指什么 | 不是什么 |
|---|---|---|
| **MinisFix** | deb 包/插件总名(Package: com.linsars.minisfix) | 不是某个 dylib |
| **设置页** | folderx/Resources/Root.plist(系统设置→TweakSettings→MinisFix) | 不是 IAP工具箱 面板里的页面 |
| **IAP工具箱** | IAPtools.dylib 里的悬浮面板(数据分析/Product 两树) | 只是 MinisFix 的一个功能体系 |
| **FolderX** | SpringBoard dylib + 同名设置 bundle(folderx 子项目) | — |
| repo 名 iaphunter-tweak | 旧命名没改而已 | 与 IAPHunter 时代强绑定 |

## 目标架构(v2.4.0,按注入目标分类)

```
deb = 4 dylib + 1 设置 bundle
├── FolderX.dylib      filter: com.apple.springboard
│   ├── 文件夹变色(FX*.m, FolderColor.xm)
│   └── 充电限制 + Wi-Fi永连(MFSystemEnhance.m, IOKit IOPMPowerSource + allowIdleSleep hook)
├── AppHooks.dylib     filter: Executables [appstored, installd, TestFlight](原 AppStoreSpoof 扩编)
│   ├── AppStore 版本伪装(MFAppStoreSpoof.m, UA+installd 版本检查)
│   └── TestFlight 增强(MFTestFlightHooks.m, TFAppBuild swizzle,自 MFPanel.m 迁出)
├── IAPtools.dylib     filter: com.apple.UIKit(全局 UI 进程;原 MinisFix 改名)
│   └── IAP工具箱面板(数据分析/Product)
└── FolderX.bundle     folderx/ 子项目(bundle.mk, 装系统设置)
    ├── Root.plist = 设置页: 功能[IAP工具箱/FolderX/⚡️系统增强] + 关于
    ├── SystemEnhanceSettings.plist(新): 伪装3键+TF2键+诊断清理+充电+WiFi
    └── IAPSettings.plist: 只剩 IAP 工具箱自身(伪装/TF/清理三组迁出)
```

## 新功能归属决策树(加功能前必走)

```
新功能的注入目标是什么?
├── SpringBoard          → FolderX.dylib
├── 指定 App/守护进程     → AppHooks.dylib(改 filter Executables + ctor isProcess 分支)
├── 全局 UI(要面板/弹窗) → IAPtools.dylib
├── 纯设置项(无 hook)    → folderx bundle 对应 plist
└── 都不是 → 单独新 dylib + 自己的 filter,别塞现有
```

## 铁律

1. 系统功能(充电/WiFi/商店 hook)永不进 IAPtools.dylib——它只做 IAP 面板
2. 偏好统一域 `com.linsars.minisfix`(/var/jb/var/mobile/Library/Preferences/),不再寄生第三方域
3. ctor 首行系统进程守卫不可移除(IAPtools 全局注入,appstored 事故 .ips 实锤)
4. Makefile 两处名单(FolderX filter-out + 各 dylib _FILES)必须同步
5. 架构变更 → 同步更新本文件 + GLOBAL.md 锚

## 当前架构(v2.3.1,重组前,历史存档)

三 dylib: FolderX(SB) / MinisFix(全局,含 TF hook 在 MFPanel.m) / AppStoreSpoof(appstored+installd)。
设置页 Root.plist 的 IAPSettings.plist 里挤着伪装/TF/清理三组非 IAP 项(待迁出)。
伪装偏好寄生 dev.mineek.appstoretroller 域(待统一)。

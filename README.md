# MinisFix

iOS 越狱插件集合，包含以下功能：

## 功能

### 文件夹变色 (FolderX)
- 自定义文件夹颜色
- Dock 多图标显示

### IAP 工具箱 (MinisFix)
- IAP 收购和分析
- 网络捕获和规则
- JS 规则引擎
- TestFlight 版本绕过

### AppStore 版本伪装 (AppStoreSpoof)
- 伪装 iOS 版本号
- 绕过最低版本检查
- 让低版本设备购买/安装高版本 App

## 设置

- IAP 工具箱：`com.linsars.minisfix`
- AppStore 版本伪装：`dev.mineek.appstoretroller`

## 编译

```bash
make package
```

## 安装

```bash
sudo dpkg -i packages/com.linsars.minisfix_1.2.0_iphoneos-arm64.deb
sudo killall -9 SpringBoard appstored installd
```

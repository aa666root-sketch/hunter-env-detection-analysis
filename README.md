# hunter-env-detection-analysis

对 `com.zhenxi.hunter` 6.42 的一次静态逆向记录。样本是一个 Android 侧的设备环境检测（风控自检）应用，覆盖 Root、Magisk/Zygisk、Xposed/LSPosed、Frida、inline hook、ptrace、seccomp、模拟器/云手机、多开沙箱、改机、VPN、调试、签名篡改、Bootloader 解锁等维度。

写这份东西的出发点是搞清它到底在查什么、查得准不准，以及它自身的工程实现有没有问题，顺带作为自己 Android 逆向的一个练习记录。

## 分析方法

全程**纯静态**，样本没有运行、没有联网、也没在真实设备上做动态验证。

| 环节 | 工具 |
| --- | --- |
| 包结构 / 清单 / 资源 | `androguard` 4.1.4（APK、AXMLPrinter、ARSCParser）、`REA` |
| DEX 类与调用点 | `androguard` DEX / Analysis，解析 `invoke-*` |
| Java 反编译核对 | JADX headless 0.7.1 |
| Native 结构 | `pyelftools` 解析 `.dynsym` / `.symtab` / 程序头 / 动态段 |
| 字符串证据 | `libhunter.so`、`libhunter_maps_hide.so` 的 ASCII / UTF-8 中文串；`resources.arsc` |

所有判断都以静态字符串、清单和 ELF 结构为证据。凡是涉及"可利用性"的条目，文中都标了"条件性"，意思是需要动态或网络验证才能确认，这里没有做。

## 仓库内容

| 文件 | 说明 |
| --- | --- |
| [`docs/Hunter_6.42_环境检测分析报告.md`](docs/Hunter_6.42_环境检测分析报告.md) | 主报告。样本指纹、进程模型、Java/native 检测机制分解、10 条 Findings（F-01 ~ F-10，各含证据、影响、验证方向、修复建议）、检测能力矩阵、组件与权限清单、静态复现命令、原始证据串附录 |
| [`docs/逆向分析报告.txt`](docs/逆向分析报告.txt) | 过程稿。检测链时序还原、缺陷面按危害排序、证据与复现、检测项总表 |

## 样本信息

```
包名        com.zhenxi.hunter
版本        6.42 (642)
SHA-256     a91d1a11539626dec702310d9717205e99cd536635fc23f086a6b23698d96391
大小        12,986,158 字节
SDK         minSdk 28 / targetSdk 36
ABI         arm64-v8a
```

## 主要结论

- 没有可直接远程利用的内存破坏漏洞（栈溢出、UAF、越界写），也没有第三方应用能直接调用的敏感导出组件。
- native 库加固水平不差：Full RELRO + BIND_NOW，PIE / NX / Canary / FORTIFY 齐全。
- 问题主要在架构与配置层面：检测结论完全在客户端产生；完整性校验与反调试属于"同进程自证"，同时又自带一个 maps 隐藏库；更新通道是明文 HTTP + 硬编码 IP + 装包权限；FileProvider 声明了 `root-path` 和全盘 `external-path`；release 包带 `profileable shell=true`；25 MB 规则库只用了 ZipCrypto。
- 权限偏多：全量应用列表、使用统计、通话状态、定位、蓝牙、AD_ID。

细节、证据和分级见两份文档。

## 声明

- 样本版权归原开发者所有，仓库里不放 APK，只有分析文本。
- 静态分析的结论可能随版本更新失效，6.42 之后的版本没测。
- 这份记录用于了解检测机制和评估实现质量。**不要拿它去绕风控、刷量、多开养号或者干别的违规事**。
- 仓库保持私有，只是个人研究归档。

## 许可

文档内容采用 [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/deed.zh)。转载注明出处，不得商用。

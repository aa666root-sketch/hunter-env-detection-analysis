# Hunter 6.42（com.zhenxi.hunter）环境检测机制逆向与安全缺陷分析

> 分析对象：`com.zhenxi.hunter.App.apk.1`（实际为 APK）
> 分析方式：纯静态分析（未运行、未联网、未对任何真实设备做动态验证）
> 分析日期：2026-11-20
> 结论级别：以静态证据为准；标注"条件性"的条目需要动态/网络验证才能确认可利用性

---

## 0. 摘要

Hunter 6.42 是一个"设备环境检测 / 风控自检"型应用，检测能力由 **Java 层包名与属性扫描 + native 层内核级检查 + 多进程隔离 + 系统级认证** 四部分组成，覆盖 Root、Magisk/Zygisk、Xposed/LSPosed、Frida、inline hook、ptrace、seccomp、模拟器/云手机、多开/沙箱、改机、VPN、调试、签名篡改、Bootloader 解锁等维度。

本次分析**未发现可直接远程利用的内存破坏类漏洞**（栈溢出、UAF、越界写等），也未发现可被第三方应用直接调用的敏感导出组件。主要问题集中在架构与配置：

| 编号 | 级别 | 问题 |
|---|---|---|
| F-01 | 高 | 检测结论完全在客户端产生，可被 hook/patch 伪造 |
| F-02 | 高 | 完整性/反调试为"同进程自证"，且自带 maps 隐藏库，自相矛盾 |
| F-03 | 中高（条件性） | 全局允许明文流量 + XUpdate 自更新 + 安装 APK 权限 |
| F-04 | 中（条件性） | FileProvider 声明 `root-path`/全盘 `external-path`，存在任意文件 URI 映射 |
| F-05 | 中 | release 包 `profileable shell=true`，可被 adb 采样/转储，削弱反调试 |
| F-06 | 中低 | 25 MB 指纹库仅用 ZipCrypto 加密，且随包附带内部课程 PDF |
| F-07 | 中（合规） | 权限过度：全量应用列表、使用统计、通话状态、定位、蓝牙、AD_ID |
| F-08 | 低 | native 加固良好（Full RELRO/NX/PIE/Canary），但 `extractNativeLibs=true` 便于离线分析与替换 |
| F-09 | 低（稳定性） | ptrace/seccomp/守护线程在部分 ROM 失败会导致误报甚至直接退出 |
| F-10 | 低（信息） | 冗余系统级权限与可导出的 MainActivity / Firebase SDK 组件 |

---

## 1. 样本信息

| 项目 | 值 |
|---|---|
| 文件名 | `com.zhenxi.hunter.App.apk.1` |
| 文件大小 | 12,986,158 字节 |
| MD5 | `8EA29B7DCDDE0C50E92867DB0767F048` |
| SHA-256 | `A91D1A11539626DEC702310D9717205E99CD536635FC23F086A6B23698D96391` |
| 包名 | `com.zhenxi.hunter` |
| 应用名 | Hunter |
| versionName / versionCode | 6.42 / 642 |
| minSdk / targetSdk | 28 / 36 |
| ABI | 仅 `arm64-v8a` |
| DEX | 单个 `classes.dex`，6,557,424 字节，7,227 个类，38,643 条字符串 |
| 混淆 | 业务类全部改名为 `YouAreLoser.*`；字符串以 `\u06xx` 片段 + `YouAreLoser.SP.ۥۜۨ()` 运行时解密；资源名混淆（所有 XML 资源名均为 `Zhenxi`） |
| Native | `libhunter.so`（3,561,456 B）、`libhunter_maps_hide.so`（1,055,960 B）、`libdatastore_shared_counter.so`（7,112 B） |
| 资产 | `assets/data.zip`（1,784,210 B）；`assets/HunterRuntime.pdf`（272,562 B）；`assets/AndroidReverse.pdf`（461,230 B）；`PublicSuffixDatabase.list` |

`assets/data.zip` 内部只有一个 `data.json`，解压后 **25,427,761 字节**，ZIP 加密方式为传统 ZipCrypto（`compress_type=8`、`flag_bits=11`，非 AES），未在静态分析中取得口令。

---

## 2. 分析方法与证据来源

| 环节 | 工具/方法 | 产出 |
|---|---|---|
| 包结构、清单、资源 | `androguard 4.1.4`（`APK`、`AXMLPrinter`、`ARSCParser`） | `AndroidManifest.xml`、资源 XML、权限与组件清单 |
| DEX 类/字符串/调用点 | `androguard` 的 `DEX`/`Analysis`，解析 `invoke-*` 指令输出 | 类清单、38,643 条字符串、危险 API 调用点 |
| Native 结构 | `pyelftools` 解析 `.dynsym`/`.symtab`、程序头、动态段 | JNI 导出、安全编译选项 |
| 字符串证据 | 对 `libhunter.so`/`libhunter_maps_hide.so` 提取 ASCII 与 UTF-8 中文串 | 检测项、路径、提示语 |
| 资源字符串 | 从 `resources.arsc` 提取 UTF-8 中文 | 判定结论、错误提示 |

> 证据均为静态字符串/清单/ELF 结构，未做运行时 hook 或抓包验证。凡涉及"可利用性"的判断，均已在文中注明前提。

---

## 3. 运行架构

### 3.1 进程模型

```text
com.zhenxi.hunter（应用）
├─ :hunter_main_process      主进程（UI / 结果汇总 / 自更新）
├─ :hunter_server_iso        isolatedProcess=true（独立 UID 沙箱进程，无应用权限）
├─ :hunter_server_twin       useAppZygote=true（应用 zygote 预加载进程）
└─ .HunterPreload            zygotePreloadName（早于 Application 执行）
```

清单证据：

```xml
<application
    android:name="com.zhenxi.hunter.App"
    android:process=":hunter_main_process"
    android:largeHeap="true"
    android:extractNativeLibs="true"
    android:zygotePreloadName=".HunterPreload"
    android:networkSecurityConfig="@7F140008"
    android:fullBackupContent="@7F140000"
    android:dataExtractionRules="@7F140001" />

<profileable android:shell="true"/>

<service android:name="com.zhenxi.hunter.ZhenxiServer"
         android:exported="false"
         android:process=":hunter_server_iso"
         android:isolatedProcess="true"/>
<service android:name="com.zhenxi.hunter.ZhenxiServerTwin"
         android:exported="false"
         android:process=":hunter_server_twin"
         android:useAppZygote="true"/>
```

**设计意图**：把检测拆到隔离进程/应用 zygote 中，尽量早于被测代码运行，降低被目标进程 hook 的概率；主进程只做展示与聚合。但由于所有进程同属一个 APK、同一份 native 代码，最终结果仍回到主进程展示，隔离并不能改变"结论本地产生"的性质。

### 3.2 判定输出

从 `resources.arsc` 提取到的判定字符串（原文）：

```text
未发现风险
风险设备
高风险设备
黑灰产设备
当前设备不可信！
可能存在攻击行为
当前手机可能已经被Root
当前手机可能存在Magisk
当前Apk可能被Hook
当前设备指纹可能被修改！
可能存在自定义ROM
当前手机已经被解锁
当前手机Boot分区签名验证失败
检测到Frida线程
检测到程序可能正在被调试
检测到Root
检测到可疑Root文件
检测到FakeLocation已开启
电池异常:充电功率过高 / 可能是云手机
环境信息查询失败！当前系统非ROM原生系统 ！
```

### 3.3 自保护守护线程

```text
检测到CRC线程未开启！程序退出！
检测进程未开启
检测Ptrace进程未开启
```

说明应用启动后会拉起 CRC 线程 / 检测进程 / ptrace 线程，任一缺失即判定环境异常并退出。这既是反调试手段，也是稳定性风险（见 F-09）。

---

## 4. 环境检测机制

### 4.1 Java 层检测

#### 4.1.1 包名扫描（85 个 `<queries>`）

清单中声明了 85 个可见包名，按用途分类：

| 类别 | 代表包名 |
|---|---|
| Root 管理器 | `com.topjohnwu.magisk`、`io.github.vvb2060.magisk`、`io.github.huskydg.magisk`、`me.weishu.kernelsu`、`com.rifsxd.ksunext`、`com.sukisu.ultra`、`me.bmax.apatch`、`me.garfieldhan.apatch.next` |
| 传统 Root | `eu.chainfire.supersu`、`com.noshufou.android.su`、`com.noshufou.android.su.elite`、`com.koushikdutta.superuser`、`com.kingroot.kinguser`、`com.kingo.root`、`com.smedialink.oneclickroot`、`com.alephzain.framaroot` |
| Hook / 隐藏 | `de.robv.android.xposed.installer`、`org.meowcat.edxposed.manager`、`org.lsposed.manager`、`top.canyie.dreamland.manager`、`com.tsng.hidemyapplist`、`com.tsng.hidemyroot`、`com.variable.apkhook` |
| 虚拟化 / 多开 | `io.va.exposed`、`io.va.exposed64`、`io.virtualapp`、`io.virtualapp.sandvxposed64` |
| 自动点击 / 群控 | `com.touchsprite.android`、`com.cyjh.mobileanjian`、`org.autojs.autojs`、`org.autojs.autojspro`、`com.zidongdianji`、`com.adinall.autoclick`、`com.github.uiautomator`、`com.github.uiautomator2`、`com.genymobile.scrcpy` |
| 改机 / 擦机 | `com.lerist.fakeloction`、`com.yicu.yichujifa`、`com.bigsing.changer`、`zap.fh.wipe`、`com.android1500.androidfaker`、`com.soft.apk008v`、`com.soft.apk008Tool`、`com.xenice.mask` |
| 云手机 / 群控工具 | `com.yztc.studio.plugin`、`com.uwish.app`、`com.sigma_rt.totalcontrol`、`com.auyou.auyouwzs` |

#### 4.1.2 Root 文件与属性

DEX 字符串中的 Root 路径集合：

```text
/system/app/Superuser.apk
/system/xbin/su
/system/sd/xbin/
/system/xbin/
/sbin/
/data/local/
/data/local/bin/
/data/local/xbin/
```

相关字段/方法名：`isRooted`、`rootCause`、`DEVICE_ROOT`、`TAG_ROOT_PATH`、`checkRootFromAVCLog`。

#### 4.1.3 网络 / VPN / 代理

- `Landroid/net/NetworkCapabilities;` 与 `TRANSPORT_VPN`：用系统 API 判断当前网络是否 VPN。
- native 侧 `CheckVpn`、`Find Vpn Native`，并读取 `/proc/net/tun` 等特征。
- 资源字符串包含 `tun`/代理相关检测逻辑（见附录 A）。

#### 4.1.4 调试、模拟器、云手机

- 调试：`Debug.isDebuggerConnected`、`TracerPid`（native）、JDWP 相关端口/属性。
- 模拟器：native 检查 `goldfish_pipe`、`goldfish_battery`、`vboxguest`、`vboxuser`、`vboxsf`、`libc_malloc_debug_qemu.so`、`vbox2345_x86` 等。
- 云手机：Java 侧读取 `BatteryManager` 的 `DEVICE_CHARGING` / `EXTRA_SCALE`，以"充电功率异常"作为云手机特征；对应字符串 `检测到过大的充电功率`、`电池异常:充电功率过高`、`可能是云手机`。

#### 4.1.5 系统可信与硬件密钥

从 DEX 字符串与清单可见以下能力：

```text
com.xiaomi.security.xsof.IMiSafetyDetectServer / SAFETY_DETECT_SERVICE
com.xiaomi.security.permission.ACCESS_XSOF
com.soter.permission.ACCESS_SOTER_KEYSTORE
com.google.firebase.appcheck.playintegrity.FirebaseAppCheckPlayIntegrityRegistrar
exchangePlayIntegrityToken / generatePlayIntegrityChallenge / playIntegrityToken
AndroidKeyStore / setAttestationChallenge / setDevicePropertiesAttestationIncluded
```

对应判定：`当前手机已经被解锁`、`当前手机Boot分区签名验证失败`、`当前手机不支持密钥认证检测`。

#### 4.1.6 改机与指纹一致性

- `getCPUFingerprinting`、`getZhenxiLoctionCrc`（位置指纹 CRC）。
- `assets/data.zip` 内 25 MB `data.json` 作为机型/硬件指纹对照库（静态分析未取得口令）。
- 判定字符串：`当前设备指纹可能被修改！`、`当前设备机型可能被修改`。

#### 4.1.7 APK 自身完整性

- `Landroid/content/pm/Signature;`、`getApkContentsSigners`。
- 判定字符串：`当前Apk可能被Hook`、`检测到Apk签名被修改`。

#### 4.1.8 黑灰产应用与行为面

- `QUERY_ALL_PACKAGES` + `PACKAGE_USAGE_STATS`（使用统计需用户授权）。
- 自动点击/Auto.js/UIAutomator/群控包名扫描（见 4.1.1）。
- 相机与录屏：`SecCameraActivity`（`exported=false`）。

### 4.2 Native 层检测（libhunter.so）

`libhunter.so` 导出符号仅 2 个静态 JNI 函数，主体通过 `JNI_OnLoad`（9,504 字节）动态 `RegisterNatives`：

```text
0x341664  188  Java_com_zhenxi_hunter_NativeEngine_getZhenxiInfoMethodCode
0x341654  16   Java_com_zhenxi_hunter_NativeEngine_getZhenxiInfoReleaseNative
0x33f134  9504 JNI_OnLoad
```

native 字符串揭示的检查项：

| 检查项 | 关键证据字符串 |
|---|---|
| ptrace / 反调试 | `checkPtraceTracerForMain is start ,tracer tid ->`、`main process check error TracerPid`、`check ptrace thread create fail!`、`>>>>>>>>>>>> native kill self process !!!!!!!!!!` |
| 硬件断点 | `DetectHardwareBreakpoints`（方法名） |
| seccomp | `JNI_OnLoad install seccomp`、`install_check_arch_seccomp prctl(PR_SET_NO_NEW_PRIVS)`、`Seccomp bpf Rule is Replaced !`、`Seccomp+Bpf attach error ,error msg ->` |
| 代码完整性 | `checkLinkerCheckSum`、`checkLibCheckSum`、`check_elf_checksum`、`find libart.so hooked`、`Linker Find Hook Mark`、`Base Check Inline Flag`、`Twin Service Crc Find Hooked`、`Twin Service Hardware Check Find Hooked` |
| Frida | `gum-js-loop`、`gmain`、`Find Frida NAME PIPE(linjector)`、`/dev/ashmem//jit-cache`、`/memfd:/jit-cache`、`unusual jit-cache ->` |
| unidbg | `Unidbg`、`JNI_OnLoad find maybe unidbg`、`JNI_OnLoad check unidbg` |
| Magisk | `/sbin/.magisk`、`/data/adb/magisk`、`/cache/magisk.log`、`/system/addon.d/99-magisk.sh`、`/dev/magisk/img`、`/data/magisk.apk`、`/system/bin/magisk32`、`checkMagiskMark find file`、`Find Magisk Modules Mark` |
| APatch / KernelSU | `/data/adb/ap`、`/data/adb/apd`、`/data/adb/ap/su_path`、`/data/adb/ap/log/bin/magiskpolicy`、`kernelSu` |
| Zygisk | `/system/lib64/libzygisk.so`、`/system/lib64/libzygisk_loader.so`、`find zygisk detected ,zygote root pid`、`runInZygisk`、`checkFromZygote` |
| Xposed / LSPosed / Riru | `/system/framework/XposedBridge.jar`、`/system/lib64/libxposed_art.so(.no_orig)`、`/sbin/.magisk/modules/riru_lsposed`、`/sbin/.magisk/modules/riru_edxposed`、`/data/misc/riru/modules/dreamland` |
| OverlayFS / 挂载 | `found OVERLAYFS_SUPER_MAGIC, but no overlayfs mount found`、`/proc/self/mounts`、`/proc/self/mountinfo`、`/proc/self/mountstats`、`find OverlayFS ->`、`Time stamp anomaly detected for /proc/self/attr/current` |
| maps 隐藏检测 | `Check Maps Find Hide`、`RuntimeHideMapsMarks`、`/proc/self/map_files/`、`getZhenxiInfoMapELF` |
| 沙箱 / 多开 | `check sandbox`、`>>>>> NOT FIND SANDBOX`、`com.netease.mumu.cloner`、`/system/bin/tencent_virtual_input`、`/data/local/tmp/mqc-scrcpy.jar` |
| 模拟器 | `goldfish_pipe`、`goldfish_battery`、`/system/lib/vboxguest.ko`、`/system/lib/vboxvideo.ko`、`/sys/module/vboxsf`、`/init.vbox2345_x86.rc` |
| VPN | `CheckVpn`、`Find Vpn Native` |
| 自身 / 双进程 | `ISO Service Hardware Find Hooked`、`Twin Service Hardware Check Find Hooked`、`Twin Service Crc Find Hooked`、`JNI_OnLoad mainPid check COORDINATE_TAG success` |

### 4.3 检测逻辑总览

```text
启动
 ├─ HunterPreload（zygote 预加载）
 ├─ 主进程初始化 → 拉起 :hunter_server_iso / :hunter_server_twin
 ├─ Java 层：85 包名、Root 路径、属性、VPN、电池、签名、指纹库、系统认证
 ├─ Native 层：ptrace/seccomp/CRC/inline hook/Frida/Magisk/Zygisk/OverlayFS/maps
 ├─ 守护线程：CRC、Ptrace、检测进程（缺失即退出）
 └─ 聚合 → HunterDataBean/ListItemBean → 风险等级 UI
```

---

## 5. 安全缺陷（Findings）

### F-01【高】检测结论完全在客户端产生，可被 hook/patch 伪造

**证据**

- 所有 native 检查最终通过 `NativeEngine` 的 JNI 方法返回 `bool/int`，交由 Java 层聚合；未发现把原始证据送服务端复算的逻辑。
- 判定字符串（`未发现风险`/`风险设备`/`黑灰产设备`）直接来自本地资源。
- 业务方法通过 `RegisterNatives` 注册，仅 2 个静态 JNI 导出，但 Java 层仍可被 Frida/LSPosed 在结果聚合处拦截。
- 应用内自带 `DobbyHook`/`DobbyInstrument`/`DobbyCodePatch`，证明同一套 hook 能力可用于反向篡改自身。

**影响**

对于一个以"验证环境是否干净"为目的的应用，客户端判定等于"被测方可自证清白"：hook 返回值或直接替换 UI 数据即可让任意环境显示为"未发现风险"。若第三方依赖该结果做风控，结论不可信。

**验证建议（授权环境）**

在测试机上用 Frida 对 `NativeEngine` 的 native 方法做 `Interceptor.attach`，比较 hook 前后 UI 判定；或在 Java 聚合方法处替换返回列表。预期可完全控制判定。

**修复建议**

- 客户端只上报原始证据（带时间戳、随机数、签名），由服务端计算结论。
- 结论与 Play Integrity / 硬件密钥认证的 nonce 绑定，服务端校验。
- 关键检测结果不要以可拦截的 Java 对象返回，改为服务端一次性令牌。

---

### F-02【高】完整性/反调试为"同进程自证"，且自带 maps 隐藏库

**证据**

- `libhunter_maps_hide.so` 存在，字符串包含 `RuntimeHideMapsMarks`、`Check Maps Find Hide`。
- CRC 校验（`checkLinkerCheckSum`、`checkLibCheckSum`、`check_elf_checksum`）在同一个被检测进程内计算内存与磁盘值。
- `Twin Service Crc Find Hooked` 说明双进程也在做同类校验，但仍是同一 APK 内的代码。

**影响**

- 自身既是"检测者"又是"被检测者"，攻击者可在校验函数返回前篡改结果。
- 应用自己使用 maps 隐藏，说明其清楚 `/proc/self/maps` 可被伪造；这与"检测 maps 异常"的能力互相抵消。
- 结论：这类自保护只能提高成本，不能提供可信保证。

**修复建议**

把完整性证据（ELF 哈希、maps 摘要、attestation）交给服务端/可信执行环境验证；不要在同进程内做最终裁决。

---

### F-03【中高·条件性】全局允许明文流量 + XUpdate 自更新 + 安装 APK 权限

**证据**

APK 内唯一的 network-security-config（清单引用 `@7F140008`）：

```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="true"/>
</network-security-config>
```

清单与代码：

```text
<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>
<uses-permission android:name="android.permission.INSTALL_PACKAGES"/>
<service android:name="com.xuexiang.xupdate.service.DownloadService"/>
更新失败：apk的下载缓存目录为空！
更新失败：已经被忽略的版本！
下载失败 / 安装APK失败！
```

**影响（条件性）**

- 若更新配置/下载地址为 `http://`，或服务端被劫持，攻击者可篡改版本信息与下载包。
- 结合 `REQUEST_INSTALL_PACKAGES`，可诱导用户安装替换后的 APK（仍需用户在系统弹窗确认）。
- 明文流量也允许同网段攻击者观察/篡改其他 HTTP 请求（如有）。

**待确认项**

更新 URL 位于运行时解密的字符串中，静态分析未能还原；需动态抓包确认协议与是否校验 APK 哈希/签名。

**修复建议**

- `cleartextTrafficPermitted="false"`，仅对必要域名开白名单。
- 更新清单使用离线签名（如 Ed25519），客户端验签后再下载。
- 安装前校验 APK 签名证书与 SHA-256，拒绝非预期签名。

---

### F-04【中·条件性】FileProvider 声明 `root-path` 与全盘 `external-path`

**证据**

三个 FileProvider 与三份 paths 配置：

```xml
<provider android:name="androidx.core.content.FileProvider"
          android:authorities="com.zhenxi.hunter.provider"
          android:exported="false" android:grantUriPermissions="true"/>
<provider android:name="com.xuexiang.xupdate.utils.UpdateFileProvider"
          android:authorities="com.zhenxi.hunter.updateFileProvider"
          android:exported="false" android:grantUriPermissions="true"/>
<provider android:name="androidx.core.content.FileProvider4Utils"
          android:authorities="com.zhenxi.hunter.xutil.provider"
          android:exported="false" android:grantUriPermissions="true"/>
```

```xml
<!-- 其中一份：声明 root-path，全盘映射 -->
<paths>
  <root-path name="root" path=""/>
  <files-path name="files_path" path="."/>
  <cache-path name="cache_path" path="."/>
  <external-path name="external_path" path="."/>
  <external-files-path name="external_files_path" path="."/>
  <external-cache-path name="external_cache_path" path="."/>
</paths>

<!-- 另一份：files/cache/external 全部映射为 . -->
<paths>
  <files-path name="update_files_path" path="."/>
  <cache-path name="update_cache_path" path="."/>
  <external-path name="update_external_path" path="."/>
  <external-files-path name="update_external_files_path" path="."/>
  <external-cache-path name="update_external_cache_path" path="."/>
</paths>
```

**影响（条件性）**

- Provider 本身 `exported=false`，第三方应用不能直接访问；但只要应用在分享/更新流程中把某个 URI 授予第三方，`root-path` 允许该 URI 指向整机任意路径。
- 若未来某个导出组件或深链接受外部传入的路径/URI，就等同于任意文件读取（日志、配置、APK、其他应用可读文件）。
- `UpdateFileProvider` 把外部存储根目录整体映射，下载目录之外的用户文件也可能被纳入可分享范围。

**修复建议**

- 删除 `root-path`；只保留 `cache-path`/专用下载子目录。
- 分享前校验路径是否位于允许目录内（规范化后前缀匹配）。
- 不接受外部传入的绝对路径。

---

### F-05【中】release 包可被 profiling（`profileable shell=true`）

**证据**

```xml
<profileable android:shell="true"/>
```

**影响**

- `adb shell` 可使用 `simpleperf` / `perfetto` / heap dump 对 release 应用采样，读取 native 内存、Java 堆与执行路径。
- 对一个以"反调试、反注入"为卖点的应用，这相当于官方留下了一个调试通道，便于攻击者提取加密字符串、定位检测函数并 patch。
- 与 `android:largeHeap="true"` 叠加，堆转储更容易成功。

**修复建议**

- 移除 `profileable`，或只在 debug variant 的清单中保留。
- 敏感数据不长期驻留内存，使用后立即清零。

---

### F-06【中低】指纹库仅 ZipCrypto 加密，且随包附带内部资料

**证据**

- `assets/data.zip` → `data.json`，25,427,761 字节；`compress_type=8`、`flag_bits=11`（传统 ZipCrypto，非 AES）。
- 口令未在静态字符串中出现，应由运行时字符串解密逻辑提供。
- 同目录附带 `HunterRuntime.pdf`（272,562 B）与 `AndroidReverse.pdf`（461,230 B）。

**影响**

- ZipCrypto 存在已知明文攻击面；若攻击者能获得 `data.json` 头部若干字节（JSON 结构通常高度可预测），可离线恢复密钥。
- 指纹库泄露后，攻击者可针对性地伪造机型/硬件字段，降低"改机检测"的有效性。
- 附带 PDF 会直接暴露检测设计、课程内容与工具链信息。

**修复建议**

- 不要把规则库以可离线解密的形式随包分发；改为服务端下发（签名+加密，密钥与设备/账号绑定）。
- 如必须本地缓存，使用 Android Keystore 派生密钥 + AES-GCM。
- 不要把内部文档打进 release 包。

---

### F-07【中·合规】权限过度与隐私风险

**证据（节选）**

```text
QUERY_ALL_PACKAGES
PACKAGE_USAGE_STATS
READ_PHONE_STATE
READ_PRIVILEGED_PHONE_STATE
READ_LOGS
INSTALL_PACKAGES
SYSTEM_ALERT_WINDOW
ACCESS_FINE_LOCATION / ACCESS_COARSE_LOCATION
BLUETOOTH_SCAN / BLUETOOTH_CONNECT
READ_EXTERNAL_STORAGE / WRITE_EXTERNAL_STORAGE
ACCESS_ADSERVICES_AD_ID / com.google.android.gms.permission.AD_ID
com.xiaomi.security.permission.ACCESS_XSOF
com.soter.permission.ACCESS_SOTER_KEYSTORE
```

**影响**

- `QUERY_ALL_PACKAGES` + `PACKAGE_USAGE_STATS` 可枚举全量应用与使用习惯；配合定位、蓝牙、AD_ID，属于高敏感画像。
- 项目包含 Firestore 依赖；若上传应用列表/设备信息，存在个人信息保护合规风险（国内 PIPL、应用商店审核）。
- `READ_LOGS`、`INSTALL_PACKAGES`、`READ_PRIVILEGED_PHONE_STATE` 对普通应用无效，属冗余声明，但会提高商店风控评分。

**修复建议**

- 仅保留检测必需权限；应用列表在本机聚合为布尔结果，不上传原始列表。
- 隐私政策中明确采集范围与用途；提供关闭开关。
- 删除无效的系统级权限声明。

---

### F-08【低】Native 加固良好，但 `extractNativeLibs=true` 便于离线分析与替换

**证据（`pyelftools`）**

```text
libhunter.so:
  ET_DYN / EM_AARCH64（PIE）
  PT_GNU_STACK flags=6（NX）
  PT_GNU_RELRO 0x35dde0, size 0xb220
  DT_FLAGS=0x8（DF_BIND_NOW）, DT_FLAGS_1=0x1（DF_1_NOW）
  .got 0x366b60 / .got.plt 0x3672d8 均落在 RELRO 区间内
  .symtab = None（已剥离）
  .dynsym = 2442
  __stack_chk_fail 存在
  *_chk 符号 18 个（部分 FORTIFY）
```

**结论**

- 该库实际为 **Full RELRO + BIND_NOW**，配合 PIE/NX/Canary/FORTIFY，编译期加固达到较好水平；`.symtab` 已剥离，静态 JNI 导出仅 2 个，逆向门槛主要来自字符串加密与业务混淆，而不是加固缺失。
- 唯一可提的配置项是 `android:extractNativeLibs="true"`：`.so` 会被解压到磁盘，便于离线复制、比对与在 root 设备上替换/打补丁。签名校验可以拦截替换，但校验本身的结论仍受 F-01/F-02 影响。

**修复建议**

- 如无兼容性要求，可改为 `extractNativeLibs=false`（Android 6.0+ 支持从 APK 直接加载）。
- 继续保留 Full RELRO/NX/Canary，并在服务端校验 ELF 哈希。

---

### F-09【低·稳定性】误报与自伤

**证据**

```text
check ptrace thread create fail!
Seccomp+Bpf attach error ,error msg ->
检测到CRC线程未开启！程序退出！
检测到过大的充电功率 - ... 可能是云手机
当前手机不支持密钥认证检测
环境信息查询失败！当前系统非ROM原生系统 ！
```

**影响**

- 部分 ROM/内核限制 ptrace 或 seccomp，会导致守护线程创建失败，应用直接退出或误报"被调试"。
- 快充（高功率）会被当作云手机特征，误伤正常用户。
- 指纹库过期会让新机型被判定为"机型被修改"。
- 这些误报会削弱检测结果的可信度，也给用户带来可用性问题。

**修复建议**

- 对 ptrace/seccomp 失败做降级处理，区分"不支持"与"被篡改"。
- 云手机判定改为多特征加权，不用单一充电功率阈值。
- 指纹库支持服务端热更新与未知机型降权。

---

### F-10【低·信息】导出组件与冗余声明

**证据**

```text
MainActivity                       exported=true（无敏感 extra 处理）
GenericIdpActivity/RecaptchaActivity exported=true（Firebase Auth SDK 自带）
ProfileInstallReceiver             exported=true（DUMP 权限保护）
RevocationBoundService             exported=true（Google 签名权限保护）
ZhenxiServer/ZhenxiServerTwin      exported=false
ShareActivity/FeedbackActivity     exported=false
```

**影响**

- `MainActivity` 可被任意应用拉起（singleTask），可被用于前台劫持/骚扰；结合本应用自身的 `SYSTEM_ALERT_WINDOW`，存在 tapjacking 展示面。
- Firebase 导出组件为 SDK 默认，风险取决于版本，建议随 SDK 升级。
- 冗余权限声明提高审核风险。

**修复建议**

- 非启动器入口一律 `exported=false`。
- 保持 Firebase/GMS 依赖为最新版本。
- 删除无效权限。

---

## 6. 检测能力评估

| 检测维度 | 实现层 | 可靠性 | 说明 |
|---|---|---|---|
| Root 管理器包名 | Java | 低 | 改包名/隐藏应用即可绕过 |
| Root 文件路径 | Java | 低 | 路径可重定向/删除 |
| Magisk/APatch 挂载 | Native | 中 | 检查 mountinfo/overlayfs，依赖内核行为 |
| Zygisk/Riru/LSPosed | Native | 中 | 特征多，但可被 Shamiko 类工具隐藏 |
| Xposed 框架 | Native+Java | 中 | 经典特征，易被针对性隐藏 |
| Frida 线程/管道 | Native | 中 | `gum-js-loop`/`linjector`，改名/改管道可绕过 |
| inline hook / CRC | Native | 中高 | 内存与磁盘比对，但仍在同进程 |
| ptrace/seccomp | Native | 高（条件） | 依赖 ROM 支持，失败会误报 |
| 模拟器/云手机属性 | Native | 低 | 属性/节点可伪造 |
| 充电功率 | Java | 低 | 快充误报，hook BatteryManager 即绕过 |
| 硬件指纹一致性 | Java+库 | 中 | 依赖 25 MB 指纹库时效性 |
| Bootloader/密钥认证 | 系统 API | 高 | XSOF/SOTER/KeyStore/Play Integrity |
| 最终判定 | 本地 | 低 | 可被 hook 伪造（F-01） |

---

## 7. 结论

1. **检测覆盖面很广**，实现上采用"Java 包名/属性扫描 + native 内核级检查 + 隔离进程 + 系统认证"的组合，工程完整度高。
2. **没有发现远程可利用的内存破坏漏洞或敏感导出组件**；唯一导出业务组件 `MainActivity` 未处理敏感外部数据。
3. **真正的缺陷在可信模型**：检测与判定都在客户端，且自保护为同进程自证，攻击者可通过 hook/重打包让任意环境显示为"安全"。
4. **配置层面存在明确可改进项**：全局明文流量、FileProvider 全盘映射、release 可 profile、ZipCrypto 指纹库、权限过度。
5. 如果该应用的结果要用于真实风控，建议把"判定"上移到服务端，并把 Play Integrity / 硬件 attestation 作为结论的一部分；否则该检测只能作为"提高成本"的手段，不能作为可信依据。

---

## 附录 A：关键字符串证据

### A.1 native（`libhunter.so`，节选）

```text
checkPtraceTracerForMain is start ,tracer tid ->
main process check  error TracerPid - >
check ptrace thread create fail!
check ptrace thread setname fail!
>>>>>>>>>>>> native kill self  process !!!!!!!!!!
JNI_OnLoad install seccomp
install_check_arch_seccomp prctl(PR_SET_NO_NEW_PRIVS)
install_check_arch_seccomp prctl(PR_SET_SECCOMP)
Seccomp bpf Rule is Replaced !
Seccomp+Bpf attach error ,error msg ->
checkLinkerCheckSum
checkLibCheckSum
check_elf_checksum [
fetch_checksum_of_library open file error
find libart.so hooked
Linker Find Hook Mark
Base Check Inline Flag
Twin Service Crc Find Hooked
Twin Service Hardware Check Find Hooked
ISO Service Hardware Find Hooked
Find Frida NAME PIPE(linjector)
gum-js-loop
gmain
/dev/ashmem//jit-cache
/memfd:/jit-cache
jit-cache)unusual jit-cache ->
JNI_OnLoad find maybe unidbg
JNI_OnLoad check unidbg
/sbin/.magisk
/data/adb/magisk
/cache/magisk.log
/system/addon.d/99-magisk.sh
/dev/magisk/img
/data/magisk.apk
/system/bin/magisk32
checkMagiskMark find file
Find Magisk Modules Mark
/sbin/.magisk/modules/riru_lsposed
/sbin/.magisk/modules/riru_edxposed
/sbin/.magisk/modules/taichi
/sbin/.magisk/modules/dreamland
/data/misc/riru/modules/dreamland
/system/framework/XposedBridge.jar
/system/lib64/libxposed_art.so
/system/lib64/libxposed_art.so.no_orig
/system/lib64/libzygisk.so
/system/lib64/libzygisk_loader.so
find zygisk detected ,zygote root pid
top.canyie.magiskkiller.SubprocessMain
/data/adb/ap
/data/adb/apd
/data/adb/ap/su_path
/data/adb/ap/log/bin/magiskpolicy
kernelSu
found OVERLAYFS_SUPER_MAGIC, but no overlayfs mount found
find OverlayFS ->
/proc/self/mounts
/proc/self/mountinfo
/proc/self/mountstats
/proc/self/map_files/
/proc/self/attr/current
Time stamp anomaly detected for /proc/self/attr/current
Check Maps Find Hide
RuntimeHideMapsMarks
getZhenxiInfoMapELF
check sandbox
>>>>> NOT FIND SANDBOX
com.netease.mumu.cloner
/system/bin/tencent_virtual_input
/data/local/tmp/mqc-scrcpy.jar
/sys/devices/virtual/misc/goldfish_pipe
/sys/module/goldfish_audio
/dev/goldfish_pipe
/system/lib/libc_malloc_debug_qemu.so
/system/lib/vboxguest.ko
/system/lib/vboxvideo.ko
/sys/module/vboxsf
/init.vbox2345_x86.rc
CheckVpn
Find Vpn Native
JNI_OnLoad mainPid check COORDINATE_TAG success
frida AntiReadText read error
```

### A.2 Java/DEX（节选）

```text
/system/app/Superuser.apk
/system/xbin/su
/system/sd/xbin/
/system/xbin/
/sbin/
/data/local/
/data/local/bin/
/data/local/xbin/
isRooted
rootCause
DEVICE_ROOT
checkRootFromAVCLog
Landroid/net/NetworkCapabilities;
TRANSPORT_VPN
Landroid/os/BatteryManager;
DEVICE_CHARGING
Landroid/content/pm/Signature;
getApkContentsSigners
Lcom/google/firebase/appcheck/playintegrity/FirebaseAppCheckPlayIntegrityRegistrar;
Lcom/google/firebase/firestore/FirebaseFirestore;
com.xiaomi.security.xsof.IMiSafetyDetectServer
com.xiaomi.security.xsof.SAFETY_DETECT_SERVICE
TENCENT_SOTER_SCENE
android-keystore://
setAttestationChallenge
exchangePlayIntegrityToken
```

### A.3 资源字符串（判定结果）

```text
未发现风险 / 风险设备 / 高风险设备 / 黑灰产设备
当前设备不可信！
当前手机可能已经被Root
当前手机可能存在Magisk
当前Apk可能被Hook
当前设备指纹可能被修改！
可能存在自定义ROM
当前手机已经被解锁
当前手机Boot分区签名验证失败
检测到Frida线程
检测到程序可能正在被调试
检测到Root
检测到可疑Root文件
检测到FakeLocation已开启
检测到过大的充电功率 - 可能是云手机
环境信息查询失败！当前系统非ROM原生系统 ！
检测到CRC线程未开启！程序退出！
检测进程未开启
检测Ptrace进程未开启
```

---

## 附录 B：组件导出清单

| 组件 | 导出 | 说明 |
|---|---|---|
| `com.zhenxi.hunter.MainActivity` | true | 唯一导出业务组件，singleTask |
| `com.zhenxi.hunter.ZhenxiServer` | false | isolatedProcess |
| `com.zhenxi.hunter.ZhenxiServerTwin` | false | useAppZygote |
| `ShareActivity` / `FeedbackActivity` / `SecCameraActivity` / `LogActivity` / `BaseActivity` | false | 业务页面 |
| `com.google.firebase.auth.internal.GenericIdpActivity` | true | Firebase SDK |
| `com.google.firebase.auth.internal.RecaptchaActivity` | true | Firebase SDK |
| `androidx.profileinstaller.ProfileInstallReceiver` | true | 受 `android.permission.DUMP` 保护 |
| `com.google.android.gms.auth.api.signin.RevocationBoundService` | true | 受 Google 签名权限保护 |
| 三个 FileProvider | false | 均 `grantUriPermissions=true` |
| `com.xuexiang.xupdate.service.DownloadService` | 默认 false | 无 intent-filter |

---

## 附录 C：安全相关权限

```text
QUERY_ALL_PACKAGES
PACKAGE_USAGE_STATS
READ_PHONE_STATE
READ_PRIVILEGED_PHONE_STATE
READ_LOGS
INSTALL_PACKAGES
REQUEST_INSTALL_PACKAGES
SYSTEM_ALERT_WINDOW
ACCESS_FINE_LOCATION
ACCESS_COARSE_LOCATION
ACCESS_LOCATION_EXTRA_COMMANDS
BLUETOOTH / BLUETOOTH_ADMIN / BLUETOOTH_SCAN / BLUETOOTH_CONNECT
CAMERA
USE_BIOMETRIC / USE_FINGERPRINT / USE_FACERECOGNITION
READ_EXTERNAL_STORAGE / WRITE_EXTERNAL_STORAGE
ACCESS_ADSERVICES_AD_ID
com.google.android.gms.permission.AD_ID
com.xiaomi.security.permission.ACCESS_XSOF
com.soter.permission.ACCESS_SOTER_KEYSTORE
```

---

## 附录 D：复现命令（静态）

```powershell
# 解包
Copy-Item .\com.zhenxi.hunter.App.apk.1 .\app.zip
Expand-Archive .\app.zip -DestinationPath .\x -Force

# 解析清单/组件/权限
python -c "from loguru import logger; logger.remove(); from androguard.core.apk import APK; a=APK(r'app.zip'); print(a.get_package(), a.get_permissions())"

# 提取 DEX 字符串与类
python -c "from loguru import logger; logger.remove(); from androguard.core.dex import DEX; d=DEX(open(r'x/classes.dex','rb').read()); print(len(d.get_classes()), len(d.get_strings()))"

# ELF 安全选项
python -c "from elftools.elf.elffile import ELFFile; e=ELFFile(open(r'x/lib/arm64-v8a/libhunter.so','rb')); print([ (s.header.p_type, s.header.p_flags) for s in e.iter_segments() ])"

# 中文资源字符串
python -c "import re; t=open(r'x/resources.arsc','rb').read().decode('utf-8','ignore'); print(len(re.findall('[\u4e00-\u9fff]+', t)))"
```

> 说明：以上为本次分析使用的等价命令；临时脚本位于 `%TEMP%\zx\`，可能被系统清理。

---

## 免责声明

本报告基于对样本 APK 的静态逆向分析，未进行动态运行、网络交互或对真实设备的攻击验证。报告中标注"条件性"的结论需要进一步动态测试确认。请在获得授权的前提下使用本报告内容。

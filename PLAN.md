# Phantom Stealer v2 二次开发规划书（v10 — COM IElevator 移植版）

---

## 重大勘误

### v2 → v5 修正（已确认，摘要）

| 版本 | 修正要点 |
|------|---------|
| v2→v3 | xaitax 签名悖论 → 内存读取；NtDuplicateObject → 文件复制三元组；ISO 无用 → 砍掉 |
| v3→v4 | elevator key 幻想 → 只取 cookie v20；WAL 锁幻觉 → 共享兼容证明；GUI syscall → 砍掉，换 maldev keylog |
| v4→v5 | CPU 炸弹 → 查表+预筛选+稀疏采样；Chrome 未运行 → 静默启动；uTLS → 砍掉 |

### v5 → v6 修正（已确认）

| 编号 | v5 问题 | 失败原因 | v6 修正方案 |
|------|--------|---------|-----------|
| 漏洞G | `--no-startup-window` 静默启动 Chrome → 扫内存拿 key | Chrome 惰性解密（Lazy Decryption） | SW_HIDE + --restore-last-session |
| 漏洞H | 内存扫描步长=8 | 密钥起始地址非 8 字节对齐时全部错过 | 步长改为 4（PartitionAlloc 16字节对齐） |
| 漏洞I | UPX 压缩作为构建流水线最后一步 | UPX .UPX0/.UPX1 节区秒杀静态特征库 | 砍掉 UPX |
| 漏洞J | PLAN 只讨论 Chrome，忽略其他 Chromium 浏览器 | Edge ~15% 市场份额同样受 ABE 影响 | 全 8 浏览器 ABE 覆盖 |

### v6 → v7 修正（本版 —— 两个致命架构漏洞）

| 编号 | v6 问题 | 失败原因 | v7 修正方案 |
|------|--------|---------|-----------|
| **漏洞K** | "先扫内存，后读文件"时序死锁（Catch-22） | 内存扫描需要 AES-GCM 验证候选 key，但验证所需的密文+IV+Tag 样本在 Cookies/Login Data 数据库里——而读数据库被放在了"拿到 key 之后"。扫描器拿到 2000 个候选块却无法判断哪个是真 Key，整个 ABE 流程瘫痪。 | **完全放弃熵值搜索方案。** 改用 LummaC2/Remus 的**结构确定性方法**：走 PEB → 定位 chrome.dll → 特征码搜索 `os_crypt_async::Encryptor` vftable 引用 → 扫描内存匹配 vftable 指针 → 走已知偏移取 `v20_master_key` → 注入 51 字节 shellcode 调 `CryptUnprotectMemory`。不依赖数据库样本，从根源消灭 Catch-22。详见 2.2。 |
| **漏洞L** | Keylogger 的 `AttachThreadInput` 死亡陷阱 | WH_KEYBOARD_LL 回调运行在木马线程上下文，`AttachThreadInput` 强行绑定前景窗口线程的输入队列。若目标窗口卡顿或受 UIPI 隔离 → 钩子线程死锁 → `LowLevelHooksTimeout`（默认 300ms）→ Windows 内核强杀钩子。键盘记录器实战中活不过 1 分钟。 | 砍掉 `AttachThreadInput`。改用 `GetAsyncKeyState` 逐键追踪修饰键（Shift/Ctrl/Alt/CapsLock），手工构建键盘状态数组传给 `ToUnicodeEx`。牺牲死键组合的完美翻译（ê/ë 等），换取钩子稳定性。详见 八。 |

### v7 → v8 修正（本版 —— 三个致命/严重架构漏洞 + 向 LummaC2 实际实现全面对齐）

| 编号 | v7 问题 | 失败原因 | v8 修正方案 |
|------|--------|---------|-----------|
| **漏洞M** | Chromium 多进程架构"皮囊陷阱"（目标定位迷失） | Chrome 运行时存在十几个进程：1 个 Browser Process（真正持有 `Encryptor` 实例）+ 数 个 Renderer/GPU/Utility 进程。v7 的进程遍历未区分进程类型，可能将大量时间浪费在扫描渲染进程的无效内存上。这些渲染进程同样加载了 chrome.dll（特征码匹配会成功），但堆内存中**不存在** `Encryptor` 实例（vftable 指针匹配失败）。虽非完全致命（遍历+逐个尝试最终会命中 Browser Process），但严重增加扫描时间与 EDR 暴露窗口。 | **新增 PEB → CommandLine 过滤**：`NtQueryInformationProcess` → PEB → `RtlUserProcessParameters` → `CommandLine` → 过滤掉 `--type=renderer` / `--type=gpu-process` / `--type=utility` 的进程，**精准锁定 Browser Process**。这是对 LummaC2 遍历全进程做法的**改进优化**——LummaC2 的"全扫直到命中"也有效，但浪费 200-800ms 每无效进程。ChromElevator 则完全绕过此问题（先全杀 → 自建单进程 = 必然是 Browser Process）。详见 2.2 Phase 1。 |
| **漏洞N** | 汇编指令"基因错乱"——B9 ≠ LEA（特征码定位崩溃） | v7 中特征码写为 `B9 ?? ?? ?? ?? 34 72 6E...`，描述为"LEA reg, [rip+disp32]"。**这是 x86 与 x64 汇编的灾难级混淆**：机器码 `B9` = `MOV ECX, imm32`（加载 32 位立即数），**绝不是** RIP 相对寻址的 LEA。x64 下 LEA 的机器码以 `8D` 为核心：`48 8D 0D` = `LEA RCX, [RIP+disp32]`，`48 8D 05` = `LEA RAX, [RIP+disp32]`。若用 `B9` 模式去匹配，匹配到的是 MOV ECX 指令（加载一个绝对常量），其后的 4 字节不是 RIP 偏移量而是绝对地址。用 `match + 7 + disp32` 公式去算会产生完全随机的垃圾地址。**后果：Phase 3 特征码匹配要么零匹配（B9 模式与 LEA 完全不兼容），要么误匹配到无关的 MOV 指令导致 vftable 地址彻底错误。整个 ABE 绕过从第一步就崩盘。** | **修正为 x64 标准 LEA 模式**：`48 8D 0D ?? ?? ?? ??` (LEA RCX, [RIP+disp32]) 和 `48 8D 05 ?? ?? ?? ??` (LEA RAX, [RIP+disp32])。对 LEA 而言 `vftable_addr = match + 7 + disp32` 公式本身是正确的——v7 的错误在于匹配了错误的 opcode，修复 opcode 后公式即正确。Remus 的 `0xEFF87` opcode 通配符掩码也是用于 LEA 匹配的。详见 2.2 Phase 3。 |
| **漏洞O** | Chrome 单例锁"幽灵竞态"——静默启动自杀式崩溃 | Chrome 是强制单例（Singleton）的。若用户在后台运行了 Chrome（常见场景："关闭后继续运行后台应用"、Chrome 扩展后台进程），`User Data\SingletonLock` 被占用。v7 执行 `CreateProcess("chrome.exe")` → 新进程检测到 lockfile 被锁 → 通过 IPC 向已有进程发送"帮我开个新窗口"消息 → **新进程立即自行退出**。v7 等待 4-5 秒后试图对已 CID 的进程句柄执行 `VirtualAllocEx` 和 `NtCreateThreadEx` → 面对的是已终止的空壳进程 → `STATUS_PROCESS_IS_TERMINATING` 异常 → 注入失败。 | **新增 `KillBrowserProcesses()` 步骤**：启动自定义浏览器进程前，先遍历并终止所有同名浏览器进程（参考 ChromElevator `browser_terminator.cpp` 的完整实现：`CreateToolhelp32Snapshot` + `Process32FirstW/Next` → `NtOpenProcess(PROCESS_TERMINATE)` → `NtTerminateProcess` → `WaitForSingleObject` 等待确认退出）。终止后 `SingletonLock` 释放，新进程可正常初始化。LummaC2 在野外同样需要此步骤（否则 Hidden Desktop 方案同样会因 lockfile 而崩溃），Gen Digital 分析中虽未逐行详述，但从其进程管理逻辑推断必然包含此步骤。详见 2.2 Phase 1。 |

### v8 → v9 修正（本版 —— 三个物理实现层致命漏洞 + 彻底放弃自构造逻辑）

| 编号 | v8 问题 | 失败原因 | v9 修正方案 |
|------|--------|---------|-----------|
| **漏洞P** | vftable → Encryptor 实例 → `KNOWN_OFFSET` 直接读 32 字节 key | C++ STL 内存布局：`v20_master_key_` 若为 `std::vector<uint8_t>` (24B 控制块 + 堆分配数据)，直接从 `instance+offset` 读 32 字节读到的是三个指针 + 结构体填充垃圾，不是密钥。正确做法必须先读 8 字节指针再解引用到独立堆内存 | **v9：彻底放弃 vftable 方案。** 改用 SYSTEM token DPAPI 直接从 Local State JSON 读取 `app_bound_encrypted_key` → 双层 DPAPI 解密 → 解析 flag 1/2/3 blob。完全绕过 Encryptor 内存结构问题。详见 Section 二 |
| **漏洞Q** | 51 字节 shellcode：`xor rdx, rdx` (cbData=0) + R8 未初始化 (随机垃圾 dwFlags) | x64 `__fastcall` ABI：`CryptUnprotectMemory(pData, cbData, dwFlags)` → RCX/RDX/R8。`xor rdx,rdx` = cbData=0 → `ERROR_INVALID_PARAMETER`。R8 未初始化 → 随机垃圾 flags。shellcode 物理报废 | **v9：彻底放弃 shellcode 注入。** SYSTEM token DPAPI 方案不需要 CryptProtectMemory（SAME_PROCESS 约束被完全绕过——SYSTEM 令牌下的 DPAPI 不需要在浏览器进程上下文中执行）。详见 Section 二 |
| **漏洞R** | `disp32 = *(int32*)(match+3); vftable_addr = match + 7 + disp32` 在 Go 中不加符号扩展 | LEA [RIP+disp32] 的 disp32 是有符号 int32，vftable 在引用指令之前时 disp32 为负数。Go 中 `binary.LittleEndian.Uint32()` 返回 uint32，直接加 uintptr 会把 0xFFFFFFF0 变成 4294967280 而非 -16，地址飞向外太空 | **v9：彻底放弃 RIP 相对地址计算。** SYSTEM token DPAPI 方案不涉及任何 PE 特征码扫描，不需要手动计算 RIP 相对寻址。详见 Section 二 |

**v8→v9 核心决策**：v8 中的 Phase 2-5（PEB 遍历 → 特征码扫描 → vftable 匹配 → shellcode 注入）全部是我们根据 Gen Digital 报告的高层描述**自行构造的**，在 `E:\skuld\ccfile\` 下所有参考仓库中**零源码实现**。v9 用 `chrome_abe_poc/main.go`（Go, 390行）+ `Chrome-App-Bound-Decryption/main.py`（Python, 285行）的 **SYSTEM token DPAPI + Flag 1/2/3 完整 blob 解析器** 替代，所有代码有公开源码直接移植，不自行构造一行逻辑。

### v9 → v10 修正（本版 —— 三个物理实现层致命漏洞 + 全面切换 COM IElevator 方案）

| 编号 | v9 问题 | 失败原因 | v10 修正方案 |
|------|--------|---------|-----------|
| **漏洞S** | Go M:N 协程调度与 `ImpersonateLoggedOnUser` 的"脱轨死锁" | Windows 的 `ImpersonateLoggedOnUser` 作用域是当前 **OS 线程**。Go 的 M:N 调度器在 `ImpersonateLoggedOnUser` 和 `CryptUnprotectData` 两行之间可能将 goroutine 迁移到另一个 OS 线程 → `CryptUnprotectData` 在普通用户权限的线程上执行 → `ERROR_ACCESS_DENIED`。被提升为 SYSTEM 的 OS 线程留在后台 → 后续被其他 goroutine 复用时全局状态污染。chrome_abe_poc 源码中**完全没有 `runtime.LockOSThread()`** | **v10：彻底放弃 SYSTEM token DPAPI。** 改用 ChromElevator 的 COM IElevator 方案——COM 调用在注入浏览器进程的 DLL 中执行，不涉及任何线程令牌模拟。详见 Section 二 |
| **漏洞T** | `findLsassProcess()` → `OpenProcess(lsass.exe)` 的 OPSEC 悖论 | lsass.exe 是整个 Windows 系统中监控级别最高的进程，所有 EDR/AV 将其视为绝对红线。直接 `OpenProcess(lsass)` 的告警级别等同于 Mimikatz 抓密码。花了 2 天工作量做间接 syscall + ntdll unhook 追求极致隐蔽，然后主动触碰最高优先级监控目标——战术自毁 | **v10：COM IElevator 方案完全不接触 lsass.exe。** Chrome 的 `elevator_service.exe` 自己就是 SYSTEM 权限，COM 调用 `CoCreateInstance(CLSCTX_LOCAL_SERVER)` 启动它来解密，不需要窃取任何进程的令牌。详见 Section 二 |
| **漏洞U** | `NCryptOpenKey("Google Chromekey1", 0, 0)` dwFlags=0 → 用户密钥库 vs 机器密钥库不匹配 | Chrome 的 Elevation Service 作为系统级服务，创建的 `Google Chromekey1` 是**机器级密钥（Machine-level Key）**。dwFlags=0 让 CNG 去 SYSTEM 账户的"用户私有密钥库"查找 → `NTE_BAD_KEYSET (0x80090016)`。需要传 `NCRYPT_MACHINE_KEY_FLAG (0x20)`。修复它违反铁律——自行修改移植代码的底层逻辑 | **v10：COM IElevator 方案不直接调 NCryptOpenKey。** Chrome 的 elevation_service.exe 内部处理 CNG KSP，它自己知道正确的 flag。我们从不接触 CNG API |

**v9→v10 核心决策**：v9 移植的 chrome_abe_poc SYSTEM token DPAPI 方案存在 3 个物理实现层致命漏洞（全部由 Go 与 Windows 底层 API 的交互特性导致，非 chrome_abe_poc 逻辑错误——C 版本中不存在这些 Go 特有问题）。修复任何一个都需要自行修改移植代码的底层逻辑，违反铁律。**v10 改用 xaitax ChromElevator 的 COM IElevator 方案**：注入预编译的 C DLL 到浏览器进程 → DLL 内部调用 Chrome 自己的 COM 解密服务 → 返回完全解密后的 master key。三个致命漏洞全部天然免疫，因为：

- 不涉及 `ImpersonateLoggedOnUser` → 无 Go 线程调度问题
- 不访问 lsass.exe → 无 OPSEC 悖论
- 不直接调 `NCryptOpenKey` → 无 CNG flag 错误

**v10 对 Chrome v144+ 的覆盖**也比 v9 更好：ChromElevator 已适配 IElevator2 新接口（v144 新增），而 chrome_abe_poc 的 Flag 3 CNG 路径需要手动调 NCryptOpenKey。

### 附加缺失（v6 补充 → v10 持续更新）

| 编号 | 缺失内容 | 版本 | 补充方案 |
|------|---------|------|---------|
| **缺失1** | 密码 ABE 解密格式未验证（chrome_abe_poc 只有 `decryptCookieValue()`） | v6 | Chrome v130+ 密码也走 ABE。需验证密码解密格式是否与 cookie v20 相同。若不同，需额外实现 `decryptPasswordABE()` |
| **缺失2** | `getMasterKey()` 对 ABE 密钥返回 nil → 整个浏览器被 `continue` 跳过 | v6 → v10 已修复 | v10 改造 `StealAll()` 调用链：检查 Local State 中 `app_bound_encrypted_key` → ABE 路径走 ChromElevator DLL 注入 + COM IElevator → 返回 32 字节 master key；无 APPB → DPAPI 路径 |
| **缺失3** | exe 路径解析 | v6 → v10 已修复 | v10 COM IElevator 方案需要浏览器 exe 路径（CreateProcess(SUSPENDED)），从注册表读取浏览器安装路径。ChromElevator `browser_discovery.cpp` 已实现完整路径查找 |
| **缺失4** | 多 Profile 时只拿到活跃 Profile 的 key | v6 → v10 已消除 | `app_bound_encrypted_key` 存放于 `User Data/Local State`（根目录），所有 Profile 共享同一个 ABE master key。v10 COM IElevator::DecryptData 返回的 32 字节 key 适用于所有 Profile 的 cookie/密码解密，与 v9 结论一致但实现路径不同（COM 服务代替双层 DPAPI） |
| **缺失5** | WAL 非原子复制一致性风险 | v6 | 低概率（<5% 导致数据丢失，非数据库损坏）。SQLite WAL checksum 校验自动跳过不一致帧。接受此限制 |
| **缺失6** | 新鲜浏览器 L3 fallback 可能仍无法触发 OSCrypt::GetKey() | v6 → v10 已消除 | v10 需要浏览器进程运行（CreateProcess SUSPENDED + DLL 注入），但 DLL 直接从 Local State JSON 读取 `app_bound_encrypted_key` → COM IElevator::DecryptData → 得 key。不依赖 Encryptor 惰性派生——无论 Chrome 是否全新安装，只要 Local State 存在加密数据即能解密 |
| **缺失7** | ABE key blob 三层 flag 格式未文档化 | **v8 → v10 不再需要** | v9 曾需要手动解析 flag 1/2/3 blob（AES-GCM / ChaCha20-Poly1305 / CNG KSP）。**v10 COM IElevator::DecryptData 返回的已经是最终 32 字节 master key**——elevator_service.exe 内部处理全部 flag 解析，payload DLL 拿到的是可直接用于 AES-GCM 解密的密钥。此知识缺口被 COM 黑盒封装自然关闭 |
| **缺失8** | 多浏览器 CLSID/IID 差异未覆盖 | **v8 → v10 已消除** | ChromElevator `browser_config.hpp` 已定义全部 5 种浏览器变体的 CLSID/IID（Chrome/Chrome Beta/Edge/Brave/Avast），含 v144+ IElevator2 新接口。COM IElevator 主路径直接覆盖所有浏览器，不需要任何回退逻辑 |
| **缺失9** | 钱包扩展目标列表不完整（仅 12 个） | **v8** | LummaC2 反向源码揭示了 **45+** 浏览器扩展钱包/2FA 硬编码 ID 列表。从 LummaC2-Stealer `CryptoWalletsAnd2FA.c` 直接移植完整列表。新增 Section 七.2 |
| **缺失10** | 浏览器进程终止后再创建未被文档化 | **v8 → v10 已修复** | v10 COM IElevator DLL 注入主路径必须 KillBrowserProcesses() → CreateProcess(SUSPENDED) → 注入 DLL。ChromElevator `browser_terminator.cpp` 提供完整实现：`CreateToolhelp32Snapshot` + `Process32FirstW/Next` → `NtOpenProcess(PROCESS_TERMINATE)` → `NtTerminateProcess` → `WaitForSingleObject`。此步骤已上升为主路径必要环节，不再是回退备选 |

---

## 一、项目现状与代码资产

### 1.1 phantom-stealer 当前状态

**13 个 Go 文件，纯 Go 项目，无 C 依赖。** 是 Skuld 的 Go 重写版，结构清晰、模块分离好。

### 1.2 参考代码库

| 路径 | 用途 | 角色 |
|------|------|------|
| `ccfile/Chrome-App-Bound-Encryption-Decryption/` | C 完整工程（xaitax ChromElevator, 1.6k stars, MIT） | **v10 主移植源**：编译为 DLL，零修改。COM IElevator/IElevator2 (5 浏览器) + AES-GCM 数据解密 + 间接 syscall + RDI。v0.20.0 (2026-02)，覆盖 Chrome v127→v144+ |
| `ccfile/chrome_abe_poc/` | Go Chrome ABE PoC（githubesson/chrome_abe_poc） | **v10 格式参考**：仅用于理解 cookie/password v20 AES-GCM 加密格式（3B prefix + 12B IV + 32B cookie prefix）。不移植其 DPAPI/令牌逻辑 |
| `ccfile/Chrome-App-Bound-Decryption/` | Python ABE 绕过（jiushill） | **v10 格式参考**：仅用于理解 Flag 1/2/3 blob 结构。COM 内部已处理解密，不移植 |
| `ccfile/ChromeV20Decrypt/` | C# Chrome v20 解密（jiushill） | **v10 算法交叉验证** |
| `ccfile/LummaC2-Stealer/` | LummaC2 逆向 C 源码（x86byte） | **v9 功能移植源**：47 个 browser extension wallet/2FA ID (`CryptoWalletsAnd2FA.c`) + CPUID 硬件指纹 (`CollectSystemInfo.c`) + DJB2 hash lookup + JSON parser (`crypt32_RelatedStuffs.c`) |
| `ccfile/OXIL_STEALER/` | Go stealer（benzoXdev） | **结构参考**：Chromium+Gecko 双浏览器、Firefox key4.db ASN1 PBE、DPAPI master key、Webhook 外传 |
| `ccfile/maldev/` | Go 恶意软件开发库（oioio-space/maldev, v0.61.0, 743 commits, MIT） | **规避库依赖**：不再"移植代码片段"，而是 `import` maldev 作为 Go 库。indirect syscall (Hell's+Halo's+Tartarus+Hash Gate, 5 call methods) + ntdll unhook (3 strategies incl. Perun) + AMSI/ETW (Caller-routed) + callstack spoofing + sleepmask (Ekko/Foliage/Inline) + blockdlls + stealthopen。所有模块共用 `evasion.Technique` 接口 + `win/syscall.Caller` 抽象 |
| `ccfile/phantom-stealer/` | phantom-stealer 参考副本 | 当前代码基准 |
| `E:\skuld\` (skuld) | 另一个 Go stealer | 功能模块移植源：clipper、games、gofile.io 上传、浏览器/钱包路径扩展 |

---

## 二、P0 - 1. Chrome App-Bound Encryption (ABE) 绕过

### 2.1 问题本质

Chrome v127+ 引入了 App-Bound Encryption：
- `encrypted_key` 在 Local State 中前缀从 `DPAPI` 变为 `APPB`
- DPAPI（`CryptUnprotectData`）对 ABE 加密的 key **直接失效**
- v127+ Cookies、v130+ Passwords 均受影响
- **不改 → 新版 Chrome/Edge/Brave 一个密码和 cookie 都偷不到**

### 2.2 技术方案：ChromElevator COM IElevator（xaitax, C, 1.6k stars）

**全部逻辑由 xaitax ChromElevator 的预编译 DLL 完成，Go 只做进程/管道编排。零行底层加解密代码由我们手写。**

**架构概览**：

```
┌─────────────────────────────────────────────────────────────┐
│ Go (phantom-stealer) — 仅编排                                │
│                                                             │
│  1. KillBrowserProcesses()       ← 终止残留浏览器进程        │
│  2. CreateProcess(browserPath, CREATE_SUSPENDED,             │
│                   STARTF_USESHOWWINDOW, SW_HIDE)             │
│     → 挂起 + 隐藏窗口                                        │
│  3. ResumeThread + Sleep(300ms)  ← ★ 借 Chrome 原生启动流程  │
│     完成 CRT/COM/GUI/ALPC 全部初始化，COM RPC 零风险         │
│  4. CreateNamedPipe              ← ★ 管道必须先于注入创建    │
│     (物理上不存在竞态：ChromElevator injector_main.cpp:52-63 │
│      验证的顺序是 pipe.Create → injector.Inject →             │
│      pipe.WaitForClient。DLL 的 Bootstrap 需数百ms 执行       │
│      PEB遍历→导入解析→重定位→DllMain，管道此时早已就绪)       │
│  5. VirtualAllocEx + WriteProcessMemory + RDI Bootstrap     │
│     → 注入预编译的 chromlevator-payload.dll                  │
│  6. ConnectNamedPipe             ← 等待 DLL 连接             │
│  7. 从 pipe 读取 "KEY:<hex>" + cookies/passwords JSON       │
│  8. TerminateProcess()           ← 清理                     │
└────────────┬────────────────────────────────────────────────┘
             │ 注入 (进程内执行)
┌────────────▼────────────────────────────────────────────────┐
│ chromlevator-payload.dll (C, 预编译, 零修改)                  │
│ 运行在 chrome.exe 进程内部 → PathValidation 自然通过          │
│                                                             │
│  1. directory_iterator(User Data/*) → 遍历全部 Profile       │
│     不是硬编码 Default。检查 Network/Cookies + Login Data     │
│  2. GetEncryptedKeyByName("app_bound_encrypted_key")        │
│     → 读 Local State → base64 解码 → 跳过 4B 前缀            │
│  3. CoCreateInstance(CLSID_Elevator, CLSCTX_LOCAL_SERVER)   │
│     → Chrome 自带的 elevator_service.exe (Google 签名)       │
│  4. IElevator::DecryptData → 返回 32 字节 v20 master key    │
│     ★ 这是 Chrome 自己的合法 COM 接口，不是 Windows 漏洞     │
│     ★ elevator_service 内部处理 DPAPI/CNG/Flag blob，       │
│       我们零行加解密代码                                     │
│  5. AES-GCM 解密 Cookies/Passwords/Cards/IBANs/Tokens       │
│  6. 通过命名管道发送 KEY + JSON 数据给 Go 端                  │
│  7. 若无 app_bound_encrypted_key → 发送 NO_ABE              │
│     → Go 端 fallback 到 phantom 原有 DPAPI 路径             │
└─────────────────────────────────────────────────────────────┘
```

**为什么 COM IElevator 是唯一正确的方案**：

| 事实 | 说明 |
|------|------|
| **Chrome 自己提供的解密接口** | IElevator/IElevator2 是 Chrome 内置的 COM 接口，设计目的就是让浏览器自身组件解密 ABE 数据。我们调用的是 Chrome 自己的合法基础设施 |
| **1.6k stars, MIT license** | xaitax ChromElevator 是此领域最成熟的开源项目，v0.20.0 (2026-02)，97 commits，持续维护 |
| **覆盖 v127→v144+** | IElevator 覆盖 v127-143，IElevator2 覆盖 v144+。5 种浏览器变体（Chrome/Edge/Brave/Avast + Beta），各有独立 CLSID/IID |
| **ferrox (Rust stealer) 验证同方案** | 另一个独立项目 ferrox 使用完全相同的 ChromElevator DLL 注入方案，证明此架构在 stealer 场景下实战可行 |
| **三个致命漏洞全部天然免疫** | 不涉及 `ImpersonateLoggedOnUser`（无 Go 线程问题）、不触碰 lsass（Chrome 自己的服务是 SYSTEM）、不调 `NCryptOpenKey`（Chrome 服务内部处理 CNG KSP） |
| **Flag 1/2/3 全版本自动处理** | Chrome 的 elevator_service 随浏览器自动更新，新 flag/新加密算法由 Chrome 自己适配。我们不需要维护 flag 解析器 |

**攻击层次澄清：我们绕过的是什么？**

```
┌──────────────────────────────────────────────────────────────┐
│ Chrome App-Bound Encryption (应用层)                          │
│ ★ 这是我们要绕过的目标                                        │
│ "只有 chrome.exe 才能调 IElevator::DecryptData"              │
│ → DLL 注入到 chrome.exe → PathValidation 通过 → COM 解密      │
├──────────────────────────────────────────────────────────────┤
│ Windows DPAPI / CNG KSP / Credential Guard (OS 层)            │
│ ★ 不需要绕过！全部正常工作                                    │
│ elevator_service.exe 是 Google 签名、Chrome 安装时注册的       │
│ 合法 COM 服务，它调用 DPAPI/CNG 是正常业务，不是攻击           │
│ 我们没有任何一行代码试图破坏或绕过 Windows 加密机制              │
├──────────────────────────────────────────────────────────────┤
│ EDR/AV 检测 (安全产品层)                                       │
│ ★ 这是 maldev 规避层的目标                                    │
│ 间接 syscall (Hell's Gate) → 绕过用户态 hook                 │
│ AMSI/ETW patch → 阻断脚本扫描/事件追踪                         │
│ callstack spoofing + sleepmask → 混淆调用栈 + 内存扫描规避     │
│ PE packer → 绕过静态特征库                                    │
└──────────────────────────────────────────────────────────────┘
```

**浏览器兼容路径**：

```
StealAll(browserType):
├── browserType ∈ {Chrome, Edge, Brave, Avast, Chrome Beta}
│   └── ABE 路径: Kill → CreateSuspended(SW_HIDE) → ResumeThread
│       → Sleep(300ms) → CreatePipe → Inject DLL → ReadPipe
│       │
│       ├── 收到 KEY:<hex> → v20 master key → 所有 Profile 的 cookie/密码已由 DLL 解密
│       └── 收到 NO_ABE:... → 浏览器未启用 ABE（旧版/企业策略禁用）
│           → fallback 到下方 DPAPI 路径
│
└── browserType ∈ {Opera, OperaGX, Vivaldi, Yandex, Chromium}
    └── DPAPI 路径（phantom 现有模块，无需修改）:
        读 Local State → encrypted_key → DPAPI 解密 → v10/v11 解密
```

**Chrome/Edge/Brave → DLL 注入；Opera/Vivaldi → 原有 DPAPI。两条路径在 Go 编排层统一调度，对外暴露同一个 `StealAll()` 接口。**

### 2.3 代码来源与分工（v10）

#### 2.3.1 移植部分：ChromElevator C 代码 —— 编译为 DLL，零修改

| 来源文件 | 功能 | 移植方式 |
|---------|------|---------|
| `src/com/elevator.cpp` + `elevator.hpp` | COM IElevator/IElevator2 接口调用（CoCreateInstance → DecryptData），5 种浏览器 CLSID/IID 适配 | 直接编译，**零修改** |
| `src/payload/payload_main.cpp` | DLL 入口：读 Local State → 调 COM 解密 → AES-GCM 解密 cookie/密码 → 命名管道通信 | 直接编译，**零修改** |
| `src/payload/data_extractor.cpp` | SQLite 查询 + AES-GCM 解密 cookies/passwords/cards/IBANs/tokens | 直接编译，**零修改** |
| `src/payload/browser_config.hpp` | 5 种浏览器配置（CLSID/IID/User Data 路径/进程名） | 直接编译，**零修改** |
| `src/payload/handle_duplicator.cpp` | 锁定文件复制（绕过浏览器文件锁） | 直接编译，**零修改** |
| `src/crypto/aes_gcm.cpp` | AES-256-GCM 加解密 | 直接编译，**零修改** |
| `src/sys/` | 间接 syscall（Hell's Gate）+ RDI bootstrap | 直接编译，**零修改** |
| `src/injector/pipe_server.cpp` | 命名管道服务端（在 injector 侧） | **不移植** — Go 自己写 pipe 通信 |

**C 代码总移植量：~2000 行，零行修改。** 编译命令：运行 ChromElevator 的 `make.bat`，产出 `chromlevator-payload.dll`。

#### 2.3.2 自行编写部分：Go 编排层（~150 行纯工程胶水代码）

| 功能 | 行数 | 说明 |
|------|------|------|
| `KillBrowserProcesses(browserExe)` | ~20 行 | CreateToolhelp32Snapshot → Process32First/Next → OpenProcess(PROCESS_TERMINATE) → TerminateProcess → WaitForSingleObject。**纯 Win32 API 调用，无逻辑设计** |
| `CreateSuspendedBrowser(browserPath)` | ~15 行 | CreateProcess(CREATE_SUSPENDED \| STARTF_USESHOWWINDOW, SW_HIDE)。SW_HIDE 确保 Chrome 窗口即使在 ResumeThread 后的 300ms 初始化期间也物理不可见 |
| `ResumeAndWaitInit(hProcess, hThread)` | ~5 行 | ResumeThread(hThread) → Sleep(300ms)。利用 Chrome 原生启动流程完成 CRT/COM/GUI/ALPC 全部初始化，消除挂起进程 COM RPC 的"幽灵 Bug"（Windows 11 22H2+ 内核隔离下的 ALPC 端口握手时序风险） |
| `CreatePipeAndInject(pid, dllBytes, pipeName)` | ~40 行 | **★ CreateNamedPipe 必须先于注入执行**（ChromElevator `injector_main.cpp:52-63` 验证的正确顺序：pipe.Create → injector.Inject → pipe.WaitForClient。DLL 的 Bootstrap 需数百ms 执行 PEB 遍历→导入解析→重定位→DllMain，管道此时早已就绪，物理上不存在竞态窗口）。然后 VirtualAllocEx → WriteProcessMemory(DLL + pipeName) → NtCreateThreadEx(Bootstrap)。**机械翻译 C→Go，严格遵循 C 源码顺序** |
| `ReadPipeData(pipeName)` | ~30 行 | ConnectNamedPipe → ReadFile 循环 → 解析 "KEY:<hex>" / "PROFILE:<name>" / "COOKIES:n:m" / "NO_ABE:..." 等结构化消息 → 收集 JSON 数据。若收到 NO_ABE，标记此浏览器走 DPAPI fallback 路径。**标准 Win32 pipe 操作** |
| `TerminateAndCleanup(pid, hProcess)` | ~10 行 | TerminateProcess → CloseHandle。**无逻辑** |
| 错误处理 + 浏览器路径查找 + 结果汇总 | ~30 行 | — |

**自行编写的 ~150 行 Go 代码全部属于"机械翻译 Win32 API 调用"——不需要设计算法、不需要理解加密、不需要处理边界条件。对照 ChromElevator C 源码逐行翻译即可。关键约束只有两条：管道先于注入创建（防时序死锁），注入前 ResumeThread+Sleep(300ms)（防 COM 初始化幽灵 Bug）。**

#### 2.3.3 不需要写的代码（全部由 ChromElevator DLL 内部完成）

| 功能 | 由 ChromElevator 的哪个文件处理 |
|------|-------------------------------|
| Local State JSON 解析 + base64 解码 | `payload_main.cpp:23-60` |
| COM IElevator CoCreateInstance → DecryptData | `elevator.cpp:25-127` |
| Flag 1/2/3 blob 解析 | Chrome elevator_service 内部处理（COM 返回的就是最终 key） |
| AES-256-GCM / ChaCha20-Poly1305 / CNG KSP 解密 | Chrome elevator_service 内部处理 |
| Cookie v20 AES-GCM 解密（3B prefix → 12B IV → decrypt → skip 32B prefix） | `data_extractor.cpp:128-179` |
| Password AES-GCM 解密（3B prefix → 12B IV → decrypt，无 prefix 跳过） | `data_extractor.cpp:181-217` |
| 锁定文件复制（Win32 CreateFile 共享读） | `handle_duplicator.cpp` |
| SQLite 查询 + JSON 序列化 | `data_extractor.cpp` |
| 间接 syscall + ntdll unhook | `src/sys/` |

#### 2.3.4 代码构成总结（v10）

```
ChromElevator C 代码（预编译 DLL，零修改）:
  COM elevator 调用:         ~130 行 (elevator.cpp)
  Payload DLL 入口 + 管道:   ~160 行 (payload_main.cpp)
  数据提取 + AES-GCM:        ~380 行 (data_extractor.cpp)
  浏览器配置 (常量):          ~80 行 (browser_config.hpp)
  锁定文件复制:              ~80 行 (handle_duplicator.cpp)
  AES-GCM 算法:              ~60 行 (aes_gcm.cpp)
  间接 syscall + bootstrap:  ~450 行 (src/sys/)
  管道服务端:                ~90 行 (pipe_server.cpp) — 在 DLL 侧需要 pipe_client
                            ─────
                            约 1430 行 C 代码，编译为 DLL，零修改

Go 编排层（自行编写，纯 API 翻译）:
  KillBrowser + CreateSuspended(SW_HIDE) + ResumeThread+Sleep: ~40 行
  CreatePipe + InjectDLL + ReadPipe + Parse + Cleanup:          ~80 行
  浏览器路径查找 + 结果汇总 + NO_ABE fallback:                    ~30 行
                                                                ─────
                                                                约 150 行 Go 胶水代码

LummaC2 功能移植:
  wallet 扩展列表 + CPUID 指纹:                              ~90 行
规避层（maldev 库依赖，import + 初始化）:
  间接 syscall + AMSI/ETW + unhook + callstack + sleepmask:  ~35 行 Go 初始化代码
  (maldev 743 commits 的库质量保证，非手工拼接)
```

### 2.4 全浏览器覆盖

ChromElevator 已实现 5 种浏览器变体的完整 COM CLSID/IID 适配：

| 浏览器 | 进程名 | IElevator IID (v127-143) | IElevator2 IID (v144+) | User Data 路径 |
|--------|--------|--------------------------|------------------------|---------------|
| Chrome | `chrome.exe` | `463ABECF-...` | `1BF5208B-...` | `%LOCAL%\\Google\\Chrome\\User Data` |
| Chrome Beta | `chrome.exe` | `A2721D66-...` | `B96A14B8-...` | `%LOCAL%\\Google\\Chrome Beta\\User Data` |
| Edge | `msedge.exe` | `C9C2B807-...` | `8F7B6792-...` | `%LOCAL%\\Microsoft\\Edge\\User Data` |
| Brave | `brave.exe` | `F396861E-...` | `1BF5208B-...` | `%LOCAL%\\BraveSoftware\\Brave-Browser\\User Data` |
| Avast | `AvastBrowser.exe` | `7737BB9F-...` | (无 IElevator2) | `%LOCAL%\\AVAST Software\\Browser\\User Data` |

所有 CLSID/IID 定义在 `browser_config.hpp` 中，编译进 DLL。Go 端只需传入浏览器类型枚举值。

Opera/OperaGX/Vivaldi/Yandex 不在 ChromElevator 当前覆盖范围内（它们未注册 COM elevation service 或使用不同的 CLSID）。可通过 `comrade_abe.py` 工具探测这些浏览器的 COM 接口并在后续版本中扩展。

### 2.5 方案对比：v10 COM IElevator vs v9 SYSTEM token DPAPI

| 维度 | v9 (chrome_abe_poc — SYSTEM token DPAPI) | v10 (ChromElevator — COM IElevator) |
|------|------------------------------------------|-------------------------------------|
| **原理** | 窃取 lsass SYSTEM 令牌 → 自己调 DPAPI → 自己解析 flag blob | Chrome 自己的 COM 解密服务（elevator_service.exe） |
| **漏洞S (Go线程)** | ❌ 致命 — LockOSThread 缺失 | ✅ 天然免疫 — 不涉及线程令牌 |
| **漏洞T (lsass OPSEC)** | ❌ 致命 — OpenProcess(lsass) | ✅ 天然免疫 — 不触碰 lsass |
| **漏洞U (CNG flag)** | ❌ 致命 — NCryptOpenKey dwFlags=0 | ✅ 天然免疫 — Chrome 服务内部处理 |
| **Chrome v144+** | Flag 3 CNG 需要手动调 API（高危） | ✅ IElevator2 已适配 |
| **Flag 1/2/3 解析** | 需从 Python 移植 Flag 2/3 到 Go | ✅ Chrome 服务内部自动处理 |
| **lsass 访问** | 必须（最高 EDR 告警级别） | 不需要 |
| **浏览器进程** | 不需要运行 | **必须**创建挂起进程 + 注入 DLL |
| **额外文件** | 零（全部 Go 编译进 exe） | **需附带预编译 DLL** (~200KB) |
| **EDR 检测面** | lsass 访问（一级告警） | 进程注入（二级告警）+ COM 服务启动 |
| **移植代码量** | ~335 行 Go（含 Flag 1/2/3） | ~1430 行 C（零修改编译）+ ~150 行 Go |
| **自写逻辑** | 0 行（但需修改移植代码修 bug） | ~150 行（纯 API 翻译，无逻辑设计） |
| **维护成本** | Flag 4 出现时需自行逆向 + 移植 | Chrome 自动更新 elevator_service，无需跟进 |

### 2.6 参考实现全景图（v10 更新）

| 项目 | 语言 | 与 v10 关系 | 核心价值 |
|------|------|-----------|---------|
| **ChromElevator** (xaitax) | C | **v10 主移植源** — 编译为 DLL，零修改 | COM IElevator/IElevator2 全套 + AES-GCM 数据解密 + 间接 syscall + RDI。**1.6k stars, MIT, v0.20.0** |
| **ferrox** | Rust | **v10 独立验证** — 使用相同 ChromElevator DLL | 证明 ChromElevator DLL 注入方案在 stealer 场景下完整可用 |
| **chrome_abe_poc** (githubesson) | Go | **v10 参考** — cookie/password v20 AES-GCM 解密格式 | 仅用于理解 v20 加密格式（3B prefix + 12B IV + ciphertext + 16B tag, cookie 有 32B 明文前缀），不移植其 DPAPI/令牌逻辑 |
| **Chrome-App-Bound-Decryption** (jiushill) | Python | **v10 参考** — Flag 1/2/3 格式文档 | 仅用于理解 flag blob 结构（COM 内部已处理），不移植其解密逻辑 |
| **ChromeV20Decrypt** (jiushill) | C# | **v10 算法验证** | Flag 1/2/3 格式交叉验证 |
| **Browser_Artifact_Framework** | Python | **v10 工程参考** — Early Bird APC 注入 + 命名管道 IPC | 若需要备选注入方式（APC 替代 RDI），可参考其注入器协议 |
| **LummaC2-Stealer** (x86byte 逆向) | C | **功能移植源** | 47 wallet 扩展 ID + CPUID 指纹 |
| **OXIL_STEALER** (benzoXdev) | Go | **结构参考** | Go stealer 代码组织 |
| **maldev** | Go | **规避库依赖** — `import` 不移植 | 间接 syscall (Hell's+Halo's+Tartarus+Hash Gate, 5 方法) + ntdll unhook (3 策略) + AMSI/ETW (Caller-routed) + callstack + sleepmask + blockdlls + stealthopen。v0.61.0, 743 commits, MIT |

**v10 不再需要的 v9 参考源**：chrome_abe_poc 和 Chrome-App-Bound-Decryption 的 DPAPI/令牌/CNG 解密逻辑全部不再移植。仅保留其 v20 解密格式作为文档参考（cookie 32B 前缀跳过等格式细节已由 ChromElevator 的 `data_extractor.cpp` 实现）。

---

---

## 三、P0 - 2. SQLite WAL 完整性修复

### 3.1 问题重评估（修正 v2 的过度定性）

v2 规划书中将 NtDuplicateObject 方案定性为"必然损坏"——**对于 NtDuplicateObject 方案，这个定性是正确的**。但 phantom-stealer 当前使用的是**普通文件复制**，不是 NtDuplicateObject。文件复制方案的问题被过度定性了。

**实际情况**：

| 数据库 | 写入频率 | WAL 未 checkpoint 导致数据丢失的概率 |
|--------|---------|--------------------------------------|
| Login Data | 极低（用户保存密码才写，日均 0-1 次） | **<5%** |
| Cookies | 极高（每次网页请求都可能写） | **10-30%**（仅丢失最近几分钟内设置的 cookie） |
| Web Data | 低（用户填表/保存信用卡才写） | **<10%** |

**不是"数据库损坏"**。SQLite 打开没有 WAL 的 .db 文件只是读取到最后一次 checkpoint 的状态——数据完整，只是不包含最近未同步的写入。

### 3.2 解决方案（改动极小）

不弃用 phantom 现有的「复制到 %TEMP% + SQLite 打开」方案。只增强为复制 WAL 三元组：

```go
// phantom 当前代码（chromium.go:244）
copyFile(loginDataPath, tempPath)

// 改为（+4 行）
for _, suffix := range []string{"", "-wal", "-shm"} {
    src := loginDataPath + suffix
    dst := tempPath + suffix
    if _, err := os.Stat(src); err == nil {
        copyFile(src, dst)
    }
}
```

改动量：**3 行 → 7 行**。不对现有架构做任何破坏性修改。

### 3.3 「Chrome 运行 → 文件锁 → 复制失败」不存在

v3 版担心"Chrome 运行时 .wal/.shm 被 SQLite 锁定导致 copyFile 失败"。经核实，**此担心不成立**：

SQLite WAL 模式在 Windows 上的文件共享策略：

| 文件 | SQLite 打开权限 | 共享模式 | `CreateFile(GENERIC_READ, FILE_SHARE_READ\|FILE_SHARE_WRITE)` |
|------|----------------|---------|------------------------------------------------------|
| `Login Data` (.db) | `GENERIC_READ\|WRITE` | `FILE_SHARE_READ\|FILE_SHARE_WRITE` | **兼容，读取成功** |
| `Login Data-wal` | `GENERIC_READ\|WRITE` | `FILE_SHARE_READ\|FILE_SHARE_WRITE`（SQLite 3.22+） | **兼容，读取成功** |
| `Login Data-shm` | memory-mapped | `FILE_SHARE_READ\|FILE_SHARE_WRITE` | **兼容，读取成功** |

这是 SQLite 的刻意设计——允许备份工具在数据库运行期间并发读取所有文件。不存在 ERROR_SHARING_VIOLATION。

**Fallback（保守防御）**：若个别文件因任何原因无法复制（旧版 SQLite、文件系统驱动干涉），仅 .db 主文件也包含最后一次 checkpoint 的完整数据（95%+ cookie、100% 密码），仅丢失 WAL 中最近几分钟未 checkpoint 的写入。

### 3.4 maldev 可移植到本模块的组件

| 组件 | 用途 | 是否引入 |
|------|------|----------|
| `evasion/stealthopen` | 绕过 EDR 路径监控打开 Chrome 文件（通过 NTFS Object ID 而非路径） | **可选**（用户目录文件不一定有 NTFS Object ID） |
| `cleanup/memory.SecureZero` | 解密后清除内存中的密钥/明文密码 | **推荐**（3 行代码，零成本） |

---

## 四、P2 - 3. ISO 投递载体

**不做。** 理由：
- Windows 11 22H2+ 已修复 CVE-2022-41091，MotW 标签会递归传播到 ISO 内文件
- 无意义的额外复杂度
- 直接编译 exe，MotW 绕过不在当前优先范围

---

## 五、编译流水线（简化版）

### 5.1 为什么需要流水线

Go 编译的 exe 有天然劣势：
1. **体积大**（5MB+，包含 Go 运行时）
2. **garble 混淆后熵值飙升**（~7.8 bits/byte），ML 模型判定为可疑
3. **浏览器下载的 exe 被标记 MotW**（Mark of the Web），触发 SmartScreen

### 5.2 简化后的流水线

```
Go 代码
  │
  ▼
[1] garble -literals -tiny -seed=random build
    产出：混淆后的 exe
  │
  ▼
[2] maldev/pe/packer — 加密 .text 段（SGN 多态编码）
    每次构建的加密外壳不同 → 哈希匹配失效
  │
  ▼
  最终投递物：混淆 + 加壳 的 exe
```

> 去掉了 v2 规划中的 ISO 封装步骤。
> 
> **v6 进一步移除 UPX**（漏洞I）：UPX 将 PE 节区重命名为 `.UPX0/.UPX1` + 解压存根 → 所有杀软静态特征库秒杀。前面 packer 的伪装（伪造导入表、熵值优化）被 UPX 完全覆盖销毁。非大规模分发型 stealer 不需要极限压缩体积。

### 5.3 maldev 模块可移植到流水线的组件

| maldev 模块 | 作用 |
|------------|------|
| `pe/packer` | 加密 .text 段、多态编码、每次构建产出不同哈希 |
| `pe/morph` | PE 结构变形，进一步降低静态检测率 |

> v5 已移除 uTLS 指纹伪装步骤。exfil 目标（Discord webhook / Telegram API / gofile.io）均为公共合法服务，企业防火墙按 IP/域名封堵，不按 TLS 指纹区别对待。使用 Go 标准 `net/http`，HTTP/2 多路复用和大文件上传稳定可靠。

---

## 六、规避增强（maldev 库集成）

### 6.0 为什么是库依赖而不是"移植几个模块"

之前 PLAN.md 把 maldev 描述为"从 maldev 移植 ~180 行代码"，这是对 maldev 性质的误解。

**maldev (`oioio-space/maldev`, v0.61.0, 743 commits, MIT) 是一个完整的 Go 恶意软件开发库**，不是代码片段集合。它的关键特征是**统一架构**：

```
所有规避模块共享同一个抽象层：

┌─────────────────────────────────────────────┐
│ evasion.Technique 接口                       │
│   Name() string                             │
│   Apply(caller evasion.Caller) error        │
│                                             │
│ → 所有模块实现同一接口，可通过 evasion.ApplyAll │
│   一键批量启用                                │
├─────────────────────────────────────────────┤
│ win/syscall.Caller (系统调用路由层)            │
│   5 种调用方法：                              │
│   · MethodWinAPI       → kernel32!Foo       │
│   · MethodNativeAPI    → ntdll!NtFoo        │
│   · MethodDirect       → 进程内 syscall 指令  │
│   · MethodIndirect     → ntdll 内 syscall;ret│
│   · MethodIndirectAsm  → Go 汇编跳板         │
│                                             │
│ → 传入 nil = WinAPI 默认（调试用）              │
│ → 传入配置好的 Caller = 所有敏感 API 走间接    │
│   syscall，完全绕过 EDR 用户态 hook           │
├─────────────────────────────────────────────┤
│ SSN 解析器（系统调用号动态获取）                 │
│   · HellsGateResolver  → 从未 hook 的 stub 读│
│   · HalosGateResolver  → 相邻 stub 偏移推算   │
│   · TartarusGateResolver → 追踪 hook 跳板    │
│   · HashGateResolver   → ROR13 hash 免字符串 │
│   · ChainResolver      → 依次尝试，命中即停   │
└─────────────────────────────────────────────┘
```

**这意味着我们不需要"拼接"任何东西**——只需要 `import` 几个包，传入同一个 `Caller` 实例，所有模块的底层 API 调用自动走间接 syscall。不是"从 maldev 复制代码到自己项目里"，而是"我们的项目 import maldev 作为库依赖"。

### 6.1 Go 编译机制：只编译用到的包

Go 的编译是**包粒度**的。`import "github.com/oioio-space/maldev/evasion/amsi"` 只编译：
1. `evasion/amsi` 包本身（~210 行）
2. 它的传递依赖（`evasion` 接口包 → `win/syscall` → `win/api`）
3. maldev 其余 25+ 个包（inject、c2、pe、collection、recon……）**一行都不编译进二进制**

这不像 C 的静态链接（整个 `.lib` 打进二进制）。实际编译进我们二进制的 maldev 代码约 800-1200 行（含传递依赖），不是整个仓库的几万行。

### 6.2 我们需要哪几个模块

#### P0 级（核心规避——必须）

**① `win/syscall` — 间接系统调用**

| 项目 | 内容 |
|------|------|
| 作用 | 替换 phantom 现有的 `syscall.NewLazyDLL("ntdll.dll")`。所有敏感 Win32 API 调用不再经过 ntdll.dll 导出表（EDR hook 所在地），而是走自己解析的 `syscall;ret` 指令 |
| Win 11 兼容性 | ✅ **完全兼容**。SSN 值随 Windows 构建版本变化，但 maldev 通过 PEB walk 在运行时动态解析，不硬编码任何系统调用号。Hell's Gate / Halo's Gate / Tartarus Gate 三种 fallback 策略确保即使某个 stub 被 hook 也能通过相邻 stub 或追踪跳板拿到正确 SSN |
| 最近提交 | 2026-05-04（文档），2026-05-03（HashFunc 修复），2026-04-28（MethodIndirectAsm + gadget pool） |
| phantom 现有状态 | **零 syscall 实现**——所有调用走 `NewLazyDLL` → EDR 全量可见 |

```go
// 用法（生产环境）
import "github.com/oioio-space/maldev/win/syscall"

caller := syscall.Must(syscall.New(
    syscall.MethodIndirectAsm,            // Go 汇编跳板，最干净
    syscall.WithResolver(syscall.NewChainResolver(
        syscall.HellsGateResolver{},
        syscall.HalosGateResolver{},
    )),
))
// 之后所有敏感操作通过 caller 调用，自动走间接 syscall
```

**② `evasion/unhook` — ntdll.dll 脱钩**

| 项目 | 内容 |
|------|------|
| 作用 | 移除 EDR 在 ntdll.dll 内存中的 inline hook。EDR 在 `Nt*` 函数入口写入 5 字节 `JMP`，指向自己的监控 DLL。Unhook 从干净源恢复原始 `mov r10, rcx; mov eax, SSN` 序列 |
| Win 11 兼容性 | ✅ **三种策略适配不同场景**：<br>· **ClassicUnhook** — 从磁盘 `C:\Windows\System32\ntdll.dll` 读单个函数的 5 字节原始 prologue 覆盖回去。低噪音，适合已知被 hook 的具体函数<br>· **FullUnhook** — 整个 `.text` 段一次性替换。彻底但动作大<br>· **PerunUnhook** — 从挂起的子进程（如 svchost.exe）读干净 ntdll 内存，**不碰磁盘**。专为 Win 11 22H2+ 磁盘读取被监控的环境设计 |
| 安全机制 | 内置 safelist——拒绝脱钩 `NtClose`、`NtReadFile` 等 Go 运行时关键函数，防止脱钩操作本身触发死锁 |
| 最近提交 | 2026-05-05（PE 解析优化），2026-05-04（文档），2026-04-27（Phase 4a） |
| phantom 现有状态 | **零实现** |

```go
import "github.com/oioio-space/maldev/evasion/unhook"

// 生产环境：Perun 模式（不碰磁盘，最隐蔽）
unhook.Perun("svchost.exe").Apply(caller)

// 如果 Perun 失败，fallback 到 Classic
unhook.Classic("NtAllocateVirtualMemory").Apply(caller)
```

**③ `evasion/blockdlls` — 阻止非微软 DLL 加载**

| 项目 | 内容 |
|------|------|
| 作用 | 调用 `SetProcessMitigationPolicy(PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES)`。进程启动后立即设置此策略，后续 EDR 尝试通过 `AppInit_DLLs` 或 image-load callback 注入自己的监控 DLL 时，Windows 加载器拒载非微软签名的 DLL |
| Win 11 兼容性 | ✅ 这是 Windows 自身的合法缓解策略，从 Win 8 开始存在，Win 10/11 完全支持 |
| 局限性 | 只影响策略设置**之后**的 DLL 加载。如果 EDR 在进程创建瞬间（我们的代码运行之前）已注入，此策略不回溯清除。因此需要与 unhook 配合使用 |

#### P1 级（重要规避）

**④ `evasion/amsi` — AMSI 扫描绕过**

| 项目 | 内容 |
|------|------|
| 作用 | 内存 patch `AmsiScanBuffer` 入口为 `xor eax, eax; ret`（返回 `S_OK` = 干净）。同时 patch `AmsiOpenSession` 的条件跳转使其始终走失败路径 |
| Win 11 兼容性 | ✅ AMSI 是用户态 DLL 接口，MS 保持向后兼容。`AmsiScanBuffer` 的函数签名和入口字节序列在 Win 10/11 全版本一致 |
| vs phantom 现有 | phantom 的 `PatchAMSI()`（`evasion.go:332-376`）功能相同，但 patch 操作本身走 `NewLazyDLL` → `VirtualProtect` → EDR 可见。maldev 的版本将 `NtProtectVirtualMemory` 路由到 Caller（间接 syscall），**patch 操作本身对 EDR 不可见** |
| 检测级别 | noisy（内存扫描器可检测 `xor eax,eax; ret` 字节模式） |

**⑤ `evasion/etw` — ETW 事件追踪阻断**

| 项目 | 内容 |
|------|------|
| 作用 | 内存 patch `EtwEventWrite` 入口为 `ret`（立即返回）。EDR 的 ETW TI（Threat Intelligence）消费者收不到进程的追踪事件 |
| Win 11 兼容性 | ✅ 同 AMSI——用户态 DLL 接口，入口字节序列跨版本一致 |
| vs phantom 现有 | phantom 的 `PatchETW()` 同样走 `NewLazyDLL`。maldev 版本走间接 syscall |

**⑥ `evasion/stealthopen` — 隐蔽文件打开**

| 项目 | 内容 |
|------|------|
| 作用 | 通过 `OpenFileById` 而不是 `CreateFileW(path)` 打开文件。路径不走 EDR 的文件系统 minifilter hook |
| 用途 | unhook 模块的 Classic 策略用它来读 `ntdll.dll`，避免路径级监控 |
| 最近提交 | 2026-04-23 |

#### P2 级（深度规避——时间允许再做）

**⑦ `evasion/callstack` — 调用栈伪造**

| 项目 | 内容 |
|------|------|
| 作用 | 在调用敏感 API 前伪造返回地址链。EDR 做 `RtlVirtualUnwind` 栈回溯时看到的是 `kernel32!BaseThreadInitThunk → ntdll!RtlUserThreadStart`，而非我们的模块 |
| Win 11 兼容性 | ✅ amd64 only（伪造的 unwind 帧依赖 x64 调用约定和 Win64 栈布局，这些从 Win 7 到 Win 11 24H2 未变） |
| 局限性 | 最多 4 个参数（RCX/RDX/R8/R9），第 5+ 个栈参数不支持 |
| 检测级别 | quiet——walkable 的帧链骗过大多数栈回溯消费者 |
| 最近提交 | 2026-04-22, 2026-04-14 |

**⑧ `evasion/sleepmask` — 睡眠混淆**

| 项目 | 内容 |
|------|------|
| 作用 | Sleep 期间用 AES-CTR 或 RC4 加密自身内存中的 shellcode/PE 区域 → Sleep → 醒来后原地解密 → 恢复内存保护。EDR 内存扫描期间看到的是随机字节 |
| Win 11 兼容性 | ✅ amd64 only（Ekko/Foliage 的 ROP 链依赖 x64 栈布局，Win 11 兼容） |
| 策略矩阵 | · **EkkoStrategy** — 完整 ROP 链（Cracked5pider/Ekko 移植），最高隐蔽度<br>· **FoliageStrategy** — APC 驱动，在另一线程执行 mask<br>· **InlineStrategy** — 线性加密-睡眠-解密，短延迟场景<br>· **RemoteInlineStrategy** — 跨进程 mask |
| 检测级别 | quiet——VirtualProtect + XOR 是高频率合法操作 |
| 最近提交 | 2026-04-24, 2026-04-23 |

### 6.3 集成方式：不是"拼接"，是"导入"

phantom-stealer 的 `go.mod` 加入一行：

```
require github.com/oioio-space/maldev v0.61.0
```

实际调用代码：

```go
import (
    "github.com/oioio-space/maldev/win/syscall"
    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/unhook"
    "github.com/oioio-space/maldev/evasion/amsi"
    "github.com/oioio-space/maldev/evasion/etw"
    "github.com/oioio-space/maldev/evasion/blockdlls"
    "github.com/oioio-space/maldev/evasion/stealthopen"
)

func InitEvasion() (*syscall.Caller, error) {
    // 1. 创建间接 syscall 调度器
    caller := syscall.Must(syscall.New(
        syscall.MethodIndirectAsm,
        syscall.WithResolver(syscall.NewChainResolver(
            syscall.HellsGateResolver{},
            syscall.HalosGateResolver{},
        )),
    ))

    // 2. 阻止 EDR 注入新 DLL
    blockdlls.Enable().Apply(caller)

    // 3. 脱钩 ntdll（Perun 优先，不碰磁盘）
    if err := unhook.Perun("svchost.exe").Apply(caller); err != nil {
        // fallback: 全量脱钩
        unhook.Full().Apply(caller)
    }

    // 4. 批量应用 AMSI + ETW patch
    evasion.ApplyAll([]evasion.Technique{
        amsi.All(),
        etw.Patch(),
    }, caller)

    return caller, nil
}
```

**这就是全部。约 35 行初始化代码。不是"从 maldev 移植 180 行"，而是"import 6 个包 + 35 行初始化"。**

### 6.4 这种方式的优势

| 对比 | 旧方案（从 maldev 移植 ~180 行） | 新方案（import maldev 库） |
|------|-------------------------------|--------------------------|
| 代码量 | ~180 行复制 + 适配 | ~35 行初始化 |
| 维护 | 自己维护移植代码，maldev 上游更新需手动跟进 | `go get -u github.com/oioio-space/maldev` 自动更新 |
| 正确性 | 移植过程可能引入 bug（漏移植依赖、截断常量等） | 使用 upstream 已测试的 API，743 commits 的质量保证 |
| OPSEC | 手工翻译可能改变 syscall stub 字节模式 | maldev 的 MethodIndirectAsm 使用 gadget pool 随机化 |
| 兼容性 | 自己保证模块间兼容 | maldev 作者保证同一版本下所有 evasion 模块兼容（共用 Caller + Technique 接口） |

### 6.5 对 phantom 现有代码的影响

| phantom 现有代码 | 处理方式 |
|-----------------|---------|
| `evasion/evasion.go` — `PatchAMSI()`, `PatchETW()` | **删除**，替换为 maldev 版本 |
| `evasion/evasion.go` — 反调试/反VM | **保留**，maldev 不覆盖此领域 |
| `syscalls/syscalls.go` — `NewLazyDLL` 封装 | **保留作 fallback**，敏感操作路由到 maldev caller |
| `evasion/evasion.go` — Defender 操作 | **保留**，maldev 不覆盖 |

### 6.6 工作量（更新）

| # | 任务 | 优先级 | 工作量 | 来源 |
|---|------|--------|--------|------|
| 3 | 间接 syscall（引入 maldev `win/syscall` + 替换敏感 API 调用点） | P0 | **1 天**（原 2 天） | maldev win/syscall |
| 4 | ntdll unhook（引入 maldev `evasion/unhook`） | P0 | **0.2 天**（原 0.5 天） | maldev evasion/unhook |
| 5 | AMSI/ETW patch 替换（删除自写代码，换 maldev 版本） | P1 | **0.3 天**（原 0.5 天） | maldev evasion/amsi + etw |
| 10 | 调用栈伪造 | P2 | **0.5 天**（原 1 天） | maldev evasion/callstack |
| 11 | 睡眠混淆 | P2 | **0.5 天**（原 1 天） | maldev evasion/sleepmask |

**规避层节省 ~2 天**（从原来的 5 天 → 2.5 天），因为从"移植+适配+测试"变成"import + 初始化 + 验证"。

---

## 七、功能扩展（从 skuld 移植）

以下模块 skuld 已有完整 Go 实现，直接移植到 phantom-stealer：

| 模块 | skuld 源 | phantom 目标 | 内容 |
|------|---------|-------------|------|
| 剪贴板劫持 | `modules/clipper/clipper.go` | `clipper/` (新) | 11 种币的地址检测与替换 |
| 游戏会话 | `modules/games/games.go` | `games/` (新) | Minecraft(14启动器) + Steam + Epic + Riot + Uplay |
| gofile.io 上传 | `utils/requests/requests.go` | `exfil/` (扩展现有) | POST 上传大文件拿回下载链接 |
| 浏览器路径扩展 | `modules/browsers/paths.go` | `config/` (扩展现有) | 从 8 浏览器路径扩展到 37+ Chromium + 10 Gecko |
| 钱包路径扩展 | `modules/wallets/wallets.go` | `config/` + `wallets/` | 从 6 桌面钱包 + 12 扩展钱包扩展到更完整列表 |

**预估**：1 天（五个模块一起搬，主要工作是改 import 路径和适配数据结构）。

### 七.2 钱包扩展列表扩容 — LummaC2 完整 47 条目移植（v8 新增）

**来源**：`LummaC2-Stealer/_SUBS/CryptoWalletsAnd2FA.c` — LummaC2 硬编码的 47 个浏览器扩展 wallet/2FA ID。

**当前状态**：phantom-stealer `wallets/wallets.go` 已有 **38 个**扩展 ID（含 34 个钱包 + 4 个 2FA/其他）。但对比 LummaC2 完整列表，**缺失约 25 个**条目——主要是小众钱包和 2FA 验证器。

**v8 方案**：将 phantom 现有列表与 LummaC2 列表合并，去重后形成 **47 条目**完整列表。所有新增 ID 均来自 LummaC2 逆向源码（公开参考实现），非凭空杜撰。

**LummaC2 独有、phantom 缺失的条目**（应新增到 wallets.go）：

| 钱包名 | 扩展 ID | 类型 |
|--------|--------|------|
| Yoroi | `ffnbelfdoeiohenkjibnmadjiehjhajb` | Cardano 钱包 |
| Nifty | `jbdaocneiiinmjbjlgalhcelgbejmnid` | NFT 钱包 |
| Math | `afbcbjpbpfadlkmhmclhkeeodmamcflc` | 多链钱包 |
| Guarda | `hpglfhgfnhbgpjdenjgmdgoeiappafln` | 多链钱包（phantom 仅桌面） |
| EQUAL | `blnieiiffboillknjnepogjhkgnoapac` | 多链钱包 |
| Jaxx Liberty | `cjelfplplebdjjenllpjcblmjkfcffne` | 多链钱包（phantom 仅桌面） |
| BitApp | `fihkakfobkmkjojpchpfgcmhfjnmnfpi` | 钱包 |
| iWlt | `kncchdigobghenbbaddojjnnaogfppfj` | 钱包 |
| Wombat | `amkmjjmmflddogmhpjloimipbofnfjih` | 多链钱包 |
| MEW CX | `nlbmnnijcnlegkjjpcfjclmcfggfefdm` | Ethereum 钱包 |
| Guild | `nanjmdknhkinifnkgdcggcfnhdaammmj` | 钱包 |
| Saturn | `nkddgncdjgjfcddamfgcmfnlhccnimig` | 钱包 |
| NeoLine | `cphhlgmgameodnhkjdmkpanlelnlohao` | Neo 钱包 |
| Clover | `nhnkbkgjikgcigadomkphalanndcapjk` | 多链钱包 |
| Liquality | `kpfopkelmapcoipemfendmdcghnegimn` | 多链钱包 |
| Terra Station | `aiifbnbfobpmeekipheeijimdpnlpgpp` | Terra 钱包 |
| Sollet | `fhmfendgdocmcbmfikdcogofphimnkno` | Solana 钱包 |
| Auro | `cnmamaachppnkjgnildpdmkaakejnhae` | 钱包 |
| Polymesh | `jojhfeoedkpkglbfimdfabpdfjaoolaf` | Polymesh 钱包 |
| ICONex | `flpiciilemghbmfalicajoolhkkenfel` | ICON 钱包 |
| Nabox | `nknhiehlklippafakaeklbeglecifhad` | 多链钱包 |
| KHC | `hcflpincpppdclinealmandijcmnkbgn` | 钱包 |
| Temple | `ookjlbkiijinhpmnjffcofjonbfbgaoc` | Tezos 钱包 |
| TezBox | `mnfifefkajgofkcjkemidiaecocnkjeh` | Tezos 钱包 |
| DAppPlay | `lodccjjbdhfakaekdiahmedfbieldgik` | 钱包 |
| BitClip | `ijmpgkjfkbfhoebgogflfebnmejmfbml` | 钱包 |
| Steem Keychain | `lkcjlnjfpbikmcmbachjpdbijejflpcm` | Steem 钱包 |
| Nash | `onofpnbbkehpmmoabgpcpmigafmmnjhl` | 钱包 |
| Hycon | `bcopgchhojmggmffilplmbdicgaihlkp` | Hycon 钱包 |
| ZilPay | `klnaejjgbibmhlephnhpmaofohgkpgkd` | Zilliqa 钱包 |
| **2FA / Authenticator** | | |
| Authenticator | `bhghoamapcdpbohphigoooaddinpkbai` | 2FA |
| Cyano | `dkdedlpgdmmkkfjabffeganieamfklkm` | 2FA / 钱包 |
| Byone | `nlgbhdfgdhgbiamfdfmbikcdghidoadd` | 2FA / 钱包 |
| OneKey | `infeboajgfhgbjpjbeppbkgnabfdkdaf` | 2FA / 硬件钱包 |
| Leaf | `cihmoadaighcejopammfbmddcmdekcje` | 2FA |
| Authy | `gaedmjdfmmahhbjefcbgaolhhanlaolb` | 2FA（Twilio，已停止桌面端但在旧安装中存在） |
| EOS Authenticator | `oeljdldpnmdbchonielidgobddffflal` | EOS 2FA |
| GAuth Authenticator | `ilgcnhelpchnceeipipijaljkblbcobl` | 2FA |

**合并后完整列表**：phantom 现有 38 个 + LummaC2 独有 37 个（部分与 phantom 现有重叠） → 去重后约 **47 个**唯一扩展条目。

**移植方式**：直接将以上缺失条目追加到 `wallets/wallets.go` 的 `extensionWallets` map 中。工作量 <30 行代码（常量表），约 0.5 天（含验证各扩展 ID 的 Chrome Web Store 对应关系）。

**注意事项**：
- LummaC2 源码中扩展 ID 经过 `"edx765"` 字符串混淆（`GetFilePath` 函数在运行时移除 `"edx765"` 子串）。上表中所有 ID 已去除混淆，为最终真实 ID。
- Authy 桌面端已于 2024 年停止，但旧安装中仍有数据残留，保留在列表中零成本。
- 部分钱包（如 Terra Station、Sollet）可能已停止运营，但钱包数据文件仍可被提取用于私钥恢复。

---

## 八、新增功能

### 键盘记录（P1）— 移植 maldev `collection/keylog` 模块（v7 修复 AttachThreadInput 死锁）

**问题**：浏览器偷不到的密码（加密钱包密码、2FA 备份码、加密笔记），键盘输入可能抓到。

**方案**：移植 `ccfile/maldev/collection/keylog/` 模块（477行 Go），但 **必须砍掉 `AttachThreadInput`**（漏洞L）。

**v7 关键修正 — 漏洞L（AttachThreadInput 死亡陷阱）**：

maldev keylog 模块的 `translateKey()` 使用 `AttachThreadInput` 绑定前景窗口线程，以便 `GetKeyboardState` 读到正确的大写/修饰键状态。这在以下场景下导致致命死锁：

| 触发条件 | 机制 | 后果 |
|---------|------|------|
| 前景窗口线程卡顿 | `AttachThreadInput` 等待目标线程的消息队列 → 死锁 | 钩子回调卡住 |
| 高权限窗口 (UIPI 隔离) | 低完整性进程无法 attach 到高完整性进程的线程 | `AttachThreadInput` 失败或挂起 |
| 死锁超过 300ms | `LowLevelHooksTimeout` 注册表键 (Win10+，默认 300ms) | Windows 内核**强杀并永久移除钩子** |

后果：键盘记录器实战中活不过 1 分钟。

**v7 修正方案**：完全删除 `AttachThreadInput` 调用，改用 `GetAsyncKeyState` 手工构建键盘状态数组。

```go
// v7 — 无 AttachThreadInput 的修饰键追踪
func buildKeyboardState() [256]byte {
    var state [256]byte
    // 追踪各修饰键的异步状态（跨线程有效，无死锁风险）
    if (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0   { state[VK_SHIFT] = 0x80 }
    if (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0  { state[VK_CONTROL] = 0x80 }
    if (GetAsyncKeyState(VK_MENU) & 0x8000) != 0     { state[VK_MENU] = 0x80 }
    if (GetAsyncKeyState(VK_CAPITAL) & 0x1) != 0     { state[VK_CAPITAL] = 0x01 }
    // 注意: 死键状态 (VK_DEAD) 无法通过 GetAsyncKeyState 获取
    //       欧洲键盘死键序列 (^e→ê, ¨a→ä 等) 将被记录为原始按键
    return state
}
// ToUnicodeEx(wVirtKey, wScanCode, &keyState, &buf, 0x4, GetKeyboardLayout(0))
```

**代价 — 诚实的精度退化**：

| 键盘类型 | 影响 |
|---------|------|
| 英文 (US) 键盘 | **无影响** — 无死键，修饰键追踪完全准确 |
| 中文/日文/韩文 IME | **无影响** — IME 不依赖死键机制 |
| 欧洲键盘 (德/法/瑞典等) | **死键组合丢失完美翻译** — `^` + `e` → 记录为 `^e` 而非 `ê`；但独立按键和 Shift 修饰完全正确 |
| 俄文/阿拉伯文等 | 取决于布局是否使用死键。多数非拉丁布局不依赖死键 |

**移植内容与改动**（`maldev/collection/keylog/` → `phantom-stealer/keylogger/`）：

| 文件 | 内容 | v7 改动 |
|------|------|--------|
| `keylog_windows.go` | 完整实现（~477行） | **砍掉 `translateKey()` 中的 `AttachThreadInput` 调用块**（约 10 行），替换为 `buildKeyboardState()` 如上 |
| `keylog/doc.go` | 包文档 | 更新文档：标注死键翻译限制 + AttachThreadInput 移除原因 |

**保留的 maldev 组件**（不受影响）：
- `runtime.LockOSThread` + `GetMessageW` — 标准 Win32 消息泵（无风险）
- `GetAsyncKeyState` — 跨线程修饰键追踪（无风险，本身就是方案的一部分）
- HWND 缓存 + `QueryFullProcessImageName` — 前景窗口归属（无风险）
- Ctrl+V 剪贴板捕获 — 直接读剪贴板（无风险）

**OPSEC 说明**：
- `WH_KEYBOARD_LL` 安装触发 Sysmon Event 7 / ETW Win32k 事件 — **不变**
- **移除 AttachThreadInput 不会降低 OPSEC 风险，但消除了钩子熔断的根本原因**
- `SetWindowsHookEx` 走 user32→win32u→win32k.sys，不适用间接 syscall — **不变**
- 缓解：运行在 AMSI/ETW Patch + ntdll Unhook 之后，减少 telemetry 上报 — **不变**

**预估**：0.5 天（移植 maldev keylog + 删除 AttachThreadInput + 替换为 GetAsyncKeyState 方案）。

---

## 九、代码结构规划

```
phantom-stealer/
├── main.go                    # 不改动
├── config/
│   └── config.go              # 扩展：更多浏览器/钱包路径
├── browsers/
│   ├── chromium.go            # 保留 + WAL 三元组修复 + ABE 调用入口
│   ├── firefox.go             # 保留（Firefox 不受 ABE 影响）
│   ├── dpapi.go               # 保留（pre-ABE 的 DPAPI 解密）
│   └── abe.go                 # 新：Go 编排层 — KillBrowser → CreateSuspended(SW_HIDE) → ResumeThread → Sleep(300ms) → CreatePipe → Inject DLL → ReadPipe → 收数据 (~150行)
├── bin/
│   └── chromlevator-payload.dll  # 新：ChromElevator 预编译 DLL（零修改）
├── crypto/
│   └── crypto.go              # 保留
├── evasion/
│   └── evasion.go             # 改写：替换自写 AMSI/ETW 为 maldev import；反调试/反VM 保留；新增 evasionsetup.go (~35行 maldev 初始化：syscall.Caller + unhook + blockdlls + amsi + etw)
├── exfil/
│   └── exfil.go               # 扩展：gofile.io 上传（Go 标准 net/http）
├── clipper/                    # 新：从 skuld 移植
├── games/                      # 新：从 skuld 移植
├── keylogger/                  # 新：移植 maldev collection/keylog
├── wallets/                    # 扩展：+LummaC2 47 条目
├── tokens/                     # 保留
├── recon/                      # 保留
└── persist/                    # 保留
```

---

## 十、工作量汇总

| # | 模块 | 优先级 | 工作量 | 来源 |
|---|------|--------|--------|------|
| 1 | 全浏览器 ABE 绕过（ChromElevator COM IElevator DLL 注入 — 5 浏览器 CLSID/IID + IElevator2 v144+ + 间接 syscall + AES-GCM 数据解密） | P0 | 1.5 天 | ChromElevator C 代码 ~1430 行编译为 DLL（零修改）+ Go 编排层 ~150 行（纯 Win32 API 翻译） |
| 2 | WAL 三元组修复（chromium.go 改 4 行） | P0 | 0.1 天 | 自己改 |
| 3 | 规避层集成（import maldev：syscall + unhook + blockdlls + AMSI/ETW + stealthopen；~35 行初始化；替换 phantom 现有 NewLazyDLL 调用点为 maldev Caller） | P0 | **1 天**（原 2 天） | maldev win/syscall + evasion/* |
| 4 | PE 打包器 + 构建流水线（无 UPX） | P1 | 1 天 | maldev pe/packer |
| 5 | 键盘记录（移植 maldev keylog，砍掉 AttachThreadInput，换 GetAsyncKeyState） | P1 | 0.5 天 | maldev collection/keylog |
| 6 | 从 skuld 移植（clipper/games/gofile/浏览器/钱包） | P1 | 1 天 | skuld |
| 7 | 钱包扩展列表扩容（12 → 47 个扩展 ID，移植 LummaC2 完整列表 + CPUID 硬件指纹） | P1 | 0.5 天 | LummaC2-Stealer CryptoWalletsAnd2FA.c + CollectSystemInfo.c |
| 8 | 调用栈伪造（P2） | P2 | 0.5 天 | maldev evasion/callstack |
| 9 | 睡眠混淆（P2） | P2 | 0.5 天 | maldev evasion/sleepmask |
| 10 | 自删除增强（P2） | P2 | 0.5 天 | maldev cleanup/selfdelete |

**P0 总计：2.6 天 | P0+P1 总计：5.6 天 | 全部总计：7.1 天（约 1.5 周）**

> v10 规避层工作量变化：
> - 间接 syscall + ntdll unhook + AMSI/ETW：**从 3 天 → 1.3 天**（不再"从 maldev 移植 ~180 行代码 + 自行适配 + 测 bug"，改为 `import` 6 个包 + ~35 行初始化 + 替换 phantom 现有 `NewLazyDLL` 调用点）
> - callstack + sleepmask：**从 2 天 → 1 天**（同理：import 即用，不需要移植）
> - **规避层总节省 ~2.7 天**
> - ABE 绕过 + 规避层：**总计节省 ~4.2 天**（对比 v9）
> - 关于 maldev 的性质澄清：它不是"代码片段集合"——它是 **v0.61.0、743 commits、完整三层架构**的 Go 恶意软件开发库。所有 evasion 模块共用 `evasion.Technique` 接口 + `win/syscall.Caller` 抽象。我们 import 几个包，传入同一个 Caller，所有模块的底层敏感 API 调用自动走间接 syscall。不是"拼接模块"，是"使用库"

### 执行顺序

```
第 0 轮（0.1 天）— 紧急修复：
    WAL 三元组修复（3 行 → 7 行）
    理由：零风险，立即生效

第 1 轮（2.6 天）— 核心能力：
    #3 规避层集成（import maldev: syscall + unhook + blockdlls + AMSI/ETW + stealthopen）
    + #1 全浏览器 ABE 绕过（ChromElevator DLL 编译 + Go 编排层）
    理由：规避层是所有后续模块的基础——import maldev 后所有敏感 Win32 调用
    走间接 syscall。ABE 绕过不改的话新版 Chrome/Edge 偷不到东西。
    两个任务可并行：规避层仅依赖 maldev 库（纯 Go），ABE 部分需要 DLL 编译

第 2 轮（3 天）— 功能扩展：
    #4 PE 打包器 + #5 键盘记录 + #6 skuld 模块移植 + #7 钱包扩展扩容 + CPUID 指纹
    理由：数据采集能力从基础版升级到完整版；钱包从 34 个扩展到 47 个 LummaC2 完整列表

第 3 轮（1.5 天）— 规避增强：
    #8 调用栈伪造 + #9 睡眠混淆 + #10 自删除增强
    理由：在功能完整的基础上提高持久生存率。callstack + sleepmask 都是 import 即用
```

---

## 十一、关键依赖路径速查（v10 更新）

| 用途 | 来源路径 |
|------|---------|
| **ABE 绕过核心（v10 COM IElevator 方案）** | |
| ChromElevator — COM IElevator/IElevator2 + AES-GCM 数据解密 + 间接 syscall + RDI（主移植源，编译为 DLL，零修改） | `ccfile/Chrome-App-Bound-Encryption-Decryption/src/` |
| chromlevator-payload.dll 编译脚本 | `ccfile/Chrome-App-Bound-Encryption-Decryption/make.bat` |
| **v20 加密格式参考（不移植，仅供理解）** | |
| chrome_abe_poc — cookie v20 AES-GCM 格式（3B prefix + 12B IV + 32B cookie prefix） | `ccfile/chrome_abe_poc/main.go:270-303` |
| Chrome-App-Bound-Decryption — Flag 1/2/3 blob 结构文档 | `ccfile/Chrome-App-Bound-Decryption/main.py:40-59` |
| ChromeV20Decrypt — Flag 格式独立验证 | `ccfile/ChromeV20Decrypt/` |
| **LummaC2 逆向源码 (直接移植源)** | |
| 45+ 浏览器扩展 wallet/2FA ID 完整列表 | `ccfile/LummaC2-Stealer/LummaC2-Stealer/_SUBS/CryptoWalletsAnd2FA.c` |
| CPUID 硬件指纹采集 + 屏幕/语言/内存/HWID | `ccfile/LummaC2-Stealer/LummaC2-Stealer/_SUBS/CollectSystemInfo.c` |
| DJB2 哈希查找 + JSON 解析 + key 提取 | `ccfile/LummaC2-Stealer/LummaC2-Stealer/_SUBS/crypt32_RelatedStuffs.c` |
| **结构参考 — Go stealer 代码组织** | |
| OXIL_STEALER — Chromium+Gecko 双浏览器 + DPAPI 主密钥 + Firefox ASN1 PBE | `ccfile/OXIL_STEALER/` |
| **工程参考 — 注入 + IPC 协议** | |
| Browser_Artifact_Framework — Early Bird APC 注入 + Named Pipe IPC + volsnap 哈希管道名 | `ccfile/Browser_Artifact_Framework/utils/injector.py` |
| **规避层 — maldev 库依赖** | |
| `github.com/oioio-space/maldev` v0.61.0 | Go 库依赖（go.mod 一行），不移植代码 |
| 间接 syscall (Hell's+Halo's+Tartarus+Hash Gate, 5 调用方法) | `maldev/win/syscall` (import) |
| ntdll unhook (Classic / Full / Perun, 3 策略) | `maldev/evasion/unhook` (import) |
| AMSI patch (Caller-routed NtProtectVirtualMemory) | `maldev/evasion/amsi` (import) |
| ETW patch (Caller-routed) | `maldev/evasion/etw` (import) |
| 阻止非微软 DLL 注入 | `maldev/evasion/blockdlls` (import) |
| 隐蔽文件打开 (OpenFileById, unhook 依赖) | `maldev/evasion/stealthopen` (import) |
| 调用栈伪造 (x64 unwind 帧合成) | `maldev/evasion/callstack` (import) |
| 睡眠混淆 (Ekko/Foliage/Inline/RemoteInline) | `maldev/evasion/sleepmask` (import) |
| **其他移植/参考** | |
| PE 打包器 | `ccfile/maldev/pe/packer/` (移植) |
| 键盘记录 (砍掉 AttachThreadInput) | `ccfile/maldev/collection/keylog/` (移植+修改) |
| 剪贴板读取（keylog 依赖） | `ccfile/maldev/collection/clipboard/` (移植) |
| **skuld 功能模块** | |
| clipper/games/gofile/浏览器路径/钱包路径 | `E:\skuld\modules\`（skuld） |
| **威胁情报** | |
| LummaC2/Remus C2 域名检测特征 | `ccfile/maltrail/trails/static/malware/lummac2.txt` (stamparm) |

---

## 十二、风险评估（v10 更新）

### 12.1 本版已消除的漏洞

| 编号 | 漏洞 | 消除方案 | 状态 |
|------|------|---------|------|
| 漏洞K | Catch-22 时序死锁 | v7→v10：已消除 | ✅ |
| 漏洞L | AttachThreadInput 钩子熔断 | v7：砍掉 `AttachThreadInput` | ✅ v7 |
| 漏洞M | 多进程"皮囊陷阱" | v8→v10：COM 方案精准创建单一浏览器进程 | ✅ |
| 漏洞N | B9 ≠ LEA opcode 错误 | v8→v10：COM 方案不需要特征码扫描 | ✅ |
| 漏洞O | Chrome SingletonLock 自杀 | v10：KillBrowser + CreateSuspended（有意为之） | ✅ |
| 漏洞P | C++ STL vector 间接寻址 | v9→v10：COM 方案不读 C++ 对象内存 | ✅ |
| 漏洞Q | shellcode cbData=0 + R8 未初始化 | v9→v10：COM 方案不需要 shellcode | ✅ |
| 漏洞R | Go int32 符号扩展黑洞 | v9→v10：COM 方案不需要 RIP 寻址 | ✅ |
| **漏洞S** | Go M:N 调度器与 `ImpersonateLoggedOnUser` 脱轨 | v10：COM 不涉及线程令牌 | ✅ v10 |
| **漏洞T** | `OpenProcess(lsass.exe)` OPSEC 悖论 | v10：COM 不触碰 lsass | ✅ v10 |
| **漏洞U** | `NCryptOpenKey` dwFlags=0 机器密钥库不匹配 | v10：COM 不调 CNG API | ✅ v10 |

### 12.2 当前风险评估（v10）

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| **DLL 注入 + 浏览器进程相关（v10 核心风险）** | | | |
| **DLL 注入被 EDR 检测并阻断**（VirtualAllocEx + WriteProcessMemory + RDI） | **中** — RDI 规避了 LoadLibrary 监控，但跨进程内存写入是 EDR 常规检测项。告警级别**低于 lsass 访问** | **高**（注入失败 → DLL 无法进入浏览器进程 → COM 无法调用 → ABE 瘫痪） | ① ChromElevator 内置间接 syscall（Hell's Gate）。② RDI 不经过 LoadLibrary → DLL 不出现在 PEB 模块列表。③ 浏览器进程仅创建一次，数十秒完成 |
| `CreateProcess(SUSPENDED)` + `KillBrowserProcesses()` 行为链被关联 | 中 | 中 | ① 浏览器崩溃后自动恢复也是 Kill + 重建模式。② 使用 ChromElevator 的 `browser_terminator.cpp` 已验证实现 |
| Chrome v144+ PathValidation 阻止外部进程调用 COM | **低** — DLL 在浏览器进程内部执行，路径验证自然通过 | 高（若失败） | IElevator2 已适配（`browser_config.hpp` v2 IID） |
| Chrome 未安装或 elevator_service 未注册 | 低 | 中（回退 DPAPI） | 检查 Local State 中 `app_bound_encrypted_key` 字段有无 |
| **COM 服务相关** | | | |
| `CoCreateInstance(CLSCTX_LOCAL_SERVER)` 启动 elevator_service 被记录 | 低 — COM 服务启动是 Windows 常规操作，服务由 Google/微软签名 | 低 | 使用 `CoSetProxyBlanket` 标准 COM 安全配置 |
| Opera/Vivaldi/Yandex 等未注册 COM elevation service | **中** — ChromElevator 当前仅 5 种浏览器 | 中（这些浏览器 ABE 数据无法解密） | ① `comrade_abe.py` 探测 COM 接口。② 找到新 CLSID/IID → 加入 `browser_config.hpp` |
| **Chrome 版本适配** | | | |
| Chrome v145+ 引入 IElevator3 或新认证 | 低（IElevator→IElevator2 间隔约 17 个大版本） | 中 | ChromElevator 社区活跃（1.6k stars），更新 `browser_config.hpp` + 重新编译 DLL |
| Avast 无 IElevator2（v144+ 仅支持旧接口） | 低（Avast 份额极小） | 低 | Chrome 若废弃 IElevator v1 → Avast 暂时不可用 |
| **通用风险** | | | |
| 间接 syscall 被 EDR 检测 | 低 | 中 | maldev + ChromElevator 双源间接 syscall |
| Chrome cookie/密码 v20 格式变更 | 低 | 中 | ChromElevator `data_extractor.cpp` AES-GCM ~60 行，更新成本低 |
| WH_KEYBOARD_LL hook 被 EDR 检测 | 中 | 中 | 瞬时事件，AMSI/ETW Patch 后安装 |
| DLL 作为独立文件被静态扫描 | 低 | 低 | Go `embed.FS` 嵌入 exe 资源段，运行时释放到内存 |

### 12.3 v10 风险三版对比

| 特性 | v8 (vftable+shellcode) | v9 (SYSTEM token DPAPI) | v10 (COM IElevator) |
|------|----------------------|------------------------|---------------------|
| 主要检测点 | RPM + RWX + 远程线程 | **lsass 访问**（一级告警） | DLL 注入（二级告警） |
| 已知致命漏洞 | 3 (P/Q/R) | 3 (S/T/U) | **0** |
| 自构造底层逻辑 | ~460 行 | 0 行 | 0 行 |
| 版本覆盖 | v127-145（需维护特征码DB） | v127-137+（需移植 Flag 2/3） | **v127-144+**（COM 自动适配） |
| 浏览器覆盖 | 8（理论） | 7（理论） | **5（实际验证）** + 可扩展 |
| 维护成本 | 高（每 4 周更新特征码） | 中（新 Flag 逆向） | **低**（Chrome 维护 elevator） |
| 额外文件 | 0 | 0 | 1 DLL (~200KB, 可 embed) |
| 失败回退 | COM IElevator | COM IElevator | DPAPI 路径 |

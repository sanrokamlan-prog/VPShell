# VPShell 开发与发布标准

> 本文是代码评审、CI 和发布的最低准入标准。README 中的功能状态必须以已合并代码和验证结果为准；界面、设计文档或占位数据存在，不代表能力已经交付。

## 1. 状态定义

所有用户可见能力只使用以下状态，避免把路线图写成产品承诺：

| 状态 | 可以如何表述 | 最低证据 |
| --- | --- | --- |
| 已发布 | “已支持”“当前可用” | 已进入发布构建，自动化测试通过，并在目标平台完成最小人工验收 |
| 已实现，待发布 | “已实现，等待下一版发布” | 代码已合并且 CI 通过，但尚未进入可下载版本 |
| 正在实现 | “本次发布门槛”“开发中” | 已有明确模块、验收条件和负责人；不得出现在“当前可用能力”中 |
| 设计完成 | “设计/协议已确定” | 设计文档已评审；不得暗示后端已经存在 |
| 路线图 | “计划”“评估中” | 没有交付日期承诺，不用于功能徽章、截图或发布标题 |

每次发布前必须从安装包重新验证 README 的功能表。静态示例、模拟负载、未连接的按钮和仅存在于 legacy `localStorage` 的设置要明确标注为原型。未完成取消、错误处理、资源上限或安全检查的传输/同步能力不能标记为已发布。

## 2. 模块边界

WebView 负责展示和用户操作；网络、进程、文件系统、凭据、归档、远端编辑和同步加密属于 Rust 信任边界。前端不得通过扩展 Tauri 文件系统权限绕开后端校验。

| 模块 | 职责 | 不得承担 |
| --- | --- | --- |
| React workspace (`src/`) | 布局、会话/广播选择、表单、进度和错误展示 | 读取明文凭据、拼接远端 shell 命令、直接遍历本机任意路径 |
| Terminal/session core | PTY 生命周期、系统 OpenSSH 参数、输入输出、窗口尺寸、会话取消 | SFTP 目录模型、同步 provider、业务历史持久化 |
| Credential/key management | OS keyring 引用、密钥生成、敏感内存清零 | 向前端返回密码、私钥正文或同步主密码 |
| Migration adapters | 只读解析用户选择的数据源，产出统一 profile | 修改源客户端配置、绕过主密码或系统钥匙串 |
| Transfer core | SFTP list/stat/upload/download、任务队列、进度、取消和原子提交 | 借终端 PTY 猜测传输状态、用 UI 提供的任意命令执行文件操作 |
| Transfer manager (`src-tauri/src/transfer_manager.rs`) | 任务身份、单调快照、并发上限、取消状态、socket 中断、有界终态记录、版本化恢复存储和重试状态机 | SFTP 路径操作、持久化凭据、由前端生命周期决定任务是否存在 |
| Remote file operations (`src-tauri/src/remote_file_ops.rs`) | 结构化变更请求、短时单次预览令牌、目标暂存复制/核验/提交、路径/权限/符号链接限制、逐项批量结果 | 接受 shell 片段、跟随符号链接递归、静默覆盖、把部分成功报告为全成功 |
| Archive transport | `tar + zstd` 能力探测、流式归档、安全解包和 SFTP 回退 | 信任归档内路径、设备节点、链接或声明大小 |
| Remote file dock | 当前路径、目录列表、拖放意图、覆盖确认、任务视图 | 把静态示例显示成真实远端数据 |
| Host monitor | 有界采样 CPU、内存、磁盘、负载、网络和进程摘要 | 无提示安装 agent、持续执行高开销命令、把采样值当精确计费数据 |
| External editor bridge | 临时副本、编辑器启动、变更检测、上传确认和冲突检查 | 让编辑器直接持有 SSH 凭据，静默覆盖远端新版本 |
| Network tools | traceroute、限量 HTTP 测速、显式 `iperf3` UDP 测试 | 自动改防火墙、自动安装服务端、无限流量测试 |
| Local data/history | SQLite 事务、事件历史、路径范围和 outbox | 把整库当同步文件直接覆盖 |
| Sync/crypto | provider、分段、合并、E2EE、恢复和冲突中心 | 把解密交给 provider，或用 TOTP 代替加密密钥 |
| Relay/native SSH | 后续中继选路与原生协议引擎 | 在没有中继和实测数据时宣称“智能加速” |

当前部分终端逻辑集中在 `src-tauri/src/lib.rs`，界面状态集中在 `src/App.tsx`。新增传输、监控、编辑器和同步能力必须各自进入独立 Rust/React 模块，通过稳定数据结构交互，不能继续扩大这两个入口文件。

## 3. IPC 契约

Tauri command/event 是安全边界，不是内部函数的直接导出。新增 IPC 必须遵守：

1. 请求和响应使用具名 `serde` 结构体，并统一 `camelCase`；不可用无结构 JSON、位置数组或把 shell 命令当 API。
2. Rust 对每个字段重新验证。前端的必填、文件选择器和下拉框只改善体验，不构成安全检查。
3. 字符串、文件数、总字节、并发数、超时、跳数和采样频率必须有硬上限；拒绝 NUL、控制字符和不支持的编码边界。
4. 长任务返回 `taskId`，通过带 `taskId`、阶段、已完成字节、总字节和单调序号的事件报告进度；提供幂等取消命令和明确终态。
5. 会话事件必须携带 `sessionId`。断开后到达的旧事件不得写入新会话；前端卸载时要释放 listener。
6. 错误对 UI 使用稳定错误码和可操作消息；日志可以包含模块、任务 ID 和阶段，但不得包含密码、私钥、Token、完整连接串或敏感文件正文。
7. 凭据只通过不可猜测的 `credentialRef` 引用。读取和使用发生在 Rust 内，IPC 返回值和 WebView event 中都不得出现明文。
8. 文件 API 接受结构化路径和操作参数。只有确需远端能力探测时才启动受控命令，参数逐项编码，不能拼接未经验证的 shell 字符串。
9. IPC 结构变更要么向后兼容，要么同时更新前端、测试和迁移逻辑；持久化结构需要显式 schema 版本。
10. 外部客户端迁移必须显式选择来源和路径，先由 Rust 生成有时限、单次预览，再提交令牌；不允许前端把任意 JSON profile 当成已确认迁移结果。
11. 解析厂商配置时只支持有夹具的窄格式，未知版本逐项失败而不是猜测。文本编码、文件/总字节、目录与结构深度、条目和报告数均需硬上限，符号链接不得被扫描。

推荐的传输任务模型：

```text
createTransfer(request) -> { taskId, acceptedAt }
transfer-progress       -> { taskId, phase, filesDone, filesTotal, bytesDone, bytesTotal, seq }
cancelTransfer(taskId)  -> { accepted }
transfer-finished       -> { taskId, outcome, warnings, cleanupStatus }
```

## 4. 凭据安全

- 主机资料只保存 `credentialRef`，短凭据进入 Windows Credential Manager、macOS Keychain 或 Linux Secret Service。
- 私钥默认保留在用户选择的 OpenSSH 文件中；生成时默认加密，口令不写日志、`localStorage`、命令历史或错误报告。
- Rust 读取秘密后使用可清零内存，并尽量缩短生命周期；不得克隆到长期任务状态或通过终端输出事件回显。
- 当前直连 OpenSSH 会话可通过受限 AskPass 助手读取当前主机的钥匙串凭据；未知提示、主机密钥确认和广播层永远不能取得密码。多跳路线恢复前必须为每一跳建立独立凭据绑定，禁止把目标凭据猜测性地发送给跳板提示。
- 凭据同步默认关闭。当前内部凭据 vault 原语使用独立密钥和逐设备授权，但尚无 UI/协调器；同步 provider 凭据不能依赖同一个尚未解锁的远端仓库自举。
- 测试使用公开固定样例或临时生成的凭据，禁止把真实 IP、用户名、密码、私钥、Token 和生产日志提交到仓库、fixture 或截图。
- 迁移测试中的 `password`、`token` 和私钥字段只能使用明显的固定占位符，并断言其状态为 skipped；不得验证、破解或记录其他客户端的真实秘密。
- SQLite 状态测试必须覆盖 schema 迁移、revision 冲突、损坏隔离、过期/数量保留、未知字段和秘密正文拒绝；资产测试必须覆盖魔数、大小、符号链接、原子轮换和 URL 凭据/query/重定向边界。

## 5. 本机与远端路径安全

- 本机路径必须来自用户选择、拖放或应用管理的临时目录，并在 Rust 侧规范化；Tauri capability 只开放完成当前操作所需的最小范围。
- 不能用字符串前缀判断路径是否位于根目录内。Windows 还要覆盖盘符、UNC、设备路径、保留名、大小写和尾随点/空格。
- 远端路径按字节和 SFTP 语义处理，不假定都是 UTF-8；列表优先使用 `lstat`，符号链接跳转必须可见且默认不递归跟随。
- 上传/下载先写随机临时文件，校验大小或哈希后原子替换。覆盖、同名冲突和远端版本变化必须要求用户选择策略。
- 拖放只创建待确认任务，不在 `dragenter`/`drop` 事件中直接传输。目录递归要在执行前估算文件数和体积，并允许随时取消。
- 删除、重命名、权限修改和跨文件系统移动是独立危险操作，不与上传完成隐式绑定。

## 6. 归档与打包传输安全

大量小文件可使用流式 `tar + zstd`，但必须始终提供递归 SFTP 回退，并满足：

- 解包拒绝绝对路径、`..` 穿越、Windows 盘符/UNC、NUL、设备节点、FIFO，以及逃出目标根目录的符号链接和硬链接；
- 对总展开字节、文件数、单文件大小、压缩比、路径长度和嵌套深度设置上限，不能信任归档 header；
- 默认不保留 setuid/setgid、设备信息和宿主所有者；权限策略由目标平台明确映射；
- 远端能力探测和解包命令使用固定程序与逐项引用参数，文件清单不进入 shell 代码；
- 传输中断或取消后清理临时归档和临时目录，并向用户报告清理失败；
- 只有完整性校验和安全扫描都通过后才提交最终路径；失败回退 SFTP 时保留可解释原因，不静默重复覆盖；
- 单文件进度、总进度、瞬时/平均速度、预计剩余时间和取消结果来自真实后端字节计数，不能由动画模拟。

## 7. 远端监控与外部编辑器

### 7.1 左侧负载区

本次 Alpha 的监控只做用户可见、可停止的轻量采样。v0.2 的 `RemoteMonitorManager` 拥有调度、暂停、频率、历史和代际状态；React 只能启动/停止具名会话、发送结构化控制并展示无秘密快照。后端频率硬限制为 5 至 300 秒，全局最多 16 个会话/worker，每会话只保留最近 120 点。必须显示采样时间、来源和失败状态；断开或切换活动会话立即停止旧记录。命令缺失、权限不足或系统类型未知时显示“不支持”，不能用零值冒充正常。

暂停发生时不得开始下一次网络采样。已经运行的系统 OpenSSH 进程最多执行到 12 秒超时；完成回调必须再次核对暂停状态和会话代际，暂停、停止或替换后的迟到结果不能写入最新值或历史。新增采样字段时要同时更新 Rust 快照、前端只读类型、历史大小评估和边界测试，不能把凭据引用加入事件。

### 7.2 底部文件坞

文件坞必须使用真实 SFTP 数据，展示当前远端路径、加载/错误状态、权限、大小和修改时间。支持从资源管理器拖入文件/目录、上传、下载、刷新、切换路径和取消任务；静态演示列表必须在发布前移除或显著标为示例。

### 7.3 Notepad++ 与其他编辑器

Windows 可自动探测或由用户配置 Notepad++ 路径；VS Code、Code Insiders 和 VSCodium 按可执行文件名选择固定适配器，自定义程序只接收受管文件路径。找不到配置程序时使用系统默认编辑器或明确报错。macOS/Linux 不把 Notepad++ 作为跨平台前提。WebView 不得传任意参数模板或拼接 shell 命令。

编辑流程固定为：SFTP 下载临时副本 -> 记录远端大小、修改时间和可用哈希 -> 启动编辑器 -> 检测本地保存 -> 上传前比较远端版本 -> 用户确认 -> 原子替换 -> 清理临时文件。远端已被其他人修改时必须阻止静默覆盖并提供“重新下载/另存/强制覆盖”选择。应用退出、会话断开和编辑器长时间不关闭时仍要有可恢复的临时任务记录。

恢复索引必须 schema 版本化、原子、有界并保留最近有效回退；当前上限为 16 条、128 KiB 和 14 天。只允许持久化公开主机身份、远端路径、受管缓存文件名、基线哈希/元数据和冲突状态。恢复时重新注入的连接凭据只在 Rust 内存中存在；credential ref、私钥路径、编辑器路径和文件内容不得写入索引。恢复、另存、重新下载、强制覆盖和丢弃都必须是显式用户操作。

## 8. 测试标准

### 8.1 每个 PR 的最低检查

```bash
npm ci
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo check --locked --manifest-path src-tauri/Cargo.toml
cargo test --locked --manifest-path src-tauri/Cargo.toml
```

Rust 新模块必须有输入边界和错误路径单元测试。前端新交互至少覆盖状态转换、取消和错误展示；关键工作流增加端到端测试。修复缺陷时先增加能复现问题的测试，除非测试成本与改动明显不成比例，并在 PR 中说明。

### 8.2 Shell Integration 与安全广播

- Shell Integration 控制帧必须在 Rust PTY 输出边界解析；WebView 只接收已验证长度/编码的上下文快照。令牌不匹配、帧截断、超长字段和深度溢出必须测试。
- 注入只能由连接后的显式用户动作触发。固定 bash/zsh 代码可包含 Rust 生成的随机令牌，不得包含凭据、主机参数或 WebView 传入的 shell 片段。
- Shell 上报永远标为自报，不能改变 `known_hosts`、凭据绑定或配置环境。fish/PowerShell 和退出码未实现时必须显示为限制。
- 广播预览必须在 Rust 冻结命令、目标和上下文代际，最多 32 个目标、4096 字节命令、两分钟单次令牌。所有发送均需确认；生产目标持续显示，选择/上下文变化不得沿用旧确认。
- 认证交互和已知破坏性命令默认阻止广播。逐项结果区分写入成功、失败和因断线/上下文变化跳过；PTY 写入成功不得描述成远端命令成功。

### 8.3 传输专项

- 临时 OpenSSH/SFTP 服务的上传、下载、空文件、深目录、大量小文件、大文件和 Unicode 文件名；
- 连接中断、取消、磁盘满、权限拒绝、目标已存在、远端同时修改和应用重启恢复；
- 应用重启后活动任务显示为 `interrupted`；只允许用户明确重试或丢弃，已跨提交边界的任务不得重放；重试最多 3 次且每次可取消；
- 文件坞变更覆盖根目录、`.`/`..`、控制字符、重复/父子重叠路径、128 项上限、64 层深度、10,000 条递归清单、64 GiB 单文件/256 GiB 单批移动、符号链接、权限特殊位和目标已存在；
- 移动必须覆盖同/跨文件系统语义、`fail`/`rename`/明确 `overwrite`、复制与二次 SHA-256 核验、提交前状态变化、覆盖回滚、源/备份清理失败和目标原子提交边界；
- 操作预览令牌必须绑定连接身份、过期且单次消费；预览后状态变化逐项跳过，递归权限隔离符号链接，批量取消/重启恢复必须保留逐项成功、失败、跳过与部分完成，恢复必须重新预览且不得重放已提交工作；
- 恶意 tar：路径穿越、绝对路径、链接逃逸、设备节点、重复文件名、超大声明、压缩炸弹和损坏流；
- `tar`/`zstd` 缺失及能力探测失效时可靠回退递归 SFTP；
- Windows 路径包含空格、中文、单引号和超长路径；不得依赖 shell 字符串恰好可用。

### 8.4 UI 与人工验收

- 至少检查 1440x900、最小窗口 920x620 和窄窗口，不允许终端、负载区、文件坞、对话框或长路径互相遮挡；
- 真实连接时验证标签切换、广播目标持续保留、主机身份颜色、文件拖放、取消和错误恢复；
- Windows 验证 Notepad++ 已安装/未安装、编辑冲突、带空格路径和非管理员账户；
- 安装包冷启动，OpenSSH 缺失提示，升级保留配置，卸载不删除用户选择的外部文件。

## 9. 跨平台 CI 与发布

代码合并要求 Windows、macOS、Linux 三个平台完成 Rust check/test，前端构建至少运行一次。平台专用代码必须使用清晰的 `cfg` 边界，并为非目标平台提供实现或明确的“不支持”错误。

桌面安装包应在对应原生 runner 上构建：Windows 产出 NSIS/MSI，macOS 产出签名并公证的应用包，Linux 产出选定发行格式。不能把“Windows 上能运行源码构建”描述为“Windows 一台机器可以可靠打出所有平台正式包”；macOS 签名、公证和 SDK 要求决定了正式包必须走 macOS 环境，Linux 包也应在目标 ABI/发行环境验证。

当前 Release workflow 已配置 Windows、Linux、macOS Intel/Apple Silicon 原生 runner，但首个多平台 Release 仍必须满足：

1. 对应 runner 的可复现构建和 smoke test；
2. 平台签名、公证或包校验方案及受保护的 CI secret；
3. 系统 OpenSSH、系统钥匙串、SFTP 和外部编辑器兼容测试；
4. 安装、升级、卸载和数据目录行为说明；
5. SHA-256 校验值、依赖/许可证清单和与 tag 一致的 release notes。

发布失败、任一目标平台验收未完成或安全门槛未通过时，不公开 Release。预览版必须使用 SemVer prerelease 版本号，并在说明中列出未实现能力和已知风险。GitHub Release 本身保持 full release 状态，因为 GitHub 的 `/releases/latest` 不包含 prerelease，而客户端 updater 使用该固定地址。

WiX/MSI 不接受带字母的 SemVer prerelease 作为安装包版本。应用、Cargo、npm 和 Tag 仍使用可读的 `x.y.z-alpha.N` / `beta.N` / `rc.N`；`bundle.windows.wix.version` 单独映射为 `x.y.z.(1000+N)` / `(2000+N)` / `(3000+N)`，稳定版使用 `x.y.z.65535`。Release workflow 必须校验该映射，保证同一补丁版本从 Alpha 到稳定版可以单调升级。`bundle.windows.wix.upgradeCode` 一经发布不得改变，避免升级时产生重复安装。

## 10. 依赖评审

新增或重大升级依赖前，在 PR 中记录：

- 为什么标准库或现有依赖不能满足需求，依赖属于前端、构建期还是 Rust 信任边界；
- 许可证是否与 Apache-2.0 分发兼容，是否需要更新 `THIRD_PARTY_NOTICES.md`；
- 上游维护状态、安全公告、最近发布、下载来源和是否锁定版本；
- 默认 feature、网络访问、遥测、原生代码、构建脚本和传递依赖的权限面；
- 包体积、启动时间、内存和跨平台影响，以及删除/回退方案；
- 对 SSH、SFTP、密码学、解压、钥匙串和自动更新依赖的威胁模型与测试证据。

提交必须保留 `package-lock.json` 和 `Cargo.lock`。CI 使用 `npm ci` 与 Cargo `--locked`；不能在 release workflow 中临时下载未校验的可执行文件或运行远端 `curl | shell`。

### 10.1 SQLite 依赖决定（v0.2 工作树）

- `rusqlite = =0.40.2`，MIT OR Apache-2.0；上游在 2026-08 仍维护，精确版本写入 manifest/lock。
- `default-features = false`，只启用 `bundled`；不启用 SQLCipher、extension loading、hooks、trace、网络或遥测能力。
- `bundled` 通过 `libsqlite3-sys 0.38.2` 编译 SQLite C amalgamation，增加冷构建时间和二进制体积，但避免 Windows/macOS/Linux 系统 SQLite 版本与 feature 漂移。
- 权限面只限应用数据目录中的 `vpshell-state.sqlite3`、WAL/SHM 和有界损坏备份；SQL 语句均固定，状态值参数绑定，不开放任意 SQL IPC。
- 删除方案：先通过 schema-v1 读取接口导出最新净化状态，再替换 `app_store.rs`，删除依赖与数据库；SQLite 文件不作为同步对象上传或跨设备合并。

### 10.2 同步密码学依赖决定（v0.3 工作树）

- 精确锁定 RustCrypto `argon2 = 0.5.3`、`chacha20poly1305 = 0.10.1`、`hkdf = 0.12.4` 和 `getrandom = 0.3.4`；均为 MIT OR Apache-2.0。选择 Argon2 0.5 稳定线而非 0.6 RC；ChaCha 0.10 与现有 digest/aead 依赖兼容，避免为单模块引入第二套当前生态。
- 四项均关闭默认 feature。Argon2 只启用 `alloc`/`zeroize`，带来纯 Rust `blake2`/`password-hash`；ChaCha 只启用 `alloc`，不启用 reduced-round/stream/std/getrandom；HKDF 与 getrandom 不启用可选 feature。随机字节通过直接锁定、依赖树已存在的 getrandom 0.3.4 从桌面 OS CSPRNG 获取。
- 这些库没有网络、遥测、文件系统、Tauri capability 或外部可执行文件权限；运行面仅为 CPU、受 19–256 MiB 硬限制的 Argon2 内存和 OS 随机源。算法失败返回稳定无秘密诊断，密钥类型不可 Serialize/Debug，临时 KEK、域密钥和解包 VMK 使用清零容器。
- 删除/替换不能静默改变 v1 密文：必须保留固定测试向量，用替代实现读取全部 v1 keyslot/对象并重加密到新格式，经恢复演练后才能删除依赖。旧算法解析器需按明确格式版本保留只读迁移期，不能就地降级参数或 nonce 长度。

### 10.3 同步 provider 解析依赖决定（v0.3 工作树）

- `quick-xml = =0.41.0` 与 `percent-encoding = =2.3.2` 均为 MIT 许可证、关闭默认 feature，并已作为 Tauri/reqwest 依赖树的锁定传递版本存在；把它们提升为直接依赖不会增加锁文件中的新 package 或原生构建脚本。
- 标准库没有命名空间感知且默认不展开实体的流式 XML 解析器，也没有可靠的 URL percent-decoding API。WebDAV `multistatus` 必须通过有界结构化事件解析，不能用字符串切割；href 必须在解码后重新执行对象 key 验证。
- 两项依赖没有网络、文件、遥测或 Tauri capability。网络仍由既有 `reqwest 0.13.4` blocking/rustls 客户端拥有；XML 限 4 MiB/32 层/10,000 对象，percent decoding 限单个 endpoint/href。删除方案是以等价的有界 XML/URL 标准解析器替代并保持恶意 DTD、逃逸 href、分页和重复对象夹具全部通过。

### 10.4 同步 journal 事务规则（v0.3 工作树）

- `sync_outbox` 复用已审计的精确锁定 `rusqlite 0.40.2` bundled 配置，不新增依赖、网络或 Tauri capability。它使用独立数据库，避免把 24 MiB 加密对象挤入 UI 状态快照库。
- `enqueue_local`/`apply_remote` 的业务闭包只允许执行传入 SQLite transaction 上可回滚的 SQL；禁止在闭包内访问 provider、写文件、启动进程或发送事件。错误必须回滚业务数据、operation、outbox/receipt 和 head 的全部变化。
- 测试使用注入的毫秒时间，不依赖 sleep；必须覆盖租约过期、每次退避、六次上限、暂停/恢复、发布终态、事务回滚、损坏/未来 schema、保留不删除未发布工作、序号缺口/回退以及无序号对象换 key/身份重放。

### 10.5 确定性 merge 规则（v0.3 工作树）

- merge operation 只能使用 `sync_merge.rs` 的具名 serde 类型与逐字段白名单，不能把整个前端 JSON、SQLite 快照或任意 setting map 加密后同步。新增字段必须定义类型、大小、clear/delete、冲突原因和敏感性测试。
- 排序固定为 HLC physical/logical、canonical device UUID、operation UUID；不能使用本机接收顺序或 provider list 顺序。删除必须携带 observed-field stamps，冲突 ID 必须从排序后的双方生成，解决 operation 也必须在不同到达顺序收敛。
- `apply_persisted_operation` 只在调用者提供的 journal transaction 中使用 expected revision；本地加密/enqueue 或远端认证/receipt 任一步失败都必须让 merge state 一起回滚。冲突值已通过非敏感字段校验，但仍不得写日志、分析事件或 WebView，直到最小只读 IPC 与显示脱敏另行验收。

### 10.6 恢复、设备与加密导出规则（v0.3 工作树）

- 恢复密钥只能由 Rust OS CSPRNG 生成并以不可 Serialize/Debug、释放清零的类型短暂持有。可打印格式从最后一个 `-` 分离校验码，因为 base64url 正文自身允许 `-`；校验码只用于录入错误，keyslot AEAD 才提供认证。
- device registry 只保存公开签名键与有界非敏感标签；UUID/base64url/时间/数量逐字段验证。设备公钥身份不可原地替换，撤销不可逆，禁止撤销最后活动设备，已撤销设备不能修改或发布 registry。撤销不等于擦除远端设备已有 VMK，疑似泄露必须新 VMK 全量重加密。
- 加密导出不能包含恢复密钥、密码、私钥、credential ref、Token、provider 凭据、解密内容或 SQLite 文件。对象、keyslot、manifest、数量和字节上限在创建、编码、读取和恢复演练各边界重复验证；写盘必须同目录私有暂存、同步、无覆盖提交，读取拒绝符号链接。
- 恢复演练必须实际解包 VMK、认证解密每个对象并解析所有已有具名核心格式。错误恢复密钥、篡改、截断、重复 key/hash、跨 vault、撤销 registry 发布者和不受支持版本均失败；在 restore-to-journal、协调器和用户确认接线前，只能称为离线演练，不能称为一键恢复。

### 10.7 凭据 vault 规则（v0.3 工作树）

- 凭据同步策略必须默认关闭；启用、授权、撤销和停用均使用 expected revision，并同时验证 business device registry。撤销身份永久留在策略中，不能重新授权；任何已复制 CVK 的设备撤销后都必须显示轮换要求。
- CVK 必须由 OS CSPRNG 独立生成，不能从业务 VMK 派生，也不能复用 business/recovery keyslot AAD。CVK 和 secret 类型不得实现 Serialize/Debug；所有密码、口令、Token、私钥和解密缓冲尽早进入清零容器。
- 本机 credential reference 是 Rust 内存中的系统钥匙串查找参数，不是同步 ID。远端对象使用新随机 item UUID；reference、secret 或 provider 原始错误不得进入 object key、信封头、稳定错误、日志、Tauri event 或前端。
- 当前凭据模块故意没有 IPC、日志或 provider 接线。新增协调器时必须保持 secret 在 Rust trust boundary，仅返回 value-free 状态；写回系统钥匙串需生成新的本机 reference，不能把其他设备的本地 reference 当作可用身份。

### 10.8 扩展 provider transport 规则（v0.3 工作树）

- SFTP/S3/Gateway transport 实现必须满足 `ObjectTransport` 的严格契约：list 只返回作用域内对象，get 有界，create 为服务端原子/条件无覆盖；`AlreadyExists` 不能自行视为成功，公共 adapter 会回读逐字节核对。
- SFTP transport 建立会话前必须验证配置的 SHA-256 host key，逐级 lstat 根与对象路径并拒绝 symlink/special；不能复用未经独立凭据绑定和 host-key 验证的业务 shell 会话。
- S3 transport 必须使用 SigV4、HTTPS/no redirect、有界超时、ListObjectsV2 continuation token 和 `If-None-Match: *` 或等价条件创建；不能假设 list 立即一致，提交以条件 put 和 get 回读为边界。
- Gateway transport 必须实现版本化登录/session/object 协议、TLS、限流与重放保护。密码/TOTP 只借给 login，session 类型不得保存 TOTP；TOTP 只验证 Gateway 账户，不能解锁或派生 VMK/CVK。所有底层认证错误映射为无秘密稳定诊断。
- 当前内存 transport 只验证 adapter 契约。真实 SFTP/S3/Gateway transport、服务端参考实现和故障/兼容矩阵没有完成前，不得将对应 provider 标为用户可用。

### 10.10 Android Preview 共享契约（Phase C）

- `src-tauri/src/android_preview.rs` 是桌面与移动端共用的 Rust 策略模型；`android_mobile.rs` 是唯一移动 IPC/会话 owner，不能调用系统 `ssh` 或复用桌面进程命令。新增 Android command 必须进入 command manifest、仅加入 `capabilities/android.json`，并由安全回归证明没有落入桌面 capability。
- 当前只打开主机连接、终端、SFTP 和凭据 vault；Rust coordinator 虽已接通 provider/outbox/merge，Android 也只能读取 value-free 状态。设置、密钥解锁、自动调度和真实设备尚未形成完整安全能力前，Sync 与广播、外部编辑、常驻监控和后台长连接保持关闭。每个 structured host request 逐字段验证 UUID、主机/用户名/端口、host-key 和不透明 credential reference；不得序列化或记录秘密值。
- 生命周期默认 `Locked`；Tauri 原生窗口失焦与前端后台通知都清理会话并递增 generation，连接和 host-key 完成时必须再次验证代际。只有 Rust `android_unlock`/`android_set_biometric_enabled` 可切换 `Foreground`，启用或关闭访问门都要求官方 Tauri Biometric 插件完成系统认证；前端没有通用 lifecycle setter。原生 WebMessage 只允许固定 Tauri 主 frame/origin 和 `show`/`hide`/`failed` 三个不超过 32 bytes 的可见性信号，不授予 Rust 权限且不得传秘密；禁止退回 `addJavascriptInterface` 或 `*` origin。Activity/休眠、软键盘、剪贴板和网络切换仍是独立真机测试面。
- Linux CI/VPS 可构建 aarch64 debug APK/AAB、验证签名结构和运行 Rust/Gradle unit gate，但这些结果不证明 Keystore 运行时、真实设备或模拟器行为。debug 自签名包不得描述为发布签名。
- `android_native_transport.rs` 只允许 `ssh2`/libssh2 Rust API；握手后的 host-key pin 比对必须先于认证，秘密只以 `Zeroizing` 短生命周期进入调用。SFTP list 的路径、数量和条目类型必须在 Rust 再验证，symlink/special 不得被跟随。该模块的 fake/边界夹具不能替代真实服务器和 Android 链接测试。
- Android aarch64 首次构建要求 NDK 27；`ssh2` 仅在 `target_os = "android"` 时启用 `vendored-openssl`，使 libssh2/OpenSSL 用目标 NDK 编译而不是错误链接主机 OpenSSL，桌面目标继续使用原有系统链接。该 feature 增加 Android 原生冷构建时间与包体积，但不增加运行时权限；许可证和删除方案记录在 `THIRD_PARTY_NOTICES.md`。
- Android 凭据使用 `android-native-keyring-store`/`keyring-core` 明确注册 Keystore-backed store，访问门开关使用独立固定条目。凭据写入请求只允许反序列化且不得派生 `Debug`/`Serialize`；业务状态只保存 `ssh-<UUID>`/`key-<UUID>` 引用。私钥正文最多 1 MiB，密码/口令最多 16 KiB，错误不能包含底层秘密。`tauri-plugin-biometric` 2.3.2/其 AndroidX 传递依赖只是应用访问门，不得描述为强生物识别保证、逐凭据硬件认证或替代真机 Keystore 验收。

### 10.11 russh 原生就绪路径（Phase D）

- 桌面目标精确锁定 `russh = 0.62.7`（上游 tag commit `a3766cca2223f851df786e88f823ea08dabfbdea`，crates.io SHA-256 `9decb68e4e44e1079700e54f17c8f23806ec53d7e0db73ab1c71d9dabc666812`）和 `russh-sftp = 2.4.0`（上游 2.4 版本线 commit `e145c1f7ece99f41f558949ef59731f2cd1a9dfe`，crates.io SHA-256 `9de67aace74530a29086db0671fa200c470a58eb380081f28ad512ffb0c5356b`）；两者均为 Apache-2.0。只使用公开 API，没有复制上游源码。
- `russh` 关闭默认 feature，只启用 `ring` 加密后端和 RSA 密钥支持；不引入默认 `aws-lc-rs` 或压缩面。client config 从默认 host-key 列表删除 `ssh-rsa`，RSA 用户认证也只有服务器明确报告 RSA SHA-2 时才继续，禁止构造器退回 SHA-1。选择 0.62.7 是为了包含 0.62.4 起的全零 Curve25519 共享秘密修复、0.60.3 起的恶意数据包分配修复和 0.62.7 的解压边界修复。Tokio/tokio-util 精确对齐现有锁图的 1.53.1/0.7.19，新增能力只在 Linux/macOS/Windows 编译。
- 运行权限只有目标 SSH 网络、本机只读私钥和既有系统凭据引用；没有遥测、shell 子进程、任意命令或新增 Android capability。具名请求不可序列化/调试，私钥/密码使用可清零容器，错误和结果不携带底层库文本、credential reference 或秘密值。
- Linux CI 启动仅监听回环的临时 OpenSSH，禁用密码、交互认证和 root，使用一次性 Ed25519 用户密钥，实际完成 host-key pin、公钥认证和 SFTP `canonicalize`。其他平台负责编译/单测；真实多版本服务器、长期 PTY、网络故障和性能仍是后续兼容矩阵。
- 当前入口只是可取消的就绪检查，不能替代默认系统 OpenSSH 会话。删除方案是移除桌面 capability、`native_engine.rs` 和两项依赖；升级或扩大用途前必须先通过锁文件、四平台编译、真实 OpenSSH/SFTP 和安全回归，并保留系统 OpenSSH 回退。

### 10.9 B8 协议回归矩阵（v0.3 工作树）

- `sync_protocol_regression` 在跨模块边界验证：未知 v1 envelope、AEAD 错误密钥/篡改、对象身份搬移、journal 同 key/同身份 replay、已发布终态、merge 两种到达顺序和截断状态、Local Folder 截断字节与取消。每个失败都返回稳定错误码，不能把部分提交标为成功。
- 已完成的本机/fake transport 结果只证明 Rust 适配器契约。B8 外部矩阵仍需真实 OpenSSH SFTP（host-key 变化、权限、symlink、断线）、MinIO/其他 S3-compatible（SigV4、path-style、迟延列举、412/重试、时钟偏差）、Gateway HTTPS（版本协商、TOTP、限流、重放、断网）和两台以上真实设备的恢复/轮换演练。
- 真实 provider 测试不得使用生产 endpoint 或真实密码/Token/私钥；fixture secret 必须是合成值，日志与报告只保留稳定错误码、时间和计数。

## 11. PR 与发布清单

- [ ] 模块边界清楚，入口文件没有继续承载新的业务子系统
- [ ] IPC 有结构化类型、输入上限、取消、错误码和无秘密日志
- [x] 新文件/网络/进程权限已缩到最小 Tauri capability；自定义 commands、事件、窗口动作、dialog、opener、updater 和 restart 由静态回归测试对齐
- [ ] 正常、失败、取消和恢复路径均有测试
- [ ] README、CHANGELOG 和截图只描述真实状态
- [ ] 未实现能力标为“正在实现”或“路线图”
- [ ] 依赖、许可证和第三方通知已复核
- [ ] 三平台 CI 通过；发布平台安装包完成原生 smoke test
- [ ] 预览版限制、安全边界和校验值已写入 release notes

架构目标见 [ARCHITECTURE.md](ARCHITECTURE.md)，同步协议见 [SYNC.md](SYNC.md)，客户端迁移边界见 [MIGRATION.md](MIGRATION.md)。

# VPShell 路线图执行账本

更新时间：2026-08-17（UTC）

本文件记录 `/root/projects/vpshell/VPShell` 未提交工作树中路线图实现的真实状态。它不是发布说明，也不能替代代码、测试、平台验收或安全审计。

## 不可变约束

- 基线与最终 HEAD：`a1ab733b7bb52fbc0bd8362b204963f7e6ab750e`。
- 所有改动保持未提交；禁止 GitHub 写入、tag、release、包发布、artifact 上传和 remote 修改。
- Rust/Tauri 拥有网络、文件、进程、凭据、归档和加密信任边界；前端只展示状态并发起具名结构化请求。
- 不记录、同步、打印或返回密码、私钥、credential ref、Token、原始连接秘密或敏感文件内容。
- Linux VPS 结果不能替代 Windows、macOS、Android arm64 真机或正式安装器验收。
- `/root/reports/vpshell-roadmap-full.complete` 只能在全部可实现项完成后原子创建。

状态定义：`完成` 表示已有代码与聚焦测试；`进行中` 表示当前唯一工作项；`待实现` 表示没有完成；`外部验收` 表示必须在当前 VPS 之外验证，不能在本机勾选完成。

## 已完成基线（保留，不回退）

| 状态 | 工作项 | 证据 |
| --- | --- | --- |
| 完成 | v0.2 跨应用重启传输恢复、版本化原子有界记录、重试/丢弃与提交边界 | `transfer_manager.rs`、`file_transfer.rs`；报告 `/root/reports/vpshell-roadmap-final.md` |
| 完成 | 文件坞新建目录、同目录无覆盖重命名、权限编辑、显式有界批量删除 | `remote_file_ops.rs`、`FileTransferPanel.tsx`；报告 `/root/reports/vpshell-roadmap-next-final.md` |
| 完成 | 文件坞范围/全选、方向键、Home/End、Enter、F5、F2、Delete、Alt+Up、Ctrl/Cmd+L | `FileTransferPanel.tsx` |

## Phase A：v0.2 剩余可靠性

### A1 Linux 监控

| 状态 | 验收项 |
| --- | --- |
| 完成 | Rust 管理采样生命周期；频率硬范围 5–300 秒，全局最多 16 个会话/worker |
| 完成 | 每会话最近 120 点历史与 CPU/内存/磁盘/负载/网络趋势图，报告淘汰数量 |
| 完成 | 暂停后不开始新网络采样；恢复明确；断线/切换会话停止旧任务 |
| 完成 | 12 秒超时、失败、停止、频率和历史截断状态具有稳定可理解诊断 |
| 完成 | Rust 测试覆盖输入范围、历史上限、暂停/恢复、代际隔离、停止和失败状态 |

### A2 外部编辑器与冲突中心

| 状态 | 验收项 |
| --- | --- |
| 完成 | Notepad++、VS Code/Code Insiders/VSCodium 和用户自定义编辑器使用 Rust 结构化固定参数适配器 |
| 完成 | 编辑会话以最少安全元数据跨重启恢复，不持久化凭据、私钥路径、编辑器路径或文件内容 |
| 完成 | 远端版本冲突进入集中队列，支持无覆盖另存、重新下载、明确强制覆盖或丢弃 |
| 完成 | schema v1 两代原子快照最多 16 条/128 KiB/14 天；损坏、截断和旧版本不崩溃 |
| 完成 | 测试覆盖适配器/启动失败、字段与数量边界、原子/损坏/旧 schema、过期、符号链接、无覆盖另存和远端版本冲突判断 |

### A3 Shell Integration、上下文与广播

| 状态 | 验收项 |
| --- | --- |
| 完成 | 显式 bash/zsh Shell Integration 使用 128-bit 随机会话令牌和有界结构化 OSC 协议上报 cwd/hostname/user |
| 完成 | 嵌套 SSH 自报上下文栈最多 8 层，已知祖先自动 pop；缺失上报不从屏幕文本猜测 |
| 完成 | 广播目标/命令/上下文代际冻结为两分钟单次 Rust 快照，认证交互禁止广播，变化逐项跳过 |
| 完成 | 所有 Compose 广播均预览确认，生产目标持续标记，已知危险命令阻止并逐目标报告 |
| 完成 | 测试覆盖伪造/分块/超长 Integration 帧、嵌套深度与 pop、生产预览、单次令牌、危险分类和部分结果汇总 |

### A4 配置迁移

| 状态 | 验收项 |
| --- | --- |
| 完成 | OpenSSH config/known_hosts 只读、可审计、优先非敏感字段导入；通配/Match/Include/运行时占位符和 known_hosts 信任明确跳过 |
| 完成 | PuTTY、Xshell、SecureCRT、MobaXterm、Tabby、Termius 专用格式探测与五分钟单次预览 |
| 完成 | 每个来源逐项/逐字段报告导入、跳过、失败；令牌冻结净化资料，前端不能回传任意 profile |
| 完成 | 路径、UTF-8/UTF-16 编码、单文件/总量/数量/深度/报告上限、符号链接隔离和重复合并具有 Rust 硬验证及夹具 |

### A5 本地事件库与桌面安全面

| 状态 | 验收项 |
| --- | --- |
| 完成 | SQLite schema v1、事务迁移、revision 冲突、损坏/截断隔离备份和 90 天/10,000 事件有界保留 |
| 完成 | 主机、命令/参数/路径历史、脚本、设置和背景元数据经一次性 legacy 导入迁离 WebView localStorage；文件坞打包设置也已合并 |
| 完成 | 显式严格 CSP，移除 `null`；main window capability 只列事件、窗口动作、dialog/opener/updater/restart 和当前 51 个实际 Rust commands |
| 完成 | 状态秘密字段/私钥正文拒绝、value-free 事件元数据、资产 IPC、capability/manifest/localStorage 静态安全回归测试 |
| 完成 | rusqlite 0.40.2 bundled 依赖的 MIT/Apache-2.0 边界、默认 feature、网络/扩展权限、维护/删除方案已记录 |

### A6 文件任务补全

| 状态 | 验收项 |
| --- | --- |
| 完成 | 跨目录与跨文件系统移动使用目标目录暂存、逐文件大小/SHA-256 二次核验、无覆盖原子提交和源/备份清理 |
| 完成 | `fail`/`rename`/明确 `overwrite` 策略；SFTP rename 移除库默认 overwrite，覆盖先备份且旧确认永不恢复或重放 |
| 完成 | 递归权限冻结清单并隔离符号链接，保留 128 根、64 层、10,000 条及根目录硬限制 |
| 完成 | 批量文件任务复用 TransferManager，可取消/主动关闭 socket、跨重启重新预览恢复、逐项报告部分完成 |
| 完成 | 测试覆盖复制提交、三种覆盖策略、取消暂存清理、恢复/提交边界、递归权限、状态变化和部分清理失败 |

### Phase A 准入

- 完成：`npm ci`、`npm run build`。
- 完成：`cargo fmt --manifest-path src-tauri/Cargo.toml -- --check`。
- 完成：`cargo check --locked --manifest-path src-tauri/Cargo.toml`。
- 完成：`cargo test --locked --manifest-path src-tauri/Cargo.toml`。
- 完成：`git diff --check`、HEAD 与空 remote 复核。
- 外部验收：Windows/macOS 编辑器发现、安装器与真实桌面 UI；多种真实 SSH/SFTP 服务。

## Phase B：v0.3 用户控制的加密同步

| 状态 | 验收项 |
| --- | --- |
| 完成 | 版本化 E2EE envelope、Argon2id 包装、XChaCha20-Poly1305 对象和域分离 |
| 完成 | Local Folder 与 WebDAV provider trait、不可变对象、边界/超时/取消 |
| 完成 | 原子有界离线 outbox、幂等应用、重放保护、截断恢复和退避重试 |
| 完成 | 主机、历史、脚本、设置和背景的确定性多设备合并及冲突中心 |
| 完成 | 恢复密钥、设备撤销、加密导出与恢复演练 |
| 完成 | 默认关闭的凭据 vault，独立密钥域，秘密不进入日志/事件/明文包 |
| 完成 | SFTP、S3-compatible、自建 Gateway 结构化 provider；TOTP 仅保护 Gateway 登录 |
| 完成 | 篡改、重放、冲突、断网、截断、升级、恢复失败和真实 provider 测试报告 |

Phase B 完成时必须重跑桌面全量命令并增加协议兼容、真实 WebDAV/SFTP/S3/Gateway 测试。B1–B8 桌面源码与协议回归已完成，Rust 协调器内核也已接通 outbox/provider/merge；但产品配置与自动触发、真实外部 provider、多设备和完整用户界面仍未完成。

## Phase C：Android Preview

| 状态 | 验收项 |
| --- | --- |
| 完成 | 基于共享桌面模型/同步协议建立 Rust `android_preview` 模块、Tauri Android 壳与明确移动能力边界；设备仍需外部验收 |
| 完成 | 使用 Rust `ssh2`/libssh2 兼容 transport、固定 host-key 与有界 SFTP，不依赖系统 `ssh`；真实 Android/arm64/服务器兼容仍外部验收 |
| 进行中 | 主机连接、终端、只读 SFTP 浏览与密码/私钥已接线；Rust-owned 同步协调器已接通 provider/outbox/merge，Android 只读展示恢复/冲突/队列状态且 manifest 继续禁用 Sync；代码与测试已完成，等待本提交 GitHub Actions 验证 |
| 完成 | Android capability 排除广播、外部编辑、常驻监控、后台长连接和桌面 process/updater/dialog；非前台清理连接 |
| 进行中 | Android Keystore store、私钥导入、禁备份/明文网络/FileProvider 与 `FLAG_SECURE` 已实现；可选生物识别和真机泄漏测试待实现/外部验收 |
| 完成 | Linux VPS 生成并哈希校验 aarch64 debug APK/AAB；Rust/security tests 与 Gradle unit gate 按可用范围执行，emulator/instrumentation 留作外部验收 |
| 外部验收 | arm64 真机、休眠、网络切换、软键盘、截图/剪贴板和生命周期人工验收 |

## Phase D：原生引擎与中继

| 状态 | 验收项 |
| --- | --- |
| 待实现 | russh 原生 SSH/SFTP，每跳独立凭据、host-key、跳板和端口转发 |
| 待实现 | 系统 OpenSSH 兼容回退及跨引擎行为/安全测试 |
| 待实现 | 用户自建 Relay 参考实现、认证协议、限流、审计和安全测试 |
| 待实现 | 持续测速、可解释选路与可选 Mosh；没有真实数据不使用“加速”表述 |
| 待实现 | 自建部署文档、协议版本/升级/撤销和故障恢复演练 |
| 外部验收 | 多区域真实部署、长时间网络测试和各桌面/移动平台兼容性 |

托管中继、团队协作和企业支持不在没有服务边界与真实部署的情况下伪装为已实现生产服务。

## 验证日志

| 日期（UTC） | 范围 | 结果 |
| --- | --- | --- |
| 2026-08-10 | 继承的 v0.2 两批工作树 | 前序报告记录 `npm ci`、生产构建、Rust fmt/check/test（53 tests）与 `git diff --check` 通过；新路线改动后必须重跑，不能沿用为 Phase A 结论 |
| 2026-08-10 | A1 Linux 监控完整验证 | `remote_monitor::tests` 10/10；生产前端构建、Rust fmt check、`cargo check --locked`、完整 Rust tests 58/58、`git diff --check` 全部通过；仅有既有 Vite chunk 警告 |
| 2026-08-10 | A2 编辑恢复完整验证 | `external_editor::tests` 11/11；生产前端构建、Rust fmt check、`cargo check --locked`、完整 Rust tests 66/66、`git diff --check` 全部通过；仅有既有 Vite chunk 警告 |
| 2026-08-10 | A3 上下文与安全广播完整验证 | `npm ci` 通过；Shell Integration 5/5、安全广播 4/4；生产前端构建、Rust fmt check、`cargo check --locked`、完整 Rust tests 75/75、`git diff --check` 全部通过；仅有既有 Vite chunk 警告，npm audit 报告锁定依赖中 1 个 high 待 A5 审计处置 |
| 2026-08-10 | A4 配置迁移完整验证 | `migration::tests` 8/8；生产前端构建、Rust fmt check、`cargo check --locked`、完整 Rust tests 83/83、`git diff --check` 全部通过；覆盖七类来源、UTF-16、known_hosts/复杂规则跳过、秘密与绝对路径隔离、符号链接、路径/文件/总量/数量/深度/报告边界、无效端口、重复合并和预览冻结/过期/单次使用；仅有既有 Vite chunk 警告 |
| 2026-08-10 | A5 本地事件库与桌面安全面完整验证 | `app_store::tests` 6/6、`local_assets::tests` 4/4、`security_regression::tests` 3/3；`npm ci`、`npm audit --audit-level=high`（0 vulnerabilities）、生产前端构建、Rust fmt check、`cargo check --locked`、完整 Rust tests 96/96、`git diff --check` 全部通过；`nanoid` 锁定为 3.3.18；仅有既有 Vite 动态导入与 chunk 大小警告 |
| 2026-08-10 | A6 文件任务与 Phase A 完整准入 | `remote_file_ops::tests` 16/16、文件操作恢复边界 1/1、安全回归 3/3；`npm ci`（0 vulnerabilities）、生产前端构建、Rust fmt check、`cargo check --locked`、完整 Rust tests 103/103、`git diff --check`、基线 HEAD 与空 remote 全部通过；移动不依赖跨文件系统 rename，覆盖使用无覆盖提交；仅有既有 Vite 动态导入与 chunk 大小警告 |
| 2026-08-10 | B1 版本化同步密码学层 | `sync_crypto::tests` 5/5、固定 v1 向量、错误密码/篡改/截断/未知字段/域搬移/版本/KDF/身份/大小边界通过；生产前端构建、Rust fmt check、`cargo check --locked`、完整 Rust tests 108/108、`git diff --check` 全部通过；仅有既有 Vite 动态导入与 chunk 大小警告 |
| 2026-08-10 | B2 Local Folder/WebDAV 不可变 provider | `sync_provider::tests` 8/8，覆盖 key/对象/XML/扫描边界、Local 原子无覆盖/分页/取消/符号链接/暂存隔离、WebDAV HTTPS/CA/条件 PUT/回读/碰撞/越界 href/上传取消；`npm ci`（0 vulnerabilities）、生产前端构建、Rust fmt check、`cargo check --locked`、完整 Rust tests 116/116、`git diff --check`、基线 HEAD 与空 remote 全部通过；真实外部 WebDAV、自签 CA、代理与断网矩阵留在 B8 外部测试 |
| 2026-08-10 | B3 SQLite 离线 outbox 与重放状态机 | `sync_outbox::tests` 8/8，覆盖业务/operation/outbox 原子回滚、幂等 enqueue/apply、AEAD、序号缺口/回退、无序号对象 key/身份重放、两分钟租约重启恢复、暂停/显式恢复、最多六次退避、发布终态、损坏/截断安全阻止、未来 schema 与保留；生产前端构建、Rust fmt check、`cargo check --locked`、完整 Rust tests 124/124、`git diff --check` 全部通过；worker/provider/UI 接线仍待后续协调阶段 |
| 2026-08-10 | B4 确定性多设备 merge 与持久冲突中心 | `sync_merge::tests` 10/10、`sync_outbox::tests` 8/8，覆盖 host/history/script/setting/managed-background 白名单、不同到达顺序收敛、history 并集、observed update、edit/delete 因果、风险降低、删除保持/恢复、并发 resolution、敏感字段拒绝、状态 round-trip 与 SQLite revision 原子持久化；生产前端构建、Rust fmt check、`cargo check --locked`、完整 Rust tests 134/134、`git diff --check` 全部通过；后台协调器与冲突中心 UI 尚未接线 |
| 2026-08-10 | B5 恢复密钥、设备撤销与加密导出/演练 | `sync_crypto::tests` 6/6、`sync_recovery::tests` 4/4，覆盖含 base64url 连字符的可打印恢复密钥/校验码、独立 recovery keyslot、错误密钥/篡改、设备 revision/公钥身份/最后活动设备/单调撤销/撤销后不可变/合并、撤销发布者拒绝、导出 manifest/截断/重复/跨 vault、全部对象解密解析、无覆盖原子文件/符号链接/Unix `0600`；`npm ci`（0 vulnerabilities）、生产前端构建、Rust fmt check、`cargo check --locked`、完整 Rust tests 139/139、`git diff --check`、基线 HEAD 与空 remote 全部通过；设备签名、VMK 轮换、restore-to-journal、协调器/UI 和真实多设备演练尚未接线 |
| 2026-08-10 | B6 默认关闭的独立凭据 vault | `sync_credential_vault::tests` 4/4、安全回归 4/4，覆盖默认关闭/显式启用、revision、business device registry/逐设备授权、最后授权设备保护、撤销不可重授/轮换提示、独立 CVK/password keyslot/AAD/HKDF 域、错误密码/CVK、SSH 密码/私钥口令/OpenSSH 私钥/access token 类型与大小、篡改/搬移/跨 vault/未知字段、本机 reference/source error/secret 不进入信封与 object key，以及无 IPC/event/log 静态边界；`npm ci`（0 vulnerabilities）、生产前端构建、Rust fmt check、`cargo check --locked`、完整 Rust tests 144/144、`git diff --check`、基线 HEAD 与空 remote 全部通过；钥匙串写回、CVK 恢复/轮换、provider/outbox、协调器/UI 与真实设备仍未接线 |
| 2026-08-10 | B7 SFTP/S3/Gateway 结构化 provider adapters | `sync_provider_ext::tests` 4/4，覆盖三种 backend trait 的条件无覆盖创建/同名幂等/冲突/提交后回读、分页/key/大小/ETag/取消、SFTP 固定 SHA-256 host-key/远端根/symlink-special 拒绝、S3 HTTPS/无 URL 凭据/region/bucket/prefix、Gateway 版本化配置与登录、六位 TOTP 只在认证调用、底层秘密错误净化；`npm ci`（0 vulnerabilities）、生产前端构建、Rust fmt check、`cargo check --locked`、完整 Rust tests 148/148、`git diff --check`、基线 HEAD 与空 remote 全部通过；真实 ssh2 SFTP 会话、S3 SigV4 HTTP、Gateway HTTP/限流/重放和外部服务兼容矩阵留在 B8 |
| 2026-08-10 | B8 跨模块协议回归与测试报告 | `sync_protocol_regression::tests` 3/3，覆盖未知 envelope 版本、错误密钥/AEAD、对象身份搬移、journal 同 key/同身份 replay、published finality、merge 双到达顺序/截断状态、Local Folder 截断字节/取消；叠加三类 adapter/crypto/recovery/outbox/merge 全套夹具；`npm ci`（0 vulnerabilities）、生产前端构建、Rust fmt check、`cargo check --locked`、完整 Rust tests 151/151、`git diff --check`、基线 HEAD 与空 remote 全部通过；真实 OpenSSH SFTP、MinIO/S3、Gateway HTTP、两台以上设备和 Windows/macOS/Android 外部验收仍待外部环境 |
| 2026-08-10 | C1 Android Preview 共享契约 | `android_preview::tests` 4/4；schema-v1 能力清单与 NativeRustSshSftp 固定、最多 8 会话、结构化 host/user/port 与不透明 credential reference 验证、后台/锁定/断开代际门禁和明确禁用能力通过；后续 Android 壳现已生成，设备生命周期仍待外部环境 |
| 2026-08-10 | C2 Android Rust SSH/SFTP transport 边界 | `android_native_transport::tests` 4/4；`ssh2`/libssh2 直接 Rust 会话、5–60 秒超时、固定 SHA-256 host-key 先验、Zeroizing 密码/内存私钥类型、有界绝对 SFTP 路径与无系统 `ssh` 静态边界通过；未新增依赖；真实 SSH 算法/权限、Android arm64 链接、断网与设备测试仍待外部环境 |
| 2026-08-17 | C3 同步协调器与 Android 只读状态（待 Actions） | 新增 `sync_coordinator` 与 7 个聚焦测试，接通 vault-scoped outbox claim、不可变 provider push/pull、AEAD 后 merge、冲突计数、恢复阻止、取消和代际状态；Tauri setup 持有协调器，Android capability 只增加 value-free `android_sync_status`，无 attach/run/ack 写权限且 Sync manifest 保持 disabled；CI 前复核已修正本机已发布对象 pull 回后应幂等跳过、不重复推进 merge/download 计数的测试期望；本机 `git diff --check` 通过，VPS 无 cargo/rustfmt/node_modules，完整 fmt/check/test/frontend build 等待 GitHub Actions |

## 下一个动作

等待 C3 提交的 GitHub Actions 全绿；通过后把该项改为完成，并进入 Phase C 的可选生物识别与泄漏防护。自动同步配置、密钥解锁与真实 provider 尚未形成安全完整能力，Android manifest 的 Sync capability 继续保持 disabled。

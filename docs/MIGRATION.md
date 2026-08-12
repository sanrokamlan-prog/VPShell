# 迁移到 VPShell

本文说明 VPShell 能从哪些 SSH 客户端迁移数据、凭据会被放在哪里，以及哪些能力仍在路线图中。迁移器的目标是帮助用户带走自己的连接资料，而不是绕过原客户端的主密码、系统钥匙串或云端加密。

> [!IMPORTANT]
> 已发布的 `v0.1.0-alpha.7` 只实现 FinalShell 本地连接配置导入。当前 v0.2 **未提交工作树**另实现 OpenSSH、PuTTY、Xshell、SecureCRT、MobaXterm、Tabby 和 Termius 的非敏感字段预览/导入；它不是已发布能力。所有跨客户端导出仍未实现。

## 兼容性矩阵

| 来源/目标 | `v0.1.0-alpha.7` | 可迁移凭据 | 当前边界 | 后续方向 |
| --- | --- | --- | --- | --- |
| FinalShell | **已实现导入** | 可选导入 SSH 密码 | 导入主机名、地址、端口、用户名和密码；直连终端、采样和 SFTP 可自动使用；代理引用只标记，不自动复原；不支持回写/导出 | 增加导入预览和冲突处理 |
| OpenSSH | v0.2 工作树已实现预览/导入 | 不迁移密码、证书或私钥引用 | 读取明确选择的 `config`/`*.conf`；`known_hosts` 只统计不复制；通配/否定 Host、`Match`、`Include` 和运行时占位符逐项跳过 | 实机验证平台变量与复杂 include 树；未来只导出非敏感配置 |
| PuTTY | v0.2 工作树已实现预览/导入 | 不迁移密码或密钥引用 | 只读用户主动导出的 `Sessions` `.reg`，支持 UTF-8/UTF-16 与字符串/DWORD 主机字段；不访问注册表本体 | 在真实 PuTTY 版本核对导出变体 |
| Xshell | v0.2 工作树已实现预览/导入 | 不解密密码、主密码或 user key | 只读 `.xsh` 的 SSH connection/authentication 字段；陌生区段不猜测 | 在各主版本官方导出上验证字段差异 |
| SecureCRT | v0.2 工作树已实现预览/导入 | 不破解 Password V2 或迁移 identity 引用 | 只读 Sessions `.ini` 的 SSH hostname/username/port；非 SSH 会话跳过 | 在 Windows/macOS 真实配置目录验证版本差异 |
| MobaXterm | v0.2 工作树已实现预览/导入 | 不读取密码库或私钥 | 只读用户选择的 `.ini`/`.mobaconf` 中 `#109#` SSH bookmark；安装/便携位置不自动扫描 | 用官方导出与安装/便携模式实机验收 |
| Tabby | v0.2 工作树已实现预览/导入 | 不读取系统钥匙串、vault 或私钥内容 | 只读用户选择的 YAML/JSON SSH profile 窄子集；不自动发现配置目录 | 跟踪上游 schema 并用真实导出验收 |
| Termius | v0.2 工作树已实现预览/导入 | 不访问账户、Token 或端到端加密云仓库 | 只读用户主动提供的 JSON 主机对象；不调用云 API | 在官方导出可用的平台/版本核对 schema |
| VPShell 加密仓库 | 路线图 | 连接密码、私钥口令等可选秘密 | `v0.1.0-alpha.7` 尚无可携带的加密仓库导入/导出 | 二级密码使用 Argon2id 派生密钥，数据使用 XChaCha20-Poly1305 加密 |

## FinalShell 导入（当前可用）

在 VPShell 中打开“迁移”，选择 FinalShell 配置所在的**文件夹**。迁移器会递归查找 `*_connect_config.json`，源文件只读，不修改也不删除 FinalShell 的任何数据。

当前读取以下字段：

- 连接名称；
- VPS IP/域名、SSH 端口；
- 用户名；
- 可选的已保存密码；
- 是否存在旧代理引用。

为降低误导和导入风险，当前行为还有这些明确限制：

- 同一批次按 `主机 + 端口 + 用户名` 去重；
- 已存在的同地址、端口和用户名主机会保留名称、分组与历史，同时更新新导入的系统凭据引用；
- 每个配置文件最大 1 MiB，单次最多扫描 2,000 个连接配置；
- 跳过符号链接、损坏 JSON、无效主机/用户名和异常文件；
- FinalShell 的 `proxy_id` 不足以可靠还原完整跳板链，因此只添加“原配置含代理”标记；
- 某条密码无法解密或无法写入系统凭据库时，该主机仍可导入，并在结果中单独统计失败；
- 导入不会验证服务器在线，也不会替用户接受新的 SSH 主机指纹。

### 密码如何处理

勾选“导入已保存密码”后，FinalShell 兼容解码仅在 Rust 后端短暂运行。明文密码不会返回 React/WebView，也不会写进主机 JSON、`localStorage`、命令历史或日志：

```text
FinalShell 配置
  -> Rust 内存中兼容解码
  -> Windows Credential Manager / 对应平台系统钥匙串
  -> 主机资料只保存随机 credentialRef
```

`v0.1.0-alpha.7` 的直连 OpenSSH 终端和 Linux 采样通过受限 AskPass 助手使用 `credentialRef`，SFTP 在 Rust 内直接读取同一引用并尝试 password 与 keyboard-interactive/PAM 认证。助手只响应明确的 password/passphrase 提示；主机指纹由系统 OpenSSH 工具链的独立预检流程处理，明文不会经过 WebView、命令栏或广播层。导入结果只表示密码是否成功解密并写入系统凭据库，不使用远端握手或采样结果判断密码正确性。

> [!NOTE]
> FinalShell 使用的旧 DES 兼容逻辑只用于读取用户现有数据。VPShell **不会**把密码导出或回写成 FinalShell DES 格式，也不会用 DES 保护新数据、SSH 密钥或同步对象。

系统钥匙串中的密码目前只存在于执行导入的设备上；`v0.1.0-alpha.7` 尚未实现凭据同步。迁移完成后先保留原配置备份，逐台验证连接、指纹和认证方式，再决定是否停用旧客户端。

> [!NOTE]
> 从 alpha.2 升级后，重新选择同一个 FinalShell 配置目录导入一次即可修复旧版本丢弃的重复主机凭据引用。这个过程不要求输入任何主机密码，也不会修改源配置。

## v0.2 非敏感迁移预览

除 FinalShell 独立流程外，七类来源都经过同一个 Rust 两阶段边界：

```text
显式选择来源 + 普通文件/目录
  -> Rust 有界只读扫描与专用解析器
  -> 净化 profile + 逐项/逐字段报告冻结在内存
  -> WebView 展示五分钟单次预览
  -> 用户确认令牌
  -> Rust 返回同一份冻结 profile 供资料库合并
```

前端不能把任意 profile 作为确认结果传回。来源或路径改变会丢弃界面中的旧确认；令牌最多保留五分钟、只能使用一次，Rust 同时最多保留 16 个预览。扫描不会连接服务器、接受主机密钥、修改源配置或读取其他应用的凭据存储。

统一硬边界如下：

- 路径必须是最多 4,096 字节的绝对路径，根路径和扫描项不跟随符号链接；
- 单文件最大 1 MiB、总读取最大 16 MiB、最多 2,000 个文件，目录最多 12 层；
- 只严格接受 UTF-8（可带 BOM）、UTF-16LE 或 UTF-16BE，不做有损编码猜测；
- JSON 最多 16 层，最终最多 2,000 个 profile、4,000 条报告；
- 主机、端口、用户名逐字段验证；无效值导致该条失败，不静默回落；
- 同批按 `host + port + username` 保留首次出现项，重复项明确报告 skipped；资料库合并仍保留用户已有名称、分组和历史。

报告状态不会把部分结果伪装成全成功：每个源 item 为 `ready`、`skipped` 或 `failed`，其中字段另列 `imported`、`skipped`、`failed`。界面最多呈现前 100 条详情以保持可用性，但总计数覆盖 Rust 返回的全部有界报告。

### 支持的窄格式

- **OpenSSH**：静态 `Host`、`HostName`、`Port`、`User`；`ProxyJump` 只保留“原配置含跳板”标记。`IdentityFile`、`CertificateFile`、`IdentityAgent`、`Match`、`Include`、通配/否定 Host 和 `%` 运行时占位符不自动迁移。`known_hosts` 继续由系统 OpenSSH 管理，迁移不能隐式授予信任。
- **PuTTY**：官方文档所述 `HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions` 注册表导出中的 `HostName`、`PortNumber`、`UserName`、`Protocol`。VPShell 不读取注册表本体；参考 [PuTTY 配置存储文档](https://documentation.help/PuTTY/config-file.html)。
- **Xshell / SecureCRT**：只接受专用 `.xsh` / Sessions `.ini` 的 SSH 主机、端口和用户名窄字段；加密密码、master password 与 identity 字段均跳过。SecureCRT 官方文档确认 session 设置存于会话配置，实际字段仍可能随版本变化。
- **MobaXterm**：只接受 `[Bookmarks]` 中已识别的 `#109#` SSH bookmark，不扫描密码库。
- **Tabby**：只解析用户选择的 YAML/JSON SSH profile 的 name/host/port/user/group 窄字段。Tabby 上游明确其 SSH secrets/config 可由加密容器管理，VPShell 不读取该容器。
- **Termius**：只解析用户主动导出的 JSON 中明确的 SSH host/address、port、username 和 label/group；任何 password/token/secret/key/credential 字段均跳过，不离线访问云仓库。

这些解析器刻意拒绝“尽量猜”。未在夹具覆盖的厂商版本应产生 failed/skipped 报告，并用不含真实秘密的最小样本扩展测试后再宣称兼容。Linux 单元测试不能替代 Windows/macOS 客户端的真实导出验收。

## 其他客户端的迁移原则

不同工具把“会话资料”和“秘密”放在不同位置。VPShell 的导入器会遵循以下规则：

1. 优先使用厂商公开文档、官方导出或用户明确选择的配置文件。
2. 导入前展示预览和字段差异，不在后台批量连接服务器。
3. 操作系统钥匙串、主密码保护库和端到端加密云仓库必须由用户在原软件/系统中解锁或通过官方接口授权。
4. 无法可靠映射的代理、键盘交互、宏、终端编码和端口转发规则保持未迁移状态并明确提示。
5. 私钥默认保留原文件路径引用；除非用户另行选择，不复制私钥内容。
6. 无密码可迁移不代表连接丢失：主机资料仍可导入，之后可改用 SSH 密钥或重新录入密码。

### OpenSSH

当前工作树只导入可静态验证的别名、`HostName`、`Port` 和 `User`。通配 `Host`、`Match`、`Include`、多值指令和平台变量不能简单展开，因此保留在 OpenSSH 原配置并报告未迁移。`IdentityFile` 路径也不自动复制到资料，避免把本机私钥布局扩散到 WebView 状态。OpenSSH 配置本身不应承载登录密码。

### PuTTY、Xshell、SecureCRT 与 MobaXterm

这些客户端的配置格式、安装/便携模式和密码保护方式会随版本变化。当前适配器只覆盖上表列出的可审计会话导出窄格式，并将字段映射、跳过和失败分开统计。遇到未公开或受主密码保护的秘密时，正确流程是让用户从原客户端重新录入，而不是加入破解逻辑。

### Tabby 与 Termius

Tabby 的秘密可能由操作系统钥匙串/vault 保护；Termius 还涉及账户和端到端加密云数据。当前适配只读取用户明确选择的 YAML/JSON 非敏感字段。VPShell 不读取其他应用的钥匙串条目，也不要求用户把 Termius 云账户密码交给迁移器。

## 导出策略

`v0.1.0-alpha.7` 尚未提供导出器。未来导出分为两类：

- **OpenSSH 配置导出**：只写主机、用户、端口、私钥路径、跳板等非秘密字段，便于迁移到通用客户端；
- **VPShell 便携加密仓库**：用于用户明确选择的凭据和同步资料，采用随机主密钥；二级密码通过 Argon2id 包裹主密钥，对象使用 XChaCha20-Poly1305 认证加密。

便携仓库会带版本、KDF 参数、随机 salt/nonce 和完整性校验，不会降级到 DES、固定密钥或可逆混淆。恢复密钥与二级密码的职责也会分开；TOTP 只用于未来 Gateway 登录，不能替代仓库加密密码。

## 建议的迁移流程

1. 在旧客户端保留一份只读备份，并确认备份不进入 Git、聊天或工单附件。
2. 首轮取消勾选密码导入，先核对导入后的主机数量和字段映射。
3. 确认主机名、端口、用户、环境标签和代理提示无误后，再从备份副本导入凭据。
4. 先用一台非生产服务器验证主机指纹、自动认证、终端编码和 SFTP。
5. 生产服务器逐台验证；不要使用多终端广播做首次迁移测试。
6. 确认新客户端可用后，再按照旧客户端的安全删除流程清理原副本。

发现某个客户端版本无法导入时，请提交不含主机、用户名、密码、私钥和 Token 的最小化样本，并在报告中注明客户端版本、操作系统和导出方式。

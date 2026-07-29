<div align="center">

<img src="src-tauri/icons/icon.png" width="96" alt="VPShell icon">

# VPShell

**面向 VPS 运维的轻量、可审计、同步端自选的 SSH 工作台。**

[![CI](https://github.com/sanrokamlan-prog/VPShell/actions/workflows/ci.yml/badge.svg)](https://github.com/sanrokamlan-prog/VPShell/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/sanrokamlan-prog/VPShell?include_prereleases&style=flat-square)](https://github.com/sanrokamlan-prog/VPShell/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-3b6f9d?style=flat-square)](LICENSE)
[![Tauri](https://img.shields.io/badge/Tauri-2-287a4e?style=flat-square&logo=tauri&logoColor=white)](https://tauri.app/)

[下载预览版](https://github.com/sanrokamlan-prog/VPShell/releases/latest) · [架构设计](docs/ARCHITECTURE.md) · [开发标准](docs/DEVELOPMENT.md) · [迁移指南](docs/MIGRATION.md) · [同步协议](docs/SYNC.md) · [安全策略](SECURITY.md)

</div>

![VPShell 工作台](docs/assets/workspace.png)

> [!IMPORTANT]
> `v0.1.0-alpha.1` 是 Windows-first 技术预览版。系统 OpenSSH 终端、直连 SFTP、打包传输、Linux 负载采样和安全外部编辑已经接通真实后端，后续仍会扩大实机与安装包兼容性验证。端到端同步、Shell Integration 和中继加速属于后续里程碑。当前版本不应作为生产密码或私钥管理器。

## 为什么做 VPShell

现有 SSH 工具往往把体验做在厂商云、封闭加速服务或单一平台之上。VPShell 希望保留好用的工作流，同时把数据和基础设施控制权交还给用户。

## 定位与可持续性

VPShell 是 **Apache-2.0 开源、local-first 的 VPS/SSH 运维工作台**。连接资料、密钥引用、终端、SFTP 和用户自建的同步基础设施始终由用户控制；

若长期运营需要商业收入，收费边界只会放在可选的托管基础设施与服务上，例如托管中继、团队协作与审计、企业支持或托管加密同步。基础 SSH、SFTP、密钥管理、本地资料库以及用户自建同步不会因托管服务出现而被撤回或锁进付费版。

| 运维痛点 | VPShell 方向 | `v0.1.0-alpha.1` |
| --- | --- | :---: |
| 多设备配置被厂商云锁定 | Local Folder、WebDAV、SFTP、S3、自建 Gateway，上传前端到端加密 | **未实现**：仅协议设计与设置界面 |
| 大量小文件/目录传输缓慢 | 自动探测 `tar + zstd`，失败回退 SFTP | **已实现**：直连后端 |
| 命令、路径和参数反复复制 | 不设产品条数上限的事件历史、快速检索和参数模板 | **部分实现**：本地历史与最近连接 |
| 跳板后忘记当前主机 | 常驻主机链、环境边框、Shell Integration 上报 hostname/cwd | **部分实现**：配置链与 Linux 实时概况 |
| 多机操作效率低且容易误发 | Compose 广播、目标清单、生产/危险命令保护 | **部分实现**：基础 Compose 广播 |
| 常用运维脚本四处散落 | 有来源、版本、风险和参数的可同步脚本中心 | **部分实现**：本地脚本中心 |
| 不知道该运行什么排障命令 | 中文意图匹配、参数表单、风险分级和执行前预览 | **已实现**：22 项本地命令/工具 |
| 本机与 VPS 线路难量化 | 路由追踪、限量 HTTP 下载、双向 UDP 吞吐/抖动/丢包 | **已实现**：本机网络诊断 |
| 海外 SSH 高延迟 | 直连/跳板/代理/自建中继测速选路，可选 Mosh | **部分实现**：直连与 ProxyJump |
| 终端外观受限 | 本机或 URL 背景、可见度调节并随资料库同步 | **已实现**：本机/URL 背景 |

## 当前可用能力

- Tauri 2 + 系统 WebView，安装包不捆绑完整 Chromium。
- xterm.js 多标签终端，支持输入输出、窗口缩放、断开和 250,000 行 scrollback。
- Rust 后端通过跨平台 PTY 启动系统 `ssh`，支持自定义端口、`ProxyJump (-J)`、私钥路径和 keepalive。
- 真实 SFTP 目录、递归文件/目录上传下载、资源管理器拖放、字节进度、临时文件校验和原子提交。
- 大量小文件可使用客户端生成的 `tar + zstd` 包传输；远端能力不足或打包失败时回退递归 SFTP。
- 左侧主机概况常驻显示配置 IP、用户、跳板链并可复制 IP；密钥/agent 可用时每 15 秒读取 Linux `/proc` 的 CPU、内存、磁盘、负载、流量和进程摘要。
- 远端普通文件可用 Notepad++、用户指定编辑器或系统编辑器打开；检测本地保存，回传前比较远端哈希，冲突时阻止静默覆盖。
- 主机分组、生产/基础设施/测试环境标记，以及常驻连接路线。
- 成功连接历史按最近时间置顶，并保留最后路径、用户和连接时间。
- FinalShell 主机、端口、用户名和可选密码导入；密码只进入系统钥匙串，不返回前端。
- Ed25519/RSA4096 密钥生成、OpenSSH 口令加密，以及把所选公钥安装到当前已连接主机。
- 多终端 Compose 命令栏、命令历史检索和路径快捷输入。
- 22 项命令/工具的本地中文意图搜索、参数填写、风险提示和执行前预览。
- 脚本来源、风险提示、复制/加入命令栏和用户自建配方。
- 本机路由追踪、指定 URL 限量下载测速，以及本机与自建 VPS 之间的 iperf3 UDP 双向测速。
- 本机 PNG/JPEG/WebP 或 URL 终端背景。

当前传输不支持断点续传、任务取消或持久队列；SFTP/外部编辑暂不支持经过 ProxyJump，远端监控仅支持 Linux 且不弹出密码提示。同步设置仍是本地草稿。完整边界见 [架构文档](docs/ARCHITECTURE.md#2-v010-已实现)。

## 下载与安装

正式预览产物只从 [GitHub Releases](https://github.com/sanrokamlan-prog/VPShell/releases) 发布：

| 平台 | GitHub Actions 产物 | 当前支持级别 |
| --- | --- | --- |
| Windows 10/11 x64 | NSIS `setup.exe`、MSI | Windows-first，首要验收平台 |
| Linux x64 | AppImage、DEB | 技术预览，需继续覆盖发行版兼容性 |
| macOS Apple Silicon / Intel | DMG | 技术预览，当前为 ad-hoc 签名、未公证 |

推送 `v*` 标签后，[Release workflow](.github/workflows/release.yml) 会分别在 Windows、Ubuntu 和 macOS 原生 GitHub-hosted runner 上构建，先写入不可见草稿，确认安装包和四个平台 updater 条目完整后再公开。Alpha/RC 由 SemVer 后缀标识；GitHub Release 元数据保持 full release，原因是 GitHub 的 `/releases/latest` 会排除 prerelease，而客户端自动更新使用该固定地址。这不代表 Alpha 已达到稳定版质量。项目不声称能在一台 Windows 机器上可靠产出所有平台的正式安装包；本地构建只用于开发和目标平台验证。

每个 Release 同时提供 `SHA256SUMS`、Tauri updater 签名和 `THIRD_PARTY_NOTICES.md`；Release Notes 从同版本 [CHANGELOG](CHANGELOG.md) 自动生成。SHA-256 与 updater 签名用于验证下载内容，不能替代 Windows/macOS 的发行者身份签名。

当前 Windows 安装包尚无 Authenticode 代码签名，macOS 包也尚无 Apple Developer ID 公证，系统可能显示未知发布者或安全提醒。Tauri updater 的产物签名用于校验更新文件完整性，不能替代操作系统发行者签名。稳定版发布前必须补齐相应签名、公证和实机验收。

VPShell 当前调用系统 `ssh`。安装后先验证：

```powershell
ssh -V
```

Windows 如找不到该命令，请在可选功能中安装 **OpenSSH Client**；macOS/Linux 请使用系统包管理器安装 OpenSSH 客户端。首次连接和主机密钥变化仍由 OpenSSH 在终端内明确提示，VPShell 不会自动回答 `yes`。

## 使用

1. 点击主机区域的 `+`，填写 IP/域名、端口、用户名和可选跳板机。
2. 打开主机标签，核对顶部常驻的别名、用户、IP、环境和跳板链。
3. 点击“连接”，在终端中完成首次指纹确认或密码/私钥认证。
4. 需要复用命令时使用底部命令栏；广播前逐个勾选目标。
5. 也可以在命令栏输入“磁盘满了”“查看 nginx 日志”或“UDP 测速”，选择本地匹配结果并先核对最终命令。
6. 脚本中心只会显示来源并把最终命令加入命令栏，不会后台静默执行。
7. 打开底部文件坞浏览真实 SFTP 目录；双击普通文件可启动外部编辑，发生远端冲突时必须选择重新下载或确认强制覆盖。

种子主机使用 RFC 5737 文档保留地址，不会连接真实服务器。添加自己的主机后即可使用真实 SSH 会话。

## 从其他 SSH 工具迁移

`v0.1.0-alpha.1` 已支持从 FinalShell 配置目录导入主机、端口、用户名和可选密码。密码在 Rust 后端解码后直接写入 Windows Credential Manager（或对应平台系统钥匙串），明文不会进入 WebView；旧代理引用目前只会标记，需人工重新配置。

OpenSSH、PuTTY、Xshell、SecureCRT、MobaXterm、Tabby、Termius 的专用导入器及跨客户端导出仍在路线图。格式、凭据边界和安全迁移步骤见 [MIGRATION.md](docs/MIGRATION.md)。VPShell 不会把凭据导出成 FinalShell 的旧 DES 格式。

## 脚本中心

首批目录根据项目 README 核对入口，不复制第三方脚本正文：

| 配方 | 来源 | 默认风险 |
| --- | --- | --- |
| SafeVPS 安全加固 | [sanrokamlan-prog/safevps](https://github.com/sanrokamlan-prog/safevps) | 高 |
| Nginx Easy Deploy | [sanrokamlan-prog/nginx-easy-deploy](https://github.com/sanrokamlan-prog/nginx-easy-deploy) | 高 |
| VPS Health Check | [sanrokamlan-prog/vps-health-check](https://github.com/sanrokamlan-prog/vps-health-check) | 低 |
| 流媒体、IP 风险、节点质量检查 | 各上游公开来源 | 中 |
| BBR 调优 | [chnnic/BBR-tune](https://github.com/chnnic/BBR-tune) | 高 |
| DD 重装系统 | 用户配置具体配方 | 破坏性 |

远程 `curl | bash`/`wget | bash` 会显示最终命令和来源。明文 HTTP、系统调优、防火墙和磁盘操作必须保持高风险标记；未来版本会增加固定 commit/hash、参数 schema 和逐主机确认。

## 网络诊断

路由追踪和测速由本机 Rust 后端执行，不会隐式广播到 SSH 会话。路由追踪在 Windows 调用 `tracert`，在 macOS/Linux 调用 `traceroute`；HTTP 下载测速必须填写目标 URL，并受超时与最大下载量限制。

本机与自建 VPS 之间的 UDP 测速使用系统 `iperf3`。先在测速 VPS 显式运行：

```bash
iperf3 -s -p 5201
```

再在 VPShell 选择正向“本机 → VPS”或反向“VPS → 本机”，填写目标带宽、时长和端口。VPShell 不会自动安装 `iperf3`、启动服务端或修改防火墙；执行前会显示按设定带宽估算的最大流量。

## 同步与二次验证

同步目标设计为不可信对象存储。完整方案不会上传 SQLite 整库，而是把本地 operation 分段、压缩、加密后上传；二级同步密码通过 Argon2id 包裹随机 Vault Master Key，数据对象使用 XChaCha20-Poly1305。

Google Authenticator/TOTP 只用于未来自建 Gateway 的账户登录，不能替代二级同步密码或恢复密钥。Local Folder、WebDAV、SFTP 和 S3 不虚构一层本地 TOTP。完整边界见 [SYNC.md](docs/SYNC.md)。

## “智能加速”的边界

调整 SSH keepalive、压缩或复用连接并不等于海外线路加速。真正的跨境选路需要中继节点、持续测速和可解释的路线选择。

VPShell 的路线是：

```text
Direct -> ProxyJump -> SOCKS/HTTP -> 用户自建 Relay -> 可选托管节点
```

中继只转发到目标的 SSH 密文字节，不终止最终 SSH，也不读取凭据。没有实际中继和公开实测指标前，项目不会把普通客户端优化宣传成“海外智能加速”。

## 本地开发

环境要求：Node.js 22+、Rust stable，以及 [Tauri 2 对应平台依赖](https://v2.tauri.app/start/prerequisites/)。Windows 需要 Microsoft C++ Build Tools 的 **Desktop development with C++** 工作负载。

```bash
npm install
npm run build
npm run tauri dev
```

普通 Windows PowerShell 没有加载 MSVC 环境时，可使用仓库脚本：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/windows-dev.ps1 check
powershell -ExecutionPolicy Bypass -File scripts/windows-dev.ps1 test
powershell -ExecutionPolicy Bypass -File scripts/windows-dev.ps1 dev
powershell -ExecutionPolicy Bypass -File scripts/windows-dev.ps1 build
```

验证：

```bash
npm run build
cargo check --manifest-path src-tauri/Cargo.toml
```

## 项目结构

```text
src/                    React 工作台与 xterm.js
src-tauri/src/          PTY、OpenSSH 会话和 Tauri IPC
src-tauri/icons/        可编辑 SVG 与平台图标
docs/ARCHITECTURE.md    SSH、终端、传输、历史、脚本和中继设计
docs/DEVELOPMENT.md     模块边界、IPC、安全、测试与发布准入标准
docs/MIGRATION.md       FinalShell 导入与其他客户端迁移边界
docs/SYNC.md            加密同步、冲突、恢复和 TOTP 边界
scripts/                本地开发辅助脚本
```

## 路线图

路线图描述未来方向，不是发布日期或功能承诺。只有进入安装包、通过对应平台验收并写入 Release Notes 的能力，才会移动到“当前可用能力”。

| 里程碑 | 主题 | 当前状态 |
| --- | --- | --- |
| Alpha | 真实 SSH/SFTP 工作流与可安装预览版 | 首个技术预览 |
| v0.2 | 传输可靠性、上下文识别与安全批量运维 | 计划 |
| v0.3 | 用户自控的端到端加密同步 | 协议设计完成，尚未实现 |
| 后续 | 原生 SSH 引擎、可验证中继和可选托管服务 | 研究方向 |

### Alpha 当前阶段

已经打通系统 OpenSSH 真实终端、FinalShell 导入、SSH 密钥、命令/脚本库、多会话 Compose 广播、本机网络诊断、真实 SFTP、打包传输、Linux 负载区、最近连接和安全外部编辑。**VPShell** 名称与 **A - Terminal V** 图标已经定稿并生成平台图标。

Alpha 发布后的重点验证：

- 扩大临时及真实 OpenSSH/SFTP 主机覆盖，继续验证上传、下载、目录、中文路径、远端冲突和失败清理；
- 扩大 Windows 安装包冷启动、签名更新链路、OpenSSH 缺失，以及 Notepad++ 已安装/未安装场景覆盖；
- 扩大 Linux 发行版和 macOS Intel/Apple Silicon 实机兼容性反馈，未通过的平台问题按 Alpha 缺陷处理。

### v0.2 - 文件、监控与编辑器

- 稳定传输任务队列、取消、断点续传、覆盖/重试/恢复策略和失败诊断；
- 文件坞的目录操作、权限编辑、批量任务和更完整的键盘工作流；
- 在现有 Linux 实时概况上增加采样历史、趋势图和可配置频率；
- Notepad++、VS Code 和用户自定义编辑器适配，编辑会话恢复与远端版本冲突中心；
- Shell Integration、嵌套 SSH 主机上下文栈，以及安全广播的密码隔离、生产确认和危险命令保护；
- OpenSSH、PuTTY、Xshell、SecureCRT、MobaXterm、Tabby 和 Termius 的可审计配置迁移，优先迁移非敏感字段；
- SQLite 事件库、严格 CSP、最小 Tauri capability 和持续安全回归测试。

### v0.3 - 用户自控的加密同步

- Local Folder + WebDAV 的端到端加密、自动同步、离线 outbox 和冲突中心；
- 主机、命令/参数/路径历史、脚本、设置和背景的多设备合并；
- 恢复密钥、设备管理、加密导出/恢复演练，以及默认关闭的独立凭据 vault；
- SFTP、S3 和自建 Gateway provider；TOTP 只保护 Gateway 登录，不替代二级同步密码。

### 后续 - 原生引擎与可验证中继

- `russh` 原生 SSH/SFTP/跳板/端口转发引擎，并长期保留系统 OpenSSH 兼容回退；
- 用户自建 Relay、持续测速与可解释选路，以及可选 Mosh；
- 可选的托管中继、团队协作与审计、企业支持；开源客户端与自建链路继续独立可用；
- 只有中继真实部署并有公开测试数据后，才会使用“线路加速”表述。

详细技术门槛见 [ARCHITECTURE.md](docs/ARCHITECTURE.md#13-路线图与交付门槛)，模块边界、IPC、安全和跨平台发布规范见 [DEVELOPMENT.md](docs/DEVELOPMENT.md)。

## 参与与安全

- 提交代码前阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。
- 新模块和发布在提交前遵循 [DEVELOPMENT.md](docs/DEVELOPMENT.md)。
- 安全问题请按 [SECURITY.md](SECURITY.md) 私密报告，不要公开密码、私钥、Token、生产 IP 或终端日志。
- 版本变化见 [CHANGELOG.md](CHANGELOG.md)。

## License

[Apache License 2.0](LICENSE)。该许可证允许商业和个人使用、修改与再分发，并提供明确的专利授权。内置目录链接到的外部脚本仍由各自项目许可证约束。

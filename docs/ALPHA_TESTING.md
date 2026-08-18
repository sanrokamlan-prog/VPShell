# VPShell Alpha 测试指南

本指南适用于 `v0.1.0-alpha.9`。这是技术预览版，目标是尽快发现安装、兼容性、连接、传输和数据持久化问题，不是让测试者在生产环境替代现有 SSH 工具。

## 1. 下载与测试边界

- 只从 [VPShell GitHub Release](https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.9) 下载安装包。
- Windows 10/11 x64 优先使用 `VPShell_0.1.0-alpha.9_x64-setup.exe`；MSI 用于需要 MSI 部署验证的场景。
- Linux x64 可测试 AppImage 或 DEB；macOS 可按 Intel/Apple Silicon 选择 DMG。
- Windows 安装包尚无 Authenticode 签名；macOS 包尚未公证，系统可能显示未知发布者警告。
- 请使用测试 VPS、临时目录和可丢弃文件。不要用生产主机做首次广播、脚本、密钥安装或批量传输测试。
- 提交反馈前删除密码、私钥、Token、生产 IP、主机名、URL 密钥和敏感终端内容。

安全漏洞不要创建公开 Issue，请使用 [私密漏洞报告](https://github.com/sanrokamlan-prog/VPShell/security/advisories/new)。

## 2. 测试前记录

请先记录以下信息，提交反馈时会用到：

- VPShell 版本和安装包类型；
- 操作系统版本、架构和系统语言；
- `ssh -V` 输出；
- 远端系统及版本；
- 认证方式：密码、私钥或 SSH Agent；
- 连接方式：当前 Alpha 仅直连；
- 是否安装 Notepad++、`tar`、`zstd`、`iperf3`。

首次测试建议准备一台非生产 VPS；测试 UDP 双向测速时可再准备一台运行 `iperf3` 的 VPS。远端准备一个仅用于测试的目录，例如 `~/vpshell-alpha-test`。

## 3. 必测清单

### A. 安装、启动与升级入口

- 安装后能正常冷启动、关闭并再次启动；图标、窗口和版本号正确。
- 全新安装首次启动应自动显示 5 步使用指南；逐步切换、点击进度点、完成关闭均正常，右上角问号可再次打开指南。
- Windows 分别记录 NSIS/MSI 的安装结果、系统警告和卸载结果。
- 设置页“检查更新”能正确报告当前版本；真正的下载安装流程要等下一版发布后再回归。
- 系统未安装 OpenSSH Client 时，错误信息应明确且应用不能卡死。

### B. SSH 终端与会话

- 分别验证密码、加密私钥或 SSH Agent 中至少一种认证方式。
- 验证默认 22 端口和一个自定义端口；首次主机指纹必须显示算法和 SHA256 值并由用户确认，更换服务端主机密钥后必须硬阻止。
- 对一台系统 OpenSSH 可以连接、但旧版曾提示“SSH 握手失败”的主机重点回归；当前终端预检不应再被 SFTP/libssh2 的算法协商能力阻断。
- 同时打开 3 个标签，测试输入输出、中文、窗口缩放、断开、重连和大量输出回滚。
- 新发起的连接按最近时间置顶；记录当前表示 SSH 进程已启动，不代表认证已经成功，因此失败认证也可能出现。请重点反馈排序、重复项和路径是否正确。
- 关闭并重启 VPShell 后，确认主机配置和历史仍在本机。

### C. 主机识别与负载采样

- 核对左侧主机 IP、用户、环境颜色和复制 IP 按钮。
- Linux 目标在保存密码、私钥或 Agent 可用时，应显示 CPU、内存、磁盘、负载、流量和进程摘要；断开后停止采样。
- 等待至少两个采样点，确认 CPU、内存、磁盘、负载和网络趋势出现；频率可切换为 5/15/30/60/120 秒，历史达到 120 点后只淘汰最旧点并显示淘汰数量。
- 点击暂停后允许当前已经启动的采样在最多 12 秒内收口，但不得出现新的历史点或新连接；恢复后重新采样。切换标签或断开时，旧会话的迟到结果不得重新出现。
- 终端刚连接时观察 SFTP 和概况是否依次启动；概况独立连接失败时可以单独报错，但不得把已导入密码标记为无效，也不得断开正常终端。
- Windows 采样期间不得弹出独立的 `ssh.exe` 黑色窗口。
- v0.1.0 发布物不会识别手动嵌套 SSH；在 v0.2 工作树中，进入 bash/zsh 后点击“识别当前 Shell”，再手动进入下一台并再次点击，顶部应增加自报上下文；退出后应回退到已知祖先。fish/PowerShell 不在本批支持范围。
- 桌面添加主机可选择一台已有跳板；只有原生 `russh` 引擎执行该 route。跳板和目标都必须预先配置独立认证来源与 SHA256 pin；Android、兼容 OpenSSH 和独立大传输仍不执行跳板路线。

### D. SFTP 与打包传输

- 浏览目录并上传、下载单文件和文件夹，验证空目录、中文、空格和较深目录。
- 在未连接标签显式选择 `russh` 后连接，文件坞应显示“原生共享”；连续刷新和切换多个目录时终端必须持续收发，断开终端后迟到目录结果不得重新填充面板。上传下载、外部编辑和远端变更仍应走独立兼容连接，不能宣称大传输已经复用终端通道。
- 当 SFTP 失败而同一主机终端正常时，错误应明确区分握手、主机密钥、网络和认证；不得只显示“凭据错误”。
- 从 Windows 资源管理器拖入文件和文件夹，观察字节进度和完成状态。
- 至少测试一个 1 GiB 左右的大文件，以及一个包含 1,000 个以上小文件的目录。
- 下载后使用 SHA-256 或系统工具抽查内容一致性。
- 在目标已存在、权限不足、磁盘空间不足或网络中断时，记录提示、临时文件清理和是否误覆盖。
- 对大量小文件测试 `tar + zstd` 打包模式；远端缺少 `tar`/`zstd` 时应回退递归 SFTP，打包、上传、解包或提交失败时应明确报错且不能误覆盖。
- 传输过程中关闭文件面板、切换到另一台主机，再返回原主机打开文件面板；同一应用进程中的任务状态和进度应恢复，不能被误报为完成或凭空消失。
- 在大文件、递归目录和打包传输的扫描、复制或解包阶段点击停止；状态应先变为“正在取消”，随后明确显示“已取消”，并报告是否已有部分条目提交。
- 取消或制造网络中断后，检查目标目录是否遗留 `.vpshell-*.part`、临时压缩包或本机临时目录；无法清理时界面必须显示具体警告，不能静默成功。
- 最终原子提交开始后，停止按钮应禁用或明确提示已经来不及取消，不能把已经提交的数据伪装成已取消。
- `v0.1.0-alpha.7` 发布产物不支持暂停、断点续传或应用重启后的任务恢复；当前 v0.2 工作区已加入恢复记录，但尚未进入该 Alpha 安装包。SFTP/打包传输只支持直连。

### E. 外部编辑

- 双击远端普通文本文件，分别测试 Notepad++、VS Code/Code Insiders/VSCodium、自定义编辑器或系统默认编辑器；带空格的可执行路径和文件路径不得被拆分为 shell 参数。
- 修改本地副本后直接结束 VPShell，再次启动应在“编辑恢复与冲突”中看到记录，但不得自动联网或回传。只有连接到相同主机/端口/用户后才能恢复；其他主机记录只能另存或丢弃。
- 制造远端版本冲突，逐项验证另存本地副本（不得覆盖已有文件）、重新下载、明确强制覆盖和丢弃。切换选择或重启应用不能绕过冲突。
- 将最新恢复状态截断或改为未知 schema 时，应用应回退到最近有效快照或显示清理警告，不得崩溃；超过 14 天的记录和受管缓存应清理。
- 保存后确认自动回传；在编辑期间从另一终端修改远端文件，确认 VPShell 阻止静默覆盖。
- 测试“重新下载”和明确确认后的“强制覆盖”。
- 当前仅支持不超过 64 MiB 的普通文件、直连目标；应用重启后不能恢复编辑会话。

### F. 客户端迁移与 SSH 密钥

- 先备份 FinalShell 配置目录，再从副本导入主机、端口、用户和可选密码。
- 从 alpha.2 升级的机器需重新选择同一目录导入一次；重复主机应更新凭据且不要求逐台输入密码。
- 抽查导入数量、重复项、端口、用户名和连接结果；不要在 Issue 中上传原始配置文件。
- 确认首次启动和迁移后没有 3 条旧示例主机；任意添加或导入的主机均可从列表删除。
- 删除主机后应进入左侧回收站，保留期显示为 30 天；验证恢复后配置和历史返回，再验证永久删除需要二次确认。不要对唯一生产凭据做此项测试。
- 导入结果中“密码未迁移”应为 0；该数字只表示本机解密/保存结果。随后断开重连，终端、负载采样和 SFTP 不应再次要求输入同一密码；某次辅助连接失败也不能反向修改导入结果。
- 首次未知主机指纹仍必须人工确认；确认后 SFTP 应复用 OpenSSH `known_hosts`，真实换钥必须硬阻止。
- 分别生成一把带口令的 Ed25519 或 RSA4096 密钥，确认公钥、私钥路径和再次连接。
- 只向测试 VPS安装公钥，确认加入当前连接主机后可登录。
- 分别用不含真实秘密的 OpenSSH config、PuTTY Sessions `.reg`、Xshell `.xsh`、SecureCRT session `.ini`、MobaXterm bookmark、Tabby YAML/JSON 和 Termius JSON 导出生成预览。改变来源或路径后旧预览必须消失，第二次确认才加入资料库。
- 核对每条报告把主机/端口/用户名标为映射，把密码、Token、私钥、vault、known_hosts 信任和无法无损展开的规则标为跳过；损坏编码、无效端口、过深结构和陌生格式应逐项失败且应用不崩溃。
- 在 Windows/macOS 真实客户端上记录版本和官方导出方式。当前 Linux 夹具通过不能替代 PuTTY 注册表、Xshell/SecureCRT 版本差异、MobaXterm 安装/便携模式以及 Tabby/Termius 官方导出的实机验收。
- 当前没有跨客户端导出。

### G. 命令、脚本与多终端广播

- 在命令栏搜索“磁盘满了”“查看 nginx 日志”“UDP 测速”等中文意图，核对参数表单、风险提示和最终命令。
- 新建一个自定义脚本，重启应用后确认仍存在；脚本应只加入命令栏，不得后台静默执行。
- 勾选多台已连接测试机发送 `hostname` 或 `pwd`：第一次提交只出现冻结命令/目标预览，第二次确认才发送；发送后目标清空，逐台结果只表示 PTY 写入状态。
- 预览后断开一台或在已启用 Integration 的终端切换嵌套上下文，确认该目标被跳过而其他目标可成功，整体显示部分完成。
- 把测试 profile 标为生产，确认预览持续显示生产标签并要求确认。不要用真实生产主机做首次验证。
- 尝试广播 `sudo`、`passwd`、`ssh`、递归强制 `rm`、`mkfs`、关机和 `curl ... | bash`，应在 Rust 预览阶段阻止；在单终端中输入密码不得出现在其他终端。
- 关闭广播必须清空目标；重新打开不能沿用旧选择或旧确认。Raw input 广播仍不可用。

### H. 网络诊断

- 对公开目标执行路由追踪，记录系统兼容性和输出是否完整。
- 使用非敏感 URL 执行限量 HTTP 下载测试，确认到达流量或时间上限后停止。
- 在自有 VPS 手动启动 `iperf3 -s -p 5201`，分别测试本机到 VPS 和 VPS 到本机的 UDP 方向。
- 核对带宽、时长、抖动、丢包与预计最大流量。VPShell 不会安装 `iperf3`、开放防火墙或启动服务端。

### I. 外观、设置与本地持久化

- 测试本机 PNG/JPEG/WebP 和无凭据/query/fragment 的 HTTPS 图片 URL 作为终端背景，以及可读性调节；符号链接、错误魔数、超过 8 MiB、重定向 URL 必须由 Rust 拒绝。
- 测试系统字体、选择 TTF/OTF/WOFF/WOFF2 和字号；错误魔数、符号链接和超过 12 MiB 必须拒绝，确认长主机名、中文和窗口缩放后没有遮挡。
- 修改主机、历史、脚本、打包传输、编辑器和背景设置，重启应用确认从 `vpshell-state.sqlite3` 恢复；旧 WebView 状态只在 SQLite 初始化成功后删除。
- 在测试副本中截断 SQLite 文件，确认显示恢复诊断、最多保留两个 `.corrupt-*` 备份且不崩溃。不要把数据库或备份上传到 Issue。
- 静态核对生产 CSP 不为 `null`，`object/frame/form` 禁止，capability 没有 core/plugin `default` 集合；Linux 构建不能替代 Windows/macOS WebView 与安装器权限验收。
- 当前资料保存在本机 SQLite/受管资产缓存；桌面 Local Folder 已把不可变 bootstrap、二级密码解锁和 Rust 单周期 worker 接入设置页，但 AppState operation 入队/回写与自动调度仍未实现。初始化空目录后应确认 bootstrap 不含录入密码；“解锁已有”对空目录失败，“初始化新 vault”对已有 bootstrap 失败，错误密码、未知版本、符号链接和特殊文件均 fail closed。Android 只显示 value-free 恢复/冲突/队列状态且 Sync capability 保持禁用。真实 WebDAV 服务、自签 CA、代理、断网和平台目录兼容仍需外部矩阵；S3/SFTP 真实同步 transport 尚未实现。
- 内部 `vpshell-sync.sqlite3` outbox 夹具应覆盖业务/operation/outbox 原子回滚、两分钟过期租约、暂停/显式恢复、六次退避上限、发布后拒绝重试、损坏隔离后的 `reconcile-required`、未来 schema 原样保留、未发布保留，以及 AEAD/序号/对象身份重放拒绝。当前手动 worker 只处理已存在的 journal 项，不能通过空周期点击宣称业务数据已完成端到端同步。
- merge 夹具必须把同一组 host/script/setting/background/history operation 以不同顺序应用并比较完整状态；覆盖 observed update 不误报、未观察 edit/delete 冲突、删除保持/明确恢复、并发冲突解决、风险降低、history 并集、revision 冲突、损坏/未知 schema，以及 password/Token/private key/credentialRef/trust pin/本机路径拒绝。当前冲突中心没有 UI，源码测试不能替代多设备人工可用性验收。
- 恢复密钥夹具必须覆盖可打印格式往返（包括 base64url 正文含 `-`）、校验码、错误密钥、独立 keyslot 域、篡改和未知字段；恢复密钥、VMK 和解密明文不得出现在导出 JSON、日志或前端事件中。
- device registry 夹具必须覆盖 revision 冲突、公钥身份不可替换、最后活动设备保护、撤销不可逆、撤销后标签不可变、不同合并顺序和已撤销发布者拒绝。撤销后的报告必须要求 VMK 轮换，不能声称远程擦除。
- 加密导出夹具必须覆盖 manifest/对象篡改、截断、重复 key/hash、跨 vault、数量/大小、恰好一个 registry、错误恢复密钥、无覆盖原子写、Unix `0600` 与符号链接拒绝；演练必须认证每个对象并解析 event/registry。当前没有同步 UI、真实多设备签名或 restore-to-journal，不能做产品级恢复声明。
- 凭据 vault 夹具必须确认默认关闭、revision 冲突、仅活动且已授权设备可访问、最后授权设备保护、撤销不可重新授权和轮换提示；错误 CVK、AAD 身份搬移、类型/大小、未知字段和跨 vault 必须拒绝。
- 对 SSH 密码、私钥口令、OpenSSH 私钥和 access token 逐类往返，扫描 keyslot/信封/object key/稳定错误，确保不含 secret 或本机 credential reference。静态安全测试必须持续禁止该模块新增 Tauri command/event/日志；当前没有 UI 或钥匙串写回，不能用源码测试宣称凭据同步可用。
- 扩展 provider adapter 夹具必须对 SFTP/S3/Gateway 复用同一不可变测试：首次创建、相同内容幂等、不同内容冲突、提交后回读、分页、非法/重复/越界 list、24 MiB 上限和取消。SFTP 另测 host-key/root/symlink/special，S3 另测 HTTPS/region/bucket/prefix，Gateway 另测六位 TOTP 只在登录消费及底层含秘密错误净化。
- B8 必须补真实 OpenSSH SFTP（不同服务器/权限/host-key 变化）、MinIO 或其他 S3-compatible（SigV4/path-style/延迟 list/条件写）及自建 Gateway HTTP 的断网、超时、限流、认证、重复请求和篡改测试；当前 trait fake 不能替代这些结果。
- `sync_protocol_regression` 源码夹具应在每次协议改动后运行并记录：未知版本拒绝、AEAD/对象身份错误、journal replay 与 published finality、merge order convergence、截断状态和取消诊断。它不访问网络，也不替代真实 provider、两台设备或 Windows/macOS/Android 验收。

### L. Android Preview 共享契约（Linux 可验证部分）

- `android_preview::tests` 必须验证 schema-v1 capability 清单、最多 8 个会话、结构化 host/user/port 和 `ssh-`/`key-` UUID 引用边界；模块不能出现系统 `ssh` 进程入口。
- 前台建立会话后切到后台应拒绝新连接与操作；锁定或断开应清理会话索引，恢复前台后必须重新建立会话。广播、外部编辑、常驻监控和后台长连接应保持明确禁用。
- `android_mobile::tests` 与安全回归还应验证 64 KiB 终端 I/O、密码/私钥类型和大小、默认 Locked/原生失焦重锁、只有 Rust 系统认证 command 可解锁、host-key/凭据命令授权、固定主 frame/origin 与 32-byte 可见性 WebMessage、桌面/Android capability 平台互斥且不给 WebView biometric permission、仅 INTERNET 权限、禁用 backup/cleartext/FileProvider、长按选择/autofill/content capture 及 `FLAG_SECURE`。移动敏感请求不得派生 `Debug`/`Serialize` 或使用日志宏。
- Linux VPS 可记录 aarch64 debug APK/AAB 的路径、大小、SHA-256 与 debug 签名结构，但不能替代 Android Keystore/生物识别、emulator/instrumentation、arm64 真机、休眠/网络切换、软键盘、截图或剪贴板人工验收。
- `android_native_transport::tests` 还应验证固定 SHA-256 host-key、5--60 秒超时、清零密码/内存私钥载荷、绝对远端路径与 1,000 条 list 上限；它只能证明 Rust API 边界，不证明真实 SSH 算法、SFTP 权限或 Android arm64 链接。

### M. Phase D 原生 route 契约

- 原生 probe 与终端的 IPC 必须只接受 `route.hops[]`；空 route、超过 4 跳、重复 hop UUID、重复 host/port、无效端点/指纹/超时、同跳多认证来源、旧的扁平请求和 `password` 等未知秘密字段都应拒绝。
- 两跳夹具必须使用不同 host-key、用户和一次性私钥；跳板 sshd 只允许连接目标测试端口，目标 sshd 禁止继续转发。先用错误目标 pin 确认只返回第 2 跳，再以正确 pin 实际完成 probe、共享 SFTP、PTY 字节收发和取消；错误不得包含 host、credentialRef、私钥路径或底层库文本。
- 单跳 Linux 回环 fixture 必须继续实际完成 pin、公钥认证、两次共享 SFTP 浏览、PTY resize/字节收发和取消，证明 route 重构没有把现有直连退化为 mock。
- 系统 OpenSSH fixture 必须使用生产参数构造器和精确写入的临时 host key 实际执行远端标记命令；请求未知字段、非 canonical UUID、选项式 host/user、0 端口、越界 PTY 和 ProxyCommand 注入都必须拒绝，credential/key reference 不能出现在 argv。单跳只允许密钥格式、认证算法协商和 RSA SHA-2 不可用三类原生错误携带 OpenSSH 回退；host-key 不匹配/未验证、认证失败/拒绝、取消、超时、无效请求和多跳 route 必须保持无回退字段。
- 本地转发 IPC 不接受 `bindHost`、密码或 route 外凭据字段；监听必须固定为 `127.0.0.1`，0 端口由 OS 安全分配。远端转发 IPC 还必须拒绝 `targetHost`，最终 SSH 目标的监听与客户端目标都固定为 `127.0.0.1`；未登记、端点不匹配或超过 32 连接的 forwarded channel 必须在确认前拒绝。动态转发 IPC 只接受 UUID、route 和端口，固定回环监听；验证无认证 SOCKS5 CONNECT 的 IPv4/域名/IPv6 目标，并确认 BIND、UDP ASSOCIATE、未知地址类型、无效域名、零端口和超过 32 个连接 fail closed。Linux 双跳夹具的最终 sshd 只能 `PermitOpen` 自身测试端口、`PermitListen` 回环地址，测试必须分别经本地 listener、服务器分配的远端 listener 和动态 SOCKS5 listener 读取真实 SSH banner，停止后等待 Rust 代际清理；非回环监听始终不可用。
- 自建 Relay 源码测试必须使用真实回环 TCP 完成 challenge/HMAC 双向 proof、opaque SSH-like 字节往返、错误 token、目标篡改/拒绝、challenge 重放、全局/单 IP/认证速率、字节/空闲/总时长/取消、audit fail-closed、token/audit 私有文件边界、旧/新 token 重叠与撤销后拒绝，并证明未知 wire version 不协商或降级；command manifest、desktop/Android capability 与 WebView 状态中不得出现 Relay token 或启动入口。
- 外部验收只在自有非生产节点执行：Relay firewall 仅开放预期入口，allowlist 仅包含测试 SSH 目标；客户端仍须显示并验证最终 SSH host-key。分别测试错误 token、错误目标、断网、慢连接、限流、审计磁盘不可写和进程重启，确认没有开放代理、无凭据/SSH bytes/原始 IP/hostname 进入 JSONL。协议 v1 控制面不加密；未配置独立 ACL 或经审计 TLS/VPN 时不得把目标元数据称为保密。
- 仓库 systemd/logrotate 基线及 token 轮换/撤销、升级/回退、audit/token 故障恢复 runbook 只提供可执行边界；至少两地区真实节点、长时间丢包/重连、真实日志轮换、TLS/VPN/firewall 和运维演练尚未外部完成前，不宣称自动选路、线路加速或生产 Relay 服务。
- 路线评估请求必须拒绝非 canonical campaign UUID、空/超过 4 个候选、重复/非法 candidate ID、30 秒以下或 300 秒以上间隔、窗口/总轮数越界、未知字段和 hop 内明文 `password`。Android capability 必须排除 start/get/stop 三项命令。
- 为同一测试目标配置可直连且可经跳板到达的两条 route；至少完成 3 轮，确认每轮都实际通过各自 host-key/pin 和认证并完成最终 SFTP readiness。错误 pin 应只返回对应候选与 `hopIndex` 的稳定错误码；快照不得包含 host、用户名、credentialRef、私钥路径或底层错误文本。
- 人为使一条路线失败，确认成功率低于 80% 后不会被推荐；构造小于 15% 的评分波动，确认保持原建议并显示滞后原因。停止和关闭对话框均应取消在途连接且不再增加样本。该页面不得自动修改主机跳板配置，也不得显示 UDP 丢包、吞吐或“加速”结论。
- Mosh 契约测试必须拒绝未知字段、选项式 host/user、无效 UUID/PTY、固定范围以外的 UDP 端口和任意 server/SSH 参数；生成参数必须固定 `mosh-server`、adaptive 与 60000–61000，SSH bootstrap 保留严格 host-key、安全 KEX 和至多一次 AskPass，credential/key reference 不得进入 argv。Android capability 必须排除 `start_mosh_session`。
- Linux CI 使用现有回环 sshd、一次性 Ed25519 密钥和严格 known_hosts，实际启动本机 `mosh` 与远端 `mosh-server`，经 UDP 收到 marker 后有界停止。外部验收只在自有非生产节点执行：分别验证本机/远端缺少 Mosh、UDP firewall 拒绝、网络切换、休眠/恢复、长时间断网和终端 resize；Mosh 必须保持直连手动模式，不支持跳板，不替代 SFTP、传输、监控或转发，也不能作为自动加速结论。

### J. v0.2 工作区恢复验收（仅源码构建）

- 启动一个大文件或目录传输，确认关闭应用后再次启动不会自动继续、覆盖或提交；打开同一主机的文件面板后应显示“需要恢复决定”。
- 在未出现最终提交或部分文件提交的任务上选择明确“重试”，确认需要当前连接身份、任务可取消，且失败后显示剩余次数；最多 3 次后只能重新发起任务。
- 在正在最终提交、已提交部分文件或清理警告的任务上，确认不提供重试，只能先核对目标再“丢弃恢复记录”；丢弃不删除已写入文件。
- 在恢复目录制造截断 JSON、旧 `schemaVersion` 或多个快照，确认应用不崩溃，显示可操作的存储警告，并保留最近有效状态；超过 30 天或超过 200 条的记录按界面提示清理。

### K. v0.2 文件坞变更验收（仅源码构建）

- 在专用测试目录新建目录、重命名普通文件/目录并修改单项及多项权限；已有同名目标必须拒绝覆盖，权限只接受三位 `000..777`。
- 将普通文件和无符号链接目录移动到同文件系统及另一挂载点，分别验证 `fail`、`rename` 和明确 `overwrite`；目标只能在复制与 SHA-256 核验后出现，失败/取消不留 `.vpshell-stage-*`，覆盖提交失败应恢复旧目标。
- 对目录启用递归权限，确认清单受 64 层/10,000 条限制，符号链接及其目标权限均不被跟随修改；预览后增删条目必须整项跳过。
- 多选文件、目录和符号链接后执行删除，先核对 Rust 返回的逐项预览，再完成两次确认；递归删除不得跟随符号链接，根目录、父子重叠选择、`..` 和控制字符路径必须被后端拒绝。
- 在预览返回后改变选择、切换目录，或从另一会话修改/新增目标，旧确认不得继续作用于变化后的对象；结果必须逐项区分成功、失败、跳过和部分删除。
- 取消正在复制暂存的批量移动，确认暂存被清理且剩余项报告跳过；完成一项提交后取消剩余项，结果必须标记部分完成。强制关闭应用后，未提交任务只能通过新预览恢复，已提交或进入最终化的任务只能核对后丢弃。
- 用鼠标、Shift/Ctrl/Cmd 多选以及键盘方向/Home/End、Ctrl/Cmd+A、Enter、F5、F2、Delete、Alt+Up、Ctrl/Cmd+L 验证焦点与操作；复测上传/下载取消、重启恢复、外部编辑标签和屏幕阅读器名称仍正常。

## 4. 问题优先级

| 级别 | 判定 | 示例 |
| --- | --- | --- |
| P0 阻断 | 数据丢失、安全问题、错误连接生产目标、安装后无法启动 | 文件被错误覆盖、凭据泄露、连接目标与显示 IP 不一致 |
| P1 严重 | 核心流程不可用或应用崩溃，且没有合理绕过办法 | SSH 无法连接、SFTP 传输损坏、升级失败后无法启动 |
| P2 一般 | 有绕过办法的功能错误或明显兼容性问题 | 某路径无法浏览、某编辑器无法启动、监控不刷新 |
| P3 体验 | 文案、布局、操作效率和建议 | 按钮不直观、信息密度、快捷键建议 |

P0 安全问题必须私密报告。普通问题使用 [缺陷报告](https://github.com/sanrokamlan-prog/VPShell/issues/new?template=bug_report.yml)，完整跑完一轮可提交 [Alpha 测试回报](https://github.com/sanrokamlan-prog/VPShell/issues/new?template=alpha_test_report.yml)。

## 5. 可直接发给测试者的话

> VPShell `v0.1.0-alpha.8` 正在进行小范围实机测试。请优先使用 Windows 10/11 x64 和非生产 VPS，重点回归 FinalShell 导入凭据、首次主机指纹确认、无 Windows 原生外框、SFTP 文件与目录传输、拖放、打包传输、关闭面板后的任务恢复、跨重启恢复、传输取消和临时文件清理，同时测试 Notepad++ 外部编辑、多标签、最近连接、SSH 密钥、多机广播和网络诊断。当前仅支持直连，端到端同步和 Android 真机仍未完成。请不要把它当作生产密码管理器，不要首次就在生产机执行广播或脚本。发现问题请写明系统版本、安装包、OpenSSH 版本、远端系统、认证方式、复现步骤、预期和实际结果；截图和日志务必删除密码、私钥、Token、生产 IP、主机名及敏感命令输出。下载与反馈入口：https://github.com/sanrokamlan-prog/VPShell/releases/tag/v0.1.0-alpha.8

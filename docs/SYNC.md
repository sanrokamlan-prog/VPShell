# VPShell 加密同步设计

当前实现补充：`onboardingCompleted`、默认监控采样频率与背景可见度已分别作为第三、第四、第五个固定 setting 实体接入 Rust changefeed、加密 operation、merge 投影和防回声；它们分别只含一个布尔字段、一个 5–300 秒整数和一个 5%–65% 整数。通过秘密扫描的命令、远端路径与具名非敏感参数历史，以及 Rust 证明的已认证连接历史，使用独立 `history` 实体、稳定 UUID 和 tombstone 接入同一链路；含明显秘密、敏感/未知参数的记录、没有真实时间的旧路径和没有认证事实的旧/伪造连接条目保持本机。背景使用独立 `background` 实体和加密分块；PNG 由 Rust 解码并规范化，JPEG/WebP 通过结构、RIFF/chunk 或 JPEG 结束标记校验后保留原始编码；原始 URL、引导内容、运行中监控状态及设备本地数据仍不入同步包。

> 文档状态：协议设计与分阶段实现。当前未发布工作树已实现独立 Rust 密码学层、Local Folder/WebDAV/SFTP/S3-compatible/Gateway 不可变对象 provider、SQLite operation/outbox/replay 状态机、确定性 merge/冲突中心、Rust 单周期协调器、恢复密钥/设备 registry/加密恢复演练、本机 operation Ed25519 签名封套，以及默认关闭的独立凭据 vault。桌面五种 provider 已接入显式初始化/解锁、手动单周期和解锁期 Rust 自动调度；SFTP 只允许选择 AppStore 中已保存的主机，在认证前同时核对 known_hosts 和精确 SHA256 pin，并从本机系统凭据、私钥或 agent 认证。WebDAV basic-auth、S3 SigV4 与 Gateway 登录密码只保存到系统凭据管理器，显式 PEM CA 由 Rust 限量导入应用私有目录；Gateway 可选 TOTP 只进入当次登录。AppState 主机公开字段、安全自建脚本、五个固定设置实体、PNG/JPEG-WebP 背景及公开命令/路径/非敏感参数/已认证连接历史已接入事务 changefeed、具名加密 operation、outbox 和可重试投影；GC 以加密成员/确认索引和 schema-v3 候选表记录活动设备 frontier，满足 30 天保留后才尝试条件删除。协调器以签名、加密且按 revision 不可变的远端 registry 链作为授权锚，在 schema-v4 journal 持久化已验证水位，并提供桌面受控登记、改名和撤销；系统钥匙串恢复写回和 VMK/CVK 轮换流程仍未实现。SFTP/S3/Gateway 没有条件删除能力而保守保留旧密文，真实 Gateway、外部服务器与多设备矩阵也仍需验收。

### 当前 v1 密码学边界

`sync_crypto.rs` 只在 Rust 内存中持有 32-byte VMK，类型不可序列化且在释放时清零。密码 keyslot 使用 Argon2id v19，默认 64 MiB/3 次/1 lane，读取时只接受 19–256 MiB、2–10 次、1–4 lanes 和固定 32-byte 输出；密码为 8–1024 bytes。keyslot 使用 16-byte salt、24-byte nonce 和 XChaCha20-Poly1305 包裹 VMK，格式版本、vault/slot ID、业务密钥域、算法、全部 KDF 参数和密文长度进入长度前缀 AAD。

业务对象按 event/blob/index/checkpoint/device-registry 五个 HKDF-SHA256 label 派生不同密钥；vault ID 参与 extract salt，对象类型、对象 ID、设备/序号、算法和密文长度进入 AAD。对象明文最多 16 MiB，JSON 信封最多 24 MiB，keyslot 最多 16 KiB；UUID、base64url、类型与序号组合逐字段验证，未知字段和未知版本拒绝。每次生产加密都从 OS CSPRNG 取得随机 nonce；固定 nonce/salt 入口只在单元测试中用于稳定向量。

本机实体 changefeed 与冲突解决 operation 先进入严格 Ed25519 version-1 签名封套，再由 event AEAD 加密。私钥由 OS CSPRNG 生成、只保存到独立系统凭据条目且 Rust 内存副本清零；签名以固定 domain 和长度前缀绑定 canonical device UUID 与原始 operation 字节。生产配置会创建或验证 `registry/{revision}.oreg` 连续链；每个 successor 绑定前序信封 SHA-256，并由前后版本均为 active 的登记设备签名。SQLite 持久水位要求远端仍包含已信任 revision 的同一哈希，缺失、回退、断层、分叉、未知/撤销设备或 event 内外 device ID 不一致均在业务 merge 前停止。旧裸 v1 operation 只由测试/迁移入口接受，配置后的远端周期只接受 registry 授权的签名封套。

该格式能认证对象身份并阻止把密文搬到另一域/vault/设备/序号后解密，但相同完整对象的重放需要后续 outbox/head/sequence 状态机检测。当前没有任何 IPC 返回 VMK、KEK、密码或解密明文；产品流程开放桌面 Local Folder、标准 HTTPS WebDAV、固定 host-key 的 SFTP、SigV4 S3-compatible 和自建 Gateway。

## 1. 目标

同步系统需要覆盖用户在多设备间真正会复用的数据，同时允许用户选择自己的存储位置：

- 主机连接配置、分组、标签、跳板路线和偏好；
- 命令历史、远端路径历史、快捷命令、具名非敏感参数和已认证连接历史；
- 所有自建脚本、参数模板、图标和附件；
- 终端主题、背景配置及需要同步的本机背景图片；
- 可选的主机凭据和私钥 vault，默认关闭；
- Local Folder、WebDAV、SFTP、S3 兼容存储和自建 Gateway；
- 离线写入、自动增量同步、确定性合并、冲突可见和恢复演练。

同步不是远程桌面，也不传输正在运行的 PTY 缓冲区、临时密码输入或会话内存。

## 2. 威胁模型

### 2.1 需要防御

- 存储服务读取业务数据；
- 存储服务或网络攻击者修改、替换、遗漏或重放对象；
- 多设备离线编辑造成更新覆盖、历史丢失或删除复活；
- URL 背景、脚本附件和远端对象携带恶意内容；
- 用户误把密码、token 或私钥内容写入可同步历史。

TLS 仍然必须启用，但 TLS 只保护传输链路，不能替代客户端端到端加密。

### 2.2 不承诺防御

- 已解锁终端被恶意软件、键盘记录器或内存读取攻击；
- 用户主动执行的远端脚本窃取环境变量或文件；
- 存储服务删除全部对象或拒绝服务；
- 对象数量、大小和上传时间等流量元数据泄露；
- 用户忘记二级密码且同时丢失恢复密钥。

加密与哈希链能发现很多篡改和回退行为，但不能让不可信 blob 存储变成高可用备份。用户仍需保留导出备份和恢复密钥。

## 3. 当前状态与目标状态

| 能力 | v0.1.0 | 目标 |
| --- | --- | --- |
| 本地业务存储 | WebView `localStorage` 明文 JSON（legacy） | Rust 管理的 SQLite schema v1 快照 + 有界事件域；同步前再做 E2EE 对象化 |
| Provider | 桌面 Local Folder、HTTPS WebDAV、固定 host-key SFTP、SigV4 S3-compatible 与版本化 HTTPS Gateway 已接入 | 可由用户配置、解锁和自动调度的 provider |
| 二级密码 | Local Folder bootstrap 已用 Argon2id keyslot 包裹随机 VMK，密码不持久化；轮换/恢复 UI 未接线 | Argon2id 派生 KEK，包裹随机 Vault Master Key |
| 同步动作 | 桌面可显式运行单周期，并在解锁期间由 Rust 执行启动/业务变化防抖/周期/失败复查；Android 只读状态可见；主机公开字段、安全自建脚本、终端字体族/字号/行高及两个应用行为偏好已接入本地入队与远端事务投影 | 补齐其他业务域、系统网络事件直连触发与完整冲突处理；应用关闭后不伪装为后台服务 |
| 冲突 | 无 | 事件并集、字段级 LWW、tombstone、冲突中心 |
| TOTP | 只有 Gateway 条件开关 | 只用于自建 Gateway 账户登录 |
| 凭据同步 | 只有开关 | 默认关闭的独立凭据密钥域 |

## 4. 不上传 SQLite 整库

SQLite 是本地事务数据库，不是远端同步文件。直接覆盖或合并整库会带来：

- 两台设备同时上传时最后写入者覆盖全部其他变化；
- WAL、页版本和崩溃时点差异造成损坏；
- 每次小改动都上传大文件；
- 无法按实体合并、解释冲突或进行安全删除；
- 回滚和篡改难以定位。

目标方案把本地变更转换为不可变 operation，再按设备分段上传。SQLite 只负责本地视图、事务和同步游标。

## 5. 本地事务与 outbox

业务状态与 sync journal 当前位于两个 SQLite 文件，不能宣称一次提交可以跨两个数据库原子完成。业务修改先在 `vpshell-state.sqlite3` 的同一个事务中完成状态快照和 durable changefeed：

```sql
BEGIN;
  UPDATE business_view ...;
  INSERT INTO app_sync_changes (operation_id, entity_id, mutation_kind, ...);
COMMIT;
```

手动 worker 读取 changefeed 后，在独立 `vpshell-sync.sqlite3` 的一个事务内生成带 observed stamp 的具名 operation、AEAD 加密、更新 merge state、推进设备 seq/HLC 并写 outbox；journal 提交成功后才按 operation ID 从业务库确认 change。若进程在两个提交之间退出，下次运行会解密并核对 journal 中同 ID operation 的实体类型、身份与公开 payload，相同则幂等确认，不同则 fail closed。这样不依赖虚假的跨库事务，也不会出现已保存业务状态永久漏传。changefeed 只含白名单公开字段；本地主机和自建脚本 ID 分别通过持久随机 UUID 映射到协议实体，五组已接线偏好使用不同的固定协议 UUID，以便独立初始化的设备收敛。主机 credentialRef、私钥/路径、host-key pin、Token 和 provider 凭据不会写入其中；脚本只允许 name/body/source/risk/parameters，description/category/内置脚本不进入同步，正文、来源或参数未通过秘密扫描时不入队。原先安全的脚本变为不安全时只发布 tombstone，不上传新内容。终端外观只允许完整的 fontFamily/fontSize/lineHeight，行高以百分之一整数编码；行为偏好只允许完整布尔值 autoUploadEditedFiles/packageTransfersEnabled；背景可见度只允许 5–65 的整数百分比。自定义字体文件、`customFontName`、`externalEditorPath` 和背景图片来源/资产保持本机。

当前 `sync_outbox.rs` 使用独立 `vpshell-sync.sqlite3` schema v4 落实 journal 内原子边界，并持久保存随机本机 device ID、单调 HLC 与每个 vault 的已验证 registry revision/哈希/签名信封。调用者只能通过 Rust 内部闭包修改同一个 SQLite transaction；闭包不得执行网络、文件写入或其他不可回滚副作用。`sync_operations` 只保存已通过 v1 严格解析的加密信封，`sync_outbox` 保存状态/次数/租约/稳定错误码，业务明文、密码、私钥、credential ref、Token 和 provider 凭据不进入 journal。未发布最多 10,000 对象/256 MiB，整个 journal 最多 50,000 对象/384 MiB，数据库文件启动硬限制 512 MiB；已发布本地对象保留 30 天，远端 receipt 保留 90 天，但每设备持久高水位不会清理。

远端 receipt 与 merge state 提交后，协调器从 journal 分别读取完整主机、脚本、setting、background 和 history 投影，再交给 `vpshell-state.sqlite3` schema v11 的独立事务。schema v9 为 history 建立稳定 ID、内容指纹和独立投影水位；schema v10 新增不从旧快照回填的认证连接事实表；schema v11 新增固定 background 实体的内容指纹与独立投影水位。业务库要求 vault 绑定一致、没有尚未交给 journal 的本地 change，并为五个实体域分别以 `(merge_revision, projection_hash)` 拒绝回退或同 revision 换内容。background 投影仅接受固定 UUID 的因果 tombstone（无背景）或完整 `kind=managed-blob/blobId` 字段；协调器必须先恢复并安装被引用的 PNG，才允许投影 AppState。history 投影在主机之后按 `kind` 分流命令、每主机路径、具名参数与已认证连接；连接只接受活动 host、受限路径、严格时间和可信本地/远端事实，旧版或前端自行构造项保持本机。缺少必需字段、额外字段、错误类型、未知主机或超过 AppState 上限时对应事务整体回滚。专用投影不生成回声 changefeed；两个数据库之间以及五个业务投影事务之间崩溃时不伪称原子，下次周期从持久 merge state 重试。

worker claim 使用两分钟租约；进程中断后的过期租约不会立即重放，而是进入 `retry_wait`。网络、超时、限流和远端暂不可用按 2/4/8/16/32 秒退避，最多六次且单次最长五分钟；协议、认证、不可变冲突和完整性错误直接进入 `permanent_failure`。取消进入 `paused`，只能显式恢复且不重置尝试次数；`published` 是不可逆终态。损坏、截断或超过 512 MiB 的 journal 最多保留两个隔离备份，新库写入 `reconcile-required`；协调器会保持停止并只报告状态，远端核对和显式解除流程未接线前不能自动继续上传。

远端 event 先做严格信封解析与 AEAD 认证，再按已锚定 registry 的活动设备公钥验证 operation 签名和内外 device ID，随后才在同一事务执行合并回调、写 operation/receipt 并推进设备连续序号。重复 key+hash 幂等忽略；序号回退、缺口、相同密文换 key、或相同 `(vault, kind, object_id)` 出现不同密文均在业务回调前拒绝。90 天后 receipt 可清理以控制容量，此后旧序号仍由设备高水位拒绝，不会重新应用。registry 有独立前序哈希链；event segment 的逐设备 ciphertext 链与见证 head 仍属于后续协议层，因此当前实现不能向丢失本地水位的新设备证明远端完整历史。

每台设备维护：

- 随机 `device_id`；
- 设备内严格递增的 `seq`；
- Hybrid Logical Clock（HLC），用于离线设备间的确定性排序；
- 本地已验证的每设备 head、高水位和最近同步游标；
- 设备签名密钥，私钥保存在系统凭据库或本机加密 vault。

HLC 不是权限或真实性来源，只解决时间漂移下的合并排序。签名、AEAD 和已信任设备记录负责完整性验证。

当前内部 `sync_recovery` device registry 为严格 schema v1，最多 32 台，只保存 canonical device UUID、1–128 byte 非控制字符标签、公开 32-byte 签名键、时间与 active/revoked 状态。更新使用 expected revision；相同设备的公钥和加入身份不可替换，撤销单调且禁止撤销最后活动设备，合并时撤销优先并拒绝身份冲突。registry 的签名信封使用独立 domain、前序信封哈希和发布者身份，随后进入 `device-registry` AEAD 域；协调器只信任连续验证并写入本地水位的版本。封套自带公钥不再是生产远端授权来源。未登记桌面可生成最多 2 KiB、15 分钟有效、绑定 vault/device/标签/公钥/随机数并由设备私钥自签的 base64url 请求；现有活动设备验证后以 expected revision 新增，改名和撤销也必须刷新最新链、签署下一不可变 revision、条件创建并回读验证。已登记或已撤销身份不能重复申请，当前发布设备不能自撤销；Android capability 不含这些命令。撤销后的 VMK/CVK 轮换仍待实现。

## 6. Provider 抽象

所有 provider 都实现最小接口：

```text
list(prefix, cursor) -> object metadata page
get(key)              -> byte stream
put(key, byte stream) -> idempotent result
```

业务层只创建内容寻址或带唯一序列的不可变 key，不依赖远端 rename、事务、锁或就地更新。`put` 同名对象时只能接受完全相同的内容；内容不同时视为远端冲突/篡改。删除和条件写可作为 provider 优化能力，但不能成为基础协议正确性的前提。

当前 `sync_provider.rs` 实现上述最小接口但不暴露 Tauri IPC。key 最多 512 bytes/16 层，只接受 ASCII 字母数字、点、下划线和连字符分段，禁止绝对路径、空段、`.`/`..`、反斜杠、控制字符和保留暂存名；对象为 1 byte 至 24 MiB，列表页最多 1,000 项且一次扫描/响应最多 10,000 个对象。所有长读取按 64 KiB 检查取消。

Local Folder 要求现有非符号链接目录，逐级拒绝符号链接/特殊文件，写入同目录随机暂存文件并 `fsync`，再用原子 hard-link 无覆盖提交及回读校验；不支持该原语的文件系统会明确失败，而不会退化为可能覆盖的 rename。崩溃暂存名不进入对象列表。WebDAV endpoint 必须是无 URL 凭据、query、fragment 的 HTTPS URL，禁止重定向，可显式增加最多 64 KiB 的 PEM CA；连接/总请求受 5–60 秒配置上限约束。桌面入口把用户选择的绝对普通文件交给 Rust，拒绝符号链接、空文件、超限和不可解析 PEM，再以 `sync-webdav-ca-<UUID>` 复制到应用私有目录；AppState 只保存引用，配置 worker 每次重读并重新验证。它使用 MKCOL/PROPFIND/GET/带 `If-None-Match: *` 的 PUT，XML 响应最多 4 MiB，以 `quick-xml` 解析并拒绝 DTD、越界 href 和跨 origin/base 路径；成功或 412 后都回读逐字节核对。上传体与响应流可取消，但阻塞在 TLS/响应头期间最多等待配置超时。对象一旦原子链接或 PUT 成功，迟到取消不能把已提交工作误报成未提交。

| Provider | 首次范围 | 说明 |
| --- | --- | --- |
| Local Folder | MVP | 写入用户选择的目录，可由 OneDrive、Dropbox、坚果云等桌面客户端继续同步 |
| WebDAV | MVP | 使用 PROPFIND/GET/PUT；要求 HTTPS，允许用户显式信任自签 CA |
| SFTP | Desktop preview | 选择已保存主机；认证前核对 known_hosts 与精确 SHA-256 pin，逐级 lstat、无跟随有界读取、暂存 exclusive create 与无覆盖提交后回读；无可靠条件删除 |
| S3 compatible | Desktop preview | HTTPS/no redirect；SigV4 完整 payload hash、ListObjectsV2 continuation、GET、`If-None-Match: *` 条件 PUT 和提交后回读；系统凭据引用与可选受管 PEM CA；无条件删除 |
| VPShell Gateway | Desktop preview | 专用认证/session trait；版本化 HTTPS login、短期 bearer session、list/get/`If-None-Match: *` 条件 PUT；密码和可选 TOTP 只交给登录，session 只处理密文对象 |
| rclone | Roadmap | 优先通过 Local Folder/mount 兼容；若增加命令适配器，必须显式配置可执行文件和参数，不能接受任意远端下发命令 |

Gateway desktop preview 使用固定 JSON/HTTP v1：`POST {base}/session` 只接受 `protocolVersion=1`、规范 UUID 的 Gateway vault/device ID、用户名、密码和可选六位 TOTP，成功响应必须是版本 1、60–86400 秒有效期和最多 4096 字节的 ASCII graphic session token。后续请求只发送 `Authorization: Bearer` 和 `x-vpshell-protocol: 1`；`GET {base}/objects?prefix=&after=&limit=` 返回最多请求数量的有界对象元数据，`GET {base}/objects/{key}` 读取密文，`PUT` 必须携带 `If-None-Match: *` 且只接受 201/412。客户端禁重定向，连接和总请求固定 30 秒，JSON 最多 1 MiB、对象最多 24 MiB，未知 JSON 字段、未知版本、越界 token/list/object、非 HTTPS、URL 凭据/query/fragment、错误 CA 和不支持的状态均 fail closed。Gateway vault ID 是服务端租户/对象空间标识，不等于 bootstrap 内随机 E2EE vault ID；本机 device ID 由 Rust journal 持久身份提供，WebView 不能提交。

Gateway 登录密码使用独立 `sync-gateway-<UUID>` 系统凭据引用，TOTP 不持久化；AppState 只保存 endpoint、Gateway vault ID、用户名、TOTP 是否需要、凭据引用和可选 CA 引用。Linux Actions 的自签 HTTPS fixture 独立验证登录字段、协议 header、bearer session、list/get、条件创建、幂等回读和同名冲突；它不等于真实服务的限流、恢复码、审计、撤销或多设备验证。

SFTP 写入先在专用私有暂存目录以 `EXCLUSIVE` 创建，完成 `fsync`、close 和属性检查后使用不含 overwrite 的 rename 发布，再由公共 adapter 回读比较。中断不会发布半文件；崩溃遗留的严格随机暂存项不参与对象列举，但仍需外部维护清理。Linux Actions 的单一临时 OpenSSH fixture 覆盖正确/错误 pin、真实认证、创建、回读、列举和同名冲突；多版本服务器、权限、symlink 竞态、断网和真实多设备仍属于外部矩阵。

Provider 账户密码、access key 和 SFTP 私钥属于“接入远端的凭据”，不能依赖该远端自举同步。新设备必须先单独配置 endpoint 和 provider 凭据，才有能力下载加密 vault。

## 7. 远端对象布局

建议的 v1 布局如下，具体扩展名不表示明文格式：

```text
vpshell/v1/<vault_id>/
  keyslots/<slot_id>.json
  devices/<device_id>/<registration_hash>.odev
  segments/<device_id>/<start_seq>-<end_seq>-<object_hash>.oseg
  blobs/<blob_id>/<chunk_index:06>.oblob
  blobs/<blob_id>/manifest.oblob
  checkpoints/<device_id>/<seq>-<object_hash>.ocp
```

- `vault_id` 是随机标识，不来自用户名或 endpoint；
- keyslot 只包含 KDF 参数、随机 salt、被包裹密钥和版本，不包含密码；
- segment 是一批 operation 的压缩加密载荷；
- blob 用于背景图片、脚本附件和较大模板，可分块；
- checkpoint 是可选加速对象，删除它不会丢失 operation 真相；
- segment/checkpoint 对象名中的 hash 是密文对象哈希，用于幂等和传输校验；blob 因每次加密使用随机 nonce，不把密文 hash 放入稳定对象名，完整性由认证信封以及 manifest 内逐块/整图明文 hash 共同约束。

远端列表可能重复、乱序或暂时漏项。同步器按 `(device_id, seq)` 校验连续性，不以 provider 返回顺序作为真相。

## 8. 密钥层级

### 8.1 业务 vault

首次创建 vault 时，客户端生成随机 256-bit Vault Master Key（VMK）。二级同步密码不直接加密业务数据：

```text
secondary password
  -> Argon2id(password, random salt, calibrated parameters)
  -> Key Encryption Key (KEK)
  -> XChaCha20-Poly1305 wrap(random VMK)
```

Argon2id 参数随 keyslot 保存，并在设备性能允许的内存范围内校准，目标是让解锁明显有成本但不影响正常使用。不能为了低配置设备硬编码过弱参数。

VMK 再通过 HKDF 的不同 domain label 派生用途密钥，例如：

```text
K_event / K_blob / K_index / K_checkpoint / K_device_registry
```

每个加密对象使用随机 24-byte nonce；对象头作为 XChaCha20-Poly1305 的 Additional Authenticated Data（AAD），防止密文被移到另一个 vault、设备或序列位置。nonce 不得复用。

### 8.2 恢复密钥

创建 vault 时生成高熵恢复密钥，并增加独立 recovery keyslot。当前内部实现从 OS CSPRNG 生成 256-bit 密钥，输出 `VPS1-<base64url>-<8 hex checksum>`；解析从末尾分隔校验码，避免把 base64url 合法的 `-` 当作字段边界。恢复 KEK 使用 vault/slot 绑定的 HKDF-SHA256 独立域，再以 XChaCha20-Poly1305 包裹业务 VMK；恢复密钥类型不可序列化/调试并在释放时清零。

恢复密钥必须由用户离线保存，不能写入导出包或只保存在同一个同步 endpoint。TOTP、邮箱或 provider 密码都不能替代恢复密钥。校验码只发现录入错误，不提供认证；真正的密钥正确性和 keyslot 完整性由 AEAD 验证。

修改二级密码通常只新增一个包裹同一 VMK 的 keyslot，无需重加密全部数据。需要使旧密码真正失效时，必须创建新 vault/新 VMK 并重加密迁移；在不可变 blob 存储中，旧 keyslot 可能仍被攻击者取回，单纯标记“停用”不构成密码撤销。

### 8.3 凭据 vault

密码、私钥口令和私钥正文默认不同步。当前内部 `sync_credential_vault` 落实以下边界：

- schema-v1 策略默认 `enabled=false`，使用 expected revision；只有业务 device registry 中的活动设备可显式启用，最多 32 个活动/撤销授权身份，撤销不可重新授权且不能撤销最后授权设备；
- 从 OS CSPRNG 生成独立 256-bit CVK，类型不可 Serialize/Debug 且释放清零；CVK 以独立密码和 `credentials` keyslot/AAD 域包裹，不复用业务 VMK 或 recovery keyslot；
- SSH 密码/私钥口令各限 1024 bytes，access token 限 4 KiB，OpenSSH 私钥限 1 MiB；每类再使用独立 HKDF label 和随机 24-byte nonce，vault/item/type/算法/长度进入 AAD；
- secret 类型不可 Debug/Serialize，临时明文缓冲清零；认证信封只含随机 item UUID、类型、nonce 和密文。本机 `credentialRef` 只作为 Rust 内存中的一次性系统钥匙串查找参数，不写入信封、provider object key、错误、日志或事件；
- 当前模块不暴露 Tauri command/event，尚未接入设置 UI、系统钥匙串写回、provider/outbox、CVK 恢复或轮换，因此应用仍不会同步凭据。

设备撤销无法抹除已经复制到该设备的 VMK/CVK。若被撤销设备可能泄露密钥，必须执行密钥轮换和全量重加密。

## 9. Segment 格式与哈希链

同一设备的 pending operation 按条数和压缩前大小切段。建议明文载荷使用 canonical CBOR，流程为：

```text
operations
  -> canonical CBOR
  -> zstd
  -> XChaCha20-Poly1305(K_event, nonce, AAD=header)
  -> hash ciphertext object
  -> upload immutable segment
```

segment header 至少包含：

```text
format_version
vault_id
device_id
start_seq / end_seq
previous_segment_hash
created_hlc
nonce
ciphertext_length
```

header 参与 AEAD 认证；整个对象再由设备密钥签名。`previous_segment_hash` 形成每设备独立哈希链。

验证顺序：

1. 对象名 hash 与下载内容一致；
2. 设备签名属于已登记设备；
3. `previous_segment_hash` 与本地已信任 head 一致；
4. seq 连续且范围不重叠；
5. AEAD 验证通过后才解压和解析；
6. operation schema、大小和字段限制全部通过后才合并。

现有设备保存已见最高 head，并通过同步 operation 互相见证其他设备的 head。远端返回更旧 head、分叉链或缺失已见 segment 时进入“可能回滚/删除”状态，停止自动应用并展示诊断。

需要明确限制：纯 Local/WebDAV/SFTP/S3 blob 存储无法阻止服务端对一台丢失全部本地状态的新设备展示一套从头截短但内部一致的历史。哈希链能发现断链和相对本地/见证 head 的回滚，Gateway 还可提供单调 head 约束；高价值场景仍需离线备份最新恢复清单。

## 10. Operation 模型

```text
Operation
  op_id          UUIDv7
  device_id      来源设备
  seq            设备内单调序号
  hlc            Hybrid Logical Clock
  entity_kind    host | snippet | script | theme | settings | history |
                 blob_ref | device | tombstone | ...
  entity_id      稳定 ID
  action         patch | append | delete
  payload        版本化结构
  schema_version 载荷版本
```

所有解析都有最大对象、最大字段、最大嵌套深度和最大解压比例限制，避免压缩炸弹或恶意 payload 消耗资源。未知的较新 schema 不直接丢弃；保存原始已验证 operation，并提示需要升级客户端。

## 11. 合并规则

### 11.1 历史事件与可删除命令/路径/参数历史

协议保留不可变 history event，按 `event_id` 取并集，供后续脚本运行记录使用。当前产品命令、远端路径、参数与连接历史不走该 append-only 路径，而是使用稳定 UUID 的 `history` 实体；命令完整 patch 必须恰好包含 `kind=command`、公开命令、同步 host UUID、远端路径和严格 UTC 时间，路径完整 patch 必须恰好包含 `kind=path`、公开绝对路径或 `~`、同步 host UUID 和严格 UTC 时间，参数完整 patch 必须恰好包含 `kind=argument`、公开值、`commandId`、`parameterName` 和严格 UTC 时间，连接完整 patch 必须恰好包含 `kind=connection`、同步 host UUID、远端路径和 Rust 签发时间，且不含自由文本 value。参数必须由当前命令模板声明；连接必须逐字段匹配 schema v10 认证事实。显式 `sensitive`、敏感名称、未知模板、明显秘密值或无认证事实的连接保持本机。清空、去重替换或主机删除生成因果 tombstone，这样离线设备不能在缺少删除语义时重新带回已清空历史。旧裸字符串路径没有可信发生时间，只迁移为本机条目，直到用户再次访问形成真实新记录才参与同步。

本机文件路径带 `scope=local` 和 `device_id/platform`，只在原设备提供快捷切换；远端工作目录带 `scope=remote`，可按 `host_id` 在设备间同步。secret 参数值从不生成 history event。

### 11.2 可编辑实体

主机配置、快捷命令、脚本和设置使用字段级 Last Writer Wins register：

```text
field value + field_hlc + writer_device_id
```

优先比较 HLC，相同 HLC 时以 `writer_device_id` 确定性打破平局。字段级合并允许一台设备修改主机标签、另一台修改端口时保留两者，而不是整条记录覆盖。

LWW 只保证收敛，不保证业务选择正确。以下变化即使能自动排序，也进入冲突中心：

- host、port、username、ProxyJump 同时发生不兼容修改；
- 脚本正文或来源在多设备同时修改；
- 风险等级被降低；
- 同步内容尝试改变主机密钥 pin；
- 已删除实体被较旧设备重新编辑。

主机 trust pin 是本地安全状态。其他设备同步来的指纹只能作为待核对建议，不能静默替换本机已信任指纹。

当前 `sync_merge.rs` 把 host/script/setting/background/history 字段列为协议白名单，operation/state 分别限制为 1 MiB/64 MiB，单 patch 64 字段，最多 10,000 实体、50,000 旧 history event、1,000 conflict 和 50,000 已应用 operation。字段 register 按 `(HLC physical, logical, device_id, operation_id)` 排序；相同 operation ID 不同内容拒绝为 replay。公开命令/路径/参数实体限制 4,096 字节值与严格 UTC 毫秒时间，并分别要求 canonical host UUID 与远端路径、canonical host UUID 与绝对路径、或有界 `commandId` 与非敏感 `parameterName` 的完整字段形状；明显密码/Token/Authorization/私钥和 credential ref 模式拒绝。AppState 另限制每主机最多 100 条路径、最多 10,000 条参数记录，路径界面只展示最近 30 条，参数候选只展示同一命令和字段的最近值。

删除 operation 保存它观察到的每字段 stamp。这样已观察编辑随后删除不会误报，未观察的离线编辑无论先到还是后到都会生成相同 conflict ID；默认 register/tombstone 仍确定性收敛。冲突 ID由实体/字段和排序后的双方内容计算，connection identity、脚本正文/来源、风险降低、并发删除和删除后编辑有独立原因。解决 operation 必须晚于双方；多个设备并发解决时仍按 stamp 选择同一结果，并支持保持删除或显式恢复。`sync_merge_state` 通过 expected revision 在调用者的 journal transaction 内读取、apply、写回，因此可与本地 outbox 或远端 receipt 原子提交。当前没有 Tauri IPC/后台 worker 展示该中心。

### 11.3 删除

删除生成带 HLC 的 tombstone，不立即从远端删除旧对象。所有设备合并时，tombstone 与更新按实体规则比较，避免离线设备把旧记录重新带回。

只有当所有已登记设备都确认超过 tombstone 对应向量水位，且用户保留期已满足，才可生成压缩 checkpoint 并把旧对象列为可回收。对于不支持可靠删除的 provider，旧密文可以保留；敏感数据的真正密码学删除需要轮换密钥。

## 12. Blob、背景和附件

自建脚本附件、本机背景图和其他较大内容不嵌入 operation segment。当前第一批已接通 PNG、JPEG 和 WebP 背景：客户端先由 Rust 安全解析，再按固定大小分块、加密和上传：

- `blob_id` 使用 vault 私有的 keyed hash 或随机 ID，避免公开明文哈希造成跨用户内容关联；
- 每块使用独立 nonce 和包含 blob/chunk 身份的 AAD；
- 加密 manifest 记录 MIME、总大小、块数和完整性值，background operation 只引用随机 blob ID；
- PNG 限制总大小和像素并解码后 canonical 重编码；JPEG 要求完整 SOI/EOI，WebP 要求 RIFF 大小、受支持 VP8/VP8L/VP8X chunk 与有界 chunk 长度；三者均以随机 blob ID 和认证原始/规范化 bytes 纳入同步，未引入本地图像 shell 或不受控转换进程；
- 下载在 8 MiB 硬上限内聚合，完整验证后通过暂存、`fsync` 和原子替换提交；
- 未引用 blob 的回收必须等待保留期和活动设备确认规则。当前协调器发布加密成员/确认索引，live-set 同时包含 background 当前投影和所有开放冲突的 blob 候选，要求每个已登记设备对同一 frontier 和 live-set 达成确认，候选摘要在 journal 中连续保留 30 天；随后 Rust 重新认证 manifest/每个 chunk，并只通过 `delete_exact` 条件删除。无条件删除能力的 provider 返回保守保留，不会伪称对象已回收。

当前 PNG 实现使用 OS CSPRNG 生成随机 256-bit lowercase-hex `blob_id`；输入与 URL 下载缓存先经 PNG 解码，限制 16777216 像素和 64 MiB 解码缓冲，再重新编码为不超过 8 MiB 的 canonical PNG。每个 256 KiB 块和 manifest 都是独立 `blob` 域对象，使用随机 nonce，AAD 绑定 vault、blob/chunk identity；manifest 严格记录 MIME、总大小、块大小/数量、整图和逐块 SHA-256。worker 在背景 operation 前把全部块加入有界 journal；同一 vault 只要存在未发布 blob，持久领取查询就不会放行任何 event，即使某块进入退避也不会产生悬空引用。下载时逐块认证、核对精确长度和哈希，完整聚合后再次 canonical PNG 解码/编码校验，并通过暂存文件 `fsync`/原子替换安装；任何缺块、身份错配、额外字段、超限或不可解码内容都会停止投影。随机 nonce 导致同一明文密文不同，因此同名不可变对象冲突只有在两份信封身份一致且认证明文逐字节相等时才作为幂等成功。

JPEG/WebP 作为受管本机资产保存并获得 `managedBlobId`；当前不同步原始 URL，避免把来源和查询上下文带到其他设备；URL 下载后的 PNG/JPEG/WebP bytes 由 Rust 按相同边界处理。活动设备确认式 GC 只在 frontier 不落后、确认摘要稳定 30 天、对象完整认证且 provider 支持条件删除时执行；Local Folder/WebDAV 已提供比较后删除，SFTP/S3/Gateway 等未接通删除能力时远端旧 blob 保守保留。本机每次启动会清理名称严格匹配随机暂存 ID 的未提交普通文件，journal 已发布对象继续遵循 30 天本地保留。

URL 背景只同步安全缓存后的 PNG 位图，不让每台设备启动时直接请求图床，从而减少 Referer、Cookie、IP 和使用时间泄露；原始 URL 元数据当前不上传。

## 13. 自动同步流程

### 13.1 已配置设备

```text
local transaction
  -> outbox pending
  -> build/upload referenced blobs
  -> build encrypted segment
  -> upload immutable object
  -> mark outbox published

periodic/startup/manual trigger
  -> list remote objects
  -> download unknown segments
  -> verify hash/signature/chain/AEAD/schema
  -> merge in one local transaction
  -> update trusted heads and UI status
```

同步 worker 支持指数退避和抖动；离线不阻塞本地业务。启动、网络恢复、业务变更防抖、定时器和“立即同步”都可触发。单个 provider 同一 vault 只运行一个逻辑 worker，避免本机重复竞争。

当前桌面 `AutomaticSyncScheduler` 在 Local Folder 解锁成功后启动，2 秒后做首次检查；changefeed/pending 计数变化稳定 2 秒后触发，空闲时每 5 分钟检查远端，仍有 pending 或可重试错误时 30 秒复查。永久错误、显式取消和恢复阻止暂停自动周期，锁定先使 scheduler generation 失效再销毁 provider/VMK。手动周期与自动周期共用协调器单飞门。周期事件只包含 value-free 状态和 Rust AppStore snapshot；前端在本地脏代际或 revision 回退时拒绝应用，不能覆盖尚未提交的 WebView 编辑。它不是应用退出后的操作系统后台任务，也尚未接入平台网络变化事件。

状态必须可解释：`未配置`、`已锁定`、`等待网络`、`正在上传`、`正在合并`、`存在冲突`、`疑似回滚`、`认证失败`。不能只显示一个永远绿色的云图标。

### 13.2 新设备恢复

1. 安装 VPShell；
2. 手动配置 provider 类型、endpoint 和 provider 凭据；
3. 列出并选择 `vault_id`；
4. 输入二级同步密码或恢复密钥；
5. 下载 keyslot，解包 VMK；
6. 验证设备登记、segment 签名和哈希链；
7. 下载、解密并合并业务数据；
8. 创建新 `device_id` 和签名密钥，经已解锁 VMK 授权登记；
9. 若用户需要，再单独启用凭据 vault。

Provider 凭据不会从同一个尚未访问的 vault 自动恢复。若用户希望在设备间传 provider 凭据，需要使用系统密码管理器、独立导入包或人工配置。

## 14. TOTP 的正确边界

Google Authenticator/TOTP 只适用于自建 VPShell Gateway 的账户登录和设备注册：

```text
Gateway account password / token + TOTP
  -> permission to list/get/put encrypted objects

secondary sync password or recovery key
  -> decrypt VMK locally
```

两条链互不替代。Gateway 通过 TOTP 后仍看不到明文；忘记二级密码时，TOTP 不能解密 vault。Local Folder、WebDAV、SFTP 和 S3 provider 没有 VPShell 控制的登录层，因此不虚构一个本地 TOTP 开关来增加“加密强度”。

Gateway 应提供限流、重放保护、恢复码、设备列表和登录审计，但审计日志不得包含对象明文、密码或 TOTP seed。

当前 Gateway 的 `GatewayLoginSecrets` 只在 Rust 内存保存用户名、清零密码和可选六位数字 TOTP；认证 trait 返回的对象 session 不含这些字段，HTTP session 只持有清零短期 token，底层认证错误也被替换为稳定无秘密诊断。SFTP/S3 adapter 同样只接受无秘密结构化配置，连接/签名凭据由具体 transport 在 Rust trust boundary 持有，不能序列化进 provider 配置。

## 15. 冲突中心与用户操作

自动合并后仍需用户处理的项目进入冲突中心，至少展示：

- 实体名称与字段；
- 两个值各自的设备、时间、来源和风险；
- “保留本机”“采用远端”“合并为新值”；
- 主机地址/跳板/脚本风险变化的额外警告；
- 处理结果生成的新 operation，确保所有设备收敛。

同步来的脚本不得自动执行，主机配置变更不得影响已经建立的会话。新配置只在下一次连接时生效。

## 16. 备份、导出与灾难恢复

- 当前内部 schema v1 加密导出包包含 vault/export 身份、recovery/password keyslot、不可变加密对象和 SHA-256 manifest；不包含恢复密钥、密码、私钥、provider 凭据、Token、解密业务内容或 SQLite 整库；
- 包限制为最多 8 个密码 keyslot、10,000 个对象、单对象 24 MiB、密文总量 256 MiB、文件 384 MiB，并且必须且只能有一个 device registry；key、密文哈希、base64url 和所有 envelope 身份重新验证；
- Rust 以同目录私有暂存文件、`fsync`、hard-link 无覆盖提交并拒绝符号链接读取；Linux 暂存与结果权限为 `0600`。离线恢复演练使用 recovery keyslot 解包 VMK，认证并解密每个对象，严格解析全部 event 与 device registry，而不是只验证文件存在；
- 支持只导出非凭据业务 vault，凭据 vault 需要独立确认；
- 当前演练只证明包可解密和核心对象可解析；写入新的 journal/provider、VMK 轮换与用户确认 UI 尚未接线，不能宣称已完成一键灾难恢复；
- 发现分叉或回滚时先冻结自动上传，保留两侧对象和诊断报告，避免覆盖取证；
- 数据格式升级采用 append-only migration operation，旧客户端遇到未知必要版本时只读并提示升级。

## 17. 实施顺序

1. **本地数据层**：SQLite schema、operation log、transactional outbox、设备 seq/HLC、localStorage 迁移。
2. **密码学层**：VMK/keyslot、Argon2id、XChaCha20-Poly1305、恢复密钥、测试向量和密钥清零。
3. **MVP provider**：桌面 Local Folder 和 HTTPS WebDAV 已接通初始化/解锁、主机公开字段、安全自建脚本、五个固定设置实体、规范化 PNG/结构校验 JPEG-WebP 背景、公开命令/路径/非敏感参数/已认证连接历史的双向事务交接、活动设备确认式 blob 回收、持久冲突解决，以及手动与解锁期自动单周期；WebDAV 密码通过随机引用存入系统凭据管理器，显式 PEM CA 通过独立本机引用交给 Rust TLS 客户端。仍需其他尚未建模设置业务域、真实外部服务器兼容矩阵及断网退避测试。
4. **合并层**：内部历史并集、字段级 LWW、因果 tombstone、持久冲突中心、分页详情和 Rust-owned 候选解决 operation 已接入协调器事务；仍需多进程/真实设备演练。
5. **恢复与设备层**：内部可打印恢复密钥、独立 recovery keyslot、单调设备撤销、加密导出和离线恢复演练已实现；仍需设备签名、轮换、协调器/UI 与真实多设备演练。
6. **大对象**：PNG 背景的规范化分块、JPEG/WebP 的结构校验分块、限额和安全图片处理已接线；活动设备确认式垃圾回收已接线，仍需自建脚本附件和真实多设备/外部 provider 删除验收。
7. **Provider 扩展**：SFTP 已接通桌面产品入口、真实 `ssh2` transport、协调器与 Linux OpenSSH fixture；S3-compatible 已接入 SigV4 transport、系统凭据、协调器和独立验签的 HTTPS Actions fixture；Gateway 已接入版本化 HTTPS login/session transport、系统凭据、协调器和独立 HTTPS Actions fixture。真实 AWS/MinIO/其他 S3 实现、真实 Gateway 及故障矩阵仍需外部验收，再评估 rclone 适配。
8. **凭据 vault**：默认关闭、独立 CVK/keyslot/对象域和逐设备授权原语已完成；仍需系统钥匙串接线、轮换、恢复演练、协调器/UI 与真实设备验证。
9. **Gateway TOTP**：已作为可选当次登录字段接线，不持久化、不与 E2EE 解锁混在一起；真实服务的 seed 注册、恢复码、限流和审计仍需外部实现与验收。

当前源码回归夹具已覆盖未知格式/AEAD 篡改/对象身份搬移、journal replay/发布终态、merge 到达顺序/截断、Local Folder 取消与截断字节、三个扩展 adapter 的条件创建/回读/边界、单一 Linux OpenSSH SFTP fixture、独立验签的 HTTPS S3 fixture，以及版本化登录/session/对象路径的 HTTPS Gateway fixture。上线前仍必须覆盖：两设备同时离线编辑、三设备删除复活、HLC 时钟倒退、上传中断、重复 list、S3 延迟可见、WebDAV 非原子行为、错误密码、旧 keyslot、恶意压缩载荷、对象篡改、segment 缺失、链分叉、远端整体回滚、恢复密钥导入、多版本真实 SFTP 服务器、真实 AWS/MinIO/其他 S3-compatible 与 Gateway 服务和多设备 CVK 轮换。

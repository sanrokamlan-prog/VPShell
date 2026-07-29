# VPShell 加密同步设计

> 文档状态：目标协议设计。v0.1.0 只有同步设置界面，尚未实现 provider、SQLite outbox、端到端加密、自动同步、冲突合并、TOTP 或恢复流程。

## 1. 目标

同步系统需要覆盖用户在多设备间真正会复用的数据，同时允许用户选择自己的存储位置：

- 主机连接配置、分组、标签、跳板路线和偏好；
- 命令历史、远端路径历史、快捷命令和非敏感参数历史；
- 所有自建脚本、参数模板、图标和附件；
- 终端主题、背景配置及需要同步的本机背景图片；
- 可选的主机凭据和私钥 vault，默认关闭；
- Local Folder、WebDAV，以及后续 SFTP、S3 兼容存储和自建 Gateway；
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
| 本地业务存储 | WebView `localStorage` 明文 JSON | Rust 管理的 SQLite + 加密敏感字段 |
| Provider | 只有 Local/WebDAV/SFTP/S3/Gateway 选择界面 | 可插拔不可变对象存储接口 |
| 二级密码 | 只检查输入非空，不保存也不派生密钥 | Argon2id 派生 KEK，包裹随机 Vault Master Key |
| 同步动作 | 只写本地设置和“最后同步”时间 | 事务 outbox、自动 push/pull、重试和状态机 |
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

每次业务修改必须在同一个 SQLite 事务中完成三件事：

```sql
BEGIN;
  UPDATE business_view ...;
  INSERT INTO operation_log (...);
  INSERT INTO sync_outbox (op_id, state) VALUES (..., 'pending');
COMMIT;
```

如果事务失败，三者全部失败；如果应用在提交后崩溃，outbox 仍会在下次启动继续上传。远端拉回的 operation 以 origin 标记，写入本地 operation log 和业务视图，但不会再次作为本机 operation 重复发布。

每台设备维护：

- 随机 `device_id`；
- 设备内严格递增的 `seq`；
- Hybrid Logical Clock（HLC），用于离线设备间的确定性排序；
- 本地已验证的每设备 head、高水位和最近同步游标；
- 设备签名密钥，私钥保存在系统凭据库或本机加密 vault。

HLC 不是权限或真实性来源，只解决时间漂移下的合并排序。签名、AEAD 和已信任设备记录负责完整性验证。

## 6. Provider 抽象

所有 provider 都实现最小接口：

```text
list(prefix, cursor) -> object metadata page
get(key)              -> byte stream
put(key, byte stream) -> idempotent result
```

业务层只创建内容寻址或带唯一序列的不可变 key，不依赖远端 rename、事务、锁或就地更新。`put` 同名对象时只能接受完全相同的内容；内容不同时视为远端冲突/篡改。删除和条件写可作为 provider 优化能力，但不能成为基础协议正确性的前提。

| Provider | 首次范围 | 说明 |
| --- | --- | --- |
| Local Folder | MVP | 写入用户选择的目录，可由 OneDrive、Dropbox、坚果云等桌面客户端继续同步 |
| WebDAV | MVP | 使用 PROPFIND/GET/PUT；要求 HTTPS，允许用户显式信任自签 CA |
| SFTP | Roadmap | 独立于业务 SSH 会话配置；严格验证同步服务器 host key |
| S3 compatible | Roadmap | ListObjectsV2/GetObject/PutObject；不能假设强一致列举 |
| VPShell Gateway | Roadmap | 提供账户、设备管理、限流、可选 TOTP 和单调 head 辅助，但仍只保存密文 |
| rclone | Roadmap | 优先通过 Local Folder/mount 兼容；若增加命令适配器，必须显式配置可执行文件和参数，不能接受任意远端下发命令 |

Provider 账户密码、access key 和 SFTP 私钥属于“接入远端的凭据”，不能依赖该远端自举同步。新设备必须先单独配置 endpoint 和 provider 凭据，才有能力下载加密 vault。

## 7. 远端对象布局

建议的 v1 布局如下，具体扩展名不表示明文格式：

```text
vpshell/v1/<vault_id>/
  keyslots/<slot_id>.json
  devices/<device_id>/<registration_hash>.odev
  segments/<device_id>/<start_seq>-<end_seq>-<object_hash>.oseg
  blobs/<blob_id>/<chunk_index>-<object_hash>.oblob
  checkpoints/<device_id>/<seq>-<object_hash>.ocp
```

- `vault_id` 是随机标识，不来自用户名或 endpoint；
- keyslot 只包含 KDF 参数、随机 salt、被包裹密钥和版本，不包含密码；
- segment 是一批 operation 的压缩加密载荷；
- blob 用于背景图片、脚本附件和较大模板，可分块；
- checkpoint 是可选加速对象，删除它不会丢失 operation 真相；
- 对象名中的 hash 是密文对象哈希，用于幂等和传输校验。

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

创建 vault 时生成高熵恢复密钥，并增加独立 recovery keyslot。恢复密钥必须以可打印/可导出的离线材料交给用户，不能只保存在同一个同步 endpoint。TOTP、邮箱或 provider 密码都不能替代恢复密钥。

修改二级密码通常只新增一个包裹同一 VMK 的 keyslot，无需重加密全部数据。需要使旧密码真正失效时，必须创建新 vault/新 VMK 并重加密迁移；在不可变 blob 存储中，旧 keyslot 可能仍被攻击者取回，单纯标记“停用”不构成密码撤销。

### 8.3 凭据 vault

密码、私钥口令和私钥正文默认不同步。用户明确开启后：

- 生成独立随机 Credential Vault Key（CVK）；
- CVK 使用独立 domain 和 keyslot 包裹；
- UI 再次要求二级密码并展示同步范围；
- 普通业务 vault 解锁不自动向 WebView 暴露 CVK；
- 可进一步允许为凭据 vault 设置独立密码；
- 主机配置只同步 `credential_ref`，解密后由 Rust CredentialProvider 按需取值。

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

### 11.1 追加历史

命令、远端路径、参数使用和脚本运行记录是不可变事件，按 `event_id` 取并集。重复下载相同 event 幂等忽略。界面按 HLC 和设备 ID 稳定排序，但排序变化不能修改事件身份。

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

### 11.3 删除

删除生成带 HLC 的 tombstone，不立即从远端删除旧对象。所有设备合并时，tombstone 与更新按实体规则比较，避免离线设备把旧记录重新带回。

只有当所有已登记设备都确认超过 tombstone 对应向量水位，且用户保留期已满足，才可生成压缩 checkpoint 并把旧对象列为可回收。对于不支持可靠删除的 provider，旧密文可以保留；敏感数据的真正密码学删除需要轮换密钥。

## 12. Blob、背景和附件

自建脚本附件、本机背景图和其他较大内容不嵌入 operation segment。客户端先安全解析，再按固定大小分块、加密和上传：

- `blob_id` 使用 vault 私有的 keyed hash 或随机 ID，避免公开明文哈希造成跨用户内容关联；
- 每块使用独立 nonce 和包含 blob/chunk 身份的 AAD；
- manifest 记录 MIME、总大小、块数和完整性值，并作为加密 operation 引用；
- 图片限制总大小和像素，拒绝 SVG，解码后重编码为 PNG/JPEG/WebP；
- 下载到临时文件，完整验证后原子提交；
- 未引用 blob 的回收遵循保留期和设备确认规则。

URL 背景只同步安全缓存后的位图和原始 URL 元数据，不让每台设备启动时直接请求图床，从而减少 Referer、Cookie、IP 和使用时间泄露。

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

## 15. 冲突中心与用户操作

自动合并后仍需用户处理的项目进入冲突中心，至少展示：

- 实体名称与字段；
- 两个值各自的设备、时间、来源和风险；
- “保留本机”“采用远端”“合并为新值”；
- 主机地址/跳板/脚本风险变化的额外警告；
- 处理结果生成的新 operation，确保所有设备收敛。

同步来的脚本不得自动执行，主机配置变更不得影响已经建立的会话。新配置只在下一次连接时生效。

## 16. 备份、导出与灾难恢复

- 提供加密的完整导出包，包含协议版本、keyslot、segments、blobs、已信任 heads 和校验清单；
- 导出后执行离线恢复演练，而不是只验证文件存在；
- 支持只导出非凭据业务 vault，凭据 vault 需要独立确认；
- 远端全部丢失时，可从最近导出重建新 vault；
- 发现分叉或回滚时先冻结自动上传，保留两侧对象和诊断报告，避免覆盖取证；
- 数据格式升级采用 append-only migration operation，旧客户端遇到未知必要版本时只读并提示升级。

## 17. 实施顺序

1. **本地数据层**：SQLite schema、operation log、transactional outbox、设备 seq/HLC、localStorage 迁移。
2. **密码学层**：VMK/keyslot、Argon2id、XChaCha20-Poly1305、恢复密钥、测试向量和密钥清零。
3. **MVP provider**：Local Folder 和 WebDAV，完整断网/重试/重复对象测试。
4. **合并层**：历史并集、字段级 LWW、tombstone、冲突中心、路径作用域。
5. **大对象**：背景和自建脚本附件分块、限额、安全图片处理和垃圾回收。
6. **Provider 扩展**：SFTP、S3、Gateway，再评估 rclone 适配。
7. **凭据 vault**：默认关闭、独立 CVK、逐设备授权、轮换和恢复演练。
8. **Gateway TOTP**：只在 Gateway 的账户/设备认证完成后增加，不与 E2EE 解锁混在一起。

上线前必须覆盖：两设备同时离线编辑、三设备删除复活、HLC 时钟倒退、上传中断、重复 list、S3 延迟可见、WebDAV 非原子行为、错误密码、旧 keyslot、恶意压缩载荷、对象篡改、segment 缺失、链分叉、远端整体回滚和恢复密钥导入。

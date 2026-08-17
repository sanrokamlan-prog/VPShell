use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    sync_crypto::{EncryptedSyncObject, SyncObjectKind, VaultKey, decrypt_sync_object},
    sync_merge::{MergeError, MergeErrorCode, apply_persisted_operation, load_persisted_state},
    sync_provider::validate_key,
};

const JOURNAL_SCHEMA_VERSION: i64 = 1;
const MAX_DATABASE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PENDING_OBJECTS: i64 = 10_000;
const MAX_STORED_OBJECTS: i64 = 50_000;
const MAX_PENDING_BYTES: i64 = 256 * 1024 * 1024;
const MAX_STORED_BYTES: i64 = 384 * 1024 * 1024;
const MAX_ENVELOPE_BYTES: usize = 24 * 1024 * 1024;
const MAX_ATTEMPTS: u32 = 6;
const LEASE_DURATION_MS: i64 = 2 * 60 * 1000;
const BASE_RETRY_MS: i64 = 2_000;
const MAX_RETRY_MS: i64 = 5 * 60 * 1000;
const PUBLISHED_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
const RECEIPT_RETENTION_MS: i64 = 90 * 24 * 60 * 60 * 1000;
const MAX_CORRUPT_BACKUPS: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JournalErrorCode {
    InvalidInput,
    Conflict,
    Replay,
    SequenceGap,
    LimitExceeded,
    SafetyBlocked,
    NotFound,
    StaleLease,
    Finalized,
    Storage,
    Authentication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalError {
    pub(crate) code: JournalErrorCode,
    pub(crate) message: String,
}

impl JournalError {
    fn new(code: JournalErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

type JournalResult<T> = Result<T, JournalError>;

#[derive(Clone, Debug)]
pub(crate) struct SyncJournal {
    inner: Arc<SyncJournalInner>,
}

#[derive(Debug)]
struct SyncJournalInner {
    path: PathBuf,
    lock: Mutex<()>,
    recovery_note: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnqueueOutcome {
    Queued,
    AlreadyQueued,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteApplyOutcome {
    Applied,
    AlreadyApplied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutboxState {
    Pending,
    InFlight,
    RetryWait,
    Paused,
    Published,
    PermanentFailure,
}

impl OutboxState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InFlight => "in_flight",
            Self::RetryWait => "retry_wait",
            Self::Paused => "paused",
            Self::Published => "published",
            Self::PermanentFailure => "permanent_failure",
        }
    }

    fn parse(value: &str) -> JournalResult<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "in_flight" => Ok(Self::InFlight),
            "retry_wait" => Ok(Self::RetryWait),
            "paused" => Ok(Self::Paused),
            "published" => Ok(Self::Published),
            "permanent_failure" => Ok(Self::PermanentFailure),
            _ => Err(JournalError::new(
                JournalErrorCode::Storage,
                "同步 outbox 包含未知状态",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AttemptFailure {
    Network,
    Timeout,
    RateLimited,
    RemoteUnavailable,
    Conflict,
    Protocol,
    Authentication,
    Integrity,
}

impl AttemptFailure {
    fn code(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Timeout => "timeout",
            Self::RateLimited => "rate-limited",
            Self::RemoteUnavailable => "remote-unavailable",
            Self::Conflict => "immutable-conflict",
            Self::Protocol => "protocol",
            Self::Authentication => "authentication",
            Self::Integrity => "integrity",
        }
    }

    fn retryable(self) -> bool {
        matches!(
            self,
            Self::Network | Self::Timeout | Self::RateLimited | Self::RemoteUnavailable
        )
    }
}

pub(crate) struct ClaimedObject {
    pub(crate) object_key: String,
    pub(crate) encrypted_object: Vec<u8>,
    pub(crate) lease_id: String,
    pub(crate) attempt: u32,
    pub(crate) lease_expires_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutboxSnapshot {
    pub(crate) object_key: String,
    pub(crate) state: OutboxState,
    pub(crate) attempt_count: u32,
    pub(crate) next_attempt_ms: i64,
    pub(crate) last_error_code: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JournalStatus {
    pub(crate) safety_blocked: bool,
    pub(crate) safety_reason: Option<String>,
    pub(crate) recovery_note: Option<String>,
    pub(crate) pending_objects: u64,
    pub(crate) pending_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MergeJournalStatus {
    pub(crate) revision: u64,
    pub(crate) open_conflicts: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RemoteMergeResult {
    pub(crate) outcome: RemoteApplyOutcome,
    pub(crate) revision: u64,
    pub(crate) open_conflicts: usize,
}

fn map_merge_error(error: MergeError) -> JournalError {
    let code = match error.code {
        MergeErrorCode::Replay => JournalErrorCode::Replay,
        MergeErrorCode::LimitExceeded => JournalErrorCode::LimitExceeded,
        MergeErrorCode::RevisionConflict => JournalErrorCode::Conflict,
        MergeErrorCode::Storage | MergeErrorCode::CorruptState => JournalErrorCode::Storage,
        MergeErrorCode::InvalidInput
        | MergeErrorCode::ConflictMissing
        | MergeErrorCode::StaleResolution => JournalErrorCode::InvalidInput,
    };
    JournalError::new(code, error.message)
}

fn journal_path(app_data_directory: &Path) -> PathBuf {
    app_data_directory.join("vpshell-sync.sqlite3")
}

fn open_connection(path: &Path) -> JournalResult<Connection> {
    let connection = Connection::open(path)
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法打开同步 journal"))?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| {
            JournalError::new(JournalErrorCode::Storage, "无法配置同步 journal 等待时间")
        })?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法启用同步 journal 外键"))?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法启用同步 journal WAL"))?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|_| {
            JournalError::new(JournalErrorCode::Storage, "无法启用同步 journal 完整同步")
        })?;
    Ok(connection)
}

fn quick_check(connection: &Connection) -> JournalResult<()> {
    let value: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "同步 journal 完整性检查失败"))?;
    if value == "ok" {
        Ok(())
    } else {
        Err(JournalError::new(
            JournalErrorCode::Storage,
            "同步 journal 完整性检查失败",
        ))
    }
}

fn current_schema(connection: &Connection) -> JournalResult<i64> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法读取同步 journal schema"))
}

fn migrate_schema(connection: &mut Connection) -> JournalResult<()> {
    let version = current_schema(connection)?;
    if version > JOURNAL_SCHEMA_VERSION {
        return Err(JournalError::new(
            JournalErrorCode::Storage,
            "同步 journal schema 高于当前支持版本，未修改文件",
        ));
    }
    if version == JOURNAL_SCHEMA_VERSION {
        return Ok(());
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法开始同步 journal 迁移"))?;
    transaction.execute_batch(
        "CREATE TABLE sync_safety (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            blocked INTEGER NOT NULL CHECK (blocked IN (0, 1)),
            reason TEXT
        );
        INSERT INTO sync_safety(singleton, blocked, reason) VALUES (1, 0, NULL);
        CREATE TABLE sync_operations (
            object_key TEXT PRIMARY KEY,
            object_hash TEXT NOT NULL,
            vault_id TEXT NOT NULL,
            object_kind TEXT NOT NULL,
            object_id TEXT NOT NULL,
            device_id TEXT,
            sequence INTEGER CHECK (sequence IS NULL OR sequence > 0),
            encrypted_object BLOB NOT NULL,
            origin TEXT NOT NULL CHECK (origin IN ('local', 'remote')),
            created_at_ms INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX idx_sync_operation_sequence
            ON sync_operations(origin, device_id, sequence)
            WHERE device_id IS NOT NULL AND sequence IS NOT NULL;
        CREATE UNIQUE INDEX idx_sync_operation_hash
            ON sync_operations(object_hash);
        CREATE UNIQUE INDEX idx_sync_operation_identity
            ON sync_operations(vault_id, object_kind, object_id);
        CREATE TABLE sync_outbox (
            object_key TEXT PRIMARY KEY REFERENCES sync_operations(object_key) ON DELETE CASCADE,
            state TEXT NOT NULL CHECK (state IN ('pending', 'in_flight', 'retry_wait', 'paused', 'published', 'permanent_failure')),
            attempt_count INTEGER NOT NULL CHECK (attempt_count BETWEEN 0 AND 6),
            next_attempt_ms INTEGER NOT NULL,
            lease_id TEXT,
            lease_expires_ms INTEGER,
            last_error_code TEXT,
            published_at_ms INTEGER,
            updated_at_ms INTEGER NOT NULL,
            CHECK ((state = 'in_flight') = (lease_id IS NOT NULL AND lease_expires_ms IS NOT NULL))
        );
        CREATE INDEX idx_sync_outbox_ready
            ON sync_outbox(state, next_attempt_ms, updated_at_ms);
        CREATE TABLE sync_heads (
            direction TEXT NOT NULL CHECK (direction IN ('local', 'remote')),
            device_id TEXT NOT NULL,
            highest_sequence INTEGER NOT NULL CHECK (highest_sequence > 0),
            object_hash TEXT NOT NULL,
            PRIMARY KEY(direction, device_id)
        );
        CREATE TABLE sync_applied_receipts (
            object_key TEXT PRIMARY KEY,
            object_hash TEXT NOT NULL UNIQUE,
            device_id TEXT,
            sequence INTEGER,
            applied_at_ms INTEGER NOT NULL
        );
        CREATE INDEX idx_sync_receipts_applied
            ON sync_applied_receipts(applied_at_ms);
        CREATE TABLE sync_merge_state (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            schema_version INTEGER NOT NULL,
            revision INTEGER NOT NULL CHECK (revision >= 0),
            state_blob BLOB NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );"
    ).map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法创建同步 journal schema"))?;
    transaction
        .pragma_update(None, "user_version", JOURNAL_SCHEMA_VERSION)
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法写入同步 journal schema"))?;
    transaction
        .commit()
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法提交同步 journal 迁移"))
}

fn backup_prefix(path: &Path) -> String {
    format!(
        "{}.corrupt-",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("vpshell-sync.sqlite3")
    )
}

fn quarantine(path: &Path) -> JournalResult<()> {
    if !path.exists() {
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| JournalError::new(JournalErrorCode::Storage, "同步 journal 路径无父目录"))?;
    let backup = path.with_file_name(format!(
        "{}.corrupt-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("vpshell-sync.sqlite3"),
        Uuid::new_v4().simple()
    ));
    fs::rename(path, &backup)
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法隔离损坏同步 journal"))?;
    for suffix in ["-wal", "-shm"] {
        let source = PathBuf::from(format!("{}{suffix}", path.display()));
        if source.exists() {
            let target = PathBuf::from(format!("{}{suffix}", backup.display()));
            fs::rename(source, target).map_err(|_| {
                JournalError::new(JournalErrorCode::Storage, "无法隔离同步 journal 附属文件")
            })?;
        }
    }
    let prefix = backup_prefix(path);
    let mut backups = fs::read_dir(parent)
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法读取同步 journal 备份"))?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
                name.starts_with(&prefix) && !name.ends_with("-wal") && !name.ends_with("-shm")
            })
        })
        .collect::<Vec<_>>();
    backups.sort_by_key(|entry| entry.file_name());
    let remove_count = backups.len().saturating_sub(MAX_CORRUPT_BACKUPS);
    for entry in backups.into_iter().take(remove_count) {
        let backup = entry.path();
        fs::remove_file(&backup).map_err(|_| {
            JournalError::new(JournalErrorCode::Storage, "无法清理同步 journal 备份")
        })?;
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", backup.display()));
            if sidecar.exists() {
                let _ = fs::remove_file(sidecar);
            }
        }
    }
    Ok(())
}

fn prepare(path: &Path) -> JournalResult<Option<String>> {
    if path
        .metadata()
        .is_ok_and(|metadata| metadata.len() > MAX_DATABASE_BYTES)
    {
        quarantine(path)?;
        create_recovery_database(path)?;
        return Ok(Some(
            "同步 journal 超过 512 MiB，已隔离并阻止自动同步，必须重新核对远端".to_string(),
        ));
    }
    match open_connection(path).and_then(|mut connection| {
        quick_check(&connection)?;
        migrate_schema(&mut connection)
    }) {
        Ok(()) => Ok(None),
        Err(error) if error.message.contains("高于当前支持版本") => Err(error),
        Err(_) => {
            quarantine(path)?;
            create_recovery_database(path)?;
            Ok(Some(
                "同步 journal 损坏或截断，已隔离并阻止自动同步，必须重新核对远端".to_string(),
            ))
        }
    }
}

fn create_recovery_database(path: &Path) -> JournalResult<()> {
    let mut connection = open_connection(path)?;
    migrate_schema(&mut connection)?;
    connection
        .execute(
            "UPDATE sync_safety SET blocked = 1, reason = 'reconcile-required' WHERE singleton = 1",
            [],
        )
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法阻止恢复后的自动同步"))?;
    Ok(())
}

fn object_hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn validate_now(now_ms: i64) -> JournalResult<()> {
    if now_ms < 0 {
        Err(JournalError::new(
            JournalErrorCode::InvalidInput,
            "同步 journal 时间不能为负数",
        ))
    } else {
        Ok(())
    }
}

fn ensure_unblocked(transaction: &Transaction<'_>) -> JournalResult<()> {
    let (blocked, reason): (i64, Option<String>) = transaction
        .query_row(
            "SELECT blocked, reason FROM sync_safety WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法读取同步安全状态"))?;
    if blocked != 0 {
        return Err(JournalError::new(
            JournalErrorCode::SafetyBlocked,
            format!(
                "自动同步已安全阻止：{}",
                reason.unwrap_or_else(|| "unknown".to_string())
            ),
        ));
    }
    Ok(())
}

fn validate_envelope(encoded: &[u8]) -> JournalResult<EncryptedSyncObject> {
    if encoded.is_empty() || encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(JournalError::new(
            JournalErrorCode::LimitExceeded,
            "同步 outbox 对象必须为 1 字节至 24 MiB",
        ));
    }
    EncryptedSyncObject::decode(encoded).map_err(|_| {
        JournalError::new(
            JournalErrorCode::InvalidInput,
            "同步 outbox 只接受有效的加密对象信封",
        )
    })
}

fn object_kind_label(kind: &SyncObjectKind) -> &'static str {
    match kind {
        SyncObjectKind::Event => "event",
        SyncObjectKind::Blob => "blob",
        SyncObjectKind::Index => "index",
        SyncObjectKind::Checkpoint => "checkpoint",
        SyncObjectKind::DeviceRegistry => "device-registry",
    }
}

fn sequence_to_i64(sequence: u64) -> JournalResult<i64> {
    i64::try_from(sequence).map_err(|_| {
        JournalError::new(
            JournalErrorCode::InvalidInput,
            "同步对象序号超过 SQLite INTEGER",
        )
    })
}

fn ensure_capacity(transaction: &Transaction<'_>, additional: usize) -> JournalResult<()> {
    let (count, bytes): (i64, i64) = transaction
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(o.encrypted_object)), 0)
             FROM sync_outbox q JOIN sync_operations o USING(object_key)
             WHERE q.state != 'published'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法统计同步 outbox"))?;
    let stored: i64 = transaction
        .query_row("SELECT COUNT(*) FROM sync_operations", [], |row| row.get(0))
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法统计同步 operation"))?;
    let stored_bytes: i64 = transaction
        .query_row(
            "SELECT COALESCE(SUM(LENGTH(encrypted_object)), 0) FROM sync_operations",
            [],
            |row| row.get(0),
        )
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法统计同步 operation 大小"))?;
    if count >= MAX_PENDING_OBJECTS
        || stored >= MAX_STORED_OBJECTS
        || bytes.saturating_add(additional as i64) > MAX_PENDING_BYTES
        || stored_bytes.saturating_add(additional as i64) > MAX_STORED_BYTES
    {
        return Err(JournalError::new(
            JournalErrorCode::LimitExceeded,
            "同步 outbox 达到 10000 项/256 MiB 或 journal 达到 50000 项/384 MiB 上限",
        ));
    }
    Ok(())
}

fn verify_next_sequence(
    transaction: &Transaction<'_>,
    direction: &str,
    device_id: Option<&str>,
    sequence: Option<u64>,
) -> JournalResult<Option<i64>> {
    let (Some(device_id), Some(sequence)) = (device_id, sequence) else {
        return Ok(None);
    };
    let sequence = sequence_to_i64(sequence)?;
    let highest: Option<i64> = transaction
        .query_row(
            "SELECT highest_sequence FROM sync_heads WHERE direction = ?1 AND device_id = ?2",
            params![direction, device_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法读取同步设备水位"))?;
    let expected = highest.unwrap_or(0).saturating_add(1);
    if sequence < expected {
        return Err(JournalError::new(
            JournalErrorCode::Replay,
            "同步对象序号已应用或发生回退",
        ));
    }
    if sequence > expected {
        return Err(JournalError::new(
            JournalErrorCode::SequenceGap,
            "同步对象序号不连续，必须先补齐缺口",
        ));
    }
    Ok(Some(sequence))
}

fn update_head(
    transaction: &Transaction<'_>,
    direction: &str,
    object: &EncryptedSyncObject,
    hash: &str,
    sequence: Option<i64>,
) -> JournalResult<()> {
    let (Some(device_id), Some(sequence)) = (object.device_id(), sequence) else {
        return Ok(());
    };
    transaction
        .execute(
            "INSERT INTO sync_heads(direction, device_id, highest_sequence, object_hash)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(direction, device_id) DO UPDATE SET
           highest_sequence = excluded.highest_sequence,
           object_hash = excluded.object_hash",
            params![direction, device_id, sequence, hash],
        )
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法更新同步设备水位"))?;
    Ok(())
}

fn retry_delay_ms(attempt: u32) -> i64 {
    let exponent = attempt.saturating_sub(1).min(16);
    BASE_RETRY_MS
        .saturating_mul(1_i64 << exponent)
        .min(MAX_RETRY_MS)
}

impl SyncJournal {
    pub(crate) fn open(app_data_directory: PathBuf) -> JournalResult<Self> {
        fs::create_dir_all(&app_data_directory).map_err(|_| {
            JournalError::new(JournalErrorCode::Storage, "无法创建同步 journal 目录")
        })?;
        let path = journal_path(&app_data_directory);
        let recovery_note = prepare(&path)?;
        Ok(Self {
            inner: Arc::new(SyncJournalInner {
                path,
                lock: Mutex::new(()),
                recovery_note,
            }),
        })
    }

    fn transaction<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>) -> JournalResult<T>,
    ) -> JournalResult<T> {
        let _guard =
            self.inner.lock.lock().map_err(|_| {
                JournalError::new(JournalErrorCode::Storage, "同步 journal 锁不可用")
            })?;
        let mut connection = open_connection(&self.inner.path)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| {
                JournalError::new(JournalErrorCode::Storage, "无法开始同步 journal 事务")
            })?;
        let result = operation(&transaction)?;
        transaction.commit().map_err(|_| {
            JournalError::new(JournalErrorCode::Storage, "无法提交同步 journal 事务")
        })?;
        Ok(result)
    }

    pub(crate) fn status(&self) -> JournalResult<JournalStatus> {
        self.transaction(|transaction| {
            let (blocked, reason): (i64, Option<String>) = transaction
                .query_row(
                    "SELECT blocked, reason FROM sync_safety WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法读取同步安全状态")
                })?;
            let (count, bytes): (i64, i64) = transaction
                .query_row(
                    "SELECT COUNT(*), COALESCE(SUM(LENGTH(o.encrypted_object)), 0)
                     FROM sync_outbox q JOIN sync_operations o USING(object_key)
                     WHERE q.state != 'published'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法统计同步 outbox"))?;
            Ok(JournalStatus {
                safety_blocked: blocked != 0,
                safety_reason: reason,
                recovery_note: self.inner.recovery_note.clone(),
                pending_objects: count.max(0) as u64,
                pending_bytes: bytes.max(0) as u64,
            })
        })
    }

    pub(crate) fn merge_status(&self) -> JournalResult<MergeJournalStatus> {
        self.transaction(|transaction| {
            let (revision, state) = load_persisted_state(transaction).map_err(map_merge_error)?;
            Ok(MergeJournalStatus {
                revision,
                open_conflicts: state.open_conflicts().len(),
            })
        })
    }

    pub(crate) fn acknowledge_reconciliation(&self) -> JournalResult<()> {
        self.transaction(|transaction| {
            transaction
                .execute(
                    "UPDATE sync_safety SET blocked = 0, reason = NULL
                 WHERE singleton = 1 AND blocked = 1 AND reason = 'reconcile-required'",
                    [],
                )
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法解除同步安全阻止")
                })?;
            Ok(())
        })
    }

    pub(crate) fn enqueue_local<F>(
        &self,
        object_key: &str,
        encrypted_object: &[u8],
        now_ms: i64,
        apply_business_change: F,
    ) -> JournalResult<EnqueueOutcome>
    where
        F: FnOnce(&Transaction<'_>) -> JournalResult<()>,
    {
        validate_now(now_ms)?;
        validate_key(object_key).map_err(|_| {
            JournalError::new(
                JournalErrorCode::InvalidInput,
                "同步 outbox object key 无效",
            )
        })?;
        let object = validate_envelope(encrypted_object)?;
        let hash = object_hash(encrypted_object);
        self.transaction(|transaction| {
            ensure_unblocked(transaction)?;
            let existing: Option<String> = transaction
                .query_row(
                    "SELECT object_hash FROM sync_operations WHERE object_key = ?1",
                    params![object_key],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法检查同步 operation")
                })?;
            if let Some(existing) = existing {
                if existing == hash {
                    return Ok(EnqueueOutcome::AlreadyQueued);
                }
                return Err(JournalError::new(
                    JournalErrorCode::Conflict,
                    "同名同步 operation 的密文哈希不同",
                ));
            }
            let relocated: Option<(String, String)> = transaction
                .query_row(
                    "SELECT object_key, object_hash FROM sync_operations
                     WHERE object_hash = ?1
                        OR (vault_id = ?2 AND object_kind = ?3 AND object_id = ?4)
                     LIMIT 1",
                    params![
                        hash,
                        object.vault_id(),
                        object_kind_label(object.object_kind()),
                        object.object_id(),
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法核对同步 operation 身份")
                })?;
            if relocated.is_some() {
                return Err(JournalError::new(
                    JournalErrorCode::Conflict,
                    "同步 operation 的密文或对象身份已由其他 key 使用",
                ));
            }
            ensure_capacity(transaction, encrypted_object.len())?;
            let sequence =
                verify_next_sequence(transaction, "local", object.device_id(), object.sequence())?;
            apply_business_change(transaction)?;
            transaction
                .execute(
                    "INSERT INTO sync_operations(
                    object_key, object_hash, vault_id, object_kind, object_id, device_id, sequence,
                    encrypted_object, origin, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'local', ?9)",
                    params![
                        object_key,
                        hash,
                        object.vault_id(),
                        object_kind_label(object.object_kind()),
                        object.object_id(),
                        object.device_id(),
                        sequence,
                        encrypted_object,
                        now_ms,
                    ],
                )
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法写入本地同步 operation")
                })?;
            transaction
                .execute(
                    "INSERT INTO sync_outbox(
                    object_key, state, attempt_count, next_attempt_ms, lease_id,
                    lease_expires_ms, last_error_code, published_at_ms, updated_at_ms
                 ) VALUES (?1, 'pending', 0, ?2, NULL, NULL, NULL, NULL, ?2)",
                    params![object_key, now_ms],
                )
                .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法写入同步 outbox"))?;
            update_head(transaction, "local", &object, &hash, sequence)?;
            Ok(EnqueueOutcome::Queued)
        })
    }

    pub(crate) fn claim_next(&self, now_ms: i64) -> JournalResult<Option<ClaimedObject>> {
        self.claim_next_scoped(None, now_ms)
    }

    pub(crate) fn claim_next_for_vault(
        &self,
        vault_id: &str,
        now_ms: i64,
    ) -> JournalResult<Option<ClaimedObject>> {
        let vault_id = Uuid::parse_str(vault_id)
            .map_err(|_| JournalError::new(JournalErrorCode::InvalidInput, "同步 vault ID 无效"))?
            .to_string();
        self.claim_next_scoped(Some(&vault_id), now_ms)
    }

    fn claim_next_scoped(
        &self,
        vault_id: Option<&str>,
        now_ms: i64,
    ) -> JournalResult<Option<ClaimedObject>> {
        validate_now(now_ms)?;
        self.transaction(|transaction| {
            ensure_unblocked(transaction)?;
            recover_expired_leases(transaction, now_ms)?;
            let row: Option<(String, Vec<u8>, i64)> = transaction
                .query_row(
                    "SELECT q.object_key, o.encrypted_object, q.attempt_count
                     FROM sync_outbox q JOIN sync_operations o USING(object_key)
                     WHERE q.state IN ('pending', 'retry_wait')
                       AND q.next_attempt_ms <= ?1 AND q.attempt_count < ?2
                       AND (?3 IS NULL OR o.vault_id = ?3)
                     ORDER BY q.next_attempt_ms, q.updated_at_ms, q.object_key
                     LIMIT 1",
                    params![now_ms, MAX_ATTEMPTS, vault_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法选择同步 outbox 项")
                })?;
            let Some((object_key, encrypted_object, previous_attempts)) = row else {
                return Ok(None);
            };
            let attempt = previous_attempts.saturating_add(1);
            let lease_id = Uuid::new_v4().to_string();
            let lease_expires_ms = now_ms.saturating_add(LEASE_DURATION_MS);
            transaction
                .execute(
                    "UPDATE sync_outbox SET state = 'in_flight', attempt_count = ?1,
                    lease_id = ?2, lease_expires_ms = ?3, updated_at_ms = ?4
                 WHERE object_key = ?5 AND state IN ('pending', 'retry_wait')",
                    params![attempt, lease_id, lease_expires_ms, now_ms, object_key],
                )
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法租用同步 outbox 项")
                })?;
            Ok(Some(ClaimedObject {
                object_key,
                encrypted_object,
                lease_id,
                attempt: attempt as u32,
                lease_expires_ms,
            }))
        })
    }

    pub(crate) fn mark_published(
        &self,
        object_key: &str,
        lease_id: &str,
        now_ms: i64,
    ) -> JournalResult<OutboxSnapshot> {
        validate_now(now_ms)?;
        self.finish_claim(object_key, lease_id, |transaction, attempt| {
            transaction
                .execute(
                    "UPDATE sync_outbox SET state = 'published', lease_id = NULL,
                    lease_expires_ms = NULL, last_error_code = NULL,
                    published_at_ms = ?1, updated_at_ms = ?1 WHERE object_key = ?2",
                    params![now_ms, object_key],
                )
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法完成同步 outbox 项")
                })?;
            Ok((OutboxState::Published, attempt, 0, None))
        })
    }

    pub(crate) fn mark_failed(
        &self,
        object_key: &str,
        lease_id: &str,
        failure: AttemptFailure,
        now_ms: i64,
    ) -> JournalResult<OutboxSnapshot> {
        validate_now(now_ms)?;
        self.finish_claim(object_key, lease_id, |transaction, attempt| {
            let retry = failure.retryable() && attempt < MAX_ATTEMPTS;
            let state = if retry {
                OutboxState::RetryWait
            } else {
                OutboxState::PermanentFailure
            };
            let next_attempt = if retry {
                now_ms.saturating_add(retry_delay_ms(attempt))
            } else {
                0
            };
            transaction
                .execute(
                    "UPDATE sync_outbox SET state = ?1, next_attempt_ms = ?2,
                    lease_id = NULL, lease_expires_ms = NULL, last_error_code = ?3,
                    updated_at_ms = ?4 WHERE object_key = ?5",
                    params![
                        state.as_str(),
                        next_attempt,
                        failure.code(),
                        now_ms,
                        object_key
                    ],
                )
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法记录同步 outbox 失败")
                })?;
            Ok((
                state,
                attempt,
                next_attempt,
                Some(failure.code().to_string()),
            ))
        })
    }

    pub(crate) fn pause_claim(
        &self,
        object_key: &str,
        lease_id: &str,
        now_ms: i64,
    ) -> JournalResult<OutboxSnapshot> {
        validate_now(now_ms)?;
        self.finish_claim(object_key, lease_id, |transaction, attempt| {
            transaction
                .execute(
                    "UPDATE sync_outbox SET state = 'paused', next_attempt_ms = 0,
                    lease_id = NULL, lease_expires_ms = NULL, last_error_code = 'cancelled',
                    updated_at_ms = ?1 WHERE object_key = ?2",
                    params![now_ms, object_key],
                )
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法暂停同步 outbox 项")
                })?;
            Ok((
                OutboxState::Paused,
                attempt,
                0,
                Some("cancelled".to_string()),
            ))
        })
    }

    pub(crate) fn resume(&self, object_key: &str, now_ms: i64) -> JournalResult<OutboxSnapshot> {
        validate_now(now_ms)?;
        self.transaction(|transaction| {
            ensure_unblocked(transaction)?;
            let snapshot = query_snapshot(transaction, object_key)?;
            if snapshot.state == OutboxState::Published {
                return Err(JournalError::new(
                    JournalErrorCode::Finalized,
                    "已发布同步对象不能重试",
                ));
            }
            if !matches!(
                snapshot.state,
                OutboxState::Paused | OutboxState::PermanentFailure
            ) {
                return Err(JournalError::new(
                    JournalErrorCode::Conflict,
                    "只有暂停或永久失败的同步对象可显式恢复",
                ));
            }
            if snapshot.attempt_count >= MAX_ATTEMPTS {
                return Err(JournalError::new(
                    JournalErrorCode::Finalized,
                    "同步对象已达到 6 次尝试上限",
                ));
            }
            transaction
                .execute(
                    "UPDATE sync_outbox SET state = 'pending', next_attempt_ms = ?1,
                    last_error_code = NULL, updated_at_ms = ?1 WHERE object_key = ?2",
                    params![now_ms, object_key],
                )
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法恢复同步 outbox 项")
                })?;
            Ok(OutboxSnapshot {
                state: OutboxState::Pending,
                next_attempt_ms: now_ms,
                last_error_code: None,
                ..snapshot
            })
        })
    }

    fn finish_claim<T>(
        &self,
        object_key: &str,
        lease_id: &str,
        operation: impl FnOnce(&Transaction<'_>, u32) -> JournalResult<T>,
    ) -> JournalResult<OutboxSnapshot>
    where
        T: Into<(OutboxState, u32, i64, Option<String>)>,
    {
        if lease_id.is_empty() || lease_id.len() > 64 {
            return Err(JournalError::new(
                JournalErrorCode::InvalidInput,
                "同步 outbox lease 无效",
            ));
        }
        self.transaction(|transaction| {
            let snapshot = query_snapshot(transaction, object_key)?;
            if snapshot.state == OutboxState::Published {
                return Err(JournalError::new(
                    JournalErrorCode::Finalized,
                    "同步对象已经发布",
                ));
            }
            let stored_lease: Option<String> = transaction
                .query_row(
                    "SELECT lease_id FROM sync_outbox WHERE object_key = ?1 AND state = 'in_flight'",
                    params![object_key],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法核对同步 lease"))?
                .flatten();
            if stored_lease.as_deref() != Some(lease_id) {
                return Err(JournalError::new(
                    JournalErrorCode::StaleLease,
                    "同步 outbox lease 已过期或不匹配",
                ));
            }
            let (state, attempt_count, next_attempt_ms, last_error_code) =
                operation(transaction, snapshot.attempt_count)?.into();
            Ok(OutboxSnapshot {
                object_key: object_key.to_string(),
                state,
                attempt_count,
                next_attempt_ms,
                last_error_code,
            })
        })
    }

    pub(crate) fn apply_remote<F>(
        &self,
        object_key: &str,
        encoded: &[u8],
        vault_key: &VaultKey,
        now_ms: i64,
        apply_business_change: F,
    ) -> JournalResult<RemoteApplyOutcome>
    where
        F: FnOnce(&Transaction<'_>, &[u8]) -> JournalResult<()>,
    {
        validate_now(now_ms)?;
        validate_key(object_key).map_err(|_| {
            JournalError::new(JournalErrorCode::InvalidInput, "远端同步 object key 无效")
        })?;
        let object = validate_envelope(encoded)?;
        let plaintext = decrypt_sync_object(vault_key, &object).map_err(|_| {
            JournalError::new(JournalErrorCode::Authentication, "远端同步对象认证失败")
        })?;
        let hash = object_hash(encoded);
        self.transaction(|transaction| {
            ensure_unblocked(transaction)?;
            let receipt: Option<String> = transaction
                .query_row(
                    "SELECT object_hash FROM sync_applied_receipts WHERE object_key = ?1",
                    params![object_key],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法读取同步 receipt")
                })?;
            if let Some(receipt) = receipt {
                if receipt == hash {
                    return Ok(RemoteApplyOutcome::AlreadyApplied);
                }
                return Err(JournalError::new(
                    JournalErrorCode::Replay,
                    "同名远端同步对象哈希不同",
                ));
            }
            let existing: Option<(String, String)> = transaction
                .query_row(
                    "SELECT object_key, object_hash FROM sync_operations
                     WHERE object_key = ?1 OR object_hash = ?2
                        OR (vault_id = ?3 AND object_kind = ?4 AND object_id = ?5)
                     LIMIT 1",
                    params![
                        object_key,
                        hash,
                        object.vault_id(),
                        object_kind_label(object.object_kind()),
                        object.object_id(),
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法核对远端同步对象身份")
                })?;
            if let Some((existing_key, existing_hash)) = existing {
                if existing_key == object_key && existing_hash == hash {
                    return Ok(RemoteApplyOutcome::AlreadyApplied);
                }
                return Err(JournalError::new(
                    JournalErrorCode::Replay,
                    "远端同步对象密文或身份已在其他 key 出现",
                ));
            }
            ensure_capacity(transaction, encoded.len())?;
            let sequence =
                verify_next_sequence(transaction, "remote", object.device_id(), object.sequence())?;
            apply_business_change(transaction, &plaintext)?;
            transaction
                .execute(
                    "INSERT INTO sync_operations(
                    object_key, object_hash, vault_id, object_kind, object_id, device_id, sequence,
                    encrypted_object, origin, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'remote', ?9)",
                    params![
                        object_key,
                        hash,
                        object.vault_id(),
                        object_kind_label(object.object_kind()),
                        object.object_id(),
                        object.device_id(),
                        sequence,
                        encoded,
                        now_ms,
                    ],
                )
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Replay, "远端同步 operation 已存在")
                })?;
            transaction
                .execute(
                    "INSERT INTO sync_applied_receipts(
                    object_key, object_hash, device_id, sequence, applied_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![object_key, hash, object.device_id(), sequence, now_ms],
                )
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法写入同步 receipt")
                })?;
            update_head(transaction, "remote", &object, &hash, sequence)?;
            Ok(RemoteApplyOutcome::Applied)
        })
    }

    pub(crate) fn apply_remote_merge(
        &self,
        object_key: &str,
        encoded: &[u8],
        vault_key: &VaultKey,
        now_ms: i64,
    ) -> JournalResult<RemoteMergeResult> {
        let outcome = self.apply_remote(
            object_key,
            encoded,
            vault_key,
            now_ms,
            |transaction, plaintext| {
                let (revision, _) = load_persisted_state(transaction).map_err(map_merge_error)?;
                apply_persisted_operation(transaction, plaintext, revision, now_ms)
                    .map_err(map_merge_error)?;
                Ok(())
            },
        )?;
        let status = self.merge_status()?;
        Ok(RemoteMergeResult {
            outcome,
            revision: status.revision,
            open_conflicts: status.open_conflicts,
        })
    }

    pub(crate) fn prune(&self, now_ms: i64) -> JournalResult<()> {
        validate_now(now_ms)?;
        self.transaction(|transaction| {
            transaction
                .execute(
                    "DELETE FROM sync_operations WHERE object_key IN (
                    SELECT object_key FROM sync_outbox
                    WHERE state = 'published' AND published_at_ms < ?1
                 )",
                    params![now_ms.saturating_sub(PUBLISHED_RETENTION_MS)],
                )
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法清理已发布同步对象")
                })?;
            transaction
                .execute(
                    "DELETE FROM sync_applied_receipts WHERE applied_at_ms < ?1",
                    params![now_ms.saturating_sub(RECEIPT_RETENTION_MS)],
                )
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法清理同步 receipt")
                })?;
            transaction
                .execute(
                    "DELETE FROM sync_operations WHERE origin = 'remote'
                 AND object_key NOT IN (SELECT object_key FROM sync_applied_receipts)",
                    [],
                )
                .map_err(|_| {
                    JournalError::new(JournalErrorCode::Storage, "无法清理远端同步 operation")
                })?;
            Ok(())
        })
    }
}

fn query_snapshot(
    transaction: &Transaction<'_>,
    object_key: &str,
) -> JournalResult<OutboxSnapshot> {
    let row: Option<(String, i64, i64, Option<String>)> = transaction
        .query_row(
            "SELECT state, attempt_count, next_attempt_ms, last_error_code
             FROM sync_outbox WHERE object_key = ?1",
            params![object_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法读取同步 outbox 状态"))?;
    let Some((state, attempt_count, next_attempt_ms, last_error_code)) = row else {
        return Err(JournalError::new(
            JournalErrorCode::NotFound,
            "同步 outbox 对象不存在",
        ));
    };
    Ok(OutboxSnapshot {
        object_key: object_key.to_string(),
        state: OutboxState::parse(&state)?,
        attempt_count: attempt_count.max(0) as u32,
        next_attempt_ms,
        last_error_code,
    })
}

fn recover_expired_leases(transaction: &Transaction<'_>, now_ms: i64) -> JournalResult<()> {
    let mut statement = transaction
        .prepare(
            "SELECT object_key, attempt_count FROM sync_outbox
             WHERE state = 'in_flight' AND lease_expires_ms <= ?1",
        )
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法检查过期同步 lease"))?;
    let expired = statement
        .query_map(params![now_ms], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法读取过期同步 lease"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法解析过期同步 lease"))?;
    drop(statement);
    for (object_key, attempt) in expired {
        let attempt_u32 = attempt.max(0) as u32;
        let (state, next_attempt) = if attempt_u32 >= MAX_ATTEMPTS {
            (OutboxState::PermanentFailure, 0)
        } else {
            (
                OutboxState::RetryWait,
                now_ms.saturating_add(retry_delay_ms(attempt_u32)),
            )
        };
        transaction
            .execute(
                "UPDATE sync_outbox SET state = ?1, next_attempt_ms = ?2,
                lease_id = NULL, lease_expires_ms = NULL,
                last_error_code = 'interrupted', updated_at_ms = ?3
             WHERE object_key = ?4 AND state = 'in_flight'",
                params![state.as_str(), next_attempt, now_ms, object_key],
            )
            .map_err(|_| JournalError::new(JournalErrorCode::Storage, "无法恢复过期同步 lease"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_crypto::{SyncObjectKind, encrypt_sync_object};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("vpshell-sync-{label}-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const VAULT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const DEVICE_ID: &str = "22222222-2222-4222-8222-222222222222";

    fn encrypted(key: &VaultKey, sequence: u64, plaintext: &[u8]) -> Vec<u8> {
        encrypt_sync_object(
            key,
            VAULT_ID,
            SyncObjectKind::Event,
            &format!("event-{sequence}"),
            Some(DEVICE_ID),
            Some(sequence),
            plaintext,
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    fn encrypted_blob(key: &VaultKey, object_id: &str, plaintext: &[u8]) -> Vec<u8> {
        encrypt_sync_object(
            key,
            VAULT_ID,
            SyncObjectKind::Blob,
            object_id,
            None,
            None,
            plaintext,
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    fn create_business_table(transaction: &Transaction<'_>) -> JournalResult<()> {
        transaction
            .execute(
                "CREATE TABLE IF NOT EXISTS fixture_business(value TEXT NOT NULL)",
                [],
            )
            .map_err(|_| JournalError::new(JournalErrorCode::Storage, "fixture failed"))?;
        Ok(())
    }

    #[test]
    fn local_operation_and_outbox_are_atomic_and_idempotent() {
        let root = TempDir::new("atomic");
        let journal = SyncJournal::open(root.0.clone()).unwrap();
        let key = VaultKey::generate().unwrap();
        let object = encrypted(&key, 1, b"operation");
        let failure = journal.enqueue_local("segments/device/1.oseg", &object, 10, |transaction| {
            create_business_table(transaction)?;
            transaction
                .execute(
                    "INSERT INTO fixture_business(value) VALUES ('rolled-back')",
                    [],
                )
                .map_err(|_| JournalError::new(JournalErrorCode::Storage, "fixture failed"))?;
            Err(JournalError::new(
                JournalErrorCode::Conflict,
                "fixture rollback",
            ))
        });
        assert_eq!(failure.unwrap_err().code, JournalErrorCode::Conflict);
        let connection = open_connection(&journal_path(&root.0)).unwrap();
        assert!(
            connection
                .query_row("SELECT value FROM fixture_business", [], |row| row
                    .get::<_, String>(0))
                .optional()
                .is_err()
        );

        assert_eq!(
            journal.enqueue_local("segments/device/1.oseg", &object, 10, |transaction| {
                create_business_table(transaction)?;
                transaction
                    .execute(
                        "INSERT INTO fixture_business(value) VALUES ('committed')",
                        [],
                    )
                    .map_err(|_| JournalError::new(JournalErrorCode::Storage, "fixture failed"))?;
                Ok(())
            }),
            Ok(EnqueueOutcome::Queued)
        );
        assert_eq!(
            journal.enqueue_local("segments/device/1.oseg", &object, 11, |_| {
                panic!("idempotent enqueue must not reapply business change")
            }),
            Ok(EnqueueOutcome::AlreadyQueued)
        );
        let status = journal.status().unwrap();
        assert_eq!(status.pending_objects, 1);
        assert_eq!(status.pending_bytes, object.len() as u64);
    }

    #[test]
    fn retry_pause_resume_and_finalization_transitions_are_bounded() {
        let root = TempDir::new("retry");
        let journal = SyncJournal::open(root.0.clone()).unwrap();
        let key = VaultKey::generate().unwrap();
        let object = encrypted(&key, 1, b"retry");
        journal
            .enqueue_local("segments/retry/1.oseg", &object, 0, |_| Ok(()))
            .unwrap();

        let first = journal.claim_next(0).unwrap().unwrap();
        assert_eq!(first.attempt, 1);
        let waiting = journal
            .mark_failed(
                &first.object_key,
                &first.lease_id,
                AttemptFailure::Network,
                100,
            )
            .unwrap();
        assert_eq!(waiting.state, OutboxState::RetryWait);
        assert_eq!(waiting.next_attempt_ms, 2_100);
        assert!(journal.claim_next(2_099).unwrap().is_none());

        let second = journal.claim_next(2_100).unwrap().unwrap();
        let paused = journal
            .pause_claim(&second.object_key, &second.lease_id, 2_101)
            .unwrap();
        assert_eq!(paused.state, OutboxState::Paused);
        assert!(journal.claim_next(999_999).unwrap().is_none());
        assert_eq!(
            journal.resume(&second.object_key, 3_000).unwrap().state,
            OutboxState::Pending
        );

        let mut now = 3_000;
        for expected_attempt in 3..=MAX_ATTEMPTS {
            let claim = journal.claim_next(now).unwrap().unwrap();
            assert_eq!(claim.attempt, expected_attempt);
            let snapshot = journal
                .mark_failed(
                    &claim.object_key,
                    &claim.lease_id,
                    AttemptFailure::Timeout,
                    now,
                )
                .unwrap();
            if expected_attempt == MAX_ATTEMPTS {
                assert_eq!(snapshot.state, OutboxState::PermanentFailure);
                assert_eq!(
                    journal.resume(&claim.object_key, now).unwrap_err().code,
                    JournalErrorCode::Finalized
                );
            } else {
                assert_eq!(snapshot.state, OutboxState::RetryWait);
                now = snapshot.next_attempt_ms;
            }
        }
        assert!(journal.claim_next(i64::MAX / 2).unwrap().is_none());
    }

    #[test]
    fn non_retryable_failure_and_published_boundary_are_explicit() {
        let root = TempDir::new("final");
        let journal = SyncJournal::open(root.0.clone()).unwrap();
        let key = VaultKey::generate().unwrap();
        let first_object = encrypted(&key, 1, b"one");
        journal
            .enqueue_local("segments/final/1.oseg", &first_object, 0, |_| Ok(()))
            .unwrap();
        let first = journal.claim_next(0).unwrap().unwrap();
        let failed = journal
            .mark_failed(
                &first.object_key,
                &first.lease_id,
                AttemptFailure::Integrity,
                1,
            )
            .unwrap();
        assert_eq!(failed.state, OutboxState::PermanentFailure);
        assert_eq!(failed.last_error_code.as_deref(), Some("integrity"));
        journal.resume(&first.object_key, 2).unwrap();
        let retry = journal.claim_next(2).unwrap().unwrap();
        let published = journal
            .mark_published(&retry.object_key, &retry.lease_id, 3)
            .unwrap();
        assert_eq!(published.state, OutboxState::Published);
        assert_eq!(
            journal
                .mark_published(&retry.object_key, &retry.lease_id, 4)
                .unwrap_err()
                .code,
            JournalErrorCode::Finalized
        );
        assert_eq!(
            journal.resume(&retry.object_key, 4).unwrap_err().code,
            JournalErrorCode::Finalized
        );
    }

    #[test]
    fn expired_leases_recover_after_restart_without_immediate_replay() {
        let root = TempDir::new("lease");
        let key = VaultKey::generate().unwrap();
        let journal = SyncJournal::open(root.0.clone()).unwrap();
        let object = encrypted(&key, 1, b"lease");
        journal
            .enqueue_local("segments/lease/1.oseg", &object, 0, |_| Ok(()))
            .unwrap();
        let claimed = journal.claim_next(0).unwrap().unwrap();
        drop(journal);

        let reopened = SyncJournal::open(root.0.clone()).unwrap();
        assert!(
            reopened
                .claim_next(claimed.lease_expires_ms)
                .unwrap()
                .is_none()
        );
        let retried = reopened
            .claim_next(claimed.lease_expires_ms + retry_delay_ms(1))
            .unwrap()
            .unwrap();
        assert_eq!(retried.attempt, 2);
        assert_eq!(
            reopened
                .mark_published(&retried.object_key, &claimed.lease_id, 999_999)
                .unwrap_err()
                .code,
            JournalErrorCode::StaleLease
        );
    }

    #[test]
    fn remote_apply_is_authenticated_atomic_idempotent_and_sequence_safe() {
        let root = TempDir::new("remote");
        let journal = SyncJournal::open(root.0.clone()).unwrap();
        let key = VaultKey::generate().unwrap();
        let first = encrypted(&key, 1, b"remote-one");
        let second = encrypted(&key, 2, b"remote-two");
        let third = encrypted(&key, 3, b"remote-three");

        assert_eq!(
            journal
                .apply_remote("segments/remote/2.oseg", &second, &key, 1, |_, _| Ok(()))
                .unwrap_err()
                .code,
            JournalErrorCode::SequenceGap
        );
        assert_eq!(
            journal.apply_remote(
                "segments/remote/1.oseg",
                &first,
                &key,
                2,
                |transaction, plaintext| {
                    assert_eq!(plaintext, b"remote-one");
                    create_business_table(transaction)?;
                    transaction
                        .execute("INSERT INTO fixture_business(value) VALUES ('remote')", [])
                        .map_err(|_| {
                            JournalError::new(JournalErrorCode::Storage, "fixture failed")
                        })?;
                    Ok(())
                }
            ),
            Ok(RemoteApplyOutcome::Applied)
        );
        assert_eq!(
            journal.apply_remote("segments/remote/1.oseg", &first, &key, 3, |_, _| {
                panic!("idempotent remote object must not reapply")
            }),
            Ok(RemoteApplyOutcome::AlreadyApplied)
        );
        assert_eq!(
            journal
                .apply_remote(
                    "segments/remote/replay.oseg",
                    &first,
                    &key,
                    4,
                    |_, _| Ok(())
                )
                .unwrap_err()
                .code,
            JournalErrorCode::Replay
        );
        let failed = journal.apply_remote(
            "segments/remote/2.oseg",
            &second,
            &key,
            5,
            |transaction, _| {
                transaction
                    .execute(
                        "INSERT INTO fixture_business(value) VALUES ('rollback')",
                        [],
                    )
                    .map_err(|_| JournalError::new(JournalErrorCode::Storage, "fixture failed"))?;
                Err(JournalError::new(
                    JournalErrorCode::Conflict,
                    "merge conflict",
                ))
            },
        );
        assert_eq!(failed.unwrap_err().code, JournalErrorCode::Conflict);
        assert_eq!(
            journal.apply_remote("segments/remote/2.oseg", &second, &key, 6, |_, _| Ok(())),
            Ok(RemoteApplyOutcome::Applied)
        );
        assert_eq!(
            journal
                .apply_remote(
                    "segments/remote/3.oseg",
                    &third,
                    &VaultKey::generate().unwrap(),
                    7,
                    |_, _| Ok(())
                )
                .unwrap_err()
                .code,
            JournalErrorCode::Authentication
        );
    }

    #[test]
    fn unsequenced_objects_cannot_be_replayed_under_another_key_or_identity() {
        let root = TempDir::new("blob-replay");
        let journal = SyncJournal::open(root.0.clone()).unwrap();
        let key = VaultKey::generate().unwrap();
        let blob = encrypted_blob(&key, "blob-one", b"blob-content");
        assert_eq!(
            journal.apply_remote("blobs/blob-one/a.oblob", &blob, &key, 1, |_, plaintext| {
                assert_eq!(plaintext, b"blob-content");
                Ok(())
            }),
            Ok(RemoteApplyOutcome::Applied)
        );
        assert_eq!(
            journal.apply_remote("blobs/blob-one/a.oblob", &blob, &key, 2, |_, _| {
                panic!("same key and hash must be idempotent")
            }),
            Ok(RemoteApplyOutcome::AlreadyApplied)
        );
        assert_eq!(
            journal
                .apply_remote("blobs/blob-one/relocated.oblob", &blob, &key, 3, |_, _| {
                    panic!("relocated ciphertext must not be applied")
                })
                .unwrap_err()
                .code,
            JournalErrorCode::Replay
        );
        let reencrypted = encrypted_blob(&key, "blob-one", b"blob-content");
        assert_eq!(
            journal
                .apply_remote(
                    "blobs/blob-one/reencrypted.oblob",
                    &reencrypted,
                    &key,
                    4,
                    |_, _| panic!("duplicate identity must not be applied")
                )
                .unwrap_err()
                .code,
            JournalErrorCode::Replay
        );
    }

    #[test]
    fn corrupt_or_truncated_journal_is_quarantined_and_safety_blocked() {
        let root = TempDir::new("corrupt");
        let path = journal_path(&root.0);
        fs::write(&path, b"truncated sqlite").unwrap();
        let journal = SyncJournal::open(root.0.clone()).unwrap();
        let status = journal.status().unwrap();
        assert!(status.safety_blocked);
        assert_eq!(status.safety_reason.as_deref(), Some("reconcile-required"));
        assert!(status.recovery_note.unwrap().contains("损坏或截断"));
        let key = VaultKey::generate().unwrap();
        assert_eq!(
            journal
                .enqueue_local(
                    "segments/blocked/1.oseg",
                    &encrypted(&key, 1, b"blocked"),
                    1,
                    |_| Ok(())
                )
                .unwrap_err()
                .code,
            JournalErrorCode::SafetyBlocked
        );
        journal.acknowledge_reconciliation().unwrap();
        assert!(!journal.status().unwrap().safety_blocked);
        assert!(
            fs::read_dir(&root.0)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| { entry.file_name().to_string_lossy().contains(".corrupt-") })
        );
    }

    #[test]
    fn future_schema_is_preserved_and_retention_never_drops_pending_work() {
        let root = TempDir::new("schema");
        let path = journal_path(&root.0);
        let connection = Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "user_version", JOURNAL_SCHEMA_VERSION + 1)
            .unwrap();
        drop(connection);
        assert_eq!(
            SyncJournal::open(root.0.clone()).unwrap_err().code,
            JournalErrorCode::Storage
        );
        assert!(path.exists());
        assert!(
            !fs::read_dir(&root.0)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| { entry.file_name().to_string_lossy().contains(".corrupt-") })
        );

        fs::remove_file(&path).unwrap();
        let journal = SyncJournal::open(root.0.clone()).unwrap();
        let key = VaultKey::generate().unwrap();
        let object = encrypted(&key, 1, b"retain");
        journal
            .enqueue_local("segments/retain/1.oseg", &object, 0, |_| Ok(()))
            .unwrap();
        journal.prune(PUBLISHED_RETENTION_MS * 2).unwrap();
        assert_eq!(journal.status().unwrap().pending_objects, 1);
        let claimed = journal
            .claim_next(PUBLISHED_RETENTION_MS * 2)
            .unwrap()
            .unwrap();
        journal
            .mark_published(&claimed.object_key, &claimed.lease_id, 1)
            .unwrap();
        journal.prune(PUBLISHED_RETENTION_MS + 2).unwrap();
        assert_eq!(journal.status().unwrap().pending_objects, 0);
    }
}

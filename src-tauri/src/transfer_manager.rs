use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    net::{Shutdown, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use crate::remote_file_ops::{RemoteFileOperationRequest, RemoteOperationResult};

pub(crate) const TRANSFER_CANCELLED: &str = "__VPSHELL_TRANSFER_CANCELLED__";
const TRANSFER_EVENT: &str = "transfer-task-updated";
const RECOVERY_SCHEMA_VERSION: u32 = 1;
const MAX_ACTIVE_TRANSFERS: usize = 6;
const MAX_RETAINED_TRANSFERS: usize = 200;
const MAX_RETRY_ATTEMPTS: u8 = 3;
const MAX_RECOVERY_STATE_BYTES: u64 = 1024 * 1024;
const MAX_RECOVERY_PATHS: usize = 256;
const MAX_RECOVERY_PATH_LENGTH: usize = 4096;
const MAX_RECOVERY_IDENTITY_LENGTH: usize = 255;
const RECOVERY_RETENTION_MILLIS: u64 = 30 * 24 * 60 * 60 * 1000;
const RECOVERY_DIRECTORY_NAME: &str = "transfer-recovery";
const SNAPSHOT_PREFIX: &str = "state-";
const SNAPSHOT_SUFFIX: &str = ".json";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TransferStatus {
    Queued,
    Running,
    Cancelling,
    Interrupted,
    Completed,
    Failed,
    Cancelled,
}

impl TransferStatus {
    fn is_active(&self) -> bool {
        matches!(self, Self::Queued | Self::Running | Self::Cancelling)
    }

    fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    fn requires_recovery(&self) -> bool {
        matches!(self, Self::Interrupted)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum CleanupStatus {
    NotRequired,
    Pending,
    Completed,
    Warning,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum RecoveryState {
    None,
    RetryAvailable,
    RetryExhausted,
    UnsafeToRetry,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "direction")]
pub(crate) enum TransferRequest {
    Upload {
        local_paths: Vec<String>,
        remote_directory: String,
        package_transfer: bool,
    },
    Download {
        remote_paths: Vec<String>,
        local_directory: String,
        package_transfer: bool,
    },
    FileOperation {
        request: RemoteFileOperationRequest,
    },
}

impl TransferRequest {
    fn kind(&self) -> &'static str {
        match self {
            Self::Upload { .. } => "upload",
            Self::Download { .. } => "download",
            Self::FileOperation { .. } => "fileOperation",
        }
    }

    fn validate_for_persistence(&self) -> Result<(), String> {
        let (paths, directory) = match self {
            Self::Upload {
                local_paths,
                remote_directory,
                ..
            } => (local_paths, remote_directory),
            Self::Download {
                remote_paths,
                local_directory,
                ..
            } => (remote_paths, local_directory),
            Self::FileOperation { request } => {
                return crate::remote_file_ops::validate_request(request);
            }
        };
        if paths.is_empty() || paths.len() > MAX_RECOVERY_PATHS {
            return Err("传输恢复路径数量超出安全限制".to_string());
        }
        if directory.is_empty() || directory.len() > MAX_RECOVERY_PATH_LENGTH {
            return Err("传输恢复目标路径长度无效".to_string());
        }
        if paths.iter().any(|path| {
            path.is_empty() || path.len() > MAX_RECOVERY_PATH_LENGTH || path.contains('\0')
        }) || directory.contains('\0')
        {
            return Err("传输恢复路径包含无效内容".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransferResult {
    pub(crate) transfer_id: String,
    pub(crate) mode: String,
    pub(crate) files_transferred: u64,
    pub(crate) bytes_transferred: u64,
    pub(crate) skipped_symlinks: u64,
    pub(crate) fallback_used: bool,
    pub(crate) resumable: bool,
    pub(crate) verification: String,
    pub(crate) limitations: Vec<String>,
    pub(crate) operation_result: Option<RemoteOperationResult>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransferSnapshot {
    pub(crate) transfer_id: String,
    pub(crate) kind: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: String,
    pub(crate) status: TransferStatus,
    pub(crate) seq: u64,
    pub(crate) phase: String,
    pub(crate) current_path: String,
    pub(crate) transferred_bytes: u64,
    pub(crate) total_bytes: Option<u64>,
    pub(crate) result: Option<TransferResult>,
    pub(crate) error: Option<String>,
    pub(crate) partial_commit: bool,
    pub(crate) cleanup_status: CleanupStatus,
    pub(crate) cleanup_warnings: Vec<String>,
    pub(crate) finalizing: bool,
    pub(crate) can_cancel: bool,
    pub(crate) can_dismiss: bool,
    pub(crate) recovery_state: RecoveryState,
    pub(crate) recovery_reason: Option<String>,
    pub(crate) retry_attempts: u8,
    pub(crate) max_retry_attempts: u8,
    pub(crate) can_retry: bool,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoveryStoreStatus {
    pub(crate) warning: Option<String>,
    pub(crate) loaded_records: usize,
    pub(crate) discarded_records: usize,
    pub(crate) retention_days: u64,
    pub(crate) maximum_records: usize,
    pub(crate) maximum_retry_attempts: u8,
}

struct TransferRuntime {
    snapshot: TransferSnapshot,
    request: Option<TransferRequest>,
    cancel_requested: bool,
    finalizing: bool,
    replay_unsafe: bool,
    cleanup_attempted: bool,
    committed_units: u64,
    socket: Option<TcpStream>,
}

struct TransferRecord {
    runtime: Mutex<TransferRuntime>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistedTransferRecord {
    transfer_id: String,
    kind: String,
    host: String,
    port: u16,
    username: String,
    status: TransferStatus,
    phase: String,
    request: Option<TransferRequest>,
    retry_attempts: u8,
    replay_unsafe: bool,
    finalizing: bool,
    committed_units: u64,
    created_at: u64,
    updated_at: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistedEnvelope {
    schema_version: u32,
    generation: u64,
    written_at: u64,
    records: Vec<PersistedTransferRecord>,
}

struct LoadOutcome {
    records: Vec<PersistedTransferRecord>,
    warning: Option<String>,
    discarded_records: usize,
    generation: u64,
}

#[derive(Clone)]
struct RecoveryStore {
    directory: PathBuf,
    generation: Arc<AtomicU64>,
}

impl RecoveryStore {
    fn new(app_data_directory: PathBuf) -> Self {
        Self {
            directory: app_data_directory.join(RECOVERY_DIRECTORY_NAME),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    fn load(&self) -> LoadOutcome {
        if let Err(error) = fs::create_dir_all(&self.directory) {
            return LoadOutcome {
                records: Vec::new(),
                warning: Some(format!("无法打开传输恢复存储，重启恢复暂不可用: {error}")),
                discarded_records: 0,
                generation: 0,
            };
        }

        let mut candidates = recovery_snapshot_paths(&self.directory);
        candidates.sort_by(|left, right| right.0.cmp(&left.0));
        let mut valid = Vec::new();
        let mut invalid_files = 0_usize;
        let mut discarded_records = 0_usize;
        let mut maximum_generation = 0_u64;

        for (filename_generation, path) in &candidates {
            maximum_generation = maximum_generation.max(*filename_generation);
            match read_envelope(path) {
                Ok(envelope) if envelope.schema_version == RECOVERY_SCHEMA_VERSION => {
                    maximum_generation = maximum_generation.max(envelope.generation);
                    if envelope.records.len() > MAX_RETAINED_TRANSFERS
                        || envelope
                            .records
                            .iter()
                            .any(|record| validate_persisted_record(record).is_err())
                    {
                        invalid_files += 1;
                    } else {
                        valid.push((path.clone(), envelope));
                    }
                }
                Ok(envelope) => {
                    maximum_generation = maximum_generation.max(envelope.generation);
                    invalid_files += 1;
                    discarded_records = discarded_records.saturating_add(envelope.records.len());
                }
                Err(_) => invalid_files += 1,
            }
        }

        self.generation.store(maximum_generation, Ordering::Relaxed);
        let records = valid
            .first()
            .map(|(_, envelope)| envelope.records.clone())
            .unwrap_or_default();
        let keep = valid
            .iter()
            .take(2)
            .map(|(path, _)| path.clone())
            .collect::<HashSet<_>>();
        cleanup_recovery_files(&self.directory, &keep);

        LoadOutcome {
            records,
            warning: (invalid_files > 0).then(|| {
                format!("已忽略并清理 {invalid_files} 个损坏、截断或不受支持的传输恢复状态文件")
            }),
            discarded_records,
            generation: maximum_generation,
        }
    }

    fn write(&self, records: Vec<PersistedTransferRecord>) -> Result<(), String> {
        fs::create_dir_all(&self.directory)
            .map_err(|error| format!("无法创建传输恢复目录: {error}"))?;
        if records.len() > MAX_RETAINED_TRANSFERS {
            return Err("传输恢复记录超过持久化上限".to_string());
        }
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let envelope = PersistedEnvelope {
            schema_version: RECOVERY_SCHEMA_VERSION,
            generation,
            written_at: now_millis(),
            records,
        };
        let bytes = serde_json::to_vec(&envelope)
            .map_err(|error| format!("无法编码传输恢复状态: {error}"))?;
        if bytes.len() as u64 > MAX_RECOVERY_STATE_BYTES {
            return Err("传输恢复状态超过 1 MiB 安全上限".to_string());
        }

        let nonce = uuid::Uuid::new_v4();
        let temporary = self
            .directory
            .join(format!(".state-{generation:020}-{nonce}.tmp"));
        let destination = self.directory.join(format!(
            "{SNAPSHOT_PREFIX}{generation:020}-{nonce}{SNAPSHOT_SUFFIX}"
        ));
        let write_result: Result<(), String> = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|error| format!("无法创建传输恢复临时文件: {error}"))?;
            file.write_all(&bytes)
                .map_err(|error| format!("无法写入传输恢复状态: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("无法同步传输恢复状态: {error}"))?;
            drop(file);
            fs::rename(&temporary, &destination)
                .map_err(|error| format!("无法原子提交传输恢复状态: {error}"))?;
            sync_directory(&self.directory)?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result?;

        let mut snapshots = recovery_snapshot_paths(&self.directory);
        snapshots.sort_by(|left, right| right.0.cmp(&left.0));
        let keep = snapshots
            .into_iter()
            .take(2)
            .map(|(_, path)| path)
            .collect::<HashSet<_>>();
        cleanup_recovery_files(&self.directory, &keep);
        Ok(())
    }
}

struct TransferManagerInner {
    tasks: Mutex<HashMap<String, Arc<TransferRecord>>>,
    next_seq: AtomicU64,
    store: Option<RecoveryStore>,
    store_status: Mutex<RecoveryStoreStatus>,
}

#[derive(Clone)]
pub(crate) struct TransferManager {
    inner: Arc<TransferManagerInner>,
}

impl Default for TransferManager {
    fn default() -> Self {
        Self::empty(
            None,
            RecoveryStoreStatus {
                warning: None,
                loaded_records: 0,
                discarded_records: 0,
                retention_days: RECOVERY_RETENTION_MILLIS / (24 * 60 * 60 * 1000),
                maximum_records: MAX_RETAINED_TRANSFERS,
                maximum_retry_attempts: MAX_RETRY_ATTEMPTS,
            },
        )
    }
}

impl TransferManager {
    pub(crate) fn load(app_data_directory: PathBuf) -> Self {
        let store = RecoveryStore::new(app_data_directory);
        let outcome = store.load();
        let now = now_millis();
        let mut discarded_records = outcome.discarded_records;
        let mut tasks = HashMap::new();
        let mut maximum_seq = 0_u64;

        for persisted in outcome.records {
            if now.saturating_sub(persisted.updated_at) > RECOVERY_RETENTION_MILLIS {
                discarded_records = discarded_records.saturating_add(1);
                continue;
            }
            let (record, seq) = record_from_persisted(persisted);
            maximum_seq = maximum_seq.max(seq);
            let transfer_id = lock(&record.runtime).snapshot.transfer_id.clone();
            tasks.insert(transfer_id, record);
        }
        prune_terminal_tasks(&mut tasks, MAX_RETAINED_TRANSFERS);

        let manager = Self {
            inner: Arc::new(TransferManagerInner {
                tasks: Mutex::new(tasks),
                next_seq: AtomicU64::new(maximum_seq.max(outcome.generation)),
                store: Some(store),
                store_status: Mutex::new(RecoveryStoreStatus {
                    warning: outcome.warning,
                    loaded_records: 0,
                    discarded_records,
                    retention_days: RECOVERY_RETENTION_MILLIS / (24 * 60 * 60 * 1000),
                    maximum_records: MAX_RETAINED_TRANSFERS,
                    maximum_retry_attempts: MAX_RETRY_ATTEMPTS,
                }),
            }),
        };
        let loaded_records = lock(&manager.inner.tasks).len();
        lock(&manager.inner.store_status).loaded_records = loaded_records;
        if let Err(error) = manager.persist() {
            manager.note_store_warning(error);
        }
        manager
    }

    fn empty(store: Option<RecoveryStore>, status: RecoveryStoreStatus) -> Self {
        Self {
            inner: Arc::new(TransferManagerInner {
                tasks: Mutex::new(HashMap::new()),
                next_seq: AtomicU64::new(0),
                store,
                store_status: Mutex::new(status),
            }),
        }
    }

    pub(crate) fn accept(
        &self,
        app: &AppHandle,
        transfer_id: String,
        host: &str,
        port: u16,
        username: &str,
        request: TransferRequest,
    ) -> Result<(TransferSnapshot, TransferTask), String> {
        request.validate_for_persistence()?;
        validate_recovery_identity(&transfer_id, host, username)?;
        let now = now_millis();
        let snapshot = new_snapshot(
            transfer_id.clone(),
            request.kind(),
            host,
            port,
            username,
            self.next_seq(),
            now,
        );
        let record = Arc::new(TransferRecord {
            runtime: Mutex::new(TransferRuntime {
                snapshot: snapshot.clone(),
                request: Some(request),
                cancel_requested: false,
                finalizing: false,
                replay_unsafe: false,
                cleanup_attempted: false,
                committed_units: 0,
                socket: None,
            }),
        });

        {
            let mut tasks = lock(&self.inner.tasks);
            if tasks.contains_key(&transfer_id) {
                return Err("传输任务 ID 已存在；请查询或移除原任务后重试".to_string());
            }
            let active = tasks
                .values()
                .filter(|task| lock(&task.runtime).snapshot.status.is_active())
                .count();
            if active >= MAX_ACTIVE_TRANSFERS {
                return Err(format!(
                    "同时运行的传输任务已达到上限（{MAX_ACTIVE_TRANSFERS} 个）"
                ));
            }
            prune_stale_tasks(&mut tasks, now);
            prune_terminal_tasks(&mut tasks, MAX_RETAINED_TRANSFERS.saturating_sub(1));
            tasks.insert(transfer_id.clone(), Arc::clone(&record));
        }
        if let Err(error) = self.persist() {
            lock(&self.inner.tasks).remove(&transfer_id);
            return Err(format!("无法安全登记传输任务，任务未启动: {error}"));
        }

        emit_snapshot(app, &snapshot);
        Ok((snapshot, self.task(app, record)))
    }

    pub(crate) fn begin_retry(
        &self,
        app: &AppHandle,
        transfer_id: &str,
        host: &str,
        port: u16,
        username: &str,
    ) -> Result<(TransferSnapshot, TransferTask, TransferRequest), String> {
        let record = self
            .record(transfer_id)
            .ok_or_else(|| "传输恢复记录不存在或已经丢弃".to_string())?;
        let (snapshot, request) = {
            let mut runtime = lock(&record.runtime);
            if runtime.snapshot.host != host
                || runtime.snapshot.port != port
                || runtime.snapshot.username != username
            {
                return Err("当前连接身份与恢复记录不一致，拒绝重试".to_string());
            }
            if runtime.snapshot.status.is_active() {
                return Err("传输任务已经在运行，拒绝重复重试".to_string());
            }
            if runtime.replay_unsafe || runtime.finalizing || runtime.committed_units > 0 {
                return Err(
                    "任务可能已提交部分结果或进入最终提交阶段，为避免覆盖不能重试".to_string(),
                );
            }
            if runtime.snapshot.retry_attempts >= MAX_RETRY_ATTEMPTS {
                return Err(format!("传输重试已达到上限（{MAX_RETRY_ATTEMPTS} 次）"));
            }
            let request = runtime
                .request
                .clone()
                .ok_or_else(|| "恢复记录不包含可重试请求；请丢弃后重新发起".to_string())?;
            request.validate_for_persistence()?;
            runtime.snapshot.retry_attempts = runtime.snapshot.retry_attempts.saturating_add(1);
            runtime.snapshot.status = TransferStatus::Queued;
            runtime.snapshot.phase = "retrying".to_string();
            runtime.snapshot.error = None;
            runtime.snapshot.recovery_state = RecoveryState::None;
            runtime.snapshot.recovery_reason = Some(format!(
                "正在执行第 {} / {MAX_RETRY_ATTEMPTS} 次明确重试",
                runtime.snapshot.retry_attempts
            ));
            runtime.snapshot.can_retry = false;
            runtime.snapshot.can_dismiss = false;
            runtime.cancel_requested = false;
            runtime.cleanup_attempted = false;
            runtime.snapshot.cleanup_status = CleanupStatus::NotRequired;
            runtime.snapshot.cleanup_warnings.clear();
            runtime.committed_units = 0;
            runtime.replay_unsafe = false;
            runtime.finalizing = false;
            (self.touch(&mut runtime), request)
        };
        if let Err(error) = self.persist() {
            let mut runtime = lock(&record.runtime);
            set_retry_state(&mut runtime);
            self.touch(&mut runtime);
            return Err(format!("无法持久化重试决定，任务未启动: {error}"));
        }
        emit_snapshot(app, &snapshot);
        Ok((snapshot, self.task(app, record), request))
    }

    pub(crate) fn get(&self, transfer_id: &str) -> Option<TransferSnapshot> {
        let record = lock(&self.inner.tasks).get(transfer_id).cloned()?;
        Some(lock(&record.runtime).snapshot.clone())
    }

    pub(crate) fn list(&self) -> Vec<TransferSnapshot> {
        let records = lock(&self.inner.tasks)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut snapshots = records
            .iter()
            .map(|record| lock(&record.runtime).snapshot.clone())
            .collect::<Vec<_>>();
        snapshots.sort_by_key(|snapshot| (snapshot.created_at, snapshot.seq));
        snapshots
    }

    pub(crate) fn store_status(&self) -> RecoveryStoreStatus {
        lock(&self.inner.store_status).clone()
    }

    pub(crate) fn recovery_file_operation_request(
        &self,
        transfer_id: &str,
        host: &str,
        port: u16,
        username: &str,
    ) -> Result<RemoteFileOperationRequest, String> {
        let record = self
            .record(transfer_id)
            .ok_or_else(|| "文件任务恢复记录不存在或已经丢弃".to_string())?;
        let runtime = lock(&record.runtime);
        if runtime.snapshot.host != host
            || runtime.snapshot.port != port
            || runtime.snapshot.username != username
        {
            return Err("当前连接身份与文件任务恢复记录不一致".to_string());
        }
        if !matches!(
            runtime.snapshot.recovery_state,
            RecoveryState::RetryAvailable
        ) || runtime.replay_unsafe
            || runtime.finalizing
            || runtime.committed_units > 0
        {
            return Err("文件任务可能已经提交结果，不能重新预览或重放".to_string());
        }
        match runtime.request.as_ref() {
            Some(TransferRequest::FileOperation { request }) => Ok(request.clone()),
            _ => Err("该恢复记录不是远端文件操作".to_string()),
        }
    }

    pub(crate) fn cancel(
        &self,
        app: &AppHandle,
        transfer_id: &str,
    ) -> Result<TransferSnapshot, String> {
        let record = self
            .record(transfer_id)
            .ok_or_else(|| "传输任务不存在".to_string())?;
        let snapshot = {
            let mut runtime = lock(&record.runtime);
            if !runtime.snapshot.status.is_active() {
                return Err("传输任务没有在运行，无法取消".to_string());
            }
            if runtime.finalizing {
                return Err("传输任务已进入最终提交阶段，现在取消已经太晚".to_string());
            }
            runtime.cancel_requested = true;
            runtime.snapshot.status = TransferStatus::Cancelling;
            runtime.snapshot.phase = "cancelling".to_string();
            runtime.snapshot.can_cancel = false;
            if let Some(socket) = runtime.socket.as_ref() {
                let _ = socket.shutdown(Shutdown::Both);
            }
            self.touch(&mut runtime)
        };
        if let Err(error) = self.persist() {
            self.note_store_warning(error);
        }
        emit_snapshot(app, &snapshot);
        Ok(snapshot)
    }

    pub(crate) fn dismiss(&self, transfer_id: &str) -> Result<(), String> {
        let removed = {
            let mut tasks = lock(&self.inner.tasks);
            let record = tasks
                .get(transfer_id)
                .cloned()
                .ok_or_else(|| "传输任务不存在".to_string())?;
            let status = &lock(&record.runtime).snapshot.status;
            if status.is_active() {
                return Err("仍在运行的传输任务不能移除；请先取消并等待清理完成".to_string());
            }
            tasks.remove(transfer_id)
        };
        if let Err(error) = self.persist() {
            if let Some(record) = removed {
                lock(&self.inner.tasks).insert(transfer_id.to_string(), record);
            }
            return Err(format!("无法持久化丢弃决定，恢复记录仍保留: {error}"));
        }
        Ok(())
    }

    fn task(&self, app: &AppHandle, record: Arc<TransferRecord>) -> TransferTask {
        TransferTask {
            app: app.clone(),
            manager: self.clone(),
            record,
        }
    }

    fn record(&self, transfer_id: &str) -> Option<Arc<TransferRecord>> {
        lock(&self.inner.tasks).get(transfer_id).cloned()
    }

    fn next_seq(&self) -> u64 {
        self.inner.next_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn touch(&self, runtime: &mut TransferRuntime) -> TransferSnapshot {
        runtime.snapshot.seq = self.next_seq();
        runtime.snapshot.updated_at = now_millis();
        runtime.snapshot.finalizing = runtime.finalizing;
        runtime.snapshot.can_cancel =
            runtime.snapshot.status.is_active() && !runtime.cancel_requested && !runtime.finalizing;
        runtime.snapshot.can_dismiss =
            runtime.snapshot.status.is_terminal() || runtime.snapshot.status.requires_recovery();
        runtime.snapshot.can_retry = matches!(
            runtime.snapshot.recovery_state,
            RecoveryState::RetryAvailable
        );
        runtime.snapshot.clone()
    }

    fn persist(&self) -> Result<(), String> {
        let Some(store) = &self.inner.store else {
            return Ok(());
        };
        let records = persisted_records(&self.inner.tasks);
        store.write(records)
    }

    fn note_store_warning(&self, error: String) {
        lock(&self.inner.store_status).warning = Some(error);
    }
}

#[derive(Clone)]
pub(crate) struct TransferTask {
    app: AppHandle,
    manager: TransferManager,
    record: Arc<TransferRecord>,
}

impl TransferTask {
    pub(crate) fn start(&self) -> Result<(), String> {
        let snapshot = {
            let mut runtime = lock(&self.record.runtime);
            if runtime.cancel_requested {
                return Err(TRANSFER_CANCELLED.to_string());
            }
            runtime.snapshot.status = TransferStatus::Running;
            runtime.snapshot.phase = "starting".to_string();
            self.manager.touch(&mut runtime)
        };
        self.manager.persist()?;
        emit_snapshot(&self.app, &snapshot);
        Ok(())
    }

    pub(crate) fn checkpoint(&self) -> Result<(), String> {
        if lock(&self.record.runtime).cancel_requested {
            Err(TRANSFER_CANCELLED.to_string())
        } else {
            Ok(())
        }
    }

    pub(crate) fn progress(
        &self,
        phase: impl Into<String>,
        current_path: impl Into<String>,
        transferred_bytes: u64,
        total_bytes: Option<u64>,
    ) -> Result<TransferSnapshot, String> {
        let snapshot = {
            let mut runtime = lock(&self.record.runtime);
            if runtime.cancel_requested {
                return Err(TRANSFER_CANCELLED.to_string());
            }
            runtime.snapshot.phase = phase.into();
            runtime.snapshot.current_path = current_path.into();
            runtime.snapshot.transferred_bytes = transferred_bytes;
            runtime.snapshot.total_bytes = total_bytes;
            self.manager.touch(&mut runtime)
        };
        emit_snapshot(&self.app, &snapshot);
        Ok(snapshot)
    }

    pub(crate) fn register_socket(&self, socket: TcpStream) -> Result<(), String> {
        let mut runtime = lock(&self.record.runtime);
        if runtime.cancel_requested {
            let _ = socket.shutdown(Shutdown::Both);
            return Err(TRANSFER_CANCELLED.to_string());
        }
        runtime.socket = Some(socket);
        Ok(())
    }

    pub(crate) fn clear_socket(&self) {
        lock(&self.record.runtime).socket = None;
    }

    pub(crate) fn mark_commit_boundary(&self) -> Result<(), String> {
        {
            let mut runtime = lock(&self.record.runtime);
            if runtime.cancel_requested {
                return Err(TRANSFER_CANCELLED.to_string());
            }
            runtime.replay_unsafe = true;
            runtime.snapshot.recovery_reason =
                Some("任务已到达提交边界；应用异常退出后不会自动或手动重放".to_string());
            self.manager.touch(&mut runtime);
        }
        self.manager
            .persist()
            .map_err(|error| format!("无法在提交前持久化安全边界，已阻止最终提交: {error}"))
    }

    pub(crate) fn begin_finalizing(&self, current_path: impl Into<String>) -> Result<(), String> {
        let snapshot = {
            let mut runtime = lock(&self.record.runtime);
            if runtime.cancel_requested {
                return Err(TRANSFER_CANCELLED.to_string());
            }
            runtime.finalizing = true;
            runtime.replay_unsafe = true;
            runtime.snapshot.phase = "finalizing".to_string();
            runtime.snapshot.current_path = current_path.into();
            runtime.snapshot.recovery_reason =
                Some("任务已进入最终提交；重启后必须核对目标，不会重放".to_string());
            self.manager.touch(&mut runtime)
        };
        self.manager
            .persist()
            .map_err(|error| format!("无法在最终提交前持久化安全边界，已阻止提交: {error}"))?;
        emit_snapshot(&self.app, &snapshot);
        Ok(())
    }

    pub(crate) fn end_finalizing(&self) {
        let snapshot = {
            let mut runtime = lock(&self.record.runtime);
            runtime.finalizing = false;
            self.manager.touch(&mut runtime)
        };
        if let Err(error) = self.manager.persist() {
            self.manager.note_store_warning(error);
        }
        emit_snapshot(&self.app, &snapshot);
    }

    pub(crate) fn note_commit(&self) {
        {
            let mut runtime = lock(&self.record.runtime);
            runtime.committed_units = runtime.committed_units.saturating_add(1);
            runtime.replay_unsafe = true;
        }
        if let Err(error) = self.manager.persist() {
            self.manager.note_store_warning(error);
        }
    }

    pub(crate) fn note_rollback(&self) {
        let mut runtime = lock(&self.record.runtime);
        runtime.committed_units = runtime.committed_units.saturating_sub(1);
    }

    pub(crate) fn begin_cleanup(&self) {
        let snapshot = {
            let mut runtime = lock(&self.record.runtime);
            runtime.cleanup_attempted = true;
            if runtime.snapshot.cleanup_warnings.is_empty() {
                runtime.snapshot.cleanup_status = CleanupStatus::Pending;
            }
            self.manager.touch(&mut runtime)
        };
        emit_snapshot(&self.app, &snapshot);
    }

    pub(crate) fn cleanup_warning(&self, warning: impl Into<String>) {
        let snapshot = {
            let mut runtime = lock(&self.record.runtime);
            runtime.cleanup_attempted = true;
            runtime.snapshot.cleanup_status = CleanupStatus::Warning;
            runtime.snapshot.cleanup_warnings.push(warning.into());
            self.manager.touch(&mut runtime)
        };
        emit_snapshot(&self.app, &snapshot);
    }

    pub(crate) fn finish(&self, result: Result<TransferResult, String>) -> TransferSnapshot {
        self.clear_socket();
        let snapshot = {
            let mut runtime = lock(&self.record.runtime);
            let cancellation = runtime.cancel_requested
                || matches!(result.as_ref(), Err(error) if error == TRANSFER_CANCELLED);
            if cancellation {
                runtime.snapshot.status = TransferStatus::Cancelled;
                runtime.snapshot.phase = "cancelled".to_string();
                runtime.snapshot.result = result.ok();
                runtime.snapshot.error = None;
                runtime.snapshot.partial_commit = runtime.committed_units > 0;
                runtime.snapshot.recovery_state = RecoveryState::None;
                runtime.snapshot.recovery_reason = None;
                runtime.snapshot.can_retry = false;
                runtime.request = None;
            } else {
                match result {
                    Ok(result) => {
                        runtime.snapshot.status = TransferStatus::Completed;
                        runtime.snapshot.phase = "completed".to_string();
                        runtime.snapshot.transferred_bytes = result.bytes_transferred;
                        runtime.snapshot.total_bytes = Some(result.bytes_transferred);
                        runtime.snapshot.result = Some(result);
                        runtime.snapshot.error = None;
                        runtime.snapshot.partial_commit = false;
                        runtime.snapshot.recovery_state = RecoveryState::None;
                        runtime.snapshot.recovery_reason = None;
                        runtime.snapshot.can_retry = false;
                        runtime.request = None;
                    }
                    Err(error) => {
                        runtime.snapshot.status = TransferStatus::Failed;
                        runtime.snapshot.phase = "failed".to_string();
                        runtime.snapshot.result = None;
                        runtime.snapshot.error = Some(error);
                        runtime.snapshot.partial_commit = runtime.committed_units > 0;
                        set_retry_state(&mut runtime);
                    }
                }
            }
            runtime.finalizing = false;
            if runtime.cleanup_attempted && runtime.snapshot.cleanup_warnings.is_empty() {
                runtime.snapshot.cleanup_status = CleanupStatus::Completed;
            }
            self.manager.touch(&mut runtime)
        };
        if let Err(error) = self.manager.persist() {
            self.manager.note_store_warning(error);
        }
        emit_snapshot(&self.app, &snapshot);
        snapshot
    }
}

fn new_snapshot(
    transfer_id: String,
    kind: &str,
    host: &str,
    port: u16,
    username: &str,
    seq: u64,
    now: u64,
) -> TransferSnapshot {
    TransferSnapshot {
        transfer_id,
        kind: kind.to_string(),
        host: host.to_string(),
        port,
        username: username.to_string(),
        status: TransferStatus::Queued,
        seq,
        phase: "queued".to_string(),
        current_path: String::new(),
        transferred_bytes: 0,
        total_bytes: None,
        result: None,
        error: None,
        partial_commit: false,
        cleanup_status: CleanupStatus::NotRequired,
        cleanup_warnings: Vec::new(),
        finalizing: false,
        can_cancel: true,
        can_dismiss: false,
        recovery_state: RecoveryState::None,
        recovery_reason: None,
        retry_attempts: 0,
        max_retry_attempts: MAX_RETRY_ATTEMPTS,
        can_retry: false,
        created_at: now,
        updated_at: now,
    }
}

fn set_retry_state(runtime: &mut TransferRuntime) {
    runtime.snapshot.can_retry = false;
    if runtime.replay_unsafe || runtime.finalizing || runtime.committed_units > 0 {
        runtime.snapshot.recovery_state = RecoveryState::UnsafeToRetry;
        runtime.snapshot.recovery_reason = Some(
            "任务可能已提交部分结果或进入最终提交阶段；请核对目标后丢弃记录，系统不会重放"
                .to_string(),
        );
        runtime.request = None;
    } else if runtime.snapshot.retry_attempts >= MAX_RETRY_ATTEMPTS {
        runtime.snapshot.recovery_state = RecoveryState::RetryExhausted;
        runtime.snapshot.recovery_reason = Some(format!(
            "已达到 {MAX_RETRY_ATTEMPTS} 次应用级重试上限；请查看错误后重新发起任务"
        ));
        runtime.request = None;
    } else if runtime.request.is_some() {
        runtime.snapshot.recovery_state = RecoveryState::RetryAvailable;
        runtime.snapshot.recovery_reason = Some(format!(
            "未记录最终提交，可明确重试；剩余 {} 次",
            MAX_RETRY_ATTEMPTS.saturating_sub(runtime.snapshot.retry_attempts)
        ));
        runtime.snapshot.can_retry = true;
    } else {
        runtime.snapshot.recovery_state = RecoveryState::UnsafeToRetry;
        runtime.snapshot.recovery_reason =
            Some("恢复记录缺少安全重试所需的最小请求元数据，请丢弃后重新发起".to_string());
    }
}

fn record_from_persisted(persisted: PersistedTransferRecord) -> (Arc<TransferRecord>, u64) {
    let seq = persisted.updated_at.max(persisted.created_at);
    let was_active = persisted.status.is_active();
    let mut runtime = TransferRuntime {
        snapshot: TransferSnapshot {
            transfer_id: persisted.transfer_id,
            kind: persisted.kind,
            host: persisted.host,
            port: persisted.port,
            username: persisted.username,
            status: if was_active {
                TransferStatus::Interrupted
            } else {
                persisted.status
            },
            seq,
            phase: if was_active {
                "recoveryRequired".to_string()
            } else {
                persisted.phase
            },
            current_path: String::new(),
            transferred_bytes: 0,
            total_bytes: None,
            result: None,
            error: was_active.then(|| "应用在任务结束前退出；任务不会自动继续".to_string()),
            partial_commit: persisted.committed_units > 0,
            cleanup_status: CleanupStatus::NotRequired,
            cleanup_warnings: Vec::new(),
            finalizing: false,
            can_cancel: false,
            can_dismiss: true,
            recovery_state: RecoveryState::None,
            recovery_reason: None,
            retry_attempts: persisted.retry_attempts,
            max_retry_attempts: MAX_RETRY_ATTEMPTS,
            can_retry: false,
            created_at: persisted.created_at,
            updated_at: persisted.updated_at,
        },
        request: persisted.request,
        cancel_requested: false,
        finalizing: false,
        replay_unsafe: persisted.replay_unsafe || persisted.finalizing,
        cleanup_attempted: false,
        committed_units: persisted.committed_units,
        socket: None,
    };
    if was_active || matches!(runtime.snapshot.status, TransferStatus::Failed) {
        set_retry_state(&mut runtime);
    }
    (
        Arc::new(TransferRecord {
            runtime: Mutex::new(runtime),
        }),
        seq,
    )
}

fn persisted_records(
    tasks: &Mutex<HashMap<String, Arc<TransferRecord>>>,
) -> Vec<PersistedTransferRecord> {
    let records = lock(tasks).values().cloned().collect::<Vec<_>>();
    let mut persisted = records
        .iter()
        .map(|record| {
            let runtime = lock(&record.runtime);
            let retain_request = !runtime.replay_unsafe
                && !runtime.finalizing
                && matches!(
                    runtime.snapshot.status,
                    TransferStatus::Queued
                        | TransferStatus::Running
                        | TransferStatus::Cancelling
                        | TransferStatus::Interrupted
                        | TransferStatus::Failed
                );
            PersistedTransferRecord {
                transfer_id: runtime.snapshot.transfer_id.clone(),
                kind: runtime.snapshot.kind.clone(),
                host: runtime.snapshot.host.clone(),
                port: runtime.snapshot.port,
                username: runtime.snapshot.username.clone(),
                status: runtime.snapshot.status.clone(),
                phase: runtime.snapshot.phase.clone(),
                request: retain_request.then(|| runtime.request.clone()).flatten(),
                retry_attempts: runtime.snapshot.retry_attempts,
                replay_unsafe: runtime.replay_unsafe,
                finalizing: runtime.finalizing,
                committed_units: runtime.committed_units,
                created_at: runtime.snapshot.created_at,
                updated_at: runtime.snapshot.updated_at,
            }
        })
        .collect::<Vec<_>>();
    persisted.sort_by_key(|record| (record.created_at, record.updated_at));
    persisted
}

fn validate_persisted_record(record: &PersistedTransferRecord) -> Result<(), String> {
    validate_recovery_identity(&record.transfer_id, &record.host, &record.username)?;
    if !matches!(
        record.kind.as_str(),
        "upload" | "download" | "fileOperation"
    ) || record.port == 0
    {
        return Err("恢复记录的传输类型或端口无效".to_string());
    }
    if record.retry_attempts > MAX_RETRY_ATTEMPTS {
        return Err("恢复记录的重试次数无效".to_string());
    }
    if let Some(request) = &record.request {
        request.validate_for_persistence()?;
        if request.kind() != record.kind {
            return Err("恢复记录的请求方向不一致".to_string());
        }
    }
    Ok(())
}

fn validate_recovery_identity(transfer_id: &str, host: &str, username: &str) -> Result<(), String> {
    if transfer_id.is_empty()
        || transfer_id.len() > 128
        || !transfer_id
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
    {
        return Err("传输恢复任务 ID 无效".to_string());
    }
    if host.is_empty()
        || host.len() > MAX_RECOVERY_IDENTITY_LENGTH
        || username.is_empty()
        || username.len() > 128
        || host.contains('\0')
        || username.contains('\0')
    {
        return Err("传输恢复连接身份无效".to_string());
    }
    Ok(())
}

fn read_envelope(path: &Path) -> Result<PersistedEnvelope, String> {
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if metadata.len() > MAX_RECOVERY_STATE_BYTES {
        return Err("恢复状态文件超过大小上限".to_string());
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn recovery_snapshot_paths(directory: &Path) -> Vec<(u64, PathBuf)> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            let generation = name
                .strip_prefix(SNAPSHOT_PREFIX)?
                .split('-')
                .next()?
                .parse::<u64>()
                .ok()?;
            name.ends_with(SNAPSHOT_SUFFIX)
                .then_some((generation, entry.path()))
        })
        .collect()
}

fn cleanup_recovery_files(directory: &Path, keep: &HashSet<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !keep.contains(&path)
            && (name.starts_with(SNAPSHOT_PREFIX)
                || (name.starts_with(".state-") && name.ends_with(".tmp")))
        {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), String> {
    fs::File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("无法同步传输恢复目录: {error}"))
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), String> {
    Ok(())
}

fn emit_snapshot(app: &AppHandle, snapshot: &TransferSnapshot) {
    let _ = app.emit(TRANSFER_EVENT, snapshot.clone());
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn prune_stale_tasks(tasks: &mut HashMap<String, Arc<TransferRecord>>, now: u64) {
    tasks.retain(|_, record| {
        let runtime = lock(&record.runtime);
        runtime.snapshot.status.is_active()
            || now.saturating_sub(runtime.snapshot.updated_at) <= RECOVERY_RETENTION_MILLIS
    });
}

fn prune_terminal_tasks(tasks: &mut HashMap<String, Arc<TransferRecord>>, maximum: usize) {
    if tasks.len() <= maximum {
        return;
    }
    let mut removable = tasks
        .iter()
        .filter_map(|(id, record)| {
            let runtime = lock(&record.runtime);
            (!runtime.snapshot.status.is_active())
                .then_some((id.clone(), runtime.snapshot.updated_at))
        })
        .collect::<Vec<_>>();
    removable.sort_by_key(|(_, updated_at)| *updated_at);
    let remove_count = tasks.len().saturating_sub(maximum).min(removable.len());
    for (id, _) in removable.into_iter().take(remove_count) {
        tasks.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vpshell-transfer-{name}-{}", uuid::Uuid::new_v4()))
    }

    fn request() -> TransferRequest {
        TransferRequest::Upload {
            local_paths: vec!["/tmp/source.txt".to_string()],
            remote_directory: "/tmp/target".to_string(),
            package_transfer: false,
        }
    }

    fn persisted(id: &str, status: TransferStatus, updated_at: u64) -> PersistedTransferRecord {
        PersistedTransferRecord {
            transfer_id: id.to_string(),
            kind: "upload".to_string(),
            host: "example.com".to_string(),
            port: 22,
            username: "root".to_string(),
            status,
            phase: "test".to_string(),
            request: Some(request()),
            retry_attempts: 0,
            replay_unsafe: false,
            finalizing: false,
            committed_units: 0,
            created_at: updated_at,
            updated_at,
        }
    }

    fn record(id: &str, status: TransferStatus) -> Arc<TransferRecord> {
        record_from_persisted(persisted(id, status, now_millis())).0
    }

    #[test]
    fn statuses_separate_active_terminal_and_recovery_tasks() {
        assert!(TransferStatus::Queued.is_active());
        assert!(TransferStatus::Running.is_active());
        assert!(TransferStatus::Cancelling.is_active());
        assert!(TransferStatus::Interrupted.requires_recovery());
        assert!(TransferStatus::Completed.is_terminal());
        assert!(TransferStatus::Failed.is_terminal());
        assert!(TransferStatus::Cancelled.is_terminal());
    }

    #[test]
    fn persistence_is_versioned_atomic_and_does_not_store_credentials_or_contents() {
        let root = test_directory("atomic");
        let store = RecoveryStore::new(root.clone());
        store
            .write(vec![persisted("one", TransferStatus::Running, 10)])
            .unwrap();
        let outcome = store.load();
        assert_eq!(outcome.records.len(), 1);
        let directory = root.join(RECOVERY_DIRECTORY_NAME);
        let files = fs::read_dir(&directory)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            files
                .iter()
                .all(|entry| !entry.file_name().to_string_lossy().ends_with(".tmp"))
        );
        let body = fs::read_to_string(files[0].path()).unwrap();
        assert!(body.contains("\"schemaVersion\":1"));
        assert!(!body.contains("credentialRef"));
        assert!(!body.contains("identityFile"));
        assert!(!body.contains("file contents"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_or_truncated_newest_state_falls_back_without_crashing() {
        let root = test_directory("corrupt");
        let store = RecoveryStore::new(root.clone());
        store
            .write(vec![persisted("safe", TransferStatus::Running, 10)])
            .unwrap();
        let directory = root.join(RECOVERY_DIRECTORY_NAME);
        fs::write(
            directory.join("state-00000000000000000999-corrupt.json"),
            b"{\"schemaVersion\":1,",
        )
        .unwrap();
        let outcome = store.load();
        assert_eq!(outcome.records[0].transfer_id, "safe");
        assert!(outcome.warning.is_some());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unsupported_schema_is_ignored_and_cleaned() {
        let root = test_directory("schema");
        let store = RecoveryStore::new(root.clone());
        fs::create_dir_all(&store.directory).unwrap();
        let envelope = PersistedEnvelope {
            schema_version: 99,
            generation: 4,
            written_at: 1,
            records: vec![persisted("old", TransferStatus::Running, 1)],
        };
        fs::write(
            store.directory.join("state-00000000000000000004-old.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
        let outcome = store.load();
        assert!(outcome.records.is_empty());
        assert_eq!(outcome.discarded_records, 1);
        assert!(recovery_snapshot_paths(&store.directory).is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn retention_discards_stale_records_and_bounds_count() {
        let now = now_millis();
        let stale = persisted(
            "stale",
            TransferStatus::Failed,
            now.saturating_sub(RECOVERY_RETENTION_MILLIS + 1),
        );
        let fresh = persisted("fresh", TransferStatus::Completed, now);
        let root = test_directory("retention");
        let store = RecoveryStore::new(root.clone());
        store.write(vec![stale, fresh]).unwrap();
        let manager = TransferManager::load(root.clone());
        assert!(manager.get("stale").is_none());
        assert!(manager.get("fresh").is_some());

        let mut tasks = HashMap::new();
        for index in 0..205 {
            let id = format!("task-{index}");
            tasks.insert(id.clone(), record(&id, TransferStatus::Completed));
            lock(&tasks[&id].runtime).snapshot.updated_at = index;
        }
        prune_terminal_tasks(&mut tasks, MAX_RETAINED_TRANSFERS);
        assert_eq!(tasks.len(), MAX_RETAINED_TRANSFERS);
        assert!(!tasks.contains_key("task-0"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn restart_requires_a_decision_and_never_replays_commit_boundaries() {
        let safe = record_from_persisted(persisted("safe", TransferStatus::Running, 10)).0;
        let safe_runtime = lock(&safe.runtime);
        assert_eq!(safe_runtime.snapshot.status, TransferStatus::Interrupted);
        assert_eq!(
            safe_runtime.snapshot.recovery_state,
            RecoveryState::RetryAvailable
        );
        assert!(safe_runtime.snapshot.can_retry);
        drop(safe_runtime);

        let mut unsafe_record = persisted("unsafe", TransferStatus::Running, 10);
        unsafe_record.replay_unsafe = true;
        unsafe_record.finalizing = true;
        unsafe_record.committed_units = 1;
        let unsafe_record = record_from_persisted(unsafe_record).0;
        let unsafe_runtime = lock(&unsafe_record.runtime);
        assert_eq!(
            unsafe_runtime.snapshot.recovery_state,
            RecoveryState::UnsafeToRetry
        );
        assert!(!unsafe_runtime.snapshot.can_retry);
        assert!(unsafe_runtime.request.is_none());
    }

    #[test]
    fn retry_state_transitions_are_bounded_and_explainable() {
        let item = record("retry", TransferStatus::Failed);
        let mut runtime = lock(&item.runtime);
        runtime.snapshot.retry_attempts = MAX_RETRY_ATTEMPTS - 1;
        set_retry_state(&mut runtime);
        assert_eq!(
            runtime.snapshot.recovery_state,
            RecoveryState::RetryAvailable
        );
        runtime.snapshot.retry_attempts += 1;
        set_retry_state(&mut runtime);
        assert_eq!(
            runtime.snapshot.recovery_state,
            RecoveryState::RetryExhausted
        );
        assert!(!runtime.snapshot.can_retry);
        assert!(
            runtime
                .snapshot
                .recovery_reason
                .as_deref()
                .unwrap()
                .contains("上限")
        );
    }

    #[test]
    fn cancellation_and_finalization_boundaries_remain_distinct() {
        let item = record("boundary", TransferStatus::Running);
        let mut runtime = lock(&item.runtime);
        runtime.cancel_requested = true;
        assert!(!runtime.finalizing);
        runtime.cancel_requested = false;
        runtime.finalizing = true;
        runtime.replay_unsafe = true;
        set_retry_state(&mut runtime);
        assert_eq!(
            runtime.snapshot.recovery_state,
            RecoveryState::UnsafeToRetry
        );
    }

    #[test]
    fn file_operation_recovery_requires_fresh_preview_and_rejects_committed_work() {
        let file_request = TransferRequest::FileOperation {
            request: crate::remote_file_ops::RemoteFileOperationRequest::Move {
                source_paths: vec!["/source/file".to_string()],
                destination_directory: "/destination".to_string(),
                conflict_policy: crate::remote_file_ops::ConflictPolicy::Overwrite,
            },
        };
        let (record, _) = record_from_persisted(PersistedTransferRecord {
            transfer_id: "file-operation-recovery".to_string(),
            kind: "fileOperation".to_string(),
            host: "example.com".to_string(),
            port: 22,
            username: "root".to_string(),
            status: TransferStatus::Running,
            phase: "fileOperation".to_string(),
            request: Some(file_request.clone()),
            retry_attempts: 0,
            replay_unsafe: false,
            finalizing: false,
            committed_units: 0,
            created_at: 1,
            updated_at: 2,
        });
        let manager = TransferManager::empty(
            None,
            RecoveryStoreStatus {
                warning: None,
                loaded_records: 1,
                discarded_records: 0,
                retention_days: 30,
                maximum_records: MAX_RETAINED_TRANSFERS,
                maximum_retry_attempts: MAX_RETRY_ATTEMPTS,
            },
        );
        lock(&manager.inner.tasks).insert("file-operation-recovery".to_string(), record.clone());
        assert_eq!(
            manager
                .recovery_file_operation_request(
                    "file-operation-recovery",
                    "example.com",
                    22,
                    "root",
                )
                .expect("fresh preview request"),
            match file_request {
                TransferRequest::FileOperation { request } => request,
                _ => unreachable!(),
            }
        );

        {
            let mut runtime = lock(&record.runtime);
            runtime.committed_units = 1;
            runtime.replay_unsafe = true;
            set_retry_state(&mut runtime);
        }
        assert!(
            manager
                .recovery_file_operation_request(
                    "file-operation-recovery",
                    "example.com",
                    22,
                    "root",
                )
                .is_err()
        );
    }

    #[test]
    fn pruning_keeps_active_tasks_and_removes_oldest_terminal_records() {
        let active = record("active", TransferStatus::Running);
        let oldest = record("oldest", TransferStatus::Completed);
        let newest = record("newest", TransferStatus::Failed);
        lock(&oldest.runtime).snapshot.updated_at = 10;
        lock(&newest.runtime).snapshot.updated_at = 20;
        let mut tasks = HashMap::from([
            ("active".to_string(), active),
            ("oldest".to_string(), oldest),
            ("newest".to_string(), newest),
        ]);
        prune_terminal_tasks(&mut tasks, 2);
        assert!(tasks.contains_key("active"));
        assert!(!tasks.contains_key("oldest"));
        assert!(tasks.contains_key("newest"));
    }
}

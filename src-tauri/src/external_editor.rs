use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(windows)]
use std::env;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh2::{FileStat, RenameFlags, Sftp};
use tauri::State;

use crate::file_transfer::{ConnectionSpec, connect, validate_connection, validate_remote_path};

const MAX_EDIT_SESSIONS: usize = 16;
const MAX_EDIT_FILE_SIZE: u64 = 64 * 1024 * 1024;
const COPY_BUFFER_SIZE: usize = 128 * 1024;
const MAX_EDITOR_PATH_LENGTH: usize = 4096;
const MAX_EXPORT_PATH_LENGTH: usize = 4096;
const EDIT_RECOVERY_SCHEMA_VERSION: u32 = 1;
const MAX_EDIT_RECOVERY_BYTES: u64 = 128 * 1024;
const EDIT_RECOVERY_RETENTION_MILLIS: u64 = 14 * 24 * 60 * 60 * 1000;
const EDIT_RECOVERY_DIRECTORY: &str = "external-edit-recovery";
const EDIT_SNAPSHOT_PREFIX: &str = "state-";
const EDIT_SNAPSHOT_SUFFIX: &str = ".json";

#[derive(Clone)]
pub(crate) struct ExternalEditorManager {
    sessions: Arc<Mutex<HashMap<String, EditSession>>>,
    recoveries: Arc<Mutex<HashMap<String, PersistedEditSession>>>,
    store: Option<EditRecoveryStore>,
    cache_root: PathBuf,
    recovery_warning: Arc<Mutex<Option<String>>>,
}

#[derive(Clone)]
struct EditSession {
    connection: ConnectionSpec,
    remote_path: String,
    local_path: PathBuf,
    work_dir: PathBuf,
    baseline: RemoteFingerprint,
    created_at: u64,
    updated_at: u64,
    conflict: bool,
    busy: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RemoteFingerprint {
    size: u64,
    modified: Option<u64>,
    permissions: Option<u32>,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalRevision {
    size: u64,
    modified_millis: Option<u64>,
    sha256: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteVersionSummary {
    size: u64,
    modified: Option<u64>,
    permissions: Option<u32>,
}

impl From<&RemoteFingerprint> for RemoteVersionSummary {
    fn from(value: &RemoteFingerprint) -> Self {
        Self {
            size: value.size,
            modified: value.modified,
            permissions: value.permissions,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BeginExternalEditResult {
    session_id: String,
    remote_path: String,
    local_path: String,
    editor_label: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExternalEditStatus {
    session_id: String,
    remote_path: String,
    local_path: String,
    dirty: bool,
    busy: bool,
    local_missing: bool,
    local_size: u64,
    local_modified_millis: Option<u64>,
    local_revision: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SaveExternalEditResult {
    outcome: String,
    remote_version: Option<RemoteVersionSummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReloadExternalEditResult {
    remote_version: RemoteVersionSummary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EditorPlan {
    NotepadPlusPlus(PathBuf),
    VisualStudioCode(PathBuf),
    Custom(PathBuf),
    SystemDefault,
    #[cfg(target_os = "macos")]
    MacApplication(PathBuf),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistedEditSession {
    session_id: String,
    host: String,
    port: u16,
    username: String,
    remote_path: String,
    local_file_name: String,
    baseline: RemoteFingerprint,
    created_at: u64,
    updated_at: u64,
    conflict: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistedEditEnvelope {
    schema_version: u32,
    generation: u64,
    written_at: u64,
    records: Vec<PersistedEditSession>,
}

#[derive(Clone)]
struct EditRecoveryStore {
    directory: PathBuf,
    generation: Arc<AtomicU64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EditRecoverySummary {
    session_id: String,
    host: String,
    port: u16,
    username: String,
    remote_path: String,
    local_file_name: String,
    created_at: u64,
    updated_at: u64,
    conflict: bool,
    state: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EditRecoveryList {
    sessions: Vec<EditRecoverySummary>,
    warning: Option<String>,
    retention_days: u64,
    maximum_sessions: usize,
}

struct OperationGuard {
    manager: ExternalEditorManager,
    session_id: String,
}

impl Default for ExternalEditorManager {
    fn default() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            recoveries: Arc::new(Mutex::new(HashMap::new())),
            store: None,
            cache_root: std::env::temp_dir().join("vpshell-external-edits"),
            recovery_warning: Arc::new(Mutex::new(None)),
        }
    }
}

impl EditRecoveryStore {
    fn new(app_data_directory: PathBuf) -> Self {
        Self {
            directory: app_data_directory.join(EDIT_RECOVERY_DIRECTORY),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    fn load(&self) -> (Vec<PersistedEditSession>, Option<String>) {
        if let Err(error) = fs::create_dir_all(&self.directory) {
            return (
                Vec::new(),
                Some(format!("无法打开编辑恢复存储，重启恢复暂不可用: {error}")),
            );
        }
        let mut candidates = edit_snapshot_paths(&self.directory);
        candidates.sort_by(|left, right| right.0.cmp(&left.0));
        let mut valid = Vec::new();
        let mut invalid = 0_usize;
        let mut maximum_generation = 0_u64;
        for (filename_generation, path) in &candidates {
            maximum_generation = maximum_generation.max(*filename_generation);
            match read_edit_envelope(path) {
                Ok(envelope)
                    if envelope.schema_version == EDIT_RECOVERY_SCHEMA_VERSION
                        && envelope.records.len() <= MAX_EDIT_SESSIONS
                        && envelope
                            .records
                            .iter()
                            .all(|record| validate_persisted_edit(record).is_ok()) =>
                {
                    maximum_generation = maximum_generation.max(envelope.generation);
                    valid.push((path.clone(), envelope));
                }
                Ok(envelope) => {
                    maximum_generation = maximum_generation.max(envelope.generation);
                    invalid += 1;
                }
                Err(_) => invalid += 1,
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
        cleanup_edit_snapshots(&self.directory, &keep);
        (
            records,
            (invalid > 0).then(|| {
                format!("已忽略并清理 {invalid} 个损坏、截断或不受支持的编辑恢复状态文件")
            }),
        )
    }

    fn write(&self, records: Vec<PersistedEditSession>) -> Result<(), String> {
        if records.len() > MAX_EDIT_SESSIONS
            || records
                .iter()
                .any(|record| validate_persisted_edit(record).is_err())
        {
            return Err("编辑恢复记录超过数量或字段安全限制".to_string());
        }
        fs::create_dir_all(&self.directory)
            .map_err(|error| format!("无法创建编辑恢复目录: {error}"))?;
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let envelope = PersistedEditEnvelope {
            schema_version: EDIT_RECOVERY_SCHEMA_VERSION,
            generation,
            written_at: now_millis(),
            records,
        };
        let bytes = serde_json::to_vec(&envelope)
            .map_err(|error| format!("无法编码编辑恢复状态: {error}"))?;
        if bytes.len() as u64 > MAX_EDIT_RECOVERY_BYTES {
            return Err("编辑恢复状态超过 128 KiB 安全上限".to_string());
        }
        let nonce = uuid::Uuid::new_v4();
        let temporary = self
            .directory
            .join(format!(".state-{generation:020}-{nonce}.tmp"));
        let destination = self.directory.join(format!(
            "{EDIT_SNAPSHOT_PREFIX}{generation:020}-{nonce}{EDIT_SNAPSHOT_SUFFIX}"
        ));
        let result: Result<(), String> = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|error| format!("无法创建编辑恢复临时文件: {error}"))?;
            restrict_file_permissions(&temporary)?;
            file.write_all(&bytes)
                .map_err(|error| format!("无法写入编辑恢复状态: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("无法同步编辑恢复状态: {error}"))?;
            drop(file);
            fs::rename(&temporary, &destination)
                .map_err(|error| format!("无法原子提交编辑恢复状态: {error}"))?;
            sync_directory(&self.directory)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        let mut snapshots = edit_snapshot_paths(&self.directory);
        snapshots.sort_by(|left, right| right.0.cmp(&left.0));
        let keep = snapshots
            .iter()
            .take(2)
            .map(|(_, path)| path.clone())
            .collect::<HashSet<_>>();
        cleanup_edit_snapshots(&self.directory, &keep);
        Ok(())
    }
}

fn edit_snapshot_paths(directory: &Path) -> Vec<(u64, PathBuf)> {
    fs::read_dir(directory)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            let generation = name
                .strip_prefix(EDIT_SNAPSHOT_PREFIX)?
                .split('-')
                .next()?
                .parse::<u64>()
                .ok()?;
            name.ends_with(EDIT_SNAPSHOT_SUFFIX)
                .then_some((generation, entry.path()))
        })
        .collect()
}

fn read_edit_envelope(path: &Path) -> Result<PersistedEditEnvelope, String> {
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if metadata.len() > MAX_EDIT_RECOVERY_BYTES {
        return Err("编辑恢复状态超过读取上限".to_string());
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn cleanup_edit_snapshots(directory: &Path, keep: &HashSet<PathBuf>) {
    if let Ok(entries) = fs::read_dir(directory) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !keep.contains(&path)
                && (name.starts_with(EDIT_SNAPSHOT_PREFIX) || name.starts_with(".state-"))
            {
                let _ = fs::remove_file(path);
            }
        }
    }
}

fn validate_persisted_edit(record: &PersistedEditSession) -> Result<(), String> {
    validate_session_id(&record.session_id)?;
    validate_remote_path(&record.remote_path)?;
    validate_connection(&ConnectionSpec {
        host: record.host.clone(),
        port: record.port,
        username: record.username.clone(),
        credential_ref: None,
        identity_file: None,
        identity_passphrase_ref: None,
    })?;
    if record.local_file_name.is_empty()
        || record.local_file_name.len() > 255
        || Path::new(&record.local_file_name)
            .file_name()
            .and_then(|value| value.to_str())
            != Some(record.local_file_name.as_str())
        || record.baseline.sha256.len() != 64
        || !record
            .baseline
            .sha256
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("编辑恢复记录字段无效".to_string());
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("无法同步编辑恢复目录: {error}"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.manager.sessions.lock()
            && let Some(session) = sessions.get_mut(&self.session_id)
        {
            session.busy = false;
        }
    }
}

impl ExternalEditorManager {
    pub(crate) fn load(app_data_directory: PathBuf, app_cache_directory: PathBuf) -> Self {
        let cache_root = app_cache_directory.join("external-edits");
        let mut warning = None;
        if let Err(error) = fs::create_dir_all(&cache_root)
            .and_then(|_| restrict_directory_permissions(&cache_root).map_err(io::Error::other))
        {
            warning = Some(format!("无法准备外部编辑缓存目录: {error}"));
        }
        let store = EditRecoveryStore::new(app_data_directory);
        let (records, load_warning) = store.load();
        if load_warning.is_some() {
            warning = load_warning;
        }
        let now = now_millis();
        let mut recoveries = HashMap::new();
        let mut stale = 0_usize;
        for record in records {
            if now.saturating_sub(record.updated_at) > EDIT_RECOVERY_RETENTION_MILLIS {
                stale += 1;
                remove_managed_work_dir(&cache_root, &record.session_id);
                continue;
            }
            recoveries.insert(record.session_id.clone(), record);
        }
        if stale > 0 {
            let retention_warning = format!("已清理 {stale} 个超过 14 天的外部编辑恢复记录");
            warning = Some(match warning {
                Some(existing) => format!("{existing}；{retention_warning}"),
                None => retention_warning,
            });
        }
        let manager = Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            recoveries: Arc::new(Mutex::new(recoveries)),
            store: Some(store),
            cache_root,
            recovery_warning: Arc::new(Mutex::new(warning)),
        };
        if stale > 0
            && let Err(error) = manager.persist()
        {
            if let Ok(mut warning) = manager.recovery_warning.lock() {
                *warning = Some(format!("清理过期编辑记录后写入状态失败: {error}"));
            }
        }
        manager
    }

    fn lock(&self) -> Result<MutexGuard<'_, HashMap<String, EditSession>>, String> {
        self.sessions
            .lock()
            .map_err(|_| "外部编辑会话状态已损坏".to_string())
    }

    fn lock_recoveries(
        &self,
    ) -> Result<MutexGuard<'_, HashMap<String, PersistedEditSession>>, String> {
        self.recoveries
            .lock()
            .map_err(|_| "外部编辑恢复状态已损坏".to_string())
    }

    fn persist(&self) -> Result<(), String> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let sessions = self.lock()?;
        let recoveries = self.lock_recoveries()?;
        let mut records = sessions
            .iter()
            .map(|(session_id, session)| persisted_from_active_edit(session_id, session))
            .chain(recoveries.values().cloned())
            .collect::<Vec<_>>();
        records.sort_by_key(|record| (record.created_at, record.session_id.clone()));
        store.write(records)
    }

    fn list_recovery(&self) -> Result<EditRecoveryList, String> {
        let active = self.lock()?;
        let recoveries = self.lock_recoveries()?;
        let mut sessions = active
            .iter()
            .map(|(session_id, session)| {
                summary_from_persisted(&persisted_from_active_edit(session_id, session), "active")
            })
            .chain(
                recoveries
                    .values()
                    .map(|record| summary_from_persisted(record, "recovery")),
            )
            .collect::<Vec<_>>();
        sessions.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
        Ok(EditRecoveryList {
            sessions,
            warning: self
                .recovery_warning
                .lock()
                .ok()
                .and_then(|value| value.clone()),
            retention_days: EDIT_RECOVERY_RETENTION_MILLIS / 86_400_000,
            maximum_sessions: MAX_EDIT_SESSIONS,
        })
    }

    fn snapshot(&self, session_id: &str) -> Result<EditSession, String> {
        validate_session_id(session_id)?;
        self.lock()?
            .get(session_id)
            .cloned()
            .ok_or_else(|| "外部编辑会话不存在或已结束".to_string())
    }

    fn checkout(&self, session_id: &str) -> Result<(EditSession, OperationGuard), String> {
        validate_session_id(session_id)?;
        let session = {
            let mut sessions = self.lock()?;
            let session = sessions
                .get_mut(session_id)
                .ok_or_else(|| "外部编辑会话不存在或已结束".to_string())?;
            if session.busy {
                return Err("外部编辑会话正在执行另一项操作".to_string());
            }
            session.busy = true;
            session.clone()
        };
        Ok((
            session,
            OperationGuard {
                manager: self.clone(),
                session_id: session_id.to_string(),
            },
        ))
    }

    fn replace_baseline(
        &self,
        session_id: &str,
        baseline: RemoteFingerprint,
    ) -> Result<(), String> {
        let mut sessions = self.lock()?;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| "外部编辑会话已结束，无法更新基线".to_string())?;
        session.baseline = baseline;
        session.updated_at = now_millis();
        session.conflict = false;
        drop(sessions);
        self.persist()?;
        Ok(())
    }

    fn mark_conflict(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.lock()?;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| "外部编辑会话已结束，无法记录冲突".to_string())?;
        session.conflict = true;
        session.updated_at = now_millis();
        drop(sessions);
        self.persist()
    }
}

fn persisted_from_active_edit(session_id: &str, session: &EditSession) -> PersistedEditSession {
    PersistedEditSession {
        session_id: session_id.to_string(),
        host: session.connection.host.clone(),
        port: session.connection.port,
        username: session.connection.username.clone(),
        remote_path: session.remote_path.clone(),
        local_file_name: session
            .local_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("remote-file.txt")
            .to_string(),
        baseline: session.baseline.clone(),
        created_at: session.created_at,
        updated_at: session.updated_at,
        conflict: session.conflict,
    }
}

fn summary_from_persisted(record: &PersistedEditSession, state: &str) -> EditRecoverySummary {
    EditRecoverySummary {
        session_id: record.session_id.clone(),
        host: record.host.clone(),
        port: record.port,
        username: record.username.clone(),
        remote_path: record.remote_path.clone(),
        local_file_name: record.local_file_name.clone(),
        created_at: record.created_at,
        updated_at: record.updated_at,
        conflict: record.conflict,
        state: state.to_string(),
    }
}

fn remove_managed_work_dir(cache_root: &Path, session_id: &str) {
    if validate_session_id(session_id).is_err() {
        return;
    }
    let path = cache_root.join(session_id);
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() {
            let _ = fs::remove_file(path);
        } else if metadata.is_dir() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

#[tauri::command]
pub(crate) async fn begin_external_edit(
    manager: State<'_, ExternalEditorManager>,
    connection: ConnectionSpec,
    remote_path: String,
    editor_path: String,
) -> Result<BeginExternalEditResult, String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        begin_external_edit_blocking(manager, connection, remote_path, editor_path)
    })
    .await
    .map_err(|error| format!("外部编辑启动任务异常结束: {error}"))?
}

#[tauri::command]
pub(crate) fn list_external_edit_recovery(
    manager: State<'_, ExternalEditorManager>,
) -> Result<EditRecoveryList, String> {
    manager.list_recovery()
}

#[tauri::command]
pub(crate) fn resume_external_edit(
    manager: State<'_, ExternalEditorManager>,
    connection: ConnectionSpec,
    session_id: String,
    editor_path: String,
) -> Result<BeginExternalEditResult, String> {
    validate_connection(&connection)?;
    validate_session_id(&session_id)?;
    let editor = resolve_editor(&editor_path)?;
    let manager = manager.inner().clone();
    let recovery = manager
        .lock_recoveries()?
        .get(&session_id)
        .cloned()
        .ok_or_else(|| "外部编辑恢复记录不存在或已处理".to_string())?;
    if recovery.host != connection.host
        || recovery.port != connection.port
        || recovery.username != connection.username
    {
        return Err("当前连接与编辑恢复记录的主机身份不匹配".to_string());
    }
    if manager.lock()?.len() >= MAX_EDIT_SESSIONS {
        return Err("同时外部编辑的文件不能超过 16 个".to_string());
    }
    let work_dir = manager.cache_root.join(&session_id);
    let local_path = work_dir.join(&recovery.local_file_name);
    validate_managed_local_copy(&manager.cache_root, &session_id, &local_path)?;
    let editor_label = launch_editor(&editor, &local_path)?;
    let session = EditSession {
        connection,
        remote_path: recovery.remote_path.clone(),
        local_path: local_path.clone(),
        work_dir,
        baseline: recovery.baseline,
        created_at: recovery.created_at,
        updated_at: now_millis(),
        conflict: recovery.conflict,
        busy: false,
    };
    manager.lock()?.insert(session_id.clone(), session);
    manager.lock_recoveries()?.remove(&session_id);
    if let Err(error) = manager.persist() {
        if let Some(session) = manager.lock()?.remove(&session_id) {
            manager.lock_recoveries()?.insert(
                session_id.clone(),
                persisted_from_active_edit(&session_id, &session),
            );
        }
        return Err(format!("恢复编辑会话后无法保存状态: {error}"));
    }
    Ok(BeginExternalEditResult {
        session_id,
        remote_path: recovery.remote_path,
        local_path: local_path.display().to_string(),
        editor_label,
    })
}

#[tauri::command]
pub(crate) fn discard_external_edit_recovery(
    manager: State<'_, ExternalEditorManager>,
    session_id: String,
) -> Result<(), String> {
    validate_session_id(&session_id)?;
    let manager = manager.inner().clone();
    if manager.lock()?.contains_key(&session_id) {
        return Err("活动编辑会话必须先结束，不能从恢复中心直接丢弃".to_string());
    }
    if !manager.lock_recoveries()?.contains_key(&session_id) {
        return Err("外部编辑恢复记录不存在或已处理".to_string());
    }
    remove_managed_work_dir(&manager.cache_root, &session_id);
    manager.lock_recoveries()?.remove(&session_id);
    manager.persist()
}

#[tauri::command]
pub(crate) async fn export_external_edit_copy(
    manager: State<'_, ExternalEditorManager>,
    session_id: String,
    destination: String,
) -> Result<String, String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        validate_session_id(&session_id)?;
        let local_path = if let Some(session) = manager.lock()?.get(&session_id) {
            session.local_path.clone()
        } else {
            let recovery = manager
                .lock_recoveries()?
                .get(&session_id)
                .cloned()
                .ok_or_else(|| "外部编辑会话或恢复记录不存在".to_string())?;
            manager
                .cache_root
                .join(&session_id)
                .join(recovery.local_file_name)
        };
        validate_managed_local_copy(&manager.cache_root, &session_id, &local_path)?;
        let destination = validate_export_destination(&destination)?;
        export_local_copy(&local_path, &destination)?;
        Ok(destination.display().to_string())
    })
    .await
    .map_err(|error| format!("另存编辑副本的任务异常结束: {error}"))?
}

#[tauri::command]
pub(crate) async fn get_external_edit_status(
    manager: State<'_, ExternalEditorManager>,
    session_id: String,
) -> Result<ExternalEditStatus, String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let session = manager.snapshot(&session_id)?;
        match local_revision(&session.local_path) {
            Ok(revision) => Ok(ExternalEditStatus {
                session_id,
                remote_path: session.remote_path,
                local_path: session.local_path.display().to_string(),
                dirty: revision.sha256 != session.baseline.sha256,
                busy: session.busy,
                local_missing: false,
                local_size: revision.size,
                local_modified_millis: revision.modified_millis,
                local_revision: revision.sha256,
            }),
            Err(_error) if !session.local_path.exists() => Ok(ExternalEditStatus {
                session_id,
                remote_path: session.remote_path,
                local_path: session.local_path.display().to_string(),
                dirty: true,
                busy: session.busy,
                local_missing: true,
                local_size: 0,
                local_modified_millis: None,
                local_revision: String::new(),
            }),
            Err(error) => Err(error),
        }
    })
    .await
    .map_err(|error| format!("读取外部编辑状态的任务异常结束: {error}"))?
}

#[tauri::command]
pub(crate) async fn save_external_edit(
    manager: State<'_, ExternalEditorManager>,
    session_id: String,
    force: bool,
) -> Result<SaveExternalEditResult, String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        save_external_edit_blocking(manager, session_id, force)
    })
    .await
    .map_err(|error| format!("外部编辑回传任务异常结束: {error}"))?
}

#[tauri::command]
pub(crate) async fn reload_external_edit(
    manager: State<'_, ExternalEditorManager>,
    session_id: String,
) -> Result<ReloadExternalEditResult, String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || reload_external_edit_blocking(manager, session_id))
        .await
        .map_err(|error| format!("重新下载远端文件的任务异常结束: {error}"))?
}

#[tauri::command]
pub(crate) async fn end_external_edit(
    manager: State<'_, ExternalEditorManager>,
    session_id: String,
) -> Result<(), String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || end_external_edit_blocking(manager, session_id))
        .await
        .map_err(|error| format!("结束外部编辑会话的任务异常结束: {error}"))?
}

fn begin_external_edit_blocking(
    manager: ExternalEditorManager,
    connection: ConnectionSpec,
    remote_path: String,
    editor_path: String,
) -> Result<BeginExternalEditResult, String> {
    validate_connection(&connection)?;
    validate_remote_path(&remote_path)?;
    let editor = resolve_editor(&editor_path)?;
    if manager.lock()?.len() >= MAX_EDIT_SESSIONS {
        return Err("同时外部编辑的文件不能超过 16 个".to_string());
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let cache_root = manager.cache_root.clone();
    fs::create_dir_all(&cache_root)
        .map_err(|error| format!("无法创建外部编辑缓存根目录: {error}"))?;
    restrict_directory_permissions(&cache_root)?;
    let work_dir = cache_root.join(&session_id);
    fs::create_dir_all(&work_dir).map_err(|error| format!("无法创建外部编辑缓存目录: {error}"))?;
    restrict_directory_permissions(&work_dir)?;

    let result = (|| {
        let session = connect(&connection)?;
        let sftp = session
            .sftp()
            .map_err(|_| "无法建立外部编辑所需的 SFTP 子系统".to_string())?;
        let canonical_path = canonical_edit_path(&sftp, &remote_path)?;
        let local_path = work_dir.join(safe_local_filename(&canonical_path)?);
        let staging_path = work_dir.join(format!(".download-{}.part", uuid::Uuid::new_v4()));
        let downloaded = download_to_staging(&sftp, &canonical_path, &staging_path)?;
        let current = remote_fingerprint(&sftp, &canonical_path)?
            .ok_or_else(|| "远端文件在下载过程中被删除，请重试".to_string())?;
        if downloaded.size != current.size || downloaded.sha256 != current.sha256 {
            return Err("远端文件在下载过程中发生变化，已拒绝打开不一致副本".to_string());
        }
        commit_local_staging(&staging_path, &local_path, false)?;

        let edit_session = EditSession {
            connection,
            remote_path: canonical_path.clone(),
            local_path: local_path.clone(),
            work_dir: work_dir.clone(),
            baseline: current,
            created_at: now_millis(),
            updated_at: now_millis(),
            conflict: false,
            busy: false,
        };
        {
            let mut sessions = manager.lock()?;
            if sessions.len() >= MAX_EDIT_SESSIONS {
                return Err("同时外部编辑的文件不能超过 16 个".to_string());
            }
            sessions.insert(session_id.clone(), edit_session);
        }

        if let Err(error) = manager.persist() {
            let _ = manager
                .lock()
                .map(|mut sessions| sessions.remove(&session_id));
            return Err(format!("无法保存外部编辑恢复记录: {error}"));
        }

        let editor_label = match launch_editor(&editor, &local_path) {
            Ok(label) => label,
            Err(error) => {
                let _ = manager
                    .lock()
                    .map(|mut sessions| sessions.remove(&session_id));
                let _ = manager.persist();
                return Err(error);
            }
        };
        Ok(BeginExternalEditResult {
            session_id: session_id.clone(),
            remote_path: canonical_path,
            local_path: local_path.display().to_string(),
            editor_label,
        })
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(&work_dir);
    }
    result
}

fn save_external_edit_blocking(
    manager: ExternalEditorManager,
    session_id: String,
    force: bool,
) -> Result<SaveExternalEditResult, String> {
    let (edit, _operation) = manager.checkout(&session_id)?;
    let local = local_revision(&edit.local_path)?;
    if local.sha256 == edit.baseline.sha256 {
        return Ok(SaveExternalEditResult {
            outcome: "unchanged".to_string(),
            remote_version: Some((&edit.baseline).into()),
        });
    }

    validate_connection(&edit.connection)?;
    let session = connect(&edit.connection)?;
    let sftp = session
        .sftp()
        .map_err(|_| "无法建立外部编辑回传所需的 SFTP 子系统".to_string())?;
    let current = remote_fingerprint(&sftp, &edit.remote_path)?;
    if !force && version_conflicts(&edit.baseline, current.as_ref()) {
        manager.mark_conflict(&session_id)?;
        return Ok(SaveExternalEditResult {
            outcome: "conflict".to_string(),
            remote_version: current.as_ref().map(Into::into),
        });
    }

    let part_path = format!(
        "{}.vpshell-edit-{}.part",
        edit.remote_path,
        uuid::Uuid::new_v4()
    );
    validate_remote_path(&part_path)?;
    let permissions = current
        .as_ref()
        .and_then(|version| version.permissions)
        .or(edit.baseline.permissions);
    let upload_result = (|| {
        upload_local_to_remote_part(&sftp, &edit.local_path, &part_path, &local, permissions)?;

        let latest = remote_fingerprint(&sftp, &edit.remote_path)?;
        if !force && version_conflicts(&edit.baseline, latest.as_ref()) {
            manager.mark_conflict(&session_id)?;
            return Ok(SaveExternalEditResult {
                outcome: "conflict".to_string(),
                remote_version: latest.as_ref().map(Into::into),
            });
        }

        sftp.rename(
            Path::new(&part_path),
            Path::new(&edit.remote_path),
            Some(RenameFlags::ATOMIC | RenameFlags::OVERWRITE | RenameFlags::NATIVE),
        )
        .map_err(|error| format!("远端服务器无法原子提交编辑结果: {error}"))?;

        let committed = remote_fingerprint(&sftp, &edit.remote_path)?
            .ok_or_else(|| "编辑结果提交后远端文件不可见".to_string())?;
        if committed.size != local.size || committed.sha256 != local.sha256 {
            return Err("编辑结果已提交，但回读校验失败；请立即检查远端文件".to_string());
        }
        manager.replace_baseline(&session_id, committed.clone())?;
        Ok(SaveExternalEditResult {
            outcome: "saved".to_string(),
            remote_version: Some((&committed).into()),
        })
    })();
    if !matches!(&upload_result, Ok(result) if result.outcome == "saved") {
        let _ = sftp.unlink(Path::new(&part_path));
    }
    upload_result
}

fn reload_external_edit_blocking(
    manager: ExternalEditorManager,
    session_id: String,
) -> Result<ReloadExternalEditResult, String> {
    let (edit, _operation) = manager.checkout(&session_id)?;
    validate_connection(&edit.connection)?;
    let session = connect(&edit.connection)?;
    let sftp = session
        .sftp()
        .map_err(|_| "无法建立重新下载所需的 SFTP 子系统".to_string())?;
    let staging_path = edit
        .work_dir
        .join(format!(".reload-{}.part", uuid::Uuid::new_v4()));
    let downloaded = download_to_staging(&sftp, &edit.remote_path, &staging_path)?;
    let current = remote_fingerprint(&sftp, &edit.remote_path)?
        .ok_or_else(|| "远端文件已被删除，无法重新下载".to_string())?;
    if downloaded.size != current.size || downloaded.sha256 != current.sha256 {
        let _ = fs::remove_file(&staging_path);
        return Err("远端文件在重新下载过程中发生变化，请重试".to_string());
    }
    commit_local_staging(&staging_path, &edit.local_path, true)?;
    manager.replace_baseline(&session_id, current.clone())?;
    Ok(ReloadExternalEditResult {
        remote_version: (&current).into(),
    })
}

fn end_external_edit_blocking(
    manager: ExternalEditorManager,
    session_id: String,
) -> Result<(), String> {
    validate_session_id(&session_id)?;
    let edit = {
        let mut sessions = manager.lock()?;
        let current = sessions
            .get(&session_id)
            .ok_or_else(|| "外部编辑会话不存在或已结束".to_string())?;
        if current.busy {
            return Err("外部编辑会话仍在保存或重新下载，请稍后再结束".to_string());
        }
        sessions
            .remove(&session_id)
            .ok_or_else(|| "外部编辑会话不存在或已结束".to_string())?
    };
    match fs::remove_dir_all(&edit.work_dir) {
        Ok(()) if !edit.work_dir.exists() => manager.persist(),
        Ok(()) => Err("外部编辑缓存目录仍然存在，请关闭编辑器后重试".to_string()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => manager.persist(),
        Err(error) => {
            manager.lock()?.insert(session_id, edit);
            Err(format!("无法清理外部编辑缓存；请先关闭编辑器: {error}"))
        }
    }
}

fn canonical_edit_path(sftp: &Sftp, requested: &str) -> Result<String, String> {
    validate_remote_path(requested)?;
    let requested_stat = sftp
        .lstat(Path::new(requested))
        .map_err(|error| format!("无法读取远端文件: {error}"))?;
    if requested_stat.file_type().is_symlink() {
        return Err("安全模式不允许通过符号链接打开外部编辑".to_string());
    }
    if !requested_stat.is_file() {
        return Err("只有远端普通文件可以使用外部编辑器".to_string());
    }
    let canonical = sftp
        .realpath(Path::new(requested))
        .map_err(|error| format!("无法解析远端文件路径: {error}"))?;
    let canonical = canonical
        .to_str()
        .ok_or_else(|| "远端文件路径不是有效的 UTF-8".to_string())?
        .replace('\\', "/");
    validate_remote_path(&canonical)?;
    Ok(canonical)
}

fn remote_fingerprint(sftp: &Sftp, path: &str) -> Result<Option<RemoteFingerprint>, String> {
    validate_remote_path(path)?;
    let before = match sftp.lstat(Path::new(path)) {
        Ok(stat) => stat,
        Err(error) => {
            let message = error.to_string();
            let io_error: io::Error = error.into();
            if io_error.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(format!("无法读取远端文件版本: {message}"));
        }
    };
    validate_remote_regular_file(&before)?;
    let before_meta = remote_metadata(&before)?;
    let (size, sha256) = hash_remote_file(sftp, path)?;
    let after = sftp
        .lstat(Path::new(path))
        .map_err(|error| format!("校验期间远端文件变得不可访问: {error}"))?;
    validate_remote_regular_file(&after)?;
    let after_meta = remote_metadata(&after)?;
    if before_meta != after_meta || size != after_meta.0 {
        return Err("校验期间远端文件发生变化，请重试".to_string());
    }
    Ok(Some(RemoteFingerprint {
        size,
        modified: after_meta.1,
        permissions: after_meta.2,
        sha256,
    }))
}

fn remote_metadata(stat: &FileStat) -> Result<(u64, Option<u64>, Option<u32>), String> {
    let size = stat
        .size
        .ok_or_else(|| "SFTP 服务器未返回远端文件大小".to_string())?;
    if size > MAX_EDIT_FILE_SIZE {
        return Err("外部编辑仅支持不超过 64 MB 的普通文件".to_string());
    }
    Ok((size, stat.mtime, stat.perm.map(|mode| mode & 0o7777)))
}

fn validate_remote_regular_file(stat: &FileStat) -> Result<(), String> {
    if stat.file_type().is_symlink() {
        return Err("安全模式拒绝编辑远端符号链接".to_string());
    }
    if !stat.is_file() {
        return Err("远端目标不再是普通文件".to_string());
    }
    Ok(())
}

fn hash_remote_file(sftp: &Sftp, path: &str) -> Result<(u64, String), String> {
    let mut input = sftp
        .open(Path::new(path))
        .map_err(|error| format!("无法打开远端文件进行校验: {error}"))?;
    hash_reader(&mut input, "读取远端文件进行校验失败")
}

fn download_to_staging(
    sftp: &Sftp,
    remote_path: &str,
    staging_path: &Path,
) -> Result<LocalRevision, String> {
    let stat = sftp
        .lstat(Path::new(remote_path))
        .map_err(|error| format!("无法读取远端编辑文件: {error}"))?;
    validate_remote_regular_file(&stat)?;
    let (expected_size, _, _) = remote_metadata(&stat)?;
    let result = (|| {
        let mut input = sftp
            .open(Path::new(remote_path))
            .map_err(|error| format!("无法打开远端编辑文件: {error}"))?;
        let mut output = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(staging_path)
            .map_err(|error| format!("无法创建本机编辑临时文件: {error}"))?;
        restrict_file_permissions(staging_path)?;
        let mut hasher = Sha256::new();
        let mut size = 0_u64;
        let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
        loop {
            let length = input
                .read(&mut buffer)
                .map_err(|error| format!("下载远端编辑文件失败: {error}"))?;
            if length == 0 {
                break;
            }
            size = size.saturating_add(length as u64);
            if size > MAX_EDIT_FILE_SIZE {
                return Err("远端文件在下载时超过 64 MB 限制".to_string());
            }
            hasher.update(&buffer[..length]);
            output
                .write_all(&buffer[..length])
                .map_err(|error| format!("写入本机编辑临时文件失败: {error}"))?;
        }
        output
            .flush()
            .map_err(|error| format!("刷新本机编辑临时文件失败: {error}"))?;
        output
            .sync_all()
            .map_err(|error| format!("同步本机编辑临时文件失败: {error}"))?;
        if size != expected_size {
            return Err("下载的编辑文件大小与远端版本不一致".to_string());
        }
        Ok(LocalRevision {
            size,
            modified_millis: file_modified_millis(staging_path),
            sha256: format!("{:x}", hasher.finalize()),
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(staging_path);
    }
    result
}

fn upload_local_to_remote_part(
    sftp: &Sftp,
    local_path: &Path,
    remote_part: &str,
    expected: &LocalRevision,
    permissions: Option<u32>,
) -> Result<(), String> {
    let result = (|| {
        let mut input =
            fs::File::open(local_path).map_err(|error| format!("无法打开本机编辑文件: {error}"))?;
        let mut output = sftp
            .create(Path::new(remote_part))
            .map_err(|error| format!("无法创建远端编辑临时文件: {error}"))?;
        io::copy(&mut input, &mut output).map_err(|error| format!("回传编辑文件失败: {error}"))?;
        output
            .flush()
            .map_err(|error| format!("刷新远端编辑临时文件失败: {error}"))?;
        drop(output);

        if let Some(permissions) = permissions {
            sftp.setstat(
                Path::new(remote_part),
                FileStat {
                    size: None,
                    uid: None,
                    gid: None,
                    perm: Some(permissions),
                    atime: None,
                    mtime: None,
                },
            )
            .map_err(|error| format!("无法保留远端文件权限: {error}"))?;
        }
        let uploaded = remote_fingerprint(sftp, remote_part)?
            .ok_or_else(|| "远端编辑临时文件写入后不可见".to_string())?;
        if uploaded.size != expected.size || uploaded.sha256 != expected.sha256 {
            return Err("远端编辑临时文件校验失败，未提交".to_string());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = sftp.unlink(Path::new(remote_part));
    }
    result
}

fn local_revision(path: &Path) -> Result<LocalRevision, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("无法读取本机编辑文件: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("本机编辑副本不再是普通文件，已拒绝回传".to_string());
    }
    if metadata.len() > MAX_EDIT_FILE_SIZE {
        return Err("编辑后的文件超过 64 MB，已拒绝回传".to_string());
    }
    let mut input =
        fs::File::open(path).map_err(|error| format!("无法打开本机编辑文件进行校验: {error}"))?;
    let (size, sha256) = hash_reader(&mut input, "读取本机编辑文件失败")?;
    Ok(LocalRevision {
        size,
        modified_millis: file_modified_millis(path),
        sha256,
    })
}

fn validate_managed_local_copy(
    cache_root: &Path,
    session_id: &str,
    local_path: &Path,
) -> Result<LocalRevision, String> {
    validate_session_id(session_id)?;
    let expected_work_dir = cache_root.join(session_id);
    if local_path.parent() != Some(expected_work_dir.as_path()) {
        return Err("编辑恢复文件不在受管缓存目录中".to_string());
    }
    let work_metadata = fs::symlink_metadata(&expected_work_dir)
        .map_err(|error| format!("编辑恢复缓存目录不可用: {error}"))?;
    if work_metadata.file_type().is_symlink() || !work_metadata.is_dir() {
        return Err("编辑恢复缓存目录类型不安全".to_string());
    }
    local_revision(local_path)
}

fn validate_export_destination(destination: &str) -> Result<PathBuf, String> {
    if destination.is_empty()
        || destination.len() > MAX_EXPORT_PATH_LENGTH
        || destination.chars().any(char::is_control)
    {
        return Err("另存目标路径无效或过长".to_string());
    }
    let path = PathBuf::from(destination);
    if !path.is_absolute() || path.file_name().is_none() {
        return Err("另存目标必须是绝对文件路径".to_string());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "另存目标缺少父目录".to_string())?;
    if !parent.is_dir() {
        return Err("另存目标父目录不存在".to_string());
    }
    Ok(path)
}

fn export_local_copy(source: &Path, destination: &Path) -> Result<(), String> {
    let before = local_revision(source)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|error| format!("无法创建另存副本；不会覆盖已有文件: {error}"))?;
    let result = (|| {
        let mut input =
            fs::File::open(source).map_err(|error| format!("无法读取本地编辑副本: {error}"))?;
        let copied = io::copy(&mut input, &mut output)
            .map_err(|error| format!("另存本地编辑副本失败: {error}"))?;
        if copied != before.size || copied > MAX_EDIT_FILE_SIZE {
            return Err("另存副本大小超过限制或在复制时发生变化".to_string());
        }
        output
            .flush()
            .and_then(|_| output.sync_all())
            .map_err(|error| format!("同步另存副本失败: {error}"))?;
        drop(output);
        let after = local_revision(source)?;
        if after.size != before.size || after.sha256 != before.sha256 {
            return Err("本地编辑副本在另存过程中发生变化，请重试".to_string());
        }
        let exported = local_revision(destination)?;
        if exported.size != before.size || exported.sha256 != before.sha256 {
            return Err("另存副本校验失败，未保留目标文件".to_string());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

fn hash_reader<R: Read>(reader: &mut R, error_prefix: &str) -> Result<(u64, String), String> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    loop {
        let length = reader
            .read(&mut buffer)
            .map_err(|error| format!("{error_prefix}: {error}"))?;
        if length == 0 {
            break;
        }
        size = size.saturating_add(length as u64);
        if size > MAX_EDIT_FILE_SIZE {
            return Err("外部编辑文件超过 64 MB 限制".to_string());
        }
        hasher.update(&buffer[..length]);
    }
    Ok((size, format!("{:x}", hasher.finalize())))
}

fn commit_local_staging(staging: &Path, destination: &Path, replace: bool) -> Result<(), String> {
    if !replace || !destination.exists() {
        return fs::rename(staging, destination)
            .map_err(|error| format!("无法提交本机编辑副本: {error}"));
    }

    #[cfg(not(windows))]
    {
        fs::rename(staging, destination).map_err(|error| format!("无法替换本机编辑副本: {error}"))
    }

    #[cfg(windows)]
    {
        let backup =
            destination.with_file_name(format!(".edit-backup-{}.tmp", uuid::Uuid::new_v4()));
        fs::rename(destination, &backup)
            .map_err(|error| format!("无法暂存旧的本机编辑副本，请关闭编辑器后重试: {error}"))?;
        match fs::rename(staging, destination) {
            Ok(()) => {
                let _ = fs::remove_file(backup);
                Ok(())
            }
            Err(error) => {
                let _ = fs::rename(&backup, destination);
                Err(format!("无法替换本机编辑副本: {error}"))
            }
        }
    }
}

fn version_conflicts(baseline: &RemoteFingerprint, current: Option<&RemoteFingerprint>) -> bool {
    current != Some(baseline)
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.len() != 36
        || !session_id
            .chars()
            .all(|value| value.is_ascii_hexdigit() || value == '-')
    {
        return Err("外部编辑会话 ID 无效".to_string());
    }
    Ok(())
}

fn safe_local_filename(remote_path: &str) -> Result<String, String> {
    let basename = remote_path
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty() && !matches!(*value, "." | ".."))
        .ok_or_else(|| "远端编辑文件缺少有效文件名".to_string())?;
    let sanitized: String = basename
        .chars()
        .take(120)
        .map(|value| {
            if value.is_ascii_alphanumeric() || matches!(value, '.' | '-' | '_') {
                value
            } else {
                '_'
            }
        })
        .collect();
    let sanitized = sanitized.trim_matches('.');
    if sanitized.is_empty() {
        Ok("remote-file.txt".to_string())
    } else {
        Ok(format!("remote-{sanitized}"))
    }
}

fn resolve_editor(configured: &str) -> Result<EditorPlan, String> {
    let configured = configured.trim();
    if configured.is_empty() {
        return Ok(default_editor_plan());
    }
    if configured.len() > MAX_EDITOR_PATH_LENGTH
        || configured.contains('\0')
        || configured.chars().any(|value| matches!(value, '\r' | '\n'))
    {
        return Err("外部编辑器路径无效或过长".to_string());
    }
    let path = PathBuf::from(configured);
    if !path.is_absolute() {
        return Err("外部编辑器必须配置为绝对路径".to_string());
    }

    #[cfg(target_os = "macos")]
    if path.is_dir()
        && path
            .extension()
            .is_some_and(|value| value.eq_ignore_ascii_case("app"))
    {
        return Ok(EditorPlan::MacApplication(path));
    }

    if !path.is_file() {
        return Err("设置中的外部编辑器不存在或不是普通文件".to_string());
    }

    #[cfg(windows)]
    if !path
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
    {
        return Err("Windows 外部编辑器必须是 .exe 文件".to_string());
    }
    Ok(classify_direct_editor(path))
}

fn classify_direct_editor(path: PathBuf) -> EditorPlan {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(name.as_str(), "notepad++.exe" | "notepad++") {
        EditorPlan::NotepadPlusPlus(path)
    } else if matches!(
        name.as_str(),
        "code"
            | "code.exe"
            | "code-insiders"
            | "code-insiders.exe"
            | "codium"
            | "codium.exe"
            | "vscodium"
            | "vscodium.exe"
    ) {
        EditorPlan::VisualStudioCode(path)
    } else {
        EditorPlan::Custom(path)
    }
}

fn default_editor_plan() -> EditorPlan {
    #[cfg(windows)]
    if let Some(program_files) = env::var_os("ProgramFiles") {
        let notepad_plus_plus = PathBuf::from(program_files)
            .join("Notepad++")
            .join("notepad++.exe");
        if notepad_plus_plus.is_file() {
            return EditorPlan::NotepadPlusPlus(notepad_plus_plus);
        }
    }
    EditorPlan::SystemDefault
}

fn launch_editor(editor: &EditorPlan, local_path: &Path) -> Result<String, String> {
    match editor {
        EditorPlan::NotepadPlusPlus(executable) => {
            spawn_detached(
                Command::new(executable)
                    .arg("-multiInst")
                    .arg("-nosession")
                    .arg(local_path),
            )?;
            Ok("Notepad++".to_string())
        }
        EditorPlan::VisualStudioCode(executable) => {
            spawn_detached(
                Command::new(executable)
                    .arg("--reuse-window")
                    .arg(local_path),
            )?;
            Ok("Visual Studio Code".to_string())
        }
        EditorPlan::Custom(executable) => {
            spawn_detached(Command::new(executable).arg(local_path))?;
            Ok(executable
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("外部编辑器")
                .to_string())
        }
        EditorPlan::SystemDefault => launch_system_editor(local_path),
        #[cfg(target_os = "macos")]
        EditorPlan::MacApplication(application) => {
            spawn_detached(
                Command::new("open")
                    .arg("-a")
                    .arg(application)
                    .arg(local_path),
            )?;
            Ok(application
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("macOS 应用")
                .to_string())
        }
    }
}

#[cfg(windows)]
fn launch_system_editor(local_path: &Path) -> Result<String, String> {
    spawn_detached(Command::new("notepad.exe").arg(local_path))?;
    Ok("Windows 记事本".to_string())
}

#[cfg(target_os = "macos")]
fn launch_system_editor(local_path: &Path) -> Result<String, String> {
    spawn_detached(Command::new("open").arg(local_path))?;
    Ok("macOS 默认编辑器".to_string())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn launch_system_editor(local_path: &Path) -> Result<String, String> {
    spawn_detached(Command::new("xdg-open").arg(local_path))?;
    Ok("系统默认编辑器".to_string())
}

#[cfg(not(any(windows, unix)))]
fn launch_system_editor(_local_path: &Path) -> Result<String, String> {
    Err("当前平台没有可用的默认外部编辑器".to_string())
}

fn spawn_detached(command: &mut Command) -> Result<(), String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("无法启动外部编辑器: {error}"))
}

fn file_modified_millis(path: &Path) -> Option<u64> {
    fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}

#[cfg(unix)]
fn restrict_directory_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("无法限制外部编辑缓存目录权限: {error}"))
}

#[cfg(not(unix))]
fn restrict_directory_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("无法限制外部编辑临时文件权限: {error}"))
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(sha256: &str) -> RemoteFingerprint {
        RemoteFingerprint {
            size: 12,
            modified: Some(100),
            permissions: Some(0o644),
            sha256: sha256.to_string(),
        }
    }

    #[test]
    fn sanitizes_remote_filename_for_managed_cache() {
        assert_eq!(
            safe_local_filename("/etc/a:b*?.conf").unwrap(),
            "remote-a_b__.conf"
        );
        assert_eq!(
            safe_local_filename("/").unwrap_err(),
            "远端编辑文件缺少有效文件名"
        );
    }

    #[test]
    fn validates_uuid_shaped_session_ids() {
        assert!(validate_session_id("8d4147a2-3bd4-4b67-a077-8ec7daf253b0").is_ok());
        assert!(validate_session_id("../external-edits").is_err());
        assert!(validate_session_id("-bad-command-option----------------").is_err());
    }

    #[test]
    fn detects_content_and_metadata_conflicts() {
        let baseline = fingerprint("aaa");
        assert!(!version_conflicts(&baseline, Some(&baseline)));
        assert!(version_conflicts(&baseline, None));

        let mut changed_content = baseline.clone();
        changed_content.sha256 = "bbb".to_string();
        assert!(version_conflicts(&baseline, Some(&changed_content)));

        let mut changed_permissions = baseline.clone();
        changed_permissions.permissions = Some(0o600);
        assert!(version_conflicts(&baseline, Some(&changed_permissions)));
    }

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vpshell-edit-{label}-{}", uuid::Uuid::new_v4()))
    }

    fn persisted(session_id: &str, updated_at: u64) -> PersistedEditSession {
        PersistedEditSession {
            session_id: session_id.to_string(),
            host: "203.0.113.20".to_string(),
            port: 22,
            username: "ops".to_string(),
            remote_path: "/etc/example.conf".to_string(),
            local_file_name: "remote-example.conf".to_string(),
            baseline: RemoteFingerprint {
                size: 12,
                modified: Some(100),
                permissions: Some(0o644),
                sha256: "a".repeat(64),
            },
            created_at: updated_at,
            updated_at,
            conflict: false,
        }
    }

    #[test]
    fn recovery_store_is_atomic_bounded_and_contains_no_secret_fields() {
        let root = test_root("atomic");
        let store = EditRecoveryStore::new(root.clone());
        let record = persisted("8d4147a2-3bd4-4b67-a077-8ec7daf253b0", now_millis());
        store.write(vec![record]).unwrap();
        let snapshots = edit_snapshot_paths(&store.directory);
        assert_eq!(snapshots.len(), 1);
        let text = fs::read_to_string(&snapshots[0].1).unwrap();
        assert!(text.contains("\"schemaVersion\":1"));
        for forbidden in [
            "credentialRef",
            "identityFile",
            "identityPassphraseRef",
            "editorPath",
            "password",
            "privateKey",
        ] {
            assert!(!text.contains(forbidden));
        }
        assert!(fs::metadata(&snapshots[0].1).unwrap().len() <= MAX_EDIT_RECOVERY_BYTES);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_newest_recovery_snapshot_falls_back_without_crashing() {
        let root = test_root("corrupt");
        let store = EditRecoveryStore::new(root.clone());
        store
            .write(vec![persisted(
                "8d4147a2-3bd4-4b67-a077-8ec7daf253b0",
                now_millis(),
            )])
            .unwrap();
        store
            .write(vec![persisted(
                "7c3036a1-2ac3-4a56-b166-7db6c9e142a1",
                now_millis(),
            )])
            .unwrap();
        let mut snapshots = edit_snapshot_paths(&store.directory);
        snapshots.sort_by(|left, right| right.0.cmp(&left.0));
        fs::write(&snapshots[0].1, b"{truncated").unwrap();

        let (records, warning) = store.load();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].session_id,
            "8d4147a2-3bd4-4b67-a077-8ec7daf253b0"
        );
        assert!(warning.unwrap().contains("损坏、截断"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unsupported_recovery_schema_and_excess_records_are_rejected() {
        let root = test_root("schema");
        let store = EditRecoveryStore::new(root.clone());
        store
            .write(vec![persisted(
                "8d4147a2-3bd4-4b67-a077-8ec7daf253b0",
                now_millis(),
            )])
            .unwrap();
        let snapshot = edit_snapshot_paths(&store.directory).remove(0).1;
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&snapshot).unwrap()).unwrap();
        envelope["schemaVersion"] = serde_json::Value::from(99);
        fs::write(&snapshot, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let (records, warning) = store.load();
        assert!(records.is_empty());
        assert!(warning.unwrap().contains("不受支持"));

        let too_many = (0..=MAX_EDIT_SESSIONS)
            .map(|_| persisted(&uuid::Uuid::new_v4().to_string(), now_millis()))
            .collect();
        assert!(store.write(too_many).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn recovery_load_prunes_stale_records_and_managed_cache() {
        let root = test_root("retention");
        let data = root.join("data");
        let cache = root.join("cache");
        let stale_id = "8d4147a2-3bd4-4b67-a077-8ec7daf253b0";
        let fresh_id = "7c3036a1-2ac3-4a56-b166-7db6c9e142a1";
        let stale_dir = cache.join("external-edits").join(stale_id);
        fs::create_dir_all(&stale_dir).unwrap();
        fs::write(stale_dir.join("remote-example.conf"), b"stale").unwrap();
        let store = EditRecoveryStore::new(data.clone());
        store
            .write(vec![
                persisted(
                    stale_id,
                    now_millis().saturating_sub(EDIT_RECOVERY_RETENTION_MILLIS + 1),
                ),
                persisted(fresh_id, now_millis()),
            ])
            .unwrap();

        let manager = ExternalEditorManager::load(data, cache);
        let list = manager.list_recovery().unwrap();
        assert_eq!(list.sessions.len(), 1);
        assert_eq!(list.sessions[0].session_id, fresh_id);
        assert!(!stale_dir.exists());
        assert!(list.warning.unwrap().contains("超过 14 天"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn editor_adapters_are_structured_by_known_executable_name() {
        assert!(matches!(
            classify_direct_editor(PathBuf::from("/apps/notepad++.exe")),
            EditorPlan::NotepadPlusPlus(_)
        ));
        for name in ["code", "code.exe", "code-insiders", "VSCodium.exe"] {
            assert!(matches!(
                classify_direct_editor(PathBuf::from(format!("/apps/{name}"))),
                EditorPlan::VisualStudioCode(_)
            ));
        }
        assert!(matches!(
            classify_direct_editor(PathBuf::from("/apps/my-editor")),
            EditorPlan::Custom(_)
        ));
        assert!(
            launch_editor(
                &EditorPlan::Custom(PathBuf::from("/definitely/missing/vpshell-editor")),
                Path::new("/tmp/file.txt")
            )
            .is_err()
        );
    }

    #[test]
    fn persisted_records_reject_paths_and_unbounded_hashes() {
        let mut record = persisted("8d4147a2-3bd4-4b67-a077-8ec7daf253b0", now_millis());
        assert!(validate_persisted_edit(&record).is_ok());
        record.local_file_name = "../outside".to_string();
        assert!(validate_persisted_edit(&record).is_err());
        record.local_file_name = "remote-example.conf".to_string();
        record.baseline.sha256 = "not-a-sha256".to_string();
        assert!(validate_persisted_edit(&record).is_err());
    }

    #[test]
    fn local_export_is_verified_and_never_overwrites_existing_files() {
        let root = test_root("export");
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source.txt");
        let destination = root.join("saved.txt");
        fs::write(&source, b"edited content").unwrap();
        assert_eq!(
            validate_export_destination(destination.to_str().unwrap()).unwrap(),
            destination
        );
        export_local_copy(&source, &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"edited content");

        fs::write(&source, b"new content").unwrap();
        assert!(export_local_copy(&source, &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"edited content");
        assert!(validate_export_destination("relative.txt").is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn recovery_rejects_symlinked_cache_boundaries() {
        use std::os::unix::fs::symlink;

        let root = test_root("symlink");
        let cache = root.join("cache");
        let outside = root.join("outside");
        let session_id = "8d4147a2-3bd4-4b67-a077-8ec7daf253b0";
        fs::create_dir_all(&cache).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("remote-example.conf"), b"content").unwrap();
        symlink(&outside, cache.join(session_id)).unwrap();
        assert!(
            validate_managed_local_copy(
                &cache,
                session_id,
                &cache.join(session_id).join("remote-example.conf")
            )
            .is_err()
        );
        let _ = fs::remove_dir_all(root);
    }
}

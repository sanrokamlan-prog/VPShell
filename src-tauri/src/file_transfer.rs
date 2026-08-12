use std::{
    collections::HashSet,
    env, fs,
    fs::OpenOptions,
    io::{self, Read, Seek, SeekFrom, Write},
    net::{TcpStream, ToSocketAddrs},
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Component, Path, PathBuf},
    process::Command,
    sync::OnceLock,
    time::Duration,
};

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh2::{
    CheckResult, ErrorCode, ExtendedData, FileStat, KeyboardInteractivePrompt, KnownHostFileKind,
    MethodType, Prompt, Session, Sftp,
};
use tauri::{AppHandle, Emitter, State};
use zeroize::Zeroizing;

use crate::{
    CREDENTIAL_SERVICE, LEGACY_CREDENTIAL_SERVICE,
    transfer_manager::{
        RecoveryStoreStatus, TransferManager, TransferRequest, TransferResult, TransferSnapshot,
        TransferTask,
    },
};

const MAX_HOST_LENGTH: usize = 255;
const MAX_USERNAME_LENGTH: usize = 128;
const MAX_PATH_LENGTH: usize = 4096;
const MAX_TRANSFER_PATHS: usize = 256;
const MAX_TRANSFER_ID_LENGTH: usize = 128;
const MAX_DIRECTORY_DEPTH: usize = 128;
const MAX_TRANSFER_ENTRIES: u64 = 1_000_000;
const MAX_KNOWN_HOSTS_SIZE: u64 = 16 * 1024 * 1024;
const MAX_KEYSCAN_OUTPUT_SIZE: usize = 512 * 1024;
const COPY_BUFFER_SIZE: usize = 128 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(60);

const PREFERRED_OPENSSH_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp521",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp256",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha256",
];

static OPENSSH_KEX_ALGORITHMS: OnceLock<Result<String, String>> = OnceLock::new();

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectionSpec {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: String,
    pub(crate) credential_ref: Option<String>,
    pub(crate) identity_file: Option<String>,
    pub(crate) identity_passphrase_ref: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HostKeyRequest {
    host: String,
    port: u16,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HostKeyInspection {
    host: String,
    port: u16,
    status: String,
    algorithm: String,
    fingerprint: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RemoteEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoteEntry {
    name: String,
    path: String,
    kind: RemoteEntryKind,
    size: u64,
    modified: Option<u64>,
    permissions: String,
    owner_group: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoteDirectoryResult {
    path: String,
    entries: Vec<RemoteEntry>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferProgress {
    transfer_id: String,
    phase: String,
    current_path: String,
    transferred_bytes: u64,
    total_bytes: Option<u64>,
}

#[derive(Clone)]
struct ProgressReporter {
    app: AppHandle,
    transfer_id: String,
    task: TransferTask,
}

impl ProgressReporter {
    fn emit(
        &self,
        phase: impl Into<String>,
        current_path: impl Into<String>,
        bytes_done: u64,
        bytes_total: Option<u64>,
    ) -> Result<(), String> {
        let phase = phase.into();
        let current_path = current_path.into();
        self.task
            .progress(&phase, &current_path, bytes_done, bytes_total)?;
        let _ = self.app.emit(
            "transfer-progress",
            TransferProgress {
                transfer_id: self.transfer_id.clone(),
                phase,
                current_path,
                transferred_bytes: bytes_done,
                total_bytes: bytes_total,
            },
        );
        Ok(())
    }

    fn checkpoint(&self) -> Result<(), String> {
        self.task.checkpoint()
    }
}

#[derive(Default)]
struct TransferStats {
    files: u64,
    bytes: u64,
    skipped_symlinks: u64,
    entries: u64,
    sha256_verified: bool,
}

struct TempFileGuard(PathBuf);

struct CancellableReader<R> {
    inner: R,
    task: TransferTask,
}

impl<R> CancellableReader<R> {
    fn new(inner: R, task: TransferTask) -> Self {
        Self { inner, task }
    }
}

impl<R: Read> Read for CancellableReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.task
            .checkpoint()
            .map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "传输已取消"))?;
        self.inner.read(buffer)
    }
}

impl TempFileGuard {
    fn new(transfer_id: &str, suffix: &str) -> Self {
        let safe_id: String = transfer_id
            .chars()
            .filter(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
            .take(48)
            .collect();
        Self(env::temp_dir().join(format!(
            "vpshell-{safe_id}-{}-{suffix}",
            uuid::Uuid::new_v4()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[tauri::command]
pub(crate) async fn list_remote_files(
    connection: ConnectionSpec,
    path: String,
) -> Result<RemoteDirectoryResult, String> {
    tauri::async_runtime::spawn_blocking(move || list_remote_files_blocking(connection, path))
        .await
        .map_err(|error| format!("SFTP 浏览任务异常结束: {error}"))?
}

#[tauri::command]
pub(crate) async fn inspect_host_key(request: HostKeyRequest) -> Result<HostKeyInspection, String> {
    tauri::async_runtime::spawn_blocking(move || inspect_host_key_blocking(request))
        .await
        .map_err(|error| format!("SSH 主机指纹检查任务异常结束: {error}"))?
}

#[tauri::command]
pub(crate) async fn trust_host_key(
    request: HostKeyRequest,
    expected_fingerprint: String,
) -> Result<HostKeyInspection, String> {
    tauri::async_runtime::spawn_blocking(move || {
        trust_host_key_blocking(request, expected_fingerprint)
    })
    .await
    .map_err(|error| format!("SSH 主机指纹保存任务异常结束: {error}"))?
}

#[tauri::command]
pub(crate) async fn upload_remote(
    app: AppHandle,
    manager: State<'_, TransferManager>,
    connection: ConnectionSpec,
    local_paths: Vec<String>,
    remote_directory: String,
    package_transfer: bool,
    transfer_id: String,
) -> Result<TransferSnapshot, String> {
    validate_transfer_id(&transfer_id)?;
    let request = TransferRequest::Upload {
        local_paths: local_paths.clone(),
        remote_directory: remote_directory.clone(),
        package_transfer,
    };
    let (accepted, task) = manager.accept(
        &app,
        transfer_id.clone(),
        &connection.host,
        connection.port,
        &connection.username,
        request,
    )?;
    let reporter = ProgressReporter {
        app,
        transfer_id: transfer_id.clone(),
        task: task.clone(),
    };
    tauri::async_runtime::spawn_blocking(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            task.start()?;
            upload_paths_blocking(
                connection,
                local_paths,
                remote_directory,
                package_transfer,
                transfer_id,
                reporter,
            )
        }))
        .unwrap_or_else(|_| Err("SFTP 上传任务发生内部异常".to_string()));
        task.finish(result);
    });
    Ok(accepted)
}

#[tauri::command]
pub(crate) async fn download_remote(
    app: AppHandle,
    manager: State<'_, TransferManager>,
    connection: ConnectionSpec,
    remote_paths: Vec<String>,
    local_directory: String,
    package_transfer: bool,
    transfer_id: String,
) -> Result<TransferSnapshot, String> {
    validate_transfer_id(&transfer_id)?;
    let request = TransferRequest::Download {
        remote_paths: remote_paths.clone(),
        local_directory: local_directory.clone(),
        package_transfer,
    };
    let (accepted, task) = manager.accept(
        &app,
        transfer_id.clone(),
        &connection.host,
        connection.port,
        &connection.username,
        request,
    )?;
    let reporter = ProgressReporter {
        app,
        transfer_id: transfer_id.clone(),
        task: task.clone(),
    };
    tauri::async_runtime::spawn_blocking(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            task.start()?;
            download_paths_blocking(
                connection,
                remote_paths,
                local_directory,
                package_transfer,
                transfer_id,
                reporter,
            )
        }))
        .unwrap_or_else(|_| Err("SFTP 下载任务发生内部异常".to_string()));
        task.finish(result);
    });
    Ok(accepted)
}

#[tauri::command]
pub(crate) fn get_transfer_task(
    manager: State<'_, TransferManager>,
    transfer_id: String,
) -> Result<Option<TransferSnapshot>, String> {
    validate_transfer_id(&transfer_id)?;
    Ok(manager.get(&transfer_id))
}

#[tauri::command]
pub(crate) fn list_transfer_tasks(manager: State<'_, TransferManager>) -> Vec<TransferSnapshot> {
    manager.list()
}

#[tauri::command]
pub(crate) fn get_transfer_recovery_status(
    manager: State<'_, TransferManager>,
) -> RecoveryStoreStatus {
    manager.store_status()
}

#[tauri::command]
pub(crate) async fn retry_transfer_task(
    app: AppHandle,
    manager: State<'_, TransferManager>,
    connection: ConnectionSpec,
    transfer_id: String,
) -> Result<TransferSnapshot, String> {
    validate_transfer_id(&transfer_id)?;
    validate_connection(&connection)?;
    if manager
        .get(&transfer_id)
        .is_some_and(|snapshot| snapshot.kind == "fileOperation")
    {
        return Err("远端文件任务必须重新生成并确认预览，不能从旧计划直接重试".to_string());
    }
    let (accepted, task, request) = manager.begin_retry(
        &app,
        &transfer_id,
        &connection.host,
        connection.port,
        &connection.username,
    )?;
    let reporter = ProgressReporter {
        app,
        transfer_id: transfer_id.clone(),
        task: task.clone(),
    };
    tauri::async_runtime::spawn_blocking(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            task.start()?;
            match request {
                TransferRequest::Upload {
                    local_paths,
                    remote_directory,
                    package_transfer,
                } => upload_paths_blocking(
                    connection,
                    local_paths,
                    remote_directory,
                    package_transfer,
                    transfer_id,
                    reporter,
                ),
                TransferRequest::Download {
                    remote_paths,
                    local_directory,
                    package_transfer,
                } => download_paths_blocking(
                    connection,
                    remote_paths,
                    local_directory,
                    package_transfer,
                    transfer_id,
                    reporter,
                ),
                TransferRequest::FileOperation { .. } => {
                    Err("远端文件任务必须通过新的安全预览恢复".to_string())
                }
            }
        }))
        .unwrap_or_else(|_| Err("SFTP 重试任务发生内部异常".to_string()));
        task.finish(result);
    });
    Ok(accepted)
}

#[tauri::command]
pub(crate) fn cancel_transfer_task(
    app: AppHandle,
    manager: State<'_, TransferManager>,
    transfer_id: String,
) -> Result<TransferSnapshot, String> {
    validate_transfer_id(&transfer_id)?;
    manager.cancel(&app, &transfer_id)
}

#[tauri::command]
pub(crate) fn dismiss_transfer_task(
    manager: State<'_, TransferManager>,
    transfer_id: String,
) -> Result<(), String> {
    validate_transfer_id(&transfer_id)?;
    manager.dismiss(&transfer_id)
}

fn list_remote_files_blocking(
    connection: ConnectionSpec,
    path: String,
) -> Result<RemoteDirectoryResult, String> {
    validate_connection(&connection)?;
    validate_remote_path(&path)?;
    let session = connect(&connection)?;
    let sftp = session
        .sftp()
        .map_err(|_| "无法建立 SFTP 子系统".to_string())?;
    let canonical = canonical_remote_path(&sftp, &path)?;
    let mut entries = sftp
        .readdir(Path::new(&canonical))
        .map_err(|error| format!("无法读取远程目录: {error}"))?
        .into_iter()
        .map(|(entry_path, stat)| remote_entry(entry_path, stat))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by(|left, right| {
        entry_kind_order(&left.kind)
            .cmp(&entry_kind_order(&right.kind))
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
    });
    Ok(RemoteDirectoryResult {
        path: canonical,
        entries,
    })
}

fn upload_paths_blocking(
    connection: ConnectionSpec,
    local_paths: Vec<String>,
    remote_directory: String,
    package: bool,
    transfer_id: String,
    reporter: ProgressReporter,
) -> Result<TransferResult, String> {
    validate_connection(&connection)?;
    validate_remote_path(&remote_directory)?;
    let roots = validate_local_inputs(local_paths)?;
    ensure_unique_local_names(&roots)?;

    let mut inventory = TransferStats::default();
    for root in &roots {
        inspect_local_entry(root, 0, &mut inventory, &reporter)?;
    }
    if inventory.files == 0 {
        return Err("没有可上传的普通文件（符号链接会被跳过）".to_string());
    }

    reporter.emit("connecting", "", 0, Some(inventory.bytes))?;
    let session = connect_for_transfer(&connection, &reporter)?;
    let sftp = session
        .sftp()
        .map_err(|_| "无法建立 SFTP 子系统".to_string())?;
    let destination = canonical_remote_directory(&sftp, &remote_directory)?;

    let mut fallback_used = false;
    let result = if package {
        reporter.emit("checking", "tar + zstd", 0, Some(inventory.bytes))?;
        if remote_supports_package_mode(&session, &reporter)? {
            upload_package(
                &connection,
                &session,
                &sftp,
                &roots,
                &destination,
                &transfer_id,
                &reporter,
                &inventory,
            )?
        } else {
            fallback_used = true;
            reporter.emit("fallback", "recursive SFTP", 0, Some(inventory.bytes))?;
            upload_recursive_roots(
                &connection,
                &session,
                &sftp,
                &roots,
                &destination,
                &reporter,
                inventory.bytes,
            )?
        }
    } else {
        upload_recursive_roots(
            &connection,
            &session,
            &sftp,
            &roots,
            &destination,
            &reporter,
            inventory.bytes,
        )?
    };

    reporter.task.begin_finalizing(&destination)?;
    reporter.emit("completed", destination, result.bytes, Some(result.bytes))?;
    Ok(TransferResult {
        transfer_id,
        mode: if package && !fallback_used {
            "package".to_string()
        } else {
            "sftp".to_string()
        },
        files_transferred: result.files,
        bytes_transferred: result.bytes,
        skipped_symlinks: result.skipped_symlinks,
        fallback_used,
        resumable: false,
        verification: if result.sha256_verified {
            "size+sha256".to_string()
        } else {
            "size".to_string()
        },
        limitations: vec![
            "当前版本不支持断点续传；失败任务不会提交 .part 文件".to_string(),
            "打包模式仅原子提交到不存在的同名目标；已有目标请使用递归 SFTP".to_string(),
        ],
        operation_result: None,
    })
}

fn download_paths_blocking(
    connection: ConnectionSpec,
    remote_paths: Vec<String>,
    local_directory: String,
    package: bool,
    transfer_id: String,
    reporter: ProgressReporter,
) -> Result<TransferResult, String> {
    validate_connection(&connection)?;
    let requested_paths = validate_remote_inputs(remote_paths)?;
    let local_root = prepare_local_directory(&local_directory)?;

    reporter.emit("connecting", "", 0, None)?;
    let session = connect_for_transfer(&connection, &reporter)?;
    let sftp = session
        .sftp()
        .map_err(|_| "无法建立 SFTP 子系统".to_string())?;
    let roots = resolve_remote_roots(&sftp, &requested_paths)?;
    ensure_unique_remote_names(&roots)?;

    let mut inventory = TransferStats::default();
    for root in &roots {
        inspect_remote_entry(&sftp, root, 0, &mut inventory, &reporter)?;
    }
    if inventory.files == 0 {
        return Err("没有可下载的普通文件（符号链接不会下载）".to_string());
    }

    let mut fallback_used = false;
    let result = if package {
        reporter.emit("checking", "tar + zstd", 0, Some(inventory.bytes))?;
        if remote_supports_package_mode(&session, &reporter)? {
            download_package(
                &connection,
                &session,
                &sftp,
                &roots,
                &local_root,
                &transfer_id,
                &reporter,
                &inventory,
            )?
        } else {
            fallback_used = true;
            reporter.emit("fallback", "recursive SFTP", 0, Some(inventory.bytes))?;
            download_recursive_roots(
                &session,
                &sftp,
                &roots,
                &local_root,
                &reporter,
                inventory.bytes,
            )?
        }
    } else {
        download_recursive_roots(
            &session,
            &sftp,
            &roots,
            &local_root,
            &reporter,
            inventory.bytes,
        )?
    };

    reporter
        .task
        .begin_finalizing(local_root.display().to_string())?;
    reporter.emit(
        "completed",
        local_root.display().to_string(),
        result.bytes,
        Some(result.bytes),
    )?;
    Ok(TransferResult {
        transfer_id,
        mode: if package && !fallback_used {
            "package".to_string()
        } else {
            "sftp".to_string()
        },
        files_transferred: result.files,
        bytes_transferred: result.bytes,
        skipped_symlinks: result.skipped_symlinks,
        fallback_used,
        resumable: false,
        verification: if result.sha256_verified {
            "size+sha256".to_string()
        } else {
            "size".to_string()
        },
        limitations: vec![
            "当前版本不支持断点续传；失败任务不会提交 .part 文件".to_string(),
            "打包模式仅原子提交到不存在的同名目标；已有目标请使用递归 SFTP".to_string(),
        ],
        operation_result: None,
    })
}

pub(crate) fn validate_connection(connection: &ConnectionSpec) -> Result<(), String> {
    validate_host(&connection.host, connection.port)?;
    let username = connection.username.trim();
    if username.is_empty()
        || username.len() > MAX_USERNAME_LENGTH
        || username.starts_with('-')
        || username.contains('@')
        || username
            .chars()
            .any(|value| value.is_whitespace() || value.is_control())
    {
        return Err("SFTP 用户名格式无效".to_string());
    }
    validate_optional_reference(connection.credential_ref.as_deref(), "ssh-")?;
    validate_optional_reference(connection.identity_passphrase_ref.as_deref(), "key-")?;
    if connection.identity_passphrase_ref.is_some() && connection.identity_file.is_none() {
        return Err("私钥口令引用缺少对应的私钥文件".to_string());
    }
    if let Some(identity) = connection.identity_file.as_deref() {
        validate_local_path_text(identity)?;
        let path = Path::new(identity);
        if !path.is_absolute() {
            return Err("SFTP 私钥路径必须是绝对路径".to_string());
        }
        let metadata = fs::metadata(path).map_err(|_| "无法读取 SFTP 私钥文件".to_string())?;
        if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 {
            return Err("SFTP 私钥文件无效或过大".to_string());
        }
    }
    Ok(())
}

fn validate_host(host: &str, port: u16) -> Result<(), String> {
    let host = host.trim();
    if host.is_empty() || host.len() > MAX_HOST_LENGTH || port == 0 {
        return Err("SSH 主机地址或端口无效".to_string());
    }
    if host.starts_with('-')
        || host
            .chars()
            .any(|value| value.is_whitespace() || value.is_control())
    {
        return Err("SSH 主机地址格式无效".to_string());
    }
    Ok(())
}

pub(crate) fn validate_optional_reference(
    reference: Option<&str>,
    prefix: &str,
) -> Result<(), String> {
    if let Some(reference) = reference {
        if reference.len() > 128
            || !reference.starts_with(prefix)
            || !reference
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
        {
            return Err("凭据引用无效".to_string());
        }
    }
    Ok(())
}

fn validate_transfer_id(transfer_id: &str) -> Result<(), String> {
    if transfer_id.is_empty()
        || transfer_id.len() > MAX_TRANSFER_ID_LENGTH
        || !transfer_id
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
    {
        return Err("传输任务 ID 无效".to_string());
    }
    Ok(())
}

pub(crate) fn validate_remote_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > MAX_PATH_LENGTH
        || path.contains('\0')
        || path.chars().any(|value| matches!(value, '\r' | '\n'))
    {
        return Err("远程路径无效或过长".to_string());
    }
    Ok(())
}

fn validate_local_path_text(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > MAX_PATH_LENGTH
        || path.contains('\0')
        || path.chars().any(|value| matches!(value, '\r' | '\n'))
    {
        return Err("本机路径无效或过长".to_string());
    }
    Ok(())
}

fn validate_local_inputs(paths: Vec<String>) -> Result<Vec<PathBuf>, String> {
    if paths.is_empty() || paths.len() > MAX_TRANSFER_PATHS {
        return Err("请选择 1 到 256 个本机文件或目录".to_string());
    }
    paths
        .into_iter()
        .map(|value| {
            validate_local_path_text(&value)?;
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err("上传路径必须是绝对路径".to_string());
            }
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("无法读取上传路径 {}: {error}", path.display()))?;
            if metadata_is_linklike(&metadata) {
                return Err(format!("不能把符号链接作为上传根路径: {}", path.display()));
            }
            if !metadata.is_file() && !metadata.is_dir() {
                return Err(format!("不支持的上传路径类型: {}", path.display()));
            }
            Ok(path)
        })
        .collect()
}

fn validate_remote_inputs(paths: Vec<String>) -> Result<Vec<String>, String> {
    if paths.is_empty() || paths.len() > MAX_TRANSFER_PATHS {
        return Err("请选择 1 到 256 个远程文件或目录".to_string());
    }
    paths
        .into_iter()
        .map(|path| {
            validate_remote_path(&path)?;
            Ok(path)
        })
        .collect()
}

pub(crate) fn connect(connection: &ConnectionSpec) -> Result<Session, String> {
    let session = open_session(&connection.host, connection.port)?;
    verify_known_host(&session, &connection.host, connection.port)?;
    authenticate(&session, connection)?;
    Ok(session)
}

fn connect_for_transfer(
    connection: &ConnectionSpec,
    reporter: &ProgressReporter,
) -> Result<Session, String> {
    connect_for_task(connection, &reporter.task)
}

pub(crate) fn connect_for_task(
    connection: &ConnectionSpec,
    task: &TransferTask,
) -> Result<Session, String> {
    task.checkpoint()?;
    let session = open_session_for_task(&connection.host, connection.port, task)?;
    task.checkpoint()?;
    verify_known_host(&session, &connection.host, connection.port)?;
    task.checkpoint()?;
    authenticate(&session, connection)?;
    task.checkpoint()?;
    Ok(session)
}

fn open_session(host: &str, port: u16) -> Result<Session, String> {
    open_session_internal(host, port, None)
}

fn open_session_for_task(host: &str, port: u16, task: &TransferTask) -> Result<Session, String> {
    open_session_internal(host, port, Some(task))
}

fn open_session_internal(
    host: &str,
    port: u16,
    task: Option<&TransferTask>,
) -> Result<Session, String> {
    if let Some(task) = task {
        task.checkpoint()?;
    }
    let preferences = known_host_key_preferences(host, port, &known_hosts_files());
    for preference in preferences.iter().map(String::as_str).map(Some) {
        match open_session_with_preference(host, port, preference, task) {
            Ok(session) => return Ok(session),
            Err(error) if error == crate::transfer_manager::TRANSFER_CANCELLED => {
                return Err(error);
            }
            Err(_) => continue,
        }
    }
    match open_session_with_preference(host, port, None, task) {
        Ok(session) => Ok(session),
        // The unforced attempt reflects the server's actual negotiation result. A failure from an
        // earlier compatibility preference must not replace it and masquerade as a credential issue.
        Err(error) => Err(error),
    }
}

fn open_session_with_preference(
    host: &str,
    port: u16,
    host_key_preference: Option<&str>,
    task: Option<&TransferTask>,
) -> Result<Session, String> {
    if let Some(task) = task {
        task.checkpoint()?;
    }
    let mut last_error = None;
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|_| "无法解析 SSH 主机地址".to_string())?;
    let mut tcp = None;
    for address in addresses.take(16) {
        if let Some(task) = task {
            task.checkpoint()?;
        }
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => {
                tcp = Some(stream);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let tcp = tcp.ok_or_else(|| {
        last_error
            .map(|error| format!("无法连接 SSH 主机: {error}"))
            .unwrap_or_else(|| "SSH 主机没有可用地址".to_string())
    })?;
    tcp.set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("无法设置 SFTP 读取超时: {error}"))?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("无法设置 SFTP 写入超时: {error}"))?;
    if let Some(task) = task {
        task.register_socket(
            tcp.try_clone()
                .map_err(|error| format!("无法注册可取消的 SFTP 连接: {error}"))?,
        )?;
    }

    let mut session = Session::new().map_err(|_| "无法初始化 SSH 会话".to_string())?;
    if let Some(preference) = host_key_preference {
        session
            .method_pref(MethodType::HostKey, preference)
            .map_err(|_| format!("SSH 不支持主机密钥算法偏好: {preference}"))?;
    }
    session.set_tcp_stream(tcp);
    session.set_timeout(IO_TIMEOUT.as_millis() as u32);
    if let Some(task) = task {
        task.checkpoint()?;
    }
    session.handshake().map_err(|error| {
        let preference = host_key_preference
            .map(|value| format!("，主机密钥偏好 {value}"))
            .unwrap_or_default();
        format!(
            "SFTP SSH 握手失败（独立传输连接{preference}）：{error}；终端凭据不会因此被判为无效"
        )
    })?;
    Ok(session)
}

fn verify_known_host(session: &Session, host: &str, port: u16) -> Result<(), String> {
    let (status, key_type) = check_known_host(session, host, port)?;
    match status {
        CheckResult::Match => Ok(()),
        CheckResult::Mismatch => Err(format!(
            "SSH 主机密钥与 known_hosts 不匹配，已拒绝连接（协商算法: {key_type:?}）"
        )),
        CheckResult::NotFound => {
            Err("SSH 主机不在 known_hosts 中；请先核验并信任主机指纹".to_string())
        }
        CheckResult::Failure => Err("SSH 主机密钥校验失败，已拒绝连接".to_string()),
    }
}

fn check_known_host(
    session: &Session,
    host: &str,
    port: u16,
) -> Result<(CheckResult, ssh2::HostKeyType), String> {
    let mut known_hosts = session
        .known_hosts()
        .map_err(|_| "无法初始化 known_hosts 校验".to_string())?;
    let files = known_hosts_files();
    for path in files.iter().filter(|path| path.is_file()) {
        let metadata = fs::metadata(path).map_err(|_| "无法读取 known_hosts 文件".to_string())?;
        if metadata.len() > MAX_KNOWN_HOSTS_SIZE {
            return Err(format!("known_hosts 文件过大: {}", path.display()));
        }
        known_hosts
            .read_file(path, KnownHostFileKind::OpenSSH)
            .map_err(|_| format!("无法解析 known_hosts 文件: {}", path.display()))?;
    }
    let (key, key_type) = session
        .host_key()
        .ok_or_else(|| "SSH 服务器未提供主机密钥".to_string())?;
    Ok((known_hosts.check_port(host, port, key), key_type))
}

fn inspect_host_key_blocking(request: HostKeyRequest) -> Result<HostKeyInspection, String> {
    validate_host(&request.host, request.port)?;
    inspect_scanned_host(&request.host, request.port)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostKeyMaterial {
    algorithm: String,
    encoded: String,
    key: Vec<u8>,
}

fn inspect_scanned_host(host: &str, port: u16) -> Result<HostKeyInspection, String> {
    let scanned = scan_host_keys(host, port)?;
    let known = lookup_known_host_keys(host, port)?;
    inspect_host_key_material(host, port, &scanned, &known)
}

fn inspect_host_key_material(
    host: &str,
    port: u16,
    scanned: &[HostKeyMaterial],
    known: &[HostKeyMaterial],
) -> Result<HostKeyInspection, String> {
    if let Some(material) = scanned
        .iter()
        .find(|candidate| known.iter().any(|saved| saved == *candidate))
    {
        return Ok(host_key_inspection(host, port, "verified", material));
    }
    if let Some(material) = scanned.iter().find(|candidate| {
        known
            .iter()
            .any(|saved| saved.algorithm == candidate.algorithm)
    }) {
        return Ok(host_key_inspection(host, port, "changed", material));
    }

    scanned
        .first()
        .map(|material| host_key_inspection(host, port, "unknown", material))
        .ok_or_else(|| "OpenSSH 未返回可识别的主机密钥".to_string())
}

fn host_key_inspection(
    host: &str,
    port: u16,
    status: &str,
    material: &HostKeyMaterial,
) -> HostKeyInspection {
    HostKeyInspection {
        host: host.to_string(),
        port,
        status: status.to_string(),
        algorithm: host_key_algorithm_label(&material.algorithm).to_string(),
        fingerprint: host_key_fingerprint(&material.key),
    }
}

fn host_key_fingerprint(key: &[u8]) -> String {
    format!(
        "SHA256:{}",
        BASE64_STANDARD_NO_PAD.encode(Sha256::digest(key))
    )
}

fn trust_host_key_blocking(
    request: HostKeyRequest,
    expected_fingerprint: String,
) -> Result<HostKeyInspection, String> {
    validate_host(&request.host, request.port)?;
    // Re-scan exactly once after the user confirms the displayed fingerprint. The initial
    // inspection and this confirmation may be separated by an arbitrary amount of time.
    let scanned = scan_host_keys(&request.host, request.port)?;
    let known = lookup_known_host_keys(&request.host, request.port)?;
    let inspection = inspect_host_key_material(&request.host, request.port, &scanned, &known)?;
    if inspection.status == "verified" {
        return Ok(inspection);
    }
    if inspection.status == "changed" {
        return Err("主机指纹与现有记录不一致，不能覆盖；请先人工核查 known_hosts".to_string());
    }
    if inspection.status != "unknown" {
        return Err("主机指纹校验失败，不能保存".to_string());
    }
    if expected_fingerprint != inspection.fingerprint {
        return Err("服务器指纹在确认期间发生变化，已取消连接".to_string());
    }

    let material = scanned
        .iter()
        .find(|material| host_key_fingerprint(&material.key) == expected_fingerprint)
        .ok_or_else(|| "服务器指纹在确认期间发生变化，已取消连接".to_string())?;
    let path = user_known_hosts_file()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("无法创建 .ssh 目录: {error}"))?;
    }
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata_is_linklike(&metadata) {
            return Err("拒绝写入符号链接或重解析点形式的 known_hosts".to_string());
        }
        if metadata.len() > MAX_KNOWN_HOSTS_SIZE {
            return Err("known_hosts 文件过大，拒绝写入".to_string());
        }
    }

    let marker = known_host_marker(&request.host, request.port);
    let line = format!(
        "{marker} {} {} VPShell\n",
        material.algorithm, material.encoded
    );

    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("无法打开 known_hosts: {error}"))?;
    let length = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
    if length > 0 {
        file.seek(SeekFrom::End(-1))
            .map_err(|error| format!("无法检查 known_hosts 结尾: {error}"))?;
        let mut last = [0_u8; 1];
        file.read_exact(&mut last)
            .map_err(|error| format!("无法读取 known_hosts 结尾: {error}"))?;
        if last[0] != b'\n' {
            file.write_all(b"\n")
                .map_err(|error| format!("无法写入 known_hosts: {error}"))?;
        }
    }
    file.write_all(line.as_bytes())
        .and_then(|_| file.flush())
        .map_err(|error| format!("无法保存 known_hosts: {error}"))?;

    // Verify the local write without opening another pre-auth SSH connection. The subsequent
    // terminal and SFTP handshakes still enforce the saved key independently.
    let saved = lookup_known_host_keys(&request.host, request.port)?;
    if !saved.iter().any(|candidate| candidate == material) {
        return Err("主机指纹已写入，但复核失败".to_string());
    }
    Ok(host_key_inspection(
        &request.host,
        request.port,
        "verified",
        material,
    ))
}

pub(crate) fn openssh_kex_algorithms() -> Result<String, String> {
    OPENSSH_KEX_ALGORITHMS
        .get_or_init(discover_openssh_kex_algorithms)
        .clone()
}

fn discover_openssh_kex_algorithms() -> Result<String, String> {
    let mut command = Command::new("ssh");
    command.arg("-Q").arg("kex");
    hide_console_window(&mut command);
    let output = command
        .output()
        .map_err(|error| format!("无法查询系统 OpenSSH KEX 算法: {error}"))?;
    if !output.status.success() {
        return Err("系统 OpenSSH 不支持查询 KEX 算法，请升级 OpenSSH 客户端".to_string());
    }
    if output.stdout.len() > MAX_KEYSCAN_OUTPUT_SIZE {
        return Err("OpenSSH KEX 算法列表超过安全上限".to_string());
    }
    select_openssh_kex_algorithms(&String::from_utf8_lossy(&output.stdout))
}

fn select_openssh_kex_algorithms(output: &str) -> Result<String, String> {
    let supported = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<HashSet<_>>();
    let selected = PREFERRED_OPENSSH_KEX
        .iter()
        .copied()
        .filter(|algorithm| supported.contains(algorithm))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Err("系统 OpenSSH 没有 VPShell 支持的安全 KEX 算法".to_string());
    }
    Ok(selected.join(","))
}

fn scan_host_keys(host: &str, port: u16) -> Result<Vec<HostKeyMaterial>, String> {
    let kex_algorithms = openssh_kex_algorithms()?;
    let temp_known_hosts = TempFileGuard::new("hostkey-scan", "known_hosts");
    let null_device = null_device();

    let mut command = Command::new("ssh");
    command
        .arg("-F")
        .arg(null_device)
        .arg("-T")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("NumberOfPasswordPrompts=0")
        .arg("-o")
        .arg("PreferredAuthentications=none")
        .arg("-o")
        .arg("PubkeyAuthentication=no")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
        .arg("HashKnownHosts=no")
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            temp_known_hosts.path().display()
        ))
        .arg("-o")
        .arg(format!("GlobalKnownHostsFile={null_device}"))
        .arg("-o")
        .arg("ConnectTimeout=8")
        .arg("-o")
        .arg("ConnectionAttempts=1")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("-o")
        .arg(format!("KexAlgorithms={kex_algorithms}"))
        .arg("-p")
        .arg(port.to_string())
        .arg("-l")
        .arg("vpshell-hostkey-probe")
        .arg("--")
        .arg(host)
        .arg("exit");
    hide_console_window(&mut command);
    let output = command
        .output()
        .map_err(|error| format!("无法启动系统 ssh；请确认已安装 OpenSSH 客户端: {error}"))?;
    if output.stdout.len() > MAX_KEYSCAN_OUTPUT_SIZE
        || output.stderr.len() > MAX_KEYSCAN_OUTPUT_SIZE
    {
        return Err("OpenSSH 主机指纹握手输出超过安全上限".to_string());
    }
    let known_hosts = fs::read(temp_known_hosts.path()).unwrap_or_default();
    if known_hosts.len() > MAX_KEYSCAN_OUTPUT_SIZE {
        return Err("临时 known_hosts 超过安全上限".to_string());
    }
    let mut keys = parse_host_key_lines(&String::from_utf8_lossy(&known_hosts));
    keys.sort_by_key(|material| host_key_algorithm_priority(&material.algorithm));
    keys.dedup();
    if keys.is_empty() {
        let detail = String::from_utf8_lossy(&output.stderr)
            .chars()
            .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
            .take(300)
            .collect::<String>()
            .trim()
            .to_string();
        return Err(host_key_probe_failure(&detail));
    }
    Ok(keys)
}

fn host_key_probe_failure(detail: &str) -> String {
    let lower = detail.to_ascii_lowercase();
    if lower.contains("kex_exchange_identification")
        || lower.contains("connection closed by remote host")
        || lower.contains("connection reset by peer")
    {
        return "远端在发送 SSH 主机密钥前主动关闭连接；请检查 sshd、来源 IP 限制、防火墙/Fail2Ban 或 MaxStartups 限流".to_string();
    }
    if lower.contains("no matching key exchange method") {
        return "与服务器没有共同的安全 KEX 算法；VPShell 不会自动启用 SHA-1 旧算法".to_string();
    }
    if lower.contains("connection timed out") || lower.contains("operation timed out") {
        return "SSH 主机指纹握手超时；请检查地址、端口、防火墙和服务器状态".to_string();
    }
    if lower.contains("connection refused") {
        return "SSH 端口拒绝连接；请确认 sshd 已启动且端口配置正确".to_string();
    }
    if detail.is_empty() {
        "SSH 主机未返回指纹；可能未响应、在密钥交换前限流/断开，或没有共同的安全 KEX 算法"
            .to_string()
    } else {
        format!("OpenSSH 主机指纹握手失败: {detail}")
    }
}

#[cfg(windows)]
fn null_device() -> &'static str {
    "NUL"
}

#[cfg(not(windows))]
fn null_device() -> &'static str {
    "/dev/null"
}

fn lookup_known_host_keys(host: &str, port: u16) -> Result<Vec<HostKeyMaterial>, String> {
    let normalized_host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    let lookups = if port == 22 {
        vec![
            normalized_host.to_string(),
            format!("[{normalized_host}]:22"),
        ]
    } else {
        vec![format!("[{normalized_host}]:{port}")]
    };
    let mut known = Vec::new();
    for path in known_hosts_files().iter().filter(|path| path.is_file()) {
        let metadata = fs::metadata(path)
            .map_err(|error| format!("无法读取 known_hosts {}: {error}", path.display()))?;
        if metadata.len() > MAX_KNOWN_HOSTS_SIZE {
            return Err(format!("known_hosts 文件过大: {}", path.display()));
        }
        for lookup in &lookups {
            let mut command = Command::new("ssh-keygen");
            command.arg("-F").arg(lookup).arg("-f").arg(path);
            hide_console_window(&mut command);
            let output = command.output().map_err(|error| {
                format!("无法启动系统 ssh-keygen；请确认已安装 OpenSSH 客户端: {error}")
            })?;
            if output.stdout.len() > MAX_KEYSCAN_OUTPUT_SIZE {
                return Err("ssh-keygen 输出超过安全上限".to_string());
            }
            known.extend(parse_host_key_lines(&String::from_utf8_lossy(
                &output.stdout,
            )));
        }
    }
    known.sort_by(|left, right| {
        left.algorithm
            .cmp(&right.algorithm)
            .then_with(|| left.encoded.cmp(&right.encoded))
    });
    known.dedup();
    Ok(known)
}

fn parse_host_key_lines(output: &str) -> Vec<HostKeyMaterial> {
    output
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let algorithm_index = if fields.first().is_some_and(|field| field.starts_with('@')) {
                2
            } else {
                1
            };
            let algorithm = *fields.get(algorithm_index)?;
            if !matches!(
                algorithm,
                "ssh-ed25519"
                    | "ecdsa-sha2-nistp256"
                    | "ecdsa-sha2-nistp384"
                    | "ecdsa-sha2-nistp521"
                    | "ssh-rsa"
                    | "ssh-dss"
            ) {
                return None;
            }
            let encoded = *fields.get(algorithm_index + 1)?;
            let key = BASE64_STANDARD.decode(encoded).ok()?;
            if key.is_empty() {
                return None;
            }
            Some(HostKeyMaterial {
                algorithm: algorithm.to_string(),
                encoded: encoded.to_string(),
                key,
            })
        })
        .collect()
}

fn host_key_algorithm_priority(algorithm: &str) -> usize {
    match algorithm {
        "ssh-ed25519" => 0,
        "ecdsa-sha2-nistp256" => 1,
        "ecdsa-sha2-nistp384" => 2,
        "ecdsa-sha2-nistp521" => 3,
        "ssh-rsa" => 4,
        "ssh-dss" => 5,
        _ => usize::MAX,
    }
}

fn host_key_algorithm_label(algorithm: &str) -> &'static str {
    match algorithm {
        "ssh-ed25519" => "ED25519",
        "ecdsa-sha2-nistp256" => "ECDSA P-256",
        "ecdsa-sha2-nistp384" => "ECDSA P-384",
        "ecdsa-sha2-nistp521" => "ECDSA P-521",
        "ssh-rsa" => "RSA",
        "ssh-dss" => "DSA",
        _ => "未知算法",
    }
}

fn known_host_marker(host: &str, port: u16) -> String {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

fn user_known_hosts_file() -> Result<PathBuf, String> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(|home| PathBuf::from(home).join(".ssh").join("known_hosts"))
        .ok_or_else(|| "无法定位当前用户的 known_hosts".to_string())
}

fn known_host_key_preferences(host: &str, port: u16, files: &[PathBuf]) -> Vec<String> {
    let normalized_host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    let lookup = if port == 22 {
        normalized_host.to_string()
    } else {
        format!("[{normalized_host}]:{port}")
    };
    let mut key_types: HashSet<String> = HashSet::new();

    for path in files.iter().filter(|path| path.is_file()) {
        let Ok(metadata) = fs::metadata(path) else {
            continue;
        };
        if metadata.len() > MAX_KNOWN_HOSTS_SIZE {
            continue;
        }
        let lookups = if port == 22 {
            vec![lookup.clone(), format!("[{normalized_host}]:22")]
        } else {
            vec![lookup.clone()]
        };
        for lookup in lookups {
            let mut command = Command::new("ssh-keygen");
            command.arg("-F").arg(&lookup).arg("-f").arg(path);
            hide_console_window(&mut command);
            let Ok(output) = command.output() else {
                continue;
            };
            if output.status.success() && output.stdout.len() <= MAX_KNOWN_HOSTS_SIZE as usize {
                collect_known_host_key_types(
                    &String::from_utf8_lossy(&output.stdout),
                    &mut key_types,
                );
            }
        }
    }

    let mut preferences = Vec::new();
    for key_type in [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ] {
        if key_types.contains(key_type) {
            preferences.push(key_type);
        }
    }
    if key_types.contains("ssh-rsa") {
        preferences.extend(["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]);
    }
    preferences.into_iter().map(str::to_string).collect()
}

fn collect_known_host_key_types(output: &str, key_types: &mut HashSet<String>) {
    for line in output.lines().filter(|line| !line.starts_with('#')) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let key_type = if fields.first().is_some_and(|field| field.starts_with('@')) {
            fields.get(2)
        } else {
            fields.get(1)
        };
        if let Some(key_type) = key_type
            && matches!(
                *key_type,
                "ssh-ed25519"
                    | "ecdsa-sha2-nistp256"
                    | "ecdsa-sha2-nistp384"
                    | "ecdsa-sha2-nistp521"
                    | "ssh-rsa"
            )
        {
            key_types.insert((*key_type).to_string());
        }
    }
}

#[cfg(target_os = "windows")]
fn hide_console_window(command: &mut Command) {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(target_os = "windows"))]
fn hide_console_window(_command: &mut Command) {}

fn known_hosts_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(home) = env::var_os("HOME").or_else(|| env::var_os("USERPROFILE")) {
        files.push(PathBuf::from(home).join(".ssh").join("known_hosts"));
    }
    #[cfg(unix)]
    files.push(PathBuf::from("/etc/ssh/ssh_known_hosts"));
    #[cfg(windows)]
    if let Some(program_data) = env::var_os("PROGRAMDATA") {
        files.push(
            PathBuf::from(program_data)
                .join("ssh")
                .join("ssh_known_hosts"),
        );
    }
    files
}

fn authenticate(session: &Session, connection: &ConnectionSpec) -> Result<(), String> {
    let username = connection.username.trim();
    let advertised_methods = session
        .auth_methods(username)
        .unwrap_or_default()
        .to_string();
    let mut identity_attempted = false;
    let mut saved_password_attempted = false;

    if let Some(identity_file) = connection.identity_file.as_deref() {
        identity_attempted = true;
        let passphrase = connection
            .identity_passphrase_ref
            .as_deref()
            .map(|reference| read_secret(reference, "未找到已保存的私钥口令"))
            .transpose()?;
        let result = session.userauth_pubkey_file(
            username,
            None,
            Path::new(identity_file),
            passphrase.as_deref().map(String::as_str),
        );
        if result.is_ok() && session.authenticated() {
            return Ok(());
        }
    }

    if let Some(reference) = connection.credential_ref.as_deref() {
        let password = read_secret(reference, "未找到已保存的 SSH 密码")?;
        saved_password_attempted = true;
        let result = session.userauth_password(username, &password);
        if result.is_ok() && session.authenticated() {
            return Ok(());
        }
        let mut prompt = StoredPasswordPrompt {
            password: &password,
            used: false,
        };
        let result = session.userauth_keyboard_interactive(username, &mut prompt);
        if result.is_ok() && session.authenticated() {
            return Ok(());
        }
    }

    if session.userauth_agent(username).is_ok() && session.authenticated() {
        return Ok(());
    }

    if saved_password_attempted {
        if !advertised_methods.is_empty()
            && !advertised_methods.contains("password")
            && !advertised_methods.contains("keyboard-interactive")
        {
            return Err(format!(
                "SFTP 服务器不接受密码认证（仅提供: {advertised_methods}）；已导入凭据仍安全保存在本机，未被判为错误"
            ));
        }
        return Err(
            "SFTP 服务器拒绝了这次密码/交互认证；凭据已从系统凭据库成功读取，但该结果不能单独证明导入密码有误"
                .to_string(),
        );
    }
    if identity_attempted {
        return Err(
            "SFTP 私钥认证未通过；请检查私钥格式、口令、authorized_keys 或服务器允许的认证方式"
                .to_string(),
        );
    }

    Err("SFTP 没有可用的认证方式；请配置密码、私钥或 ssh-agent".to_string())
}

struct StoredPasswordPrompt<'a> {
    password: &'a str,
    used: bool,
}

impl KeyboardInteractivePrompt for StoredPasswordPrompt<'_> {
    fn prompt<'a>(
        &mut self,
        _username: &str,
        _instructions: &str,
        prompts: &[Prompt<'a>],
    ) -> Vec<String> {
        prompts
            .iter()
            .map(|prompt| {
                if !self.used && !prompt.echo {
                    self.used = true;
                    self.password.to_string()
                } else {
                    String::new()
                }
            })
            .collect()
    }
}

pub(crate) fn read_secret(
    reference: &str,
    missing_message: &str,
) -> Result<Zeroizing<String>, String> {
    let entry = keyring::Entry::new(CREDENTIAL_SERVICE, reference)
        .map_err(|_| "无法访问系统凭据管理器".to_string())?;
    if let Ok(secret) = entry.get_password() {
        return Ok(Zeroizing::new(secret));
    }

    let legacy_entry = keyring::Entry::new(LEGACY_CREDENTIAL_SERVICE, reference)
        .map_err(|_| "无法访问系统凭据管理器".to_string())?;
    let secret = legacy_entry
        .get_password()
        .map_err(|_| missing_message.to_string())?;

    // Keep the legacy entry intact until users have had a full release cycle to migrate.
    let _ = entry.set_password(&secret);
    Ok(Zeroizing::new(secret))
}

fn remote_entry(path: PathBuf, stat: FileStat) -> Result<RemoteEntry, String> {
    let path = path
        .to_str()
        .ok_or_else(|| "远程目录包含无法显示的文件名".to_string())?
        .replace('\\', "/");
    let name = remote_basename(&path)?.to_string();
    let file_type = stat.file_type();
    let kind = if file_type.is_file() {
        RemoteEntryKind::File
    } else if file_type.is_dir() {
        RemoteEntryKind::Directory
    } else if file_type.is_symlink() {
        RemoteEntryKind::Symlink
    } else {
        RemoteEntryKind::Other
    };
    let owner_group = match (stat.uid, stat.gid) {
        (Some(uid), Some(gid)) => Some(format!("{uid}:{gid}")),
        (Some(uid), None) => Some(uid.to_string()),
        (None, Some(gid)) => Some(format!(":{gid}")),
        (None, None) => None,
    };
    Ok(RemoteEntry {
        name,
        path,
        kind,
        size: stat.size.unwrap_or(0),
        modified: stat.mtime,
        permissions: stat
            .perm
            .map(|mode| format!("{:04o}", mode & 0o7777))
            .unwrap_or_else(|| "----".to_string()),
        owner_group,
    })
}

fn entry_kind_order(kind: &RemoteEntryKind) -> u8 {
    match kind {
        RemoteEntryKind::Directory => 0,
        RemoteEntryKind::File => 1,
        RemoteEntryKind::Symlink => 2,
        RemoteEntryKind::Other => 3,
    }
}

fn canonical_remote_path(sftp: &Sftp, path: &str) -> Result<String, String> {
    let canonical = sftp
        .realpath(Path::new(path))
        .map_err(|error| format!("远程路径不存在或不可访问: {error}"))?;
    let canonical = canonical
        .to_str()
        .ok_or_else(|| "远程路径不是有效的 UTF-8".to_string())?
        .replace('\\', "/");
    validate_remote_path(&canonical)?;
    Ok(canonical)
}

fn canonical_remote_directory(sftp: &Sftp, path: &str) -> Result<String, String> {
    let canonical = canonical_remote_path(sftp, path)?;
    let stat = sftp
        .lstat(Path::new(&canonical))
        .map_err(|error| format!("无法读取远程目录: {error}"))?;
    if stat.file_type().is_symlink() || !stat.is_dir() {
        return Err("远程目标必须是非符号链接目录".to_string());
    }
    Ok(canonical)
}

fn resolve_remote_roots(sftp: &Sftp, paths: &[String]) -> Result<Vec<String>, String> {
    paths
        .iter()
        .map(|path| {
            let stat = sftp
                .lstat(Path::new(path))
                .map_err(|error| format!("无法读取远程路径 {path}: {error}"))?;
            if stat.file_type().is_symlink() {
                return Err(format!("不能下载远程符号链接: {path}"));
            }
            let canonical = canonical_remote_path(sftp, path)?;
            let name = remote_basename(&canonical)?;
            validate_local_component(name)?;
            Ok(canonical)
        })
        .collect()
}

fn remote_basename(path: &str) -> Result<&str, String> {
    let trimmed = path.trim_end_matches('/');
    let name = trimmed.rsplit('/').next().unwrap_or_default();
    if name.is_empty() || matches!(name, "." | "..") {
        return Err("远程路径缺少安全的文件名".to_string());
    }
    Ok(name)
}

fn remote_parent(path: &str) -> Result<&str, String> {
    let trimmed = path.trim_end_matches('/');
    let index = trimmed
        .rfind('/')
        .ok_or_else(|| "远程路径必须是绝对路径".to_string())?;
    if index == 0 {
        Ok("/")
    } else {
        Ok(&trimmed[..index])
    }
}

fn remote_join(base: &str, name: &str) -> String {
    if base == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", base.trim_end_matches('/'))
    }
}

fn ensure_unique_local_names(paths: &[PathBuf]) -> Result<(), String> {
    let mut names = HashSet::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "上传路径缺少有效文件名".to_string())?;
        if !names.insert(name.to_string()) {
            return Err(format!("多个上传路径具有相同名称: {name}"));
        }
    }
    Ok(())
}

fn ensure_unique_remote_names(paths: &[String]) -> Result<(), String> {
    let mut names = HashSet::new();
    for path in paths {
        let name = remote_basename(path)?;
        if !names.insert(name.to_string()) {
            return Err(format!("多个下载路径具有相同名称: {name}"));
        }
    }
    Ok(())
}

fn inspect_local_entry(
    path: &Path,
    depth: usize,
    stats: &mut TransferStats,
    reporter: &ProgressReporter,
) -> Result<(), String> {
    reporter.checkpoint()?;
    check_depth_and_count(depth, stats)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("无法读取本机路径 {}: {error}", path.display()))?;
    if metadata_is_linklike(&metadata) {
        stats.skipped_symlinks += 1;
        return Ok(());
    }
    if metadata.is_file() {
        stats.files += 1;
        stats.bytes = stats.bytes.saturating_add(metadata.len());
    } else if metadata.is_dir() {
        for child in sorted_local_children(path)? {
            inspect_local_entry(&child, depth + 1, stats, reporter)?;
        }
    }
    Ok(())
}

fn inspect_remote_entry(
    sftp: &Sftp,
    path: &str,
    depth: usize,
    stats: &mut TransferStats,
    reporter: &ProgressReporter,
) -> Result<(), String> {
    reporter.checkpoint()?;
    check_depth_and_count(depth, stats)?;
    let metadata = sftp
        .lstat(Path::new(path))
        .map_err(|error| format!("无法读取远程路径 {path}: {error}"))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        stats.skipped_symlinks += 1;
        return Ok(());
    }
    if file_type.is_file() {
        stats.files += 1;
        stats.bytes = stats.bytes.saturating_add(metadata.size.unwrap_or(0));
    } else if file_type.is_dir() {
        for (child, _) in sorted_remote_children(sftp, path)? {
            inspect_remote_entry(sftp, &child, depth + 1, stats, reporter)?;
        }
    }
    Ok(())
}

fn check_depth_and_count(depth: usize, stats: &mut TransferStats) -> Result<(), String> {
    if depth > MAX_DIRECTORY_DEPTH {
        return Err("目录层级超过安全限制".to_string());
    }
    stats.entries += 1;
    if stats.entries > MAX_TRANSFER_ENTRIES {
        return Err("传输条目数量超过安全限制".to_string());
    }
    Ok(())
}

fn sorted_local_children(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let mut children = fs::read_dir(directory)
        .map_err(|error| format!("无法读取本机目录 {}: {error}", directory.display()))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| format!("无法读取本机目录项: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    children.sort();
    Ok(children)
}

fn sorted_remote_children(sftp: &Sftp, directory: &str) -> Result<Vec<(String, FileStat)>, String> {
    let mut children = sftp
        .readdir(Path::new(directory))
        .map_err(|error| format!("无法读取远程目录 {directory}: {error}"))?
        .into_iter()
        .map(|(path, stat)| {
            let path = path
                .to_str()
                .ok_or_else(|| "远程目录包含无法传输的文件名".to_string())?
                .replace('\\', "/");
            validate_remote_path(&path)?;
            Ok((path, stat))
        })
        .collect::<Result<Vec<_>, String>>()?;
    children.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(children)
}

fn upload_recursive_roots(
    connection: &ConnectionSpec,
    session: &Session,
    sftp: &Sftp,
    roots: &[PathBuf],
    remote_directory: &str,
    reporter: &ProgressReporter,
    total: u64,
) -> Result<TransferStats, String> {
    let mut stats = TransferStats {
        sha256_verified: true,
        ..TransferStats::default()
    };
    for root in roots {
        let name = root
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "上传路径缺少有效文件名".to_string())?;
        upload_local_entry(
            connection,
            session,
            sftp,
            root,
            &remote_join(remote_directory, name),
            0,
            reporter,
            total,
            &mut stats,
        )?;
    }
    Ok(stats)
}

fn upload_local_entry(
    connection: &ConnectionSpec,
    session: &Session,
    sftp: &Sftp,
    local_path: &Path,
    remote_path: &str,
    depth: usize,
    reporter: &ProgressReporter,
    total: u64,
    stats: &mut TransferStats,
) -> Result<(), String> {
    reporter.checkpoint()?;
    check_depth_and_count(depth, stats)?;
    let metadata = fs::symlink_metadata(local_path)
        .map_err(|error| format!("无法读取本机路径 {}: {error}", local_path.display()))?;
    if metadata_is_linklike(&metadata) {
        stats.skipped_symlinks += 1;
        return Ok(());
    }
    if metadata.is_dir() {
        ensure_remote_directory(sftp, remote_path)?;
        for child in sorted_local_children(local_path)? {
            let name = child
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| "本机目录包含无法传输的文件名".to_string())?;
            upload_local_entry(
                connection,
                session,
                sftp,
                &child,
                &remote_join(remote_path, name),
                depth + 1,
                reporter,
                total,
                stats,
            )?;
        }
    } else if metadata.is_file() {
        reject_remote_symlink_if_present(sftp, remote_path)?;
        reporter.emit("uploading", remote_path, stats.bytes, Some(total))?;
        let part_path = format!("{remote_path}.vpshell-{}.part", uuid::Uuid::new_v4());
        let expected_size = metadata.len();
        let result = (|| {
            let mut input = fs::File::open(local_path)
                .map_err(|error| format!("无法打开本机文件 {}: {error}", local_path.display()))?;
            let mut output = sftp
                .create(Path::new(&part_path))
                .map_err(|error| format!("无法创建远程临时文件: {error}"))?;
            let bytes_before = stats.bytes;
            copy_with_progress(
                &mut input,
                &mut output,
                remote_path,
                "uploading",
                reporter,
                &mut stats.bytes,
                Some(total),
            )?;
            output
                .flush()
                .map_err(|error| format!("无法刷新远程临时文件: {error}"))?;
            drop(output);
            let copied = stats.bytes.saturating_sub(bytes_before);
            let remote_size = sftp
                .stat(Path::new(&part_path))
                .map_err(|error| format!("无法校验远程临时文件大小: {error}"))?
                .size
                .ok_or_else(|| "SFTP 服务器未返回远程文件大小".to_string())?;
            if copied != expected_size || remote_size != expected_size {
                return Err("上传文件大小校验失败，未提交 .part 文件".to_string());
            }

            let local_hash = sha256_file(local_path, reporter)?;
            if let Some(remote_hash) = remote_sha256(session, &part_path, reporter)? {
                if remote_hash != local_hash {
                    return Err("上传文件 SHA-256 校验失败，未提交 .part 文件".to_string());
                }
            } else {
                stats.sha256_verified = false;
            }
            reporter.checkpoint()?;
            reporter.task.mark_commit_boundary()?;
            sftp.rename(Path::new(&part_path), Path::new(remote_path), None)
                .map_err(|error| format!("无法原子提交远程文件: {error}"))?;
            reporter.task.note_commit();
            Ok(())
        })();
        if result.is_err() {
            cleanup_remote_artifacts(connection, sftp, &[&part_path], None, reporter);
        }
        result?;
        stats.files += 1;
    }
    Ok(())
}

fn download_recursive_roots(
    session: &Session,
    sftp: &Sftp,
    roots: &[String],
    local_directory: &Path,
    reporter: &ProgressReporter,
    total: u64,
) -> Result<TransferStats, String> {
    let mut stats = TransferStats {
        sha256_verified: true,
        ..TransferStats::default()
    };
    for root in roots {
        let name = remote_basename(root)?;
        validate_local_component(name)?;
        download_remote_entry(
            session,
            sftp,
            root,
            &local_directory.join(name),
            local_directory,
            0,
            reporter,
            total,
            &mut stats,
        )?;
    }
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
fn download_remote_entry(
    session: &Session,
    sftp: &Sftp,
    remote_path: &str,
    local_path: &Path,
    local_root: &Path,
    depth: usize,
    reporter: &ProgressReporter,
    total: u64,
    stats: &mut TransferStats,
) -> Result<(), String> {
    reporter.checkpoint()?;
    check_depth_and_count(depth, stats)?;
    ensure_local_destination_safe(local_root, local_path)?;
    let metadata = sftp
        .lstat(Path::new(remote_path))
        .map_err(|error| format!("无法读取远程路径 {remote_path}: {error}"))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        stats.skipped_symlinks += 1;
        return Ok(());
    }
    if file_type.is_dir() {
        fs::create_dir_all(local_path)
            .map_err(|error| format!("无法创建本机目录 {}: {error}", local_path.display()))?;
        for (child, _) in sorted_remote_children(sftp, remote_path)? {
            let name = remote_basename(&child)?;
            validate_local_component(name)?;
            download_remote_entry(
                session,
                sftp,
                &child,
                &local_path.join(name),
                local_root,
                depth + 1,
                reporter,
                total,
                stats,
            )?;
        }
    } else if file_type.is_file() {
        reporter.emit("downloading", remote_path, stats.bytes, Some(total))?;
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("无法创建本机目录 {}: {error}", parent.display()))?;
        }
        ensure_local_destination_safe(local_root, local_path)?;
        if local_path.exists() {
            return Err(format!(
                "为保证原子提交，当前安全模式不覆盖已有文件: {}",
                local_path.display()
            ));
        }
        let local_name = local_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "本机下载文件名无效".to_string())?;
        let part_path = local_path.with_file_name(format!(
            ".{local_name}.vpshell-{}.part",
            uuid::Uuid::new_v4()
        ));
        let expected_size = metadata
            .size
            .ok_or_else(|| "SFTP 服务器未返回远程文件大小".to_string())?;
        let remote_hash = remote_sha256(session, remote_path, reporter)?;
        let result = (|| {
            let mut input = sftp
                .open(Path::new(remote_path))
                .map_err(|error| format!("无法打开远程文件 {remote_path}: {error}"))?;
            let mut output = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&part_path)
                .map_err(|error| format!("无法创建本机临时文件: {error}"))?;
            let bytes_before = stats.bytes;
            copy_with_progress(
                &mut input,
                &mut output,
                remote_path,
                "downloading",
                reporter,
                &mut stats.bytes,
                Some(total),
            )?;
            output
                .flush()
                .map_err(|error| format!("无法刷新本机临时文件: {error}"))?;
            output
                .sync_all()
                .map_err(|error| format!("无法同步本机临时文件: {error}"))?;
            drop(output);
            let copied = stats.bytes.saturating_sub(bytes_before);
            let local_size = fs::metadata(&part_path)
                .map_err(|error| format!("无法校验本机临时文件大小: {error}"))?
                .len();
            if copied != expected_size || local_size != expected_size {
                return Err("下载文件大小校验失败，未提交 .part 文件".to_string());
            }
            if let Some(remote_hash) = remote_hash.as_deref() {
                if sha256_file(&part_path, reporter)? != remote_hash {
                    return Err("下载文件 SHA-256 校验失败，未提交 .part 文件".to_string());
                }
            } else {
                stats.sha256_verified = false;
            }
            reporter.checkpoint()?;
            reporter.task.mark_commit_boundary()?;
            fs::rename(&part_path, local_path)
                .map_err(|error| format!("无法原子提交本机文件: {error}"))?;
            reporter.task.note_commit();
            Ok(())
        })();
        if result.is_err() {
            cleanup_local_file(&part_path, reporter);
        }
        result?;
        stats.files += 1;
    }
    Ok(())
}

fn copy_with_progress<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    current_path: &str,
    phase: &str,
    reporter: &ProgressReporter,
    bytes_done: &mut u64,
    bytes_total: Option<u64>,
) -> Result<(), String> {
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    loop {
        reporter.checkpoint()?;
        let length = input
            .read(&mut buffer)
            .map_err(|error| format!("读取传输数据失败: {error}"))?;
        if length == 0 {
            break;
        }
        output
            .write_all(&buffer[..length])
            .map_err(|error| format!("写入传输数据失败: {error}"))?;
        *bytes_done = bytes_done.saturating_add(length as u64);
        reporter.emit(phase, current_path, *bytes_done, bytes_total)?;
    }
    Ok(())
}

fn ensure_remote_directory(sftp: &Sftp, path: &str) -> Result<(), String> {
    validate_remote_path(path)?;
    if !path.starts_with('/') {
        return Err("远程目录必须是绝对路径".to_string());
    }
    let mut current = String::new();
    for component in path.split('/').filter(|value| !value.is_empty()) {
        if matches!(component, "." | "..") {
            return Err("远程目录包含不安全的路径段".to_string());
        }
        current.push('/');
        current.push_str(component);
        match sftp.lstat(Path::new(&current)) {
            Ok(stat) if stat.file_type().is_symlink() => {
                return Err(format!("远程目录路径包含符号链接: {current}"));
            }
            Ok(stat) if stat.is_dir() => {}
            Ok(_) => return Err(format!("远程路径不是目录: {current}")),
            Err(_) => sftp
                .mkdir(Path::new(&current), 0o755)
                .map_err(|error| format!("无法创建远程目录 {current}: {error}"))?,
        }
    }
    Ok(())
}

fn reject_remote_symlink_if_present(sftp: &Sftp, path: &str) -> Result<(), String> {
    match sftp.lstat(Path::new(path)) {
        Ok(stat) if stat.file_type().is_symlink() => Err(format!("拒绝覆盖远程符号链接: {path}")),
        Ok(stat) if stat.is_dir() => Err(format!("远程目标是目录: {path}")),
        Ok(_) | Err(_) => Ok(()),
    }
}

fn remote_supports_package_mode(
    session: &Session,
    reporter: &ProgressReporter,
) -> Result<bool, String> {
    let status = run_remote_command(
        session,
        "command -v tar >/dev/null 2>&1 && command -v zstd >/dev/null 2>&1",
        reporter,
    )?;
    Ok(status == 0)
}

fn run_remote_command(
    session: &Session,
    command: &str,
    reporter: &ProgressReporter,
) -> Result<i32, String> {
    run_remote_command_capture(session, command, reporter).map(|(status, _)| status)
}

fn run_remote_command_capture(
    session: &Session,
    command: &str,
    reporter: &ProgressReporter,
) -> Result<(i32, String), String> {
    reporter.checkpoint()?;
    if command.len() > 64 * 1024 || command.contains('\0') {
        return Err("远程命令无效或过长".to_string());
    }
    let mut channel = session
        .channel_session()
        .map_err(|_| "无法创建远程命令通道".to_string())?;
    channel
        .handle_extended_data(ExtendedData::Merge)
        .map_err(|_| "无法合并远程命令输出".to_string())?;
    channel
        .exec(command)
        .map_err(|_| "无法执行远程打包命令".to_string())?;
    reporter.checkpoint()?;
    let mut output = Vec::new();
    {
        let mut limited = (&mut channel).take(256 * 1024);
        limited
            .read_to_end(&mut output)
            .map_err(|_| "读取远程命令输出失败".to_string())?;
    }
    io::copy(&mut channel, &mut io::sink()).map_err(|_| "读取远程命令输出失败".to_string())?;
    channel
        .wait_close()
        .map_err(|_| "等待远程命令结束失败".to_string())?;
    reporter.checkpoint()?;
    let status = channel
        .exit_status()
        .map_err(|_| "无法获取远程命令状态".to_string())?;
    Ok((status, String::from_utf8_lossy(&output).into_owned()))
}

fn remote_sha256(
    session: &Session,
    path: &str,
    reporter: &ProgressReporter,
) -> Result<Option<String>, String> {
    validate_remote_path(path)?;
    let quoted_path = quote_posix_literal(path);
    let command = format!(
        "if command -v sha256sum >/dev/null 2>&1; then sha256sum -- {quoted_path}; elif command -v shasum >/dev/null 2>&1; then shasum -a 256 -- {quoted_path}; else exit 125; fi"
    );
    let (status, output) = run_remote_command_capture(session, &command, reporter)?;
    if status == 125 {
        return Ok(None);
    }
    if status != 0 {
        return Err("远程 SHA-256 校验命令失败".to_string());
    }
    let digest = output
        .split_whitespace()
        .next()
        .filter(|value| value.len() == 64 && value.chars().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| "远程 SHA-256 输出无效".to_string())?;
    Ok(Some(digest.to_ascii_lowercase()))
}

fn sha256_file(path: &Path, reporter: &ProgressReporter) -> Result<String, String> {
    let mut file =
        fs::File::open(path).map_err(|error| format!("无法打开文件进行 SHA-256 校验: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    loop {
        reporter.checkpoint()?;
        let length = file
            .read(&mut buffer)
            .map_err(|error| format!("读取文件进行 SHA-256 校验失败: {error}"))?;
        if length == 0 {
            break;
        }
        hasher.update(&buffer[..length]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn upload_package(
    connection: &ConnectionSpec,
    session: &Session,
    sftp: &Sftp,
    roots: &[PathBuf],
    destination: &str,
    transfer_id: &str,
    reporter: &ProgressReporter,
    inventory: &TransferStats,
) -> Result<TransferStats, String> {
    let archive = TempFileGuard::new(transfer_id, "upload.tar.zst");
    reporter.emit("packaging", archive.path().display().to_string(), 0, None)?;
    create_local_archive(roots, archive.path(), reporter)?;

    let remote_home = canonical_remote_path(sftp, ".")?;
    let cache = remote_join(&remote_home, ".cache/vpshell");
    ensure_remote_directory(sftp, &cache)?;
    let remote_archive = remote_join(
        &cache,
        &format!("{}-{}.tar.zst", transfer_id, uuid::Uuid::new_v4()),
    );
    let remote_part = format!("{remote_archive}.part");
    let remote_tar_part = format!("{remote_archive}.tar.part");
    let remote_staging = remote_join(
        &cache,
        &format!("{}-{}.dir.part", transfer_id, uuid::Uuid::new_v4()),
    );

    let result = (|| {
        let archive_size = fs::metadata(archive.path())
            .map_err(|error| format!("无法读取本机打包文件: {error}"))?
            .len();
        let mut input = fs::File::open(archive.path())
            .map_err(|error| format!("无法打开本机打包文件: {error}"))?;
        let mut output = sftp
            .create(Path::new(&remote_part))
            .map_err(|error| format!("无法创建远程打包文件: {error}"))?;
        let mut uploaded = 0_u64;
        copy_with_progress(
            &mut input,
            &mut output,
            &remote_part,
            "uploading-package",
            reporter,
            &mut uploaded,
            Some(archive_size),
        )?;
        output
            .flush()
            .map_err(|error| format!("无法刷新远程打包文件: {error}"))?;
        drop(output);
        let remote_size = sftp
            .stat(Path::new(&remote_part))
            .map_err(|error| format!("无法校验远程打包文件大小: {error}"))?
            .size
            .ok_or_else(|| "SFTP 服务器未返回远程打包文件大小".to_string())?;
        if remote_size != archive_size || uploaded != archive_size {
            return Err("上传打包文件大小校验失败，未提交 .part 文件".to_string());
        }
        let mut sha256_verified = false;
        if let Some(remote_hash) = remote_sha256(session, &remote_part, reporter)? {
            if remote_hash != sha256_file(archive.path(), reporter)? {
                return Err("上传打包文件 SHA-256 校验失败，未提交 .part 文件".to_string());
            }
            sha256_verified = true;
        }
        sftp.rename(Path::new(&remote_part), Path::new(&remote_archive), None)
            .map_err(|error| format!("无法原子提交远程打包文件: {error}"))?;

        ensure_remote_directory(sftp, &remote_staging)?;
        reporter.emit("extracting", &remote_staging, 0, Some(inventory.bytes))?;
        let command = format!(
            "zstd -dc -- {} > {} && tar -xf {} -C {}; status=$?; rm -f -- {}; exit \"$status\"",
            quote_posix_literal(&remote_archive),
            quote_posix_literal(&remote_tar_part),
            quote_posix_literal(&remote_tar_part),
            quote_posix_literal(&remote_staging),
            quote_posix_literal(&remote_tar_part)
        );
        let status = run_remote_command(session, &command, reporter)?;
        if status != 0 {
            return Err("远程 tar+zstd 解包失败".to_string());
        }
        reporter.task.begin_finalizing(destination)?;
        commit_remote_staged_roots(sftp, roots, &remote_staging, destination, reporter)?;
        Ok(TransferStats {
            files: inventory.files,
            bytes: inventory.bytes,
            skipped_symlinks: inventory.skipped_symlinks,
            entries: inventory.entries,
            sha256_verified,
        })
    })();
    cleanup_remote_artifacts(
        connection,
        sftp,
        &[&remote_part, &remote_tar_part, &remote_archive],
        Some(&remote_staging),
        reporter,
    );
    cleanup_local_file(archive.path(), reporter);
    result
}

fn commit_remote_staged_roots(
    sftp: &Sftp,
    roots: &[PathBuf],
    staging_directory: &str,
    destination: &str,
    reporter: &ProgressReporter,
) -> Result<(), String> {
    reporter.checkpoint()?;
    let expected = roots
        .iter()
        .map(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .map(str::to_string)
                .ok_or_else(|| "上传路径缺少有效文件名".to_string())
        })
        .collect::<Result<HashSet<_>, _>>()?;
    let actual = sftp
        .readdir(Path::new(staging_directory))
        .map_err(|error| format!("无法读取远程解包临时目录: {error}"))?
        .into_iter()
        .map(|(path, _)| {
            let path = path
                .to_str()
                .ok_or_else(|| "远程解包条目名称无效".to_string())?
                .replace('\\', "/");
            remote_basename(&path).map(str::to_string)
        })
        .collect::<Result<HashSet<_>, _>>()?;
    if actual != expected {
        return Err("远程解包的顶层条目与请求不一致，拒绝提交".to_string());
    }

    for name in &expected {
        reporter.checkpoint()?;
        let target = remote_join(destination, name);
        if sftp.lstat(Path::new(&target)).is_ok() {
            return Err(format!(
                "为保证原子提交，打包模式不覆盖已有远程路径: {target}"
            ));
        }
    }

    let mut committed: Vec<String> = Vec::new();
    for name in &expected {
        let source = remote_join(staging_directory, name);
        let target = remote_join(destination, name);
        if let Err(error) = sftp.rename(Path::new(&source), Path::new(&target), None) {
            for committed_name in committed.iter().rev() {
                match sftp.rename(
                    Path::new(&remote_join(destination, committed_name)),
                    Path::new(&remote_join(staging_directory, committed_name)),
                    None,
                ) {
                    Ok(()) => reporter.task.note_rollback(),
                    Err(rollback_error) => reporter.task.cleanup_warning(format!(
                        "远程提交回滚失败（{committed_name}）: {rollback_error}"
                    )),
                }
            }
            return Err(format!("无法原子提交远程条目: {error}"));
        }
        committed.push(name.clone());
        reporter.task.note_commit();
    }
    Ok(())
}

fn remove_remote_tree(sftp: &Sftp, path: &str, depth: usize) -> Result<(), String> {
    if depth > MAX_DIRECTORY_DEPTH {
        return Err("远程临时目录层级超过安全限制".to_string());
    }
    let stat = match sftp.lstat(Path::new(path)) {
        Ok(stat) => stat,
        Err(error) if is_sftp_not_found(&error) => return Ok(()),
        Err(error) => return Err(format!("无法检查远程临时路径 {path}: {error}")),
    };
    if stat.file_type().is_dir() {
        for (child, _) in sorted_remote_children(sftp, path)? {
            remove_remote_tree(sftp, &child, depth + 1)?;
        }
        sftp.rmdir(Path::new(path))
            .map_err(|error| format!("无法清理远程临时目录: {error}"))
    } else {
        sftp.unlink(Path::new(path))
            .map_err(|error| format!("无法清理远程临时文件: {error}"))
    }
}

fn cleanup_remote_artifacts(
    connection: &ConnectionSpec,
    sftp: &Sftp,
    files: &[&str],
    tree: Option<&str>,
    reporter: &ProgressReporter,
) {
    reporter.task.begin_cleanup();
    let mut failed_files = Vec::new();
    for path in files {
        if remove_remote_file_if_present(sftp, path).is_err() {
            failed_files.push((*path).to_string());
        }
    }
    let mut failed_tree = tree
        .map(|path| remove_remote_tree(sftp, path, 0).is_err())
        .unwrap_or(false);

    if failed_files.is_empty() && !failed_tree {
        return;
    }

    let retry = (|| {
        let session =
            connect(connection).map_err(|error| format!("无法重连以清理传输临时文件: {error}"))?;
        let retry_sftp = session
            .sftp()
            .map_err(|_| "无法重建 SFTP 子系统以清理临时文件".to_string())?;
        failed_files.retain(|path| remove_remote_file_if_present(&retry_sftp, path).is_err());
        if failed_tree {
            failed_tree = tree
                .map(|path| remove_remote_tree(&retry_sftp, path, 0).is_err())
                .unwrap_or(false);
        }
        Ok::<(), String>(())
    })();

    if let Err(error) = retry {
        reporter.task.cleanup_warning(error);
    }
    if !failed_files.is_empty() {
        reporter.task.cleanup_warning(format!(
            "远程临时文件清理不完整: {}",
            failed_files.join(", ")
        ));
    }
    if failed_tree {
        reporter.task.cleanup_warning(format!(
            "远程临时目录清理不完整: {}",
            tree.unwrap_or_default()
        ));
    }
}

fn remove_remote_file_if_present(sftp: &Sftp, path: &str) -> Result<(), String> {
    match sftp.lstat(Path::new(path)) {
        Err(error) if is_sftp_not_found(&error) => Ok(()),
        Err(error) => Err(format!("无法检查远程临时文件 {path}: {error}")),
        Ok(stat) if stat.is_dir() => Err(format!("远程临时路径意外成为目录: {path}")),
        Ok(_) => sftp
            .unlink(Path::new(path))
            .map_err(|error| format!("无法清理远程临时文件 {path}: {error}")),
    }
}

fn is_sftp_not_found(error: &ssh2::Error) -> bool {
    matches!(error.code(), ErrorCode::SFTP(2))
}

fn cleanup_local_file(path: &Path, reporter: &ProgressReporter) {
    reporter.task.begin_cleanup();
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => reporter.task.cleanup_warning(format!(
            "本机临时文件清理失败（{}）: {error}",
            path.display()
        )),
    }
}

fn cleanup_local_tree(path: &Path, reporter: &ProgressReporter) {
    reporter.task.begin_cleanup();
    match fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => reporter.task.cleanup_warning(format!(
            "本机临时目录清理失败（{}）: {error}",
            path.display()
        )),
    }
}

fn create_local_archive(
    roots: &[PathBuf],
    archive_path: &Path,
    reporter: &ProgressReporter,
) -> Result<(), String> {
    reporter.checkpoint()?;
    let output =
        fs::File::create(archive_path).map_err(|error| format!("无法创建本机打包文件: {error}"))?;
    let encoder = zstd::stream::write::Encoder::new(output, 3)
        .map_err(|error| format!("无法初始化 zstd 压缩: {error}"))?;
    let mut builder = tar::Builder::new(encoder);
    builder.follow_symlinks(false);
    for root in roots {
        let name = root
            .file_name()
            .ok_or_else(|| "上传路径缺少文件名".to_string())?;
        append_local_archive_entry(&mut builder, root, Path::new(name), 0, reporter)?;
    }
    let encoder = builder
        .into_inner()
        .map_err(|error| format!("无法完成 tar 打包: {error}"))?;
    encoder
        .finish()
        .map_err(|error| format!("无法完成 zstd 压缩: {error}"))?;
    reporter.checkpoint()?;
    validate_archive_contents(archive_path, None, reporter)?;
    Ok(())
}

fn append_local_archive_entry<W: Write>(
    builder: &mut tar::Builder<W>,
    source: &Path,
    archive_path: &Path,
    depth: usize,
    reporter: &ProgressReporter,
) -> Result<(), String> {
    reporter.checkpoint()?;
    if depth > MAX_DIRECTORY_DEPTH {
        return Err("目录层级超过安全限制".to_string());
    }
    validate_archive_path(archive_path)?;
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("无法读取本机路径 {}: {error}", source.display()))?;
    if metadata_is_linklike(&metadata) {
        return Ok(());
    }
    if metadata.is_dir() {
        builder
            .append_dir(archive_path, source)
            .map_err(|error| format!("无法加入目录 {}: {error}", source.display()))?;
        for child in sorted_local_children(source)? {
            let name = child
                .file_name()
                .ok_or_else(|| "本机目录包含无效文件名".to_string())?;
            append_local_archive_entry(
                builder,
                &child,
                &archive_path.join(name),
                depth + 1,
                reporter,
            )?;
        }
    } else if metadata.is_file() {
        let mut input = fs::File::open(source)
            .map_err(|error| format!("无法打开待打包文件 {}: {error}", source.display()))?;
        let mut header = tar::Header::new_gnu();
        header.set_metadata(&metadata);
        header.set_cksum();
        let mut input = CancellableReader::new(&mut input, reporter.task.clone());
        builder
            .append_data(&mut header, archive_path, &mut input)
            .map_err(|error| format!("无法加入文件 {}: {error}", source.display()))?;
    }
    Ok(())
}

fn download_package(
    connection: &ConnectionSpec,
    session: &Session,
    sftp: &Sftp,
    roots: &[String],
    local_directory: &Path,
    transfer_id: &str,
    reporter: &ProgressReporter,
    inventory: &TransferStats,
) -> Result<TransferStats, String> {
    let remote_home = canonical_remote_path(sftp, ".")?;
    let cache = remote_join(&remote_home, ".cache/vpshell");
    ensure_remote_directory(sftp, &cache)?;
    let remote_archive = remote_join(
        &cache,
        &format!("{}-{}.tar.zst", transfer_id, uuid::Uuid::new_v4()),
    );
    let remote_part = format!("{remote_archive}.part");
    let remote_tar_part = format!("{remote_archive}.tar.part");
    let local_archive = TempFileGuard::new(transfer_id, "download.tar.zst.part");

    let result = (|| {
        let mut tar_arguments = String::new();
        for root in roots {
            let parent = remote_parent(root)?;
            let name = remote_basename(root)?;
            tar_arguments.push_str(" -C ");
            tar_arguments.push_str(&quote_posix_literal(parent));
            tar_arguments.push(' ');
            tar_arguments.push_str(&quote_posix_literal(&format!("./{name}")));
        }
        let command = format!(
            "tar -cf {}{tar_arguments} && zstd -q -T0 -f {} -o {}; status=$?; rm -f -- {}; exit \"$status\"",
            quote_posix_literal(&remote_tar_part),
            quote_posix_literal(&remote_tar_part),
            quote_posix_literal(&remote_part),
            quote_posix_literal(&remote_tar_part)
        );
        reporter.emit("packaging", roots.join(", "), 0, Some(inventory.bytes))?;
        let status = run_remote_command(session, &command, reporter)?;
        if status != 0 {
            return Err("远程 tar+zstd 打包失败".to_string());
        }

        let archive_size = sftp
            .stat(Path::new(&remote_part))
            .map_err(|error| format!("无法读取远程打包文件: {error}"))?
            .size
            .ok_or_else(|| "SFTP 服务器未返回远程打包文件大小".to_string())?;
        let remote_hash = remote_sha256(session, &remote_part, reporter)?;
        sftp.rename(Path::new(&remote_part), Path::new(&remote_archive), None)
            .map_err(|error| format!("无法原子提交远程打包文件: {error}"))?;
        let mut input = sftp
            .open(Path::new(&remote_archive))
            .map_err(|error| format!("无法打开远程打包文件: {error}"))?;
        let mut output = fs::File::create(local_archive.path())
            .map_err(|error| format!("无法创建本机打包文件: {error}"))?;
        let mut downloaded = 0_u64;
        copy_with_progress(
            &mut input,
            &mut output,
            &remote_archive,
            "downloading-package",
            reporter,
            &mut downloaded,
            Some(archive_size),
        )?;
        output
            .flush()
            .map_err(|error| format!("无法刷新本机打包文件: {error}"))?;
        output
            .sync_all()
            .map_err(|error| format!("无法同步本机打包文件: {error}"))?;
        drop(output);
        if downloaded != archive_size
            || fs::metadata(local_archive.path())
                .map_err(|error| format!("无法校验本机打包文件大小: {error}"))?
                .len()
                != archive_size
        {
            return Err("下载打包文件大小校验失败，未处理临时文件".to_string());
        }
        let mut sha256_verified = false;
        if let Some(remote_hash) = remote_hash {
            if sha256_file(local_archive.path(), reporter)? != remote_hash {
                return Err("下载打包文件 SHA-256 校验失败，未处理临时文件".to_string());
            }
            sha256_verified = true;
        }

        reporter.emit(
            "extracting",
            local_directory.display().to_string(),
            0,
            Some(inventory.bytes),
        )?;
        let staging_directory =
            local_directory.join(format!(".vpshell-{}.part", uuid::Uuid::new_v4()));
        fs::create_dir(&staging_directory)
            .map_err(|error| format!("无法创建本机解包临时目录: {error}"))?;
        let staging_directory = staging_directory
            .canonicalize()
            .map_err(|error| format!("无法规范化本机解包临时目录: {error}"))?;
        let extract_result = (|| {
            extract_archive_safely(
                local_archive.path(),
                &staging_directory,
                inventory.bytes,
                reporter,
            )?;
            reporter
                .task
                .begin_finalizing(local_directory.display().to_string())?;
            commit_staged_roots(roots, &staging_directory, local_directory, reporter)
        })();
        cleanup_local_tree(&staging_directory, reporter);
        extract_result?;
        Ok(TransferStats {
            files: inventory.files,
            bytes: inventory.bytes,
            skipped_symlinks: inventory.skipped_symlinks,
            entries: inventory.entries,
            sha256_verified,
        })
    })();
    cleanup_remote_artifacts(
        connection,
        sftp,
        &[&remote_part, &remote_tar_part, &remote_archive],
        None,
        reporter,
    );
    cleanup_local_file(local_archive.path(), reporter);
    result
}

fn commit_staged_roots(
    roots: &[String],
    staging_directory: &Path,
    destination: &Path,
    reporter: &ProgressReporter,
) -> Result<(), String> {
    reporter.checkpoint()?;
    let expected = roots
        .iter()
        .map(|path| remote_basename(path).map(str::to_string))
        .collect::<Result<HashSet<_>, _>>()?;
    let actual = fs::read_dir(staging_directory)
        .map_err(|error| format!("无法读取本机解包临时目录: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("无法读取本机解包条目: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "本机解包条目名称无效".to_string())
        })
        .collect::<Result<HashSet<_>, _>>()?;
    if actual != expected {
        return Err("打包文件的顶层条目与请求不一致，拒绝提交".to_string());
    }

    for name in &expected {
        reporter.checkpoint()?;
        let target = destination.join(name);
        if target.exists() {
            return Err(format!(
                "为保证原子提交，当前安全模式不覆盖已有路径: {}",
                target.display()
            ));
        }
    }

    let mut committed: Vec<String> = Vec::new();
    for name in &expected {
        let source = staging_directory.join(name);
        let target = destination.join(name);
        if let Err(error) = fs::rename(&source, &target) {
            for committed_name in committed.iter().rev() {
                match fs::rename(
                    destination.join(committed_name),
                    staging_directory.join(committed_name),
                ) {
                    Ok(()) => reporter.task.note_rollback(),
                    Err(rollback_error) => reporter.task.cleanup_warning(format!(
                        "本机提交回滚失败（{committed_name}）: {rollback_error}"
                    )),
                }
            }
            return Err(format!("无法原子提交下载条目: {error}"));
        }
        committed.push(name.clone());
        reporter.task.note_commit();
    }
    Ok(())
}

fn validate_archive_contents(
    archive_path: &Path,
    expected_bytes: Option<u64>,
    reporter: &ProgressReporter,
) -> Result<(), String> {
    let input =
        fs::File::open(archive_path).map_err(|error| format!("无法打开打包文件: {error}"))?;
    let decoder = zstd::stream::read::Decoder::new(input)
        .map_err(|error| format!("无法初始化 zstd 校验: {error}"))?;
    let mut archive = tar::Archive::new(decoder);
    let mut entries_seen = 0_u64;
    let mut bytes_seen = 0_u64;
    let maximum_bytes = expected_bytes.map(maximum_archive_bytes);
    for entry in archive
        .entries()
        .map_err(|error| format!("无法读取 tar 目录: {error}"))?
    {
        reporter.checkpoint()?;
        let entry = entry.map_err(|error| format!("无法读取 tar 条目: {error}"))?;
        entries_seen += 1;
        if entries_seen > MAX_TRANSFER_ENTRIES {
            return Err("打包文件条目数量超过安全限制".to_string());
        }
        let path = entry
            .path()
            .map_err(|error| format!("tar 路径无效: {error}"))?
            .into_owned();
        validate_archive_entry(&path, entry.header().entry_type())?;
        bytes_seen = bytes_seen.saturating_add(entry.size());
        if maximum_bytes.is_some_and(|maximum| bytes_seen > maximum) {
            return Err("打包文件解压大小超过安全限制".to_string());
        }
    }
    Ok(())
}

fn extract_archive_safely(
    archive_path: &Path,
    destination: &Path,
    expected_bytes: u64,
    reporter: &ProgressReporter,
) -> Result<(), String> {
    validate_archive_contents(archive_path, Some(expected_bytes), reporter)?;
    let input =
        fs::File::open(archive_path).map_err(|error| format!("无法打开下载的打包文件: {error}"))?;
    let decoder = zstd::stream::read::Decoder::new(input)
        .map_err(|error| format!("无法初始化 zstd 解压: {error}"))?;
    let mut archive = tar::Archive::new(decoder);
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);
    archive.set_unpack_xattrs(false);
    let mut entries_seen = 0_u64;
    let mut bytes_seen = 0_u64;
    let maximum_bytes = maximum_archive_bytes(expected_bytes);
    let entries = archive
        .entries()
        .map_err(|error| format!("无法读取 tar 目录: {error}"))?;
    for entry in entries {
        reporter.checkpoint()?;
        let mut entry = entry.map_err(|error| format!("无法读取 tar 条目: {error}"))?;
        entries_seen += 1;
        if entries_seen > MAX_TRANSFER_ENTRIES {
            return Err("打包文件条目数量超过安全限制".to_string());
        }
        bytes_seen = bytes_seen.saturating_add(entry.size());
        if bytes_seen > maximum_bytes {
            return Err("打包文件解压大小超过安全限制".to_string());
        }
        let path = entry
            .path()
            .map_err(|error| format!("tar 路径无效: {error}"))?
            .into_owned();
        validate_archive_entry(&path, entry.header().entry_type())?;
        ensure_archive_destination_safe(destination, &path)?;
        entry.set_preserve_permissions(false);
        let unpacked = entry
            .unpack_in(destination)
            .map_err(|error| format!("无法安全解包 {}: {error}", path.display()))?;
        if !unpacked {
            return Err(format!("tar 条目试图写出目标目录: {}", path.display()));
        }
    }
    Ok(())
}

fn maximum_archive_bytes(expected_bytes: u64) -> u64 {
    expected_bytes
        .saturating_add(64 * 1024 * 1024)
        .max(64 * 1024 * 1024)
}

fn validate_archive_entry(path: &Path, entry_type: tar::EntryType) -> Result<(), String> {
    validate_archive_path(path)?;
    if entry_type.is_symlink() || entry_type.is_hard_link() {
        return Err(format!("打包文件包含链接条目: {}", path.display()));
    }
    if !entry_type.is_file() && !entry_type.is_dir() {
        return Err(format!("打包文件包含不支持的条目: {}", path.display()));
    }
    Ok(())
}

fn validate_archive_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() || path.as_os_str().len() > MAX_PATH_LENGTH {
        return Err("打包文件包含空路径或超长路径".to_string());
    }
    let mut normal_components = 0_usize;
    for component in path.components() {
        match component {
            Component::Normal(_) => normal_components += 1,
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("打包文件包含路径穿越: {}", path.display()));
            }
        }
    }
    if normal_components == 0 {
        return Err("打包文件包含空路径".to_string());
    }
    Ok(())
}

fn prepare_local_directory(path: &str) -> Result<PathBuf, String> {
    validate_local_path_text(path)?;
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err("下载目录必须是绝对路径".to_string());
    }
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && metadata_is_linklike(&metadata)
    {
        return Err("下载目录不能是符号链接或重解析点".to_string());
    }
    fs::create_dir_all(&path)
        .map_err(|error| format!("无法创建下载目录 {}: {error}", path.display()))?;
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("无法读取下载目录 {}: {error}", path.display()))?;
    if !metadata.is_dir() {
        return Err("下载目标不是目录".to_string());
    }
    path.canonicalize()
        .map_err(|error| format!("无法规范化下载目录: {error}"))
}

fn validate_local_component(name: &str) -> Result<(), String> {
    if name.is_empty()
        || matches!(name, "." | "..")
        || name.contains(['/', '\\', '\0'])
        || name.chars().any(|value| matches!(value, '\r' | '\n'))
        || Path::new(name).components().count() != 1
    {
        return Err(format!("远程文件名无法安全保存到本机: {name}"));
    }
    Ok(())
}

fn ensure_local_destination_safe(root: &Path, target: &Path) -> Result<(), String> {
    if !target.starts_with(root) {
        return Err("本机目标路径超出下载目录".to_string());
    }
    if let Ok(metadata) = fs::symlink_metadata(target)
        && metadata_is_linklike(&metadata)
    {
        return Err(format!("拒绝覆盖本机符号链接: {}", target.display()));
    }
    let mut current = target.parent();
    while let Some(path) = current {
        if path == root.parent().unwrap_or(root) {
            break;
        }
        if let Ok(metadata) = fs::symlink_metadata(path)
            && metadata_is_linklike(&metadata)
        {
            return Err(format!("本机目标路径包含符号链接: {}", path.display()));
        }
        if path == root {
            break;
        }
        current = path.parent();
    }
    Ok(())
}

fn ensure_archive_destination_safe(root: &Path, relative: &Path) -> Result<(), String> {
    validate_archive_path(relative)?;
    ensure_local_destination_safe(root, &root.join(relative))
}

fn quote_posix_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(windows)]
fn metadata_is_linklike(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_linklike(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_connection() -> ConnectionSpec {
        ConnectionSpec {
            host: "example.com".to_string(),
            port: 22,
            username: "root".to_string(),
            credential_ref: None,
            identity_file: None,
            identity_passphrase_ref: None,
        }
    }

    #[test]
    fn rejects_invalid_connection_fields() {
        let mut connection = valid_connection();
        connection.host = "-oProxyCommand=bad".to_string();
        assert!(validate_connection(&connection).is_err());

        let mut connection = valid_connection();
        connection.username = "bad@user".to_string();
        assert!(validate_connection(&connection).is_err());

        let mut connection = valid_connection();
        connection.credential_ref = Some("wrong-reference".to_string());
        assert!(validate_connection(&connection).is_err());
    }

    #[test]
    fn validates_transfer_ids() {
        assert!(validate_transfer_id("transfer_01-abc").is_ok());
        assert!(validate_transfer_id("").is_err());
        assert!(validate_transfer_id("contains space").is_err());
        assert!(validate_transfer_id("../escape").is_err());
    }

    #[test]
    fn parses_only_known_host_key_fields() {
        let mut key_types = HashSet::new();
        collect_known_host_key_types(
            "# Host example found: line 1\nexample ssh-ed25519 AAAA comment ssh-rsa\n\
             @cert-authority *.example ecdsa-sha2-nistp256 AAAA\n",
            &mut key_types,
        );
        assert!(key_types.contains("ssh-ed25519"));
        assert!(key_types.contains("ecdsa-sha2-nistp256"));
        assert!(!key_types.contains("ssh-rsa"));
    }

    #[test]
    fn parses_scanned_and_marked_host_keys_without_comments() {
        let encoded = BASE64_STANDARD.encode(b"test-host-key");
        let output = format!(
            "# scan comment\nexample ssh-ed25519 {encoded}\n\
             @cert-authority *.example ssh-rsa {encoded} comment\n\
             malformed unsupported {encoded}\n"
        );
        let keys = parse_host_key_lines(&output);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].algorithm, "ssh-ed25519");
        assert_eq!(keys[1].algorithm, "ssh-rsa");
        assert_eq!(keys[0].key, b"test-host-key");
    }

    #[test]
    fn prioritizes_modern_host_key_algorithms() {
        assert!(
            host_key_algorithm_priority("ssh-ed25519")
                < host_key_algorithm_priority("ecdsa-sha2-nistp256")
        );
        assert!(
            host_key_algorithm_priority("ecdsa-sha2-nistp256")
                < host_key_algorithm_priority("ssh-rsa")
        );
    }

    #[test]
    fn selects_only_kex_algorithms_the_openssh_binary_reports() {
        let selected = select_openssh_kex_algorithms(
            "curve25519-sha256\ncurve25519-sha256@libssh.org\n\
             diffie-hellman-group14-sha256\ndiffie-hellman-group14-sha1\n",
        )
        .unwrap();
        assert_eq!(
            selected,
            "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256"
        );
        assert!(!selected.contains("sntrup"));
        assert!(!selected.contains("group14-sha1"));
    }

    #[test]
    fn classifies_disconnects_before_the_server_host_key() {
        let message =
            host_key_probe_failure("kex_exchange_identification: Connection closed by remote host");
        assert!(message.contains("主动关闭"));
        assert!(message.contains("MaxStartups"));
        assert!(!message.contains("没有共同"));
    }

    #[test]
    fn classifies_missing_safe_key_exchange_separately() {
        let message =
            host_key_probe_failure("Unable to negotiate: no matching key exchange method found");
        assert!(message.contains("没有共同的安全 KEX"));
        assert!(message.contains("SHA-1"));
    }

    #[test]
    fn formats_known_host_markers_for_default_and_custom_ports() {
        assert_eq!(known_host_marker("example.com", 22), "example.com");
        assert_eq!(known_host_marker("example.com", 2202), "[example.com]:2202");
        assert_eq!(
            known_host_marker("[2001:db8::1]", 2202),
            "[2001:db8::1]:2202"
        );
    }

    #[test]
    fn quotes_posix_literals_without_interpolation() {
        assert_eq!(quote_posix_literal("simple"), "'simple'");
        assert_eq!(
            quote_posix_literal("a'b; $(touch bad)"),
            "'a'\"'\"'b; $(touch bad)'"
        );
    }

    #[test]
    fn rejects_archive_path_traversal() {
        assert!(validate_archive_path(Path::new("safe/file.txt")).is_ok());
        assert!(validate_archive_path(Path::new("../escape.txt")).is_err());
        assert!(validate_archive_path(Path::new("safe/../../escape.txt")).is_err());
        assert!(validate_archive_path(Path::new("/absolute/file.txt")).is_err());
    }

    #[test]
    fn rejects_archive_links_and_special_entries() {
        let path = Path::new("safe/name");
        assert!(validate_archive_entry(path, tar::EntryType::Regular).is_ok());
        assert!(validate_archive_entry(path, tar::EntryType::Directory).is_ok());
        assert!(validate_archive_entry(path, tar::EntryType::Symlink).is_err());
        assert!(validate_archive_entry(path, tar::EntryType::Link).is_err());
        assert!(validate_archive_entry(path, tar::EntryType::Fifo).is_err());
    }
}

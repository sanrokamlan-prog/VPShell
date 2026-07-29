use std::{
    collections::HashSet,
    env, fs,
    io::{self, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh2::{CheckResult, ExtendedData, FileStat, KnownHostFileKind, Session, Sftp};
use tauri::{AppHandle, Emitter};
use zeroize::Zeroizing;

use crate::{CREDENTIAL_SERVICE, LEGACY_CREDENTIAL_SERVICE};

const MAX_HOST_LENGTH: usize = 255;
const MAX_USERNAME_LENGTH: usize = 128;
const MAX_PATH_LENGTH: usize = 4096;
const MAX_TRANSFER_PATHS: usize = 256;
const MAX_TRANSFER_ID_LENGTH: usize = 128;
const MAX_DIRECTORY_DEPTH: usize = 128;
const MAX_TRANSFER_ENTRIES: u64 = 1_000_000;
const MAX_KNOWN_HOSTS_SIZE: u64 = 16 * 1024 * 1024;
const COPY_BUFFER_SIZE: usize = 128 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectionSpec {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: String,
    pub(crate) credential_ref: Option<String>,
    pub(crate) identity_file: Option<String>,
    pub(crate) identity_passphrase_ref: Option<String>,
    pub(crate) proxy_jump: Option<String>,
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
pub(crate) struct TransferResult {
    transfer_id: String,
    mode: String,
    files_transferred: u64,
    bytes_transferred: u64,
    skipped_symlinks: u64,
    fallback_used: bool,
    resumable: bool,
    verification: String,
    limitations: Vec<String>,
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
}

impl ProgressReporter {
    fn emit(
        &self,
        phase: impl Into<String>,
        current_path: impl Into<String>,
        bytes_done: u64,
        bytes_total: Option<u64>,
    ) {
        let _ = self.app.emit(
            "transfer-progress",
            TransferProgress {
                transfer_id: self.transfer_id.clone(),
                phase: phase.into(),
                current_path: current_path.into(),
                transferred_bytes: bytes_done,
                total_bytes: bytes_total,
            },
        );
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
pub(crate) async fn upload_remote(
    app: AppHandle,
    connection: ConnectionSpec,
    local_paths: Vec<String>,
    remote_directory: String,
    package_transfer: bool,
    transfer_id: String,
) -> Result<TransferResult, String> {
    validate_transfer_id(&transfer_id)?;
    let reporter = ProgressReporter {
        app,
        transfer_id: transfer_id.clone(),
    };
    tauri::async_runtime::spawn_blocking(move || {
        upload_paths_blocking(
            connection,
            local_paths,
            remote_directory,
            package_transfer,
            transfer_id,
            reporter,
        )
    })
    .await
    .map_err(|error| format!("SFTP 上传任务异常结束: {error}"))?
}

#[tauri::command]
pub(crate) async fn download_remote(
    app: AppHandle,
    connection: ConnectionSpec,
    remote_paths: Vec<String>,
    local_directory: String,
    package_transfer: bool,
    transfer_id: String,
) -> Result<TransferResult, String> {
    validate_transfer_id(&transfer_id)?;
    let reporter = ProgressReporter {
        app,
        transfer_id: transfer_id.clone(),
    };
    tauri::async_runtime::spawn_blocking(move || {
        download_paths_blocking(
            connection,
            remote_paths,
            local_directory,
            package_transfer,
            transfer_id,
            reporter,
        )
    })
    .await
    .map_err(|error| format!("SFTP 下载任务异常结束: {error}"))?
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
        inspect_local_entry(root, 0, &mut inventory)?;
    }
    if inventory.files == 0 {
        return Err("没有可上传的普通文件（符号链接会被跳过）".to_string());
    }

    reporter.emit("connecting", "", 0, Some(inventory.bytes));
    let session = connect(&connection)?;
    let sftp = session
        .sftp()
        .map_err(|_| "无法建立 SFTP 子系统".to_string())?;
    let destination = canonical_remote_directory(&sftp, &remote_directory)?;

    let mut fallback_used = false;
    let result = if package {
        reporter.emit("checking", "tar + zstd", 0, Some(inventory.bytes));
        if remote_supports_package_mode(&session)? {
            upload_package(
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
            reporter.emit("fallback", "recursive SFTP", 0, Some(inventory.bytes));
            upload_recursive_roots(
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
            &session,
            &sftp,
            &roots,
            &destination,
            &reporter,
            inventory.bytes,
        )?
    };

    reporter.emit("completed", destination, result.bytes, Some(result.bytes));
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

    reporter.emit("connecting", "", 0, None);
    let session = connect(&connection)?;
    let sftp = session
        .sftp()
        .map_err(|_| "无法建立 SFTP 子系统".to_string())?;
    let roots = resolve_remote_roots(&sftp, &requested_paths)?;
    ensure_unique_remote_names(&roots)?;

    let mut inventory = TransferStats::default();
    for root in &roots {
        inspect_remote_entry(&sftp, root, 0, &mut inventory)?;
    }
    if inventory.files == 0 {
        return Err("没有可下载的普通文件（符号链接不会下载）".to_string());
    }

    let mut fallback_used = false;
    let result = if package {
        reporter.emit("checking", "tar + zstd", 0, Some(inventory.bytes));
        if remote_supports_package_mode(&session)? {
            download_package(
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
            reporter.emit("fallback", "recursive SFTP", 0, Some(inventory.bytes));
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

    reporter.emit(
        "completed",
        local_root.display().to_string(),
        result.bytes,
        Some(result.bytes),
    );
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
    })
}

pub(crate) fn validate_connection(connection: &ConnectionSpec) -> Result<(), String> {
    let host = connection.host.trim();
    let username = connection.username.trim();
    if host.is_empty() || host.len() > MAX_HOST_LENGTH || connection.port == 0 {
        return Err("SFTP 主机地址或端口无效".to_string());
    }
    if host.starts_with('-')
        || host
            .chars()
            .any(|value| value.is_whitespace() || value.is_control())
    {
        return Err("SFTP 主机地址格式无效".to_string());
    }
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
    if connection
        .proxy_jump
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        return Err("SFTP 当前仅支持直连主机，ProxyJump 将在后续版本支持".to_string());
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

fn validate_optional_reference(reference: Option<&str>, prefix: &str) -> Result<(), String> {
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
    let mut last_error = None;
    let addresses = (connection.host.as_str(), connection.port)
        .to_socket_addrs()
        .map_err(|_| "无法解析 SFTP 主机地址".to_string())?;
    let mut tcp = None;
    for address in addresses.take(16) {
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
            .map(|error| format!("无法连接 SFTP 主机: {error}"))
            .unwrap_or_else(|| "SFTP 主机没有可用地址".to_string())
    })?;
    tcp.set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("无法设置 SFTP 读取超时: {error}"))?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("无法设置 SFTP 写入超时: {error}"))?;

    let mut session = Session::new().map_err(|_| "无法初始化 SSH 会话".to_string())?;
    session.set_tcp_stream(tcp);
    session.set_timeout(IO_TIMEOUT.as_millis() as u32);
    session
        .handshake()
        .map_err(|_| "SSH 握手失败".to_string())?;
    verify_known_host(&session, &connection.host, connection.port)?;
    authenticate(&session, connection)?;
    Ok(session)
}

fn verify_known_host(session: &Session, host: &str, port: u16) -> Result<(), String> {
    let mut known_hosts = session
        .known_hosts()
        .map_err(|_| "无法初始化 known_hosts 校验".to_string())?;
    let files = known_hosts_files();
    let mut loaded_files = 0_u32;
    for path in files.iter().filter(|path| path.is_file()) {
        let metadata = fs::metadata(path).map_err(|_| "无法读取 known_hosts 文件".to_string())?;
        if metadata.len() > MAX_KNOWN_HOSTS_SIZE {
            return Err(format!("known_hosts 文件过大: {}", path.display()));
        }
        known_hosts
            .read_file(path, KnownHostFileKind::OpenSSH)
            .map_err(|_| format!("无法解析 known_hosts 文件: {}", path.display()))?;
        loaded_files += 1;
    }
    if loaded_files == 0 {
        return Err(
            "未找到现有 OpenSSH known_hosts；请先用系统 ssh 核验并保存主机指纹".to_string(),
        );
    }
    let (key, _) = session
        .host_key()
        .ok_or_else(|| "SSH 服务器未提供主机密钥".to_string())?;
    match known_hosts.check_port(host, port, key) {
        CheckResult::Match => Ok(()),
        CheckResult::Mismatch => Err("SSH 主机密钥与 known_hosts 不匹配，已拒绝连接".to_string()),
        CheckResult::NotFound => {
            Err("SSH 主机不在 known_hosts 中；请先用系统 ssh 核验并保存主机指纹".to_string())
        }
        CheckResult::Failure => Err("SSH 主机密钥校验失败，已拒绝连接".to_string()),
    }
}

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
    if let Some(identity_file) = connection.identity_file.as_deref() {
        let passphrase = connection
            .identity_passphrase_ref
            .as_deref()
            .map(|reference| read_secret(reference, "未找到已保存的私钥口令"))
            .transpose()?;
        let result = session.userauth_pubkey_file(
            connection.username.trim(),
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
        let result = session.userauth_password(connection.username.trim(), &password);
        if result.is_ok() && session.authenticated() {
            return Ok(());
        }
    }

    if session.userauth_agent(connection.username.trim()).is_ok() && session.authenticated() {
        return Ok(());
    }

    Err("SFTP 身份验证失败；请检查私钥、凭据或 ssh-agent".to_string())
}

fn read_secret(reference: &str, missing_message: &str) -> Result<Zeroizing<String>, String> {
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

fn inspect_local_entry(path: &Path, depth: usize, stats: &mut TransferStats) -> Result<(), String> {
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
            inspect_local_entry(&child, depth + 1, stats)?;
        }
    }
    Ok(())
}

fn inspect_remote_entry(
    sftp: &Sftp,
    path: &str,
    depth: usize,
    stats: &mut TransferStats,
) -> Result<(), String> {
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
            inspect_remote_entry(sftp, &child, depth + 1, stats)?;
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
    session: &Session,
    sftp: &Sftp,
    local_path: &Path,
    remote_path: &str,
    depth: usize,
    reporter: &ProgressReporter,
    total: u64,
    stats: &mut TransferStats,
) -> Result<(), String> {
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
        reporter.emit("uploading", remote_path, stats.bytes, Some(total));
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

            let local_hash = sha256_file(local_path)?;
            if let Some(remote_hash) = remote_sha256(session, &part_path)? {
                if remote_hash != local_hash {
                    return Err("上传文件 SHA-256 校验失败，未提交 .part 文件".to_string());
                }
            } else {
                stats.sha256_verified = false;
            }
            sftp.rename(Path::new(&part_path), Path::new(remote_path), None)
                .map_err(|error| format!("无法原子提交远程文件: {error}"))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = sftp.unlink(Path::new(&part_path));
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
        reporter.emit("downloading", remote_path, stats.bytes, Some(total));
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
        let remote_hash = remote_sha256(session, remote_path)?;
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
                if sha256_file(&part_path)? != remote_hash {
                    return Err("下载文件 SHA-256 校验失败，未提交 .part 文件".to_string());
                }
            } else {
                stats.sha256_verified = false;
            }
            fs::rename(&part_path, local_path)
                .map_err(|error| format!("无法原子提交本机文件: {error}"))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&part_path);
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
        reporter.emit(phase, current_path, *bytes_done, bytes_total);
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

fn remote_supports_package_mode(session: &Session) -> Result<bool, String> {
    let status = run_remote_command(
        session,
        "command -v tar >/dev/null 2>&1 && command -v zstd >/dev/null 2>&1",
    )?;
    Ok(status == 0)
}

fn run_remote_command(session: &Session, command: &str) -> Result<i32, String> {
    run_remote_command_capture(session, command).map(|(status, _)| status)
}

fn run_remote_command_capture(session: &Session, command: &str) -> Result<(i32, String), String> {
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
    let status = channel
        .exit_status()
        .map_err(|_| "无法获取远程命令状态".to_string())?;
    Ok((status, String::from_utf8_lossy(&output).into_owned()))
}

fn remote_sha256(session: &Session, path: &str) -> Result<Option<String>, String> {
    validate_remote_path(path)?;
    let quoted_path = quote_posix_literal(path);
    let command = format!(
        "if command -v sha256sum >/dev/null 2>&1; then sha256sum -- {quoted_path}; elif command -v shasum >/dev/null 2>&1; then shasum -a 256 -- {quoted_path}; else exit 125; fi"
    );
    let (status, output) = run_remote_command_capture(session, &command)?;
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

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(path).map_err(|error| format!("无法打开文件进行 SHA-256 校验: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    loop {
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
    session: &Session,
    sftp: &Sftp,
    roots: &[PathBuf],
    destination: &str,
    transfer_id: &str,
    reporter: &ProgressReporter,
    inventory: &TransferStats,
) -> Result<TransferStats, String> {
    let archive = TempFileGuard::new(transfer_id, "upload.tar.zst");
    reporter.emit("packaging", archive.path().display().to_string(), 0, None);
    create_local_archive(roots, archive.path())?;

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
        if let Some(remote_hash) = remote_sha256(session, &remote_part)? {
            if remote_hash != sha256_file(archive.path())? {
                return Err("上传打包文件 SHA-256 校验失败，未提交 .part 文件".to_string());
            }
            sha256_verified = true;
        }
        sftp.rename(Path::new(&remote_part), Path::new(&remote_archive), None)
            .map_err(|error| format!("无法原子提交远程打包文件: {error}"))?;

        ensure_remote_directory(sftp, &remote_staging)?;
        reporter.emit("extracting", &remote_staging, 0, Some(inventory.bytes));
        let command = format!(
            "zstd -dc -- {} > {} && tar -xf {} -C {}; status=$?; rm -f -- {}; exit \"$status\"",
            quote_posix_literal(&remote_archive),
            quote_posix_literal(&remote_tar_part),
            quote_posix_literal(&remote_tar_part),
            quote_posix_literal(&remote_staging),
            quote_posix_literal(&remote_tar_part)
        );
        let status = run_remote_command(session, &command)?;
        if status != 0 {
            return Err("远程 tar+zstd 解包失败".to_string());
        }
        commit_remote_staged_roots(sftp, roots, &remote_staging, destination)?;
        Ok(TransferStats {
            files: inventory.files,
            bytes: inventory.bytes,
            skipped_symlinks: inventory.skipped_symlinks,
            entries: inventory.entries,
            sha256_verified,
        })
    })();
    let _ = sftp.unlink(Path::new(&remote_part));
    let _ = sftp.unlink(Path::new(&remote_tar_part));
    let _ = sftp.unlink(Path::new(&remote_archive));
    let _ = remove_remote_tree(sftp, &remote_staging, 0);
    result
}

fn commit_remote_staged_roots(
    sftp: &Sftp,
    roots: &[PathBuf],
    staging_directory: &str,
    destination: &str,
) -> Result<(), String> {
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
                let _ = sftp.rename(
                    Path::new(&remote_join(destination, committed_name)),
                    Path::new(&remote_join(staging_directory, committed_name)),
                    None,
                );
            }
            return Err(format!("无法原子提交远程条目: {error}"));
        }
        committed.push(name.clone());
    }
    Ok(())
}

fn remove_remote_tree(sftp: &Sftp, path: &str, depth: usize) -> Result<(), String> {
    if depth > MAX_DIRECTORY_DEPTH {
        return Err("远程临时目录层级超过安全限制".to_string());
    }
    let stat = match sftp.lstat(Path::new(path)) {
        Ok(stat) => stat,
        Err(_) => return Ok(()),
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

fn create_local_archive(roots: &[PathBuf], archive_path: &Path) -> Result<(), String> {
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
        append_local_archive_entry(&mut builder, root, Path::new(name), 0)?;
    }
    let encoder = builder
        .into_inner()
        .map_err(|error| format!("无法完成 tar 打包: {error}"))?;
    encoder
        .finish()
        .map_err(|error| format!("无法完成 zstd 压缩: {error}"))?;
    validate_archive_contents(archive_path, None)?;
    Ok(())
}

fn append_local_archive_entry<W: Write>(
    builder: &mut tar::Builder<W>,
    source: &Path,
    archive_path: &Path,
    depth: usize,
) -> Result<(), String> {
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
            append_local_archive_entry(builder, &child, &archive_path.join(name), depth + 1)?;
        }
    } else if metadata.is_file() {
        builder
            .append_path_with_name(source, archive_path)
            .map_err(|error| format!("无法加入文件 {}: {error}", source.display()))?;
    }
    Ok(())
}

fn download_package(
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
        reporter.emit("packaging", roots.join(", "), 0, Some(inventory.bytes));
        let status = run_remote_command(session, &command)?;
        if status != 0 {
            return Err("远程 tar+zstd 打包失败".to_string());
        }

        let archive_size = sftp
            .stat(Path::new(&remote_part))
            .map_err(|error| format!("无法读取远程打包文件: {error}"))?
            .size
            .ok_or_else(|| "SFTP 服务器未返回远程打包文件大小".to_string())?;
        let remote_hash = remote_sha256(session, &remote_part)?;
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
            if sha256_file(local_archive.path())? != remote_hash {
                return Err("下载打包文件 SHA-256 校验失败，未处理临时文件".to_string());
            }
            sha256_verified = true;
        }

        reporter.emit(
            "extracting",
            local_directory.display().to_string(),
            0,
            Some(inventory.bytes),
        );
        let staging_directory =
            local_directory.join(format!(".vpshell-{}.part", uuid::Uuid::new_v4()));
        fs::create_dir(&staging_directory)
            .map_err(|error| format!("无法创建本机解包临时目录: {error}"))?;
        let staging_directory = staging_directory
            .canonicalize()
            .map_err(|error| format!("无法规范化本机解包临时目录: {error}"))?;
        let extract_result = (|| {
            extract_archive_safely(local_archive.path(), &staging_directory, inventory.bytes)?;
            commit_staged_roots(roots, &staging_directory, local_directory)
        })();
        let _ = fs::remove_dir_all(&staging_directory);
        extract_result?;
        Ok(TransferStats {
            files: inventory.files,
            bytes: inventory.bytes,
            skipped_symlinks: inventory.skipped_symlinks,
            entries: inventory.entries,
            sha256_verified,
        })
    })();
    let _ = sftp.unlink(Path::new(&remote_part));
    let _ = sftp.unlink(Path::new(&remote_tar_part));
    let _ = sftp.unlink(Path::new(&remote_archive));
    result
}

fn commit_staged_roots(
    roots: &[String],
    staging_directory: &Path,
    destination: &Path,
) -> Result<(), String> {
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
                let _ = fs::rename(
                    destination.join(committed_name),
                    staging_directory.join(committed_name),
                );
            }
            return Err(format!("无法原子提交下载条目: {error}"));
        }
        committed.push(name.clone());
    }
    Ok(())
}

fn validate_archive_contents(
    archive_path: &Path,
    expected_bytes: Option<u64>,
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
) -> Result<(), String> {
    validate_archive_contents(archive_path, Some(expected_bytes))?;
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
            proxy_jump: None,
        }
    }

    #[test]
    fn rejects_proxy_jump_for_sftp() {
        let mut connection = valid_connection();
        connection.proxy_jump = Some("jump.example.com".to_string());
        let error = validate_connection(&connection).expect_err("ProxyJump must be rejected");
        assert!(error.contains("ProxyJump"));
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

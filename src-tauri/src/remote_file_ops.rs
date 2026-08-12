use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh2::{ErrorCode, FileStat, OpenFlags, OpenType, RenameFlags, Sftp};
use tauri::{AppHandle, State};

use crate::file_transfer::{ConnectionSpec, connect, connect_for_task, validate_connection};
use crate::transfer_manager::{
    TRANSFER_CANCELLED, TransferManager, TransferRequest, TransferResult, TransferSnapshot,
    TransferTask,
};

const MAX_OPERATION_PATHS: usize = 128;
const MAX_REMOTE_PATH_LENGTH: usize = 4096;
const MAX_REMOTE_COMPONENT_LENGTH: usize = 255;
const MAX_OPERATION_DEPTH: usize = 64;
const MAX_RECURSIVE_ENTRIES: usize = 10_000;
const MAX_PENDING_PREVIEWS: usize = 32;
const PREVIEW_TTL_MILLIS: u64 = 2 * 60 * 1000;
const MAX_RENAME_ATTEMPTS: usize = 100;
const COPY_BUFFER_BYTES: usize = 128 * 1024;
const MAX_COPY_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_COPY_TOTAL_BYTES: u64 = 256 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "operation")]
pub(crate) enum RemoteFileOperationRequest {
    CreateDirectory {
        parent_path: String,
        name: String,
    },
    Rename {
        source_path: String,
        new_name: String,
    },
    Move {
        source_paths: Vec<String>,
        destination_directory: String,
        conflict_policy: ConflictPolicy,
    },
    SetPermissions {
        paths: Vec<String>,
        mode: u32,
        #[serde(default)]
        recursive: bool,
    },
    Delete {
        paths: Vec<String>,
        recursive: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ConflictPolicy {
    Fail,
    Rename,
    Overwrite,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum RemoteNodeKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoteOperationPreviewItem {
    path: String,
    target_path: Option<String>,
    kind: RemoteNodeKind,
    current_permissions: Option<String>,
    requested_permissions: Option<String>,
    action: String,
    warning: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoteOperationPreview {
    confirmation_token: String,
    operation: String,
    summary: String,
    destructive: bool,
    requires_second_confirmation: bool,
    expires_at: u64,
    items: Vec<RemoteOperationPreviewItem>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoteOperationResultItem {
    path: String,
    target_path: Option<String>,
    outcome: String,
    message: String,
    partial: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoteOperationResult {
    operation: String,
    outcome: String,
    succeeded: usize,
    failed: usize,
    skipped: usize,
    partial: bool,
    cancelled: bool,
    items: Vec<RemoteOperationResultItem>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RemoteNode {
    kind: RemoteNodeKind,
    size: u64,
    modified: Option<u64>,
    permissions: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InventoryNode {
    path: String,
    node: RemoteNode,
}

#[derive(Clone, Debug)]
enum PlannedAction {
    CreateDirectory {
        path: String,
        parent: String,
        parent_node: RemoteNode,
        mode: u32,
    },
    Rename {
        path: String,
        target_path: String,
        node: RemoteNode,
        parent: String,
        parent_node: RemoteNode,
    },
    Move {
        path: String,
        target_path: String,
        source_inventory: Vec<InventoryNode>,
        target_inventory: Option<Vec<InventoryNode>>,
        destination_parent: RemoteNode,
        conflict_policy: ConflictPolicy,
    },
    SetPermissions {
        path: String,
        inventory: Vec<InventoryNode>,
        mode: u32,
        recursive: bool,
    },
    Delete {
        path: String,
        inventory: Vec<InventoryNode>,
        recursive: bool,
    },
    Skip {
        path: String,
        target_path: Option<String>,
        kind: RemoteNodeKind,
        reason: String,
    },
}

#[derive(Clone, Debug)]
struct OperationPlan {
    operation: String,
    destructive: bool,
    actions: Vec<PlannedAction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConnectionIdentity {
    host: String,
    port: u16,
    username: String,
}

impl ConnectionIdentity {
    fn from_connection(connection: &ConnectionSpec) -> Self {
        Self {
            host: connection
                .host
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_ascii_lowercase(),
            port: connection.port,
            username: connection.username.clone(),
        }
    }
}

#[derive(Clone)]
struct PendingPreview {
    identity: ConnectionIdentity,
    request: RemoteFileOperationRequest,
    plan: OperationPlan,
    recovery_transfer_id: Option<String>,
    expires_at: u64,
}

#[derive(Clone, Default)]
pub(crate) struct RemoteFileOperationManager {
    pending: Arc<Mutex<HashMap<String, PendingPreview>>>,
}

impl RemoteFileOperationManager {
    fn register(
        &self,
        identity: ConnectionIdentity,
        request: RemoteFileOperationRequest,
        plan: OperationPlan,
        recovery_transfer_id: Option<String>,
    ) -> Result<RemoteOperationPreview, String> {
        let now = now_millis();
        let expires_at = now.saturating_add(PREVIEW_TTL_MILLIS);
        let token = uuid::Uuid::new_v4().to_string();
        let preview = preview_from_plan(&token, expires_at, &plan);
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| "远端文件操作确认状态已损坏".to_string())?;
        pending.retain(|_, item| item.expires_at > now);
        while pending.len() >= MAX_PENDING_PREVIEWS {
            let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, item)| item.expires_at)
                .map(|(token, _)| token.clone())
            else {
                break;
            };
            pending.remove(&oldest);
        }
        pending.insert(
            token,
            PendingPreview {
                identity,
                request,
                plan,
                recovery_transfer_id,
                expires_at,
            },
        );
        Ok(preview)
    }

    fn take(&self, token: &str, identity: &ConnectionIdentity) -> Result<PendingPreview, String> {
        validate_confirmation_token(token)?;
        let now = now_millis();
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| "远端文件操作确认状态已损坏".to_string())?;
        pending.retain(|_, item| item.expires_at > now);
        let item = pending
            .get(token)
            .ok_or_else(|| "操作预览已失效或已使用，请重新预览".to_string())?;
        if &item.identity != identity {
            return Err("当前连接身份与操作预览不一致，请重新预览".to_string());
        }
        pending
            .remove(token)
            .ok_or_else(|| "操作预览已失效或已使用，请重新预览".to_string())
    }
}

#[tauri::command]
pub(crate) async fn preview_remote_file_operation(
    manager: State<'_, RemoteFileOperationManager>,
    connection: ConnectionSpec,
    request: RemoteFileOperationRequest,
) -> Result<RemoteOperationPreview, String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        validate_connection(&connection)?;
        validate_request(&request)?;
        let session = connect(&connection)?;
        let sftp = session
            .sftp()
            .map_err(|_| "无法建立 SFTP 子系统".to_string())?;
        let backend = SftpBackend(&sftp);
        let plan = build_plan(&backend, &request)?;
        manager.register(
            ConnectionIdentity::from_connection(&connection),
            request,
            plan,
            None,
        )
    })
    .await
    .map_err(|error| format!("远端文件操作预览异常结束: {error}"))?
}

#[tauri::command]
pub(crate) async fn execute_remote_file_operation(
    app: AppHandle,
    manager: State<'_, RemoteFileOperationManager>,
    transfer_manager: State<'_, TransferManager>,
    connection: ConnectionSpec,
    confirmation_token: String,
    transfer_id: String,
) -> Result<TransferSnapshot, String> {
    let manager = manager.inner().clone();
    validate_connection(&connection)?;
    let pending = manager.take(
        &confirmation_token,
        &ConnectionIdentity::from_connection(&connection),
    )?;
    let (accepted, task) = if let Some(recovery_id) = pending.recovery_transfer_id.as_deref() {
        if recovery_id != transfer_id {
            return Err("恢复预览与文件任务 ID 不一致".to_string());
        }
        let (accepted, task, request) = transfer_manager.begin_retry(
            &app,
            &transfer_id,
            &connection.host,
            connection.port,
            &connection.username,
        )?;
        if request
            != (TransferRequest::FileOperation {
                request: pending.request.clone(),
            })
        {
            return Err("恢复记录在预览后发生变化，拒绝执行".to_string());
        }
        (accepted, task)
    } else {
        transfer_manager.accept(
            &app,
            transfer_id.clone(),
            &connection.host,
            connection.port,
            &connection.username,
            TransferRequest::FileOperation {
                request: pending.request.clone(),
            },
        )?
    };
    spawn_file_operation(connection, transfer_id, pending.plan, task);
    Ok(accepted)
}

#[tauri::command]
pub(crate) async fn preview_remote_file_operation_recovery(
    manager: State<'_, RemoteFileOperationManager>,
    transfer_manager: State<'_, TransferManager>,
    connection: ConnectionSpec,
    transfer_id: String,
) -> Result<RemoteOperationPreview, String> {
    validate_connection(&connection)?;
    let request = transfer_manager.recovery_file_operation_request(
        &transfer_id,
        &connection.host,
        connection.port,
        &connection.username,
    )?;
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let session = connect(&connection)?;
        let sftp = session
            .sftp()
            .map_err(|_| "无法建立 SFTP 子系统".to_string())?;
        let plan = build_plan(&SftpBackend(&sftp), &request)?;
        manager.register(
            ConnectionIdentity::from_connection(&connection),
            request,
            plan,
            Some(transfer_id),
        )
    })
    .await
    .map_err(|error| format!("文件任务恢复预览异常结束: {error}"))?
}

fn spawn_file_operation(
    connection: ConnectionSpec,
    transfer_id: String,
    plan: OperationPlan,
    task: TransferTask,
) {
    tauri::async_runtime::spawn_blocking(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            task.start()?;
            let session = connect_for_task(&connection, &task)?;
            let sftp = session
                .sftp()
                .map_err(|_| "无法建立 SFTP 子系统".to_string())?;
            let operation = execute_plan_with_task(&SftpBackend(&sftp), plan, Some(&task))?;
            Ok(TransferResult {
                transfer_id,
                mode: "remoteFileOperation".to_string(),
                files_transferred: operation.succeeded as u64,
                bytes_transferred: operation.items.len() as u64,
                skipped_symlinks: operation
                    .items
                    .iter()
                    .filter(|item| item.message.contains("符号链接"))
                    .count() as u64,
                fallback_used: false,
                resumable: false,
                verification: "lstat+size+sha256".to_string(),
                limitations: vec![
                    "恢复必须重新预览；覆盖和已进入提交边界的任务不会重放".to_string(),
                    "跨目录移动使用目标目录暂存、逐文件 SHA-256 核验、原子提交和源清理".to_string(),
                ],
                operation_result: Some(operation),
            })
        }))
        .unwrap_or_else(|_| Err("远端文件任务发生内部异常".to_string()));
        task.finish(result);
    });
}

trait RemoteFileBackend {
    fn lstat(&self, path: &str) -> Result<Option<RemoteNode>, String>;
    fn read_dir(&self, path: &str) -> Result<Vec<String>, String>;
    fn mkdir(&self, path: &str, mode: u32) -> Result<(), String>;
    fn rename(&self, source: &str, target: &str) -> Result<(), String>;
    fn set_permissions(&self, path: &str, mode: u32) -> Result<(), String>;
    fn unlink(&self, path: &str) -> Result<(), String>;
    fn rmdir(&self, path: &str) -> Result<(), String>;
    fn copy_file_verified(
        &self,
        source: &str,
        target: &str,
        expected_size: u64,
        checkpoint: &dyn Fn() -> Result<(), String>,
    ) -> Result<(), String>;
}

struct SftpBackend<'a>(&'a Sftp);

impl RemoteFileBackend for SftpBackend<'_> {
    fn lstat(&self, path: &str) -> Result<Option<RemoteNode>, String> {
        match self.0.lstat(Path::new(path)) {
            Ok(stat) => Ok(Some(node_from_stat(stat))),
            Err(error) if is_sftp_not_found(&error) => Ok(None),
            Err(error) => Err(format!("无法读取远程路径 {path}: {error}")),
        }
    }

    fn read_dir(&self, path: &str) -> Result<Vec<String>, String> {
        self.0
            .readdir(Path::new(path))
            .map_err(|error| format!("无法读取远程目录 {path}: {error}"))?
            .into_iter()
            .map(|(path, _)| {
                path.to_str()
                    .map(str::to_string)
                    .ok_or_else(|| "远程目录包含无法安全操作的文件名".to_string())
            })
            .collect()
    }

    fn mkdir(&self, path: &str, mode: u32) -> Result<(), String> {
        self.0
            .mkdir(Path::new(path), mode as i32)
            .map_err(|error| format!("无法创建远程目录 {path}: {error}"))
    }

    fn rename(&self, source: &str, target: &str) -> Result<(), String> {
        self.0
            .rename(
                Path::new(source),
                Path::new(target),
                Some(RenameFlags::ATOMIC | RenameFlags::NATIVE),
            )
            .map_err(|error| format!("无法重命名 {source}: {error}"))
    }

    fn set_permissions(&self, path: &str, mode: u32) -> Result<(), String> {
        self.0
            .setstat(
                Path::new(path),
                FileStat {
                    size: None,
                    uid: None,
                    gid: None,
                    perm: Some(mode),
                    atime: None,
                    mtime: None,
                },
            )
            .map_err(|error| format!("无法修改 {path} 的权限: {error}"))
    }

    fn unlink(&self, path: &str) -> Result<(), String> {
        self.0
            .unlink(Path::new(path))
            .map_err(|error| format!("无法删除远程条目 {path}: {error}"))
    }

    fn rmdir(&self, path: &str) -> Result<(), String> {
        self.0
            .rmdir(Path::new(path))
            .map_err(|error| format!("无法删除远程目录 {path}: {error}"))
    }

    fn copy_file_verified(
        &self,
        source: &str,
        target: &str,
        expected_size: u64,
        checkpoint: &dyn Fn() -> Result<(), String>,
    ) -> Result<(), String> {
        if expected_size > MAX_COPY_FILE_BYTES {
            return Err(format!(
                "文件超过跨目录移动上限（{MAX_COPY_FILE_BYTES} 字节）"
            ));
        }
        let mut input = self
            .0
            .open_mode(Path::new(source), OpenFlags::READ, 0, OpenType::File)
            .map_err(|error| format!("无法读取移动源 {source}: {error}"))?;
        let mut output = self
            .0
            .open_mode(
                Path::new(target),
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
                0o600,
                OpenType::File,
            )
            .map_err(|error| format!("无法创建移动暂存文件 {target}: {error}"))?;
        let mut source_hash = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
        loop {
            checkpoint()?;
            let read = input
                .read(&mut buffer)
                .map_err(|error| format!("读取移动源失败 {source}: {error}"))?;
            if read == 0 {
                break;
            }
            copied = copied.saturating_add(read as u64);
            if copied > expected_size || copied > MAX_COPY_FILE_BYTES {
                return Err("移动源大小在预览后发生变化".to_string());
            }
            source_hash.update(&buffer[..read]);
            output
                .write_all(&buffer[..read])
                .map_err(|error| format!("写入移动暂存文件失败 {target}: {error}"))?;
        }
        output
            .flush()
            .map_err(|error| format!("刷新移动暂存文件失败 {target}: {error}"))?;
        drop(output);
        if copied != expected_size {
            return Err("移动源大小在预览后发生变化".to_string());
        }
        checkpoint()?;
        let mut verify = self
            .0
            .open_mode(Path::new(target), OpenFlags::READ, 0, OpenType::File)
            .map_err(|error| format!("无法核验移动暂存文件 {target}: {error}"))?;
        let mut target_hash = Sha256::new();
        let mut verified = 0_u64;
        loop {
            checkpoint()?;
            let read = verify
                .read(&mut buffer)
                .map_err(|error| format!("核验移动暂存文件失败 {target}: {error}"))?;
            if read == 0 {
                break;
            }
            verified = verified.saturating_add(read as u64);
            target_hash.update(&buffer[..read]);
        }
        let source_hash = source_hash.finalize();
        let target_hash = target_hash.finalize();
        if verified != expected_size || source_hash != target_hash {
            return Err("移动暂存文件大小或 SHA-256 核验失败".to_string());
        }
        checkpoint()?;
        let mut source_verify = self
            .0
            .open_mode(Path::new(source), OpenFlags::READ, 0, OpenType::File)
            .map_err(|error| format!("无法重新核验移动源 {source}: {error}"))?;
        let mut source_verify_hash = Sha256::new();
        let mut source_verified = 0_u64;
        loop {
            checkpoint()?;
            let read = source_verify
                .read(&mut buffer)
                .map_err(|error| format!("重新核验移动源失败 {source}: {error}"))?;
            if read == 0 {
                break;
            }
            source_verified = source_verified.saturating_add(read as u64);
            source_verify_hash.update(&buffer[..read]);
        }
        if source_verified != expected_size || source_verify_hash.finalize() != source_hash {
            return Err("移动源在复制核验期间发生变化".to_string());
        }
        Ok(())
    }
}

fn node_from_stat(stat: FileStat) -> RemoteNode {
    let file_type = stat.file_type();
    let kind = if file_type.is_file() {
        RemoteNodeKind::File
    } else if file_type.is_dir() {
        RemoteNodeKind::Directory
    } else if file_type.is_symlink() {
        RemoteNodeKind::Symlink
    } else {
        RemoteNodeKind::Other
    };
    RemoteNode {
        kind,
        size: stat.size.unwrap_or(0),
        modified: stat.mtime,
        permissions: stat.perm.map(|mode| mode & 0o7777),
    }
}

fn build_plan(
    backend: &impl RemoteFileBackend,
    request: &RemoteFileOperationRequest,
) -> Result<OperationPlan, String> {
    validate_request(request)?;
    match request {
        RemoteFileOperationRequest::CreateDirectory { parent_path, name } => {
            let parent_node = required_node(backend, parent_path)?;
            if parent_node.kind != RemoteNodeKind::Directory {
                return Err("新建目录的父路径必须是非符号链接目录".to_string());
            }
            let path = remote_join(parent_path, name);
            if backend.lstat(&path)?.is_some() {
                return Err("目标名称已经存在；本批操作不允许覆盖".to_string());
            }
            Ok(OperationPlan {
                operation: "createDirectory".to_string(),
                destructive: false,
                actions: vec![PlannedAction::CreateDirectory {
                    path,
                    parent: parent_path.clone(),
                    parent_node,
                    mode: 0o755,
                }],
            })
        }
        RemoteFileOperationRequest::Rename {
            source_path,
            new_name,
        } => {
            let node = required_node(backend, source_path)?;
            if matches!(node.kind, RemoteNodeKind::Symlink | RemoteNodeKind::Other) {
                return Err("本批重命名仅支持普通文件和非符号链接目录".to_string());
            }
            let parent = remote_parent(source_path)?.to_string();
            let parent_node = required_node(backend, &parent)?;
            if parent_node.kind != RemoteNodeKind::Directory {
                return Err("重命名父路径必须是非符号链接目录".to_string());
            }
            let target_path = remote_join(&parent, new_name);
            if target_path == *source_path {
                return Err("新名称与当前名称相同".to_string());
            }
            if backend.lstat(&target_path)?.is_some() {
                return Err("重命名目标已经存在；本批操作不允许覆盖".to_string());
            }
            Ok(OperationPlan {
                operation: "rename".to_string(),
                destructive: true,
                actions: vec![PlannedAction::Rename {
                    path: source_path.clone(),
                    target_path,
                    node,
                    parent,
                    parent_node,
                }],
            })
        }
        RemoteFileOperationRequest::Move {
            source_paths,
            destination_directory,
            conflict_policy,
        } => {
            let destination_parent = required_node(backend, destination_directory)?;
            if destination_parent.kind != RemoteNodeKind::Directory {
                return Err("移动目标必须是非符号链接目录".to_string());
            }
            let mut actions = Vec::with_capacity(source_paths.len());
            let mut total_entries = 0_usize;
            let mut total_bytes = 0_u64;
            for path in source_paths {
                let mut source_inventory = Vec::new();
                collect_inventory(backend, path, 0, &mut total_entries, &mut source_inventory)?;
                let root = &source_inventory[0];
                for item in &source_inventory {
                    total_bytes = total_bytes
                        .checked_add(item.node.size)
                        .ok_or_else(|| "移动总字节数溢出".to_string())?;
                }
                if total_bytes > MAX_COPY_TOTAL_BYTES {
                    return Err(format!(
                        "跨目录移动总量超过安全上限（{MAX_COPY_TOTAL_BYTES} 字节）"
                    ));
                }
                if source_inventory.iter().any(|item| {
                    matches!(
                        item.node.kind,
                        RemoteNodeKind::Symlink | RemoteNodeKind::Other
                    )
                }) {
                    actions.push(PlannedAction::Skip {
                        path: path.clone(),
                        target_path: None,
                        kind: root.node.kind.clone(),
                        reason: "跨目录移动不会复制或跟随符号链接及特殊条目".to_string(),
                    });
                    continue;
                }
                if source_inventory.iter().any(|item| {
                    item.node.kind == RemoteNodeKind::File && item.node.size > MAX_COPY_FILE_BYTES
                }) {
                    actions.push(PlannedAction::Skip {
                        path: path.clone(),
                        target_path: None,
                        kind: root.node.kind.clone(),
                        reason: format!("文件超过移动上限（{MAX_COPY_FILE_BYTES} 字节）"),
                    });
                    continue;
                }
                let name = path.rsplit('/').next().unwrap_or_default();
                let mut target_path = remote_join(destination_directory, name);
                if target_path == *path
                    || (root.node.kind == RemoteNodeKind::Directory
                        && destination_directory
                            .strip_prefix(path)
                            .is_some_and(|suffix| suffix.starts_with('/')))
                {
                    return Err("不能把条目移动到自身或自身子目录".to_string());
                }
                let mut target_inventory = inventory_if_present(backend, &target_path)?;
                if let Some(target) = &target_inventory {
                    total_entries = total_entries.saturating_add(target.len());
                    if total_entries > MAX_RECURSIVE_ENTRIES {
                        return Err(format!(
                            "移动源与覆盖目标总条目超过安全上限（{MAX_RECURSIVE_ENTRIES}）"
                        ));
                    }
                }
                match conflict_policy {
                    ConflictPolicy::Fail if target_inventory.is_some() => {
                        actions.push(PlannedAction::Skip {
                            path: path.clone(),
                            target_path: Some(target_path),
                            kind: root.node.kind.clone(),
                            reason: "目标已存在，fail 策略拒绝覆盖".to_string(),
                        });
                        continue;
                    }
                    ConflictPolicy::Rename if target_inventory.is_some() => {
                        target_path = find_rename_target(backend, destination_directory, name)?;
                        target_inventory = None;
                    }
                    ConflictPolicy::Overwrite => {
                        if target_inventory.as_ref().is_some_and(|inventory| {
                            inventory.iter().any(|item| {
                                matches!(
                                    item.node.kind,
                                    RemoteNodeKind::Symlink | RemoteNodeKind::Other
                                )
                            })
                        }) {
                            actions.push(PlannedAction::Skip {
                                path: path.clone(),
                                target_path: Some(target_path),
                                kind: root.node.kind.clone(),
                                reason: "overwrite 不会替换符号链接或包含符号链接/特殊条目的目标"
                                    .to_string(),
                            });
                            continue;
                        }
                    }
                    _ => {}
                }
                actions.push(PlannedAction::Move {
                    path: path.clone(),
                    target_path,
                    source_inventory,
                    target_inventory,
                    destination_parent: destination_parent.clone(),
                    conflict_policy: conflict_policy.clone(),
                });
            }
            Ok(OperationPlan {
                operation: "move".to_string(),
                destructive: true,
                actions,
            })
        }
        RemoteFileOperationRequest::SetPermissions {
            paths,
            mode,
            recursive,
        } => {
            let mut actions = Vec::with_capacity(paths.len());
            let mut total_entries = 0_usize;
            for path in paths {
                match backend.lstat(path)? {
                    None => actions.push(PlannedAction::Skip {
                        path: path.clone(),
                        target_path: None,
                        kind: RemoteNodeKind::Other,
                        reason: "路径在预览时已不存在".to_string(),
                    }),
                    Some(node) if node.kind == RemoteNodeKind::Symlink => {
                        actions.push(PlannedAction::Skip {
                            path: path.clone(),
                            target_path: None,
                            kind: node.kind,
                            reason: "权限编辑不会跟随或修改符号链接".to_string(),
                        });
                    }
                    Some(node) if node.kind == RemoteNodeKind::Other => {
                        actions.push(PlannedAction::Skip {
                            path: path.clone(),
                            target_path: None,
                            kind: node.kind,
                            reason: "不支持修改该远程条目类型".to_string(),
                        });
                    }
                    Some(node) => {
                        let inventory = if *recursive && node.kind == RemoteNodeKind::Directory {
                            let mut inventory = Vec::new();
                            collect_inventory(
                                backend,
                                path,
                                0,
                                &mut total_entries,
                                &mut inventory,
                            )?;
                            inventory
                        } else {
                            total_entries = total_entries.saturating_add(1);
                            vec![InventoryNode {
                                path: path.clone(),
                                node,
                            }]
                        };
                        actions.push(PlannedAction::SetPermissions {
                            path: path.clone(),
                            inventory,
                            mode: *mode,
                            recursive: *recursive,
                        });
                    }
                }
            }
            Ok(OperationPlan {
                operation: "setPermissions".to_string(),
                destructive: true,
                actions,
            })
        }
        RemoteFileOperationRequest::Delete { paths, recursive } => {
            let mut actions = Vec::with_capacity(paths.len());
            let mut total_entries = 0_usize;
            for path in paths {
                match backend.lstat(path)? {
                    None => actions.push(PlannedAction::Skip {
                        path: path.clone(),
                        target_path: None,
                        kind: RemoteNodeKind::Other,
                        reason: "路径在预览时已不存在".to_string(),
                    }),
                    Some(node) if node.kind == RemoteNodeKind::Other => {
                        actions.push(PlannedAction::Skip {
                            path: path.clone(),
                            target_path: None,
                            kind: node.kind,
                            reason: "不支持删除该远程条目类型".to_string(),
                        });
                    }
                    Some(node) if node.kind == RemoteNodeKind::Directory && !recursive => {
                        actions.push(PlannedAction::Skip {
                            path: path.clone(),
                            target_path: None,
                            kind: node.kind,
                            reason: "目录删除必须明确启用递归模式".to_string(),
                        });
                    }
                    Some(_) => {
                        let mut inventory = Vec::new();
                        collect_inventory(backend, path, 0, &mut total_entries, &mut inventory)?;
                        actions.push(PlannedAction::Delete {
                            path: path.clone(),
                            inventory,
                            recursive: *recursive,
                        });
                    }
                }
            }
            Ok(OperationPlan {
                operation: "delete".to_string(),
                destructive: true,
                actions,
            })
        }
    }
}

fn preview_from_plan(token: &str, expires_at: u64, plan: &OperationPlan) -> RemoteOperationPreview {
    let items = plan.actions.iter().map(preview_item).collect::<Vec<_>>();
    let actionable = items.iter().filter(|item| item.action == "apply").count();
    let skipped = items.len().saturating_sub(actionable);
    RemoteOperationPreview {
        confirmation_token: token.to_string(),
        operation: plan.operation.clone(),
        summary: if skipped == 0 {
            format!("将执行 {actionable} 项远端文件操作")
        } else {
            format!("将执行 {actionable} 项，跳过 {skipped} 项")
        },
        destructive: plan.destructive,
        requires_second_confirmation: true,
        expires_at,
        items,
    }
}

fn preview_item(action: &PlannedAction) -> RemoteOperationPreviewItem {
    match action {
        PlannedAction::CreateDirectory { path, mode, .. } => RemoteOperationPreviewItem {
            path: path.clone(),
            target_path: None,
            kind: RemoteNodeKind::Directory,
            current_permissions: None,
            requested_permissions: Some(format_mode(*mode)),
            action: "apply".to_string(),
            warning: None,
        },
        PlannedAction::Rename {
            path,
            target_path,
            node,
            ..
        } => RemoteOperationPreviewItem {
            path: path.clone(),
            target_path: Some(target_path.clone()),
            kind: node.kind.clone(),
            current_permissions: node.permissions.map(format_mode),
            requested_permissions: None,
            action: "apply".to_string(),
            warning: Some("不会覆盖已有目标".to_string()),
        },
        PlannedAction::Move {
            path,
            target_path,
            source_inventory,
            target_inventory,
            conflict_policy,
            ..
        } => RemoteOperationPreviewItem {
            path: path.clone(),
            target_path: Some(target_path.clone()),
            kind: source_inventory[0].node.kind.clone(),
            current_permissions: source_inventory[0].node.permissions.map(format_mode),
            requested_permissions: None,
            action: "apply".to_string(),
            warning: Some(match (conflict_policy, target_inventory) {
                (ConflictPolicy::Overwrite, Some(target)) => format!(
                    "明确 overwrite：先备份并替换现有目标（{} 个条目），再清理源；重启不会重放",
                    target.len()
                ),
                (ConflictPolicy::Rename, _) => {
                    "目标重名时使用预览中冻结的新名称；不会覆盖".to_string()
                }
                _ => format!(
                    "将复制并核验 {} 个条目后原子提交，再清理源",
                    source_inventory.len()
                ),
            }),
        },
        PlannedAction::SetPermissions {
            path,
            inventory,
            mode,
            recursive,
        } => RemoteOperationPreviewItem {
            path: path.clone(),
            target_path: None,
            kind: inventory[0].node.kind.clone(),
            current_permissions: inventory[0].node.permissions.map(format_mode),
            requested_permissions: Some(format_mode(*mode)),
            action: "apply".to_string(),
            warning: (*recursive).then(|| {
                let skipped_links = inventory
                    .iter()
                    .filter(|item| item.node.kind == RemoteNodeKind::Symlink)
                    .count();
                format!(
                    "递归范围 {} 个条目；其中 {skipped_links} 个符号链接保持不变",
                    inventory.len()
                )
            }),
        },
        PlannedAction::Delete {
            path, inventory, ..
        } => RemoteOperationPreviewItem {
            path: path.clone(),
            target_path: None,
            kind: inventory
                .first()
                .map(|item| item.node.kind.clone())
                .unwrap_or(RemoteNodeKind::Other),
            current_permissions: inventory
                .first()
                .and_then(|item| item.node.permissions)
                .map(format_mode),
            requested_permissions: None,
            action: "apply".to_string(),
            warning: Some(format!("将永久删除 {} 个条目，不能撤销", inventory.len())),
        },
        PlannedAction::Skip {
            path,
            target_path,
            kind,
            reason,
        } => RemoteOperationPreviewItem {
            path: path.clone(),
            target_path: target_path.clone(),
            kind: kind.clone(),
            current_permissions: None,
            requested_permissions: None,
            action: "skip".to_string(),
            warning: Some(reason.clone()),
        },
    }
}

#[cfg(test)]
fn execute_plan(
    backend: &impl RemoteFileBackend,
    plan: OperationPlan,
) -> Result<RemoteOperationResult, String> {
    execute_plan_with_task(backend, plan, None)
}

fn execute_plan_with_task(
    backend: &impl RemoteFileBackend,
    plan: OperationPlan,
    task: Option<&TransferTask>,
) -> Result<RemoteOperationResult, String> {
    let mut items = Vec::with_capacity(plan.actions.len());
    let total = plan.actions.len();
    let mut cancelled = false;
    for (index, action) in plan.actions.into_iter().enumerate() {
        if cancelled || task.is_some_and(|task| task.checkpoint().is_err()) {
            cancelled = true;
            let preview = preview_item(&action);
            items.push(skipped_result(
                preview.path,
                preview.target_path,
                "任务已取消，该项未执行",
            ));
            continue;
        }
        if let Some(task) = task {
            task.progress(
                "fileOperation",
                preview_item(&action).path,
                index as u64,
                Some(total as u64),
            )?;
        }
        let item = execute_action(backend, action, task);
        if item.message == TRANSFER_CANCELLED {
            cancelled = true;
        }
        items.push(item);
    }
    let succeeded = items
        .iter()
        .filter(|item| item.outcome == "succeeded")
        .count();
    let failed = items.iter().filter(|item| item.outcome == "failed").count();
    let skipped = items
        .iter()
        .filter(|item| item.outcome == "skipped")
        .count();
    let partial = items.iter().any(|item| item.partial)
        || (succeeded > 0 && failed.saturating_add(skipped) > 0);
    let outcome = if cancelled {
        "cancelled"
    } else if failed == 0 && skipped == 0 {
        "completed"
    } else if succeeded > 0 || partial {
        "partial"
    } else {
        "failed"
    };
    Ok(RemoteOperationResult {
        operation: plan.operation,
        outcome: outcome.to_string(),
        succeeded,
        failed,
        skipped,
        partial,
        cancelled,
        items,
    })
}

fn execute_action(
    backend: &impl RemoteFileBackend,
    action: PlannedAction,
    task: Option<&TransferTask>,
) -> RemoteOperationResultItem {
    match action {
        PlannedAction::CreateDirectory {
            path,
            parent,
            parent_node,
            mode,
        } => {
            let precondition = (|| {
                Ok::<_, String>(
                    backend.lstat(&parent)?.as_ref() == Some(&parent_node)
                        && backend.lstat(&path)?.is_none(),
                )
            })();
            match precondition {
                Err(error) => return operation_result(path, None, Err(error), false),
                Ok(false) => {
                    return skipped_result(path, None, "父目录或目标状态在确认后发生变化");
                }
                Ok(true) => {}
            }
            if let Some(task) = task {
                if let Err(error) = task.mark_commit_boundary() {
                    return operation_result(path, None, Err(error), false);
                }
            }
            let result = backend.mkdir(&path, mode);
            if result.is_ok() {
                if let Some(task) = task {
                    task.note_commit();
                }
            }
            operation_result(path, None, result, false)
        }
        PlannedAction::Rename {
            path,
            target_path,
            node,
            parent,
            parent_node,
        } => {
            let precondition = (|| {
                Ok::<_, String>(
                    backend.lstat(&path)?.as_ref() == Some(&node)
                        && backend.lstat(&parent)?.as_ref() == Some(&parent_node)
                        && backend.lstat(&target_path)?.is_none(),
                )
            })();
            match precondition {
                Err(error) => {
                    return operation_result(path, Some(target_path), Err(error), false);
                }
                Ok(false) => {
                    return skipped_result(
                        path,
                        Some(target_path),
                        "源、父目录或目标状态在确认后发生变化",
                    );
                }
                Ok(true) => {}
            }
            if let Some(task) = task {
                if let Err(error) = task.mark_commit_boundary() {
                    return operation_result(path, Some(target_path), Err(error), false);
                }
            }
            let result = backend.rename(&path, &target_path);
            if result.is_ok() {
                if let Some(task) = task {
                    task.note_commit();
                }
            }
            operation_result(path, Some(target_path), result, false)
        }
        PlannedAction::Move {
            path,
            target_path,
            source_inventory,
            target_inventory,
            destination_parent,
            conflict_policy,
        } => execute_move_action(
            backend,
            path,
            target_path,
            source_inventory,
            target_inventory,
            destination_parent,
            conflict_policy,
            task,
        ),
        PlannedAction::SetPermissions {
            path,
            inventory,
            mode,
            recursive,
        } => {
            let current = if recursive {
                let mut current = Vec::new();
                let mut count = 0_usize;
                if let Err(error) = collect_inventory(backend, &path, 0, &mut count, &mut current) {
                    return operation_result(path, None, Err(error), false);
                }
                current
            } else {
                match backend.lstat(&path) {
                    Ok(Some(node)) => vec![InventoryNode {
                        path: path.clone(),
                        node,
                    }],
                    Ok(None) => return skipped_result(path, None, "路径在确认后已不存在"),
                    Err(error) => return operation_result(path, None, Err(error), false),
                }
            };
            if current != inventory {
                return skipped_result(path, None, "递归权限范围在确认后发生变化");
            }
            if let Some(task) = task {
                if let Err(error) = task.mark_commit_boundary() {
                    return operation_result(path, None, Err(error), false);
                }
            }
            let mut changed = 0_usize;
            let mut skipped_links = 0_usize;
            for item in inventory {
                if task.is_some_and(|task| task.checkpoint().is_err()) {
                    return RemoteOperationResultItem {
                        path,
                        target_path: None,
                        outcome: "skipped".to_string(),
                        message: TRANSFER_CANCELLED.to_string(),
                        partial: changed > 0,
                    };
                }
                if item.node.kind == RemoteNodeKind::Symlink {
                    skipped_links += 1;
                    continue;
                }
                if let Err(error) = backend.set_permissions(&item.path, mode) {
                    return RemoteOperationResultItem {
                        path,
                        target_path: None,
                        outcome: "failed".to_string(),
                        message: error,
                        partial: changed > 0,
                    };
                }
                changed += 1;
                if let Some(task) = task {
                    task.note_commit();
                }
            }
            RemoteOperationResultItem {
                path,
                target_path: None,
                outcome: "succeeded".to_string(),
                message: format!("已修改 {changed} 个条目，隔离 {skipped_links} 个符号链接"),
                partial: false,
            }
        }
        PlannedAction::Delete {
            path,
            inventory,
            recursive,
        } => {
            match backend.lstat(&path) {
                Err(error) => return operation_result(path, None, Err(error), false),
                Ok(None) => return skipped_result(path, None, "路径在确认后已不存在"),
                Ok(Some(_)) => {}
            }
            let mut current = Vec::new();
            let mut count = 0_usize;
            if let Err(error) = collect_inventory(backend, &path, 0, &mut count, &mut current) {
                return operation_result(path, None, Err(error), false);
            }
            if current != inventory {
                return skipped_result(path, None, "目录内容或路径状态在确认后发生变化");
            }
            if let Some(task) = task {
                if let Err(error) = task.mark_commit_boundary() {
                    return operation_result(path, None, Err(error), false);
                }
            }
            let mut removed = 0_usize;
            for item in inventory.iter().rev() {
                if task.is_some_and(|task| task.checkpoint().is_err()) {
                    return RemoteOperationResultItem {
                        path,
                        target_path: None,
                        outcome: "skipped".to_string(),
                        message: TRANSFER_CANCELLED.to_string(),
                        partial: removed > 0,
                    };
                }
                let result = match item.node.kind {
                    RemoteNodeKind::Directory if recursive => backend.rmdir(&item.path),
                    RemoteNodeKind::Directory => Err("目录删除未启用递归模式".to_string()),
                    RemoteNodeKind::File | RemoteNodeKind::Symlink => backend.unlink(&item.path),
                    RemoteNodeKind::Other => Err("不支持删除该远程条目类型".to_string()),
                };
                if let Err(error) = result {
                    return RemoteOperationResultItem {
                        path,
                        target_path: None,
                        outcome: "failed".to_string(),
                        message: error,
                        partial: removed > 0,
                    };
                }
                removed += 1;
                if let Some(task) = task {
                    task.note_commit();
                }
            }
            RemoteOperationResultItem {
                path,
                target_path: None,
                outcome: "succeeded".to_string(),
                message: format!("已删除 {removed} 个条目"),
                partial: false,
            }
        }
        PlannedAction::Skip {
            path,
            target_path,
            reason,
            ..
        } => skipped_result(path, target_path, &reason),
    }
}

fn operation_result(
    path: String,
    target_path: Option<String>,
    result: Result<(), String>,
    partial: bool,
) -> RemoteOperationResultItem {
    match result {
        Ok(()) => RemoteOperationResultItem {
            path,
            target_path,
            outcome: "succeeded".to_string(),
            message: "操作完成".to_string(),
            partial,
        },
        Err(message) => RemoteOperationResultItem {
            path,
            target_path,
            outcome: "failed".to_string(),
            message,
            partial,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_move_action(
    backend: &impl RemoteFileBackend,
    path: String,
    target_path: String,
    source_inventory: Vec<InventoryNode>,
    target_inventory: Option<Vec<InventoryNode>>,
    destination_parent: RemoteNode,
    conflict_policy: ConflictPolicy,
    task: Option<&TransferTask>,
) -> RemoteOperationResultItem {
    let precondition = (|| {
        let mut current_source = Vec::new();
        let mut count = 0_usize;
        collect_inventory(backend, &path, 0, &mut count, &mut current_source)?;
        if current_source != source_inventory {
            return Ok::<_, String>(false);
        }
        if backend.lstat(remote_parent(&target_path)?)?.as_ref() != Some(&destination_parent) {
            return Ok(false);
        }
        Ok(inventory_if_present(backend, &target_path)? == target_inventory)
    })();
    match precondition {
        Err(error) => {
            return operation_result(path, Some(target_path), Err(error), false);
        }
        Ok(false) => {
            return skipped_result(
                path,
                Some(target_path),
                "源、目标或目标目录状态在确认后发生变化",
            );
        }
        Ok(true) => {}
    }

    let stage_path = match unique_sibling_path(backend, &target_path, "stage") {
        Ok(path) => path,
        Err(error) => return operation_result(path, Some(target_path), Err(error), false),
    };
    let checkpoint = || task.map_or(Ok(()), TransferTask::checkpoint);
    let staged = stage_inventory(backend, &path, &stage_path, &source_inventory, &checkpoint);
    if let Err(error) = staged {
        let cleanup = cleanup_tree(backend, &stage_path);
        let message = if let Err(cleanup_error) = cleanup {
            format!("{error}；暂存清理失败: {cleanup_error}")
        } else {
            error
        };
        return RemoteOperationResultItem {
            path,
            target_path: Some(target_path),
            outcome: if message.starts_with(TRANSFER_CANCELLED) {
                "skipped".to_string()
            } else {
                "failed".to_string()
            },
            message,
            partial: false,
        };
    }

    let commit_precondition = (|| {
        let mut current_source = Vec::new();
        let mut count = 0_usize;
        collect_inventory(backend, &path, 0, &mut count, &mut current_source)?;
        Ok::<_, String>(
            current_source == source_inventory
                && inventory_if_present(backend, &target_path)? == target_inventory
                && backend.lstat(remote_parent(&target_path)?)?.as_ref()
                    == Some(&destination_parent),
        )
    })();
    match commit_precondition {
        Err(error) => {
            let _ = cleanup_tree(backend, &stage_path);
            return operation_result(path, Some(target_path), Err(error), false);
        }
        Ok(false) => {
            let _ = cleanup_tree(backend, &stage_path);
            return skipped_result(
                path,
                Some(target_path),
                "源、目标或目标目录在复制核验期间发生变化",
            );
        }
        Ok(true) => {}
    }

    if let Some(task) = task {
        if let Err(error) = task.begin_finalizing(&target_path) {
            let _ = cleanup_tree(backend, &stage_path);
            return operation_result(path, Some(target_path), Err(error), false);
        }
        if let Err(error) = task.mark_commit_boundary() {
            let _ = cleanup_tree(backend, &stage_path);
            task.end_finalizing();
            return operation_result(path, Some(target_path), Err(error), false);
        }
    }

    let mut backup_path = None;
    if target_inventory.is_some() {
        if conflict_policy != ConflictPolicy::Overwrite {
            let _ = cleanup_tree(backend, &stage_path);
            if let Some(task) = task {
                task.end_finalizing();
            }
            return skipped_result(path, Some(target_path), "目标已存在且没有明确 overwrite");
        }
        let backup = match unique_sibling_path(backend, &target_path, "backup") {
            Ok(path) => path,
            Err(error) => {
                let _ = cleanup_tree(backend, &stage_path);
                if let Some(task) = task {
                    task.end_finalizing();
                }
                return operation_result(path, Some(target_path), Err(error), false);
            }
        };
        if let Err(error) = backend.rename(&target_path, &backup) {
            let _ = cleanup_tree(backend, &stage_path);
            if let Some(task) = task {
                task.end_finalizing();
            }
            return operation_result(path, Some(target_path), Err(error), false);
        }
        backup_path = Some(backup);
    }

    if let Err(error) = backend.rename(&stage_path, &target_path) {
        let rollback = backup_path
            .as_ref()
            .map(|backup| backend.rename(backup, &target_path));
        let rollback_failed = rollback.as_ref().is_some_and(Result::is_err);
        let message = match rollback.as_ref() {
            Some(Err(rollback_error)) => {
                format!("提交移动目标失败: {error}；恢复原目标失败: {rollback_error}")
            }
            _ => format!("提交移动目标失败: {error}"),
        };
        let _ = cleanup_tree(backend, &stage_path);
        if let Some(task) = task {
            task.end_finalizing();
        }
        return RemoteOperationResultItem {
            path,
            target_path: Some(target_path),
            outcome: "failed".to_string(),
            message,
            partial: rollback_failed,
        };
    }
    if let Some(task) = task {
        task.note_commit();
        task.begin_cleanup();
    }

    let mut cleanup_errors = Vec::new();
    if let Err(error) = remove_frozen_inventory(backend, &source_inventory) {
        cleanup_errors.push(format!("源清理失败: {error}"));
    }
    if let Some(backup) = backup_path {
        if let Err(error) = cleanup_tree(backend, &backup) {
            cleanup_errors.push(format!("旧目标备份清理失败: {error}"));
        }
    }
    if cleanup_errors.is_empty() {
        if let Some(task) = task {
            task.end_finalizing();
        }
        RemoteOperationResultItem {
            path,
            target_path: Some(target_path),
            outcome: "succeeded".to_string(),
            message: "复制与 SHA-256 核验完成，目标已提交且源已清理".to_string(),
            partial: false,
        }
    } else {
        if let Some(task) = task {
            for warning in &cleanup_errors {
                task.cleanup_warning(warning.clone());
            }
            task.end_finalizing();
        }
        RemoteOperationResultItem {
            path,
            target_path: Some(target_path),
            outcome: "failed".to_string(),
            message: cleanup_errors.join("；"),
            partial: true,
        }
    }
}

fn stage_inventory(
    backend: &impl RemoteFileBackend,
    source_root: &str,
    stage_root: &str,
    inventory: &[InventoryNode],
    checkpoint: &dyn Fn() -> Result<(), String>,
) -> Result<(), String> {
    for item in inventory {
        checkpoint()?;
        let suffix = item
            .path
            .strip_prefix(source_root)
            .ok_or_else(|| "移动清单包含源目录之外的条目".to_string())?;
        let staged_path = format!("{stage_root}{suffix}");
        match item.node.kind {
            RemoteNodeKind::Directory => {
                backend.mkdir(&staged_path, item.node.permissions.unwrap_or(0o755) & 0o777)?;
            }
            RemoteNodeKind::File => {
                backend.copy_file_verified(&item.path, &staged_path, item.node.size, checkpoint)?;
                if let Some(mode) = item.node.permissions {
                    backend.set_permissions(&staged_path, mode & 0o777)?;
                }
            }
            RemoteNodeKind::Symlink | RemoteNodeKind::Other => {
                return Err("移动清单包含不允许复制的符号链接或特殊条目".to_string());
            }
        }
    }
    for item in inventory {
        let suffix = item.path.strip_prefix(source_root).unwrap_or_default();
        let staged_path = format!("{stage_root}{suffix}");
        let staged = required_node(backend, &staged_path)?;
        if staged.kind != item.node.kind
            || (staged.kind == RemoteNodeKind::File && staged.size != item.node.size)
        {
            return Err("移动暂存清单核验失败".to_string());
        }
    }
    Ok(())
}

fn remove_frozen_inventory(
    backend: &impl RemoteFileBackend,
    inventory: &[InventoryNode],
) -> Result<(), String> {
    for item in inventory.iter().rev() {
        let result = match item.node.kind {
            RemoteNodeKind::Directory => backend.rmdir(&item.path),
            RemoteNodeKind::File | RemoteNodeKind::Symlink => backend.unlink(&item.path),
            RemoteNodeKind::Other => Err("不能清理特殊远程条目".to_string()),
        };
        result?;
    }
    Ok(())
}

fn cleanup_tree(backend: &impl RemoteFileBackend, path: &str) -> Result<(), String> {
    let Some(_) = backend.lstat(path)? else {
        return Ok(());
    };
    let mut inventory = Vec::new();
    let mut count = 0_usize;
    collect_inventory(backend, path, 0, &mut count, &mut inventory)?;
    remove_frozen_inventory(backend, &inventory)
}

fn skipped_result(
    path: String,
    target_path: Option<String>,
    message: &str,
) -> RemoteOperationResultItem {
    RemoteOperationResultItem {
        path,
        target_path,
        outcome: "skipped".to_string(),
        message: message.to_string(),
        partial: false,
    }
}

fn collect_inventory(
    backend: &impl RemoteFileBackend,
    path: &str,
    depth: usize,
    total_entries: &mut usize,
    inventory: &mut Vec<InventoryNode>,
) -> Result<(), String> {
    if depth > MAX_OPERATION_DEPTH {
        return Err(format!("递归目录深度超过安全上限（{MAX_OPERATION_DEPTH}）"));
    }
    *total_entries = total_entries.saturating_add(1);
    if *total_entries > MAX_RECURSIVE_ENTRIES {
        return Err(format!(
            "递归操作条目超过安全上限（{MAX_RECURSIVE_ENTRIES}）"
        ));
    }
    let node = required_node(backend, path)?;
    inventory.push(InventoryNode {
        path: path.to_string(),
        node: node.clone(),
    });
    if node.kind != RemoteNodeKind::Directory {
        return Ok(());
    }
    let mut children = backend.read_dir(path)?;
    children.sort();
    for child in children {
        validate_mutation_path(&child)?;
        if remote_parent(&child)? != path {
            return Err("远程目录返回了父目录之外的条目，已拒绝递归操作".to_string());
        }
        collect_inventory(backend, &child, depth + 1, total_entries, inventory)?;
    }
    Ok(())
}

fn required_node(backend: &impl RemoteFileBackend, path: &str) -> Result<RemoteNode, String> {
    backend
        .lstat(path)?
        .ok_or_else(|| format!("远程路径不存在: {path}"))
}

fn inventory_if_present(
    backend: &impl RemoteFileBackend,
    path: &str,
) -> Result<Option<Vec<InventoryNode>>, String> {
    if backend.lstat(path)?.is_none() {
        return Ok(None);
    }
    let mut inventory = Vec::new();
    let mut count = 0_usize;
    collect_inventory(backend, path, 0, &mut count, &mut inventory)?;
    Ok(Some(inventory))
}

fn find_rename_target(
    backend: &impl RemoteFileBackend,
    parent: &str,
    original_name: &str,
) -> Result<String, String> {
    let (stem, extension) = original_name
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map_or((original_name, ""), |(stem, extension)| (stem, extension));
    for index in 1..=MAX_RENAME_ATTEMPTS {
        let name = if extension.is_empty() {
            format!("{stem} ({index})")
        } else {
            format!("{stem} ({index}).{extension}")
        };
        if validate_component(&name).is_err() {
            continue;
        }
        let candidate = remote_join(parent, &name);
        if backend.lstat(&candidate)?.is_none() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "无法在 {MAX_RENAME_ATTEMPTS} 次尝试内生成无冲突目标名称"
    ))
}

fn unique_sibling_path(
    backend: &impl RemoteFileBackend,
    target: &str,
    purpose: &str,
) -> Result<String, String> {
    let parent = remote_parent(target)?;
    for _ in 0..8 {
        let name = format!(".vpshell-{purpose}-{}", uuid::Uuid::new_v4().simple());
        let candidate = remote_join(parent, &name);
        if backend.lstat(&candidate)?.is_none() {
            return Ok(candidate);
        }
    }
    Err("无法分配唯一的远端暂存路径".to_string())
}

pub(crate) fn validate_request(request: &RemoteFileOperationRequest) -> Result<(), String> {
    match request {
        RemoteFileOperationRequest::CreateDirectory { parent_path, name } => {
            validate_absolute_path(parent_path, true)?;
            validate_component(name)?;
            validate_mutation_path(&remote_join(parent_path, name))
        }
        RemoteFileOperationRequest::Rename {
            source_path,
            new_name,
        } => {
            validate_mutation_path(source_path)?;
            validate_component(new_name)?;
            validate_mutation_path(&remote_join(remote_parent(source_path)?, new_name))
        }
        RemoteFileOperationRequest::Move {
            source_paths,
            destination_directory,
            ..
        } => {
            validate_operation_paths(source_paths)?;
            validate_absolute_path(destination_directory, true)?;
            if source_paths
                .iter()
                .any(|path| path == destination_directory)
            {
                return Err("移动目标目录不能同时是移动源".to_string());
            }
            Ok(())
        }
        RemoteFileOperationRequest::SetPermissions { paths, mode, .. } => {
            validate_permission_mode(*mode)?;
            validate_operation_paths(paths)
        }
        RemoteFileOperationRequest::Delete { paths, .. } => validate_operation_paths(paths),
    }
}

fn validate_operation_paths(paths: &[String]) -> Result<(), String> {
    if paths.is_empty() || paths.len() > MAX_OPERATION_PATHS {
        return Err(format!("请选择 1 到 {MAX_OPERATION_PATHS} 个远程条目"));
    }
    let mut unique = HashSet::new();
    for path in paths {
        validate_mutation_path(path)?;
        if !unique.insert(path.as_str()) {
            return Err("批量操作包含重复路径".to_string());
        }
    }
    let mut ordered = paths.iter().map(String::as_str).collect::<Vec<_>>();
    ordered.sort_unstable();
    if ordered.windows(2).any(|pair| {
        pair[1]
            .strip_prefix(pair[0])
            .is_some_and(|suffix| suffix.starts_with('/'))
    }) {
        return Err("批量操作不能同时包含父路径及其子路径".to_string());
    }
    Ok(())
}

fn validate_mutation_path(path: &str) -> Result<(), String> {
    validate_absolute_path(path, false)
}

fn validate_absolute_path(path: &str, allow_root: bool) -> Result<(), String> {
    if path.is_empty()
        || path.len() > MAX_REMOTE_PATH_LENGTH
        || !path.starts_with('/')
        || path.contains('\0')
        || path.chars().any(char::is_control)
        || (path.len() > 1 && path.ends_with('/'))
        || path.contains("//")
    {
        return Err("远端操作路径必须是规范的绝对路径".to_string());
    }
    if path == "/" {
        return if allow_root {
            Ok(())
        } else {
            Err("禁止对远端根目录执行变更操作".to_string())
        };
    }
    let components = path.split('/').skip(1).collect::<Vec<_>>();
    if components.len() > MAX_OPERATION_DEPTH {
        return Err(format!("远端路径深度超过安全上限（{MAX_OPERATION_DEPTH}）"));
    }
    for component in components {
        validate_component(component)?;
    }
    Ok(())
}

fn validate_component(component: &str) -> Result<(), String> {
    if component.is_empty()
        || component.len() > MAX_REMOTE_COMPONENT_LENGTH
        || matches!(component, "." | "..")
        || component.contains('/')
        || component.contains('\\')
        || component.contains('\0')
        || component.chars().any(char::is_control)
    {
        return Err("远端名称包含空值、路径分隔符、控制字符、`.`/`..` 或长度超限".to_string());
    }
    Ok(())
}

fn validate_permission_mode(mode: u32) -> Result<(), String> {
    if mode > 0o777 {
        return Err("权限必须在 000 到 777 之间，不允许 setuid、setgid 或 sticky 位".to_string());
    }
    Ok(())
}

fn validate_confirmation_token(token: &str) -> Result<(), String> {
    if token.len() != 36
        || !token
            .chars()
            .all(|value| value.is_ascii_hexdigit() || value == '-')
    {
        return Err("文件操作确认令牌无效".to_string());
    }
    Ok(())
}

fn remote_parent(path: &str) -> Result<&str, String> {
    let index = path
        .rfind('/')
        .ok_or_else(|| "远端操作路径必须是绝对路径".to_string())?;
    if index == 0 {
        Ok("/")
    } else {
        Ok(&path[..index])
    }
}

fn remote_join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn format_mode(mode: u32) -> String {
    format!("{:03o}", mode & 0o777)
}

fn is_sftp_not_found(error: &ssh2::Error) -> bool {
    matches!(error.code(), ErrorCode::SFTP(2))
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap};

    use super::*;

    #[derive(Default)]
    struct FakeBackend {
        nodes: RefCell<BTreeMap<String, RemoteNode>>,
        fail_permissions: RefCell<HashSet<String>>,
        fail_removal: RefCell<HashSet<String>>,
        cancel_copy: RefCell<HashSet<String>>,
        reads: RefCell<Vec<String>>,
    }

    impl FakeBackend {
        fn add(&self, path: &str, kind: RemoteNodeKind, mode: u32) {
            self.nodes.borrow_mut().insert(
                path.to_string(),
                RemoteNode {
                    kind,
                    size: 1,
                    modified: Some(10),
                    permissions: Some(mode),
                },
            );
        }
    }

    impl RemoteFileBackend for FakeBackend {
        fn lstat(&self, path: &str) -> Result<Option<RemoteNode>, String> {
            Ok(self.nodes.borrow().get(path).cloned())
        }

        fn read_dir(&self, path: &str) -> Result<Vec<String>, String> {
            self.reads.borrow_mut().push(path.to_string());
            Ok(self
                .nodes
                .borrow()
                .keys()
                .filter(|candidate| remote_parent(candidate).ok() == Some(path))
                .cloned()
                .collect())
        }

        fn mkdir(&self, path: &str, mode: u32) -> Result<(), String> {
            self.add(path, RemoteNodeKind::Directory, mode);
            Ok(())
        }

        fn rename(&self, source: &str, target: &str) -> Result<(), String> {
            if self.nodes.borrow().contains_key(target) {
                return Err("target exists".to_string());
            }
            let moved = self
                .nodes
                .borrow()
                .iter()
                .filter(|(path, _)| {
                    path.as_str() == source
                        || path
                            .strip_prefix(source)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                })
                .map(|(path, node)| (path.clone(), node.clone()))
                .collect::<Vec<_>>();
            if moved.is_empty() {
                return Err("missing".to_string());
            }
            let mut nodes = self.nodes.borrow_mut();
            for (path, _) in &moved {
                nodes.remove(path);
            }
            for (old_path, node) in moved {
                let suffix = old_path.strip_prefix(source).unwrap_or_default();
                nodes.insert(format!("{target}{suffix}"), node);
            }
            Ok(())
        }

        fn set_permissions(&self, path: &str, mode: u32) -> Result<(), String> {
            if self.fail_permissions.borrow().contains(path) {
                return Err("permission denied".to_string());
            }
            self.nodes
                .borrow_mut()
                .get_mut(path)
                .ok_or_else(|| "missing".to_string())?
                .permissions = Some(mode);
            Ok(())
        }

        fn unlink(&self, path: &str) -> Result<(), String> {
            if self.fail_removal.borrow().contains(path) {
                return Err("remove denied".to_string());
            }
            self.nodes
                .borrow_mut()
                .remove(path)
                .map(|_| ())
                .ok_or_else(|| "missing".to_string())
        }

        fn rmdir(&self, path: &str) -> Result<(), String> {
            if self.fail_removal.borrow().contains(path) {
                return Err("remove denied".to_string());
            }
            self.unlink(path)
        }

        fn copy_file_verified(
            &self,
            source: &str,
            target: &str,
            expected_size: u64,
            checkpoint: &dyn Fn() -> Result<(), String>,
        ) -> Result<(), String> {
            checkpoint()?;
            if self.cancel_copy.borrow().contains(source) {
                return Err(TRANSFER_CANCELLED.to_string());
            }
            let mut node = self
                .nodes
                .borrow()
                .get(source)
                .cloned()
                .ok_or_else(|| "missing".to_string())?;
            if node.kind != RemoteNodeKind::File || node.size != expected_size {
                return Err("verification failed".to_string());
            }
            node.permissions = Some(0o600);
            self.nodes.borrow_mut().insert(target.to_string(), node);
            checkpoint()
        }
    }

    #[test]
    fn mutation_paths_reject_root_parent_segments_controls_and_excess_depth() {
        assert!(validate_mutation_path("/").is_err());
        assert!(validate_mutation_path("relative/file").is_err());
        assert!(validate_mutation_path("/safe/../file").is_err());
        assert!(validate_mutation_path("/safe\nfile").is_err());
        assert!(validate_mutation_path("/safe//file").is_err());
        let deep = format!("/{}", vec!["a"; MAX_OPERATION_DEPTH + 1].join("/"));
        assert!(validate_mutation_path(&deep).is_err());
        assert!(validate_absolute_path("/", true).is_ok());
    }

    #[test]
    fn names_and_batch_counts_are_bounded() {
        assert!(validate_component("new-dir").is_ok());
        assert!(validate_component("..").is_err());
        assert!(validate_component("a/b").is_err());
        assert!(validate_component("bad\u{7f}").is_err());
        assert!(validate_component(&"a".repeat(MAX_REMOTE_COMPONENT_LENGTH + 1)).is_err());
        let too_many = (0..=MAX_OPERATION_PATHS)
            .map(|index| format!("/item-{index}"))
            .collect::<Vec<_>>();
        assert!(validate_operation_paths(&too_many).is_err());
        assert!(validate_operation_paths(&["/a".to_string(), "/a".to_string()]).is_err());
        assert!(validate_operation_paths(&["/a".to_string(), "/a/child".to_string()]).is_err());
    }

    #[test]
    fn permission_mode_excludes_special_bits_and_out_of_range_values() {
        assert!(validate_permission_mode(0o000).is_ok());
        assert!(validate_permission_mode(0o755).is_ok());
        assert!(validate_permission_mode(0o777).is_ok());
        assert!(validate_permission_mode(0o1000).is_err());
        assert!(validate_permission_mode(0o4755).is_err());
    }

    #[test]
    fn create_and_rename_never_overwrite_existing_targets() {
        let backend = FakeBackend::default();
        backend.add("/", RemoteNodeKind::Directory, 0o755);
        backend.add("/source", RemoteNodeKind::File, 0o644);
        backend.add("/existing", RemoteNodeKind::File, 0o600);
        assert!(
            build_plan(
                &backend,
                &RemoteFileOperationRequest::CreateDirectory {
                    parent_path: "/".to_string(),
                    name: "existing".to_string(),
                },
            )
            .is_err()
        );
        assert!(
            build_plan(
                &backend,
                &RemoteFileOperationRequest::Rename {
                    source_path: "/source".to_string(),
                    new_name: "existing".to_string(),
                },
            )
            .is_err()
        );
    }

    #[test]
    fn symlinks_are_skipped_by_chmod_and_deleted_without_following() {
        let backend = FakeBackend::default();
        backend.add("/link", RemoteNodeKind::Symlink, 0o777);
        backend.add("/target", RemoteNodeKind::Directory, 0o755);
        backend.add("/target/child", RemoteNodeKind::File, 0o644);

        let chmod = build_plan(
            &backend,
            &RemoteFileOperationRequest::SetPermissions {
                paths: vec!["/link".to_string()],
                mode: 0o600,
                recursive: false,
            },
        )
        .expect("chmod preview");
        assert!(matches!(chmod.actions[0], PlannedAction::Skip { .. }));

        let delete = build_plan(
            &backend,
            &RemoteFileOperationRequest::Delete {
                paths: vec!["/link".to_string()],
                recursive: true,
            },
        )
        .expect("delete preview");
        let result = execute_plan(&backend, delete).expect("delete result");
        assert_eq!(result.succeeded, 1);
        assert!(backend.lstat("/link").expect("lstat").is_none());
        assert!(backend.lstat("/target/child").expect("lstat").is_some());
        assert!(!backend.reads.borrow().iter().any(|path| path == "/link"));
    }

    #[test]
    fn batch_permission_failures_report_partial_results_per_item() {
        let backend = FakeBackend::default();
        for path in ["/one", "/two", "/three"] {
            backend.add(path, RemoteNodeKind::File, 0o644);
        }
        backend
            .fail_permissions
            .borrow_mut()
            .insert("/two".to_string());
        let plan = build_plan(
            &backend,
            &RemoteFileOperationRequest::SetPermissions {
                paths: vec!["/one".to_string(), "/two".to_string(), "/three".to_string()],
                mode: 0o600,
                recursive: false,
            },
        )
        .expect("preview");
        let result = execute_plan(&backend, plan).expect("result");
        assert_eq!(result.outcome, "partial");
        assert_eq!(result.succeeded, 2);
        assert_eq!(result.failed, 1);
        assert_eq!(result.skipped, 0);
        assert!(result.partial);
        assert_eq!(result.items[1].outcome, "failed");
    }

    #[test]
    fn recursive_delete_reports_an_item_that_was_partially_applied() {
        let backend = FakeBackend::default();
        backend.add("/dir", RemoteNodeKind::Directory, 0o755);
        backend.add("/dir/a", RemoteNodeKind::File, 0o644);
        backend.add("/dir/b", RemoteNodeKind::File, 0o644);
        backend
            .fail_removal
            .borrow_mut()
            .insert("/dir/a".to_string());
        let plan = build_plan(
            &backend,
            &RemoteFileOperationRequest::Delete {
                paths: vec!["/dir".to_string()],
                recursive: true,
            },
        )
        .expect("preview");
        let result = execute_plan(&backend, plan).expect("result");
        assert_eq!(result.outcome, "partial");
        assert_eq!(result.failed, 1);
        assert!(result.partial);
        assert!(result.items[0].partial);
        assert!(backend.lstat("/dir/b").expect("lstat").is_none());
        assert!(backend.lstat("/dir/a").expect("lstat").is_some());
    }

    #[test]
    fn state_changes_after_preview_are_skipped_instead_of_replayed() {
        let backend = FakeBackend::default();
        backend.add("/file", RemoteNodeKind::File, 0o644);
        let plan = build_plan(
            &backend,
            &RemoteFileOperationRequest::SetPermissions {
                paths: vec!["/file".to_string()],
                mode: 0o600,
                recursive: false,
            },
        )
        .expect("preview");
        backend
            .nodes
            .borrow_mut()
            .get_mut("/file")
            .expect("file")
            .modified = Some(11);
        let result = execute_plan(&backend, plan).expect("result");
        assert_eq!(result.succeeded, 0);
        assert_eq!(result.skipped, 1);
        assert_eq!(result.items[0].outcome, "skipped");
    }

    #[test]
    fn recursive_delete_stops_at_depth_and_entry_limits() {
        let backend = FakeBackend::default();
        for depth in 0..=MAX_OPERATION_DEPTH + 1 {
            let path = format!("/{}", vec!["d"; depth + 1].join("/"));
            backend.add(&path, RemoteNodeKind::Directory, 0o755);
        }
        let request = RemoteFileOperationRequest::Delete {
            paths: vec!["/d".to_string()],
            recursive: true,
        };
        assert!(build_plan(&backend, &request).is_err());

        let mut count = MAX_RECURSIVE_ENTRIES;
        let mut inventory = Vec::new();
        assert!(collect_inventory(&backend, "/d", 0, &mut count, &mut inventory).is_err());
    }

    #[test]
    fn cross_directory_move_copies_verifies_commits_and_cleans_source() {
        let backend = FakeBackend::default();
        backend.add("/source", RemoteNodeKind::Directory, 0o755);
        backend.add("/source/tree", RemoteNodeKind::Directory, 0o750);
        backend.add("/source/tree/file.txt", RemoteNodeKind::File, 0o640);
        backend.add("/destination", RemoteNodeKind::Directory, 0o755);
        let plan = build_plan(
            &backend,
            &RemoteFileOperationRequest::Move {
                source_paths: vec!["/source/tree".to_string()],
                destination_directory: "/destination".to_string(),
                conflict_policy: ConflictPolicy::Fail,
            },
        )
        .expect("move preview");
        let result = execute_plan(&backend, plan).expect("move result");
        assert_eq!(result.outcome, "completed");
        assert_eq!(result.succeeded, 1);
        assert!(backend.lstat("/source/tree").expect("source").is_none());
        assert!(
            backend
                .lstat("/destination/tree/file.txt")
                .expect("target")
                .is_some()
        );
        assert!(
            !backend
                .nodes
                .borrow()
                .keys()
                .any(|path| path.contains(".vpshell-"))
        );
    }

    #[test]
    fn move_conflict_policies_fail_rename_and_explicit_overwrite() {
        let fail_backend = FakeBackend::default();
        for path in ["/source", "/destination"] {
            fail_backend.add(path, RemoteNodeKind::Directory, 0o755);
        }
        fail_backend.add("/source/file.txt", RemoteNodeKind::File, 0o640);
        fail_backend.add("/destination/file.txt", RemoteNodeKind::File, 0o600);
        let fail = build_plan(
            &fail_backend,
            &RemoteFileOperationRequest::Move {
                source_paths: vec!["/source/file.txt".to_string()],
                destination_directory: "/destination".to_string(),
                conflict_policy: ConflictPolicy::Fail,
            },
        )
        .expect("fail preview");
        assert!(matches!(fail.actions[0], PlannedAction::Skip { .. }));

        let rename = build_plan(
            &fail_backend,
            &RemoteFileOperationRequest::Move {
                source_paths: vec!["/source/file.txt".to_string()],
                destination_directory: "/destination".to_string(),
                conflict_policy: ConflictPolicy::Rename,
            },
        )
        .expect("rename preview");
        let rename_result = execute_plan(&fail_backend, rename).expect("rename result");
        assert_eq!(rename_result.outcome, "completed");
        assert!(
            fail_backend
                .lstat("/destination/file (1).txt")
                .expect("renamed target")
                .is_some()
        );

        let overwrite_backend = FakeBackend::default();
        for path in ["/source", "/destination"] {
            overwrite_backend.add(path, RemoteNodeKind::Directory, 0o755);
        }
        overwrite_backend.add("/source/file.txt", RemoteNodeKind::File, 0o640);
        overwrite_backend.add("/destination/file.txt", RemoteNodeKind::File, 0o600);
        let overwrite = build_plan(
            &overwrite_backend,
            &RemoteFileOperationRequest::Move {
                source_paths: vec!["/source/file.txt".to_string()],
                destination_directory: "/destination".to_string(),
                conflict_policy: ConflictPolicy::Overwrite,
            },
        )
        .expect("overwrite preview");
        let overwrite_result = execute_plan(&overwrite_backend, overwrite).expect("overwrite");
        assert_eq!(overwrite_result.outcome, "completed");
        assert_eq!(
            overwrite_backend
                .lstat("/destination/file.txt")
                .expect("target")
                .expect("target exists")
                .permissions,
            Some(0o640)
        );
        assert!(
            !overwrite_backend
                .nodes
                .borrow()
                .keys()
                .any(|path| path.contains(".vpshell-"))
        );
    }

    #[test]
    fn recursive_permissions_isolate_symlinks_and_freeze_inventory() {
        let backend = FakeBackend::default();
        backend.add("/tree", RemoteNodeKind::Directory, 0o755);
        backend.add("/tree/file", RemoteNodeKind::File, 0o644);
        backend.add("/tree/link", RemoteNodeKind::Symlink, 0o777);
        let plan = build_plan(
            &backend,
            &RemoteFileOperationRequest::SetPermissions {
                paths: vec!["/tree".to_string()],
                mode: 0o700,
                recursive: true,
            },
        )
        .expect("recursive chmod preview");
        let result = execute_plan(&backend, plan).expect("recursive chmod result");
        assert_eq!(result.outcome, "completed");
        assert_eq!(
            backend.lstat("/tree/file").unwrap().unwrap().permissions,
            Some(0o700)
        );
        assert_eq!(
            backend.lstat("/tree/link").unwrap().unwrap().permissions,
            Some(0o777)
        );
    }

    #[test]
    fn move_cancellation_cleans_staging_and_skips_remaining_items() {
        let backend = FakeBackend::default();
        for path in ["/source", "/destination"] {
            backend.add(path, RemoteNodeKind::Directory, 0o755);
        }
        backend.add("/source/a", RemoteNodeKind::File, 0o644);
        backend.add("/source/b", RemoteNodeKind::File, 0o644);
        backend
            .cancel_copy
            .borrow_mut()
            .insert("/source/a".to_string());
        let plan = build_plan(
            &backend,
            &RemoteFileOperationRequest::Move {
                source_paths: vec!["/source/a".to_string(), "/source/b".to_string()],
                destination_directory: "/destination".to_string(),
                conflict_policy: ConflictPolicy::Fail,
            },
        )
        .expect("move preview");
        let result = execute_plan(&backend, plan).expect("cancelled result");
        assert!(result.cancelled);
        assert_eq!(result.outcome, "cancelled");
        assert_eq!(result.skipped, 2);
        assert!(backend.lstat("/source/a").unwrap().is_some());
        assert!(backend.lstat("/source/b").unwrap().is_some());
        assert!(
            !backend
                .nodes
                .borrow()
                .keys()
                .any(|path| path.contains(".vpshell-"))
        );
    }

    #[test]
    fn committed_move_cleanup_failure_is_reported_as_partial() {
        let backend = FakeBackend::default();
        for path in ["/source", "/destination"] {
            backend.add(path, RemoteNodeKind::Directory, 0o755);
        }
        backend.add("/source/file", RemoteNodeKind::File, 0o644);
        backend
            .fail_removal
            .borrow_mut()
            .insert("/source/file".to_string());
        let plan = build_plan(
            &backend,
            &RemoteFileOperationRequest::Move {
                source_paths: vec!["/source/file".to_string()],
                destination_directory: "/destination".to_string(),
                conflict_policy: ConflictPolicy::Fail,
            },
        )
        .expect("move preview");
        let result = execute_plan(&backend, plan).expect("partial result");
        assert_eq!(result.outcome, "partial");
        assert!(result.partial);
        assert_eq!(result.failed, 1);
        assert!(backend.lstat("/destination/file").unwrap().is_some());
        assert!(backend.lstat("/source/file").unwrap().is_some());
    }

    #[test]
    fn target_change_after_move_preview_is_skipped() {
        let backend = FakeBackend::default();
        for path in ["/source", "/destination"] {
            backend.add(path, RemoteNodeKind::Directory, 0o755);
        }
        backend.add("/source/file", RemoteNodeKind::File, 0o644);
        let plan = build_plan(
            &backend,
            &RemoteFileOperationRequest::Move {
                source_paths: vec!["/source/file".to_string()],
                destination_directory: "/destination".to_string(),
                conflict_policy: ConflictPolicy::Fail,
            },
        )
        .expect("move preview");
        backend.add("/destination/file", RemoteNodeKind::File, 0o600);
        let result = execute_plan(&backend, plan).expect("stale result");
        assert_eq!(result.skipped, 1);
        assert!(backend.lstat("/source/file").unwrap().is_some());
    }

    #[test]
    fn confirmation_tokens_are_connection_bound_and_single_use() {
        let manager = RemoteFileOperationManager::default();
        let identity = ConnectionIdentity {
            host: "example.test".to_string(),
            port: 22,
            username: "root".to_string(),
        };
        let other = ConnectionIdentity {
            username: "other".to_string(),
            ..identity.clone()
        };
        let plan = OperationPlan {
            operation: "delete".to_string(),
            destructive: true,
            actions: vec![],
        };
        let preview = manager
            .register(
                identity.clone(),
                RemoteFileOperationRequest::Delete {
                    paths: vec!["/unused".to_string()],
                    recursive: false,
                },
                plan,
                None,
            )
            .expect("register preview");
        assert!(manager.take(&preview.confirmation_token, &other).is_err());
        assert!(manager.take(&preview.confirmation_token, &identity).is_ok());
        assert!(
            manager
                .take(&preview.confirmation_token, &identity)
                .is_err()
        );
    }
}

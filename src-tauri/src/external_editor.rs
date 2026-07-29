use std::{
    collections::HashMap,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, MutexGuard},
    time::UNIX_EPOCH,
};

#[cfg(windows)]
use std::env;

use serde::Serialize;
use sha2::{Digest, Sha256};
use ssh2::{FileStat, RenameFlags, Sftp};
use tauri::{AppHandle, Manager, State};

use crate::file_transfer::{ConnectionSpec, connect, validate_connection, validate_remote_path};

const MAX_EDIT_SESSIONS: usize = 16;
const MAX_EDIT_FILE_SIZE: u64 = 64 * 1024 * 1024;
const COPY_BUFFER_SIZE: usize = 128 * 1024;
const MAX_EDITOR_PATH_LENGTH: usize = 4096;

#[derive(Clone, Default)]
pub(crate) struct ExternalEditorManager {
    sessions: Arc<Mutex<HashMap<String, EditSession>>>,
}

#[derive(Clone)]
struct EditSession {
    connection: ConnectionSpec,
    remote_path: String,
    local_path: PathBuf,
    work_dir: PathBuf,
    baseline: RemoteFingerprint,
    busy: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

enum EditorPlan {
    Direct(PathBuf),
    SystemDefault,
    #[cfg(target_os = "macos")]
    MacApplication(PathBuf),
}

struct OperationGuard {
    manager: ExternalEditorManager,
    session_id: String,
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
    fn lock(&self) -> Result<MutexGuard<'_, HashMap<String, EditSession>>, String> {
        self.sessions
            .lock()
            .map_err(|_| "外部编辑会话状态已损坏".to_string())
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
        Ok(())
    }
}

#[tauri::command]
pub(crate) async fn begin_external_edit(
    app: AppHandle,
    manager: State<'_, ExternalEditorManager>,
    connection: ConnectionSpec,
    remote_path: String,
    editor_path: String,
) -> Result<BeginExternalEditResult, String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        begin_external_edit_blocking(app, manager, connection, remote_path, editor_path)
    })
    .await
    .map_err(|error| format!("外部编辑启动任务异常结束: {error}"))?
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
    app: AppHandle,
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
    let cache_root = app
        .path()
        .app_cache_dir()
        .map_err(|error| format!("无法定位应用缓存目录: {error}"))?
        .join("external-edits");
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
            busy: false,
        };
        {
            let mut sessions = manager.lock()?;
            if sessions.len() >= MAX_EDIT_SESSIONS {
                return Err("同时外部编辑的文件不能超过 16 个".to_string());
            }
            sessions.insert(session_id.clone(), edit_session);
        }

        let editor_label = match launch_editor(&editor, &local_path) {
            Ok(label) => label,
            Err(error) => {
                let _ = manager
                    .lock()
                    .map(|mut sessions| sessions.remove(&session_id));
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
        Ok(()) if !edit.work_dir.exists() => Ok(()),
        Ok(()) => Err("外部编辑缓存目录仍然存在，请关闭编辑器后重试".to_string()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
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
        #[cfg(windows)]
        if path
            .file_name()
            .is_some_and(|value| value.eq_ignore_ascii_case("notepad++.exe"))
        {
            return Ok(EditorPlan::SystemDefault);
        }
        return Err("设置中的外部编辑器不存在或不是普通文件".to_string());
    }

    #[cfg(windows)]
    if !path
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
    {
        return Err("Windows 外部编辑器必须是 .exe 文件".to_string());
    }
    Ok(EditorPlan::Direct(path))
}

fn default_editor_plan() -> EditorPlan {
    #[cfg(windows)]
    if let Some(program_files) = env::var_os("ProgramFiles") {
        let notepad_plus_plus = PathBuf::from(program_files)
            .join("Notepad++")
            .join("notepad++.exe");
        if notepad_plus_plus.is_file() {
            return EditorPlan::Direct(notepad_plus_plus);
        }
    }
    EditorPlan::SystemDefault
}

fn launch_editor(editor: &EditorPlan, local_path: &Path) -> Result<String, String> {
    match editor {
        EditorPlan::Direct(executable) => {
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
    use super::{RemoteFingerprint, safe_local_filename, validate_session_id, version_conflicts};

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
}

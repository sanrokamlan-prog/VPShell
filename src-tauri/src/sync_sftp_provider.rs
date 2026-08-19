use std::{
    io::{Read, Write},
    path::Path,
    sync::Mutex,
};

use ssh2::{FileStat, OpenFlags, OpenType, RenameFlags, Session, Sftp};

use crate::{
    file_transfer::{ConnectionSpec, connect_pinned},
    sync_provider::{
        ProviderCancellation, ProviderError, ProviderErrorCode, ProviderResult, validate_key,
        validate_object_bytes,
    },
    sync_provider_ext::{
        ConditionalCreateResult, ObjectTransport, SftpObjectTransport, SftpProviderConfig,
        TransportEntryKind, TransportObject,
    },
};

const MAX_OBJECT_BYTES: usize = 24 * 1024 * 1024;
const MAX_LIST_ENTRIES: usize = 10_000;
const MAX_KEY_DEPTH: usize = 16;
const IO_CHUNK_BYTES: usize = 64 * 1024;
const STAGING_DIRECTORY: &str = ".vpshell-staging";

struct SftpTransportState {
    // Drop the SFTP channel before its owning SSH session.
    sftp: Sftp,
    _session: Session,
}

pub(crate) struct Ssh2SftpObjectTransport {
    root: String,
    state: Mutex<SftpTransportState>,
}

impl Ssh2SftpObjectTransport {
    pub(crate) fn connect(
        config: &SftpProviderConfig,
        connection: ConnectionSpec,
    ) -> ProviderResult<Self> {
        config.validate()?;
        if connection.host != config.host
            || connection.port != config.port
            || connection.username != config.username
        {
            return Err(provider_error(
                ProviderErrorCode::InvalidInput,
                "SFTP 同步主机与本机连接资料不一致",
            ));
        }
        let session = connect_pinned(&connection, &config.host_key_sha256)
            .map_err(|_| provider_error(ProviderErrorCode::Unavailable, "SFTP 同步连接失败"))?;
        let timeout_ms =
            u32::try_from(config.timeout_seconds.saturating_mul(1_000)).map_err(|_| {
                provider_error(ProviderErrorCode::InvalidInput, "SFTP 同步超时配置无效")
            })?;
        session.set_timeout(timeout_ms);
        let sftp = session.sftp().map_err(|_| {
            provider_error(ProviderErrorCode::Unavailable, "无法建立 SFTP 同步通道")
        })?;
        let transport = Self {
            root: config.root.clone(),
            state: Mutex::new(SftpTransportState {
                sftp,
                _session: session,
            }),
        };
        {
            let state = transport.lock_state()?;
            verify_directory_chain(&state.sftp, &transport.root, false)?;
            ensure_staging_directory(&state.sftp, &transport.root)?;
        }
        Ok(transport)
    }

    fn lock_state(&self) -> ProviderResult<std::sync::MutexGuard<'_, SftpTransportState>> {
        self.state
            .lock()
            .map_err(|_| provider_error(ProviderErrorCode::Unavailable, "SFTP 同步会话锁不可用"))
    }

    fn object_path(&self, key: &str) -> ProviderResult<String> {
        validate_key(key)?;
        Ok(format!("{}/{}", self.root, key))
    }
}

impl ObjectTransport for Ssh2SftpObjectTransport {
    fn list_objects(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Vec<TransportObject>> {
        cancellation.check()?;
        let state = self.lock_state()?;
        verify_directory_chain(&state.sftp, &self.root, false)?;
        let mut entries = Vec::new();
        let mut visited = 0usize;
        collect_objects(
            &state.sftp,
            &self.root,
            "",
            0,
            &mut visited,
            &mut entries,
            cancellation,
        )?;
        entries.retain(|entry| {
            entry.key.starts_with(prefix) && cursor.is_none_or(|cursor| entry.key.as_str() > cursor)
        });
        entries.sort_by(|left, right| left.key.cmp(&right.key));
        entries.truncate(limit);
        Ok(entries)
    }

    fn get_object(
        &self,
        key: &str,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Vec<u8>> {
        cancellation.check()?;
        let path = self.object_path(key)?;
        let state = self.lock_state()?;
        verify_object_parent_chain(&state.sftp, &self.root, key, false)?;
        let stat = lstat_required(&state.sftp, &path)?;
        if !stat.file_type().is_file() || stat.file_type().is_symlink() {
            return Err(provider_error(
                ProviderErrorCode::UnsafePath,
                "SFTP 同步对象不是普通文件",
            ));
        }
        let size = bounded_size(&stat)?;
        let mut file = state.sftp.open(Path::new(&path)).map_err(|_| {
            provider_error(ProviderErrorCode::Unavailable, "无法打开 SFTP 同步对象")
        })?;
        let mut bytes = Vec::with_capacity(size);
        let mut buffer = [0u8; IO_CHUNK_BYTES];
        loop {
            cancellation.check()?;
            let count = file.read(&mut buffer).map_err(|_| {
                provider_error(ProviderErrorCode::Unavailable, "无法读取 SFTP 同步对象")
            })?;
            if count == 0 {
                break;
            }
            if bytes.len().saturating_add(count) > MAX_OBJECT_BYTES {
                return Err(provider_error(
                    ProviderErrorCode::LimitExceeded,
                    "SFTP 同步对象超过 24 MiB",
                ));
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        if bytes.len() != size {
            return Err(provider_error(
                ProviderErrorCode::Protocol,
                "SFTP 同步对象大小在读取期间发生变化",
            ));
        }
        validate_object_bytes(&bytes)?;
        Ok(bytes)
    }

    fn create_object(
        &self,
        key: &str,
        bytes: &[u8],
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<ConditionalCreateResult> {
        validate_object_bytes(bytes)?;
        cancellation.check()?;
        let path = self.object_path(key)?;
        let state = self.lock_state()?;
        verify_object_parent_chain(&state.sftp, &self.root, key, true)?;
        if lstat_optional(&state.sftp, &path)?.is_some() {
            return Ok(ConditionalCreateResult::AlreadyExists);
        }
        ensure_staging_directory(&state.sftp, &self.root)?;
        let staging_path = format!(
            "{}/{}/{}.tmp",
            self.root,
            STAGING_DIRECTORY,
            uuid::Uuid::new_v4()
        );
        let mut file = match state.sftp.open_mode(
            Path::new(&staging_path),
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
            0o600,
            OpenType::File,
        ) {
            Ok(file) => file,
            Err(_) => {
                return Err(provider_error(
                    ProviderErrorCode::Unavailable,
                    "无法创建 SFTP 同步暂存对象",
                ));
            }
        };
        let write_result: ProviderResult<()> = (|| {
            for chunk in bytes.chunks(IO_CHUNK_BYTES) {
                cancellation.check()?;
                file.write_all(chunk).map_err(|_| {
                    provider_error(ProviderErrorCode::Unavailable, "无法写入 SFTP 同步对象")
                })?;
            }
            file.flush().map_err(|_| {
                provider_error(ProviderErrorCode::Unavailable, "无法刷新 SFTP 同步对象")
            })?;
            file.fsync().map_err(|_| {
                provider_error(ProviderErrorCode::Unavailable, "无法持久化 SFTP 同步对象")
            })?;
            file.close().map_err(|_| {
                provider_error(ProviderErrorCode::Unavailable, "无法关闭 SFTP 同步对象")
            })?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = state.sftp.unlink(Path::new(&staging_path));
            return Err(error);
        }
        let stat = lstat_required(&state.sftp, &staging_path)?;
        if !stat.file_type().is_file()
            || stat.file_type().is_symlink()
            || !private_permissions(&stat)
            || stat.size != Some(bytes.len() as u64)
        {
            let _ = state.sftp.unlink(Path::new(&staging_path));
            return Err(provider_error(
                ProviderErrorCode::Protocol,
                "SFTP 同步暂存对象类型或大小不一致",
            ));
        }
        if lstat_optional(&state.sftp, &path)?.is_some() {
            let _ = state.sftp.unlink(Path::new(&staging_path));
            return Ok(ConditionalCreateResult::AlreadyExists);
        }
        if state
            .sftp
            .rename(
                Path::new(&staging_path),
                Path::new(&path),
                Some(RenameFlags::ATOMIC | RenameFlags::NATIVE),
            )
            .is_err()
        {
            let target_exists = lstat_optional(&state.sftp, &path)?.is_some();
            let _ = state.sftp.unlink(Path::new(&staging_path));
            return if target_exists {
                Ok(ConditionalCreateResult::AlreadyExists)
            } else {
                Err(provider_error(
                    ProviderErrorCode::Unavailable,
                    "无法无覆盖提交 SFTP 同步对象",
                ))
            };
        }
        let stat = lstat_required(&state.sftp, &path)?;
        if !stat.file_type().is_file()
            || stat.file_type().is_symlink()
            || !private_permissions(&stat)
            || stat.size != Some(bytes.len() as u64)
        {
            return Err(provider_error(
                ProviderErrorCode::Protocol,
                "SFTP 同步对象提交后类型或大小不一致",
            ));
        }
        Ok(ConditionalCreateResult::Created)
    }
}

impl SftpObjectTransport for Ssh2SftpObjectTransport {}

fn provider_error(code: ProviderErrorCode, message: &str) -> ProviderError {
    ProviderError::new(code, message)
}

fn lstat_optional(sftp: &Sftp, path: &str) -> ProviderResult<Option<FileStat>> {
    match sftp.lstat(Path::new(path)) {
        Ok(stat) => Ok(Some(stat)),
        Err(error) if matches!(error.code(), ssh2::ErrorCode::SFTP(2)) => Ok(None),
        Err(_) => Err(provider_error(
            ProviderErrorCode::Unavailable,
            "无法读取 SFTP 同步路径属性",
        )),
    }
}

fn lstat_required(sftp: &Sftp, path: &str) -> ProviderResult<FileStat> {
    lstat_optional(sftp, path)?
        .ok_or_else(|| provider_error(ProviderErrorCode::NotFound, "SFTP 同步对象不存在"))
}

fn verify_directory_chain(sftp: &Sftp, root: &str, create: bool) -> ProviderResult<()> {
    let mut current = String::new();
    for segment in root.trim_start_matches('/').split('/') {
        current.push('/');
        current.push_str(segment);
        match lstat_optional(sftp, &current)? {
            Some(stat) if stat.file_type().is_dir() && !stat.file_type().is_symlink() => {}
            Some(_) => {
                return Err(provider_error(
                    ProviderErrorCode::UnsafePath,
                    "SFTP 同步目录链包含符号链接或非目录条目",
                ));
            }
            None if create => {
                sftp.mkdir(Path::new(&current), 0o700).map_err(|_| {
                    provider_error(ProviderErrorCode::Unavailable, "无法创建 SFTP 同步目录")
                })?;
                let stat = lstat_required(sftp, &current)?;
                if !stat.file_type().is_dir() || stat.file_type().is_symlink() {
                    return Err(provider_error(
                        ProviderErrorCode::UnsafePath,
                        "新建 SFTP 同步目录类型不安全",
                    ));
                }
            }
            None => {
                return Err(provider_error(
                    ProviderErrorCode::InvalidInput,
                    "SFTP 同步根目录必须已存在",
                ));
            }
        }
    }
    Ok(())
}

fn ensure_staging_directory(sftp: &Sftp, root: &str) -> ProviderResult<()> {
    let path = format!("{root}/{STAGING_DIRECTORY}");
    if lstat_optional(sftp, &path)?.is_none() {
        let _ = sftp.mkdir(Path::new(&path), 0o700);
    }
    let stat = lstat_required(sftp, &path)?;
    if !stat.file_type().is_dir() || stat.file_type().is_symlink() || !private_permissions(&stat) {
        return Err(provider_error(
            ProviderErrorCode::UnsafePath,
            "SFTP 同步暂存目录类型不安全",
        ));
    }
    Ok(())
}

fn private_permissions(stat: &FileStat) -> bool {
    stat.perm
        .is_some_and(|permissions| permissions & 0o077 == 0)
}

fn verify_object_parent_chain(
    sftp: &Sftp,
    root: &str,
    key: &str,
    create: bool,
) -> ProviderResult<()> {
    verify_directory_chain(sftp, root, false)?;
    let segments = validate_key(key)?;
    let mut current = root.to_string();
    for segment in segments.iter().take(segments.len().saturating_sub(1)) {
        current.push('/');
        current.push_str(segment);
        match lstat_optional(sftp, &current)? {
            Some(stat) if stat.file_type().is_dir() && !stat.file_type().is_symlink() => {}
            Some(_) => {
                return Err(provider_error(
                    ProviderErrorCode::UnsafePath,
                    "SFTP 同步对象父路径包含符号链接或非目录条目",
                ));
            }
            None if create => {
                sftp.mkdir(Path::new(&current), 0o700).map_err(|_| {
                    provider_error(ProviderErrorCode::Unavailable, "无法创建 SFTP 同步对象目录")
                })?;
                let stat = lstat_required(sftp, &current)?;
                if !stat.file_type().is_dir() || stat.file_type().is_symlink() {
                    return Err(provider_error(
                        ProviderErrorCode::UnsafePath,
                        "新建 SFTP 同步对象目录类型不安全",
                    ));
                }
            }
            None => {
                return Err(provider_error(
                    ProviderErrorCode::NotFound,
                    "SFTP 同步对象父目录不存在",
                ));
            }
        }
    }
    Ok(())
}

fn bounded_size(stat: &FileStat) -> ProviderResult<usize> {
    let size = stat.size.unwrap_or(0);
    if size == 0 || size > MAX_OBJECT_BYTES as u64 {
        return Err(provider_error(
            ProviderErrorCode::LimitExceeded,
            "SFTP 同步对象大小必须为 1 字节至 24 MiB",
        ));
    }
    Ok(size as usize)
}

#[allow(clippy::too_many_arguments)]
fn collect_objects(
    sftp: &Sftp,
    root: &str,
    relative: &str,
    depth: usize,
    visited: &mut usize,
    entries: &mut Vec<TransportObject>,
    cancellation: &ProviderCancellation,
) -> ProviderResult<()> {
    if depth > MAX_KEY_DEPTH {
        return Err(provider_error(
            ProviderErrorCode::LimitExceeded,
            "SFTP 同步对象目录超过 16 层",
        ));
    }
    cancellation.check()?;
    let directory = if relative.is_empty() {
        root.to_string()
    } else {
        format!("{root}/{relative}")
    };
    let children = sftp
        .readdir(Path::new(&directory))
        .map_err(|_| provider_error(ProviderErrorCode::Unavailable, "无法列出 SFTP 同步目录"))?;
    for (path, stat) in children {
        cancellation.check()?;
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                provider_error(
                    ProviderErrorCode::Protocol,
                    "SFTP 同步目录返回无法解析的名称",
                )
            })?;
        if matches!(name, "." | "..") {
            continue;
        }
        if relative.is_empty() && name == STAGING_DIRECTORY {
            if !stat.file_type().is_dir()
                || stat.file_type().is_symlink()
                || !private_permissions(&stat)
            {
                return Err(provider_error(
                    ProviderErrorCode::UnsafePath,
                    "SFTP 同步暂存目录类型不安全",
                ));
            }
            continue;
        }
        let key = if relative.is_empty() {
            name.to_string()
        } else {
            format!("{relative}/{name}")
        };
        validate_key(&key).map_err(|_| {
            provider_error(ProviderErrorCode::Protocol, "SFTP 同步目录返回非法对象 key")
        })?;
        *visited = visited.saturating_add(1);
        if *visited > MAX_LIST_ENTRIES {
            return Err(provider_error(
                ProviderErrorCode::LimitExceeded,
                "SFTP 同步目录超过 10000 个条目",
            ));
        }
        let file_type = stat.file_type();
        if file_type.is_symlink() {
            return Err(provider_error(
                ProviderErrorCode::UnsafePath,
                "SFTP 同步目录包含符号链接",
            ));
        }
        if file_type.is_dir() {
            collect_objects(
                sftp,
                root,
                &key,
                depth.saturating_add(1),
                visited,
                entries,
                cancellation,
            )?;
        } else if file_type.is_file() {
            entries.push(TransportObject {
                key,
                size: bounded_size(&stat)? as u64,
                etag: None,
                kind: TransportEntryKind::Regular,
            });
        } else {
            return Err(provider_error(
                ProviderErrorCode::UnsafePath,
                "SFTP 同步目录包含特殊文件",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;

    use crate::{
        sync_provider::{ProviderCancellation, ProviderErrorCode, SyncObjectProvider},
        sync_provider_ext::{SftpProviderConfig, SftpSyncProvider},
    };

    use super::*;

    #[test]
    fn real_sftp_provider_when_configured() {
        let Some(host) = env::var("VPSHELL_NATIVE_TEST_HOST").ok() else {
            return;
        };
        let port = env::var("VPSHELL_NATIVE_TEST_PORT")
            .expect("fixture port")
            .parse::<u16>()
            .expect("numeric fixture port");
        let username = env::var("VPSHELL_NATIVE_TEST_USER").expect("fixture user");
        let identity_file = env::var("VPSHELL_NATIVE_TEST_IDENTITY_FILE").expect("fixture key");
        let host_key_sha256 = env::var("VPSHELL_NATIVE_TEST_HOST_KEY_SHA256").expect("fixture pin");
        let root = env::var("VPSHELL_SYNC_SFTP_TEST_ROOT").expect("fixture sync root");
        let connection = ConnectionSpec {
            host: host.clone(),
            port,
            username: username.clone(),
            credential_ref: None,
            identity_file: Some(identity_file),
            identity_passphrase_ref: None,
        };
        let config = SftpProviderConfig {
            host,
            port,
            username,
            root,
            host_key_sha256,
            timeout_seconds: 30,
        };
        config.validate().expect("fixture config");
        let mut wrong_host_key_sha256 = config.host_key_sha256.clone();
        let replacement = if wrong_host_key_sha256.starts_with("SHA256:A") {
            "B"
        } else {
            "A"
        };
        wrong_host_key_sha256.replace_range(7..8, replacement);
        let wrong_pin = SftpProviderConfig {
            host_key_sha256: wrong_host_key_sha256,
            ..config.clone()
        };
        let wrong_pin_error = Ssh2SftpObjectTransport::connect(&wrong_pin, connection.clone())
            .err()
            .expect("wrong pin must fail");
        assert_eq!(wrong_pin_error.code, ProviderErrorCode::Unavailable);
        let transport = Ssh2SftpObjectTransport::connect(&config, connection).expect("transport");
        let provider = SftpSyncProvider::connect(config, transport).expect("provider");
        let cancellation = ProviderCancellation::default();
        let key = format!("objects/{}.oseg", uuid::Uuid::new_v4());
        assert!(provider.put(&key, b"alpha", &cancellation).is_ok());
        assert_eq!(provider.get(&key, &cancellation).unwrap(), b"alpha");
        let page = provider.list("objects/", None, 100, &cancellation).unwrap();
        assert!(page.objects.iter().any(|object| object.key == key));
        assert!(
            page.objects
                .iter()
                .all(|object| !object.key.contains(STAGING_DIRECTORY))
        );
        assert_eq!(
            provider
                .put(&key, b"different", &cancellation)
                .unwrap_err()
                .code,
            ProviderErrorCode::Conflict
        );
    }
}

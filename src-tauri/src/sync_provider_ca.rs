use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::Deserialize;
use uuid::Uuid;

use crate::sync_provider::validate_trusted_ca_pem;

const MAX_SOURCE_PATH_BYTES: usize = 4096;
const MAX_CA_BYTES: usize = 64 * 1024;
pub(crate) const WEBDAV_CA_PREFIX: &str = "sync-webdav-ca-";

#[derive(Clone)]
pub(crate) struct SyncProviderCaManager {
    inner: Arc<SyncProviderCaInner>,
}

struct SyncProviderCaInner {
    directory: PathBuf,
    lock: Mutex<()>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InstallWebDavCaRequest {
    path: String,
}

impl SyncProviderCaManager {
    pub(crate) fn load(app_data_directory: PathBuf) -> Result<Self, String> {
        let directory = app_data_directory.join("sync-provider-ca");
        fs::create_dir_all(&directory).map_err(|_| "无法创建 WebDAV CA 私有目录".to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| "无法保护 WebDAV CA 私有目录".to_string())?;
        }
        Ok(Self {
            inner: Arc::new(SyncProviderCaInner {
                directory,
                lock: Mutex::new(()),
            }),
        })
    }

    pub(crate) fn install(&self, request: InstallWebDavCaRequest) -> Result<String, String> {
        let source = validate_source_path(&request.path)?;
        let bytes = read_bounded_ca(&source, "无法读取 WebDAV CA 文件")?;
        validate_trusted_ca_pem(&bytes)
            .map_err(|_| "WebDAV CA 文件不是有效的 PEM 证书".to_string())?;
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "WebDAV CA 资产锁不可用".to_string())?;
        let reference = format!("{WEBDAV_CA_PREFIX}{}", Uuid::new_v4());
        let target = self.path_for_reference(&reference)?;
        let next = self
            .inner
            .directory
            .join(format!(".{reference}.next-{}", Uuid::new_v4().simple()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&next)
            .map_err(|_| "无法创建 WebDAV CA 暂存文件".to_string())?;
        let result = file
            .write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "无法写入 WebDAV CA 暂存文件".to_string());
        drop(file);
        if let Err(error) = result {
            let _ = fs::remove_file(&next);
            return Err(error);
        }
        if target.exists() {
            let _ = fs::remove_file(&next);
            return Err("WebDAV CA 随机引用发生碰撞".to_string());
        }
        if fs::rename(&next, &target).is_err() {
            let _ = fs::remove_file(&next);
            return Err("无法提交 WebDAV CA 资产".to_string());
        }
        Ok(reference)
    }

    pub(crate) fn read(&self, reference: &str) -> Result<Vec<u8>, String> {
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "WebDAV CA 资产锁不可用".to_string())?;
        let path = self.path_for_reference(reference)?;
        let bytes = read_bounded_ca(&path, "未找到已保存的 WebDAV CA")?;
        validate_trusted_ca_pem(&bytes).map_err(|_| "已保存的 WebDAV CA 已损坏".to_string())?;
        Ok(bytes)
    }

    pub(crate) fn delete(&self, reference: &str) -> Result<(), String> {
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "WebDAV CA 资产锁不可用".to_string())?;
        let path = self.path_for_reference(reference)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                Err("WebDAV CA 资产类型无效".to_string())
            }
            Ok(_) => fs::remove_file(path).map_err(|_| "无法删除 WebDAV CA 资产".to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("无法检查 WebDAV CA 资产".to_string()),
        }
    }

    fn path_for_reference(&self, reference: &str) -> Result<PathBuf, String> {
        validate_webdav_ca_reference(reference)?;
        Ok(self.inner.directory.join(format!("{reference}.pem")))
    }
}

pub(crate) fn validate_webdav_ca_reference(reference: &str) -> Result<(), String> {
    if reference.len() > 128
        || !reference.starts_with(WEBDAV_CA_PREFIX)
        || !reference
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
    {
        return Err("WebDAV CA 引用无效".to_string());
    }
    let identifier = reference
        .strip_prefix(WEBDAV_CA_PREFIX)
        .ok_or_else(|| "WebDAV CA 引用无效".to_string())?;
    Uuid::parse_str(identifier).map_err(|_| "WebDAV CA 引用无效".to_string())?;
    Ok(())
}

fn validate_source_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty()
        || value.len() > MAX_SOURCE_PATH_BYTES
        || value.chars().any(|character| character.is_control())
    {
        return Err("WebDAV CA 路径必须为 1 至 4096 字节且不含控制字符".to_string());
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err("WebDAV CA 路径必须是绝对路径".to_string());
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "无法读取 WebDAV CA 文件元数据".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("WebDAV CA 必须是普通文件，不能是符号链接".to_string());
    }
    path.canonicalize()
        .map_err(|_| "无法规范化 WebDAV CA 路径".to_string())
}

fn read_bounded_ca(path: &Path, error_message: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| error_message.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_CA_BYTES as u64
    {
        return Err("WebDAV CA 必须是 1 字节至 64 KiB 的普通文件".to_string());
    }
    let mut file = File::open(path).map_err(|_| error_message.to_string())?;
    let opened = file.metadata().map_err(|_| error_message.to_string())?;
    if !opened.is_file() || opened.len() != metadata.len() {
        return Err("WebDAV CA 文件在读取期间发生变化".to_string());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_CA_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error_message.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_CA_BYTES || bytes.len() as u64 != opened.len() {
        return Err("WebDAV CA 文件在读取期间发生变化或超过 64 KiB".to_string());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CA: &[u8] = include_bytes!("../fixtures/webdav-test-ca.pem");

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("vpshell-webdav-ca-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn imports_reads_and_deletes_private_ca_by_random_reference() {
        let root = TempDir::new();
        let source = root.0.join("source.pem");
        fs::write(&source, TEST_CA).unwrap();
        let manager = SyncProviderCaManager::load(root.0.join("app-data")).unwrap();
        let reference = manager
            .install(InstallWebDavCaRequest {
                path: source.to_string_lossy().into_owned(),
            })
            .unwrap();
        assert!(validate_webdav_ca_reference(&reference).is_ok());
        assert_eq!(manager.read(&reference).unwrap(), TEST_CA);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let directory_mode = fs::metadata(&manager.inner.directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let file_mode = fs::metadata(manager.path_for_reference(&reference).unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(directory_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
        manager.delete(&reference).unwrap();
        assert!(manager.read(&reference).is_err());
    }

    #[test]
    fn references_paths_contents_and_sizes_are_strictly_bounded() {
        for invalid in [
            "sync-webdav-not-a-ca",
            "sync-webdav-ca-not-a-uuid",
            "sync-webdav-ca-00000000-0000-0000-0000-000000000000/escape",
        ] {
            assert!(validate_webdav_ca_reference(invalid).is_err());
        }
        let root = TempDir::new();
        let manager = SyncProviderCaManager::load(root.0.join("app-data")).unwrap();
        assert!(
            manager
                .install(InstallWebDavCaRequest {
                    path: "relative.pem".to_string(),
                })
                .is_err()
        );
        let invalid = root.0.join("invalid.pem");
        fs::write(&invalid, b"not-a-certificate").unwrap();
        assert!(
            manager
                .install(InstallWebDavCaRequest {
                    path: invalid.to_string_lossy().into_owned(),
                })
                .is_err()
        );
        let private_material = root.0.join("private-material.pem");
        let mut combined = TEST_CA.to_vec();
        combined.extend_from_slice(
            b"-----BEGIN PRIVATE KEY-----\nforbidden\n-----END PRIVATE KEY-----\n",
        );
        fs::write(&private_material, combined).unwrap();
        assert!(
            manager
                .install(InstallWebDavCaRequest {
                    path: private_material.to_string_lossy().into_owned(),
                })
                .is_err()
        );
        let oversized = root.0.join("oversized.pem");
        fs::write(&oversized, vec![b'x'; MAX_CA_BYTES + 1]).unwrap();
        assert!(
            manager
                .install(InstallWebDavCaRequest {
                    path: oversized.to_string_lossy().into_owned(),
                })
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_ca_sources_are_rejected() {
        use std::os::unix::fs::symlink;

        let root = TempDir::new();
        let source = root.0.join("source.pem");
        let link = root.0.join("link.pem");
        fs::write(&source, TEST_CA).unwrap();
        symlink(&source, &link).unwrap();
        let manager = SyncProviderCaManager::load(root.0.join("app-data")).unwrap();
        assert!(
            manager
                .install(InstallWebDavCaRequest {
                    path: link.to_string_lossy().into_owned(),
                })
                .is_err()
        );
        let reference = format!("{WEBDAV_CA_PREFIX}{}", Uuid::new_v4());
        let managed_link = manager.path_for_reference(&reference).unwrap();
        symlink(&source, &managed_link).unwrap();
        assert!(manager.read(&reference).is_err());
        assert!(manager.delete(&reference).is_err());
    }
}

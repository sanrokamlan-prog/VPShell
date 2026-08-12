use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::prelude::*;
use reqwest::{StatusCode, Url, blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_PATH_BYTES: usize = 4096;
const MAX_URL_BYTES: usize = 2048;
const MAX_WALLPAPER_BYTES: usize = 8 * 1024 * 1024;
const MAX_FONT_BYTES: usize = 12 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct LocalAssetManager {
    inner: Arc<LocalAssetInner>,
}

struct LocalAssetInner {
    directory: PathBuf,
    lock: Mutex<()>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InstallWallpaperRequest {
    source: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InstallFontRequest {
    path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RenderAsset {
    data_url: String,
    label: String,
    media_type: String,
    size: usize,
}

fn validate_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() || value.len() > MAX_PATH_BYTES {
        return Err("资产路径必须为 1–4096 字节".to_string());
    }
    if value
        .chars()
        .any(|character| character == '\0' || character.is_control())
    {
        return Err("资产路径不能包含控制字符".to_string());
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err("资产路径必须是绝对路径".to_string());
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("无法读取资产: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("资产必须是普通文件，不能是符号链接".to_string());
    }
    path.canonicalize()
        .map_err(|error| format!("无法规范化资产路径: {error}"))
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("无法读取资产元数据: {error}"))?;
    if metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err(format!("资产必须为 1 字节至 {} MiB", maximum / 1024 / 1024));
    }
    let bytes = fs::read(path).map_err(|error| format!("无法读取资产: {error}"))?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("资产读取后大小超出限制".to_string());
    }
    Ok(bytes)
}

fn wallpaper_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

fn font_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x00, 0x01, 0x00, 0x00]) || bytes.starts_with(b"true") {
        Some("font/ttf")
    } else if bytes.starts_with(b"OTTO") {
        Some("font/otf")
    } else if bytes.starts_with(b"wOFF") {
        Some("font/woff")
    } else if bytes.starts_with(b"wOF2") {
        Some("font/woff2")
    } else {
        None
    }
}

fn data_url(media_type: &str, bytes: &[u8]) -> String {
    format!("data:{media_type};base64,{}", BASE64_STANDARD.encode(bytes))
}

fn safe_label(path: &Path, fallback: &str) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .map(|value| value.chars().take(128).collect())
        .unwrap_or_else(|| fallback.to_string())
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let next = path.with_extension(format!("next-{}", Uuid::new_v4().simple()));
    let previous = path.with_extension("previous");
    let mut file = File::create(&next).map_err(|error| format!("无法创建资产暂存文件: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("无法写入资产暂存文件: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("无法同步资产暂存文件: {error}"))?;
    drop(file);
    if previous.exists() {
        fs::remove_file(&previous).map_err(|error| format!("无法清理旧资产备份: {error}"))?;
    }
    if path.exists() {
        fs::rename(path, &previous).map_err(|error| format!("无法轮换当前资产: {error}"))?;
    }
    if let Err(error) = fs::rename(&next, path) {
        if previous.exists() {
            let _ = fs::rename(&previous, path);
        }
        let _ = fs::remove_file(&next);
        return Err(format!("无法提交新资产: {error}"));
    }
    if previous.exists() {
        fs::remove_file(previous).map_err(|error| format!("无法清理资产备份: {error}"))?;
    }
    Ok(())
}

fn decode_legacy_wallpaper(value: &str) -> Result<Vec<u8>, String> {
    if value.len() > (MAX_WALLPAPER_BYTES * 4 / 3 + 128) {
        return Err("旧壁纸 data URL 超过限制".to_string());
    }
    let (_, encoded) = value
        .split_once(";base64,")
        .filter(|(prefix, _)| prefix.starts_with("data:image/"))
        .ok_or_else(|| "旧壁纸不是受支持的 base64 图片".to_string())?;
    let bytes = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| "旧壁纸 base64 无效".to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_WALLPAPER_BYTES {
        return Err("旧壁纸大小超出限制".to_string());
    }
    Ok(bytes)
}

fn download_wallpaper(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() > MAX_URL_BYTES || value.chars().any(char::is_control) {
        return Err("壁纸 URL 必须为 1–2048 字节且不含控制字符".to_string());
    }
    let url = Url::parse(value).map_err(|_| "壁纸 URL 无效".to_string())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("壁纸 URL 必须是无凭据、query 和 fragment 的 HTTPS 地址".to_string());
    }
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(Policy::none())
        .build()
        .map_err(|error| format!("无法创建壁纸下载器: {error}"))?;
    let mut response = client
        .get(url)
        .send()
        .map_err(|error| format!("壁纸下载失败: {error}"))?;
    if response.status() != StatusCode::OK {
        return Err(format!(
            "壁纸服务器返回 HTTP {}",
            response.status().as_u16()
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_WALLPAPER_BYTES as u64)
    {
        return Err("壁纸响应超过 8 MiB".to_string());
    }
    let mut bytes = Vec::new();
    response
        .copy_to(&mut bytes)
        .map_err(|error| format!("无法读取壁纸响应: {error}"))?;
    if bytes.is_empty() || bytes.len() > MAX_WALLPAPER_BYTES {
        return Err("壁纸响应大小必须为 1 字节至 8 MiB".to_string());
    }
    Ok(bytes)
}

impl LocalAssetManager {
    pub(crate) fn load(app_data_directory: PathBuf) -> Result<Self, String> {
        let directory = app_data_directory.join("assets");
        fs::create_dir_all(&directory).map_err(|error| format!("无法创建本地资产目录: {error}"))?;
        Ok(Self {
            inner: Arc::new(LocalAssetInner {
                directory,
                lock: Mutex::new(()),
            }),
        })
    }

    fn wallpaper_path(&self) -> PathBuf {
        self.inner.directory.join("wallpaper.asset")
    }
    fn font_path(&self) -> PathBuf {
        self.inner.directory.join("terminal-font.asset")
    }

    pub(crate) fn install_wallpaper(
        &self,
        request: InstallWallpaperRequest,
    ) -> Result<RenderAsset, String> {
        let (bytes, label) = match request.source.as_str() {
            "local" => {
                let path = validate_path(&request.value)?;
                (
                    read_bounded(&path, MAX_WALLPAPER_BYTES)?,
                    safe_label(&path, "本机壁纸"),
                )
            }
            "url" => (
                download_wallpaper(&request.value)?,
                "HTTPS 壁纸".to_string(),
            ),
            "legacy-data" => (
                decode_legacy_wallpaper(&request.value)?,
                "迁移的本机壁纸".to_string(),
            ),
            _ => return Err("壁纸来源只允许 local、url 或 legacy-data".to_string()),
        };
        let media_type = wallpaper_type(&bytes)
            .ok_or_else(|| "壁纸内容不是有效 PNG、JPEG 或 WebP".to_string())?;
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地资产锁不可用".to_string())?;
        atomic_replace(&self.wallpaper_path(), &bytes)?;
        Ok(RenderAsset {
            data_url: data_url(media_type, &bytes),
            label,
            media_type: media_type.to_string(),
            size: bytes.len(),
        })
    }

    pub(crate) fn load_wallpaper(&self) -> Result<Option<RenderAsset>, String> {
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地资产锁不可用".to_string())?;
        let path = self.wallpaper_path();
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_bounded(&path, MAX_WALLPAPER_BYTES)?;
        let media_type = wallpaper_type(&bytes).ok_or_else(|| "缓存壁纸格式损坏".to_string())?;
        Ok(Some(RenderAsset {
            data_url: data_url(media_type, &bytes),
            label: "受管壁纸".to_string(),
            media_type: media_type.to_string(),
            size: bytes.len(),
        }))
    }

    pub(crate) fn install_font(&self, request: InstallFontRequest) -> Result<RenderAsset, String> {
        let path = validate_path(&request.path)?;
        let bytes = read_bounded(&path, MAX_FONT_BYTES)?;
        let media_type = font_type(&bytes)
            .ok_or_else(|| "字体内容不是有效 TTF、OTF、WOFF 或 WOFF2".to_string())?;
        let label = safe_label(&path, "自定义字体");
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地资产锁不可用".to_string())?;
        atomic_replace(&self.font_path(), &bytes)?;
        Ok(RenderAsset {
            data_url: data_url(media_type, &bytes),
            label,
            media_type: media_type.to_string(),
            size: bytes.len(),
        })
    }

    pub(crate) fn load_font(&self) -> Result<Option<RenderAsset>, String> {
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地资产锁不可用".to_string())?;
        let path = self.font_path();
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_bounded(&path, MAX_FONT_BYTES)?;
        let media_type = font_type(&bytes).ok_or_else(|| "缓存字体格式损坏".to_string())?;
        Ok(Some(RenderAsset {
            data_url: data_url(media_type, &bytes),
            label: "受管字体".to_string(),
            media_type: media_type.to_string(),
            size: bytes.len(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("vpshell-assets-{}", Uuid::new_v4()));
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
    fn local_assets_validate_magic_and_replace_atomically() {
        let root = TempDir::new();
        let manager = LocalAssetManager::load(root.0.clone()).unwrap();
        let image = root.0.join("image.png");
        fs::write(&image, b"\x89PNG\r\n\x1a\nfixture").unwrap();
        let installed = manager
            .install_wallpaper(InstallWallpaperRequest {
                source: "local".to_string(),
                value: image.to_str().unwrap().to_string(),
            })
            .unwrap();
        assert_eq!(installed.media_type, "image/png");
        assert!(manager.load_wallpaper().unwrap().is_some());
        fs::write(&image, b"not-an-image").unwrap();
        assert!(
            manager
                .install_wallpaper(InstallWallpaperRequest {
                    source: "local".to_string(),
                    value: image.to_str().unwrap().to_string()
                })
                .is_err()
        );
        assert_eq!(
            manager.load_wallpaper().unwrap().unwrap().media_type,
            "image/png"
        );
    }

    #[test]
    fn urls_reject_credentials_queries_redirect_surface_and_non_https() {
        for value in [
            "http://example.com/a.png",
            "https://user:pass@example.com/a.png",
            "https://example.com/a.png?token=x",
            "https://example.com/a.png#x",
        ] {
            assert!(download_wallpaper(value).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_files_are_rejected() {
        use std::os::unix::fs::symlink;
        let root = TempDir::new();
        let image = root.0.join("image.png");
        let link = root.0.join("link.png");
        fs::write(&image, b"\x89PNG\r\n\x1a\nfixture").unwrap();
        symlink(&image, &link).unwrap();
        assert!(validate_path(link.to_str().unwrap()).is_err());
    }

    #[test]
    fn font_and_legacy_data_are_bounded_and_typed() {
        let root = TempDir::new();
        let manager = LocalAssetManager::load(root.0.clone()).unwrap();
        let font = root.0.join("font.woff2");
        fs::write(&font, b"wOF2fixture").unwrap();
        assert_eq!(
            manager
                .install_font(InstallFontRequest {
                    path: font.to_str().unwrap().to_string()
                })
                .unwrap()
                .media_type,
            "font/woff2"
        );
        let legacy = format!(
            "data:image/png;base64,{}",
            BASE64_STANDARD.encode(b"\x89PNG\r\n\x1a\nlegacy")
        );
        assert_eq!(
            manager
                .install_wallpaper(InstallWallpaperRequest {
                    source: "legacy-data".to_string(),
                    value: legacy
                })
                .unwrap()
                .media_type,
            "image/png"
        );
    }
}

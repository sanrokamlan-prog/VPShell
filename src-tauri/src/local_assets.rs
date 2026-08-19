use std::{
    fs::{self, File},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::prelude::*;
use reqwest::{StatusCode, Url, blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_PATH_BYTES: usize = 4096;
const MAX_URL_BYTES: usize = 2048;
const MAX_WALLPAPER_BYTES: usize = 8 * 1024 * 1024;
const MAX_WALLPAPER_PIXELS: u64 = 16 * 1024 * 1024;
const MAX_DECODED_WALLPAPER_BYTES: usize = 64 * 1024 * 1024;
const MAX_FONT_BYTES: usize = 12 * 1024 * 1024;
const WALLPAPER_METADATA_VERSION: u16 = 1;

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
    pub(crate) source: String,
    pub(crate) value: String,
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
    pub(crate) managed_blob_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WallpaperAssetMetadata {
    format_version: u16,
    blob_id: Option<String>,
    media_type: String,
    label: String,
    size: usize,
    content_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedWallpaper {
    pub(crate) blob_id: String,
    pub(crate) media_type: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) content_hash: String,
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
    let file = File::open(path).map_err(|error| format!("无法打开资产: {error}"))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(maximum)
            .min(maximum),
    );
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("无法读取资产: {error}"))?;
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

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn content_hash(bytes: &[u8]) -> String {
    lowercase_hex(&Sha256::digest(bytes))
}

fn validate_blob_id(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("壁纸 blob ID 必须是 64 位 lowercase hex".to_string());
    }
    Ok(())
}

fn new_blob_id() -> Result<String, String> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).map_err(|_| "无法生成壁纸 blob ID".to_string())?;
    Ok(lowercase_hex(&random))
}

fn normalize_png(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() < 24 || wallpaper_type(bytes) != Some("image/png") {
        return Err("同步壁纸必须是 PNG".to_string());
    }
    let width = u32::from_be_bytes(bytes[16..20].try_into().expect("PNG width bytes"));
    let height = u32::from_be_bytes(bytes[20..24].try_into().expect("PNG height bytes"));
    if width == 0
        || height == 0
        || u64::from(width).saturating_mul(u64::from(height)) > MAX_WALLPAPER_PIXELS
    {
        return Err("PNG 壁纸像素必须为 1 至 16777216".to_string());
    }
    let mut decoder = png::Decoder::new(Cursor::new(bytes));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder
        .read_info()
        .map_err(|_| "PNG 壁纸结构或校验无效".to_string())?;
    let output_size = reader.output_buffer_size();
    if output_size == 0 || output_size > MAX_DECODED_WALLPAPER_BYTES {
        return Err("PNG 壁纸解码后超过 64 MiB".to_string());
    }
    let mut decoded = vec![0_u8; output_size];
    let info = reader
        .next_frame(&mut decoded)
        .map_err(|_| "PNG 壁纸解码失败".to_string())?;
    if info.width != width || info.height != height || info.buffer_size() > decoded.len() {
        return Err("PNG 壁纸尺寸在解码期间发生变化".to_string());
    }
    decoded.truncate(info.buffer_size());
    let mut normalized = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut normalized, info.width, info.height);
        encoder.set_color(info.color_type);
        encoder.set_depth(info.bit_depth);
        encoder.set_compression(png::Compression::Default);
        let mut writer = encoder
            .write_header()
            .map_err(|_| "无法建立 PNG 壁纸编码器".to_string())?;
        writer
            .write_image_data(&decoded)
            .map_err(|_| "无法重新编码 PNG 壁纸".to_string())?;
    }
    if normalized.is_empty() || normalized.len() > MAX_WALLPAPER_BYTES {
        return Err("规范化 PNG 壁纸超过 8 MiB".to_string());
    }
    Ok(normalized)
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

fn cleanup_asset_staging(directory: &Path) -> Result<(), String> {
    for entry in
        fs::read_dir(directory).map_err(|error| format!("无法扫描本地资产暂存文件: {error}"))?
    {
        let entry = entry.map_err(|error| format!("无法读取本地资产暂存项: {error}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let suffix = [
            "wallpaper.next-",
            "wallpaper.metadata.next-",
            "terminal-font.next-",
        ]
        .iter()
        .find_map(|prefix| name.strip_prefix(prefix));
        let Some(suffix) = suffix else {
            continue;
        };
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("无法读取本地资产暂存元数据: {error}"))?;
        if metadata.is_file() && !metadata.file_type().is_symlink() {
            fs::remove_file(entry.path())
                .map_err(|error| format!("无法清理本地资产暂存文件: {error}"))?;
        }
    }
    Ok(())
}

fn encode_wallpaper_metadata(metadata: &WallpaperAssetMetadata) -> Result<Vec<u8>, String> {
    if metadata.format_version != WALLPAPER_METADATA_VERSION
        || metadata.media_type.is_empty()
        || metadata.media_type.len() > 64
        || metadata.label.is_empty()
        || metadata.label.len() > 512
        || metadata.label.chars().any(char::is_control)
        || metadata.size == 0
        || metadata.size > MAX_WALLPAPER_BYTES
        || metadata.content_hash.len() != 64
        || !metadata
            .content_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("壁纸受管元数据无效".to_string());
    }
    if let Some(blob_id) = metadata.blob_id.as_deref() {
        validate_blob_id(blob_id)?;
        if metadata.media_type != "image/png" {
            return Err("只有安全规范化 PNG 可以生成同步 blob".to_string());
        }
    }
    serde_json::to_vec(metadata).map_err(|_| "无法编码壁纸受管元数据".to_string())
}

fn decode_wallpaper_metadata(bytes: &[u8]) -> Result<WallpaperAssetMetadata, String> {
    if bytes.is_empty() || bytes.len() > 2048 {
        return Err("壁纸受管元数据为空或超过 2 KiB".to_string());
    }
    let metadata: WallpaperAssetMetadata =
        serde_json::from_slice(bytes).map_err(|_| "壁纸受管元数据损坏".to_string())?;
    encode_wallpaper_metadata(&metadata)?;
    Ok(metadata)
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
    let response = client
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
    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(MAX_WALLPAPER_BYTES),
    );
    response
        .take((MAX_WALLPAPER_BYTES as u64).saturating_add(1))
        .read_to_end(&mut bytes)
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
        cleanup_asset_staging(&directory)?;
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
    fn wallpaper_metadata_path(&self) -> PathBuf {
        self.inner.directory.join("wallpaper.metadata.json")
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
        let (bytes, blob_id) = if media_type == "image/png" {
            (normalize_png(&bytes)?, Some(new_blob_id()?))
        } else {
            (bytes, None)
        };
        let metadata = WallpaperAssetMetadata {
            format_version: WALLPAPER_METADATA_VERSION,
            blob_id: blob_id.clone(),
            media_type: media_type.to_string(),
            label: label.clone(),
            size: bytes.len(),
            content_hash: content_hash(&bytes),
        };
        let metadata_bytes = encode_wallpaper_metadata(&metadata)?;
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地资产锁不可用".to_string())?;
        atomic_replace(&self.wallpaper_path(), &bytes)?;
        atomic_replace(&self.wallpaper_metadata_path(), &metadata_bytes)?;
        Ok(RenderAsset {
            data_url: data_url(media_type, &bytes),
            label,
            media_type: media_type.to_string(),
            size: bytes.len(),
            managed_blob_id: blob_id,
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
        let managed_blob_id = read_bounded(&self.wallpaper_metadata_path(), 2048)
            .ok()
            .and_then(|encoded| decode_wallpaper_metadata(&encoded).ok())
            .filter(|metadata| {
                metadata.media_type == media_type
                    && metadata.size == bytes.len()
                    && metadata.content_hash == content_hash(&bytes)
            })
            .and_then(|metadata| metadata.blob_id);
        Ok(Some(RenderAsset {
            data_url: data_url(media_type, &bytes),
            label: "受管壁纸".to_string(),
            media_type: media_type.to_string(),
            size: bytes.len(),
            managed_blob_id,
        }))
    }

    pub(crate) fn syncable_wallpaper(
        &self,
        expected_blob_id: &str,
    ) -> Result<ManagedWallpaper, String> {
        validate_blob_id(expected_blob_id)?;
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地资产锁不可用".to_string())?;
        let bytes = read_bounded(&self.wallpaper_path(), MAX_WALLPAPER_BYTES)?;
        let metadata = decode_wallpaper_metadata(
            &read_bounded(&self.wallpaper_metadata_path(), 2048)
                .map_err(|_| "同步壁纸缺少受管元数据".to_string())?,
        )?;
        if metadata.blob_id.as_deref() != Some(expected_blob_id)
            || metadata.media_type != "image/png"
            || metadata.size != bytes.len()
            || metadata.content_hash != content_hash(&bytes)
            || normalize_png(&bytes)? != bytes
        {
            return Err("同步壁纸与受管引用不匹配".to_string());
        }
        Ok(ManagedWallpaper {
            blob_id: expected_blob_id.to_string(),
            media_type: metadata.media_type,
            content_hash: metadata.content_hash,
            bytes,
        })
    }

    pub(crate) fn install_synced_wallpaper(
        &self,
        blob_id: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<RenderAsset, String> {
        validate_blob_id(blob_id)?;
        if media_type != "image/png" || bytes.is_empty() || bytes.len() > MAX_WALLPAPER_BYTES {
            return Err("远端壁纸只接受 1 字节至 8 MiB 的 PNG".to_string());
        }
        let normalized = normalize_png(bytes)?;
        if normalized != bytes {
            return Err("远端 PNG 壁纸不是规范化编码".to_string());
        }
        let label = "同步壁纸".to_string();
        let metadata = WallpaperAssetMetadata {
            format_version: WALLPAPER_METADATA_VERSION,
            blob_id: Some(blob_id.to_string()),
            media_type: media_type.to_string(),
            label: label.clone(),
            size: bytes.len(),
            content_hash: content_hash(bytes),
        };
        let metadata_bytes = encode_wallpaper_metadata(&metadata)?;
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地资产锁不可用".to_string())?;
        atomic_replace(&self.wallpaper_path(), bytes)?;
        atomic_replace(&self.wallpaper_metadata_path(), &metadata_bytes)?;
        Ok(RenderAsset {
            data_url: data_url(media_type, bytes),
            label,
            media_type: media_type.to_string(),
            size: bytes.len(),
            managed_blob_id: Some(blob_id.to_string()),
        })
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
            managed_blob_id: None,
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
            managed_blob_id: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_fixture() -> Vec<u8> {
        BASE64_STANDARD
            .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
            .unwrap()
    }

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
        fs::write(&image, png_fixture()).unwrap();
        let installed = manager
            .install_wallpaper(InstallWallpaperRequest {
                source: "local".to_string(),
                value: image.to_str().unwrap().to_string(),
            })
            .unwrap();
        assert_eq!(installed.media_type, "image/png");
        assert!(installed.managed_blob_id.is_some());
        assert_eq!(
            manager
                .syncable_wallpaper(installed.managed_blob_id.as_deref().unwrap())
                .unwrap()
                .media_type,
            "image/png"
        );
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
    fn startup_removes_only_exact_regular_asset_staging_files() {
        let root = TempDir::new();
        let assets = root.0.join("assets");
        fs::create_dir_all(&assets).unwrap();
        let stale = assets.join("wallpaper.next-0123456789abcdef0123456789abcdef");
        let unrelated = assets.join("wallpaper.next-not-a-staging-id");
        fs::write(&stale, b"incomplete").unwrap();
        fs::write(&unrelated, b"keep").unwrap();

        LocalAssetManager::load(root.0.clone()).unwrap();

        assert!(!stale.exists());
        assert!(unrelated.exists());
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

    #[test]
    fn png_normalization_rejects_truncation_and_pixel_overflow() {
        assert!(normalize_png(b"\x89PNG\r\n\x1a\ntruncated").is_err());
        let mut oversized = png_fixture();
        oversized[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            normalize_png(&oversized).unwrap_err(),
            "PNG 壁纸像素必须为 1 至 16777216"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_files_are_rejected() {
        use std::os::unix::fs::symlink;
        let root = TempDir::new();
        let image = root.0.join("image.png");
        let link = root.0.join("link.png");
        fs::write(&image, png_fixture()).unwrap();
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
            BASE64_STANDARD.encode(png_fixture())
        );
        let installed = manager
            .install_wallpaper(InstallWallpaperRequest {
                source: "legacy-data".to_string(),
                value: legacy,
            })
            .unwrap();
        assert_eq!(installed.media_type, "image/png");
        let managed = manager
            .syncable_wallpaper(installed.managed_blob_id.as_deref().unwrap())
            .unwrap();
        assert!(
            manager
                .install_synced_wallpaper(&managed.blob_id, &managed.media_type, &managed.bytes)
                .is_ok()
        );
    }
}

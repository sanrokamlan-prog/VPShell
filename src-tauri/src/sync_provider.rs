use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use percent_encoding::percent_decode_str;
use quick_xml::{Reader, events::Event};
use reqwest::{
    Certificate, Method, StatusCode, Url,
    blocking::{Client, RequestBuilder, Response},
    header::{CONTENT_LENGTH, ETAG, HeaderValue, IF_MATCH, IF_NONE_MATCH},
    redirect::Policy,
};
use zeroize::Zeroizing;

const MAX_OBJECT_BYTES: usize = 24 * 1024 * 1024;
const MAX_KEY_BYTES: usize = 512;
const MAX_SEGMENT_BYTES: usize = 128;
const MAX_KEY_DEPTH: usize = 16;
const MAX_LIST_LIMIT: usize = 1_000;
const MAX_LIST_ENTRIES: usize = 10_000;
const MAX_WEBDAV_XML_BYTES: usize = 4 * 1024 * 1024;
const MAX_CA_BYTES: usize = 64 * 1024;
const MAX_ENDPOINT_BYTES: usize = 2_048;
const MAX_USERNAME_BYTES: usize = 256;
const STAGE_PREFIX: &str = ".vpshell-stage-";
const MIN_TIMEOUT_SECONDS: u64 = 5;
const MAX_TIMEOUT_SECONDS: u64 = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderErrorCode {
    Cancelled,
    InvalidInput,
    UnsafePath,
    NotFound,
    Conflict,
    LimitExceeded,
    Unavailable,
    Protocol,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderError {
    pub(crate) code: ProviderErrorCode,
    pub(crate) message: String,
}

impl ProviderError {
    pub(crate) fn new(code: ProviderErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub(crate) type ProviderResult<T> = Result<T, ProviderError>;

#[derive(Clone, Default)]
pub(crate) struct ProviderCancellation {
    cancelled: Arc<AtomicBool>,
}

impl ProviderCancellation {
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub(crate) fn check(&self) -> ProviderResult<()> {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(ProviderError::new(
                ProviderErrorCode::Cancelled,
                "同步 provider 操作已取消",
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SyncObjectMetadata {
    pub(crate) key: String,
    pub(crate) size: u64,
    pub(crate) etag: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SyncObjectPage {
    pub(crate) objects: Vec<SyncObjectMetadata>,
    pub(crate) next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PutObjectOutcome {
    Created,
    AlreadyPresent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeleteObjectOutcome {
    Deleted,
    AlreadyAbsent,
}

pub(crate) trait SyncObjectProvider: Send + Sync {
    fn list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<SyncObjectPage>;

    fn get(&self, key: &str, cancellation: &ProviderCancellation) -> ProviderResult<Vec<u8>>;

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<PutObjectOutcome>;

    fn delete_exact(
        &self,
        _key: &str,
        _expected: &[u8],
        _cancellation: &ProviderCancellation,
    ) -> ProviderResult<DeleteObjectOutcome> {
        Err(ProviderError::new(
            ProviderErrorCode::Protocol,
            "同步 provider 未实现条件删除",
        ))
    }
}

#[derive(Debug)]
pub(crate) struct LocalFolderProvider {
    root: PathBuf,
}

impl LocalFolderProvider {
    pub(crate) fn open(root: impl AsRef<Path>) -> ProviderResult<Self> {
        let root = root.as_ref();
        let metadata = fs::symlink_metadata(root).map_err(|_| {
            ProviderError::new(
                ProviderErrorCode::InvalidInput,
                "Local Folder 必须是已存在的目录",
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ProviderError::new(
                ProviderErrorCode::UnsafePath,
                "Local Folder 根目录不能是符号链接或普通文件",
            ));
        }
        let root = fs::canonicalize(root).map_err(|_| {
            ProviderError::new(
                ProviderErrorCode::Unavailable,
                "无法解析 Local Folder 根目录",
            )
        })?;
        Ok(Self { root })
    }

    fn existing_object_path(&self, key: &str) -> ProviderResult<PathBuf> {
        let segments = validate_key(key)?;
        let mut path = self.root.clone();
        for segment in segments {
            path.push(segment);
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    ProviderError::new(ProviderErrorCode::NotFound, "同步对象不存在")
                } else {
                    ProviderError::new(ProviderErrorCode::Unavailable, "无法读取同步对象元数据")
                }
            })?;
            if metadata.file_type().is_symlink() {
                return Err(ProviderError::new(
                    ProviderErrorCode::UnsafePath,
                    "Local Folder 对象路径包含符号链接",
                ));
            }
        }
        let metadata = fs::metadata(&path).map_err(|_| {
            ProviderError::new(ProviderErrorCode::Unavailable, "无法读取同步对象元数据")
        })?;
        if !metadata.is_file() {
            return Err(ProviderError::new(
                ProviderErrorCode::UnsafePath,
                "同步对象必须是普通文件",
            ));
        }
        let canonical = fs::canonicalize(&path).map_err(|_| {
            ProviderError::new(ProviderErrorCode::Unavailable, "无法解析同步对象路径")
        })?;
        if !canonical.starts_with(&self.root) {
            return Err(ProviderError::new(
                ProviderErrorCode::UnsafePath,
                "同步对象逃逸 Local Folder 根目录",
            ));
        }
        Ok(path)
    }

    fn ensure_parent(&self, key: &str) -> ProviderResult<PathBuf> {
        let segments = validate_key(key)?;
        let mut parent = self.root.clone();
        for segment in &segments[..segments.len() - 1] {
            parent.push(segment);
            match fs::symlink_metadata(&parent) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        return Err(ProviderError::new(
                            ProviderErrorCode::UnsafePath,
                            "Local Folder 父路径包含符号链接或普通文件",
                        ));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&parent).map_err(|_| {
                        ProviderError::new(
                            ProviderErrorCode::Unavailable,
                            "无法创建 Local Folder 对象目录",
                        )
                    })?;
                }
                Err(_) => {
                    return Err(ProviderError::new(
                        ProviderErrorCode::Unavailable,
                        "无法检查 Local Folder 对象目录",
                    ));
                }
            }
            let canonical = fs::canonicalize(&parent).map_err(|_| {
                ProviderError::new(
                    ProviderErrorCode::Unavailable,
                    "无法解析 Local Folder 对象目录",
                )
            })?;
            if !canonical.starts_with(&self.root) {
                return Err(ProviderError::new(
                    ProviderErrorCode::UnsafePath,
                    "Local Folder 对象目录逃逸根目录",
                ));
            }
        }
        Ok(parent.join(segments.last().expect("validated key has a segment")))
    }

    fn read_existing(
        &self,
        key: &str,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Vec<u8>> {
        cancellation.check()?;
        let path = self.existing_object_path(key)?;
        let before = fs::metadata(&path).map_err(|_| {
            ProviderError::new(ProviderErrorCode::Unavailable, "无法读取同步对象元数据")
        })?;
        if before.len() > MAX_OBJECT_BYTES as u64 {
            return Err(ProviderError::new(
                ProviderErrorCode::LimitExceeded,
                "同步对象超过 24 MiB 限制",
            ));
        }
        let mut file = File::open(&path)
            .map_err(|_| ProviderError::new(ProviderErrorCode::Unavailable, "无法打开同步对象"))?;
        let bytes = read_bounded(&mut file, MAX_OBJECT_BYTES, cancellation)?;
        let after = fs::metadata(&path).map_err(|_| {
            ProviderError::new(ProviderErrorCode::Unavailable, "无法复核同步对象元数据")
        })?;
        if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
            return Err(ProviderError::new(
                ProviderErrorCode::Conflict,
                "读取期间同步对象发生变化",
            ));
        }
        Ok(bytes)
    }
}

impl SyncObjectProvider for LocalFolderProvider {
    fn list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<SyncObjectPage> {
        validate_list_request(prefix, cursor, limit)?;
        cancellation.check()?;
        let mut objects = Vec::new();
        let mut stack = vec![(self.root.clone(), 0usize)];
        let mut visited = 0usize;
        while let Some((directory, depth)) = stack.pop() {
            cancellation.check()?;
            if depth > MAX_KEY_DEPTH {
                return Err(ProviderError::new(
                    ProviderErrorCode::LimitExceeded,
                    "Local Folder 扫描深度超过限制",
                ));
            }
            let entries = fs::read_dir(&directory).map_err(|_| {
                ProviderError::new(
                    ProviderErrorCode::Unavailable,
                    "无法列举 Local Folder 对象目录",
                )
            })?;
            for entry in entries {
                cancellation.check()?;
                visited += 1;
                if visited > MAX_LIST_ENTRIES {
                    return Err(ProviderError::new(
                        ProviderErrorCode::LimitExceeded,
                        "Local Folder 扫描超过 10000 项限制",
                    ));
                }
                let entry = entry.map_err(|_| {
                    ProviderError::new(
                        ProviderErrorCode::Unavailable,
                        "无法读取 Local Folder 目录项",
                    )
                })?;
                let metadata = fs::symlink_metadata(entry.path()).map_err(|_| {
                    ProviderError::new(
                        ProviderErrorCode::Unavailable,
                        "无法读取 Local Folder 目录项元数据",
                    )
                })?;
                if metadata.file_type().is_symlink() {
                    return Err(ProviderError::new(
                        ProviderErrorCode::UnsafePath,
                        "Local Folder 中存在不允许的符号链接",
                    ));
                }
                if metadata.is_dir() {
                    stack.push((entry.path(), depth + 1));
                    continue;
                }
                if !metadata.is_file() {
                    return Err(ProviderError::new(
                        ProviderErrorCode::UnsafePath,
                        "Local Folder 中存在不允许的特殊文件",
                    ));
                }
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(STAGE_PREFIX) && name.ends_with(".tmp"))
                {
                    continue;
                }
                let entry_path = entry.path();
                let relative = entry_path.strip_prefix(&self.root).map_err(|_| {
                    ProviderError::new(
                        ProviderErrorCode::UnsafePath,
                        "Local Folder 目录项逃逸根目录",
                    )
                })?;
                let key = path_to_key(relative)?;
                validate_key(&key)?;
                if key.starts_with(prefix) && cursor.is_none_or(|cursor| key.as_str() > cursor) {
                    objects.push(SyncObjectMetadata {
                        key,
                        size: metadata.len(),
                        etag: None,
                    });
                }
            }
        }
        objects.sort_by(|left, right| left.key.cmp(&right.key));
        let next_cursor = (objects.len() > limit).then(|| objects[limit - 1].key.clone());
        objects.truncate(limit);
        Ok(SyncObjectPage {
            objects,
            next_cursor,
        })
    }

    fn get(&self, key: &str, cancellation: &ProviderCancellation) -> ProviderResult<Vec<u8>> {
        self.read_existing(key, cancellation)
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<PutObjectOutcome> {
        validate_object_bytes(bytes)?;
        cancellation.check()?;
        match self.read_existing(key, cancellation) {
            Ok(existing) if existing == bytes => return Ok(PutObjectOutcome::AlreadyPresent),
            Ok(_) => {
                return Err(ProviderError::new(
                    ProviderErrorCode::Conflict,
                    "同名同步对象内容不同，拒绝覆盖",
                ));
            }
            Err(error) if error.code == ProviderErrorCode::NotFound => {}
            Err(error) => return Err(error),
        }
        let target = self.ensure_parent(key)?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| {
            ProviderError::new(
                ProviderErrorCode::Unavailable,
                "无法生成 Local Folder 暂存文件名",
            )
        })?;
        let stage = target
            .parent()
            .expect("validated key has a parent")
            .join(format!("{STAGE_PREFIX}{}.tmp", hex(&random)));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&stage)
                .map_err(|_| {
                    ProviderError::new(
                        ProviderErrorCode::Unavailable,
                        "无法创建 Local Folder 暂存对象",
                    )
                })?;
            for chunk in bytes.chunks(64 * 1024) {
                cancellation.check()?;
                file.write_all(chunk).map_err(|_| {
                    ProviderError::new(
                        ProviderErrorCode::Unavailable,
                        "无法写入 Local Folder 暂存对象",
                    )
                })?;
            }
            file.sync_all().map_err(|_| {
                ProviderError::new(
                    ProviderErrorCode::Unavailable,
                    "无法同步 Local Folder 暂存对象",
                )
            })?;
            drop(file);
            cancellation.check()?;
            match fs::hard_link(&stage, &target) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let existing = self.read_existing(key, cancellation)?;
                    if existing == bytes {
                        return Ok(PutObjectOutcome::AlreadyPresent);
                    }
                    return Err(ProviderError::new(
                        ProviderErrorCode::Conflict,
                        "同名同步对象在提交时已出现且内容不同",
                    ));
                }
                Err(_) => {
                    return Err(ProviderError::new(
                        ProviderErrorCode::Unavailable,
                        "文件系统不支持安全的 Local Folder 无覆盖提交",
                    ));
                }
            }
            // The hard link is the commit boundary. Cancellation after this point
            // must not report a committed immutable object as uncommitted work.
            let committed = self.read_existing(key, &ProviderCancellation::default())?;
            if committed != bytes {
                return Err(ProviderError::new(
                    ProviderErrorCode::Conflict,
                    "Local Folder 提交后校验失败",
                ));
            }
            Ok(PutObjectOutcome::Created)
        })();
        let _ = fs::remove_file(&stage);
        result
    }

    fn delete_exact(
        &self,
        key: &str,
        expected: &[u8],
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<DeleteObjectOutcome> {
        validate_object_bytes(expected)?;
        cancellation.check()?;
        let path = match self.existing_object_path(key) {
            Ok(path) => path,
            Err(error) if error.code == ProviderErrorCode::NotFound => {
                return Ok(DeleteObjectOutcome::AlreadyAbsent);
            }
            Err(error) => return Err(error),
        };
        if self.read_existing(key, cancellation)? != expected {
            return Err(ProviderError::new(
                ProviderErrorCode::Conflict,
                "Local Folder 条件删除内容不匹配",
            ));
        }
        cancellation.check()?;
        fs::remove_file(&path).map_err(|_| {
            ProviderError::new(
                ProviderErrorCode::Unavailable,
                "无法删除 Local Folder 同步对象",
            )
        })?;
        match self.read_existing(key, &ProviderCancellation::default()) {
            Err(error) if error.code == ProviderErrorCode::NotFound => {
                Ok(DeleteObjectOutcome::Deleted)
            }
            _ => Err(ProviderError::new(
                ProviderErrorCode::Conflict,
                "Local Folder 同步对象删除后仍然存在",
            )),
        }
    }
}

pub(crate) struct WebDavCredentials {
    username: String,
    password: Zeroizing<String>,
}

impl WebDavCredentials {
    pub(crate) fn new(username: String, password: String) -> ProviderResult<Self> {
        Self::from_secret(username, Zeroizing::new(password))
    }

    pub(crate) fn from_secret(
        username: String,
        password: Zeroizing<String>,
    ) -> ProviderResult<Self> {
        if username.is_empty()
            || username.len() > MAX_USERNAME_BYTES
            || username.contains(':')
            || username.chars().any(char::is_control)
            || password.is_empty()
            || password.len() > 1_024
        {
            return Err(ProviderError::new(
                ProviderErrorCode::InvalidInput,
                "WebDAV 凭据字段超出限制",
            ));
        }
        Ok(Self { username, password })
    }
}

pub(crate) struct WebDavProvider {
    endpoint: Url,
    client: Client,
    credentials: Option<WebDavCredentials>,
}

impl WebDavProvider {
    pub(crate) fn connect(
        endpoint: &str,
        credentials: Option<WebDavCredentials>,
        trusted_ca_pem: Option<&[u8]>,
        timeout_seconds: u64,
    ) -> ProviderResult<Self> {
        let endpoint = validate_endpoint(endpoint, false)?;
        if !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&timeout_seconds) {
            return Err(ProviderError::new(
                ProviderErrorCode::InvalidInput,
                "WebDAV 超时必须为 5 至 60 秒",
            ));
        }
        let mut builder = Client::builder()
            .https_only(true)
            .connect_timeout(Duration::from_secs(timeout_seconds.min(10)))
            .timeout(Duration::from_secs(timeout_seconds))
            .redirect(Policy::none());
        if let Some(pem) = trusted_ca_pem {
            builder = builder.add_root_certificate(parse_trusted_ca_pem(pem)?);
        }
        let client = builder.build().map_err(|_| {
            ProviderError::new(
                ProviderErrorCode::Unavailable,
                "无法创建 WebDAV HTTPS 客户端",
            )
        })?;
        Ok(Self {
            endpoint,
            client,
            credentials,
        })
    }

    #[cfg(test)]
    fn connect_http_for_test(endpoint: &str) -> ProviderResult<Self> {
        let endpoint = validate_endpoint(endpoint, true)?;
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .build()
            .expect("test client");
        Ok(Self {
            endpoint,
            client,
            credentials: None,
        })
    }

    fn request(&self, method: Method, url: Url) -> RequestBuilder {
        let request = self.client.request(method, url);
        if let Some(credentials) = &self.credentials {
            request.basic_auth(&credentials.username, Some(credentials.password.as_str()))
        } else {
            request
        }
    }

    fn object_url(&self, key: &str) -> ProviderResult<Url> {
        let segments = validate_key(key)?;
        let mut url = self.endpoint.clone();
        {
            let mut path = url.path_segments_mut().map_err(|_| {
                ProviderError::new(ProviderErrorCode::InvalidInput, "WebDAV endpoint 路径无效")
            })?;
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }
        Ok(url)
    }

    fn prefix_url(&self, prefix: &str) -> ProviderResult<Url> {
        if prefix.is_empty() {
            return Ok(self.endpoint.clone());
        }
        let normalized = prefix.trim_end_matches('/');
        self.object_url(normalized)
    }

    fn read_response(
        &self,
        response: Response,
        maximum: usize,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Vec<u8>> {
        if response
            .content_length()
            .is_some_and(|length| length > maximum as u64)
        {
            return Err(ProviderError::new(
                ProviderErrorCode::LimitExceeded,
                "WebDAV 响应超过大小限制",
            ));
        }
        read_bounded(response, maximum, cancellation)
    }

    fn get_internal(
        &self,
        key: &str,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Vec<u8>> {
        cancellation.check()?;
        let response = self
            .request(Method::GET, self.object_url(key)?)
            .send()
            .map_err(|_| {
                ProviderError::new(ProviderErrorCode::Unavailable, "WebDAV GET 请求失败")
            })?;
        cancellation.check()?;
        match response.status() {
            StatusCode::OK => self.read_response(response, MAX_OBJECT_BYTES, cancellation),
            StatusCode::NOT_FOUND => Err(ProviderError::new(
                ProviderErrorCode::NotFound,
                "WebDAV 同步对象不存在",
            )),
            status if status.is_redirection() => Err(ProviderError::new(
                ProviderErrorCode::Protocol,
                "WebDAV 不允许重定向",
            )),
            _ => Err(ProviderError::new(
                ProviderErrorCode::Unavailable,
                "WebDAV GET 返回非成功状态",
            )),
        }
    }

    fn ensure_collections(
        &self,
        key: &str,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<()> {
        let segments = validate_key(key)?;
        if segments.len() == 1 {
            return Ok(());
        }
        let method = Method::from_bytes(b"MKCOL").expect("fixed WebDAV method");
        let mut current = self.endpoint.clone();
        for segment in &segments[..segments.len() - 1] {
            cancellation.check()?;
            current
                .path_segments_mut()
                .map_err(|_| {
                    ProviderError::new(ProviderErrorCode::InvalidInput, "WebDAV endpoint 路径无效")
                })?
                .pop_if_empty()
                .push(segment);
            let response = self
                .request(method.clone(), current.clone())
                .send()
                .map_err(|_| {
                    ProviderError::new(ProviderErrorCode::Unavailable, "WebDAV MKCOL 请求失败")
                })?;
            match response.status() {
                StatusCode::CREATED | StatusCode::METHOD_NOT_ALLOWED => {}
                status if status.is_redirection() => {
                    return Err(ProviderError::new(
                        ProviderErrorCode::Protocol,
                        "WebDAV 不允许重定向",
                    ));
                }
                _ => {
                    return Err(ProviderError::new(
                        ProviderErrorCode::Unavailable,
                        "WebDAV 无法创建对象集合",
                    ));
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_trusted_ca_pem(pem: &[u8]) -> ProviderResult<()> {
    parse_trusted_ca_pem(pem).map(|_| ())
}

fn parse_trusted_ca_pem(pem: &[u8]) -> ProviderResult<Certificate> {
    if pem.is_empty() || pem.len() > MAX_CA_BYTES {
        return Err(ProviderError::new(
            ProviderErrorCode::InvalidInput,
            "WebDAV 自定义 CA 必须为 1 字节至 64 KiB",
        ));
    }
    if !pem.starts_with(b"-----BEGIN CERTIFICATE-----")
        || !pem
            .windows(b"-----END CERTIFICATE-----".len())
            .any(|window| window == b"-----END CERTIFICATE-----")
        || pem
            .windows(b"PRIVATE KEY".len())
            .any(|window| window == b"PRIVATE KEY")
    {
        return Err(ProviderError::new(
            ProviderErrorCode::InvalidInput,
            "WebDAV 自定义 CA PEM 无效",
        ));
    }
    Certificate::from_pem(pem).map_err(|_| {
        ProviderError::new(ProviderErrorCode::InvalidInput, "WebDAV 自定义 CA PEM 无效")
    })
}

impl SyncObjectProvider for WebDavProvider {
    fn list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<SyncObjectPage> {
        validate_list_request(prefix, cursor, limit)?;
        cancellation.check()?;
        let method = Method::from_bytes(b"PROPFIND").expect("fixed WebDAV method");
        let response = self
            .request(method, self.prefix_url(prefix)?)
            .header("Depth", "infinity")
            .header("Content-Type", "application/xml; charset=utf-8")
            .body("<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><prop><getcontentlength/><getetag/><resourcetype/></prop></propfind>")
            .send()
            .map_err(|_| {
                ProviderError::new(ProviderErrorCode::Unavailable, "WebDAV PROPFIND 请求失败")
            })?;
        cancellation.check()?;
        if response.status() != StatusCode::MULTI_STATUS {
            return Err(ProviderError::new(
                if response.status().is_redirection() {
                    ProviderErrorCode::Protocol
                } else {
                    ProviderErrorCode::Unavailable
                },
                "WebDAV PROPFIND 返回非 207 状态",
            ));
        }
        let xml = self.read_response(response, MAX_WEBDAV_XML_BYTES, cancellation)?;
        let mut objects = parse_multistatus(&xml, &self.endpoint)?;
        objects.retain(|object| {
            object.key.starts_with(prefix)
                && cursor.is_none_or(|cursor| object.key.as_str() > cursor)
        });
        objects.sort_by(|left, right| left.key.cmp(&right.key));
        objects.dedup_by(|left, right| left.key == right.key);
        if objects.len() > MAX_LIST_ENTRIES {
            return Err(ProviderError::new(
                ProviderErrorCode::LimitExceeded,
                "WebDAV 列表超过 10000 项限制",
            ));
        }
        let next_cursor = (objects.len() > limit).then(|| objects[limit - 1].key.clone());
        objects.truncate(limit);
        Ok(SyncObjectPage {
            objects,
            next_cursor,
        })
    }

    fn get(&self, key: &str, cancellation: &ProviderCancellation) -> ProviderResult<Vec<u8>> {
        validate_key(key)?;
        self.get_internal(key, cancellation)
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<PutObjectOutcome> {
        validate_key(key)?;
        validate_object_bytes(bytes)?;
        cancellation.check()?;
        match self.get_internal(key, cancellation) {
            Ok(existing) if existing == bytes => return Ok(PutObjectOutcome::AlreadyPresent),
            Ok(_) => {
                return Err(ProviderError::new(
                    ProviderErrorCode::Conflict,
                    "同名 WebDAV 对象内容不同，拒绝覆盖",
                ));
            }
            Err(error) if error.code == ProviderErrorCode::NotFound => {}
            Err(error) => return Err(error),
        }
        self.ensure_collections(key, cancellation)?;
        cancellation.check()?;
        let response = self
            .request(Method::PUT, self.object_url(key)?)
            .header(IF_NONE_MATCH, HeaderValue::from_static("*"))
            .header(CONTENT_LENGTH, bytes.len())
            .body(reqwest::blocking::Body::new(CancellableUpload::new(
                bytes.to_vec(),
                cancellation.clone(),
            )))
            .send()
            .map_err(|_| {
                cancellation.check().err().unwrap_or_else(|| {
                    ProviderError::new(ProviderErrorCode::Unavailable, "WebDAV PUT 请求失败")
                })
            })?;
        let outcome = match response.status() {
            StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT => {
                PutObjectOutcome::Created
            }
            StatusCode::PRECONDITION_FAILED => PutObjectOutcome::AlreadyPresent,
            status if status.is_redirection() => {
                return Err(ProviderError::new(
                    ProviderErrorCode::Protocol,
                    "WebDAV 不允许重定向",
                ));
            }
            _ => {
                return Err(ProviderError::new(
                    ProviderErrorCode::Unavailable,
                    "WebDAV PUT 返回非成功状态",
                ));
            }
        };
        // A successful/412 PUT response is the mutation boundary. Complete the
        // read-back even if cancellation arrives now, so callers get the truth.
        let committed = self.get_internal(key, &ProviderCancellation::default())?;
        if committed != bytes {
            return Err(ProviderError::new(
                ProviderErrorCode::Conflict,
                "WebDAV 对象提交后内容不同，远端不可变性校验失败",
            ));
        }
        Ok(outcome)
    }

    fn delete_exact(
        &self,
        key: &str,
        expected: &[u8],
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<DeleteObjectOutcome> {
        validate_key(key)?;
        validate_object_bytes(expected)?;
        cancellation.check()?;
        let head = self
            .request(Method::HEAD, self.object_url(key)?)
            .send()
            .map_err(|_| {
                ProviderError::new(ProviderErrorCode::Unavailable, "WebDAV HEAD 请求失败")
            })?;
        cancellation.check()?;
        if head.status() == StatusCode::NOT_FOUND {
            return Ok(DeleteObjectOutcome::AlreadyAbsent);
        }
        if head.status() != StatusCode::OK {
            return Err(ProviderError::new(
                if head.status().is_redirection() {
                    ProviderErrorCode::Protocol
                } else {
                    ProviderErrorCode::Unavailable
                },
                "WebDAV HEAD 返回非成功状态",
            ));
        }
        let etag = head.headers().get(ETAG).cloned().ok_or_else(|| {
            ProviderError::new(ProviderErrorCode::Protocol, "WebDAV 条件删除要求强 ETag")
        })?;
        let etag_bytes = etag.as_bytes();
        if etag_bytes.starts_with(b"W/")
            || etag_bytes.len() < 2
            || etag_bytes.first() != Some(&b'"')
            || etag_bytes.last() != Some(&b'"')
        {
            return Err(ProviderError::new(
                ProviderErrorCode::Protocol,
                "WebDAV 条件删除拒绝弱 ETag",
            ));
        }
        let response = self
            .request(Method::GET, self.object_url(key)?)
            .header(IF_MATCH, etag.clone())
            .send()
            .map_err(|_| {
                cancellation.check().err().unwrap_or_else(|| {
                    ProviderError::new(ProviderErrorCode::Unavailable, "WebDAV GET 请求失败")
                })
            })?;
        cancellation.check()?;
        let existing = match response.status() {
            StatusCode::OK => self.read_response(response, MAX_OBJECT_BYTES, cancellation)?,
            StatusCode::NOT_FOUND => return Ok(DeleteObjectOutcome::AlreadyAbsent),
            StatusCode::PRECONDITION_FAILED => {
                return Err(ProviderError::new(
                    ProviderErrorCode::Conflict,
                    "WebDAV 条件读取 ETag 已变化",
                ));
            }
            status if status.is_redirection() => {
                return Err(ProviderError::new(
                    ProviderErrorCode::Protocol,
                    "WebDAV 不允许重定向",
                ));
            }
            _ => {
                return Err(ProviderError::new(
                    ProviderErrorCode::Unavailable,
                    "WebDAV 条件读取返回非成功状态",
                ));
            }
        };
        if existing != expected {
            return Err(ProviderError::new(
                ProviderErrorCode::Conflict,
                "WebDAV 条件删除内容不匹配",
            ));
        }
        cancellation.check()?;
        let response = self
            .request(Method::DELETE, self.object_url(key)?)
            .header(IF_MATCH, etag)
            .send()
            .map_err(|_| {
                cancellation.check().err().unwrap_or_else(|| {
                    ProviderError::new(ProviderErrorCode::Unavailable, "WebDAV DELETE 请求失败")
                })
            })?;
        match response.status() {
            StatusCode::OK | StatusCode::NO_CONTENT => {}
            StatusCode::NOT_FOUND => return Ok(DeleteObjectOutcome::AlreadyAbsent),
            StatusCode::PRECONDITION_FAILED => {
                return Err(ProviderError::new(
                    ProviderErrorCode::Conflict,
                    "WebDAV 条件删除 ETag 已变化",
                ));
            }
            status if status.is_redirection() => {
                return Err(ProviderError::new(
                    ProviderErrorCode::Protocol,
                    "WebDAV 不允许重定向",
                ));
            }
            _ => {
                return Err(ProviderError::new(
                    ProviderErrorCode::Unavailable,
                    "WebDAV DELETE 返回非成功状态",
                ));
            }
        }
        match self.get_internal(key, &ProviderCancellation::default()) {
            Err(error) if error.code == ProviderErrorCode::NotFound => {
                Ok(DeleteObjectOutcome::Deleted)
            }
            _ => Err(ProviderError::new(
                ProviderErrorCode::Conflict,
                "WebDAV 同步对象删除后仍然存在",
            )),
        }
    }
}

fn validate_endpoint(value: &str, allow_http_for_test: bool) -> ProviderResult<Url> {
    if value.is_empty() || value.len() > MAX_ENDPOINT_BYTES || value.chars().any(char::is_control) {
        return Err(ProviderError::new(
            ProviderErrorCode::InvalidInput,
            "WebDAV endpoint 超出长度限制",
        ));
    }
    let mut url = Url::parse(value).map_err(|_| {
        ProviderError::new(ProviderErrorCode::InvalidInput, "WebDAV endpoint URL 无效")
    })?;
    if (url.scheme() != "https" && !(allow_http_for_test && url.scheme() == "http"))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ProviderError::new(
            ProviderErrorCode::InvalidInput,
            "WebDAV endpoint 必须是无凭据、query 和 fragment 的 HTTPS URL",
        ));
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

pub(crate) fn validate_list_request(
    prefix: &str,
    cursor: Option<&str>,
    limit: usize,
) -> ProviderResult<()> {
    validate_prefix(prefix)?;
    if let Some(cursor) = cursor {
        validate_key(cursor)?;
    }
    if !(1..=MAX_LIST_LIMIT).contains(&limit) {
        return Err(ProviderError::new(
            ProviderErrorCode::InvalidInput,
            "同步对象列表页大小必须为 1 至 1000",
        ));
    }
    Ok(())
}

fn validate_prefix(prefix: &str) -> ProviderResult<()> {
    if prefix.is_empty() {
        return Ok(());
    }
    let normalized = prefix.strip_suffix('/').unwrap_or(prefix);
    validate_key(normalized).map(|_| ())
}

pub(crate) fn validate_key(key: &str) -> ProviderResult<Vec<&str>> {
    if key.is_empty()
        || key.len() > MAX_KEY_BYTES
        || key.starts_with('/')
        || key.ends_with('/')
        || key.contains('\\')
        || key.chars().any(char::is_control)
    {
        return Err(ProviderError::new(
            ProviderErrorCode::InvalidInput,
            "同步对象 key 格式无效",
        ));
    }
    let segments = key.split('/').collect::<Vec<_>>();
    if segments.len() > MAX_KEY_DEPTH
        || segments.iter().any(|segment| {
            segment.is_empty()
                || *segment == "."
                || *segment == ".."
                || segment.len() > MAX_SEGMENT_BYTES
                || segment.starts_with(STAGE_PREFIX)
                || !segment.bytes().all(|value| {
                    value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b'-')
                })
        })
    {
        return Err(ProviderError::new(
            ProviderErrorCode::InvalidInput,
            "同步对象 key 分段无效或超过深度限制",
        ));
    }
    Ok(segments)
}

struct CancellableUpload {
    bytes: Vec<u8>,
    offset: usize,
    cancellation: ProviderCancellation,
}

impl CancellableUpload {
    fn new(bytes: Vec<u8>, cancellation: ProviderCancellation) -> Self {
        Self {
            bytes,
            offset: 0,
            cancellation,
        }
    }
}

impl Read for CancellableUpload {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.cancellation.cancelled.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "provider upload cancelled",
            ));
        }
        let remaining = &self.bytes[self.offset..];
        let count = remaining.len().min(buffer.len());
        buffer[..count].copy_from_slice(&remaining[..count]);
        self.offset += count;
        Ok(count)
    }
}

pub(crate) fn validate_object_bytes(bytes: &[u8]) -> ProviderResult<()> {
    if bytes.is_empty() || bytes.len() > MAX_OBJECT_BYTES {
        return Err(ProviderError::new(
            ProviderErrorCode::LimitExceeded,
            "同步对象大小必须为 1 字节至 24 MiB",
        ));
    }
    Ok(())
}

fn read_bounded(
    mut reader: impl Read,
    maximum: usize,
    cancellation: &ProviderCancellation,
) -> ProviderResult<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        cancellation.check()?;
        let count = reader
            .read(&mut buffer)
            .map_err(|_| ProviderError::new(ProviderErrorCode::Unavailable, "读取同步对象失败"))?;
        if count == 0 {
            break;
        }
        if output.len().saturating_add(count) > maximum {
            return Err(ProviderError::new(
                ProviderErrorCode::LimitExceeded,
                "同步 provider 响应超过大小限制",
            ));
        }
        output.extend_from_slice(&buffer[..count]);
    }
    Ok(output)
}

fn path_to_key(path: &Path) -> ProviderResult<String> {
    let mut segments = Vec::new();
    for component in path.components() {
        let segment = component.as_os_str().to_str().ok_or_else(|| {
            ProviderError::new(
                ProviderErrorCode::UnsafePath,
                "Local Folder 包含非 UTF-8 对象名",
            )
        })?;
        segments.push(segment);
    }
    Ok(segments.join("/"))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn parse_multistatus(xml: &[u8], endpoint: &Url) -> ProviderResult<Vec<SyncObjectMetadata>> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut depth = 0usize;
    let mut current: Option<WebDavXmlObject> = None;
    let mut field = XmlField::None;
    let mut objects = BTreeMap::new();
    loop {
        match reader
            .read_event_into(&mut buffer)
            .map_err(|_| ProviderError::new(ProviderErrorCode::Protocol, "WebDAV XML 无效"))?
        {
            Event::Start(event) => {
                depth += 1;
                if depth > 32 {
                    return Err(ProviderError::new(
                        ProviderErrorCode::LimitExceeded,
                        "WebDAV XML 嵌套超过限制",
                    ));
                }
                match event.local_name().as_ref() {
                    b"response" => current = Some(WebDavXmlObject::default()),
                    b"href" => field = XmlField::Href,
                    b"getcontentlength" => field = XmlField::Length,
                    b"getetag" => field = XmlField::Etag,
                    b"collection" => {
                        if let Some(current) = &mut current {
                            current.collection = true;
                        }
                    }
                    _ => {}
                }
            }
            Event::Empty(event) => {
                if event.local_name().as_ref() == b"collection" {
                    if let Some(current) = &mut current {
                        current.collection = true;
                    }
                }
            }
            Event::Text(event) => {
                let value = event.decode().map_err(|_| {
                    ProviderError::new(ProviderErrorCode::Protocol, "WebDAV XML 文本编码无效")
                })?;
                if value.len() > MAX_KEY_BYTES * 4 {
                    return Err(ProviderError::new(
                        ProviderErrorCode::LimitExceeded,
                        "WebDAV XML 字段超过限制",
                    ));
                }
                if let Some(current) = &mut current {
                    match field {
                        XmlField::Href => current.href = Some(value.into_owned()),
                        XmlField::Length => {
                            current.size = Some(value.parse::<u64>().map_err(|_| {
                                ProviderError::new(
                                    ProviderErrorCode::Protocol,
                                    "WebDAV 对象长度无效",
                                )
                            })?)
                        }
                        XmlField::Etag => current.etag = Some(value.into_owned()),
                        XmlField::None => {}
                    }
                }
            }
            Event::End(event) => {
                match event.local_name().as_ref() {
                    b"response" => {
                        if let Some(current) = current.take() {
                            if !current.collection {
                                let href = current.href.ok_or_else(|| {
                                    ProviderError::new(
                                        ProviderErrorCode::Protocol,
                                        "WebDAV 文件响应缺少 href",
                                    )
                                })?;
                                let key = href_to_key(endpoint, &href)?;
                                let size = current.size.ok_or_else(|| {
                                    ProviderError::new(
                                        ProviderErrorCode::Protocol,
                                        "WebDAV 文件响应缺少长度",
                                    )
                                })?;
                                if size > MAX_OBJECT_BYTES as u64 {
                                    return Err(ProviderError::new(
                                        ProviderErrorCode::LimitExceeded,
                                        "WebDAV 对象超过 24 MiB 限制",
                                    ));
                                }
                                objects.insert(
                                    key.clone(),
                                    SyncObjectMetadata {
                                        key,
                                        size,
                                        etag: current.etag,
                                    },
                                );
                                if objects.len() > MAX_LIST_ENTRIES {
                                    return Err(ProviderError::new(
                                        ProviderErrorCode::LimitExceeded,
                                        "WebDAV 列表超过 10000 项限制",
                                    ));
                                }
                            }
                        }
                    }
                    b"href" | b"getcontentlength" | b"getetag" => field = XmlField::None,
                    _ => {}
                }
                depth = depth.saturating_sub(1);
            }
            Event::DocType(_) => {
                return Err(ProviderError::new(
                    ProviderErrorCode::Protocol,
                    "WebDAV XML 不允许 DTD",
                ));
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(objects.into_values().collect())
}

#[derive(Default)]
struct WebDavXmlObject {
    href: Option<String>,
    size: Option<u64>,
    etag: Option<String>,
    collection: bool,
}

#[derive(Clone, Copy)]
enum XmlField {
    None,
    Href,
    Length,
    Etag,
}

fn href_to_key(endpoint: &Url, href: &str) -> ProviderResult<String> {
    if href.len() > MAX_ENDPOINT_BYTES + MAX_KEY_BYTES * 3 || href.chars().any(char::is_control) {
        return Err(ProviderError::new(
            ProviderErrorCode::Protocol,
            "WebDAV href 超出限制",
        ));
    }
    let url = endpoint
        .join(href)
        .map_err(|_| ProviderError::new(ProviderErrorCode::Protocol, "WebDAV href URL 无效"))?;
    if url.scheme() != endpoint.scheme()
        || url.host_str() != endpoint.host_str()
        || url.port_or_known_default() != endpoint.port_or_known_default()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().starts_with(endpoint.path())
    {
        return Err(ProviderError::new(
            ProviderErrorCode::Protocol,
            "WebDAV href 逃逸配置的 endpoint",
        ));
    }
    let encoded = &url.path()[endpoint.path().len()..];
    let key = percent_decode_str(encoded)
        .decode_utf8()
        .map_err(|_| ProviderError::new(ProviderErrorCode::Protocol, "WebDAV href 不是 UTF-8"))?
        .into_owned();
    validate_key(&key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader},
        net::{TcpListener, TcpStream},
        thread,
    };

    use super::*;

    fn temp_directory(label: &str) -> PathBuf {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!("vpshell-{label}-{}", hex(&random)));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn keys_endpoints_credentials_and_limits_are_strict() {
        for invalid in [
            "",
            "/absolute",
            "trailing/",
            "a//b",
            "a/../b",
            "a/./b",
            "a\\b",
            "a/空",
            "a/\u{0000}b",
            ".vpshell-stage-deadbeef.tmp",
        ] {
            assert!(validate_key(invalid).is_err(), "accepted {invalid:?}");
        }
        assert!(validate_key("vpshell/v1/vault/segments/device/1-2-hash.oseg").is_ok());
        assert!(validate_key(&vec!["a"; MAX_KEY_DEPTH + 1].join("/")).is_err());
        assert!(validate_object_bytes(&[]).is_err());
        assert!(validate_object_bytes(&vec![0; MAX_OBJECT_BYTES + 1]).is_err());
        for endpoint in [
            "http://example.com/root/",
            "https://user:pass@example.com/root/",
            "https://example.com/root/?x=1",
            "https://example.com/root/#fragment",
        ] {
            assert!(WebDavProvider::connect(endpoint, None, None, 10).is_err());
        }
        assert!(WebDavProvider::connect("https://example.com/root/", None, None, 4).is_err());
        assert!(WebDavCredentials::new("u:ser".into(), "password".into()).is_err());
        assert!(WebDavCredentials::new("user".into(), "password".into()).is_ok());
        assert!(WebDavProvider::connect("https://example.com/root/", None, Some(b""), 10).is_err());
        assert!(
            WebDavProvider::connect(
                "https://example.com/root/",
                None,
                Some(include_bytes!("../fixtures/webdav-test-ca.pem")),
                10,
            )
            .is_ok()
        );
    }

    #[test]
    fn local_provider_is_immutable_paginated_and_cancellable() {
        let root = temp_directory("local-provider");
        let provider = LocalFolderProvider::open(&root).unwrap();
        let cancellation = ProviderCancellation::default();
        assert_eq!(
            provider.put("vpshell/v1/a.oseg", b"alpha", &cancellation),
            Ok(PutObjectOutcome::Created)
        );
        assert_eq!(
            provider.put("vpshell/v1/a.oseg", b"alpha", &cancellation),
            Ok(PutObjectOutcome::AlreadyPresent)
        );
        assert_eq!(
            provider
                .put("vpshell/v1/a.oseg", b"different", &cancellation)
                .unwrap_err()
                .code,
            ProviderErrorCode::Conflict
        );
        provider
            .put("vpshell/v1/b.oseg", b"beta", &cancellation)
            .unwrap();
        fs::write(root.join(".vpshell-stage-crash.tmp"), b"partial").unwrap();
        assert_eq!(
            provider.get("vpshell/v1/a.oseg", &cancellation).unwrap(),
            b"alpha"
        );
        let first = provider
            .list("vpshell/v1/", None, 1, &cancellation)
            .unwrap();
        assert_eq!(first.objects[0].key, "vpshell/v1/a.oseg");
        let second = provider
            .list(
                "vpshell/v1/",
                first.next_cursor.as_deref(),
                1,
                &cancellation,
            )
            .unwrap();
        assert_eq!(second.objects[0].key, "vpshell/v1/b.oseg");
        assert!(second.next_cursor.is_none());
        let all = provider.list("", None, 10, &cancellation).unwrap();
        assert_eq!(all.objects.len(), 2);
        cancellation.cancel();
        assert_eq!(
            provider
                .get("vpshell/v1/a.oseg", &cancellation)
                .unwrap_err()
                .code,
            ProviderErrorCode::Cancelled
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn local_provider_rejects_symlink_roots_and_entries() {
        use std::os::unix::fs::symlink;
        let root = temp_directory("local-symlink");
        let linked_root = root.with_extension("link");
        symlink(&root, &linked_root).unwrap();
        assert_eq!(
            LocalFolderProvider::open(&linked_root).unwrap_err().code,
            ProviderErrorCode::UnsafePath
        );
        let provider = LocalFolderProvider::open(&root).unwrap();
        symlink("/tmp", root.join("objects")).unwrap();
        assert_eq!(
            provider
                .put(
                    "objects/a.oseg",
                    b"secret",
                    &ProviderCancellation::default()
                )
                .unwrap_err()
                .code,
            ProviderErrorCode::UnsafePath
        );
        assert_eq!(
            provider
                .list("", None, 10, &ProviderCancellation::default())
                .unwrap_err()
                .code,
            ProviderErrorCode::UnsafePath
        );
        fs::remove_file(linked_root).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn webdav_xml_is_bounded_and_rejects_escaping_hrefs() {
        let endpoint = Url::parse("https://example.com/dav/root/").unwrap();
        let xml = br#"<?xml version="1.0"?>
          <d:multistatus xmlns:d="DAV:">
            <d:response><d:href>/dav/root/a%20b.oseg</d:href><d:propstat><d:prop>
              <d:getcontentlength>5</d:getcontentlength><d:getetag>&quot;x&quot;</d:getetag>
            </d:prop></d:propstat></d:response>
            <d:response><d:href>/dav/root/folder/</d:href><d:propstat><d:prop>
              <d:resourcetype><d:collection/></d:resourcetype>
            </d:prop></d:propstat></d:response>
          </d:multistatus>"#;
        assert!(parse_multistatus(xml, &endpoint).is_err());
        let valid = br#"<multistatus xmlns="DAV:"><response><href>/dav/root/a-b.oseg</href><propstat><prop><getcontentlength>5</getcontentlength><getetag>x</getetag></prop></propstat></response></multistatus>"#;
        let parsed = parse_multistatus(valid, &endpoint).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].key, "a-b.oseg");
        let escaping = br#"<multistatus xmlns="DAV:"><response><href>https://evil.example/a</href><propstat><prop><getcontentlength>1</getcontentlength></prop></propstat></response></multistatus>"#;
        assert_eq!(
            parse_multistatus(escaping, &endpoint).unwrap_err().code,
            ProviderErrorCode::Protocol
        );
        let dtd = br#"<!DOCTYPE x [<!ENTITY e "x">]><multistatus xmlns="DAV:"></multistatus>"#;
        assert_eq!(
            parse_multistatus(dtd, &endpoint).unwrap_err().code,
            ProviderErrorCode::Protocol
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn webdav_custom_ca_verifies_real_ephemeral_tls_fixture() {
        let Ok(endpoint) = std::env::var("VPSHELL_WEBDAV_CA_TEST_ENDPOINT") else {
            return;
        };
        let ca_path = std::env::var("VPSHELL_WEBDAV_CA_TEST_PEM").expect("fixture CA path");
        let trusted_ca = fs::read(ca_path).expect("read fixture CA");
        let cancellation = ProviderCancellation::default();

        let untrusted = WebDavProvider::connect(&endpoint, None, None, 5).unwrap();
        assert_eq!(
            untrusted.get("probe", &cancellation).unwrap_err().code,
            ProviderErrorCode::Unavailable
        );

        let trusted = WebDavProvider::connect(&endpoint, None, Some(&trusted_ca), 5).unwrap();
        assert!(!trusted.get("probe", &cancellation).unwrap().is_empty());
    }

    #[test]
    fn webdav_put_is_conditional_verified_and_idempotent() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for (index, stream) in listener.incoming().take(5).enumerate() {
                let mut stream = stream.unwrap();
                let request = read_request(&mut stream);
                match index {
                    0 => {
                        assert!(request.starts_with("GET /dav/root/objects/a.oseg "));
                        respond(&mut stream, 404, b"");
                    }
                    1 => {
                        assert!(request.starts_with("MKCOL /dav/root/objects "));
                        respond(&mut stream, 201, b"");
                    }
                    2 => {
                        assert!(request.starts_with("PUT /dav/root/objects/a.oseg "));
                        assert!(request.to_ascii_lowercase().contains("if-none-match: *"));
                        assert!(request.ends_with("payload"));
                        respond(&mut stream, 201, b"");
                    }
                    3 | 4 => {
                        assert!(request.starts_with("GET /dav/root/objects/a.oseg "));
                        respond(&mut stream, 200, b"payload");
                    }
                    _ => unreachable!(),
                }
            }
        });
        let provider =
            WebDavProvider::connect_http_for_test(&format!("http://{address}/dav/root/")).unwrap();
        let cancellation = ProviderCancellation::default();
        assert_eq!(
            provider.put("objects/a.oseg", b"payload", &cancellation),
            Ok(PutObjectOutcome::Created)
        );
        assert_eq!(
            provider.put("objects/a.oseg", b"payload", &cancellation),
            Ok(PutObjectOutcome::AlreadyPresent)
        );
        server.join().unwrap();
    }

    #[test]
    fn webdav_precondition_collision_never_becomes_success() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for (index, stream) in listener.incoming().take(3).enumerate() {
                let mut stream = stream.unwrap();
                let request = read_request(&mut stream);
                match index {
                    0 => respond(&mut stream, 404, b""),
                    1 => {
                        assert!(request.starts_with("PUT /dav/root/a.oseg "));
                        respond_status(&mut stream, "412 Precondition Failed", b"");
                    }
                    2 => respond(&mut stream, 200, b"remote-different"),
                    _ => unreachable!(),
                }
            }
        });
        let provider =
            WebDavProvider::connect_http_for_test(&format!("http://{address}/dav/root/")).unwrap();
        assert_eq!(
            provider
                .put("a.oseg", b"local-content", &ProviderCancellation::default())
                .unwrap_err()
                .code,
            ProviderErrorCode::Conflict
        );
        server.join().unwrap();
    }

    #[test]
    fn webdav_delete_requires_strong_etag_and_verifies_absence() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for (index, stream) in listener.incoming().take(4).enumerate() {
                let mut stream = stream.unwrap();
                let request = read_request(&mut stream);
                match index {
                    0 => {
                        assert!(request.starts_with("HEAD /dav/root/a.oseg "));
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nETag: \"immutable\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .unwrap();
                    }
                    1 => {
                        assert!(request.starts_with("GET /dav/root/a.oseg "));
                        assert!(
                            request
                                .to_ascii_lowercase()
                                .contains("if-match: \"immutable\"")
                        );
                        respond(&mut stream, 200, b"payload");
                    }
                    2 => {
                        assert!(request.starts_with("DELETE /dav/root/a.oseg "));
                        assert!(
                            request
                                .to_ascii_lowercase()
                                .contains("if-match: \"immutable\"")
                        );
                        respond_status(&mut stream, "204 No Content", b"");
                    }
                    3 => {
                        assert!(request.starts_with("GET /dav/root/a.oseg "));
                        respond(&mut stream, 404, b"");
                    }
                    _ => unreachable!(),
                }
            }
        });
        let provider =
            WebDavProvider::connect_http_for_test(&format!("http://{address}/dav/root/")).unwrap();
        assert_eq!(
            provider.delete_exact("a.oseg", b"payload", &ProviderCancellation::default(),),
            Ok(DeleteObjectOutcome::Deleted)
        );
        server.join().unwrap();
    }

    #[test]
    fn upload_reader_observes_cancellation_between_chunks() {
        let cancellation = ProviderCancellation::default();
        let mut upload = CancellableUpload::new(vec![7; 128], cancellation.clone());
        let mut buffer = [0; 32];
        assert_eq!(upload.read(&mut buffer).unwrap(), 32);
        cancellation.cancel();
        assert_eq!(
            upload.read(&mut buffer).unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
    }

    #[test]
    fn webdav_list_parses_structured_multistatus_and_pages() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let request = read_request(&mut stream);
            assert!(request.starts_with("PROPFIND /dav/root/vpshell/v1 "));
            assert!(request.to_ascii_lowercase().contains("depth: infinity"));
            let body = br#"<d:multistatus xmlns:d="DAV:">
              <d:response><d:href>/dav/root/vpshell/v1/a.oseg</d:href><d:propstat><d:prop><d:getcontentlength>1</d:getcontentlength><d:getetag>a</d:getetag></d:prop></d:propstat></d:response>
              <d:response><d:href>/dav/root/vpshell/v1/b.oseg</d:href><d:propstat><d:prop><d:getcontentlength>2</d:getcontentlength><d:getetag>b</d:getetag></d:prop></d:propstat></d:response>
            </d:multistatus>"#;
            respond_status(&mut stream, "207 Multi-Status", body);
        });
        let provider =
            WebDavProvider::connect_http_for_test(&format!("http://{address}/dav/root/")).unwrap();
        let page = provider
            .list("vpshell/v1/", None, 1, &ProviderCancellation::default())
            .unwrap();
        assert_eq!(page.objects[0].key, "vpshell/v1/a.oseg");
        assert_eq!(page.next_cursor.as_deref(), Some("vpshell/v1/a.oseg"));
        server.join().unwrap();
    }

    fn read_request(stream: &mut TcpStream) -> String {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut headers = String::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some(value) = line
                .to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::trim)
            {
                content_length = value.parse().unwrap();
            }
            headers.push_str(&line);
        }
        let mut body = vec![0; content_length];
        reader.read_exact(&mut body).unwrap();
        headers.push_str(&String::from_utf8_lossy(&body));
        headers
    }

    fn respond(stream: &mut TcpStream, status: u16, body: &[u8]) {
        let reason = match status {
            200 => "OK",
            201 => "Created",
            404 => "Not Found",
            _ => "Response",
        };
        respond_status(stream, &format!("{status} {reason}"), body);
    }

    fn respond_status(stream: &mut TcpStream, status: &str, body: &[u8]) {
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
    }
}

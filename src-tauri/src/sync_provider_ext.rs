use std::{collections::BTreeSet, sync::Arc};

use reqwest::Url;
use zeroize::Zeroizing;

use crate::sync_provider::{
    ProviderCancellation, ProviderError, ProviderErrorCode, ProviderResult, PutObjectOutcome,
    SyncObjectMetadata, SyncObjectPage, SyncObjectProvider, validate_key, validate_list_request,
    validate_object_bytes,
};

const MAX_OBJECT_BYTES: u64 = 24 * 1024 * 1024;
const MAX_TRANSPORT_LIST: usize = 10_000;
const MAX_ENDPOINT_BYTES: usize = 2_048;
const MAX_ROOT_BYTES: usize = 1_024;
const MIN_TIMEOUT_SECONDS: u64 = 5;
const MAX_TIMEOUT_SECONDS: u64 = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransportEntryKind {
    Regular,
    Directory,
    Symlink,
    Special,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransportObject {
    pub(crate) key: String,
    pub(crate) size: u64,
    pub(crate) etag: Option<String>,
    pub(crate) kind: TransportEntryKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConditionalCreateResult {
    Created,
    AlreadyExists,
}

pub(crate) trait ObjectTransport: Send + Sync {
    fn list_objects(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Vec<TransportObject>>;

    fn get_object(&self, key: &str, cancellation: &ProviderCancellation)
    -> ProviderResult<Vec<u8>>;

    fn create_object(
        &self,
        key: &str,
        bytes: &[u8],
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<ConditionalCreateResult>;
}

pub(crate) trait SftpObjectTransport: ObjectTransport {}
pub(crate) trait S3CompatibleTransport: ObjectTransport {}
pub(crate) trait GatewayObjectTransport: ObjectTransport {}

struct ValidatedObjectProvider<T> {
    transport: Arc<T>,
    label: &'static str,
}

impl<T: ObjectTransport> ValidatedObjectProvider<T> {
    fn new(transport: T, label: &'static str) -> Self {
        Self {
            transport: Arc::new(transport),
            label,
        }
    }

    fn list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<SyncObjectPage> {
        validate_list_request(prefix, cursor, limit)?;
        cancellation.check()?;
        let mut raw =
            self.transport
                .list_objects(prefix, cursor, limit.saturating_add(1), cancellation)?;
        if raw.len() > MAX_TRANSPORT_LIST {
            return Err(ProviderError::new(
                ProviderErrorCode::LimitExceeded,
                format!("{} list 响应超过 10000 项", self.label),
            ));
        }
        let mut seen = BTreeSet::new();
        let mut objects = Vec::with_capacity(raw.len());
        for object in raw.drain(..) {
            cancellation.check()?;
            match object.kind {
                TransportEntryKind::Directory => continue,
                TransportEntryKind::Symlink | TransportEntryKind::Special => {
                    return Err(ProviderError::new(
                        ProviderErrorCode::UnsafePath,
                        format!("{} 返回符号链接或特殊对象", self.label),
                    ));
                }
                TransportEntryKind::Regular => {}
            }
            validate_key(&object.key)?;
            if object.size == 0 || object.size > MAX_OBJECT_BYTES {
                return Err(ProviderError::new(
                    ProviderErrorCode::LimitExceeded,
                    format!("{} 返回越界对象大小", self.label),
                ));
            }
            if !object.key.starts_with(prefix)
                || cursor.is_some_and(|cursor| object.key.as_str() <= cursor)
                || !seen.insert(object.key.clone())
            {
                return Err(ProviderError::new(
                    ProviderErrorCode::Protocol,
                    format!("{} list 返回越界、乱页或重复 key", self.label),
                ));
            }
            objects.push(SyncObjectMetadata {
                key: object.key,
                size: object.size,
                etag: validate_etag(object.etag)?,
            });
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
        validate_key(key)?;
        cancellation.check()?;
        let bytes = self.transport.get_object(key, cancellation)?;
        validate_object_bytes(&bytes)?;
        cancellation.check()?;
        Ok(bytes)
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
        match self.transport.get_object(key, cancellation) {
            Ok(existing) if existing == bytes => return Ok(PutObjectOutcome::AlreadyPresent),
            Ok(_) => {
                return Err(ProviderError::new(
                    ProviderErrorCode::Conflict,
                    format!("{} 同名对象内容不同", self.label),
                ));
            }
            Err(error) if error.code == ProviderErrorCode::NotFound => {}
            Err(error) => return Err(error),
        }
        cancellation.check()?;
        let outcome = self.transport.create_object(key, bytes, cancellation)?;
        // create_object is the commit boundary. Readback no longer uses the
        // caller cancellation, so a late cancel cannot hide committed work.
        let committed = self
            .transport
            .get_object(key, &ProviderCancellation::default())?;
        if committed != bytes {
            return Err(ProviderError::new(
                ProviderErrorCode::Conflict,
                format!("{} 条件创建后回读不一致", self.label),
            ));
        }
        Ok(match outcome {
            ConditionalCreateResult::Created => PutObjectOutcome::Created,
            ConditionalCreateResult::AlreadyExists => PutObjectOutcome::AlreadyPresent,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SftpProviderConfig {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: String,
    pub(crate) root: String,
    pub(crate) host_key_sha256: String,
    pub(crate) timeout_seconds: u64,
}

impl SftpProviderConfig {
    pub(crate) fn validate(&self) -> ProviderResult<()> {
        validate_host(&self.host)?;
        if self.port == 0
            || self.username.is_empty()
            || self.username.len() > 256
            || self.username.chars().any(char::is_control)
            || !valid_remote_root(&self.root)
            || !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&self.timeout_seconds)
            || !valid_sha256_fingerprint(&self.host_key_sha256)
        {
            return Err(ProviderError::new(
                ProviderErrorCode::InvalidInput,
                "SFTP 同步配置字段无效",
            ));
        }
        Ok(())
    }
}

pub(crate) struct SftpSyncProvider<T> {
    inner: ValidatedObjectProvider<T>,
    _config: SftpProviderConfig,
}

impl<T: SftpObjectTransport> SftpSyncProvider<T> {
    pub(crate) fn connect(config: SftpProviderConfig, transport: T) -> ProviderResult<Self> {
        config.validate()?;
        Ok(Self {
            inner: ValidatedObjectProvider::new(transport, "SFTP"),
            _config: config,
        })
    }
}

impl<T: SftpObjectTransport> SyncObjectProvider for SftpSyncProvider<T> {
    fn list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<SyncObjectPage> {
        self.inner.list(prefix, cursor, limit, cancellation)
    }
    fn get(&self, key: &str, cancellation: &ProviderCancellation) -> ProviderResult<Vec<u8>> {
        self.inner.get(key, cancellation)
    }
    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<PutObjectOutcome> {
        self.inner.put(key, bytes, cancellation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct S3ProviderConfig {
    pub(crate) endpoint: String,
    pub(crate) region: String,
    pub(crate) bucket: String,
    pub(crate) prefix: String,
    pub(crate) path_style: bool,
    pub(crate) timeout_seconds: u64,
}

impl S3ProviderConfig {
    pub(crate) fn validate(&self) -> ProviderResult<()> {
        validate_https_endpoint(&self.endpoint, "S3")?;
        if self.region.is_empty()
            || self.region.len() > 128
            || !self
                .region
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !valid_bucket(&self.bucket)
            || (!self.prefix.is_empty() && validate_key(&self.prefix).is_err())
            || !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&self.timeout_seconds)
        {
            return Err(ProviderError::new(
                ProviderErrorCode::InvalidInput,
                "S3-compatible 同步配置字段无效",
            ));
        }
        Ok(())
    }
}

pub(crate) struct S3SyncProvider<T> {
    inner: ValidatedObjectProvider<T>,
    _config: S3ProviderConfig,
}

impl<T: S3CompatibleTransport> S3SyncProvider<T> {
    pub(crate) fn connect(config: S3ProviderConfig, transport: T) -> ProviderResult<Self> {
        config.validate()?;
        Ok(Self {
            inner: ValidatedObjectProvider::new(transport, "S3-compatible"),
            _config: config,
        })
    }
}

impl<T: S3CompatibleTransport> SyncObjectProvider for S3SyncProvider<T> {
    fn list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<SyncObjectPage> {
        self.inner.list(prefix, cursor, limit, cancellation)
    }
    fn get(&self, key: &str, cancellation: &ProviderCancellation) -> ProviderResult<Vec<u8>> {
        self.inner.get(key, cancellation)
    }
    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<PutObjectOutcome> {
        self.inner.put(key, bytes, cancellation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GatewayProviderConfig {
    pub(crate) endpoint: String,
    pub(crate) vault_id: String,
    pub(crate) device_id: String,
    pub(crate) timeout_seconds: u64,
}

impl GatewayProviderConfig {
    pub(crate) fn validate(&self) -> ProviderResult<()> {
        validate_https_endpoint(&self.endpoint, "Gateway")?;
        if !canonical_uuid(&self.vault_id)
            || !canonical_uuid(&self.device_id)
            || !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&self.timeout_seconds)
        {
            return Err(ProviderError::new(
                ProviderErrorCode::InvalidInput,
                "Gateway 同步配置字段无效",
            ));
        }
        Ok(())
    }
}

pub(crate) struct GatewayLoginSecrets {
    username: String,
    password: Zeroizing<String>,
    totp: Option<Zeroizing<String>>,
}

impl GatewayLoginSecrets {
    pub(crate) fn new(
        username: String,
        password: String,
        totp: Option<String>,
    ) -> ProviderResult<Self> {
        if username.is_empty()
            || username.len() > 256
            || username.chars().any(char::is_control)
            || password.is_empty()
            || password.len() > 1_024
            || totp.as_deref().is_some_and(|value| {
                value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err(ProviderError::new(
                ProviderErrorCode::InvalidInput,
                "Gateway 登录字段无效",
            ));
        }
        Ok(Self {
            username,
            password: Zeroizing::new(password),
            totp: totp.map(Zeroizing::new),
        })
    }
}

pub(crate) trait GatewayAuthenticator: Send + Sync {
    type Session: GatewayObjectTransport;

    fn authenticate(
        &self,
        config: &GatewayProviderConfig,
        username: &str,
        password: &str,
        totp: Option<&str>,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Self::Session>;
}

pub(crate) struct GatewaySyncProvider<T> {
    inner: ValidatedObjectProvider<T>,
    _config: GatewayProviderConfig,
}

impl<T: GatewayObjectTransport> GatewaySyncProvider<T> {
    pub(crate) fn login<A: GatewayAuthenticator<Session = T>>(
        config: GatewayProviderConfig,
        secrets: GatewayLoginSecrets,
        authenticator: &A,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Self> {
        config.validate()?;
        cancellation.check()?;
        let session = authenticator
            .authenticate(
                &config,
                &secrets.username,
                secrets.password.as_str(),
                secrets.totp.as_deref().map(|value| value.as_str()),
                cancellation,
            )
            .map_err(|error| ProviderError::new(error.code, "Gateway 身份验证失败"))?;
        Ok(Self {
            inner: ValidatedObjectProvider::new(session, "Gateway"),
            _config: config,
        })
    }
}

impl<T: GatewayObjectTransport> SyncObjectProvider for GatewaySyncProvider<T> {
    fn list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<SyncObjectPage> {
        self.inner.list(prefix, cursor, limit, cancellation)
    }
    fn get(&self, key: &str, cancellation: &ProviderCancellation) -> ProviderResult<Vec<u8>> {
        self.inner.get(key, cancellation)
    }
    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<PutObjectOutcome> {
        self.inner.put(key, bytes, cancellation)
    }
}

fn validate_etag(value: Option<String>) -> ProviderResult<Option<String>> {
    if value.as_ref().is_some_and(|etag| {
        etag.is_empty() || etag.len() > 256 || etag.chars().any(char::is_control)
    }) {
        return Err(ProviderError::new(
            ProviderErrorCode::Protocol,
            "provider ETag 字段无效",
        ));
    }
    Ok(value)
}

fn validate_host(host: &str) -> ProviderResult<()> {
    if host.is_empty()
        || host.len() > 253
        || host.chars().any(char::is_control)
        || host.contains(['/', '\\', '@', ' ', '\t', '\n'])
    {
        return Err(ProviderError::new(
            ProviderErrorCode::InvalidInput,
            "SFTP host 无效",
        ));
    }
    Ok(())
}

fn valid_remote_root(root: &str) -> bool {
    let Some(relative) = root.strip_prefix('/') else {
        return false;
    };
    !relative.is_empty()
        && root.len() <= MAX_ROOT_BYTES
        && !root.contains('\\')
        && !root.chars().any(char::is_control)
        && relative
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn valid_sha256_fingerprint(value: &str) -> bool {
    value.strip_prefix("SHA256:").is_some_and(|digest| {
        (43..=44).contains(&digest.len())
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    })
}

fn validate_https_endpoint(endpoint: &str, label: &str) -> ProviderResult<()> {
    if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(ProviderError::new(
            ProviderErrorCode::InvalidInput,
            format!("{label} endpoint 长度无效"),
        ));
    }
    let url = Url::parse(endpoint).map_err(|_| {
        ProviderError::new(
            ProviderErrorCode::InvalidInput,
            format!("{label} endpoint URL 无效"),
        )
    })?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ProviderError::new(
            ProviderErrorCode::InvalidInput,
            format!("{label} endpoint 必须是无凭据/query/fragment 的 HTTPS URL"),
        ));
    }
    Ok(())
}

fn valid_bucket(bucket: &str) -> bool {
    (3..=63).contains(&bucket.len())
        && bucket.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && !bucket.starts_with(['.', '-'])
        && !bucket.ends_with(['.', '-'])
        && !bucket.contains("..")
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Mutex};

    use super::*;

    const VAULT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const DEVICE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    #[derive(Clone, Default)]
    struct FakeTransport {
        objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        unsafe_entry: Arc<Mutex<Option<TransportEntryKind>>>,
    }

    impl ObjectTransport for FakeTransport {
        fn list_objects(
            &self,
            prefix: &str,
            cursor: Option<&str>,
            _limit: usize,
            cancellation: &ProviderCancellation,
        ) -> ProviderResult<Vec<TransportObject>> {
            cancellation.check()?;
            if let Some(kind) = *self.unsafe_entry.lock().unwrap() {
                return Ok(vec![TransportObject {
                    key: "objects/link.oseg".into(),
                    size: 1,
                    etag: None,
                    kind,
                }]);
            }
            Ok(self
                .objects
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, _)| {
                    key.starts_with(prefix) && cursor.is_none_or(|cursor| key.as_str() > cursor)
                })
                .map(|(key, bytes)| TransportObject {
                    key: key.clone(),
                    size: bytes.len() as u64,
                    etag: Some("etag".into()),
                    kind: TransportEntryKind::Regular,
                })
                .collect())
        }

        fn get_object(
            &self,
            key: &str,
            cancellation: &ProviderCancellation,
        ) -> ProviderResult<Vec<u8>> {
            cancellation.check()?;
            self.objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| ProviderError::new(ProviderErrorCode::NotFound, "object missing"))
        }

        fn create_object(
            &self,
            key: &str,
            bytes: &[u8],
            cancellation: &ProviderCancellation,
        ) -> ProviderResult<ConditionalCreateResult> {
            cancellation.check()?;
            let mut objects = self.objects.lock().unwrap();
            if objects.contains_key(key) {
                Ok(ConditionalCreateResult::AlreadyExists)
            } else {
                objects.insert(key.to_string(), bytes.to_vec());
                Ok(ConditionalCreateResult::Created)
            }
        }
    }

    impl SftpObjectTransport for FakeTransport {}
    impl S3CompatibleTransport for FakeTransport {}
    impl GatewayObjectTransport for FakeTransport {}

    fn sftp_config() -> SftpProviderConfig {
        SftpProviderConfig {
            host: "sync.example.com".into(),
            port: 22,
            username: "sync".into(),
            root: "/srv/vpshell".into(),
            host_key_sha256: format!("SHA256:{}", "A".repeat(43)),
            timeout_seconds: 20,
        }
    }

    fn s3_config() -> S3ProviderConfig {
        S3ProviderConfig {
            endpoint: "https://s3.example.com/".into(),
            region: "us-test-1".into(),
            bucket: "vpshell-test".into(),
            prefix: "objects".into(),
            path_style: true,
            timeout_seconds: 20,
        }
    }

    fn gateway_config() -> GatewayProviderConfig {
        GatewayProviderConfig {
            endpoint: "https://gateway.example.com/v1/".into(),
            vault_id: VAULT_ID.into(),
            device_id: DEVICE_ID.into(),
            timeout_seconds: 20,
        }
    }

    fn exercise_provider(provider: &impl SyncObjectProvider) {
        let cancellation = ProviderCancellation::default();
        assert_eq!(
            provider.put("objects/a.oseg", b"alpha", &cancellation),
            Ok(PutObjectOutcome::Created)
        );
        assert_eq!(
            provider.put("objects/a.oseg", b"alpha", &cancellation),
            Ok(PutObjectOutcome::AlreadyPresent)
        );
        assert_eq!(
            provider
                .put("objects/a.oseg", b"other", &cancellation)
                .unwrap_err()
                .code,
            ProviderErrorCode::Conflict
        );
        assert_eq!(
            provider.get("objects/a.oseg", &cancellation).unwrap(),
            b"alpha"
        );
        assert_eq!(
            provider
                .list("objects/", None, 10, &cancellation)
                .unwrap()
                .objects
                .len(),
            1
        );
        cancellation.cancel();
        assert_eq!(
            provider
                .get("objects/a.oseg", &cancellation)
                .unwrap_err()
                .code,
            ProviderErrorCode::Cancelled
        );
    }

    #[test]
    fn sftp_provider_requires_pinned_host_and_rejects_links() {
        let transport = FakeTransport::default();
        let provider = SftpSyncProvider::connect(sftp_config(), transport.clone()).unwrap();
        exercise_provider(&provider);
        *transport.unsafe_entry.lock().unwrap() = Some(TransportEntryKind::Symlink);
        assert_eq!(
            provider
                .list("objects/", None, 10, &ProviderCancellation::default())
                .unwrap_err()
                .code,
            ProviderErrorCode::UnsafePath
        );
        let mut invalid = sftp_config();
        invalid.host_key_sha256.clear();
        assert!(SftpSyncProvider::connect(invalid, FakeTransport::default()).is_err());
    }

    #[test]
    fn s3_provider_is_immutable_and_configuration_is_https_bounded() {
        let provider = S3SyncProvider::connect(s3_config(), FakeTransport::default()).unwrap();
        exercise_provider(&provider);
        let mut invalid = s3_config();
        invalid.endpoint = "http://access:secret@example.com/?x=1".into();
        assert!(S3SyncProvider::connect(invalid, FakeTransport::default()).is_err());
        let mut invalid = s3_config();
        invalid.bucket = "UPPER".into();
        assert!(S3SyncProvider::connect(invalid, FakeTransport::default()).is_err());
    }

    struct FakeGatewayAuth;

    impl GatewayAuthenticator for FakeGatewayAuth {
        type Session = FakeTransport;

        fn authenticate(
            &self,
            config: &GatewayProviderConfig,
            username: &str,
            password: &str,
            totp: Option<&str>,
            cancellation: &ProviderCancellation,
        ) -> ProviderResult<Self::Session> {
            cancellation.check()?;
            assert_eq!(config.vault_id, VAULT_ID);
            assert_eq!(username, "user");
            assert_eq!(password, "login-secret");
            assert_eq!(totp, Some("123456"));
            Ok(FakeTransport::default())
        }
    }

    struct FailingGatewayAuth;

    impl GatewayAuthenticator for FailingGatewayAuth {
        type Session = FakeTransport;

        fn authenticate(
            &self,
            _config: &GatewayProviderConfig,
            _username: &str,
            _password: &str,
            _totp: Option<&str>,
            _cancellation: &ProviderCancellation,
        ) -> ProviderResult<Self::Session> {
            Err(ProviderError::new(
                ProviderErrorCode::Unavailable,
                "login-secret 123456",
            ))
        }
    }

    #[test]
    fn gateway_totp_is_only_consumed_during_login() {
        assert!(
            GatewayLoginSecrets::new("user".into(), "password".into(), Some("12ab56".into()))
                .is_err()
        );
        let secrets =
            GatewayLoginSecrets::new("user".into(), "login-secret".into(), Some("123456".into()))
                .unwrap();
        let provider = GatewaySyncProvider::login(
            gateway_config(),
            secrets,
            &FakeGatewayAuth,
            &ProviderCancellation::default(),
        )
        .unwrap();
        exercise_provider(&provider);
        let failure = GatewaySyncProvider::login(
            gateway_config(),
            GatewayLoginSecrets::new("user".into(), "login-secret".into(), Some("123456".into()))
                .unwrap(),
            &FailingGatewayAuth,
            &ProviderCancellation::default(),
        )
        .err()
        .unwrap();
        assert_eq!(failure.message, "Gateway 身份验证失败");
        assert!(!failure.message.contains("login-secret"));
        assert!(!failure.message.contains("123456"));
        let source = include_str!("sync_provider_ext.rs");
        assert!(
            !source.contains("totp: Option<Zeroizing<String>>,")
                || !source.contains("struct GatewaySyncProvider<T> {\n    totp")
        );
    }

    #[test]
    fn transport_list_protocol_and_all_backend_configs_are_strict() {
        assert!(sftp_config().validate().is_ok());
        assert!(s3_config().validate().is_ok());
        assert!(gateway_config().validate().is_ok());
        let transport = FakeTransport::default();
        transport
            .objects
            .lock()
            .unwrap()
            .insert("../escape".into(), b"x".to_vec());
        let provider = S3SyncProvider::connect(s3_config(), transport).unwrap();
        assert!(
            provider
                .list("", None, 10, &ProviderCancellation::default())
                .is_err()
        );
        assert!(
            GatewayProviderConfig {
                endpoint: "https://user:secret@gateway.example.com/".into(),
                ..gateway_config()
            }
            .validate()
            .is_err()
        );
        let mut unsafe_root = sftp_config();
        unsafe_root.root = "/".into();
        assert!(unsafe_root.validate().is_err());
        unsafe_root.root = "/safe/../escape".into();
        assert!(unsafe_root.validate().is_err());
    }
}

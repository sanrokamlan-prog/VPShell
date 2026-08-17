//! Desktop-only pure Rust SSH/SFTP readiness path for Phase D.
//!
//! This module deliberately exposes a bounded probe before the native engine owns
//! long-lived product sessions. Secrets are resolved inside Rust and neither the
//! request nor the result can serialize credential material.

use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};

use russh::{
    Disconnect,
    client::{self, Handler},
    keys::{Algorithm, HashAlg, PrivateKeyWithHashAlg, decode_secret_key, ssh_key::PublicKey},
};
use russh_sftp::client::SftpSession;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

const SCHEMA_VERSION: u16 = 1;
const ENGINE_NAME: &str = "russh";
const MAX_ACTIVE_OPERATIONS: usize = 8;
const MAX_HOST_BYTES: usize = 253;
const MAX_USERNAME_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PRIVATE_KEY_BYTES: u64 = 1024 * 1024;
const MIN_TIMEOUT_SECONDS: u16 = 5;
const MAX_TIMEOUT_SECONDS: u16 = 60;
const HOST_KEY_UNSEEN: u8 = 0;
const HOST_KEY_MATCHED: u8 = 1;
const HOST_KEY_MISMATCHED: u8 = 2;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NativeEngineProbeRequest {
    operation_id: String,
    host: String,
    port: u16,
    username: String,
    host_key_sha256: String,
    timeout_seconds: u16,
    credential_ref: Option<String>,
    identity_file: Option<String>,
    identity_passphrase_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NativeEngineProbeResult {
    schema_version: u16,
    engine: &'static str,
    ssh_ready: bool,
    sftp_ready: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NativeEngineError {
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

impl NativeEngineError {
    fn new(code: &'static str, message: &'static str, retryable: bool) -> Self {
        Self {
            code,
            message,
            retryable,
        }
    }

    fn invalid(message: &'static str) -> Self {
        Self::new("native-engine-invalid-request", message, false)
    }

    fn cancelled() -> Self {
        Self::new("native-engine-cancelled", "原生引擎检查已取消", true)
    }
}

#[derive(Clone)]
pub(crate) struct NativeEngineManager {
    inner: Arc<NativeEngineManagerInner>,
}

struct NativeEngineManagerInner {
    operations: Mutex<HashMap<Uuid, ActiveOperation>>,
    next_generation: AtomicU64,
}

struct ActiveOperation {
    generation: u64,
    cancellation: CancellationToken,
}

struct OperationLease {
    manager: NativeEngineManager,
    operation_id: Uuid,
    generation: u64,
    cancellation: CancellationToken,
}

impl Default for NativeEngineManager {
    fn default() -> Self {
        Self {
            inner: Arc::new(NativeEngineManagerInner {
                operations: Mutex::new(HashMap::new()),
                next_generation: AtomicU64::new(0),
            }),
        }
    }
}

impl NativeEngineManager {
    pub(crate) async fn probe(
        &self,
        request: NativeEngineProbeRequest,
    ) -> Result<NativeEngineProbeResult, NativeEngineError> {
        let operation_id = parse_operation_id(&request.operation_id)?;
        let lease = self.begin(operation_id)?;
        let validated = ValidatedProbe::try_from(request)?;
        let timeout = Duration::from_secs(u64::from(validated.timeout_seconds));
        let cancellation = lease.cancellation.clone();
        let outcome = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(NativeEngineError::cancelled()),
            result = tokio::time::timeout(timeout, probe_once(validated)) => {
                match result {
                    Ok(outcome) => outcome,
                    Err(_) => Err(NativeEngineError::new(
                        "native-engine-timeout",
                        "原生 SSH/SFTP 检查超时",
                        true,
                    )),
                }
            }
        };
        drop(lease);
        outcome
    }

    pub(crate) fn cancel(&self, operation_id: &str) -> Result<(), NativeEngineError> {
        let operation_id = parse_operation_id(operation_id)?;
        let operations = self.lock_operations()?;
        let operation = operations.get(&operation_id).ok_or_else(|| {
            NativeEngineError::new(
                "native-engine-operation-not-found",
                "原生引擎检查不存在或已经结束",
                false,
            )
        })?;
        operation.cancellation.cancel();
        Ok(())
    }

    fn begin(&self, operation_id: Uuid) -> Result<OperationLease, NativeEngineError> {
        let mut operations = self.lock_operations()?;
        if operations.len() >= MAX_ACTIVE_OPERATIONS {
            return Err(NativeEngineError::new(
                "native-engine-capacity",
                "同时进行的原生引擎检查已达到上限",
                true,
            ));
        }
        if operations.contains_key(&operation_id) {
            return Err(NativeEngineError::new(
                "native-engine-operation-conflict",
                "原生引擎操作标识已经在使用",
                false,
            ));
        }
        let previous_generation = self
            .inner
            .next_generation
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map_err(|_| {
                NativeEngineError::new(
                    "native-engine-generation-exhausted",
                    "原生引擎代际已耗尽",
                    false,
                )
            })?;
        let generation = previous_generation + 1;
        let cancellation = CancellationToken::new();
        operations.insert(
            operation_id,
            ActiveOperation {
                generation,
                cancellation: cancellation.clone(),
            },
        );
        Ok(OperationLease {
            manager: self.clone(),
            operation_id,
            generation,
            cancellation,
        })
    }

    fn finish(&self, operation_id: Uuid, generation: u64) {
        if let Ok(mut operations) = self.inner.operations.lock()
            && operations
                .get(&operation_id)
                .is_some_and(|operation| operation.generation == generation)
        {
            operations.remove(&operation_id);
        }
    }

    fn lock_operations(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<Uuid, ActiveOperation>>, NativeEngineError> {
        self.inner.operations.lock().map_err(|_| {
            NativeEngineError::new(
                "native-engine-state-corrupt",
                "原生引擎操作状态已损坏",
                false,
            )
        })
    }
}

impl Drop for OperationLease {
    fn drop(&mut self) {
        self.manager.finish(self.operation_id, self.generation);
    }
}

struct ValidatedProbe {
    host: String,
    port: u16,
    username: String,
    host_key_sha256: String,
    timeout_seconds: u16,
    auth: NativeAuth,
}

enum NativeAuth {
    Password(Zeroizing<String>),
    PrivateKey {
        private_key: Zeroizing<Vec<u8>>,
        passphrase: Option<Zeroizing<String>>,
    },
}

impl TryFrom<NativeEngineProbeRequest> for ValidatedProbe {
    type Error = NativeEngineError;

    fn try_from(request: NativeEngineProbeRequest) -> Result<Self, Self::Error> {
        parse_operation_id(&request.operation_id)?;
        validate_host(&request.host)?;
        validate_username(&request.username)?;
        if request.port == 0 {
            return Err(NativeEngineError::invalid("原生 SSH 端口无效"));
        }
        if !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&request.timeout_seconds) {
            return Err(NativeEngineError::invalid(
                "原生 SSH 超时必须在 5 到 60 秒之间",
            ));
        }
        validate_fingerprint(&request.host_key_sha256)?;
        let auth = resolve_auth(
            request.credential_ref.as_deref(),
            request.identity_file.as_deref(),
            request.identity_passphrase_ref.as_deref(),
        )?;
        Ok(Self {
            host: request.host,
            port: request.port,
            username: request.username,
            host_key_sha256: request.host_key_sha256,
            timeout_seconds: request.timeout_seconds,
            auth,
        })
    }
}

fn parse_operation_id(value: &str) -> Result<Uuid, NativeEngineError> {
    let parsed =
        Uuid::parse_str(value).map_err(|_| NativeEngineError::invalid("原生引擎操作标识无效"))?;
    if value.len() != 36 || parsed.to_string() != value {
        return Err(NativeEngineError::invalid("原生引擎操作标识无效"));
    }
    Ok(parsed)
}

fn validate_host(host: &str) -> Result<(), NativeEngineError> {
    if host.is_empty()
        || host.len() > MAX_HOST_BYTES
        || host.starts_with('-')
        || host.contains('/')
        || host.contains('\\')
        || host
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(NativeEngineError::invalid("原生 SSH 主机地址格式无效"));
    }
    Ok(())
}

fn validate_username(username: &str) -> Result<(), NativeEngineError> {
    if username.is_empty()
        || username.len() > MAX_USERNAME_BYTES
        || username.starts_with('-')
        || username.contains('@')
        || username
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(NativeEngineError::invalid("原生 SSH 用户名格式无效"));
    }
    Ok(())
}

fn validate_fingerprint(value: &str) -> Result<(), NativeEngineError> {
    let encoded = value
        .strip_prefix("SHA256:")
        .ok_or_else(|| NativeEngineError::invalid("原生 SSH 必须固定 SHA256 主机指纹"))?;
    if encoded.len() != 43
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
    {
        return Err(NativeEngineError::invalid("原生 SSH 主机指纹格式无效"));
    }
    Ok(())
}

fn resolve_auth(
    credential_ref: Option<&str>,
    identity_file: Option<&str>,
    identity_passphrase_ref: Option<&str>,
) -> Result<NativeAuth, NativeEngineError> {
    match (credential_ref, identity_file) {
        (Some(_), Some(_)) => Err(NativeEngineError::invalid(
            "原生引擎检查每次只允许一种认证方式",
        )),
        (Some(reference), None) => {
            if identity_passphrase_ref.is_some() {
                return Err(NativeEngineError::invalid("密码认证不能携带私钥口令引用"));
            }
            crate::file_transfer::validate_optional_reference(Some(reference), "ssh-")
                .map_err(|_| NativeEngineError::invalid("原生 SSH 凭据引用无效"))?;
            let password =
                crate::file_transfer::read_secret(reference, "原生 SSH 密码引用不存在或无法读取")
                    .map_err(|_| {
                    NativeEngineError::new(
                        "native-engine-credential-unavailable",
                        "原生 SSH 凭据不可用",
                        false,
                    )
                })?;
            Ok(NativeAuth::Password(password))
        }
        (None, Some(identity_file)) => {
            let private_key = read_private_key(identity_file)?;
            let passphrase = match identity_passphrase_ref {
                Some(reference) => {
                    crate::file_transfer::validate_optional_reference(Some(reference), "key-")
                        .map_err(|_| NativeEngineError::invalid("原生 SSH 私钥口令引用无效"))?;
                    Some(
                        crate::file_transfer::read_secret(
                            reference,
                            "原生 SSH 私钥口令引用不存在或无法读取",
                        )
                        .map_err(|_| {
                            NativeEngineError::new(
                                "native-engine-key-passphrase-unavailable",
                                "原生 SSH 私钥口令不可用",
                                false,
                            )
                        })?,
                    )
                }
                None => None,
            };
            Ok(NativeAuth::PrivateKey {
                private_key,
                passphrase,
            })
        }
        (None, None) => Err(NativeEngineError::invalid(
            "原生引擎检查需要凭据引用或私钥文件",
        )),
    }
}

fn read_private_key(value: &str) -> Result<Zeroizing<Vec<u8>>, NativeEngineError> {
    if value.is_empty() || value.len() > MAX_PATH_BYTES {
        return Err(NativeEngineError::invalid("原生 SSH 私钥路径无效"));
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(NativeEngineError::invalid(
            "原生 SSH 私钥路径必须是绝对路径",
        ));
    }
    reject_symlink_components(path)?;
    let mut file = File::open(path).map_err(|_| {
        NativeEngineError::new(
            "native-engine-key-unavailable",
            "原生 SSH 私钥无法读取",
            false,
        )
    })?;
    reject_symlink_components(path)?;
    let metadata = file.metadata().map_err(|_| {
        NativeEngineError::new(
            "native-engine-key-unavailable",
            "原生 SSH 私钥无法读取",
            false,
        )
    })?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(NativeEngineError::invalid(
            "原生 SSH 私钥文件大小或类型无效",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_PRIVATE_KEY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            NativeEngineError::new(
                "native-engine-key-unavailable",
                "原生 SSH 私钥无法读取",
                false,
            )
        })?;
    if bytes.len() as u64 > MAX_PRIVATE_KEY_BYTES {
        return Err(NativeEngineError::invalid("原生 SSH 私钥文件过大"));
    }
    if std::str::from_utf8(&bytes).is_err() {
        return Err(NativeEngineError::invalid(
            "原生 SSH 私钥必须使用 UTF-8 文本格式",
        ));
    }
    Ok(Zeroizing::new(bytes))
}

fn reject_symlink_components(path: &Path) -> Result<(), NativeEngineError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
            }
            Component::CurDir | Component::ParentDir => {
                return Err(NativeEngineError::invalid(
                    "原生 SSH 私钥路径不能包含 . 或 ..",
                ));
            }
        }
        if current.as_os_str().is_empty() || current.parent().is_none() {
            continue;
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| {
            NativeEngineError::new(
                "native-engine-key-unavailable",
                "原生 SSH 私钥路径无法读取",
                false,
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(NativeEngineError::invalid(
                "原生 SSH 私钥路径不能经过符号链接",
            ));
        }
    }
    Ok(())
}

#[derive(Clone)]
struct PinnedServerKey {
    expected_sha256: String,
    state: Arc<AtomicU8>,
}

impl Handler for PinnedServerKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let matched =
            server_public_key.fingerprint(HashAlg::Sha256).to_string() == self.expected_sha256;
        self.state.store(
            if matched {
                HOST_KEY_MATCHED
            } else {
                HOST_KEY_MISMATCHED
            },
            Ordering::SeqCst,
        );
        Ok(matched)
    }
}

async fn probe_once(
    mut request: ValidatedProbe,
) -> Result<NativeEngineProbeResult, NativeEngineError> {
    let host_key_state = Arc::new(AtomicU8::new(HOST_KEY_UNSEEN));
    let handler = PinnedServerKey {
        expected_sha256: request.host_key_sha256,
        state: Arc::clone(&host_key_state),
    };
    let timeout = Duration::from_secs(u64::from(request.timeout_seconds));
    let config = native_client_config(timeout);
    let mut session = client::connect(
        Arc::new(config),
        (request.host.as_str(), request.port),
        handler,
    )
    .await
    .map_err(|_| {
        if host_key_state.load(Ordering::SeqCst) == HOST_KEY_MISMATCHED {
            NativeEngineError::new(
                "native-engine-host-key-mismatch",
                "原生 SSH 主机指纹不匹配，已在认证前拒绝连接",
                false,
            )
        } else {
            NativeEngineError::new(
                "native-engine-connect-failed",
                "原生 SSH 连接或握手失败",
                true,
            )
        }
    })?;
    if host_key_state.load(Ordering::SeqCst) != HOST_KEY_MATCHED {
        return Err(NativeEngineError::new(
            "native-engine-host-key-unverified",
            "原生 SSH 未完成主机指纹验证",
            false,
        ));
    }

    let authenticated = match &mut request.auth {
        NativeAuth::Password(password) => session
            .authenticate_password(request.username, password.as_str())
            .await
            .map_err(|_| {
                NativeEngineError::new("native-engine-auth-failed", "原生 SSH 身份验证失败", false)
            })?
            .success(),
        NativeAuth::PrivateKey {
            private_key,
            passphrase,
        } => {
            let encoded = std::str::from_utf8(private_key.as_slice())
                .map_err(|_| NativeEngineError::invalid("原生 SSH 私钥必须使用 UTF-8 文本格式"))?;
            let private_key =
                decode_secret_key(encoded, passphrase.as_ref().map(|value| value.as_str()))
                    .map_err(|_| {
                        NativeEngineError::new(
                            "native-engine-key-invalid",
                            "原生 SSH 私钥或口令无效",
                            false,
                        )
                    })?;
            let hash = if private_key.algorithm().is_rsa() {
                Some(
                    session
                        .best_supported_rsa_hash()
                        .await
                        .map_err(|_| {
                            NativeEngineError::new(
                                "native-engine-auth-negotiation-failed",
                                "原生 SSH 认证算法协商失败",
                                false,
                            )
                        })?
                        .flatten()
                        .ok_or_else(|| {
                            NativeEngineError::new(
                                "native-engine-rsa-sha2-unavailable",
                                "服务器未协商 RSA SHA-2，请使用系统 OpenSSH 兼容引擎",
                                false,
                            )
                        })?,
                )
            } else {
                None
            };
            session
                .authenticate_publickey(
                    request.username,
                    PrivateKeyWithHashAlg::new(Arc::new(private_key), hash),
                )
                .await
                .map_err(|_| {
                    NativeEngineError::new(
                        "native-engine-auth-failed",
                        "原生 SSH 身份验证失败",
                        false,
                    )
                })?
                .success()
        }
    };
    if !authenticated {
        return Err(NativeEngineError::new(
            "native-engine-auth-rejected",
            "原生 SSH 身份验证被服务器拒绝",
            false,
        ));
    }

    let channel = session.channel_open_session().await.map_err(|_| {
        NativeEngineError::new(
            "native-engine-sftp-channel-failed",
            "原生 SSH 无法打开 SFTP 通道",
            true,
        )
    })?;
    channel.request_subsystem(true, "sftp").await.map_err(|_| {
        NativeEngineError::new(
            "native-engine-sftp-subsystem-failed",
            "服务器未提供 SFTP 子系统",
            false,
        )
    })?;
    let sftp = SftpSession::new(channel.into_stream()).await.map_err(|_| {
        NativeEngineError::new(
            "native-engine-sftp-init-failed",
            "原生 SFTP 协议初始化失败",
            true,
        )
    })?;
    sftp.set_timeout(u64::from(request.timeout_seconds));
    sftp.canonicalize(".").await.map_err(|_| {
        NativeEngineError::new(
            "native-engine-sftp-probe-failed",
            "原生 SFTP 无法读取远端工作目录",
            true,
        )
    })?;
    sftp.close().await.map_err(|_| {
        NativeEngineError::new(
            "native-engine-sftp-close-failed",
            "原生 SFTP 检查已完成但通道关闭失败",
            true,
        )
    })?;
    session
        .disconnect(
            Disconnect::ByApplication,
            "native engine probe complete",
            "",
        )
        .await
        .map_err(|_| {
            NativeEngineError::new(
                "native-engine-disconnect-failed",
                "原生 SSH 检查已完成但连接关闭失败",
                true,
            )
        })?;

    Ok(NativeEngineProbeResult {
        schema_version: SCHEMA_VERSION,
        engine: ENGINE_NAME,
        ssh_ready: true,
        sftp_ready: true,
    })
}

fn native_client_config(timeout: Duration) -> client::Config {
    let mut config = client::Config {
        inactivity_timeout: Some(timeout),
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 2,
        window_size: 2 * 1024 * 1024,
        maximum_packet_size: 32 * 1024,
        channel_buffer_size: 64,
        nodelay: true,
        ..Default::default()
    };
    config
        .preferred
        .key
        .to_mut()
        .retain(|algorithm| !matches!(algorithm, Algorithm::Rsa { hash: None }));
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> NativeEngineProbeRequest {
        NativeEngineProbeRequest {
            operation_id: "018f1f55-26f8-7a9f-9cd8-4d7558482211".to_string(),
            host: "host.example".to_string(),
            port: 22,
            username: "operator".to_string(),
            host_key_sha256: format!("SHA256:{}", "A".repeat(43)),
            timeout_seconds: 15,
            credential_ref: Some("ssh-018f1f55-26f8-7a9f-9cd8-4d7558482212".to_string()),
            identity_file: None,
            identity_passphrase_ref: None,
        }
    }

    #[test]
    fn request_fields_and_authentication_are_bounded() {
        assert!(validate_host("host.example").is_ok());
        assert!(validate_host("../host").is_err());
        assert!(validate_username("operator").is_ok());
        assert!(validate_username("operator@example").is_err());
        assert!(validate_fingerprint(&format!("SHA256:{}", "A".repeat(43))).is_ok());
        assert!(validate_fingerprint("ssh-ed25519 AAAA").is_err());

        let mut invalid = request();
        invalid.timeout_seconds = 4;
        let error = match ValidatedProbe::try_from(invalid) {
            Ok(_) => panic!("invalid timeout accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, "native-engine-invalid-request");

        let mut conflicting_auth = request();
        conflicting_auth.identity_file = Some("/tmp/private-key".to_string());
        let error = match ValidatedProbe::try_from(conflicting_auth) {
            Ok(_) => panic!("multiple authentication sources accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, "native-engine-invalid-request");

        let mut missing_auth = request();
        missing_auth.credential_ref = None;
        let error = match ValidatedProbe::try_from(missing_auth) {
            Ok(_) => panic!("missing authentication source accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, "native-engine-invalid-request");
        assert!(read_private_key("relative-key").is_err());

        let config = native_client_config(Duration::from_secs(15));
        assert!(
            !config
                .preferred
                .key
                .iter()
                .any(|algorithm| matches!(algorithm, Algorithm::Rsa { hash: None }))
        );
    }

    #[test]
    fn manager_enforces_capacity_cancellation_and_generation_cleanup() {
        let manager = NativeEngineManager::default();
        let mut leases = Vec::new();
        for index in 0..MAX_ACTIVE_OPERATIONS {
            let operation_id = Uuid::from_u128(index as u128 + 1);
            leases.push(manager.begin(operation_id).unwrap());
        }
        let error = match manager.begin(Uuid::from_u128(99)) {
            Ok(_) => panic!("operation capacity exceeded"),
            Err(error) => error,
        };
        assert_eq!(error.code, "native-engine-capacity");
        let cancelled_id = leases[0].operation_id;
        manager.cancel(&cancelled_id.to_string()).unwrap();
        assert!(leases[0].cancellation.is_cancelled());
        drop(leases);
        assert!(manager.lock_operations().unwrap().is_empty());

        let reused_id = Uuid::from_u128(101);
        let old = manager.begin(reused_id).unwrap();
        let old_generation = old.generation;
        drop(old);
        let replacement = manager.begin(reused_id).unwrap();
        manager.finish(reused_id, old_generation);
        assert!(manager.lock_operations().unwrap().contains_key(&reused_id));
        drop(replacement);
        assert!(manager.lock_operations().unwrap().is_empty());
    }

    #[test]
    fn secret_bearing_request_is_deserialize_only_and_module_has_no_logging() {
        let source = include_str!("native_engine.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("derive(Debug, Deserialize)"));
        assert!(!production.contains("derive(Serialize, Deserialize)"));
        for forbidden in ["println!", "eprintln!", "dbg!", "tracing::", "log::"] {
            assert!(!production.contains(forbidden));
        }
        assert!(production.contains("check_server_key"));
        assert!(production.contains("HOST_KEY_MISMATCHED"));
        assert!(production.contains("SftpSession::new"));
        assert!(!production.contains("Command::new(\"ssh\")"));
    }

    #[tokio::test]
    async fn real_openssh_and_sftp_probe_when_configured() {
        let Ok(host) = std::env::var("VPSHELL_NATIVE_TEST_HOST") else {
            return;
        };
        let port = std::env::var("VPSHELL_NATIVE_TEST_PORT")
            .expect("test port")
            .parse()
            .expect("numeric test port");
        let username = std::env::var("VPSHELL_NATIVE_TEST_USER").expect("test user");
        let fingerprint =
            std::env::var("VPSHELL_NATIVE_TEST_HOST_KEY_SHA256").expect("test host key");
        let identity_file =
            std::env::var("VPSHELL_NATIVE_TEST_IDENTITY_FILE").expect("test identity file");
        let manager = NativeEngineManager::default();
        let mismatch = manager
            .probe(NativeEngineProbeRequest {
                operation_id: Uuid::new_v4().to_string(),
                host: host.clone(),
                port,
                username: username.clone(),
                host_key_sha256: format!("SHA256:{}", "A".repeat(43)),
                timeout_seconds: 15,
                credential_ref: None,
                identity_file: Some(identity_file.clone()),
                identity_passphrase_ref: None,
            })
            .await
            .expect_err("mismatched host key must fail before authentication");
        assert_eq!(mismatch.code, "native-engine-host-key-mismatch");
        let result = manager
            .probe(NativeEngineProbeRequest {
                operation_id: Uuid::new_v4().to_string(),
                host,
                port,
                username,
                host_key_sha256: fingerprint,
                timeout_seconds: 15,
                credential_ref: None,
                identity_file: Some(identity_file),
                identity_passphrase_ref: None,
            })
            .await
            .expect("real OpenSSH/SFTP probe");
        assert!(result.ssh_ready);
        assert!(result.sftp_ready);
        assert!(manager.lock_operations().unwrap().is_empty());
    }
}

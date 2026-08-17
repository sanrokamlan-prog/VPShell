//! Shared Rust policy and lifecycle model for the Android Preview.
//!
//! This module deliberately contains no Android UI, process spawning, or Tauri
//! commands.  It is the platform-neutral contract that an Android shell can
//! consume once the Tauri Android project and native transport are available.

use std::collections::BTreeSet;

use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const ANDROID_PREVIEW_SCHEMA_VERSION: u16 = 1;
pub const ANDROID_PREVIEW_MAX_SESSIONS: usize = 8;
const MAX_HOST_BYTES: usize = 253;
const MAX_USERNAME_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AndroidPreviewCapability {
    HostConnection,
    Terminal,
    Sftp,
    CredentialVault,
    Sync,
    Broadcast,
    ExternalEditor,
    PersistentMonitoring,
    BackgroundLongConnection,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidPreviewCapabilityStatus {
    pub capability: AndroidPreviewCapability,
    pub enabled: bool,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AndroidPreviewEngine {
    NativeRustSshSftp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AndroidLifecycle {
    Foreground,
    Background,
    Locked,
    Disconnected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidPreviewManifest {
    pub schema_version: u16,
    pub engine: AndroidPreviewEngine,
    pub capabilities: Vec<AndroidPreviewCapabilityStatus>,
    pub max_sessions: u8,
    pub background_long_connections: bool,
}

impl Default for AndroidPreviewManifest {
    fn default() -> Self {
        let enabled = [
            AndroidPreviewCapability::HostConnection,
            AndroidPreviewCapability::Terminal,
            AndroidPreviewCapability::Sftp,
            AndroidPreviewCapability::CredentialVault,
        ];
        let all = [
            AndroidPreviewCapability::HostConnection,
            AndroidPreviewCapability::Terminal,
            AndroidPreviewCapability::Sftp,
            AndroidPreviewCapability::CredentialVault,
            AndroidPreviewCapability::Sync,
            AndroidPreviewCapability::Broadcast,
            AndroidPreviewCapability::ExternalEditor,
            AndroidPreviewCapability::PersistentMonitoring,
            AndroidPreviewCapability::BackgroundLongConnection,
        ];
        Self {
            schema_version: ANDROID_PREVIEW_SCHEMA_VERSION,
            engine: AndroidPreviewEngine::NativeRustSshSftp,
            capabilities: all
                .into_iter()
                .map(|capability| AndroidPreviewCapabilityStatus {
                    enabled: enabled.contains(&capability),
                    reason: match capability {
                        _ if enabled.contains(&capability) => "首版预览支持".to_string(),
                        AndroidPreviewCapability::Sync => {
                            "仅展示 Rust 协调器状态，自动同步仍禁用".to_string()
                        }
                        _ => "Android Preview 首版明确不支持，需单独验收".to_string(),
                    },
                    capability,
                })
                .collect(),
            max_sessions: ANDROID_PREVIEW_MAX_SESSIONS as u8,
            background_long_connections: false,
        }
    }
}

impl AndroidPreviewManifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != ANDROID_PREVIEW_SCHEMA_VERSION {
            return Err("Android Preview schema 版本不受支持".to_string());
        }
        if self.engine != AndroidPreviewEngine::NativeRustSshSftp {
            return Err("Android Preview 必须使用 Rust 原生 SSH/SFTP 引擎".to_string());
        }
        if self.max_sessions == 0 || self.max_sessions as usize > ANDROID_PREVIEW_MAX_SESSIONS {
            return Err("Android Preview 会话数量超出范围".to_string());
        }
        if self.background_long_connections {
            return Err("Android Preview 首版禁止后台长连接".to_string());
        }
        let expected: BTreeSet<_> = [
            AndroidPreviewCapability::HostConnection,
            AndroidPreviewCapability::Terminal,
            AndroidPreviewCapability::Sftp,
            AndroidPreviewCapability::CredentialVault,
        ]
        .into_iter()
        .collect();
        let mut seen = BTreeSet::new();
        for status in &self.capabilities {
            if !seen.insert(status.capability) {
                return Err("Android Preview capability 重复".to_string());
            }
            let should_enable = expected.contains(&status.capability);
            if status.enabled != should_enable || status.reason.trim().is_empty() {
                return Err("Android Preview capability 状态无效".to_string());
            }
        }
        if seen.len() != 9 {
            return Err("Android Preview capability 清单不完整".to_string());
        }
        Ok(())
    }

    pub fn allows(&self, capability: AndroidPreviewCapability) -> bool {
        self.capabilities
            .iter()
            .any(|status| status.capability == capability && status.enabled)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AndroidAuthKind {
    PasswordReference,
    PrivateKeyReference,
}

#[derive(Clone, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidHostRequest {
    pub session_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub host_key_sha256: String,
    pub timeout_seconds: u16,
    pub auth_kind: AndroidAuthKind,
    pub credential_ref: String,
    pub passphrase_ref: Option<String>,
}

impl AndroidHostRequest {
    pub fn validate(&self) -> Result<Uuid, String> {
        let session_id = Uuid::parse_str(&self.session_id)
            .map_err(|_| "Android 会话 ID 格式无效".to_string())?;
        if self.host.is_empty()
            || self.host.len() > MAX_HOST_BYTES
            || self.host.starts_with('-')
            || self
                .host
                .contains(|ch: char| ch.is_whitespace() || ch.is_control())
            || self.host.contains('/')
            || self.host.contains('\\')
            || self.host == "."
            || self.host == ".."
        {
            return Err("Android 主机地址格式无效".to_string());
        }
        if !(1..=65535).contains(&self.port) {
            return Err("Android SSH 端口超出范围".to_string());
        }
        if !(5..=60).contains(&self.timeout_seconds) {
            return Err("Android SSH 超时必须在 5 到 60 秒之间".to_string());
        }
        let fingerprint = self
            .host_key_sha256
            .strip_prefix("SHA256:")
            .ok_or_else(|| "Android SSH host-key 必须使用 SHA256 指纹".to_string())?;
        if fingerprint.len() != 43
            || base64::prelude::BASE64_STANDARD_NO_PAD
                .decode(fingerprint)
                .map_or(true, |bytes| bytes.len() != 32)
        {
            return Err("Android SSH host-key SHA256 指纹格式无效".to_string());
        }
        if self.username.is_empty()
            || self.username.len() > MAX_USERNAME_BYTES
            || self.username.starts_with('-')
            || self.username.contains('@')
            || self
                .username
                .contains(|ch: char| ch.is_whitespace() || ch.is_control())
        {
            return Err("Android SSH 用户名格式无效".to_string());
        }
        let expected_prefix = match self.auth_kind {
            AndroidAuthKind::PasswordReference => "ssh-",
            AndroidAuthKind::PrivateKeyReference => "key-",
        };
        let Some(suffix) = self.credential_ref.strip_prefix(expected_prefix) else {
            return Err("Android 凭据引用格式无效".to_string());
        };
        Uuid::parse_str(suffix).map_err(|_| "Android 凭据引用格式无效".to_string())?;
        if let Some(passphrase_ref) = &self.passphrase_ref {
            let suffix = passphrase_ref
                .strip_prefix("key-")
                .ok_or_else(|| "Android 私钥口令引用格式无效".to_string())?;
            Uuid::parse_str(suffix).map_err(|_| "Android 私钥口令引用格式无效".to_string())?;
            if self.auth_kind != AndroidAuthKind::PrivateKeyReference {
                return Err("密码认证不能携带私钥口令引用".to_string());
            }
        }
        Ok(session_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidPreviewOperation {
    Connect,
    Terminal,
    Sftp,
    Sync,
    Broadcast,
    ExternalEditor,
    PersistentMonitoring,
    BackgroundLongConnection,
}

impl AndroidPreviewOperation {
    fn capability(self) -> AndroidPreviewCapability {
        match self {
            Self::Connect => AndroidPreviewCapability::HostConnection,
            Self::Terminal => AndroidPreviewCapability::Terminal,
            Self::Sftp => AndroidPreviewCapability::Sftp,
            Self::Sync => AndroidPreviewCapability::Sync,
            Self::Broadcast => AndroidPreviewCapability::Broadcast,
            Self::ExternalEditor => AndroidPreviewCapability::ExternalEditor,
            Self::PersistentMonitoring => AndroidPreviewCapability::PersistentMonitoring,
            Self::BackgroundLongConnection => AndroidPreviewCapability::BackgroundLongConnection,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidPreviewRuntime {
    manifest: AndroidPreviewManifest,
    lifecycle: AndroidLifecycle,
    generation: u64,
    sessions: BTreeSet<Uuid>,
}

impl Default for AndroidPreviewRuntime {
    fn default() -> Self {
        Self {
            manifest: AndroidPreviewManifest::default(),
            lifecycle: AndroidLifecycle::Foreground,
            generation: 0,
            sessions: BTreeSet::new(),
        }
    }
}

impl AndroidPreviewRuntime {
    pub fn new(manifest: AndroidPreviewManifest) -> Result<Self, String> {
        manifest.validate()?;
        Ok(Self {
            manifest,
            ..Self::default()
        })
    }

    pub fn lifecycle(&self) -> AndroidLifecycle {
        self.lifecycle
    }

    pub fn manifest(&self) -> &AndroidPreviewManifest {
        &self.manifest
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn has_session(&self, session_id: Uuid) -> bool {
        self.sessions.contains(&session_id)
    }

    pub fn set_lifecycle(&mut self, lifecycle: AndroidLifecycle) {
        if self.lifecycle != lifecycle {
            self.lifecycle = lifecycle;
            self.generation = self.generation.saturating_add(1);
            if lifecycle != AndroidLifecycle::Foreground {
                self.sessions.clear();
            }
        }
    }

    pub fn authorize(&self, operation: AndroidPreviewOperation) -> Result<(), String> {
        if !self.manifest.allows(operation.capability()) {
            return Err(format!("Android Preview 不支持 {:?} 操作", operation));
        }
        if self.lifecycle != AndroidLifecycle::Foreground {
            return Err("Android Preview 需要在前台且已解锁时操作".to_string());
        }
        Ok(())
    }

    pub fn open_session(&mut self, request: &AndroidHostRequest) -> Result<Uuid, String> {
        self.authorize(AndroidPreviewOperation::Connect)?;
        let session_id = request.validate()?;
        if self.sessions.len() >= self.manifest.max_sessions as usize {
            return Err("Android Preview 会话数量已达上限".to_string());
        }
        if !self.sessions.insert(session_id) {
            return Err("Android 会话已经存在".to_string());
        }
        Ok(session_id)
    }

    pub fn close_session(&mut self, session_id: Uuid) -> bool {
        self.sessions.remove(&session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(prefix: &str) -> AndroidHostRequest {
        AndroidHostRequest {
            session_id: Uuid::new_v4().to_string(),
            host: "host.example".to_string(),
            port: 22,
            username: "operator".to_string(),
            host_key_sha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            timeout_seconds: 15,
            auth_kind: if prefix == "key-" {
                AndroidAuthKind::PrivateKeyReference
            } else {
                AndroidAuthKind::PasswordReference
            },
            credential_ref: format!("{prefix}{}", Uuid::new_v4()),
            passphrase_ref: None,
        }
    }

    #[test]
    fn manifest_enables_initial_scope_and_rejects_background_connections() {
        let manifest = AndroidPreviewManifest::default();
        manifest.validate().unwrap();
        assert!(manifest.allows(AndroidPreviewCapability::Terminal));
        assert!(!manifest.allows(AndroidPreviewCapability::Sync));
        assert!(manifest.capabilities.iter().any(|status| {
            status.capability == AndroidPreviewCapability::Sync
                && !status.enabled
                && status.reason.contains("仅展示")
        }));
        assert!(!manifest.allows(AndroidPreviewCapability::Broadcast));
        assert!(!manifest.background_long_connections);

        let mut invalid = manifest;
        invalid.background_long_connections = true;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn host_request_is_structured_and_secret_free() {
        let password = request("ssh-");
        assert!(password.validate().is_ok());
        let key = request("key-");
        assert!(key.validate().is_ok());

        let mut bad = password.clone();
        bad.host = "../tmp".to_string();
        assert!(bad.validate().is_err());
        bad = password.clone();
        bad.credential_ref = "ssh-not-a-uuid".to_string();
        assert!(bad.validate().is_err());
        bad = password;
        bad.credential_ref = format!("key-{}", Uuid::new_v4());
        assert!(bad.validate().is_err());

        let mut bad_pin = request("ssh-");
        bad_pin.host_key_sha256 = "SHA256:invalid".to_string();
        assert!(bad_pin.validate().is_err());
        let mut password_with_key_passphrase = request("ssh-");
        password_with_key_passphrase.passphrase_ref = Some(format!("key-{}", Uuid::new_v4()));
        assert!(password_with_key_passphrase.validate().is_err());
        let mut key_with_passphrase = request("key-");
        key_with_passphrase.passphrase_ref = Some(format!("key-{}", Uuid::new_v4()));
        assert!(key_with_passphrase.validate().is_ok());
    }

    #[test]
    fn lifecycle_requires_foreground_and_clears_sessions_when_locked() {
        let mut runtime = AndroidPreviewRuntime::default();
        let host_request = request("ssh-");
        runtime.open_session(&host_request).unwrap();
        assert_eq!(runtime.session_count(), 1);
        runtime.set_lifecycle(AndroidLifecycle::Background);
        assert_eq!(runtime.session_count(), 0);
        assert!(
            runtime
                .authorize(AndroidPreviewOperation::Terminal)
                .is_err()
        );
        assert!(runtime.open_session(&request("ssh-")).is_err());
        runtime.set_lifecycle(AndroidLifecycle::Foreground);
        assert!(runtime.authorize(AndroidPreviewOperation::Sftp).is_ok());
        runtime.set_lifecycle(AndroidLifecycle::Locked);
        assert_eq!(runtime.session_count(), 0);
        assert!(runtime.authorize(AndroidPreviewOperation::Sync).is_err());
    }

    #[test]
    fn unsupported_operations_are_explicit_and_engine_is_native() {
        let runtime = AndroidPreviewRuntime::default();
        for operation in [
            AndroidPreviewOperation::Broadcast,
            AndroidPreviewOperation::ExternalEditor,
            AndroidPreviewOperation::PersistentMonitoring,
            AndroidPreviewOperation::BackgroundLongConnection,
        ] {
            assert!(runtime.authorize(operation).is_err());
        }
        assert_eq!(
            AndroidPreviewManifest::default().engine,
            AndroidPreviewEngine::NativeRustSshSftp
        );
    }
}

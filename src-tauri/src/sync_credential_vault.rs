use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{CREDENTIAL_SERVICE, sync_crypto::CredentialVaultKey, sync_recovery::DeviceRegistry};

const FORMAT_VERSION: u32 = 1;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const MAX_POLICY_BYTES: usize = 16 * 1024;
const MAX_DEVICES: usize = 32;
const MAX_PASSWORD_BYTES: usize = 1_024;
const MAX_PASSPHRASE_BYTES: usize = 1_024;
const MAX_TOKEN_BYTES: usize = 4 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 1024 * 1024;
const MAX_PLAINTEXT_BYTES: usize = MAX_PRIVATE_KEY_BYTES + 128 * 1024;
const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
const MAX_ROTATION_ITEMS: usize = 10_000;
const MAX_ROTATION_PLAINTEXT_BYTES: usize = 256 * 1024 * 1024;
const ALGORITHM: &str = "xchacha20poly1305";
const KEY_DOMAIN: &str = "credentials";
const LOCAL_REFERENCE_ATTEMPTS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialVaultErrorCode {
    Disabled,
    Unauthorized,
    Conflict,
    InvalidInput,
    LimitExceeded,
    Authentication,
    Storage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CredentialVaultError {
    pub(crate) code: CredentialVaultErrorCode,
    pub(crate) message: String,
}

impl CredentialVaultError {
    fn new(code: CredentialVaultErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

type VaultResult<T> = Result<T, CredentialVaultError>;

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialVaultPolicy {
    format_version: u32,
    vault_id: String,
    revision: u64,
    enabled: bool,
    authorized_devices: BTreeSet<String>,
    revoked_devices: BTreeSet<String>,
}

impl CredentialVaultPolicy {
    pub(crate) fn disabled(vault_id: &str) -> VaultResult<Self> {
        validate_uuid(vault_id, "vault")?;
        Ok(Self {
            format_version: FORMAT_VERSION,
            vault_id: vault_id.to_string(),
            revision: 1,
            enabled: false,
            authorized_devices: BTreeSet::new(),
            revoked_devices: BTreeSet::new(),
        })
    }

    pub(crate) fn encode(&self) -> VaultResult<Vec<u8>> {
        validate_policy(self)?;
        let encoded = serde_json::to_vec(self).map_err(|_| {
            CredentialVaultError::new(
                CredentialVaultErrorCode::InvalidInput,
                "无法序列化凭据 vault 策略",
            )
        })?;
        if encoded.len() > MAX_POLICY_BYTES {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::LimitExceeded,
                "凭据 vault 策略超过 16 KiB",
            ));
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> VaultResult<Self> {
        if encoded.is_empty() || encoded.len() > MAX_POLICY_BYTES {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::LimitExceeded,
                "凭据 vault 策略必须为 1 字节至 16 KiB",
            ));
        }
        let policy: Self = serde_json::from_slice(encoded).map_err(|_| {
            CredentialVaultError::new(
                CredentialVaultErrorCode::InvalidInput,
                "凭据 vault 策略损坏或字段不受支持",
            )
        })?;
        validate_policy(&policy)?;
        Ok(policy)
    }

    pub(crate) fn enable(
        &mut self,
        expected_revision: u64,
        registry: &DeviceRegistry,
        device_id: &str,
    ) -> VaultResult<u64> {
        self.require_revision(expected_revision)?;
        self.require_registry(registry)?;
        if self.enabled {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::Conflict,
                "凭据 vault 已启用",
            ));
        }
        if self.revoked_devices.contains(device_id) || !registry.is_authorized(device_id) {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::Unauthorized,
                "设备不能启用凭据 vault",
            ));
        }
        self.enabled = true;
        self.authorized_devices.insert(device_id.to_string());
        self.next_revision()
    }

    pub(crate) fn authorize_device(
        &mut self,
        expected_revision: u64,
        registry: &DeviceRegistry,
        acting_device_id: &str,
        target_device_id: &str,
    ) -> VaultResult<u64> {
        self.require_revision(expected_revision)?;
        self.require_access(registry, acting_device_id)?;
        if self.revoked_devices.contains(target_device_id)
            || !registry.is_authorized(target_device_id)
        {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::Unauthorized,
                "目标设备已撤销、未知或不活动",
            ));
        }
        if self.authorized_devices.len() + self.revoked_devices.len() >= MAX_DEVICES {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::LimitExceeded,
                "凭据 vault 最多授权 32 台设备",
            ));
        }
        if !self.authorized_devices.insert(target_device_id.to_string()) {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::Conflict,
                "目标设备已经授权",
            ));
        }
        self.next_revision()
    }

    pub(crate) fn revoke_device(
        &mut self,
        expected_revision: u64,
        registry: &DeviceRegistry,
        acting_device_id: &str,
        target_device_id: &str,
    ) -> VaultResult<u64> {
        self.require_revision(expected_revision)?;
        self.require_access(registry, acting_device_id)?;
        if !self.authorized_devices.contains(target_device_id) {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::Conflict,
                "目标设备没有凭据 vault 授权",
            ));
        }
        if self.authorized_devices.len() <= 1 {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::Conflict,
                "不能撤销最后一台凭据 vault 授权设备",
            ));
        }
        self.authorized_devices.remove(target_device_id);
        self.revoked_devices.insert(target_device_id.to_string());
        self.next_revision()
    }

    pub(crate) fn disable(
        &mut self,
        expected_revision: u64,
        registry: &DeviceRegistry,
        acting_device_id: &str,
    ) -> VaultResult<u64> {
        self.require_revision(expected_revision)?;
        self.require_access(registry, acting_device_id)?;
        self.enabled = false;
        self.authorized_devices.clear();
        self.next_revision()
    }

    pub(crate) fn requires_key_rotation(&self) -> bool {
        !self.revoked_devices.is_empty()
    }

    fn require_registry(&self, registry: &DeviceRegistry) -> VaultResult<()> {
        if registry.vault_id() != self.vault_id {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::Conflict,
                "设备 registry 与凭据 vault 不属于同一 vault",
            ));
        }
        Ok(())
    }

    fn require_access(&self, registry: &DeviceRegistry, device_id: &str) -> VaultResult<()> {
        self.require_registry(registry)?;
        if !self.enabled {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::Disabled,
                "凭据同步默认关闭且尚未显式启用",
            ));
        }
        if !registry.is_authorized(device_id)
            || !self.authorized_devices.contains(device_id)
            || self.revoked_devices.contains(device_id)
        {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::Unauthorized,
                "当前设备没有凭据 vault 授权",
            ));
        }
        Ok(())
    }

    fn require_revision(&self, expected_revision: u64) -> VaultResult<()> {
        if self.revision != expected_revision {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::Conflict,
                format!(
                    "凭据 vault revision 冲突：当前 {}，请求 {expected_revision}",
                    self.revision
                ),
            ));
        }
        Ok(())
    }

    fn next_revision(&mut self) -> VaultResult<u64> {
        self.revision = self.revision.checked_add(1).ok_or_else(|| {
            CredentialVaultError::new(
                CredentialVaultErrorCode::LimitExceeded,
                "凭据 vault revision 已耗尽",
            )
        })?;
        Ok(self.revision)
    }
}

fn validate_policy(policy: &CredentialVaultPolicy) -> VaultResult<()> {
    if policy.format_version != FORMAT_VERSION
        || policy.revision == 0
        || policy.authorized_devices.len() > MAX_DEVICES
        || policy.revoked_devices.len() > MAX_DEVICES
        || policy.authorized_devices.len() + policy.revoked_devices.len() > MAX_DEVICES
        || policy
            .authorized_devices
            .iter()
            .any(|device| policy.revoked_devices.contains(device))
        || (policy.enabled && policy.authorized_devices.is_empty())
        || (!policy.enabled && !policy.authorized_devices.is_empty())
    {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::InvalidInput,
            "凭据 vault 策略版本、revision、状态或数量无效",
        ));
    }
    validate_uuid(&policy.vault_id, "vault")?;
    for device_id in policy
        .authorized_devices
        .iter()
        .chain(policy.revoked_devices.iter())
    {
        validate_uuid(device_id, "device")?;
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum CredentialSecretKind {
    SshPassword,
    PrivateKeyPassphrase,
    OpenSshPrivateKey,
    AccessToken,
}

impl CredentialSecretKind {
    fn domain_label(&self) -> &'static str {
        match self {
            Self::SshPassword => "ssh-password",
            Self::PrivateKeyPassphrase => "private-key-passphrase",
            Self::OpenSshPrivateKey => "openssh-private-key",
            Self::AccessToken => "access-token",
        }
    }
}

pub(crate) struct CredentialSecret {
    kind: CredentialSecretKind,
    value: Zeroizing<String>,
}

impl CredentialSecret {
    pub(crate) fn new(kind: CredentialSecretKind, value: String) -> VaultResult<Self> {
        let value = Zeroizing::new(value);
        validate_secret(&kind, value.as_str())?;
        Ok(Self { kind, value })
    }

    #[cfg(test)]
    fn expose_for_test(&self) -> &str {
        self.value.as_str()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialEnvelope {
    format_version: u32,
    vault_id: String,
    item_id: String,
    kind: CredentialSecretKind,
    key_domain: String,
    algorithm: String,
    nonce: String,
    ciphertext: String,
}

impl CredentialEnvelope {
    pub(crate) fn encode(&self) -> VaultResult<Vec<u8>> {
        validate_envelope(self)?;
        let encoded = serde_json::to_vec(self).map_err(|_| {
            CredentialVaultError::new(
                CredentialVaultErrorCode::InvalidInput,
                "无法序列化凭据 vault 信封",
            )
        })?;
        if encoded.len() > MAX_ENVELOPE_BYTES {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::LimitExceeded,
                "凭据 vault 信封超过 2 MiB",
            ));
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> VaultResult<Self> {
        if encoded.is_empty() || encoded.len() > MAX_ENVELOPE_BYTES {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::LimitExceeded,
                "凭据 vault 信封必须为 1 字节至 2 MiB",
            ));
        }
        let envelope: Self = serde_json::from_slice(encoded).map_err(|_| {
            CredentialVaultError::new(
                CredentialVaultErrorCode::InvalidInput,
                "凭据 vault 信封损坏或字段不受支持",
            )
        })?;
        validate_envelope(&envelope)?;
        Ok(envelope)
    }

    pub(crate) fn object_key(&self) -> String {
        format!("credentials/{}/{}.ocred", self.vault_id, self.item_id)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialPayload {
    format_version: u32,
    kind: CredentialSecretKind,
    secret: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialPayloadRef<'a> {
    format_version: u32,
    kind: &'a CredentialSecretKind,
    secret: &'a str,
}

pub(crate) fn encrypt_credential(
    policy: &CredentialVaultPolicy,
    registry: &DeviceRegistry,
    device_id: &str,
    credential_key: &CredentialVaultKey,
    secret: &CredentialSecret,
) -> VaultResult<CredentialEnvelope> {
    policy.require_access(registry, device_id)?;
    let item_id = Uuid::new_v4().to_string();
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| {
        CredentialVaultError::new(
            CredentialVaultErrorCode::Authentication,
            "无法生成凭据 vault nonce",
        )
    })?;
    let payload = CredentialPayloadRef {
        format_version: FORMAT_VERSION,
        kind: &secret.kind,
        secret: secret.value.as_str(),
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| {
        CredentialVaultError::new(
            CredentialVaultErrorCode::InvalidInput,
            "无法编码凭据 vault 载荷",
        )
    })?);
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::LimitExceeded,
            "凭据 vault 明文载荷超过 1152 KiB",
        ));
    }
    let ciphertext_len = plaintext.len().checked_add(TAG_BYTES).ok_or_else(|| {
        CredentialVaultError::new(
            CredentialVaultErrorCode::LimitExceeded,
            "凭据 vault 载荷长度溢出",
        )
    })?;
    let aad = envelope_aad(&policy.vault_id, &item_id, &secret.kind, ciphertext_len)?;
    let domain_key = derive_key(credential_key, &policy.vault_id, &secret.kind)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(domain_key.as_ref()));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| {
            CredentialVaultError::new(
                CredentialVaultErrorCode::Authentication,
                "无法加密凭据 vault 对象",
            )
        })?;
    let envelope = CredentialEnvelope {
        format_version: FORMAT_VERSION,
        vault_id: policy.vault_id.clone(),
        item_id,
        kind: secret.kind.clone(),
        key_domain: KEY_DOMAIN.to_string(),
        algorithm: ALGORITHM.to_string(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    validate_envelope(&envelope)?;
    Ok(envelope)
}

pub(crate) fn encrypt_local_reference<F>(
    policy: &CredentialVaultPolicy,
    registry: &DeviceRegistry,
    device_id: &str,
    credential_key: &CredentialVaultKey,
    local_reference: &str,
    kind: CredentialSecretKind,
    read_secret: F,
) -> VaultResult<CredentialEnvelope>
where
    F: FnOnce(&str) -> Result<Zeroizing<String>, String>,
{
    validate_local_reference(local_reference)?;
    if !matches!(
        kind,
        CredentialSecretKind::SshPassword | CredentialSecretKind::PrivateKeyPassphrase
    ) {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::InvalidInput,
            "本机 credential reference 只允许密码或私钥口令",
        ));
    }
    let source = read_secret(local_reference).map_err(|_| {
        CredentialVaultError::new(CredentialVaultErrorCode::Authentication, "无法读取本机凭据")
    })?;
    let secret = CredentialSecret::new(kind, source.as_str().to_string())?;
    encrypt_credential(policy, registry, device_id, credential_key, &secret)
}

pub(crate) fn decrypt_credential(
    policy: &CredentialVaultPolicy,
    registry: &DeviceRegistry,
    device_id: &str,
    credential_key: &CredentialVaultKey,
    envelope: &CredentialEnvelope,
) -> VaultResult<CredentialSecret> {
    policy.require_access(registry, device_id)?;
    validate_envelope(envelope)?;
    if envelope.vault_id != policy.vault_id {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::Conflict,
            "凭据 vault 信封属于其他 vault",
        ));
    }
    let nonce = decode_exact::<NONCE_BYTES>(&envelope.nonce, "凭据 vault nonce")?;
    let ciphertext = decode_bounded(
        &envelope.ciphertext,
        TAG_BYTES,
        MAX_PLAINTEXT_BYTES + TAG_BYTES,
        "凭据 vault 密文",
    )?;
    let aad = envelope_aad(
        &envelope.vault_id,
        &envelope.item_id,
        &envelope.kind,
        ciphertext.len(),
    )?;
    let domain_key = derive_key(credential_key, &envelope.vault_id, &envelope.kind)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(domain_key.as_ref()));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                CredentialVaultError::new(
                    CredentialVaultErrorCode::Authentication,
                    "凭据 vault 对象认证失败",
                )
            })?,
    );
    let payload: CredentialPayload = serde_json::from_slice(&plaintext).map_err(|_| {
        CredentialVaultError::new(
            CredentialVaultErrorCode::Authentication,
            "凭据 vault 载荷认证后格式无效",
        )
    })?;
    if payload.format_version != FORMAT_VERSION || payload.kind != envelope.kind {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::Authentication,
            "凭据 vault 载荷版本或类型不匹配",
        ));
    }
    CredentialSecret::new(payload.kind, payload.secret)
}

pub(crate) fn reencrypt_credential(
    policy: &CredentialVaultPolicy,
    registry: &DeviceRegistry,
    device_id: &str,
    old_credential_key: &CredentialVaultKey,
    new_credential_key: &CredentialVaultKey,
    envelope: &CredentialEnvelope,
) -> VaultResult<CredentialEnvelope> {
    if old_credential_key.key_material() == new_credential_key.key_material() {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::InvalidInput,
            "新旧凭据 vault 密钥必须不同",
        ));
    }
    let secret = decrypt_credential(policy, registry, device_id, old_credential_key, envelope)?;
    encrypt_credential_with_identity(policy, new_credential_key, envelope, secret)
}

pub(crate) fn reencrypt_credentials(
    policy: &CredentialVaultPolicy,
    registry: &DeviceRegistry,
    device_id: &str,
    old_credential_key: &CredentialVaultKey,
    new_credential_key: &CredentialVaultKey,
    envelopes: &[CredentialEnvelope],
) -> VaultResult<Vec<CredentialEnvelope>> {
    if old_credential_key.key_material() == new_credential_key.key_material() {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::InvalidInput,
            "新旧凭据 vault 密钥必须不同",
        ));
    }
    if envelopes.is_empty() || envelopes.len() > MAX_ROTATION_ITEMS {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::LimitExceeded,
            "凭据 vault 轮换批次必须为 1 至 10000 项",
        ));
    }

    policy.require_access(registry, device_id)?;
    let mut item_ids = BTreeSet::new();
    let mut total_plaintext_bytes = 0usize;
    let mut plaintexts = Vec::with_capacity(envelopes.len());
    for envelope in envelopes {
        validate_envelope(envelope)?;
        if envelope.vault_id != policy.vault_id {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::Conflict,
                "凭据 vault 轮换批次不能跨 vault",
            ));
        }
        if !item_ids.insert(envelope.item_id.as_str()) {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::Conflict,
                "凭据 vault 轮换批次包含重复 item",
            ));
        }
        let secret = decrypt_credential(policy, registry, device_id, old_credential_key, envelope)?;
        let kind = secret.kind.clone();
        let plaintext = encode_credential_rotation_payload(&secret)?;
        total_plaintext_bytes =
            checked_rotation_plaintext_total(total_plaintext_bytes, plaintext.len())?;
        plaintexts.push((kind, plaintext));
    }

    envelopes
        .iter()
        .zip(plaintexts)
        .map(|(envelope, (kind, plaintext))| {
            encrypt_credential_plaintext_with_identity(
                policy,
                new_credential_key,
                envelope,
                kind,
                plaintext,
            )
        })
        .collect()
}

fn checked_rotation_plaintext_total(current: usize, next: usize) -> VaultResult<usize> {
    let total = current.checked_add(next).ok_or_else(|| {
        CredentialVaultError::new(
            CredentialVaultErrorCode::LimitExceeded,
            "凭据 vault 轮换批次总明文长度溢出",
        )
    })?;
    if total > MAX_ROTATION_PLAINTEXT_BYTES {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::LimitExceeded,
            "凭据 vault 轮换批次总明文超过 256 MiB",
        ));
    }
    Ok(total)
}

fn encrypt_credential_with_identity(
    policy: &CredentialVaultPolicy,
    new_credential_key: &CredentialVaultKey,
    envelope: &CredentialEnvelope,
    secret: CredentialSecret,
) -> VaultResult<CredentialEnvelope> {
    let kind = secret.kind.clone();
    let plaintext = encode_credential_rotation_payload(&secret)?;
    encrypt_credential_plaintext_with_identity(
        policy,
        new_credential_key,
        envelope,
        kind,
        plaintext,
    )
}

fn encode_credential_rotation_payload(
    secret: &CredentialSecret,
) -> VaultResult<Zeroizing<Vec<u8>>> {
    let payload = CredentialPayloadRef {
        format_version: FORMAT_VERSION,
        kind: &secret.kind,
        secret: secret.value.as_str(),
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| {
        CredentialVaultError::new(
            CredentialVaultErrorCode::InvalidInput,
            "无法编码凭据 vault 轮换载荷",
        )
    })?);
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::LimitExceeded,
            "凭据 vault 轮换明文载荷超过 1152 KiB",
        ));
    }
    Ok(plaintext)
}

fn encrypt_credential_plaintext_with_identity(
    policy: &CredentialVaultPolicy,
    new_credential_key: &CredentialVaultKey,
    envelope: &CredentialEnvelope,
    kind: CredentialSecretKind,
    plaintext: Zeroizing<Vec<u8>>,
) -> VaultResult<CredentialEnvelope> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| {
        CredentialVaultError::new(
            CredentialVaultErrorCode::Authentication,
            "无法生成凭据 vault 轮换 nonce",
        )
    })?;
    let ciphertext_len = plaintext.len().checked_add(TAG_BYTES).ok_or_else(|| {
        CredentialVaultError::new(
            CredentialVaultErrorCode::LimitExceeded,
            "凭据 vault 轮换载荷长度溢出",
        )
    })?;
    let aad = envelope_aad(&policy.vault_id, &envelope.item_id, &kind, ciphertext_len)?;
    let domain_key = derive_key(new_credential_key, &policy.vault_id, &kind)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(domain_key.as_ref()));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| {
            CredentialVaultError::new(
                CredentialVaultErrorCode::Authentication,
                "无法重加密凭据 vault 对象",
            )
        })?;
    let rotated = CredentialEnvelope {
        format_version: FORMAT_VERSION,
        vault_id: envelope.vault_id.clone(),
        item_id: envelope.item_id.clone(),
        kind,
        key_domain: KEY_DOMAIN.to_string(),
        algorithm: ALGORITHM.to_string(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    validate_envelope(&rotated)?;
    Ok(rotated)
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RestoredCredentialReference {
    kind: CredentialSecretKind,
    reference: String,
}

impl RestoredCredentialReference {
    pub(crate) fn kind(&self) -> &CredentialSecretKind {
        &self.kind
    }

    pub(crate) fn reference(&self) -> &str {
        &self.reference
    }
}

trait LocalCredentialStore {
    fn contains(&mut self, reference: &str) -> Result<bool, ()>;
    fn write(&mut self, reference: &str, secret: &str) -> Result<(), ()>;
    fn read(&mut self, reference: &str) -> Result<Zeroizing<String>, ()>;
    fn remove(&mut self, reference: &str) -> Result<(), ()>;
}

struct SystemCredentialStore;

impl SystemCredentialStore {
    fn entry(reference: &str) -> Result<keyring::Entry, ()> {
        keyring::Entry::new(CREDENTIAL_SERVICE, reference).map_err(|_| ())
    }
}

impl LocalCredentialStore for SystemCredentialStore {
    fn contains(&mut self, reference: &str) -> Result<bool, ()> {
        match Self::entry(reference)?.get_password() {
            Ok(secret) => {
                let _secret = Zeroizing::new(secret);
                Ok(true)
            }
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(_) => Err(()),
        }
    }

    fn write(&mut self, reference: &str, secret: &str) -> Result<(), ()> {
        Self::entry(reference)?.set_password(secret).map_err(|_| ())
    }

    fn read(&mut self, reference: &str) -> Result<Zeroizing<String>, ()> {
        Self::entry(reference)?
            .get_password()
            .map(Zeroizing::new)
            .map_err(|_| ())
    }

    fn remove(&mut self, reference: &str) -> Result<(), ()> {
        match Self::entry(reference)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

pub(crate) fn restore_credential_to_system_keyring(
    policy: &CredentialVaultPolicy,
    registry: &DeviceRegistry,
    device_id: &str,
    credential_key: &CredentialVaultKey,
    envelope: &CredentialEnvelope,
) -> VaultResult<RestoredCredentialReference> {
    let mut store = SystemCredentialStore;
    restore_credential_with_store(
        policy,
        registry,
        device_id,
        credential_key,
        envelope,
        &mut store,
        Uuid::new_v4,
    )
}

fn restore_credential_with_store<S, F>(
    policy: &CredentialVaultPolicy,
    registry: &DeviceRegistry,
    device_id: &str,
    credential_key: &CredentialVaultKey,
    envelope: &CredentialEnvelope,
    store: &mut S,
    mut new_id: F,
) -> VaultResult<RestoredCredentialReference>
where
    S: LocalCredentialStore,
    F: FnMut() -> Uuid,
{
    let secret = decrypt_credential(policy, registry, device_id, credential_key, envelope)?;
    let prefix = match &secret.kind {
        CredentialSecretKind::SshPassword => "ssh-",
        CredentialSecretKind::PrivateKeyPassphrase => "key-",
        CredentialSecretKind::OpenSshPrivateKey | CredentialSecretKind::AccessToken => {
            return Err(CredentialVaultError::new(
                CredentialVaultErrorCode::InvalidInput,
                "该凭据类型尚无安全的本机安装目标",
            ));
        }
    };

    for _ in 0..LOCAL_REFERENCE_ATTEMPTS {
        let reference = format!("{prefix}{}", new_id());
        validate_local_reference(&reference)?;
        if store.contains(&reference).map_err(|_| storage_error())? {
            continue;
        }
        if store.write(&reference, secret.value.as_str()).is_err() {
            let _ = store.remove(&reference);
            return Err(storage_error());
        }
        let verified = store
            .read(&reference)
            .is_ok_and(|stored| stored.as_str() == secret.value.as_str());
        if !verified {
            let _ = store.remove(&reference);
            return Err(storage_error());
        }
        return Ok(RestoredCredentialReference {
            kind: secret.kind,
            reference,
        });
    }

    Err(CredentialVaultError::new(
        CredentialVaultErrorCode::Storage,
        "无法分配新的本机凭据引用",
    ))
}

fn storage_error() -> CredentialVaultError {
    CredentialVaultError::new(CredentialVaultErrorCode::Storage, "系统凭据管理器写回失败")
}

fn validate_secret(kind: &CredentialSecretKind, value: &str) -> VaultResult<()> {
    let invalid_line = value.contains(['\0', '\r']);
    let valid = match kind {
        CredentialSecretKind::SshPassword => {
            !value.is_empty()
                && value.len() <= MAX_PASSWORD_BYTES
                && !invalid_line
                && !value.contains('\n')
        }
        CredentialSecretKind::PrivateKeyPassphrase => {
            !value.is_empty()
                && value.len() <= MAX_PASSPHRASE_BYTES
                && !invalid_line
                && !value.contains('\n')
        }
        CredentialSecretKind::AccessToken => {
            !value.is_empty()
                && value.len() <= MAX_TOKEN_BYTES
                && !invalid_line
                && !value.contains('\n')
        }
        CredentialSecretKind::OpenSshPrivateKey => {
            value.len() <= MAX_PRIVATE_KEY_BYTES
                && value.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n")
                && value
                    .trim_end()
                    .ends_with("-----END OPENSSH PRIVATE KEY-----")
                && !value.contains('\0')
        }
    };
    if !valid {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::InvalidInput,
            "凭据值类型、格式或长度无效",
        ));
    }
    Ok(())
}

fn validate_envelope(envelope: &CredentialEnvelope) -> VaultResult<()> {
    if envelope.format_version != FORMAT_VERSION
        || envelope.key_domain != KEY_DOMAIN
        || envelope.algorithm != ALGORITHM
    {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::InvalidInput,
            "凭据 vault 信封版本、密钥域或算法不受支持",
        ));
    }
    validate_uuid(&envelope.vault_id, "vault")?;
    validate_uuid(&envelope.item_id, "credential item")?;
    decode_exact::<NONCE_BYTES>(&envelope.nonce, "凭据 vault nonce")?;
    decode_bounded(
        &envelope.ciphertext,
        TAG_BYTES,
        MAX_PLAINTEXT_BYTES + TAG_BYTES,
        "凭据 vault 密文",
    )?;
    Ok(())
}

fn derive_key(
    credential_key: &CredentialVaultKey,
    vault_id: &str,
    kind: &CredentialSecretKind,
) -> VaultResult<Zeroizing<[u8; 32]>> {
    validate_uuid(vault_id, "vault")?;
    let salt = format!("vpshell-sync-v1/credential-vault/{vault_id}");
    let info = format!("vpshell-sync-v1/credential-domain/{}", kind.domain_label());
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), credential_key.key_material());
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(info.as_bytes(), output.as_mut()).map_err(|_| {
        CredentialVaultError::new(
            CredentialVaultErrorCode::Authentication,
            "无法派生凭据 vault 域密钥",
        )
    })?;
    Ok(output)
}

fn envelope_aad(
    vault_id: &str,
    item_id: &str,
    kind: &CredentialSecretKind,
    ciphertext_len: usize,
) -> VaultResult<Vec<u8>> {
    validate_uuid(vault_id, "vault")?;
    validate_uuid(item_id, "credential item")?;
    let mut aad = b"VPSHELL-CREDENTIAL-OBJECT-V1".to_vec();
    push_field(&mut aad, vault_id.as_bytes())?;
    push_field(&mut aad, item_id.as_bytes())?;
    push_field(&mut aad, kind.domain_label().as_bytes())?;
    push_field(&mut aad, KEY_DOMAIN.as_bytes())?;
    push_field(&mut aad, ALGORITHM.as_bytes())?;
    aad.extend_from_slice(&(ciphertext_len as u64).to_be_bytes());
    Ok(aad)
}

fn push_field(output: &mut Vec<u8>, value: &[u8]) -> VaultResult<()> {
    let length = u32::try_from(value.len()).map_err(|_| {
        CredentialVaultError::new(
            CredentialVaultErrorCode::LimitExceeded,
            "凭据 vault AAD 字段过长",
        )
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn decode_exact<const N: usize>(value: &str, label: &str) -> VaultResult<[u8; N]> {
    let decoded = decode_bounded(value, N, N, label)?;
    let mut output = [0u8; N];
    output.copy_from_slice(&decoded);
    Ok(output)
}

fn decode_bounded(
    value: &str,
    minimum: usize,
    maximum: usize,
    label: &str,
) -> VaultResult<Vec<u8>> {
    if value.is_empty() || value.len() > maximum.saturating_mul(4) / 3 + 8 {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::LimitExceeded,
            format!("{label} 超过限制"),
        ));
    }
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        CredentialVaultError::new(
            CredentialVaultErrorCode::InvalidInput,
            format!("{label} base64url 无效"),
        )
    })?;
    if !(minimum..=maximum).contains(&decoded.len()) || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::InvalidInput,
            format!("{label} 非 canonical 或长度无效"),
        ));
    }
    Ok(decoded)
}

fn validate_local_reference(value: &str) -> VaultResult<()> {
    let suffix = value
        .strip_prefix("ssh-")
        .or_else(|| value.strip_prefix("key-"))
        .ok_or_else(|| {
            CredentialVaultError::new(
                CredentialVaultErrorCode::InvalidInput,
                "本机 credential reference 类型无效",
            )
        })?;
    validate_uuid(suffix, "credential reference")
}

fn validate_uuid(value: &str, label: &str) -> VaultResult<()> {
    let parsed = Uuid::parse_str(value).map_err(|_| {
        CredentialVaultError::new(
            CredentialVaultErrorCode::InvalidInput,
            format!("{label} ID 无效"),
        )
    })?;
    if parsed.to_string() != value {
        return Err(CredentialVaultError::new(
            CredentialVaultErrorCode::InvalidInput,
            format!("{label} ID 必须是 canonical lowercase UUID"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};

    use super::*;
    use crate::{
        sync_crypto::{CredentialKeyslot, create_credential_keyslot, open_credential_keyslot},
        sync_recovery::DeviceRegistry,
    };

    const VAULT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_VAULT: &str = "22222222-2222-4222-8222-222222222222";
    const DEVICE_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const DEVICE_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    #[derive(Default)]
    struct MemoryCredentialStore {
        values: BTreeMap<String, String>,
        contains_calls: usize,
        corrupt_readback: bool,
        removed: Vec<String>,
    }

    impl LocalCredentialStore for MemoryCredentialStore {
        fn contains(&mut self, reference: &str) -> Result<bool, ()> {
            self.contains_calls += 1;
            Ok(self.values.contains_key(reference))
        }

        fn write(&mut self, reference: &str, secret: &str) -> Result<(), ()> {
            self.values
                .insert(reference.to_string(), secret.to_string());
            Ok(())
        }

        fn read(&mut self, reference: &str) -> Result<Zeroizing<String>, ()> {
            let value = self.values.get(reference).ok_or(())?;
            if self.corrupt_readback {
                Ok(Zeroizing::new("different-value".to_string()))
            } else {
                Ok(Zeroizing::new(value.clone()))
            }
        }

        fn remove(&mut self, reference: &str) -> Result<(), ()> {
            self.values.remove(reference);
            self.removed.push(reference.to_string());
            Ok(())
        }
    }

    fn registry() -> DeviceRegistry {
        let mut registry = DeviceRegistry::new(VAULT_ID, DEVICE_A, "Laptop", &[1; 32], 1).unwrap();
        registry
            .add_device(1, DEVICE_B, "Phone", &[2; 32], 2)
            .unwrap();
        registry
    }

    fn enabled_policy() -> (DeviceRegistry, CredentialVaultPolicy) {
        let registry = registry();
        let mut policy = CredentialVaultPolicy::disabled(VAULT_ID).unwrap();
        policy.enable(1, &registry, DEVICE_A).unwrap();
        (registry, policy)
    }

    fn error_code<T>(result: VaultResult<T>) -> CredentialVaultErrorCode {
        match result {
            Ok(_) => panic!("expected credential vault error"),
            Err(error) => error.code,
        }
    }

    #[test]
    fn vault_is_default_off_revisioned_and_device_authorized() {
        let registry = registry();
        let key = CredentialVaultKey::from_bytes([7; 32]);
        let secret =
            CredentialSecret::new(CredentialSecretKind::SshPassword, "hidden-password".into())
                .unwrap();
        let mut policy = CredentialVaultPolicy::disabled(VAULT_ID).unwrap();
        assert_eq!(
            encrypt_credential(&policy, &registry, DEVICE_A, &key, &secret)
                .unwrap_err()
                .code,
            CredentialVaultErrorCode::Disabled
        );
        assert!(policy.enable(2, &registry, DEVICE_A).is_err());
        assert_eq!(policy.enable(1, &registry, DEVICE_A).unwrap(), 2);
        assert_eq!(
            policy
                .revoke_device(2, &registry, DEVICE_A, DEVICE_A)
                .unwrap_err()
                .code,
            CredentialVaultErrorCode::Conflict
        );
        assert_eq!(
            policy
                .authorize_device(2, &registry, DEVICE_A, DEVICE_B)
                .unwrap(),
            3
        );
        let envelope = encrypt_credential(&policy, &registry, DEVICE_B, &key, &secret).unwrap();
        assert_eq!(
            policy
                .revoke_device(3, &registry, DEVICE_A, DEVICE_B)
                .unwrap(),
            4
        );
        assert!(policy.requires_key_rotation());
        assert_eq!(
            error_code(decrypt_credential(
                &policy, &registry, DEVICE_B, &key, &envelope,
            )),
            CredentialVaultErrorCode::Unauthorized
        );
        assert!(
            policy
                .authorize_device(4, &registry, DEVICE_A, DEVICE_B)
                .is_err()
        );
        assert_eq!(
            CredentialVaultPolicy::decode(&policy.encode().unwrap()).unwrap(),
            policy
        );
        assert_eq!(policy.disable(4, &registry, DEVICE_A).unwrap(), 5);
        assert!(!policy.enabled);
    }

    #[test]
    fn credential_keyslot_is_independent_strict_and_password_authenticated() {
        let key = CredentialVaultKey::from_bytes([9; 32]);
        let slot = create_credential_keyslot(b"separate vault password", VAULT_ID, &key).unwrap();
        let encoded = slot.encode().unwrap();
        let encoded_text = String::from_utf8(encoded.clone()).unwrap();
        assert!(!encoded_text.contains("separate vault password"));
        assert_eq!(CredentialKeyslot::decode(&encoded).unwrap(), slot);
        assert_eq!(
            open_credential_keyslot(b"separate vault password", &slot)
                .unwrap()
                .key_material(),
            key.key_material()
        );
        assert!(open_credential_keyslot(b"wrong password", &slot).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["keyDomain"] = serde_json::json!("business");
        assert!(CredentialKeyslot::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn typed_secrets_round_trip_without_plaintext_or_reference_leaks() {
        let (registry, policy) = enabled_policy();
        let key = CredentialVaultKey::from_bytes([3; 32]);
        let private_key =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
        for (kind, value) in [
            (CredentialSecretKind::SshPassword, "ssh-secret"),
            (CredentialSecretKind::PrivateKeyPassphrase, "key-secret"),
            (CredentialSecretKind::OpenSshPrivateKey, private_key),
            (CredentialSecretKind::AccessToken, "token-secret"),
        ] {
            let secret = CredentialSecret::new(kind, value.to_string()).unwrap();
            let envelope = encrypt_credential(&policy, &registry, DEVICE_A, &key, &secret).unwrap();
            let encoded = envelope.encode().unwrap();
            let text = String::from_utf8(encoded.clone()).unwrap();
            assert!(!text.contains(value));
            assert!(!text.contains("credentialRef"));
            assert!(envelope.object_key().starts_with("credentials/"));
            let decoded = CredentialEnvelope::decode(&encoded).unwrap();
            assert_eq!(
                decrypt_credential(&policy, &registry, DEVICE_A, &key, &decoded)
                    .unwrap()
                    .expose_for_test(),
                value
            );
        }

        let reference = "ssh-33333333-3333-4333-8333-333333333333";
        let envelope = encrypt_local_reference(
            &policy,
            &registry,
            DEVICE_A,
            &key,
            reference,
            CredentialSecretKind::SshPassword,
            |_| Ok(Zeroizing::new("source-secret".to_string())),
        )
        .unwrap();
        let encoded = String::from_utf8(envelope.encode().unwrap()).unwrap();
        assert!(!encoded.contains(reference));
        assert!(!encoded.contains("source-secret"));

        let error = encrypt_local_reference(
            &policy,
            &registry,
            DEVICE_A,
            &key,
            reference,
            CredentialSecretKind::SshPassword,
            |_| Err("source-secret in provider diagnostic".to_string()),
        )
        .unwrap_err();
        assert!(!error.message.contains("source-secret"));
    }

    #[test]
    fn authenticated_passwords_restore_to_new_consumable_references() {
        let (registry, policy) = enabled_policy();
        let key = CredentialVaultKey::from_bytes([6; 32]);
        for (kind, value, identifier, prefix) in [
            (
                CredentialSecretKind::SshPassword,
                "restored-password",
                "33333333-3333-4333-8333-333333333333",
                "ssh-",
            ),
            (
                CredentialSecretKind::PrivateKeyPassphrase,
                "restored-passphrase",
                "44444444-4444-4444-8444-444444444444",
                "key-",
            ),
        ] {
            let envelope = encrypt_credential(
                &policy,
                &registry,
                DEVICE_A,
                &key,
                &CredentialSecret::new(kind.clone(), value.to_string()).unwrap(),
            )
            .unwrap();
            let mut store = MemoryCredentialStore::default();
            let restored = restore_credential_with_store(
                &policy,
                &registry,
                DEVICE_A,
                &key,
                &envelope,
                &mut store,
                || Uuid::parse_str(identifier).unwrap(),
            )
            .unwrap();
            assert_eq!(restored.kind(), &kind);
            let expected_reference = format!("{prefix}{identifier}");
            assert_eq!(restored.reference(), expected_reference.as_str());
            assert_eq!(
                store.values.get(restored.reference()).map(String::as_str),
                Some(value)
            );
        }
    }

    #[test]
    fn restore_authenticates_before_write_and_rejects_uninstallable_kinds() {
        let (registry, policy) = enabled_policy();
        let key = CredentialVaultKey::from_bytes([8; 32]);
        let password = CredentialSecret::new(
            CredentialSecretKind::SshPassword,
            "never-written-password".to_string(),
        )
        .unwrap();
        let password_envelope =
            encrypt_credential(&policy, &registry, DEVICE_A, &key, &password).unwrap();
        let mut store = MemoryCredentialStore::default();
        assert_eq!(
            error_code(restore_credential_with_store(
                &policy,
                &registry,
                DEVICE_B,
                &key,
                &password_envelope,
                &mut store,
                Uuid::new_v4,
            )),
            CredentialVaultErrorCode::Unauthorized
        );
        assert_eq!(store.contains_calls, 0);
        assert!(store.values.is_empty());

        let wrong_key = CredentialVaultKey::from_bytes([9; 32]);
        assert_eq!(
            error_code(restore_credential_with_store(
                &policy,
                &registry,
                DEVICE_A,
                &wrong_key,
                &password_envelope,
                &mut store,
                Uuid::new_v4,
            )),
            CredentialVaultErrorCode::Authentication
        );
        assert_eq!(store.contains_calls, 0);
        assert!(store.values.is_empty());

        let token =
            CredentialSecret::new(CredentialSecretKind::AccessToken, "token-value".to_string())
                .unwrap();
        let token_envelope =
            encrypt_credential(&policy, &registry, DEVICE_A, &key, &token).unwrap();
        assert_eq!(
            error_code(restore_credential_with_store(
                &policy,
                &registry,
                DEVICE_A,
                &key,
                &token_envelope,
                &mut store,
                Uuid::new_v4,
            )),
            CredentialVaultErrorCode::InvalidInput
        );
        assert_eq!(store.contains_calls, 0);
        assert!(store.values.is_empty());
    }

    #[test]
    fn restore_never_overwrites_and_removes_unverified_writeback() {
        let (registry, policy) = enabled_policy();
        let key = CredentialVaultKey::from_bytes([10; 32]);
        let secret_value = "writeback-secret";
        let envelope = encrypt_credential(
            &policy,
            &registry,
            DEVICE_A,
            &key,
            &CredentialSecret::new(CredentialSecretKind::SshPassword, secret_value.to_string())
                .unwrap(),
        )
        .unwrap();
        let first_id = Uuid::parse_str("55555555-5555-4555-8555-555555555555").unwrap();
        let second_id = Uuid::parse_str("66666666-6666-4666-8666-666666666666").unwrap();
        let first_reference = format!("ssh-{first_id}");
        let second_reference = format!("ssh-{second_id}");
        let mut store = MemoryCredentialStore::default();
        store
            .values
            .insert(first_reference.clone(), "existing-value".to_string());
        let mut identifiers = VecDeque::from([first_id, second_id]);
        let restored = restore_credential_with_store(
            &policy,
            &registry,
            DEVICE_A,
            &key,
            &envelope,
            &mut store,
            || identifiers.pop_front().unwrap(),
        )
        .unwrap();
        assert_eq!(restored.reference(), second_reference.as_str());
        assert_eq!(
            store.values.get(&first_reference).map(String::as_str),
            Some("existing-value")
        );
        assert_eq!(
            store.values.get(&second_reference).map(String::as_str),
            Some(secret_value)
        );

        let failed_id = Uuid::parse_str("77777777-7777-4777-8777-777777777777").unwrap();
        let failed_reference = format!("ssh-{failed_id}");
        let mut corrupt_store = MemoryCredentialStore {
            corrupt_readback: true,
            ..MemoryCredentialStore::default()
        };
        let error = match restore_credential_with_store(
            &policy,
            &registry,
            DEVICE_A,
            &key,
            &envelope,
            &mut corrupt_store,
            || failed_id,
        ) {
            Ok(_) => panic!("expected writeback verification failure"),
            Err(error) => error,
        };
        assert_eq!(error.code, CredentialVaultErrorCode::Storage);
        assert!(!error.message.contains(secret_value));
        assert!(!error.message.contains(&failed_reference));
        assert!(!corrupt_store.values.contains_key(&failed_reference));
        assert_eq!(corrupt_store.removed, vec![failed_reference]);
    }

    #[test]
    fn tampering_relocation_unknown_fields_and_secret_bounds_are_rejected() {
        let (registry, policy) = enabled_policy();
        let key = CredentialVaultKey::from_bytes([4; 32]);
        let secret =
            CredentialSecret::new(CredentialSecretKind::SshPassword, "hidden-password".into())
                .unwrap();
        let envelope = encrypt_credential(&policy, &registry, DEVICE_A, &key, &secret).unwrap();
        let mut tampered = envelope.clone();
        tampered.item_id = Uuid::new_v4().to_string();
        assert_eq!(
            error_code(decrypt_credential(
                &policy, &registry, DEVICE_A, &key, &tampered,
            )),
            CredentialVaultErrorCode::Authentication
        );
        let wrong_key = CredentialVaultKey::from_bytes([5; 32]);
        assert!(decrypt_credential(&policy, &registry, DEVICE_A, &wrong_key, &envelope).is_err());

        let mut value: serde_json::Value =
            serde_json::from_slice(&envelope.encode().unwrap()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(CredentialEnvelope::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut policy_value: serde_json::Value =
            serde_json::from_slice(&policy.encode().unwrap()).unwrap();
        policy_value["vaultId"] = serde_json::json!(OTHER_VAULT);
        assert!(CredentialVaultPolicy::decode(&serde_json::to_vec(&policy_value).unwrap()).is_ok());
        let other_policy =
            CredentialVaultPolicy::decode(&serde_json::to_vec(&policy_value).unwrap()).unwrap();
        assert_eq!(
            error_code(decrypt_credential(
                &other_policy,
                &registry,
                DEVICE_A,
                &key,
                &envelope,
            )),
            CredentialVaultErrorCode::Conflict
        );
        assert!(
            CredentialSecret::new(
                CredentialSecretKind::SshPassword,
                "x".repeat(MAX_PASSWORD_BYTES + 1)
            )
            .is_err()
        );
        assert!(
            CredentialSecret::new(
                CredentialSecretKind::OpenSshPrivateKey,
                "not-a-private-key".into()
            )
            .is_err()
        );
    }

    #[test]
    fn credential_rotation_reencrypts_with_new_cvk_without_changing_item_identity() {
        let (registry, policy) = enabled_policy();
        let old_key = CredentialVaultKey::from_bytes([0x31; 32]);
        let new_key = CredentialVaultKey::from_bytes([0x32; 32]);
        let envelope = encrypt_credential(
            &policy,
            &registry,
            DEVICE_A,
            &old_key,
            &CredentialSecret::new(
                CredentialSecretKind::PrivateKeyPassphrase,
                "passphrase".into(),
            )
            .unwrap(),
        )
        .unwrap();
        let rotated =
            reencrypt_credential(&policy, &registry, DEVICE_A, &old_key, &new_key, &envelope)
                .unwrap();
        assert_eq!(rotated.item_id, envelope.item_id);
        assert_eq!(rotated.kind, envelope.kind);
        assert_ne!(rotated.nonce, envelope.nonce);
        assert_eq!(
            decrypt_credential(&policy, &registry, DEVICE_A, &new_key, &rotated)
                .unwrap()
                .expose_for_test(),
            "passphrase"
        );
        assert!(decrypt_credential(&policy, &registry, DEVICE_A, &old_key, &rotated).is_err());
        assert!(
            reencrypt_credential(
                &policy,
                &registry,
                DEVICE_A,
                &CredentialVaultKey::from_bytes([0x33; 32]),
                &new_key,
                &envelope,
            )
            .is_err()
        );
        assert!(
            reencrypt_credential(&policy, &registry, DEVICE_A, &old_key, &old_key, &envelope,)
                .is_err()
        );
    }

    #[test]
    fn credential_rotation_batch_is_bounded_ordered_and_all_or_nothing() {
        assert_eq!(
            checked_rotation_plaintext_total(MAX_ROTATION_PLAINTEXT_BYTES - 1, 1).unwrap(),
            MAX_ROTATION_PLAINTEXT_BYTES
        );
        assert_eq!(
            error_code(checked_rotation_plaintext_total(
                MAX_ROTATION_PLAINTEXT_BYTES,
                1,
            )),
            CredentialVaultErrorCode::LimitExceeded
        );
        assert_eq!(
            error_code(checked_rotation_plaintext_total(usize::MAX, 1)),
            CredentialVaultErrorCode::LimitExceeded
        );

        let (registry, policy) = enabled_policy();
        let old_key = CredentialVaultKey::from_bytes([0x41; 32]);
        let new_key = CredentialVaultKey::from_bytes([0x42; 32]);
        let first = encrypt_credential(
            &policy,
            &registry,
            DEVICE_A,
            &old_key,
            &CredentialSecret::new(CredentialSecretKind::SshPassword, "first-password".into())
                .unwrap(),
        )
        .unwrap();
        let second = encrypt_credential(
            &policy,
            &registry,
            DEVICE_A,
            &old_key,
            &CredentialSecret::new(CredentialSecretKind::AccessToken, "second-token".into())
                .unwrap(),
        )
        .unwrap();

        let rotated = reencrypt_credentials(
            &policy,
            &registry,
            DEVICE_A,
            &old_key,
            &new_key,
            &[first.clone(), second.clone()],
        )
        .unwrap();
        assert_eq!(rotated.len(), 2);
        assert_eq!(rotated[0].item_id, first.item_id);
        assert_eq!(rotated[1].item_id, second.item_id);
        assert_ne!(rotated[0].nonce, first.nonce);
        assert_ne!(rotated[1].nonce, second.nonce);
        assert_eq!(
            decrypt_credential(&policy, &registry, DEVICE_A, &new_key, &rotated[0])
                .unwrap()
                .expose_for_test(),
            "first-password"
        );
        assert_eq!(
            decrypt_credential(&policy, &registry, DEVICE_A, &new_key, &rotated[1])
                .unwrap()
                .expose_for_test(),
            "second-token"
        );
        assert!(decrypt_credential(&policy, &registry, DEVICE_A, &old_key, &rotated[0]).is_err());
        assert!(decrypt_credential(&policy, &registry, DEVICE_A, &old_key, &rotated[1]).is_err());

        let wrong_key = CredentialVaultKey::from_bytes([0x43; 32]);
        let late_wrong_key = encrypt_credential(
            &policy,
            &registry,
            DEVICE_A,
            &wrong_key,
            &CredentialSecret::new(CredentialSecretKind::AccessToken, "wrong-key-token".into())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            error_code(reencrypt_credentials(
                &policy,
                &registry,
                DEVICE_A,
                &old_key,
                &new_key,
                &[first.clone(), late_wrong_key],
            )),
            CredentialVaultErrorCode::Authentication
        );
        assert_eq!(
            error_code(reencrypt_credentials(
                &policy,
                &registry,
                DEVICE_A,
                &old_key,
                &new_key,
                &[first.clone(), first.clone()],
            )),
            CredentialVaultErrorCode::Conflict
        );
        let oversized = vec![first.clone(); MAX_ROTATION_ITEMS + 1];
        assert_eq!(
            error_code(reencrypt_credentials(
                &policy, &registry, DEVICE_A, &old_key, &new_key, &oversized,
            )),
            CredentialVaultErrorCode::LimitExceeded
        );

        let mut other_vault = second.clone();
        other_vault.vault_id = OTHER_VAULT.to_string();
        assert_eq!(
            error_code(reencrypt_credentials(
                &policy,
                &registry,
                DEVICE_A,
                &old_key,
                &new_key,
                &[first.clone(), other_vault],
            )),
            CredentialVaultErrorCode::Conflict
        );
        assert_eq!(
            error_code(reencrypt_credentials(
                &policy,
                &registry,
                DEVICE_A,
                &old_key,
                &new_key,
                &[],
            )),
            CredentialVaultErrorCode::LimitExceeded
        );
        assert_eq!(
            error_code(reencrypt_credentials(
                &policy,
                &registry,
                DEVICE_A,
                &old_key,
                &old_key,
                &[second],
            )),
            CredentialVaultErrorCode::InvalidInput
        );
    }
}

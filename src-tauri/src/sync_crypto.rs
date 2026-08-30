use std::collections::BTreeSet;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const FORMAT_VERSION: u32 = 1;
const KEY_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const MIN_PASSWORD_BYTES: usize = 8;
const MAX_PASSWORD_BYTES: usize = 1024;
const MIN_MEMORY_KIB: u32 = 19 * 1024;
const MAX_MEMORY_KIB: u32 = 256 * 1024;
const MIN_ITERATIONS: u32 = 2;
const MAX_ITERATIONS: u32 = 10;
const MAX_LANES: u32 = 4;
const MAX_OBJECT_ID_BYTES: usize = 256;
const MAX_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_KEYSLOT_BYTES: usize = 16 * 1024;
const MAX_ENVELOPE_BYTES: usize = 24 * 1024 * 1024;
const MAX_ROTATION_OBJECTS: usize = 10_000;
const MAX_ROTATION_PLAINTEXT_BYTES: usize = 256 * 1024 * 1024;
const ARGON2_VERSION: u32 = 0x13;
const KEYSLOT_ALGORITHM: &str = "argon2id+xchacha20poly1305";
const OBJECT_ALGORITHM: &str = "xchacha20poly1305";
const RECOVERY_KEYSLOT_ALGORITHM: &str = "hkdf-sha256+xchacha20poly1305";
const CREDENTIAL_RECOVERY_KEYSLOT_ALGORITHM: &str = "hkdf-sha256+xchacha20poly1305";
const CREDENTIAL_KEYSLOT_ALGORITHM: &str = "argon2id+xchacha20poly1305";
const RECOVERY_KEY_PREFIX: &str = "VPS1";

pub(crate) struct VaultKey([u8; KEY_BYTES]);

impl VaultKey {
    pub(crate) fn generate() -> Result<Self, String> {
        let mut bytes = [0_u8; KEY_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|_| "无法从操作系统安全随机源生成同步主密钥".to_string())?;
        Ok(Self(bytes))
    }

    pub(crate) fn same_material(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    #[cfg(test)]
    fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }
}

impl Drop for VaultKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) struct CredentialVaultKey([u8; KEY_BYTES]);

impl CredentialVaultKey {
    pub(crate) fn generate() -> Result<Self, String> {
        let mut bytes = [0_u8; KEY_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|_| "无法从操作系统安全随机源生成凭据 vault 密钥".to_string())?;
        Ok(Self(bytes))
    }

    pub(crate) fn key_material(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }
}

impl Drop for CredentialVaultKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) struct RecoveryKey([u8; KEY_BYTES]);

impl RecoveryKey {
    pub(crate) fn generate() -> Result<Self, String> {
        let mut bytes = [0_u8; KEY_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|_| "无法从操作系统安全随机源生成同步恢复密钥".to_string())?;
        Ok(Self(bytes))
    }

    pub(crate) fn export_string(&self) -> Zeroizing<String> {
        let encoded = URL_SAFE_NO_PAD.encode(self.0);
        let checksum = Sha256::digest(self.0);
        Zeroizing::new(format!(
            "{RECOVERY_KEY_PREFIX}-{encoded}-{}",
            hex_lower(&checksum[..4])
        ))
    }

    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        if value.len() > 64 || value.chars().any(char::is_control) {
            return Err("同步恢复密钥格式无效".to_string());
        }
        let body = value
            .strip_prefix(&format!("{RECOVERY_KEY_PREFIX}-"))
            .ok_or_else(|| "同步恢复密钥格式无效".to_string())?;
        let (encoded, checksum) = body
            .rsplit_once('-')
            .ok_or_else(|| "同步恢复密钥格式无效".to_string())?;
        if encoded.is_empty() || checksum.len() != 8 {
            return Err("同步恢复密钥格式无效".to_string());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "同步恢复密钥编码无效".to_string())?;
        if bytes.len() != KEY_BYTES {
            return Err("同步恢复密钥长度无效".to_string());
        }
        let expected = Sha256::digest(&bytes);
        let expected_checksum = hex_lower(&expected[..4]);
        if checksum != expected_checksum {
            return Err("同步恢复密钥校验码不匹配".to_string());
        }
        let mut key = [0_u8; KEY_BYTES];
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }

    #[cfg(test)]
    fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }
}

impl Drop for RecoveryKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RecoveryKeyslot {
    format_version: u32,
    vault_id: String,
    slot_id: String,
    key_domain: String,
    algorithm: String,
    nonce: String,
    wrapped_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialRecoveryKeyslot {
    format_version: u32,
    vault_id: String,
    slot_id: String,
    key_domain: String,
    algorithm: String,
    nonce: String,
    wrapped_key: String,
}

impl CredentialRecoveryKeyslot {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, String> {
        validate_credential_recovery_keyslot(self)?;
        let encoded =
            serde_json::to_vec(self).map_err(|_| "无法序列化凭据恢复 keyslot".to_string())?;
        if encoded.len() > MAX_KEYSLOT_BYTES {
            return Err("凭据恢复 keyslot 超过 16 KiB 上限".to_string());
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, String> {
        if encoded.is_empty() || encoded.len() > MAX_KEYSLOT_BYTES {
            return Err("凭据恢复 keyslot 为空或超过 16 KiB 上限".to_string());
        }
        let keyslot: Self = serde_json::from_slice(encoded)
            .map_err(|_| "凭据恢复 keyslot JSON 损坏或字段不受支持".to_string())?;
        validate_credential_recovery_keyslot(&keyslot)?;
        decode_exact::<NONCE_BYTES>(&keyslot.nonce, "凭据恢复 keyslot nonce")?;
        decode_exact::<{ KEY_BYTES + TAG_BYTES }>(
            &keyslot.wrapped_key,
            "凭据恢复 keyslot wrapped key",
        )?;
        Ok(keyslot)
    }

    pub(crate) fn vault_id(&self) -> &str {
        &self.vault_id
    }
}

impl RecoveryKeyslot {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, String> {
        validate_recovery_keyslot(self)?;
        let encoded =
            serde_json::to_vec(self).map_err(|_| "无法序列化同步 recovery keyslot".to_string())?;
        if encoded.len() > MAX_KEYSLOT_BYTES {
            return Err("同步 recovery keyslot 超过 16 KiB 上限".to_string());
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, String> {
        if encoded.is_empty() || encoded.len() > MAX_KEYSLOT_BYTES {
            return Err("同步 recovery keyslot 文件为空或超过 16 KiB 上限".to_string());
        }
        let keyslot: Self = serde_json::from_slice(encoded)
            .map_err(|_| "同步 recovery keyslot JSON 损坏或字段不受支持".to_string())?;
        validate_recovery_keyslot(&keyslot)?;
        decode_exact::<NONCE_BYTES>(&keyslot.nonce, "recovery keyslot nonce")?;
        decode_exact::<{ KEY_BYTES + TAG_BYTES }>(
            &keyslot.wrapped_key,
            "recovery keyslot wrapped key",
        )?;
        Ok(keyslot)
    }

    pub(crate) fn vault_id(&self) -> &str {
        &self.vault_id
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialKeyslot {
    format_version: u32,
    vault_id: String,
    slot_id: String,
    key_domain: String,
    algorithm: String,
    kdf: Argon2Parameters,
    salt: String,
    nonce: String,
    wrapped_key: String,
}

impl CredentialKeyslot {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, String> {
        validate_credential_keyslot(self)?;
        let encoded =
            serde_json::to_vec(self).map_err(|_| "无法序列化凭据 vault keyslot".to_string())?;
        if encoded.len() > MAX_KEYSLOT_BYTES {
            return Err("凭据 vault keyslot 超过 16 KiB 上限".to_string());
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, String> {
        if encoded.is_empty() || encoded.len() > MAX_KEYSLOT_BYTES {
            return Err("凭据 vault keyslot 为空或超过 16 KiB 上限".to_string());
        }
        let keyslot: Self = serde_json::from_slice(encoded)
            .map_err(|_| "凭据 vault keyslot JSON 损坏或字段不受支持".to_string())?;
        validate_credential_keyslot(&keyslot)?;
        decode_exact::<SALT_BYTES>(&keyslot.salt, "凭据 vault keyslot salt")?;
        decode_exact::<NONCE_BYTES>(&keyslot.nonce, "凭据 vault keyslot nonce")?;
        decode_exact::<{ KEY_BYTES + TAG_BYTES }>(
            &keyslot.wrapped_key,
            "凭据 vault keyslot wrapped key",
        )?;
        Ok(keyslot)
    }

    pub(crate) fn vault_id(&self) -> &str {
        &self.vault_id
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Argon2Parameters {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    output_bytes: u32,
}

impl Default for Argon2Parameters {
    fn default() -> Self {
        Self {
            algorithm: "argon2id".to_string(),
            version: ARGON2_VERSION,
            memory_kib: 64 * 1024,
            iterations: 3,
            lanes: 1,
            output_bytes: KEY_BYTES as u32,
        }
    }
}

impl Argon2Parameters {
    fn validate(&self) -> Result<(), String> {
        if self.algorithm != "argon2id"
            || self.version != ARGON2_VERSION
            || !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations)
            || !(1..=MAX_LANES).contains(&self.lanes)
            || self.output_bytes != KEY_BYTES as u32
        {
            return Err("同步 keyslot 的 Argon2id 参数或版本不受支持".to_string());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn minimum_for_tests() -> Self {
        Self {
            memory_kib: MIN_MEMORY_KIB,
            iterations: MIN_ITERATIONS,
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PasswordKeyslot {
    format_version: u32,
    vault_id: String,
    slot_id: String,
    key_domain: String,
    algorithm: String,
    kdf: Argon2Parameters,
    salt: String,
    nonce: String,
    wrapped_key: String,
}

impl PasswordKeyslot {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, String> {
        validate_keyslot(self)?;
        let encoded = serde_json::to_vec(self).map_err(|_| "无法序列化同步 keyslot".to_string())?;
        if encoded.len() > MAX_KEYSLOT_BYTES {
            return Err("同步 keyslot 超过 16 KiB 上限".to_string());
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, String> {
        if encoded.is_empty() || encoded.len() > MAX_KEYSLOT_BYTES {
            return Err("同步 keyslot 文件为空或超过 16 KiB 上限".to_string());
        }
        let keyslot: Self = serde_json::from_slice(encoded)
            .map_err(|_| "同步 keyslot JSON 损坏或字段不受支持".to_string())?;
        validate_keyslot(&keyslot)?;
        Ok(keyslot)
    }

    pub(crate) fn vault_id(&self) -> &str {
        &self.vault_id
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SyncObjectKind {
    Event,
    Blob,
    Index,
    Checkpoint,
    DeviceRegistry,
}

impl SyncObjectKind {
    fn domain_label(&self) -> &'static str {
        match self {
            Self::Event => "event",
            Self::Blob => "blob",
            Self::Index => "index",
            Self::Checkpoint => "checkpoint",
            Self::DeviceRegistry => "device-registry",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EncryptedSyncObject {
    format_version: u32,
    vault_id: String,
    object_kind: SyncObjectKind,
    object_id: String,
    device_id: Option<String>,
    sequence: Option<u64>,
    algorithm: String,
    nonce: String,
    ciphertext: String,
}

impl EncryptedSyncObject {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, String> {
        validate_encrypted_object(self)?;
        let encoded = serde_json::to_vec(self).map_err(|_| "无法序列化加密同步对象".to_string())?;
        if encoded.len() > MAX_ENVELOPE_BYTES {
            return Err("加密同步对象信封超过 24 MiB 上限".to_string());
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, String> {
        if encoded.is_empty() || encoded.len() > MAX_ENVELOPE_BYTES {
            return Err("加密同步对象信封为空或超过 24 MiB 上限".to_string());
        }
        let object: Self = serde_json::from_slice(encoded)
            .map_err(|_| "加密同步对象 JSON 损坏或字段不受支持".to_string())?;
        validate_encrypted_object(&object)?;
        decode_exact::<NONCE_BYTES>(&object.nonce, "同步对象 nonce")?;
        decode_bounded(
            &object.ciphertext,
            TAG_BYTES,
            MAX_PLAINTEXT_BYTES + TAG_BYTES,
            "同步对象密文",
        )?;
        Ok(object)
    }

    pub(crate) fn object_id(&self) -> &str {
        &self.object_id
    }

    pub(crate) fn object_kind(&self) -> &SyncObjectKind {
        &self.object_kind
    }

    pub(crate) fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub(crate) fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    pub(crate) fn sequence(&self) -> Option<u64> {
        self.sequence
    }
}

pub(crate) fn create_password_keyslot(
    password: &[u8],
    vault_id: &str,
    vault_key: &VaultKey,
    kdf: Argon2Parameters,
) -> Result<PasswordKeyslot, String> {
    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut salt)
        .map_err(|_| "无法从操作系统安全随机源生成 keyslot salt".to_string())?;
    getrandom::fill(&mut nonce)
        .map_err(|_| "无法从操作系统安全随机源生成 keyslot nonce".to_string())?;
    create_password_keyslot_with_material(
        password,
        vault_id,
        &uuid::Uuid::new_v4().to_string(),
        vault_key,
        kdf,
        salt,
        nonce,
    )
}

#[allow(clippy::too_many_arguments)]
fn create_password_keyslot_with_material(
    password: &[u8],
    vault_id: &str,
    slot_id: &str,
    vault_key: &VaultKey,
    kdf: Argon2Parameters,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
) -> Result<PasswordKeyslot, String> {
    validate_uuid(vault_id, "vault")?;
    validate_uuid(slot_id, "keyslot")?;
    kdf.validate()?;
    let kek = derive_password_key(password, &salt, &kdf)?;
    let aad = keyslot_aad(vault_id, slot_id, &kdf, KEY_BYTES + TAG_BYTES)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let wrapped_key = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &vault_key.0,
                aad: &aad,
            },
        )
        .map_err(|_| "无法包裹同步主密钥".to_string())?;
    Ok(PasswordKeyslot {
        format_version: FORMAT_VERSION,
        vault_id: vault_id.to_string(),
        slot_id: slot_id.to_string(),
        key_domain: "business".to_string(),
        algorithm: KEYSLOT_ALGORITHM.to_string(),
        kdf,
        salt: URL_SAFE_NO_PAD.encode(salt),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        wrapped_key: URL_SAFE_NO_PAD.encode(wrapped_key),
    })
}

pub(crate) fn open_password_keyslot(
    password: &[u8],
    keyslot: &PasswordKeyslot,
) -> Result<VaultKey, String> {
    validate_keyslot(keyslot)?;
    let salt = decode_exact::<SALT_BYTES>(&keyslot.salt, "keyslot salt")?;
    let nonce = decode_exact::<NONCE_BYTES>(&keyslot.nonce, "keyslot nonce")?;
    let wrapped = decode_bounded(
        &keyslot.wrapped_key,
        KEY_BYTES + TAG_BYTES,
        KEY_BYTES + TAG_BYTES,
        "包裹密钥",
    )?;
    let kek = derive_password_key(password, &salt, &keyslot.kdf)?;
    let aad = keyslot_aad(
        &keyslot.vault_id,
        &keyslot.slot_id,
        &keyslot.kdf,
        wrapped.len(),
    )?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &wrapped,
                    aad: &aad,
                },
            )
            .map_err(|_| "同步密码错误或 keyslot 已被篡改".to_string())?,
    );
    if plaintext.len() != KEY_BYTES {
        return Err("keyslot 解包后的主密钥长度无效".to_string());
    }
    let mut bytes = [0_u8; KEY_BYTES];
    bytes.copy_from_slice(&plaintext);
    Ok(VaultKey(bytes))
}

pub(crate) fn create_credential_keyslot(
    password: &[u8],
    vault_id: &str,
    credential_key: &CredentialVaultKey,
) -> Result<CredentialKeyslot, String> {
    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut salt).map_err(|_| "无法生成凭据 vault keyslot salt".to_string())?;
    getrandom::fill(&mut nonce).map_err(|_| "无法生成凭据 vault keyslot nonce".to_string())?;
    let slot_id = uuid::Uuid::new_v4().to_string();
    let kdf = Argon2Parameters::default();
    validate_uuid(vault_id, "vault")?;
    let kek = derive_password_key(password, &salt, &kdf)?;
    let aad = credential_keyslot_aad(vault_id, &slot_id, &kdf, KEY_BYTES + TAG_BYTES)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let wrapped_key = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &credential_key.0,
                aad: &aad,
            },
        )
        .map_err(|_| "无法包裹凭据 vault 密钥".to_string())?;
    Ok(CredentialKeyslot {
        format_version: FORMAT_VERSION,
        vault_id: vault_id.to_string(),
        slot_id,
        key_domain: "credentials".to_string(),
        algorithm: CREDENTIAL_KEYSLOT_ALGORITHM.to_string(),
        kdf,
        salt: URL_SAFE_NO_PAD.encode(salt),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        wrapped_key: URL_SAFE_NO_PAD.encode(wrapped_key),
    })
}

pub(crate) fn open_credential_keyslot(
    password: &[u8],
    keyslot: &CredentialKeyslot,
) -> Result<CredentialVaultKey, String> {
    validate_credential_keyslot(keyslot)?;
    let salt = decode_exact::<SALT_BYTES>(&keyslot.salt, "凭据 vault keyslot salt")?;
    let nonce = decode_exact::<NONCE_BYTES>(&keyslot.nonce, "凭据 vault keyslot nonce")?;
    let wrapped = decode_exact::<{ KEY_BYTES + TAG_BYTES }>(
        &keyslot.wrapped_key,
        "凭据 vault keyslot wrapped key",
    )?;
    let kek = derive_password_key(password, &salt, &keyslot.kdf)?;
    let aad = credential_keyslot_aad(
        &keyslot.vault_id,
        &keyslot.slot_id,
        &keyslot.kdf,
        wrapped.len(),
    )?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &wrapped,
                    aad: &aad,
                },
            )
            .map_err(|_| "凭据 vault 密码错误或 keyslot 已被篡改".to_string())?,
    );
    if plaintext.len() != KEY_BYTES {
        return Err("凭据 vault keyslot 解包长度无效".to_string());
    }
    let mut bytes = [0_u8; KEY_BYTES];
    bytes.copy_from_slice(&plaintext);
    Ok(CredentialVaultKey(bytes))
}

pub(crate) fn create_recovery_keyslot(
    recovery_key: &RecoveryKey,
    vault_id: &str,
    vault_key: &VaultKey,
) -> Result<RecoveryKeyslot, String> {
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce)
        .map_err(|_| "无法从操作系统安全随机源生成 recovery keyslot nonce".to_string())?;
    create_recovery_keyslot_with_nonce(
        recovery_key,
        vault_id,
        &uuid::Uuid::new_v4().to_string(),
        vault_key,
        nonce,
    )
}

fn create_recovery_keyslot_with_nonce(
    recovery_key: &RecoveryKey,
    vault_id: &str,
    slot_id: &str,
    vault_key: &VaultKey,
    nonce: [u8; NONCE_BYTES],
) -> Result<RecoveryKeyslot, String> {
    validate_uuid(vault_id, "vault")?;
    validate_uuid(slot_id, "recovery keyslot")?;
    let kek = derive_recovery_key(recovery_key, vault_id, slot_id)?;
    let aad = recovery_keyslot_aad(vault_id, slot_id, KEY_BYTES + TAG_BYTES)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let wrapped_key = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &vault_key.0,
                aad: &aad,
            },
        )
        .map_err(|_| "无法使用恢复密钥包裹同步主密钥".to_string())?;
    Ok(RecoveryKeyslot {
        format_version: FORMAT_VERSION,
        vault_id: vault_id.to_string(),
        slot_id: slot_id.to_string(),
        key_domain: "business-recovery".to_string(),
        algorithm: RECOVERY_KEYSLOT_ALGORITHM.to_string(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        wrapped_key: URL_SAFE_NO_PAD.encode(wrapped_key),
    })
}

pub(crate) fn open_recovery_keyslot(
    recovery_key: &RecoveryKey,
    keyslot: &RecoveryKeyslot,
) -> Result<VaultKey, String> {
    validate_recovery_keyslot(keyslot)?;
    let nonce = decode_exact::<NONCE_BYTES>(&keyslot.nonce, "recovery keyslot nonce")?;
    let wrapped = decode_exact::<{ KEY_BYTES + TAG_BYTES }>(
        &keyslot.wrapped_key,
        "recovery keyslot wrapped key",
    )?;
    let kek = derive_recovery_key(recovery_key, &keyslot.vault_id, &keyslot.slot_id)?;
    let aad = recovery_keyslot_aad(&keyslot.vault_id, &keyslot.slot_id, wrapped.len())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &wrapped,
                    aad: &aad,
                },
            )
            .map_err(|_| "同步恢复密钥错误或 keyslot 已被篡改".to_string())?,
    );
    if plaintext.len() != KEY_BYTES {
        return Err("recovery keyslot 解包后的主密钥长度无效".to_string());
    }
    let mut bytes = [0_u8; KEY_BYTES];
    bytes.copy_from_slice(&plaintext);
    Ok(VaultKey(bytes))
}

pub(crate) fn create_credential_recovery_keyslot(
    recovery_key: &RecoveryKey,
    vault_id: &str,
    credential_key: &CredentialVaultKey,
) -> Result<CredentialRecoveryKeyslot, String> {
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce)
        .map_err(|_| "无法从操作系统安全随机源生成凭据恢复 keyslot nonce".to_string())?;
    create_credential_recovery_keyslot_with_nonce(
        recovery_key,
        vault_id,
        &uuid::Uuid::new_v4().to_string(),
        credential_key,
        nonce,
    )
}

fn create_credential_recovery_keyslot_with_nonce(
    recovery_key: &RecoveryKey,
    vault_id: &str,
    slot_id: &str,
    credential_key: &CredentialVaultKey,
    nonce: [u8; NONCE_BYTES],
) -> Result<CredentialRecoveryKeyslot, String> {
    validate_uuid(vault_id, "vault")?;
    validate_uuid(slot_id, "credential recovery keyslot")?;
    let kek = derive_credential_recovery_key(recovery_key, vault_id, slot_id)?;
    let aad = credential_recovery_keyslot_aad(vault_id, slot_id, KEY_BYTES + TAG_BYTES)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let wrapped_key = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &credential_key.0,
                aad: &aad,
            },
        )
        .map_err(|_| "无法使用恢复密钥包裹凭据 vault 密钥".to_string())?;
    Ok(CredentialRecoveryKeyslot {
        format_version: FORMAT_VERSION,
        vault_id: vault_id.to_string(),
        slot_id: slot_id.to_string(),
        key_domain: "credential-recovery".to_string(),
        algorithm: CREDENTIAL_RECOVERY_KEYSLOT_ALGORITHM.to_string(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        wrapped_key: URL_SAFE_NO_PAD.encode(wrapped_key),
    })
}

pub(crate) fn open_credential_recovery_keyslot(
    recovery_key: &RecoveryKey,
    keyslot: &CredentialRecoveryKeyslot,
) -> Result<CredentialVaultKey, String> {
    validate_credential_recovery_keyslot(keyslot)?;
    let nonce = decode_exact::<NONCE_BYTES>(&keyslot.nonce, "凭据恢复 keyslot nonce")?;
    let wrapped = decode_exact::<{ KEY_BYTES + TAG_BYTES }>(
        &keyslot.wrapped_key,
        "凭据恢复 keyslot wrapped key",
    )?;
    let kek = derive_credential_recovery_key(recovery_key, &keyslot.vault_id, &keyslot.slot_id)?;
    let aad = credential_recovery_keyslot_aad(&keyslot.vault_id, &keyslot.slot_id, wrapped.len())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &wrapped,
                    aad: &aad,
                },
            )
            .map_err(|_| "同步凭据恢复密钥错误或 keyslot 已被篡改".to_string())?,
    );
    if plaintext.len() != KEY_BYTES {
        return Err("凭据恢复 keyslot 解包后的密钥长度无效".to_string());
    }
    let mut bytes = [0_u8; KEY_BYTES];
    bytes.copy_from_slice(&plaintext);
    Ok(CredentialVaultKey(bytes))
}

pub(crate) fn encrypt_sync_object(
    vault_key: &VaultKey,
    vault_id: &str,
    object_kind: SyncObjectKind,
    object_id: &str,
    device_id: Option<&str>,
    sequence: Option<u64>,
    plaintext: &[u8],
) -> Result<EncryptedSyncObject, String> {
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce)
        .map_err(|_| "无法从操作系统安全随机源生成同步对象 nonce".to_string())?;
    encrypt_sync_object_with_nonce(
        vault_key,
        vault_id,
        object_kind,
        object_id,
        device_id,
        sequence,
        plaintext,
        nonce,
    )
}

#[allow(clippy::too_many_arguments)]
fn encrypt_sync_object_with_nonce(
    vault_key: &VaultKey,
    vault_id: &str,
    object_kind: SyncObjectKind,
    object_id: &str,
    device_id: Option<&str>,
    sequence: Option<u64>,
    plaintext: &[u8],
    nonce: [u8; NONCE_BYTES],
) -> Result<EncryptedSyncObject, String> {
    validate_object_identity(vault_id, &object_kind, object_id, device_id, sequence)?;
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err("同步对象明文超过 16 MiB 上限".to_string());
    }
    let device_id = device_id.map(str::to_string);
    let ciphertext_length = plaintext
        .len()
        .checked_add(TAG_BYTES)
        .ok_or_else(|| "同步对象长度溢出".to_string())?;
    let aad = object_aad(
        vault_id,
        &object_kind,
        object_id,
        device_id.as_deref(),
        sequence,
        ciphertext_length,
    )?;
    let domain_key = derive_domain_key(vault_key, vault_id, &object_kind)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(domain_key.as_ref()));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| "无法加密同步对象".to_string())?;
    Ok(EncryptedSyncObject {
        format_version: FORMAT_VERSION,
        vault_id: vault_id.to_string(),
        object_kind,
        object_id: object_id.to_string(),
        device_id,
        sequence,
        algorithm: OBJECT_ALGORITHM.to_string(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub(crate) fn decrypt_sync_object(
    vault_key: &VaultKey,
    object: &EncryptedSyncObject,
) -> Result<Vec<u8>, String> {
    validate_encrypted_object(object)?;
    let nonce = decode_exact::<NONCE_BYTES>(&object.nonce, "同步对象 nonce")?;
    let ciphertext = decode_bounded(
        &object.ciphertext,
        TAG_BYTES,
        MAX_PLAINTEXT_BYTES + TAG_BYTES,
        "同步对象密文",
    )?;
    let aad = object_aad(
        &object.vault_id,
        &object.object_kind,
        &object.object_id,
        object.device_id.as_deref(),
        object.sequence,
        ciphertext.len(),
    )?;
    let domain_key = derive_domain_key(vault_key, &object.vault_id, &object.object_kind)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(domain_key.as_ref()));
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| "同步对象认证失败：密文、身份或域已被篡改".to_string())
}

pub(crate) fn reencrypt_sync_object(
    old_vault_key: &VaultKey,
    new_vault_key: &VaultKey,
    object: &EncryptedSyncObject,
) -> Result<EncryptedSyncObject, String> {
    if old_vault_key.0 == new_vault_key.0 {
        return Err("新旧同步主密钥必须不同".to_string());
    }
    let plaintext = Zeroizing::new(decrypt_sync_object(old_vault_key, object)?);
    encrypt_sync_object(
        new_vault_key,
        &object.vault_id,
        object.object_kind.clone(),
        &object.object_id,
        object.device_id.as_deref(),
        object.sequence,
        plaintext.as_ref(),
    )
}

pub(crate) fn reencrypt_sync_objects(
    old_vault_key: &VaultKey,
    new_vault_key: &VaultKey,
    objects: &[EncryptedSyncObject],
) -> Result<Vec<EncryptedSyncObject>, String> {
    if old_vault_key.0 == new_vault_key.0 {
        return Err("新旧同步主密钥必须不同".to_string());
    }
    if objects.is_empty() || objects.len() > MAX_ROTATION_OBJECTS {
        return Err("同步对象轮换批次必须为 1 至 10000 项".to_string());
    }

    let vault_id = objects[0].vault_id.as_str();
    let mut identities = BTreeSet::new();
    let mut total_plaintext_bytes = 0usize;
    let mut plaintexts = Vec::with_capacity(objects.len());
    for object in objects {
        if object.vault_id != vault_id {
            return Err("同步对象轮换批次不能跨 vault".to_string());
        }
        if !identities.insert((object.object_kind.domain_label(), object.object_id.as_str())) {
            return Err("同步对象轮换批次包含重复身份".to_string());
        }
        let plaintext = Zeroizing::new(decrypt_sync_object(old_vault_key, object)?);
        total_plaintext_bytes =
            checked_rotation_plaintext_total(total_plaintext_bytes, plaintext.len())?;
        plaintexts.push(plaintext);
    }

    objects
        .iter()
        .zip(plaintexts.iter())
        .map(|(object, plaintext)| {
            encrypt_sync_object(
                new_vault_key,
                &object.vault_id,
                object.object_kind.clone(),
                &object.object_id,
                object.device_id.as_deref(),
                object.sequence,
                plaintext.as_ref(),
            )
        })
        .collect()
}

fn checked_rotation_plaintext_total(current: usize, next: usize) -> Result<usize, String> {
    let total = current
        .checked_add(next)
        .ok_or_else(|| "同步对象轮换批次总明文长度溢出".to_string())?;
    if total > MAX_ROTATION_PLAINTEXT_BYTES {
        return Err("同步对象轮换批次总明文超过 256 MiB".to_string());
    }
    Ok(total)
}

fn validate_keyslot(keyslot: &PasswordKeyslot) -> Result<(), String> {
    if keyslot.format_version != FORMAT_VERSION
        || keyslot.key_domain != "business"
        || keyslot.algorithm != KEYSLOT_ALGORITHM
    {
        return Err("同步 keyslot 格式版本、密钥域或算法不受支持".to_string());
    }
    validate_uuid(&keyslot.vault_id, "vault")?;
    validate_uuid(&keyslot.slot_id, "keyslot")?;
    keyslot.kdf.validate()
}

fn validate_recovery_keyslot(keyslot: &RecoveryKeyslot) -> Result<(), String> {
    if keyslot.format_version != FORMAT_VERSION
        || keyslot.key_domain != "business-recovery"
        || keyslot.algorithm != RECOVERY_KEYSLOT_ALGORITHM
    {
        return Err("同步 recovery keyslot 格式版本、密钥域或算法不受支持".to_string());
    }
    validate_uuid(&keyslot.vault_id, "vault")?;
    validate_uuid(&keyslot.slot_id, "recovery keyslot")
}

fn validate_credential_recovery_keyslot(keyslot: &CredentialRecoveryKeyslot) -> Result<(), String> {
    if keyslot.format_version != FORMAT_VERSION
        || keyslot.key_domain != "credential-recovery"
        || keyslot.algorithm != CREDENTIAL_RECOVERY_KEYSLOT_ALGORITHM
    {
        return Err("凭据恢复 keyslot 格式版本、密钥域或算法不受支持".to_string());
    }
    validate_uuid(&keyslot.vault_id, "vault")?;
    validate_uuid(&keyslot.slot_id, "credential recovery keyslot")
}

fn validate_credential_keyslot(keyslot: &CredentialKeyslot) -> Result<(), String> {
    if keyslot.format_version != FORMAT_VERSION
        || keyslot.key_domain != "credentials"
        || keyslot.algorithm != CREDENTIAL_KEYSLOT_ALGORITHM
    {
        return Err("凭据 vault keyslot 版本、密钥域或算法不受支持".to_string());
    }
    validate_uuid(&keyslot.vault_id, "vault")?;
    validate_uuid(&keyslot.slot_id, "凭据 vault keyslot")?;
    keyslot.kdf.validate()
}

fn validate_encrypted_object(object: &EncryptedSyncObject) -> Result<(), String> {
    if object.format_version != FORMAT_VERSION || object.algorithm != OBJECT_ALGORITHM {
        return Err("同步对象格式版本或算法不受支持".to_string());
    }
    validate_object_identity(
        &object.vault_id,
        &object.object_kind,
        &object.object_id,
        object.device_id.as_deref(),
        object.sequence,
    )
}

fn validate_object_identity(
    vault_id: &str,
    kind: &SyncObjectKind,
    object_id: &str,
    device_id: Option<&str>,
    sequence: Option<u64>,
) -> Result<(), String> {
    validate_uuid(vault_id, "vault")?;
    if object_id.is_empty()
        || object_id.len() > MAX_OBJECT_ID_BYTES
        || !object_id.bytes().all(|value| {
            value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err("同步对象 ID 包含无效字符或长度超限".to_string());
    }
    if let Some(device_id) = device_id {
        validate_uuid(device_id, "device")?;
    }
    match kind {
        SyncObjectKind::Event | SyncObjectKind::Checkpoint
            if device_id.is_none() || sequence.is_none() || sequence == Some(0) =>
        {
            Err("事件与检查点对象必须绑定设备和正序号".to_string())
        }
        SyncObjectKind::DeviceRegistry if device_id.is_none() || sequence.is_some() => {
            Err("设备登记对象必须绑定设备且不能携带序号".to_string())
        }
        SyncObjectKind::Blob | SyncObjectKind::Index
            if device_id.is_some() || sequence.is_some() =>
        {
            Err("blob 与 index 对象不能伪装设备序列".to_string())
        }
        _ => Ok(()),
    }
}

fn derive_password_key(
    password: &[u8],
    salt: &[u8; SALT_BYTES],
    kdf: &Argon2Parameters,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, String> {
    if !(MIN_PASSWORD_BYTES..=MAX_PASSWORD_BYTES).contains(&password.len()) {
        return Err("同步密码必须为 8 到 1024 字节".to_string());
    }
    kdf.validate()?;
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.lanes, Some(KEY_BYTES))
        .map_err(|_| "无法建立受支持的 Argon2id 参数".to_string())?;
    let mut output = Zeroizing::new([0_u8; KEY_BYTES]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, output.as_mut())
        .map_err(|_| "Argon2id 密钥派生失败".to_string())?;
    Ok(output)
}

fn derive_domain_key(
    vault_key: &VaultKey,
    vault_id: &str,
    kind: &SyncObjectKind,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, String> {
    validate_uuid(vault_id, "vault")?;
    let salt = format!("vpshell-sync-v1/vault/{vault_id}");
    let info = format!("vpshell-sync-v1/domain/{}", kind.domain_label());
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &vault_key.0);
    let mut output = Zeroizing::new([0_u8; KEY_BYTES]);
    hkdf.expand(info.as_bytes(), output.as_mut())
        .map_err(|_| "同步对象域密钥派生失败".to_string())?;
    Ok(output)
}

fn derive_recovery_key(
    recovery_key: &RecoveryKey,
    vault_id: &str,
    slot_id: &str,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, String> {
    validate_uuid(vault_id, "vault")?;
    validate_uuid(slot_id, "recovery keyslot")?;
    let salt = format!("vpshell-sync-v1/recovery/{vault_id}");
    let info = format!("vpshell-sync-v1/recovery-keyslot/{slot_id}");
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &recovery_key.0);
    let mut output = Zeroizing::new([0_u8; KEY_BYTES]);
    hkdf.expand(info.as_bytes(), output.as_mut())
        .map_err(|_| "同步恢复 KEK 派生失败".to_string())?;
    Ok(output)
}

fn derive_credential_recovery_key(
    recovery_key: &RecoveryKey,
    vault_id: &str,
    slot_id: &str,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, String> {
    validate_uuid(vault_id, "vault")?;
    validate_uuid(slot_id, "credential recovery keyslot")?;
    let salt = format!("vpshell-sync-v1/credential-recovery/{vault_id}");
    let info = format!("vpshell-sync-v1/credential-recovery-keyslot/{slot_id}");
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &recovery_key.0);
    let mut output = Zeroizing::new([0_u8; KEY_BYTES]);
    hkdf.expand(info.as_bytes(), output.as_mut())
        .map_err(|_| "凭据恢复 KEK 派生失败".to_string())?;
    Ok(output)
}

fn keyslot_aad(
    vault_id: &str,
    slot_id: &str,
    kdf: &Argon2Parameters,
    wrapped_length: usize,
) -> Result<Vec<u8>, String> {
    let mut aad = b"VPSHELL-KEYSLOT-V1".to_vec();
    push_field(&mut aad, vault_id.as_bytes())?;
    push_field(&mut aad, slot_id.as_bytes())?;
    push_field(&mut aad, b"business")?;
    push_field(&mut aad, KEYSLOT_ALGORITHM.as_bytes())?;
    push_field(&mut aad, kdf.algorithm.as_bytes())?;
    aad.extend_from_slice(&kdf.version.to_be_bytes());
    aad.extend_from_slice(&kdf.memory_kib.to_be_bytes());
    aad.extend_from_slice(&kdf.iterations.to_be_bytes());
    aad.extend_from_slice(&kdf.lanes.to_be_bytes());
    aad.extend_from_slice(&kdf.output_bytes.to_be_bytes());
    aad.extend_from_slice(&(wrapped_length as u64).to_be_bytes());
    Ok(aad)
}

fn recovery_keyslot_aad(
    vault_id: &str,
    slot_id: &str,
    wrapped_length: usize,
) -> Result<Vec<u8>, String> {
    let mut aad = b"VPSHELL-RECOVERY-KEYSLOT-V1".to_vec();
    push_field(&mut aad, vault_id.as_bytes())?;
    push_field(&mut aad, slot_id.as_bytes())?;
    push_field(&mut aad, b"business-recovery")?;
    push_field(&mut aad, RECOVERY_KEYSLOT_ALGORITHM.as_bytes())?;
    aad.extend_from_slice(&(wrapped_length as u64).to_be_bytes());
    Ok(aad)
}

fn credential_recovery_keyslot_aad(
    vault_id: &str,
    slot_id: &str,
    wrapped_length: usize,
) -> Result<Vec<u8>, String> {
    let mut aad = b"VPSHELL-CREDENTIAL-RECOVERY-KEYSLOT-V1".to_vec();
    push_field(&mut aad, vault_id.as_bytes())?;
    push_field(&mut aad, slot_id.as_bytes())?;
    push_field(&mut aad, b"credential-recovery")?;
    push_field(&mut aad, CREDENTIAL_RECOVERY_KEYSLOT_ALGORITHM.as_bytes())?;
    aad.extend_from_slice(&(wrapped_length as u64).to_be_bytes());
    Ok(aad)
}

fn credential_keyslot_aad(
    vault_id: &str,
    slot_id: &str,
    kdf: &Argon2Parameters,
    wrapped_length: usize,
) -> Result<Vec<u8>, String> {
    let mut aad = b"VPSHELL-CREDENTIAL-KEYSLOT-V1".to_vec();
    push_field(&mut aad, vault_id.as_bytes())?;
    push_field(&mut aad, slot_id.as_bytes())?;
    push_field(&mut aad, b"credentials")?;
    push_field(&mut aad, CREDENTIAL_KEYSLOT_ALGORITHM.as_bytes())?;
    push_field(&mut aad, kdf.algorithm.as_bytes())?;
    aad.extend_from_slice(&kdf.version.to_be_bytes());
    aad.extend_from_slice(&kdf.memory_kib.to_be_bytes());
    aad.extend_from_slice(&kdf.iterations.to_be_bytes());
    aad.extend_from_slice(&kdf.lanes.to_be_bytes());
    aad.extend_from_slice(&kdf.output_bytes.to_be_bytes());
    aad.extend_from_slice(&(wrapped_length as u64).to_be_bytes());
    Ok(aad)
}

fn object_aad(
    vault_id: &str,
    kind: &SyncObjectKind,
    object_id: &str,
    device_id: Option<&str>,
    sequence: Option<u64>,
    ciphertext_length: usize,
) -> Result<Vec<u8>, String> {
    let mut aad = b"VPSHELL-OBJECT-V1".to_vec();
    push_field(&mut aad, vault_id.as_bytes())?;
    push_field(&mut aad, kind.domain_label().as_bytes())?;
    push_field(&mut aad, object_id.as_bytes())?;
    push_field(&mut aad, device_id.unwrap_or("").as_bytes())?;
    aad.extend_from_slice(&sequence.unwrap_or(0).to_be_bytes());
    aad.extend_from_slice(&(ciphertext_length as u64).to_be_bytes());
    push_field(&mut aad, OBJECT_ALGORITHM.as_bytes())?;
    Ok(aad)
}

fn push_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let length: u32 = value
        .len()
        .try_into()
        .map_err(|_| "同步认证头字段长度溢出".to_string())?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn validate_uuid(value: &str, label: &str) -> Result<(), String> {
    let parsed =
        uuid::Uuid::parse_str(value).map_err(|_| format!("同步 {label} ID 必须是规范 UUID"))?;
    if parsed.to_string() != value {
        return Err(format!("同步 {label} ID 必须是小写规范 UUID"));
    }
    Ok(())
}

fn decode_exact<const N: usize>(encoded: &str, label: &str) -> Result<[u8; N], String> {
    let decoded = decode_bounded(encoded, N, N, label)?;
    decoded.try_into().map_err(|_| format!("{label} 长度无效"))
}

fn decode_bounded(
    encoded: &str,
    minimum: usize,
    maximum: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let maximum_encoded = maximum.saturating_add(2) / 3 * 4;
    if encoded.is_empty() || encoded.len() > maximum_encoded {
        return Err(format!("{label} 编码长度无效"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| format!("{label} 不是规范 base64url"))?;
    if !(minimum..=maximum).contains(&decoded.len()) || URL_SAFE_NO_PAD.encode(&decoded) != encoded
    {
        return Err(format!("{label} 长度或编码不规范"));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT_ID: &str = "11111111-2222-4333-8444-555555555555";
    const DEVICE_ID: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const SLOT_ID: &str = "01234567-89ab-4cde-8fab-0123456789ab";

    fn key() -> VaultKey {
        VaultKey::from_bytes([0x42; KEY_BYTES])
    }

    #[test]
    fn password_keyslot_round_trips_and_rejects_wrong_password_or_tampering() {
        let password = b"correct horse battery staple";
        let slot = create_password_keyslot_with_material(
            password,
            VAULT_ID,
            SLOT_ID,
            &key(),
            Argon2Parameters::minimum_for_tests(),
            [0x11; SALT_BYTES],
            [0x22; NONCE_BYTES],
        )
        .expect("create keyslot");
        let encoded = slot.encode().expect("encode keyslot");
        assert_eq!(PasswordKeyslot::decode(&encoded).unwrap(), slot);
        assert_eq!(
            open_password_keyslot(password, &slot).unwrap().0,
            [0x42; KEY_BYTES]
        );
        assert!(open_password_keyslot(b"wrong password", &slot).is_err());

        let mut tampered = slot.clone();
        tampered.slot_id = "01234567-89ab-4cde-8fab-0123456789ac".to_string();
        assert!(open_password_keyslot(password, &tampered).is_err());
        let mut truncated = slot;
        truncated.wrapped_key.pop();
        assert!(open_password_keyslot(password, &truncated).is_err());
        let with_unknown =
            String::from_utf8(encoded)
                .unwrap()
                .replacen('{', "{\"unknown\":true,", 1);
        assert!(PasswordKeyslot::decode(with_unknown.as_bytes()).is_err());
    }

    #[test]
    fn object_domains_round_trip_and_identity_relocation_fails_authentication() {
        let cases = [
            (SyncObjectKind::Event, Some(DEVICE_ID), Some(7)),
            (SyncObjectKind::Blob, None, None),
            (SyncObjectKind::Index, None, None),
            (SyncObjectKind::Checkpoint, Some(DEVICE_ID), Some(8)),
            (SyncObjectKind::DeviceRegistry, Some(DEVICE_ID), None),
        ];
        for (index, (kind, device, sequence)) in cases.into_iter().enumerate() {
            let object = encrypt_sync_object_with_nonce(
                &key(),
                VAULT_ID,
                kind,
                &format!("object-{index}"),
                device,
                sequence,
                b"bounded plaintext",
                [index as u8 + 1; NONCE_BYTES],
            )
            .expect("encrypt object");
            let encoded = object.encode().expect("encode object");
            assert_eq!(EncryptedSyncObject::decode(&encoded).unwrap(), object);
            assert_eq!(
                decrypt_sync_object(&key(), &object).expect("decrypt object"),
                b"bounded plaintext"
            );
            let mut relocated = object;
            relocated.object_id.push('x');
            assert!(decrypt_sync_object(&key(), &relocated).is_err());
        }
    }

    #[test]
    fn domain_separation_and_tampering_are_detected() {
        let object = encrypt_sync_object_with_nonce(
            &key(),
            VAULT_ID,
            SyncObjectKind::Blob,
            "blob-1",
            None,
            None,
            b"image bytes",
            [0x33; NONCE_BYTES],
        )
        .unwrap();
        let mut wrong_domain = object.clone();
        wrong_domain.object_kind = SyncObjectKind::Index;
        assert!(decrypt_sync_object(&key(), &wrong_domain).is_err());
        let mut ciphertext = URL_SAFE_NO_PAD.decode(&object.ciphertext).unwrap();
        ciphertext[0] ^= 1;
        let mut tampered = object;
        tampered.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
        assert!(decrypt_sync_object(&key(), &tampered).is_err());
    }

    #[test]
    fn versions_kdf_costs_identities_and_sizes_are_strictly_bounded() {
        let mut params = Argon2Parameters::minimum_for_tests();
        params.memory_kib = MAX_MEMORY_KIB + 1;
        assert!(params.validate().is_err());
        assert!(
            derive_password_key(b"short", &[0; SALT_BYTES], &Argon2Parameters::default()).is_err()
        );
        assert!(validate_uuid("AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", "device").is_err());
        assert!(
            validate_object_identity(VAULT_ID, &SyncObjectKind::Event, "event", None, Some(1))
                .is_err()
        );
        assert!(
            encrypt_sync_object(
                &key(),
                VAULT_ID,
                SyncObjectKind::Blob,
                "blob",
                None,
                None,
                &vec![0; MAX_PLAINTEXT_BYTES + 1],
            )
            .is_err()
        );
    }

    #[test]
    fn deterministic_v1_vectors_remain_stable() {
        let slot = create_password_keyslot_with_material(
            b"vector password",
            VAULT_ID,
            SLOT_ID,
            &key(),
            Argon2Parameters::minimum_for_tests(),
            [0x11; SALT_BYTES],
            [0x22; NONCE_BYTES],
        )
        .unwrap();
        assert_eq!(slot.salt, "EREREREREREREREREREREQ");
        assert_eq!(slot.nonce, "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi");
        assert_eq!(
            slot.wrapped_key,
            "PRmGiIBztA-8tDSFVYXc2y6nKUEser8NQK0yjMRrIfGlGk6wTjD-bXENX_T5bahq"
        );

        let object = encrypt_sync_object_with_nonce(
            &key(),
            VAULT_ID,
            SyncObjectKind::Event,
            "event-7",
            Some(DEVICE_ID),
            Some(7),
            b"vpshell sync vector",
            [0x33; NONCE_BYTES],
        )
        .unwrap();
        assert_eq!(object.nonce, "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz");
        assert_eq!(
            object.ciphertext,
            "zS2H3yEbsRxLSM1hOi13uYbfqiS-tj6_pNwXaqUvXBsogio"
        );
    }

    #[test]
    fn recovery_keys_are_printable_checked_and_use_an_independent_keyslot() {
        let recovery = RecoveryKey::from_bytes([0x44; KEY_BYTES]);
        let exported = recovery.export_string();
        assert!(exported.starts_with("VPS1-"));
        let parsed = RecoveryKey::parse(&exported).expect("parse exported recovery key");
        let vault_key = VaultKey::from_bytes([0x11; KEY_BYTES]);
        let slot = create_recovery_keyslot_with_nonce(
            &parsed,
            VAULT_ID,
            "44444444-4444-4444-8444-444444444444",
            &vault_key,
            [0x55; NONCE_BYTES],
        )
        .expect("create recovery keyslot");
        let encoded = slot.encode().expect("encode recovery keyslot");
        assert_eq!(RecoveryKeyslot::decode(&encoded).unwrap(), slot);
        let opened = open_recovery_keyslot(&parsed, &slot).expect("open recovery keyslot");
        assert_eq!(opened.0, vault_key.0);

        let wrong = RecoveryKey::from_bytes([0x45; KEY_BYTES]);
        assert!(open_recovery_keyslot(&wrong, &slot).is_err());
        let mut tampered = slot;
        let mut wrapped = URL_SAFE_NO_PAD.decode(&tampered.wrapped_key).unwrap();
        wrapped[0] ^= 0x80;
        tampered.wrapped_key = URL_SAFE_NO_PAD.encode(wrapped);
        assert!(open_recovery_keyslot(&parsed, &tampered).is_err());

        let mut bad_checksum = exported.to_string();
        bad_checksum.pop();
        bad_checksum.push('0');
        assert!(RecoveryKey::parse(&bad_checksum).is_err());
        assert!(RecoveryKey::parse("VPS1-not-a-key-00000000").is_err());

        let contains_separator = RecoveryKey::from_bytes([0xfb; KEY_BYTES]);
        let exported = contains_separator.export_string();
        assert!(exported[5..exported.len() - 9].contains('-'));
        assert_eq!(
            contains_separator.0,
            RecoveryKey::parse(&exported).unwrap().0
        );
    }

    #[test]
    fn credential_recovery_keyslot_is_domain_separated_and_round_trips() {
        let recovery = RecoveryKey::from_bytes([0x64; KEY_BYTES]);
        let credential = CredentialVaultKey::from_bytes([0x27; KEY_BYTES]);
        let slot = create_credential_recovery_keyslot_with_nonce(
            &recovery,
            VAULT_ID,
            "55555555-5555-4555-8555-555555555555",
            &credential,
            [0x66; NONCE_BYTES],
        )
        .expect("create credential recovery keyslot");
        assert_eq!(slot.key_domain, "credential-recovery");
        assert_eq!(slot.algorithm, CREDENTIAL_RECOVERY_KEYSLOT_ALGORITHM);
        let encoded = slot.encode().expect("encode credential recovery keyslot");
        assert_eq!(CredentialRecoveryKeyslot::decode(&encoded).unwrap(), slot);
        let opened = open_credential_recovery_keyslot(&recovery, &slot)
            .expect("open credential recovery keyslot");
        assert_eq!(opened.key_material(), credential.key_material());

        let wrong = RecoveryKey::from_bytes([0x65; KEY_BYTES]);
        assert!(open_credential_recovery_keyslot(&wrong, &slot).is_err());

        let mut tampered = slot.clone();
        tampered.key_domain = "business-recovery".to_string();
        assert!(tampered.encode().is_err());
        assert!(RecoveryKeyslot::decode(&encoded).is_err());

        let mut identity_tampered = slot.clone();
        identity_tampered.vault_id = "22222222-2222-4222-8222-222222222222".to_string();
        assert!(open_credential_recovery_keyslot(&recovery, &identity_tampered).is_err());

        let mut wrapped_tampered = slot;
        let mut wrapped = URL_SAFE_NO_PAD
            .decode(&wrapped_tampered.wrapped_key)
            .expect("decode wrapped key");
        wrapped[0] ^= 0x01;
        wrapped_tampered.wrapped_key = URL_SAFE_NO_PAD.encode(wrapped);
        assert!(open_credential_recovery_keyslot(&recovery, &wrapped_tampered).is_err());
    }

    #[test]
    fn reencrypt_sync_object_authenticates_old_key_and_preserves_identity() {
        let old_key = VaultKey::from_bytes([0x11; KEY_BYTES]);
        let new_key = VaultKey::from_bytes([0x22; KEY_BYTES]);
        let object = encrypt_sync_object_with_nonce(
            &old_key,
            VAULT_ID,
            SyncObjectKind::Event,
            "event-rotate",
            Some(DEVICE_ID),
            Some(9),
            b"rotation payload",
            [0x71; NONCE_BYTES],
        )
        .unwrap();
        let rotated = reencrypt_sync_object(&old_key, &new_key, &object).unwrap();
        assert_eq!(rotated.vault_id, object.vault_id);
        assert_eq!(rotated.object_id, object.object_id);
        assert_eq!(rotated.object_kind, object.object_kind);
        assert_eq!(rotated.device_id, object.device_id);
        assert_eq!(rotated.sequence, object.sequence);
        assert_ne!(rotated.nonce, object.nonce);
        assert_eq!(
            decrypt_sync_object(&new_key, &rotated).unwrap(),
            b"rotation payload"
        );
        assert!(decrypt_sync_object(&old_key, &rotated).is_err());
        let wrong = VaultKey::from_bytes([0x33; KEY_BYTES]);
        assert!(reencrypt_sync_object(&wrong, &new_key, &object).is_err());
        assert!(reencrypt_sync_object(&old_key, &old_key, &object).is_err());
    }

    #[test]
    fn reencrypt_sync_object_batch_authenticates_every_item_before_rotation() {
        assert_eq!(
            checked_rotation_plaintext_total(MAX_ROTATION_PLAINTEXT_BYTES - 1, 1).unwrap(),
            MAX_ROTATION_PLAINTEXT_BYTES
        );
        assert!(checked_rotation_plaintext_total(MAX_ROTATION_PLAINTEXT_BYTES, 1).is_err());
        assert!(checked_rotation_plaintext_total(usize::MAX, 1).is_err());

        let old_key = VaultKey::from_bytes([0x41; KEY_BYTES]);
        let new_key = VaultKey::from_bytes([0x42; KEY_BYTES]);
        let first = encrypt_sync_object_with_nonce(
            &old_key,
            VAULT_ID,
            SyncObjectKind::Event,
            "event-batch-rotate",
            Some(DEVICE_ID),
            Some(21),
            b"first rotation payload",
            [0x51; NONCE_BYTES],
        )
        .unwrap();
        let second = encrypt_sync_object_with_nonce(
            &old_key,
            VAULT_ID,
            SyncObjectKind::Blob,
            "blob-batch-rotate",
            None,
            None,
            b"second rotation payload",
            [0x52; NONCE_BYTES],
        )
        .unwrap();

        let rotated =
            reencrypt_sync_objects(&old_key, &new_key, &[first.clone(), second.clone()]).unwrap();
        assert_eq!(rotated.len(), 2);
        assert_eq!(rotated[0].object_id, first.object_id);
        assert_eq!(rotated[1].object_id, second.object_id);
        assert_ne!(rotated[0].nonce, first.nonce);
        assert_ne!(rotated[1].nonce, second.nonce);
        assert_eq!(
            decrypt_sync_object(&new_key, &rotated[0]).unwrap(),
            b"first rotation payload"
        );
        assert_eq!(
            decrypt_sync_object(&new_key, &rotated[1]).unwrap(),
            b"second rotation payload"
        );
        assert!(decrypt_sync_object(&old_key, &rotated[0]).is_err());
        assert!(decrypt_sync_object(&old_key, &rotated[1]).is_err());

        let wrong_key = VaultKey::from_bytes([0x43; KEY_BYTES]);
        let late_wrong_key = encrypt_sync_object_with_nonce(
            &wrong_key,
            VAULT_ID,
            SyncObjectKind::Index,
            "index-wrong-key",
            None,
            None,
            b"wrong key payload",
            [0x53; NONCE_BYTES],
        )
        .unwrap();
        assert!(
            reencrypt_sync_objects(&old_key, &new_key, &[first.clone(), late_wrong_key]).is_err()
        );
        assert!(
            reencrypt_sync_objects(&old_key, &new_key, &[first.clone(), first.clone()]).is_err()
        );
        let oversized = vec![first.clone(); MAX_ROTATION_OBJECTS + 1];
        assert!(reencrypt_sync_objects(&old_key, &new_key, &oversized).is_err());

        let other_vault = encrypt_sync_object_with_nonce(
            &old_key,
            "22222222-2222-4222-8222-222222222222",
            SyncObjectKind::Blob,
            "blob-other-vault",
            None,
            None,
            b"other vault payload",
            [0x54; NONCE_BYTES],
        )
        .unwrap();
        assert!(reencrypt_sync_objects(&old_key, &new_key, &[first, other_vault]).is_err());
        assert!(reencrypt_sync_objects(&old_key, &new_key, &[]).is_err());
        assert!(reencrypt_sync_objects(&old_key, &old_key, &[second]).is_err());
    }
}

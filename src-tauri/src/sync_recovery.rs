use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    sync_crypto::{
        EncryptedSyncObject, PasswordKeyslot, RecoveryKey, RecoveryKeyslot, SyncObjectKind,
        VaultKey, decrypt_sync_object, encrypt_sync_object, open_recovery_keyslot,
    },
    sync_merge::MergeOperation,
    sync_provider::validate_key,
};

const REGISTRY_FORMAT_VERSION: u32 = 1;
const EXPORT_FORMAT_VERSION: u32 = 1;
const MAX_REGISTRY_BYTES: usize = 64 * 1024;
const MAX_DEVICES: usize = 32;
const MAX_DEVICE_LABEL_BYTES: usize = 128;
const MAX_KEYSLOTS: usize = 8;
const MAX_EXPORT_OBJECTS: usize = 10_000;
const MAX_EXPORT_OBJECT_BYTES: usize = 24 * 1024 * 1024;
const MAX_EXPORT_CONTENT_BYTES: usize = 256 * 1024 * 1024;
const MAX_EXPORT_PACKAGE_BYTES: usize = 384 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryErrorCode {
    InvalidInput,
    Conflict,
    LimitExceeded,
    NotFound,
    Authentication,
    Integrity,
    Storage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryError {
    pub(crate) code: RecoveryErrorCode,
    pub(crate) message: String,
}

impl RecoveryError {
    fn new(code: RecoveryErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

type RecoveryResult<T> = Result<T, RecoveryError>;

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RevocationReason {
    Lost,
    Stolen,
    Retired,
    Compromised,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "camelCase")]
pub(crate) enum DeviceStatus {
    Active,
    Revoked {
        revoked_at_ms: i64,
        reason: RevocationReason,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeviceRecord {
    device_id: String,
    label: String,
    label_updated_at_ms: i64,
    public_signing_key: String,
    added_at_ms: i64,
    status: DeviceStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeviceRegistry {
    format_version: u32,
    vault_id: String,
    revision: u64,
    devices: BTreeMap<String, DeviceRecord>,
}

impl DeviceRegistry {
    pub(crate) fn new(
        vault_id: &str,
        device_id: &str,
        label: &str,
        public_signing_key: &[u8; 32],
        now_ms: i64,
    ) -> RecoveryResult<Self> {
        validate_uuid(vault_id, "vault")?;
        let record = device_record(device_id, label, public_signing_key, now_ms)?;
        let registry = Self {
            format_version: REGISTRY_FORMAT_VERSION,
            vault_id: vault_id.to_string(),
            revision: 1,
            devices: BTreeMap::from([(device_id.to_string(), record)]),
        };
        validate_registry(&registry)?;
        Ok(registry)
    }

    pub(crate) fn encode(&self) -> RecoveryResult<Vec<u8>> {
        validate_registry(self)?;
        let encoded = serde_json::to_vec(self).map_err(|_| {
            RecoveryError::new(
                RecoveryErrorCode::InvalidInput,
                "无法序列化同步设备 registry",
            )
        })?;
        if encoded.len() > MAX_REGISTRY_BYTES {
            return Err(RecoveryError::new(
                RecoveryErrorCode::LimitExceeded,
                "同步设备 registry 超过 64 KiB",
            ));
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> RecoveryResult<Self> {
        if encoded.is_empty() || encoded.len() > MAX_REGISTRY_BYTES {
            return Err(RecoveryError::new(
                RecoveryErrorCode::LimitExceeded,
                "同步设备 registry 必须为 1 字节至 64 KiB",
            ));
        }
        let registry: Self = serde_json::from_slice(encoded).map_err(|_| {
            RecoveryError::new(
                RecoveryErrorCode::InvalidInput,
                "同步设备 registry JSON 损坏或字段不受支持",
            )
        })?;
        validate_registry(&registry)?;
        Ok(registry)
    }

    pub(crate) fn add_device(
        &mut self,
        expected_revision: u64,
        device_id: &str,
        label: &str,
        public_signing_key: &[u8; 32],
        now_ms: i64,
    ) -> RecoveryResult<u64> {
        self.require_revision(expected_revision)?;
        if self.devices.contains_key(device_id) {
            return Err(RecoveryError::new(
                RecoveryErrorCode::Conflict,
                "同步设备 ID 已存在且不能替换公钥",
            ));
        }
        if self.devices.len() >= MAX_DEVICES {
            return Err(RecoveryError::new(
                RecoveryErrorCode::LimitExceeded,
                "同步设备最多 32 台",
            ));
        }
        let record = device_record(device_id, label, public_signing_key, now_ms)?;
        self.revision = self.revision.checked_add(1).ok_or_else(|| {
            RecoveryError::new(
                RecoveryErrorCode::LimitExceeded,
                "设备 registry revision 已耗尽",
            )
        })?;
        self.devices.insert(device_id.to_string(), record);
        Ok(self.revision)
    }

    pub(crate) fn rename_device(
        &mut self,
        expected_revision: u64,
        device_id: &str,
        label: &str,
        now_ms: i64,
    ) -> RecoveryResult<u64> {
        self.require_revision(expected_revision)?;
        validate_label(label)?;
        validate_time(now_ms)?;
        let device = self
            .devices
            .get_mut(device_id)
            .ok_or_else(|| RecoveryError::new(RecoveryErrorCode::NotFound, "同步设备不存在"))?;
        if matches!(device.status, DeviceStatus::Revoked { .. }) {
            return Err(RecoveryError::new(
                RecoveryErrorCode::Conflict,
                "已撤销设备不能修改",
            ));
        }
        if now_ms < device.label_updated_at_ms {
            return Err(RecoveryError::new(
                RecoveryErrorCode::Conflict,
                "设备标签时间早于当前版本",
            ));
        }
        device.label = label.to_string();
        device.label_updated_at_ms = now_ms;
        self.revision = self.revision.checked_add(1).ok_or_else(|| {
            RecoveryError::new(
                RecoveryErrorCode::LimitExceeded,
                "设备 registry revision 已耗尽",
            )
        })?;
        Ok(self.revision)
    }

    pub(crate) fn revoke_device(
        &mut self,
        expected_revision: u64,
        device_id: &str,
        reason: RevocationReason,
        now_ms: i64,
    ) -> RecoveryResult<u64> {
        self.require_revision(expected_revision)?;
        validate_time(now_ms)?;
        if self
            .devices
            .values()
            .filter(|record| matches!(record.status, DeviceStatus::Active))
            .count()
            <= 1
        {
            return Err(RecoveryError::new(
                RecoveryErrorCode::Conflict,
                "不能撤销最后一台活动同步设备；请先登记替代设备",
            ));
        }
        let device = self
            .devices
            .get_mut(device_id)
            .ok_or_else(|| RecoveryError::new(RecoveryErrorCode::NotFound, "同步设备不存在"))?;
        if matches!(device.status, DeviceStatus::Revoked { .. }) {
            return Err(RecoveryError::new(
                RecoveryErrorCode::Conflict,
                "同步设备已撤销，不能重新激活或重复撤销",
            ));
        }
        if now_ms < device.added_at_ms {
            return Err(RecoveryError::new(
                RecoveryErrorCode::InvalidInput,
                "设备撤销时间早于添加时间",
            ));
        }
        device.status = DeviceStatus::Revoked {
            revoked_at_ms: now_ms,
            reason,
        };
        self.revision = self.revision.checked_add(1).ok_or_else(|| {
            RecoveryError::new(
                RecoveryErrorCode::LimitExceeded,
                "设备 registry revision 已耗尽",
            )
        })?;
        Ok(self.revision)
    }

    pub(crate) fn merge(&self, other: &Self) -> RecoveryResult<Self> {
        validate_registry(self)?;
        validate_registry(other)?;
        if self.vault_id != other.vault_id {
            return Err(RecoveryError::new(
                RecoveryErrorCode::Conflict,
                "不能合并不同 vault 的设备 registry",
            ));
        }
        let mut devices = self.devices.clone();
        for (device_id, incoming) in &other.devices {
            match devices.get(device_id) {
                None => {
                    devices.insert(device_id.clone(), incoming.clone());
                }
                Some(existing) => {
                    if existing.public_signing_key != incoming.public_signing_key
                        || existing.added_at_ms != incoming.added_at_ms
                    {
                        return Err(RecoveryError::new(
                            RecoveryErrorCode::Integrity,
                            "相同设备 ID 的公钥或添加身份不同",
                        ));
                    }
                    devices.insert(device_id.clone(), merge_device(existing, incoming));
                }
            }
        }
        if devices.len() > MAX_DEVICES {
            return Err(RecoveryError::new(
                RecoveryErrorCode::LimitExceeded,
                "合并后的同步设备超过 32 台",
            ));
        }
        let revision = if devices != self.devices && devices != other.devices {
            self.revision
                .max(other.revision)
                .checked_add(1)
                .ok_or_else(|| {
                    RecoveryError::new(
                        RecoveryErrorCode::LimitExceeded,
                        "合并后的设备 registry revision 已耗尽",
                    )
                })?
        } else {
            self.revision.max(other.revision)
        };
        let merged = Self {
            format_version: REGISTRY_FORMAT_VERSION,
            vault_id: self.vault_id.clone(),
            revision,
            devices,
        };
        validate_registry(&merged)?;
        Ok(merged)
    }

    pub(crate) fn is_authorized(&self, device_id: &str) -> bool {
        self.devices
            .get(device_id)
            .is_some_and(|device| matches!(device.status, DeviceStatus::Active))
    }

    pub(crate) fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub(crate) fn requires_key_rotation(&self) -> bool {
        self.devices
            .values()
            .any(|device| matches!(device.status, DeviceStatus::Revoked { .. }))
    }

    fn require_revision(&self, expected: u64) -> RecoveryResult<()> {
        if self.revision != expected {
            Err(RecoveryError::new(
                RecoveryErrorCode::Conflict,
                format!(
                    "设备 registry revision 冲突：当前 {}，请求 {expected}",
                    self.revision
                ),
            ))
        } else {
            Ok(())
        }
    }
}

fn device_record(
    device_id: &str,
    label: &str,
    public_signing_key: &[u8; 32],
    now_ms: i64,
) -> RecoveryResult<DeviceRecord> {
    validate_uuid(device_id, "device")?;
    validate_label(label)?;
    validate_time(now_ms)?;
    Ok(DeviceRecord {
        device_id: device_id.to_string(),
        label: label.to_string(),
        label_updated_at_ms: now_ms,
        public_signing_key: URL_SAFE_NO_PAD.encode(public_signing_key),
        added_at_ms: now_ms,
        status: DeviceStatus::Active,
    })
}

fn merge_device(left: &DeviceRecord, right: &DeviceRecord) -> DeviceRecord {
    let label_source = if (left.label_updated_at_ms, left.label.as_str())
        >= (right.label_updated_at_ms, right.label.as_str())
    {
        left
    } else {
        right
    };
    let status = match (&left.status, &right.status) {
        (DeviceStatus::Active, DeviceStatus::Active) => DeviceStatus::Active,
        (DeviceStatus::Revoked { .. }, DeviceStatus::Active) => left.status.clone(),
        (DeviceStatus::Active, DeviceStatus::Revoked { .. }) => right.status.clone(),
        (
            DeviceStatus::Revoked {
                revoked_at_ms: left_at,
                reason: left_reason,
            },
            DeviceStatus::Revoked {
                revoked_at_ms: right_at,
                reason: right_reason,
            },
        ) => {
            let (revoked_at_ms, reason) = if (left_at, left_reason) <= (right_at, right_reason) {
                (*left_at, left_reason.clone())
            } else {
                (*right_at, right_reason.clone())
            };
            DeviceStatus::Revoked {
                revoked_at_ms,
                reason,
            }
        }
    };
    DeviceRecord {
        device_id: left.device_id.clone(),
        label: label_source.label.clone(),
        label_updated_at_ms: label_source.label_updated_at_ms,
        public_signing_key: left.public_signing_key.clone(),
        added_at_ms: left.added_at_ms,
        status,
    }
}

fn validate_registry(registry: &DeviceRegistry) -> RecoveryResult<()> {
    if registry.format_version != REGISTRY_FORMAT_VERSION
        || registry.revision == 0
        || registry.devices.is_empty()
        || registry.devices.len() > MAX_DEVICES
    {
        return Err(RecoveryError::new(
            RecoveryErrorCode::InvalidInput,
            "设备 registry 版本、revision 或数量无效",
        ));
    }
    validate_uuid(&registry.vault_id, "vault")?;
    let mut active_devices = 0usize;
    for (device_id, record) in &registry.devices {
        if device_id != &record.device_id {
            return Err(RecoveryError::new(
                RecoveryErrorCode::Integrity,
                "设备 registry map key 与记录不匹配",
            ));
        }
        validate_uuid(device_id, "device")?;
        validate_label(&record.label)?;
        validate_time(record.label_updated_at_ms)?;
        validate_time(record.added_at_ms)?;
        decode_exact_32(&record.public_signing_key, "设备签名公钥")?;
        if record.label_updated_at_ms < record.added_at_ms {
            return Err(RecoveryError::new(
                RecoveryErrorCode::InvalidInput,
                "设备标签时间早于添加时间",
            ));
        }
        if let DeviceStatus::Revoked { revoked_at_ms, .. } = record.status {
            validate_time(revoked_at_ms)?;
            if revoked_at_ms < record.added_at_ms || record.label_updated_at_ms > revoked_at_ms {
                return Err(RecoveryError::new(
                    RecoveryErrorCode::InvalidInput,
                    "设备撤销时间早于添加或最后标签更新时间",
                ));
            }
        } else {
            active_devices += 1;
        }
    }
    if active_devices == 0 {
        return Err(RecoveryError::new(
            RecoveryErrorCode::Conflict,
            "设备 registry 必须保留至少一台活动设备",
        ));
    }
    Ok(())
}

pub(crate) fn encrypt_device_registry(
    registry: &DeviceRegistry,
    vault_key: &VaultKey,
    publishing_device_id: &str,
) -> RecoveryResult<EncryptedSyncObject> {
    if !registry.is_authorized(publishing_device_id) {
        return Err(RecoveryError::new(
            RecoveryErrorCode::Conflict,
            "只有未撤销设备可以发布 device registry",
        ));
    }
    encrypt_sync_object(
        vault_key,
        &registry.vault_id,
        SyncObjectKind::DeviceRegistry,
        &format!("device-registry-{}", registry.revision),
        Some(publishing_device_id),
        None,
        &registry.encode()?,
    )
    .map_err(|_| {
        RecoveryError::new(
            RecoveryErrorCode::Authentication,
            "无法加密 device registry",
        )
    })
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportObject {
    key: String,
    sha256: String,
    envelope: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportBody {
    format_version: u32,
    export_id: String,
    vault_id: String,
    created_at_ms: i64,
    recovery_keyslot: String,
    password_keyslots: Vec<String>,
    objects: Vec<ExportObject>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EncryptedExportPackage {
    body: ExportBody,
    manifest_sha256: String,
}

impl EncryptedExportPackage {
    pub(crate) fn create(
        vault_id: &str,
        recovery_keyslot: &RecoveryKeyslot,
        password_keyslots: &[PasswordKeyslot],
        objects: Vec<(String, Vec<u8>)>,
        now_ms: i64,
    ) -> RecoveryResult<Self> {
        validate_uuid(vault_id, "vault")?;
        validate_time(now_ms)?;
        if recovery_keyslot.vault_id() != vault_id || password_keyslots.len() > MAX_KEYSLOTS {
            return Err(RecoveryError::new(
                RecoveryErrorCode::InvalidInput,
                "导出 keyslot 的 vault 或数量无效",
            ));
        }
        let recovery_keyslot = URL_SAFE_NO_PAD.encode(recovery_keyslot.encode().map_err(|_| {
            RecoveryError::new(RecoveryErrorCode::InvalidInput, "恢复 keyslot 无效")
        })?);
        let mut password_encoded = Vec::with_capacity(password_keyslots.len());
        for keyslot in password_keyslots {
            if keyslot.vault_id() != vault_id {
                return Err(RecoveryError::new(
                    RecoveryErrorCode::InvalidInput,
                    "密码 keyslot 属于其他 vault",
                ));
            }
            password_encoded.push(URL_SAFE_NO_PAD.encode(keyslot.encode().map_err(|_| {
                RecoveryError::new(RecoveryErrorCode::InvalidInput, "密码 keyslot 无效")
            })?));
        }
        if objects.is_empty() || objects.len() > MAX_EXPORT_OBJECTS {
            return Err(RecoveryError::new(
                RecoveryErrorCode::LimitExceeded,
                "加密导出对象必须为 1 至 10000 项",
            ));
        }
        let mut total = 0usize;
        let mut keys = BTreeSet::new();
        let mut hashes = BTreeSet::new();
        let mut exported = Vec::with_capacity(objects.len());
        let mut registry_count = 0usize;
        for (key, encoded) in objects {
            validate_key(&key).map_err(|_| {
                RecoveryError::new(RecoveryErrorCode::InvalidInput, "导出 object key 无效")
            })?;
            if encoded.is_empty() || encoded.len() > MAX_EXPORT_OBJECT_BYTES {
                return Err(RecoveryError::new(
                    RecoveryErrorCode::LimitExceeded,
                    "导出对象超过 24 MiB",
                ));
            }
            total = total.checked_add(encoded.len()).ok_or_else(|| {
                RecoveryError::new(RecoveryErrorCode::LimitExceeded, "导出总大小溢出")
            })?;
            if total > MAX_EXPORT_CONTENT_BYTES {
                return Err(RecoveryError::new(
                    RecoveryErrorCode::LimitExceeded,
                    "导出密文总量超过 256 MiB",
                ));
            }
            let envelope = EncryptedSyncObject::decode(&encoded).map_err(|_| {
                RecoveryError::new(RecoveryErrorCode::InvalidInput, "导出对象信封无效")
            })?;
            if envelope.vault_id() != vault_id {
                return Err(RecoveryError::new(
                    RecoveryErrorCode::Conflict,
                    "导出对象属于其他 vault",
                ));
            }
            if matches!(envelope.object_kind(), SyncObjectKind::DeviceRegistry) {
                registry_count += 1;
            }
            let hash = sha256_hex(&encoded);
            if !keys.insert(key.clone()) || !hashes.insert(hash.clone()) {
                return Err(RecoveryError::new(
                    RecoveryErrorCode::Conflict,
                    "导出对象 key 或密文哈希重复",
                ));
            }
            exported.push(ExportObject {
                key,
                sha256: hash,
                envelope: URL_SAFE_NO_PAD.encode(encoded),
            });
        }
        if registry_count != 1 {
            return Err(RecoveryError::new(
                RecoveryErrorCode::InvalidInput,
                "加密导出必须且只能包含一个 device registry",
            ));
        }
        exported.sort_by(|left, right| left.key.cmp(&right.key));
        let body = ExportBody {
            format_version: EXPORT_FORMAT_VERSION,
            export_id: Uuid::new_v4().to_string(),
            vault_id: vault_id.to_string(),
            created_at_ms: now_ms,
            recovery_keyslot,
            password_keyslots: password_encoded,
            objects: exported,
        };
        let manifest_sha256 = body_hash(&body)?;
        Ok(Self {
            body,
            manifest_sha256,
        })
    }

    pub(crate) fn encode(&self) -> RecoveryResult<Vec<u8>> {
        validate_package(self)?;
        let encoded = serde_json::to_vec(self).map_err(|_| {
            RecoveryError::new(RecoveryErrorCode::InvalidInput, "无法序列化加密导出包")
        })?;
        if encoded.len() > MAX_EXPORT_PACKAGE_BYTES {
            return Err(RecoveryError::new(
                RecoveryErrorCode::LimitExceeded,
                "加密导出包超过 384 MiB",
            ));
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> RecoveryResult<Self> {
        if encoded.is_empty() || encoded.len() > MAX_EXPORT_PACKAGE_BYTES {
            return Err(RecoveryError::new(
                RecoveryErrorCode::LimitExceeded,
                "加密导出包必须为 1 字节至 384 MiB",
            ));
        }
        let package: Self = serde_json::from_slice(encoded).map_err(|_| {
            RecoveryError::new(
                RecoveryErrorCode::InvalidInput,
                "加密导出包 JSON 损坏或字段不受支持",
            )
        })?;
        validate_package(&package)?;
        Ok(package)
    }
}

fn validate_package(package: &EncryptedExportPackage) -> RecoveryResult<()> {
    let body = &package.body;
    if body.format_version != EXPORT_FORMAT_VERSION
        || body.password_keyslots.len() > MAX_KEYSLOTS
        || body.objects.is_empty()
        || body.objects.len() > MAX_EXPORT_OBJECTS
    {
        return Err(RecoveryError::new(
            RecoveryErrorCode::InvalidInput,
            "加密导出包版本或数量无效",
        ));
    }
    validate_uuid(&body.export_id, "export")?;
    validate_uuid(&body.vault_id, "vault")?;
    validate_time(body.created_at_ms)?;
    if body_hash(body)? != package.manifest_sha256 {
        return Err(RecoveryError::new(
            RecoveryErrorCode::Integrity,
            "加密导出 manifest 哈希不匹配",
        ));
    }
    let recovery = decode_canonical(&body.recovery_keyslot, 16 * 1024, "recovery keyslot")?;
    if RecoveryKeyslot::decode(&recovery)
        .map_err(|_| RecoveryError::new(RecoveryErrorCode::InvalidInput, "恢复 keyslot 无效"))?
        .vault_id()
        != body.vault_id
    {
        return Err(RecoveryError::new(
            RecoveryErrorCode::Conflict,
            "恢复 keyslot 属于其他 vault",
        ));
    }
    for encoded in &body.password_keyslots {
        let bytes = decode_canonical(encoded, 16 * 1024, "password keyslot")?;
        if PasswordKeyslot::decode(&bytes)
            .map_err(|_| RecoveryError::new(RecoveryErrorCode::InvalidInput, "密码 keyslot 无效"))?
            .vault_id()
            != body.vault_id
        {
            return Err(RecoveryError::new(
                RecoveryErrorCode::Conflict,
                "密码 keyslot 属于其他 vault",
            ));
        }
    }
    let mut keys = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    let mut total = 0usize;
    let mut registries = 0usize;
    for object in &body.objects {
        validate_key(&object.key).map_err(|_| {
            RecoveryError::new(RecoveryErrorCode::InvalidInput, "导出 object key 无效")
        })?;
        validate_sha256(&object.sha256)?;
        let bytes = decode_canonical(&object.envelope, MAX_EXPORT_OBJECT_BYTES, "导出对象")?;
        total = total.checked_add(bytes.len()).ok_or_else(|| {
            RecoveryError::new(RecoveryErrorCode::LimitExceeded, "导出总大小溢出")
        })?;
        if total > MAX_EXPORT_CONTENT_BYTES || sha256_hex(&bytes) != object.sha256 {
            return Err(RecoveryError::new(
                RecoveryErrorCode::Integrity,
                "导出对象大小或 SHA-256 不匹配",
            ));
        }
        let envelope = EncryptedSyncObject::decode(&bytes)
            .map_err(|_| RecoveryError::new(RecoveryErrorCode::InvalidInput, "导出对象信封无效"))?;
        if envelope.vault_id() != body.vault_id {
            return Err(RecoveryError::new(
                RecoveryErrorCode::Conflict,
                "导出对象属于其他 vault",
            ));
        }
        if matches!(envelope.object_kind(), SyncObjectKind::DeviceRegistry) {
            registries += 1;
        }
        if !keys.insert(object.key.clone()) || !hashes.insert(object.sha256.clone()) {
            return Err(RecoveryError::new(
                RecoveryErrorCode::Conflict,
                "导出对象 key 或哈希重复",
            ));
        }
    }
    if registries != 1 {
        return Err(RecoveryError::new(
            RecoveryErrorCode::InvalidInput,
            "加密导出必须且只能包含一个 device registry",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryDrillReport {
    pub(crate) vault_id: String,
    pub(crate) verified_objects: usize,
    pub(crate) verified_events: usize,
    pub(crate) active_devices: usize,
    pub(crate) revoked_devices: usize,
    pub(crate) requires_key_rotation: bool,
}

pub(crate) fn run_recovery_drill(
    package: &EncryptedExportPackage,
    recovery_key: &RecoveryKey,
) -> RecoveryResult<RecoveryDrillReport> {
    validate_package(package)?;
    let recovery_bytes = decode_canonical(
        &package.body.recovery_keyslot,
        16 * 1024,
        "recovery keyslot",
    )?;
    let keyslot = RecoveryKeyslot::decode(&recovery_bytes)
        .map_err(|_| RecoveryError::new(RecoveryErrorCode::InvalidInput, "恢复 keyslot 无效"))?;
    let vault_key = open_recovery_keyslot(recovery_key, &keyslot).map_err(|_| {
        RecoveryError::new(
            RecoveryErrorCode::Authentication,
            "恢复密钥错误或恢复 keyslot 已被篡改",
        )
    })?;
    let mut events = 0usize;
    let mut registry: Option<DeviceRegistry> = None;
    for exported in &package.body.objects {
        let bytes = decode_canonical(&exported.envelope, MAX_EXPORT_OBJECT_BYTES, "导出对象")?;
        let envelope = EncryptedSyncObject::decode(&bytes)
            .map_err(|_| RecoveryError::new(RecoveryErrorCode::InvalidInput, "导出对象信封无效"))?;
        let plaintext = decrypt_sync_object(&vault_key, &envelope).map_err(|_| {
            RecoveryError::new(RecoveryErrorCode::Authentication, "恢复演练对象认证失败")
        })?;
        match envelope.object_kind() {
            SyncObjectKind::Event => {
                MergeOperation::decode(&plaintext).map_err(|_| {
                    RecoveryError::new(
                        RecoveryErrorCode::Integrity,
                        "恢复演练 event operation 无效",
                    )
                })?;
                events += 1;
            }
            SyncObjectKind::DeviceRegistry => {
                if registry.is_some() {
                    return Err(RecoveryError::new(
                        RecoveryErrorCode::Integrity,
                        "恢复演练发现多个 device registry",
                    ));
                }
                let decoded = DeviceRegistry::decode(&plaintext)?;
                if decoded.vault_id != package.body.vault_id {
                    return Err(RecoveryError::new(
                        RecoveryErrorCode::Integrity,
                        "恢复演练 device registry vault 不匹配",
                    ));
                }
                let publisher = envelope.device_id().ok_or_else(|| {
                    RecoveryError::new(
                        RecoveryErrorCode::Integrity,
                        "恢复演练 device registry 缺少发布设备",
                    )
                })?;
                if !decoded.is_authorized(publisher) {
                    return Err(RecoveryError::new(
                        RecoveryErrorCode::Integrity,
                        "恢复演练 device registry 由已撤销或未知设备发布",
                    ));
                }
                registry = Some(decoded);
            }
            SyncObjectKind::Blob | SyncObjectKind::Index | SyncObjectKind::Checkpoint => {}
        }
    }
    let registry = registry.ok_or_else(|| {
        RecoveryError::new(RecoveryErrorCode::Integrity, "恢复演练缺少 device registry")
    })?;
    let active_devices = registry
        .devices
        .values()
        .filter(|device| matches!(device.status, DeviceStatus::Active))
        .count();
    let revoked_devices = registry.devices.len().saturating_sub(active_devices);
    Ok(RecoveryDrillReport {
        vault_id: package.body.vault_id.clone(),
        verified_objects: package.body.objects.len(),
        verified_events: events,
        active_devices,
        revoked_devices,
        requires_key_rotation: registry.requires_key_rotation(),
    })
}

pub(crate) fn write_export_atomic(path: &Path, encoded: &[u8]) -> RecoveryResult<()> {
    EncryptedExportPackage::decode(encoded)?;
    if path.as_os_str().is_empty() || encoded.len() > MAX_EXPORT_PACKAGE_BYTES {
        return Err(RecoveryError::new(
            RecoveryErrorCode::InvalidInput,
            "加密导出目标或大小无效",
        ));
    }
    if fs::symlink_metadata(path).is_ok() {
        return Err(RecoveryError::new(
            RecoveryErrorCode::Conflict,
            "加密导出目标已存在，拒绝覆盖",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        RecoveryError::new(RecoveryErrorCode::InvalidInput, "加密导出目标缺少父目录")
    })?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|_| RecoveryError::new(RecoveryErrorCode::Storage, "加密导出父目录不存在"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RecoveryError::new(
            RecoveryErrorCode::InvalidInput,
            "加密导出父目录不能是符号链接或文件",
        ));
    }
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| RecoveryError::new(RecoveryErrorCode::Storage, "无法生成加密导出暂存名"))?;
    let stage = parent.join(format!(".vpshell-export-{}.tmp", hex_lower(&random)));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&stage).map_err(|_| {
            RecoveryError::new(RecoveryErrorCode::Storage, "无法创建加密导出暂存文件")
        })?;
        for chunk in encoded.chunks(64 * 1024) {
            file.write_all(chunk).map_err(|_| {
                RecoveryError::new(RecoveryErrorCode::Storage, "无法写入加密导出暂存文件")
            })?;
        }
        file.sync_all().map_err(|_| {
            RecoveryError::new(RecoveryErrorCode::Storage, "无法同步加密导出暂存文件")
        })?;
        drop(file);
        fs::hard_link(&stage, path).map_err(|error| {
            RecoveryError::new(
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    RecoveryErrorCode::Conflict
                } else {
                    RecoveryErrorCode::Storage
                },
                "无法无覆盖提交加密导出文件",
            )
        })?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| {
                RecoveryError::new(RecoveryErrorCode::Storage, "无法同步加密导出父目录")
            })?;
        Ok(())
    })();
    let _ = fs::remove_file(&stage);
    result
}

pub(crate) fn read_export(path: &Path) -> RecoveryResult<EncryptedExportPackage> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| RecoveryError::new(RecoveryErrorCode::NotFound, "加密导出文件不存在"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_EXPORT_PACKAGE_BYTES as u64
    {
        return Err(RecoveryError::new(
            RecoveryErrorCode::InvalidInput,
            "加密导出必须是大小受限的普通文件",
        ));
    }
    let mut file = File::open(path)
        .map_err(|_| RecoveryError::new(RecoveryErrorCode::Storage, "无法打开加密导出文件"))?;
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| RecoveryError::new(RecoveryErrorCode::Storage, "无法读取加密导出文件"))?;
        if count == 0 {
            break;
        }
        if encoded.len().saturating_add(count) > MAX_EXPORT_PACKAGE_BYTES {
            return Err(RecoveryError::new(
                RecoveryErrorCode::LimitExceeded,
                "加密导出读取超过 384 MiB",
            ));
        }
        encoded.extend_from_slice(&buffer[..count]);
    }
    EncryptedExportPackage::decode(&encoded)
}

fn body_hash(body: &ExportBody) -> RecoveryResult<String> {
    serde_json::to_vec(body)
        .map(|encoded| sha256_hex(&encoded))
        .map_err(|_| RecoveryError::new(RecoveryErrorCode::InvalidInput, "无法计算导出 manifest"))
}

fn decode_canonical(value: &str, maximum: usize, label: &str) -> RecoveryResult<Vec<u8>> {
    if value.is_empty() || value.len() > maximum.saturating_mul(4) / 3 + 8 {
        return Err(RecoveryError::new(
            RecoveryErrorCode::LimitExceeded,
            format!("{label} base64url 超过限制"),
        ));
    }
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        RecoveryError::new(
            RecoveryErrorCode::InvalidInput,
            format!("{label} base64url 无效"),
        )
    })?;
    if decoded.len() > maximum || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(RecoveryError::new(
            RecoveryErrorCode::InvalidInput,
            format!("{label} base64url 非 canonical 或超过限制"),
        ));
    }
    Ok(decoded)
}

fn decode_exact_32(value: &str, label: &str) -> RecoveryResult<[u8; 32]> {
    let decoded = decode_canonical(value, 32, label)?;
    if decoded.len() != 32 {
        return Err(RecoveryError::new(
            RecoveryErrorCode::InvalidInput,
            format!("{label} 长度无效"),
        ));
    }
    let mut output = [0u8; 32];
    output.copy_from_slice(&decoded);
    Ok(output)
}

fn validate_label(value: &str) -> RecoveryResult<()> {
    if value.is_empty()
        || value.len() > MAX_DEVICE_LABEL_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(RecoveryError::new(
            RecoveryErrorCode::InvalidInput,
            "设备标签必须为 1 至 128 字节且不含控制字符",
        ));
    }
    Ok(())
}

fn validate_time(value: i64) -> RecoveryResult<()> {
    if value < 0 {
        Err(RecoveryError::new(
            RecoveryErrorCode::InvalidInput,
            "同步恢复时间不能为负数",
        ))
    } else {
        Ok(())
    }
}

fn validate_uuid(value: &str, label: &str) -> RecoveryResult<()> {
    let parsed = Uuid::parse_str(value).map_err(|_| {
        RecoveryError::new(RecoveryErrorCode::InvalidInput, format!("{label} ID 无效"))
    })?;
    if parsed.to_string() != value {
        return Err(RecoveryError::new(
            RecoveryErrorCode::InvalidInput,
            format!("{label} ID 必须是 canonical lowercase UUID"),
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> RecoveryResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RecoveryError::new(
            RecoveryErrorCode::InvalidInput,
            "导出 SHA-256 必须为 lowercase hex",
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const VAULT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const DEVICE_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const DEVICE_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const ENTITY_ID: &str = "22222222-2222-4222-8222-222222222222";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("vpshell-export-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn operation() -> MergeOperation {
        serde_json::from_value(serde_json::json!({
            "formatVersion": 1,
            "operationId": "33333333-3333-4333-8333-333333333333",
            "deviceId": DEVICE_A,
            "sequence": 1,
            "hlc": {"physicalMs": 1, "logical": 0},
            "payload": {
                "kind": "patch",
                "payload": {
                    "entityKind": "setting",
                    "entityId": ENTITY_ID,
                    "fields": {"fontSize": {"type": "integer", "value": 14}},
                    "observedFields": {"fontSize": null},
                    "observedTombstone": null
                }
            }
        }))
        .unwrap()
    }

    fn fixture() -> (
        VaultKey,
        RecoveryKey,
        RecoveryKeyslot,
        DeviceRegistry,
        Vec<(String, Vec<u8>)>,
    ) {
        let vault_key = VaultKey::generate().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        let recovery_slot =
            crate::sync_crypto::create_recovery_keyslot(&recovery_key, VAULT_ID, &vault_key)
                .unwrap();
        let registry = DeviceRegistry::new(VAULT_ID, DEVICE_A, "Laptop", &[1; 32], 1).unwrap();
        let registry_object = encrypt_device_registry(&registry, &vault_key, DEVICE_A)
            .unwrap()
            .encode()
            .unwrap();
        let event_object = encrypt_sync_object(
            &vault_key,
            VAULT_ID,
            SyncObjectKind::Event,
            "event-one",
            Some(DEVICE_A),
            Some(1),
            &operation().encode().unwrap(),
        )
        .unwrap()
        .encode()
        .unwrap();
        (
            vault_key,
            recovery_key,
            recovery_slot,
            registry,
            vec![
                ("devices/registry.odev".into(), registry_object),
                ("segments/device/1.oseg".into(), event_object),
            ],
        )
    }

    #[test]
    fn device_revocation_is_monotonic_merged_and_requires_rotation() {
        let mut registry = DeviceRegistry::new(VAULT_ID, DEVICE_A, "Laptop", &[1; 32], 1).unwrap();
        assert_eq!(
            registry
                .revoke_device(1, DEVICE_A, RevocationReason::Retired, 2)
                .unwrap_err()
                .code,
            RecoveryErrorCode::Conflict
        );
        registry
            .add_device(1, DEVICE_B, "Phone", &[2; 32], 2)
            .unwrap();
        let active = registry.clone();
        registry
            .revoke_device(2, DEVICE_B, RevocationReason::Lost, 3)
            .unwrap();
        assert!(!registry.is_authorized(DEVICE_B));
        assert!(registry.requires_key_rotation());
        assert!(
            registry
                .revoke_device(3, DEVICE_B, RevocationReason::Retired, 4)
                .is_err()
        );
        assert!(registry.rename_device(3, DEVICE_B, "Again", 4).is_err());
        let merged = active.merge(&registry).unwrap();
        assert_eq!(merged, registry);
        assert_eq!(registry.merge(&active).unwrap(), registry);

        let mut forged = active;
        forged.devices.get_mut(DEVICE_B).unwrap().public_signing_key =
            URL_SAFE_NO_PAD.encode([9; 32]);
        assert_eq!(
            registry.merge(&forged).unwrap_err().code,
            RecoveryErrorCode::Integrity
        );
        assert_eq!(
            DeviceRegistry::decode(&registry.encode().unwrap()).unwrap(),
            registry
        );

        let mut invalid: serde_json::Value =
            serde_json::from_slice(&registry.encode().unwrap()).unwrap();
        invalid["devices"][DEVICE_B]["labelUpdatedAtMs"] = serde_json::json!(4);
        assert!(DeviceRegistry::decode(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }

    #[test]
    fn encrypted_export_drill_decrypts_and_parses_every_required_object() {
        let (_vault_key, recovery_key, recovery_slot, _registry, objects) = fixture();
        let package =
            EncryptedExportPackage::create(VAULT_ID, &recovery_slot, &[], objects, 10).unwrap();
        let encoded = package.encode().unwrap();
        let decoded = EncryptedExportPackage::decode(&encoded).unwrap();
        let report = run_recovery_drill(&decoded, &recovery_key).unwrap();
        assert_eq!(report.verified_objects, 2);
        assert_eq!(report.verified_events, 1);
        assert_eq!(report.active_devices, 1);
        assert_eq!(report.revoked_devices, 0);
        assert!(!report.requires_key_rotation);

        let wrong = RecoveryKey::generate().unwrap();
        assert_eq!(
            run_recovery_drill(&decoded, &wrong).unwrap_err().code,
            RecoveryErrorCode::Authentication
        );
    }

    #[test]
    fn export_rejects_tampering_truncation_duplicates_and_other_vaults() {
        let (vault_key, recovery_key, recovery_slot, _registry, objects) = fixture();
        let package =
            EncryptedExportPackage::create(VAULT_ID, &recovery_slot, &[], objects.clone(), 10)
                .unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&package.encode().unwrap()).unwrap();
        value["body"]["createdAtMs"] = serde_json::json!(11);
        assert_eq!(
            EncryptedExportPackage::decode(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .code,
            RecoveryErrorCode::Integrity
        );
        let encoded = package.encode().unwrap();
        assert!(EncryptedExportPackage::decode(&encoded[..encoded.len() / 2]).is_err());

        let mut duplicates = objects;
        duplicates.push(duplicates[0].clone());
        assert_eq!(
            EncryptedExportPackage::create(VAULT_ID, &recovery_slot, &[], duplicates, 10)
                .unwrap_err()
                .code,
            RecoveryErrorCode::Conflict
        );
        assert!(run_recovery_drill(&package, &recovery_key).is_ok());

        let mut revoked_registry =
            DeviceRegistry::new(VAULT_ID, DEVICE_A, "Laptop", &[1; 32], 1).unwrap();
        revoked_registry
            .add_device(1, DEVICE_B, "Phone", &[2; 32], 2)
            .unwrap();
        revoked_registry
            .revoke_device(2, DEVICE_A, RevocationReason::Compromised, 3)
            .unwrap();
        let registry_object = encrypt_sync_object(
            &vault_key,
            VAULT_ID,
            SyncObjectKind::DeviceRegistry,
            "device-registry-3",
            Some(DEVICE_A),
            None,
            &revoked_registry.encode().unwrap(),
        )
        .unwrap()
        .encode()
        .unwrap();
        let mut revoked_objects = package
            .body
            .objects
            .iter()
            .map(|object| {
                (
                    object.key.clone(),
                    decode_canonical(&object.envelope, MAX_EXPORT_OBJECT_BYTES, "test").unwrap(),
                )
            })
            .collect::<Vec<_>>();
        revoked_objects
            .iter_mut()
            .find(|(key, _)| key == "devices/registry.odev")
            .unwrap()
            .1 = registry_object;
        let revoked_package =
            EncryptedExportPackage::create(VAULT_ID, &recovery_slot, &[], revoked_objects, 12)
                .unwrap();
        assert_eq!(
            run_recovery_drill(&revoked_package, &recovery_key)
                .unwrap_err()
                .code,
            RecoveryErrorCode::Integrity
        );
    }

    #[test]
    fn export_file_is_atomic_no_overwrite_and_rejects_symlinks() {
        let (_vault_key, _recovery_key, recovery_slot, _registry, objects) = fixture();
        let package =
            EncryptedExportPackage::create(VAULT_ID, &recovery_slot, &[], objects, 10).unwrap();
        let encoded = package.encode().unwrap();
        let root = TempDir::new();
        let path = root.0.join("backup.vpshell-export");
        write_export_atomic(&path, &encoded).unwrap();
        assert_eq!(read_export(&path).unwrap(), package);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            write_export_atomic(&path, &encoded).unwrap_err().code,
            RecoveryErrorCode::Conflict
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = root.0.join("backup-link");
            symlink(&path, &link).unwrap();
            assert!(read_export(&link).is_err());
        }
    }
}

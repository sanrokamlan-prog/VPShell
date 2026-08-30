//! Provider-side staging for a complete VMK rotation.
//!
//! Rotation never overwrites active objects. It authenticates the complete
//! provider snapshot first, publishes re-encrypted objects below a fresh
//! rotation namespace, and writes an encrypted manifest last. Activating that
//! manifest and switching keyslots are separate operations.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    sync_blob::object_key_matches_blob_envelope,
    sync_crypto::{
        EncryptedSyncObject, SyncObjectKind, VaultKey, decrypt_sync_object, encrypt_sync_object,
        reencrypt_sync_objects,
    },
    sync_provider::{
        ProviderCancellation, ProviderErrorCode, PutObjectOutcome, SyncObjectMetadata,
        SyncObjectProvider, validate_key, validate_object_bytes,
    },
};

const ROTATION_FORMAT_VERSION: u16 = 1;
const LIST_PAGE_SIZE: usize = 250;
const MAX_ROTATION_OBJECTS: usize = 10_000;
const MAX_ROTATION_PLAINTEXT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ROTATION_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_OBJECT_BYTES: u64 = 24 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RotationPublication {
    pub(crate) rotation_id: String,
    pub(crate) manifest_key: String,
    pub(crate) manifest_hash: String,
    pub(crate) published_objects: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RotationManifest {
    format_version: u16,
    vault_id: String,
    rotation_id: String,
    source_count: usize,
    source_plaintext_bytes: u64,
    objects: Vec<RotationManifestObject>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RotationManifestObject {
    source_key: String,
    target_key: String,
    source_hash: String,
    target_hash: String,
}

struct SourceObject {
    metadata: SyncObjectMetadata,
    encoded: Vec<u8>,
    envelope: EncryptedSyncObject,
}

pub(crate) fn publish_vault_rotation(
    provider: &dyn SyncObjectProvider,
    old_vault_key: &VaultKey,
    new_vault_key: &VaultKey,
    vault_id: &str,
    cancellation: &ProviderCancellation,
) -> Result<RotationPublication, String> {
    if Uuid::parse_str(vault_id)
        .ok()
        .is_none_or(|value| value.to_string() != vault_id)
    {
        return Err("同步轮换 vault ID 无效".to_string());
    }
    if old_vault_key.same_material(new_vault_key) {
        return Err("新旧同步主密钥必须不同".to_string());
    }

    let mut metadata = Vec::new();
    for prefix in source_prefixes(vault_id) {
        list_all(provider, &prefix, cancellation, &mut metadata)?;
    }
    metadata.sort_by(|left, right| left.key.cmp(&right.key));
    if metadata.is_empty() || metadata.len() > MAX_ROTATION_OBJECTS {
        return Err("同步 provider 轮换对象必须为 1 至 10000 项".to_string());
    }

    let mut sources = Vec::with_capacity(metadata.len());
    let mut identities = BTreeSet::new();
    let mut plaintext_bytes = 0_u64;
    for item in metadata {
        cancellation.check().map_err(|_| "cancelled".to_string())?;
        if item.size == 0 || item.size > MAX_OBJECT_BYTES {
            return Err("同步 provider 轮换对象大小越界".to_string());
        }
        let encoded = provider
            .get(&item.key, cancellation)
            .map_err(provider_code)?;
        if encoded.len() as u64 != item.size {
            return Err("integrity".to_string());
        }
        validate_object_bytes(&encoded).map_err(|_| "resource-limit".to_string())?;
        let envelope =
            EncryptedSyncObject::decode(&encoded).map_err(|_| "integrity".to_string())?;
        validate_source_identity(&item.key, vault_id, &envelope)?;
        let identity = envelope_identity(&envelope);
        if !identities.insert(identity) {
            return Err("同步 provider 轮换包含重复对象身份".to_string());
        }
        let plaintext = Zeroizing::new(decrypt_sync_object(old_vault_key, &envelope)?);
        plaintext_bytes = plaintext_bytes
            .checked_add(plaintext.len() as u64)
            .ok_or_else(|| "同步 provider 轮换明文总量溢出".to_string())?;
        if plaintext_bytes > MAX_ROTATION_PLAINTEXT_BYTES {
            return Err("同步 provider 轮换明文总量超过 256 MiB".to_string());
        }
        sources.push(SourceObject {
            metadata: item,
            encoded,
            envelope,
        });
    }

    let rotation_id = Uuid::new_v4().to_string();
    let rotation_prefix = format!("vpshell/v1/{vault_id}/rotations/{rotation_id}/");
    validate_key(&format!("{rotation_prefix}00000.orot")).map_err(|_| "protocol".to_string())?;
    let envelopes = sources
        .iter()
        .map(|source| source.envelope.clone())
        .collect::<Vec<_>>();
    cancellation.check().map_err(|_| "cancelled".to_string())?;
    let rotated_objects = reencrypt_sync_objects(old_vault_key, new_vault_key, &envelopes)?;
    let mut manifest_objects = Vec::with_capacity(sources.len());
    for (index, (source, rotated)) in sources.iter().zip(rotated_objects).enumerate() {
        cancellation.check().map_err(|_| "cancelled".to_string())?;
        let encoded = rotated.encode()?;
        let target_key = format!("{rotation_prefix}{index:05}.orot");
        publish_staged(provider, &target_key, &encoded, cancellation)?;
        manifest_objects.push(RotationManifestObject {
            source_key: source.metadata.key.clone(),
            target_key,
            source_hash: sha256_hex(&source.encoded),
            target_hash: sha256_hex(&encoded),
        });
    }

    let manifest = RotationManifest {
        format_version: ROTATION_FORMAT_VERSION,
        vault_id: vault_id.to_string(),
        rotation_id: rotation_id.clone(),
        source_count: manifest_objects.len(),
        source_plaintext_bytes: plaintext_bytes,
        objects: manifest_objects,
    };
    let manifest_plaintext = serde_json::to_vec(&manifest).map_err(|_| "protocol".to_string())?;
    if manifest_plaintext.is_empty() || manifest_plaintext.len() > MAX_ROTATION_MANIFEST_BYTES {
        return Err("resource-limit".to_string());
    }
    let manifest_id = format!("rotation-{rotation_id}-manifest");
    let manifest_key = format!("{rotation_prefix}manifest.orom");
    let manifest_encoded = encrypt_sync_object(
        new_vault_key,
        vault_id,
        SyncObjectKind::Index,
        &manifest_id,
        None,
        None,
        &manifest_plaintext,
    )?
    .encode()?;
    publish_staged(provider, &manifest_key, &manifest_encoded, cancellation)?;
    Ok(RotationPublication {
        rotation_id,
        manifest_key,
        manifest_hash: sha256_hex(&manifest_encoded),
        published_objects: u32::try_from(sources.len() + 1).unwrap_or(u32::MAX),
    })
}

fn source_prefixes(vault_id: &str) -> [String; 4] {
    [
        format!("vpshell/v1/{vault_id}/segments/"),
        format!("vpshell/v1/{vault_id}/blobs/"),
        format!("vpshell/v1/{vault_id}/registry/"),
        format!("vpshell/v1/{vault_id}/blob-gc/"),
    ]
}

fn list_all(
    provider: &dyn SyncObjectProvider,
    prefix: &str,
    cancellation: &ProviderCancellation,
    output: &mut Vec<SyncObjectMetadata>,
) -> Result<(), String> {
    let mut cursor = None;
    let mut seen = BTreeSet::new();
    loop {
        cancellation.check().map_err(|_| "cancelled".to_string())?;
        let page = provider
            .list(prefix, cursor.as_deref(), LIST_PAGE_SIZE, cancellation)
            .map_err(provider_code)?;
        for object in page.objects {
            if !object.key.starts_with(prefix) || !seen.insert(object.key.clone()) {
                return Err("protocol".to_string());
            }
            output.push(object);
            if output.len() > MAX_ROTATION_OBJECTS {
                return Err("resource-limit".to_string());
            }
        }
        let Some(next) = page.next_cursor else {
            break;
        };
        if cursor.as_ref().is_some_and(|current| next <= *current) || !seen.contains(&next) {
            return Err("protocol".to_string());
        }
        cursor = Some(next);
    }
    Ok(())
}

fn validate_source_identity(
    key: &str,
    vault_id: &str,
    envelope: &EncryptedSyncObject,
) -> Result<(), String> {
    if envelope.vault_id() != vault_id {
        return Err("cross-vault".to_string());
    }
    if object_key_matches_blob_envelope(key, vault_id, envelope) {
        return Ok(());
    }
    let segments_prefix = format!("vpshell/v1/{vault_id}/segments/");
    if let Some(relative) = key.strip_prefix(&segments_prefix) {
        let (device_id, filename) = relative
            .split_once('/')
            .ok_or_else(|| "protocol".to_string())?;
        let sequence = filename
            .strip_suffix(".oseg")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| "protocol".to_string())?;
        if Uuid::parse_str(device_id)
            .ok()
            .is_none_or(|value| value.to_string() != device_id)
            || filename != format!("{sequence}.oseg")
            || envelope.object_kind() != &SyncObjectKind::Event
            || envelope.device_id() != Some(device_id)
            || envelope.sequence() != Some(sequence)
        {
            return Err("integrity".to_string());
        }
        return Ok(());
    }
    let registry_prefix = format!("vpshell/v1/{vault_id}/registry/");
    if let Some(filename) = key.strip_prefix(&registry_prefix) {
        let revision = filename
            .strip_suffix(".oreg")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| "protocol".to_string())?;
        if filename != format!("{revision}.oreg")
            || envelope.object_kind() != &SyncObjectKind::DeviceRegistry
            || envelope.object_id() != format!("device-registry-{revision}")
            || envelope.device_id().is_none()
            || envelope.sequence().is_some()
        {
            return Err("integrity".to_string());
        }
        return Ok(());
    }
    let index_prefix = format!("vpshell/v1/{vault_id}/blob-gc/");
    let relative = key
        .strip_prefix(&index_prefix)
        .ok_or_else(|| "protocol".to_string())?;
    let valid_member = relative
        .strip_prefix("members/")
        .and_then(|name| name.strip_suffix(".ogcm"))
        .filter(|device| {
            let device = *device;
            Uuid::parse_str(device)
                .ok()
                .is_some_and(|value| value.to_string() == device)
        })
        .map(|device| format!("blob-gc-member-{device}"));
    let valid_ack = relative.split_once('/').and_then(|(device, filename)| {
        let digest = filename.strip_suffix(".ogca")?;
        if Uuid::parse_str(device)
            .ok()
            .is_none_or(|value| value.to_string() != device)
            || !is_hash(digest)
        {
            return None;
        }
        Some(format!("blob-gc-ack-{device}-{digest}"))
    });
    let expected_id = valid_member
        .or(valid_ack)
        .ok_or_else(|| "protocol".to_string())?;
    if envelope.object_kind() != &SyncObjectKind::Index
        || envelope.object_id() != expected_id
        || envelope.device_id().is_some()
        || envelope.sequence().is_some()
    {
        return Err("integrity".to_string());
    }
    Ok(())
}

fn envelope_identity(
    envelope: &EncryptedSyncObject,
) -> (String, String, Option<String>, Option<u64>) {
    (
        envelope.vault_id().to_string(),
        format!("{:?}", envelope.object_kind()),
        envelope.device_id().map(str::to_string),
        envelope.sequence(),
    )
}

fn publish_staged(
    provider: &dyn SyncObjectProvider,
    key: &str,
    encoded: &[u8],
    cancellation: &ProviderCancellation,
) -> Result<(), String> {
    match provider
        .put(key, encoded, cancellation)
        .map_err(provider_code)?
    {
        PutObjectOutcome::Created | PutObjectOutcome::AlreadyPresent => Ok(()),
    }
}

fn provider_code(error: crate::sync_provider::ProviderError) -> String {
    match error.code {
        ProviderErrorCode::Cancelled => "cancelled",
        ProviderErrorCode::LimitExceeded => "resource-limit",
        ProviderErrorCode::Conflict => "publish-conflict",
        ProviderErrorCode::NotFound => "not-found",
        ProviderErrorCode::InvalidInput | ProviderErrorCode::Protocol => "protocol",
        ProviderErrorCode::UnsafePath => "integrity",
        ProviderErrorCode::Unavailable => "remote-unavailable",
    }
    .to_string()
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::sync_provider::LocalFolderProvider;

    const VAULT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const DEVICE_ID: &str = "22222222-2222-4222-8222-222222222222";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("vpshell-rotation-{label}-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn event(key: &VaultKey, sequence: u64, body: &[u8]) -> Vec<u8> {
        encrypt_sync_object(
            key,
            VAULT_ID,
            SyncObjectKind::Event,
            &format!("event-{sequence}"),
            Some(DEVICE_ID),
            Some(sequence),
            body,
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    #[test]
    fn publishes_complete_authenticated_snapshot_before_manifest() {
        let temp = TempDir::new("success");
        let provider = LocalFolderProvider::open(&temp.0).unwrap();
        let cancellation = ProviderCancellation::default();
        let old = VaultKey::generate().unwrap();
        let new = VaultKey::generate().unwrap();
        provider
            .put(
                &format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg"),
                &event(&old, 1, b"one"),
                &cancellation,
            )
            .unwrap();
        provider
            .put(
                &format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/2.oseg"),
                &event(&old, 2, b"two"),
                &cancellation,
            )
            .unwrap();
        let publication =
            publish_vault_rotation(&provider, &old, &new, VAULT_ID, &cancellation).unwrap();
        assert_eq!(publication.published_objects, 3);
        let manifest = provider
            .get(&publication.manifest_key, &cancellation)
            .unwrap();
        let envelope = EncryptedSyncObject::decode(&manifest).unwrap();
        let plaintext = decrypt_sync_object(&new, &envelope).unwrap();
        let decoded: RotationManifest = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(decoded.source_count, 2);
        assert_eq!(
            decoded.objects[0].source_key,
            format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg")
        );
        assert_eq!(
            decoded.objects[1].source_key,
            format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/2.oseg")
        );
        for object in decoded.objects {
            let rotated = provider.get(&object.target_key, &cancellation).unwrap();
            let rotated = EncryptedSyncObject::decode(&rotated).unwrap();
            assert_eq!(decrypt_sync_object(&new, &rotated).unwrap().len(), 3);
        }
    }

    #[test]
    fn late_authentication_failure_leaves_no_commit_manifest() {
        let temp = TempDir::new("late-auth");
        let provider = LocalFolderProvider::open(&temp.0).unwrap();
        let cancellation = ProviderCancellation::default();
        let old = VaultKey::generate().unwrap();
        let new = VaultKey::generate().unwrap();
        let wrong = VaultKey::generate().unwrap();
        provider
            .put(
                &format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg"),
                &event(&old, 1, b"one"),
                &cancellation,
            )
            .unwrap();
        provider
            .put(
                &format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/2.oseg"),
                &event(&wrong, 2, b"two"),
                &cancellation,
            )
            .unwrap();
        assert!(publish_vault_rotation(&provider, &old, &new, VAULT_ID, &cancellation).is_err());
        let page = provider
            .list(
                &format!("vpshell/v1/{VAULT_ID}/rotations/"),
                None,
                10,
                &cancellation,
            )
            .unwrap();
        assert!(page.objects.is_empty());
    }
}

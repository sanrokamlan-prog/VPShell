//! Provider-side staging for a complete VMK rotation.
//!
//! Rotation never overwrites active objects. It authenticates the complete
//! provider snapshot first, publishes re-encrypted objects below a fresh
//! rotation namespace, and writes an encrypted manifest last. Activation
//! revalidates both snapshots, publishes new password and recovery keyslots,
//! then commits one current-key-authenticated revision marker as the logical
//! switch point.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    sync_blob::object_key_matches_blob_envelope,
    sync_crypto::{
        Argon2Parameters, EncryptedSyncObject, PasswordKeyslot, RecoveryKey, RecoveryKeyslot,
        SyncObjectKind, VaultKey, create_password_keyslot, create_recovery_keyslot,
        decrypt_sync_object, encrypt_sync_object, open_password_keyslot, open_recovery_keyslot,
        reencrypt_sync_objects,
    },
    sync_outbox::SyncJournal,
    sync_provider::{
        DeleteObjectOutcome, ProviderCancellation, ProviderErrorCode, PutObjectOutcome,
        SyncObjectMetadata, SyncObjectProvider, validate_key, validate_object_bytes,
    },
};

const ROTATION_FORMAT_VERSION: u16 = 1;
const ROTATION_ACTIVATION_FORMAT_VERSION: u16 = 2;
const LEGACY_ROTATION_ACTIVATION_FORMAT_VERSION: u16 = 1;
const LIST_PAGE_SIZE: usize = 250;
const MAX_ROTATION_OBJECTS: usize = 10_000;
const MAX_ROTATION_PLAINTEXT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ROTATION_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_ROTATION_ACTIVATION_BYTES: usize = 64 * 1024;
const MAX_OBJECT_BYTES: u64 = 24 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RotationPublication {
    pub(crate) rotation_id: String,
    pub(crate) manifest_key: String,
    pub(crate) manifest_hash: String,
    pub(crate) published_objects: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RotationActivation {
    pub(crate) rotation_id: String,
    pub(crate) activation_revision: u64,
    pub(crate) activation_key: String,
    pub(crate) activation_hash: String,
    pub(crate) password_keyslot_key: String,
    pub(crate) recovery_keyslot_key: String,
}

pub(crate) struct OpenedRotationActivation {
    pub(crate) rotation_id: String,
    pub(crate) activation_hash: String,
    pub(crate) vault_key: VaultKey,
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

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RotationActivationCommit {
    format_version: u16,
    vault_id: String,
    rotation_id: String,
    activation_revision: u64,
    previous_activation_hash: String,
    manifest_key: String,
    manifest_hash: String,
    password_keyslot_key: String,
    password_keyslot_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_keyslot_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_keyslot_hash: Option<String>,
    staged_objects: u32,
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn activate_vault_rotation(
    provider: &dyn SyncObjectProvider,
    current_vault_key: &VaultKey,
    new_vault_key: &VaultKey,
    vault_id: &str,
    publication: &RotationPublication,
    activation_revision: u64,
    previous_activation_hash: &str,
    new_password: &[u8],
    kdf: Argon2Parameters,
    recovery_key: &RecoveryKey,
    cancellation: &ProviderCancellation,
) -> Result<RotationActivation, String> {
    validate_activation_lineage(vault_id, activation_revision, previous_activation_hash)?;
    if current_vault_key.same_material(new_vault_key) {
        return Err("轮换激活的新旧同步主密钥必须不同".to_string());
    }
    let manifest =
        load_rotation_manifest(provider, new_vault_key, vault_id, publication, cancellation)?;
    validate_current_snapshot(
        provider,
        current_vault_key,
        vault_id,
        &manifest,
        cancellation,
    )?;
    cancellation.check().map_err(|_| "cancelled".to_string())?;

    let password_keyslot = create_password_keyslot(new_password, vault_id, new_vault_key, kdf)?;
    let password_keyslot_encoded = password_keyslot.encode()?;
    let password_keyslot_key = format!(
        "vpshell/v1/{vault_id}/rotations/{}/keyslots/{}.json",
        publication.rotation_id,
        password_keyslot.slot_id()
    );
    validate_key(&password_keyslot_key).map_err(|_| "protocol".to_string())?;
    let recovery_keyslot = create_recovery_keyslot(recovery_key, vault_id, new_vault_key)?;
    let recovery_keyslot_encoded = recovery_keyslot.encode()?;
    let recovery_keyslot_key = format!(
        "vpshell/v1/{vault_id}/rotations/{}/recovery-keyslots/{}.json",
        publication.rotation_id,
        recovery_keyslot.slot_id()
    );
    validate_key(&recovery_keyslot_key).map_err(|_| "protocol".to_string())?;
    publish_staged(
        provider,
        &password_keyslot_key,
        &password_keyslot_encoded,
        cancellation,
    )?;
    publish_staged(
        provider,
        &recovery_keyslot_key,
        &recovery_keyslot_encoded,
        cancellation,
    )?;

    let commit = RotationActivationCommit {
        format_version: ROTATION_ACTIVATION_FORMAT_VERSION,
        vault_id: vault_id.to_string(),
        rotation_id: publication.rotation_id.clone(),
        activation_revision,
        previous_activation_hash: previous_activation_hash.to_string(),
        manifest_key: publication.manifest_key.clone(),
        manifest_hash: publication.manifest_hash.clone(),
        password_keyslot_key: password_keyslot_key.clone(),
        password_keyslot_hash: sha256_hex(&password_keyslot_encoded),
        recovery_keyslot_key: Some(recovery_keyslot_key.clone()),
        recovery_keyslot_hash: Some(sha256_hex(&recovery_keyslot_encoded)),
        staged_objects: publication.published_objects,
    };
    let commit_plaintext = encode_activation_commit(&commit)?;
    let activation_key = activation_object_key(vault_id, activation_revision);
    let activation_id = format!("rotation-activation-{activation_revision}");
    let activation_encoded = encrypt_sync_object(
        current_vault_key,
        vault_id,
        SyncObjectKind::Index,
        &activation_id,
        None,
        None,
        &commit_plaintext,
    )?
    .encode()?;
    publish_staged(provider, &activation_key, &activation_encoded, cancellation)?;
    Ok(RotationActivation {
        rotation_id: publication.rotation_id.clone(),
        activation_revision,
        activation_key,
        activation_hash: sha256_hex(&activation_encoded),
        password_keyslot_key,
        recovery_keyslot_key,
    })
}

pub(crate) fn open_vault_rotation_activation(
    provider: &dyn SyncObjectProvider,
    current_vault_key: &VaultKey,
    vault_id: &str,
    activation_revision: u64,
    expected_previous_activation_hash: &str,
    password: &[u8],
    cancellation: &ProviderCancellation,
) -> Result<OpenedRotationActivation, String> {
    let (commit, activation_hash) = load_rotation_activation_commit(
        provider,
        current_vault_key,
        vault_id,
        activation_revision,
        expected_previous_activation_hash,
        cancellation,
    )?;
    let (password_keyslot, _) =
        load_bound_rotation_keyslots(provider, vault_id, &commit, cancellation)?;
    let new_vault_key = open_password_keyslot(password, &password_keyslot)?;
    finish_opened_rotation_activation(
        provider,
        vault_id,
        commit,
        activation_hash,
        new_vault_key,
        cancellation,
    )
}

pub(crate) fn open_vault_rotation_activation_with_recovery(
    provider: &dyn SyncObjectProvider,
    current_vault_key: &VaultKey,
    vault_id: &str,
    activation_revision: u64,
    expected_previous_activation_hash: &str,
    recovery_key: &RecoveryKey,
    cancellation: &ProviderCancellation,
) -> Result<OpenedRotationActivation, String> {
    let (commit, activation_hash) = load_rotation_activation_commit(
        provider,
        current_vault_key,
        vault_id,
        activation_revision,
        expected_previous_activation_hash,
        cancellation,
    )?;
    let (_, recovery_keyslot) =
        load_bound_rotation_keyslots(provider, vault_id, &commit, cancellation)?;
    let recovery_keyslot = recovery_keyslot.ok_or_else(|| "recovery-unavailable".to_string())?;
    let new_vault_key = open_recovery_keyslot(recovery_key, &recovery_keyslot)?;
    finish_opened_rotation_activation(
        provider,
        vault_id,
        commit,
        activation_hash,
        new_vault_key,
        cancellation,
    )
}

fn load_rotation_activation_commit(
    provider: &dyn SyncObjectProvider,
    current_vault_key: &VaultKey,
    vault_id: &str,
    activation_revision: u64,
    expected_previous_activation_hash: &str,
    cancellation: &ProviderCancellation,
) -> Result<(RotationActivationCommit, String), String> {
    validate_activation_lineage(
        vault_id,
        activation_revision,
        expected_previous_activation_hash,
    )?;
    let activation_key = activation_object_key(vault_id, activation_revision);
    let activation_encoded = provider
        .get(&activation_key, cancellation)
        .map_err(provider_code)?;
    validate_object_bytes(&activation_encoded).map_err(|_| "resource-limit".to_string())?;
    let activation_hash = sha256_hex(&activation_encoded);
    let envelope =
        EncryptedSyncObject::decode(&activation_encoded).map_err(|_| "integrity".to_string())?;
    let activation_id = format!("rotation-activation-{activation_revision}");
    if envelope.vault_id() != vault_id
        || envelope.object_kind() != &SyncObjectKind::Index
        || envelope.object_id() != activation_id
        || envelope.device_id().is_some()
        || envelope.sequence().is_some()
    {
        return Err("integrity".to_string());
    }
    let plaintext = Zeroizing::new(decrypt_sync_object(current_vault_key, &envelope)?);
    let commit = decode_activation_commit(&plaintext)?;
    validate_activation_commit(
        &commit,
        vault_id,
        activation_revision,
        expected_previous_activation_hash,
    )?;
    Ok((commit, activation_hash))
}

fn load_bound_rotation_keyslots(
    provider: &dyn SyncObjectProvider,
    vault_id: &str,
    commit: &RotationActivationCommit,
    cancellation: &ProviderCancellation,
) -> Result<(PasswordKeyslot, Option<RecoveryKeyslot>), String> {
    let password_encoded = provider
        .get(&commit.password_keyslot_key, cancellation)
        .map_err(provider_code)?;
    validate_object_bytes(&password_encoded).map_err(|_| "resource-limit".to_string())?;
    if sha256_hex(&password_encoded) != commit.password_keyslot_hash {
        return Err("integrity".to_string());
    }
    let password_keyslot =
        PasswordKeyslot::decode(&password_encoded).map_err(|_| "integrity".to_string())?;
    let expected_password_key = format!(
        "vpshell/v1/{vault_id}/rotations/{}/keyslots/{}.json",
        commit.rotation_id,
        password_keyslot.slot_id()
    );
    if password_keyslot.vault_id() != vault_id
        || commit.password_keyslot_key != expected_password_key
    {
        return Err("integrity".to_string());
    }

    let recovery_keyslot = match (
        commit.recovery_keyslot_key.as_deref(),
        commit.recovery_keyslot_hash.as_deref(),
    ) {
        (None, None) => None,
        (Some(key), Some(expected_hash)) => {
            let encoded = provider.get(key, cancellation).map_err(provider_code)?;
            validate_object_bytes(&encoded).map_err(|_| "resource-limit".to_string())?;
            if sha256_hex(&encoded) != expected_hash {
                return Err("integrity".to_string());
            }
            let keyslot = RecoveryKeyslot::decode(&encoded).map_err(|_| "integrity".to_string())?;
            let expected_key = format!(
                "vpshell/v1/{vault_id}/rotations/{}/recovery-keyslots/{}.json",
                commit.rotation_id,
                keyslot.slot_id()
            );
            if keyslot.vault_id() != vault_id || key != expected_key {
                return Err("integrity".to_string());
            }
            Some(keyslot)
        }
        _ => return Err("integrity".to_string()),
    };
    Ok((password_keyslot, recovery_keyslot))
}

fn finish_opened_rotation_activation(
    provider: &dyn SyncObjectProvider,
    vault_id: &str,
    commit: RotationActivationCommit,
    activation_hash: String,
    new_vault_key: VaultKey,
    cancellation: &ProviderCancellation,
) -> Result<OpenedRotationActivation, String> {
    let publication = RotationPublication {
        rotation_id: commit.rotation_id.clone(),
        manifest_key: commit.manifest_key.clone(),
        manifest_hash: commit.manifest_hash.clone(),
        published_objects: commit.staged_objects,
    };
    load_rotation_manifest(
        provider,
        &new_vault_key,
        vault_id,
        &publication,
        cancellation,
    )?;
    Ok(OpenedRotationActivation {
        rotation_id: commit.rotation_id,
        activation_hash,
        vault_key: new_vault_key,
    })
}

/// Discover and verify the newest contiguous activation chain. The journal
/// watermark is advanced only after every marker and its successor payload
/// has been authenticated, so remote rollback or a fork cannot silently move
/// the active VMK backwards.
pub(crate) fn discover_vault_rotation_activation(
    provider: &dyn SyncObjectProvider,
    current_vault_key: &VaultKey,
    vault_id: &str,
    bootstrap_activation_hash: &str,
    password: &[u8],
    journal: &SyncJournal,
    cancellation: &ProviderCancellation,
    now_ms: i64,
) -> Result<Option<OpenedRotationActivation>, String> {
    validate_activation_lineage(vault_id, 1, bootstrap_activation_hash)?;
    if !is_hash(bootstrap_activation_hash) {
        return Err("protocol".to_string());
    }
    let prefix = format!("vpshell/v1/{vault_id}/activations/");
    let mut metadata = Vec::new();
    list_all(provider, &prefix, cancellation, &mut metadata)?;
    let mut markers = BTreeMap::new();
    for item in metadata {
        let relative = item
            .key
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(".orac"))
            .ok_or_else(|| "protocol".to_string())?;
        let revision = relative
            .parse::<u64>()
            .map_err(|_| "protocol".to_string())?;
        if revision == 0
            || relative != format!("{revision:020}")
            || markers.insert(revision, item).is_some()
        {
            return Err("protocol".to_string());
        }
    }
    let trusted = journal
        .trusted_rotation_activation(vault_id)
        .map_err(rotation_journal_code)?;
    if markers.is_empty() {
        if trusted.is_some() {
            return Err("rotation-rollback".to_string());
        }
        return Ok(None);
    }
    let highest = *markers
        .keys()
        .next_back()
        .ok_or_else(|| "protocol".to_string())?;
    let trusted = trusted;
    if trusted
        .as_ref()
        .is_some_and(|value| value.revision > highest)
    {
        return Err("rotation-rollback".to_string());
    }
    if !markers.contains_key(&1) {
        return Err("rotation-rollback".to_string());
    }
    let mut revision = 1_u64;
    let previous_hash = bootstrap_activation_hash.to_string();
    let mut opened = open_vault_rotation_activation(
        provider,
        current_vault_key,
        vault_id,
        revision,
        &previous_hash,
        password,
        cancellation,
    )?;
    if trusted.as_ref().is_some_and(|value| {
        value.revision == revision && value.activation_hash != opened.activation_hash
    }) {
        return Err("rotation-rollback".to_string());
    }
    if trusted.is_none() {
        journal
            .advance_trusted_rotation_activation(
                vault_id,
                None,
                revision,
                &opened.activation_hash,
                now_ms,
            )
            .map_err(rotation_journal_code)?;
    }
    while revision < highest {
        let next_revision = revision
            .checked_add(1)
            .ok_or_else(|| "resource-limit".to_string())?;
        if !markers.contains_key(&next_revision) {
            return Err("rotation-rollback".to_string());
        }
        let next = open_vault_rotation_activation(
            provider,
            &opened.vault_key,
            vault_id,
            next_revision,
            &opened.activation_hash,
            password,
            cancellation,
        )?;
        if trusted
            .as_ref()
            .is_none_or(|value| next_revision > value.revision)
        {
            journal
                .advance_trusted_rotation_activation(
                    vault_id,
                    Some((revision, &opened.activation_hash)),
                    next_revision,
                    &next.activation_hash,
                    now_ms,
                )
                .map_err(rotation_journal_code)?;
        } else if trusted.as_ref().is_some_and(|value| {
            value.revision == next_revision && value.activation_hash != next.activation_hash
        }) {
            return Err("rotation-rollback".to_string());
        }
        opened = next;
        revision = next_revision;
    }
    if trusted.as_ref().is_some_and(|value| {
        value.revision == revision && value.activation_hash != opened.activation_hash
    }) {
        return Err("rotation-rollback".to_string());
    }
    Ok(Some(opened))
}

/// Remove an unpublished rotation namespace only after every activation marker
/// has been authenticated and proven not to reference it. Providers without
/// conditional deletion fail closed through `delete_exact`.
pub(crate) fn cleanup_orphaned_rotation(
    provider: &dyn SyncObjectProvider,
    current_vault_key: &VaultKey,
    vault_id: &str,
    rotation_id: &str,
    cancellation: &ProviderCancellation,
) -> Result<u32, String> {
    validate_canonical_uuid(vault_id)?;
    validate_canonical_uuid(rotation_id)?;
    let activation_prefix = format!("vpshell/v1/{vault_id}/activations/");
    let mut activation_metadata = Vec::new();
    list_all(
        provider,
        &activation_prefix,
        cancellation,
        &mut activation_metadata,
    )?;
    for item in activation_metadata {
        cancellation.check().map_err(|_| "cancelled".to_string())?;
        let encoded = provider
            .get(&item.key, cancellation)
            .map_err(provider_code)?;
        if encoded.len() as u64 != item.size {
            return Err("integrity".to_string());
        }
        validate_object_bytes(&encoded).map_err(|_| "resource-limit".to_string())?;
        let envelope =
            EncryptedSyncObject::decode(&encoded).map_err(|_| "integrity".to_string())?;
        let relative = item
            .key
            .strip_prefix(&activation_prefix)
            .and_then(|value| value.strip_suffix(".orac"))
            .ok_or_else(|| "protocol".to_string())?;
        let revision = relative
            .parse::<u64>()
            .map_err(|_| "protocol".to_string())?;
        if revision == 0
            || relative != format!("{revision:020}")
            || envelope.vault_id() != vault_id
            || envelope.object_kind() != &SyncObjectKind::Index
            || envelope.object_id() != format!("rotation-activation-{revision}")
            || envelope.device_id().is_some()
            || envelope.sequence().is_some()
        {
            return Err("integrity".to_string());
        }
        let plaintext = Zeroizing::new(decrypt_sync_object(current_vault_key, &envelope)?);
        let commit = decode_activation_commit(&plaintext)?;
        validate_activation_lineage(vault_id, revision, &commit.previous_activation_hash)?;
        validate_activation_commit(
            &commit,
            vault_id,
            revision,
            &commit.previous_activation_hash,
        )?;
        if commit.rotation_id == rotation_id {
            return Err("rotation-in-use".to_string());
        }
    }

    let rotation_prefix = format!("vpshell/v1/{vault_id}/rotations/{rotation_id}/");
    let mut metadata = Vec::new();
    list_all(provider, &rotation_prefix, cancellation, &mut metadata)?;
    let mut objects = Vec::with_capacity(metadata.len());
    for item in metadata {
        cancellation.check().map_err(|_| "cancelled".to_string())?;
        if !item.key.starts_with(&rotation_prefix) || item.key == rotation_prefix {
            return Err("protocol".to_string());
        }
        let encoded = provider
            .get(&item.key, cancellation)
            .map_err(provider_code)?;
        if encoded.len() as u64 != item.size {
            return Err("integrity".to_string());
        }
        validate_object_bytes(&encoded).map_err(|_| "resource-limit".to_string())?;
        objects.push((item.key, encoded));
    }

    let mut deleted = 0_u32;
    for (key, encoded) in objects {
        cancellation.check().map_err(|_| "cancelled".to_string())?;
        match provider
            .delete_exact(&key, &encoded, cancellation)
            .map_err(provider_code)?
        {
            DeleteObjectOutcome::Deleted => {
                deleted = deleted.saturating_add(1);
            }
            DeleteObjectOutcome::AlreadyAbsent => {}
        }
    }
    Ok(deleted)
}

/// Reclaim the source objects superseded by an authenticated active rotation.
/// The activation marker and new namespace are verified first; source objects
/// are then authenticated with the previous VMK and conditionally deleted.
/// Missing sources are treated as already reclaimed so interrupted cleanup can
/// be retried safely.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cleanup_activated_rotation_sources(
    provider: &dyn SyncObjectProvider,
    current_vault_key: &VaultKey,
    new_vault_key: &VaultKey,
    vault_id: &str,
    activation_revision: u64,
    previous_activation_hash: &str,
    expected_activation_hash: &str,
    cancellation: &ProviderCancellation,
) -> Result<u32, String> {
    if current_vault_key.same_material(new_vault_key) || !is_hash(expected_activation_hash) {
        return Err("integrity".to_string());
    }
    let (commit, activation_hash) = load_rotation_activation_commit(
        provider,
        current_vault_key,
        vault_id,
        activation_revision,
        previous_activation_hash,
        cancellation,
    )?;
    if activation_hash != expected_activation_hash {
        return Err("integrity".to_string());
    }
    let _ = load_bound_rotation_keyslots(provider, vault_id, &commit, cancellation)?;
    let publication = RotationPublication {
        rotation_id: commit.rotation_id.clone(),
        manifest_key: commit.manifest_key.clone(),
        manifest_hash: commit.manifest_hash.clone(),
        published_objects: commit.staged_objects,
    };
    let manifest = load_rotation_manifest(
        provider,
        new_vault_key,
        vault_id,
        &publication,
        cancellation,
    )?;

    let mut authenticated = Vec::with_capacity(manifest.objects.len());
    for item in &manifest.objects {
        cancellation.check().map_err(|_| "cancelled".to_string())?;
        let encoded = match provider.get(&item.source_key, cancellation) {
            Ok(encoded) => encoded,
            Err(error) if error.code == ProviderErrorCode::NotFound => continue,
            Err(error) => return Err(provider_code(error)),
        };
        validate_object_bytes(&encoded).map_err(|_| "resource-limit".to_string())?;
        if sha256_hex(&encoded) != item.source_hash {
            return Err("rotation-source-changed".to_string());
        }
        let envelope =
            EncryptedSyncObject::decode(&encoded).map_err(|_| "integrity".to_string())?;
        validate_source_identity(&item.source_key, vault_id, &envelope)?;
        let _plaintext = Zeroizing::new(decrypt_sync_object(current_vault_key, &envelope)?);
        authenticated.push((item.source_key.clone(), encoded));
    }

    let mut deleted = 0_u32;
    for (key, encoded) in authenticated {
        cancellation.check().map_err(|_| "cancelled".to_string())?;
        match provider
            .delete_exact(&key, &encoded, cancellation)
            .map_err(provider_code)?
        {
            DeleteObjectOutcome::Deleted => {
                deleted = deleted.saturating_add(1);
            }
            DeleteObjectOutcome::AlreadyAbsent => {}
        }
    }
    Ok(deleted)
}

fn rotation_journal_code(error: crate::sync_outbox::JournalError) -> String {
    use crate::sync_outbox::JournalErrorCode;
    match error.code {
        JournalErrorCode::Replay => "rotation-rollback",
        JournalErrorCode::Conflict => "conflict",
        JournalErrorCode::InvalidInput => "protocol",
        JournalErrorCode::SafetyBlocked => "reconcile-required",
        _ => "storage",
    }
    .to_string()
}

fn load_rotation_manifest(
    provider: &dyn SyncObjectProvider,
    new_vault_key: &VaultKey,
    vault_id: &str,
    publication: &RotationPublication,
    cancellation: &ProviderCancellation,
) -> Result<RotationManifest, String> {
    let rotation_prefix = validate_publication(vault_id, publication)?;
    let encoded = provider
        .get(&publication.manifest_key, cancellation)
        .map_err(provider_code)?;
    validate_object_bytes(&encoded).map_err(|_| "resource-limit".to_string())?;
    if sha256_hex(&encoded) != publication.manifest_hash {
        return Err("integrity".to_string());
    }
    let envelope = EncryptedSyncObject::decode(&encoded).map_err(|_| "integrity".to_string())?;
    let manifest_id = format!("rotation-{}-manifest", publication.rotation_id);
    if envelope.vault_id() != vault_id
        || envelope.object_kind() != &SyncObjectKind::Index
        || envelope.object_id() != manifest_id
        || envelope.device_id().is_some()
        || envelope.sequence().is_some()
    {
        return Err("integrity".to_string());
    }
    let plaintext = Zeroizing::new(decrypt_sync_object(new_vault_key, &envelope)?);
    if plaintext.is_empty() || plaintext.len() > MAX_ROTATION_MANIFEST_BYTES {
        return Err("resource-limit".to_string());
    }
    let manifest: RotationManifest =
        serde_json::from_slice(&plaintext).map_err(|_| "integrity".to_string())?;
    if manifest.format_version != ROTATION_FORMAT_VERSION
        || manifest.vault_id != vault_id
        || manifest.rotation_id != publication.rotation_id
        || manifest.source_count != manifest.objects.len()
        || manifest.source_count == 0
        || manifest.source_count > MAX_ROTATION_OBJECTS
        || manifest.source_plaintext_bytes > MAX_ROTATION_PLAINTEXT_BYTES
        || publication.published_objects
            != u32::try_from(manifest.source_count + 1).map_err(|_| "resource-limit".to_string())?
    {
        return Err("integrity".to_string());
    }

    let mut source_keys = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut plaintext_bytes = 0_u64;
    for (index, item) in manifest.objects.iter().enumerate() {
        cancellation.check().map_err(|_| "cancelled".to_string())?;
        let expected_target = format!("{rotation_prefix}{index:05}.orot");
        if item.target_key != expected_target
            || !is_hash(&item.source_hash)
            || !is_hash(&item.target_hash)
            || !source_keys.insert(item.source_key.clone())
        {
            return Err("integrity".to_string());
        }
        validate_key(&item.source_key).map_err(|_| "integrity".to_string())?;
        validate_key(&item.target_key).map_err(|_| "integrity".to_string())?;
        let target = provider
            .get(&item.target_key, cancellation)
            .map_err(provider_code)?;
        validate_object_bytes(&target).map_err(|_| "resource-limit".to_string())?;
        if sha256_hex(&target) != item.target_hash {
            return Err("integrity".to_string());
        }
        let target_envelope =
            EncryptedSyncObject::decode(&target).map_err(|_| "integrity".to_string())?;
        validate_source_identity(&item.source_key, vault_id, &target_envelope)?;
        if !identities.insert(envelope_identity(&target_envelope)) {
            return Err("integrity".to_string());
        }
        let target_plaintext =
            Zeroizing::new(decrypt_sync_object(new_vault_key, &target_envelope)?);
        plaintext_bytes = checked_plaintext_total(plaintext_bytes, target_plaintext.len())?;
    }
    if plaintext_bytes != manifest.source_plaintext_bytes {
        return Err("integrity".to_string());
    }
    Ok(manifest)
}

fn validate_current_snapshot(
    provider: &dyn SyncObjectProvider,
    current_vault_key: &VaultKey,
    vault_id: &str,
    manifest: &RotationManifest,
    cancellation: &ProviderCancellation,
) -> Result<(), String> {
    let mut metadata = Vec::new();
    for prefix in source_prefixes(vault_id) {
        list_all(provider, &prefix, cancellation, &mut metadata)?;
    }
    metadata.sort_by(|left, right| left.key.cmp(&right.key));
    if metadata.len() != manifest.objects.len() {
        return Err("rotation-source-changed".to_string());
    }
    let mut plaintext_bytes = 0_u64;
    for (metadata, item) in metadata.iter().zip(&manifest.objects) {
        cancellation.check().map_err(|_| "cancelled".to_string())?;
        if metadata.key != item.source_key || metadata.size == 0 || metadata.size > MAX_OBJECT_BYTES
        {
            return Err("rotation-source-changed".to_string());
        }
        let encoded = provider
            .get(&metadata.key, cancellation)
            .map_err(provider_code)?;
        if encoded.len() as u64 != metadata.size || sha256_hex(&encoded) != item.source_hash {
            return Err("rotation-source-changed".to_string());
        }
        validate_object_bytes(&encoded).map_err(|_| "resource-limit".to_string())?;
        let envelope =
            EncryptedSyncObject::decode(&encoded).map_err(|_| "integrity".to_string())?;
        validate_source_identity(&metadata.key, vault_id, &envelope)?;
        let plaintext = Zeroizing::new(decrypt_sync_object(current_vault_key, &envelope)?);
        plaintext_bytes = checked_plaintext_total(plaintext_bytes, plaintext.len())?;
    }
    if plaintext_bytes != manifest.source_plaintext_bytes {
        return Err("rotation-source-changed".to_string());
    }
    Ok(())
}

fn validate_publication(
    vault_id: &str,
    publication: &RotationPublication,
) -> Result<String, String> {
    validate_canonical_uuid(vault_id)?;
    validate_canonical_uuid(&publication.rotation_id)?;
    let rotation_prefix = format!(
        "vpshell/v1/{vault_id}/rotations/{}/",
        publication.rotation_id
    );
    if publication.manifest_key != format!("{rotation_prefix}manifest.orom")
        || !is_hash(&publication.manifest_hash)
        || !(2..=u32::try_from(MAX_ROTATION_OBJECTS + 1).unwrap_or(u32::MAX))
            .contains(&publication.published_objects)
    {
        return Err("integrity".to_string());
    }
    validate_key(&publication.manifest_key).map_err(|_| "integrity".to_string())?;
    Ok(rotation_prefix)
}

fn validate_activation_lineage(
    vault_id: &str,
    activation_revision: u64,
    previous_activation_hash: &str,
) -> Result<(), String> {
    validate_canonical_uuid(vault_id)?;
    if activation_revision == 0 || !is_hash(previous_activation_hash) {
        return Err("轮换激活 revision 或前序哈希无效".to_string());
    }
    validate_key(&activation_object_key(vault_id, activation_revision))
        .map_err(|_| "protocol".to_string())?;
    Ok(())
}

fn validate_activation_commit(
    commit: &RotationActivationCommit,
    vault_id: &str,
    activation_revision: u64,
    previous_activation_hash: &str,
) -> Result<(), String> {
    let valid_keyslots = match commit.format_version {
        LEGACY_ROTATION_ACTIVATION_FORMAT_VERSION => {
            commit.recovery_keyslot_key.is_none() && commit.recovery_keyslot_hash.is_none()
        }
        ROTATION_ACTIVATION_FORMAT_VERSION => commit
            .recovery_keyslot_key
            .as_deref()
            .zip(commit.recovery_keyslot_hash.as_deref())
            .is_some_and(|(key, hash)| validate_key(key).is_ok() && is_hash(hash)),
        _ => false,
    };
    if !valid_keyslots
        || commit.vault_id != vault_id
        || commit.activation_revision != activation_revision
        || commit.previous_activation_hash != previous_activation_hash
        || !is_hash(&commit.manifest_hash)
        || !is_hash(&commit.password_keyslot_hash)
    {
        return Err("integrity".to_string());
    }
    validate_publication(
        vault_id,
        &RotationPublication {
            rotation_id: commit.rotation_id.clone(),
            manifest_key: commit.manifest_key.clone(),
            manifest_hash: commit.manifest_hash.clone(),
            published_objects: commit.staged_objects,
        },
    )?;
    validate_key(&commit.password_keyslot_key).map_err(|_| "integrity".to_string())?;
    Ok(())
}

fn encode_activation_commit(commit: &RotationActivationCommit) -> Result<Vec<u8>, String> {
    validate_activation_commit(
        commit,
        &commit.vault_id,
        commit.activation_revision,
        &commit.previous_activation_hash,
    )?;
    let encoded = serde_json::to_vec(commit).map_err(|_| "protocol".to_string())?;
    if encoded.is_empty() || encoded.len() > MAX_ROTATION_ACTIVATION_BYTES {
        return Err("resource-limit".to_string());
    }
    Ok(encoded)
}

fn decode_activation_commit(encoded: &[u8]) -> Result<RotationActivationCommit, String> {
    if encoded.is_empty() || encoded.len() > MAX_ROTATION_ACTIVATION_BYTES {
        return Err("resource-limit".to_string());
    }
    serde_json::from_slice(encoded).map_err(|_| "integrity".to_string())
}

fn activation_object_key(vault_id: &str, activation_revision: u64) -> String {
    format!("vpshell/v1/{vault_id}/activations/{activation_revision:020}.orac")
}

fn checked_plaintext_total(current: u64, next: usize) -> Result<u64, String> {
    let total = current
        .checked_add(next as u64)
        .ok_or_else(|| "resource-limit".to_string())?;
    if total > MAX_ROTATION_PLAINTEXT_BYTES {
        return Err("resource-limit".to_string());
    }
    Ok(total)
}

fn validate_canonical_uuid(value: &str) -> Result<(), String> {
    if Uuid::parse_str(value)
        .ok()
        .is_none_or(|parsed| parsed.to_string() != value)
    {
        return Err("integrity".to_string());
    }
    Ok(())
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
) -> (String, String, String, Option<String>, Option<u64>) {
    (
        envelope.vault_id().to_string(),
        format!("{:?}", envelope.object_kind()),
        envelope.object_id().to_string(),
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
    use std::{collections::BTreeMap, fs, path::PathBuf, sync::Mutex};

    use super::*;
    use crate::sync_provider::{
        LocalFolderProvider, ProviderError, ProviderResult, SyncObjectPage,
    };

    const VAULT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const DEVICE_ID: &str = "22222222-2222-4222-8222-222222222222";

    struct TempDir(PathBuf);

    struct MemoryProvider {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        puts: Mutex<Vec<String>>,
        fail_activation_put: bool,
        supports_delete: bool,
    }

    impl MemoryProvider {
        fn new(fail_activation_put: bool) -> Self {
            Self {
                objects: Mutex::new(BTreeMap::new()),
                puts: Mutex::new(Vec::new()),
                fail_activation_put,
                supports_delete: true,
            }
        }

        fn without_delete() -> Self {
            Self {
                objects: Mutex::new(BTreeMap::new()),
                puts: Mutex::new(Vec::new()),
                fail_activation_put: false,
                supports_delete: false,
            }
        }

        fn put_keys(&self) -> Vec<String> {
            self.puts.lock().unwrap().clone()
        }
    }

    impl SyncObjectProvider for MemoryProvider {
        fn list(
            &self,
            prefix: &str,
            cursor: Option<&str>,
            limit: usize,
            cancellation: &ProviderCancellation,
        ) -> ProviderResult<SyncObjectPage> {
            cancellation.check()?;
            let objects = self.objects.lock().unwrap();
            let mut page = objects
                .iter()
                .filter(|(key, _)| {
                    key.starts_with(prefix) && cursor.is_none_or(|cursor| key.as_str() > cursor)
                })
                .map(|(key, bytes)| SyncObjectMetadata {
                    key: key.clone(),
                    size: bytes.len() as u64,
                    etag: None,
                })
                .collect::<Vec<_>>();
            let next_cursor = (page.len() > limit).then(|| page[limit - 1].key.clone());
            page.truncate(limit);
            Ok(SyncObjectPage {
                objects: page,
                next_cursor,
            })
        }

        fn get(&self, key: &str, cancellation: &ProviderCancellation) -> ProviderResult<Vec<u8>> {
            cancellation.check()?;
            self.objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| {
                    ProviderError::new(ProviderErrorCode::NotFound, "fixture object missing")
                })
        }

        fn put(
            &self,
            key: &str,
            bytes: &[u8],
            cancellation: &ProviderCancellation,
        ) -> ProviderResult<PutObjectOutcome> {
            cancellation.check()?;
            validate_key(key)?;
            validate_object_bytes(bytes)?;
            if self.fail_activation_put && key.contains("/activations/") {
                return Err(ProviderError::new(
                    ProviderErrorCode::Unavailable,
                    "fixture activation failure",
                ));
            }
            let mut objects = self.objects.lock().unwrap();
            if let Some(existing) = objects.get(key) {
                if existing == bytes {
                    return Ok(PutObjectOutcome::AlreadyPresent);
                }
                return Err(ProviderError::new(
                    ProviderErrorCode::Conflict,
                    "fixture immutable conflict",
                ));
            }
            objects.insert(key.to_string(), bytes.to_vec());
            self.puts.lock().unwrap().push(key.to_string());
            Ok(PutObjectOutcome::Created)
        }

        fn delete_exact(
            &self,
            key: &str,
            expected: &[u8],
            cancellation: &ProviderCancellation,
        ) -> ProviderResult<DeleteObjectOutcome> {
            cancellation.check()?;
            if !self.supports_delete {
                return Err(ProviderError::new(
                    ProviderErrorCode::Protocol,
                    "fixture conditional delete unsupported",
                ));
            }
            let mut objects = self.objects.lock().unwrap();
            let Some(existing) = objects.get(key) else {
                return Ok(DeleteObjectOutcome::AlreadyAbsent);
            };
            if existing != expected {
                return Err(ProviderError::new(
                    ProviderErrorCode::Conflict,
                    "fixture conditional delete mismatch",
                ));
            }
            objects.remove(key);
            Ok(DeleteObjectOutcome::Deleted)
        }
    }

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
    fn unsequenced_rotation_identity_includes_object_id() {
        let key = VaultKey::generate().unwrap();
        let first = encrypt_sync_object(
            &key,
            VAULT_ID,
            SyncObjectKind::Index,
            "first-index",
            None,
            None,
            b"first",
        )
        .unwrap();
        let second = encrypt_sync_object(
            &key,
            VAULT_ID,
            SyncObjectKind::Index,
            "second-index",
            None,
            None,
            b"second",
        )
        .unwrap();
        assert_ne!(envelope_identity(&first), envelope_identity(&second));
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

    #[test]
    fn activation_commit_is_last_and_opens_the_new_keyslot() {
        let provider = MemoryProvider::new(false);
        let cancellation = ProviderCancellation::default();
        let current = VaultKey::generate().unwrap();
        let new = VaultKey::generate().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        let password = b"rotation-password";
        let source_key = format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg");
        provider
            .put(&source_key, &event(&current, 1, b"one"), &cancellation)
            .unwrap();
        let publication =
            publish_vault_rotation(&provider, &current, &new, VAULT_ID, &cancellation).unwrap();
        let previous_hash = "11".repeat(32);
        let activation = activate_vault_rotation(
            &provider,
            &current,
            &new,
            VAULT_ID,
            &publication,
            1,
            &previous_hash,
            password,
            Argon2Parameters::minimum_for_tests(),
            &recovery_key,
            &cancellation,
        )
        .unwrap();

        let puts = provider.put_keys();
        assert_eq!(puts.last(), Some(&activation.activation_key));
        let keyslot_index = puts
            .iter()
            .position(|key| key == &activation.password_keyslot_key)
            .unwrap();
        let activation_index = puts
            .iter()
            .position(|key| key == &activation.activation_key)
            .unwrap();
        let recovery_index = puts
            .iter()
            .position(|key| key == &activation.recovery_keyslot_key)
            .unwrap();
        assert!(keyslot_index < activation_index);
        assert!(recovery_index < activation_index);
        assert_eq!(activation.activation_revision, 1);
        assert_eq!(activation.rotation_id, publication.rotation_id);

        let opened = open_vault_rotation_activation(
            &provider,
            &current,
            VAULT_ID,
            1,
            &previous_hash,
            password,
            &cancellation,
        )
        .unwrap();
        assert!(opened.vault_key.same_material(&new));
        assert_eq!(opened.rotation_id, activation.rotation_id);
        assert_eq!(opened.activation_hash, activation.activation_hash);
        let recovered = open_vault_rotation_activation_with_recovery(
            &provider,
            &current,
            VAULT_ID,
            1,
            &previous_hash,
            &recovery_key,
            &cancellation,
        )
        .unwrap();
        assert!(recovered.vault_key.same_material(&new));
        let wrong_recovery_key = RecoveryKey::generate().unwrap();
        assert!(
            open_vault_rotation_activation_with_recovery(
                &provider,
                &current,
                VAULT_ID,
                1,
                &previous_hash,
                &wrong_recovery_key,
                &cancellation,
            )
            .is_err()
        );
        assert!(
            open_vault_rotation_activation(
                &provider,
                &current,
                VAULT_ID,
                1,
                &"55".repeat(32),
                password,
                &cancellation,
            )
            .is_err()
        );

        let recovery_keyslot = provider
            .objects
            .lock()
            .unwrap()
            .remove(&activation.recovery_keyslot_key)
            .unwrap();
        assert!(
            open_vault_rotation_activation(
                &provider,
                &current,
                VAULT_ID,
                1,
                &previous_hash,
                password,
                &cancellation,
            )
            .is_err()
        );
        provider
            .objects
            .lock()
            .unwrap()
            .insert(activation.recovery_keyslot_key.clone(), recovery_keyslot);
        let mut objects = provider.objects.lock().unwrap();
        let password_keyslot = objects.get_mut(&activation.password_keyslot_key).unwrap();
        password_keyslot[0] ^= 1;
        drop(objects);
        assert!(
            open_vault_rotation_activation_with_recovery(
                &provider,
                &current,
                VAULT_ID,
                1,
                &previous_hash,
                &recovery_key,
                &cancellation,
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_password_only_activation_commit_remains_readable() {
        let provider = MemoryProvider::new(false);
        let cancellation = ProviderCancellation::default();
        let current = VaultKey::generate().unwrap();
        let new = VaultKey::generate().unwrap();
        let password = b"legacy-rotation-password";
        provider
            .put(
                &format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg"),
                &event(&current, 1, b"one"),
                &cancellation,
            )
            .unwrap();
        let publication =
            publish_vault_rotation(&provider, &current, &new, VAULT_ID, &cancellation).unwrap();
        let password_keyslot = create_password_keyslot(
            password,
            VAULT_ID,
            &new,
            Argon2Parameters::minimum_for_tests(),
        )
        .unwrap();
        let password_keyslot_encoded = password_keyslot.encode().unwrap();
        let password_keyslot_key = format!(
            "vpshell/v1/{VAULT_ID}/rotations/{}/keyslots/{}.json",
            publication.rotation_id,
            password_keyslot.slot_id()
        );
        provider
            .put(
                &password_keyslot_key,
                &password_keyslot_encoded,
                &cancellation,
            )
            .unwrap();
        let previous_hash = "66".repeat(32);
        let commit = RotationActivationCommit {
            format_version: LEGACY_ROTATION_ACTIVATION_FORMAT_VERSION,
            vault_id: VAULT_ID.to_string(),
            rotation_id: publication.rotation_id.clone(),
            activation_revision: 1,
            previous_activation_hash: previous_hash.clone(),
            manifest_key: publication.manifest_key.clone(),
            manifest_hash: publication.manifest_hash.clone(),
            password_keyslot_key,
            password_keyslot_hash: sha256_hex(&password_keyslot_encoded),
            recovery_keyslot_key: None,
            recovery_keyslot_hash: None,
            staged_objects: publication.published_objects,
        };
        let activation = encrypt_sync_object(
            &current,
            VAULT_ID,
            SyncObjectKind::Index,
            "rotation-activation-1",
            None,
            None,
            &encode_activation_commit(&commit).unwrap(),
        )
        .unwrap()
        .encode()
        .unwrap();
        provider
            .put(
                &activation_object_key(VAULT_ID, 1),
                &activation,
                &cancellation,
            )
            .unwrap();

        let opened = open_vault_rotation_activation(
            &provider,
            &current,
            VAULT_ID,
            1,
            &previous_hash,
            password,
            &cancellation,
        )
        .unwrap();
        assert!(opened.vault_key.same_material(&new));
        let recovery_key = RecoveryKey::generate().unwrap();
        assert_eq!(
            open_vault_rotation_activation_with_recovery(
                &provider,
                &current,
                VAULT_ID,
                1,
                &previous_hash,
                &recovery_key,
                &cancellation,
            )
            .err()
            .as_deref(),
            Some("recovery-unavailable")
        );
    }

    #[test]
    fn discovery_advances_journal_and_rejects_remote_rollback() {
        let provider = MemoryProvider::new(false);
        let cancellation = ProviderCancellation::default();
        let journal_root = TempDir::new("activation-discovery");
        let journal = SyncJournal::open(journal_root.0.clone()).unwrap();
        let current = VaultKey::generate().unwrap();
        let next = VaultKey::generate().unwrap();
        let newest = VaultKey::generate().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        let password = b"rotation-password";
        let source_key = format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg");
        provider
            .put(&source_key, &event(&current, 1, b"one"), &cancellation)
            .unwrap();
        let publication =
            publish_vault_rotation(&provider, &current, &next, VAULT_ID, &cancellation).unwrap();
        let bootstrap_hash = "aa".repeat(32);
        let activation = activate_vault_rotation(
            &provider,
            &current,
            &next,
            VAULT_ID,
            &publication,
            1,
            &bootstrap_hash,
            password,
            Argon2Parameters::minimum_for_tests(),
            &recovery_key,
            &cancellation,
        )
        .unwrap();
        provider
            .objects
            .lock()
            .unwrap()
            .insert(source_key, event(&next, 1, b"one"));
        let second_publication =
            publish_vault_rotation(&provider, &next, &newest, VAULT_ID, &cancellation).unwrap();
        let second_activation = activate_vault_rotation(
            &provider,
            &next,
            &newest,
            VAULT_ID,
            &second_publication,
            2,
            &activation.activation_hash,
            password,
            Argon2Parameters::minimum_for_tests(),
            &recovery_key,
            &cancellation,
        )
        .unwrap();
        let discovered = discover_vault_rotation_activation(
            &provider,
            &current,
            VAULT_ID,
            &bootstrap_hash,
            password,
            &journal,
            &cancellation,
            10,
        )
        .unwrap()
        .unwrap();
        assert!(discovered.vault_key.same_material(&newest));
        assert_eq!(
            discovered.activation_hash,
            second_activation.activation_hash
        );
        assert_eq!(
            journal
                .trusted_rotation_activation(VAULT_ID)
                .unwrap()
                .unwrap()
                .revision,
            2
        );
        provider
            .objects
            .lock()
            .unwrap()
            .remove(&second_activation.activation_key);
        let rollback = discover_vault_rotation_activation(
            &provider,
            &current,
            VAULT_ID,
            &bootstrap_hash,
            password,
            &journal,
            &cancellation,
            11,
        )
        .err();
        assert_eq!(rollback.as_deref(), Some("rotation-rollback"));
    }

    #[test]
    fn changed_source_snapshot_is_rejected_before_keyslot_publication() {
        let provider = MemoryProvider::new(false);
        let cancellation = ProviderCancellation::default();
        let current = VaultKey::generate().unwrap();
        let new = VaultKey::generate().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        provider
            .put(
                &format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg"),
                &event(&current, 1, b"one"),
                &cancellation,
            )
            .unwrap();
        let publication =
            publish_vault_rotation(&provider, &current, &new, VAULT_ID, &cancellation).unwrap();
        provider
            .put(
                &format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/2.oseg"),
                &event(&current, 2, b"two"),
                &cancellation,
            )
            .unwrap();
        let puts_before = provider.put_keys().len();
        assert!(
            activate_vault_rotation(
                &provider,
                &current,
                &new,
                VAULT_ID,
                &publication,
                1,
                &"22".repeat(32),
                b"rotation-password",
                Argon2Parameters::minimum_for_tests(),
                &recovery_key,
                &cancellation,
            )
            .is_err()
        );
        assert_eq!(provider.put_keys().len(), puts_before);
    }

    #[test]
    fn wrong_manifest_hash_is_rejected_without_activation_side_effects() {
        let provider = MemoryProvider::new(false);
        let cancellation = ProviderCancellation::default();
        let current = VaultKey::generate().unwrap();
        let new = VaultKey::generate().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        provider
            .put(
                &format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg"),
                &event(&current, 1, b"one"),
                &cancellation,
            )
            .unwrap();
        let mut publication =
            publish_vault_rotation(&provider, &current, &new, VAULT_ID, &cancellation).unwrap();
        publication.manifest_hash = "00".repeat(32);
        let puts_before = provider.put_keys().len();
        assert!(
            activate_vault_rotation(
                &provider,
                &current,
                &new,
                VAULT_ID,
                &publication,
                1,
                &"33".repeat(32),
                b"rotation-password",
                Argon2Parameters::minimum_for_tests(),
                &recovery_key,
                &cancellation,
            )
            .is_err()
        );
        assert_eq!(provider.put_keys().len(), puts_before);
    }

    #[test]
    fn activation_put_failure_leaves_only_an_inert_orphan_keyslot() {
        let provider = MemoryProvider::new(true);
        let cancellation = ProviderCancellation::default();
        let current = VaultKey::generate().unwrap();
        let new = VaultKey::generate().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        let previous_hash = "44".repeat(32);
        provider
            .put(
                &format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg"),
                &event(&current, 1, b"one"),
                &cancellation,
            )
            .unwrap();
        let publication =
            publish_vault_rotation(&provider, &current, &new, VAULT_ID, &cancellation).unwrap();
        assert!(
            activate_vault_rotation(
                &provider,
                &current,
                &new,
                VAULT_ID,
                &publication,
                1,
                &previous_hash,
                b"rotation-password",
                Argon2Parameters::minimum_for_tests(),
                &recovery_key,
                &cancellation,
            )
            .is_err()
        );
        let puts = provider.put_keys();
        assert!(puts.iter().any(|key| key.contains("/keyslots/")));
        assert!(puts.iter().any(|key| key.contains("/recovery-keyslots/")));
        assert!(!puts.iter().any(|key| key.contains("/activations/")));
        assert!(
            open_vault_rotation_activation(
                &provider,
                &current,
                VAULT_ID,
                1,
                &previous_hash,
                b"rotation-password",
                &cancellation,
            )
            .is_err()
        );
    }

    #[test]
    fn orphan_rotation_cleanup_deletes_unreferenced_namespace() {
        let provider = MemoryProvider::new(false);
        let cancellation = ProviderCancellation::default();
        let current = VaultKey::generate().unwrap();
        let new = VaultKey::generate().unwrap();
        provider
            .put(
                &format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg"),
                &event(&current, 1, b"one"),
                &cancellation,
            )
            .unwrap();
        let publication =
            publish_vault_rotation(&provider, &current, &new, VAULT_ID, &cancellation).unwrap();

        let deleted = cleanup_orphaned_rotation(
            &provider,
            &current,
            VAULT_ID,
            &publication.rotation_id,
            &cancellation,
        )
        .unwrap();
        assert_eq!(deleted, publication.published_objects);
        assert!(
            provider
                .list(
                    &format!("vpshell/v1/{VAULT_ID}/rotations/"),
                    None,
                    LIST_PAGE_SIZE,
                    &cancellation,
                )
                .unwrap()
                .objects
                .is_empty()
        );
    }

    #[test]
    fn orphan_rotation_cleanup_refuses_referenced_namespace() {
        let provider = MemoryProvider::new(false);
        let cancellation = ProviderCancellation::default();
        let current = VaultKey::generate().unwrap();
        let new = VaultKey::generate().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        provider
            .put(
                &format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg"),
                &event(&current, 1, b"one"),
                &cancellation,
            )
            .unwrap();
        let publication =
            publish_vault_rotation(&provider, &current, &new, VAULT_ID, &cancellation).unwrap();
        activate_vault_rotation(
            &provider,
            &current,
            &new,
            VAULT_ID,
            &publication,
            1,
            &"77".repeat(32),
            b"rotation-password",
            Argon2Parameters::minimum_for_tests(),
            &recovery_key,
            &cancellation,
        )
        .unwrap();

        assert_eq!(
            cleanup_orphaned_rotation(
                &provider,
                &current,
                VAULT_ID,
                &publication.rotation_id,
                &cancellation,
            )
            .err()
            .as_deref(),
            Some("rotation-in-use")
        );
        assert!(
            !provider
                .list(
                    &format!(
                        "vpshell/v1/{VAULT_ID}/rotations/{}/",
                        publication.rotation_id
                    ),
                    None,
                    LIST_PAGE_SIZE,
                    &cancellation,
                )
                .unwrap()
                .objects
                .is_empty()
        );
    }

    #[test]
    fn orphan_rotation_cleanup_fails_closed_for_unreadable_marker() {
        let provider = MemoryProvider::new(false);
        let cancellation = ProviderCancellation::default();
        let current = VaultKey::generate().unwrap();
        let new = VaultKey::generate().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        provider
            .put(
                &format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg"),
                &event(&current, 1, b"one"),
                &cancellation,
            )
            .unwrap();
        let publication =
            publish_vault_rotation(&provider, &current, &new, VAULT_ID, &cancellation).unwrap();
        activate_vault_rotation(
            &provider,
            &current,
            &new,
            VAULT_ID,
            &publication,
            1,
            &"88".repeat(32),
            b"rotation-password",
            Argon2Parameters::minimum_for_tests(),
            &recovery_key,
            &cancellation,
        )
        .unwrap();

        assert!(
            cleanup_orphaned_rotation(
                &provider,
                &VaultKey::generate().unwrap(),
                VAULT_ID,
                &publication.rotation_id,
                &cancellation,
            )
            .is_err()
        );
        assert!(
            !provider
                .list(
                    &format!(
                        "vpshell/v1/{VAULT_ID}/rotations/{}/",
                        publication.rotation_id
                    ),
                    None,
                    LIST_PAGE_SIZE,
                    &cancellation,
                )
                .unwrap()
                .objects
                .is_empty()
        );
    }

    #[test]
    fn activated_rotation_cleanup_reclaims_authenticated_sources() {
        let provider = MemoryProvider::new(false);
        let cancellation = ProviderCancellation::default();
        let current = VaultKey::generate().unwrap();
        let new = VaultKey::generate().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        provider
            .put(
                &format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg"),
                &event(&current, 1, b"one"),
                &cancellation,
            )
            .unwrap();
        let publication =
            publish_vault_rotation(&provider, &current, &new, VAULT_ID, &cancellation).unwrap();
        let previous_hash = "99".repeat(32);
        let activation = activate_vault_rotation(
            &provider,
            &current,
            &new,
            VAULT_ID,
            &publication,
            1,
            &previous_hash,
            b"rotation-password",
            Argon2Parameters::minimum_for_tests(),
            &recovery_key,
            &cancellation,
        )
        .unwrap();

        let deleted = cleanup_activated_rotation_sources(
            &provider,
            &current,
            &new,
            VAULT_ID,
            activation.activation_revision,
            &previous_hash,
            &activation.activation_hash,
            &cancellation,
        )
        .unwrap();
        assert_eq!(deleted, 1);
        assert!(
            provider
                .list(
                    &format!("vpshell/v1/{VAULT_ID}/segments/"),
                    None,
                    LIST_PAGE_SIZE,
                    &cancellation,
                )
                .unwrap()
                .objects
                .is_empty()
        );
        assert!(
            !provider
                .list(
                    &format!(
                        "vpshell/v1/{VAULT_ID}/rotations/{}/",
                        publication.rotation_id
                    ),
                    None,
                    LIST_PAGE_SIZE,
                    &cancellation,
                )
                .unwrap()
                .objects
                .is_empty()
        );
    }

    #[test]
    fn activated_rotation_cleanup_fails_closed_for_changed_source() {
        let provider = MemoryProvider::new(false);
        let cancellation = ProviderCancellation::default();
        let current = VaultKey::generate().unwrap();
        let new = VaultKey::generate().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        let source_key = format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg");
        provider
            .put(&source_key, &event(&current, 1, b"one"), &cancellation)
            .unwrap();
        let publication =
            publish_vault_rotation(&provider, &current, &new, VAULT_ID, &cancellation).unwrap();
        let previous_hash = "aa".repeat(32);
        let activation = activate_vault_rotation(
            &provider,
            &current,
            &new,
            VAULT_ID,
            &publication,
            1,
            &previous_hash,
            b"rotation-password",
            Argon2Parameters::minimum_for_tests(),
            &recovery_key,
            &cancellation,
        )
        .unwrap();
        provider.objects.lock().unwrap().get_mut(&source_key).unwrap()[0] ^= 1;

        assert_eq!(
            cleanup_activated_rotation_sources(
                &provider,
                &current,
                &new,
                VAULT_ID,
                activation.activation_revision,
                &previous_hash,
                &activation.activation_hash,
                &cancellation,
            )
            .err()
            .as_deref(),
            Some("rotation-source-changed")
        );
        assert!(provider.objects.lock().unwrap().contains_key(&source_key));
    }

    #[test]
    fn activated_rotation_cleanup_is_idempotent_for_missing_sources() {
        let provider = MemoryProvider::new(false);
        let cancellation = ProviderCancellation::default();
        let current = VaultKey::generate().unwrap();
        let new = VaultKey::generate().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        let source_key = format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg");
        provider
            .put(&source_key, &event(&current, 1, b"one"), &cancellation)
            .unwrap();
        let publication =
            publish_vault_rotation(&provider, &current, &new, VAULT_ID, &cancellation).unwrap();
        let previous_hash = "bb".repeat(32);
        let activation = activate_vault_rotation(
            &provider,
            &current,
            &new,
            VAULT_ID,
            &publication,
            1,
            &previous_hash,
            b"rotation-password",
            Argon2Parameters::minimum_for_tests(),
            &recovery_key,
            &cancellation,
        )
        .unwrap();
        provider.objects.lock().unwrap().remove(&source_key);

        assert_eq!(
            cleanup_activated_rotation_sources(
                &provider,
                &current,
                &new,
                VAULT_ID,
                activation.activation_revision,
                &previous_hash,
                &activation.activation_hash,
                &cancellation,
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn activated_rotation_cleanup_fails_closed_without_conditional_delete() {
        let provider = MemoryProvider::without_delete();
        let cancellation = ProviderCancellation::default();
        let current = VaultKey::generate().unwrap();
        let new = VaultKey::generate().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        let source_key = format!("vpshell/v1/{VAULT_ID}/segments/{DEVICE_ID}/1.oseg");
        provider
            .put(&source_key, &event(&current, 1, b"one"), &cancellation)
            .unwrap();
        let publication =
            publish_vault_rotation(&provider, &current, &new, VAULT_ID, &cancellation).unwrap();
        let previous_hash = "cc".repeat(32);
        let activation = activate_vault_rotation(
            &provider,
            &current,
            &new,
            VAULT_ID,
            &publication,
            1,
            &previous_hash,
            b"rotation-password",
            Argon2Parameters::minimum_for_tests(),
            &recovery_key,
            &cancellation,
        )
        .unwrap();

        assert_eq!(
            cleanup_activated_rotation_sources(
                &provider,
                &current,
                &new,
                VAULT_ID,
                activation.activation_revision,
                &previous_hash,
                &activation.activation_hash,
                &cancellation,
            )
            .err()
            .as_deref(),
            Some("protocol")
        );
        assert!(provider.objects.lock().unwrap().contains_key(&source_key));
    }
}

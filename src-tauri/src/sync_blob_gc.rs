//! Conservative remote garbage collection for encrypted wallpaper blobs.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    sync_blob::{object_key_matches_blob_envelope, restore_wallpaper_blob},
    sync_crypto::{
        EncryptedSyncObject, SyncObjectKind, VaultKey, decrypt_sync_object, encrypt_sync_object,
    },
    sync_outbox::SyncJournal,
    sync_provider::{
        DeleteObjectOutcome, ProviderCancellation, ProviderErrorCode, PutObjectOutcome,
        SyncObjectMetadata, SyncObjectProvider,
    },
};

const GC_FORMAT_VERSION: u16 = 1;
const GC_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
const MAX_GC_MEMBERS: usize = 32;
const MAX_GC_LIVE_BLOBS: usize = 2_048;
const MAX_GC_OBJECTS: usize = 10_000;
const LIST_PAGE_SIZE: usize = 250;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlobGcMember {
    format_version: u16,
    vault_id: String,
    device_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlobGcAcknowledgement {
    format_version: u16,
    vault_id: String,
    device_id: String,
    members: Vec<String>,
    frontier: BTreeMap<String, u64>,
    live_blob_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BlobGcCycleResult {
    pub(crate) published_objects: u32,
    pub(crate) deleted_objects: u32,
}

fn hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn member_key(vault_id: &str, device_id: &str) -> String {
    format!("vpshell/v1/{vault_id}/blob-gc/members/{device_id}.ogcm")
}

fn acknowledgement_key(vault_id: &str, device_id: &str, digest: &str) -> String {
    format!("vpshell/v1/{vault_id}/blob-gc/acks/{device_id}/{digest}.ogca")
}

fn member_object_id(device_id: &str) -> String {
    format!("blob-gc-member-{device_id}")
}

fn acknowledgement_object_id(device_id: &str, digest: &str) -> String {
    format!("blob-gc-ack-{device_id}-{digest}")
}

fn list_all(
    provider: &dyn SyncObjectProvider,
    prefix: &str,
    cancellation: &ProviderCancellation,
) -> Result<Vec<SyncObjectMetadata>, String> {
    let mut objects = Vec::new();
    let mut cursor = None;
    let mut seen = BTreeSet::new();
    loop {
        cancellation.check().map_err(|_| "cancelled".to_string())?;
        let page = provider
            .list(prefix, cursor.as_deref(), LIST_PAGE_SIZE, cancellation)
            .map_err(provider_error)?;
        for object in page.objects {
            if !object.key.starts_with(prefix) || !seen.insert(object.key.clone()) {
                return Err("protocol".to_string());
            }
            if objects.len() >= MAX_GC_OBJECTS {
                return Err("resource-limit".to_string());
            }
            objects.push(object);
        }
        let Some(next) = page.next_cursor else {
            break;
        };
        if cursor.as_ref().is_some_and(|current| next <= *current) || !seen.contains(&next) {
            return Err("protocol".to_string());
        }
        cursor = Some(next);
    }
    Ok(objects)
}

fn provider_error(error: crate::sync_provider::ProviderError) -> String {
    match error.code {
        ProviderErrorCode::Cancelled => "cancelled",
        ProviderErrorCode::LimitExceeded => "resource-limit",
        ProviderErrorCode::UnsafePath => "integrity",
        ProviderErrorCode::Conflict => "immutable-conflict",
        ProviderErrorCode::NotFound
        | ProviderErrorCode::InvalidInput
        | ProviderErrorCode::Protocol => "protocol",
        ProviderErrorCode::Unavailable => "remote-unavailable",
    }
    .to_string()
}

fn decode_index<T: for<'de> Deserialize<'de>>(
    encoded: &[u8],
    vault_key: &VaultKey,
    vault_id: &str,
    expected_object_id: &str,
) -> Result<T, String> {
    let envelope = EncryptedSyncObject::decode(encoded).map_err(|_| "integrity".to_string())?;
    if envelope.vault_id() != vault_id
        || envelope.object_kind() != &SyncObjectKind::Index
        || envelope.object_id() != expected_object_id
        || envelope.device_id().is_some()
        || envelope.sequence().is_some()
    {
        return Err("integrity".to_string());
    }
    let plaintext =
        decrypt_sync_object(vault_key, &envelope).map_err(|_| "integrity".to_string())?;
    serde_json::from_slice(&plaintext).map_err(|_| "protocol".to_string())
}

fn put_index(
    provider: &dyn SyncObjectProvider,
    cancellation: &ProviderCancellation,
    vault_key: &VaultKey,
    vault_id: &str,
    key: &str,
    object_id: &str,
    plaintext: &[u8],
) -> Result<bool, String> {
    match provider.get(key, cancellation) {
        Ok(existing) => {
            let envelope =
                EncryptedSyncObject::decode(&existing).map_err(|_| "integrity".to_string())?;
            if envelope.vault_id() != vault_id
                || envelope.object_kind() != &SyncObjectKind::Index
                || envelope.object_id() != object_id
                || envelope.device_id().is_some()
                || envelope.sequence().is_some()
                || decrypt_sync_object(vault_key, &envelope).map_err(|_| "integrity".to_string())?
                    != plaintext
            {
                return Err("immutable-conflict".to_string());
            }
            Ok(false)
        }
        Err(error) if error.code == ProviderErrorCode::NotFound => {
            let encoded = encrypt_sync_object(
                vault_key,
                vault_id,
                SyncObjectKind::Index,
                object_id,
                None,
                None,
                plaintext,
            )
            .and_then(|object| object.encode())
            .map_err(|_| "integrity".to_string())?;
            match provider
                .put(key, &encoded, cancellation)
                .map_err(provider_error)?
            {
                PutObjectOutcome::Created => Ok(true),
                PutObjectOutcome::AlreadyPresent => {
                    let existing = provider.get(key, cancellation).map_err(provider_error)?;
                    let envelope = EncryptedSyncObject::decode(&existing)
                        .map_err(|_| "integrity".to_string())?;
                    let decoded = decrypt_sync_object(vault_key, &envelope)
                        .map_err(|_| "integrity".to_string())?;
                    if envelope.vault_id() == vault_id
                        && envelope.object_kind() == &SyncObjectKind::Index
                        && envelope.object_id() == object_id
                        && envelope.device_id().is_none()
                        && envelope.sequence().is_none()
                        && decoded == plaintext
                    {
                        Ok(false)
                    } else {
                        Err("immutable-conflict".to_string())
                    }
                }
            }
        }
        Err(error) => Err(provider_error(error)),
    }
}

fn validate_membership(member: &BlobGcMember, vault_id: &str) -> Result<(), String> {
    if member.format_version != GC_FORMAT_VERSION
        || member.vault_id != vault_id
        || Uuid::parse_str(&member.device_id)
            .ok()
            .is_none_or(|value| value.to_string() != member.device_id)
    {
        return Err("protocol".to_string());
    }
    Ok(())
}

fn validate_acknowledgement(
    acknowledgement: &BlobGcAcknowledgement,
    vault_id: &str,
) -> Result<(), String> {
    if acknowledgement.format_version != GC_FORMAT_VERSION
        || acknowledgement.vault_id != vault_id
        || acknowledgement.members.is_empty()
        || acknowledgement.members.len() > MAX_GC_MEMBERS
        || acknowledgement.frontier.len() > MAX_GC_MEMBERS
        || acknowledgement.live_blob_ids.len() > MAX_GC_LIVE_BLOBS
    {
        return Err("protocol".to_string());
    }
    let mut members = acknowledgement.members.clone();
    members.sort();
    members.dedup();
    if members != acknowledgement.members
        || members.binary_search(&acknowledgement.device_id).is_err()
        || members.iter().any(|device_id| {
            Uuid::parse_str(device_id)
                .ok()
                .is_none_or(|value| value.to_string() != *device_id)
        })
        || acknowledgement
            .frontier
            .keys()
            .any(|device_id| members.binary_search(device_id).is_err())
        || !acknowledgement
            .live_blob_ids
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || acknowledgement
            .live_blob_ids
            .iter()
            .any(|id| !valid_hash(id))
    {
        return Err("protocol".to_string());
    }
    Ok(())
}

fn remote_segment_frontier(
    provider: &dyn SyncObjectProvider,
    vault_key: &VaultKey,
    vault_id: &str,
    cancellation: &ProviderCancellation,
) -> Result<BTreeMap<String, u64>, String> {
    let prefix = format!("vpshell/v1/{vault_id}/segments/");
    let mut frontier = BTreeMap::new();
    for object in list_all(provider, &prefix, cancellation)? {
        let relative = object
            .key
            .strip_prefix(&prefix)
            .ok_or_else(|| "protocol".to_string())?;
        let (device_id, filename) = relative
            .split_once('/')
            .ok_or_else(|| "protocol".to_string())?;
        if Uuid::parse_str(device_id)
            .ok()
            .is_none_or(|value| value.to_string() != device_id)
            || filename.matches('/').count() != 0
        {
            return Err("protocol".to_string());
        }
        let sequence = filename
            .strip_suffix(".oseg")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| "protocol".to_string())?;
        if filename != format!("{sequence}.oseg") {
            return Err("protocol".to_string());
        }
        let encoded = provider
            .get(&object.key, cancellation)
            .map_err(provider_error)?;
        if encoded.len() as u64 != object.size {
            return Err("integrity".to_string());
        }
        let envelope =
            EncryptedSyncObject::decode(&encoded).map_err(|_| "integrity".to_string())?;
        if envelope.vault_id() != vault_id
            || envelope.object_kind() != &SyncObjectKind::Event
            || envelope.device_id() != Some(device_id)
            || envelope.sequence() != Some(sequence)
            || decrypt_sync_object(vault_key, &envelope).is_err()
        {
            return Err("integrity".to_string());
        }
        frontier
            .entry(device_id.to_string())
            .and_modify(|current| *current = (*current).max(sequence))
            .or_insert(sequence);
    }
    Ok(frontier)
}

pub(crate) fn run_blob_gc(
    provider: &dyn SyncObjectProvider,
    journal: &SyncJournal,
    cancellation: &ProviderCancellation,
    vault_key: &VaultKey,
    vault_id: &str,
    additional_live_blob_id: Option<&str>,
    now_ms: i64,
) -> Result<BlobGcCycleResult, String> {
    let blob_prefix = format!("vpshell/v1/{vault_id}/blobs/");
    let blob_objects = list_all(provider, &blob_prefix, cancellation)?;
    if blob_objects.is_empty() {
        return Ok(BlobGcCycleResult::default());
    }
    let snapshot = journal
        .blob_gc_frontier(vault_id)
        .map_err(|_| "storage".to_string())?;
    if snapshot.has_pending_objects {
        return Ok(BlobGcCycleResult::default());
    }
    let mut live_blob_ids = snapshot.live_blob_ids.into_iter().collect::<BTreeSet<_>>();
    if let Some(blob_id) = additional_live_blob_id {
        if !valid_hash(blob_id) {
            return Err("protocol".to_string());
        }
        live_blob_ids.insert(blob_id.to_string());
    }
    if live_blob_ids.len() > MAX_GC_LIVE_BLOBS {
        return Err("resource-limit".to_string());
    }
    let live_blob_ids = live_blob_ids.into_iter().collect::<Vec<_>>();

    let member_prefix = format!("vpshell/v1/{vault_id}/blob-gc/members/");
    let local_member = BlobGcMember {
        format_version: GC_FORMAT_VERSION,
        vault_id: vault_id.to_string(),
        device_id: snapshot.local_device_id.clone(),
    };
    let local_member_bytes =
        serde_json::to_vec(&local_member).map_err(|_| "protocol".to_string())?;
    let published_member = put_index(
        provider,
        cancellation,
        vault_key,
        vault_id,
        &member_key(vault_id, &snapshot.local_device_id),
        &member_object_id(&snapshot.local_device_id),
        &local_member_bytes,
    )?;

    let mut members = BTreeSet::new();
    for metadata in list_all(provider, &member_prefix, cancellation)? {
        let device_id = metadata
            .key
            .strip_prefix(&member_prefix)
            .and_then(|value| value.strip_suffix(".ogcm"))
            .ok_or_else(|| "protocol".to_string())?;
        let encoded = provider
            .get(&metadata.key, cancellation)
            .map_err(provider_error)?;
        if encoded.len() as u64 != metadata.size {
            return Err("integrity".to_string());
        }
        let member: BlobGcMember =
            decode_index(&encoded, vault_key, vault_id, &member_object_id(device_id))?;
        validate_membership(&member, vault_id)?;
        if member.device_id != device_id || !members.insert(device_id.to_string()) {
            return Err("protocol".to_string());
        }
    }
    if members.is_empty() || members.len() > MAX_GC_MEMBERS {
        return Err("resource-limit".to_string());
    }
    if snapshot
        .frontier
        .keys()
        .any(|device_id| !members.contains(device_id))
    {
        return Ok(BlobGcCycleResult {
            published_objects: if published_member { 1 } else { 0 },
            deleted_objects: 0,
        });
    }

    let member_list = members.iter().cloned().collect::<Vec<_>>();
    let acknowledgement = BlobGcAcknowledgement {
        format_version: GC_FORMAT_VERSION,
        vault_id: vault_id.to_string(),
        device_id: snapshot.local_device_id.clone(),
        members: member_list.clone(),
        frontier: snapshot.frontier.clone(),
        live_blob_ids: live_blob_ids.clone(),
    };
    validate_acknowledgement(&acknowledgement, vault_id)?;
    let acknowledgement_bytes =
        serde_json::to_vec(&acknowledgement).map_err(|_| "protocol".to_string())?;
    let acknowledgement_hash = hash(&acknowledgement_bytes);
    let published_ack = put_index(
        provider,
        cancellation,
        vault_key,
        vault_id,
        &acknowledgement_key(vault_id, &snapshot.local_device_id, &acknowledgement_hash),
        &acknowledgement_object_id(&snapshot.local_device_id, &acknowledgement_hash),
        &acknowledgement_bytes,
    )?;

    let acknowledgement_prefix = format!("vpshell/v1/{vault_id}/blob-gc/acks/");
    let mut acknowledgements = Vec::new();
    for metadata in list_all(provider, &acknowledgement_prefix, cancellation)? {
        let relative = metadata
            .key
            .strip_prefix(&acknowledgement_prefix)
            .ok_or_else(|| "protocol".to_string())?;
        let (device_id, filename) = relative
            .split_once('/')
            .ok_or_else(|| "protocol".to_string())?;
        let digest = filename
            .strip_suffix(".ogca")
            .filter(|value| valid_hash(value))
            .ok_or_else(|| "protocol".to_string())?;
        let encoded = provider
            .get(&metadata.key, cancellation)
            .map_err(provider_error)?;
        if encoded.len() as u64 != metadata.size {
            return Err("integrity".to_string());
        }
        let decoded: BlobGcAcknowledgement = decode_index(
            &encoded,
            vault_key,
            vault_id,
            &acknowledgement_object_id(device_id, digest),
        )?;
        validate_acknowledgement(&decoded, vault_id)?;
        let canonical = serde_json::to_vec(&decoded).map_err(|_| "protocol".to_string())?;
        if decoded.device_id != device_id || hash(&canonical) != digest {
            return Err("integrity".to_string());
        }
        acknowledgements.push((metadata.key, decoded));
    }

    let mut grouped = BTreeMap::<String, Vec<SyncObjectMetadata>>::new();
    for metadata in blob_objects {
        let relative = metadata
            .key
            .strip_prefix(&blob_prefix)
            .ok_or_else(|| "protocol".to_string())?;
        let (blob_id, filename) = relative
            .split_once('/')
            .ok_or_else(|| "protocol".to_string())?;
        if !valid_hash(blob_id)
            || !(filename == "manifest.oblob"
                || (filename.len() == 12
                    && filename.ends_with(".oblob")
                    && filename[..6].bytes().all(|byte| byte.is_ascii_digit())))
        {
            return Err("protocol".to_string());
        }
        grouped
            .entry(blob_id.to_string())
            .or_default()
            .push(metadata);
    }

    let mut result = BlobGcCycleResult {
        published_objects: (if published_member { 1 } else { 0 })
            + (if published_ack { 1 } else { 0 }),
        deleted_objects: 0,
    };
    let expected_remote = snapshot
        .frontier
        .iter()
        .filter(|(_, sequence)| **sequence > 0)
        .map(|(device_id, sequence)| (device_id.clone(), *sequence))
        .collect::<BTreeMap<_, _>>();
    let mut verified_remote_frontier = None;
    for (blob_id, mut objects) in grouped {
        if live_blob_ids.binary_search(&blob_id).is_ok() {
            journal
                .reset_blob_gc_candidate(vault_id, &blob_id)
                .map_err(|_| "storage".to_string())?;
            continue;
        }
        if !objects
            .iter()
            .any(|object| object.key.ends_with("/manifest.oblob"))
        {
            return Err("integrity".to_string());
        }
        let mut selected = Vec::new();
        for member in &member_list {
            let matching = acknowledgements
                .iter()
                .filter(|(_, acknowledgement)| {
                    acknowledgement.device_id.as_str() == member.as_str()
                        && acknowledgement.members == member_list
                        && snapshot.frontier.iter().all(|(device_id, sequence)| {
                            acknowledgement
                                .frontier
                                .get(device_id)
                                .copied()
                                .unwrap_or(0)
                                >= *sequence
                        })
                })
                .collect::<Vec<_>>();
            if matching.is_empty()
                || matching
                    .iter()
                    .any(|(_, acknowledgement)| acknowledgement.live_blob_ids.contains(&blob_id))
            {
                journal
                    .reset_blob_gc_candidate(vault_id, &blob_id)
                    .map_err(|_| "storage".to_string())?;
                selected.clear();
                break;
            }
            selected.extend(matching.into_iter().map(|(key, _)| key.clone()));
        }
        if selected.len() < member_list.len() {
            continue;
        }
        selected.sort();
        let confirmation_hash = hash(selected.join("\n").as_bytes());
        let ready = journal
            .observe_blob_gc_candidate(
                vault_id,
                &blob_id,
                &confirmation_hash,
                now_ms,
                GC_RETENTION_MS,
            )
            .map_err(|_| "storage".to_string())?;
        if !ready {
            continue;
        }
        if verified_remote_frontier.is_none() {
            verified_remote_frontier = Some(remote_segment_frontier(
                provider,
                vault_key,
                vault_id,
                cancellation,
            )?);
        }
        if verified_remote_frontier.as_ref() != Some(&expected_remote) {
            journal
                .reset_blob_gc_candidate(vault_id, &blob_id)
                .map_err(|_| "storage".to_string())?;
            continue;
        }
        let restored =
            restore_wallpaper_blob(provider, cancellation, vault_key, vault_id, &blob_id)
                .map_err(|_| "integrity".to_string())?;
        if restored.blob_id != blob_id
            || usize::try_from(restored.object_count).ok() != Some(objects.len())
        {
            return Err("integrity".to_string());
        }
        objects.sort_by(|left, right| {
            left.key
                .ends_with("/manifest.oblob")
                .cmp(&right.key.ends_with("/manifest.oblob"))
                .then_with(|| left.key.cmp(&right.key))
        });
        let mut authenticated = Vec::with_capacity(objects.len());
        for metadata in &objects {
            let encoded = provider
                .get(&metadata.key, cancellation)
                .map_err(provider_error)?;
            if encoded.len() as u64 != metadata.size {
                return Err("integrity".to_string());
            }
            let envelope =
                EncryptedSyncObject::decode(&encoded).map_err(|_| "integrity".to_string())?;
            if !object_key_matches_blob_envelope(&metadata.key, vault_id, &envelope)
                || decrypt_sync_object(vault_key, &envelope).is_err()
            {
                return Err("integrity".to_string());
            }
            authenticated.push((metadata.key.clone(), encoded));
        }
        for (key, encoded) in authenticated {
            let outcome = match provider.delete_exact(&key, &encoded, cancellation) {
                Err(error) if error.code == ProviderErrorCode::Protocol => {
                    return Ok(result);
                }
                Err(error) => return Err(provider_error(error)),
                Ok(outcome) => outcome,
            };
            match outcome {
                DeleteObjectOutcome::Deleted | DeleteObjectOutcome::AlreadyAbsent => {
                    result.deleted_objects = result.deleted_objects.saturating_add(1);
                }
            }
        }
        journal
            .reset_blob_gc_candidate(vault_id, &blob_id)
            .map_err(|_| "storage".to_string())?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::{
        local_assets::ManagedWallpaper,
        sync_blob::prepare_wallpaper_blob,
        sync_provider::{LocalFolderProvider, SyncObjectProvider},
    };

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("vpshell-blob-gc-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).expect("temp directory");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn seed_blob(
        provider: &LocalFolderProvider,
        vault_key: &VaultKey,
        vault_id: &str,
        blob_id: String,
    ) {
        let bytes = b"gc fixture".to_vec();
        let wallpaper = ManagedWallpaper {
            blob_id,
            media_type: "image/png".to_string(),
            content_hash: hash(&bytes),
            bytes,
        };
        let cancellation = ProviderCancellation::default();
        for object in prepare_wallpaper_blob(vault_key, vault_id, &wallpaper).expect("blob") {
            provider
                .put(&object.key, &object.encoded, &cancellation)
                .expect("seed object");
        }
    }

    #[test]
    fn gc_requires_retention_before_deleting_authenticated_blob() {
        let temp = TempDir::new();
        let provider_root = temp.0.join("remote");
        fs::create_dir_all(&provider_root).expect("provider directory");
        let provider = LocalFolderProvider::open(&provider_root).expect("provider");
        let journal = SyncJournal::open(temp.0.join("journal")).expect("journal");
        let vault_key = VaultKey::generate().expect("vault key");
        let vault_id = Uuid::new_v4().to_string();
        let blob_id = "ab".repeat(32);
        seed_blob(&provider, &vault_key, &vault_id, blob_id.clone());
        let cancellation = ProviderCancellation::default();

        let first = run_blob_gc(
            &provider,
            &journal,
            &cancellation,
            &vault_key,
            &vault_id,
            None,
            1_000,
        )
        .expect("first gc cycle");
        assert_eq!(first.deleted_objects, 0);
        assert!(first.published_objects >= 2);

        let second = run_blob_gc(
            &provider,
            &journal,
            &cancellation,
            &vault_key,
            &vault_id,
            None,
            1_000 + GC_RETENTION_MS,
        )
        .expect("retained gc cycle");
        assert_eq!(second.deleted_objects, 2);
        assert!(
            provider
                .list(
                    &format!("vpshell/v1/{vault_id}/blobs/{blob_id}/"),
                    None,
                    LIST_PAGE_SIZE,
                    &cancellation,
                )
                .expect("list after gc")
                .objects
                .is_empty()
        );
    }

    #[test]
    fn gc_never_deletes_current_live_blob() {
        let temp = TempDir::new();
        let provider_root = temp.0.join("remote");
        fs::create_dir_all(&provider_root).expect("provider directory");
        let provider = LocalFolderProvider::open(&provider_root).expect("provider");
        let journal = SyncJournal::open(temp.0.join("journal")).expect("journal");
        let vault_key = VaultKey::generate().expect("vault key");
        let vault_id = Uuid::new_v4().to_string();
        let blob_id = "cd".repeat(32);
        seed_blob(&provider, &vault_key, &vault_id, blob_id.clone());
        let cancellation = ProviderCancellation::default();

        let result = run_blob_gc(
            &provider,
            &journal,
            &cancellation,
            &vault_key,
            &vault_id,
            Some(&blob_id),
            1_000 + GC_RETENTION_MS * 2,
        )
        .expect("live blob gc cycle");
        assert_eq!(result.deleted_objects, 0);
        assert!(
            !provider
                .list(
                    &format!("vpshell/v1/{vault_id}/blobs/{blob_id}/"),
                    None,
                    LIST_PAGE_SIZE,
                    &cancellation,
                )
                .expect("list live blob")
                .objects
                .is_empty()
        );
    }
}

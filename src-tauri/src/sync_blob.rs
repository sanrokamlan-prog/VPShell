//! Bounded immutable objects for managed wallpaper synchronization.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    local_assets::ManagedWallpaper,
    sync_crypto::{
        EncryptedSyncObject, SyncObjectKind, VaultKey, decrypt_sync_object, encrypt_sync_object,
    },
    sync_provider::{
        ProviderCancellation, ProviderErrorCode, SyncObjectProvider, validate_object_bytes,
    },
};

const BLOB_FORMAT_VERSION: u16 = 1;
const CHUNK_BYTES: usize = 256 * 1024;
const MAX_WALLPAPER_BYTES: usize = 8 * 1024 * 1024;
const MAX_CHUNKS: usize = MAX_WALLPAPER_BYTES / CHUNK_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedBlobObject {
    pub(crate) key: String,
    pub(crate) encoded: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RestoredWallpaper {
    pub(crate) blob_id: String,
    pub(crate) media_type: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) object_count: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WallpaperBlobManifest {
    format_version: u16,
    blob_id: String,
    media_type: String,
    total_size: usize,
    chunk_size: usize,
    chunk_count: usize,
    content_hash: String,
    chunk_hashes: Vec<String>,
}

fn is_lowercase_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn validate_blob_id(blob_id: &str) -> Result<(), String> {
    if is_lowercase_hash(blob_id) {
        Ok(())
    } else {
        Err("blob-invalid".to_string())
    }
}

fn blob_prefix(vault_id: &str, blob_id: &str) -> String {
    format!("vpshell/v1/{vault_id}/blobs/{blob_id}/")
}

fn manifest_object_id(blob_id: &str) -> String {
    format!("{blob_id}-manifest")
}

fn chunk_object_id(blob_id: &str, index: usize) -> String {
    format!("{blob_id}-{index:06}")
}

fn manifest_key(vault_id: &str, blob_id: &str) -> String {
    format!("{}manifest.oblob", blob_prefix(vault_id, blob_id))
}

fn chunk_key(vault_id: &str, blob_id: &str, index: usize) -> String {
    format!("{}{index:06}.oblob", blob_prefix(vault_id, blob_id))
}

fn validate_manifest(manifest: &WallpaperBlobManifest) -> Result<(), String> {
    validate_blob_id(&manifest.blob_id)?;
    if manifest.format_version != BLOB_FORMAT_VERSION
        || !matches!(
            manifest.media_type.as_str(),
            "image/png" | "image/jpeg" | "image/webp"
        )
        || manifest.total_size == 0
        || manifest.total_size > MAX_WALLPAPER_BYTES
        || manifest.chunk_size != CHUNK_BYTES
        || manifest.chunk_count == 0
        || manifest.chunk_count > MAX_CHUNKS
        || manifest.chunk_count != manifest.total_size.div_ceil(CHUNK_BYTES)
        || manifest.chunk_hashes.len() != manifest.chunk_count
        || !is_lowercase_hash(&manifest.content_hash)
        || manifest
            .chunk_hashes
            .iter()
            .any(|value| !is_lowercase_hash(value))
    {
        return Err("blob-manifest-invalid".to_string());
    }
    Ok(())
}

pub(crate) fn prepare_wallpaper_blob(
    vault_key: &VaultKey,
    vault_id: &str,
    wallpaper: &ManagedWallpaper,
) -> Result<Vec<PreparedBlobObject>, String> {
    validate_blob_id(&wallpaper.blob_id)?;
    if !matches!(
        wallpaper.media_type.as_str(),
        "image/png" | "image/jpeg" | "image/webp"
    ) || wallpaper.bytes.is_empty()
        || wallpaper.bytes.len() > MAX_WALLPAPER_BYTES
        || wallpaper.content_hash != hash(&wallpaper.bytes)
    {
        return Err("blob-source-invalid".to_string());
    }
    let chunks = wallpaper.bytes.chunks(CHUNK_BYTES).collect::<Vec<_>>();
    if chunks.is_empty() || chunks.len() > MAX_CHUNKS {
        return Err("resource-limit".to_string());
    }
    let chunk_hashes = chunks.iter().map(|chunk| hash(chunk)).collect::<Vec<_>>();
    let manifest = WallpaperBlobManifest {
        format_version: BLOB_FORMAT_VERSION,
        blob_id: wallpaper.blob_id.clone(),
        media_type: wallpaper.media_type.clone(),
        total_size: wallpaper.bytes.len(),
        chunk_size: CHUNK_BYTES,
        chunk_count: chunks.len(),
        content_hash: wallpaper.content_hash.clone(),
        chunk_hashes,
    };
    validate_manifest(&manifest)?;
    let manifest_bytes =
        serde_json::to_vec(&manifest).map_err(|_| "blob-manifest-invalid".to_string())?;
    let mut objects = Vec::with_capacity(chunks.len() + 1);
    for (index, chunk) in chunks.into_iter().enumerate() {
        let encoded = encrypt_sync_object(
            vault_key,
            vault_id,
            SyncObjectKind::Blob,
            &chunk_object_id(&wallpaper.blob_id, index),
            None,
            None,
            chunk,
        )
        .and_then(|object| object.encode())
        .map_err(|_| "blob-encrypt".to_string())?;
        validate_object_bytes(&encoded).map_err(|_| "resource-limit".to_string())?;
        objects.push(PreparedBlobObject {
            key: chunk_key(vault_id, &wallpaper.blob_id, index),
            encoded,
        });
    }
    let encoded = encrypt_sync_object(
        vault_key,
        vault_id,
        SyncObjectKind::Blob,
        &manifest_object_id(&wallpaper.blob_id),
        None,
        None,
        &manifest_bytes,
    )
    .and_then(|object| object.encode())
    .map_err(|_| "blob-encrypt".to_string())?;
    validate_object_bytes(&encoded).map_err(|_| "resource-limit".to_string())?;
    objects.push(PreparedBlobObject {
        key: manifest_key(vault_id, &wallpaper.blob_id),
        encoded,
    });
    Ok(objects)
}

fn provider_code(code: ProviderErrorCode) -> String {
    match code {
        ProviderErrorCode::Cancelled => "cancelled",
        ProviderErrorCode::NotFound => "blob-missing",
        ProviderErrorCode::LimitExceeded => "resource-limit",
        ProviderErrorCode::Unavailable => "remote-unavailable",
        ProviderErrorCode::InvalidInput
        | ProviderErrorCode::UnsafePath
        | ProviderErrorCode::Conflict
        | ProviderErrorCode::Protocol => "blob-integrity",
    }
    .to_string()
}

fn decrypt_expected(
    encoded: &[u8],
    vault_key: &VaultKey,
    vault_id: &str,
    object_id: &str,
) -> Result<Vec<u8>, String> {
    let envelope =
        EncryptedSyncObject::decode(encoded).map_err(|_| "blob-integrity".to_string())?;
    if envelope.vault_id() != vault_id
        || envelope.object_kind() != &SyncObjectKind::Blob
        || envelope.object_id() != object_id
        || envelope.device_id().is_some()
        || envelope.sequence().is_some()
    {
        return Err("blob-integrity".to_string());
    }
    decrypt_sync_object(vault_key, &envelope).map_err(|_| "blob-integrity".to_string())
}

pub(crate) fn restore_wallpaper_blob(
    provider: &dyn SyncObjectProvider,
    cancellation: &ProviderCancellation,
    vault_key: &VaultKey,
    vault_id: &str,
    blob_id: &str,
) -> Result<RestoredWallpaper, String> {
    validate_blob_id(blob_id)?;
    cancellation
        .check()
        .map_err(|error| provider_code(error.code))?;
    let manifest_encoded = provider
        .get(&manifest_key(vault_id, blob_id), cancellation)
        .map_err(|error| provider_code(error.code))?;
    let manifest_plaintext = decrypt_expected(
        &manifest_encoded,
        vault_key,
        vault_id,
        &manifest_object_id(blob_id),
    )?;
    if manifest_plaintext.is_empty() || manifest_plaintext.len() > 16 * 1024 {
        return Err("blob-manifest-invalid".to_string());
    }
    let manifest: WallpaperBlobManifest = serde_json::from_slice(&manifest_plaintext)
        .map_err(|_| "blob-manifest-invalid".to_string())?;
    validate_manifest(&manifest)?;
    if manifest.blob_id != blob_id {
        return Err("blob-integrity".to_string());
    }
    let mut bytes = Vec::with_capacity(manifest.total_size);
    let mut seen = BTreeSet::new();
    for index in 0..manifest.chunk_count {
        cancellation
            .check()
            .map_err(|error| provider_code(error.code))?;
        let key = chunk_key(vault_id, blob_id, index);
        if !seen.insert(key.clone()) {
            return Err("blob-integrity".to_string());
        }
        let encoded = provider
            .get(&key, cancellation)
            .map_err(|error| provider_code(error.code))?;
        let chunk = decrypt_expected(
            &encoded,
            vault_key,
            vault_id,
            &chunk_object_id(blob_id, index),
        )?;
        let expected_size = if index + 1 == manifest.chunk_count {
            manifest.total_size - CHUNK_BYTES * index
        } else {
            CHUNK_BYTES
        };
        if chunk.len() != expected_size || hash(&chunk) != manifest.chunk_hashes[index] {
            return Err("blob-integrity".to_string());
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != manifest.total_size || hash(&bytes) != manifest.content_hash {
        return Err("blob-integrity".to_string());
    }
    cancellation
        .check()
        .map_err(|error| provider_code(error.code))?;
    Ok(RestoredWallpaper {
        blob_id: blob_id.to_string(),
        media_type: manifest.media_type,
        bytes,
        object_count: u32::try_from(manifest.chunk_count)
            .unwrap_or(u32::MAX)
            .saturating_add(1),
    })
}

pub(crate) fn equivalent_blob_objects(
    vault_key: &VaultKey,
    expected: &[u8],
    actual: &[u8],
) -> bool {
    let Ok(expected) = EncryptedSyncObject::decode(expected) else {
        return false;
    };
    let Ok(actual) = EncryptedSyncObject::decode(actual) else {
        return false;
    };
    if expected.object_kind() != &SyncObjectKind::Blob
        || actual.object_kind() != &SyncObjectKind::Blob
        || expected.vault_id() != actual.vault_id()
        || expected.object_id() != actual.object_id()
        || expected.device_id().is_some()
        || actual.device_id().is_some()
        || expected.sequence().is_some()
        || actual.sequence().is_some()
    {
        return false;
    }
    match (
        decrypt_sync_object(vault_key, &expected),
        decrypt_sync_object(vault_key, &actual),
    ) {
        (Ok(expected), Ok(actual)) => expected == actual,
        _ => false,
    }
}

pub(crate) fn object_key_matches_blob_envelope(
    key: &str,
    vault_id: &str,
    envelope: &EncryptedSyncObject,
) -> bool {
    if envelope.vault_id() != vault_id
        || envelope.object_kind() != &SyncObjectKind::Blob
        || envelope.device_id().is_some()
        || envelope.sequence().is_some()
    {
        return false;
    }
    let Some((blob_id, suffix)) = envelope.object_id().split_once('-') else {
        return false;
    };
    if validate_blob_id(blob_id).is_err() {
        return false;
    }
    if suffix == "manifest" {
        key == manifest_key(vault_id, blob_id)
    } else if suffix.len() == 6 && suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        suffix
            .parse::<usize>()
            .is_ok_and(|index| index < MAX_CHUNKS && key == chunk_key(vault_id, blob_id, index))
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::sync_provider::{LocalFolderProvider, SyncObjectProvider};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("vpshell-sync-blob-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn jpeg_fixture() -> Vec<u8> {
        vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x02, 0xff, 0xd9]
    }

    fn webp_fixture() -> Vec<u8> {
        let mut bytes = b"RIFF".to_vec();
        bytes.extend_from_slice(&12_u32.to_le_bytes());
        bytes.extend_from_slice(b"WEBPVP8 ");
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes
    }

    #[test]
    fn wallpaper_blob_round_trips_multiple_authenticated_chunks() {
        let root = TempDir::new();
        let provider = LocalFolderProvider::open(&root.0).unwrap();
        let key = VaultKey::generate().unwrap();
        let vault_id = uuid::Uuid::new_v4().to_string();
        let bytes = vec![0x5a; CHUNK_BYTES + 19];
        let wallpaper = ManagedWallpaper {
            blob_id: "ab".repeat(32),
            media_type: "image/png".to_string(),
            content_hash: hash(&bytes),
            bytes: bytes.clone(),
        };
        let cancellation = ProviderCancellation::default();
        let objects = prepare_wallpaper_blob(&key, &vault_id, &wallpaper).unwrap();
        assert_eq!(objects.len(), 3);
        for object in objects {
            provider
                .put(&object.key, &object.encoded, &cancellation)
                .unwrap();
        }
        let restored = restore_wallpaper_blob(
            &provider,
            &cancellation,
            &key,
            &vault_id,
            &wallpaper.blob_id,
        )
        .unwrap();
        assert_eq!(restored.bytes, bytes);
    }

    #[test]
    fn jpeg_and_webp_blob_manifests_round_trip_media_type() {
        let root = TempDir::new();
        let provider = LocalFolderProvider::open(&root.0).unwrap();
        let key = VaultKey::generate().unwrap();
        let vault_id = uuid::Uuid::new_v4().to_string();
        let cancellation = ProviderCancellation::default();
        for (blob_id, media_type, bytes) in [
            ("34".repeat(32), "image/jpeg", jpeg_fixture()),
            ("56".repeat(32), "image/webp", webp_fixture()),
        ] {
            let wallpaper = ManagedWallpaper {
                blob_id,
                media_type: media_type.to_string(),
                content_hash: hash(&bytes),
                bytes: bytes.clone(),
            };
            for object in prepare_wallpaper_blob(&key, &vault_id, &wallpaper).unwrap() {
                provider
                    .put(&object.key, &object.encoded, &cancellation)
                    .unwrap();
            }
            let restored = restore_wallpaper_blob(
                &provider,
                &cancellation,
                &key,
                &vault_id,
                &wallpaper.blob_id,
            )
            .unwrap();
            assert_eq!(restored.media_type, media_type);
            assert_eq!(restored.bytes, bytes);
        }
    }

    #[test]
    fn wrong_identity_missing_chunk_and_oversized_manifest_fail_closed() {
        let key = VaultKey::generate().unwrap();
        let vault_id = uuid::Uuid::new_v4().to_string();
        let wallpaper = ManagedWallpaper {
            blob_id: "cd".repeat(32),
            media_type: "image/png".to_string(),
            content_hash: hash(b"fixture"),
            bytes: b"fixture".to_vec(),
        };
        let objects = prepare_wallpaper_blob(&key, &vault_id, &wallpaper).unwrap();
        let envelope = EncryptedSyncObject::decode(&objects[0].encoded).unwrap();
        assert!(object_key_matches_blob_envelope(
            &objects[0].key,
            &vault_id,
            &envelope
        ));
        assert!(!object_key_matches_blob_envelope(
            &objects[0].key.replace("000000", "000001"),
            &vault_id,
            &envelope,
        ));
        let invalid = WallpaperBlobManifest {
            format_version: BLOB_FORMAT_VERSION,
            blob_id: wallpaper.blob_id,
            media_type: "image/png".to_string(),
            total_size: MAX_WALLPAPER_BYTES + 1,
            chunk_size: CHUNK_BYTES,
            chunk_count: MAX_CHUNKS + 1,
            content_hash: "ef".repeat(32),
            chunk_hashes: vec!["ef".repeat(32); MAX_CHUNKS + 1],
        };
        assert!(validate_manifest(&invalid).is_err());
    }

    #[test]
    fn missing_chunk_and_different_authenticated_content_fail_closed() {
        let root = TempDir::new();
        let provider = LocalFolderProvider::open(&root.0).unwrap();
        let key = VaultKey::generate().unwrap();
        let vault_id = uuid::Uuid::new_v4().to_string();
        let bytes = vec![0x33; CHUNK_BYTES + 1];
        let wallpaper = ManagedWallpaper {
            blob_id: "12".repeat(32),
            media_type: "image/png".to_string(),
            content_hash: hash(&bytes),
            bytes,
        };
        let objects = prepare_wallpaper_blob(&key, &vault_id, &wallpaper).unwrap();
        let cancellation = ProviderCancellation::default();
        provider
            .put(
                &objects.last().unwrap().key,
                &objects.last().unwrap().encoded,
                &cancellation,
            )
            .unwrap();
        assert_eq!(
            restore_wallpaper_blob(
                &provider,
                &cancellation,
                &key,
                &vault_id,
                &wallpaper.blob_id,
            )
            .unwrap_err(),
            "blob-missing"
        );

        let first = &objects[0];
        let envelope = EncryptedSyncObject::decode(&first.encoded).unwrap();
        let different = encrypt_sync_object(
            &key,
            &vault_id,
            SyncObjectKind::Blob,
            envelope.object_id(),
            None,
            None,
            b"different",
        )
        .and_then(|object| object.encode())
        .unwrap();
        assert!(!equivalent_blob_objects(&key, &first.encoded, &different));
    }
}

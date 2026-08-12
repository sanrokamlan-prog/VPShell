//! Cross-module protocol regression fixtures.
//!
//! These tests intentionally exercise the public(crate) boundaries together so a
//! format change cannot pass isolated unit tests while breaking replay or merge
//! coordination.

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use serde_json::json;

    use crate::{
        sync_crypto::{
            EncryptedSyncObject, SyncObjectKind, VaultKey, decrypt_sync_object, encrypt_sync_object,
        },
        sync_merge::{ApplyOutcome, MergeState},
        sync_outbox::{EnqueueOutcome, JournalErrorCode, SyncJournal},
        sync_provider::{
            LocalFolderProvider, ProviderCancellation, ProviderErrorCode, PutObjectOutcome,
            SyncObjectProvider,
        },
    };

    const VAULT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const DEVICE_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const ENTITY_ID: &str = "22222222-2222-4222-8222-222222222222";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("vpshell-protocol-{label}-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn blob(key: &VaultKey, id: &str, bytes: &[u8]) -> Vec<u8> {
        encrypt_sync_object(key, VAULT_ID, SyncObjectKind::Blob, id, None, None, bytes)
            .unwrap()
            .encode()
            .unwrap()
    }

    #[test]
    fn crypto_upgrade_and_tamper_fail_before_journal_or_plaintext_use() {
        let key = VaultKey::generate().unwrap();
        let encoded = blob(&key, "blob-a", b"encrypted-data");
        let mut unknown: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        unknown["formatVersion"] = json!(99);
        assert!(EncryptedSyncObject::decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
        assert!(
            decrypt_sync_object(
                &VaultKey::generate().unwrap(),
                &EncryptedSyncObject::decode(&encoded).unwrap()
            )
            .is_err()
        );

        let root = TempDir::new("replay");
        let journal = SyncJournal::open(root.0.clone()).unwrap();
        assert_eq!(
            journal
                .enqueue_local("objects/blob-a.oseg", &encoded, 1, |_| Ok(()))
                .unwrap(),
            EnqueueOutcome::Queued
        );
        assert_eq!(
            journal
                .enqueue_local("objects/blob-a.oseg", &encoded, 2, |_| Ok(()))
                .unwrap(),
            EnqueueOutcome::AlreadyQueued
        );
        let moved_key = blob(&key, "blob-a", b"encrypted-data");
        assert_eq!(
            journal
                .enqueue_local("objects/blob-moved.oseg", &moved_key, 3, |_| Ok(()))
                .unwrap_err()
                .code,
            JournalErrorCode::Conflict
        );
        let claimed = journal.claim_next(1).unwrap().unwrap();
        journal
            .mark_published(&claimed.object_key, &claimed.lease_id, 2)
            .unwrap();
        assert_eq!(
            journal
                .mark_published(&claimed.object_key, &claimed.lease_id, 3)
                .unwrap_err()
                .code,
            JournalErrorCode::Finalized
        );
    }

    fn merge_operation(operation_id: &str, device_id: &str, sequence: u64, port: i64) -> Vec<u8> {
        json!({
            "formatVersion": 1,
            "operationId": operation_id,
            "deviceId": device_id,
            "sequence": sequence,
            "hlc": { "physicalMs": sequence, "logical": 0 },
            "payload": {
                "kind": "patch",
                "payload": {
                    "entityKind": "host",
                    "entityId": ENTITY_ID,
                    "fields": { "port": { "type": "integer", "value": port } },
                    "observedFields": {},
                    "observedTombstone": null
                }
            }
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn merge_conflicts_converge_in_both_arrival_orders_and_corrupt_state_stops() {
        let first = crate::sync_merge::MergeOperation::decode(&merge_operation(
            "33333333-3333-4333-8333-333333333333",
            DEVICE_A,
            1,
            22,
        ))
        .unwrap();
        let second = crate::sync_merge::MergeOperation::decode(&merge_operation(
            "44444444-4444-4444-8444-444444444444",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            1,
            2222,
        ))
        .unwrap();
        let mut left = MergeState::default();
        let mut right = MergeState::default();
        assert_eq!(left.apply(&first).unwrap(), ApplyOutcome::Applied);
        assert_eq!(left.apply(&second).unwrap(), ApplyOutcome::Applied);
        assert_eq!(right.apply(&second).unwrap(), ApplyOutcome::Applied);
        assert_eq!(right.apply(&first).unwrap(), ApplyOutcome::Applied);
        assert_eq!(left, right);
        assert_eq!(left.open_conflicts().len(), 1);
        let encoded = left.encode().unwrap();
        assert_eq!(MergeState::decode(&encoded).unwrap(), left);
        assert!(MergeState::decode(&encoded[..encoded.len() / 2]).is_err());
    }

    #[test]
    fn local_provider_offline_cancel_and_truncated_object_are_explicit() {
        let root = TempDir::new("provider");
        let provider = LocalFolderProvider::open(&root.0).unwrap();
        let cancellation = ProviderCancellation::default();
        assert_eq!(
            provider.put("objects/a.oseg", b"bytes", &cancellation),
            Ok(PutObjectOutcome::Created)
        );
        fs::write(root.0.join("objects/truncated.oseg"), b"{").unwrap();
        assert_eq!(
            provider
                .get("objects/truncated.oseg", &cancellation)
                .unwrap(),
            b"{"
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
}

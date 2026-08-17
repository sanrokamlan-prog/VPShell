//! Rust-owned orchestration for encrypted object synchronization.
//!
//! The coordinator is the only layer allowed to move objects between a
//! provider and the journal.  It exposes value-free status snapshots; vault
//! keys, provider credentials, decrypted operations, and object bytes remain
//! inside Rust.

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use serde::Serialize;

use crate::{
    sync_crypto::{EncryptedSyncObject, SyncObjectKind, VaultKey},
    sync_outbox::{AttemptFailure, JournalErrorCode, RemoteApplyOutcome, SyncJournal},
    sync_provider::{
        ProviderCancellation, ProviderError, ProviderErrorCode, SyncObjectMetadata,
        SyncObjectProvider,
    },
};

const COORDINATOR_SCHEMA_VERSION: u16 = 1;
const MAX_PUSH_OBJECTS_PER_CYCLE: usize = 128;
const MAX_PULL_OBJECTS_PER_CYCLE: usize = 1_000;
const MAX_PULL_BYTES_PER_CYCLE: u64 = 64 * 1024 * 1024;
const LIST_PAGE_SIZE: usize = 250;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SyncCoordinatorPhase {
    NotConfigured,
    Idle,
    Uploading,
    Downloading,
    Merging,
    WaitingRetry,
    Conflicts,
    ReconcileRequired,
    Suspended,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SyncCoordinatorStatus {
    pub(crate) schema_version: u16,
    pub(crate) phase: SyncCoordinatorPhase,
    pub(crate) configured: bool,
    pub(crate) running: bool,
    pub(crate) generation: u64,
    pub(crate) pending_objects: u64,
    pub(crate) pending_bytes: u64,
    pub(crate) merge_revision: u64,
    pub(crate) open_conflicts: usize,
    pub(crate) recovery_required: bool,
    pub(crate) recovery_note: Option<String>,
    pub(crate) last_error_code: Option<String>,
    pub(crate) last_completed_at_ms: Option<i64>,
    pub(crate) last_uploaded_objects: u32,
    pub(crate) last_downloaded_objects: u32,
}

struct CoordinatorSession {
    provider: Arc<dyn SyncObjectProvider>,
    vault_key: Arc<VaultKey>,
    vault_id: String,
    remote_prefix: String,
}

struct CoordinatorRuntime {
    phase: SyncCoordinatorPhase,
    session: Option<CoordinatorSession>,
    running: bool,
    generation: u64,
    cancellation: ProviderCancellation,
    last_error_code: Option<String>,
    last_completed_at_ms: Option<i64>,
    last_uploaded_objects: u32,
    last_downloaded_objects: u32,
}

impl Default for CoordinatorRuntime {
    fn default() -> Self {
        Self {
            phase: SyncCoordinatorPhase::NotConfigured,
            session: None,
            running: false,
            generation: 0,
            cancellation: ProviderCancellation::default(),
            last_error_code: None,
            last_completed_at_ms: None,
            last_uploaded_objects: 0,
            last_downloaded_objects: 0,
        }
    }
}

pub(crate) struct SyncCoordinatorManager {
    journal: SyncJournal,
    runtime: Mutex<CoordinatorRuntime>,
}

struct RemoteCandidate {
    metadata: SyncObjectMetadata,
    encoded: Vec<u8>,
    device_id: String,
    sequence: u64,
}

#[derive(Clone, Copy)]
struct CycleCounts {
    uploaded: u32,
    downloaded: u32,
}

impl SyncCoordinatorManager {
    pub(crate) fn open(app_data_directory: std::path::PathBuf) -> Result<Self, String> {
        let journal = SyncJournal::open(app_data_directory)
            .map_err(|_| "无法初始化同步协调器 journal".to_string())?;
        Ok(Self {
            journal,
            runtime: Mutex::new(CoordinatorRuntime::default()),
        })
    }

    fn lock_runtime(&self) -> Result<std::sync::MutexGuard<'_, CoordinatorRuntime>, String> {
        self.runtime
            .lock()
            .map_err(|_| "同步协调器状态已损坏".to_string())
    }

    pub(crate) fn status(&self) -> Result<SyncCoordinatorStatus, String> {
        let journal = self
            .journal
            .status()
            .map_err(|_| "无法读取同步 journal 状态".to_string())?;
        let merge = self
            .journal
            .merge_status()
            .map_err(|_| "无法读取同步冲突状态".to_string())?;
        let runtime = self.lock_runtime()?;
        let recovery_required = journal.safety_blocked;
        let phase = if recovery_required {
            SyncCoordinatorPhase::ReconcileRequired
        } else if !runtime.running && merge.open_conflicts > 0 {
            SyncCoordinatorPhase::Conflicts
        } else {
            runtime.phase
        };
        Ok(SyncCoordinatorStatus {
            schema_version: COORDINATOR_SCHEMA_VERSION,
            phase,
            configured: runtime.session.is_some(),
            running: runtime.running,
            generation: runtime.generation,
            pending_objects: journal.pending_objects,
            pending_bytes: journal.pending_bytes,
            merge_revision: merge.revision,
            open_conflicts: merge.open_conflicts,
            recovery_required,
            recovery_note: journal.recovery_note,
            last_error_code: runtime.last_error_code.clone(),
            last_completed_at_ms: runtime.last_completed_at_ms,
            last_uploaded_objects: runtime.last_uploaded_objects,
            last_downloaded_objects: runtime.last_downloaded_objects,
        })
    }

    pub(crate) fn cancel(&self) -> Result<(), String> {
        let mut runtime = self.lock_runtime()?;
        runtime.cancellation.cancel();
        runtime.generation = runtime.generation.saturating_add(1);
        runtime.phase = SyncCoordinatorPhase::Cancelled;
        runtime.running = false;
        runtime.last_error_code = Some("cancelled".to_string());
        Ok(())
    }

    pub(crate) fn acknowledge_reconciliation(&self) -> Result<(), String> {
        self.journal
            .acknowledge_reconciliation()
            .map_err(|_| "无法解除同步恢复阻止".to_string())?;
        let mut runtime = self.lock_runtime()?;
        runtime.phase = if runtime.session.is_some() {
            SyncCoordinatorPhase::Idle
        } else {
            SyncCoordinatorPhase::NotConfigured
        };
        runtime.last_error_code = None;
        Ok(())
    }

    pub(crate) fn attach_session(
        &self,
        provider: Arc<dyn SyncObjectProvider>,
        vault_key: VaultKey,
        vault_id: &str,
    ) -> Result<(), String> {
        let vault_id = uuid::Uuid::parse_str(vault_id)
            .map_err(|_| "同步 vault ID 格式无效".to_string())?
            .to_string();
        let mut runtime = self.lock_runtime()?;
        if runtime.running {
            return Err("同步运行期间不能替换 provider 会话".to_string());
        }
        runtime.cancellation.cancel();
        runtime.generation = runtime.generation.saturating_add(1);
        runtime.cancellation = ProviderCancellation::default();
        runtime.session = Some(CoordinatorSession {
            provider,
            vault_key: Arc::new(vault_key),
            vault_id: vault_id.clone(),
            remote_prefix: format!("vpshell/v1/{vault_id}/segments/"),
        });
        runtime.phase = SyncCoordinatorPhase::Idle;
        runtime.last_error_code = None;
        Ok(())
    }

    pub(crate) fn detach_session(&self) -> Result<(), String> {
        let mut runtime = self.lock_runtime()?;
        runtime.cancellation.cancel();
        runtime.generation = runtime.generation.saturating_add(1);
        runtime.running = false;
        runtime.session = None;
        runtime.phase = SyncCoordinatorPhase::NotConfigured;
        runtime.last_error_code = None;
        Ok(())
    }

    pub(crate) fn run_once(&self, now_ms: i64) -> Result<SyncCoordinatorStatus, String> {
        if now_ms < 0 {
            return Err("同步协调器时间不能为负数".to_string());
        }
        let (generation, provider, vault_key, vault_id, remote_prefix, cancellation) = {
            let mut runtime = self.lock_runtime()?;
            if runtime.running {
                return Err("同一 vault 已有同步 worker 运行".to_string());
            }
            let (provider, vault_key, vault_id, remote_prefix) = {
                let session = runtime
                    .session
                    .as_ref()
                    .ok_or_else(|| "同步尚未配置或已锁定".to_string())?;
                (
                    Arc::clone(&session.provider),
                    Arc::clone(&session.vault_key),
                    session.vault_id.clone(),
                    session.remote_prefix.clone(),
                )
            };
            runtime.running = true;
            runtime.generation = runtime.generation.saturating_add(1);
            runtime.cancellation = ProviderCancellation::default();
            runtime.phase = SyncCoordinatorPhase::Uploading;
            runtime.last_error_code = None;
            runtime.last_uploaded_objects = 0;
            runtime.last_downloaded_objects = 0;
            (
                runtime.generation,
                provider,
                vault_key,
                vault_id,
                remote_prefix,
                runtime.cancellation.clone(),
            )
        };

        let result = self.run_cycle(
            provider.as_ref(),
            vault_key.as_ref(),
            &vault_id,
            &remote_prefix,
            &cancellation,
            generation,
            now_ms,
        );
        match result {
            Ok(counts) => self.finish_cycle(generation, now_ms, counts, None)?,
            Err(code) => {
                let phase = if code == "cancelled" {
                    SyncCoordinatorPhase::Cancelled
                } else if matches!(
                    code.as_str(),
                    "network" | "timeout" | "rate-limited" | "remote-unavailable"
                ) {
                    SyncCoordinatorPhase::WaitingRetry
                } else {
                    SyncCoordinatorPhase::Suspended
                };
                self.finish_cycle_with_error(generation, phase, &code)?;
            }
        }
        self.status()
    }

    fn run_cycle(
        &self,
        provider: &dyn SyncObjectProvider,
        vault_key: &VaultKey,
        vault_id: &str,
        remote_prefix: &str,
        cancellation: &ProviderCancellation,
        generation: u64,
        now_ms: i64,
    ) -> Result<CycleCounts, String> {
        let journal_status = self.journal.status().map_err(journal_code)?;
        if journal_status.safety_blocked {
            return Err("reconcile-required".to_string());
        }
        let uploaded = self.push_pending(
            provider,
            vault_id,
            remote_prefix,
            cancellation,
            generation,
            now_ms,
        )?;
        self.set_phase(generation, SyncCoordinatorPhase::Downloading)?;
        let candidates =
            self.download_candidates(provider, vault_id, remote_prefix, cancellation)?;
        self.set_phase(generation, SyncCoordinatorPhase::Merging)?;
        let mut downloaded = 0_u32;
        for candidate in candidates {
            self.check_generation(generation, cancellation)?;
            let result = self
                .journal
                .apply_remote_merge(
                    &candidate.metadata.key,
                    &candidate.encoded,
                    vault_key,
                    now_ms,
                )
                .map_err(journal_code)?;
            if result.outcome == RemoteApplyOutcome::Applied {
                downloaded = downloaded.saturating_add(1);
            }
        }
        self.journal.prune(now_ms).map_err(journal_code)?;
        Ok(CycleCounts {
            uploaded,
            downloaded,
        })
    }

    fn push_pending(
        &self,
        provider: &dyn SyncObjectProvider,
        vault_id: &str,
        remote_prefix: &str,
        cancellation: &ProviderCancellation,
        generation: u64,
        now_ms: i64,
    ) -> Result<u32, String> {
        let mut uploaded = 0_u32;
        for _ in 0..MAX_PUSH_OBJECTS_PER_CYCLE {
            self.check_generation(generation, cancellation)?;
            let Some(claim) = self
                .journal
                .claim_next_for_vault(vault_id, now_ms)
                .map_err(journal_code)?
            else {
                return Ok(uploaded);
            };
            let envelope = match EncryptedSyncObject::decode(&claim.encrypted_object) {
                Ok(envelope) => envelope,
                Err(_) => {
                    self.journal
                        .mark_failed(
                            &claim.object_key,
                            &claim.lease_id,
                            AttemptFailure::Integrity,
                            now_ms,
                        )
                        .map_err(journal_code)?;
                    return Err("integrity".to_string());
                }
            };
            let device_prefix = envelope
                .device_id()
                .map(|device_id| format!("{remote_prefix}{device_id}/"));
            if envelope.vault_id() != vault_id
                || envelope.object_kind() != &SyncObjectKind::Event
                || device_prefix
                    .as_deref()
                    .is_none_or(|prefix| !claim.object_key.starts_with(prefix))
            {
                self.journal
                    .mark_failed(
                        &claim.object_key,
                        &claim.lease_id,
                        AttemptFailure::Protocol,
                        now_ms,
                    )
                    .map_err(journal_code)?;
                return Err("protocol".to_string());
            }
            match provider.put(&claim.object_key, &claim.encrypted_object, cancellation) {
                Ok(_) => {
                    self.journal
                        .mark_published(&claim.object_key, &claim.lease_id, now_ms)
                        .map_err(journal_code)?;
                    uploaded = uploaded.saturating_add(1);
                }
                Err(error) if error.code == ProviderErrorCode::Cancelled => {
                    self.journal
                        .pause_claim(&claim.object_key, &claim.lease_id, now_ms)
                        .map_err(journal_code)?;
                    return Err("cancelled".to_string());
                }
                Err(error) => {
                    let (failure, code) = provider_failure(&error);
                    self.journal
                        .mark_failed(&claim.object_key, &claim.lease_id, failure, now_ms)
                        .map_err(journal_code)?;
                    return Err(code.to_string());
                }
            }
        }
        Ok(uploaded)
    }

    fn download_candidates(
        &self,
        provider: &dyn SyncObjectProvider,
        vault_id: &str,
        remote_prefix: &str,
        cancellation: &ProviderCancellation,
    ) -> Result<Vec<RemoteCandidate>, String> {
        let mut metadata = Vec::new();
        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        loop {
            cancellation.check().map_err(provider_code)?;
            let page = provider
                .list(
                    remote_prefix,
                    cursor.as_deref(),
                    LIST_PAGE_SIZE,
                    cancellation,
                )
                .map_err(provider_code)?;
            for object in page.objects {
                if !object.key.starts_with(remote_prefix)
                    || !seen_cursors.insert(object.key.clone())
                {
                    return Err("protocol".to_string());
                }
                if metadata.len() >= MAX_PULL_OBJECTS_PER_CYCLE {
                    return Err("resource-limit".to_string());
                }
                metadata.push(object);
            }
            let Some(next) = page.next_cursor else {
                break;
            };
            if cursor.as_ref().is_some_and(|current| next <= *current)
                || !seen_cursors.contains(&next)
            {
                return Err("protocol".to_string());
            }
            cursor = Some(next);
        }

        let mut total_bytes = 0_u64;
        let mut candidates = Vec::with_capacity(metadata.len());
        for metadata in metadata {
            cancellation.check().map_err(provider_code)?;
            total_bytes = total_bytes
                .checked_add(metadata.size)
                .ok_or_else(|| "resource-limit".to_string())?;
            if total_bytes > MAX_PULL_BYTES_PER_CYCLE {
                return Err("resource-limit".to_string());
            }
            let encoded = provider
                .get(&metadata.key, cancellation)
                .map_err(provider_code)?;
            if encoded.len() as u64 != metadata.size {
                return Err("integrity".to_string());
            }
            let envelope =
                EncryptedSyncObject::decode(&encoded).map_err(|_| "integrity".to_string())?;
            if envelope.vault_id() != vault_id || envelope.object_kind() != &SyncObjectKind::Event {
                return Err("unsupported-object-kind".to_string());
            }
            let device_id = envelope
                .device_id()
                .ok_or_else(|| "protocol".to_string())?
                .to_string();
            if !metadata
                .key
                .starts_with(&format!("{remote_prefix}{device_id}/"))
            {
                return Err("protocol".to_string());
            }
            let sequence = envelope.sequence().ok_or_else(|| "protocol".to_string())?;
            candidates.push(RemoteCandidate {
                metadata,
                encoded,
                device_id,
                sequence,
            });
        }
        candidates.sort_by(|left, right| {
            left.device_id
                .cmp(&right.device_id)
                .then_with(|| left.sequence.cmp(&right.sequence))
                .then_with(|| left.metadata.key.cmp(&right.metadata.key))
        });
        Ok(candidates)
    }

    fn check_generation(
        &self,
        generation: u64,
        cancellation: &ProviderCancellation,
    ) -> Result<(), String> {
        cancellation.check().map_err(provider_code)?;
        let runtime = self.lock_runtime()?;
        if runtime.generation != generation || !runtime.running {
            return Err("cancelled".to_string());
        }
        Ok(())
    }

    fn set_phase(&self, generation: u64, phase: SyncCoordinatorPhase) -> Result<(), String> {
        let mut runtime = self.lock_runtime()?;
        if runtime.generation != generation || !runtime.running {
            return Err("cancelled".to_string());
        }
        runtime.phase = phase;
        Ok(())
    }

    fn finish_cycle(
        &self,
        generation: u64,
        now_ms: i64,
        counts: CycleCounts,
        error: Option<String>,
    ) -> Result<(), String> {
        let open_conflicts = self
            .journal
            .merge_status()
            .map_err(|_| "无法读取同步冲突状态".to_string())?
            .open_conflicts;
        let mut runtime = self.lock_runtime()?;
        if runtime.generation != generation {
            return Ok(());
        }
        runtime.running = false;
        runtime.phase = if open_conflicts > 0 {
            SyncCoordinatorPhase::Conflicts
        } else {
            SyncCoordinatorPhase::Idle
        };
        runtime.last_error_code = error;
        runtime.last_completed_at_ms = Some(now_ms);
        runtime.last_uploaded_objects = counts.uploaded;
        runtime.last_downloaded_objects = counts.downloaded;
        Ok(())
    }

    fn finish_cycle_with_error(
        &self,
        generation: u64,
        phase: SyncCoordinatorPhase,
        code: &str,
    ) -> Result<(), String> {
        let mut runtime = self.lock_runtime()?;
        if runtime.generation != generation {
            return Ok(());
        }
        runtime.running = false;
        runtime.phase = phase;
        runtime.last_error_code = Some(code.to_string());
        Ok(())
    }
}

fn provider_failure(error: &ProviderError) -> (AttemptFailure, &'static str) {
    match error.code {
        ProviderErrorCode::Cancelled => (AttemptFailure::Network, "cancelled"),
        ProviderErrorCode::Unavailable => (AttemptFailure::RemoteUnavailable, "remote-unavailable"),
        ProviderErrorCode::Conflict => (AttemptFailure::Conflict, "immutable-conflict"),
        ProviderErrorCode::Protocol | ProviderErrorCode::NotFound => {
            (AttemptFailure::Protocol, "protocol")
        }
        ProviderErrorCode::InvalidInput | ProviderErrorCode::LimitExceeded => {
            (AttemptFailure::Protocol, "resource-limit")
        }
        ProviderErrorCode::UnsafePath => (AttemptFailure::Integrity, "integrity"),
    }
}

fn provider_code(error: ProviderError) -> String {
    provider_failure(&error).1.to_string()
}

fn journal_code(error: crate::sync_outbox::JournalError) -> String {
    match error.code {
        JournalErrorCode::InvalidInput => "invalid-input",
        JournalErrorCode::Conflict => "conflict",
        JournalErrorCode::Replay => "replay",
        JournalErrorCode::SequenceGap => "sequence-gap",
        JournalErrorCode::LimitExceeded => "resource-limit",
        JournalErrorCode::SafetyBlocked => "reconcile-required",
        JournalErrorCode::NotFound => "not-found",
        JournalErrorCode::StaleLease => "stale-lease",
        JournalErrorCode::Finalized => "finalized",
        JournalErrorCode::Storage => "storage",
        JournalErrorCode::Authentication => "authentication",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use uuid::Uuid;

    use super::*;
    use crate::{
        sync_crypto::{SyncObjectKind, encrypt_sync_object},
        sync_provider::{
            ProviderError, ProviderErrorCode, ProviderResult, PutObjectOutcome, SyncObjectPage,
        },
    };

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "vpshell-sync-coordinator-{label}-{}",
                Uuid::new_v4()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Default)]
    struct MemoryProvider {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl MemoryProvider {
        fn insert(&self, key: &str, bytes: Vec<u8>) {
            self.objects.lock().unwrap().insert(key.to_string(), bytes);
        }
    }

    #[derive(Default)]
    struct CancelOnPutProvider;

    impl SyncObjectProvider for CancelOnPutProvider {
        fn list(
            &self,
            _prefix: &str,
            _cursor: Option<&str>,
            _limit: usize,
            cancellation: &ProviderCancellation,
        ) -> ProviderResult<SyncObjectPage> {
            cancellation.check()?;
            Ok(SyncObjectPage {
                objects: Vec::new(),
                next_cursor: None,
            })
        }

        fn get(&self, _key: &str, _cancellation: &ProviderCancellation) -> ProviderResult<Vec<u8>> {
            Err(ProviderError::new(
                ProviderErrorCode::NotFound,
                "fixture object missing",
            ))
        }

        fn put(
            &self,
            _key: &str,
            _bytes: &[u8],
            cancellation: &ProviderCancellation,
        ) -> ProviderResult<PutObjectOutcome> {
            cancellation.cancel();
            Err(ProviderError::new(
                ProviderErrorCode::Cancelled,
                "fixture cancellation",
            ))
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
            let mut objects = self.objects.lock().unwrap();
            match objects.get(key) {
                Some(existing) if existing == bytes => Ok(PutObjectOutcome::AlreadyPresent),
                Some(_) => Err(ProviderError::new(
                    ProviderErrorCode::Conflict,
                    "fixture immutable conflict",
                )),
                None => {
                    objects.insert(key.to_string(), bytes.to_vec());
                    Ok(PutObjectOutcome::Created)
                }
            }
        }
    }

    fn operation(device_id: &str, sequence: u64) -> Vec<u8> {
        operation_patch(
            device_id,
            sequence,
            &Uuid::new_v4().to_string(),
            "name",
            "fixture",
        )
    }

    fn operation_patch(
        device_id: &str,
        sequence: u64,
        entity_id: &str,
        field: &str,
        value: &str,
    ) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "formatVersion": 1,
            "operationId": Uuid::new_v4().to_string(),
            "deviceId": device_id,
            "sequence": sequence,
            "hlc": { "physicalMs": 1000 + sequence as i64, "logical": 0 },
            "payload": {
                "kind": "patch",
                "payload": {
                    "entityKind": "host",
                    "entityId": entity_id,
                    "fields": { (field): { "type": "text", "value": value } },
                    "observedFields": { (field): null },
                    "observedTombstone": null
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn cycle_uploads_claimed_objects_and_applies_remote_merge_atomically() {
        let root = TempDir::new("cycle");
        let coordinator = SyncCoordinatorManager::open(root.0.clone()).unwrap();
        let provider = Arc::new(MemoryProvider::default());
        let vault_id = Uuid::new_v4().to_string();
        let local_device = Uuid::new_v4().to_string();
        let remote_device = Uuid::new_v4().to_string();
        let vault_key = VaultKey::generate().unwrap();

        let local = encrypt_sync_object(
            &vault_key,
            &vault_id,
            SyncObjectKind::Event,
            &Uuid::new_v4().to_string(),
            Some(&local_device),
            Some(1),
            &operation(&local_device, 1),
        )
        .unwrap()
        .encode()
        .unwrap();
        let local_key = format!("vpshell/v1/{vault_id}/segments/{local_device}/1.oseg");
        coordinator
            .journal
            .enqueue_local(&local_key, &local, 1, |_| Ok(()))
            .unwrap();

        let remote = encrypt_sync_object(
            &vault_key,
            &vault_id,
            SyncObjectKind::Event,
            &Uuid::new_v4().to_string(),
            Some(&remote_device),
            Some(1),
            &operation(&remote_device, 1),
        )
        .unwrap()
        .encode()
        .unwrap();
        let remote_key = format!("vpshell/v1/{vault_id}/segments/{remote_device}/1.oseg");
        provider.insert(&remote_key, remote);

        coordinator
            .attach_session(provider.clone(), vault_key, &vault_id)
            .unwrap();
        let status = coordinator.run_once(2_000).unwrap();
        assert_eq!(status.phase, SyncCoordinatorPhase::Idle);
        assert_eq!(status.pending_objects, 0);
        assert_eq!(status.merge_revision, 1);
        assert_eq!(status.last_uploaded_objects, 1);
        assert_eq!(status.last_downloaded_objects, 1);
        assert!(provider.objects.lock().unwrap().contains_key(&local_key));
    }

    #[test]
    fn tampered_remote_object_suspends_without_advancing_merge_state() {
        let root = TempDir::new("tamper");
        let coordinator = SyncCoordinatorManager::open(root.0.clone()).unwrap();
        let provider = Arc::new(MemoryProvider::default());
        let vault_id = Uuid::new_v4().to_string();
        let device_id = Uuid::new_v4().to_string();
        let vault_key = VaultKey::generate().unwrap();
        let key = format!("vpshell/v1/{vault_id}/segments/{device_id}/1.oseg");
        let encoded = encrypt_sync_object(
            &vault_key,
            &vault_id,
            SyncObjectKind::Event,
            &Uuid::new_v4().to_string(),
            Some(&device_id),
            Some(1),
            &operation(&device_id, 1),
        )
        .unwrap()
        .encode()
        .unwrap();
        let mut envelope: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        let ciphertext = envelope["ciphertext"].as_str().unwrap();
        let mut tampered = ciphertext.as_bytes().to_vec();
        tampered[0] = if tampered[0] == b'A' { b'B' } else { b'A' };
        envelope["ciphertext"] = String::from_utf8(tampered).unwrap().into();
        let encoded = serde_json::to_vec(&envelope).unwrap();
        provider.insert(&key, encoded);
        coordinator
            .attach_session(provider, vault_key, &vault_id)
            .unwrap();

        let status = coordinator.run_once(2_000).unwrap();
        assert_eq!(status.phase, SyncCoordinatorPhase::Suspended);
        assert_eq!(status.last_error_code.as_deref(), Some("authentication"));
        assert_eq!(status.merge_revision, 0);
    }

    #[test]
    fn status_exposes_only_value_free_recovery_and_conflict_counters() {
        let root = TempDir::new("status");
        let coordinator = SyncCoordinatorManager::open(root.0.clone()).unwrap();
        let status = coordinator.status().unwrap();
        assert_eq!(status.phase, SyncCoordinatorPhase::NotConfigured);
        assert!(!status.configured);
        assert_eq!(status.pending_objects, 0);
        let encoded = serde_json::to_string(&status).unwrap();
        for forbidden in [
            "password",
            "privateKey",
            "credentialRef",
            "vaultKey",
            "token",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn cycle_claims_only_the_attached_vault() {
        let root = TempDir::new("vault-scope");
        let coordinator = SyncCoordinatorManager::open(root.0.clone()).unwrap();
        let provider = Arc::new(MemoryProvider::default());
        let attached_vault = Uuid::new_v4().to_string();
        let other_vault = Uuid::new_v4().to_string();
        let attached_device = Uuid::new_v4().to_string();
        let other_device = Uuid::new_v4().to_string();
        let attached_key = VaultKey::generate().unwrap();
        let other_key = VaultKey::generate().unwrap();

        for (vault_id, device_id, vault_key) in [
            (&attached_vault, &attached_device, &attached_key),
            (&other_vault, &other_device, &other_key),
        ] {
            let encrypted = encrypt_sync_object(
                vault_key,
                vault_id,
                SyncObjectKind::Event,
                &Uuid::new_v4().to_string(),
                Some(device_id),
                Some(1),
                &operation(device_id, 1),
            )
            .unwrap()
            .encode()
            .unwrap();
            let key = format!("vpshell/v1/{vault_id}/segments/{device_id}/1.oseg");
            coordinator
                .journal
                .enqueue_local(&key, &encrypted, 1, |_| Ok(()))
                .unwrap();
        }

        coordinator
            .attach_session(provider.clone(), attached_key, &attached_vault)
            .unwrap();
        let status = coordinator.run_once(2_000).unwrap();
        assert_eq!(status.last_uploaded_objects, 1);
        assert_eq!(status.pending_objects, 1);
        let objects = provider.objects.lock().unwrap();
        assert_eq!(objects.len(), 1);
        assert!(objects.keys().all(|key| key.contains(&attached_vault)));
    }

    #[test]
    fn remote_concurrent_edits_surface_as_value_free_conflict_count() {
        let root = TempDir::new("conflict");
        let coordinator = SyncCoordinatorManager::open(root.0.clone()).unwrap();
        let provider = Arc::new(MemoryProvider::default());
        let vault_id = Uuid::new_v4().to_string();
        let vault_key = VaultKey::generate().unwrap();
        let entity_id = Uuid::new_v4().to_string();
        for (device_id, value) in [
            (Uuid::new_v4().to_string(), "first.example"),
            (Uuid::new_v4().to_string(), "second.example"),
        ] {
            let encrypted = encrypt_sync_object(
                &vault_key,
                &vault_id,
                SyncObjectKind::Event,
                &Uuid::new_v4().to_string(),
                Some(&device_id),
                Some(1),
                &operation_patch(&device_id, 1, &entity_id, "address", value),
            )
            .unwrap()
            .encode()
            .unwrap();
            provider.insert(
                &format!("vpshell/v1/{vault_id}/segments/{device_id}/1.oseg"),
                encrypted,
            );
        }

        coordinator
            .attach_session(provider, vault_key, &vault_id)
            .unwrap();
        let status = coordinator.run_once(2_000).unwrap();
        assert_eq!(status.phase, SyncCoordinatorPhase::Conflicts);
        assert_eq!(status.open_conflicts, 1);
        assert_eq!(status.merge_revision, 2);
    }

    #[test]
    fn corrupted_journal_stays_reconcile_required_until_explicit_acknowledgement() {
        let root = TempDir::new("recovery");
        fs::write(root.0.join("vpshell-sync.sqlite3"), b"truncated sqlite").unwrap();
        let coordinator = SyncCoordinatorManager::open(root.0.clone()).unwrap();
        let status = coordinator.status().unwrap();
        assert_eq!(status.phase, SyncCoordinatorPhase::ReconcileRequired);
        assert!(status.recovery_required);
        assert!(status.recovery_note.is_some());

        let vault_id = Uuid::new_v4().to_string();
        coordinator
            .attach_session(
                Arc::new(MemoryProvider::default()),
                VaultKey::generate().unwrap(),
                &vault_id,
            )
            .unwrap();
        let blocked = coordinator.run_once(2_000).unwrap();
        assert_eq!(blocked.phase, SyncCoordinatorPhase::ReconcileRequired);
        assert_eq!(
            blocked.last_error_code.as_deref(),
            Some("reconcile-required")
        );
    }

    #[test]
    fn provider_cancellation_pauses_claim_and_finishes_cancelled() {
        let root = TempDir::new("cancel");
        let coordinator = SyncCoordinatorManager::open(root.0.clone()).unwrap();
        let vault_id = Uuid::new_v4().to_string();
        let device_id = Uuid::new_v4().to_string();
        let vault_key = VaultKey::generate().unwrap();
        let encrypted = encrypt_sync_object(
            &vault_key,
            &vault_id,
            SyncObjectKind::Event,
            &Uuid::new_v4().to_string(),
            Some(&device_id),
            Some(1),
            &operation(&device_id, 1),
        )
        .unwrap()
        .encode()
        .unwrap();
        coordinator
            .journal
            .enqueue_local(
                &format!("vpshell/v1/{vault_id}/segments/{device_id}/1.oseg"),
                &encrypted,
                1,
                |_| Ok(()),
            )
            .unwrap();
        coordinator
            .attach_session(Arc::new(CancelOnPutProvider), vault_key, &vault_id)
            .unwrap();

        let status = coordinator.run_once(2_000).unwrap();
        assert_eq!(status.phase, SyncCoordinatorPhase::Cancelled);
        assert_eq!(status.last_error_code.as_deref(), Some("cancelled"));
        assert_eq!(status.pending_objects, 1);
    }
}

//! Rust-owned orchestration for encrypted object synchronization.
//!
//! The coordinator is the only layer allowed to move objects between a
//! provider and the journal.  It exposes value-free status snapshots; vault
//! keys, provider credentials, decrypted operations, and object bytes remain
//! inside Rust.

use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    app_store::AppStore,
    sync_crypto::{
        Argon2Parameters, EncryptedSyncObject, PasswordKeyslot, SyncObjectKind, VaultKey,
        create_password_keyslot, open_password_keyslot,
    },
    sync_outbox::{AttemptFailure, JournalErrorCode, RemoteApplyOutcome, SyncJournal},
    sync_provider::{
        LocalFolderProvider, ProviderCancellation, ProviderError, ProviderErrorCode,
        PutObjectOutcome, SyncObjectMetadata, SyncObjectProvider,
    },
};

const COORDINATOR_SCHEMA_VERSION: u16 = 1;
const MAX_PUSH_OBJECTS_PER_CYCLE: usize = 128;
const MAX_PULL_OBJECTS_PER_CYCLE: usize = 1_000;
const MAX_PULL_BYTES_PER_CYCLE: u64 = 64 * 1024 * 1024;
const LIST_PAGE_SIZE: usize = 250;
const BOOTSTRAP_FORMAT_VERSION: u16 = 1;
const BOOTSTRAP_OBJECT_KEY: &str = "vpshell/v1/bootstrap.json";
const MAX_BOOTSTRAP_BYTES: usize = 32 * 1024;
const MAX_LOCAL_FOLDER_PATH_BYTES: usize = 4096;

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum LocalFolderSetupMode {
    Initialize,
    Unlock,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConfigureLocalFolderSyncRequest {
    root_path: String,
    password: String,
    mode: LocalFolderSetupMode,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SyncBootstrap {
    format_version: u16,
    vault_id: String,
    password_keyslot: PasswordKeyslot,
}

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
    configuring: bool,
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
            configuring: false,
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

#[derive(Clone)]
pub(crate) struct SyncCoordinatorManager {
    journal: SyncJournal,
    runtime: Arc<Mutex<CoordinatorRuntime>>,
}

struct ConfigurationGuard<'a> {
    coordinator: &'a SyncCoordinatorManager,
}

impl Drop for ConfigurationGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut runtime) = self.coordinator.runtime.lock() {
            runtime.configuring = false;
        }
    }
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
            runtime: Arc::new(Mutex::new(CoordinatorRuntime::default())),
        })
    }

    fn lock_runtime(&self) -> Result<std::sync::MutexGuard<'_, CoordinatorRuntime>, String> {
        self.runtime
            .lock()
            .map_err(|_| "同步协调器状态已损坏".to_string())
    }

    fn begin_configuration(&self) -> Result<ConfigurationGuard<'_>, String> {
        let mut runtime = self.lock_runtime()?;
        if runtime.running || runtime.configuring {
            return Err("同步运行或配置期间不能开始新的配置".to_string());
        }
        runtime.configuring = true;
        drop(runtime);
        Ok(ConfigurationGuard { coordinator: self })
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

    pub(crate) fn status_with_app_store(
        &self,
        app_store: &AppStore,
    ) -> Result<SyncCoordinatorStatus, String> {
        let mut status = self.status()?;
        status.pending_objects = status
            .pending_objects
            .saturating_add(app_store.pending_entity_sync_change_count()?);
        Ok(status)
    }

    pub(crate) fn cancel(&self) -> Result<(), String> {
        let mut runtime = self.lock_runtime()?;
        if !runtime.running {
            return Err("当前没有正在运行的同步周期".to_string());
        }
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
        self.attach_session_inner(provider, vault_key, vault_id, false)
    }

    fn attach_session_inner(
        &self,
        provider: Arc<dyn SyncObjectProvider>,
        vault_key: VaultKey,
        vault_id: &str,
        from_configuration: bool,
    ) -> Result<(), String> {
        let vault_id = uuid::Uuid::parse_str(vault_id)
            .map_err(|_| "同步 vault ID 格式无效".to_string())?
            .to_string();
        let mut runtime = self.lock_runtime()?;
        if runtime.running || (runtime.configuring && !from_configuration) {
            return Err("同步运行或配置期间不能替换 provider 会话".to_string());
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
        if runtime.configuring {
            return Err("同步配置期间不能锁定 vault".to_string());
        }
        runtime.cancellation.cancel();
        runtime.generation = runtime.generation.saturating_add(1);
        runtime.running = false;
        runtime.session = None;
        runtime.phase = SyncCoordinatorPhase::NotConfigured;
        runtime.last_error_code = None;
        Ok(())
    }

    pub(crate) fn configure_local_folder(
        &self,
        request: ConfigureLocalFolderSyncRequest,
    ) -> Result<SyncCoordinatorStatus, String> {
        self.configure_local_folder_with_kdf(request, Argon2Parameters::default())
    }

    fn configure_local_folder_with_kdf(
        &self,
        request: ConfigureLocalFolderSyncRequest,
        kdf: Argon2Parameters,
    ) -> Result<SyncCoordinatorStatus, String> {
        let _guard = self.begin_configuration()?;
        self.configure_local_folder_inner(request, kdf)
    }

    fn configure_local_folder_inner(
        &self,
        request: ConfigureLocalFolderSyncRequest,
        kdf: Argon2Parameters,
    ) -> Result<SyncCoordinatorStatus, String> {
        validate_local_folder_path(&request.root_path)?;
        let password = Zeroizing::new(request.password);
        validate_sync_password(password.as_bytes())?;
        let provider = Arc::new(
            LocalFolderProvider::open(PathBuf::from(&request.root_path))
                .map_err(|error| provider_setup_error(&error))?,
        );
        let cancellation = ProviderCancellation::default();
        let (vault_id, vault_key) = match request.mode {
            LocalFolderSetupMode::Initialize => {
                match provider.get(BOOTSTRAP_OBJECT_KEY, &cancellation) {
                    Ok(_) => return Err("同步目录已经初始化；请改用解锁已有 vault".to_string()),
                    Err(error) if error.code == ProviderErrorCode::NotFound => {}
                    Err(error) => return Err(provider_setup_error(&error)),
                }
                let vault_id = uuid::Uuid::new_v4().to_string();
                let vault_key = VaultKey::generate()?;
                let keyslot =
                    create_password_keyslot(password.as_bytes(), &vault_id, &vault_key, kdf)?;
                let bootstrap = encode_bootstrap(&SyncBootstrap {
                    format_version: BOOTSTRAP_FORMAT_VERSION,
                    vault_id: vault_id.clone(),
                    password_keyslot: keyslot,
                })?;
                match provider.put(BOOTSTRAP_OBJECT_KEY, &bootstrap, &cancellation) {
                    Ok(PutObjectOutcome::Created) => {}
                    Ok(PutObjectOutcome::AlreadyPresent) => {
                        return Err("同步目录初始化发生并发冲突；请改用解锁重试".to_string());
                    }
                    Err(error) if error.code == ProviderErrorCode::Conflict => {
                        return Err("同步目录已被另一台设备初始化；请改用解锁".to_string());
                    }
                    Err(error) => return Err(provider_setup_error(&error)),
                }
                (vault_id, vault_key)
            }
            LocalFolderSetupMode::Unlock => {
                let encoded =
                    provider
                        .get(BOOTSTRAP_OBJECT_KEY, &cancellation)
                        .map_err(|error| {
                            if error.code == ProviderErrorCode::NotFound {
                                "同步目录尚未初始化；请明确选择初始化新 vault".to_string()
                            } else {
                                provider_setup_error(&error)
                            }
                        })?;
                let bootstrap = decode_bootstrap(&encoded)?;
                let vault_key =
                    open_password_keyslot(password.as_bytes(), &bootstrap.password_keyslot)?;
                (bootstrap.vault_id, vault_key)
            }
        };
        self.attach_session_inner(provider, vault_key, &vault_id, true)?;
        self.status()
    }

    pub(crate) fn run_once(
        &self,
        app_store: &AppStore,
        now_ms: i64,
    ) -> Result<SyncCoordinatorStatus, String> {
        if now_ms < 0 {
            return Err("同步协调器时间不能为负数".to_string());
        }
        let (generation, provider, vault_key, vault_id, remote_prefix, cancellation) = {
            let mut runtime = self.lock_runtime()?;
            if runtime.running || runtime.configuring {
                return Err("同一 vault 已有同步配置或 worker 运行".to_string());
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
            app_store,
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
        self.status_with_app_store(app_store)
    }

    fn run_cycle(
        &self,
        app_store: &AppStore,
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
        self.drain_app_state_changes(app_store, vault_key, vault_id, now_ms)?;
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
        self.check_generation(generation, cancellation)?;
        let projection = self.journal.host_merge_projection().map_err(journal_code)?;
        app_store
            .apply_remote_host_projection(
                vault_id,
                projection.revision,
                &projection.entities,
                now_ms,
            )
            .map_err(|_| "app-state-writeback".to_string())?;
        let projection = self
            .journal
            .script_merge_projection()
            .map_err(journal_code)?;
        app_store
            .apply_remote_script_projection(
                vault_id,
                projection.revision,
                &projection.entities,
                now_ms,
            )
            .map_err(|_| "app-state-writeback".to_string())?;
        self.journal.prune(now_ms).map_err(journal_code)?;
        Ok(CycleCounts {
            uploaded,
            downloaded,
        })
    }

    fn drain_app_state_changes(
        &self,
        app_store: &AppStore,
        vault_key: &VaultKey,
        vault_id: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        app_store
            .bind_sync_vault(vault_id)
            .map_err(|_| "app-state-handoff".to_string())?;
        for change in app_store
            .pending_entity_sync_changes(MAX_PUSH_OBJECTS_PER_CYCLE)
            .map_err(|_| "app-state-handoff".to_string())?
        {
            self.journal
                .enqueue_local_entity_change(
                    vault_key,
                    vault_id,
                    &change.operation_id,
                    change.entity_kind,
                    &change.entity_id,
                    change.mutation,
                    now_ms,
                )
                .map_err(journal_code)?;
            app_store
                .acknowledge_entity_sync_change(vault_id, &change.operation_id)
                .map_err(|_| "app-state-handoff".to_string())?;
        }
        Ok(())
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

fn validate_local_folder_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > MAX_LOCAL_FOLDER_PATH_BYTES
        || path.contains('\0')
        || path.chars().any(char::is_control)
    {
        return Err("Local Folder 路径为空、过长或包含控制字符".to_string());
    }
    Ok(())
}

fn validate_sync_password(password: &[u8]) -> Result<(), String> {
    if !(8..=1024).contains(&password.len()) {
        return Err("二级同步密码必须为 8 至 1024 字节".to_string());
    }
    Ok(())
}

fn encode_bootstrap(bootstrap: &SyncBootstrap) -> Result<Vec<u8>, String> {
    if bootstrap.format_version != BOOTSTRAP_FORMAT_VERSION
        || uuid::Uuid::parse_str(&bootstrap.vault_id).is_err()
        || bootstrap.password_keyslot.vault_id() != bootstrap.vault_id
    {
        return Err("同步 bootstrap 版本或 vault identity 无效".to_string());
    }
    bootstrap.password_keyslot.encode()?;
    let encoded =
        serde_json::to_vec(bootstrap).map_err(|_| "无法编码同步 bootstrap".to_string())?;
    if encoded.is_empty() || encoded.len() > MAX_BOOTSTRAP_BYTES {
        return Err("同步 bootstrap 为空或超过 32 KiB 上限".to_string());
    }
    Ok(encoded)
}

fn decode_bootstrap(encoded: &[u8]) -> Result<SyncBootstrap, String> {
    if encoded.is_empty() || encoded.len() > MAX_BOOTSTRAP_BYTES {
        return Err("同步 bootstrap 为空或超过 32 KiB 上限".to_string());
    }
    let bootstrap: SyncBootstrap = serde_json::from_slice(encoded)
        .map_err(|_| "同步 bootstrap 损坏或包含不支持字段".to_string())?;
    encode_bootstrap(&bootstrap)?;
    Ok(bootstrap)
}

fn provider_setup_error(error: &ProviderError) -> String {
    match error.code {
        ProviderErrorCode::Cancelled => "同步配置已取消",
        ProviderErrorCode::Unavailable => "Local Folder 当前不可用",
        ProviderErrorCode::Conflict => "Local Folder 对象发生不可变冲突",
        ProviderErrorCode::Protocol => "Local Folder provider 协议错误",
        ProviderErrorCode::NotFound => "Local Folder 对象不存在",
        ProviderErrorCode::InvalidInput => "Local Folder 配置无效",
        ProviderErrorCode::LimitExceeded => "Local Folder 超过资源上限",
        ProviderErrorCode::UnsafePath => "Local Folder 路径不安全",
    }
    .to_string()
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
        app_store::SaveAppStateRequest,
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

    fn test_app_store(root: &TempDir) -> AppStore {
        AppStore::load(root.0.join("app-state")).unwrap()
    }

    fn app_state_fixture() -> String {
        serde_json::json!({
            "hosts": [{
                "id": "host-local", "name": "Example", "group": "Test",
                "host": "192.0.2.1", "port": 22, "username": "dev",
                "environment": "development", "tags": ["fixture"],
                "credentialRef": "ssh-reference", "hostKeySha256":
                "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }],
            "deletedHosts": [], "scripts": [], "commands": [], "sshKeys": [],
            "commandHistory": [], "connectionHistory": [], "pathHistory": {},
            "sync": {"enabled": true, "provider": "local", "endpoint": "", "remotePath": "/vpshell", "username": "", "totpEnabled": false, "syncSecrets": false},
            "wallpaper": {"source": "none", "value": "", "opacity": 0.2},
            "terminalAppearance": {"fontFamily": "monospace", "fontSize": 13, "lineHeight": 1.25},
            "settings": {"externalEditorPath": "", "autoUploadEditedFiles": false},
            "onboardingCompleted": true
        })
        .to_string()
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
            "host",
            &Uuid::new_v4().to_string(),
            "name",
            "fixture",
        )
    }

    fn operation_patch(
        device_id: &str,
        sequence: u64,
        entity_kind: &str,
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
                    "entityKind": entity_kind,
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
    fn app_state_changefeed_is_encrypted_merged_and_acknowledged_before_upload() {
        let root = TempDir::new("app-state-outbox");
        let store = test_app_store(&root);
        store
            .save(SaveAppStateRequest {
                state_json: app_state_fixture(),
                expected_revision: 0,
            })
            .unwrap();
        assert_eq!(store.pending_entity_sync_changes(128).unwrap().len(), 1);

        let coordinator = SyncCoordinatorManager::open(root.0.join("journal")).unwrap();
        let provider = Arc::new(MemoryProvider::default());
        let vault_id = Uuid::new_v4().to_string();
        coordinator
            .attach_session(provider.clone(), VaultKey::generate().unwrap(), &vault_id)
            .unwrap();
        assert_eq!(
            coordinator
                .status_with_app_store(&store)
                .unwrap()
                .pending_objects,
            1
        );
        let status = coordinator.run_once(&store, 2_000).unwrap();
        assert_eq!(status.last_uploaded_objects, 1);
        assert_eq!(status.merge_revision, 1);
        assert_eq!(status.open_conflicts, 0);
        assert!(store.pending_entity_sync_changes(128).unwrap().is_empty());
        let objects = provider.objects.lock().unwrap();
        assert_eq!(objects.len(), 1);
        let encoded = objects.values().next().unwrap();
        assert!(
            !encoded
                .windows(b"192.0.2.1".len())
                .any(|value| value == b"192.0.2.1")
        );
        assert!(
            !encoded
                .windows(b"ssh-reference".len())
                .any(|value| value == b"ssh-reference")
        );
    }

    #[test]
    fn cycle_projects_remote_host_fields_back_to_app_state_without_secrets() {
        let root = TempDir::new("app-state-writeback");
        let store = test_app_store(&root);
        store
            .save(SaveAppStateRequest {
                state_json: app_state_fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let entity_id = store.pending_entity_sync_changes(128).unwrap()[0]
            .entity_id
            .clone();
        let coordinator = SyncCoordinatorManager::open(root.0.join("journal")).unwrap();
        let provider = Arc::new(MemoryProvider::default());
        let vault_id = Uuid::new_v4().to_string();
        let remote_device = Uuid::new_v4().to_string();
        let vault_key = VaultKey::generate().unwrap();
        let remote = encrypt_sync_object(
            &vault_key,
            &vault_id,
            SyncObjectKind::Event,
            &Uuid::new_v4().to_string(),
            Some(&remote_device),
            Some(1),
            &operation_patch(
                &remote_device,
                1,
                "host",
                &entity_id,
                "address",
                "remote.example",
            ),
        )
        .unwrap()
        .encode()
        .unwrap();
        provider.insert(
            &format!("vpshell/v1/{vault_id}/segments/{remote_device}/1.oseg"),
            remote,
        );
        coordinator
            .attach_session(provider, vault_key, &vault_id)
            .unwrap();

        let status = coordinator.run_once(&store, 1_000).unwrap();
        assert_eq!(status.last_uploaded_objects, 1);
        assert_eq!(status.last_downloaded_objects, 1);
        let snapshot = serde_json::to_value(store.snapshot().unwrap()).unwrap();
        assert_eq!(snapshot["revision"].as_u64(), Some(2));
        let state: serde_json::Value =
            serde_json::from_str(snapshot["stateJson"].as_str().unwrap()).unwrap();
        assert_eq!(state["hosts"][0]["host"], "remote.example");
        assert_eq!(state["hosts"][0]["credentialRef"], "ssh-reference");
        assert!(store.pending_entity_sync_changes(128).unwrap().is_empty());
    }

    #[test]
    fn cycle_encrypts_custom_script_and_projects_remote_body_without_local_metadata() {
        let root = TempDir::new("app-state-script");
        let store = test_app_store(&root);
        let mut state: serde_json::Value = serde_json::from_str(&app_state_fixture()).unwrap();
        state["scripts"] = serde_json::json!([{
            "id": Uuid::new_v4().to_string(),
            "title": "Audit",
            "description": "local description",
            "category": "local category",
            "command": "echo local",
            "sourceUrl": "",
            "risk": "low",
            "custom": true
        }]);
        store
            .save(SaveAppStateRequest {
                state_json: state.to_string(),
                expected_revision: 0,
            })
            .unwrap();
        let script_entity = store
            .pending_entity_sync_changes(128)
            .unwrap()
            .into_iter()
            .find(|change| change.entity_kind == crate::sync_merge::EntityKind::Script)
            .unwrap()
            .entity_id;
        let coordinator = SyncCoordinatorManager::open(root.0.join("journal")).unwrap();
        let provider = Arc::new(MemoryProvider::default());
        let vault_id = Uuid::new_v4().to_string();
        let remote_device = Uuid::new_v4().to_string();
        let vault_key = VaultKey::generate().unwrap();
        let remote = encrypt_sync_object(
            &vault_key,
            &vault_id,
            SyncObjectKind::Event,
            &Uuid::new_v4().to_string(),
            Some(&remote_device),
            Some(1),
            &operation_patch(
                &remote_device,
                1,
                "script",
                &script_entity,
                "body",
                "echo remote",
            ),
        )
        .unwrap()
        .encode()
        .unwrap();
        provider.insert(
            &format!("vpshell/v1/{vault_id}/segments/{remote_device}/1.oseg"),
            remote,
        );
        coordinator
            .attach_session(provider.clone(), vault_key, &vault_id)
            .unwrap();

        let status = coordinator.run_once(&store, 1_000).unwrap();
        assert_eq!(status.last_uploaded_objects, 2);
        assert_eq!(status.last_downloaded_objects, 1);
        assert_eq!(status.open_conflicts, 1);
        let snapshot = serde_json::to_value(store.snapshot().unwrap()).unwrap();
        let state: serde_json::Value =
            serde_json::from_str(snapshot["stateJson"].as_str().unwrap()).unwrap();
        assert_eq!(state["scripts"][0]["command"], "echo remote");
        assert_eq!(state["scripts"][0]["description"], "local description");
        assert_eq!(state["scripts"][0]["category"], "local category");
        assert!(store.pending_entity_sync_changes(128).unwrap().is_empty());
        for encoded in provider.objects.lock().unwrap().values() {
            assert!(!encoded.windows("local description".len()).any(|window| {
                window == "local description".as_bytes()
            }));
        }
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
        let status = coordinator.run_once(&test_app_store(&root), 2_000).unwrap();
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

        let status = coordinator.run_once(&test_app_store(&root), 2_000).unwrap();
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
        let status = coordinator.run_once(&test_app_store(&root), 2_000).unwrap();
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
                &operation_patch(&device_id, 1, "host", &entity_id, "address", value),
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
        let status = coordinator.run_once(&test_app_store(&root), 2_000).unwrap();
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
        let blocked = coordinator.run_once(&test_app_store(&root), 2_000).unwrap();
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

        let status = coordinator.run_once(&test_app_store(&root), 2_000).unwrap();
        assert_eq!(status.phase, SyncCoordinatorPhase::Cancelled);
        assert_eq!(status.last_error_code.as_deref(), Some("cancelled"));
        assert_eq!(status.pending_objects, 1);
    }

    #[test]
    fn local_folder_bootstrap_requires_explicit_initialize_then_password_unlock() {
        let root = TempDir::new("local-bootstrap");
        let app_data = root.0.join("app-data");
        let remote = root.0.join("remote");
        fs::create_dir_all(&app_data).unwrap();
        fs::create_dir_all(&remote).unwrap();
        let coordinator = SyncCoordinatorManager::open(app_data).unwrap();
        let password = "fixture-password-that-must-not-be-persisted";

        let initialized = coordinator
            .configure_local_folder_with_kdf(
                ConfigureLocalFolderSyncRequest {
                    root_path: remote.to_string_lossy().into_owned(),
                    password: password.to_string(),
                    mode: LocalFolderSetupMode::Initialize,
                },
                Argon2Parameters::minimum_for_tests(),
            )
            .unwrap();
        assert!(initialized.configured);
        assert_eq!(initialized.phase, SyncCoordinatorPhase::Idle);
        let bootstrap = fs::read(remote.join(BOOTSTRAP_OBJECT_KEY)).unwrap();
        assert!(!String::from_utf8_lossy(&bootstrap).contains(password));
        assert_eq!(decode_bootstrap(&bootstrap).unwrap().format_version, 1);

        coordinator.detach_session().unwrap();
        let wrong_password = coordinator
            .configure_local_folder_with_kdf(
                ConfigureLocalFolderSyncRequest {
                    root_path: remote.to_string_lossy().into_owned(),
                    password: "different-password".to_string(),
                    mode: LocalFolderSetupMode::Unlock,
                },
                Argon2Parameters::minimum_for_tests(),
            )
            .unwrap_err();
        assert!(wrong_password.contains("密码错误") || wrong_password.contains("篡改"));
        assert!(!coordinator.status().unwrap().configured);

        let unlocked = coordinator
            .configure_local_folder_with_kdf(
                ConfigureLocalFolderSyncRequest {
                    root_path: remote.to_string_lossy().into_owned(),
                    password: password.to_string(),
                    mode: LocalFolderSetupMode::Unlock,
                },
                Argon2Parameters::minimum_for_tests(),
            )
            .unwrap();
        assert!(unlocked.configured);
        assert_eq!(
            coordinator
                .run_once(&test_app_store(&root), 2_000)
                .unwrap()
                .phase,
            SyncCoordinatorPhase::Idle
        );
    }

    #[test]
    fn local_folder_bootstrap_refuses_implicit_create_reinitialize_and_unknown_version() {
        let root = TempDir::new("local-bootstrap-fail-closed");
        let app_data = root.0.join("app-data");
        let remote = root.0.join("remote");
        fs::create_dir_all(&app_data).unwrap();
        fs::create_dir_all(&remote).unwrap();
        let coordinator = SyncCoordinatorManager::open(app_data).unwrap();
        let request = |mode| ConfigureLocalFolderSyncRequest {
            root_path: remote.to_string_lossy().into_owned(),
            password: "fixture-password".to_string(),
            mode,
        };

        let short_password = coordinator
            .configure_local_folder_with_kdf(
                ConfigureLocalFolderSyncRequest {
                    root_path: remote.to_string_lossy().into_owned(),
                    password: "short".to_string(),
                    mode: LocalFolderSetupMode::Initialize,
                },
                Argon2Parameters::minimum_for_tests(),
            )
            .unwrap_err();
        assert!(short_password.contains("8 至 1024"));

        let missing = coordinator
            .configure_local_folder_with_kdf(
                request(LocalFolderSetupMode::Unlock),
                Argon2Parameters::minimum_for_tests(),
            )
            .unwrap_err();
        assert!(missing.contains("尚未初始化"));
        coordinator
            .configure_local_folder_with_kdf(
                request(LocalFolderSetupMode::Initialize),
                Argon2Parameters::minimum_for_tests(),
            )
            .unwrap();
        coordinator.detach_session().unwrap();
        let duplicate = coordinator
            .configure_local_folder_with_kdf(
                request(LocalFolderSetupMode::Initialize),
                Argon2Parameters::minimum_for_tests(),
            )
            .unwrap_err();
        assert!(duplicate.contains("已经初始化"));

        let bootstrap_path = remote.join(BOOTSTRAP_OBJECT_KEY);
        let mut bootstrap: serde_json::Value =
            serde_json::from_slice(&fs::read(&bootstrap_path).unwrap()).unwrap();
        bootstrap["formatVersion"] = serde_json::json!(2);
        fs::write(&bootstrap_path, serde_json::to_vec(&bootstrap).unwrap()).unwrap();
        let unsupported = coordinator
            .configure_local_folder_with_kdf(
                request(LocalFolderSetupMode::Unlock),
                Argon2Parameters::minimum_for_tests(),
            )
            .unwrap_err();
        assert!(unsupported.contains("版本") || unsupported.contains("identity"));
    }

    #[test]
    fn configuration_gate_blocks_concurrent_cycle_lock_and_session_replacement() {
        let root = TempDir::new("configuration-gate");
        let coordinator = SyncCoordinatorManager::open(root.0.clone()).unwrap();
        let vault_id = Uuid::new_v4().to_string();
        let guard = coordinator.begin_configuration().unwrap();

        assert!(
            coordinator
                .configure_local_folder_with_kdf(
                    ConfigureLocalFolderSyncRequest {
                        root_path: root.0.to_string_lossy().into_owned(),
                        password: "fixture-password".to_string(),
                        mode: LocalFolderSetupMode::Initialize,
                    },
                    Argon2Parameters::minimum_for_tests(),
                )
                .is_err()
        );
        assert!(coordinator.run_once(&test_app_store(&root), 2_000).is_err());
        assert!(coordinator.detach_session().is_err());
        assert!(
            coordinator
                .attach_session(
                    Arc::new(MemoryProvider::default()),
                    VaultKey::generate().unwrap(),
                    &vault_id,
                )
                .is_err()
        );

        drop(guard);
        coordinator
            .attach_session(
                Arc::new(MemoryProvider::default()),
                VaultKey::generate().unwrap(),
                &vault_id,
            )
            .unwrap();
        assert!(coordinator.status().unwrap().configured);
    }
}

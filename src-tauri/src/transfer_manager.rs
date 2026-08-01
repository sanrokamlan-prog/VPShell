use std::{
    collections::HashMap,
    net::{Shutdown, TcpStream},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tauri::{AppHandle, Emitter};

pub(crate) const TRANSFER_CANCELLED: &str = "__VPSHELL_TRANSFER_CANCELLED__";
const TRANSFER_EVENT: &str = "transfer-task-updated";
const MAX_ACTIVE_TRANSFERS: usize = 6;
const MAX_RETAINED_TRANSFERS: usize = 200;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TransferStatus {
    Queued,
    Running,
    Cancelling,
    Completed,
    Failed,
    Cancelled,
}

impl TransferStatus {
    fn is_active(&self) -> bool {
        matches!(self, Self::Queued | Self::Running | Self::Cancelling)
    }

    fn is_terminal(&self) -> bool {
        !self.is_active()
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum CleanupStatus {
    NotRequired,
    Pending,
    Completed,
    Warning,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransferResult {
    pub(crate) transfer_id: String,
    pub(crate) mode: String,
    pub(crate) files_transferred: u64,
    pub(crate) bytes_transferred: u64,
    pub(crate) skipped_symlinks: u64,
    pub(crate) fallback_used: bool,
    pub(crate) resumable: bool,
    pub(crate) verification: String,
    pub(crate) limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransferSnapshot {
    pub(crate) transfer_id: String,
    pub(crate) kind: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: String,
    pub(crate) status: TransferStatus,
    pub(crate) seq: u64,
    pub(crate) phase: String,
    pub(crate) current_path: String,
    pub(crate) transferred_bytes: u64,
    pub(crate) total_bytes: Option<u64>,
    pub(crate) result: Option<TransferResult>,
    pub(crate) error: Option<String>,
    pub(crate) partial_commit: bool,
    pub(crate) cleanup_status: CleanupStatus,
    pub(crate) cleanup_warnings: Vec<String>,
    pub(crate) finalizing: bool,
    pub(crate) can_cancel: bool,
    pub(crate) can_dismiss: bool,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
}

struct TransferRuntime {
    snapshot: TransferSnapshot,
    cancel_requested: bool,
    finalizing: bool,
    cleanup_attempted: bool,
    committed_units: u64,
    socket: Option<TcpStream>,
}

struct TransferRecord {
    runtime: Mutex<TransferRuntime>,
}

struct TransferManagerInner {
    tasks: Mutex<HashMap<String, Arc<TransferRecord>>>,
    next_seq: AtomicU64,
}

#[derive(Clone)]
pub(crate) struct TransferManager {
    inner: Arc<TransferManagerInner>,
}

impl Default for TransferManager {
    fn default() -> Self {
        Self {
            inner: Arc::new(TransferManagerInner {
                tasks: Mutex::new(HashMap::new()),
                next_seq: AtomicU64::new(0),
            }),
        }
    }
}

impl TransferManager {
    pub(crate) fn accept(
        &self,
        app: &AppHandle,
        transfer_id: String,
        kind: &str,
        host: &str,
        port: u16,
        username: &str,
    ) -> Result<(TransferSnapshot, TransferTask), String> {
        let now = now_millis();
        let snapshot = TransferSnapshot {
            transfer_id: transfer_id.clone(),
            kind: kind.to_string(),
            host: host.to_string(),
            port,
            username: username.to_string(),
            status: TransferStatus::Queued,
            seq: self.next_seq(),
            phase: "queued".to_string(),
            current_path: String::new(),
            transferred_bytes: 0,
            total_bytes: None,
            result: None,
            error: None,
            partial_commit: false,
            cleanup_status: CleanupStatus::NotRequired,
            cleanup_warnings: Vec::new(),
            finalizing: false,
            can_cancel: true,
            can_dismiss: false,
            created_at: now,
            updated_at: now,
        };
        let record = Arc::new(TransferRecord {
            runtime: Mutex::new(TransferRuntime {
                snapshot: snapshot.clone(),
                cancel_requested: false,
                finalizing: false,
                cleanup_attempted: false,
                committed_units: 0,
                socket: None,
            }),
        });

        {
            let mut tasks = lock(&self.inner.tasks);
            if tasks.contains_key(&transfer_id) {
                return Err("传输任务 ID 已存在；请查询或移除原任务后重试".to_string());
            }
            let active = tasks
                .values()
                .filter(|task| lock(&task.runtime).snapshot.status.is_active())
                .count();
            if active >= MAX_ACTIVE_TRANSFERS {
                return Err(format!(
                    "同时运行的传输任务已达到上限（{MAX_ACTIVE_TRANSFERS} 个）"
                ));
            }
            prune_terminal_tasks(&mut tasks, MAX_RETAINED_TRANSFERS.saturating_sub(1));
            tasks.insert(transfer_id, Arc::clone(&record));
        }

        emit_snapshot(app, &snapshot);
        Ok((
            snapshot,
            TransferTask {
                app: app.clone(),
                manager: self.clone(),
                record,
            },
        ))
    }

    pub(crate) fn get(&self, transfer_id: &str) -> Option<TransferSnapshot> {
        let record = lock(&self.inner.tasks).get(transfer_id).cloned()?;
        Some(lock(&record.runtime).snapshot.clone())
    }

    pub(crate) fn list(&self) -> Vec<TransferSnapshot> {
        let records = lock(&self.inner.tasks)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut snapshots = records
            .iter()
            .map(|record| lock(&record.runtime).snapshot.clone())
            .collect::<Vec<_>>();
        snapshots.sort_by_key(|snapshot| (snapshot.created_at, snapshot.seq));
        snapshots
    }

    pub(crate) fn cancel(
        &self,
        app: &AppHandle,
        transfer_id: &str,
    ) -> Result<TransferSnapshot, String> {
        let record = self
            .record(transfer_id)
            .ok_or_else(|| "传输任务不存在".to_string())?;
        let snapshot = {
            let mut runtime = lock(&record.runtime);
            if runtime.snapshot.status.is_terminal() {
                return Err("传输任务已经结束，无法取消".to_string());
            }
            if runtime.finalizing {
                return Err("传输任务已进入最终提交阶段，现在取消已经太晚".to_string());
            }
            runtime.cancel_requested = true;
            runtime.snapshot.status = TransferStatus::Cancelling;
            runtime.snapshot.phase = "cancelling".to_string();
            runtime.snapshot.can_cancel = false;
            if let Some(socket) = runtime.socket.as_ref() {
                let _ = socket.shutdown(Shutdown::Both);
            }
            self.touch(&mut runtime)
        };
        emit_snapshot(app, &snapshot);
        Ok(snapshot)
    }

    pub(crate) fn dismiss(&self, transfer_id: &str) -> Result<(), String> {
        let mut tasks = lock(&self.inner.tasks);
        let record = tasks
            .get(transfer_id)
            .cloned()
            .ok_or_else(|| "传输任务不存在".to_string())?;
        if !lock(&record.runtime).snapshot.status.is_terminal() {
            return Err("仍在运行的传输任务不能移除；请先取消并等待清理完成".to_string());
        }
        tasks.remove(transfer_id);
        Ok(())
    }

    fn record(&self, transfer_id: &str) -> Option<Arc<TransferRecord>> {
        lock(&self.inner.tasks).get(transfer_id).cloned()
    }

    fn next_seq(&self) -> u64 {
        self.inner.next_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn touch(&self, runtime: &mut TransferRuntime) -> TransferSnapshot {
        runtime.snapshot.seq = self.next_seq();
        runtime.snapshot.updated_at = now_millis();
        runtime.snapshot.finalizing = runtime.finalizing;
        runtime.snapshot.can_cancel =
            runtime.snapshot.status.is_active() && !runtime.cancel_requested && !runtime.finalizing;
        runtime.snapshot.can_dismiss = runtime.snapshot.status.is_terminal();
        runtime.snapshot.clone()
    }
}

#[derive(Clone)]
pub(crate) struct TransferTask {
    app: AppHandle,
    manager: TransferManager,
    record: Arc<TransferRecord>,
}

impl TransferTask {
    pub(crate) fn start(&self) -> Result<(), String> {
        let snapshot = {
            let mut runtime = lock(&self.record.runtime);
            if runtime.cancel_requested {
                return Err(TRANSFER_CANCELLED.to_string());
            }
            runtime.snapshot.status = TransferStatus::Running;
            runtime.snapshot.phase = "starting".to_string();
            self.manager.touch(&mut runtime)
        };
        emit_snapshot(&self.app, &snapshot);
        Ok(())
    }

    pub(crate) fn checkpoint(&self) -> Result<(), String> {
        if lock(&self.record.runtime).cancel_requested {
            Err(TRANSFER_CANCELLED.to_string())
        } else {
            Ok(())
        }
    }

    pub(crate) fn progress(
        &self,
        phase: impl Into<String>,
        current_path: impl Into<String>,
        transferred_bytes: u64,
        total_bytes: Option<u64>,
    ) -> Result<TransferSnapshot, String> {
        let snapshot = {
            let mut runtime = lock(&self.record.runtime);
            if runtime.cancel_requested {
                return Err(TRANSFER_CANCELLED.to_string());
            }
            runtime.snapshot.phase = phase.into();
            runtime.snapshot.current_path = current_path.into();
            runtime.snapshot.transferred_bytes = transferred_bytes;
            runtime.snapshot.total_bytes = total_bytes;
            self.manager.touch(&mut runtime)
        };
        emit_snapshot(&self.app, &snapshot);
        Ok(snapshot)
    }

    pub(crate) fn register_socket(&self, socket: TcpStream) -> Result<(), String> {
        let mut runtime = lock(&self.record.runtime);
        if runtime.cancel_requested {
            let _ = socket.shutdown(Shutdown::Both);
            return Err(TRANSFER_CANCELLED.to_string());
        }
        runtime.socket = Some(socket);
        Ok(())
    }

    pub(crate) fn clear_socket(&self) {
        lock(&self.record.runtime).socket = None;
    }

    pub(crate) fn begin_finalizing(&self, current_path: impl Into<String>) -> Result<(), String> {
        let snapshot = {
            let mut runtime = lock(&self.record.runtime);
            if runtime.cancel_requested {
                return Err(TRANSFER_CANCELLED.to_string());
            }
            runtime.finalizing = true;
            runtime.snapshot.phase = "finalizing".to_string();
            runtime.snapshot.current_path = current_path.into();
            self.manager.touch(&mut runtime)
        };
        emit_snapshot(&self.app, &snapshot);
        Ok(())
    }

    pub(crate) fn note_commit(&self) {
        let mut runtime = lock(&self.record.runtime);
        runtime.committed_units = runtime.committed_units.saturating_add(1);
    }

    pub(crate) fn note_rollback(&self) {
        let mut runtime = lock(&self.record.runtime);
        runtime.committed_units = runtime.committed_units.saturating_sub(1);
    }

    pub(crate) fn begin_cleanup(&self) {
        let snapshot = {
            let mut runtime = lock(&self.record.runtime);
            runtime.cleanup_attempted = true;
            if runtime.snapshot.cleanup_warnings.is_empty() {
                runtime.snapshot.cleanup_status = CleanupStatus::Pending;
            }
            self.manager.touch(&mut runtime)
        };
        emit_snapshot(&self.app, &snapshot);
    }

    pub(crate) fn cleanup_warning(&self, warning: impl Into<String>) {
        let snapshot = {
            let mut runtime = lock(&self.record.runtime);
            runtime.cleanup_attempted = true;
            runtime.snapshot.cleanup_status = CleanupStatus::Warning;
            runtime.snapshot.cleanup_warnings.push(warning.into());
            self.manager.touch(&mut runtime)
        };
        emit_snapshot(&self.app, &snapshot);
    }

    pub(crate) fn finish(&self, result: Result<TransferResult, String>) -> TransferSnapshot {
        self.clear_socket();
        let snapshot = {
            let mut runtime = lock(&self.record.runtime);
            let cancellation = runtime.cancel_requested
                || matches!(result.as_ref(), Err(error) if error == TRANSFER_CANCELLED);
            if cancellation {
                runtime.snapshot.status = TransferStatus::Cancelled;
                runtime.snapshot.phase = "cancelled".to_string();
                runtime.snapshot.result = None;
                runtime.snapshot.error = None;
                runtime.snapshot.partial_commit = runtime.committed_units > 0;
            } else {
                match result {
                    Ok(result) => {
                        runtime.snapshot.status = TransferStatus::Completed;
                        runtime.snapshot.phase = "completed".to_string();
                        runtime.snapshot.transferred_bytes = result.bytes_transferred;
                        runtime.snapshot.total_bytes = Some(result.bytes_transferred);
                        runtime.snapshot.result = Some(result);
                        runtime.snapshot.error = None;
                        runtime.snapshot.partial_commit = false;
                    }
                    Err(error) => {
                        runtime.snapshot.status = TransferStatus::Failed;
                        runtime.snapshot.phase = "failed".to_string();
                        runtime.snapshot.result = None;
                        runtime.snapshot.error = Some(error);
                        runtime.snapshot.partial_commit = runtime.committed_units > 0;
                    }
                }
            }
            runtime.finalizing = false;
            if runtime.cleanup_attempted && runtime.snapshot.cleanup_warnings.is_empty() {
                runtime.snapshot.cleanup_status = CleanupStatus::Completed;
            }
            self.manager.touch(&mut runtime)
        };
        emit_snapshot(&self.app, &snapshot);
        snapshot
    }
}

fn emit_snapshot(app: &AppHandle, snapshot: &TransferSnapshot) {
    let _ = app.emit(TRANSFER_EVENT, snapshot.clone());
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn prune_terminal_tasks(tasks: &mut HashMap<String, Arc<TransferRecord>>, maximum: usize) {
    if tasks.len() <= maximum {
        return;
    }
    let mut terminal = tasks
        .iter()
        .filter_map(|(id, record)| {
            let runtime = lock(&record.runtime);
            runtime
                .snapshot
                .status
                .is_terminal()
                .then_some((id.clone(), runtime.snapshot.updated_at))
        })
        .collect::<Vec<_>>();
    terminal.sort_by_key(|(_, updated_at)| *updated_at);
    let remove_count = tasks.len().saturating_sub(maximum).min(terminal.len());
    for (id, _) in terminal.into_iter().take(remove_count) {
        tasks.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, status: TransferStatus) -> Arc<TransferRecord> {
        Arc::new(TransferRecord {
            runtime: Mutex::new(TransferRuntime {
                snapshot: TransferSnapshot {
                    transfer_id: id.to_string(),
                    kind: "upload".to_string(),
                    host: "example.com".to_string(),
                    port: 22,
                    username: "root".to_string(),
                    status,
                    seq: 1,
                    phase: "test".to_string(),
                    current_path: String::new(),
                    transferred_bytes: 0,
                    total_bytes: None,
                    result: None,
                    error: None,
                    partial_commit: false,
                    cleanup_status: CleanupStatus::NotRequired,
                    cleanup_warnings: Vec::new(),
                    finalizing: false,
                    can_cancel: true,
                    can_dismiss: false,
                    created_at: 1,
                    updated_at: 1,
                },
                cancel_requested: false,
                finalizing: false,
                cleanup_attempted: false,
                committed_units: 0,
                socket: None,
            }),
        })
    }

    #[test]
    fn statuses_separate_active_and_terminal_tasks() {
        assert!(TransferStatus::Queued.is_active());
        assert!(TransferStatus::Running.is_active());
        assert!(TransferStatus::Cancelling.is_active());
        assert!(TransferStatus::Completed.is_terminal());
        assert!(TransferStatus::Failed.is_terminal());
        assert!(TransferStatus::Cancelled.is_terminal());
    }

    #[test]
    fn sequence_numbers_are_monotonic() {
        let manager = TransferManager::default();
        assert!(manager.next_seq() < manager.next_seq());
        assert!(manager.next_seq() < manager.next_seq());
    }

    #[test]
    fn task_record_tracks_commits_without_exposing_partial_success_early() {
        let item = record("one", TransferStatus::Running);
        {
            let mut runtime = lock(&item.runtime);
            runtime.committed_units += 1;
            assert!(!runtime.snapshot.partial_commit);
            runtime.snapshot.partial_commit = runtime.committed_units > 0;
        }
        assert!(lock(&item.runtime).snapshot.partial_commit);
    }

    #[test]
    fn pruning_keeps_active_tasks_and_removes_oldest_terminal_records() {
        let active = record("active", TransferStatus::Running);
        let oldest = record("oldest", TransferStatus::Completed);
        let newest = record("newest", TransferStatus::Failed);
        lock(&oldest.runtime).snapshot.updated_at = 10;
        lock(&newest.runtime).snapshot.updated_at = 20;
        let mut tasks = HashMap::from([
            ("active".to_string(), active),
            ("oldest".to_string(), oldest),
            ("newest".to_string(), newest),
        ]);

        prune_terminal_tasks(&mut tasks, 2);

        assert!(tasks.contains_key("active"));
        assert!(!tasks.contains_key("oldest"));
        assert!(tasks.contains_key("newest"));
    }
}

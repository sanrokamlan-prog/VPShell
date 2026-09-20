use std::sync::{Arc, Mutex};

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tauri::Emitter;

use crate::{
    app_store::{AppStore, AppStoreSnapshot},
    sync_coordinator::{SyncCoordinatorManager, SyncCoordinatorPhase, SyncCoordinatorStatus},
};

pub(crate) const AUTOMATIC_SYNC_CYCLE_EVENT: &str = "desktop-sync-cycle";
const STARTUP_DELAY_MS: i64 = 2_000;
const CHANGE_DEBOUNCE_MS: i64 = 2_000;
const PENDING_RECHECK_MS: i64 = 30_000;
const RETRY_DELAY_MS: i64 = 30_000;
const PERIODIC_INTERVAL_MS: i64 = 5 * 60_000;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AutomaticSyncCycleEvent {
    status: SyncCoordinatorStatus,
    app_store: AppStoreSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CycleDisposition {
    Success,
    RetryableFailure,
    Suspended,
}

#[derive(Debug)]
struct AutomaticSyncPolicy {
    next_run_at_ms: i64,
    observed_pending: u64,
    pending_changed_at_ms: Option<i64>,
    last_observed_at_ms: i64,
    suspended: bool,
}

impl AutomaticSyncPolicy {
    fn new(now_ms: i64) -> Self {
        Self {
            next_run_at_ms: now_ms.saturating_add(STARTUP_DELAY_MS),
            observed_pending: 0,
            pending_changed_at_ms: None,
            last_observed_at_ms: now_ms,
            suspended: false,
        }
    }

    fn observe(&mut self, now_ms: i64, pending_objects: u64) -> bool {
        if self.suspended || now_ms < self.last_observed_at_ms {
            return false;
        }
        self.last_observed_at_ms = now_ms;
        if pending_objects != self.observed_pending {
            self.observed_pending = pending_objects;
            self.pending_changed_at_ms = Some(now_ms);
        }
        let change_due = pending_objects > 0
            && self
                .pending_changed_at_ms
                .is_some_and(|changed_at| now_ms.saturating_sub(changed_at) >= CHANGE_DEBOUNCE_MS);
        now_ms >= self.next_run_at_ms || change_due
    }

    fn complete(&mut self, now_ms: i64, pending_objects: u64, disposition: CycleDisposition) {
        self.last_observed_at_ms = now_ms.max(self.last_observed_at_ms);
        self.observed_pending = pending_objects;
        self.pending_changed_at_ms = None;
        self.suspended = disposition == CycleDisposition::Suspended;
        self.next_run_at_ms = match disposition {
            CycleDisposition::Success if pending_objects > 0 => {
                now_ms.saturating_add(PENDING_RECHECK_MS)
            }
            CycleDisposition::Success => now_ms.saturating_add(PERIODIC_INTERVAL_MS),
            CycleDisposition::RetryableFailure => now_ms.saturating_add(RETRY_DELAY_MS),
            CycleDisposition::Suspended => i64::MAX,
        };
    }

    fn resume_after_external_success(&mut self, now_ms: i64, pending_objects: u64) {
        if !self.suspended || now_ms < self.last_observed_at_ms {
            return;
        }
        self.suspended = false;
        self.last_observed_at_ms = now_ms;
        self.observed_pending = pending_objects;
        self.pending_changed_at_ms = None;
        self.next_run_at_ms = now_ms.saturating_add(if pending_objects > 0 {
            PENDING_RECHECK_MS
        } else {
            PERIODIC_INTERVAL_MS
        });
    }
}

#[derive(Clone, Default)]
pub(crate) struct AutomaticSyncScheduler {
    generation: Arc<Mutex<u64>>,
}

impl AutomaticSyncScheduler {
    pub(crate) fn ensure_supported() -> Result<(), String> {
        if cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows"
        )) {
            Ok(())
        } else {
            Err("自动同步调度仅在桌面平台可用".to_string())
        }
    }

    fn advance_generation(&self) -> Result<u64, String> {
        let mut generation = self
            .generation
            .lock()
            .map_err(|_| "自动同步调度状态已损坏".to_string())?;
        *generation = generation
            .checked_add(1)
            .ok_or_else(|| "自动同步调度代际已耗尽".to_string())?;
        Ok(*generation)
    }

    fn is_current(&self, expected: u64) -> bool {
        self.generation
            .lock()
            .map(|generation| *generation == expected)
            .unwrap_or(false)
    }

    pub(crate) fn stop(&self) -> Result<(), String> {
        self.advance_generation().map(|_| ())
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(crate) fn start(
        &self,
        app: tauri::AppHandle,
        coordinator: SyncCoordinatorManager,
        app_store: AppStore,
    ) -> Result<(), String> {
        Self::ensure_supported()?;
        let generation = self.advance_generation()?;
        let scheduler = self.clone();
        tauri::async_runtime::spawn(async move {
            run_scheduler(app, scheduler, generation, coordinator, app_store).await;
        });
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub(crate) fn start(
        &self,
        _app: tauri::AppHandle,
        _coordinator: SyncCoordinatorManager,
        _app_store: AppStore,
    ) -> Result<(), String> {
        Self::ensure_supported()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn cycle_disposition(status: &SyncCoordinatorStatus, worker_failed: bool) -> CycleDisposition {
    if status.recovery_required
        || matches!(
            status.phase,
            SyncCoordinatorPhase::ReconcileRequired
                | SyncCoordinatorPhase::Suspended
                | SyncCoordinatorPhase::Cancelled
        )
    {
        CycleDisposition::Suspended
    } else if worker_failed || status.phase == SyncCoordinatorPhase::WaitingRetry {
        CycleDisposition::RetryableFailure
    } else {
        CycleDisposition::Success
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn run_scheduler(
    app: tauri::AppHandle,
    scheduler: AutomaticSyncScheduler,
    generation: u64,
    coordinator: SyncCoordinatorManager,
    app_store: AppStore,
) {
    let mut policy = AutomaticSyncPolicy::new(now_ms());
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if !scheduler.is_current(generation) {
            return;
        }
        let observed_at_ms = now_ms();
        let status = match coordinator.status_with_app_store(&app_store) {
            Ok(status) => status,
            Err(_) => continue,
        };
        if !status.configured {
            return;
        }
        if status.running || status.recovery_required {
            continue;
        }
        if status.last_error_code.is_none() {
            policy.resume_after_external_success(observed_at_ms, status.pending_objects);
        }
        if !policy.observe(observed_at_ms, status.pending_objects) {
            continue;
        }

        let worker_coordinator = coordinator.clone();
        let worker_store = app_store.clone();
        let worker_result = tauri::async_runtime::spawn_blocking(move || {
            worker_coordinator.run_once(&worker_store, observed_at_ms)
        })
        .await;
        if !scheduler.is_current(generation) {
            return;
        }

        let status = match coordinator.status_with_app_store(&app_store) {
            Ok(status) => status,
            Err(_) => continue,
        };
        if status.running {
            policy.complete(
                now_ms(),
                status.pending_objects,
                CycleDisposition::RetryableFailure,
            );
            continue;
        }
        let disposition = cycle_disposition(&status, !matches!(worker_result, Ok(Ok(_))));
        policy.complete(now_ms(), status.pending_objects, disposition);
        let app_store_snapshot = match app_store.snapshot() {
            Ok(snapshot) => snapshot,
            Err(_) => continue,
        };
        if !scheduler.is_current(generation) {
            return;
        }
        let _ = app.emit(
            AUTOMATIC_SYNC_CYCLE_EVENT,
            AutomaticSyncCycleEvent {
                status,
                app_store: app_store_snapshot,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_and_business_changes_are_debounced() {
        let mut policy = AutomaticSyncPolicy::new(1_000);
        assert!(!policy.observe(2_999, 0));
        assert!(policy.observe(3_000, 0));

        policy.complete(3_000, 0, CycleDisposition::Success);
        assert!(!policy.observe(3_500, 1));
        assert!(!policy.observe(5_499, 1));
        assert!(policy.observe(5_500, 1));
    }

    #[test]
    fn successful_cycles_use_periodic_or_pending_recheck_deadlines() {
        let mut periodic_policy = AutomaticSyncPolicy::new(0);
        periodic_policy.complete(10, 0, CycleDisposition::Success);
        assert!(!periodic_policy.observe(10 + PERIODIC_INTERVAL_MS - 1, 0));
        assert!(periodic_policy.observe(10 + PERIODIC_INTERVAL_MS, 0));

        let mut pending_policy = AutomaticSyncPolicy::new(0);
        pending_policy.complete(20, 4, CycleDisposition::Success);
        assert!(!pending_policy.observe(20 + PENDING_RECHECK_MS - 1, 4));
        assert!(pending_policy.observe(20 + PENDING_RECHECK_MS, 4));
    }

    #[test]
    fn retryable_failures_suppress_tight_business_retries() {
        let mut policy = AutomaticSyncPolicy::new(0);
        policy.complete(100, 2, CycleDisposition::RetryableFailure);
        assert!(!policy.observe(100 + CHANGE_DEBOUNCE_MS, 2));
        assert!(!policy.observe(100 + RETRY_DELAY_MS - 1, 2));
        assert!(policy.observe(100 + RETRY_DELAY_MS, 2));
    }

    #[test]
    fn permanent_failure_requires_external_success_to_resume() {
        let mut policy = AutomaticSyncPolicy::new(0);
        policy.complete(100, 1, CycleDisposition::Suspended);
        assert!(!policy.observe(i64::MAX, 2));

        policy.resume_after_external_success(200, 2);
        assert!(!policy.observe(200 + PENDING_RECHECK_MS - 1, 2));
        assert!(policy.observe(200 + PENDING_RECHECK_MS, 2));
    }

    #[test]
    fn clock_regression_never_triggers_a_cycle() {
        let mut policy = AutomaticSyncPolicy::new(10_000);
        assert!(!policy.observe(9_999, 1));
        assert!(!policy.observe(9_999, 2));
        assert!(!policy.observe(11_999, 2));
        assert!(policy.observe(12_000, 2));
    }

    #[test]
    fn stop_invalidates_the_previous_scheduler_generation() {
        let scheduler = AutomaticSyncScheduler::default();
        let generation = scheduler.advance_generation().unwrap();
        assert!(scheduler.is_current(generation));
        scheduler.stop().unwrap();
        assert!(!scheduler.is_current(generation));
    }
}

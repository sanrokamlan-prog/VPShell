//! Bounded, explicit measurement of fully authenticated native SSH routes.

use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::native_engine::{
    NativeEngineManager, NativeRouteRequest, validate_measurement_route,
};

const SCHEMA_VERSION: u16 = 1;
const MAX_CANDIDATES: usize = 4;
const MIN_INTERVAL_SECONDS: u16 = 30;
const MAX_INTERVAL_SECONDS: u16 = 300;
const MIN_WINDOW_SIZE: u8 = 3;
const MAX_WINDOW_SIZE: u8 = 20;
const MAX_ROUNDS: u16 = 120;
const MIN_BASELINE_SAMPLES: usize = 3;
const MIN_SUCCESS_RATE_PERCENT: u8 = 80;
const FAILURE_PENALTY_MS_PER_PERCENT: u64 = 25;
const SWITCH_HYSTERESIS_PERCENT: u64 = 15;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RouteMeasurementStartRequest {
    campaign_id: String,
    interval_seconds: u16,
    window_size: u8,
    max_rounds: u16,
    candidates: Vec<RouteMeasurementCandidateRequest>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RouteMeasurementCandidateRequest {
    candidate_id: String,
    route: NativeRouteRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RouteMeasurementCampaignRequest {
    campaign_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RouteMeasurementSnapshot {
    schema_version: u16,
    campaign_id: String,
    running: bool,
    sampling: bool,
    interval_seconds: u16,
    window_size: u8,
    max_rounds: u16,
    completed_rounds: u16,
    started_at_ms: u64,
    selected_candidate_id: Option<String>,
    selection_reason_code: &'static str,
    candidates: Vec<RouteCandidateSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteCandidateSnapshot {
    candidate_id: String,
    status: &'static str,
    sample_count: u8,
    successful_samples: u8,
    success_rate_percent: u8,
    median_duration_ms: Option<u64>,
    p95_duration_ms: Option<u64>,
    score_ms: Option<u64>,
    eligible: bool,
    last_sampled_at_ms: Option<u64>,
    last_error_code: Option<&'static str>,
    last_error_retryable: Option<bool>,
    last_error_hop_index: Option<u8>,
    reason_codes: Vec<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RouteMeasurementError {
    code: &'static str,
    message: &'static str,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hop_index: Option<u8>,
}

impl RouteMeasurementError {
    fn new(code: &'static str, message: &'static str, retryable: bool) -> Self {
        Self {
            code,
            message,
            retryable,
            candidate_id: None,
            hop_index: None,
        }
    }

    fn invalid(message: &'static str) -> Self {
        Self::new("route-measurement-invalid-request", message, false)
    }

}

#[derive(Clone, Default)]
pub(crate) struct RouteMeasurementManager {
    inner: Arc<RouteMeasurementManagerInner>,
}

#[derive(Default)]
struct RouteMeasurementManagerInner {
    active: Mutex<Option<ActiveCampaign>>,
    next_generation: AtomicU64,
}

struct ActiveCampaign {
    campaign_id: Uuid,
    generation: u64,
    cancellation: CancellationToken,
    state: Arc<Mutex<CampaignState>>,
}

struct CampaignState {
    running: bool,
    sampling: bool,
    interval_seconds: u16,
    window_size: u8,
    max_rounds: u16,
    completed_rounds: u16,
    started_at_ms: u64,
    selected_candidate_id: Option<String>,
    selection_reason_code: &'static str,
    candidates: BTreeMap<String, CandidateState>,
}

#[derive(Default)]
struct CandidateState {
    samples: VecDeque<RouteSample>,
}

struct RouteSample {
    sampled_at_ms: u64,
    duration_ms: u64,
    outcome: RouteSampleOutcome,
}

enum RouteSampleOutcome {
    Ready,
    Failed {
        code: &'static str,
        retryable: bool,
        hop_index: Option<u8>,
    },
}

struct ValidatedStart {
    campaign_id: Uuid,
    interval_seconds: u16,
    window_size: u8,
    max_rounds: u16,
    candidates: Vec<RouteMeasurementCandidateRequest>,
}

struct MeasurementResult {
    candidate_id: String,
    sampled_at_ms: u64,
    duration_ms: u64,
    outcome: RouteSampleOutcome,
}

struct CandidateEvaluation {
    snapshot: RouteCandidateSnapshot,
    score_ms: Option<u64>,
}

impl RouteMeasurementManager {
    pub(crate) fn start(
        &self,
        native: NativeEngineManager,
        request: RouteMeasurementStartRequest,
    ) -> Result<RouteMeasurementSnapshot, RouteMeasurementError> {
        let request = validate_start_request(request)?;
        let generation = self
            .inner
            .next_generation
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map(|previous| previous + 1)
            .map_err(|_| {
                RouteMeasurementError::new(
                    "route-measurement-generation-exhausted",
                    "路线测量代际已耗尽",
                    false,
                )
            })?;
        let cancellation = CancellationToken::new();
        let state = Arc::new(Mutex::new(CampaignState {
            running: true,
            sampling: false,
            interval_seconds: request.interval_seconds,
            window_size: request.window_size,
            max_rounds: request.max_rounds,
            completed_rounds: 0,
            started_at_ms: unix_time_ms(),
            selected_candidate_id: None,
            selection_reason_code: "collecting-baseline",
            candidates: request
                .candidates
                .iter()
                .map(|candidate| (candidate.candidate_id.clone(), CandidateState::default()))
                .collect(),
        }));
        {
            let mut active = self.lock_active()?;
            if active.is_some() {
                return Err(RouteMeasurementError::new(
                    "route-measurement-conflict",
                    "已有路线测量正在运行或等待关闭",
                    true,
                ));
            }
            *active = Some(ActiveCampaign {
                campaign_id: request.campaign_id,
                generation,
                cancellation: cancellation.clone(),
                state: Arc::clone(&state),
            });
        }
        let snapshot = snapshot_state(request.campaign_id, &state)?;
        tokio::spawn(run_campaign(
            self.clone(),
            native,
            request.candidates,
            state,
            cancellation,
            request.campaign_id,
            generation,
            request.interval_seconds,
            request.max_rounds,
        ));
        Ok(snapshot)
    }

    pub(crate) fn get(
        &self,
        request: RouteMeasurementCampaignRequest,
    ) -> Result<RouteMeasurementSnapshot, RouteMeasurementError> {
        let campaign_id = parse_campaign_id(&request.campaign_id)?;
        let active = self.lock_active()?;
        let campaign = active
            .as_ref()
            .filter(|campaign| campaign.campaign_id == campaign_id)
            .ok_or_else(campaign_not_found)?;
        snapshot_state(campaign_id, &campaign.state)
    }

    pub(crate) fn stop(
        &self,
        request: RouteMeasurementCampaignRequest,
    ) -> Result<(), RouteMeasurementError> {
        let campaign_id = parse_campaign_id(&request.campaign_id)?;
        let campaign = {
            let mut active = self.lock_active()?;
            if active
                .as_ref()
                .is_none_or(|campaign| campaign.campaign_id != campaign_id)
            {
                return Err(campaign_not_found());
            }
            active.take().expect("checked active campaign")
        };
        campaign.cancellation.cancel();
        if let Ok(mut state) = campaign.state.lock() {
            state.running = false;
            state.sampling = false;
        }
        Ok(())
    }

    fn lock_active(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<ActiveCampaign>>, RouteMeasurementError> {
        self.inner.active.lock().map_err(|_| {
            RouteMeasurementError::new(
                "route-measurement-state-corrupt",
                "路线测量状态已损坏",
                false,
            )
        })
    }

    fn is_current(&self, campaign_id: Uuid, generation: u64) -> bool {
        self.lock_active().is_ok_and(|active| {
            active.as_ref().is_some_and(|campaign| {
                campaign.campaign_id == campaign_id && campaign.generation == generation
            })
        })
    }
}

async fn run_campaign(
    manager: RouteMeasurementManager,
    native: NativeEngineManager,
    candidates: Vec<RouteMeasurementCandidateRequest>,
    state: Arc<Mutex<CampaignState>>,
    cancellation: CancellationToken,
    campaign_id: Uuid,
    generation: u64,
    interval_seconds: u16,
    max_rounds: u16,
) {
    for _ in 0..max_rounds {
        if cancellation.is_cancelled() || !manager.is_current(campaign_id, generation) {
            break;
        }
        if let Ok(mut current) = state.lock() {
            current.sampling = true;
        } else {
            cancellation.cancel();
            break;
        }
        let round_started = Instant::now();
        let mut tasks = JoinSet::new();
        for candidate in candidates.iter().cloned() {
            let native = native.clone();
            let cancellation = cancellation.clone();
            tasks.spawn(async move {
                let started = Instant::now();
                let outcome = native.measure_route(candidate.route, cancellation).await;
                MeasurementResult {
                    candidate_id: candidate.candidate_id,
                    sampled_at_ms: unix_time_ms(),
                    duration_ms: elapsed_millis(started.elapsed()),
                    outcome: match outcome {
                        Ok(()) => RouteSampleOutcome::Ready,
                        Err(error) => RouteSampleOutcome::Failed {
                            code: error.code(),
                            retryable: error.retryable(),
                            hop_index: error.hop_index(),
                        },
                    },
                }
            });
        }
        let mut results = Vec::with_capacity(candidates.len());
        let mut worker_failed = false;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(result) => results.push(result),
                Err(_) => worker_failed = true,
            }
        }
        if worker_failed {
            cancellation.cancel();
            if let Ok(mut current) = state.lock() {
                current.running = false;
                current.sampling = false;
                current.selection_reason_code = "probe-worker-failed";
            }
            break;
        }
        if cancellation.is_cancelled() || !manager.is_current(campaign_id, generation) {
            break;
        }
        let update_succeeded = if let Ok(mut current) = state.lock() {
            let window_size = usize::from(current.window_size);
            for result in results {
                if let Some(candidate) = current.candidates.get_mut(&result.candidate_id) {
                    record_sample(
                        candidate,
                        RouteSample {
                            sampled_at_ms: result.sampled_at_ms,
                            duration_ms: result.duration_ms,
                            outcome: result.outcome,
                        },
                        window_size,
                    );
                }
            }
            current.completed_rounds = current.completed_rounds.saturating_add(1);
            current.sampling = false;
            recompute_selection(&mut current);
            true
        } else {
            false
        };
        if !update_succeeded {
            cancellation.cancel();
            break;
        }
        if state
            .lock()
            .map_or(true, |current| current.completed_rounds >= max_rounds)
        {
            break;
        }
        let wait = Duration::from_secs(u64::from(interval_seconds))
            .saturating_sub(round_started.elapsed());
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            _ = tokio::time::sleep(wait) => {}
        }
    }
    if let Ok(mut current) = state.lock() {
        current.running = false;
        current.sampling = false;
    }
}

fn validate_start_request(
    request: RouteMeasurementStartRequest,
) -> Result<ValidatedStart, RouteMeasurementError> {
    let campaign_id = parse_campaign_id(&request.campaign_id)?;
    if !(MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&request.interval_seconds) {
        return Err(RouteMeasurementError::invalid(
            "路线测量间隔必须在 30 到 300 秒之间",
        ));
    }
    if !(MIN_WINDOW_SIZE..=MAX_WINDOW_SIZE).contains(&request.window_size) {
        return Err(RouteMeasurementError::invalid(
            "路线测量窗口必须包含 3 到 20 轮",
        ));
    }
    if request.max_rounds < u16::from(request.window_size) || request.max_rounds > MAX_ROUNDS {
        return Err(RouteMeasurementError::invalid(
            "路线测量总轮数必须覆盖窗口且不超过 120 轮",
        ));
    }
    if request.candidates.is_empty() || request.candidates.len() > MAX_CANDIDATES {
        return Err(RouteMeasurementError::invalid(
            "路线测量必须包含 1 到 4 个候选",
        ));
    }
    let mut candidate_ids = HashSet::with_capacity(request.candidates.len());
    for candidate in &request.candidates {
        validate_candidate_id(&candidate.candidate_id)?;
        if !candidate_ids.insert(candidate.candidate_id.as_str()) {
            return Err(RouteMeasurementError::invalid("路线测量候选标识重复"));
        }
        validate_measurement_route(candidate.route.clone()).map_err(|error| {
            RouteMeasurementError {
                code: error.code(),
                message: error.user_message(),
                retryable: error.retryable(),
                candidate_id: Some(candidate.candidate_id.clone()),
                hop_index: error.hop_index(),
            }
        })?;
    }
    Ok(ValidatedStart {
        campaign_id,
        interval_seconds: request.interval_seconds,
        window_size: request.window_size,
        max_rounds: request.max_rounds,
        candidates: request.candidates,
    })
}

fn parse_campaign_id(value: &str) -> Result<Uuid, RouteMeasurementError> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| RouteMeasurementError::invalid("路线测量标识无效"))?;
    if value.len() != 36 || parsed.to_string() != value {
        return Err(RouteMeasurementError::invalid("路线测量标识无效"));
    }
    Ok(parsed)
}

fn validate_candidate_id(value: &str) -> Result<(), RouteMeasurementError> {
    if value.is_empty()
        || value.len() > 32
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
        })
        || value.starts_with('-')
        || value.ends_with('-')
    {
        return Err(RouteMeasurementError::invalid(
            "路线测量候选标识格式无效",
        ));
    }
    Ok(())
}

fn record_sample(candidate: &mut CandidateState, sample: RouteSample, window_size: usize) {
    candidate.samples.push_back(sample);
    while candidate.samples.len() > window_size {
        candidate.samples.pop_front();
    }
}

fn recompute_selection(state: &mut CampaignState) {
    let evaluations = state
        .candidates
        .iter()
        .map(|(candidate_id, candidate)| {
            (
                candidate_id.clone(),
                evaluate_candidate(candidate_id, candidate),
            )
        })
        .collect::<Vec<_>>();
    let mut eligible = evaluations
        .iter()
        .filter_map(|(candidate_id, evaluation)| {
            evaluation
                .snapshot
                .eligible
                .then(|| (candidate_id.clone(), evaluation.score_ms.unwrap_or(u64::MAX)))
        })
        .collect::<Vec<_>>();
    eligible.sort_by(|(left_id, left_score), (right_id, right_score)| {
        left_score
            .cmp(right_score)
            .then_with(|| left_id.cmp(right_id))
    });
    let Some((best_id, best_score)) = eligible.first() else {
        state.selected_candidate_id = None;
        state.selection_reason_code = if evaluations
            .iter()
            .any(|(_, evaluation)| evaluation.snapshot.sample_count < MIN_BASELINE_SAMPLES as u8)
        {
            "collecting-baseline"
        } else {
            "no-reliable-candidate"
        };
        return;
    };
    if let Some(previous_id) = state.selected_candidate_id.as_ref()
        && let Some((_, previous_score)) = eligible
            .iter()
            .find(|(candidate_id, _)| candidate_id == previous_id)
        && previous_score.saturating_mul(100)
            <= best_score
                .saturating_mul(100 + SWITCH_HYSTERESIS_PERCENT)
    {
        state.selection_reason_code = if previous_id == best_id {
            "lowest-observed-score"
        } else {
            "retained-within-hysteresis"
        };
        return;
    }
    state.selected_candidate_id = Some(best_id.clone());
    state.selection_reason_code = if eligible.len() == 1 {
        "only-reliable-candidate"
    } else {
        "lowest-observed-score"
    };
}

fn evaluate_candidate(candidate_id: &str, state: &CandidateState) -> CandidateEvaluation {
    let total = state.samples.len();
    let mut durations = state
        .samples
        .iter()
        .filter_map(|sample| match &sample.outcome {
            RouteSampleOutcome::Ready => Some(sample.duration_ms),
            RouteSampleOutcome::Failed { .. } => None,
        })
        .collect::<Vec<_>>();
    durations.sort_unstable();
    let successful = durations.len();
    let success_rate = if total == 0 {
        0
    } else {
        u8::try_from(successful.saturating_mul(100) / total).unwrap_or(100)
    };
    let median = percentile(&durations, 50);
    let p95 = percentile(&durations, 95);
    let score = median.zip(p95).map(|(median, p95)| {
        median
            .saturating_add(p95.saturating_sub(median))
            .saturating_add(
                u64::from(100_u8.saturating_sub(success_rate))
                    .saturating_mul(FAILURE_PENALTY_MS_PER_PERCENT),
            )
    });
    let eligible = total >= MIN_BASELINE_SAMPLES
        && successful >= 2
        && success_rate >= MIN_SUCCESS_RATE_PERCENT;
    let last = state.samples.back();
    let (status, last_error_code, last_error_retryable, last_error_hop_index) = match last {
        None => ("pending", None, None, None),
        Some(RouteSample {
            outcome: RouteSampleOutcome::Ready,
            ..
        }) => ("ready", None, None, None),
        Some(RouteSample {
            outcome:
                RouteSampleOutcome::Failed {
                    code,
                    retryable,
                    hop_index,
                },
            ..
        }) => ("failed", Some(*code), Some(*retryable), *hop_index),
    };
    let mut reason_codes = Vec::with_capacity(4);
    if total == 0 {
        reason_codes.push("no-samples");
    } else if total < MIN_BASELINE_SAMPLES {
        reason_codes.push("collecting-baseline");
    } else if success_rate < MIN_SUCCESS_RATE_PERCENT {
        reason_codes.push("success-rate-below-threshold");
    } else {
        reason_codes.push("full-route-ready");
    }
    if status == "failed" {
        reason_codes.push("latest-probe-failed");
    }
    if eligible {
        reason_codes.push("eligible");
    }
    CandidateEvaluation {
        snapshot: RouteCandidateSnapshot {
            candidate_id: candidate_id.to_string(),
            status,
            sample_count: u8::try_from(total).unwrap_or(u8::MAX),
            successful_samples: u8::try_from(successful).unwrap_or(u8::MAX),
            success_rate_percent: success_rate,
            median_duration_ms: median,
            p95_duration_ms: p95,
            score_ms: score,
            eligible,
            last_sampled_at_ms: last.map(|sample| sample.sampled_at_ms),
            last_error_code,
            last_error_retryable,
            last_error_hop_index,
            reason_codes,
        },
        score_ms: score,
    }
}

fn percentile(values: &[u64], percentile: usize) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let rank = values
        .len()
        .saturating_mul(percentile)
        .saturating_add(99)
        / 100;
    values.get(rank.saturating_sub(1)).copied()
}

fn snapshot_state(
    campaign_id: Uuid,
    state: &Arc<Mutex<CampaignState>>,
) -> Result<RouteMeasurementSnapshot, RouteMeasurementError> {
    let state = state.lock().map_err(|_| {
        RouteMeasurementError::new(
            "route-measurement-state-corrupt",
            "路线测量状态已损坏",
            false,
        )
    })?;
    Ok(RouteMeasurementSnapshot {
        schema_version: SCHEMA_VERSION,
        campaign_id: campaign_id.to_string(),
        running: state.running,
        sampling: state.sampling,
        interval_seconds: state.interval_seconds,
        window_size: state.window_size,
        max_rounds: state.max_rounds,
        completed_rounds: state.completed_rounds,
        started_at_ms: state.started_at_ms,
        selected_candidate_id: state.selected_candidate_id.clone(),
        selection_reason_code: state.selection_reason_code,
        candidates: state
            .candidates
            .iter()
            .map(|(candidate_id, candidate)| evaluate_candidate(candidate_id, candidate).snapshot)
            .collect(),
    })
}

fn campaign_not_found() -> RouteMeasurementError {
    RouteMeasurementError::new(
        "route-measurement-not-found",
        "路线测量不存在或已经关闭",
        false,
    )
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, elapsed_millis)
}

fn elapsed_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn route() -> NativeRouteRequest {
        serde_json::from_value(json!({
            "hops": [{
                "hopId": "018f1f55-26f8-7a9f-9cd8-4d7558482213",
                "host": "host.example",
                "port": 22,
                "username": "operator",
                "hostKeySha256": format!("SHA256:{}", "A".repeat(43)),
                "timeoutSeconds": 15,
                "credentialRef": "ssh-018f1f55-26f8-7a9f-9cd8-4d7558482212"
            }]
        }))
        .unwrap()
    }

    fn start_request(candidate_ids: &[&str]) -> RouteMeasurementStartRequest {
        RouteMeasurementStartRequest {
            campaign_id: "018f1f55-26f8-7a9f-9cd8-4d7558482211".to_string(),
            interval_seconds: 30,
            window_size: 5,
            max_rounds: 10,
            candidates: candidate_ids
                .iter()
                .map(|candidate_id| RouteMeasurementCandidateRequest {
                    candidate_id: (*candidate_id).to_string(),
                    route: route(),
                })
                .collect(),
        }
    }

    fn ready(sampled_at_ms: u64, duration_ms: u64) -> RouteSample {
        RouteSample {
            sampled_at_ms,
            duration_ms,
            outcome: RouteSampleOutcome::Ready,
        }
    }

    fn failed(sampled_at_ms: u64) -> RouteSample {
        RouteSample {
            sampled_at_ms,
            duration_ms: 100,
            outcome: RouteSampleOutcome::Failed {
                code: "native-engine-timeout",
                retryable: true,
                hop_index: Some(1),
            },
        }
    }

    #[test]
    fn request_is_bounded_and_rejects_inline_secrets() {
        assert!(validate_start_request(start_request(&["direct", "configured-jump"])).is_ok());
        let mut invalid_interval = start_request(&["direct"]);
        invalid_interval.interval_seconds = 29;
        assert!(validate_start_request(invalid_interval).is_err());
        let mut invalid_window = start_request(&["direct"]);
        invalid_window.window_size = 2;
        assert!(validate_start_request(invalid_window).is_err());
        let mut invalid_rounds = start_request(&["direct"]);
        invalid_rounds.max_rounds = 4;
        assert!(validate_start_request(invalid_rounds).is_err());
        let mut too_many = start_request(&["a", "b", "c", "d", "e"]);
        assert!(validate_start_request(too_many).is_err());
        too_many = start_request(&["direct"]);
        too_many.campaign_id = "not-a-uuid".to_string();
        assert!(validate_start_request(too_many).is_err());
        let mut duplicate = start_request(&["direct", "direct"]);
        assert!(validate_start_request(duplicate).is_err());
        duplicate = start_request(&["Direct"]);
        assert!(validate_start_request(duplicate).is_err());
        let value = json!({
            "campaignId": "018f1f55-26f8-7a9f-9cd8-4d7558482211",
            "intervalSeconds": 30,
            "windowSize": 5,
            "maxRounds": 10,
            "candidates": [{
                "candidateId": "direct",
                "route": { "hops": [{
                    "hopId": "018f1f55-26f8-7a9f-9cd8-4d7558482213",
                    "host": "host.example",
                    "port": 22,
                    "username": "operator",
                    "hostKeySha256": format!("SHA256:{}", "A".repeat(43)),
                    "timeoutSeconds": 15,
                    "credentialRef": "ssh-018f1f55-26f8-7a9f-9cd8-4d7558482212",
                    "password": "forbidden"
                }]}
            }]
        });
        assert!(serde_json::from_value::<RouteMeasurementStartRequest>(value).is_err());
    }

    #[test]
    fn rolling_window_and_score_penalize_failures() {
        let mut candidate = CandidateState::default();
        for sample in [
            ready(0, 90),
            ready(1, 100),
            ready(2, 110),
            ready(3, 120),
            failed(4),
            ready(5, 130),
        ] {
            record_sample(&mut candidate, sample, 5);
        }
        assert_eq!(candidate.samples.len(), 5);
        assert_eq!(candidate.samples.front().map(|sample| sample.sampled_at_ms), Some(1));
        let evaluation = evaluate_candidate("direct", &candidate).snapshot;
        assert_eq!(evaluation.success_rate_percent, 80);
        assert_eq!(evaluation.median_duration_ms, Some(110));
        assert_eq!(evaluation.p95_duration_ms, Some(130));
        assert_eq!(evaluation.score_ms, Some(630));
        assert!(evaluation.eligible);
        assert_eq!(evaluation.last_error_code, None);
    }

    #[test]
    fn selection_is_deterministic_and_uses_hysteresis() {
        let mut state = CampaignState {
            running: true,
            sampling: false,
            interval_seconds: 30,
            window_size: 5,
            max_rounds: 10,
            completed_rounds: 3,
            started_at_ms: 1,
            selected_candidate_id: None,
            selection_reason_code: "collecting-baseline",
            candidates: BTreeMap::from([
                (
                    "configured-jump".to_string(),
                    CandidateState {
                        samples: VecDeque::from([ready(1, 105), ready(2, 105), ready(3, 105)]),
                    },
                ),
                (
                    "direct".to_string(),
                    CandidateState {
                        samples: VecDeque::from([ready(1, 100), ready(2, 100), ready(3, 100)]),
                    },
                ),
            ]),
        };
        recompute_selection(&mut state);
        assert_eq!(state.selected_candidate_id.as_deref(), Some("direct"));
        state.selected_candidate_id = Some("configured-jump".to_string());
        recompute_selection(&mut state);
        assert_eq!(
            state.selected_candidate_id.as_deref(),
            Some("configured-jump")
        );
        assert_eq!(state.selection_reason_code, "retained-within-hysteresis");
    }

    #[test]
    fn snapshot_contains_no_route_or_credential_values() {
        let state = Arc::new(Mutex::new(CampaignState {
            running: true,
            sampling: false,
            interval_seconds: 30,
            window_size: 5,
            max_rounds: 10,
            completed_rounds: 1,
            started_at_ms: 1,
            selected_candidate_id: None,
            selection_reason_code: "collecting-baseline",
            candidates: BTreeMap::from([(
                "direct".to_string(),
                CandidateState {
                    samples: VecDeque::from([failed(1)]),
                },
            )]),
        }));
        let snapshot = snapshot_state(Uuid::nil(), &state).unwrap();
        let encoded = serde_json::to_string(&snapshot).unwrap();
        for forbidden in [
            "host.example",
            "operator",
            "credentialRef",
            "identityFile",
            "ssh-018f",
        ] {
            assert!(!encoded.contains(forbidden));
        }
        assert!(encoded.contains("native-engine-timeout"));
    }

    #[test]
    fn stop_cancels_and_removes_campaign() {
        let manager = RouteMeasurementManager::default();
        let campaign_id = Uuid::parse_str("018f1f55-26f8-7a9f-9cd8-4d7558482211").unwrap();
        let cancellation = CancellationToken::new();
        let state = Arc::new(Mutex::new(CampaignState {
            running: true,
            sampling: true,
            interval_seconds: 30,
            window_size: 5,
            max_rounds: 10,
            completed_rounds: 0,
            started_at_ms: 1,
            selected_candidate_id: None,
            selection_reason_code: "collecting-baseline",
            candidates: BTreeMap::new(),
        }));
        *manager.lock_active().unwrap() = Some(ActiveCampaign {
            campaign_id,
            generation: 7,
            cancellation: cancellation.clone(),
            state,
        });
        assert!(manager.is_current(campaign_id, 7));
        assert!(!manager.is_current(campaign_id, 8));
        manager
            .stop(RouteMeasurementCampaignRequest {
                campaign_id: campaign_id.to_string(),
            })
            .unwrap();
        assert!(cancellation.is_cancelled());
        let error = manager
            .get(RouteMeasurementCampaignRequest {
                campaign_id: campaign_id.to_string(),
            })
            .unwrap_err();
        assert_eq!(error.code, "route-measurement-not-found");
    }
}

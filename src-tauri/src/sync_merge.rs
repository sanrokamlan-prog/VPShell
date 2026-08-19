use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const FORMAT_VERSION: u32 = 1;
const MAX_OPERATION_BYTES: usize = 1024 * 1024;
const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_FIELDS_PER_PATCH: usize = 64;
const MAX_ENTITIES: usize = 10_000;
const MAX_HISTORY_EVENTS: usize = 50_000;
const MAX_CONFLICTS: usize = 1_000;
const MAX_CONFLICT_PAGE: usize = 50;
const MAX_CONFLICT_PREVIEW_BYTES: usize = 2_048;
const MAX_APPLIED_OPERATIONS: usize = 50_000;
const MAX_TEXT_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MergeErrorCode {
    InvalidInput,
    LimitExceeded,
    Replay,
    ConflictMissing,
    StaleResolution,
    RevisionConflict,
    Storage,
    CorruptState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MergeError {
    pub(crate) code: MergeErrorCode,
    pub(crate) message: String,
}

impl MergeError {
    fn new(code: MergeErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

type MergeResult<T> = Result<T, MergeError>;

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HybridLogicalClock {
    physical_ms: i64,
    logical: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MergeStamp {
    hlc: HybridLogicalClock,
    device_id: String,
    operation_id: String,
}

impl Ord for MergeStamp {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.hlc.physical_ms,
            self.hlc.logical,
            self.device_id.as_str(),
            self.operation_id.as_str(),
        )
            .cmp(&(
                other.hlc.physical_ms,
                other.hlc.logical,
                other.device_id.as_str(),
                other.operation_id.as_str(),
            ))
    }
}

impl PartialOrd for MergeStamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EntityKind {
    Host,
    Script,
    Setting,
    Background,
    History,
}

impl EntityKind {
    fn label(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Script => "script",
            Self::Setting => "setting",
            Self::Background => "background",
            Self::History => "history",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub(crate) enum FieldValue {
    Text(String),
    Integer(i64),
    Flag(bool),
    TextList(Vec<String>),
    BlobRef(String),
    Clear,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LocalEntityMutation {
    Patch(BTreeMap<String, FieldValue>),
    Delete,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MergedEntityProjection {
    pub(crate) entity_id: String,
    pub(crate) fields: Option<BTreeMap<String, FieldValue>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FieldRegister {
    value: FieldValue,
    stamp: MergeStamp,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PatchPayload {
    entity_kind: EntityKind,
    entity_id: String,
    fields: BTreeMap<String, FieldValue>,
    observed_fields: BTreeMap<String, Option<MergeStamp>>,
    observed_tombstone: Option<MergeStamp>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeletePayload {
    entity_kind: EntityKind,
    entity_id: String,
    observed_fields: BTreeMap<String, MergeStamp>,
    observed_tombstone: Option<MergeStamp>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HistoryKind {
    Command,
    Argument,
    RemotePath,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HistoryScope {
    Global,
    Host,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HistoryEvent {
    event_id: String,
    kind: HistoryKind,
    value: String,
    scope: HistoryScope,
    host_id: Option<String>,
    parameter_name: Option<String>,
    public_value: bool,
    stamp: MergeStamp,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResolvePayload {
    conflict_id: String,
    entity_kind: EntityKind,
    entity_id: String,
    field: String,
    value: Option<FieldValue>,
    keep_deleted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "kind", content = "payload", rename_all = "camelCase")]
pub(crate) enum MergePayload {
    Patch(PatchPayload),
    Delete(DeletePayload),
    HistoryAppend(HistoryEvent),
    Resolve(ResolvePayload),
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MergeOperation {
    format_version: u32,
    operation_id: String,
    device_id: String,
    sequence: u64,
    hlc: HybridLogicalClock,
    payload: MergePayload,
}

impl MergeOperation {
    pub(crate) fn encode(&self) -> MergeResult<Vec<u8>> {
        validate_operation(self)?;
        let encoded = serde_json::to_vec(self).map_err(|_| {
            MergeError::new(
                MergeErrorCode::InvalidInput,
                "无法序列化同步 merge operation",
            )
        })?;
        if encoded.len() > MAX_OPERATION_BYTES {
            return Err(MergeError::new(
                MergeErrorCode::LimitExceeded,
                "同步 merge operation 超过 1 MiB",
            ));
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> MergeResult<Self> {
        if encoded.is_empty() || encoded.len() > MAX_OPERATION_BYTES {
            return Err(MergeError::new(
                MergeErrorCode::LimitExceeded,
                "同步 merge operation 必须为 1 字节至 1 MiB",
            ));
        }
        let operation = serde_json::from_slice(encoded).map_err(|_| {
            MergeError::new(
                MergeErrorCode::InvalidInput,
                "同步 merge operation JSON 损坏或字段不受支持",
            )
        })?;
        validate_operation(&operation)?;
        Ok(operation)
    }

    fn stamp(&self) -> MergeStamp {
        MergeStamp {
            hlc: self.hlc.clone(),
            device_id: self.device_id.clone(),
            operation_id: self.operation_id.clone(),
        }
    }
}

pub(crate) fn build_local_entity_operation(
    state: &MergeState,
    operation_id: &str,
    device_id: &str,
    sequence: u64,
    physical_ms: i64,
    logical: u16,
    entity_kind: EntityKind,
    entity_id: &str,
    mutation: LocalEntityMutation,
) -> MergeResult<MergeOperation> {
    let record = state.entities.get(&entity_key(&entity_kind, entity_id));
    let payload = match mutation {
        LocalEntityMutation::Patch(fields) => {
            let observed_fields = fields
                .keys()
                .map(|field| {
                    (
                        field.clone(),
                        record
                            .and_then(|record| record.fields.get(field))
                            .map(|register| register.stamp.clone()),
                    )
                })
                .collect();
            MergePayload::Patch(PatchPayload {
                entity_kind: entity_kind.clone(),
                entity_id: entity_id.to_string(),
                fields,
                observed_fields,
                observed_tombstone: record.and_then(|record| record.tombstone.clone()),
            })
        }
        LocalEntityMutation::Delete => MergePayload::Delete(DeletePayload {
            entity_kind,
            entity_id: entity_id.to_string(),
            observed_fields: record
                .map(|record| {
                    record
                        .fields
                        .iter()
                        .map(|(field, register)| (field.clone(), register.stamp.clone()))
                        .collect()
                })
                .unwrap_or_default(),
            observed_tombstone: record.and_then(|record| record.tombstone.clone()),
        }),
    };
    let operation = MergeOperation {
        format_version: FORMAT_VERSION,
        operation_id: operation_id.to_string(),
        device_id: device_id.to_string(),
        sequence,
        hlc: HybridLogicalClock {
            physical_ms,
            logical,
        },
        payload,
    };
    validate_operation(&operation)?;
    Ok(operation)
}

pub(crate) fn advance_local_hlc(
    state: &MergeState,
    candidate_physical_ms: i64,
    candidate_logical: u16,
) -> MergeResult<(i64, u16)> {
    if candidate_physical_ms < 0 {
        return Err(MergeError::new(
            MergeErrorCode::InvalidInput,
            "本机同步 HLC 时间无效",
        ));
    }
    let mut maximum: Option<(i64, u16)> = None;
    let mut observe = |stamp: &MergeStamp| {
        let value = (stamp.hlc.physical_ms, stamp.hlc.logical);
        if maximum.is_none_or(|current| value > current) {
            maximum = Some(value);
        }
    };
    for record in state.entities.values() {
        for register in record.fields.values() {
            observe(&register.stamp);
        }
        if let Some(stamp) = &record.tombstone {
            observe(stamp);
        }
    }
    for event in state.histories.values() {
        observe(&event.stamp);
    }
    for conflict in state.conflicts.values() {
        for alternative in &conflict.alternatives {
            observe(&alternative.stamp);
        }
        if let Some(stamp) = &conflict.resolution_stamp {
            observe(stamp);
        }
    }
    let Some(maximum) = maximum else {
        return Ok((candidate_physical_ms, candidate_logical));
    };
    if (candidate_physical_ms, candidate_logical) > maximum {
        return Ok((candidate_physical_ms, candidate_logical));
    }
    if maximum.1 < u16::MAX {
        Ok((maximum.0, maximum.1 + 1))
    } else {
        Ok((
            maximum
                .0
                .checked_add(1)
                .ok_or_else(|| MergeError::new(MergeErrorCode::LimitExceeded, "同步 HLC 已耗尽"))?,
            0,
        ))
    }
}

pub(crate) fn local_entity_operation_matches(
    encoded: &[u8],
    operation_id: &str,
    entity_kind: &EntityKind,
    entity_id: &str,
    mutation: &LocalEntityMutation,
) -> bool {
    let Ok(operation) = MergeOperation::decode(encoded) else {
        return false;
    };
    if operation.operation_id != operation_id {
        return false;
    }
    match (&operation.payload, mutation) {
        (MergePayload::Patch(payload), LocalEntityMutation::Patch(fields)) => {
            payload.entity_kind == *entity_kind
                && payload.entity_id == entity_id
                && payload.fields == *fields
        }
        (MergePayload::Delete(payload), LocalEntityMutation::Delete) => {
            payload.entity_kind == *entity_kind && payload.entity_id == entity_id
        }
        _ => false,
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ConflictReason {
    ConcurrentEdit,
    ConnectionIdentity,
    ScriptContent,
    RiskLowered,
    DeletedEntityEdited,
    ConcurrentDelete,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConflictAlternative {
    value: Option<FieldValue>,
    stamp: MergeStamp,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MergeConflict {
    conflict_id: String,
    entity_kind: EntityKind,
    entity_id: String,
    field: String,
    reason: ConflictReason,
    alternatives: [ConflictAlternative; 2],
    resolution_stamp: Option<MergeStamp>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConflictAlternativeSnapshot {
    pub(crate) index: u8,
    pub(crate) value_type: String,
    pub(crate) preview: Option<String>,
    pub(crate) byte_length: u64,
    pub(crate) content_hash: Option<String>,
    pub(crate) truncated: bool,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MergeConflictSnapshot {
    pub(crate) conflict_id: String,
    pub(crate) entity_kind: EntityKind,
    pub(crate) entity_id: String,
    pub(crate) field: String,
    pub(crate) reason: ConflictReason,
    pub(crate) alternatives: [ConflictAlternativeSnapshot; 2],
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EntityRecord {
    fields: BTreeMap<String, FieldRegister>,
    tombstone: Option<MergeStamp>,
    tombstone_observed_fields: BTreeMap<String, MergeStamp>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MergeState {
    format_version: u32,
    entities: BTreeMap<String, EntityRecord>,
    histories: BTreeMap<String, HistoryEvent>,
    conflicts: BTreeMap<String, MergeConflict>,
    applied_operations: BTreeMap<String, String>,
}

impl Default for MergeState {
    fn default() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            entities: BTreeMap::new(),
            histories: BTreeMap::new(),
            conflicts: BTreeMap::new(),
            applied_operations: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplyOutcome {
    Applied,
    AlreadyApplied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PersistedMergeResult {
    pub(crate) revision: u64,
    pub(crate) outcome: ApplyOutcome,
    pub(crate) open_conflicts: usize,
}

pub(crate) fn load_persisted_state(
    transaction: &Transaction<'_>,
) -> MergeResult<(u64, MergeState)> {
    let row: Option<(i64, i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT schema_version, revision, state_blob
             FROM sync_merge_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| MergeError::new(MergeErrorCode::Storage, "无法读取持久同步 merge 状态"))?;
    let Some((schema_version, revision, encoded)) = row else {
        return Ok((0, MergeState::default()));
    };
    if schema_version != FORMAT_VERSION as i64 || revision < 0 {
        return Err(MergeError::new(
            MergeErrorCode::CorruptState,
            "持久同步 merge 状态版本或 revision 无效",
        ));
    }
    Ok((revision as u64, MergeState::decode(&encoded)?))
}

pub(crate) fn apply_persisted_operation(
    transaction: &Transaction<'_>,
    encoded_operation: &[u8],
    expected_revision: u64,
    now_ms: i64,
) -> MergeResult<PersistedMergeResult> {
    if now_ms < 0 {
        return Err(MergeError::new(
            MergeErrorCode::InvalidInput,
            "持久同步 merge 时间不能为负数",
        ));
    }
    let operation = MergeOperation::decode(encoded_operation)?;
    let (revision, mut state) = load_persisted_state(transaction)?;
    if revision != expected_revision {
        return Err(MergeError::new(
            MergeErrorCode::RevisionConflict,
            format!("同步 merge revision 冲突：当前 {revision}，请求 {expected_revision}"),
        ));
    }
    let outcome = state.apply(&operation)?;
    if outcome == ApplyOutcome::AlreadyApplied {
        return Ok(PersistedMergeResult {
            revision,
            outcome,
            open_conflicts: state.open_conflicts().len(),
        });
    }
    let next_revision = revision.checked_add(1).ok_or_else(|| {
        MergeError::new(MergeErrorCode::LimitExceeded, "同步 merge revision 已耗尽")
    })?;
    let next_revision_sql = i64::try_from(next_revision).map_err(|_| {
        MergeError::new(
            MergeErrorCode::LimitExceeded,
            "同步 merge revision 超过 SQLite INTEGER",
        )
    })?;
    let encoded_state = state.encode()?;
    transaction
        .execute(
            "INSERT INTO sync_merge_state(
                singleton, schema_version, revision, state_blob, updated_at_ms
             ) VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(singleton) DO UPDATE SET
                schema_version = excluded.schema_version,
                revision = excluded.revision,
                state_blob = excluded.state_blob,
                updated_at_ms = excluded.updated_at_ms",
            params![FORMAT_VERSION, next_revision_sql, encoded_state, now_ms],
        )
        .map_err(|_| MergeError::new(MergeErrorCode::Storage, "无法写入持久同步 merge 状态"))?;
    Ok(PersistedMergeResult {
        revision: next_revision,
        outcome,
        open_conflicts: state.open_conflicts().len(),
    })
}

impl MergeState {
    pub(crate) fn encode(&self) -> MergeResult<Vec<u8>> {
        validate_state(self)?;
        let encoded = serde_json::to_vec(self).map_err(|_| {
            MergeError::new(MergeErrorCode::CorruptState, "无法序列化同步 merge 状态")
        })?;
        if encoded.len() > MAX_STATE_BYTES {
            return Err(MergeError::new(
                MergeErrorCode::LimitExceeded,
                "同步 merge 状态超过 64 MiB",
            ));
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> MergeResult<Self> {
        if encoded.is_empty() || encoded.len() > MAX_STATE_BYTES {
            return Err(MergeError::new(
                MergeErrorCode::LimitExceeded,
                "同步 merge 状态必须为 1 字节至 64 MiB",
            ));
        }
        let state: Self = serde_json::from_slice(encoded).map_err(|_| {
            MergeError::new(
                MergeErrorCode::CorruptState,
                "同步 merge 状态损坏或字段不受支持",
            )
        })?;
        validate_state(&state)?;
        Ok(state)
    }

    pub(crate) fn apply(&mut self, operation: &MergeOperation) -> MergeResult<ApplyOutcome> {
        validate_operation(operation)?;
        let encoded = operation.encode()?;
        let hash = sha256_hex(&encoded);
        if let Some(existing) = self.applied_operations.get(&operation.operation_id) {
            if existing == &hash {
                return Ok(ApplyOutcome::AlreadyApplied);
            }
            return Err(MergeError::new(
                MergeErrorCode::Replay,
                "相同 operation ID 的内容不同",
            ));
        }
        if self.applied_operations.len() >= MAX_APPLIED_OPERATIONS {
            return Err(MergeError::new(
                MergeErrorCode::LimitExceeded,
                "同步 merge 已应用 operation 超过 50000 项",
            ));
        }
        match &operation.payload {
            MergePayload::Patch(payload) => self.apply_patch(payload, operation.stamp())?,
            MergePayload::Delete(payload) => self.apply_delete(payload, operation.stamp())?,
            MergePayload::HistoryAppend(event) => self.apply_history(event)?,
            MergePayload::Resolve(payload) => self.apply_resolution(payload, operation.stamp())?,
        }
        self.applied_operations
            .insert(operation.operation_id.clone(), hash);
        Ok(ApplyOutcome::Applied)
    }

    pub(crate) fn open_conflicts(&self) -> Vec<MergeConflict> {
        self.conflicts
            .values()
            .filter(|conflict| conflict.resolution_stamp.is_none())
            .cloned()
            .collect()
    }

    pub(crate) fn background_blob_references(&self) -> MergeResult<Vec<String>> {
        let mut references = BTreeSet::new();
        for entity in self.background_projection()? {
            if let Some(FieldValue::BlobRef(blob_id)) = entity
                .fields
                .as_ref()
                .and_then(|fields| fields.get("blobId"))
            {
                references.insert(blob_id.clone());
            }
        }
        for conflict in self.conflicts.values().filter(|conflict| {
            conflict.resolution_stamp.is_none()
                && conflict.entity_kind == EntityKind::Background
                && conflict.field == "blobId"
        }) {
            for alternative in &conflict.alternatives {
                if let Some(FieldValue::BlobRef(blob_id)) = &alternative.value {
                    references.insert(blob_id.clone());
                }
            }
        }
        Ok(references.into_iter().collect())
    }

    pub(crate) fn conflict_snapshot(
        &self,
        offset: usize,
        limit: usize,
    ) -> MergeResult<(usize, Vec<MergeConflictSnapshot>)> {
        if offset > MAX_CONFLICTS || limit == 0 || limit > MAX_CONFLICT_PAGE {
            return Err(MergeError::new(
                MergeErrorCode::InvalidInput,
                "同步冲突分页范围无效",
            ));
        }
        let open = self.open_conflicts();
        let total = open.len();
        let snapshots = open
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|conflict| {
                Ok(MergeConflictSnapshot {
                    conflict_id: conflict.conflict_id,
                    entity_kind: conflict.entity_kind,
                    entity_id: conflict.entity_id,
                    field: conflict.field,
                    reason: conflict.reason,
                    alternatives: [
                        conflict_alternative_snapshot(0, &conflict.alternatives[0])?,
                        conflict_alternative_snapshot(1, &conflict.alternatives[1])?,
                    ],
                })
            })
            .collect::<MergeResult<Vec<_>>>()?;
        Ok((total, snapshots))
    }

    pub(crate) fn history(&self) -> Vec<HistoryEvent> {
        let mut events = self.histories.values().cloned().collect::<Vec<_>>();
        events.sort_by(|left, right| {
            left.stamp
                .cmp(&right.stamp)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        events
    }

    pub(crate) fn entity_fields(
        &self,
        kind: &EntityKind,
        entity_id: &str,
    ) -> Option<BTreeMap<String, FieldValue>> {
        let record = self.entities.get(&entity_key(kind, entity_id))?;
        if record.tombstone.as_ref().is_some_and(|tombstone| {
            record
                .fields
                .values()
                .all(|register| register.stamp <= *tombstone)
        }) {
            return None;
        }
        Some(
            record
                .fields
                .iter()
                .map(|(field, register)| (field.clone(), register.value.clone()))
                .collect(),
        )
    }

    fn entity_projection(
        &self,
        projected_kind: EntityKind,
    ) -> MergeResult<Vec<MergedEntityProjection>> {
        let mut projection = Vec::new();
        for key in self.entities.keys() {
            let (kind, entity_id) = parse_entity_key(key)?;
            if kind != projected_kind {
                continue;
            }
            projection.push(MergedEntityProjection {
                entity_id: entity_id.to_string(),
                fields: self.entity_fields(&kind, entity_id),
            });
        }
        Ok(projection)
    }

    pub(crate) fn host_projection(&self) -> MergeResult<Vec<MergedEntityProjection>> {
        self.entity_projection(EntityKind::Host)
    }

    pub(crate) fn script_projection(&self) -> MergeResult<Vec<MergedEntityProjection>> {
        self.entity_projection(EntityKind::Script)
    }

    pub(crate) fn setting_projection(&self) -> MergeResult<Vec<MergedEntityProjection>> {
        self.entity_projection(EntityKind::Setting)
    }

    pub(crate) fn background_projection(&self) -> MergeResult<Vec<MergedEntityProjection>> {
        self.entity_projection(EntityKind::Background)
    }

    pub(crate) fn history_entity_projection(&self) -> MergeResult<Vec<MergedEntityProjection>> {
        self.entity_projection(EntityKind::History)
    }

    fn apply_patch(&mut self, payload: &PatchPayload, stamp: MergeStamp) -> MergeResult<()> {
        let key = entity_key(&payload.entity_kind, &payload.entity_id);
        if !self.entities.contains_key(&key) && self.entities.len() >= MAX_ENTITIES {
            return Err(MergeError::new(
                MergeErrorCode::LimitExceeded,
                "同步实体超过 10000 项",
            ));
        }
        let record = self.entities.entry(key).or_default();
        let tombstone = record.tombstone.clone();
        let mut pending_conflicts = Vec::new();
        for (field, value) in &payload.fields {
            let existing = record.fields.get(field).cloned();
            let resurrected_without_observing = tombstone.as_ref().is_some_and(|deleted| {
                payload.observed_tombstone.as_ref() != Some(deleted)
                    && record.tombstone_observed_fields.get(field) != Some(&stamp)
            });
            if let Some(deleted) = tombstone.as_ref().filter(|_| resurrected_without_observing) {
                pending_conflicts.push(build_conflict(
                    &payload.entity_kind,
                    &payload.entity_id,
                    field,
                    ConflictReason::DeletedEntityEdited,
                    ConflictAlternative {
                        value: None,
                        stamp: deleted.clone(),
                    },
                    ConflictAlternative {
                        value: Some(value.clone()),
                        stamp: stamp.clone(),
                    },
                )?);
            } else if let Some(existing) = &existing {
                let observed = payload.observed_fields.get(field).and_then(Option::as_ref);
                let reason = conflict_reason(
                    &payload.entity_kind,
                    field,
                    &existing.value,
                    value,
                    observed == Some(&existing.stamp),
                );
                if let Some(reason) = reason {
                    pending_conflicts.push(build_conflict(
                        &payload.entity_kind,
                        &payload.entity_id,
                        field,
                        reason,
                        ConflictAlternative {
                            value: Some(existing.value.clone()),
                            stamp: existing.stamp.clone(),
                        },
                        ConflictAlternative {
                            value: Some(value.clone()),
                            stamp: stamp.clone(),
                        },
                    )?);
                }
            }
            if existing
                .as_ref()
                .is_none_or(|current| stamp > current.stamp)
            {
                record.fields.insert(
                    field.clone(),
                    FieldRegister {
                        value: value.clone(),
                        stamp: stamp.clone(),
                    },
                );
            }
        }
        for conflict in pending_conflicts {
            self.insert_conflict(conflict)?;
        }
        Ok(())
    }

    fn apply_delete(&mut self, payload: &DeletePayload, stamp: MergeStamp) -> MergeResult<()> {
        let key = entity_key(&payload.entity_kind, &payload.entity_id);
        if !self.entities.contains_key(&key) && self.entities.len() >= MAX_ENTITIES {
            return Err(MergeError::new(
                MergeErrorCode::LimitExceeded,
                "同步实体超过 10000 项",
            ));
        }
        let record = self.entities.entry(key).or_default();
        let existing = record.tombstone.clone();
        let conflict = existing
            .as_ref()
            .and_then(|existing| {
                (payload.observed_tombstone.as_ref() != Some(existing) && existing != &stamp).then(
                    || {
                        build_conflict(
                            &payload.entity_kind,
                            &payload.entity_id,
                            "$tombstone",
                            ConflictReason::ConcurrentDelete,
                            ConflictAlternative {
                                value: None,
                                stamp: existing.clone(),
                            },
                            ConflictAlternative {
                                value: None,
                                stamp: stamp.clone(),
                            },
                        )
                    },
                )
            })
            .transpose()?;
        let mut pending_conflicts = Vec::new();
        for (field, register) in &record.fields {
            if payload.observed_fields.get(field) != Some(&register.stamp) {
                pending_conflicts.push(build_conflict(
                    &payload.entity_kind,
                    &payload.entity_id,
                    field,
                    ConflictReason::DeletedEntityEdited,
                    ConflictAlternative {
                        value: Some(register.value.clone()),
                        stamp: register.stamp.clone(),
                    },
                    ConflictAlternative {
                        value: None,
                        stamp: stamp.clone(),
                    },
                )?);
            }
        }
        if existing.as_ref().is_none_or(|current| stamp > *current) {
            record.tombstone = Some(stamp);
            record.tombstone_observed_fields = payload.observed_fields.clone();
        }
        if let Some(conflict) = conflict {
            pending_conflicts.push(conflict);
        }
        for conflict in pending_conflicts {
            self.insert_conflict(conflict)?;
        }
        Ok(())
    }

    fn apply_history(&mut self, event: &HistoryEvent) -> MergeResult<()> {
        if let Some(existing) = self.histories.get(&event.event_id) {
            if existing == event {
                return Ok(());
            }
            return Err(MergeError::new(
                MergeErrorCode::Replay,
                "相同 history event ID 的内容不同",
            ));
        }
        if self.histories.len() >= MAX_HISTORY_EVENTS {
            return Err(MergeError::new(
                MergeErrorCode::LimitExceeded,
                "同步历史超过 50000 项",
            ));
        }
        self.histories.insert(event.event_id.clone(), event.clone());
        Ok(())
    }

    fn apply_resolution(&mut self, payload: &ResolvePayload, stamp: MergeStamp) -> MergeResult<()> {
        let conflict = self
            .conflicts
            .get_mut(&payload.conflict_id)
            .ok_or_else(|| {
                MergeError::new(
                    MergeErrorCode::ConflictMissing,
                    "要解决的同步冲突不存在或尚未到达",
                )
            })?;
        if conflict
            .resolution_stamp
            .as_ref()
            .is_some_and(|current| current >= &stamp)
        {
            return Ok(());
        }
        if conflict.entity_kind != payload.entity_kind
            || conflict.entity_id != payload.entity_id
            || conflict.field != payload.field
        {
            return Err(MergeError::new(
                MergeErrorCode::Replay,
                "冲突解决 operation 与冲突身份不匹配",
            ));
        }
        if conflict
            .alternatives
            .iter()
            .any(|alternative| stamp <= alternative.stamp)
        {
            return Err(MergeError::new(
                MergeErrorCode::StaleResolution,
                "冲突解决时间戳不晚于冲突双方",
            ));
        }
        if payload.keep_deleted
            && !matches!(
                conflict.reason,
                ConflictReason::DeletedEntityEdited | ConflictReason::ConcurrentDelete
            )
        {
            return Err(MergeError::new(
                MergeErrorCode::InvalidInput,
                "只有删除相关冲突可以选择保持删除",
            ));
        }
        let key = entity_key(&payload.entity_kind, &payload.entity_id);
        let record = self.entities.entry(key).or_default();
        if payload.keep_deleted {
            record.tombstone = Some(stamp.clone());
            record.tombstone_observed_fields = record
                .fields
                .iter()
                .map(|(field, register)| (field.clone(), register.stamp.clone()))
                .collect();
        } else {
            record.fields.insert(
                payload.field.clone(),
                FieldRegister {
                    value: payload.value.clone().expect("validated resolution value"),
                    stamp: stamp.clone(),
                },
            );
        }
        conflict.resolution_stamp = Some(stamp);
        Ok(())
    }

    fn insert_conflict(&mut self, conflict: MergeConflict) -> MergeResult<()> {
        if let Some(existing) = self.conflicts.get(&conflict.conflict_id) {
            if existing == &conflict {
                return Ok(());
            }
            return Err(MergeError::new(
                MergeErrorCode::Replay,
                "相同 conflict ID 的内容不同",
            ));
        }
        if self.conflicts.len() >= MAX_CONFLICTS {
            return Err(MergeError::new(
                MergeErrorCode::LimitExceeded,
                "同步冲突中心超过 1000 项",
            ));
        }
        self.conflicts
            .insert(conflict.conflict_id.clone(), conflict);
        Ok(())
    }
}

fn bounded_conflict_preview(value: &str) -> (String, bool) {
    if value.len() <= MAX_CONFLICT_PREVIEW_BYTES {
        return (value.to_string(), false);
    }
    let mut end = MAX_CONFLICT_PREVIEW_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_string(), true)
}

fn conflict_alternative_snapshot(
    index: u8,
    alternative: &ConflictAlternative,
) -> MergeResult<ConflictAlternativeSnapshot> {
    let Some(value) = &alternative.value else {
        return Ok(ConflictAlternativeSnapshot {
            index,
            value_type: "deleted".to_string(),
            preview: None,
            byte_length: 0,
            content_hash: None,
            truncated: false,
        });
    };
    let encoded = serde_json::to_vec(value)
        .map_err(|_| MergeError::new(MergeErrorCode::CorruptState, "无法编码同步冲突候选"))?;
    let (value_type, display) = match value {
        FieldValue::Text(value) => ("text", Some(value.clone())),
        FieldValue::Integer(value) => ("integer", Some(value.to_string())),
        FieldValue::Flag(value) => ("flag", Some(value.to_string())),
        FieldValue::TextList(value) => (
            "text-list",
            Some(serde_json::to_string(value).map_err(|_| {
                MergeError::new(MergeErrorCode::CorruptState, "无法编码同步冲突列表候选")
            })?),
        ),
        FieldValue::BlobRef(value) => ("blob-ref", Some(value.clone())),
        FieldValue::Clear => ("clear", None),
    };
    let (preview, truncated) = display
        .as_deref()
        .map(bounded_conflict_preview)
        .map(|(preview, truncated)| (Some(preview), truncated))
        .unwrap_or((None, false));
    Ok(ConflictAlternativeSnapshot {
        index,
        value_type: value_type.to_string(),
        preview,
        byte_length: encoded.len() as u64,
        content_hash: Some(sha256_hex(&encoded)),
        truncated,
    })
}

pub(crate) fn build_local_conflict_resolution_operation(
    state: &MergeState,
    operation_id: &str,
    device_id: &str,
    sequence: u64,
    physical_ms: i64,
    logical: u16,
    conflict_id: &str,
    alternative_index: u8,
) -> MergeResult<MergeOperation> {
    validate_uuid(operation_id, "operation")?;
    validate_uuid(device_id, "device")?;
    validate_hash(conflict_id, "conflict")?;
    let conflict = state.conflicts.get(conflict_id).ok_or_else(|| {
        MergeError::new(MergeErrorCode::ConflictMissing, "要解决的同步冲突不存在")
    })?;
    if conflict.resolution_stamp.is_some() {
        return Err(MergeError::new(
            MergeErrorCode::StaleResolution,
            "同步冲突已经解决",
        ));
    }
    let alternative = conflict
        .alternatives
        .get(usize::from(alternative_index))
        .ok_or_else(|| MergeError::new(MergeErrorCode::InvalidInput, "同步冲突候选索引无效"))?;
    let operation = MergeOperation {
        format_version: FORMAT_VERSION,
        operation_id: operation_id.to_string(),
        device_id: device_id.to_string(),
        sequence,
        hlc: HybridLogicalClock {
            physical_ms,
            logical,
        },
        payload: MergePayload::Resolve(ResolvePayload {
            conflict_id: conflict.conflict_id.clone(),
            entity_kind: conflict.entity_kind.clone(),
            entity_id: conflict.entity_id.clone(),
            field: conflict.field.clone(),
            value: alternative.value.clone(),
            keep_deleted: alternative.value.is_none(),
        }),
    };
    validate_operation(&operation)?;
    Ok(operation)
}

fn validate_operation(operation: &MergeOperation) -> MergeResult<()> {
    if operation.format_version != FORMAT_VERSION
        || operation.sequence == 0
        || operation.hlc.physical_ms < 0
    {
        return Err(MergeError::new(
            MergeErrorCode::InvalidInput,
            "同步 merge operation 版本、序号或 HLC 无效",
        ));
    }
    validate_uuid(&operation.operation_id, "operation")?;
    validate_uuid(&operation.device_id, "device")?;
    match &operation.payload {
        MergePayload::Patch(payload) => validate_patch(payload, operation),
        MergePayload::Delete(payload) => {
            validate_entity_id(&payload.entity_id)?;
            if payload.observed_fields.len() > MAX_FIELDS_PER_PATCH {
                return Err(MergeError::new(
                    MergeErrorCode::LimitExceeded,
                    "删除观察字段超过 64 项",
                ));
            }
            for (field, stamp) in &payload.observed_fields {
                if field.is_empty()
                    || field.len() > 64
                    || contains_unsafe_text(field)
                    || is_secret_name(field)
                    || !field_allowed(&payload.entity_kind, field)
                {
                    return Err(MergeError::new(
                        MergeErrorCode::InvalidInput,
                        "删除观察字段名无效",
                    ));
                }
                validate_stamp(stamp)?;
            }
            validate_optional_stamp(payload.observed_tombstone.as_ref())?;
            Ok(())
        }
        MergePayload::HistoryAppend(event) => validate_history(event, operation),
        MergePayload::Resolve(payload) => {
            validate_hash(&payload.conflict_id, "conflict")?;
            validate_entity_id(&payload.entity_id)?;
            if payload.keep_deleted {
                if payload.value.is_some()
                    || payload.field.is_empty()
                    || payload.field.len() > 64
                    || contains_unsafe_text(&payload.field)
                {
                    return Err(MergeError::new(
                        MergeErrorCode::InvalidInput,
                        "保持删除的冲突解决不能同时携带字段值",
                    ));
                }
                Ok(())
            } else {
                validate_field(
                    &payload.entity_kind,
                    &payload.field,
                    payload.value.as_ref().ok_or_else(|| {
                        MergeError::new(
                            MergeErrorCode::InvalidInput,
                            "恢复实体或解决字段冲突必须提供值",
                        )
                    })?,
                )
            }
        }
    }
}

fn validate_patch(payload: &PatchPayload, operation: &MergeOperation) -> MergeResult<()> {
    validate_entity_id(&payload.entity_id)?;
    if payload.fields.is_empty()
        || payload.fields.len() > MAX_FIELDS_PER_PATCH
        || payload.observed_fields.len() > MAX_FIELDS_PER_PATCH
    {
        return Err(MergeError::new(
            MergeErrorCode::LimitExceeded,
            "同步 patch 字段必须为 1 至 64 项",
        ));
    }
    if payload.entity_kind == EntityKind::Background
        && !(payload.fields.len() == 2
            && matches!(
                payload.fields.get("kind"),
                Some(FieldValue::Text(value)) if value == "managed-blob"
            )
            && matches!(
                payload.fields.get("blobId"),
                Some(FieldValue::BlobRef(value)) if validate_hash(value, "background blob").is_ok()
            ))
    {
        return Err(MergeError::new(
            MergeErrorCode::InvalidInput,
            "同步背景 patch 必须包含完整 managed blob 引用",
        ));
    }
    for (field, value) in &payload.fields {
        validate_field(&payload.entity_kind, field, value)?;
    }
    for (field, stamp) in &payload.observed_fields {
        if !payload.fields.contains_key(field) {
            return Err(MergeError::new(
                MergeErrorCode::InvalidInput,
                "同步 patch 的 observed field 不在变更字段中",
            ));
        }
        validate_optional_stamp(stamp.as_ref())?;
    }
    validate_optional_stamp(payload.observed_tombstone.as_ref())?;
    if operation.device_id.is_empty() {
        return Err(MergeError::new(
            MergeErrorCode::InvalidInput,
            "同步 patch 缺少设备身份",
        ));
    }
    Ok(())
}

fn validate_history(event: &HistoryEvent, operation: &MergeOperation) -> MergeResult<()> {
    validate_history_core(event)?;
    if event.stamp != operation.stamp() {
        return Err(MergeError::new(
            MergeErrorCode::InvalidInput,
            "history event stamp 必须等于 operation stamp",
        ));
    }
    Ok(())
}

fn validate_history_core(event: &HistoryEvent) -> MergeResult<()> {
    validate_uuid(&event.event_id, "history event")?;
    validate_stamp(&event.stamp)?;
    if !event.public_value
        || event.value.is_empty()
        || event.value.len() > 4096
        || contains_unsafe_text(&event.value)
        || contains_obvious_secret(&event.value)
    {
        return Err(MergeError::new(
            MergeErrorCode::InvalidInput,
            "同步历史只接受 1 至 4096 字节的非敏感公开值",
        ));
    }
    match event.scope {
        HistoryScope::Global if event.host_id.is_some() => {
            return Err(MergeError::new(
                MergeErrorCode::InvalidInput,
                "全局历史不能绑定主机",
            ));
        }
        HistoryScope::Host => validate_uuid(
            event.host_id.as_deref().ok_or_else(|| {
                MergeError::new(MergeErrorCode::InvalidInput, "主机历史缺少 host ID")
            })?,
            "host",
        )?,
        _ => {}
    }
    if matches!(event.kind, HistoryKind::Argument) {
        let parameter = event
            .parameter_name
            .as_deref()
            .ok_or_else(|| MergeError::new(MergeErrorCode::InvalidInput, "参数历史缺少参数名称"))?;
        if parameter.is_empty()
            || parameter.len() > 128
            || contains_unsafe_text(parameter)
            || is_secret_name(parameter)
        {
            return Err(MergeError::new(
                MergeErrorCode::InvalidInput,
                "敏感或无效参数不能进入同步历史",
            ));
        }
    } else if event.parameter_name.is_some() {
        return Err(MergeError::new(
            MergeErrorCode::InvalidInput,
            "非参数历史不能携带参数名称",
        ));
    }
    Ok(())
}

pub(crate) fn entity_fields_are_syncable(
    kind: &EntityKind,
    fields: &BTreeMap<String, FieldValue>,
) -> bool {
    let fields_valid = !fields.is_empty()
        && fields.len() <= MAX_FIELDS_PER_PATCH
        && fields
            .iter()
            .all(|(field, value)| validate_field(kind, field, value).is_ok());
    if !fields_valid || kind != &EntityKind::History {
        return fields_valid;
    }
    match fields.get("kind") {
        Some(FieldValue::Text(kind)) if kind == "command" => {
            fields.len() == 5
                && fields.keys().all(|field| {
                    matches!(
                        field.as_str(),
                        "kind" | "value" | "hostId" | "remotePath" | "createdAt"
                    )
                })
        }
        Some(FieldValue::Text(kind)) if kind == "path" => {
            fields.len() == 4
                && fields.keys().all(|field| {
                    matches!(field.as_str(), "kind" | "value" | "hostId" | "createdAt")
                })
                && matches!(fields.get("value"), Some(FieldValue::Text(value))
                    if value == "~" || value.starts_with('/') || value.starts_with("~/"))
        }
        Some(FieldValue::Text(kind)) if kind == "argument" => {
            fields.len() == 5
                && fields.keys().all(|field| {
                    matches!(
                        field.as_str(),
                        "kind" | "value" | "commandId" | "parameterName" | "createdAt"
                    )
                })
        }
        Some(FieldValue::Text(kind)) if kind == "connection" => {
            fields.len() == 4
                && fields.keys().all(|field| {
                    matches!(
                        field.as_str(),
                        "kind" | "hostId" | "remotePath" | "createdAt"
                    )
                })
        }
        _ => false,
    }
}

fn validate_field(kind: &EntityKind, field: &str, value: &FieldValue) -> MergeResult<()> {
    if field.is_empty() || field.len() > 64 || contains_unsafe_text(field) || is_secret_name(field)
    {
        return Err(MergeError::new(
            MergeErrorCode::InvalidInput,
            "同步字段名无效或属于敏感字段",
        ));
    }
    let allowed = field_allowed(kind, field);
    if !allowed {
        return Err(MergeError::new(
            MergeErrorCode::InvalidInput,
            "同步实体包含未列入协议的字段",
        ));
    }
    match (kind, field, value) {
        (_, _, FieldValue::Clear) => Ok(()),
        (EntityKind::Host, "port", FieldValue::Integer(value)) if (1..=65_535).contains(value) => {
            Ok(())
        }
        (EntityKind::Host, "tags", FieldValue::TextList(values))
            if validate_text_list(values, 32, 64) =>
        {
            Ok(())
        }
        (EntityKind::Host, "jumpRoute", FieldValue::TextList(values))
            if values.len() <= 8
                && values
                    .iter()
                    .all(|value| validate_uuid(value, "jump host").is_ok()) =>
        {
            Ok(())
        }
        (EntityKind::Host, "environment", FieldValue::Text(value))
            if matches!(value.as_str(), "development" | "staging" | "production") =>
        {
            Ok(())
        }
        (EntityKind::Host, "address", FieldValue::Text(value))
            if value.len() <= 255
                && !value.starts_with('-')
                && !value.chars().any(char::is_whitespace)
                && !contains_unsafe_text(value) =>
        {
            Ok(())
        }
        (EntityKind::Host, "username", FieldValue::Text(value)) if valid_text(value, 128) => Ok(()),
        (EntityKind::Host, "name" | "group", FieldValue::Text(value)) if valid_text(value, 256) => {
            Ok(())
        }
        (EntityKind::Script, "body", FieldValue::Text(value))
            if !value.is_empty()
                && value.len() <= MAX_TEXT_BYTES
                && !contains_unsafe_multiline(value)
                && !contains_obvious_secret(value) =>
        {
            Ok(())
        }
        (EntityKind::Script, "risk", FieldValue::Text(value))
            if matches!(value.as_str(), "safe" | "caution" | "danger") =>
        {
            Ok(())
        }
        (EntityKind::Script, "parameters", FieldValue::TextList(values))
            if validate_text_list(values, 64, 128)
                && values.iter().all(|value| !is_secret_name(value)) =>
        {
            Ok(())
        }
        (EntityKind::Script, "name", FieldValue::Text(value)) if valid_text(value, 256) => Ok(()),
        (EntityKind::Script, "source", FieldValue::Text(value))
            if valid_text(value, 2048) && !value.contains('@') =>
        {
            Ok(())
        }
        (EntityKind::Setting, "fontSize", FieldValue::Integer(value))
            if (8..=48).contains(value) =>
        {
            Ok(())
        }
        (EntityKind::Setting, "lineHeight", FieldValue::Integer(value))
            if (100..=200).contains(value) =>
        {
            Ok(())
        }
        (EntityKind::Setting, "monitorInterval", FieldValue::Integer(value))
            if (5..=300).contains(value) =>
        {
            Ok(())
        }
        (EntityKind::Setting, "wallpaperOpacity", FieldValue::Integer(value))
            if (5..=65).contains(value) =>
        {
            Ok(())
        }
        (
            EntityKind::Setting,
            "autoUploadEditedFiles" | "packageTransfersEnabled",
            FieldValue::Flag(_),
        ) => Ok(()),
        (EntityKind::Setting, "onboardingCompleted", FieldValue::Flag(_)) => Ok(()),
        (
            EntityKind::Setting,
            "terminalTheme" | "fontFamily" | "locale",
            FieldValue::Text(value),
        ) if valid_text(value, 256) => Ok(()),
        (EntityKind::Background, "kind", FieldValue::Text(value)) if value == "managed-blob" => {
            Ok(())
        }
        (EntityKind::Background, "blobId", FieldValue::BlobRef(value))
            if validate_hash(value, "background blob").is_ok() =>
        {
            Ok(())
        }
        (EntityKind::History, "kind", FieldValue::Text(value))
            if matches!(
                value.as_str(),
                "command" | "path" | "argument" | "connection"
            ) =>
        {
            Ok(())
        }
        (EntityKind::History, "value", FieldValue::Text(value))
            if !value.is_empty()
                && value.len() <= 4096
                && !contains_unsafe_multiline(value)
                && !contains_obvious_secret(value) =>
        {
            Ok(())
        }
        (EntityKind::History, "hostId", FieldValue::Text(value))
            if validate_uuid(value, "history host").is_ok() =>
        {
            Ok(())
        }
        (EntityKind::History, "remotePath", FieldValue::Text(value))
            if value.len() <= 4096
                && (value == "~" || value.starts_with('/') || value.starts_with("~/"))
                && !contains_unsafe_text(value)
                && !contains_obvious_secret(value) =>
        {
            Ok(())
        }
        (EntityKind::History, "createdAt", FieldValue::Text(value))
            if valid_iso_timestamp(value) =>
        {
            Ok(())
        }
        (EntityKind::History, "commandId", FieldValue::Text(value)) if valid_text(value, 128) => {
            Ok(())
        }
        (EntityKind::History, "parameterName", FieldValue::Text(value))
            if valid_text(value, 128) && !is_secret_name(value) =>
        {
            Ok(())
        }
        _ => Err(MergeError::new(
            MergeErrorCode::InvalidInput,
            "同步字段值类型或范围无效",
        )),
    }
}

fn conflict_reason(
    kind: &EntityKind,
    field: &str,
    existing: &FieldValue,
    incoming: &FieldValue,
    observed_current: bool,
) -> Option<ConflictReason> {
    if existing == incoming {
        return None;
    }
    if matches!(kind, EntityKind::Script)
        && field == "risk"
        && risk_rank(incoming) < risk_rank(existing)
    {
        return Some(ConflictReason::RiskLowered);
    }
    if observed_current {
        return None;
    }
    match (kind, field) {
        (EntityKind::Host, "address" | "port" | "username" | "jumpRoute") => {
            Some(ConflictReason::ConnectionIdentity)
        }
        (EntityKind::Script, "body" | "source") => Some(ConflictReason::ScriptContent),
        _ => Some(ConflictReason::ConcurrentEdit),
    }
}

fn field_allowed(kind: &EntityKind, field: &str) -> bool {
    match kind {
        EntityKind::Host => matches!(
            field,
            "name"
                | "address"
                | "port"
                | "username"
                | "group"
                | "tags"
                | "jumpRoute"
                | "environment"
        ),
        EntityKind::Script => {
            matches!(field, "name" | "body" | "source" | "risk" | "parameters")
        }
        EntityKind::Setting => matches!(
            field,
            "terminalTheme"
                | "fontFamily"
                | "fontSize"
                | "lineHeight"
                | "monitorInterval"
                | "wallpaperOpacity"
                | "locale"
                | "autoUploadEditedFiles"
                | "packageTransfersEnabled"
                | "onboardingCompleted"
        ),
        EntityKind::Background => matches!(field, "kind" | "blobId"),
        EntityKind::History => {
            matches!(
                field,
                "kind"
                    | "value"
                    | "hostId"
                    | "remotePath"
                    | "commandId"
                    | "parameterName"
                    | "createdAt"
            )
        }
    }
}

fn risk_rank(value: &FieldValue) -> u8 {
    match value {
        FieldValue::Text(value) if value == "danger" => 3,
        FieldValue::Text(value) if value == "caution" => 2,
        FieldValue::Text(value) if value == "safe" => 1,
        _ => 0,
    }
}

fn build_conflict(
    kind: &EntityKind,
    entity_id: &str,
    field: &str,
    reason: ConflictReason,
    first: ConflictAlternative,
    second: ConflictAlternative,
) -> MergeResult<MergeConflict> {
    let mut alternatives = [first, second];
    alternatives.sort_by(|left, right| left.stamp.cmp(&right.stamp));
    let identity =
        serde_json::to_vec(&(kind, entity_id, field, &alternatives[0], &alternatives[1])).map_err(
            |_| MergeError::new(MergeErrorCode::InvalidInput, "无法生成同步 conflict ID"),
        )?;
    Ok(MergeConflict {
        conflict_id: sha256_hex(&identity),
        entity_kind: kind.clone(),
        entity_id: entity_id.to_string(),
        field: field.to_string(),
        reason,
        alternatives,
        resolution_stamp: None,
    })
}

fn validate_state(state: &MergeState) -> MergeResult<()> {
    if state.format_version != FORMAT_VERSION
        || state.entities.len() > MAX_ENTITIES
        || state.histories.len() > MAX_HISTORY_EVENTS
        || state.conflicts.len() > MAX_CONFLICTS
        || state.applied_operations.len() > MAX_APPLIED_OPERATIONS
    {
        return Err(MergeError::new(
            MergeErrorCode::LimitExceeded,
            "同步 merge 状态版本或数量超过限制",
        ));
    }
    for (key, record) in &state.entities {
        if key.len() > 256 || record.fields.len() > MAX_FIELDS_PER_PATCH {
            return Err(MergeError::new(
                MergeErrorCode::CorruptState,
                "同步 merge 实体记录无效",
            ));
        }
        let (kind, entity_id) = parse_entity_key(key)?;
        validate_entity_id(entity_id)?;
        for (field, register) in &record.fields {
            validate_field(&kind, field, &register.value)?;
            validate_stamp(&register.stamp)?;
        }
        validate_optional_stamp(record.tombstone.as_ref())?;
        for (field, stamp) in &record.tombstone_observed_fields {
            if !field_allowed(&kind, field) {
                return Err(MergeError::new(
                    MergeErrorCode::CorruptState,
                    "tombstone 观察字段不在实体协议中",
                ));
            }
            validate_stamp(stamp)?;
        }
    }
    for (event_id, event) in &state.histories {
        if event_id != &event.event_id {
            return Err(MergeError::new(
                MergeErrorCode::CorruptState,
                "同步 history map key 不匹配",
            ));
        }
        validate_uuid(event_id, "history event")?;
        validate_history_core(event)?;
    }
    for (conflict_id, conflict) in &state.conflicts {
        if conflict_id != &conflict.conflict_id {
            return Err(MergeError::new(
                MergeErrorCode::CorruptState,
                "同步 conflict map key 不匹配",
            ));
        }
        validate_hash(conflict_id, "conflict")?;
        validate_entity_id(&conflict.entity_id)?;
        for alternative in &conflict.alternatives {
            validate_stamp(&alternative.stamp)?;
            if let Some(value) = &alternative.value {
                validate_field(&conflict.entity_kind, &conflict.field, value)?;
            }
        }
        validate_optional_stamp(conflict.resolution_stamp.as_ref())?;
        let rebuilt = build_conflict(
            &conflict.entity_kind,
            &conflict.entity_id,
            &conflict.field,
            conflict.reason.clone(),
            conflict.alternatives[0].clone(),
            conflict.alternatives[1].clone(),
        )?;
        if rebuilt.conflict_id != conflict.conflict_id {
            return Err(MergeError::new(
                MergeErrorCode::CorruptState,
                "同步 conflict ID 与内容不匹配",
            ));
        }
    }
    for (operation_id, hash) in &state.applied_operations {
        validate_uuid(operation_id, "operation")?;
        validate_hash(hash, "operation hash")?;
    }
    Ok(())
}

fn validate_stamp(stamp: &MergeStamp) -> MergeResult<()> {
    if stamp.hlc.physical_ms < 0 {
        return Err(MergeError::new(
            MergeErrorCode::InvalidInput,
            "同步 merge stamp HLC 无效",
        ));
    }
    validate_uuid(&stamp.device_id, "stamp device")?;
    validate_uuid(&stamp.operation_id, "stamp operation")
}

fn validate_optional_stamp(stamp: Option<&MergeStamp>) -> MergeResult<()> {
    if let Some(stamp) = stamp {
        validate_stamp(stamp)?;
    }
    Ok(())
}

fn validate_entity_id(value: &str) -> MergeResult<()> {
    validate_uuid(value, "entity")
}

fn validate_uuid(value: &str, field: &str) -> MergeResult<()> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| MergeError::new(MergeErrorCode::InvalidInput, format!("{field} ID 无效")))?;
    if parsed.to_string() != value {
        return Err(MergeError::new(
            MergeErrorCode::InvalidInput,
            format!("{field} ID 必须是 canonical lowercase UUID"),
        ));
    }
    Ok(())
}

fn validate_hash(value: &str, field: &str) -> MergeResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MergeError::new(
            MergeErrorCode::InvalidInput,
            format!("{field} hash 必须为 lowercase SHA-256"),
        ));
    }
    Ok(())
}

fn entity_key(kind: &EntityKind, entity_id: &str) -> String {
    format!("{}:{entity_id}", kind.label())
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !contains_unsafe_text(value)
        && !contains_obvious_secret(value)
}

fn validate_text_list(values: &[String], maximum: usize, item_maximum: usize) -> bool {
    values.len() <= maximum && values.iter().all(|value| valid_text(value, item_maximum))
}

fn contains_unsafe_text(value: &str) -> bool {
    value.contains('\0') || value.chars().any(|character| character.is_control())
}

fn contains_unsafe_multiline(value: &str) -> bool {
    value.contains('\0')
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn parse_entity_key(value: &str) -> MergeResult<(EntityKind, &str)> {
    let (kind, entity_id) = value
        .split_once(':')
        .ok_or_else(|| MergeError::new(MergeErrorCode::CorruptState, "同步 entity map key 无效"))?;
    let kind = match kind {
        "host" => EntityKind::Host,
        "script" => EntityKind::Script,
        "setting" => EntityKind::Setting,
        "background" => EntityKind::Background,
        "history" => EntityKind::History,
        _ => {
            return Err(MergeError::new(
                MergeErrorCode::CorruptState,
                "同步 entity map kind 无效",
            ));
        }
    };
    Ok((kind, entity_id))
}

fn is_secret_name(value: &str) -> bool {
    let compact = value.to_ascii_lowercase().replace(['-', '_', ' '], "");
    [
        "password",
        "passphrase",
        "token",
        "secret",
        "privatekey",
        "credential",
        "authorization",
        "apikey",
    ]
    .iter()
    .any(|needle| compact.contains(needle))
}

fn contains_obvious_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("begin openssh private key")
        || lower.contains("begin rsa private key")
        || lower.contains("begin private key")
        || lower.contains("authorization: bearer")
        || lower.contains("password=")
        || lower.contains("passwd=")
        || lower.contains("token=")
        || lower.contains("--password")
        || lower.contains("--passphrase")
        || lower.contains("--token")
        || lower.contains("--api-key")
        || lower.contains("api_key=")
        || lower.contains("apikey=")
        || lower.contains("credentialref")
}

fn valid_iso_timestamp(value: &str) -> bool {
    if value.len() != 24
        || !value.is_ascii()
        || value.as_bytes()[4] != b'-'
        || value.as_bytes()[7] != b'-'
        || value.as_bytes()[10] != b'T'
        || value.as_bytes()[13] != b':'
        || value.as_bytes()[16] != b':'
        || value.as_bytes()[19] != b'.'
        || value.as_bytes()[23] != b'Z'
        || !value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19 | 23) || byte.is_ascii_digit()
        })
    {
        return false;
    }
    let parse = |start, end| value[start..end].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        parse(0, 4),
        parse(5, 7),
        parse(8, 10),
        parse(11, 13),
        parse(14, 16),
        parse(17, 19),
    ) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year >= 1970 && (1..=maximum_day).contains(&day) && hour <= 23 && minute <= 59 && second <= 59
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
    use super::*;

    const DEVICE_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const DEVICE_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const HOST_ID: &str = "11111111-1111-4111-8111-111111111111";

    fn operation_id(number: u128) -> String {
        Uuid::from_u128(number).to_string()
    }

    fn patch(
        operation_number: u128,
        device_id: &str,
        physical_ms: i64,
        kind: EntityKind,
        entity_id: &str,
        field: &str,
        value: FieldValue,
    ) -> MergeOperation {
        MergeOperation {
            format_version: FORMAT_VERSION,
            operation_id: operation_id(operation_number),
            device_id: device_id.to_string(),
            sequence: operation_number as u64,
            hlc: HybridLogicalClock {
                physical_ms,
                logical: 0,
            },
            payload: MergePayload::Patch(PatchPayload {
                entity_kind: kind,
                entity_id: entity_id.to_string(),
                fields: BTreeMap::from([(field.to_string(), value)]),
                observed_fields: BTreeMap::from([(field.to_string(), None)]),
                observed_tombstone: None,
            }),
        }
    }

    fn background_patch(operation_number: u128, physical_ms: i64) -> MergeOperation {
        let fields = BTreeMap::from([
            ("blobId".to_string(), FieldValue::BlobRef("ab".repeat(32))),
            ("kind".to_string(), FieldValue::Text("managed-blob".into())),
        ]);
        MergeOperation {
            format_version: FORMAT_VERSION,
            operation_id: operation_id(operation_number),
            device_id: DEVICE_A.to_string(),
            sequence: operation_number as u64,
            hlc: HybridLogicalClock {
                physical_ms,
                logical: 0,
            },
            payload: MergePayload::Patch(PatchPayload {
                entity_kind: EntityKind::Background,
                entity_id: HOST_ID.to_string(),
                observed_fields: fields.keys().map(|field| (field.clone(), None)).collect(),
                fields,
                observed_tombstone: None,
            }),
        }
    }

    fn current_field(state: &MergeState, kind: EntityKind, id: &str, field: &str) -> FieldValue {
        state.entities[&entity_key(&kind, id)].fields[field]
            .value
            .clone()
    }

    #[test]
    fn concurrent_host_edits_converge_and_create_the_same_conflict() {
        let first = patch(
            1,
            DEVICE_A,
            100,
            EntityKind::Host,
            HOST_ID,
            "address",
            FieldValue::Text("host-a.example".into()),
        );
        let second = patch(
            2,
            DEVICE_B,
            100,
            EntityKind::Host,
            HOST_ID,
            "address",
            FieldValue::Text("host-b.example".into()),
        );
        let mut left = MergeState::default();
        left.apply(&first).unwrap();
        left.apply(&second).unwrap();
        let mut right = MergeState::default();
        right.apply(&second).unwrap();
        right.apply(&first).unwrap();
        assert_eq!(left.entities, right.entities);
        assert_eq!(left.conflicts, right.conflicts);
        assert_eq!(left.open_conflicts().len(), 1);
        assert_eq!(
            current_field(&left, EntityKind::Host, HOST_ID, "address"),
            FieldValue::Text("host-b.example".into())
        );
    }

    #[test]
    fn conflict_snapshot_is_bounded_and_resolution_uses_a_frozen_alternative() {
        let first_value = "a".repeat(3_000);
        let second_value = "b".repeat(3_000);
        let first = patch(
            101,
            DEVICE_A,
            100,
            EntityKind::Script,
            HOST_ID,
            "body",
            FieldValue::Text(first_value.clone()),
        );
        let second = patch(
            102,
            DEVICE_B,
            100,
            EntityKind::Script,
            HOST_ID,
            "body",
            FieldValue::Text(second_value),
        );
        let mut state = MergeState::default();
        state.apply(&first).unwrap();
        state.apply(&second).unwrap();

        let (total, conflicts) = state.conflict_snapshot(0, 1).unwrap();
        assert_eq!(total, 1);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].alternatives[0].truncated);
        assert!(conflicts[0].alternatives[0].preview.as_ref().unwrap().len() <= 2_048);
        assert_eq!(
            conflicts[0].alternatives[0]
                .content_hash
                .as_ref()
                .unwrap()
                .len(),
            64
        );
        let encoded_snapshot = serde_json::to_string(&conflicts).unwrap();
        assert!(!encoded_snapshot.contains(DEVICE_A));
        assert!(!encoded_snapshot.contains(DEVICE_B));
        assert!(state.conflict_snapshot(0, 0).is_err());
        assert!(state.conflict_snapshot(0, 51).is_err());

        let conflict_id = conflicts[0].conflict_id.clone();
        assert!(
            build_local_conflict_resolution_operation(
                &state,
                &operation_id(103),
                DEVICE_A,
                103,
                101,
                0,
                &conflict_id,
                2,
            )
            .is_err()
        );
        let operation = build_local_conflict_resolution_operation(
            &state,
            &operation_id(104),
            DEVICE_A,
            104,
            101,
            0,
            &conflict_id,
            0,
        )
        .unwrap();
        state.apply(&operation).unwrap();
        assert!(state.open_conflicts().is_empty());
        assert_eq!(
            current_field(&state, EntityKind::Script, HOST_ID, "body"),
            FieldValue::Text(first_value)
        );
    }

    #[test]
    fn observed_field_updates_do_not_create_false_conflicts() {
        let first = patch(
            3,
            DEVICE_A,
            100,
            EntityKind::Setting,
            HOST_ID,
            "fontSize",
            FieldValue::Integer(14),
        );
        let mut state = MergeState::default();
        state.apply(&first).unwrap();
        let first_stamp = first.stamp();
        let mut second = patch(
            4,
            DEVICE_A,
            101,
            EntityKind::Setting,
            HOST_ID,
            "fontSize",
            FieldValue::Integer(15),
        );
        let MergePayload::Patch(payload) = &mut second.payload else {
            unreachable!();
        };
        payload
            .observed_fields
            .insert("fontSize".into(), Some(first_stamp));
        state.apply(&second).unwrap();
        assert!(state.open_conflicts().is_empty());
    }

    #[test]
    fn delete_causality_is_order_independent_and_unobserved_edits_conflict() {
        let edit = patch(
            60,
            DEVICE_A,
            100,
            EntityKind::Host,
            HOST_ID,
            "name",
            FieldValue::Text("observed-before-delete".into()),
        );
        let observed_delete = MergeOperation {
            format_version: FORMAT_VERSION,
            operation_id: operation_id(61),
            device_id: DEVICE_B.into(),
            sequence: 61,
            hlc: HybridLogicalClock {
                physical_ms: 101,
                logical: 0,
            },
            payload: MergePayload::Delete(DeletePayload {
                entity_kind: EntityKind::Host,
                entity_id: HOST_ID.into(),
                observed_fields: BTreeMap::from([("name".into(), edit.stamp())]),
                observed_tombstone: None,
            }),
        };
        let mut left = MergeState::default();
        left.apply(&edit).unwrap();
        left.apply(&observed_delete).unwrap();
        let mut right = MergeState::default();
        right.apply(&observed_delete).unwrap();
        right.apply(&edit).unwrap();
        assert_eq!(left, right);
        assert!(left.open_conflicts().is_empty());
        assert!(left.entity_fields(&EntityKind::Host, HOST_ID).is_none());

        let concurrent_delete = MergeOperation {
            format_version: FORMAT_VERSION,
            operation_id: operation_id(62),
            device_id: DEVICE_B.into(),
            sequence: 62,
            hlc: HybridLogicalClock {
                physical_ms: 101,
                logical: 0,
            },
            payload: MergePayload::Delete(DeletePayload {
                entity_kind: EntityKind::Host,
                entity_id: HOST_ID.into(),
                observed_fields: BTreeMap::new(),
                observed_tombstone: None,
            }),
        };
        let mut forward = MergeState::default();
        forward.apply(&edit).unwrap();
        forward.apply(&concurrent_delete).unwrap();
        let mut reverse = MergeState::default();
        reverse.apply(&concurrent_delete).unwrap();
        reverse.apply(&edit).unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(forward.open_conflicts().len(), 1);
        assert_eq!(
            forward.open_conflicts()[0].reason,
            ConflictReason::DeletedEntityEdited
        );
    }

    #[test]
    fn settings_and_managed_background_fields_use_the_same_bounded_merge_model() {
        let operations = [
            patch(
                70,
                DEVICE_A,
                100,
                EntityKind::Setting,
                HOST_ID,
                "fontSize",
                FieldValue::Integer(16),
            ),
            background_patch(71, 101),
            patch(
                74,
                DEVICE_A,
                104,
                EntityKind::Setting,
                HOST_ID,
                "packageTransfersEnabled",
                FieldValue::Flag(false),
            ),
            patch(
                75,
                DEVICE_A,
                105,
                EntityKind::Setting,
                HOST_ID,
                "onboardingCompleted",
                FieldValue::Flag(true),
            ),
            patch(
                76,
                DEVICE_A,
                106,
                EntityKind::Setting,
                HOST_ID,
                "monitorInterval",
                FieldValue::Integer(30),
            ),
            patch(
                77,
                DEVICE_A,
                107,
                EntityKind::Setting,
                HOST_ID,
                "wallpaperOpacity",
                FieldValue::Integer(35),
            ),
        ];
        let mut state = MergeState::default();
        for operation in &operations {
            state.apply(operation).unwrap();
        }
        assert_eq!(
            state.entity_fields(&EntityKind::Setting, HOST_ID).unwrap()["fontSize"],
            FieldValue::Integer(16)
        );
        assert_eq!(
            state.entity_fields(&EntityKind::Setting, HOST_ID).unwrap()["onboardingCompleted"],
            FieldValue::Flag(true)
        );
        assert_eq!(
            state.setting_projection().unwrap(),
            vec![MergedEntityProjection {
                entity_id: HOST_ID.to_string(),
                fields: Some(BTreeMap::from([
                    ("fontSize".to_string(), FieldValue::Integer(16)),
                    ("monitorInterval".to_string(), FieldValue::Integer(30)),
                    (
                        "packageTransfersEnabled".to_string(),
                        FieldValue::Flag(false),
                    ),
                    ("onboardingCompleted".to_string(), FieldValue::Flag(true)),
                    ("wallpaperOpacity".to_string(), FieldValue::Integer(35)),
                ])),
            }]
        );
        assert!(
            patch(
                78,
                DEVICE_A,
                108,
                EntityKind::Setting,
                HOST_ID,
                "packageTransfersEnabled",
                FieldValue::Text("false".into()),
            )
            .encode()
            .is_err()
        );
        assert!(
            patch(
                79,
                DEVICE_A,
                109,
                EntityKind::Setting,
                HOST_ID,
                "monitorInterval",
                FieldValue::Integer(4),
            )
            .encode()
            .is_err()
        );
        assert!(
            patch(
                80,
                DEVICE_A,
                110,
                EntityKind::Setting,
                HOST_ID,
                "wallpaperOpacity",
                FieldValue::Integer(66),
            )
            .encode()
            .is_err()
        );
        let background = state
            .entity_fields(&EntityKind::Background, HOST_ID)
            .unwrap();
        assert_eq!(background["kind"], FieldValue::Text("managed-blob".into()));
        assert!(
            patch(
                81,
                DEVICE_A,
                111,
                EntityKind::Background,
                HOST_ID,
                "opacity",
                FieldValue::Integer(35),
            )
            .encode()
            .is_err()
        );
        assert!(
            patch(
                82,
                DEVICE_A,
                112,
                EntityKind::Background,
                HOST_ID,
                "kind",
                FieldValue::Text("none".into()),
            )
            .encode()
            .is_err()
        );
        assert_eq!(MergeState::decode(&state.encode().unwrap()).unwrap(), state);
    }

    #[test]
    fn background_blob_references_include_open_conflict_alternatives() {
        let mut state = MergeState::default();
        state.apply(&background_patch(90, 100)).unwrap();
        let mut concurrent = background_patch(91, 101);
        concurrent.device_id = DEVICE_B.to_string();
        let MergePayload::Patch(payload) = &mut concurrent.payload else {
            unreachable!();
        };
        payload
            .fields
            .insert("blobId".to_string(), FieldValue::BlobRef("cd".repeat(32)));
        state.apply(&concurrent).unwrap();

        assert_eq!(
            state.background_blob_references().unwrap(),
            vec!["ab".repeat(32), "cd".repeat(32)]
        );
    }

    #[test]
    fn history_is_a_deterministic_union_and_sensitive_values_are_rejected() {
        let make_event = |number, device: &str, value: &str| {
            let operation_id_value = operation_id(number);
            let stamp = MergeStamp {
                hlc: HybridLogicalClock {
                    physical_ms: 100,
                    logical: 0,
                },
                device_id: device.to_string(),
                operation_id: operation_id_value.clone(),
            };
            MergeOperation {
                format_version: FORMAT_VERSION,
                operation_id: operation_id_value,
                device_id: device.to_string(),
                sequence: number as u64,
                hlc: stamp.hlc.clone(),
                payload: MergePayload::HistoryAppend(HistoryEvent {
                    event_id: operation_id(number + 100),
                    kind: HistoryKind::Command,
                    value: value.to_string(),
                    scope: HistoryScope::Global,
                    host_id: None,
                    parameter_name: None,
                    public_value: true,
                    stamp,
                }),
            }
        };
        let first = make_event(10, DEVICE_A, "uname -a");
        let second = make_event(11, DEVICE_B, "df -h");
        let mut state = MergeState::default();
        state.apply(&second).unwrap();
        state.apply(&first).unwrap();
        assert_eq!(state.history().len(), 2);
        assert_eq!(state.apply(&first), Ok(ApplyOutcome::AlreadyApplied));

        let secret = make_event(12, DEVICE_A, "curl -H 'Authorization: Bearer hidden'");
        assert_eq!(
            secret.encode().unwrap_err().code,
            MergeErrorCode::InvalidInput
        );
    }

    #[test]
    fn command_history_entities_validate_complete_public_fields_and_preserve_tombstones() {
        let history_id = "22222222-2222-4222-8222-222222222222";
        let fields = BTreeMap::from([
            (
                "createdAt".to_string(),
                FieldValue::Text("2026-08-18T22:30:00.000Z".into()),
            ),
            ("hostId".to_string(), FieldValue::Text(HOST_ID.into())),
            ("kind".to_string(), FieldValue::Text("command".into())),
            (
                "remotePath".to_string(),
                FieldValue::Text("/srv/app".into()),
            ),
            (
                "value".to_string(),
                FieldValue::Text("systemctl status nginx".into()),
            ),
        ]);
        let mut state = MergeState::default();
        let append = build_local_entity_operation(
            &state,
            &operation_id(81),
            DEVICE_A,
            81,
            100,
            0,
            EntityKind::History,
            history_id,
            LocalEntityMutation::Patch(fields.clone()),
        )
        .unwrap();
        state.apply(&append).unwrap();
        assert_eq!(
            state.history_entity_projection().unwrap(),
            vec![MergedEntityProjection {
                entity_id: history_id.into(),
                fields: Some(fields),
            }]
        );
        let delete = build_local_entity_operation(
            &state,
            &operation_id(82),
            DEVICE_A,
            82,
            101,
            0,
            EntityKind::History,
            history_id,
            LocalEntityMutation::Delete,
        )
        .unwrap();
        state.apply(&delete).unwrap();
        assert_eq!(
            state.history_entity_projection().unwrap(),
            vec![MergedEntityProjection {
                entity_id: history_id.into(),
                fields: None,
            }]
        );
        assert!(!entity_fields_are_syncable(
            &EntityKind::History,
            &BTreeMap::from([(
                "value".to_string(),
                FieldValue::Text("deploy --token=secret".into()),
            )]),
        ));
        assert!(!entity_fields_are_syncable(
            &EntityKind::History,
            &BTreeMap::from([(
                "createdAt".to_string(),
                FieldValue::Text("2026-08-18".into()),
            )]),
        ));
    }

    #[test]
    fn path_history_entities_require_complete_public_remote_paths() {
        let fields = BTreeMap::from([
            (
                "createdAt".to_string(),
                FieldValue::Text("2026-08-18T23:30:00.000Z".into()),
            ),
            ("hostId".to_string(), FieldValue::Text(HOST_ID.into())),
            ("kind".to_string(), FieldValue::Text("path".into())),
            (
                "value".to_string(),
                FieldValue::Text("/srv/releases/current".into()),
            ),
        ]);
        assert!(entity_fields_are_syncable(&EntityKind::History, &fields));
        let mut relative = fields.clone();
        relative.insert("value".to_string(), FieldValue::Text("srv/releases".into()));
        assert!(!entity_fields_are_syncable(&EntityKind::History, &relative,));
        let mut secret = fields.clone();
        secret.insert(
            "value".to_string(),
            FieldValue::Text("/srv/token=secret".into()),
        );
        assert!(!entity_fields_are_syncable(&EntityKind::History, &secret,));
        let mut incomplete = fields;
        incomplete.remove("createdAt");
        assert!(!entity_fields_are_syncable(
            &EntityKind::History,
            &incomplete,
        ));
    }

    #[test]
    fn argument_history_entities_require_named_public_values() {
        let fields = BTreeMap::from([
            (
                "commandId".to_string(),
                FieldValue::Text("command-service-logs".into()),
            ),
            (
                "createdAt".to_string(),
                FieldValue::Text("2026-08-19T00:10:00.000Z".into()),
            ),
            ("kind".to_string(), FieldValue::Text("argument".into())),
            (
                "parameterName".to_string(),
                FieldValue::Text("SERVICE".into()),
            ),
            ("value".to_string(), FieldValue::Text("nginx".into())),
        ]);
        assert!(entity_fields_are_syncable(&EntityKind::History, &fields));
        let mut sensitive_name = fields.clone();
        sensitive_name.insert(
            "parameterName".to_string(),
            FieldValue::Text("API_TOKEN".into()),
        );
        assert!(!entity_fields_are_syncable(
            &EntityKind::History,
            &sensitive_name,
        ));
        let mut sensitive_value = fields.clone();
        sensitive_value.insert("value".to_string(), FieldValue::Text("token=secret".into()));
        assert!(!entity_fields_are_syncable(
            &EntityKind::History,
            &sensitive_value,
        ));
        let mut incomplete = fields;
        incomplete.remove("commandId");
        assert!(!entity_fields_are_syncable(
            &EntityKind::History,
            &incomplete,
        ));
    }

    #[test]
    fn connection_history_requires_host_path_and_rust_timestamp_shape() {
        let fields = BTreeMap::from([
            (
                "createdAt".to_string(),
                FieldValue::Text("2026-08-19T01:20:00.000Z".into()),
            ),
            ("hostId".to_string(), FieldValue::Text(HOST_ID.into())),
            ("kind".to_string(), FieldValue::Text("connection".into())),
            (
                "remotePath".to_string(),
                FieldValue::Text("/srv/app".into()),
            ),
        ]);
        assert!(entity_fields_are_syncable(&EntityKind::History, &fields));
        let mut with_value = fields.clone();
        with_value.insert("value".to_string(), FieldValue::Text("connected".into()));
        assert!(!entity_fields_are_syncable(
            &EntityKind::History,
            &with_value,
        ));
        let mut relative_path = fields.clone();
        relative_path.insert("remotePath".to_string(), FieldValue::Text("srv/app".into()));
        assert!(!entity_fields_are_syncable(
            &EntityKind::History,
            &relative_path,
        ));
        let mut missing_host = fields;
        missing_host.remove("hostId");
        assert!(!entity_fields_are_syncable(
            &EntityKind::History,
            &missing_host,
        ));
    }

    #[test]
    fn script_risk_lowering_and_deleted_entity_edits_enter_conflict_center() {
        let dangerous = patch(
            20,
            DEVICE_A,
            100,
            EntityKind::Script,
            HOST_ID,
            "risk",
            FieldValue::Text("danger".into()),
        );
        let mut safer = patch(
            21,
            DEVICE_A,
            101,
            EntityKind::Script,
            HOST_ID,
            "risk",
            FieldValue::Text("safe".into()),
        );
        let MergePayload::Patch(payload) = &mut safer.payload else {
            unreachable!();
        };
        payload
            .observed_fields
            .insert("risk".into(), Some(dangerous.stamp()));
        let delete = MergeOperation {
            format_version: FORMAT_VERSION,
            operation_id: operation_id(22),
            device_id: DEVICE_B.into(),
            sequence: 22,
            hlc: HybridLogicalClock {
                physical_ms: 102,
                logical: 0,
            },
            payload: MergePayload::Delete(DeletePayload {
                entity_kind: EntityKind::Script,
                entity_id: HOST_ID.into(),
                observed_fields: BTreeMap::new(),
                observed_tombstone: None,
            }),
        };
        let edited_after_delete = patch(
            23,
            DEVICE_A,
            103,
            EntityKind::Script,
            HOST_ID,
            "name",
            FieldValue::Text("resurrected".into()),
        );
        let mut state = MergeState::default();
        state.apply(&dangerous).unwrap();
        state.apply(&safer).unwrap();
        state.apply(&delete).unwrap();
        state.apply(&edited_after_delete).unwrap();
        let reasons = state
            .open_conflicts()
            .into_iter()
            .map(|conflict| conflict.reason)
            .collect::<Vec<_>>();
        assert!(reasons.contains(&ConflictReason::RiskLowered));
        assert!(reasons.contains(&ConflictReason::DeletedEntityEdited));
    }

    #[test]
    fn conflict_resolution_must_be_newer_and_round_trips_with_state() {
        let first = patch(
            30,
            DEVICE_A,
            100,
            EntityKind::Host,
            HOST_ID,
            "port",
            FieldValue::Integer(22),
        );
        let second = patch(
            31,
            DEVICE_B,
            100,
            EntityKind::Host,
            HOST_ID,
            "port",
            FieldValue::Integer(2222),
        );
        let mut state = MergeState::default();
        state.apply(&first).unwrap();
        state.apply(&second).unwrap();
        let conflict = state.open_conflicts().pop().unwrap();
        let first_resolution = MergeOperation {
            format_version: FORMAT_VERSION,
            operation_id: operation_id(32),
            device_id: DEVICE_A.into(),
            sequence: 32,
            hlc: HybridLogicalClock {
                physical_ms: 101,
                logical: 0,
            },
            payload: MergePayload::Resolve(ResolvePayload {
                conflict_id: conflict.conflict_id.clone(),
                entity_kind: EntityKind::Host,
                entity_id: HOST_ID.into(),
                field: "port".into(),
                value: Some(FieldValue::Integer(2200)),
                keep_deleted: false,
            }),
        };
        let second_resolution = MergeOperation {
            format_version: FORMAT_VERSION,
            operation_id: operation_id(33),
            device_id: DEVICE_B.into(),
            sequence: 33,
            hlc: HybridLogicalClock {
                physical_ms: 102,
                logical: 0,
            },
            payload: MergePayload::Resolve(ResolvePayload {
                conflict_id: conflict.conflict_id,
                entity_kind: EntityKind::Host,
                entity_id: HOST_ID.into(),
                field: "port".into(),
                value: Some(FieldValue::Integer(2022)),
                keep_deleted: false,
            }),
        };
        let mut reverse = state.clone();
        state.apply(&first_resolution).unwrap();
        state.apply(&second_resolution).unwrap();
        reverse.apply(&second_resolution).unwrap();
        reverse.apply(&first_resolution).unwrap();
        assert_eq!(state, reverse);
        assert!(state.open_conflicts().is_empty());
        assert_eq!(
            current_field(&state, EntityKind::Host, HOST_ID, "port"),
            FieldValue::Integer(2022)
        );
        let encoded = state.encode().unwrap();
        assert_eq!(MergeState::decode(&encoded).unwrap(), state);
    }

    #[test]
    fn deleted_entity_conflicts_can_keep_deletion_or_explicitly_restore() {
        let initial = patch(
            50,
            DEVICE_A,
            100,
            EntityKind::Script,
            HOST_ID,
            "name",
            FieldValue::Text("before-delete".into()),
        );
        let delete = MergeOperation {
            format_version: FORMAT_VERSION,
            operation_id: operation_id(51),
            device_id: DEVICE_B.into(),
            sequence: 51,
            hlc: HybridLogicalClock {
                physical_ms: 101,
                logical: 0,
            },
            payload: MergePayload::Delete(DeletePayload {
                entity_kind: EntityKind::Script,
                entity_id: HOST_ID.into(),
                observed_fields: BTreeMap::new(),
                observed_tombstone: None,
            }),
        };
        let edit = patch(
            52,
            DEVICE_A,
            102,
            EntityKind::Script,
            HOST_ID,
            "name",
            FieldValue::Text("offline-edit".into()),
        );
        let mut state = MergeState::default();
        state.apply(&initial).unwrap();
        state.apply(&delete).unwrap();
        state.apply(&edit).unwrap();
        let conflict = state
            .open_conflicts()
            .into_iter()
            .find(|conflict| conflict.reason == ConflictReason::DeletedEntityEdited)
            .unwrap();
        let keep_deleted = MergeOperation {
            format_version: FORMAT_VERSION,
            operation_id: operation_id(53),
            device_id: DEVICE_B.into(),
            sequence: 53,
            hlc: HybridLogicalClock {
                physical_ms: 103,
                logical: 0,
            },
            payload: MergePayload::Resolve(ResolvePayload {
                conflict_id: conflict.conflict_id,
                entity_kind: EntityKind::Script,
                entity_id: HOST_ID.into(),
                field: "name".into(),
                value: None,
                keep_deleted: true,
            }),
        };
        state.apply(&keep_deleted).unwrap();
        assert!(state.entity_fields(&EntityKind::Script, HOST_ID).is_none());

        let mut restore = patch(
            54,
            DEVICE_A,
            104,
            EntityKind::Script,
            HOST_ID,
            "name",
            FieldValue::Text("explicit-restore".into()),
        );
        let MergePayload::Patch(payload) = &mut restore.payload else {
            unreachable!();
        };
        payload.observed_tombstone = Some(keep_deleted.stamp());
        state.apply(&restore).unwrap();
        assert_eq!(
            state.entity_fields(&EntityKind::Script, HOST_ID).unwrap()["name"],
            FieldValue::Text("explicit-restore".into())
        );
    }

    #[test]
    fn fields_paths_credentials_and_unknown_schema_are_rejected() {
        for field in ["password", "credentialRef", "privateKey", "hostKeyPin"] {
            let invalid = patch(
                40,
                DEVICE_A,
                100,
                EntityKind::Host,
                HOST_ID,
                field,
                FieldValue::Text("hidden".into()),
            );
            assert!(invalid.encode().is_err());
        }
        let private_key = patch(
            41,
            DEVICE_A,
            100,
            EntityKind::Script,
            HOST_ID,
            "body",
            FieldValue::Text("-----BEGIN OPENSSH PRIVATE KEY-----".into()),
        );
        assert!(private_key.encode().is_err());
        let multiline = patch(
            44,
            DEVICE_A,
            100,
            EntityKind::Script,
            HOST_ID,
            "body",
            FieldValue::Text("#!/bin/sh\nprintf 'ok\\n'\n".into()),
        );
        assert!(multiline.encode().is_ok());
        let local_path = patch(
            42,
            DEVICE_A,
            100,
            EntityKind::Background,
            HOST_ID,
            "blobId",
            FieldValue::Text("/home/user/private.png".into()),
        );
        assert!(local_path.encode().is_err());

        let valid = patch(
            43,
            DEVICE_A,
            100,
            EntityKind::Host,
            HOST_ID,
            "name",
            FieldValue::Text("server".into()),
        );
        let mut json: serde_json::Value = serde_json::from_slice(&valid.encode().unwrap()).unwrap();
        json["formatVersion"] = serde_json::json!(2);
        assert!(MergeOperation::decode(&serde_json::to_vec(&json).unwrap()).is_err());
        json["formatVersion"] = serde_json::json!(1);
        json["unknown"] = serde_json::json!(true);
        assert!(MergeOperation::decode(&serde_json::to_vec(&json).unwrap()).is_err());

        let mut corrupt_state = MergeState::default();
        corrupt_state.apply(&valid).unwrap();
        corrupt_state
            .entities
            .get_mut(&entity_key(&EntityKind::Host, HOST_ID))
            .unwrap()
            .fields
            .insert(
                "credentialRef".into(),
                FieldRegister {
                    value: FieldValue::Text("ssh-reference".into()),
                    stamp: valid.stamp(),
                },
            );
        assert_eq!(
            corrupt_state.encode().unwrap_err().code,
            MergeErrorCode::InvalidInput
        );
    }

    #[test]
    fn merge_state_persists_with_revision_checks_inside_the_callers_transaction() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE sync_merge_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL,
                    revision INTEGER NOT NULL CHECK (revision >= 0),
                    state_blob BLOB NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );",
            )
            .unwrap();
        let operation = patch(
            80,
            DEVICE_A,
            100,
            EntityKind::Setting,
            HOST_ID,
            "fontSize",
            FieldValue::Integer(17),
        );
        let encoded = operation.encode().unwrap();
        let transaction = connection.transaction().unwrap();
        let applied = apply_persisted_operation(&transaction, &encoded, 0, 1).unwrap();
        assert_eq!(applied.revision, 1);
        transaction.commit().unwrap();

        let transaction = connection.transaction().unwrap();
        assert_eq!(
            apply_persisted_operation(&transaction, &encoded, 0, 2)
                .unwrap_err()
                .code,
            MergeErrorCode::RevisionConflict
        );
        let idempotent = apply_persisted_operation(&transaction, &encoded, 1, 2).unwrap();
        assert_eq!(idempotent.revision, 1);
        assert_eq!(idempotent.outcome, ApplyOutcome::AlreadyApplied);
        let (revision, state) = load_persisted_state(&transaction).unwrap();
        assert_eq!(revision, 1);
        assert_eq!(
            state.entity_fields(&EntityKind::Setting, HOST_ID).unwrap()["fontSize"],
            FieldValue::Integer(17)
        );
    }

    #[test]
    fn local_hlc_advances_past_observed_remote_clock() {
        let remote = patch(
            90,
            DEVICE_B,
            50_000,
            EntityKind::Host,
            HOST_ID,
            "name",
            FieldValue::Text("remote".into()),
        );
        let mut state = MergeState::default();
        state.apply(&remote).unwrap();
        assert_eq!(advance_local_hlc(&state, 1_000, 0).unwrap(), (50_000, 1));
        assert_eq!(advance_local_hlc(&state, 60_000, 0).unwrap(), (60_000, 0));
    }
}

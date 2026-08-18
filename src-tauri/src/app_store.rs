use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::sync_merge::{
    EntityKind, FieldValue, LocalEntityMutation, MergedEntityProjection, entity_fields_are_syncable,
};

const STORE_SCHEMA_VERSION: i64 = 7;
const TERMINAL_APPEARANCE_ENTITY_ID: &str = "00000000-0000-4000-8000-000000000001";
const APPLICATION_PREFERENCES_ENTITY_ID: &str = "00000000-0000-4000-8000-000000000002";
const ONBOARDING_ENTITY_ID: &str = "00000000-0000-4000-8000-000000000003";
const MONITOR_PREFERENCES_ENTITY_ID: &str = "00000000-0000-4000-8000-000000000004";
const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_DATABASE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EVENTS: i64 = 10_000;
const EVENT_RETENTION_MS: i64 = 90 * 24 * 60 * 60 * 1000;
const MAX_CORRUPT_BACKUPS: usize = 2;
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_NODES: usize = 250_000;
const MAX_GENERAL_STRING_BYTES: usize = 64 * 1024;
const MAX_WALLPAPER_VALUE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PENDING_SYNC_CHANGES: i64 = 10_000;
const MAX_SYNCED_HOSTS: usize = 2_000;

const TOP_LEVEL_FIELDS: &[&str] = &[
    "hosts",
    "deletedHosts",
    "scripts",
    "commands",
    "sshKeys",
    "commandHistory",
    "connectionHistory",
    "pathHistory",
    "sync",
    "wallpaper",
    "terminalAppearance",
    "settings",
    "onboardingCompleted",
];

#[derive(Clone)]
pub(crate) struct AppStore {
    inner: Arc<AppStoreInner>,
}

struct AppStoreInner {
    database_path: PathBuf,
    lock: Mutex<()>,
    recovery_note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InitializeAppStoreRequest {
    legacy_state_json: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppStoreSnapshot {
    schema_version: i64,
    revision: u64,
    state_json: Option<String>,
    migrated_legacy: bool,
    recovery_note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SaveAppStateRequest {
    pub(crate) state_json: String,
    pub(crate) expected_revision: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SaveAppStateResult {
    revision: u64,
    retained_events: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingEntitySyncChange {
    pub(crate) operation_id: String,
    pub(crate) entity_kind: EntityKind,
    pub(crate) entity_id: String,
    pub(crate) mutation: LocalEntityMutation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProjectionOutcome {
    Applied,
    Unchanged,
    Deferred,
}

fn epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn database_path(app_data_directory: &Path) -> PathBuf {
    app_data_directory.join("vpshell-state.sqlite3")
}

fn open_connection(path: &Path) -> Result<Connection, String> {
    let connection =
        Connection::open(path).map_err(|error| format!("无法打开本地事件库: {error}"))?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| format!("无法配置本地事件库等待时间: {error}"))?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|error| format!("无法启用本地事件库外键: {error}"))?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|error| format!("无法启用本地事件库 WAL: {error}"))?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|error| format!("无法配置本地事件库同步策略: {error}"))?;
    Ok(connection)
}

fn quick_check(connection: &Connection) -> Result<(), String> {
    let result: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|error| format!("本地事件库完整性检查失败: {error}"))?;
    if result == "ok" {
        Ok(())
    } else {
        Err(format!("本地事件库完整性检查失败: {result}"))
    }
}

fn current_schema(connection: &Connection) -> Result<i64, String> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| format!("无法读取本地事件库 schema: {error}"))
}

fn migrate_schema(connection: &mut Connection) -> Result<(), String> {
    let version = current_schema(connection)?;
    if version > STORE_SCHEMA_VERSION {
        return Err(format!(
            "本地事件库 schema {version} 高于当前支持版本 {STORE_SCHEMA_VERSION}，未修改文件"
        ));
    }
    if version == STORE_SCHEMA_VERSION {
        return Ok(());
    }

    let transaction = connection
        .transaction()
        .map_err(|error| format!("无法开始本地事件库迁移: {error}"))?;
    if version == 0 {
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS app_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL,
                    revision INTEGER NOT NULL CHECK (revision >= 0),
                    state_json TEXT NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS app_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_kind TEXT NOT NULL,
                    domains_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_app_events_created_at
                    ON app_events(created_at_ms);",
            )
            .map_err(|error| format!("无法创建本地事件库 schema: {error}"))?;
    }
    if version < 2 {
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS app_sync_host_ids (
                    local_id TEXT PRIMARY KEY,
                    entity_id TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS app_sync_changes (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT NOT NULL UNIQUE,
                    entity_id TEXT NOT NULL,
                    mutation_kind TEXT NOT NULL CHECK (mutation_kind IN ('patch', 'delete')),
                    fields_json TEXT,
                    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
                    created_at_ms INTEGER NOT NULL,
                    entity_kind TEXT NOT NULL CHECK (entity_kind IN ('host', 'script', 'setting')),
                    CHECK ((mutation_kind = 'patch') = (fields_json IS NOT NULL))
                );
                CREATE INDEX IF NOT EXISTS idx_app_sync_changes_revision
                    ON app_sync_changes(state_revision, seq);
                CREATE TABLE IF NOT EXISTS app_sync_binding (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    vault_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS app_sync_script_ids (
                    local_id TEXT PRIMARY KEY,
                    entity_id TEXT NOT NULL UNIQUE
                );",
            )
            .map_err(|error| format!("无法创建 AppState 同步 changefeed: {error}"))?;
        if version == 1 {
            let existing: Option<(i64, String, i64)> = transaction
                .query_row(
                    "SELECT revision, state_json, updated_at_ms
                     FROM app_state WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|error| format!("无法读取待迁移 AppState: {error}"))?;
            if let Some((revision, state_json, updated_at_ms)) = existing {
                let state: Value = serde_json::from_str(&state_json)
                    .map_err(|error| format!("待迁移 AppState JSON 损坏: {error}"))?;
                queue_host_sync_changes(
                    &transaction,
                    None,
                    &state,
                    revision.max(1) as u64,
                    updated_at_ms.max(0),
                )?;
                queue_script_sync_changes(
                    &transaction,
                    None,
                    &state,
                    revision.max(1) as u64,
                    updated_at_ms.max(0),
                )?;
            }
        }
    }
    if version < 3 {
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS app_sync_projection (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    vault_id TEXT NOT NULL,
                    merge_revision INTEGER NOT NULL CHECK (merge_revision >= 0),
                    projection_hash TEXT NOT NULL
                );",
            )
            .map_err(|error| format!("无法创建 AppState 同步投影状态: {error}"))?;
    }
    if version < 4 {
        if version >= 2 {
            transaction
                .execute(
                    "ALTER TABLE app_sync_changes
                     ADD COLUMN entity_kind TEXT NOT NULL DEFAULT 'host'
                     CHECK (entity_kind IN ('host', 'script'))",
                    [],
                )
                .map_err(|error| format!("无法扩展 AppState 实体同步 changefeed: {error}"))?;
        }
        transaction
            .execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_app_sync_changes_kind_revision
                    ON app_sync_changes(entity_kind, state_revision, seq);
                CREATE TABLE IF NOT EXISTS app_sync_script_ids (
                    local_id TEXT PRIMARY KEY,
                    entity_id TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS app_sync_script_projection (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    vault_id TEXT NOT NULL,
                    merge_revision INTEGER NOT NULL CHECK (merge_revision >= 0),
                    projection_hash TEXT NOT NULL
                );",
            )
            .map_err(|error| format!("无法创建 AppState 脚本同步 schema: {error}"))?;
    }
    if version < 5 {
        transaction
            .execute_batch(
                "DROP INDEX IF EXISTS idx_app_sync_changes_revision;
                 DROP INDEX IF EXISTS idx_app_sync_changes_kind_revision;
                 ALTER TABLE app_sync_changes RENAME TO app_sync_changes_v4;
                 CREATE TABLE app_sync_changes (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT NOT NULL UNIQUE,
                    entity_id TEXT NOT NULL,
                    mutation_kind TEXT NOT NULL CHECK (mutation_kind IN ('patch', 'delete')),
                    fields_json TEXT,
                    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
                    created_at_ms INTEGER NOT NULL,
                    entity_kind TEXT NOT NULL CHECK (entity_kind IN ('host', 'script', 'setting')),
                    CHECK ((mutation_kind = 'patch') = (fields_json IS NOT NULL))
                 );
                 INSERT INTO app_sync_changes(
                    seq, operation_id, entity_id, mutation_kind, fields_json,
                    state_revision, created_at_ms, entity_kind
                 ) SELECT seq, operation_id, entity_id, mutation_kind, fields_json,
                          state_revision, created_at_ms, entity_kind
                   FROM app_sync_changes_v4;
                 DROP TABLE app_sync_changes_v4;
                 CREATE INDEX idx_app_sync_changes_revision
                    ON app_sync_changes(state_revision, seq);
                 CREATE INDEX idx_app_sync_changes_kind_revision
                    ON app_sync_changes(entity_kind, state_revision, seq);
                 CREATE TABLE IF NOT EXISTS app_sync_setting_projection (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    vault_id TEXT NOT NULL,
                    merge_revision INTEGER NOT NULL CHECK (merge_revision >= 0),
                    projection_hash TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS app_sync_setting_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    content_hash TEXT NOT NULL
                 );",
            )
            .map_err(|error| format!("无法创建 AppState 设置同步 schema: {error}"))?;
    }
    if version < 6 {
        transaction
            .execute_batch(&format!(
                "ALTER TABLE app_sync_setting_state RENAME TO app_sync_setting_state_v5;
                 CREATE TABLE app_sync_setting_state (
                    entity_id TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL
                 );
                 INSERT INTO app_sync_setting_state(entity_id, content_hash)
                    SELECT '{TERMINAL_APPEARANCE_ENTITY_ID}', content_hash
                    FROM app_sync_setting_state_v5 WHERE singleton = 1;
                 DROP TABLE app_sync_setting_state_v5;"
            ))
            .map_err(|error| format!("无法升级 AppState 设置同步状态: {error}"))?;
        let existing: Option<(i64, String, i64)> = transaction
            .query_row(
                "SELECT revision, state_json, updated_at_ms
                 FROM app_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| format!("无法读取待迁移 AppState 设置: {error}"))?;
        if let Some((revision, state_json, updated_at_ms)) = existing {
            let state: Value = serde_json::from_str(&state_json)
                .map_err(|error| format!("待迁移 AppState JSON 损坏: {error}"))?;
            queue_setting_sync_changes(
                &transaction,
                None,
                &state,
                revision.max(1) as u64,
                updated_at_ms.max(0),
            )?;
        }
    }
    if version < 7 {
        let existing: Option<(i64, String, i64)> = transaction
            .query_row(
                "SELECT revision, state_json, updated_at_ms
                 FROM app_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| format!("无法读取待迁移 AppState 监控偏好: {error}"))?;
        if let Some((revision, state_json, updated_at_ms)) = existing {
            let state: Value = serde_json::from_str(&state_json)
                .map_err(|error| format!("待迁移 AppState JSON 损坏: {error}"))?;
            queue_fixed_setting_sync_change(
                &transaction,
                true,
                MONITOR_PREFERENCES_ENTITY_ID,
                monitor_preference_sync_fields(&state)?,
                &default_monitor_preference_sync_fields(),
                revision.max(1) as u64,
                updated_at_ms.max(0),
            )?;
        }
    }
    transaction
        .pragma_update(None, "user_version", STORE_SCHEMA_VERSION)
        .map_err(|error| format!("无法写入本地事件库 schema 版本: {error}"))?;
    transaction
        .commit()
        .map_err(|error| format!("无法提交本地事件库迁移: {error}"))
}

fn corrupt_backup_prefix(path: &Path) -> String {
    format!(
        "{}.corrupt-",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("vpshell-state.sqlite3")
    )
}

fn prune_corrupt_backups(path: &Path) -> Result<(), String> {
    let Some(directory) = path.parent() else {
        return Ok(());
    };
    let prefix = corrupt_backup_prefix(path);
    let mut backups = fs::read_dir(directory)
        .map_err(|error| format!("无法读取损坏库备份目录: {error}"))?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
                name.starts_with(&prefix) && !name.ends_with("-wal") && !name.ends_with("-shm")
            })
        })
        .collect::<Vec<_>>();
    backups.sort_by_key(|entry| entry.file_name());
    let remove_count = backups.len().saturating_sub(MAX_CORRUPT_BACKUPS);
    for entry in backups.into_iter().take(remove_count) {
        let backup = entry.path();
        fs::remove_file(&backup).map_err(|error| format!("无法清理过期损坏库备份: {error}"))?;
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", backup.display()));
            if sidecar.exists() {
                fs::remove_file(sidecar)
                    .map_err(|error| format!("无法清理损坏库附属备份: {error}"))?;
            }
        }
    }
    Ok(())
}

fn quarantine_database(path: &Path) -> Result<Option<PathBuf>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let timestamp = epoch_ms();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("vpshell-state.sqlite3");
    let backup = path.with_file_name(format!(
        "{file_name}.corrupt-{timestamp}-{}",
        Uuid::new_v4().simple()
    ));
    fs::rename(path, &backup).map_err(|error| format!("无法隔离损坏本地事件库: {error}"))?;
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
        if sidecar.exists() {
            let backup_sidecar = PathBuf::from(format!("{}{suffix}", backup.display()));
            fs::rename(&sidecar, backup_sidecar)
                .map_err(|error| format!("无法隔离损坏事件库附属文件: {error}"))?;
        }
    }
    prune_corrupt_backups(path)?;
    Ok(Some(backup))
}

fn prepare_database(path: &Path) -> Result<Option<String>, String> {
    if path
        .metadata()
        .is_ok_and(|metadata| metadata.len() > MAX_DATABASE_BYTES)
    {
        quarantine_database(path)?;
        let mut connection = open_connection(path)?;
        migrate_schema(&mut connection)?;
        return Ok(Some("本地事件库超过 64 MiB，已隔离并创建空库".to_string()));
    }

    match open_connection(path).and_then(|mut connection| {
        quick_check(&connection)?;
        migrate_schema(&mut connection)
    }) {
        Ok(()) => Ok(None),
        Err(error) if error.contains("高于当前支持版本") => Err(error),
        Err(_) => {
            quarantine_database(path)?;
            let mut connection = open_connection(path)?;
            migrate_schema(&mut connection)?;
            Ok(Some(
                "本地事件库损坏或截断，已保留最多两个隔离备份并创建空库".to_string(),
            ))
        }
    }
}

fn ensure_object<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("本地状态字段 {field} 必须是对象"))
}

fn ensure_array<'a>(
    value: &'a Value,
    field: &str,
    maximum: usize,
) -> Result<&'a Vec<Value>, String> {
    let values = value
        .as_array()
        .ok_or_else(|| format!("本地状态字段 {field} 必须是数组"))?;
    if values.len() > maximum {
        return Err(format!("本地状态字段 {field} 超过 {maximum} 项"));
    }
    Ok(values)
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<&'a str, String> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("本地状态缺少字符串字段 {field}"))?;
    if value.is_empty()
        || value.len() > maximum
        || value
            .chars()
            .any(|character| character == '\0' || character.is_control())
    {
        return Err(format!("本地状态字符串字段 {field} 无效"));
    }
    Ok(value)
}

fn validate_host_records(root: &serde_json::Map<String, Value>) -> Result<(), String> {
    for field in ["hosts", "deletedHosts"] {
        let values = ensure_array(
            root.get(field)
                .ok_or_else(|| format!("本地状态缺少 {field}"))?,
            field,
            2000,
        )?;
        for value in values {
            let host_value = if field == "deletedHosts" {
                ensure_object(value, field)?
                    .get("host")
                    .ok_or_else(|| "回收站记录缺少 host".to_string())?
            } else {
                value
            };
            let host = ensure_object(host_value, "host")?;
            required_string(host, "id", 128)?;
            required_string(host, "name", 256)?;
            let address = required_string(host, "host", 255)?;
            if address.starts_with('-') || address.chars().any(char::is_whitespace) {
                return Err("本地状态主机地址无效".to_string());
            }
            required_string(host, "username", 128)?;
            let port = host
                .get("port")
                .and_then(Value::as_u64)
                .ok_or_else(|| "本地状态主机端口无效".to_string())?;
            if !(1..=65535).contains(&port) {
                return Err("本地状态主机端口必须为 1–65535".to_string());
            }
        }
    }
    let hosts = ensure_array(
        root.get("hosts")
            .ok_or_else(|| "本地状态缺少 hosts".to_string())?,
        "hosts",
        2000,
    )?;
    let host_ids = hosts
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|host| host.get("id"))
        .filter_map(Value::as_str)
        .collect::<HashSet<_>>();
    if host_ids.len() != hosts.len() {
        return Err("本地状态 hosts 包含重复主机标识".to_string());
    }
    for value in hosts {
        let host = ensure_object(value, "host")?;
        let host_id = required_string(host, "id", 128)?;
        let Some(route) = host.get("jumpRoute") else {
            continue;
        };
        let route = ensure_array(route, "jumpRoute", 3)?;
        let mut route_ids = HashSet::with_capacity(route.len());
        for jump_id in route {
            let jump_id = jump_id
                .as_str()
                .ok_or_else(|| "本地状态 jumpRoute 必须只包含主机标识".to_string())?;
            if jump_id.is_empty()
                || jump_id.len() > 128
                || jump_id == host_id
                || !route_ids.insert(jump_id)
                || !host_ids.contains(jump_id)
            {
                return Err("本地状态 jumpRoute 引用无效、重复或形成循环".to_string());
            }
        }
    }
    Ok(())
}

fn sensitive_key_allowed(key: &str) -> bool {
    matches!(
        key,
        "credentialRef"
            | "passphraseRef"
            | "privateKeyPath"
            | "androidKeyRef"
            | "androidKeyPassphraseRef"
            | "syncSecrets"
    )
}

fn inspect_json(
    value: &Value,
    key: Option<&str>,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), String> {
    if depth > MAX_JSON_DEPTH {
        return Err(format!("本地状态 JSON 嵌套超过 {MAX_JSON_DEPTH} 层"));
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_JSON_NODES {
        return Err(format!("本地状态 JSON 节点超过 {MAX_JSON_NODES} 个"));
    }
    match value {
        Value::Object(object) => {
            for (child_key, child) in object {
                let lower = child_key.to_ascii_lowercase();
                if !sensitive_key_allowed(child_key)
                    && [
                        "password",
                        "passphrase",
                        "token",
                        "secret",
                        "privatekey",
                        "credential",
                    ]
                    .iter()
                    .any(|needle| lower.contains(needle))
                {
                    return Err(format!("本地状态禁止持久化敏感字段 {child_key}"));
                }
                inspect_json(child, Some(child_key), depth + 1, nodes)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                inspect_json(child, key, depth + 1, nodes)?;
            }
        }
        Value::String(value) => {
            let maximum = if key == Some("value") && value.starts_with("data:image/") {
                MAX_WALLPAPER_VALUE_BYTES
            } else {
                MAX_GENERAL_STRING_BYTES
            };
            if value.len() > maximum || value.contains('\0') {
                return Err(format!(
                    "本地状态字符串 {} 超过上限或含 NUL",
                    key.unwrap_or("value")
                ));
            }
            if key == Some("credentialRef") {
                crate::file_transfer::validate_optional_reference(Some(value), "ssh-")?;
            } else if key == Some("passphraseRef") {
                crate::file_transfer::validate_optional_reference(Some(value), "key-")?;
            } else if key == Some("androidKeyRef") {
                crate::file_transfer::validate_optional_reference(Some(value), "key-")?;
            } else if key == Some("androidKeyPassphraseRef") {
                crate::file_transfer::validate_optional_reference(Some(value), "key-")?;
            } else if key == Some("hostKeySha256") {
                let encoded = value
                    .strip_prefix("SHA256:")
                    .ok_or_else(|| "本地主机指纹必须使用 SHA256 格式".to_string())?;
                if encoded.len() != 43
                    || BASE64_STANDARD_NO_PAD
                        .decode(encoded)
                        .map_or(true, |bytes| bytes.len() != 32)
                {
                    return Err("本地主机 SHA256 指纹格式无效".to_string());
                }
            }
            let upper = value.to_ascii_uppercase();
            if upper.contains("BEGIN OPENSSH PRIVATE KEY")
                || upper.contains("BEGIN RSA PRIVATE KEY")
                || upper.contains("BEGIN EC PRIVATE KEY")
                || upper.contains("BEGIN PRIVATE KEY")
            {
                return Err("本地状态不能包含私钥正文".to_string());
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_state_json(state_json: &str) -> Result<Value, String> {
    if state_json.is_empty() || state_json.len() > MAX_STATE_BYTES {
        return Err("本地状态必须为 1 字节至 16 MiB".to_string());
    }
    let value: Value = serde_json::from_str(state_json)
        .map_err(|error| format!("本地状态不是有效 JSON: {error}"))?;
    let root = ensure_object(&value, "root")?;
    let allowed = TOP_LEVEL_FIELDS.iter().copied().collect::<HashSet<_>>();
    for field in root.keys() {
        if !allowed.contains(field.as_str()) {
            return Err(format!("本地状态包含未知顶层字段 {field}"));
        }
    }
    for field in TOP_LEVEL_FIELDS {
        if !root.contains_key(*field) {
            return Err(format!("本地状态缺少顶层字段 {field}"));
        }
    }
    validate_host_records(root)?;
    for (field, maximum) in [
        ("scripts", 2000),
        ("commands", 2000),
        ("sshKeys", 500),
        ("commandHistory", 10_000),
        ("connectionHistory", 10_000),
    ] {
        ensure_array(root.get(field).expect("required field"), field, maximum)?;
    }
    let path_history = ensure_object(
        root.get("pathHistory").expect("required field"),
        "pathHistory",
    )?;
    if path_history.len() > 2000 {
        return Err("本地状态路径历史超过 2000 个主机".to_string());
    }
    for paths in path_history.values() {
        ensure_array(paths, "pathHistory item", 100)?;
    }
    if !root
        .get("onboardingCompleted")
        .is_some_and(Value::is_boolean)
    {
        return Err("本地状态 onboardingCompleted 必须是布尔值".to_string());
    }
    for field in ["sync", "wallpaper", "terminalAppearance", "settings"] {
        ensure_object(root.get(field).expect("required field"), field)?;
    }
    let mut nodes = 0;
    inspect_json(&value, None, 0, &mut nodes)?;
    Ok(value)
}

fn changed_domains(previous: Option<&Value>, next: &Value) -> Vec<String> {
    let Some(next) = next.as_object() else {
        return Vec::new();
    };
    let previous = previous.and_then(Value::as_object);
    TOP_LEVEL_FIELDS
        .iter()
        .filter(|field| previous.and_then(|object| object.get(**field)) != next.get(**field))
        .map(|field| (*field).to_string())
        .collect()
}

fn host_objects(
    value: Option<&Value>,
) -> Result<BTreeMap<String, serde_json::Map<String, Value>>, String> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let root = ensure_object(value, "root")?;
    let hosts = ensure_array(
        root.get("hosts")
            .ok_or_else(|| "本地状态缺少 hosts".to_string())?,
        "hosts",
        2000,
    )?;
    hosts
        .iter()
        .map(|value| {
            let host = ensure_object(value, "host")?.clone();
            let id = required_string(&host, "id", 128)?.to_string();
            Ok((id, host))
        })
        .collect()
}

fn ensure_host_entity_ids(
    transaction: &Transaction<'_>,
    local_ids: impl IntoIterator<Item = String>,
) -> Result<BTreeMap<String, String>, String> {
    let mut result = BTreeMap::new();
    for local_id in local_ids {
        let existing: Option<String> = transaction
            .query_row(
                "SELECT entity_id FROM app_sync_host_ids WHERE local_id = ?1",
                params![local_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("无法读取主机同步身份映射: {error}"))?;
        let entity_id = match existing {
            Some(entity_id) => entity_id,
            None => {
                let entity_id = Uuid::new_v4().to_string();
                transaction
                    .execute(
                        "INSERT INTO app_sync_host_ids(local_id, entity_id) VALUES (?1, ?2)",
                        params![local_id, entity_id],
                    )
                    .map_err(|error| format!("无法写入主机同步身份映射: {error}"))?;
                entity_id
            }
        };
        result.insert(local_id, entity_id);
    }
    Ok(result)
}

fn host_sync_fields(
    host: &serde_json::Map<String, Value>,
    entity_ids: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, FieldValue>, String> {
    let text = |field: &str, maximum: usize| {
        required_string(host, field, maximum).map(|value| FieldValue::Text(value.to_string()))
    };
    let mut fields = BTreeMap::new();
    fields.insert("name".to_string(), text("name", 256)?);
    fields.insert("address".to_string(), text("host", 255)?);
    fields.insert(
        "port".to_string(),
        FieldValue::Integer(
            host.get("port")
                .and_then(Value::as_i64)
                .ok_or_else(|| "本地状态主机端口无效".to_string())?,
        ),
    );
    fields.insert("username".to_string(), text("username", 128)?);
    fields.insert(
        "group".to_string(),
        host.get("group")
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
            })
            .map(|value| FieldValue::Text(value.to_string()))
            .unwrap_or(FieldValue::Clear),
    );
    if let Some(environment) = host
        .get("environment")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "development" | "staging" | "production"))
    {
        fields.insert(
            "environment".to_string(),
            FieldValue::Text(environment.to_string()),
        );
    }
    let tags = host
        .get("tags")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .take(32)
        .filter_map(|value| {
            value
                .as_str()
                .filter(|value| {
                    !value.is_empty() && value.len() <= 64 && !value.chars().any(char::is_control)
                })
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    fields.insert("tags".to_string(), FieldValue::TextList(tags));
    let jump_route = host
        .get("jumpRoute")
        .and_then(Value::as_array)
        .map(|route| {
            route
                .iter()
                .map(|value| {
                    let local_id = value
                        .as_str()
                        .ok_or_else(|| "本地状态 jumpRoute 主机标识无效".to_string())?;
                    entity_ids
                        .get(local_id)
                        .cloned()
                        .ok_or_else(|| "本地状态 jumpRoute 缺少同步身份映射".to_string())
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    fields.insert("jumpRoute".to_string(), FieldValue::TextList(jump_route));
    Ok(fields)
}

fn queue_host_sync_changes(
    transaction: &Transaction<'_>,
    previous: Option<&Value>,
    next: &Value,
    revision: u64,
    now: i64,
) -> Result<(), String> {
    let previous_hosts = host_objects(previous)?;
    let next_hosts = host_objects(Some(next))?;
    let local_ids = previous_hosts
        .keys()
        .chain(next_hosts.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let entity_ids = ensure_host_entity_ids(transaction, local_ids)?;
    let mut changes = Vec::new();
    for (local_id, host) in &next_hosts {
        let next_fields = host_sync_fields(host, &entity_ids)?;
        let unchanged = previous_hosts
            .get(local_id)
            .map(|previous| host_sync_fields(previous, &entity_ids))
            .transpose()?
            .is_some_and(|previous| previous == next_fields);
        if !unchanged {
            changes.push((
                entity_ids[local_id].clone(),
                "patch",
                Some(
                    serde_json::to_string(&next_fields)
                        .map_err(|error| format!("无法编码脱敏主机同步变更: {error}"))?,
                ),
            ));
        }
    }
    for local_id in previous_hosts.keys() {
        if !next_hosts.contains_key(local_id) {
            changes.push((entity_ids[local_id].clone(), "delete", None));
        }
    }
    let pending: i64 = transaction
        .query_row("SELECT COUNT(*) FROM app_sync_changes", [], |row| {
            row.get(0)
        })
        .map_err(|error| format!("无法统计 AppState 同步 changefeed: {error}"))?;
    if pending.saturating_add(changes.len() as i64) > MAX_PENDING_SYNC_CHANGES {
        return Err("AppState 同步 changefeed 已达到 10000 项上限；请先完成同步".to_string());
    }
    let revision = i64::try_from(revision)
        .map_err(|_| "AppState 同步 revision 超过 SQLite INTEGER".to_string())?;
    for (entity_id, kind, fields_json) in changes {
        transaction
            .execute(
                "INSERT INTO app_sync_changes(
                    operation_id, entity_id, mutation_kind, fields_json, state_revision,
                    created_at_ms, entity_kind
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'host')",
                params![
                    Uuid::new_v4().to_string(),
                    entity_id,
                    kind,
                    fields_json,
                    revision,
                    now
                ],
            )
            .map_err(|error| format!("无法写入 AppState 同步 changefeed: {error}"))?;
    }
    Ok(())
}

fn script_objects(
    value: Option<&Value>,
) -> Result<BTreeMap<String, serde_json::Map<String, Value>>, String> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let root = ensure_object(value, "root")?;
    let scripts = ensure_array(
        root.get("scripts")
            .ok_or_else(|| "本地状态缺少 scripts".to_string())?,
        "scripts",
        2000,
    )?;
    Ok(scripts
        .iter()
        .filter_map(Value::as_object)
        .filter(|script| script.get("custom").and_then(Value::as_bool) == Some(true))
        .filter_map(|script| {
            let local_id = script.get("id")?.as_str()?;
            if local_id.is_empty() || local_id.len() > 128 || local_id.chars().any(char::is_control)
            {
                return None;
            }
            Some((local_id.to_string(), script.clone()))
        })
        .collect())
}

fn ensure_script_entity_ids(
    transaction: &Transaction<'_>,
    local_ids: impl IntoIterator<Item = String>,
) -> Result<BTreeMap<String, String>, String> {
    let mut result = BTreeMap::new();
    for local_id in local_ids {
        let existing: Option<String> = transaction
            .query_row(
                "SELECT entity_id FROM app_sync_script_ids WHERE local_id = ?1",
                params![local_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("无法读取脚本同步身份映射: {error}"))?;
        let entity_id = match existing {
            Some(entity_id) => entity_id,
            None => {
                let entity_id = Uuid::new_v4().to_string();
                transaction
                    .execute(
                        "INSERT INTO app_sync_script_ids(local_id, entity_id) VALUES (?1, ?2)",
                        params![local_id, entity_id],
                    )
                    .map_err(|error| format!("无法写入脚本同步身份映射: {error}"))?;
                entity_id
            }
        };
        result.insert(local_id, entity_id);
    }
    Ok(result)
}

fn script_sync_fields(
    script: &serde_json::Map<String, Value>,
) -> Option<BTreeMap<String, FieldValue>> {
    let text = |field: &str| script.get(field).and_then(Value::as_str);
    let risk = match text("risk")? {
        "low" => "safe",
        "medium" => "caution",
        "high" | "destructive" => "danger",
        _ => return None,
    };
    let mut fields = BTreeMap::from([
        (
            "name".to_string(),
            FieldValue::Text(text("title")?.to_string()),
        ),
        (
            "body".to_string(),
            FieldValue::Text(text("command")?.to_string()),
        ),
        ("risk".to_string(), FieldValue::Text(risk.to_string())),
    ]);
    fields.insert(
        "source".to_string(),
        text("sourceUrl")
            .filter(|value| !value.is_empty())
            .map(|value| FieldValue::Text(value.to_string()))
            .unwrap_or(FieldValue::Clear),
    );
    fields.insert(
        "parameters".to_string(),
        script
            .get("parameters")
            .and_then(Value::as_array)
            .and_then(|values| {
                values
                    .iter()
                    .map(Value::as_str)
                    .map(|value| value.map(str::to_string))
                    .collect::<Option<Vec<_>>>()
            })
            .map(FieldValue::TextList)
            .unwrap_or_else(|| FieldValue::TextList(Vec::new())),
    );
    entity_fields_are_syncable(&EntityKind::Script, &fields).then_some(fields)
}

fn queue_script_sync_changes(
    transaction: &Transaction<'_>,
    previous: Option<&Value>,
    next: &Value,
    revision: u64,
    now: i64,
) -> Result<(), String> {
    let previous_scripts = script_objects(previous)?;
    let next_scripts = script_objects(Some(next))?;
    let local_ids = previous_scripts
        .keys()
        .chain(next_scripts.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let entity_ids = ensure_script_entity_ids(transaction, local_ids)?;
    let mut changes = Vec::new();
    for (local_id, script) in &next_scripts {
        let Some(next_fields) = script_sync_fields(script) else {
            continue;
        };
        let unchanged = previous_scripts
            .get(local_id)
            .and_then(script_sync_fields)
            .is_some_and(|previous| previous == next_fields);
        if !unchanged {
            changes.push((
                entity_ids[local_id].clone(),
                "patch",
                Some(
                    serde_json::to_string(&next_fields)
                        .map_err(|error| format!("无法编码脱敏脚本同步变更: {error}"))?,
                ),
            ));
        }
    }
    for (local_id, script) in &previous_scripts {
        let was_syncable = script_sync_fields(script).is_some();
        let is_syncable = next_scripts
            .get(local_id)
            .and_then(script_sync_fields)
            .is_some();
        if was_syncable && !is_syncable {
            changes.push((entity_ids[local_id].clone(), "delete", None));
        }
    }
    let pending: i64 = transaction
        .query_row("SELECT COUNT(*) FROM app_sync_changes", [], |row| {
            row.get(0)
        })
        .map_err(|error| format!("无法统计 AppState 同步 changefeed: {error}"))?;
    if pending.saturating_add(changes.len() as i64) > MAX_PENDING_SYNC_CHANGES {
        return Err("AppState 同步 changefeed 已达到 10000 项上限；请先完成同步".to_string());
    }
    let revision = i64::try_from(revision)
        .map_err(|_| "AppState 同步 revision 超过 SQLite INTEGER".to_string())?;
    for (entity_id, kind, fields_json) in changes {
        transaction
            .execute(
                "INSERT INTO app_sync_changes(
                    operation_id, entity_id, mutation_kind, fields_json, state_revision,
                    created_at_ms, entity_kind
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'script')",
                params![
                    Uuid::new_v4().to_string(),
                    entity_id,
                    kind,
                    fields_json,
                    revision,
                    now
                ],
            )
            .map_err(|error| format!("无法写入 AppState 脚本同步 changefeed: {error}"))?;
    }
    Ok(())
}

fn terminal_appearance_sync_fields(value: &Value) -> Result<BTreeMap<String, FieldValue>, String> {
    let root = ensure_object(value, "root")?;
    let appearance = ensure_object(
        root.get("terminalAppearance")
            .ok_or_else(|| "本地状态缺少 terminalAppearance".to_string())?,
        "terminalAppearance",
    )?;
    let font_family = required_string(appearance, "fontFamily", 256)?;
    let font_size = appearance
        .get("fontSize")
        .and_then(Value::as_i64)
        .ok_or_else(|| "本地状态 terminalAppearance.fontSize 无效".to_string())?;
    let line_height = appearance
        .get("lineHeight")
        .and_then(Value::as_f64)
        .ok_or_else(|| "本地状态 terminalAppearance.lineHeight 无效".to_string())?;
    let line_height_scaled = (line_height * 100.0).round();
    if !line_height.is_finite() || (line_height * 100.0 - line_height_scaled).abs() > 0.000_001 {
        return Err("本地状态 terminalAppearance.lineHeight 必须以百分之一为步长".to_string());
    }
    let line_height = i64::try_from(line_height_scaled as i128)
        .map_err(|_| "本地状态 terminalAppearance.lineHeight 超出范围".to_string())?;
    let fields = BTreeMap::from([
        (
            "fontFamily".to_string(),
            FieldValue::Text(font_family.to_string()),
        ),
        ("fontSize".to_string(), FieldValue::Integer(font_size)),
        ("lineHeight".to_string(), FieldValue::Integer(line_height)),
    ]);
    if !entity_fields_are_syncable(&EntityKind::Setting, &fields) {
        return Err("本地状态 terminalAppearance 未通过同步字段验证".to_string());
    }
    Ok(fields)
}

fn default_terminal_appearance_sync_fields() -> BTreeMap<String, FieldValue> {
    BTreeMap::from([
        (
            "fontFamily".to_string(),
            FieldValue::Text("Cascadia Code".to_string()),
        ),
        ("fontSize".to_string(), FieldValue::Integer(13)),
        ("lineHeight".to_string(), FieldValue::Integer(125)),
    ])
}

fn application_preference_sync_fields(
    value: &Value,
) -> Result<BTreeMap<String, FieldValue>, String> {
    let root = ensure_object(value, "root")?;
    let settings = ensure_object(
        root.get("settings")
            .ok_or_else(|| "本地状态缺少 settings".to_string())?,
        "settings",
    )?;
    let flag = |field: &str, default: bool| match settings.get(field) {
        Some(Value::Bool(value)) => Ok(*value),
        None => Ok(default),
        _ => Err(format!("本地状态 settings.{field} 无效")),
    };
    let fields = BTreeMap::from([
        (
            "autoUploadEditedFiles".to_string(),
            FieldValue::Flag(flag("autoUploadEditedFiles", false)?),
        ),
        (
            "packageTransfersEnabled".to_string(),
            FieldValue::Flag(flag("packageTransfersEnabled", true)?),
        ),
    ]);
    if !entity_fields_are_syncable(&EntityKind::Setting, &fields) {
        return Err("本地状态应用行为偏好未通过同步字段验证".to_string());
    }
    Ok(fields)
}

fn default_application_preference_sync_fields() -> BTreeMap<String, FieldValue> {
    BTreeMap::from([
        ("autoUploadEditedFiles".to_string(), FieldValue::Flag(false)),
        (
            "packageTransfersEnabled".to_string(),
            FieldValue::Flag(true),
        ),
    ])
}

fn onboarding_sync_fields(value: &Value) -> Result<BTreeMap<String, FieldValue>, String> {
    let root = ensure_object(value, "root")?;
    let completed = root
        .get("onboardingCompleted")
        .and_then(Value::as_bool)
        .ok_or_else(|| "本地状态 onboardingCompleted 无效".to_string())?;
    let fields = BTreeMap::from([(
        "onboardingCompleted".to_string(),
        FieldValue::Flag(completed),
    )]);
    if !entity_fields_are_syncable(&EntityKind::Setting, &fields) {
        return Err("本地状态 onboardingCompleted 未通过同步字段验证".to_string());
    }
    Ok(fields)
}

fn default_onboarding_sync_fields() -> BTreeMap<String, FieldValue> {
    BTreeMap::from([("onboardingCompleted".to_string(), FieldValue::Flag(false))])
}

fn monitor_preference_sync_fields(value: &Value) -> Result<BTreeMap<String, FieldValue>, String> {
    let root = ensure_object(value, "root")?;
    let settings = ensure_object(
        root.get("settings")
            .ok_or_else(|| "本地状态缺少 settings".to_string())?,
        "settings",
    )?;
    let interval = match settings.get("monitorIntervalSeconds") {
        Some(value) => value
            .as_i64()
            .ok_or_else(|| "本地状态 settings.monitorIntervalSeconds 无效".to_string())?,
        None => 15,
    };
    let fields = BTreeMap::from([("monitorInterval".to_string(), FieldValue::Integer(interval))]);
    if !entity_fields_are_syncable(&EntityKind::Setting, &fields) {
        return Err("本地状态监控偏好未通过同步字段验证".to_string());
    }
    Ok(fields)
}

fn default_monitor_preference_sync_fields() -> BTreeMap<String, FieldValue> {
    BTreeMap::from([("monitorInterval".to_string(), FieldValue::Integer(15))])
}

fn sync_fields_hash(fields: &BTreeMap<String, FieldValue>) -> Result<String, String> {
    let encoded =
        serde_json::to_vec(fields).map_err(|error| format!("无法编码本地同步字段指纹: {error}"))?;
    let digest = Sha256::digest(encoded);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

fn queue_fixed_setting_sync_change(
    transaction: &Transaction<'_>,
    initial_state: bool,
    entity_id: &str,
    next_fields: BTreeMap<String, FieldValue>,
    default_fields: &BTreeMap<String, FieldValue>,
    revision: u64,
    now: i64,
) -> Result<(), String> {
    let content_hash = sync_fields_hash(&next_fields)?;
    let queued_hash: Option<String> = transaction
        .query_row(
            "SELECT content_hash FROM app_sync_setting_state WHERE entity_id = ?1",
            params![entity_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("无法读取 AppState 设置同步状态: {error}"))?;
    if queued_hash.as_deref() == Some(content_hash.as_str()) {
        return Ok(());
    }
    if initial_state && &next_fields == default_fields {
        transaction
            .execute(
                "INSERT INTO app_sync_setting_state(entity_id, content_hash)
                 VALUES (?1, ?2)
                 ON CONFLICT(entity_id) DO UPDATE SET content_hash = excluded.content_hash",
                params![entity_id, content_hash],
            )
            .map_err(|error| format!("无法记录 AppState 默认设置同步状态: {error}"))?;
        return Ok(());
    }
    let pending: i64 = transaction
        .query_row("SELECT COUNT(*) FROM app_sync_changes", [], |row| {
            row.get(0)
        })
        .map_err(|error| format!("无法统计 AppState 同步 changefeed: {error}"))?;
    if pending >= MAX_PENDING_SYNC_CHANGES {
        if initial_state {
            return Ok(());
        }
        return Err("AppState 同步 changefeed 已达到 10000 项上限；请先完成同步".to_string());
    }
    let revision = i64::try_from(revision)
        .map_err(|_| "AppState 同步 revision 超过 SQLite INTEGER".to_string())?;
    let fields_json = serde_json::to_string(&next_fields)
        .map_err(|error| format!("无法编码脱敏设置同步变更: {error}"))?;
    transaction
        .execute(
            "INSERT INTO app_sync_changes(
                operation_id, entity_id, mutation_kind, fields_json, state_revision,
                created_at_ms, entity_kind
             ) VALUES (?1, ?2, 'patch', ?3, ?4, ?5, 'setting')",
            params![
                Uuid::new_v4().to_string(),
                entity_id,
                fields_json,
                revision,
                now
            ],
        )
        .map_err(|error| format!("无法写入 AppState 设置同步 changefeed: {error}"))?;
    transaction
        .execute(
            "INSERT INTO app_sync_setting_state(entity_id, content_hash)
             VALUES (?1, ?2)
             ON CONFLICT(entity_id) DO UPDATE SET content_hash = excluded.content_hash",
            params![entity_id, content_hash],
        )
        .map_err(|error| format!("无法记录 AppState 设置同步状态: {error}"))?;
    Ok(())
}

fn queue_setting_sync_changes(
    transaction: &Transaction<'_>,
    previous: Option<&Value>,
    next: &Value,
    revision: u64,
    now: i64,
) -> Result<(), String> {
    let initial_state = previous.is_none();
    queue_fixed_setting_sync_change(
        transaction,
        initial_state,
        TERMINAL_APPEARANCE_ENTITY_ID,
        terminal_appearance_sync_fields(next)?,
        &default_terminal_appearance_sync_fields(),
        revision,
        now,
    )?;
    queue_fixed_setting_sync_change(
        transaction,
        initial_state,
        APPLICATION_PREFERENCES_ENTITY_ID,
        application_preference_sync_fields(next)?,
        &default_application_preference_sync_fields(),
        revision,
        now,
    )?;
    queue_fixed_setting_sync_change(
        transaction,
        initial_state,
        ONBOARDING_ENTITY_ID,
        onboarding_sync_fields(next)?,
        &default_onboarding_sync_fields(),
        revision,
        now,
    )?;
    queue_fixed_setting_sync_change(
        transaction,
        initial_state,
        MONITOR_PREFERENCES_ENTITY_ID,
        monitor_preference_sync_fields(next)?,
        &default_monitor_preference_sync_fields(),
        revision,
        now,
    )
}

fn entity_projection_hash(entities: &[MergedEntityProjection]) -> Result<String, String> {
    let encoded = serde_json::to_vec(entities)
        .map_err(|error| format!("无法编码 AppState 实体同步投影: {error}"))?;
    let digest = Sha256::digest(encoded);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

fn validate_setting_projection_fields(
    entity_id: &str,
    fields: &BTreeMap<String, FieldValue>,
) -> Result<(), String> {
    let fields_match = match entity_id {
        TERMINAL_APPEARANCE_ENTITY_ID => {
            fields.len() == 3
                && fields
                    .keys()
                    .all(|field| matches!(field.as_str(), "fontFamily" | "fontSize" | "lineHeight"))
        }
        APPLICATION_PREFERENCES_ENTITY_ID => {
            fields.len() == 2
                && fields.keys().all(|field| {
                    matches!(
                        field.as_str(),
                        "autoUploadEditedFiles" | "packageTransfersEnabled"
                    )
                })
        }
        ONBOARDING_ENTITY_ID => {
            fields.len() == 1 && fields.keys().all(|field| field == "onboardingCompleted")
        }
        MONITOR_PREFERENCES_ENTITY_ID => {
            fields.len() == 1 && fields.keys().all(|field| field == "monitorInterval")
        }
        _ => false,
    };
    if !fields_match || !entity_fields_are_syncable(&EntityKind::Setting, fields) {
        return Err("远端设置同步投影字段未通过协议验证".to_string());
    }
    Ok(())
}

fn load_host_entity_mappings(
    transaction: &Transaction<'_>,
) -> Result<(BTreeMap<String, String>, BTreeMap<String, String>), String> {
    let mut statement = transaction
        .prepare("SELECT local_id, entity_id FROM app_sync_host_ids")
        .map_err(|error| format!("无法准备主机同步身份映射读取: {error}"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| format!("无法读取主机同步身份映射: {error}"))?;
    let mut entity_by_local = BTreeMap::new();
    let mut local_by_entity = BTreeMap::new();
    for row in rows {
        let (local_id, entity_id) =
            row.map_err(|error| format!("主机同步身份映射损坏: {error}"))?;
        if local_id.is_empty()
            || local_id.len() > 128
            || local_id.chars().any(char::is_control)
            || Uuid::parse_str(&entity_id).is_err()
            || entity_by_local
                .insert(local_id.clone(), entity_id.clone())
                .is_some()
            || local_by_entity.insert(entity_id, local_id).is_some()
        {
            return Err("主机同步身份映射损坏或重复".to_string());
        }
    }
    Ok((entity_by_local, local_by_entity))
}

fn required_projection_text(
    fields: &BTreeMap<String, FieldValue>,
    field: &str,
) -> Result<String, String> {
    match fields.get(field) {
        Some(FieldValue::Text(value)) => Ok(value.clone()),
        _ => Err(format!("远端主机同步投影缺少必需字段 {field}")),
    }
}

fn apply_host_projection_fields(
    mut host: serde_json::Map<String, Value>,
    local_id: &str,
    entity_id: &str,
    fields: &BTreeMap<String, FieldValue>,
    live_local_by_entity: &BTreeMap<String, String>,
) -> Result<serde_json::Map<String, Value>, String> {
    let allowed = [
        "name",
        "address",
        "port",
        "username",
        "group",
        "environment",
        "tags",
        "jumpRoute",
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    if fields.keys().any(|field| !allowed.contains(field.as_str())) {
        return Err("远端主机同步投影包含不支持字段".to_string());
    }
    let name = required_projection_text(fields, "name")?;
    let address = required_projection_text(fields, "address")?;
    let username = required_projection_text(fields, "username")?;
    let port = match fields.get("port") {
        Some(FieldValue::Integer(port)) if (1..=65_535).contains(port) => *port,
        _ => return Err("远端主机同步投影缺少有效端口".to_string()),
    };
    let group = match fields.get("group") {
        Some(FieldValue::Text(value)) => value.clone(),
        None | Some(FieldValue::Clear) => String::new(),
        _ => return Err("远端主机同步投影 group 类型无效".to_string()),
    };
    let environment = match fields.get("environment") {
        Some(FieldValue::Text(value))
            if matches!(value.as_str(), "development" | "staging" | "production") =>
        {
            value.clone()
        }
        None | Some(FieldValue::Clear) => "development".to_string(),
        _ => return Err("远端主机同步投影 environment 类型无效".to_string()),
    };
    let tags = match fields.get("tags") {
        Some(FieldValue::TextList(values)) if values.len() <= 32 => values.clone(),
        None | Some(FieldValue::Clear) => Vec::new(),
        _ => return Err("远端主机同步投影 tags 类型无效".to_string()),
    };
    let route_entities = match fields.get("jumpRoute") {
        Some(FieldValue::TextList(values)) if values.len() <= 3 => values.as_slice(),
        None | Some(FieldValue::Clear) => &[],
        _ => return Err("远端主机同步投影 jumpRoute 超过三跳或类型无效".to_string()),
    };
    let mut route = Vec::with_capacity(route_entities.len());
    let mut route_ids = HashSet::with_capacity(route_entities.len());
    for route_entity in route_entities {
        if route_entity == entity_id || !route_ids.insert(route_entity.as_str()) {
            return Err("远端主机同步投影 jumpRoute 重复或引用自身".to_string());
        }
        let local_route_id = live_local_by_entity
            .get(route_entity)
            .ok_or_else(|| "远端主机同步投影 jumpRoute 引用缺失或已删除主机".to_string())?;
        route.push(Value::String(local_route_id.clone()));
    }

    host.insert("id".to_string(), Value::String(local_id.to_string()));
    host.insert("name".to_string(), Value::String(name));
    host.insert("host".to_string(), Value::String(address));
    host.insert("port".to_string(), Value::Number(port.into()));
    host.insert("username".to_string(), Value::String(username));
    host.insert("group".to_string(), Value::String(group));
    host.insert("environment".to_string(), Value::String(environment));
    host.insert(
        "tags".to_string(),
        Value::Array(tags.into_iter().map(Value::String).collect()),
    );
    if route.is_empty() {
        host.remove("jumpRoute");
    } else {
        host.insert("jumpRoute".to_string(), Value::Array(route));
    }
    Ok(host)
}

fn load_script_entity_mappings(
    transaction: &Transaction<'_>,
) -> Result<(BTreeMap<String, String>, BTreeMap<String, String>), String> {
    let mut statement = transaction
        .prepare("SELECT local_id, entity_id FROM app_sync_script_ids")
        .map_err(|error| format!("无法准备脚本同步身份映射读取: {error}"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| format!("无法读取脚本同步身份映射: {error}"))?;
    let mut entity_by_local = BTreeMap::new();
    let mut local_by_entity = BTreeMap::new();
    for row in rows {
        let (local_id, entity_id) =
            row.map_err(|error| format!("脚本同步身份映射损坏: {error}"))?;
        if local_id.is_empty()
            || local_id.len() > 128
            || local_id.chars().any(char::is_control)
            || Uuid::parse_str(&entity_id).is_err()
            || entity_by_local
                .insert(local_id.clone(), entity_id.clone())
                .is_some()
            || local_by_entity.insert(entity_id, local_id).is_some()
        {
            return Err("脚本同步身份映射损坏或重复".to_string());
        }
    }
    Ok((entity_by_local, local_by_entity))
}

fn apply_script_projection_fields(
    mut script: serde_json::Map<String, Value>,
    local_id: &str,
    fields: &BTreeMap<String, FieldValue>,
) -> Result<serde_json::Map<String, Value>, String> {
    let allowed = ["name", "body", "source", "risk", "parameters"]
        .into_iter()
        .collect::<HashSet<_>>();
    if fields.keys().any(|field| !allowed.contains(field.as_str())) {
        return Err("远端脚本同步投影包含不支持字段".to_string());
    }
    let title = match fields.get("name") {
        Some(FieldValue::Text(value)) => value.clone(),
        _ => return Err("远端脚本同步投影缺少 name".to_string()),
    };
    let command = match fields.get("body") {
        Some(FieldValue::Text(value)) => value.clone(),
        _ => return Err("远端脚本同步投影缺少 body".to_string()),
    };
    let source = match fields.get("source") {
        Some(FieldValue::Text(value)) => value.clone(),
        None | Some(FieldValue::Clear) => String::new(),
        _ => return Err("远端脚本同步投影 source 类型无效".to_string()),
    };
    let remote_risk = match fields.get("risk") {
        Some(FieldValue::Text(value)) if value == "safe" => "low",
        Some(FieldValue::Text(value)) if value == "caution" => "medium",
        Some(FieldValue::Text(value)) if value == "danger" => "high",
        _ => return Err("远端脚本同步投影 risk 无效".to_string()),
    };
    let risk_rank = |risk: &str| match risk {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "destructive" => 4,
        _ => 0,
    };
    let local_risk = script.get("risk").and_then(Value::as_str);
    let risk = local_risk
        .filter(|risk| risk_rank(risk) > risk_rank(remote_risk))
        .unwrap_or(remote_risk)
        .to_string();
    let parameters = match fields.get("parameters") {
        Some(FieldValue::TextList(values)) => values.clone(),
        None | Some(FieldValue::Clear) => Vec::new(),
        _ => return Err("远端脚本同步投影 parameters 类型无效".to_string()),
    };

    script.insert("id".to_string(), Value::String(local_id.to_string()));
    script.insert("title".to_string(), Value::String(title));
    script.insert("command".to_string(), Value::String(command));
    script.insert("sourceUrl".to_string(), Value::String(source));
    script.insert("risk".to_string(), Value::String(risk));
    script.insert("custom".to_string(), Value::Bool(true));
    script
        .entry("description".to_string())
        .or_insert_with(|| Value::String("从加密同步恢复的自建脚本".to_string()));
    script
        .entry("category".to_string())
        .or_insert_with(|| Value::String("我的脚本".to_string()));
    if parameters.is_empty() {
        script.remove("parameters");
    } else {
        script.insert(
            "parameters".to_string(),
            Value::Array(parameters.into_iter().map(Value::String).collect()),
        );
    }
    if script_sync_fields(&script).is_none() {
        return Err("远端脚本同步投影未通过公开字段安全验证".to_string());
    }
    Ok(script)
}

fn insert_event(
    transaction: &Transaction<'_>,
    event_kind: &str,
    domains: &[String],
    now: i64,
) -> Result<(), String> {
    let domains_json =
        serde_json::to_string(domains).map_err(|error| format!("无法编码本地事件域: {error}"))?;
    transaction
        .execute(
            "INSERT INTO app_events(event_id, event_kind, domains_json, created_at_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![Uuid::new_v4().to_string(), event_kind, domains_json, now],
        )
        .map_err(|error| format!("无法写入本地事件元数据: {error}"))?;
    Ok(())
}

fn prune_events(transaction: &Transaction<'_>, now: i64) -> Result<u64, String> {
    transaction
        .execute(
            "DELETE FROM app_events WHERE created_at_ms < ?1",
            params![now.saturating_sub(EVENT_RETENTION_MS)],
        )
        .map_err(|error| format!("无法按时间清理本地事件: {error}"))?;
    transaction
        .execute(
            "DELETE FROM app_events
             WHERE seq NOT IN (SELECT seq FROM app_events ORDER BY seq DESC LIMIT ?1)",
            params![MAX_EVENTS],
        )
        .map_err(|error| format!("无法按数量清理本地事件: {error}"))?;
    let count: i64 = transaction
        .query_row("SELECT COUNT(*) FROM app_events", [], |row| row.get(0))
        .map_err(|error| format!("无法统计本地事件: {error}"))?;
    Ok(count.max(0) as u64)
}

impl AppStore {
    pub(crate) fn load(app_data_directory: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(&app_data_directory)
            .map_err(|error| format!("无法创建 VPShell 应用数据目录: {error}"))?;
        let database_path = database_path(&app_data_directory);
        let recovery_note = prepare_database(&database_path)?;
        Ok(Self {
            inner: Arc::new(AppStoreInner {
                database_path,
                lock: Mutex::new(()),
                recovery_note,
            }),
        })
    }

    pub(crate) fn initialize(
        &self,
        request: InitializeAppStoreRequest,
    ) -> Result<AppStoreSnapshot, String> {
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地事件库锁不可用".to_string())?;
        let mut connection = open_connection(&self.inner.database_path)?;
        quick_check(&connection)?;
        migrate_schema(&mut connection)?;
        let existing: Option<(i64, String)> = connection
            .query_row(
                "SELECT revision, state_json FROM app_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("无法读取本地状态快照: {error}"))?;
        if let Some((revision, state_json)) = existing {
            validate_state_json(&state_json)?;
            return Ok(AppStoreSnapshot {
                schema_version: STORE_SCHEMA_VERSION,
                revision: revision.max(0) as u64,
                state_json: Some(state_json),
                migrated_legacy: false,
                recovery_note: self.inner.recovery_note.clone(),
            });
        }

        let Some(legacy_state_json) = request.legacy_state_json else {
            return Ok(AppStoreSnapshot {
                schema_version: STORE_SCHEMA_VERSION,
                revision: 0,
                state_json: None,
                migrated_legacy: false,
                recovery_note: self.inner.recovery_note.clone(),
            });
        };
        let state = validate_state_json(&legacy_state_json)?;
        let now = epoch_ms();
        let transaction = connection
            .transaction()
            .map_err(|error| format!("无法开始旧状态迁移事务: {error}"))?;
        transaction
            .execute(
                "INSERT INTO app_state(singleton, schema_version, revision, state_json, updated_at_ms)
                 VALUES (1, ?1, 1, ?2, ?3)",
                params![STORE_SCHEMA_VERSION, legacy_state_json, now],
            )
            .map_err(|error| format!("无法迁移旧 WebView 状态: {error}"))?;
        queue_host_sync_changes(&transaction, None, &state, 1, now)?;
        queue_script_sync_changes(&transaction, None, &state, 1, now)?;
        queue_setting_sync_changes(&transaction, None, &state, 1, now)?;
        insert_event(
            &transaction,
            "legacy-local-storage-imported",
            &changed_domains(None, &state),
            now,
        )?;
        prune_events(&transaction, now)?;
        transaction
            .commit()
            .map_err(|error| format!("无法提交旧状态迁移: {error}"))?;
        Ok(AppStoreSnapshot {
            schema_version: STORE_SCHEMA_VERSION,
            revision: 1,
            state_json: Some(legacy_state_json),
            migrated_legacy: true,
            recovery_note: self.inner.recovery_note.clone(),
        })
    }

    pub(crate) fn snapshot(&self) -> Result<AppStoreSnapshot, String> {
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地事件库锁不可用".to_string())?;
        let connection = open_connection(&self.inner.database_path)?;
        let existing: Option<(i64, String)> = connection
            .query_row(
                "SELECT revision, state_json FROM app_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("无法读取本地状态快照: {error}"))?;
        let (revision, state_json) = match existing {
            Some((revision, state_json)) => {
                validate_state_json(&state_json)?;
                (revision.max(0) as u64, Some(state_json))
            }
            None => (0, None),
        };
        Ok(AppStoreSnapshot {
            schema_version: STORE_SCHEMA_VERSION,
            revision,
            state_json,
            migrated_legacy: false,
            recovery_note: self.inner.recovery_note.clone(),
        })
    }

    pub(crate) fn save(&self, request: SaveAppStateRequest) -> Result<SaveAppStateResult, String> {
        let next_value = validate_state_json(&request.state_json)?;
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地事件库锁不可用".to_string())?;
        let mut connection = open_connection(&self.inner.database_path)?;
        let transaction = connection
            .transaction()
            .map_err(|error| format!("无法开始本地状态事务: {error}"))?;
        let existing: Option<(i64, String)> = transaction
            .query_row(
                "SELECT revision, state_json FROM app_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("无法读取当前本地状态: {error}"))?;
        let current_revision = existing
            .as_ref()
            .map(|(revision, _)| (*revision).max(0) as u64)
            .unwrap_or(0);
        if current_revision != request.expected_revision {
            return Err(format!(
                "本地状态版本冲突：当前 {current_revision}，请求 {}，请重新加载",
                request.expected_revision
            ));
        }
        let next_revision = current_revision
            .checked_add(1)
            .ok_or_else(|| "本地状态版本已耗尽".to_string())?;
        let next_revision_sql = i64::try_from(next_revision)
            .map_err(|_| "本地状态版本超过 SQLite INTEGER".to_string())?;
        let previous_value = existing
            .as_ref()
            .and_then(|(_, state_json)| serde_json::from_str::<Value>(state_json).ok());
        let domains = changed_domains(previous_value.as_ref(), &next_value);
        let now = epoch_ms();
        transaction
            .execute(
                "INSERT INTO app_state(singleton, schema_version, revision, state_json, updated_at_ms)
                 VALUES (1, ?1, ?2, ?3, ?4)
                 ON CONFLICT(singleton) DO UPDATE SET
                    schema_version = excluded.schema_version,
                    revision = excluded.revision,
                    state_json = excluded.state_json,
                    updated_at_ms = excluded.updated_at_ms",
                params![STORE_SCHEMA_VERSION, next_revision_sql, request.state_json, now],
            )
            .map_err(|error| format!("无法写入本地状态快照: {error}"))?;
        queue_host_sync_changes(
            &transaction,
            previous_value.as_ref(),
            &next_value,
            next_revision,
            now,
        )?;
        queue_script_sync_changes(
            &transaction,
            previous_value.as_ref(),
            &next_value,
            next_revision,
            now,
        )?;
        queue_setting_sync_changes(
            &transaction,
            previous_value.as_ref(),
            &next_value,
            next_revision,
            now,
        )?;
        insert_event(&transaction, "state-replaced", &domains, now)?;
        let retained_events = prune_events(&transaction, now)?;
        transaction
            .commit()
            .map_err(|error| format!("无法提交本地状态事务: {error}"))?;
        Ok(SaveAppStateResult {
            revision: next_revision,
            retained_events,
        })
    }

    pub(crate) fn bind_sync_vault(&self, vault_id: &str) -> Result<(), String> {
        let vault_id = Uuid::parse_str(vault_id)
            .map_err(|_| "AppState 同步 vault ID 无效".to_string())?
            .to_string();
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地事件库锁不可用".to_string())?;
        let connection = open_connection(&self.inner.database_path)?;
        let existing: Option<String> = connection
            .query_row(
                "SELECT vault_id FROM app_sync_binding WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("无法读取 AppState 同步绑定: {error}"))?;
        if existing
            .as_deref()
            .is_some_and(|existing| existing != vault_id.as_str())
        {
            return Err("AppState 已绑定其他同步 vault；拒绝跨 vault 发送本地状态".to_string());
        }
        if existing.is_none() {
            connection
                .execute(
                    "INSERT INTO app_sync_binding(singleton, vault_id) VALUES (1, ?1)",
                    params![vault_id],
                )
                .map_err(|error| format!("无法写入 AppState 同步绑定: {error}"))?;
        }
        Ok(())
    }

    pub(crate) fn apply_remote_host_projection(
        &self,
        vault_id: &str,
        merge_revision: u64,
        hosts: &[MergedEntityProjection],
        now: i64,
    ) -> Result<ProjectionOutcome, String> {
        if now < 0 {
            return Err("AppState 同步投影时间不能为负数".to_string());
        }
        let vault_id = Uuid::parse_str(vault_id)
            .map_err(|_| "AppState 同步 vault ID 无效".to_string())?
            .to_string();
        let mut projection = hosts.to_vec();
        projection.sort_by(|left, right| left.entity_id.cmp(&right.entity_id));
        let mut entity_ids = BTreeSet::new();
        let mut live_count = 0_usize;
        for host in &projection {
            if Uuid::parse_str(&host.entity_id).is_err()
                || !entity_ids.insert(host.entity_id.clone())
            {
                return Err("AppState 主机同步投影包含无效或重复实体".to_string());
            }
            if host.fields.is_some() {
                live_count = live_count.saturating_add(1);
            }
        }
        if live_count > MAX_SYNCED_HOSTS {
            return Err("AppState 主机同步投影超过 2000 个活动主机".to_string());
        }
        let projection_hash = entity_projection_hash(&projection)?;
        let merge_revision_sql = i64::try_from(merge_revision)
            .map_err(|_| "AppState 同步 merge revision 超过 SQLite INTEGER".to_string())?;

        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地事件库锁不可用".to_string())?;
        let mut connection = open_connection(&self.inner.database_path)?;
        let transaction = connection
            .transaction()
            .map_err(|error| format!("无法开始 AppState 同步投影事务: {error}"))?;
        let bound_vault: Option<String> = transaction
            .query_row(
                "SELECT vault_id FROM app_sync_binding WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("无法读取 AppState 同步绑定: {error}"))?;
        if bound_vault.as_deref() != Some(vault_id.as_str()) {
            return Err("AppState 同步投影与 vault 绑定不匹配".to_string());
        }
        let applied: Option<(i64, String)> = transaction
            .query_row(
                "SELECT merge_revision, projection_hash
                 FROM app_sync_projection WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("无法读取 AppState 同步投影状态: {error}"))?;
        if let Some((applied_revision, applied_hash)) = applied {
            if applied_revision < 0 {
                return Err("AppState 同步投影 revision 损坏".to_string());
            }
            let applied_revision = applied_revision as u64;
            if merge_revision < applied_revision {
                return Err("AppState 同步投影 revision 回退".to_string());
            }
            if merge_revision == applied_revision {
                if projection_hash == applied_hash {
                    return Ok(ProjectionOutcome::Unchanged);
                }
                return Err("相同 AppState 同步投影 revision 的内容不同".to_string());
            }
        }
        let pending: i64 = transaction
            .query_row("SELECT COUNT(*) FROM app_sync_changes", [], |row| {
                row.get(0)
            })
            .map_err(|error| format!("无法统计 AppState 同步 changefeed: {error}"))?;
        if pending != 0 {
            return Ok(ProjectionOutcome::Deferred);
        }
        let existing: Option<(i64, String)> = transaction
            .query_row(
                "SELECT revision, state_json FROM app_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("无法读取待投影 AppState: {error}"))?;
        let Some((current_revision, state_json)) = existing else {
            return Ok(ProjectionOutcome::Deferred);
        };
        if current_revision < 0 {
            return Err("AppState revision 损坏".to_string());
        }
        let current_value = validate_state_json(&state_json)?;
        let mut next_value = current_value.clone();
        let root = next_value
            .as_object_mut()
            .ok_or_else(|| "AppState 根对象损坏".to_string())?;
        let current_hosts = root
            .get("hosts")
            .and_then(Value::as_array)
            .ok_or_else(|| "AppState hosts 损坏".to_string())?
            .clone();
        let current_deleted = root
            .get("deletedHosts")
            .and_then(Value::as_array)
            .ok_or_else(|| "AppState deletedHosts 损坏".to_string())?
            .clone();
        let (mut entity_by_local, mut local_by_entity) = load_host_entity_mappings(&transaction)?;
        let mut used_local_ids = entity_by_local.keys().cloned().collect::<BTreeSet<_>>();
        for value in &current_hosts {
            if let Some(local_id) = value
                .as_object()
                .and_then(|host| host.get("id"))
                .and_then(Value::as_str)
            {
                used_local_ids.insert(local_id.to_string());
            }
        }
        for value in &current_deleted {
            if let Some(local_id) = value
                .as_object()
                .and_then(|deleted| deleted.get("host"))
                .and_then(Value::as_object)
                .and_then(|host| host.get("id"))
                .and_then(Value::as_str)
            {
                used_local_ids.insert(local_id.to_string());
            }
        }
        for projected in projection.iter().filter(|host| host.fields.is_some()) {
            if local_by_entity.contains_key(&projected.entity_id) {
                continue;
            }
            let parsed = Uuid::parse_str(&projected.entity_id)
                .map_err(|_| "AppState 主机同步实体 ID 无效".to_string())?;
            let mut local_id = format!("host-sync-{parsed}");
            while used_local_ids.contains(&local_id) {
                local_id = format!("host-sync-{}", Uuid::new_v4());
            }
            transaction
                .execute(
                    "INSERT INTO app_sync_host_ids(local_id, entity_id) VALUES (?1, ?2)",
                    params![local_id, projected.entity_id],
                )
                .map_err(|error| format!("无法写入远端主机同步身份映射: {error}"))?;
            used_local_ids.insert(local_id.clone());
            entity_by_local.insert(local_id.clone(), projected.entity_id.clone());
            local_by_entity.insert(projected.entity_id.clone(), local_id);
        }
        let live_local_by_entity = projection
            .iter()
            .filter(|host| host.fields.is_some())
            .map(|host| {
                local_by_entity
                    .get(&host.entity_id)
                    .cloned()
                    .map(|local_id| (host.entity_id.clone(), local_id))
                    .ok_or_else(|| "远端主机同步投影缺少本机身份映射".to_string())
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let projected_by_entity = projection
            .iter()
            .map(|host| (host.entity_id.as_str(), host.fields.as_ref()))
            .collect::<BTreeMap<_, _>>();
        let deleted_host_by_local = current_deleted
            .iter()
            .filter_map(Value::as_object)
            .filter_map(|deleted| deleted.get("host"))
            .filter_map(Value::as_object)
            .filter_map(|host| {
                host.get("id")
                    .and_then(Value::as_str)
                    .map(|local_id| (local_id.to_string(), host.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        let mut applied_entities = BTreeSet::new();
        let mut next_hosts = Vec::new();
        for value in current_hosts {
            let host = value
                .as_object()
                .ok_or_else(|| "AppState host 损坏".to_string())?;
            let local_id = required_string(host, "id", 128)?;
            let Some(entity_id) = entity_by_local.get(local_id) else {
                next_hosts.push(Value::Object(host.clone()));
                continue;
            };
            let Some(fields) = projected_by_entity.get(entity_id.as_str()) else {
                next_hosts.push(Value::Object(host.clone()));
                continue;
            };
            applied_entities.insert(entity_id.to_string());
            if let Some(fields) = fields {
                next_hosts.push(Value::Object(apply_host_projection_fields(
                    host.clone(),
                    local_id,
                    entity_id,
                    fields,
                    &live_local_by_entity,
                )?));
            }
        }
        for projected in projection.iter().filter(|host| host.fields.is_some()) {
            if applied_entities.contains(&projected.entity_id) {
                continue;
            }
            let local_id = live_local_by_entity
                .get(&projected.entity_id)
                .ok_or_else(|| "远端主机同步投影缺少本机身份".to_string())?;
            let base = deleted_host_by_local
                .get(local_id)
                .cloned()
                .unwrap_or_default();
            next_hosts.push(Value::Object(apply_host_projection_fields(
                base,
                local_id,
                &projected.entity_id,
                projected.fields.as_ref().expect("filtered live host"),
                &live_local_by_entity,
            )?));
        }
        let restored_ids = next_hosts
            .iter()
            .filter_map(Value::as_object)
            .filter_map(|host| host.get("id"))
            .filter_map(Value::as_str)
            .collect::<HashSet<_>>();
        let next_deleted = current_deleted
            .into_iter()
            .filter(|value| {
                value
                    .as_object()
                    .and_then(|deleted| deleted.get("host"))
                    .and_then(Value::as_object)
                    .and_then(|host| host.get("id"))
                    .and_then(Value::as_str)
                    .is_none_or(|local_id| !restored_ids.contains(local_id))
            })
            .collect::<Vec<_>>();
        root.insert("hosts".to_string(), Value::Array(next_hosts));
        root.insert("deletedHosts".to_string(), Value::Array(next_deleted));
        validate_state_json(
            &serde_json::to_string(&next_value)
                .map_err(|error| format!("无法编码 AppState 同步投影结果: {error}"))?,
        )?;
        let changed = next_value != current_value;
        if changed {
            let next_revision = (current_revision as u64)
                .checked_add(1)
                .ok_or_else(|| "AppState revision 已耗尽".to_string())?;
            let next_revision_sql = i64::try_from(next_revision)
                .map_err(|_| "AppState revision 超过 SQLite INTEGER".to_string())?;
            let next_json = serde_json::to_string(&next_value)
                .map_err(|error| format!("无法编码 AppState 同步投影结果: {error}"))?;
            transaction
                .execute(
                    "UPDATE app_state SET schema_version = ?1, revision = ?2,
                        state_json = ?3, updated_at_ms = ?4 WHERE singleton = 1",
                    params![STORE_SCHEMA_VERSION, next_revision_sql, next_json, now],
                )
                .map_err(|error| format!("无法写入 AppState 主机同步投影: {error}"))?;
            insert_event(
                &transaction,
                "sync-hosts-applied",
                &changed_domains(Some(&current_value), &next_value),
                now,
            )?;
            prune_events(&transaction, now)?;
        }
        transaction
            .execute(
                "INSERT INTO app_sync_projection(
                    singleton, vault_id, merge_revision, projection_hash
                 ) VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT(singleton) DO UPDATE SET
                    vault_id = excluded.vault_id,
                    merge_revision = excluded.merge_revision,
                    projection_hash = excluded.projection_hash",
                params![vault_id, merge_revision_sql, projection_hash],
            )
            .map_err(|error| format!("无法推进 AppState 同步投影状态: {error}"))?;
        transaction
            .commit()
            .map_err(|error| format!("无法提交 AppState 同步投影事务: {error}"))?;
        Ok(if changed {
            ProjectionOutcome::Applied
        } else {
            ProjectionOutcome::Unchanged
        })
    }

    pub(crate) fn apply_remote_script_projection(
        &self,
        vault_id: &str,
        merge_revision: u64,
        scripts: &[MergedEntityProjection],
        now: i64,
    ) -> Result<ProjectionOutcome, String> {
        if now < 0 {
            return Err("AppState 脚本同步投影时间不能为负数".to_string());
        }
        let vault_id = Uuid::parse_str(vault_id)
            .map_err(|_| "AppState 同步 vault ID 无效".to_string())?
            .to_string();
        let mut projection = scripts.to_vec();
        projection.sort_by(|left, right| left.entity_id.cmp(&right.entity_id));
        let mut entity_ids = BTreeSet::new();
        let mut live_count = 0_usize;
        for script in &projection {
            if Uuid::parse_str(&script.entity_id).is_err()
                || !entity_ids.insert(script.entity_id.clone())
            {
                return Err("AppState 脚本同步投影包含无效或重复实体".to_string());
            }
            if script.fields.is_some() {
                live_count = live_count.saturating_add(1);
            }
        }
        if live_count > 2_000 {
            return Err("AppState 脚本同步投影超过 2000 个活动脚本".to_string());
        }
        let projection_hash = entity_projection_hash(&projection)?;
        let merge_revision_sql = i64::try_from(merge_revision)
            .map_err(|_| "AppState 同步 merge revision 超过 SQLite INTEGER".to_string())?;

        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地事件库锁不可用".to_string())?;
        let mut connection = open_connection(&self.inner.database_path)?;
        let transaction = connection
            .transaction()
            .map_err(|error| format!("无法开始 AppState 脚本同步投影事务: {error}"))?;
        let bound_vault: Option<String> = transaction
            .query_row(
                "SELECT vault_id FROM app_sync_binding WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("无法读取 AppState 同步绑定: {error}"))?;
        if bound_vault.as_deref() != Some(vault_id.as_str()) {
            return Err("AppState 脚本同步投影与 vault 绑定不匹配".to_string());
        }
        let applied: Option<(i64, String)> = transaction
            .query_row(
                "SELECT merge_revision, projection_hash
                 FROM app_sync_script_projection WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("无法读取 AppState 脚本同步投影状态: {error}"))?;
        if let Some((applied_revision, applied_hash)) = applied {
            if applied_revision < 0 {
                return Err("AppState 脚本同步投影 revision 损坏".to_string());
            }
            let applied_revision = applied_revision as u64;
            if merge_revision < applied_revision {
                return Err("AppState 脚本同步投影 revision 回退".to_string());
            }
            if merge_revision == applied_revision {
                if projection_hash == applied_hash {
                    return Ok(ProjectionOutcome::Unchanged);
                }
                return Err("相同 AppState 脚本同步投影 revision 的内容不同".to_string());
            }
        }
        let pending: i64 = transaction
            .query_row("SELECT COUNT(*) FROM app_sync_changes", [], |row| {
                row.get(0)
            })
            .map_err(|error| format!("无法统计 AppState 同步 changefeed: {error}"))?;
        if pending != 0 {
            return Ok(ProjectionOutcome::Deferred);
        }
        let existing: Option<(i64, String)> = transaction
            .query_row(
                "SELECT revision, state_json FROM app_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("无法读取待投影 AppState: {error}"))?;
        let Some((current_revision, state_json)) = existing else {
            return Ok(ProjectionOutcome::Deferred);
        };
        if current_revision < 0 {
            return Err("AppState revision 损坏".to_string());
        }
        let current_value = validate_state_json(&state_json)?;
        let mut next_value = current_value.clone();
        let root = next_value
            .as_object_mut()
            .ok_or_else(|| "AppState 根对象损坏".to_string())?;
        let current_scripts = root
            .get("scripts")
            .and_then(Value::as_array)
            .ok_or_else(|| "AppState scripts 损坏".to_string())?
            .clone();
        let (mut entity_by_local, mut local_by_entity) = load_script_entity_mappings(&transaction)?;
        let mut used_local_ids = entity_by_local.keys().cloned().collect::<BTreeSet<_>>();
        for value in &current_scripts {
            if let Some(local_id) = value
                .as_object()
                .and_then(|script| script.get("id"))
                .and_then(Value::as_str)
            {
                used_local_ids.insert(local_id.to_string());
            }
        }
        for projected in projection.iter().filter(|script| script.fields.is_some()) {
            if local_by_entity.contains_key(&projected.entity_id) {
                continue;
            }
            let parsed = Uuid::parse_str(&projected.entity_id)
                .map_err(|_| "AppState 脚本同步实体 ID 无效".to_string())?;
            let mut local_id = format!("script-sync-{parsed}");
            while used_local_ids.contains(&local_id) {
                local_id = format!("script-sync-{}", Uuid::new_v4());
            }
            transaction
                .execute(
                    "INSERT INTO app_sync_script_ids(local_id, entity_id) VALUES (?1, ?2)",
                    params![local_id, projected.entity_id],
                )
                .map_err(|error| format!("无法写入远端脚本同步身份映射: {error}"))?;
            used_local_ids.insert(local_id.clone());
            entity_by_local.insert(local_id.clone(), projected.entity_id.clone());
            local_by_entity.insert(projected.entity_id.clone(), local_id);
        }
        let projected_by_entity = projection
            .iter()
            .map(|script| (script.entity_id.as_str(), script.fields.as_ref()))
            .collect::<BTreeMap<_, _>>();
        let mut applied_entities = BTreeSet::new();
        let mut next_scripts = Vec::new();
        for value in current_scripts {
            let Some(script) = value.as_object() else {
                next_scripts.push(value);
                continue;
            };
            let Some(local_id) = script.get("id").and_then(Value::as_str) else {
                next_scripts.push(Value::Object(script.clone()));
                continue;
            };
            let Some(entity_id) = entity_by_local.get(local_id) else {
                next_scripts.push(Value::Object(script.clone()));
                continue;
            };
            let Some(fields) = projected_by_entity.get(entity_id.as_str()) else {
                next_scripts.push(Value::Object(script.clone()));
                continue;
            };
            applied_entities.insert(entity_id.clone());
            let locally_protected = script.get("custom").and_then(Value::as_bool) != Some(true)
                || script_sync_fields(script).is_none();
            if locally_protected {
                next_scripts.push(Value::Object(script.clone()));
            } else if let Some(fields) = fields {
                next_scripts.push(Value::Object(apply_script_projection_fields(
                    script.clone(),
                    local_id,
                    fields,
                )?));
            }
        }
        for projected in projection.iter().filter(|script| script.fields.is_some()) {
            if applied_entities.contains(&projected.entity_id) {
                continue;
            }
            let local_id = local_by_entity
                .get(&projected.entity_id)
                .ok_or_else(|| "远端脚本同步投影缺少本机身份".to_string())?;
            next_scripts.push(Value::Object(apply_script_projection_fields(
                serde_json::Map::new(),
                local_id,
                projected.fields.as_ref().expect("filtered live script"),
            )?));
        }
        root.insert("scripts".to_string(), Value::Array(next_scripts));
        validate_state_json(
            &serde_json::to_string(&next_value)
                .map_err(|error| format!("无法编码 AppState 脚本同步投影结果: {error}"))?,
        )?;
        let changed = next_value != current_value;
        if changed {
            let next_revision = (current_revision as u64)
                .checked_add(1)
                .ok_or_else(|| "AppState revision 已耗尽".to_string())?;
            let next_revision_sql = i64::try_from(next_revision)
                .map_err(|_| "AppState revision 超过 SQLite INTEGER".to_string())?;
            let next_json = serde_json::to_string(&next_value)
                .map_err(|error| format!("无法编码 AppState 脚本同步投影结果: {error}"))?;
            transaction
                .execute(
                    "UPDATE app_state SET schema_version = ?1, revision = ?2,
                        state_json = ?3, updated_at_ms = ?4 WHERE singleton = 1",
                    params![STORE_SCHEMA_VERSION, next_revision_sql, next_json, now],
                )
                .map_err(|error| format!("无法写入 AppState 脚本同步投影: {error}"))?;
            insert_event(
                &transaction,
                "sync-scripts-applied",
                &changed_domains(Some(&current_value), &next_value),
                now,
            )?;
            prune_events(&transaction, now)?;
        }
        transaction
            .execute(
                "INSERT INTO app_sync_script_projection(
                    singleton, vault_id, merge_revision, projection_hash
                 ) VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT(singleton) DO UPDATE SET
                    vault_id = excluded.vault_id,
                    merge_revision = excluded.merge_revision,
                    projection_hash = excluded.projection_hash",
                params![vault_id, merge_revision_sql, projection_hash],
            )
            .map_err(|error| format!("无法推进 AppState 脚本同步投影状态: {error}"))?;
        transaction
            .commit()
            .map_err(|error| format!("无法提交 AppState 脚本同步投影事务: {error}"))?;
        Ok(if changed {
            ProjectionOutcome::Applied
        } else {
            ProjectionOutcome::Unchanged
        })
    }

    pub(crate) fn apply_remote_setting_projection(
        &self,
        vault_id: &str,
        merge_revision: u64,
        settings: &[MergedEntityProjection],
        now: i64,
    ) -> Result<ProjectionOutcome, String> {
        if now < 0 {
            return Err("AppState 设置同步投影时间不能为负数".to_string());
        }
        let vault_id = Uuid::parse_str(vault_id)
            .map_err(|_| "AppState 同步 vault ID 无效".to_string())?
            .to_string();
        let mut projection = settings.to_vec();
        projection.sort_by(|left, right| left.entity_id.cmp(&right.entity_id));
        let mut entity_ids = BTreeSet::new();
        for setting in &projection {
            if Uuid::parse_str(&setting.entity_id).is_err()
                || !entity_ids.insert(setting.entity_id.clone())
            {
                return Err("AppState 设置同步投影包含无效或重复实体".to_string());
            }
            if setting.entity_id != TERMINAL_APPEARANCE_ENTITY_ID
                && setting.entity_id != APPLICATION_PREFERENCES_ENTITY_ID
                && setting.entity_id != ONBOARDING_ENTITY_ID
                && setting.entity_id != MONITOR_PREFERENCES_ENTITY_ID
            {
                return Err("AppState 设置同步投影包含未接线实体".to_string());
            }
            let fields = setting
                .fields
                .as_ref()
                .ok_or_else(|| "AppState 设置实体不能被删除".to_string())?;
            validate_setting_projection_fields(&setting.entity_id, fields)?;
        }
        let projection_hash = entity_projection_hash(&projection)?;
        let merge_revision_sql = i64::try_from(merge_revision)
            .map_err(|_| "AppState 同步 merge revision 超过 SQLite INTEGER".to_string())?;

        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地事件库锁不可用".to_string())?;
        let mut connection = open_connection(&self.inner.database_path)?;
        let transaction = connection
            .transaction()
            .map_err(|error| format!("无法开始 AppState 设置同步投影事务: {error}"))?;
        let bound_vault: Option<String> = transaction
            .query_row(
                "SELECT vault_id FROM app_sync_binding WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("无法读取 AppState 同步绑定: {error}"))?;
        if bound_vault.as_deref() != Some(vault_id.as_str()) {
            return Err("AppState 设置同步投影与 vault 绑定不匹配".to_string());
        }
        let applied: Option<(i64, String)> = transaction
            .query_row(
                "SELECT merge_revision, projection_hash
                 FROM app_sync_setting_projection WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("无法读取 AppState 设置同步投影状态: {error}"))?;
        if let Some((applied_revision, applied_hash)) = applied {
            if applied_revision < 0 {
                return Err("AppState 设置同步投影 revision 损坏".to_string());
            }
            let applied_revision = applied_revision as u64;
            if merge_revision < applied_revision {
                return Err("AppState 设置同步投影 revision 回退".to_string());
            }
            if merge_revision == applied_revision {
                if projection_hash == applied_hash {
                    return Ok(ProjectionOutcome::Unchanged);
                }
                return Err("相同 AppState 设置同步投影 revision 的内容不同".to_string());
            }
        }
        let pending: i64 = transaction
            .query_row("SELECT COUNT(*) FROM app_sync_changes", [], |row| {
                row.get(0)
            })
            .map_err(|error| format!("无法统计 AppState 同步 changefeed: {error}"))?;
        if pending != 0 {
            return Ok(ProjectionOutcome::Deferred);
        }
        let existing: Option<(i64, String)> = transaction
            .query_row(
                "SELECT revision, state_json FROM app_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("无法读取待投影 AppState: {error}"))?;
        let Some((current_revision, state_json)) = existing else {
            return Ok(ProjectionOutcome::Deferred);
        };
        if current_revision < 0 {
            return Err("AppState revision 损坏".to_string());
        }
        let current_value = validate_state_json(&state_json)?;
        let mut next_value = current_value.clone();
        let root = next_value
            .as_object_mut()
            .ok_or_else(|| "AppState 根对象损坏".to_string())?;
        let terminal_fields = projection
            .iter()
            .find(|setting| setting.entity_id == TERMINAL_APPEARANCE_ENTITY_ID)
            .and_then(|setting| setting.fields.as_ref());
        let preference_fields = projection
            .iter()
            .find(|setting| setting.entity_id == APPLICATION_PREFERENCES_ENTITY_ID)
            .and_then(|setting| setting.fields.as_ref());
        let onboarding_fields = projection
            .iter()
            .find(|setting| setting.entity_id == ONBOARDING_ENTITY_ID)
            .and_then(|setting| setting.fields.as_ref());
        let monitor_fields = projection
            .iter()
            .find(|setting| setting.entity_id == MONITOR_PREFERENCES_ENTITY_ID)
            .and_then(|setting| setting.fields.as_ref());
        if let Some(fields) = terminal_fields {
            let font_family = match fields.get("fontFamily") {
                Some(FieldValue::Text(value)) => value.clone(),
                _ => return Err("远端设置同步投影缺少 fontFamily".to_string()),
            };
            let font_size = match fields.get("fontSize") {
                Some(FieldValue::Integer(value)) => *value,
                _ => return Err("远端设置同步投影缺少 fontSize".to_string()),
            };
            let line_height = match fields.get("lineHeight") {
                Some(FieldValue::Integer(value)) => *value,
                _ => return Err("远端设置同步投影缺少 lineHeight".to_string()),
            };
            let line_height = serde_json::Number::from_f64(line_height as f64 / 100.0)
                .ok_or_else(|| "远端设置同步 lineHeight 无效".to_string())?;
            let appearance = root
                .get_mut("terminalAppearance")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| "AppState terminalAppearance 损坏".to_string())?;
            appearance.insert("fontFamily".to_string(), Value::String(font_family));
            appearance.insert("fontSize".to_string(), Value::Number(font_size.into()));
            appearance.insert("lineHeight".to_string(), Value::Number(line_height));
        }
        if let Some(fields) = preference_fields {
            let auto_upload_edited_files = match fields.get("autoUploadEditedFiles") {
                Some(FieldValue::Flag(value)) => *value,
                _ => return Err("远端设置同步投影缺少 autoUploadEditedFiles".to_string()),
            };
            let package_transfers_enabled = match fields.get("packageTransfersEnabled") {
                Some(FieldValue::Flag(value)) => *value,
                _ => return Err("远端设置同步投影缺少 packageTransfersEnabled".to_string()),
            };
            let settings = root
                .get_mut("settings")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| "AppState settings 损坏".to_string())?;
            settings.insert(
                "autoUploadEditedFiles".to_string(),
                Value::Bool(auto_upload_edited_files),
            );
            settings.insert(
                "packageTransfersEnabled".to_string(),
                Value::Bool(package_transfers_enabled),
            );
        }
        if let Some(fields) = onboarding_fields {
            let completed = match fields.get("onboardingCompleted") {
                Some(FieldValue::Flag(value)) => *value,
                _ => return Err("远端设置同步投影缺少 onboardingCompleted".to_string()),
            };
            root.insert("onboardingCompleted".to_string(), Value::Bool(completed));
        }
        if let Some(fields) = monitor_fields {
            let interval = match fields.get("monitorInterval") {
                Some(FieldValue::Integer(value)) => *value,
                _ => return Err("远端设置同步投影缺少 monitorInterval".to_string()),
            };
            let settings = root
                .get_mut("settings")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| "AppState settings 损坏".to_string())?;
            settings.insert(
                "monitorIntervalSeconds".to_string(),
                Value::Number(interval.into()),
            );
        }
        validate_state_json(
            &serde_json::to_string(&next_value)
                .map_err(|error| format!("无法编码 AppState 设置同步投影结果: {error}"))?,
        )?;
        let projected_content_hashes = projection
            .iter()
            .map(|setting| {
                let fields = setting
                    .fields
                    .as_ref()
                    .ok_or_else(|| "AppState 设置实体不能被删除".to_string())?;
                Ok((setting.entity_id.as_str(), sync_fields_hash(fields)?))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let changed = next_value != current_value;
        if changed {
            let next_revision = (current_revision as u64)
                .checked_add(1)
                .ok_or_else(|| "AppState revision 已耗尽".to_string())?;
            let next_revision_sql = i64::try_from(next_revision)
                .map_err(|_| "AppState revision 超过 SQLite INTEGER".to_string())?;
            let next_json = serde_json::to_string(&next_value)
                .map_err(|error| format!("无法编码 AppState 设置同步投影结果: {error}"))?;
            transaction
                .execute(
                    "UPDATE app_state SET schema_version = ?1, revision = ?2,
                        state_json = ?3, updated_at_ms = ?4 WHERE singleton = 1",
                    params![STORE_SCHEMA_VERSION, next_revision_sql, next_json, now],
                )
                .map_err(|error| format!("无法写入 AppState 设置同步投影: {error}"))?;
            insert_event(
                &transaction,
                "sync-setting-applied",
                &changed_domains(Some(&current_value), &next_value),
                now,
            )?;
            prune_events(&transaction, now)?;
        }
        for (entity_id, content_hash) in projected_content_hashes {
            transaction
                .execute(
                    "INSERT INTO app_sync_setting_state(entity_id, content_hash)
                     VALUES (?1, ?2)
                     ON CONFLICT(entity_id) DO UPDATE SET content_hash = excluded.content_hash",
                    params![entity_id, content_hash],
                )
                .map_err(|error| format!("无法记录 AppState 远端设置同步状态: {error}"))?;
        }
        transaction
            .execute(
                "INSERT INTO app_sync_setting_projection(
                    singleton, vault_id, merge_revision, projection_hash
                 ) VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT(singleton) DO UPDATE SET
                    vault_id = excluded.vault_id,
                    merge_revision = excluded.merge_revision,
                    projection_hash = excluded.projection_hash",
                params![vault_id, merge_revision_sql, projection_hash],
            )
            .map_err(|error| format!("无法推进 AppState 设置同步投影状态: {error}"))?;
        transaction
            .commit()
            .map_err(|error| format!("无法提交 AppState 设置同步投影事务: {error}"))?;
        Ok(if changed {
            ProjectionOutcome::Applied
        } else {
            ProjectionOutcome::Unchanged
        })
    }

    pub(crate) fn pending_entity_sync_changes(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingEntitySyncChange>, String> {
        if limit == 0 || limit > 128 {
            return Err("AppState 同步读取上限必须为 1 至 128".to_string());
        }
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地事件库锁不可用".to_string())?;
        let connection = open_connection(&self.inner.database_path)?;
        let mut statement = connection
            .prepare(
                "SELECT operation_id, entity_id, mutation_kind, fields_json, entity_kind
                 FROM app_sync_changes ORDER BY seq LIMIT ?1",
            )
            .map_err(|error| format!("无法准备 AppState 同步读取: {error}"))?;
        let rows = statement
            .query_map(params![limit as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|error| format!("无法读取 AppState 同步 changefeed: {error}"))?;
        let mut changes = Vec::new();
        for row in rows {
            let (operation_id, entity_id, kind, fields_json, entity_kind) =
                row.map_err(|error| format!("AppState 同步 changefeed 损坏: {error}"))?;
            let mutation = match (kind.as_str(), fields_json) {
                ("patch", Some(fields)) => LocalEntityMutation::Patch(
                    serde_json::from_str(&fields)
                        .map_err(|_| "AppState 同步 patch 损坏".to_string())?,
                ),
                ("delete", None) => LocalEntityMutation::Delete,
                _ => return Err("AppState 同步 changefeed 类型损坏".to_string()),
            };
            let entity_kind = match entity_kind.as_str() {
                "host" => EntityKind::Host,
                "script" => EntityKind::Script,
                "setting" => EntityKind::Setting,
                _ => return Err("AppState 同步 changefeed 实体类型损坏".to_string()),
            };
            if let LocalEntityMutation::Patch(fields) = &mutation {
                if !entity_fields_are_syncable(&entity_kind, fields) {
                    return Err("AppState 同步 changefeed 字段未通过协议验证".to_string());
                }
            }
            changes.push(PendingEntitySyncChange {
                operation_id,
                entity_kind,
                entity_id,
                mutation,
            });
        }
        Ok(changes)
    }

    pub(crate) fn pending_entity_sync_change_count(&self) -> Result<u64, String> {
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地事件库锁不可用".to_string())?;
        let connection = open_connection(&self.inner.database_path)?;
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM app_sync_changes", [], |row| {
                row.get(0)
            })
            .map_err(|error| format!("无法统计 AppState 同步 changefeed: {error}"))?;
        Ok(count.max(0) as u64)
    }

    pub(crate) fn ensure_setting_sync_changes(&self, now: i64) -> Result<(), String> {
        if now < 0 {
            return Err("AppState 设置同步恢复时间不能为负数".to_string());
        }
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地事件库锁不可用".to_string())?;
        let mut connection = open_connection(&self.inner.database_path)?;
        let transaction = connection
            .transaction()
            .map_err(|error| format!("无法开始 AppState 设置同步恢复事务: {error}"))?;
        let existing: Option<(i64, String)> = transaction
            .query_row(
                "SELECT revision, state_json FROM app_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("无法读取待恢复 AppState 设置: {error}"))?;
        if let Some((revision, state_json)) = existing {
            if revision < 0 {
                return Err("AppState revision 损坏".to_string());
            }
            let state = validate_state_json(&state_json)?;
            queue_setting_sync_changes(&transaction, None, &state, revision.max(1) as u64, now)?;
        }
        transaction
            .commit()
            .map_err(|error| format!("无法提交 AppState 设置同步恢复事务: {error}"))
    }

    pub(crate) fn acknowledge_entity_sync_change(
        &self,
        vault_id: &str,
        operation_id: &str,
    ) -> Result<(), String> {
        let vault_id = Uuid::parse_str(vault_id)
            .map_err(|_| "AppState 同步 vault ID 无效".to_string())?
            .to_string();
        let operation_id = Uuid::parse_str(operation_id)
            .map_err(|_| "AppState 同步 operation ID 无效".to_string())?
            .to_string();
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "本地事件库锁不可用".to_string())?;
        let connection = open_connection(&self.inner.database_path)?;
        let deleted = connection
            .execute(
                "DELETE FROM app_sync_changes
                 WHERE operation_id = ?1
                   AND EXISTS (
                     SELECT 1 FROM app_sync_binding
                     WHERE singleton = 1 AND vault_id = ?2
                   )",
                params![operation_id, vault_id],
            )
            .map_err(|error| format!("无法确认 AppState 同步 changefeed: {error}"))?;
        if deleted != 1 {
            return Err("AppState 同步确认缺少匹配 change 或 vault 绑定".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(label: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("vpshell-store-{label}-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).expect("create temp directory");
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> String {
        serde_json::json!({
            "hosts": [{
                "id": "host-1", "name": "Example", "group": "Test", "host": "192.0.2.1",
                "port": 22, "username": "dev", "environment": "development", "tags": [],
                "credentialRef": "ssh-public-reference"
            }],
            "deletedHosts": [], "scripts": [], "commands": [], "sshKeys": [],
            "commandHistory": [], "connectionHistory": [], "pathHistory": {},
            "sync": {"enabled": false, "provider": "webdav", "endpoint": "", "remotePath": "/vpshell", "username": "", "totpEnabled": false, "syncSecrets": false},
            "wallpaper": {"source": "none", "value": "", "opacity": 0.2},
            "terminalAppearance": {"fontFamily": "Cascadia Code", "fontSize": 13, "lineHeight": 1.25},
            "settings": {"externalEditorPath": "", "autoUploadEditedFiles": false, "packageTransfersEnabled": true},
            "onboardingCompleted": false
        }).to_string()
    }

    fn acknowledge_initial_host(
        store: &AppStore,
        vault_id: &str,
    ) -> (String, BTreeMap<String, FieldValue>) {
        store.bind_sync_vault(vault_id).unwrap();
        let change = store
            .pending_entity_sync_changes(128)
            .unwrap()
            .into_iter()
            .next()
            .expect("initial host change");
        let LocalEntityMutation::Patch(fields) = change.mutation else {
            panic!("initial host must be patch");
        };
        store
            .acknowledge_entity_sync_change(vault_id, &change.operation_id)
            .unwrap();
        (change.entity_id, fields)
    }

    #[test]
    fn schema_and_legacy_import_are_transactional_and_do_not_overwrite() {
        let root = TempDir::new("legacy");
        let store = AppStore::load(root.0.clone()).expect("load store");
        let first = store
            .initialize(InitializeAppStoreRequest {
                legacy_state_json: Some(fixture()),
            })
            .expect("import legacy state");
        assert_eq!(first.schema_version, STORE_SCHEMA_VERSION);
        assert_eq!(first.revision, 1);
        assert!(first.migrated_legacy);

        let mut different: Value = serde_json::from_str(&fixture()).expect("fixture JSON");
        different["hosts"][0]["name"] = Value::String("Changed legacy".to_string());
        let second = store
            .initialize(InitializeAppStoreRequest {
                legacy_state_json: Some(different.to_string()),
            })
            .expect("reload store");
        assert_eq!(second.revision, 1);
        assert!(!second.migrated_legacy);
        assert!(
            !second
                .state_json
                .expect("stored state")
                .contains("Changed legacy")
        );
    }

    #[test]
    fn saves_use_revision_conflicts_and_value_free_event_metadata() {
        let root = TempDir::new("save");
        let store = AppStore::load(root.0.clone()).expect("load store");
        let saved = store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .expect("save fixture");
        assert_eq!(saved.revision, 1);
        assert!(
            store
                .save(SaveAppStateRequest {
                    state_json: fixture(),
                    expected_revision: 0
                })
                .is_err()
        );

        let connection = open_connection(&database_path(&root.0)).expect("open database");
        let domains: String = connection
            .query_row("SELECT domains_json FROM app_events LIMIT 1", [], |row| {
                row.get(0)
            })
            .expect("read event");
        assert!(!domains.contains("192.0.2.1"));
        assert!(!domains.contains("ssh-public-reference"));
        assert!(domains.contains("hosts"));
    }

    #[test]
    fn host_changefeed_is_transactional_stable_and_secret_free() {
        let root = TempDir::new("sync-changefeed");
        let store = AppStore::load(root.0.clone()).expect("load store");
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .expect("save initial host");
        let initial = store
            .pending_entity_sync_changes(128)
            .expect("read initial changefeed");
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].entity_kind, EntityKind::Host);
        let LocalEntityMutation::Patch(fields) = &initial[0].mutation else {
            panic!("initial host must be a patch");
        };
        assert_eq!(fields["address"], FieldValue::Text("192.0.2.1".into()));
        assert!(!fields.keys().any(|field| {
            let field = field.to_ascii_lowercase();
            field.contains("credential") || field.contains("key") || field.contains("path")
        }));

        let mut credential_only: Value = serde_json::from_str(&fixture()).unwrap();
        credential_only["hosts"][0]["credentialRef"] =
            Value::String("ssh-another-public-reference".to_string());
        store
            .save(SaveAppStateRequest {
                state_json: credential_only.to_string(),
                expected_revision: 1,
            })
            .expect("save credential reference change");
        assert_eq!(store.pending_entity_sync_changes(128).unwrap().len(), 1);

        let mut deleted = credential_only;
        deleted["hosts"] = Value::Array(Vec::new());
        store
            .save(SaveAppStateRequest {
                state_json: deleted.to_string(),
                expected_revision: 2,
            })
            .expect("delete host");
        let changes = store.pending_entity_sync_changes(128).unwrap();
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].entity_id, changes[1].entity_id);
        assert_eq!(changes[1].mutation, LocalEntityMutation::Delete);

        let vault = Uuid::new_v4().to_string();
        store.bind_sync_vault(&vault).unwrap();
        assert!(store.bind_sync_vault(&Uuid::new_v4().to_string()).is_err());
        store
            .acknowledge_entity_sync_change(&vault, &changes[0].operation_id)
            .unwrap();
        assert_eq!(store.pending_entity_sync_changes(128).unwrap().len(), 1);
    }

    #[test]
    fn terminal_appearance_changefeed_uses_fixed_public_setting_fields() {
        let root = TempDir::new("setting-changefeed");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let vault_id = Uuid::new_v4().to_string();
        acknowledge_initial_host(&store, &vault_id);

        let mut state: Value = serde_json::from_str(&fixture()).unwrap();
        state["terminalAppearance"] = serde_json::json!({
            "fontFamily": "JetBrains Mono",
            "fontSize": 16,
            "lineHeight": 1.4,
            "customFontName": "device-only-font.ttf"
        });
        store
            .save(SaveAppStateRequest {
                state_json: state.to_string(),
                expected_revision: 1,
            })
            .unwrap();
        let changes = store.pending_entity_sync_changes(128).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].entity_kind, EntityKind::Setting);
        assert_eq!(changes[0].entity_id, TERMINAL_APPEARANCE_ENTITY_ID);
        let LocalEntityMutation::Patch(fields) = &changes[0].mutation else {
            panic!("terminal appearance must be a patch");
        };
        assert_eq!(fields.len(), 3);
        assert_eq!(
            fields["fontFamily"],
            FieldValue::Text("JetBrains Mono".into())
        );
        assert_eq!(fields["fontSize"], FieldValue::Integer(16));
        assert_eq!(fields["lineHeight"], FieldValue::Integer(140));
        assert!(
            !serde_json::to_string(fields)
                .unwrap()
                .contains("device-only")
        );
        store
            .acknowledge_entity_sync_change(&vault_id, &changes[0].operation_id)
            .unwrap();

        state["terminalAppearance"] = serde_json::json!({
            "fontFamily": "Cascadia Code", "fontSize": 13, "lineHeight": 1.25
        });
        store
            .save(SaveAppStateRequest {
                state_json: state.to_string(),
                expected_revision: 2,
            })
            .unwrap();
        let restored = store.pending_entity_sync_changes(128).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].entity_kind, EntityKind::Setting);
        let LocalEntityMutation::Patch(fields) = &restored[0].mutation else {
            panic!("restored terminal appearance must be a patch");
        };
        assert_eq!(fields, &default_terminal_appearance_sync_fields());

        state["terminalAppearance"]["lineHeight"] = serde_json::json!(1.234);
        assert!(
            store
                .save(SaveAppStateRequest {
                    state_json: state.to_string(),
                    expected_revision: 3,
                })
                .is_err()
        );
        assert_eq!(store.snapshot().unwrap().revision, 3);
    }

    #[test]
    fn application_preferences_changefeed_excludes_device_local_editor_path() {
        let root = TempDir::new("preference-changefeed");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let vault_id = Uuid::new_v4().to_string();
        acknowledge_initial_host(&store, &vault_id);

        let mut state: Value = serde_json::from_str(&fixture()).unwrap();
        state["settings"] = serde_json::json!({
            "externalEditorPath": "/device-only/editor",
            "autoUploadEditedFiles": true,
            "packageTransfersEnabled": false
        });
        store
            .save(SaveAppStateRequest {
                state_json: state.to_string(),
                expected_revision: 1,
            })
            .unwrap();
        let changes = store.pending_entity_sync_changes(128).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].entity_kind, EntityKind::Setting);
        assert_eq!(changes[0].entity_id, APPLICATION_PREFERENCES_ENTITY_ID);
        let LocalEntityMutation::Patch(fields) = &changes[0].mutation else {
            panic!("application preferences must be a patch");
        };
        assert_eq!(
            fields,
            &BTreeMap::from([
                ("autoUploadEditedFiles".to_string(), FieldValue::Flag(true),),
                (
                    "packageTransfersEnabled".to_string(),
                    FieldValue::Flag(false),
                ),
            ])
        );
        assert!(!serde_json::to_string(fields).unwrap().contains("editor"));
        store
            .acknowledge_entity_sync_change(&vault_id, &changes[0].operation_id)
            .unwrap();

        state["settings"]["autoUploadEditedFiles"] = Value::Bool(false);
        state["settings"]["packageTransfersEnabled"] = Value::Bool(true);
        store
            .save(SaveAppStateRequest {
                state_json: state.to_string(),
                expected_revision: 2,
            })
            .unwrap();
        let restored = store.pending_entity_sync_changes(128).unwrap();
        assert_eq!(restored.len(), 1);
        let LocalEntityMutation::Patch(fields) = &restored[0].mutation else {
            panic!("restored application preferences must be a patch");
        };
        assert_eq!(fields, &default_application_preference_sync_fields());

        state["settings"]["autoUploadEditedFiles"] = Value::String("yes".into());
        assert!(
            store
                .save(SaveAppStateRequest {
                    state_json: state.to_string(),
                    expected_revision: 3,
                })
                .is_err()
        );
        assert_eq!(store.snapshot().unwrap().revision, 3);
    }

    #[test]
    fn onboarding_completion_changefeed_and_remote_projection_are_boolean_and_non_echoing() {
        let root = TempDir::new("onboarding-setting");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let vault_id = Uuid::new_v4().to_string();
        acknowledge_initial_host(&store, &vault_id);

        let mut state: Value = serde_json::from_str(&fixture()).unwrap();
        state["onboardingCompleted"] = Value::Bool(true);
        store
            .save(SaveAppStateRequest {
                state_json: state.to_string(),
                expected_revision: 1,
            })
            .unwrap();
        let changes = store.pending_entity_sync_changes(128).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].entity_id, ONBOARDING_ENTITY_ID);
        let LocalEntityMutation::Patch(fields) = &changes[0].mutation else {
            panic!("onboarding completion must be a patch");
        };
        assert_eq!(
            fields,
            &BTreeMap::from([("onboardingCompleted".to_string(), FieldValue::Flag(true))])
        );
        store
            .acknowledge_entity_sync_change(&vault_id, &changes[0].operation_id)
            .unwrap();

        let projection = vec![MergedEntityProjection {
            entity_id: ONBOARDING_ENTITY_ID.to_string(),
            fields: Some(BTreeMap::from([(
                "onboardingCompleted".to_string(),
                FieldValue::Flag(false),
            )])),
        }];
        assert_eq!(
            store
                .apply_remote_setting_projection(&vault_id, 3, &projection, 5_000)
                .unwrap(),
            ProjectionOutcome::Applied
        );
        let snapshot = store.snapshot().unwrap();
        let projected: Value =
            serde_json::from_str(snapshot.state_json.as_deref().unwrap()).unwrap();
        assert_eq!(projected["onboardingCompleted"], false);
        assert!(store.pending_entity_sync_changes(128).unwrap().is_empty());
        assert_eq!(
            store
                .apply_remote_setting_projection(&vault_id, 3, &projection, 5_001)
                .unwrap(),
            ProjectionOutcome::Unchanged
        );

        let invalid = vec![MergedEntityProjection {
            entity_id: ONBOARDING_ENTITY_ID.to_string(),
            fields: Some(BTreeMap::from([(
                "onboardingCompleted".to_string(),
                FieldValue::Text("yes".into()),
            )])),
        }];
        assert!(
            store
                .apply_remote_setting_projection(&vault_id, 4, &invalid, 5_002)
                .is_err()
        );
        assert_eq!(store.snapshot().unwrap().revision, snapshot.revision);
    }

    #[test]
    fn monitor_preference_changefeed_and_remote_projection_are_bounded_and_non_echoing() {
        let root = TempDir::new("monitor-setting");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let vault_id = Uuid::new_v4().to_string();
        acknowledge_initial_host(&store, &vault_id);

        let mut state: Value = serde_json::from_str(&fixture()).unwrap();
        state["settings"]["monitorIntervalSeconds"] = Value::Number(30.into());
        store
            .save(SaveAppStateRequest {
                state_json: state.to_string(),
                expected_revision: 1,
            })
            .unwrap();
        let changes = store.pending_entity_sync_changes(128).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].entity_id, MONITOR_PREFERENCES_ENTITY_ID);
        let LocalEntityMutation::Patch(fields) = &changes[0].mutation else {
            panic!("monitor preference must be a patch");
        };
        assert_eq!(
            fields,
            &BTreeMap::from([("monitorInterval".to_string(), FieldValue::Integer(30))])
        );
        store
            .acknowledge_entity_sync_change(&vault_id, &changes[0].operation_id)
            .unwrap();

        state["settings"]["monitorIntervalSeconds"] = Value::Number(15.into());
        store
            .save(SaveAppStateRequest {
                state_json: state.to_string(),
                expected_revision: 2,
            })
            .unwrap();
        let restored = store.pending_entity_sync_changes(128).unwrap();
        assert_eq!(restored.len(), 1);
        let LocalEntityMutation::Patch(fields) = &restored[0].mutation else {
            panic!("restored monitor preference must be a patch");
        };
        assert_eq!(fields, &default_monitor_preference_sync_fields());
        store
            .acknowledge_entity_sync_change(&vault_id, &restored[0].operation_id)
            .unwrap();

        let projection = vec![MergedEntityProjection {
            entity_id: MONITOR_PREFERENCES_ENTITY_ID.to_string(),
            fields: Some(BTreeMap::from([(
                "monitorInterval".to_string(),
                FieldValue::Integer(60),
            )])),
        }];
        assert_eq!(
            store
                .apply_remote_setting_projection(&vault_id, 3, &projection, 5_000)
                .unwrap(),
            ProjectionOutcome::Applied
        );
        let snapshot = store.snapshot().unwrap();
        let projected: Value =
            serde_json::from_str(snapshot.state_json.as_deref().unwrap()).unwrap();
        assert_eq!(projected["settings"]["monitorIntervalSeconds"], 60);
        assert!(store.pending_entity_sync_changes(128).unwrap().is_empty());
        store
            .save(SaveAppStateRequest {
                state_json: projected.to_string(),
                expected_revision: snapshot.revision,
            })
            .unwrap();
        assert!(store.pending_entity_sync_changes(128).unwrap().is_empty());

        let invalid = vec![MergedEntityProjection {
            entity_id: MONITOR_PREFERENCES_ENTITY_ID.to_string(),
            fields: Some(BTreeMap::from([(
                "monitorInterval".to_string(),
                FieldValue::Integer(301),
            )])),
        }];
        let revision = store.snapshot().unwrap().revision;
        assert!(
            store
                .apply_remote_setting_projection(&vault_id, 4, &invalid, 5_001)
                .is_err()
        );
        assert_eq!(store.snapshot().unwrap().revision, revision);

        let mut invalid_local = projected;
        invalid_local["settings"]["monitorIntervalSeconds"] = Value::String("fast".into());
        assert!(
            store
                .save(SaveAppStateRequest {
                    state_json: invalid_local.to_string(),
                    expected_revision: revision,
                })
                .is_err()
        );
        assert_eq!(store.snapshot().unwrap().revision, revision);
    }

    #[test]
    fn setting_change_recovery_refills_a_deferred_migration_once() {
        let root = TempDir::new("setting-recovery");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let vault_id = Uuid::new_v4().to_string();
        acknowledge_initial_host(&store, &vault_id);
        let mut state: Value = serde_json::from_str(&fixture()).unwrap();
        state["terminalAppearance"]["fontSize"] = Value::Number(17.into());
        store
            .save(SaveAppStateRequest {
                state_json: state.to_string(),
                expected_revision: 1,
            })
            .unwrap();

        let connection = open_connection(&database_path(&root.0)).unwrap();
        connection
            .execute(
                "DELETE FROM app_sync_changes WHERE entity_kind = 'setting'",
                [],
            )
            .unwrap();
        connection
            .execute("DELETE FROM app_sync_setting_state", [])
            .unwrap();
        drop(connection);

        store.ensure_setting_sync_changes(3_000).unwrap();
        let recovered = store.pending_entity_sync_changes(128).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].entity_kind, EntityKind::Setting);
        let operation_id = recovered[0].operation_id.clone();
        store.ensure_setting_sync_changes(3_001).unwrap();
        let unchanged = store.pending_entity_sync_changes(128).unwrap();
        assert_eq!(unchanged.len(), 1);
        assert_eq!(unchanged[0].operation_id, operation_id);
    }

    #[test]
    fn script_changefeed_only_contains_safe_custom_fields() {
        let root = TempDir::new("script-changefeed");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let vault_id = Uuid::new_v4().to_string();
        acknowledge_initial_host(&store, &vault_id);

        let safe_id = Uuid::new_v4().to_string();
        let unsafe_id = Uuid::new_v4().to_string();
        let mut state: Value = serde_json::from_str(&fixture()).unwrap();
        state["scripts"] = serde_json::json!([
            {
                "id": safe_id,
                "title": "Public audit",
                "description": "local description",
                "category": "local category",
                "command": "printf 'ok\\n'",
                "sourceUrl": "https://example.invalid/audit.sh",
                "risk": "medium",
                "custom": true,
                "parameters": ["TARGET"]
            },
            {
                "id": unsafe_id,
                "title": "Private helper",
                "description": "local only",
                "category": "local category",
                "command": "curl --token hidden",
                "sourceUrl": "",
                "risk": "high",
                "custom": true
            },
            {
                "id": "built-in",
                "title": "Built in",
                "description": "product asset",
                "category": "built in",
                "command": "echo built-in",
                "sourceUrl": "",
                "risk": "low"
            }
        ]);
        store
            .save(SaveAppStateRequest {
                state_json: state.to_string(),
                expected_revision: 1,
            })
            .unwrap();
        let changes = store.pending_entity_sync_changes(128).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].entity_kind, EntityKind::Script);
        let LocalEntityMutation::Patch(fields) = &changes[0].mutation else {
            panic!("safe custom script must be a patch");
        };
        assert_eq!(fields["name"], FieldValue::Text("Public audit".into()));
        assert_eq!(fields["risk"], FieldValue::Text("caution".into()));
        assert_eq!(
            fields["parameters"],
            FieldValue::TextList(vec!["TARGET".into()])
        );
        assert!(!fields.contains_key("description"));
        assert!(!fields.contains_key("category"));
        assert!(!serde_json::to_string(fields).unwrap().contains("hidden"));

        let entity_id = changes[0].entity_id.clone();
        store
            .acknowledge_entity_sync_change(&vault_id, &changes[0].operation_id)
            .unwrap();
        state["scripts"][0]["command"] = Value::String("curl --token newly-private".into());
        store
            .save(SaveAppStateRequest {
                state_json: state.to_string(),
                expected_revision: 2,
            })
            .unwrap();
        let changes = store.pending_entity_sync_changes(128).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].entity_id, entity_id);
        assert_eq!(changes[0].mutation, LocalEntityMutation::Delete);
    }

    #[test]
    fn remote_script_projection_preserves_local_metadata_and_protected_scripts() {
        let root = TempDir::new("script-projection");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let vault_id = Uuid::new_v4().to_string();
        acknowledge_initial_host(&store, &vault_id);
        let safe_id = Uuid::new_v4().to_string();
        let protected_id = Uuid::new_v4().to_string();
        let former_custom_id = Uuid::new_v4().to_string();
        let mut state: Value = serde_json::from_str(&fixture()).unwrap();
        state["scripts"] = serde_json::json!([
            {
                "id": safe_id,
                "title": "Local name",
                "description": "keep description",
                "category": "keep category",
                "command": "echo local",
                "sourceUrl": "",
                "risk": "destructive",
                "custom": true
            },
            {
                "id": protected_id,
                "title": "Protected",
                "description": "local only",
                "category": "private",
                "command": "curl --token hidden",
                "sourceUrl": "",
                "risk": "high",
                "custom": true
            },
            {
                "id": former_custom_id,
                "title": "Now built in",
                "description": "product asset",
                "category": "built in",
                "command": "echo product",
                "sourceUrl": "",
                "risk": "low",
                "custom": false
            }
        ]);
        store
            .save(SaveAppStateRequest {
                state_json: state.to_string(),
                expected_revision: 1,
            })
            .unwrap();
        let change = store
            .pending_entity_sync_changes(128)
            .unwrap()
            .into_iter()
            .find(|change| change.entity_kind == EntityKind::Script)
            .unwrap();
        let safe_entity = change.entity_id.clone();
        store
            .acknowledge_entity_sync_change(&vault_id, &change.operation_id)
            .unwrap();
        let connection = open_connection(&database_path(&root.0)).unwrap();
        let protected_entity: String = connection
            .query_row(
                "SELECT entity_id FROM app_sync_script_ids WHERE local_id = ?1",
                params![protected_id],
                |row| row.get(0),
            )
            .unwrap();
        let former_custom_entity = Uuid::new_v4().to_string();
        connection
            .execute(
                "INSERT INTO app_sync_script_ids(local_id, entity_id) VALUES (?1, ?2)",
                params![former_custom_id, former_custom_entity],
            )
            .unwrap();
        drop(connection);
        let remote_entity = Uuid::new_v4().to_string();
        let remote_fields = BTreeMap::from([
            ("name".to_string(), FieldValue::Text("Remote new".into())),
            ("body".to_string(), FieldValue::Text("echo remote".into())),
            ("source".to_string(), FieldValue::Clear),
            ("risk".to_string(), FieldValue::Text("danger".into())),
            ("parameters".to_string(), FieldValue::TextList(Vec::new())),
        ]);
        let mut safe_fields = remote_fields.clone();
        safe_fields.insert("name".to_string(), FieldValue::Text("Remote name".into()));
        safe_fields.insert("body".to_string(), FieldValue::Text("echo updated".into()));
        safe_fields.insert("risk".to_string(), FieldValue::Text("safe".into()));
        let projection = vec![
            MergedEntityProjection {
                entity_id: safe_entity,
                fields: Some(safe_fields),
            },
            MergedEntityProjection {
                entity_id: protected_entity,
                fields: None,
            },
            MergedEntityProjection {
                entity_id: former_custom_entity,
                fields: Some(remote_fields.clone()),
            },
            MergedEntityProjection {
                entity_id: remote_entity,
                fields: Some(remote_fields),
            },
        ];
        assert_eq!(
            store
                .apply_remote_script_projection(&vault_id, 5, &projection, 5_000)
                .unwrap(),
            ProjectionOutcome::Applied
        );
        let snapshot = store.snapshot().unwrap();
        let state: Value = serde_json::from_str(snapshot.state_json.as_deref().unwrap()).unwrap();
        let scripts = state["scripts"].as_array().unwrap();
        assert_eq!(scripts.len(), 4);
        assert_eq!(scripts[0]["title"], "Remote name");
        assert_eq!(scripts[0]["description"], "keep description");
        assert_eq!(scripts[0]["category"], "keep category");
        assert_eq!(scripts[0]["risk"], "destructive");
        assert_eq!(scripts[1]["command"], "curl --token hidden");
        assert_eq!(scripts[2]["title"], "Now built in");
        assert_eq!(scripts[2]["command"], "echo product");
        assert_eq!(scripts[2]["custom"], false);
        assert_eq!(scripts[3]["title"], "Remote new");
        assert_eq!(scripts[3]["risk"], "high");
        assert!(store.pending_entity_sync_changes(128).unwrap().is_empty());
        assert_eq!(
            store
                .apply_remote_script_projection(&vault_id, 5, &projection, 5_001)
                .unwrap(),
            ProjectionOutcome::Unchanged
        );
        let mut invalid = projection;
        invalid.push(MergedEntityProjection {
            entity_id: Uuid::new_v4().to_string(),
            fields: Some(BTreeMap::from([(
                "name".to_string(),
                FieldValue::Text("Incomplete".into()),
            )])),
        });
        let revision = store.snapshot().unwrap().revision;
        assert!(
            store
                .apply_remote_script_projection(&vault_id, 6, &invalid, 5_002)
                .is_err()
        );
        assert_eq!(store.snapshot().unwrap().revision, revision);
    }

    #[test]
    fn remote_setting_projection_preserves_local_asset_without_echo_and_is_atomic() {
        let root = TempDir::new("setting-projection");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let vault_id = Uuid::new_v4().to_string();
        acknowledge_initial_host(&store, &vault_id);

        let mut state: Value = serde_json::from_str(&fixture()).unwrap();
        state["terminalAppearance"]["customFontName"] =
            Value::String("device-only-font.ttf".into());
        state["settings"]["externalEditorPath"] = Value::String("device-only-editor".into());
        store
            .save(SaveAppStateRequest {
                state_json: state.to_string(),
                expected_revision: 1,
            })
            .unwrap();
        assert!(store.pending_entity_sync_changes(128).unwrap().is_empty());

        let fields = BTreeMap::from([
            (
                "fontFamily".to_string(),
                FieldValue::Text("JetBrains Mono".into()),
            ),
            ("fontSize".to_string(), FieldValue::Integer(18)),
            ("lineHeight".to_string(), FieldValue::Integer(150)),
        ]);
        let preference_fields = BTreeMap::from([
            ("autoUploadEditedFiles".to_string(), FieldValue::Flag(true)),
            (
                "packageTransfersEnabled".to_string(),
                FieldValue::Flag(false),
            ),
        ]);
        let projection = vec![
            MergedEntityProjection {
                entity_id: TERMINAL_APPEARANCE_ENTITY_ID.to_string(),
                fields: Some(fields.clone()),
            },
            MergedEntityProjection {
                entity_id: APPLICATION_PREFERENCES_ENTITY_ID.to_string(),
                fields: Some(preference_fields),
            },
        ];
        assert_eq!(
            store
                .apply_remote_setting_projection(&vault_id, 5, &projection, 5_000)
                .unwrap(),
            ProjectionOutcome::Applied
        );
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.revision, 3);
        let projected: Value =
            serde_json::from_str(snapshot.state_json.as_deref().unwrap()).unwrap();
        assert_eq!(
            projected["terminalAppearance"]["fontFamily"],
            "JetBrains Mono"
        );
        assert_eq!(projected["terminalAppearance"]["fontSize"], 18);
        assert_eq!(projected["terminalAppearance"]["lineHeight"], 1.5);
        assert_eq!(
            projected["terminalAppearance"]["customFontName"],
            "device-only-font.ttf"
        );
        assert_eq!(
            projected["settings"]["externalEditorPath"],
            "device-only-editor"
        );
        assert_eq!(projected["settings"]["autoUploadEditedFiles"], true);
        assert_eq!(projected["settings"]["packageTransfersEnabled"], false);
        assert!(store.pending_entity_sync_changes(128).unwrap().is_empty());

        store
            .save(SaveAppStateRequest {
                state_json: projected.to_string(),
                expected_revision: 3,
            })
            .unwrap();
        assert!(store.pending_entity_sync_changes(128).unwrap().is_empty());
        assert_eq!(
            store
                .apply_remote_setting_projection(&vault_id, 5, &projection, 5_001)
                .unwrap(),
            ProjectionOutcome::Unchanged
        );

        let mut invalid_fields = fields;
        invalid_fields.insert("locale".into(), FieldValue::Text("en-US".into()));
        let invalid = vec![MergedEntityProjection {
            entity_id: TERMINAL_APPEARANCE_ENTITY_ID.to_string(),
            fields: Some(invalid_fields),
        }];
        let revision = store.snapshot().unwrap().revision;
        assert!(
            store
                .apply_remote_setting_projection(&vault_id, 6, &invalid, 5_002)
                .is_err()
        );
        assert_eq!(store.snapshot().unwrap().revision, revision);

        let invalid_preference = vec![MergedEntityProjection {
            entity_id: APPLICATION_PREFERENCES_ENTITY_ID.to_string(),
            fields: Some(BTreeMap::from([
                (
                    "autoUploadEditedFiles".to_string(),
                    FieldValue::Text("true".into()),
                ),
                (
                    "packageTransfersEnabled".to_string(),
                    FieldValue::Flag(false),
                ),
            ])),
        }];
        assert!(
            store
                .apply_remote_setting_projection(&vault_id, 6, &invalid_preference, 5_003)
                .is_err()
        );
        assert_eq!(store.snapshot().unwrap().revision, revision);
    }

    #[test]
    fn remote_host_projection_preserves_local_secrets_without_echo_and_is_idempotent() {
        let root = TempDir::new("remote-projection");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let vault_id = Uuid::new_v4().to_string();
        let (entity_id, mut fields) = acknowledge_initial_host(&store, &vault_id);
        fields.insert(
            "name".to_string(),
            FieldValue::Text("Remote name".to_string()),
        );
        fields.insert(
            "address".to_string(),
            FieldValue::Text("remote.example".to_string()),
        );
        let projection = vec![MergedEntityProjection {
            entity_id,
            fields: Some(fields),
        }];
        assert_eq!(
            store
                .apply_remote_host_projection(&vault_id, 2, &projection, 2_000)
                .unwrap(),
            ProjectionOutcome::Applied
        );
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.revision, 2);
        let state: Value = serde_json::from_str(snapshot.state_json.as_deref().unwrap()).unwrap();
        assert_eq!(state["hosts"][0]["name"], "Remote name");
        assert_eq!(state["hosts"][0]["host"], "remote.example");
        assert_eq!(state["hosts"][0]["credentialRef"], "ssh-public-reference");
        assert!(store.pending_entity_sync_changes(128).unwrap().is_empty());
        assert_eq!(
            store
                .apply_remote_host_projection(&vault_id, 2, &projection, 2_001)
                .unwrap(),
            ProjectionOutcome::Unchanged
        );
        assert_eq!(store.snapshot().unwrap().revision, 2);
        let mut changed = projection.clone();
        changed[0]
            .fields
            .as_mut()
            .unwrap()
            .insert("group".to_string(), FieldValue::Text("Changed".to_string()));
        assert!(
            store
                .apply_remote_host_projection(&vault_id, 2, &changed, 2_002)
                .is_err()
        );
    }

    #[test]
    fn remote_projection_defers_for_local_changes_and_rolls_back_invalid_state() {
        let root = TempDir::new("projection-deferred");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let vault_id = Uuid::new_v4().to_string();
        store.bind_sync_vault(&vault_id).unwrap();
        let mut changes = store.pending_entity_sync_changes(128).unwrap();
        let change = changes.remove(0);
        let LocalEntityMutation::Patch(fields) = change.mutation.clone() else {
            panic!("initial host must be patch");
        };
        let projection = vec![MergedEntityProjection {
            entity_id: change.entity_id.clone(),
            fields: Some(fields),
        }];
        assert_eq!(
            store
                .apply_remote_host_projection(&vault_id, 1, &projection, 2_000)
                .unwrap(),
            ProjectionOutcome::Deferred
        );
        store
            .acknowledge_entity_sync_change(&vault_id, &change.operation_id)
            .unwrap();
        let invalid = vec![MergedEntityProjection {
            entity_id: Uuid::new_v4().to_string(),
            fields: Some(BTreeMap::from([(
                "name".to_string(),
                FieldValue::Text("Incomplete".to_string()),
            )])),
        }];
        assert!(
            store
                .apply_remote_host_projection(&vault_id, 1, &invalid, 2_001)
                .is_err()
        );
        assert_eq!(store.snapshot().unwrap().revision, 1);
        let connection = open_connection(&database_path(&root.0)).unwrap();
        let projection_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM app_sync_projection", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(projection_count, 0);
    }

    #[test]
    fn remote_projection_maps_routes_and_removes_tombstoned_hosts() {
        let root = TempDir::new("projection-route-delete");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let vault_id = Uuid::new_v4().to_string();
        let (first_entity, first_fields) = acknowledge_initial_host(&store, &vault_id);
        let second_entity = Uuid::new_v4().to_string();
        let second_fields = BTreeMap::from([
            ("name".to_string(), FieldValue::Text("Target".to_string())),
            (
                "address".to_string(),
                FieldValue::Text("target.example".to_string()),
            ),
            ("port".to_string(), FieldValue::Integer(22)),
            ("username".to_string(), FieldValue::Text("root".to_string())),
            ("group".to_string(), FieldValue::Clear),
            (
                "environment".to_string(),
                FieldValue::Text("production".to_string()),
            ),
            ("tags".to_string(), FieldValue::TextList(Vec::new())),
            (
                "jumpRoute".to_string(),
                FieldValue::TextList(vec![first_entity.clone()]),
            ),
        ]);
        let projection = vec![
            MergedEntityProjection {
                entity_id: first_entity.clone(),
                fields: Some(first_fields.clone()),
            },
            MergedEntityProjection {
                entity_id: second_entity.clone(),
                fields: Some(second_fields),
            },
        ];
        assert_eq!(
            store
                .apply_remote_host_projection(&vault_id, 2, &projection, 2_000)
                .unwrap(),
            ProjectionOutcome::Applied
        );
        let snapshot = store.snapshot().unwrap();
        let state: Value = serde_json::from_str(snapshot.state_json.as_deref().unwrap()).unwrap();
        let hosts = state["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[1]["jumpRoute"][0], hosts[0]["id"]);

        let deleted = vec![
            MergedEntityProjection {
                entity_id: first_entity,
                fields: Some(first_fields),
            },
            MergedEntityProjection {
                entity_id: second_entity,
                fields: None,
            },
        ];
        assert_eq!(
            store
                .apply_remote_host_projection(&vault_id, 3, &deleted, 2_001)
                .unwrap(),
            ProjectionOutcome::Applied
        );
        let snapshot = store.snapshot().unwrap();
        let state: Value = serde_json::from_str(snapshot.state_json.as_deref().unwrap()).unwrap();
        assert_eq!(state["hosts"].as_array().unwrap().len(), 1);
        assert!(store.pending_entity_sync_changes(128).unwrap().is_empty());
    }

    #[test]
    fn version_one_snapshot_is_backfilled_during_changefeed_migration() {
        let root = TempDir::new("sync-migration");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        drop(store);
        let connection = open_connection(&database_path(&root.0)).unwrap();
        connection
            .execute_batch(
                "DROP TABLE app_sync_changes;
                 DROP TABLE app_sync_binding;
                 DROP TABLE app_sync_host_ids;
                 DROP TABLE app_sync_script_ids;
                 DROP TABLE app_sync_projection;
                 DROP TABLE app_sync_script_projection;
                 DROP TABLE app_sync_setting_projection;
                 DROP TABLE app_sync_setting_state;
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        drop(connection);

        let migrated = AppStore::load(root.0.clone()).unwrap();
        let changes = migrated.pending_entity_sync_changes(128).unwrap();
        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0].mutation, LocalEntityMutation::Patch(_)));
        assert_eq!(
            migrated
                .initialize(InitializeAppStoreRequest {
                    legacy_state_json: None,
                })
                .unwrap()
                .revision,
            1
        );
    }

    #[test]
    fn version_three_changefeed_is_labeled_host_during_schema_upgrade() {
        let root = TempDir::new("sync-v3-migration");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        drop(store);
        let connection = open_connection(&database_path(&root.0)).unwrap();
        connection
            .execute_batch(
                "DROP INDEX idx_app_sync_changes_revision;
                 DROP INDEX idx_app_sync_changes_kind_revision;
                 ALTER TABLE app_sync_changes RENAME TO app_sync_changes_v4;
                 CREATE TABLE app_sync_changes (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT NOT NULL UNIQUE,
                    entity_id TEXT NOT NULL,
                    mutation_kind TEXT NOT NULL CHECK (mutation_kind IN ('patch', 'delete')),
                    fields_json TEXT,
                    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
                    created_at_ms INTEGER NOT NULL,
                    CHECK ((mutation_kind = 'patch') = (fields_json IS NOT NULL))
                 );
                 INSERT INTO app_sync_changes(
                    seq, operation_id, entity_id, mutation_kind, fields_json,
                    state_revision, created_at_ms
                 ) SELECT seq, operation_id, entity_id, mutation_kind, fields_json,
                          state_revision, created_at_ms
                   FROM app_sync_changes_v4;
                 DROP TABLE app_sync_changes_v4;
                 CREATE INDEX idx_app_sync_changes_revision
                    ON app_sync_changes(state_revision, seq);
                 DROP TABLE app_sync_script_ids;
                 DROP TABLE app_sync_script_projection;
                 DROP TABLE app_sync_setting_projection;
                 DROP TABLE app_sync_setting_state;
                 PRAGMA user_version = 3;",
            )
            .unwrap();
        drop(connection);

        let migrated = AppStore::load(root.0.clone()).unwrap();
        let changes = migrated.pending_entity_sync_changes(128).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].entity_kind, EntityKind::Host);
        let connection = open_connection(&database_path(&root.0)).unwrap();
        assert_eq!(current_schema(&connection).unwrap(), STORE_SCHEMA_VERSION);
        let script_table: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'app_sync_script_projection'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(script_table, 1);
    }

    #[test]
    fn version_four_changefeed_preserves_rows_and_adds_setting_contract() {
        let root = TempDir::new("sync-v4-migration");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let original = store.pending_entity_sync_changes(128).unwrap();
        assert_eq!(original.len(), 1);
        let operation_id = original[0].operation_id.clone();
        drop(store);

        let connection = open_connection(&database_path(&root.0)).unwrap();
        connection
            .execute_batch(
                "DROP INDEX idx_app_sync_changes_revision;
                 DROP INDEX idx_app_sync_changes_kind_revision;
                 ALTER TABLE app_sync_changes RENAME TO app_sync_changes_v5;
                 CREATE TABLE app_sync_changes (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT NOT NULL UNIQUE,
                    entity_id TEXT NOT NULL,
                    mutation_kind TEXT NOT NULL CHECK (mutation_kind IN ('patch', 'delete')),
                    fields_json TEXT,
                    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
                    created_at_ms INTEGER NOT NULL,
                    entity_kind TEXT NOT NULL CHECK (entity_kind IN ('host', 'script')),
                    CHECK ((mutation_kind = 'patch') = (fields_json IS NOT NULL))
                 );
                 INSERT INTO app_sync_changes(
                    seq, operation_id, entity_id, mutation_kind, fields_json,
                    state_revision, created_at_ms, entity_kind
                 ) SELECT seq, operation_id, entity_id, mutation_kind, fields_json,
                          state_revision, created_at_ms, entity_kind
                   FROM app_sync_changes_v5;
                 DROP TABLE app_sync_changes_v5;
                 CREATE INDEX idx_app_sync_changes_revision
                    ON app_sync_changes(state_revision, seq);
                 CREATE INDEX idx_app_sync_changes_kind_revision
                    ON app_sync_changes(entity_kind, state_revision, seq);
                 DROP TABLE app_sync_setting_projection;
                 DROP TABLE app_sync_setting_state;
                 PRAGMA user_version = 4;",
            )
            .unwrap();
        drop(connection);

        let migrated = AppStore::load(root.0.clone()).unwrap();
        let changes = migrated.pending_entity_sync_changes(128).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].operation_id, operation_id);
        assert_eq!(changes[0].entity_kind, EntityKind::Host);
        let connection = open_connection(&database_path(&root.0)).unwrap();
        assert_eq!(current_schema(&connection).unwrap(), STORE_SCHEMA_VERSION);
        let table_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type = 'table' AND name = 'app_sync_changes'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(table_sql.contains("'setting'"));
        let setting_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name IN (
                    'app_sync_setting_projection', 'app_sync_setting_state'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(setting_tables, 2);
    }

    #[test]
    fn version_five_snapshot_backfills_application_preferences_without_losing_changes() {
        let root = TempDir::new("sync-v5-migration");
        let store = AppStore::load(root.0.clone()).unwrap();
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let host_operation_id = store.pending_entity_sync_changes(128).unwrap()[0]
            .operation_id
            .clone();
        let mut state: Value = serde_json::from_str(&fixture()).unwrap();
        state["settings"]["autoUploadEditedFiles"] = Value::Bool(true);
        store
            .save(SaveAppStateRequest {
                state_json: state.to_string(),
                expected_revision: 1,
            })
            .unwrap();
        drop(store);

        let connection = open_connection(&database_path(&root.0)).unwrap();
        connection
            .execute(
                "DELETE FROM app_sync_changes WHERE entity_id = ?1",
                params![APPLICATION_PREFERENCES_ENTITY_ID],
            )
            .unwrap();
        connection
            .execute_batch(&format!(
                "ALTER TABLE app_sync_setting_state RENAME TO app_sync_setting_state_v6;
                 CREATE TABLE app_sync_setting_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    content_hash TEXT NOT NULL
                 );
                 INSERT INTO app_sync_setting_state(singleton, content_hash)
                    SELECT 1, content_hash FROM app_sync_setting_state_v6
                    WHERE entity_id = '{TERMINAL_APPEARANCE_ENTITY_ID}';
                 DROP TABLE app_sync_setting_state_v6;
                 PRAGMA user_version = 5;"
            ))
            .unwrap();
        drop(connection);

        let migrated = AppStore::load(root.0.clone()).unwrap();
        let changes = migrated.pending_entity_sync_changes(128).unwrap();
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].operation_id, host_operation_id);
        assert_eq!(changes[0].entity_kind, EntityKind::Host);
        assert_eq!(changes[1].entity_kind, EntityKind::Setting);
        assert_eq!(changes[1].entity_id, APPLICATION_PREFERENCES_ENTITY_ID);
        let LocalEntityMutation::Patch(fields) = &changes[1].mutation else {
            panic!("migrated application preferences must be a patch");
        };
        assert_eq!(fields["autoUploadEditedFiles"], FieldValue::Flag(true));
        assert_eq!(fields["packageTransfersEnabled"], FieldValue::Flag(true));

        let connection = open_connection(&database_path(&root.0)).unwrap();
        assert_eq!(current_schema(&connection).unwrap(), STORE_SCHEMA_VERSION);
        let setting_states: i64 = connection
            .query_row("SELECT COUNT(*) FROM app_sync_setting_state", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(setting_states, 4);
    }

    #[test]
    fn version_six_snapshot_backfills_monitor_fingerprint_or_non_default_change_once() {
        let default_root = TempDir::new("sync-v6-monitor-default");
        let default_store = AppStore::load(default_root.0.clone()).unwrap();
        default_store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        drop(default_store);
        let default_connection = open_connection(&database_path(&default_root.0)).unwrap();
        default_connection
            .execute(
                "DELETE FROM app_sync_setting_state WHERE entity_id = ?1",
                params![MONITOR_PREFERENCES_ENTITY_ID],
            )
            .unwrap();
        default_connection
            .pragma_update(None, "user_version", 6)
            .unwrap();
        drop(default_connection);
        let migrated_default = AppStore::load(default_root.0.clone()).unwrap();
        let default_changes = migrated_default.pending_entity_sync_changes(128).unwrap();
        assert_eq!(default_changes.len(), 1);
        assert_eq!(default_changes[0].entity_kind, EntityKind::Host);

        let changed_root = TempDir::new("sync-v6-monitor-changed");
        let changed_store = AppStore::load(changed_root.0.clone()).unwrap();
        changed_store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .unwrap();
        let mut changed_state: Value = serde_json::from_str(&fixture()).unwrap();
        changed_state["settings"]["monitorIntervalSeconds"] = Value::Number(30.into());
        changed_store
            .save(SaveAppStateRequest {
                state_json: changed_state.to_string(),
                expected_revision: 1,
            })
            .unwrap();
        drop(changed_store);
        let changed_connection = open_connection(&database_path(&changed_root.0)).unwrap();
        changed_connection
            .execute(
                "DELETE FROM app_sync_changes WHERE entity_id = ?1",
                params![MONITOR_PREFERENCES_ENTITY_ID],
            )
            .unwrap();
        changed_connection
            .execute(
                "DELETE FROM app_sync_setting_state WHERE entity_id = ?1",
                params![MONITOR_PREFERENCES_ENTITY_ID],
            )
            .unwrap();
        changed_connection
            .pragma_update(None, "user_version", 6)
            .unwrap();
        drop(changed_connection);

        let migrated_changed = AppStore::load(changed_root.0.clone()).unwrap();
        let changed = migrated_changed
            .pending_entity_sync_changes(128)
            .unwrap()
            .into_iter()
            .find(|change| change.entity_id == MONITOR_PREFERENCES_ENTITY_ID)
            .expect("non-default monitor preference must be backfilled");
        let LocalEntityMutation::Patch(fields) = changed.mutation else {
            panic!("migrated monitor preference must be a patch");
        };
        assert_eq!(
            fields,
            BTreeMap::from([("monitorInterval".to_string(), FieldValue::Integer(30))])
        );
    }

    #[test]
    fn corrupt_database_is_quarantined_with_bounded_backups() {
        let root = TempDir::new("corrupt");
        let path = database_path(&root.0);
        for index in 0..4 {
            fs::write(&path, format!("truncated-{index}")).expect("write corrupt database");
            AppStore::load(root.0.clone()).expect("recover corrupt database");
        }
        let prefix = corrupt_backup_prefix(&path);
        let backups = fs::read_dir(&root.0)
            .expect("read backups")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(&prefix))
            })
            .count();
        assert!(backups <= MAX_CORRUPT_BACKUPS);
        let store = AppStore::load(root.0.clone()).expect("load recovered store");
        assert_eq!(
            store
                .initialize(InitializeAppStoreRequest {
                    legacy_state_json: None
                })
                .expect("initialize")
                .revision,
            0
        );
    }

    #[test]
    fn future_schema_is_preserved_and_rejected() {
        let root = TempDir::new("future");
        let path = database_path(&root.0);
        let connection = Connection::open(&path).expect("create future database");
        connection
            .pragma_update(None, "user_version", STORE_SCHEMA_VERSION + 1)
            .expect("set future schema");
        drop(connection);
        assert!(AppStore::load(root.0.clone()).is_err());
        assert!(path.exists());
        assert!(
            !fs::read_dir(&root.0)
                .expect("read directory")
                .filter_map(Result::ok)
                .any(|entry| entry.file_name().to_string_lossy().contains(".corrupt-"))
        );
    }

    #[test]
    fn state_rejects_secret_fields_private_key_contents_and_bounds() {
        let mut android_refs: Value = serde_json::from_str(&fixture()).expect("fixture JSON");
        android_refs["hosts"][0]["androidKeyRef"] =
            Value::String(format!("key-{}", Uuid::new_v4()));
        android_refs["hosts"][0]["androidKeyPassphraseRef"] =
            Value::String(format!("key-{}", Uuid::new_v4()));
        android_refs["hosts"][0]["hostKeySha256"] =
            Value::String("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string());
        assert!(validate_state_json(&android_refs.to_string()).is_ok());

        let mut jump_route: Value = serde_json::from_str(&fixture()).expect("fixture JSON");
        jump_route["hosts"]
            .as_array_mut()
            .expect("hosts")
            .push(serde_json::json!({
                "id": "host-2", "name": "Target", "group": "Test", "host": "192.0.2.2",
                "port": 22, "username": "dev", "environment": "development", "tags": [],
                "credentialRef": "ssh-target-reference", "jumpRoute": ["host-1"]
            }));
        assert!(validate_state_json(&jump_route.to_string()).is_ok());
        jump_route["hosts"][1]["jumpRoute"] = serde_json::json!(["host-1", "host-1"]);
        assert!(validate_state_json(&jump_route.to_string()).is_err());
        jump_route["hosts"][1]["jumpRoute"] = serde_json::json!(["missing-host"]);
        assert!(validate_state_json(&jump_route.to_string()).is_err());

        let mut secret: Value = serde_json::from_str(&fixture()).expect("fixture JSON");
        secret["settings"]["password"] = Value::String("must-not-persist".to_string());
        assert!(validate_state_json(&secret.to_string()).is_err());

        let mut key: Value = serde_json::from_str(&fixture()).expect("fixture JSON");
        key["scripts"] = serde_json::json!([{"command": "-----BEGIN OPENSSH PRIVATE KEY-----"}]);
        assert!(validate_state_json(&key.to_string()).is_err());

        let mut histories: Value = serde_json::from_str(&fixture()).expect("fixture JSON");
        histories["commandHistory"] = Value::Array(vec![Value::Null; 10_001]);
        assert!(validate_state_json(&histories.to_string()).is_err());
        assert!(validate_state_json(&"x".repeat(MAX_STATE_BYTES + 1)).is_err());
    }

    #[test]
    fn retention_removes_old_and_excess_events_without_touching_snapshot() {
        let root = TempDir::new("retention");
        let store = AppStore::load(root.0.clone()).expect("load store");
        store
            .save(SaveAppStateRequest {
                state_json: fixture(),
                expected_revision: 0,
            })
            .expect("save state");
        let mut connection = open_connection(&database_path(&root.0)).expect("open database");
        let transaction = connection.transaction().expect("begin fixture transaction");
        for index in 0..(MAX_EVENTS + 5) {
            transaction.execute(
                "INSERT INTO app_events(event_id, event_kind, domains_json, created_at_ms) VALUES (?1, 'fixture', '[]', ?2)",
                params![format!("event-{index}"), epoch_ms() - EVENT_RETENTION_MS - index],
            ).expect("insert fixture event");
        }
        let retained = prune_events(&transaction, epoch_ms()).expect("prune events");
        transaction.commit().expect("commit pruning");
        assert!(retained <= MAX_EVENTS as u64);
        assert_eq!(
            store
                .initialize(InitializeAppStoreRequest {
                    legacy_state_json: None
                })
                .expect("load snapshot")
                .revision,
            1
        );
    }
}

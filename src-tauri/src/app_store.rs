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
use uuid::Uuid;

use crate::sync_merge::{FieldValue, LocalHostMutation};

const STORE_SCHEMA_VERSION: i64 = 2;
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

#[derive(Debug, Serialize)]
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
pub(crate) struct PendingHostSyncChange {
    pub(crate) operation_id: String,
    pub(crate) entity_id: String,
    pub(crate) mutation: LocalHostMutation,
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
                    CHECK ((mutation_kind = 'patch') = (fields_json IS NOT NULL))
                );
                CREATE INDEX IF NOT EXISTS idx_app_sync_changes_revision
                    ON app_sync_changes(state_revision, seq);
                CREATE TABLE IF NOT EXISTS app_sync_binding (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    vault_id TEXT NOT NULL
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
            }
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
                    operation_id, entity_id, mutation_kind, fields_json, state_revision, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
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

    pub(crate) fn pending_host_sync_changes(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingHostSyncChange>, String> {
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
                "SELECT operation_id, entity_id, mutation_kind, fields_json
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
                ))
            })
            .map_err(|error| format!("无法读取 AppState 同步 changefeed: {error}"))?;
        let mut changes = Vec::new();
        for row in rows {
            let (operation_id, entity_id, kind, fields_json) =
                row.map_err(|error| format!("AppState 同步 changefeed 损坏: {error}"))?;
            let mutation = match (kind.as_str(), fields_json) {
                ("patch", Some(fields)) => LocalHostMutation::Patch(
                    serde_json::from_str(&fields)
                        .map_err(|_| "AppState 同步 patch 损坏".to_string())?,
                ),
                ("delete", None) => LocalHostMutation::Delete,
                _ => return Err("AppState 同步 changefeed 类型损坏".to_string()),
            };
            changes.push(PendingHostSyncChange {
                operation_id,
                entity_id,
                mutation,
            });
        }
        Ok(changes)
    }

    pub(crate) fn pending_host_sync_change_count(&self) -> Result<u64, String> {
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

    pub(crate) fn acknowledge_host_sync_change(
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
            "terminalAppearance": {"fontFamily": "monospace", "fontSize": 13, "lineHeight": 1.25},
            "settings": {"externalEditorPath": "", "autoUploadEditedFiles": false},
            "onboardingCompleted": true
        }).to_string()
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
            .pending_host_sync_changes(128)
            .expect("read initial changefeed");
        assert_eq!(initial.len(), 1);
        let LocalHostMutation::Patch(fields) = &initial[0].mutation else {
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
        assert_eq!(store.pending_host_sync_changes(128).unwrap().len(), 1);

        let mut deleted = credential_only;
        deleted["hosts"] = Value::Array(Vec::new());
        store
            .save(SaveAppStateRequest {
                state_json: deleted.to_string(),
                expected_revision: 2,
            })
            .expect("delete host");
        let changes = store.pending_host_sync_changes(128).unwrap();
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].entity_id, changes[1].entity_id);
        assert_eq!(changes[1].mutation, LocalHostMutation::Delete);

        let vault = Uuid::new_v4().to_string();
        store.bind_sync_vault(&vault).unwrap();
        assert!(store.bind_sync_vault(&Uuid::new_v4().to_string()).is_err());
        store
            .acknowledge_host_sync_change(&vault, &changes[0].operation_id)
            .unwrap();
        assert_eq!(store.pending_host_sync_changes(128).unwrap().len(), 1);
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
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        drop(connection);

        let migrated = AppStore::load(root.0.clone()).unwrap();
        let changes = migrated.pending_host_sync_changes(128).unwrap();
        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0].mutation, LocalHostMutation::Patch(_)));
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

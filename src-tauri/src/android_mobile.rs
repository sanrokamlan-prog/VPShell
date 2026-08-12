//! Tauri IPC surface for the Android Preview.
//!
//! Mobile commands are deliberately separate from the desktop OpenSSH PTY
//! commands.  The WebView sends only bounded metadata and opaque keyring
//! references; AndroidNativeAuth is created inside Rust and is never returned,
//! logged, or persisted.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use base64::{Engine, prelude::BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    android_native_transport::{
        AndroidHostKeyInspection, AndroidNativeAuth, AndroidNativeConnectionConfig,
        AndroidNativeSession, AndroidRemoteEntry, AndroidTerminalChannel,
    },
    android_preview::{
        AndroidHostRequest, AndroidLifecycle, AndroidPreviewManifest, AndroidPreviewOperation,
        AndroidPreviewRuntime,
    },
    file_transfer,
};

const MAX_DECODED_INPUT_BYTES: usize = 64 * 1024;
const MAX_PASSWORD_BYTES: usize = 16 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 1024 * 1024;

#[derive(Default)]
pub(crate) struct AndroidMobileManager {
    inner: Mutex<AndroidMobileState>,
}

struct AndroidMobileState {
    runtime: AndroidPreviewRuntime,
    sessions: HashMap<Uuid, Arc<Mutex<AndroidMobileSession>>>,
}

struct AndroidMobileSession {
    connection: AndroidNativeSession,
    terminals: HashMap<Uuid, AndroidTerminalChannel>,
}

impl Default for AndroidMobileState {
    fn default() -> Self {
        Self {
            runtime: AndroidPreviewRuntime::default(),
            sessions: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AndroidPreviewStatus {
    pub manifest: AndroidPreviewManifest,
    pub lifecycle: AndroidLifecycle,
    pub generation: u64,
    pub session_count: usize,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AndroidTerminalRequest {
    pub session_id: String,
    pub terminal_id: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AndroidTerminalSizeRequest {
    pub session_id: String,
    pub terminal_id: String,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AndroidTerminalInputRequest {
    pub session_id: String,
    pub terminal_id: String,
    pub data_base64: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AndroidTerminalOutput {
    pub data_base64: String,
    pub eof: bool,
}

#[derive(Clone, Copy, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum AndroidCredentialKind {
    Password,
    PrivateKey,
    PrivateKeyPassphrase,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AndroidStoreCredentialRequest {
    pub kind: AndroidCredentialKind,
    pub value: String,
}

fn lock_manager(
    manager: &AndroidMobileManager,
) -> Result<std::sync::MutexGuard<'_, AndroidMobileState>, String> {
    manager
        .inner
        .lock()
        .map_err(|_| "Android Preview 会话状态已损坏".to_string())
}

fn parse_uuid(value: &str, label: &str) -> Result<Uuid, String> {
    Uuid::parse_str(value).map_err(|_| format!("Android {label} ID 格式无效"))
}

fn get_session(
    manager: &AndroidMobileManager,
    session_id: Uuid,
    operation: AndroidPreviewOperation,
) -> Result<Arc<Mutex<AndroidMobileSession>>, String> {
    let state = lock_manager(manager)?;
    state.runtime.authorize(operation)?;
    state
        .sessions
        .get(&session_id)
        .cloned()
        .ok_or_else(|| "Android SSH 会话不存在或已断开".to_string())
}

fn lock_session(
    session: &Arc<Mutex<AndroidMobileSession>>,
) -> Result<std::sync::MutexGuard<'_, AndroidMobileSession>, String> {
    session
        .lock()
        .map_err(|_| "Android SSH 会话状态已损坏".to_string())
}

fn resolve_auth(request: &AndroidHostRequest) -> Result<AndroidNativeAuth, String> {
    let secret =
        file_transfer::read_secret(&request.credential_ref, "Android 凭据引用不存在或无法读取")?;
    match request.auth_kind {
        crate::android_preview::AndroidAuthKind::PasswordReference => {
            Ok(AndroidNativeAuth::password(secret.to_string()))
        }
        crate::android_preview::AndroidAuthKind::PrivateKeyReference => {
            let passphrase = request
                .passphrase_ref
                .as_deref()
                .map(|reference| {
                    file_transfer::read_secret(reference, "Android 私钥口令引用不存在")
                })
                .transpose()?;
            AndroidNativeAuth::private_key(
                None,
                secret.to_string(),
                passphrase.map(|value| value.to_string()),
            )
        }
    }
}

fn validate_credential_value(
    request: &AndroidStoreCredentialRequest,
) -> Result<&'static str, String> {
    if request.value.is_empty() || request.value.contains('\0') {
        return Err("Android 凭据不能为空或包含 NUL".to_string());
    }
    match request.kind {
        AndroidCredentialKind::Password => {
            if request.value.len() > MAX_PASSWORD_BYTES {
                return Err("Android 密码超过大小上限".to_string());
            }
            Ok("ssh-")
        }
        AndroidCredentialKind::PrivateKey => {
            if request.value.len() > MAX_PRIVATE_KEY_BYTES
                || !request.value.contains("-----BEGIN ")
                || request
                    .value
                    .chars()
                    .any(|ch| ch.is_control() && ch != '\n' && ch != '\r')
            {
                return Err("Android 私钥格式或大小无效".to_string());
            }
            Ok("key-")
        }
        AndroidCredentialKind::PrivateKeyPassphrase => {
            if request.value.len() > MAX_PASSWORD_BYTES {
                return Err("Android 私钥口令超过大小上限".to_string());
            }
            Ok("key-")
        }
    }
}

#[tauri::command]
pub(crate) fn android_store_credential(
    request: AndroidStoreCredentialRequest,
) -> Result<String, String> {
    let prefix = validate_credential_value(&request)?;
    let reference = format!("{prefix}{}", Uuid::new_v4());
    keyring::Entry::new(crate::CREDENTIAL_SERVICE, &reference)
        .and_then(|entry| entry.set_password(&request.value))
        .map_err(|_| "Android Keystore 凭据写入失败".to_string())?;
    Ok(reference)
}

#[tauri::command]
pub(crate) fn android_delete_credential(reference: String) -> Result<(), String> {
    let prefix = if reference.starts_with("ssh-") {
        "ssh-"
    } else if reference.starts_with("key-") {
        "key-"
    } else {
        return Err("Android 凭据引用格式无效".to_string());
    };
    file_transfer::validate_optional_reference(Some(&reference), prefix)?;
    match keyring::Entry::new(crate::CREDENTIAL_SERVICE, &reference)
        .and_then(|entry| entry.delete_credential())
    {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err("Android Keystore 凭据删除失败".to_string()),
    }
}

#[tauri::command]
pub(crate) fn android_preview_status(
    manager: tauri::State<'_, AndroidMobileManager>,
) -> Result<AndroidPreviewStatus, String> {
    let state = lock_manager(&manager)?;
    Ok(AndroidPreviewStatus {
        manifest: state.runtime.manifest().clone(),
        lifecycle: state.runtime.lifecycle(),
        generation: state.runtime.generation(),
        session_count: state.sessions.len(),
    })
}

#[tauri::command]
pub(crate) fn android_inspect_host_key(
    host: String,
    port: u16,
    timeout_seconds: u16,
) -> Result<AndroidHostKeyInspection, String> {
    crate::android_native_transport::inspect_host_key(&host, port, timeout_seconds)
}

#[tauri::command]
pub(crate) fn android_set_lifecycle(
    manager: tauri::State<'_, AndroidMobileManager>,
    lifecycle: AndroidLifecycle,
) -> Result<AndroidPreviewStatus, String> {
    let mut state = lock_manager(&manager)?;
    state.runtime.set_lifecycle(lifecycle);
    if lifecycle != AndroidLifecycle::Foreground {
        state.sessions.clear();
    }
    Ok(AndroidPreviewStatus {
        manifest: state.runtime.manifest().clone(),
        lifecycle: state.runtime.lifecycle(),
        generation: state.runtime.generation(),
        session_count: state.sessions.len(),
    })
}

#[tauri::command]
pub(crate) fn android_connect_host(
    manager: tauri::State<'_, AndroidMobileManager>,
    request: AndroidHostRequest,
) -> Result<String, String> {
    let session_id = request.validate()?;
    {
        let mut state = lock_manager(&manager)?;
        state.runtime.open_session(&request)?;
    }
    let connection = (|| {
        let auth = resolve_auth(&request)?;
        let config = AndroidNativeConnectionConfig {
            host: request.host.clone(),
            port: request.port,
            username: request.username.clone(),
            host_key_sha256: request.host_key_sha256.clone(),
            timeout_seconds: request.timeout_seconds,
        };
        AndroidNativeSession::connect(&config, &auth)
    })();
    let connection = match connection {
        Ok(connection) => connection,
        Err(error) => {
            if let Ok(mut state) = lock_manager(&manager) {
                state.runtime.close_session(session_id);
            }
            return Err(error);
        }
    };
    let mut state = lock_manager(&manager)?;
    if state
        .runtime
        .authorize(AndroidPreviewOperation::Connect)
        .is_err()
        || !state.runtime.has_session(session_id)
    {
        state.runtime.close_session(session_id);
        return Err("Android 生命周期已变化，连接结果已丢弃".to_string());
    }
    state.sessions.insert(
        session_id,
        Arc::new(Mutex::new(AndroidMobileSession {
            connection,
            terminals: HashMap::new(),
        })),
    );
    Ok(session_id.to_string())
}

#[tauri::command]
pub(crate) fn android_disconnect_host(
    manager: tauri::State<'_, AndroidMobileManager>,
    session_id: String,
) -> Result<(), String> {
    let session_id = parse_uuid(&session_id, "会话")?;
    let mut state = lock_manager(&manager)?;
    state.sessions.remove(&session_id);
    state.runtime.close_session(session_id);
    Ok(())
}

#[tauri::command]
pub(crate) fn android_list_remote_files(
    manager: tauri::State<'_, AndroidMobileManager>,
    session_id: String,
    path: String,
) -> Result<Vec<AndroidRemoteEntry>, String> {
    let session_id = parse_uuid(&session_id, "会话")?;
    let session = get_session(&manager, session_id, AndroidPreviewOperation::Sftp)?;
    let session = lock_session(&session)?;
    session.connection.list_directory(&path)
}

#[tauri::command]
pub(crate) fn android_open_terminal(
    manager: tauri::State<'_, AndroidMobileManager>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<String, String> {
    let session_id = parse_uuid(&session_id, "会话")?;
    let session = get_session(&manager, session_id, AndroidPreviewOperation::Terminal)?;
    let mut session = lock_session(&session)?;
    let terminal_id = Uuid::new_v4();
    let terminal = session.connection.open_terminal(cols, rows)?;
    session.terminals.insert(terminal_id, terminal);
    Ok(terminal_id.to_string())
}

#[tauri::command]
pub(crate) fn android_write_terminal(
    manager: tauri::State<'_, AndroidMobileManager>,
    request: AndroidTerminalInputRequest,
) -> Result<(), String> {
    let session_id = parse_uuid(&request.session_id, "会话")?;
    let terminal_id = parse_uuid(&request.terminal_id, "终端")?;
    let data = BASE64_STANDARD
        .decode(request.data_base64.as_bytes())
        .map_err(|_| "Android 终端输入不是有效的 base64".to_string())?;
    if data.is_empty() || data.len() > MAX_DECODED_INPUT_BYTES {
        return Err("Android 终端输入大小超出范围".to_string());
    }
    let session = get_session(&manager, session_id, AndroidPreviewOperation::Terminal)?;
    let mut session = lock_session(&session)?;
    let terminal = session
        .terminals
        .get_mut(&terminal_id)
        .ok_or_else(|| "Android 终端不存在或已关闭".to_string())?;
    terminal.write_input(&data)
}

#[tauri::command]
pub(crate) fn android_read_terminal(
    manager: tauri::State<'_, AndroidMobileManager>,
    request: AndroidTerminalRequest,
) -> Result<AndroidTerminalOutput, String> {
    let session_id = parse_uuid(&request.session_id, "会话")?;
    let terminal_id = parse_uuid(&request.terminal_id, "终端")?;
    let session = get_session(&manager, session_id, AndroidPreviewOperation::Terminal)?;
    let mut session = lock_session(&session)?;
    let terminal = session
        .terminals
        .get_mut(&terminal_id)
        .ok_or_else(|| "Android 终端不存在或已关闭".to_string())?;
    let output = terminal.read_output()?;
    Ok(AndroidTerminalOutput {
        data_base64: BASE64_STANDARD.encode(output.data),
        eof: output.eof,
    })
}

#[tauri::command]
pub(crate) fn android_resize_terminal(
    manager: tauri::State<'_, AndroidMobileManager>,
    request: AndroidTerminalSizeRequest,
) -> Result<(), String> {
    let session_id = parse_uuid(&request.session_id, "会话")?;
    let terminal_id = parse_uuid(&request.terminal_id, "终端")?;
    let session = get_session(&manager, session_id, AndroidPreviewOperation::Terminal)?;
    let mut session = lock_session(&session)?;
    let terminal = session
        .terminals
        .get_mut(&terminal_id)
        .ok_or_else(|| "Android 终端不存在或已关闭".to_string())?;
    terminal.resize(request.cols, request.rows)
}

#[tauri::command]
pub(crate) fn android_close_terminal(
    manager: tauri::State<'_, AndroidMobileManager>,
    request: AndroidTerminalRequest,
) -> Result<(), String> {
    let session_id = parse_uuid(&request.session_id, "会话")?;
    let terminal_id = parse_uuid(&request.terminal_id, "终端")?;
    let session = get_session(&manager, session_id, AndroidPreviewOperation::Terminal)?;
    let mut session = lock_session(&session)?;
    let terminal = session
        .terminals
        .remove(&terminal_id)
        .ok_or_else(|| "Android 终端不存在或已关闭".to_string())?;
    terminal.close()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_input_is_decoded_with_a_hard_limit() {
        let encoded = BASE64_STANDARD.encode(vec![1_u8; MAX_DECODED_INPUT_BYTES]);
        assert_eq!(
            BASE64_STANDARD.decode(encoded).unwrap().len(),
            MAX_DECODED_INPUT_BYTES
        );
        let too_large = BASE64_STANDARD.encode(vec![1_u8; MAX_DECODED_INPUT_BYTES + 1]);
        assert!(BASE64_STANDARD.decode(too_large).unwrap().len() > MAX_DECODED_INPUT_BYTES);
    }

    #[test]
    fn credential_inputs_are_typed_bounded_and_not_serializable() {
        let password = AndroidStoreCredentialRequest {
            kind: AndroidCredentialKind::Password,
            value: "synthetic-password".to_string(),
        };
        assert_eq!(validate_credential_value(&password).unwrap(), "ssh-");
        let key = AndroidStoreCredentialRequest {
            kind: AndroidCredentialKind::PrivateKey,
            value:
                "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic\n-----END OPENSSH PRIVATE KEY-----"
                    .to_string(),
        };
        assert_eq!(validate_credential_value(&key).unwrap(), "key-");
        let oversized = AndroidStoreCredentialRequest {
            kind: AndroidCredentialKind::Password,
            value: "x".repeat(MAX_PASSWORD_BYTES + 1),
        };
        assert!(validate_credential_value(&oversized).is_err());
    }
}

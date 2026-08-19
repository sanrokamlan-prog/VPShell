use std::{
    collections::HashMap,
    env,
    io::{Read, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use base64::prelude::*;
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager, State};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tokio::sync::mpsc;

mod android_mobile;
#[allow(dead_code)] // The Android shell consumes the Rust-owned SSH/SFTP transport boundary.
mod android_native_transport;
#[allow(dead_code)] // The Android shell consumes this shared preview policy and lifecycle model.
mod android_preview;
mod app_store;
mod external_editor;
mod file_transfer;
mod finalshell;
mod key_management;
mod local_assets;
mod migration;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod native_engine;
mod network_tools;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod relay;
mod remote_file_ops;
mod remote_monitor;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod route_measurement;
mod safe_broadcast;
mod security_regression;
mod shell_integration;
mod sync_coordinator;
mod sync_blob;
#[allow(dead_code)] // The coordinator/UI phases consume this opt-in credential vault API.
mod sync_credential_vault;
#[allow(dead_code)] // The coordinator/provider phases consume this bounded crypto API.
mod sync_crypto;
#[allow(dead_code)] // The sync coordinator/UI phases consume the deterministic merge model.
mod sync_merge;
#[allow(dead_code)] // The merge/coordinator phases consume the durable sync journal.
mod sync_outbox;
#[allow(dead_code)] // Cross-module protocol compatibility and failure fixtures.
mod sync_protocol_regression;
#[allow(dead_code)] // The outbox/coordinator phases consume the provider boundary.
mod sync_provider;
mod sync_provider_ca;
mod sync_provider_credentials;
#[allow(dead_code)] // Provider coordination selects these structured backend adapters.
mod sync_provider_ext;
#[allow(dead_code)] // The coordinator/UI phases consume recovery and encrypted export APIs.
mod sync_recovery;
mod sync_scheduler;
mod transfer_manager;

pub(crate) const CREDENTIAL_SERVICE: &str = "com.sanro.vpshell.credentials";
pub(crate) const LEGACY_CREDENTIAL_SERVICE: &str = "com.sanro.opsshell.credentials";
const ASKPASS_MODE_ENV: &str = "VPSHELL_SSH_ASKPASS";
const ASKPASS_PASSWORD_REF_ENV: &str = "VPSHELL_SSH_CREDENTIAL_REF";
const ASKPASS_KEY_REF_ENV: &str = "VPSHELL_SSH_KEY_PASSPHRASE_REF";
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const NATIVE_TERMINAL_ACK_QUEUE: usize = 8;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const NATIVE_TERMINAL_ACK_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const NATIVE_TERMINAL_REDELIVERY_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(target_os = "android")]
fn initialize_android_keyring() -> Result<(), String> {
    let store = android_native_keyring_store::Store::new()
        .map_err(|_| "无法初始化 Android Keystore 凭据存储".to_string())?;
    keyring_core::set_default_store(store);
    Ok(())
}

struct TerminalHandle {
    transport: TerminalTransport,
    integration: Arc<Mutex<shell_integration::ShellIntegrationParser>>,
    generation: u64,
}

enum TerminalTransport {
    SystemPty {
        writer: Box<dyn Write + Send>,
        master: Box<dyn MasterPty + Send>,
        killer: Box<dyn ChildKiller + Send + Sync>,
    },
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    Native {
        handle: native_engine::NativeTerminalHandle,
        acknowledgements: mpsc::Sender<u32>,
        pending_delivery: Arc<AtomicU64>,
    },
}

#[derive(Default)]
struct TerminalManager {
    sessions: Arc<Mutex<HashMap<String, TerminalHandle>>>,
    next_generation: AtomicU64,
}

const OPENSSH_ENGINE_NAME: &str = "openssh";
const MOSH_ENGINE_NAME: &str = "mosh";
const MIN_TERMINAL_CELLS: u16 = 2;
const MAX_TERMINAL_CELLS: u16 = 1000;
const MAX_SSH_HOST_BYTES: usize = 253;
const MAX_SSH_USERNAME_BYTES: usize = 128;
const MAX_SSH_IDENTITY_PATH_BYTES: usize = 4096;
const MOSH_UDP_PORT_START: u16 = 60_000;
const MOSH_UDP_PORT_END: u16 = 61_000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartSshRequest {
    session_id: Option<String>,
    host: String,
    port: u16,
    username: String,
    identity_file: Option<String>,
    credential_ref: Option<String>,
    identity_passphrase_ref: Option<String>,
    cols: Option<u16>,
    rows: Option<u16>,
}

struct ValidatedStartSshRequest {
    session_id: String,
    host: String,
    port: u16,
    username: String,
    identity_file: Option<String>,
    credential_ref: Option<String>,
    identity_passphrase_ref: Option<String>,
    cols: u16,
    rows: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartMoshRequest {
    session_id: Option<String>,
    host: String,
    port: u16,
    username: String,
    identity_file: Option<String>,
    credential_ref: Option<String>,
    identity_passphrase_ref: Option<String>,
    cols: Option<u16>,
    rows: Option<u16>,
    udp_port_start: u16,
    udp_port_end: u16,
}

struct ValidatedStartMoshRequest {
    ssh: ValidatedStartSshRequest,
    udp_port_start: u16,
    udp_port_end: u16,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemTerminalStartResponse {
    schema_version: u16,
    engine: &'static str,
    session_id: String,
    connection: app_store::AuthenticatedConnectionRecord,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeTerminalStartResponse {
    schema_version: u16,
    engine: &'static str,
    session_id: String,
    connection: app_store::AuthenticatedConnectionRecord,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalOutputEvent {
    session_id: String,
    data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery_id: Option<u32>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalExitEvent {
    session_id: String,
    message: Option<String>,
}

fn lock_sessions(
    manager: &TerminalManager,
) -> Result<std::sync::MutexGuard<'_, HashMap<String, TerminalHandle>>, String> {
    manager
        .sessions
        .lock()
        .map_err(|_| "终端会话状态已损坏".to_string())
}

fn next_terminal_generation(manager: &TerminalManager) -> Result<u64, String> {
    manager
        .next_generation
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            current.checked_add(1)
        })
        .map(|previous| previous + 1)
        .map_err(|_| "终端会话代际已耗尽".to_string())
}

fn select_askpass_reference<'a>(
    prompt: &str,
    credential_ref: Option<&'a str>,
    key_passphrase_ref: Option<&'a str>,
) -> Option<&'a str> {
    let prompt = prompt.to_ascii_lowercase();
    if prompt.contains("passphrase") {
        key_passphrase_ref
    } else if prompt.contains("password") {
        credential_ref
    } else {
        // Unknown confirmation prompts, including host-key prompts, must not receive a secret.
        None
    }
}

pub(crate) fn configure_process_ssh_askpass(
    command: &mut std::process::Command,
    credential_ref: Option<&str>,
    key_passphrase_ref: Option<&str>,
) -> Result<(), String> {
    if credential_ref.is_none() && key_passphrase_ref.is_none() {
        return Ok(());
    }

    file_transfer::validate_optional_reference(credential_ref, "ssh-")?;
    file_transfer::validate_optional_reference(key_passphrase_ref, "key-")?;
    let executable =
        env::current_exe().map_err(|error| format!("无法定位 VPShell AskPass 助手: {error}"))?;
    command.env("SSH_ASKPASS", executable);
    command.env("SSH_ASKPASS_REQUIRE", "force");
    command.env(ASKPASS_MODE_ENV, "1");
    if env::var_os("DISPLAY").is_none() {
        command.env("DISPLAY", "vpshell");
    }
    if let Some(reference) = credential_ref {
        command.env(ASKPASS_PASSWORD_REF_ENV, reference);
    }
    if let Some(reference) = key_passphrase_ref {
        command.env(ASKPASS_KEY_REF_ENV, reference);
    }
    command.arg("-o").arg("NumberOfPasswordPrompts=1");
    Ok(())
}

fn configure_ssh_askpass(
    command: &mut CommandBuilder,
    credential_ref: Option<&str>,
    key_passphrase_ref: Option<&str>,
) -> Result<(), String> {
    if credential_ref.is_none() && key_passphrase_ref.is_none() {
        return Ok(());
    }

    file_transfer::validate_optional_reference(credential_ref, "ssh-")?;
    file_transfer::validate_optional_reference(key_passphrase_ref, "key-")?;
    let executable =
        env::current_exe().map_err(|error| format!("无法定位 VPShell AskPass 助手: {error}"))?;
    command.env("SSH_ASKPASS", executable);
    command.env("SSH_ASKPASS_REQUIRE", "force");
    command.env(ASKPASS_MODE_ENV, "1");
    if env::var_os("DISPLAY").is_none() {
        command.env("DISPLAY", "vpshell");
    }
    if let Some(reference) = credential_ref {
        command.env(ASKPASS_PASSWORD_REF_ENV, reference);
    }
    if let Some(reference) = key_passphrase_ref {
        command.env(ASKPASS_KEY_REF_ENV, reference);
    }
    Ok(())
}

impl TryFrom<StartSshRequest> for ValidatedStartSshRequest {
    type Error = String;

    fn try_from(request: StartSshRequest) -> Result<Self, Self::Error> {
        if request.host.is_empty()
            || request.host.len() > MAX_SSH_HOST_BYTES
            || request.host.starts_with('-')
            || request.host.contains('/')
            || request.host.contains('\\')
            || request
                .host
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err("主机地址格式无效".to_string());
        }
        if request.username.is_empty()
            || request.username.len() > MAX_SSH_USERNAME_BYTES
            || request.username.starts_with('-')
            || request.username.contains('@')
            || request
                .username
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err("SSH 用户名格式无效".to_string());
        }
        if request.port == 0 {
            return Err("SSH 端口无效".to_string());
        }
        let cols = request.cols.unwrap_or(120);
        let rows = request.rows.unwrap_or(32);
        if !(MIN_TERMINAL_CELLS..=MAX_TERMINAL_CELLS).contains(&cols)
            || !(MIN_TERMINAL_CELLS..=MAX_TERMINAL_CELLS).contains(&rows)
        {
            return Err("终端行列必须在 2 到 1000 之间".to_string());
        }
        let session_id = match request.session_id {
            Some(value) => {
                let parsed =
                    uuid::Uuid::parse_str(&value).map_err(|_| "终端会话标识无效".to_string())?;
                if value.len() != 36 || parsed.to_string() != value {
                    return Err("终端会话标识无效".to_string());
                }
                value
            }
            None => uuid::Uuid::new_v4().to_string(),
        };
        let identity_file = request
            .identity_file
            .filter(|value| !value.trim().is_empty());
        if identity_file.as_ref().is_some_and(|value| {
            value.len() > MAX_SSH_IDENTITY_PATH_BYTES || value.chars().any(char::is_control)
        }) {
            return Err("SSH 私钥路径无效".to_string());
        }
        if request.identity_passphrase_ref.is_some() && identity_file.is_none() {
            return Err("未选择私钥时不能提供私钥口令引用".to_string());
        }
        file_transfer::validate_optional_reference(request.credential_ref.as_deref(), "ssh-")?;
        file_transfer::validate_optional_reference(
            request.identity_passphrase_ref.as_deref(),
            "key-",
        )?;

        Ok(Self {
            session_id,
            host: request.host,
            port: request.port,
            username: request.username,
            identity_file,
            credential_ref: request.credential_ref,
            identity_passphrase_ref: request.identity_passphrase_ref,
            cols,
            rows,
        })
    }
}

impl TryFrom<StartMoshRequest> for ValidatedStartMoshRequest {
    type Error = String;

    fn try_from(request: StartMoshRequest) -> Result<Self, Self::Error> {
        if request.udp_port_start != MOSH_UDP_PORT_START
            || request.udp_port_end != MOSH_UDP_PORT_END
        {
            return Err("Mosh UDP 端口范围必须为 60000 到 61000".to_string());
        }
        let ssh = ValidatedStartSshRequest::try_from(StartSshRequest {
            session_id: request.session_id,
            host: request.host,
            port: request.port,
            username: request.username,
            identity_file: request.identity_file,
            credential_ref: request.credential_ref,
            identity_passphrase_ref: request.identity_passphrase_ref,
            cols: request.cols,
            rows: request.rows,
        })?;
        if !ssh.host.bytes().all(is_safe_mosh_host_byte)
            || !ssh.username.bytes().all(is_safe_mosh_username_byte)
        {
            return Err("Mosh 主机地址或用户名包含不安全字符".to_string());
        }
        if ssh
            .identity_file
            .as_deref()
            .is_some_and(|path| !path.bytes().all(is_safe_mosh_ssh_byte))
        {
            return Err("Mosh 私钥路径只能包含 ASCII 字母、数字及安全路径字符".to_string());
        }
        Ok(Self {
            ssh,
            udp_port_start: request.udp_port_start,
            udp_port_end: request.udp_port_end,
        })
    }
}

fn is_safe_mosh_host_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'[' | b']' | b'%')
}

fn is_safe_mosh_username_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+')
}

fn is_safe_mosh_ssh_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_' | b'.' | b'/' | b':' | b',' | b'=' | b'@' | b'+'
        )
}

fn openssh_policy_arguments(request: &ValidatedStartSshRequest, kex: &str) -> Vec<String> {
    let mut arguments = vec![
        "-o".to_string(),
        "ServerAliveInterval=30".to_string(),
        "-o".to_string(),
        "ServerAliveCountMax=3".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=yes".to_string(),
        "-o".to_string(),
        format!("KexAlgorithms={kex}"),
        "-p".to_string(),
        request.port.to_string(),
    ];
    if let Some(identity_file) = request.identity_file.as_deref() {
        arguments.extend([
            "-o".to_string(),
            "IdentitiesOnly=yes".to_string(),
            "-i".to_string(),
            identity_file.to_string(),
        ]);
    }
    if request.credential_ref.is_some() {
        arguments.extend([
            "-o".to_string(),
            "IdentitiesOnly=yes".to_string(),
            "-o".to_string(),
            if request.identity_file.is_some() {
                "PreferredAuthentications=publickey,keyboard-interactive,password".to_string()
            } else {
                "PreferredAuthentications=keyboard-interactive,password".to_string()
            },
            "-o".to_string(),
            "PasswordAuthentication=yes".to_string(),
            "-o".to_string(),
            "KbdInteractiveAuthentication=yes".to_string(),
        ]);
    }
    if request.credential_ref.is_some() || request.identity_passphrase_ref.is_some() {
        arguments.extend(["-o".to_string(), "NumberOfPasswordPrompts=1".to_string()]);
    }
    arguments
}

fn openssh_terminal_arguments(request: &ValidatedStartSshRequest, kex: &str) -> Vec<String> {
    let mut arguments = vec!["-tt".to_string()];
    arguments.extend(openssh_policy_arguments(request, kex));
    arguments.extend([
        "--".to_string(),
        format!("{}@{}", request.username, request.host),
    ]);
    arguments
}

fn verify_system_ssh_authentication(
    request: &ValidatedStartSshRequest,
    kex: &str,
) -> Result<(), String> {
    let mut command = std::process::Command::new("ssh");
    command.args(openssh_policy_arguments(request, kex));
    if request.credential_ref.is_none() && request.identity_passphrase_ref.is_none() {
        command.args(["-o", "BatchMode=yes"]);
    }
    configure_process_ssh_askpass(
        &mut command,
        request.credential_ref.as_deref(),
        request.identity_passphrase_ref.as_deref(),
    )?;
    let target = format!("{}@{}", request.username, request.host);
    command.args(["-o", "ConnectTimeout=15", "-o", "RequestTTY=no", "--"]);
    command.arg(target).arg("true");
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|error| format!("无法启动 OpenSSH 认证检查: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match child
            .try_wait()
            .map_err(|error| format!("无法读取 OpenSSH 认证检查状态: {error}"))?
        {
            Some(status) if status.success() => return Ok(()),
            Some(_) => return Err("OpenSSH 主机密钥校验或认证失败".to_string()),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("OpenSSH 认证检查超时".to_string());
            }
            None => thread::sleep(Duration::from_millis(25)),
        }
    }
}

fn mosh_terminal_arguments(
    request: &ValidatedStartMoshRequest,
    kex: &str,
) -> Result<Vec<String>, String> {
    let ssh_arguments = std::iter::once("ssh".to_string())
        .chain(openssh_policy_arguments(&request.ssh, kex))
        .collect::<Vec<_>>();
    if ssh_arguments
        .iter()
        .any(|argument| argument.is_empty() || !argument.bytes().all(is_safe_mosh_ssh_byte))
    {
        return Err("Mosh SSH bootstrap 参数包含不安全字符".to_string());
    }
    let ssh_command = ssh_arguments.join(" ");
    Ok(vec![
        "--predict=adaptive".to_string(),
        format!("--port={}:{}", request.udp_port_start, request.udp_port_end),
        "--server=mosh-server".to_string(),
        format!("--ssh={ssh_command}"),
        "--".to_string(),
        format!("{}@{}", request.ssh.username, request.ssh.host),
    ])
}

/// Entry point used when OpenSSH starts the VPShell executable as SSH_ASKPASS.
/// Only opaque references cross the process boundary; the secret stays in the OS keyring.
pub fn run_ssh_askpass(prompt: Option<&str>) -> i32 {
    if env::var(ASKPASS_MODE_ENV).as_deref() != Ok("1") {
        return 2;
    }
    let credential_ref = env::var(ASKPASS_PASSWORD_REF_ENV).ok();
    let key_passphrase_ref = env::var(ASKPASS_KEY_REF_ENV).ok();
    let Some(reference) = select_askpass_reference(
        prompt.unwrap_or_default(),
        credential_ref.as_deref(),
        key_passphrase_ref.as_deref(),
    ) else {
        return 3;
    };
    let prefix = if reference.starts_with("key-") {
        "key-"
    } else {
        "ssh-"
    };
    if file_transfer::validate_optional_reference(Some(reference), prefix).is_err() {
        return 4;
    }
    let Ok(secret) = file_transfer::read_secret(reference, "未找到已保存的 SSH 凭据")
    else {
        return 5;
    };
    let mut stdout = std::io::stdout().lock();
    if stdout.write_all(secret.as_bytes()).is_err()
        || stdout.write_all(b"\n").is_err()
        || stdout.flush().is_err()
    {
        return 6;
    }
    0
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
async fn native_engine_probe(
    manager: State<'_, native_engine::NativeEngineManager>,
    request: native_engine::NativeEngineProbeRequest,
) -> Result<native_engine::NativeEngineProbeResult, native_engine::NativeEngineError> {
    manager.probe(request).await
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
async fn native_engine_probe(_request: serde_json::Value) -> Result<serde_json::Value, String> {
    Err("原生桌面引擎检查在移动端预览中不可用".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
fn cancel_native_engine_operation(
    manager: State<'_, native_engine::NativeEngineManager>,
    operation_id: String,
) -> Result<(), native_engine::NativeEngineError> {
    manager.cancel(&operation_id)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
async fn start_native_route_measurement(
    native: State<'_, native_engine::NativeEngineManager>,
    measurements: State<'_, route_measurement::RouteMeasurementManager>,
    request: route_measurement::RouteMeasurementStartRequest,
) -> Result<route_measurement::RouteMeasurementSnapshot, route_measurement::RouteMeasurementError> {
    measurements.start(native.inner().clone(), request)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
async fn start_native_route_measurement(
    _request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    Err("路线测量在移动端预览中不可用".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
fn get_native_route_measurement_snapshot(
    measurements: State<'_, route_measurement::RouteMeasurementManager>,
    request: route_measurement::RouteMeasurementCampaignRequest,
) -> Result<route_measurement::RouteMeasurementSnapshot, route_measurement::RouteMeasurementError> {
    measurements.get(request)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
fn get_native_route_measurement_snapshot(
    _request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    Err("路线测量在移动端预览中不可用".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
fn stop_native_route_measurement(
    measurements: State<'_, route_measurement::RouteMeasurementManager>,
    request: route_measurement::RouteMeasurementCampaignRequest,
) -> Result<(), route_measurement::RouteMeasurementError> {
    measurements.stop(request)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
fn stop_native_route_measurement(_request: serde_json::Value) -> Result<(), String> {
    Err("路线测量在移动端预览中不可用".to_string())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
fn cancel_native_engine_operation(_operation_id: String) -> Result<(), String> {
    Err("原生桌面引擎检查在移动端预览中不可用".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
async fn start_native_terminal(
    app: tauri::AppHandle,
    terminals: State<'_, TerminalManager>,
    native: State<'_, native_engine::NativeEngineManager>,
    store: State<'_, app_store::AppStore>,
    host_id: String,
    initial_path: String,
    request: native_engine::NativeTerminalStartRequest,
) -> Result<NativeTerminalStartResponse, native_engine::NativeEngineError> {
    let (target_host, target_port, target_username) = request
        .target_identity()
        .map(|(host, port, username)| (host.to_string(), port, username.to_string()))
        .ok_or_else(|| {
            native_engine::NativeEngineError::new(
                "native-terminal-route-empty",
                "原生终端路线不能为空",
                false,
            )
        })?;
    let launch = native.start_terminal(request).await?;
    let session_id = launch.result.session_id.clone();
    let generation = match next_terminal_generation(&terminals) {
        Ok(generation) => generation,
        Err(_) => {
            launch.handle.stop();
            return Err(native_engine::NativeEngineError::new(
                "native-terminal-generation-exhausted",
                "终端会话代际已耗尽",
                false,
            ));
        }
    };
    let integration = Arc::new(Mutex::new(shell_integration::ShellIntegrationParser::new()));
    let (acknowledgements, mut acknowledgement_receiver) = mpsc::channel(NATIVE_TERMINAL_ACK_QUEUE);
    let pending_delivery = Arc::new(AtomicU64::new(0));
    let bridge_handle = launch.handle.clone();
    let connection = match store.record_authenticated_connection(
        &host_id,
        &target_host,
        target_port,
        &target_username,
        &initial_path,
    ) {
        Ok(connection) => connection,
        Err(_) => {
            launch.handle.stop();
            return Err(native_engine::NativeEngineError::new(
                "native-terminal-history-rejected",
                "认证连接记录未通过 AppState 一致性验证",
                false,
            ));
        }
    };
    {
        let mut sessions = match lock_sessions(&terminals) {
            Ok(sessions) => sessions,
            Err(_) => {
                launch.handle.stop();
                return Err(native_engine::NativeEngineError::new(
                    "native-terminal-state-corrupt",
                    "终端会话状态已损坏",
                    false,
                ));
            }
        };
        if sessions.contains_key(&session_id) {
            launch.handle.stop();
            return Err(native_engine::NativeEngineError::new(
                "native-terminal-session-conflict",
                "终端会话标识已经在使用",
                false,
            ));
        }
        sessions.insert(
            session_id.clone(),
            TerminalHandle {
                transport: TerminalTransport::Native {
                    handle: launch.handle,
                    acknowledgements,
                    pending_delivery: Arc::clone(&pending_delivery),
                },
                integration: Arc::clone(&integration),
                generation,
            },
        );
    }

    let sessions = Arc::clone(&terminals.sessions);
    let result = launch.result;
    let mut events = launch.events;
    tauri::async_runtime::spawn(async move {
        let mut received_exit = false;
        let mut bridge_error = "原生终端事件流异常结束";
        let mut next_delivery_id = 0_u32;
        'event_stream: while let Some(event) = events.recv().await {
            match event {
                native_engine::NativeTerminalEvent::Data(data) => {
                    let generation_is_current = sessions
                        .lock()
                        .map(|sessions| {
                            sessions
                                .get(&session_id)
                                .is_some_and(|session| session.generation == generation)
                        })
                        .unwrap_or(false);
                    if !generation_is_current {
                        bridge_handle.stop();
                        break;
                    }
                    let (visible, updates) = integration
                        .lock()
                        .map(|mut parser| parser.feed(&data))
                        .unwrap_or_else(|_| (data, Vec::new()));
                    for (stack, warning) in updates {
                        let _ = app.emit(
                            "terminal-context",
                            shell_integration::TerminalContextEvent {
                                session_id: session_id.clone(),
                                stack,
                                warning,
                            },
                        );
                    }
                    if !visible.is_empty() {
                        let delivery_id = next_delivery_id
                            .checked_add(1)
                            .filter(|delivery_id| *delivery_id > 0);
                        let Some(delivery_id) = delivery_id else {
                            bridge_error = "原生终端输出序号已耗尽";
                            bridge_handle.stop();
                            break;
                        };
                        next_delivery_id = delivery_id;
                        pending_delivery.store(u64::from(delivery_id), Ordering::SeqCst);
                        let output = TerminalOutputEvent {
                            session_id: session_id.clone(),
                            data: BASE64_STANDARD.encode(visible),
                            delivery_id: Some(delivery_id),
                        };
                        if app.emit("terminal-output", output.clone()).is_err() {
                            pending_delivery.store(0, Ordering::SeqCst);
                            bridge_error = "原生终端输出无法发送到界面";
                            bridge_handle.stop();
                            break;
                        }
                        let acknowledged = tokio::time::timeout(
                            NATIVE_TERMINAL_ACK_TIMEOUT,
                            async {
                                loop {
                                    tokio::select! {
                                        acknowledgement = acknowledgement_receiver.recv() => {
                                            match acknowledgement {
                                                Some(received) if received == delivery_id => return true,
                                                Some(_) => continue,
                                                None => return false,
                                            }
                                        }
                                        _ = tokio::time::sleep(NATIVE_TERMINAL_REDELIVERY_INTERVAL) => {
                                            if app.emit("terminal-output", output.clone()).is_err() {
                                                return false;
                                            }
                                        }
                                    }
                                }
                            },
                        )
                        .await
                        .unwrap_or(false);
                        pending_delivery.store(0, Ordering::SeqCst);
                        if !acknowledged {
                            bridge_error = "原生终端界面未及时确认输出";
                            bridge_handle.stop();
                            break 'event_stream;
                        }
                    }
                }
                native_engine::NativeTerminalEvent::Exit { message } => {
                    received_exit = true;
                    let removed_current = sessions
                        .lock()
                        .map(|mut sessions| {
                            if sessions
                                .get(&session_id)
                                .is_some_and(|session| session.generation == generation)
                            {
                                sessions.remove(&session_id);
                                true
                            } else {
                                false
                            }
                        })
                        .unwrap_or(false);
                    if removed_current {
                        let _ = app.emit(
                            "terminal-exit",
                            TerminalExitEvent {
                                session_id: session_id.clone(),
                                message: message.map(str::to_string),
                            },
                        );
                    }
                    break;
                }
            }
        }
        if !received_exit {
            let removed_current = sessions
                .lock()
                .map(|mut sessions| {
                    if sessions
                        .get(&session_id)
                        .is_some_and(|session| session.generation == generation)
                    {
                        sessions.remove(&session_id);
                        true
                    } else {
                        false
                    }
                })
                .unwrap_or(false);
            if removed_current {
                let _ = app.emit(
                    "terminal-exit",
                    TerminalExitEvent {
                        session_id,
                        message: Some(bridge_error.to_string()),
                    },
                );
            }
        }
    });
    Ok(NativeTerminalStartResponse {
        schema_version: result.schema_version,
        engine: result.engine,
        session_id: result.session_id,
        connection,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
async fn native_list_remote_files(
    native: State<'_, native_engine::NativeEngineManager>,
    request: native_engine::NativeSftpListRequest,
) -> Result<native_engine::NativeSftpDirectoryResult, native_engine::NativeEngineError> {
    native.list_sftp_directory(request).await
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
async fn start_native_local_forward(
    native: State<'_, native_engine::NativeEngineManager>,
    request: native_engine::NativeLocalForwardStartRequest,
) -> Result<native_engine::NativeLocalForwardSnapshot, native_engine::NativeEngineError> {
    native.start_local_forward(request).await
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
async fn start_native_local_forward(
    _request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    Err("原生本地转发在移动端预览中不可用".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
fn list_native_local_forwards(
    native: State<'_, native_engine::NativeEngineManager>,
) -> Result<Vec<native_engine::NativeLocalForwardSnapshot>, native_engine::NativeEngineError> {
    native.list_local_forwards()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
fn list_native_local_forwards() -> Result<Vec<serde_json::Value>, String> {
    Err("原生本地转发在移动端预览中不可用".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
fn stop_native_local_forward(
    native: State<'_, native_engine::NativeEngineManager>,
    forward_id: String,
) -> Result<(), native_engine::NativeEngineError> {
    native.stop_local_forward(&forward_id)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
fn stop_native_local_forward(_forward_id: String) -> Result<(), String> {
    Err("原生本地转发在移动端预览中不可用".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
async fn start_native_remote_forward(
    native: State<'_, native_engine::NativeEngineManager>,
    request: native_engine::NativeRemoteForwardStartRequest,
) -> Result<native_engine::NativeRemoteForwardSnapshot, native_engine::NativeEngineError> {
    native.start_remote_forward(request).await
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
async fn start_native_remote_forward(
    _request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    Err("原生远端转发在移动端预览中不可用".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
fn list_native_remote_forwards(
    native: State<'_, native_engine::NativeEngineManager>,
) -> Result<Vec<native_engine::NativeRemoteForwardSnapshot>, native_engine::NativeEngineError> {
    native.list_remote_forwards()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
fn list_native_remote_forwards() -> Result<Vec<serde_json::Value>, String> {
    Err("原生远端转发在移动端预览中不可用".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
fn stop_native_remote_forward(
    native: State<'_, native_engine::NativeEngineManager>,
    forward_id: String,
) -> Result<(), native_engine::NativeEngineError> {
    native.stop_remote_forward(&forward_id)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
fn stop_native_remote_forward(_forward_id: String) -> Result<(), String> {
    Err("原生远端转发在移动端预览中不可用".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
async fn start_native_dynamic_forward(
    native: State<'_, native_engine::NativeEngineManager>,
    request: native_engine::NativeDynamicForwardStartRequest,
) -> Result<native_engine::NativeDynamicForwardSnapshot, native_engine::NativeEngineError> {
    native.start_dynamic_forward(request).await
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
async fn start_native_dynamic_forward(
    _request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    Err("原生动态转发在移动端预览中不可用".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
fn list_native_dynamic_forwards(
    native: State<'_, native_engine::NativeEngineManager>,
) -> Result<Vec<native_engine::NativeDynamicForwardSnapshot>, native_engine::NativeEngineError> {
    native.list_dynamic_forwards()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
fn list_native_dynamic_forwards() -> Result<Vec<serde_json::Value>, String> {
    Err("原生动态转发在移动端预览中不可用".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
fn stop_native_dynamic_forward(
    native: State<'_, native_engine::NativeEngineManager>,
    forward_id: String,
) -> Result<(), native_engine::NativeEngineError> {
    native.stop_dynamic_forward(&forward_id)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
fn stop_native_dynamic_forward(_forward_id: String) -> Result<(), String> {
    Err("原生动态转发在移动端预览中不可用".to_string())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
async fn native_list_remote_files(
    _request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    Err("原生桌面 SFTP 在移动端预览中不可用".to_string())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
async fn start_native_terminal(_request: serde_json::Value) -> Result<serde_json::Value, String> {
    Err("原生桌面终端在移动端预览中不可用".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
fn ack_native_terminal_output(
    terminals: State<'_, TerminalManager>,
    session_id: String,
    delivery_id: u32,
) -> Result<(), String> {
    if delivery_id == 0 {
        return Err("原生终端输出确认序号无效".to_string());
    }
    let sessions = lock_sessions(&terminals)?;
    let session = sessions
        .get(&session_id)
        .ok_or_else(|| "终端会话不存在或已关闭".to_string())?;
    let TerminalTransport::Native {
        acknowledgements,
        pending_delivery,
        ..
    } = &session.transport
    else {
        return Err("该终端不使用原生输出确认协议".to_string());
    };
    if pending_delivery.load(Ordering::SeqCst) != u64::from(delivery_id) {
        return Err("原生终端输出确认序号已过期或尚未发送".to_string());
    }
    acknowledgements
        .try_send(delivery_id)
        .map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => "原生终端输出确认队列已满".to_string(),
            mpsc::error::TrySendError::Closed(_) => "原生终端输出确认通道已关闭".to_string(),
        })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
fn ack_native_terminal_output(_session_id: String, _delivery_id: u32) -> Result<(), String> {
    Err("原生桌面终端输出确认在移动端预览中不可用".to_string())
}

#[tauri::command]
fn start_ssh_session(
    app: tauri::AppHandle,
    manager: State<'_, TerminalManager>,
    store: State<'_, app_store::AppStore>,
    host_id: String,
    initial_path: String,
    request: StartSshRequest,
) -> Result<SystemTerminalStartResponse, String> {
    let request = ValidatedStartSshRequest::try_from(request)?;
    let mut command = CommandBuilder::new("ssh");
    let kex = file_transfer::openssh_kex_algorithms()?;
    verify_system_ssh_authentication(&request, &kex)?;
    for argument in openssh_terminal_arguments(&request, &kex) {
        command.arg(argument);
    }
    configure_ssh_askpass(
        &mut command,
        request.credential_ref.as_deref(),
        request.identity_passphrase_ref.as_deref(),
    )?;
    command.env("TERM", "xterm-256color");
    spawn_system_terminal(
        app,
        manager,
        request.session_id,
        request.rows,
        request.cols,
        command,
        OPENSSH_ENGINE_NAME,
        "OpenSSH",
        &store,
        &host_id,
        &request.host,
        request.port,
        &request.username,
        &initial_path,
    )
}

#[tauri::command]
fn start_mosh_session(
    app: tauri::AppHandle,
    manager: State<'_, TerminalManager>,
    store: State<'_, app_store::AppStore>,
    host_id: String,
    initial_path: String,
    request: StartMoshRequest,
) -> Result<SystemTerminalStartResponse, String> {
    let request = ValidatedStartMoshRequest::try_from(request)?;
    let mut command = CommandBuilder::new("mosh");
    let kex = file_transfer::openssh_kex_algorithms()?;
    verify_system_ssh_authentication(&request.ssh, &kex)?;
    for argument in mosh_terminal_arguments(&request, &kex)? {
        command.arg(argument);
    }
    configure_ssh_askpass(
        &mut command,
        request.ssh.credential_ref.as_deref(),
        request.ssh.identity_passphrase_ref.as_deref(),
    )?;
    command.env("TERM", "xterm-256color");
    spawn_system_terminal(
        app,
        manager,
        request.ssh.session_id,
        request.ssh.rows,
        request.ssh.cols,
        command,
        MOSH_ENGINE_NAME,
        "Mosh；请确认本机已安装 mosh、远端已安装 mosh-server，并放行 UDP 60000–61000",
        &store,
        &host_id,
        &request.ssh.host,
        request.ssh.port,
        &request.ssh.username,
        &initial_path,
    )
}

#[allow(clippy::too_many_arguments)]
fn spawn_system_terminal(
    app: tauri::AppHandle,
    manager: State<'_, TerminalManager>,
    session_id: String,
    rows: u16,
    cols: u16,
    command: CommandBuilder,
    engine: &'static str,
    launch_name: &'static str,
    store: &app_store::AppStore,
    host_id: &str,
    host: &str,
    port: u16,
    username: &str,
    initial_path: &str,
) -> Result<SystemTerminalStartResponse, String> {
    if lock_sessions(&manager)?.contains_key(&session_id) {
        return Err("该终端会话已经连接".to_string());
    }
    let generation = next_terminal_generation(&manager)?;

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| format!("无法创建终端: {error}"))?;

    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| format!("无法启动 {launch_name}: {error}"))?;
    drop(pair.slave);

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| format!("无法读取终端输出: {error}"))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|error| format!("无法写入终端: {error}"))?;
    let killer = child.clone_killer();
    let integration = Arc::new(Mutex::new(shell_integration::ShellIntegrationParser::new()));

    lock_sessions(&manager)?.insert(
        session_id.clone(),
        TerminalHandle {
            transport: TerminalTransport::SystemPty {
                writer,
                master: pair.master,
                killer,
            },
            integration: Arc::clone(&integration),
            generation,
        },
    );

    let connection =
        match store.record_authenticated_connection(host_id, host, port, username, initial_path) {
            Ok(connection) => connection,
            Err(error) => {
                if let Some(session) = lock_sessions(&manager)?.remove(&session_id) {
                    if let TerminalTransport::SystemPty { mut killer, .. } = session.transport {
                        killer.kill().map_err(|kill_error| {
                            format!("{error}；同时无法停止未记录终端: {kill_error}")
                        })?;
                    }
                }
                return Err(error);
            }
        };

    let output_app = app.clone();
    let output_session_id = session_id.clone();
    let output_sessions = Arc::clone(&manager.sessions);
    thread::spawn(move || {
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    let generation_is_current = output_sessions
                        .lock()
                        .map(|sessions| {
                            sessions
                                .get(&output_session_id)
                                .is_some_and(|session| session.generation == generation)
                        })
                        .unwrap_or(false);
                    if !generation_is_current {
                        break;
                    }
                    let (visible, updates) = integration
                        .lock()
                        .map(|mut parser| parser.feed(&buffer[..length]))
                        .unwrap_or_else(|_| (buffer[..length].to_vec(), Vec::new()));
                    for (stack, warning) in updates {
                        let _ = output_app.emit(
                            "terminal-context",
                            shell_integration::TerminalContextEvent {
                                session_id: output_session_id.clone(),
                                stack,
                                warning,
                            },
                        );
                    }
                    if !visible.is_empty() {
                        let _ = output_app.emit(
                            "terminal-output",
                            TerminalOutputEvent {
                                session_id: output_session_id.clone(),
                                data: BASE64_STANDARD.encode(visible),
                                delivery_id: None,
                            },
                        );
                    }
                }
                Err(_) => break,
            }
        }
    });

    let wait_app = app;
    let wait_session_id = session_id.clone();
    let wait_sessions = Arc::clone(&manager.sessions);
    thread::spawn(move || {
        let exit_message = child.wait().err().map(|error| error.to_string());
        let removed_current = wait_sessions
            .lock()
            .map(|mut sessions| {
                if sessions
                    .get(&wait_session_id)
                    .is_some_and(|session| session.generation == generation)
                {
                    sessions.remove(&wait_session_id);
                    true
                } else {
                    false
                }
            })
            .unwrap_or(false);
        if removed_current {
            let _ = wait_app.emit(
                "terminal-exit",
                TerminalExitEvent {
                    session_id: wait_session_id,
                    message: exit_message,
                },
            );
        }
    });

    Ok(SystemTerminalStartResponse {
        schema_version: 1,
        engine,
        session_id,
        connection,
    })
}

#[tauri::command]
fn enable_shell_integration(
    manager: State<'_, TerminalManager>,
    session_id: String,
) -> Result<(), String> {
    let mut sessions = lock_sessions(&manager)?;
    let session = sessions
        .get_mut(&session_id)
        .ok_or_else(|| "终端会话不存在或已关闭".to_string())?;
    let command = session
        .integration
        .lock()
        .map_err(|_| "Shell Integration 状态已损坏".to_string())?
        .activation_command();
    match &mut session.transport {
        TerminalTransport::SystemPty { writer, .. } => {
            writer
                .write_all(command.as_bytes())
                .map_err(|error| format!("写入 Shell Integration 启用命令失败: {error}"))?;
            writer
                .flush()
                .map_err(|error| format!("刷新 Shell Integration 启用命令失败: {error}"))
        }
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        TerminalTransport::Native { handle, .. } => handle
            .write(command.as_bytes())
            .map_err(|error| error.user_message().to_string()),
    }
}

#[tauri::command]
fn preview_broadcast(
    manager: State<'_, TerminalManager>,
    broadcasts: State<'_, safe_broadcast::SafeBroadcastManager>,
    command: String,
    targets: Vec<safe_broadcast::BroadcastTargetRequest>,
) -> Result<safe_broadcast::BroadcastPreview, String> {
    let sessions = lock_sessions(&manager)?;
    let mut verified = Vec::with_capacity(targets.len());
    for target in targets {
        let session = sessions
            .get(&target.session_id)
            .ok_or_else(|| format!("广播目标 {} 已断开或不存在", target.label))?;
        let context_revision = session
            .integration
            .lock()
            .map_err(|_| "Shell Integration 状态已损坏".to_string())?
            .revision();
        verified.push(safe_broadcast::VerifiedBroadcastTarget {
            session_id: target.session_id,
            label: target.label,
            environment: target.environment,
            context_revision,
        });
    }
    broadcasts.preview(command, verified)
}

#[tauri::command]
fn execute_broadcast(
    manager: State<'_, TerminalManager>,
    broadcasts: State<'_, safe_broadcast::SafeBroadcastManager>,
    confirmation_token: String,
) -> Result<safe_broadcast::BroadcastResult, String> {
    let pending = broadcasts.consume(&confirmation_token)?;
    let mut items = Vec::with_capacity(pending.targets.len());
    for target in pending.targets {
        let context_revision = {
            let sessions = lock_sessions(&manager)?;
            sessions.get(&target.session_id).and_then(|session| {
                session
                    .integration
                    .lock()
                    .ok()
                    .map(|parser| parser.revision())
            })
        };
        let Some(context_revision) = context_revision else {
            items.push(safe_broadcast::BroadcastItemResult {
                session_id: target.session_id,
                label: target.label,
                outcome: "skipped".to_string(),
                message: "目标已断开或上下文状态不可用".to_string(),
            });
            continue;
        };
        if context_revision != target.context_revision {
            items.push(safe_broadcast::BroadcastItemResult {
                session_id: target.session_id,
                label: target.label,
                outcome: "skipped".to_string(),
                message: "目标上下文在确认后发生变化，已跳过".to_string(),
            });
            continue;
        }
        match write_to_session(
            &manager,
            &target.session_id,
            format!("{}\r", pending.command).as_bytes(),
        ) {
            Ok(()) => {
                items.push(safe_broadcast::BroadcastItemResult {
                    session_id: target.session_id,
                    label: target.label,
                    outcome: "succeeded".to_string(),
                    message: "已写入终端输入流；远端命令结果仍由该终端单独返回".to_string(),
                });
            }
            Err(error) => {
                items.push(safe_broadcast::BroadcastItemResult {
                    session_id: target.session_id,
                    label: target.label,
                    outcome: "failed".to_string(),
                    message: error,
                });
            }
        }
    }
    Ok(safe_broadcast::summarize_results(items))
}

#[tauri::command]
fn write_terminal(
    manager: State<'_, TerminalManager>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    let mut sessions = lock_sessions(&manager)?;
    let session = sessions
        .get_mut(&session_id)
        .ok_or_else(|| "终端会话不存在或已关闭".to_string())?;
    write_terminal_handle(session, data.as_bytes())
}

fn write_to_session(
    manager: &TerminalManager,
    session_id: &str,
    data: &[u8],
) -> Result<(), String> {
    let mut sessions = lock_sessions(manager)?;
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| "终端会话不存在或已关闭".to_string())?;
    write_terminal_handle(session, data)
}

fn write_terminal_handle(session: &mut TerminalHandle, data: &[u8]) -> Result<(), String> {
    match &mut session.transport {
        TerminalTransport::SystemPty { writer, .. } => {
            writer
                .write_all(data)
                .map_err(|error| format!("终端写入失败: {error}"))?;
            writer
                .flush()
                .map_err(|error| format!("终端刷新失败: {error}"))
        }
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        TerminalTransport::Native { handle, .. } => handle
            .write(data)
            .map_err(|error| error.user_message().to_string()),
    }
}

#[tauri::command]
async fn import_finalshell(
    path: String,
    include_passwords: bool,
) -> Result<finalshell::ImportResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        finalshell::import_directory(&path, include_passwords)
    })
    .await
    .map_err(|error| format!("FinalShell 导入任务异常结束: {error}"))?
}

#[tauri::command]
async fn initialize_app_store(
    store: State<'_, app_store::AppStore>,
    request: app_store::InitializeAppStoreRequest,
) -> Result<app_store::AppStoreSnapshot, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || store.initialize(request))
        .await
        .map_err(|error| format!("本地事件库初始化任务异常结束: {error}"))?
}

#[tauri::command]
async fn save_app_state(
    store: State<'_, app_store::AppStore>,
    request: app_store::SaveAppStateRequest,
) -> Result<app_store::SaveAppStateResult, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || store.save(request))
        .await
        .map_err(|error| format!("本地状态保存任务异常结束: {error}"))?
}

#[tauri::command]
fn desktop_sync_status(
    coordinator: State<'_, sync_coordinator::SyncCoordinatorManager>,
    store: State<'_, app_store::AppStore>,
) -> Result<sync_coordinator::SyncCoordinatorStatus, String> {
    coordinator.status_with_app_store(store.inner())
}

#[tauri::command]
async fn list_sync_conflicts(
    coordinator: State<'_, sync_coordinator::SyncCoordinatorManager>,
    request: sync_coordinator::ListSyncConflictsRequest,
) -> Result<sync_coordinator::SyncConflictCenterSnapshot, String> {
    let coordinator = coordinator.inner().clone();
    tauri::async_runtime::spawn_blocking(move || coordinator.list_conflicts(request))
        .await
        .map_err(|error| format!("同步冲突读取任务异常结束: {error}"))?
}

#[tauri::command]
async fn configure_local_folder_sync(
    app: tauri::AppHandle,
    coordinator: State<'_, sync_coordinator::SyncCoordinatorManager>,
    scheduler: State<'_, sync_scheduler::AutomaticSyncScheduler>,
    store: State<'_, app_store::AppStore>,
    request: sync_coordinator::ConfigureLocalFolderSyncRequest,
) -> Result<sync_coordinator::SyncCoordinatorStatus, String> {
    sync_scheduler::AutomaticSyncScheduler::ensure_supported()?;
    let coordinator = coordinator.inner().clone();
    let store = store.inner().clone();
    let worker_coordinator = coordinator.clone();
    let worker_store = store.clone();
    let status = tauri::async_runtime::spawn_blocking(move || {
        worker_coordinator.configure_local_folder(request)?;
        worker_coordinator.status_with_app_store(&worker_store)
    })
    .await
    .map_err(|error| format!("Local Folder 同步配置任务异常结束: {error}"))??;
    if let Err(error) = scheduler.start(app, coordinator.clone(), store) {
        let _ = coordinator.detach_session();
        return Err(error);
    }
    Ok(status)
}

#[tauri::command]
async fn configure_webdav_sync(
    app: tauri::AppHandle,
    coordinator: State<'_, sync_coordinator::SyncCoordinatorManager>,
    ca_manager: State<'_, sync_provider_ca::SyncProviderCaManager>,
    scheduler: State<'_, sync_scheduler::AutomaticSyncScheduler>,
    store: State<'_, app_store::AppStore>,
    request: sync_coordinator::ConfigureWebDavSyncRequest,
) -> Result<sync_coordinator::SyncCoordinatorStatus, String> {
    sync_scheduler::AutomaticSyncScheduler::ensure_supported()?;
    let coordinator = coordinator.inner().clone();
    let ca_manager = ca_manager.inner().clone();
    let store = store.inner().clone();
    let worker_coordinator = coordinator.clone();
    let worker_store = store.clone();
    let provider_ca_ref = request.provider_ca_reference().map(str::to_string);
    let status = tauri::async_runtime::spawn_blocking(move || {
        let trusted_ca_pem = provider_ca_ref
            .as_deref()
            .map(|reference| ca_manager.read(reference))
            .transpose()?;
        worker_coordinator.configure_webdav(request, trusted_ca_pem)?;
        worker_coordinator.status_with_app_store(&worker_store)
    })
    .await
    .map_err(|error| format!("WebDAV 同步配置任务异常结束: {error}"))??;
    if let Err(error) = scheduler.start(app, coordinator.clone(), store) {
        let _ = coordinator.detach_session();
        return Err(error);
    }
    Ok(status)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunSyncOnceResult {
    status: sync_coordinator::SyncCoordinatorStatus,
    app_store: app_store::AppStoreSnapshot,
}

#[tauri::command]
async fn resolve_sync_conflict(
    coordinator: State<'_, sync_coordinator::SyncCoordinatorManager>,
    store: State<'_, app_store::AppStore>,
    request: sync_coordinator::ResolveSyncConflictRequest,
) -> Result<RunSyncOnceResult, String> {
    let coordinator = coordinator.inner().clone();
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(i64::MAX);
        let status = coordinator.resolve_conflict(&store, request, now_ms)?;
        let app_store = store.snapshot()?;
        Ok(RunSyncOnceResult { status, app_store })
    })
    .await
    .map_err(|error| format!("同步冲突解决任务异常结束: {error}"))?
}

#[tauri::command]
async fn run_sync_once(
    coordinator: State<'_, sync_coordinator::SyncCoordinatorManager>,
    store: State<'_, app_store::AppStore>,
) -> Result<RunSyncOnceResult, String> {
    let coordinator = coordinator.inner().clone();
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(i64::MAX);
        let status = coordinator.run_once(&store, now_ms)?;
        let app_store = store.snapshot()?;
        Ok(RunSyncOnceResult { status, app_store })
    })
    .await
    .map_err(|error| format!("同步单周期任务异常结束: {error}"))?
}

#[tauri::command]
fn cancel_sync(
    coordinator: State<'_, sync_coordinator::SyncCoordinatorManager>,
    store: State<'_, app_store::AppStore>,
) -> Result<sync_coordinator::SyncCoordinatorStatus, String> {
    coordinator.cancel()?;
    coordinator.status_with_app_store(store.inner())
}

#[tauri::command]
fn lock_sync(
    coordinator: State<'_, sync_coordinator::SyncCoordinatorManager>,
    scheduler: State<'_, sync_scheduler::AutomaticSyncScheduler>,
    store: State<'_, app_store::AppStore>,
) -> Result<sync_coordinator::SyncCoordinatorStatus, String> {
    scheduler.stop()?;
    coordinator.detach_session()?;
    coordinator.status_with_app_store(store.inner())
}

#[tauri::command]
async fn install_wallpaper_asset(
    manager: State<'_, local_assets::LocalAssetManager>,
    request: local_assets::InstallWallpaperRequest,
) -> Result<local_assets::RenderAsset, String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || manager.install_wallpaper(request))
        .await
        .map_err(|error| format!("壁纸资产任务异常结束: {error}"))?
}

#[tauri::command]
async fn load_wallpaper_asset(
    manager: State<'_, local_assets::LocalAssetManager>,
) -> Result<Option<local_assets::RenderAsset>, String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || manager.load_wallpaper())
        .await
        .map_err(|error| format!("壁纸资产读取任务异常结束: {error}"))?
}

#[tauri::command]
async fn install_font_asset(
    manager: State<'_, local_assets::LocalAssetManager>,
    request: local_assets::InstallFontRequest,
) -> Result<local_assets::RenderAsset, String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || manager.install_font(request))
        .await
        .map_err(|error| format!("字体资产任务异常结束: {error}"))?
}

#[tauri::command]
async fn load_font_asset(
    manager: State<'_, local_assets::LocalAssetManager>,
) -> Result<Option<local_assets::RenderAsset>, String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || manager.load_font())
        .await
        .map_err(|error| format!("字体资产读取任务异常结束: {error}"))?
}

#[tauri::command]
async fn preview_migration(
    manager: State<'_, migration::MigrationManager>,
    request: migration::MigrationPreviewRequest,
) -> Result<migration::MigrationPreview, String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || manager.preview(request))
        .await
        .map_err(|error| format!("迁移预览任务异常结束: {error}"))?
}

#[tauri::command]
fn apply_migration(
    manager: State<'_, migration::MigrationManager>,
    request: migration::MigrationApplyRequest,
) -> Result<migration::MigrationApplyResult, String> {
    manager.apply(request)
}

#[tauri::command]
async fn generate_ssh_key(
    request: key_management::GenerateKeyRequest,
) -> Result<key_management::GeneratedKey, String> {
    tauri::async_runtime::spawn_blocking(move || key_management::generate_key(request))
        .await
        .map_err(|error| format!("SSH 密钥生成任务异常结束: {error}"))?
}

fn quote_posix_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[tauri::command]
fn install_public_key(
    manager: State<'_, TerminalManager>,
    session_id: String,
    public_key_path: String,
) -> Result<(), String> {
    let public_key = key_management::read_public_key(&public_key_path)?;
    let quoted_key = quote_posix_literal(public_key.trim());
    let command = format!(
        "umask 077; mkdir -p \"$HOME/.ssh\" && touch \"$HOME/.ssh/authorized_keys\" && chmod 700 \"$HOME/.ssh\" && chmod 600 \"$HOME/.ssh/authorized_keys\" && key={quoted_key}; if grep -qxF -- \"$key\" \"$HOME/.ssh/authorized_keys\"; then printf 'VPShell: public key already installed\\n'; else printf '%s\\n' \"$key\" >> \"$HOME/.ssh/authorized_keys\" && printf 'VPShell: public key installed\\n'; fi\r"
    );
    write_to_session(&manager, &session_id, command.as_bytes())
}

#[tauri::command]
fn resize_terminal(
    manager: State<'_, TerminalManager>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let sessions = lock_sessions(&manager)?;
    let session = sessions
        .get(&session_id)
        .ok_or_else(|| "终端会话不存在或已关闭".to_string())?;
    match &session.transport {
        TerminalTransport::SystemPty { master, .. } => master
            .resize(PtySize {
                rows: rows.max(2),
                cols: cols.max(2),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|error| format!("调整终端尺寸失败: {error}")),
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        TerminalTransport::Native { handle, .. } => handle
            .resize(cols, rows)
            .map_err(|error| error.user_message().to_string()),
    }
}

#[tauri::command]
fn stop_terminal(manager: State<'_, TerminalManager>, session_id: String) -> Result<(), String> {
    let mut sessions = lock_sessions(&manager)?;
    let mut session = sessions
        .remove(&session_id)
        .ok_or_else(|| "终端会话不存在或已关闭".to_string())?;
    match &mut session.transport {
        TerminalTransport::SystemPty { killer, .. } => killer
            .kill()
            .map_err(|error| format!("关闭终端失败: {error}")),
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        TerminalTransport::Native { handle, .. } => {
            handle.stop();
            Ok(())
        }
    }
}

#[tauri::command]
fn delete_credential(reference: String) -> Result<(), String> {
    if file_transfer::validate_optional_reference(Some(&reference), "ssh-").is_err() {
        sync_provider_credentials::validate_webdav_credential_reference(&reference)?;
    }
    let mut deleted = false;
    let mut last_error = None;
    for service in [CREDENTIAL_SERVICE, LEGACY_CREDENTIAL_SERVICE] {
        match keyring::Entry::new(service, &reference).and_then(|entry| entry.delete_credential()) {
            Ok(()) => deleted = true,
            Err(keyring::Error::NoEntry) => {}
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    if deleted || last_error.is_none() {
        Ok(())
    } else {
        Err(format!(
            "删除系统凭据失败: {}",
            last_error.unwrap_or_else(|| "未知错误".to_string())
        ))
    }
}

#[tauri::command]
async fn store_webdav_credential(
    request: sync_provider_credentials::StoreWebDavCredentialRequest,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        sync_provider_credentials::store_webdav_credential(request)
    })
    .await
    .map_err(|error| format!("WebDAV 凭据保存任务异常结束: {error}"))?
}

#[tauri::command]
async fn install_webdav_ca(
    manager: State<'_, sync_provider_ca::SyncProviderCaManager>,
    request: sync_provider_ca::InstallWebDavCaRequest,
) -> Result<String, String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || manager.install(request))
        .await
        .map_err(|error| format!("WebDAV CA 导入任务异常结束: {error}"))?
}

#[tauri::command]
async fn delete_webdav_ca(
    manager: State<'_, sync_provider_ca::SyncProviderCaManager>,
    reference: String,
) -> Result<(), String> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || manager.delete(&reference))
        .await
        .map_err(|error| format!("WebDAV CA 删除任务异常结束: {error}"))?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(TerminalManager::default())
        .manage(remote_file_ops::RemoteFileOperationManager::default())
        .manage(remote_monitor::RemoteMonitorManager::default())
        .manage(safe_broadcast::SafeBroadcastManager::default())
        .manage(migration::MigrationManager::default())
        .manage(sync_scheduler::AutomaticSyncScheduler::default())
        .setup(|app| {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            {
                app.manage(native_engine::NativeEngineManager::default());
                app.manage(route_measurement::RouteMeasurementManager::default());
            }
            #[cfg(target_os = "android")]
            {
                initialize_android_keyring()?;
                app.handle().plugin(tauri_plugin_biometric::init())?;
            }
            app.manage(android_mobile::AndroidMobileManager::load()?);
            let app_data_directory = app
                .path()
                .app_data_dir()
                .map_err(|error| format!("无法定位 VPShell 应用数据目录: {error}"))?;
            let app_cache_directory = app
                .path()
                .app_cache_dir()
                .map_err(|error| format!("无法定位 VPShell 应用缓存目录: {error}"))?;
            app.manage(external_editor::ExternalEditorManager::load(
                app_data_directory.clone(),
                app_cache_directory,
            ));
            app.manage(app_store::AppStore::load(app_data_directory.clone())?);
            let local_assets =
                local_assets::LocalAssetManager::load(app_data_directory.clone())?;
            app.manage(local_assets.clone());
            app.manage(sync_provider_ca::SyncProviderCaManager::load(
                app_data_directory.clone(),
            )?);
            app.manage(sync_coordinator::SyncCoordinatorManager::open_with_assets(
                app_data_directory.clone(),
                local_assets,
            )?);
            app.manage(transfer_manager::TransferManager::load(app_data_directory));
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Focused(focused) = event {
                android_mobile::android_window_focus_changed(
                    window.state::<android_mobile::AndroidMobileManager>(),
                    *focused,
                );
            }
        })
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            native_engine_probe,
            cancel_native_engine_operation,
            start_native_terminal,
            native_list_remote_files,
            ack_native_terminal_output,
            start_native_local_forward,
            list_native_local_forwards,
            stop_native_local_forward,
            start_native_remote_forward,
            list_native_remote_forwards,
            stop_native_remote_forward,
            start_native_dynamic_forward,
            list_native_dynamic_forwards,
            stop_native_dynamic_forward,
            start_native_route_measurement,
            get_native_route_measurement_snapshot,
            stop_native_route_measurement,
            start_ssh_session,
            start_mosh_session,
            write_terminal,
            enable_shell_integration,
            preview_broadcast,
            execute_broadcast,
            resize_terminal,
            stop_terminal,
            delete_credential,
            store_webdav_credential,
            install_webdav_ca,
            delete_webdav_ca,
            import_finalshell,
            initialize_app_store,
            save_app_state,
            desktop_sync_status,
            list_sync_conflicts,
            configure_local_folder_sync,
            configure_webdav_sync,
            run_sync_once,
            resolve_sync_conflict,
            cancel_sync,
            lock_sync,
            install_wallpaper_asset,
            load_wallpaper_asset,
            install_font_asset,
            load_font_asset,
            preview_migration,
            apply_migration,
            file_transfer::inspect_host_key,
            file_transfer::trust_host_key,
            generate_ssh_key,
            install_public_key,
            file_transfer::list_remote_files,
            file_transfer::upload_remote,
            file_transfer::download_remote,
            file_transfer::get_transfer_task,
            file_transfer::list_transfer_tasks,
            file_transfer::get_transfer_recovery_status,
            file_transfer::retry_transfer_task,
            file_transfer::cancel_transfer_task,
            file_transfer::dismiss_transfer_task,
            remote_file_ops::preview_remote_file_operation,
            remote_file_ops::preview_remote_file_operation_recovery,
            remote_file_ops::execute_remote_file_operation,
            external_editor::begin_external_edit,
            external_editor::list_external_edit_recovery,
            external_editor::resume_external_edit,
            external_editor::discard_external_edit_recovery,
            external_editor::export_external_edit_copy,
            external_editor::get_external_edit_status,
            external_editor::save_external_edit,
            external_editor::reload_external_edit,
            external_editor::end_external_edit,
            network_tools::trace_route,
            network_tools::download_speed_test,
            network_tools::udp_speed_test,
            remote_monitor::fetch_remote_metrics,
            remote_monitor::start_remote_monitor,
            remote_monitor::get_remote_monitor_snapshot,
            remote_monitor::set_remote_monitor_paused,
            remote_monitor::set_remote_monitor_interval,
            remote_monitor::stop_remote_monitor,
            android_mobile::android_preview_status,
            android_mobile::android_sync_status,
            android_mobile::android_security_status,
            android_mobile::android_unlock,
            android_mobile::android_set_biometric_enabled,
            android_mobile::android_inspect_host_key,
            android_mobile::android_enter_background,
            android_mobile::android_connect_host,
            android_mobile::android_disconnect_host,
            android_mobile::android_list_remote_files,
            android_mobile::android_open_terminal,
            android_mobile::android_write_terminal,
            android_mobile::android_read_terminal,
            android_mobile::android_resize_terminal,
            android_mobile::android_close_terminal,
            android_mobile::android_store_credential,
            android_mobile::android_delete_credential
        ])
        .run(tauri::generate_context!())
        .expect("error while running VPShell");
}

#[cfg(test)]
mod tests {
    use super::{
        StartMoshRequest, StartSshRequest, SystemTerminalStartResponse, TerminalOutputEvent,
        ValidatedStartMoshRequest, ValidatedStartSshRequest, mosh_terminal_arguments,
        openssh_terminal_arguments, select_askpass_reference, verify_system_ssh_authentication,
    };

    fn authenticated_connection() -> super::app_store::AuthenticatedConnectionRecord {
        super::app_store::AuthenticatedConnectionRecord {
            id: "018f1f55-26f8-7a9f-9cd8-4d7558482214".to_string(),
            host_id: "host-1".to_string(),
            connected_at: "2026-08-19T00:00:00.000Z".to_string(),
            path: "~".to_string(),
        }
    }

    fn openssh_request() -> StartSshRequest {
        StartSshRequest {
            session_id: Some("018f1f55-26f8-7a9f-9cd8-4d7558482211".to_string()),
            host: "host.example".to_string(),
            port: 22,
            username: "operator".to_string(),
            identity_file: Some("/tmp/vpshell-test-key".to_string()),
            credential_ref: Some("ssh-018f1f55-26f8-7a9f-9cd8-4d7558482212".to_string()),
            identity_passphrase_ref: Some("key-018f1f55-26f8-7a9f-9cd8-4d7558482213".to_string()),
            cols: Some(120),
            rows: Some(32),
        }
    }

    fn mosh_request() -> StartMoshRequest {
        StartMoshRequest {
            session_id: Some("018f1f55-26f8-7a9f-9cd8-4d7558482211".to_string()),
            host: "host.example".to_string(),
            port: 22,
            username: "operator".to_string(),
            identity_file: Some("/tmp/vpshell-mosh-key".to_string()),
            credential_ref: Some("ssh-018f1f55-26f8-7a9f-9cd8-4d7558482212".to_string()),
            identity_passphrase_ref: Some("key-018f1f55-26f8-7a9f-9cd8-4d7558482213".to_string()),
            cols: Some(120),
            rows: Some(32),
            udp_port_start: 60_000,
            udp_port_end: 61_000,
        }
    }

    #[test]
    fn askpass_only_selects_secrets_for_authentication_prompts() {
        assert_eq!(
            select_askpass_reference("root@example's password:", Some("ssh-a"), Some("key-a")),
            Some("ssh-a")
        );
        assert_eq!(
            select_askpass_reference("Enter passphrase for key", Some("ssh-a"), Some("key-a")),
            Some("key-a")
        );
        assert_eq!(
            select_askpass_reference(
                "Are you sure you want to continue connecting?",
                Some("ssh-a"),
                None
            ),
            None
        );
        assert_eq!(
            select_askpass_reference("root@example's password:", None, Some("key-a")),
            None
        );
        assert_eq!(
            select_askpass_reference("Enter passphrase for key", Some("ssh-a"), None),
            None
        );
    }

    #[test]
    fn terminal_output_only_serializes_native_delivery_ids() {
        let compatible = serde_json::to_value(TerminalOutputEvent {
            session_id: "session-a".to_string(),
            data: "b3V0cHV0".to_string(),
            delivery_id: None,
        })
        .unwrap();
        assert!(compatible.get("deliveryId").is_none());

        let native = serde_json::to_value(TerminalOutputEvent {
            session_id: "session-b".to_string(),
            data: "b3V0cHV0".to_string(),
            delivery_id: Some(7),
        })
        .unwrap();
        assert_eq!(native["deliveryId"], 7);
    }

    #[test]
    fn openssh_request_and_arguments_are_bounded_and_fail_closed() {
        let validated = ValidatedStartSshRequest::try_from(openssh_request()).unwrap();
        let arguments = openssh_terminal_arguments(&validated, "curve25519-sha256");
        let has_pair = |first: &str, second: &str| {
            arguments
                .windows(2)
                .any(|pair| pair[0] == first && pair[1] == second)
        };
        assert!(has_pair("-o", "StrictHostKeyChecking=yes"));
        assert!(has_pair("-o", "IdentitiesOnly=yes"));
        assert!(has_pair("-o", "NumberOfPasswordPrompts=1"));
        assert!(has_pair("--", "operator@host.example"));
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.starts_with("ssh-"))
        );
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.starts_with("key-"))
        );
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.contains("ProxyCommand"))
        );

        let mut invalid = openssh_request();
        invalid.host = "-oProxyCommand=bad".to_string();
        assert!(ValidatedStartSshRequest::try_from(invalid).is_err());
        let mut invalid = openssh_request();
        invalid.username = "operator@other".to_string();
        assert!(ValidatedStartSshRequest::try_from(invalid).is_err());
        let mut invalid = openssh_request();
        invalid.port = 0;
        assert!(ValidatedStartSshRequest::try_from(invalid).is_err());
        let mut invalid = openssh_request();
        invalid.cols = Some(1001);
        assert!(ValidatedStartSshRequest::try_from(invalid).is_err());
        let mut invalid = openssh_request();
        invalid.session_id = Some("not-a-uuid".to_string());
        assert!(ValidatedStartSshRequest::try_from(invalid).is_err());
        assert!(
            serde_json::from_value::<StartSshRequest>(serde_json::json!({
                "host": "host.example",
                "port": 22,
                "username": "operator",
                "proxyCommand": "unsafe"
            }))
            .is_err()
        );
    }

    #[test]
    fn system_terminal_response_identifies_the_effective_engine() {
        let value = serde_json::to_value(SystemTerminalStartResponse {
            schema_version: 1,
            engine: "openssh",
            session_id: "018f1f55-26f8-7a9f-9cd8-4d7558482211".to_string(),
            connection: authenticated_connection(),
        })
        .unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["engine"], "openssh");
        assert_eq!(value["sessionId"], "018f1f55-26f8-7a9f-9cd8-4d7558482211");
        assert_eq!(value["connection"]["hostId"], "host-1");
    }

    #[test]
    fn mosh_request_and_bootstrap_are_fixed_bounded_and_value_free() {
        let validated = ValidatedStartMoshRequest::try_from(mosh_request()).unwrap();
        let arguments = mosh_terminal_arguments(&validated, "curve25519-sha256").unwrap();
        assert!(arguments.contains(&"--predict=adaptive".to_string()));
        assert!(arguments.contains(&"--port=60000:61000".to_string()));
        assert!(arguments.contains(&"--server=mosh-server".to_string()));
        assert_eq!(arguments[arguments.len() - 2], "--");
        assert_eq!(arguments.last().unwrap(), "operator@host.example");
        let ssh = arguments
            .iter()
            .find(|argument| argument.starts_with("--ssh="))
            .unwrap();
        assert!(ssh.contains("StrictHostKeyChecking=yes"));
        assert!(ssh.contains("KexAlgorithms=curve25519-sha256"));
        assert!(ssh.contains("NumberOfPasswordPrompts=1"));
        assert!(!ssh.contains("ProxyCommand"));
        assert!(!ssh.contains("ssh-018f1f55"));
        assert!(!ssh.contains("key-018f1f55"));
        assert!(mosh_terminal_arguments(&validated, "unsafe kex").is_err());

        let mut invalid = mosh_request();
        invalid.udp_port_start = 59_999;
        assert!(ValidatedStartMoshRequest::try_from(invalid).is_err());
        let mut invalid = mosh_request();
        invalid.udp_port_end = 61_001;
        assert!(ValidatedStartMoshRequest::try_from(invalid).is_err());
        let mut invalid = mosh_request();
        invalid.host = "-oProxyCommand=bad".to_string();
        assert!(ValidatedStartMoshRequest::try_from(invalid).is_err());
        let mut invalid = mosh_request();
        invalid.host = "host.example;unsafe".to_string();
        assert!(ValidatedStartMoshRequest::try_from(invalid).is_err());
        let mut invalid = mosh_request();
        invalid.username = "operator$(unsafe)".to_string();
        assert!(ValidatedStartMoshRequest::try_from(invalid).is_err());
        let mut invalid = mosh_request();
        invalid.identity_file = Some("/tmp/key';unsafe".to_string());
        assert!(ValidatedStartMoshRequest::try_from(invalid).is_err());
        assert!(
            serde_json::from_value::<StartMoshRequest>(serde_json::json!({
                "host": "host.example",
                "port": 22,
                "username": "operator",
                "udpPortStart": 60000,
                "udpPortEnd": 61000,
                "server": "unsafe-command"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<StartMoshRequest>(serde_json::json!({
                "host": "host.example",
                "port": 22,
                "username": "operator",
                "udpPortStart": 60000,
                "udpPortEnd": 61000,
                "password": "forbidden"
            }))
            .is_err()
        );
    }

    #[test]
    fn mosh_response_is_explicitly_distinct_from_ssh() {
        let value = serde_json::to_value(SystemTerminalStartResponse {
            schema_version: 1,
            engine: "mosh",
            session_id: "018f1f55-26f8-7a9f-9cd8-4d7558482211".to_string(),
            connection: authenticated_connection(),
        })
        .unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["engine"], "mosh");
    }

    #[test]
    fn real_system_openssh_terminal_when_configured() {
        let Ok(host) = std::env::var("VPSHELL_NATIVE_TEST_HOST") else {
            return;
        };
        let port = std::env::var("VPSHELL_NATIVE_TEST_PORT")
            .expect("OpenSSH test port")
            .parse()
            .expect("numeric OpenSSH test port");
        let username = std::env::var("VPSHELL_NATIVE_TEST_USER").expect("OpenSSH test username");
        let identity_file =
            std::env::var("VPSHELL_NATIVE_TEST_IDENTITY_FILE").expect("OpenSSH test identity file");
        let request = ValidatedStartSshRequest::try_from(StartSshRequest {
            session_id: Some(uuid::Uuid::new_v4().to_string()),
            host,
            port,
            username,
            identity_file: Some(identity_file),
            credential_ref: None,
            identity_passphrase_ref: None,
            cols: Some(120),
            rows: Some(32),
        })
        .expect("validated OpenSSH fixture request");
        let kex = super::file_transfer::openssh_kex_algorithms().expect("OpenSSH KEX policy");
        verify_system_ssh_authentication(&request, &kex)
            .expect("bounded OpenSSH authentication check");
        let mut arguments = openssh_terminal_arguments(&request, &kex);
        arguments.push("printf 'VPSHELL_SYSTEM_OPENSSH_OK\\n'".to_string());
        let output = std::process::Command::new("ssh")
            .args(arguments)
            .output()
            .expect("run system OpenSSH fixture");
        let combined = [output.stdout, output.stderr].concat();
        assert!(output.status.success(), "system OpenSSH failed");
        assert!(
            combined
                .windows(b"VPSHELL_SYSTEM_OPENSSH_OK".len())
                .any(|window| window == b"VPSHELL_SYSTEM_OPENSSH_OK")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_mosh_terminal_when_configured() {
        use std::{
            io::Read,
            sync::mpsc,
            thread,
            time::{Duration, Instant},
        };

        use portable_pty::{CommandBuilder, PtySize, native_pty_system};

        let Ok(host) = std::env::var("VPSHELL_NATIVE_TEST_HOST") else {
            return;
        };
        let port = std::env::var("VPSHELL_NATIVE_TEST_PORT")
            .expect("Mosh bootstrap test port")
            .parse()
            .expect("numeric Mosh bootstrap test port");
        let username =
            std::env::var("VPSHELL_NATIVE_TEST_USER").expect("Mosh bootstrap test username");
        let identity_file = std::env::var("VPSHELL_NATIVE_TEST_IDENTITY_FILE")
            .expect("Mosh bootstrap test identity file");
        let request = ValidatedStartMoshRequest::try_from(StartMoshRequest {
            session_id: Some(uuid::Uuid::new_v4().to_string()),
            host,
            port,
            username,
            identity_file: Some(identity_file),
            credential_ref: None,
            identity_passphrase_ref: None,
            cols: Some(120),
            rows: Some(32),
            udp_port_start: 60_000,
            udp_port_end: 61_000,
        })
        .expect("validated Mosh fixture request");
        let kex = super::file_transfer::openssh_kex_algorithms().expect("Mosh SSH KEX policy");
        let mut arguments =
            mosh_terminal_arguments(&request, &kex).expect("validated Mosh fixture arguments");
        arguments.extend([
            "sh".to_string(),
            "-lc".to_string(),
            "printf 'VPSHELL_MOSH_OK\\n'; sleep 5".to_string(),
        ]);

        let pair = native_pty_system()
            .openpty(PtySize {
                rows: request.ssh.rows,
                cols: request.ssh.cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open Mosh fixture PTY");
        let mut command = CommandBuilder::new("mosh");
        for argument in arguments {
            command.arg(argument);
        }
        command.env("TERM", "xterm-256color");
        command.env("LANG", "C.UTF-8");
        command.env("LC_ALL", "C.UTF-8");
        let mut child = pair
            .slave
            .spawn_command(command)
            .expect("start real Mosh fixture");
        drop(pair.slave);
        let mut killer = child.clone_killer();
        let mut reader = pair.master.try_clone_reader().expect("clone Mosh reader");
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(length) = reader.read(&mut buffer) {
                if length == 0 || sender.send(buffer[..length].to_vec()).is_err() {
                    break;
                }
            }
        });

        let marker = b"VPSHELL_MOSH_OK";
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut output = Vec::new();
        while Instant::now() < deadline
            && !output.windows(marker.len()).any(|window| window == marker)
        {
            match receiver.recv_timeout(Duration::from_millis(500)) {
                Ok(chunk) => output.extend_from_slice(&chunk),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let _ = killer.kill();
        let _ = child.wait();
        assert!(
            output.windows(marker.len()).any(|window| window == marker),
            "real Mosh fixture did not produce its marker"
        );
    }
}

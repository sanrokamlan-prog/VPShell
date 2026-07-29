use std::{
    collections::HashMap,
    io::{Read, Write},
    sync::{Arc, Mutex},
    thread,
};

use base64::prelude::*;
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde::{Deserialize, Serialize};
use tauri::{Emitter, State};

mod external_editor;
mod file_transfer;
mod finalshell;
mod key_management;
mod network_tools;
mod remote_monitor;

pub(crate) const CREDENTIAL_SERVICE: &str = "com.sanro.vpshell.credentials";
pub(crate) const LEGACY_CREDENTIAL_SERVICE: &str = "com.sanro.opsshell.credentials";

struct TerminalHandle {
    writer: Box<dyn Write + Send>,
    master: Box<dyn MasterPty + Send>,
    killer: Box<dyn ChildKiller + Send + Sync>,
}

#[derive(Default)]
struct TerminalManager {
    sessions: Arc<Mutex<HashMap<String, TerminalHandle>>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartSshRequest {
    session_id: Option<String>,
    host: String,
    port: u16,
    username: String,
    proxy_jump: Option<String>,
    identity_file: Option<String>,
    cols: Option<u16>,
    rows: Option<u16>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartSshResponse {
    session_id: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalOutputEvent {
    session_id: String,
    data: String,
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

fn validate_proxy_jump(value: &str) -> Result<(), String> {
    if value.len() > 1024
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err("ProxyJump 格式无效".to_string());
    }
    let hops = value.split(',').collect::<Vec<_>>();
    if hops.is_empty() || hops.len() > 4 || hops.iter().any(|hop| hop.is_empty()) {
        return Err("ProxyJump 必须包含 1 到 4 个有效跳点".to_string());
    }
    for hop in hops {
        if hop.starts_with('-')
            || !hop.chars().all(|character| {
                character.is_ascii_alphanumeric()
                    || matches!(character, '.' | '-' | '_' | '@' | ':' | '[' | ']')
            })
        {
            return Err(format!("ProxyJump 跳点格式不安全: {hop}"));
        }
        let mut address = hop;
        if let Some((username, remainder)) = hop.split_once('@') {
            if username.is_empty() || remainder.is_empty() || remainder.contains('@') {
                return Err(format!("ProxyJump 用户或地址无效: {hop}"));
            }
            address = remainder;
        }
        let port = if address.starts_with('[') {
            let closing = address
                .find(']')
                .ok_or_else(|| format!("ProxyJump IPv6 地址缺少右括号: {hop}"))?;
            if closing == 1 {
                return Err(format!("ProxyJump 主机地址为空: {hop}"));
            }
            let suffix = &address[closing + 1..];
            if suffix.is_empty() {
                None
            } else {
                suffix
                    .strip_prefix(':')
                    .ok_or_else(|| format!("ProxyJump IPv6 端口格式无效: {hop}"))?
                    .into()
            }
        } else {
            if address.matches(':').count() > 1 {
                return Err(format!("ProxyJump IPv6 地址必须使用方括号: {hop}"));
            }
            match address.rsplit_once(':') {
                Some((host, port)) if !host.is_empty() => Some(port),
                _ if !address.is_empty() => None,
                _ => return Err(format!("ProxyJump 主机地址为空: {hop}")),
            }
        };
        if let Some(port) = port {
            let port = port
                .parse::<u16>()
                .map_err(|_| format!("ProxyJump 端口无效: {hop}"))?;
            if port == 0 {
                return Err(format!("ProxyJump 端口无效: {hop}"));
            }
        }
    }
    Ok(())
}

#[tauri::command]
fn start_ssh_session(
    app: tauri::AppHandle,
    manager: State<'_, TerminalManager>,
    request: StartSshRequest,
) -> Result<StartSshResponse, String> {
    if request.host.trim().is_empty() || request.username.trim().is_empty() {
        return Err("主机地址和用户名不能为空".to_string());
    }
    if request.host.starts_with('-')
        || request.host.chars().any(char::is_whitespace)
        || request.host.chars().any(char::is_control)
    {
        return Err("主机地址格式无效".to_string());
    }
    if request.username.starts_with('-')
        || request.username.contains('@')
        || request.username.chars().any(char::is_whitespace)
        || request.username.chars().any(char::is_control)
    {
        return Err("SSH 用户名格式无效".to_string());
    }
    if let Some(proxy_jump) = request
        .proxy_jump
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        validate_proxy_jump(proxy_jump)?;
    }

    let session_id = request
        .session_id
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    if lock_sessions(&manager)?.contains_key(&session_id) {
        return Err("该终端会话已经连接".to_string());
    }

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: request.rows.unwrap_or(32),
            cols: request.cols.unwrap_or(120),
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| format!("无法创建终端: {error}"))?;

    let mut command = CommandBuilder::new("ssh");
    command.arg("-tt");
    command.arg("-o");
    command.arg("ServerAliveInterval=30");
    command.arg("-o");
    command.arg("ServerAliveCountMax=3");
    command.arg("-p");
    command.arg(request.port.to_string());

    if let Some(proxy_jump) = request.proxy_jump.filter(|value| !value.trim().is_empty()) {
        command.arg("-J");
        command.arg(proxy_jump);
    }

    if let Some(identity_file) = request
        .identity_file
        .filter(|value| !value.trim().is_empty())
    {
        command.arg("-i");
        command.arg(identity_file);
    }

    command.arg("--");
    command.arg(format!("{}@{}", request.username, request.host));
    command.env("TERM", "xterm-256color");

    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| format!("无法启动 OpenSSH: {error}"))?;
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

    lock_sessions(&manager)?.insert(
        session_id.clone(),
        TerminalHandle {
            writer,
            master: pair.master,
            killer,
        },
    );

    let output_app = app.clone();
    let output_session_id = session_id.clone();
    thread::spawn(move || {
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    let _ = output_app.emit(
                        "terminal-output",
                        TerminalOutputEvent {
                            session_id: output_session_id.clone(),
                            data: BASE64_STANDARD.encode(&buffer[..length]),
                        },
                    );
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
        if let Ok(mut sessions) = wait_sessions.lock() {
            sessions.remove(&wait_session_id);
        }
        let _ = wait_app.emit(
            "terminal-exit",
            TerminalExitEvent {
                session_id: wait_session_id,
                message: exit_message,
            },
        );
    });

    Ok(StartSshResponse { session_id })
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
    session
        .writer
        .write_all(data.as_bytes())
        .map_err(|error| format!("终端写入失败: {error}"))?;
    session
        .writer
        .flush()
        .map_err(|error| format!("终端刷新失败: {error}"))
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
    session
        .writer
        .write_all(data)
        .map_err(|error| format!("终端写入失败: {error}"))?;
    session
        .writer
        .flush()
        .map_err(|error| format!("终端刷新失败: {error}"))
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
    session
        .master
        .resize(PtySize {
            rows: rows.max(2),
            cols: cols.max(2),
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| format!("调整终端尺寸失败: {error}"))
}

#[tauri::command]
fn stop_terminal(manager: State<'_, TerminalManager>, session_id: String) -> Result<(), String> {
    let mut sessions = lock_sessions(&manager)?;
    let mut session = sessions
        .remove(&session_id)
        .ok_or_else(|| "终端会话不存在或已关闭".to_string())?;
    session
        .killer
        .kill()
        .map_err(|error| format!("关闭终端失败: {error}"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(TerminalManager::default())
        .manage(external_editor::ExternalEditorManager::default())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            start_ssh_session,
            write_terminal,
            resize_terminal,
            stop_terminal,
            import_finalshell,
            generate_ssh_key,
            install_public_key,
            file_transfer::list_remote_files,
            file_transfer::upload_remote,
            file_transfer::download_remote,
            external_editor::begin_external_edit,
            external_editor::get_external_edit_status,
            external_editor::save_external_edit,
            external_editor::reload_external_edit,
            external_editor::end_external_edit,
            network_tools::trace_route,
            network_tools::download_speed_test,
            network_tools::udp_speed_test,
            remote_monitor::fetch_remote_metrics
        ])
        .run(tauri::generate_context!())
        .expect("error while running VPShell");
}

#[cfg(test)]
mod tests {
    use super::validate_proxy_jump;

    #[test]
    fn accepts_bounded_proxy_jump_routes() {
        assert!(validate_proxy_jump("ops@gateway.example:2222").is_ok());
        assert!(validate_proxy_jump("first,[2001:db8::2]:22").is_ok());
    }

    #[test]
    fn rejects_proxy_jump_option_injection_and_bad_ports() {
        assert!(validate_proxy_jump("-oProxyCommand=bad").is_err());
        assert!(validate_proxy_jump("host:0").is_err());
        assert!(validate_proxy_jump("host name").is_err());
        assert!(validate_proxy_jump("a,b,c,d,e").is_err());
    }
}

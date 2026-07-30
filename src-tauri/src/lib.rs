use std::{
    collections::HashMap,
    env,
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
const ASKPASS_MODE_ENV: &str = "VPSHELL_SSH_ASKPASS";
const ASKPASS_PASSWORD_REF_ENV: &str = "VPSHELL_SSH_CREDENTIAL_REF";
const ASKPASS_KEY_REF_ENV: &str = "VPSHELL_SSH_KEY_PASSPHRASE_REF";

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
    identity_file: Option<String>,
    credential_ref: Option<String>,
    identity_passphrase_ref: Option<String>,
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
    command.arg("-o");
    command.arg("NumberOfPasswordPrompts=1");
    Ok(())
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
    command.arg("-o");
    command.arg("StrictHostKeyChecking=yes");
    command.arg("-p");
    command.arg(request.port.to_string());

    let identity_file = request
        .identity_file
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    if let Some(identity_file) = identity_file {
        command.arg("-o");
        command.arg("IdentitiesOnly=yes");
        command.arg("-i");
        command.arg(identity_file);
    }

    if request.credential_ref.is_some() {
        // Do not let unrelated agent keys exhaust sshd MaxAuthTries before the imported password.
        command.arg("-o");
        command.arg("IdentitiesOnly=yes");
        command.arg("-o");
        command.arg(if identity_file.is_some() {
            "PreferredAuthentications=publickey,keyboard-interactive,password"
        } else {
            "PreferredAuthentications=keyboard-interactive,password"
        });
        command.arg("-o");
        command.arg("PasswordAuthentication=yes");
        command.arg("-o");
        command.arg("KbdInteractiveAuthentication=yes");
    }

    configure_ssh_askpass(
        &mut command,
        request.credential_ref.as_deref(),
        request.identity_passphrase_ref.as_deref(),
    )?;

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

#[tauri::command]
fn delete_credential(reference: String) -> Result<(), String> {
    file_transfer::validate_optional_reference(Some(&reference), "ssh-")?;
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
            delete_credential,
            import_finalshell,
            file_transfer::inspect_host_key,
            file_transfer::trust_host_key,
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
    use super::select_askpass_reference;

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
}

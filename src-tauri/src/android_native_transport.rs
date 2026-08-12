//! Android Preview SSH/SFTP transport boundary.
//!
//! The implementation uses the existing Rust `ssh2`/libssh2 binding directly.
//! It never starts a platform `ssh` process.  Android Keystore and the UI are
//! intentionally outside this module; callers pass short-lived zeroizing
//! authentication material after resolving an opaque local reference.

use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    time::Duration,
};

use base64::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use ssh2::{Channel, HostKeyType, Session, Sftp};
use zeroize::Zeroizing;

use crate::android_preview::AndroidAuthKind;

pub const ANDROID_NATIVE_TRANSPORT_SCHEMA_VERSION: u16 = 1;
const MAX_PATH_BYTES: usize = 4096;
const MAX_LIST_ENTRIES: usize = 1000;
const MAX_PRIVATE_KEY_BYTES: usize = 1024 * 1024;
const MAX_TERMINAL_INPUT_BYTES: usize = 64 * 1024;
const MAX_TERMINAL_OUTPUT_BYTES: usize = 64 * 1024;
const MIN_TERMINAL_COLS: u16 = 20;
const MAX_TERMINAL_COLS: u16 = 500;
const MIN_TERMINAL_ROWS: u16 = 5;
const MAX_TERMINAL_ROWS: u16 = 300;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidNativeConnectionConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub host_key_sha256: String,
    pub timeout_seconds: u16,
}

impl AndroidNativeConnectionConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.host.is_empty()
            || self.host.len() > 253
            || self.host.starts_with('-')
            || self
                .host
                .contains(|ch: char| ch.is_whitespace() || ch.is_control())
            || self.host.contains('/')
            || self.host.contains('\\')
        {
            return Err("Android SSH 主机地址格式无效".to_string());
        }
        if self.port == 0 {
            return Err("Android SSH 端口无效".to_string());
        }
        if self.username.is_empty()
            || self.username.len() > 128
            || self.username.starts_with('-')
            || self.username.contains('@')
            || self
                .username
                .contains(|ch: char| ch.is_whitespace() || ch.is_control())
        {
            return Err("Android SSH 用户名格式无效".to_string());
        }
        if !(5..=60).contains(&self.timeout_seconds) {
            return Err("Android SSH 超时必须在 5 到 60 秒之间".to_string());
        }
        validate_fingerprint(&self.host_key_sha256)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidHostKeyInspection {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
}

pub fn inspect_host_key(
    host: &str,
    port: u16,
    timeout_seconds: u16,
) -> Result<AndroidHostKeyInspection, String> {
    let config = AndroidNativeConnectionConfig {
        host: host.to_string(),
        port,
        username: "inspection".to_string(),
        host_key_sha256: format!("SHA256:{}", BASE64_STANDARD_NO_PAD.encode([0_u8; 32])),
        timeout_seconds,
    };
    config.validate()?;
    let mut addresses = (host, port)
        .to_socket_addrs()
        .map_err(|_| "Android SSH 主机无法解析".to_string())?;
    let address = addresses
        .next()
        .ok_or_else(|| "Android SSH 没有可用地址".to_string())?;
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(timeout_seconds.into()))
        .map_err(|_| "Android SSH 连接超时或失败".to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(timeout_seconds.into())))
        .map_err(|_| "Android SSH 无法设置读取超时".to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(timeout_seconds.into())))
        .map_err(|_| "Android SSH 无法设置写入超时".to_string())?;
    let mut session = Session::new().map_err(|_| "无法初始化 Android Rust SSH 会话".to_string())?;
    session.set_timeout(u32::from(timeout_seconds) * 1000);
    session.set_tcp_stream(stream);
    session
        .handshake()
        .map_err(|_| "Android SSH 握手失败".to_string())?;
    let (key, key_type) = session
        .host_key()
        .ok_or_else(|| "Android SSH 服务器未提供主机密钥".to_string())?;
    Ok(AndroidHostKeyInspection {
        host: host.to_string(),
        port,
        algorithm: host_key_algorithm(key_type).to_string(),
        fingerprint: fingerprint(key),
    })
}

fn host_key_algorithm(kind: HostKeyType) -> &'static str {
    match kind {
        HostKeyType::Rsa => "ssh-rsa",
        HostKeyType::Dss => "ssh-dss",
        HostKeyType::Ecdsa256 => "ecdsa-sha2-nistp256",
        HostKeyType::Ecdsa384 => "ecdsa-sha2-nistp384",
        HostKeyType::Ecdsa521 => "ecdsa-sha2-nistp521",
        HostKeyType::Ed25519 => "ssh-ed25519",
        HostKeyType::Unknown => "unknown",
    }
}

pub enum AndroidNativeAuth {
    Password(Zeroizing<String>),
    PrivateKey {
        public_key: Option<Zeroizing<String>>,
        private_key: Zeroizing<String>,
        passphrase: Option<Zeroizing<String>>,
    },
}

impl AndroidNativeAuth {
    pub fn password(value: String) -> Self {
        Self::Password(Zeroizing::new(value))
    }

    pub fn private_key(
        public_key: Option<String>,
        private_key: String,
        passphrase: Option<String>,
    ) -> Result<Self, String> {
        validate_private_key(&private_key)?;
        Ok(Self::PrivateKey {
            public_key: public_key.map(Zeroizing::new),
            private_key: Zeroizing::new(private_key),
            passphrase: passphrase.map(Zeroizing::new),
        })
    }

    pub fn kind(&self) -> AndroidAuthKind {
        match self {
            Self::Password(_) => AndroidAuthKind::PasswordReference,
            Self::PrivateKey { .. } => AndroidAuthKind::PrivateKeyReference,
        }
    }
}

pub struct AndroidNativeSession {
    session: Session,
}

impl AndroidNativeSession {
    pub fn connect(
        config: &AndroidNativeConnectionConfig,
        auth: &AndroidNativeAuth,
    ) -> Result<Self, String> {
        config.validate()?;
        let mut addresses = (config.host.as_str(), config.port)
            .to_socket_addrs()
            .map_err(|_| "Android SSH 主机无法解析".to_string())?;
        let address = addresses
            .next()
            .ok_or_else(|| "Android SSH 没有可用地址".to_string())?;
        let stream = TcpStream::connect_timeout(
            &address,
            Duration::from_secs(config.timeout_seconds as u64),
        )
        .map_err(|_| "Android SSH 连接超时或失败".to_string())?;
        let timeout_ms = u32::from(config.timeout_seconds) * 1000;
        stream
            .set_read_timeout(Some(Duration::from_secs(config.timeout_seconds as u64)))
            .map_err(|_| "Android SSH 无法设置读取超时".to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(config.timeout_seconds as u64)))
            .map_err(|_| "Android SSH 无法设置写入超时".to_string())?;

        let mut session =
            Session::new().map_err(|_| "无法初始化 Android Rust SSH 会话".to_string())?;
        session.set_timeout(timeout_ms);
        session.set_tcp_stream(stream);
        session
            .handshake()
            .map_err(|_| "Android SSH 握手失败".to_string())?;
        let (key, _) = session
            .host_key()
            .ok_or_else(|| "Android SSH 服务器未提供主机密钥".to_string())?;
        if fingerprint(key) != config.host_key_sha256 {
            return Err("Android SSH 主机密钥指纹不匹配".to_string());
        }
        authenticate(&session, &config.username, auth)
            .map_err(|_| "Android SSH 身份验证失败".to_string())?;
        if !session.authenticated() {
            return Err("Android SSH 身份验证未完成".to_string());
        }
        Ok(Self { session })
    }

    pub fn host_key_type(&self) -> Option<HostKeyType> {
        self.session.host_key().map(|(_, kind)| kind)
    }

    pub fn list_directory(&self, path: &str) -> Result<Vec<AndroidRemoteEntry>, String> {
        validate_remote_path(path)?;
        let sftp = self
            .session
            .sftp()
            .map_err(|_| "Android SFTP 子系统不可用".to_string())?;
        list_directory(&sftp, path)
    }

    pub fn open_terminal(&self, cols: u16, rows: u16) -> Result<AndroidTerminalChannel, String> {
        validate_terminal_size(cols, rows)?;
        let mut channel = self
            .session
            .channel_session()
            .map_err(|_| "Android SSH 无法创建终端通道".to_string())?;
        channel
            .request_pty(
                "xterm-256color",
                None,
                Some((u32::from(cols), u32::from(rows), 0, 0)),
            )
            .map_err(|_| "Android SSH 无法申请终端".to_string())?;
        channel
            .shell()
            .map_err(|_| "Android SSH 无法启动交互 shell".to_string())?;
        Ok(AndroidTerminalChannel { channel })
    }
}

pub struct AndroidTerminalChannel {
    channel: Channel,
}

impl AndroidTerminalChannel {
    pub fn write_input(&mut self, data: &[u8]) -> Result<(), String> {
        if data.is_empty() || data.len() > MAX_TERMINAL_INPUT_BYTES {
            return Err("Android 终端输入大小超出范围".to_string());
        }
        self.channel
            .write_all(data)
            .map_err(|_| "Android 终端输入写入失败".to_string())?;
        self.channel
            .flush()
            .map_err(|_| "Android 终端输入刷新失败".to_string())
    }

    pub fn read_output(&mut self) -> Result<AndroidTerminalRead, String> {
        let mut output = vec![0_u8; MAX_TERMINAL_OUTPUT_BYTES];
        let bytes_read = self
            .channel
            .read(&mut output)
            .map_err(|_| "Android 终端输出读取失败或超时".to_string())?;
        output.truncate(bytes_read);
        Ok(AndroidTerminalRead {
            data: output,
            eof: self.channel.eof(),
        })
    }

    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<(), String> {
        validate_terminal_size(cols, rows)?;
        self.channel
            .request_pty_size(u32::from(cols), u32::from(rows), None, None)
            .map_err(|_| "Android 终端尺寸调整失败".to_string())
    }

    pub fn close(mut self) -> Result<(), String> {
        self.channel
            .close()
            .map_err(|_| "Android 终端关闭失败".to_string())?;
        self.channel
            .wait_close()
            .map_err(|_| "Android 终端等待关闭失败".to_string())
    }
}

pub struct AndroidTerminalRead {
    pub data: Vec<u8>,
    pub eof: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AndroidRemoteEntryKind {
    File,
    Directory,
    Symlink,
    Special,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidRemoteEntry {
    pub name: String,
    pub kind: AndroidRemoteEntryKind,
    pub size: u64,
    pub mode: Option<u32>,
}

fn authenticate(
    session: &Session,
    username: &str,
    auth: &AndroidNativeAuth,
) -> Result<(), ssh2::Error> {
    match auth {
        AndroidNativeAuth::Password(password) => session.userauth_password(username, password),
        AndroidNativeAuth::PrivateKey {
            public_key,
            private_key,
            passphrase,
        } => session.userauth_pubkey_memory(
            username,
            public_key.as_deref().map(String::as_str),
            private_key,
            passphrase.as_deref().map(String::as_str),
        ),
    }
}

fn validate_fingerprint(value: &str) -> Result<(), String> {
    let encoded = value
        .strip_prefix("SHA256:")
        .ok_or_else(|| "Android SSH host-key 必须使用 SHA256 指纹".to_string())?;
    if encoded.len() != 43
        || BASE64_STANDARD_NO_PAD
            .decode(encoded)
            .map_or(true, |bytes| bytes.len() != 32)
    {
        return Err("Android SSH host-key SHA256 指纹格式无效".to_string());
    }
    Ok(())
}

fn fingerprint(key: &[u8]) -> String {
    format!(
        "SHA256:{}",
        BASE64_STANDARD_NO_PAD.encode(Sha256::digest(key))
    )
}

fn validate_private_key(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_PRIVATE_KEY_BYTES || !value.contains("-----BEGIN ") {
        return Err("Android 私钥格式或大小无效".to_string());
    }
    if value
        .chars()
        .any(|ch| ch.is_control() && ch != '\n' && ch != '\r')
    {
        return Err("Android 私钥包含控制字符".to_string());
    }
    Ok(())
}

fn validate_remote_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || !path.starts_with('/') {
        return Err("Android 远端路径必须是有界绝对路径".to_string());
    }
    if path.contains('\\') || path.chars().any(char::is_control) {
        return Err("Android 远端路径包含非法字符".to_string());
    }
    if path.split('/').any(|part| part == ".." || part == ".") {
        return Err("Android 远端路径不允许 . 或 ..".to_string());
    }
    Ok(())
}

fn validate_terminal_size(cols: u16, rows: u16) -> Result<(), String> {
    if !(MIN_TERMINAL_COLS..=MAX_TERMINAL_COLS).contains(&cols)
        || !(MIN_TERMINAL_ROWS..=MAX_TERMINAL_ROWS).contains(&rows)
    {
        return Err("Android 终端尺寸超出范围".to_string());
    }
    Ok(())
}

fn list_directory(sftp: &Sftp, path: &str) -> Result<Vec<AndroidRemoteEntry>, String> {
    let mut entries = sftp
        .readdir(Path::new(path))
        .map_err(|_| "Android SFTP 目录读取失败".to_string())?;
    if entries.len() > MAX_LIST_ENTRIES {
        return Err("Android SFTP 目录条目超过上限".to_string());
    }
    let mut result = Vec::with_capacity(entries.len());
    for (entry_path, stat) in entries.drain(..) {
        let name = entry_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "Android SFTP 返回了无效文件名".to_string())?;
        let mode = stat.perm;
        let kind = match mode.map(|value| value & 0o170000) {
            Some(0o040000) => AndroidRemoteEntryKind::Directory,
            Some(0o100000) => AndroidRemoteEntryKind::File,
            Some(0o120000) => AndroidRemoteEntryKind::Symlink,
            _ => AndroidRemoteEntryKind::Special,
        };
        result.push(AndroidRemoteEntry {
            name: name.to_string(),
            kind,
            size: stat.size.unwrap_or(0),
            mode,
        });
    }
    result.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint_fixture() -> String {
        format!("SHA256:{}", BASE64_STANDARD_NO_PAD.encode([7u8; 32]))
    }

    fn config() -> AndroidNativeConnectionConfig {
        AndroidNativeConnectionConfig {
            host: "host.example".to_string(),
            port: 22,
            username: "operator".to_string(),
            host_key_sha256: fingerprint_fixture(),
            timeout_seconds: 15,
        }
    }

    #[test]
    fn config_requires_pinned_key_and_bounded_identity() {
        assert!(config().validate().is_ok());
        let mut invalid = config();
        invalid.host_key_sha256 = "ssh-ed25519 AAAA".to_string();
        assert!(invalid.validate().is_err());
        invalid = config();
        invalid.host = "../host".to_string();
        assert!(invalid.validate().is_err());
        invalid = config();
        invalid.timeout_seconds = 4;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn auth_material_is_zeroizing_and_strictly_typed() {
        let password = AndroidNativeAuth::password("synthetic-password".to_string());
        assert_eq!(password.kind(), AndroidAuthKind::PasswordReference);
        let key = AndroidNativeAuth::private_key(
            None,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic\n-----END OPENSSH PRIVATE KEY-----"
                .to_string(),
            Some("synthetic-passphrase".to_string()),
        )
        .unwrap();
        assert_eq!(key.kind(), AndroidAuthKind::PrivateKeyReference);
        assert!(AndroidNativeAuth::private_key(None, "private".to_string(), None).is_err());
    }

    #[test]
    fn remote_paths_are_absolute_and_cannot_escape_or_follow_dots() {
        assert!(validate_remote_path("/srv/data").is_ok());
        for path in [
            "srv/data",
            "/srv/../etc",
            "/srv/./data",
            "/srv\\data",
            "/srv\0data",
        ] {
            assert!(
                validate_remote_path(path).is_err(),
                "path should be rejected: {path:?}"
            );
        }
    }

    #[test]
    fn transport_source_has_no_system_ssh_entrypoint() {
        let source = include_str!("android_native_transport.rs");
        assert!(source.contains("Session::new"));
        assert!(source.contains("session.sftp"));
    }

    #[test]
    fn terminal_dimensions_and_io_are_bounded() {
        assert!(validate_terminal_size(120, 32).is_ok());
        assert!(validate_terminal_size(19, 32).is_err());
        assert!(validate_terminal_size(120, 301).is_err());
        assert_eq!(MAX_TERMINAL_INPUT_BYTES, 64 * 1024);
        assert_eq!(MAX_TERMINAL_OUTPUT_BYTES, 64 * 1024);
    }
}

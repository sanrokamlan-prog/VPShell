use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub const RELAY_PROTOCOL_VERSION: u16 = 1;
const MAGIC: &[u8; 4] = b"VPSR";
const NONCE_BYTES: usize = 32;
const KEY_ID_BYTES: usize = 8;
const MAC_BYTES: usize = 32;
const SESSION_ID_BYTES: usize = 16;
const HELLO_BYTES: usize = 4 + 2 + NONCE_BYTES;
const REQUEST_PREFIX_BYTES: usize = 4 + 2 + NONCE_BYTES + KEY_ID_BYTES + 2;
const RESPONSE_BYTES: usize = 4 + 2 + 1 + SESSION_ID_BYTES + MAC_BYTES;
const MAX_HOST_BYTES: usize = 253;
const MAX_TOKEN_FILE_BYTES: u64 = 128;
const MAX_ACTIVE_TOKENS: usize = 4;
const SOURCE_BUCKET_TTL: Duration = Duration::from_secs(300);
const MAX_SOURCE_BUCKETS: usize = 4096;
const CLIENT_DOMAIN: &[u8] = b"vpshell-relay-v1-client";
const SERVER_DOMAIN: &[u8] = b"vpshell-relay-v1-server";

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RelayTarget {
    host: String,
    port: u16,
}

impl RelayTarget {
    pub fn parse(authority: &str) -> Result<Self, &'static str> {
        if authority.is_empty() || authority.len() > MAX_HOST_BYTES + 8 {
            return Err("relay-target-invalid");
        }
        let (host, port) = if authority.starts_with('[') {
            let close = authority.find(']').ok_or("relay-target-invalid")?;
            let host = &authority[1..close];
            let port = authority
                .get(close + 1..)
                .and_then(|suffix| suffix.strip_prefix(':'))
                .ok_or("relay-target-invalid")?;
            (host, port)
        } else {
            let (host, port) = authority.rsplit_once(':').ok_or("relay-target-invalid")?;
            if host.contains(':') {
                return Err("relay-target-invalid");
            }
            (host, port)
        };
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|value| *value != 0)
            .ok_or("relay-target-invalid")?;
        let host = normalize_host(host)?;
        Ok(Self { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn normalize_host(host: &str) -> Result<String, &'static str> {
    if host.is_empty()
        || host.len() > MAX_HOST_BYTES
        || host.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("relay-target-invalid");
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(address.to_string());
    }
    if !host.is_ascii() || host.starts_with('.') || host.ends_with('.') {
        return Err("relay-target-invalid");
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("relay-target-invalid");
        }
    }
    Ok(host.to_ascii_lowercase())
}

pub struct RelayToken(Zeroizing<[u8; 32]>);

impl RelayToken {
    pub fn from_base64(value: &str) -> Result<Self, &'static str> {
        if value.len() > MAX_TOKEN_FILE_BYTES as usize
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err("relay-token-invalid");
        }
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| "relay-token-invalid")?,
        );
        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| "relay-token-invalid")?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn load(path: &Path) -> Result<Self, &'static str> {
        let link_metadata = fs::symlink_metadata(path).map_err(|_| "relay-token-unavailable")?;
        if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
            return Err("relay-token-file-unsafe");
        }
        if link_metadata.len() == 0 || link_metadata.len() > MAX_TOKEN_FILE_BYTES {
            return Err("relay-token-invalid");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if link_metadata.permissions().mode() & 0o077 != 0 {
                return Err("relay-token-file-permissions");
            }
        }
        let mut file = File::open(path).map_err(|_| "relay-token-unavailable")?;
        let mut encoded = Zeroizing::new(String::new());
        file.take(MAX_TOKEN_FILE_BYTES + 1)
            .read_to_string(&mut encoded)
            .map_err(|_| "relay-token-invalid")?;
        if encoded.len() as u64 > MAX_TOKEN_FILE_BYTES {
            return Err("relay-token-invalid");
        }
        let encoded = encoded
            .strip_suffix("\r\n")
            .or_else(|| encoded.strip_suffix('\n'))
            .unwrap_or(encoded.as_str());
        Self::from_base64(encoded)
    }

    pub fn generate_file(path: &Path) -> Result<(), &'static str> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *bytes).map_err(|_| "relay-random-unavailable")?;
        let encoded = Zeroizing::new(format!("{}\n", URL_SAFE_NO_PAD.encode(bytes.as_slice())));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .map_err(|_| "relay-token-create-failed")?;
        file.write_all(encoded.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|_| "relay-token-create-failed")
    }

    fn key_id(&self) -> [u8; KEY_ID_BYTES] {
        Sha256::digest(self.0.as_slice())[..KEY_ID_BYTES]
            .try_into()
            .expect("fixed digest prefix")
    }

    fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub struct RelayTokenSet {
    tokens: Vec<RelayToken>,
}

impl RelayTokenSet {
    pub fn from_tokens(tokens: Vec<RelayToken>) -> Result<Self, &'static str> {
        if tokens.is_empty() || tokens.len() > MAX_ACTIVE_TOKENS {
            return Err("relay-token-set-invalid");
        }
        let key_ids = tokens
            .iter()
            .map(RelayToken::key_id)
            .collect::<HashSet<_>>();
        if key_ids.len() != tokens.len() {
            return Err("relay-token-set-invalid");
        }
        Ok(Self { tokens })
    }

    pub fn load_files(paths: &[PathBuf]) -> Result<Self, &'static str> {
        if paths.is_empty() || paths.len() > MAX_ACTIVE_TOKENS {
            return Err("relay-token-set-invalid");
        }
        let tokens = paths
            .iter()
            .map(|path| RelayToken::load(path))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_tokens(tokens)
    }

    fn resolve(&self, key_id: &[u8; KEY_ID_BYTES]) -> Option<&RelayToken> {
        self.tokens.iter().find(|token| token.key_id() == *key_id)
    }

    fn primary(&self) -> &RelayToken {
        self.tokens
            .first()
            .expect("validated Relay token set is non-empty")
    }
}

#[derive(Clone, Debug)]
pub struct RelayLimits {
    pub max_connections: usize,
    pub max_connections_per_ip: u16,
    pub auth_attempts_per_minute: u16,
    pub max_session_bytes: u64,
    pub idle_timeout: Duration,
    pub max_session_duration: Duration,
    pub handshake_timeout: Duration,
    pub target_connect_timeout: Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_connections: 128,
            max_connections_per_ip: 8,
            auth_attempts_per_minute: 30,
            max_session_bytes: 1024 * 1024 * 1024,
            idle_timeout: Duration::from_secs(120),
            max_session_duration: Duration::from_secs(4 * 60 * 60),
            handshake_timeout: Duration::from_secs(10),
            target_connect_timeout: Duration::from_secs(10),
        }
    }
}

impl RelayLimits {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(1..=4096).contains(&self.max_connections)
            || self.max_connections_per_ip == 0
            || self.max_connections_per_ip > 256
            || self.auth_attempts_per_minute == 0
            || self.auth_attempts_per_minute > 6000
            || !(1024..=1024 * 1024 * 1024 * 1024).contains(&self.max_session_bytes)
            || !(Duration::from_secs(5)..=Duration::from_secs(3600)).contains(&self.idle_timeout)
            || !(Duration::from_secs(30)..=Duration::from_secs(24 * 60 * 60))
                .contains(&self.max_session_duration)
            || !(Duration::from_secs(1)..=Duration::from_secs(60)).contains(&self.handshake_timeout)
            || !(Duration::from_secs(1)..=Duration::from_secs(60))
                .contains(&self.target_connect_timeout)
        {
            return Err("relay-limits-invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RelayServerConfig {
    pub allowed_targets: Vec<RelayTarget>,
    pub limits: RelayLimits,
}

impl RelayServerConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.limits.validate()?;
        if self.allowed_targets.is_empty() || self.allowed_targets.len() > 256 {
            return Err("relay-target-policy-invalid");
        }
        let unique = self.allowed_targets.iter().collect::<HashSet<_>>();
        if unique.len() != self.allowed_targets.len() {
            return Err("relay-target-policy-invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelayAuditOutcome {
    Accepted,
    Completed,
    Cancelled,
    CapacityExceeded,
    RateLimited,
    InvalidRequest,
    AuthenticationFailed,
    TargetDenied,
    TargetUnavailable,
    ByteLimit,
    IdleTimeout,
    DurationLimit,
    TransportFailed,
    AuditUnavailable,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAuditEvent {
    pub schema_version: u16,
    pub phase: &'static str,
    pub request_id: String,
    pub source_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    pub outcome: RelayAuditOutcome,
    pub transferred_bytes: u64,
    pub duration_ms: u64,
}

pub trait RelayAuditSink: Send + Sync {
    fn record(&self, event: &RelayAuditEvent) -> io::Result<()>;
}

pub struct JsonLineAudit {
    writer: Mutex<Box<dyn Write + Send>>,
}

impl JsonLineAudit {
    pub fn stdout() -> Self {
        Self {
            writer: Mutex::new(Box::new(io::stdout())),
        }
    }

    pub fn file(path: &Path) -> Result<Self, &'static str> {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("relay-audit-file-unsafe");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err("relay-audit-file-permissions");
                }
            }
        }
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|_| "relay-audit-file-unavailable")?;
        Ok(Self {
            writer: Mutex::new(Box::new(file)),
        })
    }
}

impl RelayAuditSink for JsonLineAudit {
    fn record(&self, event: &RelayAuditEvent) -> io::Result<()> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("relay audit lock unavailable"))?;
        serde_json::to_writer(&mut *writer, event).map_err(io::Error::other)?;
        writer.write_all(b"\n")?;
        writer.flush()
    }
}

struct SourceBucket {
    window_started: Instant,
    last_seen: Instant,
    attempts: u16,
    active: u16,
}

struct RelayServerState {
    config: RelayServerConfig,
    tokens: Arc<RelayTokenSet>,
    audit: Arc<dyn RelayAuditSink>,
    audit_healthy: AtomicBool,
    audit_salt: [u8; 32],
    allowed_targets: HashSet<RelayTarget>,
    global: Arc<Semaphore>,
    sources: Mutex<HashMap<IpAddr, SourceBucket>>,
    cancellation: CancellationToken,
}

struct SourceLease {
    state: Arc<RelayServerState>,
    source: IpAddr,
}

impl Drop for SourceLease {
    fn drop(&mut self) {
        if let Ok(mut sources) = self.state.sources.lock()
            && let Some(bucket) = sources.get_mut(&self.source)
        {
            bucket.active = bucket.active.saturating_sub(1);
            bucket.last_seen = Instant::now();
        }
    }
}

impl RelayServerState {
    fn source_id(&self, source: IpAddr) -> String {
        let bytes = match source {
            IpAddr::V4(value) => value.octets().to_vec(),
            IpAddr::V6(value) => value.octets().to_vec(),
        };
        hashed_id(b"source", &self.audit_salt, &bytes)
    }

    fn target_id(&self, target: &RelayTarget) -> String {
        hashed_id(b"target", &self.audit_salt, target.authority().as_bytes())
    }

    fn audit(&self, event: &RelayAuditEvent) -> bool {
        if !self.audit_healthy.load(Ordering::SeqCst) {
            return false;
        }
        if self.audit.record(event).is_err() {
            self.audit_healthy.store(false, Ordering::SeqCst);
            return false;
        }
        true
    }

    fn admit_source(self: &Arc<Self>, source: IpAddr) -> Result<SourceLease, RelayAuditOutcome> {
        let now = Instant::now();
        let mut sources = self
            .sources
            .lock()
            .map_err(|_| RelayAuditOutcome::AuditUnavailable)?;
        sources.retain(|_, bucket| {
            bucket.active != 0 || now.duration_since(bucket.last_seen) < SOURCE_BUCKET_TTL
        });
        if !sources.contains_key(&source) && sources.len() >= MAX_SOURCE_BUCKETS {
            return Err(RelayAuditOutcome::RateLimited);
        }
        let bucket = sources.entry(source).or_insert(SourceBucket {
            window_started: now,
            last_seen: now,
            attempts: 0,
            active: 0,
        });
        if now.duration_since(bucket.window_started) >= Duration::from_secs(60) {
            bucket.window_started = now;
            bucket.attempts = 0;
        }
        bucket.last_seen = now;
        if bucket.attempts >= self.config.limits.auth_attempts_per_minute
            || bucket.active >= self.config.limits.max_connections_per_ip
        {
            return Err(RelayAuditOutcome::RateLimited);
        }
        bucket.attempts += 1;
        bucket.active += 1;
        Ok(SourceLease {
            state: Arc::clone(self),
            source,
        })
    }
}

pub async fn serve(
    listener: TcpListener,
    config: RelayServerConfig,
    tokens: Arc<RelayTokenSet>,
    audit: Arc<dyn RelayAuditSink>,
    cancellation: CancellationToken,
) -> Result<(), &'static str> {
    config.validate()?;
    let mut audit_salt = [0_u8; 32];
    getrandom::fill(&mut audit_salt).map_err(|_| "relay-random-unavailable")?;
    let allowed_targets = config.allowed_targets.iter().cloned().collect();
    let global = Arc::new(Semaphore::new(config.limits.max_connections));
    let state = Arc::new(RelayServerState {
        config,
        tokens,
        audit,
        audit_healthy: AtomicBool::new(true),
        audit_salt,
        allowed_targets,
        global,
        sources: Mutex::new(HashMap::new()),
        cancellation: cancellation.clone(),
    });

    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            accepted = listener.accept() => {
                let (stream, source) = accepted.map_err(|_| "relay-listener-failed")?;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    handle_connection(stream, source, state).await;
                });
            }
        }
    }
}

async fn handle_connection(
    mut client: TcpStream,
    source: SocketAddr,
    state: Arc<RelayServerState>,
) {
    let started = Instant::now();
    let request_id = Uuid::new_v4().simple().to_string();
    let source_id = state.source_id(source.ip());
    if !state.audit_healthy.load(Ordering::SeqCst) {
        return;
    }
    let _global_permit = match Arc::clone(&state.global).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            record_rejection(
                &state,
                request_id,
                source_id,
                RelayAuditOutcome::CapacityExceeded,
                started,
            );
            return;
        }
    };
    let _source_lease = match state.admit_source(source.ip()) {
        Ok(lease) => lease,
        Err(outcome) => {
            record_rejection(&state, request_id, source_id, outcome, started);
            return;
        }
    };

    let mut server_nonce = [0_u8; NONCE_BYTES];
    if getrandom::fill(&mut server_nonce).is_err() {
        record_rejection(
            &state,
            request_id,
            source_id,
            RelayAuditOutcome::TransportFailed,
            started,
        );
        return;
    }
    if client
        .write_all(&encode_hello(&server_nonce))
        .await
        .is_err()
    {
        record_rejection(
            &state,
            request_id,
            source_id,
            RelayAuditOutcome::TransportFailed,
            started,
        );
        return;
    }
    let request = match timeout(
        state.config.limits.handshake_timeout,
        read_request(&mut client),
    )
    .await
    {
        Ok(Ok(request)) => request,
        _ => {
            record_rejection(
                &state,
                request_id,
                source_id,
                RelayAuditOutcome::InvalidRequest,
                started,
            );
            return;
        }
    };
    let selected_token = state.tokens.resolve(&request.key_id);
    let authenticated = selected_token.is_some_and(|token| {
        verify_client_mac(
            token,
            &server_nonce,
            &request.authenticated_bytes,
            &request.mac,
        )
    });
    if !authenticated {
        let response_token = selected_token.unwrap_or_else(|| state.tokens.primary());
        let _ = send_response(
            &mut client,
            response_token,
            &server_nonce,
            &request,
            ResponseStatus::AuthenticationFailed,
            [0_u8; SESSION_ID_BYTES],
        )
        .await;
        record_rejection(
            &state,
            request_id,
            source_id,
            RelayAuditOutcome::AuthenticationFailed,
            started,
        );
        return;
    }
    let token = selected_token.expect("authenticated token was selected by key id");
    if !state.allowed_targets.contains(&request.target) {
        let _ = send_response(
            &mut client,
            token,
            &server_nonce,
            &request,
            ResponseStatus::TargetDenied,
            [0_u8; SESSION_ID_BYTES],
        )
        .await;
        record_rejection(
            &state,
            request_id,
            source_id,
            RelayAuditOutcome::TargetDenied,
            started,
        );
        return;
    }
    let target_id = state.target_id(&request.target);
    let accepted_event = RelayAuditEvent {
        schema_version: 1,
        phase: "authorized",
        request_id: request_id.clone(),
        source_id: source_id.clone(),
        target_id: Some(target_id.clone()),
        outcome: RelayAuditOutcome::Accepted,
        transferred_bytes: 0,
        duration_ms: elapsed_ms(started),
    };
    if !state.audit(&accepted_event) {
        let _ = send_response(
            &mut client,
            token,
            &server_nonce,
            &request,
            ResponseStatus::AuditUnavailable,
            [0_u8; SESSION_ID_BYTES],
        )
        .await;
        return;
    }
    let target = tokio::select! {
        _ = state.cancellation.cancelled() => {
            record_rejection(&state, request_id, source_id, RelayAuditOutcome::Cancelled, started);
            return;
        }
        connected = timeout(
            state.config.limits.target_connect_timeout,
            TcpStream::connect((request.target.host(), request.target.port())),
        ) => match connected {
            Ok(Ok(stream)) => stream,
            _ => {
                let _ = send_response(
                    &mut client,
                    token,
                    &server_nonce,
                    &request,
                    ResponseStatus::TargetUnavailable,
                    [0_u8; SESSION_ID_BYTES],
                ).await;
                record_rejection(
                    &state,
                    request_id,
                    source_id,
                    RelayAuditOutcome::TargetUnavailable,
                    started,
                );
                return;
            }
        }
    };
    let mut session_id = [0_u8; SESSION_ID_BYTES];
    if getrandom::fill(&mut session_id).is_err() {
        record_rejection(
            &state,
            request_id,
            source_id,
            RelayAuditOutcome::TransportFailed,
            started,
        );
        return;
    }
    if send_response(
        &mut client,
        token,
        &server_nonce,
        &request,
        ResponseStatus::Ready,
        session_id,
    )
    .await
    .is_err()
    {
        record_finished(
            &state,
            request_id,
            source_id,
            target_id,
            RelayAuditOutcome::TransportFailed,
            0,
            started,
        );
        return;
    }
    let (outcome, transferred_bytes) = relay_stream(
        client,
        target,
        &state.config.limits,
        state.cancellation.clone(),
    )
    .await;
    record_finished(
        &state,
        request_id,
        source_id,
        target_id,
        outcome,
        transferred_bytes,
        started,
    );
}

fn record_rejection(
    state: &RelayServerState,
    request_id: String,
    source_id: String,
    outcome: RelayAuditOutcome,
    started: Instant,
) {
    let _ = state.audit(&RelayAuditEvent {
        schema_version: 1,
        phase: "rejected",
        request_id,
        source_id,
        target_id: None,
        outcome,
        transferred_bytes: 0,
        duration_ms: elapsed_ms(started),
    });
}

fn record_finished(
    state: &RelayServerState,
    request_id: String,
    source_id: String,
    target_id: String,
    outcome: RelayAuditOutcome,
    transferred_bytes: u64,
    started: Instant,
) {
    let _ = state.audit(&RelayAuditEvent {
        schema_version: 1,
        phase: "finished",
        request_id,
        source_id,
        target_id: Some(target_id),
        outcome,
        transferred_bytes,
        duration_ms: elapsed_ms(started),
    });
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn hashed_id(domain: &[u8], salt: &[u8; 32], value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(salt);
    digest.update(value);
    hex_prefix(&digest.finalize(), 16)
}

fn hex_prefix(bytes: &[u8], length: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(length * 2);
    for byte in bytes.iter().take(length) {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

struct ParsedRequest {
    client_nonce: [u8; NONCE_BYTES],
    key_id: [u8; KEY_ID_BYTES],
    target: RelayTarget,
    authenticated_bytes: Vec<u8>,
    mac: [u8; MAC_BYTES],
}

fn encode_hello(server_nonce: &[u8; NONCE_BYTES]) -> [u8; HELLO_BYTES] {
    let mut hello = [0_u8; HELLO_BYTES];
    hello[..4].copy_from_slice(MAGIC);
    hello[4..6].copy_from_slice(&RELAY_PROTOCOL_VERSION.to_be_bytes());
    hello[6..].copy_from_slice(server_nonce);
    hello
}

async fn read_request(stream: &mut TcpStream) -> Result<ParsedRequest, &'static str> {
    let mut prefix = [0_u8; REQUEST_PREFIX_BYTES];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|_| "relay-request-invalid")?;
    if &prefix[..4] != MAGIC || u16::from_be_bytes([prefix[4], prefix[5]]) != RELAY_PROTOCOL_VERSION
    {
        return Err("relay-version-unsupported");
    }
    let target_length = u16::from_be_bytes([
        prefix[REQUEST_PREFIX_BYTES - 2],
        prefix[REQUEST_PREFIX_BYTES - 1],
    ]) as usize;
    if target_length == 0 || target_length > MAX_HOST_BYTES {
        return Err("relay-request-invalid");
    }
    let mut suffix = vec![0_u8; target_length + 2 + MAC_BYTES];
    stream
        .read_exact(&mut suffix)
        .await
        .map_err(|_| "relay-request-invalid")?;
    let host =
        std::str::from_utf8(&suffix[..target_length]).map_err(|_| "relay-request-invalid")?;
    let port = u16::from_be_bytes([suffix[target_length], suffix[target_length + 1]]);
    let target = RelayTarget {
        host: normalize_host(host)?,
        port,
    };
    if target.port == 0 {
        return Err("relay-request-invalid");
    }
    let mut authenticated_bytes = prefix.to_vec();
    authenticated_bytes.extend_from_slice(&suffix[..target_length + 2]);
    let client_nonce = prefix[6..6 + NONCE_BYTES]
        .try_into()
        .expect("fixed nonce range");
    let key_start = 6 + NONCE_BYTES;
    let key_id = prefix[key_start..key_start + KEY_ID_BYTES]
        .try_into()
        .expect("fixed key id range");
    let mac = suffix[target_length + 2..]
        .try_into()
        .expect("fixed mac range");
    Ok(ParsedRequest {
        client_nonce,
        key_id,
        target,
        authenticated_bytes,
        mac,
    })
}

fn client_mac(
    token: &RelayToken,
    server_nonce: &[u8; NONCE_BYTES],
    authenticated_bytes: &[u8],
) -> [u8; MAC_BYTES] {
    let mut mac = HmacSha256::new_from_slice(token.bytes()).expect("fixed HMAC key");
    mac.update(CLIENT_DOMAIN);
    mac.update(server_nonce);
    mac.update(authenticated_bytes);
    let output = mac.finalize().into_bytes();
    let mut result = [0_u8; MAC_BYTES];
    result.copy_from_slice(&output);
    result
}

fn verify_client_mac(
    token: &RelayToken,
    server_nonce: &[u8; NONCE_BYTES],
    authenticated_bytes: &[u8],
    candidate: &[u8; MAC_BYTES],
) -> bool {
    let mut mac = HmacSha256::new_from_slice(token.bytes()).expect("fixed HMAC key");
    mac.update(CLIENT_DOMAIN);
    mac.update(server_nonce);
    mac.update(authenticated_bytes);
    mac.verify_slice(candidate).is_ok()
}

fn verify_server_mac(
    token: &RelayToken,
    server_nonce: &[u8; NONCE_BYTES],
    request: &ParsedRequest,
    status: ResponseStatus,
    session_id: &[u8; SESSION_ID_BYTES],
    candidate: &[u8],
) -> bool {
    let mut mac = HmacSha256::new_from_slice(token.bytes()).expect("fixed HMAC key");
    mac.update(SERVER_DOMAIN);
    mac.update(server_nonce);
    mac.update(&request.client_nonce);
    mac.update(&[status as u8]);
    mac.update(session_id);
    mac.update(&request_digest(request));
    mac.verify_slice(candidate).is_ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ResponseStatus {
    Ready = 0,
    AuthenticationFailed = 1,
    TargetDenied = 2,
    TargetUnavailable = 3,
    AuditUnavailable = 4,
}

impl ResponseStatus {
    fn from_byte(value: u8) -> Result<Self, RelayClientError> {
        match value {
            0 => Ok(Self::Ready),
            1 => Ok(Self::AuthenticationFailed),
            2 => Ok(Self::TargetDenied),
            3 => Ok(Self::TargetUnavailable),
            4 => Ok(Self::AuditUnavailable),
            _ => Err(RelayClientError::new("relay-response-invalid")),
        }
    }

    fn error_code(self) -> Option<&'static str> {
        match self {
            Self::Ready => None,
            Self::AuthenticationFailed => Some("relay-authentication-failed"),
            Self::TargetDenied => Some("relay-target-denied"),
            Self::TargetUnavailable => Some("relay-target-unavailable"),
            Self::AuditUnavailable => Some("relay-audit-unavailable"),
        }
    }
}

fn request_digest(request: &ParsedRequest) -> [u8; 32] {
    Sha256::digest(&request.authenticated_bytes).into()
}

fn server_mac(
    token: &RelayToken,
    server_nonce: &[u8; NONCE_BYTES],
    request: &ParsedRequest,
    status: ResponseStatus,
    session_id: &[u8; SESSION_ID_BYTES],
) -> [u8; MAC_BYTES] {
    let mut mac = HmacSha256::new_from_slice(token.bytes()).expect("fixed HMAC key");
    mac.update(SERVER_DOMAIN);
    mac.update(server_nonce);
    mac.update(&request.client_nonce);
    mac.update(&[status as u8]);
    mac.update(session_id);
    mac.update(&request_digest(request));
    let output = mac.finalize().into_bytes();
    let mut result = [0_u8; MAC_BYTES];
    result.copy_from_slice(&output);
    result
}

async fn send_response(
    stream: &mut TcpStream,
    token: &RelayToken,
    server_nonce: &[u8; NONCE_BYTES],
    request: &ParsedRequest,
    status: ResponseStatus,
    session_id: [u8; SESSION_ID_BYTES],
) -> io::Result<()> {
    let mut response = [0_u8; RESPONSE_BYTES];
    response[..4].copy_from_slice(MAGIC);
    response[4..6].copy_from_slice(&RELAY_PROTOCOL_VERSION.to_be_bytes());
    response[6] = status as u8;
    response[7..7 + SESSION_ID_BYTES].copy_from_slice(&session_id);
    response[7 + SESSION_ID_BYTES..].copy_from_slice(&server_mac(
        token,
        server_nonce,
        request,
        status,
        &session_id,
    ));
    stream.write_all(&response).await
}

async fn relay_stream(
    client: TcpStream,
    target: TcpStream,
    limits: &RelayLimits,
    cancellation: CancellationToken,
) -> (RelayAuditOutcome, u64) {
    let (mut client_reader, mut client_writer) = client.into_split();
    let (mut target_reader, mut target_writer) = target.into_split();
    let duration = sleep(limits.max_session_duration);
    tokio::pin!(duration);
    let mut transferred = 0_u64;
    let mut from_client = [0_u8; 16 * 1024];
    let mut from_target = [0_u8; 16 * 1024];
    let mut client_open = true;
    let mut target_open = true;
    loop {
        if !client_open && !target_open {
            return (RelayAuditOutcome::Completed, transferred);
        }
        let idle = sleep(limits.idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            _ = cancellation.cancelled() => {
                return (RelayAuditOutcome::Cancelled, transferred);
            }
            _ = &mut duration => {
                return (RelayAuditOutcome::DurationLimit, transferred);
            }
            _ = &mut idle => {
                return (RelayAuditOutcome::IdleTimeout, transferred);
            }
            read = client_reader.read(&mut from_client), if client_open => {
                let count = match read {
                    Ok(0) => {
                        client_open = false;
                        let _ = target_writer.shutdown().await;
                        continue;
                    }
                    Ok(count) => count,
                    Err(_) => return (RelayAuditOutcome::TransportFailed, transferred),
                };
                if transferred.saturating_add(count as u64) > limits.max_session_bytes {
                    return (RelayAuditOutcome::ByteLimit, transferred);
                }
                let write = tokio::select! {
                    _ = cancellation.cancelled() => {
                        return (RelayAuditOutcome::Cancelled, transferred);
                    }
                    _ = &mut duration => {
                        return (RelayAuditOutcome::DurationLimit, transferred);
                    }
                    result = timeout(
                        limits.idle_timeout,
                        target_writer.write_all(&from_client[..count]),
                    ) => result,
                };
                match write {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => return (RelayAuditOutcome::TransportFailed, transferred),
                    Err(_) => return (RelayAuditOutcome::IdleTimeout, transferred),
                }
                transferred += count as u64;
            }
            read = target_reader.read(&mut from_target), if target_open => {
                let count = match read {
                    Ok(0) => {
                        target_open = false;
                        let _ = client_writer.shutdown().await;
                        continue;
                    }
                    Ok(count) => count,
                    Err(_) => return (RelayAuditOutcome::TransportFailed, transferred),
                };
                if transferred.saturating_add(count as u64) > limits.max_session_bytes {
                    return (RelayAuditOutcome::ByteLimit, transferred);
                }
                let write = tokio::select! {
                    _ = cancellation.cancelled() => {
                        return (RelayAuditOutcome::Cancelled, transferred);
                    }
                    _ = &mut duration => {
                        return (RelayAuditOutcome::DurationLimit, transferred);
                    }
                    result = timeout(
                        limits.idle_timeout,
                        client_writer.write_all(&from_target[..count]),
                    ) => result,
                };
                match write {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => return (RelayAuditOutcome::TransportFailed, transferred),
                    Err(_) => return (RelayAuditOutcome::IdleTimeout, transferred),
                }
                transferred += count as u64;
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct RelayClientConfig {
    pub relay_endpoint: String,
    pub target: RelayTarget,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
}

impl RelayClientConfig {
    pub fn validate(&self) -> Result<(), RelayClientError> {
        if self.relay_endpoint.is_empty()
            || self.relay_endpoint.len() > 512
            || self
                .relay_endpoint
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || !(Duration::from_secs(1)..=Duration::from_secs(60)).contains(&self.connect_timeout)
            || !(Duration::from_secs(1)..=Duration::from_secs(60)).contains(&self.handshake_timeout)
        {
            return Err(RelayClientError::new("relay-client-config-invalid"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayClientError {
    code: &'static str,
}

impl RelayClientError {
    fn new(code: &'static str) -> Self {
        Self { code }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }
}

impl std::fmt::Display for RelayClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code)
    }
}

impl std::error::Error for RelayClientError {}

pub async fn connect_via_relay(
    config: &RelayClientConfig,
    token: &RelayToken,
) -> Result<TcpStream, RelayClientError> {
    config.validate()?;
    let mut stream = timeout(
        config.connect_timeout,
        TcpStream::connect(config.relay_endpoint.as_str()),
    )
    .await
    .map_err(|_| RelayClientError::new("relay-connect-timeout"))?
    .map_err(|_| RelayClientError::new("relay-connect-failed"))?;
    let mut hello = [0_u8; HELLO_BYTES];
    timeout(config.handshake_timeout, stream.read_exact(&mut hello))
        .await
        .map_err(|_| RelayClientError::new("relay-handshake-timeout"))?
        .map_err(|_| RelayClientError::new("relay-handshake-failed"))?;
    if &hello[..4] != MAGIC || u16::from_be_bytes([hello[4], hello[5]]) != RELAY_PROTOCOL_VERSION {
        return Err(RelayClientError::new("relay-version-unsupported"));
    }
    let server_nonce: [u8; NONCE_BYTES] = hello[6..].try_into().expect("fixed server nonce range");
    let mut client_nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut client_nonce)
        .map_err(|_| RelayClientError::new("relay-random-unavailable"))?;
    let authenticated_bytes = encode_request_prefix(token, &client_nonce, &config.target)?;
    let mac = client_mac(token, &server_nonce, &authenticated_bytes);
    let mut request_bytes = authenticated_bytes.clone();
    request_bytes.extend_from_slice(&mac);
    timeout(config.handshake_timeout, stream.write_all(&request_bytes))
        .await
        .map_err(|_| RelayClientError::new("relay-handshake-timeout"))?
        .map_err(|_| RelayClientError::new("relay-handshake-failed"))?;
    let mut response = [0_u8; RESPONSE_BYTES];
    timeout(config.handshake_timeout, stream.read_exact(&mut response))
        .await
        .map_err(|_| RelayClientError::new("relay-handshake-timeout"))?
        .map_err(|_| RelayClientError::new("relay-handshake-failed"))?;
    if &response[..4] != MAGIC
        || u16::from_be_bytes([response[4], response[5]]) != RELAY_PROTOCOL_VERSION
    {
        return Err(RelayClientError::new("relay-version-unsupported"));
    }
    let status = ResponseStatus::from_byte(response[6])?;
    let session_id: [u8; SESSION_ID_BYTES] = response[7..7 + SESSION_ID_BYTES]
        .try_into()
        .expect("fixed session id range");
    let request = ParsedRequest {
        client_nonce,
        key_id: token.key_id(),
        target: config.target.clone(),
        authenticated_bytes,
        mac,
    };
    if !verify_server_mac(
        token,
        &server_nonce,
        &request,
        status,
        &session_id,
        &response[7 + SESSION_ID_BYTES..],
    ) {
        return Err(RelayClientError::new("relay-server-proof-invalid"));
    }
    if let Some(code) = status.error_code() {
        return Err(RelayClientError::new(code));
    }
    Ok(stream)
}

fn encode_request_prefix(
    token: &RelayToken,
    client_nonce: &[u8; NONCE_BYTES],
    target: &RelayTarget,
) -> Result<Vec<u8>, RelayClientError> {
    let host_bytes = target.host().as_bytes();
    let target_length = u16::try_from(host_bytes.len())
        .map_err(|_| RelayClientError::new("relay-target-invalid"))?;
    let mut request = Vec::with_capacity(REQUEST_PREFIX_BYTES + host_bytes.len() + 2);
    request.extend_from_slice(MAGIC);
    request.extend_from_slice(&RELAY_PROTOCOL_VERSION.to_be_bytes());
    request.extend_from_slice(client_nonce);
    request.extend_from_slice(&token.key_id());
    request.extend_from_slice(&target_length.to_be_bytes());
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&target.port().to_be_bytes());
    Ok(request)
}

pub async fn run_local_connector(
    listener: TcpListener,
    relay_config: RelayClientConfig,
    token: Arc<RelayToken>,
    cancellation: CancellationToken,
) -> Result<(), &'static str> {
    let address = listener
        .local_addr()
        .map_err(|_| "relay-local-listener-invalid")?;
    if !address.ip().is_loopback() {
        return Err("relay-local-listener-must-be-loopback");
    }
    relay_config
        .validate()
        .map_err(|_| "relay-client-config-invalid")?;
    let capacity = Arc::new(Semaphore::new(32));
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            accepted = listener.accept() => {
                let (mut local, peer) = accepted.map_err(|_| "relay-local-listener-failed")?;
                if !peer.ip().is_loopback() {
                    continue;
                }
                let permit = match Arc::clone(&capacity).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                let relay_config = relay_config.clone();
                let token = Arc::clone(&token);
                tokio::spawn(async move {
                    let _permit: OwnedSemaphorePermit = permit;
                    if let Ok(mut relay) = connect_via_relay(&relay_config, &token).await {
                        let _ = tokio::io::copy_bidirectional(&mut local, &mut relay).await;
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryAudit {
        events: Mutex<Vec<RelayAuditEvent>>,
    }

    impl RelayAuditSink for MemoryAudit {
        fn record(&self, event: &RelayAuditEvent) -> io::Result<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    struct FailingAudit;

    impl RelayAuditSink for FailingAudit {
        fn record(&self, _event: &RelayAuditEvent) -> io::Result<()> {
            Err(io::Error::other("test audit failure"))
        }
    }

    fn token(byte: u8) -> Arc<RelayToken> {
        Arc::new(RelayToken(Zeroizing::new([byte; 32])))
    }

    fn token_set(bytes: &[u8]) -> Arc<RelayTokenSet> {
        Arc::new(
            RelayTokenSet::from_tokens(
                bytes
                    .iter()
                    .map(|byte| RelayToken(Zeroizing::new([*byte; 32])))
                    .collect(),
            )
            .unwrap(),
        )
    }

    async fn echo_target() -> (RelayTarget, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_cancellation.cancelled() => return,
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        tokio::spawn(async move {
                            let (mut reader, mut writer) = stream.into_split();
                            let _ = tokio::io::copy(&mut reader, &mut writer).await;
                        });
                    }
                }
            }
        });
        (
            RelayTarget::parse(&format!("127.0.0.1:{}", address.port())).unwrap(),
            cancellation,
        )
    }

    async fn start_relay(
        target: RelayTarget,
        tokens: Arc<RelayTokenSet>,
        limits: RelayLimits,
        audit: Arc<MemoryAudit>,
    ) -> (String, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        tokio::spawn(async move {
            serve(
                listener,
                RelayServerConfig {
                    allowed_targets: vec![target],
                    limits,
                },
                tokens,
                audit,
                task_cancellation,
            )
            .await
            .unwrap();
        });
        (address.to_string(), cancellation)
    }

    fn client_config(endpoint: String, target: RelayTarget) -> RelayClientConfig {
        RelayClientConfig {
            relay_endpoint: endpoint,
            target,
            connect_timeout: Duration::from_secs(2),
            handshake_timeout: Duration::from_secs(2),
        }
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (connected, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        (connected.unwrap(), accepted.unwrap().0)
    }

    #[tokio::test]
    async fn authenticated_tunnel_carries_opaque_ssh_bytes() {
        let (target, target_cancel) = echo_target().await;
        let audit = Arc::new(MemoryAudit::default());
        let relay_token = token(7);
        let (endpoint, relay_cancel) = start_relay(
            target.clone(),
            token_set(&[7]),
            RelayLimits::default(),
            Arc::clone(&audit),
        )
        .await;
        let mut tunnel = connect_via_relay(&client_config(endpoint, target), &relay_token)
            .await
            .unwrap();
        let payload = b"SSH-2.0-vpshell-test\r\n\0opaque";
        tunnel.write_all(payload).await.unwrap();
        let mut echoed = vec![0_u8; payload.len()];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        drop(tunnel);
        tokio::task::yield_now().await;
        let serialized = serde_json::to_string(&audit.events.lock().unwrap().clone()).unwrap();
        assert!(!serialized.contains("127.0.0.1"));
        assert!(!serialized.contains("SSH-2.0-vpshell-test"));
        assert!(!serialized.contains(&URL_SAFE_NO_PAD.encode([7_u8; 32])));
        relay_cancel.cancel();
        target_cancel.cancel();
    }

    #[tokio::test]
    async fn wrong_token_and_unlisted_target_fail_closed() {
        let (target, target_cancel) = echo_target().await;
        let audit = Arc::new(MemoryAudit::default());
        let relay_token = token(9);
        let (endpoint, relay_cancel) = start_relay(
            target.clone(),
            token_set(&[9]),
            RelayLimits::default(),
            Arc::clone(&audit),
        )
        .await;
        let wrong = token(10);
        let wrong_error =
            connect_via_relay(&client_config(endpoint.clone(), target.clone()), &wrong)
                .await
                .unwrap_err();
        assert_eq!(wrong_error.code(), "relay-server-proof-invalid");
        let denied = RelayTarget::parse("127.0.0.1:1").unwrap();
        let denied_error = connect_via_relay(&client_config(endpoint, denied), &relay_token)
            .await
            .unwrap_err();
        assert_eq!(denied_error.code(), "relay-target-denied");
        let outcomes = audit
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|event| format!("{:?}", event.outcome))
            .collect::<Vec<_>>();
        assert!(outcomes.contains(&"AuthenticationFailed".to_string()));
        assert!(outcomes.contains(&"TargetDenied".to_string()));
        relay_cancel.cancel();
        target_cancel.cancel();
    }

    #[tokio::test]
    async fn token_rotation_overlap_and_revocation_are_fail_closed() {
        let (target, target_cancel) = echo_target().await;
        let old_token = token(21);
        let new_token = token(22);
        let (overlap_endpoint, overlap_cancel) = start_relay(
            target.clone(),
            token_set(&[21, 22]),
            RelayLimits::default(),
            Arc::new(MemoryAudit::default()),
        )
        .await;

        for credential in [&old_token, &new_token] {
            let tunnel = connect_via_relay(
                &client_config(overlap_endpoint.clone(), target.clone()),
                credential,
            )
            .await
            .unwrap();
            drop(tunnel);
        }
        overlap_cancel.cancel();
        tokio::task::yield_now().await;

        let (revoked_endpoint, revoked_cancel) = start_relay(
            target.clone(),
            token_set(&[22]),
            RelayLimits::default(),
            Arc::new(MemoryAudit::default()),
        )
        .await;
        let old_error = connect_via_relay(
            &client_config(revoked_endpoint.clone(), target.clone()),
            &old_token,
        )
        .await
        .unwrap_err();
        assert_eq!(old_error.code(), "relay-server-proof-invalid");
        let current = connect_via_relay(&client_config(revoked_endpoint, target), &new_token)
            .await
            .unwrap();
        drop(current);

        revoked_cancel.cancel();
        target_cancel.cancel();
    }

    #[tokio::test]
    async fn audit_failure_requires_fresh_server_state_to_recover() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target_listener.local_addr().unwrap();
        let target = RelayTarget::parse(&target_address.to_string()).unwrap();
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay_listener.local_addr().unwrap();
        let relay_token = token(15);
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        tokio::spawn(async move {
            serve(
                relay_listener,
                RelayServerConfig {
                    allowed_targets: vec![target],
                    limits: RelayLimits::default(),
                },
                token_set(&[15]),
                Arc::new(FailingAudit),
                task_cancellation,
            )
            .await
            .unwrap();
        });
        let error = connect_via_relay(
            &client_config(
                relay_address.to_string(),
                RelayTarget::parse(&target_address.to_string()).unwrap(),
            ),
            &relay_token,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), "relay-audit-unavailable");
        assert!(
            timeout(Duration::from_millis(20), target_listener.accept())
                .await
                .is_err()
        );
        cancellation.cancel();
        tokio::task::yield_now().await;

        let recovered_target = RelayTarget::parse(&target_address.to_string()).unwrap();
        let (recovered_endpoint, recovered_cancel) = start_relay(
            recovered_target.clone(),
            token_set(&[15]),
            RelayLimits::default(),
            Arc::new(MemoryAudit::default()),
        )
        .await;
        let recovered = connect_via_relay(
            &client_config(recovered_endpoint, recovered_target),
            &relay_token,
        )
        .await
        .unwrap();
        drop(recovered);
        timeout(Duration::from_secs(1), target_listener.accept())
            .await
            .expect("recovered target connect timeout")
            .expect("recovered target connect");
        recovered_cancel.cancel();
    }

    #[test]
    fn challenge_binds_target_and_rejects_replay_or_tampering() {
        let relay_token = RelayToken(Zeroizing::new([11_u8; 32]));
        let target = RelayTarget::parse("ssh.example.test:22").unwrap();
        let client_nonce = [3_u8; NONCE_BYTES];
        let first_server_nonce = [4_u8; NONCE_BYTES];
        let second_server_nonce = [5_u8; NONCE_BYTES];
        let request = encode_request_prefix(&relay_token, &client_nonce, &target).unwrap();
        let mac = client_mac(&relay_token, &first_server_nonce, &request);
        assert!(verify_client_mac(
            &relay_token,
            &first_server_nonce,
            &request,
            &mac
        ));
        assert!(!verify_client_mac(
            &relay_token,
            &second_server_nonce,
            &request,
            &mac
        ));
        let mut tampered = request;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(!verify_client_mac(
            &relay_token,
            &first_server_nonce,
            &tampered,
            &mac
        ));
    }

    #[tokio::test]
    async fn unsupported_protocol_version_fails_before_authentication() {
        let (mut client, mut server) = tcp_pair().await;
        let mut prefix = [0_u8; REQUEST_PREFIX_BYTES];
        prefix[..4].copy_from_slice(MAGIC);
        prefix[4..6].copy_from_slice(&(RELAY_PROTOCOL_VERSION + 1).to_be_bytes());
        client.write_all(&prefix).await.unwrap();
        assert_eq!(
            read_request(&mut server).await.err(),
            Some("relay-version-unsupported")
        );
    }

    #[test]
    fn token_set_is_non_empty_unique_and_bounded() {
        assert_eq!(
            RelayTokenSet::from_tokens(Vec::new()).err(),
            Some("relay-token-set-invalid")
        );
        assert_eq!(
            RelayTokenSet::from_tokens(vec![
                RelayToken(Zeroizing::new([1_u8; 32])),
                RelayToken(Zeroizing::new([1_u8; 32])),
            ])
            .err(),
            Some("relay-token-set-invalid")
        );
        assert_eq!(
            RelayTokenSet::from_tokens(
                (1_u8..=5)
                    .map(|byte| RelayToken(Zeroizing::new([byte; 32])))
                    .collect(),
            )
            .err(),
            Some("relay-token-set-invalid")
        );
        assert!(
            RelayTokenSet::from_tokens(vec![
                RelayToken(Zeroizing::new([1_u8; 32])),
                RelayToken(Zeroizing::new([2_u8; 32])),
            ])
            .is_ok()
        );
    }

    #[tokio::test]
    async fn authentication_rate_limit_is_enforced_before_target_connect() {
        let (target, target_cancel) = echo_target().await;
        let audit = Arc::new(MemoryAudit::default());
        let relay_token = token(12);
        let limits = RelayLimits {
            auth_attempts_per_minute: 1,
            ..RelayLimits::default()
        };
        let (endpoint, relay_cancel) =
            start_relay(target.clone(), token_set(&[12]), limits, Arc::clone(&audit)).await;
        let wrong = token(13);
        assert!(
            connect_via_relay(&client_config(endpoint.clone(), target.clone()), &wrong)
                .await
                .is_err()
        );
        assert!(
            connect_via_relay(&client_config(endpoint, target), &relay_token)
                .await
                .is_err()
        );
        tokio::task::yield_now().await;
        assert!(
            audit
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|event| matches!(event.outcome, RelayAuditOutcome::RateLimited))
        );
        relay_cancel.cancel();
        target_cancel.cancel();
    }

    #[tokio::test]
    async fn global_connection_capacity_is_fail_closed() {
        let (target, target_cancel) = echo_target().await;
        let audit = Arc::new(MemoryAudit::default());
        let relay_token = token(14);
        let limits = RelayLimits {
            max_connections: 1,
            ..RelayLimits::default()
        };
        let (endpoint, relay_cancel) =
            start_relay(target.clone(), token_set(&[14]), limits, Arc::clone(&audit)).await;
        let first = connect_via_relay(
            &client_config(endpoint.clone(), target.clone()),
            &relay_token,
        )
        .await
        .unwrap();
        assert!(
            connect_via_relay(&client_config(endpoint, target), &relay_token)
                .await
                .is_err()
        );
        tokio::task::yield_now().await;
        assert!(
            audit
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|event| matches!(event.outcome, RelayAuditOutcome::CapacityExceeded))
        );
        drop(first);
        relay_cancel.cancel();
        target_cancel.cancel();
    }

    #[tokio::test]
    async fn stream_enforces_byte_idle_duration_and_cancellation_bounds() {
        let limits = RelayLimits {
            max_session_bytes: 1024,
            idle_timeout: Duration::from_secs(1),
            max_session_duration: Duration::from_secs(1),
            ..RelayLimits::default()
        };
        let (mut client_peer, relay_client) = tcp_pair().await;
        let (relay_target, _target_peer) = tcp_pair().await;
        client_peer.write_all(&vec![1_u8; 1025]).await.unwrap();
        let (outcome, bytes) = relay_stream(
            relay_client,
            relay_target,
            &limits,
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(outcome, RelayAuditOutcome::ByteLimit));
        assert!(bytes <= limits.max_session_bytes);

        let (relay_client, _client_peer) = tcp_pair().await;
        let (relay_target, _target_peer) = tcp_pair().await;
        let idle_limits = RelayLimits {
            idle_timeout: Duration::from_millis(10),
            max_session_duration: Duration::from_secs(1),
            ..RelayLimits::default()
        };
        let (outcome, _) = relay_stream(
            relay_client,
            relay_target,
            &idle_limits,
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(outcome, RelayAuditOutcome::IdleTimeout));

        let (relay_client, _client_peer) = tcp_pair().await;
        let (relay_target, _target_peer) = tcp_pair().await;
        let duration_limits = RelayLimits {
            idle_timeout: Duration::from_secs(1),
            max_session_duration: Duration::from_millis(10),
            ..RelayLimits::default()
        };
        let (outcome, _) = relay_stream(
            relay_client,
            relay_target,
            &duration_limits,
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(outcome, RelayAuditOutcome::DurationLimit));

        let (relay_client, _client_peer) = tcp_pair().await;
        let (relay_target, _target_peer) = tcp_pair().await;
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let (outcome, _) = relay_stream(
            relay_client,
            relay_target,
            &RelayLimits::default(),
            cancellation,
        )
        .await;
        assert!(matches!(outcome, RelayAuditOutcome::Cancelled));
    }

    #[test]
    fn target_and_limit_validation_reject_open_or_unbounded_policy() {
        for invalid in [
            "",
            "host:0",
            "-host:22",
            "host..name:22",
            "user@host:22",
            "host:65536",
        ] {
            assert!(RelayTarget::parse(invalid).is_err(), "accepted {invalid}");
        }
        let config = RelayServerConfig {
            allowed_targets: vec![],
            limits: RelayLimits::default(),
        };
        assert_eq!(config.validate(), Err("relay-target-policy-invalid"));
        let limits = RelayLimits {
            max_connections: 0,
            ..RelayLimits::default()
        };
        assert_eq!(limits.validate(), Err("relay-limits-invalid"));
    }

    #[cfg(unix)]
    #[test]
    fn token_file_requires_private_permissions_and_no_overwrite() {
        use std::os::unix::fs::PermissionsExt;

        let directory = std::env::temp_dir().join(format!("vpshell-relay-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let token_path = directory.join("token");
        RelayToken::generate_file(&token_path).unwrap();
        assert!(RelayToken::load(&token_path).is_ok());
        assert_eq!(
            RelayToken::generate_file(&token_path),
            Err("relay-token-create-failed")
        );
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            RelayToken::load(&token_path).err(),
            Some("relay-token-file-permissions")
        );

        let audit_path = directory.join("audit.jsonl");
        let audit = JsonLineAudit::file(&audit_path).unwrap();
        audit
            .record(&RelayAuditEvent {
                schema_version: 1,
                phase: "rejected",
                request_id: "00000000000000000000000000000000".to_string(),
                source_id: "source-hash".to_string(),
                target_id: None,
                outcome: RelayAuditOutcome::InvalidRequest,
                transferred_bytes: 0,
                duration_ms: 1,
            })
            .unwrap();
        drop(audit);
        assert!(
            fs::read_to_string(&audit_path)
                .unwrap()
                .contains("invalid-request")
        );
        fs::set_permissions(&audit_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            JsonLineAudit::file(&audit_path).err(),
            Some("relay-audit-file-permissions")
        );
        fs::remove_file(token_path).unwrap();
        fs::remove_file(audit_path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}

//! Desktop-only pure Rust SSH/SFTP path for Phase D.
//!
//! Secrets are resolved inside Rust. Probe and terminal requests are deserialize-only,
//! terminal I/O is bounded, and no result can serialize credential material.

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::Read,
    net::{Ipv4Addr, SocketAddrV4},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};

use russh::{
    Channel, ChannelMsg, Disconnect,
    client::{self, Handler},
    keys::{Algorithm, HashAlg, PrivateKeyWithHashAlg, decode_secret_key, ssh_key::PublicKey},
};
use russh_sftp::client::SftpSession;
use serde::{Deserialize, Serialize};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

const SCHEMA_VERSION: u16 = 1;
const ENGINE_NAME: &str = "russh";
const MAX_ACTIVE_OPERATIONS: usize = 8;
const MAX_TERMINAL_SESSIONS: usize = 16;
const MAX_LOCAL_FORWARDS: usize = 8;
const MAX_LOCAL_FORWARD_CONNECTIONS: usize = 32;
const MAX_NATIVE_ROUTE_HOPS: usize = 4;
const TERMINAL_COMMAND_QUEUE: usize = 64;
const TERMINAL_EVENT_QUEUE: usize = 64;
const SFTP_REQUEST_QUEUE: usize = 16;
const MAX_SFTP_DIRECTORY_ENTRIES: usize = 1000;
const MAX_TERMINAL_INPUT_BYTES: usize = 64 * 1024;
const MAX_INITIAL_OUTPUT_BYTES: usize = 64 * 1024;
const MIN_TERMINAL_CELLS: u16 = 2;
const MAX_TERMINAL_CELLS: u16 = 1000;
const MAX_HOST_BYTES: usize = 253;
const MAX_USERNAME_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PRIVATE_KEY_BYTES: u64 = 1024 * 1024;
const MIN_TIMEOUT_SECONDS: u16 = 5;
const MAX_TIMEOUT_SECONDS: u16 = 60;
const HOST_KEY_UNSEEN: u8 = 0;
const HOST_KEY_MATCHED: u8 = 1;
const HOST_KEY_MISMATCHED: u8 = 2;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NativeEngineProbeRequest {
    operation_id: String,
    route: NativeRouteRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeRouteRequest {
    hops: Vec<NativeRouteHopRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeRouteHopRequest {
    hop_id: String,
    host: String,
    port: u16,
    username: String,
    host_key_sha256: String,
    timeout_seconds: u16,
    credential_ref: Option<String>,
    identity_file: Option<String>,
    identity_passphrase_ref: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NativeTerminalStartRequest {
    session_id: String,
    route: NativeRouteRequest,
    cols: u16,
    rows: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NativeSftpListRequest {
    session_id: String,
    path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NativeLocalForwardStartRequest {
    forward_id: String,
    route: NativeRouteRequest,
    bind_port: u16,
    target_host: String,
    target_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NativeEngineProbeResult {
    schema_version: u16,
    engine: &'static str,
    ssh_ready: bool,
    sftp_ready: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NativeTerminalStartResult {
    pub(crate) schema_version: u16,
    pub(crate) engine: &'static str,
    pub(crate) session_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum NativeSftpEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeSftpEntry {
    name: String,
    path: String,
    kind: NativeSftpEntryKind,
    size: u64,
    modified: Option<u64>,
    permissions: String,
    owner_group: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NativeSftpDirectoryResult {
    path: String,
    entries: Vec<NativeSftpEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NativeLocalForwardSnapshot {
    schema_version: u16,
    forward_id: String,
    state: &'static str,
    bind_host: &'static str,
    bind_port: u16,
    route_host: String,
    route_hops: u8,
    target_host: String,
    target_port: u16,
    active_connections: u64,
    accepted_connections: u64,
    rejected_connections: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NativeEngineError {
    code: &'static str,
    message: &'static str,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    hop_index: Option<u8>,
}

impl NativeEngineError {
    pub(crate) fn new(code: &'static str, message: &'static str, retryable: bool) -> Self {
        Self {
            code,
            message,
            retryable,
            hop_index: None,
        }
    }

    fn invalid(message: &'static str) -> Self {
        Self::new("native-engine-invalid-request", message, false)
    }

    fn cancelled() -> Self {
        Self::new("native-engine-cancelled", "原生引擎检查已取消", true)
    }

    fn at_hop(mut self, hop_index: u8) -> Self {
        self.hop_index = Some(hop_index);
        self
    }

    pub(crate) fn user_message(&self) -> &'static str {
        self.message
    }
}

#[derive(Clone)]
pub(crate) struct NativeEngineManager {
    inner: Arc<NativeEngineManagerInner>,
}

struct NativeEngineManagerInner {
    operations: Mutex<HashMap<Uuid, ActiveOperation>>,
    terminal_sessions: Mutex<HashMap<Uuid, ActiveTerminalSession>>,
    local_forwards: Mutex<HashMap<Uuid, ActiveLocalForward>>,
    next_generation: AtomicU64,
}

struct ActiveOperation {
    generation: u64,
    cancellation: CancellationToken,
}

struct ActiveTerminalSession {
    generation: u64,
    cancellation: CancellationToken,
    sftp_requests: mpsc::Sender<NativeSftpCommand>,
    sftp_timeout: Duration,
}

struct ActiveLocalForward {
    generation: u64,
    cancellation: CancellationToken,
    bind_port: u16,
    route_host: String,
    route_hops: u8,
    target_host: String,
    target_port: u16,
    stats: Arc<LocalForwardStats>,
}

#[derive(Default)]
struct LocalForwardStats {
    ready: AtomicU8,
    active_connections: AtomicU64,
    accepted_connections: AtomicU64,
    rejected_connections: AtomicU64,
}

struct ActiveForwardConnectionGuard {
    stats: Arc<LocalForwardStats>,
}

impl Drop for ActiveForwardConnectionGuard {
    fn drop(&mut self) {
        self.stats.active_connections.fetch_sub(1, Ordering::SeqCst);
    }
}

enum NativeSftpCommand {
    List {
        path: String,
        reply: oneshot::Sender<Result<NativeSftpDirectoryResult, NativeEngineError>>,
    },
}

enum NativeTerminalCommand {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
}

pub(crate) enum NativeTerminalEvent {
    Data(Vec<u8>),
    Exit { message: Option<&'static str> },
}

pub(crate) struct NativeTerminalLaunch {
    pub(crate) result: NativeTerminalStartResult,
    pub(crate) handle: NativeTerminalHandle,
    pub(crate) events: mpsc::Receiver<NativeTerminalEvent>,
}

#[derive(Clone)]
pub(crate) struct NativeTerminalHandle {
    cancellation: CancellationToken,
    commands: mpsc::Sender<NativeTerminalCommand>,
}

impl NativeTerminalHandle {
    pub(crate) fn write(&self, data: &[u8]) -> Result<(), NativeEngineError> {
        if data.is_empty() {
            return Ok(());
        }
        if data.len() > MAX_TERMINAL_INPUT_BYTES {
            return Err(NativeEngineError::invalid("原生终端单次输入超过 64 KiB"));
        }
        self.commands
            .try_send(NativeTerminalCommand::Data(data.to_vec()))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => NativeEngineError::new(
                    "native-terminal-backpressure",
                    "原生终端输入队列已满，请稍后重试",
                    true,
                ),
                mpsc::error::TrySendError::Closed(_) => {
                    NativeEngineError::new("native-terminal-closed", "原生终端会话已经关闭", false)
                }
            })
    }

    pub(crate) fn resize(&self, cols: u16, rows: u16) -> Result<(), NativeEngineError> {
        validate_terminal_size(cols, rows)?;
        self.commands
            .try_send(NativeTerminalCommand::Resize { cols, rows })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => NativeEngineError::new(
                    "native-terminal-backpressure",
                    "原生终端控制队列已满，请稍后重试",
                    true,
                ),
                mpsc::error::TrySendError::Closed(_) => {
                    NativeEngineError::new("native-terminal-closed", "原生终端会话已经关闭", false)
                }
            })
    }

    pub(crate) fn stop(&self) {
        self.cancellation.cancel();
    }
}

struct OperationLease {
    manager: NativeEngineManager,
    operation_id: Uuid,
    generation: u64,
    cancellation: CancellationToken,
}

impl Default for NativeEngineManager {
    fn default() -> Self {
        Self {
            inner: Arc::new(NativeEngineManagerInner {
                operations: Mutex::new(HashMap::new()),
                terminal_sessions: Mutex::new(HashMap::new()),
                local_forwards: Mutex::new(HashMap::new()),
                next_generation: AtomicU64::new(0),
            }),
        }
    }
}

impl NativeEngineManager {
    pub(crate) async fn probe(
        &self,
        request: NativeEngineProbeRequest,
    ) -> Result<NativeEngineProbeResult, NativeEngineError> {
        let operation_id = parse_operation_id(&request.operation_id)?;
        let lease = self.begin(operation_id)?;
        let validated = ValidatedRoute::try_from(request)?;
        let timeout = validated.operation_timeout();
        let hop_index = validated.final_hop_index();
        let cancellation = lease.cancellation.clone();
        let outcome = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(NativeEngineError::cancelled()),
            result = tokio::time::timeout(timeout, probe_once(validated)) => {
                match result {
                    Ok(outcome) => outcome,
                    Err(_) => Err(NativeEngineError::new(
                        "native-engine-timeout",
                        "原生 SSH/SFTP 检查超时",
                        true,
                    ).at_hop(hop_index)),
                }
            }
        };
        drop(lease);
        outcome
    }

    pub(crate) async fn start_terminal(
        &self,
        request: NativeTerminalStartRequest,
    ) -> Result<NativeTerminalLaunch, NativeEngineError> {
        let session_id = parse_session_id(&request.session_id)?;
        let validated = ValidatedTerminalStart::try_from(request)?;
        let timeout = validated.route.operation_timeout();
        let sftp_timeout = validated.route.final_timeout();
        let hop_index = validated.route.final_hop_index();
        let generation = self.next_generation()?;
        let cancellation = CancellationToken::new();
        let (sftp_requests, sftp_request_receiver) = mpsc::channel(SFTP_REQUEST_QUEUE);
        self.reserve_terminal(
            session_id,
            generation,
            cancellation.clone(),
            sftp_requests,
            sftp_timeout,
        )?;
        let (commands, command_receiver) = mpsc::channel(TERMINAL_COMMAND_QUEUE);
        let (events, event_receiver) = mpsc::channel(TERMINAL_EVENT_QUEUE);

        debug_assert_eq!(validated.session_id, session_id);
        let cols = validated.cols;
        let rows = validated.rows;
        let cancellation_for_start = cancellation.clone();
        let connection = tokio::select! {
            biased;
            _ = cancellation_for_start.cancelled() => Err(NativeEngineError::new(
                "native-terminal-cancelled",
                "原生终端连接已取消",
                true,
            )),
            result = tokio::time::timeout(timeout, open_native_terminal(validated.route, cols, rows)) => {
                match result {
                    Ok(outcome) => outcome,
                    Err(_) => Err(NativeEngineError::new(
                        "native-terminal-timeout",
                        "原生终端连接超时",
                        true,
                    ).at_hop(hop_index)),
                }
            }
        };
        let (connection_chain, channel, initial_output) = match connection {
            Ok(connection) => connection,
            Err(error) => {
                self.finish_terminal(session_id, generation);
                return Err(error);
            }
        };

        let connection_chain = Arc::new(connection_chain);
        let sftp_connection_chain = Arc::clone(&connection_chain);
        let sftp_cancellation = cancellation.clone();
        tokio::spawn(async move {
            run_native_sftp_session(
                sftp_connection_chain,
                sftp_request_receiver,
                sftp_cancellation,
                sftp_timeout,
            )
            .await;
        });
        let manager = self.clone();
        let cancellation_for_task = cancellation.clone();
        tokio::spawn(async move {
            run_native_terminal(
                manager,
                session_id,
                generation,
                connection_chain,
                channel,
                initial_output,
                command_receiver,
                events,
                cancellation_for_task,
            )
            .await;
        });

        Ok(NativeTerminalLaunch {
            result: NativeTerminalStartResult {
                schema_version: SCHEMA_VERSION,
                engine: ENGINE_NAME,
                session_id: session_id.to_string(),
            },
            handle: NativeTerminalHandle {
                cancellation,
                commands,
            },
            events: event_receiver,
        })
    }

    pub(crate) async fn list_sftp_directory(
        &self,
        request: NativeSftpListRequest,
    ) -> Result<NativeSftpDirectoryResult, NativeEngineError> {
        let session_id = parse_session_id(&request.session_id)?;
        validate_sftp_request_path(&request.path)?;
        let (generation, cancellation, requests, timeout) = {
            let sessions = self.lock_terminal_sessions()?;
            let session = sessions.get(&session_id).ok_or_else(|| {
                NativeEngineError::new(
                    "native-sftp-session-not-found",
                    "原生 SFTP 会话不存在或已经关闭",
                    false,
                )
            })?;
            (
                session.generation,
                session.cancellation.clone(),
                session.sftp_requests.clone(),
                session.sftp_timeout,
            )
        };
        if cancellation.is_cancelled() {
            return Err(NativeEngineError::new(
                "native-sftp-session-closed",
                "原生 SFTP 会话已经关闭",
                true,
            ));
        }
        let (reply, response) = oneshot::channel();
        requests
            .try_send(NativeSftpCommand::List {
                path: request.path,
                reply,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => NativeEngineError::new(
                    "native-sftp-backpressure",
                    "原生 SFTP 请求队列已满，请稍后重试",
                    true,
                ),
                mpsc::error::TrySendError::Closed(_) => NativeEngineError::new(
                    "native-sftp-session-closed",
                    "原生 SFTP 会话已经关闭",
                    true,
                ),
            })?;
        let outcome = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(NativeEngineError::new(
                "native-sftp-cancelled",
                "原生 SFTP 浏览已取消",
                true,
            )),
            result = tokio::time::timeout(timeout, response) => match result {
                Ok(response) => response.unwrap_or_else(|_| Err(NativeEngineError::new(
                    "native-sftp-session-closed",
                    "原生 SFTP 会话已经关闭",
                    true,
                ))),
                Err(_) => Err(NativeEngineError::new(
                    "native-sftp-timeout",
                    "原生 SFTP 浏览超时",
                    true,
                )),
            },
        }?;
        let generation_is_current = self
            .lock_terminal_sessions()?
            .get(&session_id)
            .is_some_and(|session| session.generation == generation);
        if !generation_is_current {
            return Err(NativeEngineError::new(
                "native-sftp-generation-stale",
                "原生 SFTP 会话代际已经失效",
                true,
            ));
        }
        Ok(outcome)
    }

    pub(crate) async fn start_local_forward(
        &self,
        request: NativeLocalForwardStartRequest,
    ) -> Result<NativeLocalForwardSnapshot, NativeEngineError> {
        let ValidatedLocalForwardStart {
            forward_id,
            route,
            bind_port,
            target_host,
            target_port,
        } = ValidatedLocalForwardStart::try_from(request)?;
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, bind_port))
            .await
            .map_err(|_| {
                NativeEngineError::new(
                    "native-local-forward-bind-failed",
                    "本地转发无法绑定回环端口",
                    true,
                )
            })?;
        let bound_port = listener
            .local_addr()
            .map_err(|_| {
                NativeEngineError::new(
                    "native-local-forward-bind-failed",
                    "本地转发无法读取绑定端口",
                    true,
                )
            })?
            .port();
        let route_host = route
            .hops
            .last()
            .map(|hop| hop.host.clone())
            .ok_or_else(|| NativeEngineError::invalid("本地转发 SSH 路由为空"))?;
        let route_hops = u8::try_from(route.hops.len())
            .map_err(|_| NativeEngineError::invalid("本地转发 SSH 路由跳数无效"))?;
        let generation = self.next_generation()?;
        let cancellation = CancellationToken::new();
        let stats = Arc::new(LocalForwardStats::default());
        self.reserve_local_forward(
            forward_id,
            generation,
            cancellation.clone(),
            bound_port,
            route_host.clone(),
            route_hops,
            target_host.clone(),
            target_port,
            Arc::clone(&stats),
        )?;

        let timeout = route.operation_timeout();
        let hop_index = route.final_hop_index();
        let connection = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(NativeEngineError::new(
                "native-local-forward-cancelled",
                "本地转发连接已取消",
                true,
            )),
            result = tokio::time::timeout(timeout, connect_route(route)) => match result {
                Ok(outcome) => outcome,
                Err(_) => Err(NativeEngineError::new(
                    "native-local-forward-timeout",
                    "本地转发 SSH 路由连接超时",
                    true,
                ).at_hop(hop_index)),
            },
        };
        let connection_chain = match connection {
            Ok(connection_chain) => Arc::new(connection_chain),
            Err(error) => {
                self.finish_local_forward(forward_id, generation);
                return Err(error);
            }
        };
        stats.ready.store(1, Ordering::SeqCst);
        let result = local_forward_snapshot(
            forward_id,
            bound_port,
            &route_host,
            route_hops,
            &target_host,
            target_port,
            &stats,
        );
        let manager = self.clone();
        tokio::spawn(async move {
            run_native_local_forward(
                manager,
                forward_id,
                generation,
                listener,
                connection_chain,
                target_host,
                target_port,
                cancellation,
                stats,
            )
            .await;
        });
        Ok(result)
    }

    pub(crate) fn list_local_forwards(
        &self,
    ) -> Result<Vec<NativeLocalForwardSnapshot>, NativeEngineError> {
        let forwards = self.lock_local_forwards()?;
        let mut snapshots = forwards
            .iter()
            .map(|(forward_id, forward)| {
                local_forward_snapshot(
                    *forward_id,
                    forward.bind_port,
                    &forward.route_host,
                    forward.route_hops,
                    &forward.target_host,
                    forward.target_port,
                    &forward.stats,
                )
            })
            .collect::<Vec<_>>();
        snapshots.sort_by(|left, right| left.forward_id.cmp(&right.forward_id));
        Ok(snapshots)
    }

    pub(crate) fn stop_local_forward(&self, forward_id: &str) -> Result<(), NativeEngineError> {
        let forward_id = parse_forward_id(forward_id)?;
        let cancellation = self
            .lock_local_forwards()?
            .get(&forward_id)
            .map(|forward| forward.cancellation.clone())
            .ok_or_else(|| {
                NativeEngineError::new(
                    "native-local-forward-not-found",
                    "本地转发不存在或已经停止",
                    false,
                )
            })?;
        cancellation.cancel();
        Ok(())
    }

    pub(crate) fn cancel(&self, operation_id: &str) -> Result<(), NativeEngineError> {
        let operation_id = parse_operation_id(operation_id)?;
        let operation = self
            .lock_operations()?
            .get(&operation_id)
            .map(|operation| operation.cancellation.clone());
        let terminal = self
            .lock_terminal_sessions()?
            .get(&operation_id)
            .map(|session| session.cancellation.clone());
        if operation.is_none() && terminal.is_none() {
            return Err(NativeEngineError::new(
                "native-engine-operation-not-found",
                "原生引擎操作不存在或已经结束",
                false,
            ));
        }
        if let Some(operation) = operation {
            operation.cancel();
        }
        if let Some(terminal) = terminal {
            terminal.cancel();
        }
        Ok(())
    }

    fn begin(&self, operation_id: Uuid) -> Result<OperationLease, NativeEngineError> {
        let mut operations = self.lock_operations()?;
        if operations.len() >= MAX_ACTIVE_OPERATIONS {
            return Err(NativeEngineError::new(
                "native-engine-capacity",
                "同时进行的原生引擎检查已达到上限",
                true,
            ));
        }
        if operations.contains_key(&operation_id) {
            return Err(NativeEngineError::new(
                "native-engine-operation-conflict",
                "原生引擎操作标识已经在使用",
                false,
            ));
        }
        let generation = self.next_generation()?;
        let cancellation = CancellationToken::new();
        operations.insert(
            operation_id,
            ActiveOperation {
                generation,
                cancellation: cancellation.clone(),
            },
        );
        Ok(OperationLease {
            manager: self.clone(),
            operation_id,
            generation,
            cancellation,
        })
    }

    fn finish(&self, operation_id: Uuid, generation: u64) {
        if let Ok(mut operations) = self.inner.operations.lock()
            && operations
                .get(&operation_id)
                .is_some_and(|operation| operation.generation == generation)
        {
            operations.remove(&operation_id);
        }
    }

    fn next_generation(&self) -> Result<u64, NativeEngineError> {
        self.inner
            .next_generation
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map(|previous| previous + 1)
            .map_err(|_| {
                NativeEngineError::new(
                    "native-engine-generation-exhausted",
                    "原生引擎代际已耗尽",
                    false,
                )
            })
    }

    fn finish_terminal(&self, session_id: Uuid, generation: u64) {
        if let Ok(mut sessions) = self.inner.terminal_sessions.lock()
            && sessions
                .get(&session_id)
                .is_some_and(|session| session.generation == generation)
        {
            sessions.remove(&session_id);
        }
    }

    fn finish_local_forward(&self, forward_id: Uuid, generation: u64) {
        if let Ok(mut forwards) = self.inner.local_forwards.lock()
            && forwards
                .get(&forward_id)
                .is_some_and(|forward| forward.generation == generation)
        {
            forwards.remove(&forward_id);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn reserve_local_forward(
        &self,
        forward_id: Uuid,
        generation: u64,
        cancellation: CancellationToken,
        bind_port: u16,
        route_host: String,
        route_hops: u8,
        target_host: String,
        target_port: u16,
        stats: Arc<LocalForwardStats>,
    ) -> Result<(), NativeEngineError> {
        let mut forwards = self.lock_local_forwards()?;
        if forwards.len() >= MAX_LOCAL_FORWARDS {
            return Err(NativeEngineError::new(
                "native-local-forward-capacity",
                "同时运行的本地转发已达到上限",
                true,
            ));
        }
        if forwards.contains_key(&forward_id) {
            return Err(NativeEngineError::new(
                "native-local-forward-conflict",
                "本地转发标识已经在使用",
                false,
            ));
        }
        if forwards
            .values()
            .any(|forward| forward.bind_port == bind_port)
        {
            return Err(NativeEngineError::new(
                "native-local-forward-bind-conflict",
                "本地转发回环端口已经在使用",
                false,
            ));
        }
        forwards.insert(
            forward_id,
            ActiveLocalForward {
                generation,
                cancellation,
                bind_port,
                route_host,
                route_hops,
                target_host,
                target_port,
                stats,
            },
        );
        Ok(())
    }

    fn reserve_terminal(
        &self,
        session_id: Uuid,
        generation: u64,
        cancellation: CancellationToken,
        sftp_requests: mpsc::Sender<NativeSftpCommand>,
        sftp_timeout: Duration,
    ) -> Result<(), NativeEngineError> {
        let mut sessions = self.lock_terminal_sessions()?;
        if sessions.len() >= MAX_TERMINAL_SESSIONS {
            return Err(NativeEngineError::new(
                "native-terminal-capacity",
                "同时连接的原生终端已达到上限",
                true,
            ));
        }
        if sessions.contains_key(&session_id) {
            return Err(NativeEngineError::new(
                "native-terminal-session-conflict",
                "原生终端会话标识已经在使用",
                false,
            ));
        }
        sessions.insert(
            session_id,
            ActiveTerminalSession {
                generation,
                cancellation,
                sftp_requests,
                sftp_timeout,
            },
        );
        Ok(())
    }

    fn lock_operations(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<Uuid, ActiveOperation>>, NativeEngineError> {
        self.inner.operations.lock().map_err(|_| {
            NativeEngineError::new(
                "native-engine-state-corrupt",
                "原生引擎操作状态已损坏",
                false,
            )
        })
    }

    fn lock_terminal_sessions(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<Uuid, ActiveTerminalSession>>, NativeEngineError>
    {
        self.inner.terminal_sessions.lock().map_err(|_| {
            NativeEngineError::new(
                "native-terminal-state-corrupt",
                "原生终端会话状态已损坏",
                false,
            )
        })
    }

    fn lock_local_forwards(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<Uuid, ActiveLocalForward>>, NativeEngineError>
    {
        self.inner.local_forwards.lock().map_err(|_| {
            NativeEngineError::new(
                "native-local-forward-state-corrupt",
                "本地转发状态已损坏",
                false,
            )
        })
    }
}

impl Drop for OperationLease {
    fn drop(&mut self) {
        self.manager.finish(self.operation_id, self.generation);
    }
}

struct ValidatedConnection {
    hop_index: u8,
    host: String,
    port: u16,
    username: String,
    host_key_sha256: String,
    timeout_seconds: u16,
    auth_source: NativeAuthSource,
}

struct ValidatedTerminalStart {
    session_id: Uuid,
    route: ValidatedRoute,
    cols: u16,
    rows: u16,
}

struct ValidatedLocalForwardStart {
    forward_id: Uuid,
    route: ValidatedRoute,
    bind_port: u16,
    target_host: String,
    target_port: u16,
}

enum NativeAuth {
    Password(Zeroizing<String>),
    PrivateKey {
        private_key: Zeroizing<Vec<u8>>,
        passphrase: Option<Zeroizing<String>>,
    },
}

enum NativeAuthSource {
    PasswordReference(String),
    PrivateKeyFile {
        identity_file: String,
        passphrase_ref: Option<String>,
    },
}

struct ValidatedRoute {
    hops: Vec<ValidatedConnection>,
}

impl ValidatedRoute {
    fn final_hop_index(&self) -> u8 {
        self.hops.last().map_or(1, |hop| hop.hop_index)
    }

    fn final_timeout(&self) -> Duration {
        Duration::from_secs(
            self.hops
                .last()
                .map_or(u64::from(MIN_TIMEOUT_SECONDS), |hop| {
                    u64::from(hop.timeout_seconds)
                }),
        )
    }

    fn operation_timeout(&self) -> Duration {
        let connection_seconds = self
            .hops
            .iter()
            .map(|hop| u64::from(hop.timeout_seconds))
            .sum::<u64>();
        self.final_timeout() + Duration::from_secs(connection_seconds)
    }
}

impl TryFrom<NativeEngineProbeRequest> for ValidatedRoute {
    type Error = NativeEngineError;

    fn try_from(request: NativeEngineProbeRequest) -> Result<Self, Self::Error> {
        parse_operation_id(&request.operation_id)?;
        validate_route(request.route)
    }
}

impl TryFrom<NativeTerminalStartRequest> for ValidatedTerminalStart {
    type Error = NativeEngineError;

    fn try_from(request: NativeTerminalStartRequest) -> Result<Self, Self::Error> {
        let session_id = parse_session_id(&request.session_id)?;
        validate_terminal_size(request.cols, request.rows)?;
        let route = validate_route(request.route)?;
        Ok(Self {
            session_id,
            route,
            cols: request.cols,
            rows: request.rows,
        })
    }
}

impl TryFrom<NativeLocalForwardStartRequest> for ValidatedLocalForwardStart {
    type Error = NativeEngineError;

    fn try_from(request: NativeLocalForwardStartRequest) -> Result<Self, Self::Error> {
        let forward_id = parse_forward_id(&request.forward_id)?;
        validate_host(&request.target_host)?;
        if request.target_port == 0 {
            return Err(NativeEngineError::invalid("本地转发目标端口无效"));
        }
        Ok(Self {
            forward_id,
            route: validate_route(request.route)?,
            bind_port: request.bind_port,
            target_host: request.target_host,
            target_port: request.target_port,
        })
    }
}

fn validate_route(request: NativeRouteRequest) -> Result<ValidatedRoute, NativeEngineError> {
    if request.hops.is_empty() || request.hops.len() > MAX_NATIVE_ROUTE_HOPS {
        return Err(NativeEngineError::invalid(
            "原生 SSH 路由必须包含 1 到 4 跳",
        ));
    }
    let mut hop_ids = HashSet::with_capacity(request.hops.len());
    let mut endpoints = HashSet::with_capacity(request.hops.len());
    let mut hops = Vec::with_capacity(request.hops.len());
    for (index, hop) in request.hops.into_iter().enumerate() {
        let hop_index = u8::try_from(index + 1)
            .map_err(|_| NativeEngineError::invalid("原生 SSH 路由跳数无效"))?;
        let hop_id = parse_hop_id(&hop.hop_id).map_err(|error| error.at_hop(hop_index))?;
        if !hop_ids.insert(hop_id) {
            return Err(NativeEngineError::invalid("原生 SSH 路由跳标识重复").at_hop(hop_index));
        }
        let endpoint = (hop.host.to_ascii_lowercase(), hop.port);
        if !endpoints.insert(endpoint) {
            return Err(NativeEngineError::invalid("原生 SSH 路由包含重复端点").at_hop(hop_index));
        }
        let connection =
            validate_connection(hop_index, hop).map_err(|error| error.at_hop(hop_index))?;
        hops.push(connection);
    }
    Ok(ValidatedRoute { hops })
}

fn validate_connection(
    hop_index: u8,
    request: NativeRouteHopRequest,
) -> Result<ValidatedConnection, NativeEngineError> {
    validate_host(&request.host)?;
    validate_username(&request.username)?;
    if request.port == 0 {
        return Err(NativeEngineError::invalid("原生 SSH 端口无效"));
    }
    if !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&request.timeout_seconds) {
        return Err(NativeEngineError::invalid(
            "原生 SSH 超时必须在 5 到 60 秒之间",
        ));
    }
    validate_fingerprint(&request.host_key_sha256)?;
    let auth_source = validate_auth_source(
        request.credential_ref,
        request.identity_file,
        request.identity_passphrase_ref,
    )?;
    Ok(ValidatedConnection {
        hop_index,
        host: request.host,
        port: request.port,
        username: request.username,
        host_key_sha256: request.host_key_sha256,
        timeout_seconds: request.timeout_seconds,
        auth_source,
    })
}

fn parse_operation_id(value: &str) -> Result<Uuid, NativeEngineError> {
    let parsed =
        Uuid::parse_str(value).map_err(|_| NativeEngineError::invalid("原生引擎操作标识无效"))?;
    if value.len() != 36 || parsed.to_string() != value {
        return Err(NativeEngineError::invalid("原生引擎操作标识无效"));
    }
    Ok(parsed)
}

fn parse_session_id(value: &str) -> Result<Uuid, NativeEngineError> {
    let parsed =
        Uuid::parse_str(value).map_err(|_| NativeEngineError::invalid("原生终端会话标识无效"))?;
    if value.len() != 36 || parsed.to_string() != value {
        return Err(NativeEngineError::invalid("原生终端会话标识无效"));
    }
    Ok(parsed)
}

fn parse_forward_id(value: &str) -> Result<Uuid, NativeEngineError> {
    let parsed =
        Uuid::parse_str(value).map_err(|_| NativeEngineError::invalid("本地转发标识无效"))?;
    if value.len() != 36 || parsed.to_string() != value {
        return Err(NativeEngineError::invalid("本地转发标识无效"));
    }
    Ok(parsed)
}

fn parse_hop_id(value: &str) -> Result<Uuid, NativeEngineError> {
    let parsed =
        Uuid::parse_str(value).map_err(|_| NativeEngineError::invalid("原生 SSH 跳标识无效"))?;
    if value.len() != 36 || parsed.to_string() != value {
        return Err(NativeEngineError::invalid("原生 SSH 跳标识无效"));
    }
    Ok(parsed)
}

fn validate_terminal_size(cols: u16, rows: u16) -> Result<(), NativeEngineError> {
    if !(MIN_TERMINAL_CELLS..=MAX_TERMINAL_CELLS).contains(&cols)
        || !(MIN_TERMINAL_CELLS..=MAX_TERMINAL_CELLS).contains(&rows)
    {
        return Err(NativeEngineError::invalid(
            "原生终端行列必须在 2 到 1000 之间",
        ));
    }
    Ok(())
}

fn validate_sftp_request_path(path: &str) -> Result<(), NativeEngineError> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !(path == "." || path == "~" || path.starts_with('/'))
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return Err(NativeEngineError::invalid(
            "原生 SFTP 路径必须是受限绝对路径、~ 或 .",
        ));
    }
    Ok(())
}

fn validate_sftp_canonical_path(path: &str) -> Result<(), NativeEngineError> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return Err(NativeEngineError::new(
            "native-sftp-invalid-canonical-path",
            "服务器返回了无效的原生 SFTP 绝对路径",
            false,
        ));
    }
    Ok(())
}

fn validate_sftp_entry_name(name: &str) -> Result<(), NativeEngineError> {
    if name.is_empty()
        || name.len() > 255
        || matches!(name, "." | "..")
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
    {
        return Err(NativeEngineError::new(
            "native-sftp-invalid-entry",
            "远端目录包含无法安全显示的条目",
            false,
        ));
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<(), NativeEngineError> {
    if host.is_empty()
        || host.len() > MAX_HOST_BYTES
        || host.starts_with('-')
        || host.contains('/')
        || host.contains('\\')
        || host
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(NativeEngineError::invalid("原生 SSH 主机地址格式无效"));
    }
    Ok(())
}

fn validate_username(username: &str) -> Result<(), NativeEngineError> {
    if username.is_empty()
        || username.len() > MAX_USERNAME_BYTES
        || username.starts_with('-')
        || username.contains('@')
        || username
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(NativeEngineError::invalid("原生 SSH 用户名格式无效"));
    }
    Ok(())
}

fn validate_fingerprint(value: &str) -> Result<(), NativeEngineError> {
    let encoded = value
        .strip_prefix("SHA256:")
        .ok_or_else(|| NativeEngineError::invalid("原生 SSH 必须固定 SHA256 主机指纹"))?;
    if encoded.len() != 43
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
    {
        return Err(NativeEngineError::invalid("原生 SSH 主机指纹格式无效"));
    }
    Ok(())
}

fn validate_auth_source(
    credential_ref: Option<String>,
    identity_file: Option<String>,
    identity_passphrase_ref: Option<String>,
) -> Result<NativeAuthSource, NativeEngineError> {
    match (credential_ref, identity_file) {
        (Some(_), Some(_)) => Err(NativeEngineError::invalid(
            "原生引擎检查每次只允许一种认证方式",
        )),
        (Some(reference), None) => {
            if identity_passphrase_ref.is_some() {
                return Err(NativeEngineError::invalid("密码认证不能携带私钥口令引用"));
            }
            crate::file_transfer::validate_optional_reference(Some(&reference), "ssh-")
                .map_err(|_| NativeEngineError::invalid("原生 SSH 凭据引用无效"))?;
            Ok(NativeAuthSource::PasswordReference(reference))
        }
        (None, Some(identity_file)) => {
            validate_private_key_path_shape(&identity_file)?;
            if let Some(reference) = identity_passphrase_ref.as_deref() {
                crate::file_transfer::validate_optional_reference(Some(reference), "key-")
                    .map_err(|_| NativeEngineError::invalid("原生 SSH 私钥口令引用无效"))?;
            }
            Ok(NativeAuthSource::PrivateKeyFile {
                identity_file,
                passphrase_ref: identity_passphrase_ref,
            })
        }
        (None, None) => Err(NativeEngineError::invalid(
            "原生引擎检查需要凭据引用或私钥文件",
        )),
    }
}

fn resolve_auth(source: NativeAuthSource) -> Result<NativeAuth, NativeEngineError> {
    match source {
        NativeAuthSource::PasswordReference(reference) => {
            let password =
                crate::file_transfer::read_secret(&reference, "原生 SSH 密码引用不存在或无法读取")
                    .map_err(|_| {
                        NativeEngineError::new(
                            "native-engine-credential-unavailable",
                            "原生 SSH 凭据不可用",
                            false,
                        )
                    })?;
            Ok(NativeAuth::Password(password))
        }
        NativeAuthSource::PrivateKeyFile {
            identity_file,
            passphrase_ref,
        } => {
            let private_key = read_private_key(&identity_file)?;
            let passphrase = match passphrase_ref {
                Some(reference) => Some(
                    crate::file_transfer::read_secret(
                        &reference,
                        "原生 SSH 私钥口令引用不存在或无法读取",
                    )
                    .map_err(|_| {
                        NativeEngineError::new(
                            "native-engine-key-passphrase-unavailable",
                            "原生 SSH 私钥口令不可用",
                            false,
                        )
                    })?,
                ),
                None => None,
            };
            Ok(NativeAuth::PrivateKey {
                private_key,
                passphrase,
            })
        }
    }
}

fn validate_private_key_path_shape(value: &str) -> Result<(), NativeEngineError> {
    if value.is_empty() || value.len() > MAX_PATH_BYTES {
        return Err(NativeEngineError::invalid("原生 SSH 私钥路径无效"));
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(NativeEngineError::invalid(
            "原生 SSH 私钥路径必须是绝对路径",
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(NativeEngineError::invalid(
            "原生 SSH 私钥路径不能包含 . 或 ..",
        ));
    }
    Ok(())
}

fn read_private_key(value: &str) -> Result<Zeroizing<Vec<u8>>, NativeEngineError> {
    validate_private_key_path_shape(value)?;
    let path = Path::new(value);
    reject_symlink_components(path)?;
    let mut file = File::open(path).map_err(|_| {
        NativeEngineError::new(
            "native-engine-key-unavailable",
            "原生 SSH 私钥无法读取",
            false,
        )
    })?;
    reject_symlink_components(path)?;
    let metadata = file.metadata().map_err(|_| {
        NativeEngineError::new(
            "native-engine-key-unavailable",
            "原生 SSH 私钥无法读取",
            false,
        )
    })?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(NativeEngineError::invalid(
            "原生 SSH 私钥文件大小或类型无效",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_PRIVATE_KEY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            NativeEngineError::new(
                "native-engine-key-unavailable",
                "原生 SSH 私钥无法读取",
                false,
            )
        })?;
    if bytes.len() as u64 > MAX_PRIVATE_KEY_BYTES {
        return Err(NativeEngineError::invalid("原生 SSH 私钥文件过大"));
    }
    if std::str::from_utf8(&bytes).is_err() {
        return Err(NativeEngineError::invalid(
            "原生 SSH 私钥必须使用 UTF-8 文本格式",
        ));
    }
    Ok(Zeroizing::new(bytes))
}

fn reject_symlink_components(path: &Path) -> Result<(), NativeEngineError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
            }
            Component::CurDir | Component::ParentDir => {
                return Err(NativeEngineError::invalid(
                    "原生 SSH 私钥路径不能包含 . 或 ..",
                ));
            }
        }
        if current.as_os_str().is_empty() || current.parent().is_none() {
            continue;
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| {
            NativeEngineError::new(
                "native-engine-key-unavailable",
                "原生 SSH 私钥路径无法读取",
                false,
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(NativeEngineError::invalid(
                "原生 SSH 私钥路径不能经过符号链接",
            ));
        }
    }
    Ok(())
}

#[derive(Clone)]
struct PinnedServerKey {
    expected_sha256: String,
    state: Arc<AtomicU8>,
}

impl Handler for PinnedServerKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let matched =
            server_public_key.fingerprint(HashAlg::Sha256).to_string() == self.expected_sha256;
        self.state.store(
            if matched {
                HOST_KEY_MATCHED
            } else {
                HOST_KEY_MISMATCHED
            },
            Ordering::SeqCst,
        );
        Ok(matched)
    }
}

struct NativeConnectionChain {
    sessions: Vec<client::Handle<PinnedServerKey>>,
}

impl NativeConnectionChain {
    fn final_session(&self) -> Result<&client::Handle<PinnedServerKey>, NativeEngineError> {
        self.sessions.last().ok_or_else(|| {
            NativeEngineError::new(
                "native-engine-route-empty",
                "原生 SSH 路由没有可用连接",
                false,
            )
        })
    }

    async fn disconnect_all(&self, description: &'static str) -> bool {
        disconnect_sessions(&self.sessions, description).await
    }
}

async fn connect_route(route: ValidatedRoute) -> Result<NativeConnectionChain, NativeEngineError> {
    let mut hops = route.hops.into_iter();
    let first = hops.next().ok_or_else(|| {
        NativeEngineError::new(
            "native-engine-route-empty",
            "原生 SSH 路由没有可用连接",
            false,
        )
    })?;
    let first_hop_index = first.hop_index;
    let first_timeout = Duration::from_secs(u64::from(first.timeout_seconds));
    let first_session =
        match tokio::time::timeout(first_timeout, connect_authenticated_direct_hop(first)).await {
            Ok(result) => result.map_err(|error| error.at_hop(first_hop_index))?,
            Err(_) => {
                return Err(NativeEngineError::new(
                    "native-engine-hop-timeout",
                    "原生 SSH 路由连接超时",
                    true,
                )
                .at_hop(first_hop_index));
            }
        };
    let mut sessions = vec![first_session];

    for hop in hops {
        let hop_index = hop.hop_index;
        let timeout = Duration::from_secs(u64::from(hop.timeout_seconds));
        let previous = sessions.last().ok_or_else(|| {
            NativeEngineError::new(
                "native-engine-route-empty",
                "原生 SSH 路由没有可用连接",
                false,
            )
        })?;
        let outcome =
            tokio::time::timeout(timeout, connect_authenticated_tunneled_hop(previous, hop)).await;
        let session = match outcome {
            Ok(Ok(session)) => session,
            Ok(Err(error)) => {
                disconnect_sessions(&sessions, "native route failed").await;
                return Err(error.at_hop(hop_index));
            }
            Err(_) => {
                disconnect_sessions(&sessions, "native route timed out").await;
                return Err(NativeEngineError::new(
                    "native-engine-hop-timeout",
                    "原生 SSH 路由连接超时",
                    true,
                )
                .at_hop(hop_index));
            }
        };
        sessions.push(session);
    }

    Ok(NativeConnectionChain { sessions })
}

async fn connect_authenticated_direct_hop(
    request: ValidatedConnection,
) -> Result<client::Handle<PinnedServerKey>, NativeEngineError> {
    let ValidatedConnection {
        host,
        port,
        username,
        host_key_sha256,
        timeout_seconds,
        auth_source,
        ..
    } = request;
    let auth = resolve_auth(auth_source)?;
    let host_key_state = Arc::new(AtomicU8::new(HOST_KEY_UNSEEN));
    let handler = PinnedServerKey {
        expected_sha256: host_key_sha256,
        state: Arc::clone(&host_key_state),
    };
    let timeout = Duration::from_secs(u64::from(timeout_seconds));
    let config = native_client_config(timeout);
    let session = client::connect(Arc::new(config), (host.as_str(), port), handler)
        .await
        .map_err(|_| connection_error(&host_key_state))?;
    authenticate_connected_hop(session, username, auth, host_key_state).await
}

async fn connect_authenticated_tunneled_hop(
    previous: &client::Handle<PinnedServerKey>,
    request: ValidatedConnection,
) -> Result<client::Handle<PinnedServerKey>, NativeEngineError> {
    let ValidatedConnection {
        host,
        port,
        username,
        host_key_sha256,
        timeout_seconds,
        auth_source,
        ..
    } = request;
    let channel = previous
        .channel_open_direct_tcpip(host.clone(), u32::from(port), "127.0.0.1", 0)
        .await
        .map_err(|_| {
            NativeEngineError::new(
                "native-engine-jump-tunnel-failed",
                "跳板机无法建立到下一跳的 SSH tunnel",
                true,
            )
        })?;
    let auth = resolve_auth(auth_source)?;
    let host_key_state = Arc::new(AtomicU8::new(HOST_KEY_UNSEEN));
    let handler = PinnedServerKey {
        expected_sha256: host_key_sha256,
        state: Arc::clone(&host_key_state),
    };
    let timeout = Duration::from_secs(u64::from(timeout_seconds));
    let config = native_client_config(timeout);
    let session = client::connect_stream(Arc::new(config), channel.into_stream(), handler)
        .await
        .map_err(|_| connection_error(&host_key_state))?;
    authenticate_connected_hop(session, username, auth, host_key_state).await
}

fn connection_error(host_key_state: &AtomicU8) -> NativeEngineError {
    if host_key_state.load(Ordering::SeqCst) == HOST_KEY_MISMATCHED {
        NativeEngineError::new(
            "native-engine-host-key-mismatch",
            "原生 SSH 主机指纹不匹配，已在认证前拒绝连接",
            false,
        )
    } else {
        NativeEngineError::new(
            "native-engine-connect-failed",
            "原生 SSH 连接或握手失败",
            true,
        )
    }
}

async fn authenticate_connected_hop(
    mut session: client::Handle<PinnedServerKey>,
    username: String,
    mut auth: NativeAuth,
    host_key_state: Arc<AtomicU8>,
) -> Result<client::Handle<PinnedServerKey>, NativeEngineError> {
    if host_key_state.load(Ordering::SeqCst) != HOST_KEY_MATCHED {
        return Err(NativeEngineError::new(
            "native-engine-host-key-unverified",
            "原生 SSH 未完成主机指纹验证",
            false,
        ));
    }

    let authenticated = match &mut auth {
        NativeAuth::Password(password) => session
            .authenticate_password(username, password.as_str())
            .await
            .map_err(|_| {
                NativeEngineError::new("native-engine-auth-failed", "原生 SSH 身份验证失败", false)
            })?
            .success(),
        NativeAuth::PrivateKey {
            private_key,
            passphrase,
        } => {
            let encoded = std::str::from_utf8(private_key.as_slice())
                .map_err(|_| NativeEngineError::invalid("原生 SSH 私钥必须使用 UTF-8 文本格式"))?;
            let private_key =
                decode_secret_key(encoded, passphrase.as_ref().map(|value| value.as_str()))
                    .map_err(|_| {
                        NativeEngineError::new(
                            "native-engine-key-invalid",
                            "原生 SSH 私钥或口令无效",
                            false,
                        )
                    })?;
            let hash = if private_key.algorithm().is_rsa() {
                Some(
                    session
                        .best_supported_rsa_hash()
                        .await
                        .map_err(|_| {
                            NativeEngineError::new(
                                "native-engine-auth-negotiation-failed",
                                "原生 SSH 认证算法协商失败",
                                false,
                            )
                        })?
                        .flatten()
                        .ok_or_else(|| {
                            NativeEngineError::new(
                                "native-engine-rsa-sha2-unavailable",
                                "服务器未协商 RSA SHA-2，请使用系统 OpenSSH 兼容引擎",
                                false,
                            )
                        })?,
                )
            } else {
                None
            };
            session
                .authenticate_publickey(
                    username,
                    PrivateKeyWithHashAlg::new(Arc::new(private_key), hash),
                )
                .await
                .map_err(|_| {
                    NativeEngineError::new(
                        "native-engine-auth-failed",
                        "原生 SSH 身份验证失败",
                        false,
                    )
                })?
                .success()
        }
    };
    if !authenticated {
        return Err(NativeEngineError::new(
            "native-engine-auth-rejected",
            "原生 SSH 身份验证被服务器拒绝",
            false,
        ));
    }
    Ok(session)
}

async fn disconnect_sessions(
    sessions: &[client::Handle<PinnedServerKey>],
    description: &'static str,
) -> bool {
    let mut disconnected = true;
    for session in sessions.iter().rev() {
        if session
            .disconnect(Disconnect::ByApplication, description, "")
            .await
            .is_err()
        {
            disconnected = false;
        }
    }
    disconnected
}

fn local_forward_snapshot(
    forward_id: Uuid,
    bind_port: u16,
    route_host: &str,
    route_hops: u8,
    target_host: &str,
    target_port: u16,
    stats: &LocalForwardStats,
) -> NativeLocalForwardSnapshot {
    NativeLocalForwardSnapshot {
        schema_version: SCHEMA_VERSION,
        forward_id: forward_id.to_string(),
        state: if stats.ready.load(Ordering::SeqCst) == 1 {
            "active"
        } else {
            "starting"
        },
        bind_host: "127.0.0.1",
        bind_port,
        route_host: route_host.to_string(),
        route_hops,
        target_host: target_host.to_string(),
        target_port,
        active_connections: stats.active_connections.load(Ordering::SeqCst),
        accepted_connections: stats.accepted_connections.load(Ordering::SeqCst),
        rejected_connections: stats.rejected_connections.load(Ordering::SeqCst),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_native_local_forward(
    manager: NativeEngineManager,
    forward_id: Uuid,
    generation: u64,
    listener: TcpListener,
    connection_chain: Arc<NativeConnectionChain>,
    target_host: String,
    target_port: u16,
    cancellation: CancellationToken,
    stats: Arc<LocalForwardStats>,
) {
    let capacity = Arc::new(Semaphore::new(MAX_LOCAL_FORWARD_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            completed = connections.join_next(), if !connections.is_empty() => {
                let _ = completed;
            }
            accepted = listener.accept() => {
                let Ok((local_stream, peer)) = accepted else {
                    break;
                };
                let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() else {
                    stats.rejected_connections.fetch_add(1, Ordering::SeqCst);
                    continue;
                };
                stats.accepted_connections.fetch_add(1, Ordering::SeqCst);
                stats.active_connections.fetch_add(1, Ordering::SeqCst);
                let connection_guard = ActiveForwardConnectionGuard {
                    stats: Arc::clone(&stats),
                };
                let connection_chain = Arc::clone(&connection_chain);
                let target_host = target_host.clone();
                let cancellation = cancellation.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let _connection_guard = connection_guard;
                    forward_local_connection(
                        connection_chain,
                        local_stream,
                        peer.ip().to_string(),
                        peer.port(),
                        target_host,
                        target_port,
                        cancellation,
                    )
                    .await;
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    connection_chain
        .disconnect_all("native local forward stopped")
        .await;
    manager.finish_local_forward(forward_id, generation);
}

async fn forward_local_connection(
    connection_chain: Arc<NativeConnectionChain>,
    mut local_stream: TcpStream,
    originator_host: String,
    originator_port: u16,
    target_host: String,
    target_port: u16,
    cancellation: CancellationToken,
) {
    let Ok(session) = connection_chain.final_session() else {
        return;
    };
    let channel = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return,
        result = session.channel_open_direct_tcpip(
            target_host,
            u32::from(target_port),
            originator_host,
            u32::from(originator_port),
        ) => match result {
            Ok(channel) => channel,
            Err(_) => return,
        },
    };
    let mut remote_stream = channel.into_stream();
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => {}
        _ = copy_bidirectional(&mut local_stream, &mut remote_stream) => {}
    }
}

async fn probe_once(request: ValidatedRoute) -> Result<NativeEngineProbeResult, NativeEngineError> {
    let timeout_seconds = request
        .hops
        .last()
        .map_or(MIN_TIMEOUT_SECONDS, |hop| hop.timeout_seconds);
    let connection_chain = connect_route(request).await?;
    let session = connection_chain.final_session()?;
    let probe = async {
        let channel = session.channel_open_session().await.map_err(|_| {
            NativeEngineError::new(
                "native-engine-sftp-channel-failed",
                "原生 SSH 无法打开 SFTP 通道",
                true,
            )
        })?;
        channel.request_subsystem(true, "sftp").await.map_err(|_| {
            NativeEngineError::new(
                "native-engine-sftp-subsystem-failed",
                "服务器未提供 SFTP 子系统",
                false,
            )
        })?;
        let sftp = SftpSession::new(channel.into_stream()).await.map_err(|_| {
            NativeEngineError::new(
                "native-engine-sftp-init-failed",
                "原生 SFTP 协议初始化失败",
                true,
            )
        })?;
        sftp.set_timeout(u64::from(timeout_seconds));
        sftp.canonicalize(".").await.map_err(|_| {
            NativeEngineError::new(
                "native-engine-sftp-probe-failed",
                "原生 SFTP 无法读取远端工作目录",
                true,
            )
        })?;
        sftp.close().await.map_err(|_| {
            NativeEngineError::new(
                "native-engine-sftp-close-failed",
                "原生 SFTP 检查已完成但通道关闭失败",
                true,
            )
        })
    }
    .await;
    let disconnected = connection_chain
        .disconnect_all("native engine probe complete")
        .await;
    probe?;
    if !disconnected {
        return Err(NativeEngineError::new(
            "native-engine-disconnect-failed",
            "原生 SSH 检查已完成但连接关闭失败",
            true,
        ));
    }

    Ok(NativeEngineProbeResult {
        schema_version: SCHEMA_VERSION,
        engine: ENGINE_NAME,
        ssh_ready: true,
        sftp_ready: true,
    })
}

async fn open_native_terminal(
    request: ValidatedRoute,
    cols: u16,
    rows: u16,
) -> Result<(NativeConnectionChain, Channel<client::Msg>, Vec<u8>), NativeEngineError> {
    let final_hop_index = request.final_hop_index();
    let connection_chain = connect_route(request).await?;
    let session = connection_chain.final_session()?;
    let terminal = async {
        let mut channel = session.channel_open_session().await.map_err(|_| {
            NativeEngineError::new(
                "native-terminal-channel-failed",
                "原生 SSH 无法打开终端通道",
                true,
            )
            .at_hop(final_hop_index)
        })?;
        let mut initial_output = Vec::new();
        channel
            .request_pty(
                true,
                "xterm-256color",
                u32::from(cols),
                u32::from(rows),
                0,
                0,
                &[],
            )
            .await
            .map_err(|_| {
                NativeEngineError::new(
                    "native-terminal-pty-request-failed",
                    "原生 SSH 无法请求 PTY",
                    true,
                )
                .at_hop(final_hop_index)
            })?;
        await_channel_success(
            &mut channel,
            &mut initial_output,
            "native-terminal-pty-rejected",
            "服务器拒绝原生终端 PTY 请求",
        )
        .await
        .map_err(|error| error.at_hop(final_hop_index))?;
        channel.request_shell(true).await.map_err(|_| {
            NativeEngineError::new(
                "native-terminal-shell-request-failed",
                "原生 SSH 无法请求交互式 Shell",
                true,
            )
            .at_hop(final_hop_index)
        })?;
        await_channel_success(
            &mut channel,
            &mut initial_output,
            "native-terminal-shell-rejected",
            "服务器拒绝原生交互式 Shell",
        )
        .await
        .map_err(|error| error.at_hop(final_hop_index))?;
        Ok::<_, NativeEngineError>((channel, initial_output))
    }
    .await;
    match terminal {
        Ok((channel, initial_output)) => Ok((connection_chain, channel, initial_output)),
        Err(error) => {
            connection_chain
                .disconnect_all("native terminal start failed")
                .await;
            Err(error)
        }
    }
}

async fn open_native_sftp_session(
    session: &client::Handle<PinnedServerKey>,
    timeout: Duration,
) -> Result<SftpSession, NativeEngineError> {
    let channel = session.channel_open_session().await.map_err(|_| {
        NativeEngineError::new(
            "native-sftp-channel-failed",
            "原生 SSH 无法打开长期 SFTP 通道",
            true,
        )
    })?;
    channel.request_subsystem(true, "sftp").await.map_err(|_| {
        NativeEngineError::new(
            "native-sftp-subsystem-failed",
            "服务器未提供 SFTP 子系统",
            false,
        )
    })?;
    let sftp = SftpSession::new(channel.into_stream()).await.map_err(|_| {
        NativeEngineError::new(
            "native-sftp-init-failed",
            "长期原生 SFTP 协议初始化失败",
            true,
        )
    })?;
    sftp.set_timeout(timeout.as_secs());
    Ok(sftp)
}

async fn list_native_sftp_directory(
    session: &client::Handle<PinnedServerKey>,
    sftp: &mut Option<SftpSession>,
    path: String,
    timeout: Duration,
) -> Result<NativeSftpDirectoryResult, NativeEngineError> {
    if sftp.is_none() {
        *sftp = Some(open_native_sftp_session(session, timeout).await?);
    }
    let sftp = sftp.as_ref().ok_or_else(|| {
        NativeEngineError::new(
            "native-sftp-init-failed",
            "长期原生 SFTP 协议初始化失败",
            true,
        )
    })?;
    let requested_path = if path == "~" { ".".to_string() } else { path };
    let canonical = sftp.canonicalize(requested_path).await.map_err(|_| {
        NativeEngineError::new(
            "native-sftp-path-unavailable",
            "原生 SFTP 路径不存在或不可访问",
            true,
        )
    })?;
    validate_sftp_canonical_path(&canonical)?;
    let directory_metadata = sftp
        .symlink_metadata(canonical.clone())
        .await
        .map_err(|_| {
            NativeEngineError::new(
                "native-sftp-directory-stat-failed",
                "无法读取原生 SFTP 目录属性",
                true,
            )
        })?;
    if directory_metadata.is_symlink() || !directory_metadata.is_dir() {
        return Err(NativeEngineError::new(
            "native-sftp-not-directory",
            "原生 SFTP 浏览目标必须是非符号链接目录",
            false,
        ));
    }
    let directory = sftp.read_dir(canonical.clone()).await.map_err(|_| {
        NativeEngineError::new("native-sftp-list-failed", "无法读取原生 SFTP 目录", true)
    })?;
    let mut entries = Vec::new();
    for entry in directory {
        if entries.len() >= MAX_SFTP_DIRECTORY_ENTRIES {
            return Err(NativeEngineError::new(
                "native-sftp-directory-limit",
                "原生 SFTP 目录超过 1000 项上限",
                false,
            ));
        }
        let name = entry.file_name();
        validate_sftp_entry_name(&name)?;
        let metadata = entry.metadata();
        let kind = if metadata.is_dir() {
            NativeSftpEntryKind::Directory
        } else if metadata.is_regular() {
            NativeSftpEntryKind::File
        } else if metadata.is_symlink() {
            NativeSftpEntryKind::Symlink
        } else {
            NativeSftpEntryKind::Other
        };
        let owner_group = match (metadata.uid, metadata.gid) {
            (Some(uid), Some(gid)) => Some(format!("{uid}:{gid}")),
            (Some(uid), None) => Some(uid.to_string()),
            (None, Some(gid)) => Some(format!(":{gid}")),
            (None, None) => None,
        };
        entries.push(NativeSftpEntry {
            path: if canonical == "/" {
                format!("/{name}")
            } else {
                format!("{}/{name}", canonical.trim_end_matches('/'))
            },
            name,
            kind,
            size: metadata.size.unwrap_or(0),
            modified: metadata.mtime.map(u64::from),
            permissions: metadata
                .permissions
                .map(|mode| format!("{:04o}", mode & 0o7777))
                .unwrap_or_else(|| "----".to_string()),
            owner_group,
        });
    }
    entries.sort_by(|left, right| {
        native_sftp_kind_order(&left.kind)
            .cmp(&native_sftp_kind_order(&right.kind))
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
    });
    Ok(NativeSftpDirectoryResult {
        path: canonical,
        entries,
    })
}

fn native_sftp_kind_order(kind: &NativeSftpEntryKind) -> u8 {
    match kind {
        NativeSftpEntryKind::Directory => 0,
        NativeSftpEntryKind::File => 1,
        NativeSftpEntryKind::Symlink => 2,
        NativeSftpEntryKind::Other => 3,
    }
}

async fn run_native_sftp_session(
    connection_chain: Arc<NativeConnectionChain>,
    mut requests: mpsc::Receiver<NativeSftpCommand>,
    cancellation: CancellationToken,
    timeout: Duration,
) {
    let mut sftp = None;
    loop {
        let request = tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            request = requests.recv() => request,
        };
        let Some(NativeSftpCommand::List { path, reply }) = request else {
            break;
        };
        if reply.is_closed() {
            continue;
        }
        let final_session = match connection_chain.final_session() {
            Ok(session) => session,
            Err(error) => {
                let _ = reply.send(Err(error));
                break;
            }
        };
        let outcome = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(NativeEngineError::new(
                "native-sftp-cancelled",
                "原生 SFTP 浏览已取消",
                true,
            )),
            result = tokio::time::timeout(
                timeout,
                list_native_sftp_directory(
                    final_session,
                    &mut sftp,
                    path,
                    timeout,
                ),
            ) => match result {
                Ok(outcome) => outcome,
                Err(_) => Err(NativeEngineError::new(
                    "native-sftp-timeout",
                    "原生 SFTP 浏览超时",
                    true,
                )),
            },
        };
        if outcome.is_err()
            && let Some(failed) = sftp.take()
        {
            let _ = tokio::time::timeout(Duration::from_secs(1), failed.close()).await;
        }
        let _ = reply.send(outcome);
    }
    if let Some(sftp) = sftp {
        let _ = tokio::time::timeout(Duration::from_secs(1), sftp.close()).await;
    }
}

async fn await_channel_success(
    channel: &mut Channel<client::Msg>,
    initial_output: &mut Vec<u8>,
    rejected_code: &'static str,
    rejected_message: &'static str,
) -> Result<(), NativeEngineError> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            Some(ChannelMsg::Failure) => {
                return Err(NativeEngineError::new(
                    rejected_code,
                    rejected_message,
                    false,
                ));
            }
            Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                if initial_output.len().saturating_add(data.len()) > MAX_INITIAL_OUTPUT_BYTES {
                    return Err(NativeEngineError::new(
                        "native-terminal-early-output-limit",
                        "原生终端在启动确认前返回了过多数据",
                        false,
                    ));
                }
                initial_output.extend_from_slice(&data);
            }
            Some(ChannelMsg::Eof | ChannelMsg::Close) | None => {
                return Err(NativeEngineError::new(
                    "native-terminal-closed-during-start",
                    "原生终端在启动确认前关闭",
                    true,
                ));
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_native_terminal(
    manager: NativeEngineManager,
    session_id: Uuid,
    generation: u64,
    connection_chain: Arc<NativeConnectionChain>,
    channel: Channel<client::Msg>,
    initial_output: Vec<u8>,
    mut commands: mpsc::Receiver<NativeTerminalCommand>,
    events: mpsc::Sender<NativeTerminalEvent>,
    cancellation: CancellationToken,
) {
    let (mut reader, writer) = channel.split();
    let writer_cancellation = cancellation.clone();
    let writer_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = writer_cancellation.cancelled() => {
                    let _ = tokio::time::timeout(Duration::from_secs(1), async {
                        let _ = writer.eof().await;
                        writer.close().await
                    }).await;
                    return None;
                }
                command = commands.recv() => {
                    let Some(command) = command else {
                        return Some("原生终端控制通道已关闭");
                    };
                    let result = match command {
                        NativeTerminalCommand::Data(data) => tokio::select! {
                            biased;
                            _ = writer_cancellation.cancelled() => return None,
                            result = writer.data_bytes(data) => result,
                        },
                        NativeTerminalCommand::Resize { cols, rows } => tokio::select! {
                            biased;
                            _ = writer_cancellation.cancelled() => return None,
                            result = writer.window_change(
                                u32::from(cols),
                                u32::from(rows),
                                0,
                                0,
                            ) => result,
                        },
                    };
                    if result.is_err() {
                        writer_cancellation.cancel();
                        return Some("原生终端写入或尺寸调整失败");
                    }
                }
            }
        }
    });

    let mut exit_message = None;
    if !initial_output.is_empty()
        && !send_terminal_event(
            &events,
            NativeTerminalEvent::Data(initial_output),
            &cancellation,
        )
        .await
    {
        cancellation.cancel();
    }
    while !cancellation.is_cancelled() {
        let message = tokio::select! {
            biased;
            _ = cancellation.cancelled() => None,
            message = reader.wait() => message,
        };
        match message {
            Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                if !send_terminal_event(
                    &events,
                    NativeTerminalEvent::Data(data.to_vec()),
                    &cancellation,
                )
                .await
                {
                    cancellation.cancel();
                }
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                if exit_status != 0 {
                    exit_message = Some("原生终端以非零状态退出");
                }
                break;
            }
            Some(ChannelMsg::ExitSignal { .. }) => {
                exit_message = Some("原生终端被远端信号终止");
                break;
            }
            Some(ChannelMsg::Failure | ChannelMsg::OpenFailure(_)) => {
                exit_message = Some("原生终端通道报告失败");
                break;
            }
            Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
            _ => {}
        }
    }
    cancellation.cancel();
    match writer_task.await {
        Ok(Some(message)) if exit_message.is_none() => exit_message = Some(message),
        Err(_) if exit_message.is_none() => exit_message = Some("原生终端写入任务异常结束"),
        _ => {}
    }
    connection_chain
        .disconnect_all("native terminal closed")
        .await;
    manager.finish_terminal(session_id, generation);
    let _ = events
        .send(NativeTerminalEvent::Exit {
            message: exit_message,
        })
        .await;
}

async fn send_terminal_event(
    events: &mpsc::Sender<NativeTerminalEvent>,
    event: NativeTerminalEvent,
    cancellation: &CancellationToken,
) -> bool {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => false,
        result = events.send(event) => result.is_ok(),
    }
}

fn native_client_config(timeout: Duration) -> client::Config {
    let mut config = client::Config {
        inactivity_timeout: Some(timeout),
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 2,
        window_size: 2 * 1024 * 1024,
        maximum_packet_size: 32 * 1024,
        channel_buffer_size: 64,
        nodelay: true,
        ..Default::default()
    };
    config
        .preferred
        .key
        .to_mut()
        .retain(|algorithm| !matches!(algorithm, Algorithm::Rsa { hash: None }));
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn hop() -> NativeRouteHopRequest {
        NativeRouteHopRequest {
            hop_id: "018f1f55-26f8-7a9f-9cd8-4d7558482213".to_string(),
            host: "host.example".to_string(),
            port: 22,
            username: "operator".to_string(),
            host_key_sha256: format!("SHA256:{}", "A".repeat(43)),
            timeout_seconds: 15,
            credential_ref: Some("ssh-018f1f55-26f8-7a9f-9cd8-4d7558482212".to_string()),
            identity_file: None,
            identity_passphrase_ref: None,
        }
    }

    fn request() -> NativeEngineProbeRequest {
        NativeEngineProbeRequest {
            operation_id: "018f1f55-26f8-7a9f-9cd8-4d7558482211".to_string(),
            route: NativeRouteRequest { hops: vec![hop()] },
        }
    }

    #[test]
    fn request_fields_and_authentication_are_bounded() {
        assert!(validate_host("host.example").is_ok());
        assert!(validate_host("../host").is_err());
        assert!(validate_username("operator").is_ok());
        assert!(validate_username("operator@example").is_err());
        assert!(validate_fingerprint(&format!("SHA256:{}", "A".repeat(43))).is_ok());
        assert!(validate_fingerprint("ssh-ed25519 AAAA").is_err());

        let mut invalid = request();
        invalid.route.hops[0].timeout_seconds = 4;
        let error = match ValidatedRoute::try_from(invalid) {
            Ok(_) => panic!("invalid timeout accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, "native-engine-invalid-request");
        assert_eq!(error.hop_index, Some(1));

        let mut conflicting_auth = request();
        conflicting_auth.route.hops[0].identity_file = Some("/tmp/private-key".to_string());
        let error = match ValidatedRoute::try_from(conflicting_auth) {
            Ok(_) => panic!("multiple authentication sources accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, "native-engine-invalid-request");

        let mut missing_auth = request();
        missing_auth.route.hops[0].credential_ref = None;
        let error = match ValidatedRoute::try_from(missing_auth) {
            Ok(_) => panic!("missing authentication source accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, "native-engine-invalid-request");
        assert!(read_private_key("relative-key").is_err());

        let invalid_terminal = NativeTerminalStartRequest {
            session_id: "not-a-uuid".to_string(),
            route: NativeRouteRequest { hops: vec![hop()] },
            cols: 120,
            rows: 32,
        };
        assert!(ValidatedTerminalStart::try_from(invalid_terminal).is_err());
        assert!(validate_terminal_size(1, 32).is_err());
        assert!(validate_terminal_size(120, 1001).is_err());
        assert!(validate_terminal_size(120, 32).is_ok());
        assert!(validate_sftp_request_path(".").is_ok());
        assert!(validate_sftp_request_path("~").is_ok());
        assert!(validate_sftp_request_path("/srv/app").is_ok());
        assert!(validate_sftp_request_path("srv/app").is_err());
        assert!(validate_sftp_request_path("/srv\napp").is_err());
        assert!(validate_sftp_entry_name("release.tar.zst").is_ok());
        assert!(validate_sftp_entry_name("../release").is_err());
        assert!(
            serde_json::from_value::<NativeSftpListRequest>(serde_json::json!({
                "sessionId": Uuid::new_v4().to_string(),
                "path": "/",
                "credentialRef": "ssh-forbidden"
            }))
            .is_err()
        );

        let config = native_client_config(Duration::from_secs(15));
        assert!(
            !config
                .preferred
                .key
                .iter()
                .any(|algorithm| matches!(algorithm, Algorithm::Rsa { hash: None }))
        );
    }

    #[test]
    fn route_hops_bind_independent_authentication_and_host_keys() {
        let password_hop = hop();
        let mut key_hop = hop();
        key_hop.hop_id = "018f1f55-26f8-7a9f-9cd8-4d7558482214".to_string();
        key_hop.host = "target.example".to_string();
        key_hop.host_key_sha256 = format!("SHA256:{}", "B".repeat(43));
        key_hop.credential_ref = None;
        key_hop.identity_file = Some(
            std::env::temp_dir()
                .join("vpshell-target-key")
                .to_string_lossy()
                .into_owned(),
        );
        key_hop.identity_passphrase_ref =
            Some("key-018f1f55-26f8-7a9f-9cd8-4d7558482215".to_string());
        let route = validate_route(NativeRouteRequest {
            hops: vec![password_hop, key_hop],
        })
        .expect("independent hop route");
        assert_eq!(route.hops.len(), 2);
        assert_eq!(route.hops[0].hop_index, 1);
        assert_eq!(route.hops[1].hop_index, 2);
        assert_ne!(route.hops[0].host_key_sha256, route.hops[1].host_key_sha256);
        assert!(matches!(
            &route.hops[0].auth_source,
            NativeAuthSource::PasswordReference(_)
        ));
        assert!(matches!(
            &route.hops[1].auth_source,
            NativeAuthSource::PrivateKeyFile { .. }
        ));
        assert_eq!(route.final_hop_index(), 2);
        assert_eq!(route.final_timeout(), Duration::from_secs(15));
        assert_eq!(route.operation_timeout(), Duration::from_secs(45));

        let first = hop();
        let mut duplicate_id = hop();
        duplicate_id.host = "other.example".to_string();
        let error = match validate_route(NativeRouteRequest {
            hops: vec![first, duplicate_id],
        }) {
            Ok(_) => panic!("duplicate hop id accepted"),
            Err(error) => error,
        };
        assert_eq!(error.hop_index, Some(2));

        let first = hop();
        let mut duplicate_endpoint = hop();
        duplicate_endpoint.hop_id = "018f1f55-26f8-7a9f-9cd8-4d7558482216".to_string();
        duplicate_endpoint.username = "different-user".to_string();
        let error = match validate_route(NativeRouteRequest {
            hops: vec![first, duplicate_endpoint],
        }) {
            Ok(_) => panic!("duplicate endpoint accepted"),
            Err(error) => error,
        };
        assert_eq!(error.hop_index, Some(2));

        let mut too_many = Vec::new();
        for index in 0..=MAX_NATIVE_ROUTE_HOPS {
            let mut route_hop = hop();
            route_hop.hop_id = Uuid::from_u128(index as u128 + 100).to_string();
            route_hop.host = format!("hop-{index}.example");
            too_many.push(route_hop);
        }
        assert!(validate_route(NativeRouteRequest { hops: too_many }).is_err());
    }

    #[test]
    fn route_request_rejects_legacy_flat_and_secret_fields() {
        let operation_id = Uuid::new_v4().to_string();
        let hop_id = Uuid::new_v4().to_string();
        let fingerprint = format!("SHA256:{}", "A".repeat(43));
        assert!(
            serde_json::from_value::<NativeEngineProbeRequest>(serde_json::json!({
                "operationId": operation_id,
                "host": "host.example",
                "port": 22,
                "username": "operator",
                "hostKeySha256": fingerprint,
                "timeoutSeconds": 15,
                "credentialRef": "ssh-018f1f55-26f8-7a9f-9cd8-4d7558482212"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<NativeEngineProbeRequest>(serde_json::json!({
                "operationId": Uuid::new_v4().to_string(),
                "route": {"hops": [{
                    "hopId": hop_id,
                    "host": "host.example",
                    "port": 22,
                    "username": "operator",
                    "hostKeySha256": format!("SHA256:{}", "A".repeat(43)),
                    "timeoutSeconds": 15,
                    "credentialRef": "ssh-018f1f55-26f8-7a9f-9cd8-4d7558482212",
                    "password": "forbidden"
                }]}
            }))
            .is_err()
        );
        let encoded =
            serde_json::to_value(NativeEngineError::invalid("原生 SSH 路由跳标识重复").at_hop(2))
                .unwrap();
        assert_eq!(encoded["hopIndex"], 2);
        assert!(!encoded.to_string().contains("host.example"));
        assert!(!encoded.to_string().contains("credentialRef"));
    }

    #[test]
    fn local_forward_requests_and_lifecycle_are_bounded() {
        let request = NativeLocalForwardStartRequest {
            forward_id: Uuid::new_v4().to_string(),
            route: NativeRouteRequest { hops: vec![hop()] },
            bind_port: 0,
            target_host: "127.0.0.1".to_string(),
            target_port: 5432,
        };
        let validated = ValidatedLocalForwardStart::try_from(request).unwrap();
        assert_eq!(validated.bind_port, 0);
        assert_eq!(validated.target_host, "127.0.0.1");
        assert_eq!(validated.target_port, 5432);

        for forbidden in ["bindHost", "credentialRef", "password"] {
            let mut value = serde_json::json!({
                "forwardId": Uuid::new_v4().to_string(),
                "route": {"hops": [{
                    "hopId": Uuid::new_v4().to_string(),
                    "host": "host.example",
                    "port": 22,
                    "username": "operator",
                    "hostKeySha256": format!("SHA256:{}", "A".repeat(43)),
                    "timeoutSeconds": 15,
                    "credentialRef": "ssh-018f1f55-26f8-7a9f-9cd8-4d7558482212"
                }]},
                "bindPort": 0,
                "targetHost": "127.0.0.1",
                "targetPort": 5432
            });
            value[forbidden] = serde_json::json!("forbidden");
            assert!(serde_json::from_value::<NativeLocalForwardStartRequest>(value).is_err());
        }
        let invalid = NativeLocalForwardStartRequest {
            forward_id: Uuid::new_v4().to_string(),
            route: NativeRouteRequest { hops: vec![hop()] },
            bind_port: 0,
            target_host: "target host".to_string(),
            target_port: 0,
        };
        assert!(ValidatedLocalForwardStart::try_from(invalid).is_err());

        let manager = NativeEngineManager::default();
        let mut ids = Vec::new();
        for index in 0..MAX_LOCAL_FORWARDS {
            let forward_id = Uuid::from_u128(index as u128 + 500);
            ids.push(forward_id);
            manager
                .reserve_local_forward(
                    forward_id,
                    index as u64 + 1,
                    CancellationToken::new(),
                    10_000 + index as u16,
                    "host.example".to_string(),
                    1,
                    "database.internal".to_string(),
                    5432,
                    Arc::new(LocalForwardStats::default()),
                )
                .unwrap();
        }
        let error = manager
            .reserve_local_forward(
                Uuid::from_u128(999),
                99,
                CancellationToken::new(),
                11_000,
                "host.example".to_string(),
                1,
                "database.internal".to_string(),
                5432,
                Arc::new(LocalForwardStats::default()),
            )
            .unwrap_err();
        assert_eq!(error.code, "native-local-forward-capacity");
        let snapshots = manager.list_local_forwards().unwrap();
        assert_eq!(snapshots.len(), MAX_LOCAL_FORWARDS);
        assert!(
            snapshots
                .iter()
                .all(|snapshot| snapshot.bind_host == "127.0.0.1")
        );
        assert!(
            snapshots
                .iter()
                .all(|snapshot| snapshot.state == "starting")
        );
        manager.stop_local_forward(&ids[0].to_string()).unwrap();
        assert!(
            manager
                .lock_local_forwards()
                .unwrap()
                .get(&ids[0])
                .unwrap()
                .cancellation
                .is_cancelled()
        );
        for (index, forward_id) in ids.into_iter().enumerate() {
            manager.finish_local_forward(forward_id, index as u64 + 1);
        }
        assert!(manager.list_local_forwards().unwrap().is_empty());

        let reused_id = Uuid::from_u128(1_500);
        manager
            .reserve_local_forward(
                reused_id,
                100,
                CancellationToken::new(),
                12_000,
                "host.example".to_string(),
                1,
                "database.internal".to_string(),
                5432,
                Arc::new(LocalForwardStats::default()),
            )
            .unwrap();
        manager.finish_local_forward(reused_id, 99);
        assert!(
            manager
                .lock_local_forwards()
                .unwrap()
                .contains_key(&reused_id)
        );
        manager.finish_local_forward(reused_id, 100);
        assert!(manager.list_local_forwards().unwrap().is_empty());

        let stats = Arc::new(LocalForwardStats::default());
        stats.active_connections.store(1, Ordering::SeqCst);
        {
            let _guard = ActiveForwardConnectionGuard {
                stats: Arc::clone(&stats),
            };
        }
        assert_eq!(stats.active_connections.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn manager_enforces_capacity_cancellation_and_generation_cleanup() {
        let manager = NativeEngineManager::default();
        let mut leases = Vec::new();
        for index in 0..MAX_ACTIVE_OPERATIONS {
            let operation_id = Uuid::from_u128(index as u128 + 1);
            leases.push(manager.begin(operation_id).unwrap());
        }
        let error = match manager.begin(Uuid::from_u128(99)) {
            Ok(_) => panic!("operation capacity exceeded"),
            Err(error) => error,
        };
        assert_eq!(error.code, "native-engine-capacity");
        let cancelled_id = leases[0].operation_id;
        manager.cancel(&cancelled_id.to_string()).unwrap();
        assert!(leases[0].cancellation.is_cancelled());
        drop(leases);
        assert!(manager.lock_operations().unwrap().is_empty());

        let reused_id = Uuid::from_u128(101);
        let old = manager.begin(reused_id).unwrap();
        let old_generation = old.generation;
        drop(old);
        let replacement = manager.begin(reused_id).unwrap();
        manager.finish(reused_id, old_generation);
        assert!(manager.lock_operations().unwrap().contains_key(&reused_id));
        drop(replacement);
        assert!(manager.lock_operations().unwrap().is_empty());
    }

    #[test]
    fn terminal_control_is_bounded_and_generation_safe() {
        let (commands, mut receiver) = mpsc::channel(1);
        let cancellation = CancellationToken::new();
        let handle = NativeTerminalHandle {
            cancellation: cancellation.clone(),
            commands,
        };
        handle.write(b"first").unwrap();
        let error = handle.write(b"second").unwrap_err();
        assert_eq!(error.code, "native-terminal-backpressure");
        assert!(
            handle
                .write(&vec![0_u8; MAX_TERMINAL_INPUT_BYTES + 1])
                .is_err()
        );
        assert!(handle.resize(1, 24).is_err());
        assert!(matches!(
            receiver.try_recv().unwrap(),
            NativeTerminalCommand::Data(data) if data == b"first"
        ));
        handle.resize(120, 40).unwrap();
        assert!(matches!(
            receiver.try_recv().unwrap(),
            NativeTerminalCommand::Resize {
                cols: 120,
                rows: 40
            }
        ));
        handle.stop();
        assert!(cancellation.is_cancelled());

        let manager = NativeEngineManager::default();
        let session_id = Uuid::from_u128(201);
        let manager_cancellation = CancellationToken::new();
        let (sftp_requests, _sftp_receiver) = mpsc::channel(1);
        manager
            .reserve_terminal(
                session_id,
                9,
                manager_cancellation.clone(),
                sftp_requests,
                Duration::from_secs(15),
            )
            .unwrap();
        let (replacement_sftp_requests, _replacement_sftp_receiver) = mpsc::channel(1);
        let error = manager
            .reserve_terminal(
                session_id,
                10,
                CancellationToken::new(),
                replacement_sftp_requests,
                Duration::from_secs(15),
            )
            .unwrap_err();
        assert_eq!(error.code, "native-terminal-session-conflict");
        let colliding_operation = manager.begin(session_id).unwrap();
        manager.cancel(&session_id.to_string()).unwrap();
        assert!(manager_cancellation.is_cancelled());
        assert!(colliding_operation.cancellation.is_cancelled());
        drop(colliding_operation);
        manager.finish_terminal(session_id, 8);
        assert!(
            manager
                .lock_terminal_sessions()
                .unwrap()
                .contains_key(&session_id)
        );
        manager.finish_terminal(session_id, 9);
        assert!(manager.lock_terminal_sessions().unwrap().is_empty());

        for index in 0..MAX_TERMINAL_SESSIONS {
            let (sftp_requests, _sftp_receiver) = mpsc::channel(1);
            manager
                .reserve_terminal(
                    Uuid::from_u128(index as u128 + 300),
                    index as u64 + 20,
                    CancellationToken::new(),
                    sftp_requests,
                    Duration::from_secs(15),
                )
                .unwrap();
        }
        let (sftp_requests, _sftp_receiver) = mpsc::channel(1);
        let error = manager
            .reserve_terminal(
                Uuid::from_u128(999),
                99,
                CancellationToken::new(),
                sftp_requests,
                Duration::from_secs(15),
            )
            .unwrap_err();
        assert_eq!(error.code, "native-terminal-capacity");
    }

    #[tokio::test]
    async fn native_sftp_requests_are_bounded_cancelled_and_generation_safe() {
        let manager = NativeEngineManager::default();
        let session_id = Uuid::from_u128(1201);
        let cancellation = CancellationToken::new();
        let (requests, _request_receiver) = mpsc::channel(1);
        manager
            .reserve_terminal(
                session_id,
                41,
                cancellation.clone(),
                requests,
                Duration::from_secs(15),
            )
            .unwrap();
        let pending_manager = manager.clone();
        let pending = tokio::spawn(async move {
            pending_manager
                .list_sftp_directory(NativeSftpListRequest {
                    session_id: session_id.to_string(),
                    path: "/".to_string(),
                })
                .await
        });
        tokio::task::yield_now().await;
        let error = manager
            .list_sftp_directory(NativeSftpListRequest {
                session_id: session_id.to_string(),
                path: "/".to_string(),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, "native-sftp-backpressure");
        cancellation.cancel();
        assert_eq!(
            pending.await.unwrap().unwrap_err().code,
            "native-sftp-cancelled"
        );
        manager.finish_terminal(session_id, 40);
        assert!(
            manager
                .lock_terminal_sessions()
                .unwrap()
                .contains_key(&session_id)
        );
        manager.finish_terminal(session_id, 41);
        let error = manager
            .list_sftp_directory(NativeSftpListRequest {
                session_id: session_id.to_string(),
                path: "/".to_string(),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, "native-sftp-session-not-found");

        let stale_session_id = Uuid::from_u128(1202);
        let (requests, mut request_receiver) = mpsc::channel(1);
        manager
            .reserve_terminal(
                stale_session_id,
                42,
                CancellationToken::new(),
                requests,
                Duration::from_secs(15),
            )
            .unwrap();
        let stale_manager = manager.clone();
        let stale = tokio::spawn(async move {
            stale_manager
                .list_sftp_directory(NativeSftpListRequest {
                    session_id: stale_session_id.to_string(),
                    path: "/".to_string(),
                })
                .await
        });
        let Some(NativeSftpCommand::List { reply, .. }) = request_receiver.recv().await else {
            panic!("queued SFTP request");
        };
        manager.finish_terminal(stale_session_id, 42);
        let (replacement_requests, _replacement_receiver) = mpsc::channel(1);
        manager
            .reserve_terminal(
                stale_session_id,
                43,
                CancellationToken::new(),
                replacement_requests,
                Duration::from_secs(15),
            )
            .unwrap();
        reply
            .send(Ok(NativeSftpDirectoryResult {
                path: "/".to_string(),
                entries: Vec::new(),
            }))
            .unwrap();
        assert_eq!(
            stale.await.unwrap().unwrap_err().code,
            "native-sftp-generation-stale"
        );
        manager.finish_terminal(stale_session_id, 43);

        let timeout_session_id = Uuid::from_u128(1203);
        let (requests, _request_receiver) = mpsc::channel(1);
        manager
            .reserve_terminal(
                timeout_session_id,
                44,
                CancellationToken::new(),
                requests,
                Duration::from_millis(25),
            )
            .unwrap();
        let error = manager
            .list_sftp_directory(NativeSftpListRequest {
                session_id: timeout_session_id.to_string(),
                path: "/".to_string(),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, "native-sftp-timeout");
        manager.finish_terminal(timeout_session_id, 44);
    }

    #[tokio::test]
    async fn terminal_output_queue_applies_backpressure_without_dropping_data() {
        let (events, mut receiver) = mpsc::channel(1);
        let cancellation = CancellationToken::new();
        assert!(
            send_terminal_event(
                &events,
                NativeTerminalEvent::Data(b"first".to_vec()),
                &cancellation,
            )
            .await
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(25),
                send_terminal_event(
                    &events,
                    NativeTerminalEvent::Data(b"second".to_vec()),
                    &cancellation,
                ),
            )
            .await
            .is_err()
        );
        assert!(matches!(
            receiver.recv().await,
            Some(NativeTerminalEvent::Data(data)) if data == b"first"
        ));
        assert!(
            send_terminal_event(
                &events,
                NativeTerminalEvent::Data(b"second".to_vec()),
                &cancellation,
            )
            .await
        );
        assert!(matches!(
            receiver.recv().await,
            Some(NativeTerminalEvent::Data(data)) if data == b"second"
        ));
    }

    #[test]
    fn secret_bearing_request_is_deserialize_only_and_module_has_no_logging() {
        let source = include_str!("native_engine.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("derive(Debug, Deserialize)"));
        assert!(!production.contains("derive(Serialize, Deserialize)"));
        for forbidden in ["println!", "eprintln!", "dbg!", "tracing::", "log::"] {
            assert!(!production.contains(forbidden));
        }
        assert!(production.contains("check_server_key"));
        assert!(production.contains("HOST_KEY_MISMATCHED"));
        assert!(production.contains("SftpSession::new"));
        assert!(production.contains("channel_open_direct_tcpip"));
        assert!(production.contains("client::connect_stream"));
        assert!(!production.contains("native-engine-multi-hop-unavailable"));
        assert!(!production.contains("Command::new(\"ssh\")"));
    }

    #[tokio::test]
    async fn real_openssh_and_sftp_probe_when_configured() {
        let Ok(host) = std::env::var("VPSHELL_NATIVE_TEST_HOST") else {
            return;
        };
        let port = std::env::var("VPSHELL_NATIVE_TEST_PORT")
            .expect("test port")
            .parse()
            .expect("numeric test port");
        let username = std::env::var("VPSHELL_NATIVE_TEST_USER").expect("test user");
        let fingerprint =
            std::env::var("VPSHELL_NATIVE_TEST_HOST_KEY_SHA256").expect("test host key");
        let identity_file =
            std::env::var("VPSHELL_NATIVE_TEST_IDENTITY_FILE").expect("test identity file");
        let manager = NativeEngineManager::default();
        let mismatch = manager
            .probe(NativeEngineProbeRequest {
                operation_id: Uuid::new_v4().to_string(),
                route: NativeRouteRequest {
                    hops: vec![NativeRouteHopRequest {
                        hop_id: Uuid::new_v4().to_string(),
                        host: host.clone(),
                        port,
                        username: username.clone(),
                        host_key_sha256: format!("SHA256:{}", "A".repeat(43)),
                        timeout_seconds: 15,
                        credential_ref: None,
                        identity_file: Some(identity_file.clone()),
                        identity_passphrase_ref: None,
                    }],
                },
            })
            .await
            .expect_err("mismatched host key must fail before authentication");
        assert_eq!(mismatch.code, "native-engine-host-key-mismatch");
        assert_eq!(mismatch.hop_index, Some(1));
        let result = manager
            .probe(NativeEngineProbeRequest {
                operation_id: Uuid::new_v4().to_string(),
                route: NativeRouteRequest {
                    hops: vec![NativeRouteHopRequest {
                        hop_id: Uuid::new_v4().to_string(),
                        host,
                        port,
                        username,
                        host_key_sha256: fingerprint,
                        timeout_seconds: 15,
                        credential_ref: None,
                        identity_file: Some(identity_file),
                        identity_passphrase_ref: None,
                    }],
                },
            })
            .await
            .expect("real OpenSSH/SFTP probe");
        assert!(result.ssh_ready);
        assert!(result.sftp_ready);
        assert!(manager.lock_operations().unwrap().is_empty());
    }

    #[tokio::test]
    async fn real_openssh_terminal_stream_resize_and_cancel_when_configured() {
        let Ok(host) = std::env::var("VPSHELL_NATIVE_TEST_HOST") else {
            return;
        };
        let port = std::env::var("VPSHELL_NATIVE_TEST_PORT")
            .expect("test port")
            .parse()
            .expect("numeric test port");
        let username = std::env::var("VPSHELL_NATIVE_TEST_USER").expect("test user");
        let fingerprint =
            std::env::var("VPSHELL_NATIVE_TEST_HOST_KEY_SHA256").expect("test host key");
        let identity_file =
            std::env::var("VPSHELL_NATIVE_TEST_IDENTITY_FILE").expect("test identity file");
        let manager = NativeEngineManager::default();
        let session_id = Uuid::new_v4();
        let launch = manager
            .start_terminal(NativeTerminalStartRequest {
                session_id: session_id.to_string(),
                route: NativeRouteRequest {
                    hops: vec![NativeRouteHopRequest {
                        hop_id: Uuid::new_v4().to_string(),
                        host,
                        port,
                        username,
                        host_key_sha256: fingerprint,
                        timeout_seconds: 15,
                        credential_ref: None,
                        identity_file: Some(identity_file),
                        identity_passphrase_ref: None,
                    }],
                },
                cols: 120,
                rows: 32,
            })
            .await
            .expect("real OpenSSH terminal start");
        assert_eq!(launch.result.schema_version, SCHEMA_VERSION);
        assert_eq!(launch.result.engine, ENGINE_NAME);
        assert_eq!(launch.result.session_id, session_id.to_string());
        let first_listing = manager
            .list_sftp_directory(NativeSftpListRequest {
                session_id: session_id.to_string(),
                path: "~".to_string(),
            })
            .await
            .expect("first shared native SFTP listing");
        assert!(first_listing.path.starts_with('/'));
        assert!(first_listing.entries.len() <= MAX_SFTP_DIRECTORY_ENTRIES);
        let second_listing = manager
            .list_sftp_directory(NativeSftpListRequest {
                session_id: session_id.to_string(),
                path: first_listing.path.clone(),
            })
            .await
            .expect("reused native SFTP listing");
        assert_eq!(second_listing.path, first_listing.path);
        launch.handle.resize(132, 43).unwrap();
        launch
            .handle
            .write(b"printf 'VPSHELL_NATIVE_TERMINAL_OK\\n'\r")
            .unwrap();

        let mut events = launch.events;
        let mut output = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match events.recv().await.expect("terminal event stream") {
                    NativeTerminalEvent::Data(data) => {
                        output.extend_from_slice(&data);
                        if output
                            .windows(b"VPSHELL_NATIVE_TERMINAL_OK".len())
                            .any(|window| window == b"VPSHELL_NATIVE_TERMINAL_OK")
                        {
                            break;
                        }
                    }
                    NativeTerminalEvent::Exit { message } => {
                        panic!("terminal exited before output: {message:?}")
                    }
                }
            }
        })
        .await
        .expect("terminal output timeout");
        launch.handle.stop();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if matches!(
                    events.recv().await.expect("terminal exit event"),
                    NativeTerminalEvent::Exit { .. }
                ) {
                    break;
                }
            }
        })
        .await
        .expect("terminal cancellation timeout");
        assert!(manager.lock_terminal_sessions().unwrap().is_empty());
    }

    #[tokio::test]
    async fn real_openssh_jump_tunnel_when_configured() {
        let Ok(jump_host) = std::env::var("VPSHELL_NATIVE_TEST_JUMP_HOST") else {
            return;
        };
        let jump_port = std::env::var("VPSHELL_NATIVE_TEST_JUMP_PORT")
            .expect("jump test port")
            .parse()
            .expect("numeric jump test port");
        let jump_username = std::env::var("VPSHELL_NATIVE_TEST_JUMP_USER").expect("jump test user");
        let jump_fingerprint =
            std::env::var("VPSHELL_NATIVE_TEST_JUMP_HOST_KEY_SHA256").expect("jump test host key");
        let jump_identity_file = std::env::var("VPSHELL_NATIVE_TEST_JUMP_IDENTITY_FILE")
            .expect("jump test identity file");
        let target_host = std::env::var("VPSHELL_NATIVE_TEST_HOST").expect("target test host");
        let target_port = std::env::var("VPSHELL_NATIVE_TEST_PORT")
            .expect("target test port")
            .parse()
            .expect("numeric target test port");
        let target_username = std::env::var("VPSHELL_NATIVE_TEST_USER").expect("target test user");
        let target_fingerprint =
            std::env::var("VPSHELL_NATIVE_TEST_HOST_KEY_SHA256").expect("target test host key");
        let target_identity_file =
            std::env::var("VPSHELL_NATIVE_TEST_IDENTITY_FILE").expect("target test identity file");
        let route = |target_host_key_sha256: String| NativeRouteRequest {
            hops: vec![
                NativeRouteHopRequest {
                    hop_id: Uuid::new_v4().to_string(),
                    host: jump_host.clone(),
                    port: jump_port,
                    username: jump_username.clone(),
                    host_key_sha256: jump_fingerprint.clone(),
                    timeout_seconds: 15,
                    credential_ref: None,
                    identity_file: Some(jump_identity_file.clone()),
                    identity_passphrase_ref: None,
                },
                NativeRouteHopRequest {
                    hop_id: Uuid::new_v4().to_string(),
                    host: target_host.clone(),
                    port: target_port,
                    username: target_username.clone(),
                    host_key_sha256: target_host_key_sha256,
                    timeout_seconds: 15,
                    credential_ref: None,
                    identity_file: Some(target_identity_file.clone()),
                    identity_passphrase_ref: None,
                },
            ],
        };
        let manager = NativeEngineManager::default();
        let mismatch = manager
            .probe(NativeEngineProbeRequest {
                operation_id: Uuid::new_v4().to_string(),
                route: route(format!("SHA256:{}", "A".repeat(43))),
            })
            .await
            .expect_err("target pin mismatch must fail inside jump tunnel");
        assert_eq!(mismatch.code, "native-engine-host-key-mismatch");
        assert_eq!(mismatch.hop_index, Some(2));

        let probe = manager
            .probe(NativeEngineProbeRequest {
                operation_id: Uuid::new_v4().to_string(),
                route: route(target_fingerprint.clone()),
            })
            .await
            .expect("two-hop OpenSSH/SFTP probe");
        assert!(probe.ssh_ready);
        assert!(probe.sftp_ready);

        let forward_id = Uuid::new_v4();
        let forward = manager
            .start_local_forward(NativeLocalForwardStartRequest {
                forward_id: forward_id.to_string(),
                route: route(target_fingerprint.clone()),
                bind_port: 0,
                target_host: "127.0.0.1".to_string(),
                target_port,
            })
            .await
            .expect("two-hop local forward start");
        assert_eq!(forward.state, "active");
        assert_eq!(forward.bind_host, "127.0.0.1");
        assert_ne!(forward.bind_port, 0);
        let mut forwarded = TcpStream::connect((Ipv4Addr::LOCALHOST, forward.bind_port))
            .await
            .expect("connect local forward");
        let mut banner = [0_u8; 64];
        let bytes = tokio::time::timeout(Duration::from_secs(5), forwarded.read(&mut banner))
            .await
            .expect("forwarded banner timeout")
            .expect("read forwarded banner");
        assert!(banner[..bytes].starts_with(b"SSH-2.0-"));
        drop(forwarded);
        let snapshots = manager.list_local_forwards().unwrap();
        assert_eq!(snapshots.len(), 1);
        assert!(snapshots[0].accepted_connections >= 1);
        manager.stop_local_forward(&forward_id.to_string()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if manager.list_local_forwards().unwrap().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("local forward cancellation timeout");

        let session_id = Uuid::new_v4();
        let launch = manager
            .start_terminal(NativeTerminalStartRequest {
                session_id: session_id.to_string(),
                route: route(target_fingerprint),
                cols: 120,
                rows: 32,
            })
            .await
            .expect("two-hop OpenSSH terminal start");
        let listing = manager
            .list_sftp_directory(NativeSftpListRequest {
                session_id: session_id.to_string(),
                path: "~".to_string(),
            })
            .await
            .expect("two-hop shared native SFTP listing");
        assert!(listing.path.starts_with('/'));
        launch
            .handle
            .write(b"printf 'VPSHELL_NATIVE_JUMP_OK\\n'\r")
            .unwrap();
        let mut events = launch.events;
        let mut output = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match events.recv().await.expect("jump terminal event stream") {
                    NativeTerminalEvent::Data(data) => {
                        output.extend_from_slice(&data);
                        if output
                            .windows(b"VPSHELL_NATIVE_JUMP_OK".len())
                            .any(|window| window == b"VPSHELL_NATIVE_JUMP_OK")
                        {
                            break;
                        }
                    }
                    NativeTerminalEvent::Exit { message } => {
                        panic!("jump terminal exited before output: {message:?}")
                    }
                }
            }
        })
        .await
        .expect("jump terminal output timeout");
        launch.handle.stop();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if matches!(
                    events.recv().await.expect("jump terminal exit event"),
                    NativeTerminalEvent::Exit { .. }
                ) {
                    break;
                }
            }
        })
        .await
        .expect("jump terminal cancellation timeout");
        assert!(manager.lock_terminal_sessions().unwrap().is_empty());
    }
}
